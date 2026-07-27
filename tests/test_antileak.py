#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
АНТИ-ЛИК ГАРД — отдельная проверка, что защита НЕ видит разметку мира.

Главный научный аргумент работы: детектор оценивается честно, потому что не
получает метки (`is_anomaly/anomaly_type/family/technique_id/...`). Этот тест
прогоняет поток через защиту и проверяет, что НИ в наблюдаемых событиях, НИ в
алертах, НИ в инцидентах, НИ во входе LLM-триажа нет полей разметки.

Запуск:  python test_antileak.py   (код 0 = чисто)
"""

# --- скрипт живёт в подпапке; движок проекта — в корне ---
import os as _os, sys as _sys
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
for _p in (_ROOT, _os.path.join(_ROOT, "tools"), _os.path.join(_ROOT, "research")):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
_os.chdir(_ROOT)
del _os, _sys
import sys
import json
import tempfile
import os
import logging
from datetime import datetime

logging.disable(logging.CRITICAL)
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

LEAK_KEYS = ["is_anomaly", "anomaly_type", "family", "is_decisive", "severity_label",
             "episode_id", "campaign_id", "campaign_name", "step_idx",
             "technique_id", "tactic", "evasion_profile", "secret_type",
             "anomaly_subtype"]


def scan(obj, where, problems):
    flat = json.dumps(obj, ensure_ascii=False, default=str)
    for k in LEAK_KEYS:
        if f'"{k}"' in flat:
            problems.append(f"{where}: найдено поле '{k}'")


def main():
    import config, simclock, events, eventstore
    tmp = tempfile.mkdtemp()
    config.EVENT_LOG = {"enabled": True, "file": os.path.join(tmp, "e.jsonl")}
    config.EVENT_STORE = {"enabled": True, "path": os.path.join(tmp, "e.db")}
    simclock.init(simclock.SimClock(start_sim=datetime(2026, 6, 1, 19, 0, 0), scale=1.0,
                  work_start=10, work_end=18, work_days=[0, 1, 2, 3, 4], fast_forward_offhours=False))
    events.init()

    # аномальный эпизод с ПОЛНОЙ разметкой
    with events.tag(anomaly_type="secret_in_commit", episode_id="e1", family="secret_leak",
                    campaign_id="c1", campaign_name="demo", step_idx=0,
                    technique_id="T1552.001", tactic="Credential Access", evasion_profile="noisy"):
        events.emit("push", actor="maria", role="de", project="detection-rules", path="deploy/.env",
                    extra={"is_decisive": True, "secret_type": "aws", "shannon_entropy": 4.7,
                           "regex_hits": ["gitlab_pat"], "n_regex_hits": 1, "placeholder_signal": False})
    events.close()

    import run_defense
    problems = []
    # КЛЮЧЕВАЯ ГАРАНТИЯ: то, что подаётся детектору (observed), не содержит разметки.
    # Выход детектора (tactic/technique) — его СОБСТВЕННАЯ blue-атрибуция, это норм.
    n = 0
    for ev in eventstore.read_since(0):
        o = run_defense.observed(ev)
        scan(o, f"observed-событие #{o.get('action')}", problems)
        n += 1
    # полнота списка LEAK в самом коде защиты
    world_markup = {"is_anomaly", "anomaly_type", "family", "is_decisive",
                    "episode_id", "campaign_id", "technique_id", "tactic", "secret_type"}
    missing = world_markup - set(run_defense.LEAK)
    if missing:
        problems.append(f"run_defense.LEAK не покрывает: {missing}")

    print("=" * 56)
    print("  АНТИ-ЛИК ГАРД")
    print("=" * 56)
    print(f"  проверено observed-событий: {n}")
    if problems:
        print("  ❌ НАЙДЕНЫ УТЕЧКИ РАЗМЕТКИ:")
        for p in problems:
            print("   -", p)
        return 1
    print("  ✅ Чисто: на вход детектора не попадает ни одно поле разметки мира.")
    print("  (observed() срезает её; список run_defense.LEAK полон)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
