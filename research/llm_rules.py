#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LLM-АВТОРИНГ ПРАВИЛ — автономный detection-инжиниринг.

Замыкает цикл Detection-as-Code: находит слепые зоны (техники ATT&CK, которые
red исполнял, а правил на них нет — purple-team debrief по разметке) и для каждой
просит LLM СИНТЕЗИРОВАТЬ detection-правило по НАБЛЮДАЕМОМУ решающему событию.
Каждое правило валидируется (срабатывает ли на пропущенном событии тем же
матчером, что у детектора); если LLM недоступна или правило не прошло — берётся
эвристический шаблон. Валидные правила пишутся в detections/proposed/.

Это и есть «AI detection engineer»: модель не объясняет, а ПИШЕТ работающие
правила — то, что в арене раньше делал шаблон.

Запуск:  python llm_rules.py            # показать, что сгенерировалось
         python llm_rules.py --write    # записать в detections/proposed/
"""

# --- скрипт живёт в подпапке; движок проекта — в корне ---
import os as _os, sys as _sys
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
for _p in (_ROOT, _os.path.join(_ROOT, "tools"), _os.path.join(_ROOT, "research")):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
_os.chdir(_ROOT)
del _os, _sys
import os
import sys
import json
import argparse

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

import detection_gaps
import run_defense
import llm_client

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    ap = argparse.ArgumentParser(description="LLM authors detection rules for blind spots")
    ap.add_argument("--write", action="store_true", help="записать правила в detections/proposed/")
    args = ap.parse_args()

    rows = detection_gaps.load_events()
    if not rows:
        print("[!] Нет событий. Сначала: python make_demo.py --fresh"); sys.exit(1)

    # слепые зоны + решающее событие на технику (debrief)
    executed, decisive, fam = {}, {}, {}
    for r in rows:
        if r.get("is_anomaly") and r.get("technique_id"):
            t = r["technique_id"]; executed[t] = executed.get(t, 0) + 1
            fam[t] = r.get("tactic") or r.get("family") or "?"
            if r.get("is_decisive") and t not in decisive:
                decisive[t] = r
    covered = detection_gaps.covered_techniques()
    gaps = sorted(set(executed) - covered)

    src = "LLM (Ollama)" if llm_client.available() else "фолбэк-шаблон (Ollama недоступна)"
    print("=" * 70)
    print("  LLM-АВТОРИНГ DETECTION-ПРАВИЛ под слепые зоны")
    print("=" * 70)
    print(f"  источник: {src} | слепых зон: {len(gaps)}")
    print("-" * 70)
    if not gaps:
        print("  Слепых зон нет — всё покрыто. (Запусти атаки/арену, чтобы появились.)")
        return

    authored = []
    for t in gaps:
        dec = decisive.get(t) or {"action": "push"}
        obs = run_defense.observed(dec)        # анти-лик: только наблюдаемое
        rule = llm_client.author_rule(obs, technique=t, tactic=fam.get(t, "?"))
        authored.append(rule)
        print(f"  {t:12} ({fam.get(t,'?')})")
        print(f"     источник: {rule.get('_source')}")
        print(f"     when: {json.dumps(rule.get('when', {}), ensure_ascii=False)}")

    if args.write:
        outdir = os.path.join(BASE, "detections", "proposed")
        os.makedirs(outdir, exist_ok=True)
        n = 0
        for rule in authored:
            rid = rule.get("id") or ("llm-" + rule.get("technique", "rule").lower().replace(".", "-"))
            rule["id"] = rid
            with open(os.path.join(outdir, rid + ".json"), "w", encoding="utf-8") as f:
                json.dump(rule, f, ensure_ascii=False, indent=2)
            n += 1
        print("-" * 70)
        print(f"  Записано правил: {n} -> detections/proposed/")
        print("  Включить в детект: config.LOAD_PROPOSED = True (после ревью).")
    else:
        print("-" * 70)
        print("  Это превью. Запись: python llm_rules.py --write")


if __name__ == "__main__":
    main()
