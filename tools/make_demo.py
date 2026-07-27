#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MAKE DEMO — гарантированный демо-прогон БЕЗ GitLab (фейковый клиент).

Готовит наглядную картину «атака → детект → инцидент → покрытие» в ОСНОВНОМ
event-store (data/events.db), чтобы открыть Purple Team Console и сразу увидеть
результат, или приложить вывод к защите. Реальный GitLab не нужен.

  python make_demo.py            # норма + 2 кампании в data/events.db
  python make_demo.py --fresh    # сначала очистить data/events.db

После: открой console.py (8788) ИЛИ python metrics.py / python ir_report.py.
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
import argparse
import logging
from datetime import datetime, timedelta

logging.disable(logging.CRITICAL)
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


class FakeGL:
    def create_branch(self, *a, **k): return True
    def push_file(self, *a, **k): return True
    def create_mr(self, *a, **k): return 5
    def comment_mr(self, *a, **k): return True
    def merge_mr(self, *a, **k): return True
    def approve_mr(self, *a, **k): return True
    def create_commit(self, *a, **k): return True
    def list_files(self, *a, **k): return [f"rules/r{i}.yml" for i in range(12)]
    def create_named_token(self, *a, **k): return True
    def get_or_create_user_token(self, *a, **k): return "t"
    def get_open_mrs(self, pid): return []


def main():
    ap = argparse.ArgumentParser(description="Generate a demo stream")
    ap.add_argument("--fresh", action="store_true")
    args = ap.parse_args()

    import config, simclock, events, eventstore
    config.TELEGRAM = {"enabled": False}
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    if args.fresh:
        for f in ("data/events.db", "data/events.db-wal", "data/events.db-shm", "data/events.jsonl"):
            p = os.path.join(base, f)
            try:
                if os.path.exists(p):
                    os.remove(p)
            except Exception as e:
                print(f"  (не удалил {f}: {e}; продолжаю)")
        print("Очистил data/events.* — свежий прогон.")

    simclock.init(simclock.SimClock(start_sim=datetime(2026, 6, 1, 10, 0, 0), scale=1.0,
                  work_start=10, work_end=18, work_days=[0, 1, 2, 3, 4], fast_forward_offhours=False))
    simclock.sleep = lambda *a, **k: None
    events.init()

    print("Генерирую норму (фон команды)...")
    bt = datetime(2026, 6, 1, 10, 0, 0)
    import random; random.seed(7)
    actors = ["maria.ivanova", "dmitry.kozlov", "anna.smirnova", "sergey.volkov"]
    seq = 0
    for d in range(5):
        for h in range(0, 12):
            seq += 1
            simclock.now = lambda t=bt + timedelta(days=d, hours=h, minutes=random.randint(0, 50)): t
            a = random.choice(actors)
            repo = random.choice(["detection-rules", "threat-hunting", "normalization-rules", "playbooks"])
            path = random.choice(["rules/win/a.yml", "config/.env.example", "src/util.py", "docs/n.md"])
            ph = path.endswith(".env.example")
            events.emit("push", actor=a, role="detection_engineer", project=repo, path=path,
                        extra={"shannon_entropy": 3.2 if ph else 2.4, "regex_hits": [], "n_regex_hits": 0,
                               "filename_signal": ph, "placeholder_signal": ph, "bytes": 200, "ext": "yml"})

    from agents.base import BaseAgent
    from agents.lead import LeadAgent
    agents = {u: (LeadAgent(u, FakeGL()) if i.get("role") == "lead" else BaseAgent(u, FakeGL()))
              for u, i in config.USERS.items()}
    from red_team import RedTeamEngine
    eng = RedTeamEngine(agents, state=None)

    print("Запускаю атаки (red-кампании)...")
    simclock.now = lambda: datetime(2026, 6, 4, 19, 0, 0)
    r1 = eng.run_campaign("ci_token_to_exfil", evasion="noisy")
    simclock.now = lambda: datetime(2026, 6, 5, 3, 0, 0)
    r2 = eng.run_campaign("insider_secret_theft", evasion="stealthy")
    events.close()

    st = eventstore.stats()
    print("\n" + "=" * 54)
    print("ДЕМО ГОТОВО")
    print("=" * 54)
    print(f"  событий в сторе:   {st['events']}")
    print(f"  аномальных:        {st['anomaly_events']}")
    print(f"  кампаний:          {st['campaigns']}  ({r1['key']}, {r2['key']})")
    print("-" * 54)
    print("  Дальше:")
    print("    python console.py     # открой http://127.0.0.1:8788")
    print("    python metrics.py     # SOC-метрики")
    print("    python ir_report.py   # IR-отчёты в reports/")
    print("    python detection_gaps.py   # слепые зоны покрытия")


if __name__ == "__main__":
    main()
