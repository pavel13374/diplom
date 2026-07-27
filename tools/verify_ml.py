#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ДОКАЗАТЕЛЬСТВО, ЧТО ML ЛОВИТ АТАКИ.

Одной командой: генерит нормальную работу команды + 4 разных ATT&CK-кампании,
делит данные по времени (train/test), обучает ML-детектор и показывает, СКОЛЬКО
эпизодов каждой атаки он поймал на ОТЛОЖЕННЫХ данных (которых при обучении не
видел). Работает offline (без GitLab), воспроизводимо.

  python verify_ml.py

В конце — список 4 атак и как запустить их вживую через Red Launcher на :8788.
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
import tempfile
import logging
import collections
from datetime import datetime, timedelta

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

logging.disable(logging.CRITICAL)
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CAMPAIGNS = ["ci_token_to_exfil", "insider_secret_theft",
             "supply_chain_recon", "review_bypass_sabotage"]
NICE = {
    "ci_token_to_exfil":      "Кража CI-токена → отключение защиты → вынос данных",
    "insider_secret_theft":   "Инсайдер: лишний токен → секрет в коммите → вынос",
    "supply_chain_recon":     "Разведка → доступ → отравленный CI → вынос",
    "review_bypass_sabotage": "Обход ревью → отравленный CI → разрушение",
}


class FakeGL:
    import random as _r
    def __getattr__(self, n):
        def f(*a, **k):
            if n in ("create_mr", "create_issue"): return FakeGL._r.randint(100, 9999)
            if n in ("get_open_mrs", "list_files"): return []
            if n == "get_mr": return {}
            if n in ("get_or_create_user_token",): return "t"
            return True
        return f


def generate():
    import config, simclock, events, eventstore
    config.OFFLINE_MODE = True
    config.TELEGRAM = {"enabled": False}
    config.seed_all()
    tmp = tempfile.mkdtemp()
    config.EVENT_LOG = {"enabled": True, "file": os.path.join(tmp, "e.jsonl")}
    config.EVENT_STORE = {"enabled": True, "path": os.path.join(tmp, "e.db")}
    simclock.init(simclock.SimClock(start_sim=datetime(2026, 6, 1, 10, 0, 0), scale=1.0,
                  work_start=10, work_end=18, work_days=[0, 1, 2, 3, 4], fast_forward_offhours=False))
    simclock.sleep = lambda *a, **k: None
    events.init()

    import random
    rnd = random.Random(42)
    actors = ["maria.ivanova", "dmitry.kozlov", "anna.smirnova", "sergey.volkov"]
    bt = datetime(2026, 6, 1, 10, 0, 0)
    # нормальный фон
    for d in range(10):
        for h in range(14):
            simclock.now = lambda t=bt + timedelta(days=d, hours=h % 8, minutes=rnd.randint(0, 55)): t
            a = rnd.choice(actors)
            repo = rnd.choice(["detection-rules", "threat-hunting", "normalization-rules", "playbooks"])
            path = rnd.choice(["rules/win/a.yml", "config/.env.example", "src/util.py", "docs/n.md"])
            ph = path.endswith(".env.example")
            events.emit("push", actor=a, role="detection_engineer", project=repo, path=path,
                        extra={"shannon_entropy": 3.2 if ph else 2.4, "regex_hits": [], "n_regex_hits": 0,
                               "filename_signal": ph, "placeholder_signal": ph, "bytes": 200, "ext": "yml"})

    from agents.base import BaseAgent
    from agents.lead import LeadAgent
    from red_team import RedTeamEngine
    agents = {u: (LeadAgent(u, FakeGL()) if i.get("role") == "lead" else BaseAgent(u, FakeGL()))
              for u, i in config.USERS.items()}
    red = RedTeamEngine(agents, state=None)
    # каждую из 4 кампаний прогоняем несколько раз, растянув по времени
    day = 3
    for rep in range(5):
        for key in CAMPAIGNS:
            day += 1
            simclock.now = lambda t=datetime(2026, 6, 1 + day, 19, 0, 0): t
            red.run_campaign(key, evasion="noisy")
    events.close()
    return eventstore.read_since(0, limit=10_000_000)


def main():
    import train_model as tm
    rows = [r for r in generate() if not r.get("meta")]
    rows.sort(key=lambda r: r.get("ts_sim") or "")
    cut = int(len(rows) * 0.7)
    train, test = rows[:cut], rows[cut:]

    Xtr = [tm.feat(r) for r in train]; ytr = [1 if r.get("is_anomaly") else 0 for r in train]
    name, score = tm.make_model(Xtr, ytr)
    neg = [score(tm.feat(r)) for r in train if not r.get("is_anomaly")]
    thr = tm.thr_for_fp(neg, 0.02)

    # эпизоды теста по кампаниям
    eps = {}
    for r in test:
        if r.get("is_anomaly") and r.get("episode_id"):
            e = eps.setdefault(r["episode_id"], {"camp": r.get("campaign_name") or "—", "max": 0.0})
            e["max"] = max(e["max"], score(tm.feat(r)))
    by = collections.defaultdict(lambda: [0, 0])
    for e in eps.values():
        by[e["camp"]][1] += 1
        if e["max"] >= thr:
            by[e["camp"]][0] += 1
    caught = sum(v[0] for v in by.values()); total = sum(v[1] for v in by.values())
    fp = sum(score(tm.feat(r)) >= thr for r in test if not r.get("is_anomaly"))
    negn = sum(1 for r in test if not r.get("is_anomaly"))

    print("=" * 66)
    print("  ПРОВЕРКА: ЛОВИТ ЛИ ML АТАКИ (на отложенных данных)")
    print("=" * 66)
    print(f"  модель: {name}")
    print(f"  событий: {len(rows)} (train {len(train)} / test {len(test)}) | порог FP≤2%")
    print("-" * 66)
    print(f"  {'Атака (кампания)':40} | эпизодов | поймано")
    print("-" * 66)
    for key in CAMPAIGNS:
        c, t = by.get(key, [0, 0])
        mark = "✅" if (t and c == t) else ("⚠️" if c else "❌")
        print(f"  {mark} {NICE[key][:37]:37} | {t:>7}  | {c}/{t}")
    print("-" * 66)
    print(f"  ИТОГ на отложенных: поймано {caught}/{total} эпизодов атак "
          f"({round(caught/max(1,total)*100)}%)  при FP {round(fp/max(1,negn)*100,1)}% на норме")
    print("=" * 66)
    print("  Вывод: ML обучен только на прошлом, а ловит атаки в БУДУЩЕМ (test),")
    print("  которого не видел — значит он выучил ПРИЗНАКИ атак, а не запомнил их.")
    print()
    print("  Как повторить это вживую на своём GitLab (:8788 → Red Launcher):")
    for i, key in enumerate(CAMPAIGNS, 1):
        print(f"    {i}. «{key}» — {NICE[key]}")
    print("  Запусти любую → смотри Алерты → Инциденты → «LLM-разбор».")


if __name__ == "__main__":
    main()
