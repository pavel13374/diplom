#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SELF-TEST платформы — единый health-check всего конвейера в одном процессе.

Прогоняет на ВРЕМЕННОМ сторе (реальные данные не трогает):
  1) event-store: запись/чтение по курсору, переживание «рестарта»;
  2) мир: исполнение многошаговой red-кампании (фейковый GitLab);
  3) защита: Detection Stack (правила+UEBA) даёт алерты, benign не алертит;
  4) корреляция: алерты склеиваются в инцидент с ATT&CK kill-chain;
  5) анти-лик: в blue-выводе нет меток мира;
  6) LLM-триаж (фолбэк без Ollama): critical/TP на утечке;
  7) команды: enqueue -> claim -> исполнение кампании;
  8) экспорт датасета без утечки + rule_baseline;
  9) метрики.

Печатает PASS/FAIL по пунктам и итог. Код возврата 0/1.

Запуск:  python selftest.py
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
import os
import tempfile
import logging
from datetime import datetime, timedelta

logging.disable(logging.CRITICAL)
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    mark = "PASS" if cond else "FAIL"
    print(f"  [{mark}] {name}" + (f"  — {detail}" if detail else ""))
    return cond


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
    def create_issue(self, *a, **k): return 77
    def get_open_mrs(self, pid): return []


def main():
    import config, simclock, events, eventstore
    tmp = tempfile.mkdtemp()
    config.EVENT_LOG = {"enabled": True, "file": os.path.join(tmp, "events.jsonl")}
    config.EVENT_STORE = {"enabled": True, "path": os.path.join(tmp, "events.db")}
    config.TELEGRAM = {"enabled": False}
    simclock.init(simclock.SimClock(start_sim=datetime(2026, 6, 1, 10, 0, 0), scale=1.0,
                  work_start=10, work_end=18, work_days=[0, 1, 2, 3, 4], fast_forward_offhours=False))
    simclock.sleep = lambda *a, **k: None
    events.init()

    print("=" * 60)
    print("  SELF-TEST: SOC Purple-Team Platform")
    print("=" * 60)

    # 1) event-store + курсор
    print("\n[1] Event-store + курсор")
    base = datetime(2026, 6, 1, 10, 0, 0)
    for i in range(20):
        simclock.now = lambda t=base + timedelta(minutes=i): t
        events.emit("push", actor="maria.ivanova", role="detection_engineer",
                    project="detection-rules", path="rules/a.yml",
                    extra={"shannon_entropy": 2.3, "regex_hits": [], "n_regex_hits": 0,
                           "placeholder_signal": False, "bytes": 150, "ext": "yml"})
    n0 = eventstore.stats()["events"]
    pos = eventstore.read_since(0)[-1]["_id"]
    eventstore.set_cursor("t", pos)
    eventstore.close(); eventstore.init(path=config.EVENT_STORE["path"])
    check("запись/чтение событий", n0 >= 20, f"{n0} событий")
    check("курсор переживает рестарт", eventstore.get_cursor("t") == pos)

    # benign .env.example
    simclock.now = lambda: datetime(2026, 6, 1, 11, 0, 0)
    events.emit("push", actor="dmitry.kozlov", role="detection_engineer",
                project="detection-rules", path="config/.env.example",
                extra={"shannon_entropy": 3.2, "regex_hits": [], "n_regex_hits": 0,
                       "placeholder_signal": True, "bytes": 80, "ext": "example"})

    # 2) red-кампания
    print("\n[2] Red Team Engine (многошаговая кампания)")
    from agents.base import BaseAgent
    from agents.lead import LeadAgent
    agents = {u: (LeadAgent(u, FakeGL()) if i.get("role") == "lead" else BaseAgent(u, FakeGL()))
              for u, i in config.USERS.items()}
    simclock.now = lambda: datetime(2026, 6, 4, 19, 0, 0)
    from red_team import RedTeamEngine
    res = RedTeamEngine(agents, state=None).run_campaign("ci_token_to_exfil", evasion="noisy")
    check("кампания исполнилась", res and res["ok_steps"] >= 3, f"{res['ok_steps']}/{res['steps']} шагов")
    events.close()

    # 3) защита: детект
    print("\n[3] Detection Stack (защита)")
    import run_defense, correlator as cm
    cor = cm.Correlator(window_min=240)
    alerts = 0; benign_alerted = False
    for ev in eventstore.read_since(0):
        det = run_defense.process(ev)
        if det.get("alert"):
            alerts += 1
            o = run_defense.observed(ev)
            cor.add(o, det)
            if o.get("path") == "config/.env.example":
                benign_alerted = True
    check("детектор даёт алерты", alerts >= 3, f"{alerts} алертов")
    check("benign .env.example НЕ алертит", not benign_alerted)

    # 4) корреляция -> инцидент с kill-chain
    print("\n[4] Корреляция -> инцидент")
    inc = cor.list()[0]
    check("инцидент-кампания с kill-chain", inc.get("is_campaign") and len(inc["tactics"]) >= 3,
          f"тактик: {len(inc['tactics'])}")

    # 5) анти-лик
    print("\n[5] Анти-лик")
    import json as J
    flat = J.dumps([run_defense.observed(e) for e in eventstore.read_since(0)], ensure_ascii=False)
    leak = any(k in flat for k in ('"is_anomaly"', '"anomaly_type"', '"family"', '"is_decisive"',
                                   '"technique_id"', '"campaign_id"'))
    check("в наблюдаемых событиях нет меток мира", not leak)

    # 6) LLM-триаж (фолбэк)
    print("\n[6] LLM-триаж (фолбэк без Ollama)")
    import llm_client
    ctx = {"actor": inc["actor"], "repos": inc["repos"], "risk_score": round(inc["max_risk"], 2),
           "regex_hits": ["gitlab_pat"], "shannon_entropy": 4.6, "placeholder_signal": False,
           "kill_chain_tactics": inc["tactics"]}
    tr = llm_client.triage(ctx)
    check("триаж даёт high/critical + TP", tr["severity"] in ("high", "critical") and tr["is_true_positive"],
          f"{tr['_source']} -> {tr['severity']}")

    # 7) команды
    print("\n[7] Канал команд")
    eventstore.enqueue_command("campaign", {"key": "insider_secret_theft", "evasion": "noisy"})   # id команды не проверяем, важен сам факт постановки
    cmd = eventstore.claim_command()
    r2 = RedTeamEngine(agents, state=None).run_campaign(cmd["payload"]["key"], cmd["payload"]["evasion"])
    eventstore.set_command_result(cmd["id"], "ok")
    check("команда -> исполнение кампании", cmd and r2 and r2["ok_steps"] >= 3)

    # 8) экспорт датасета + baseline
    print("\n[8] Экспорт датасета + baseline")
    import subprocess
    out = os.path.join(tmp, "ds")
    rc = subprocess.run([sys.executable, os.path.join("research", "export_dataset.py"), "--in", config.EVENT_LOG["file"],
                         "--out", out], capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ds_ok = rc.returncode == 0 and os.path.exists(os.path.join(out, "train.jsonl"))
    # анти-лик в датасете
    leak_ds = False
    if ds_ok:
        for line in open(os.path.join(out, "train.jsonl"), encoding="utf-8"):
            r = J.loads(line)
            if any(k in r for k in ("is_anomaly", "anomaly_type", "run_id", "campaign_id")):
                leak_ds = True; break
    check("export_dataset без утечки", ds_ok and not leak_ds)
    rc2 = subprocess.run([sys.executable, os.path.join("research", "rule_baseline.py"), "--in", config.EVENT_LOG["file"]],
                         capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    check("rule_baseline отрабатывает", rc2.returncode == 0)

    # 9) метрики
    print("\n[9] Метрики")
    import metrics
    m = metrics.compute()
    check("метрики считаются", m and m["anomaly_episodes"] >= 3 and m["detection_rate"] > 0,
          f"det.rate={m['detection_rate']*100:.0f}% cov={m['attack_coverage']*100:.0f}%")

    # итог
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    total = len(RESULTS)
    print("\n" + "=" * 60)
    print(f"  ИТОГ: {passed}/{total} проверок пройдено")
    print("=" * 60)
    if passed == total:
        print("  ✅ ВСЁ РАБОТАЕТ — платформа здорова.")
        return 0
    print("  ❌ Есть провалы — см. [FAIL] выше.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
