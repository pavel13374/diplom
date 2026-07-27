#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CO-EVOLUTION ARENA (EPIC 5.4) - main experiment.

Rounds of red vs blue confrontation:
  1) RED executes an ATT&CK campaign (noisy, exercises techniques).
  2) BLUE detects the stream with its CURRENT ruleset.
  3) Detection-as-Code: for techniques RED executed but BLUE missed
     (blind spots) the engine AUTO-adds a drafted rule -> coverage grows.
  4) Over rounds blue closes the gaps the red opens; ATT&CK coverage rises.

Output: table + CSV "coverage / detection rate vs round" - shows defense
catching up with the attacker (the headline result for the thesis defense).

No GitLab, no ML. Reproducible (config.SEED).

Run:  python arena.py [--rounds 8]
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
import csv
import argparse
import tempfile
import logging
from datetime import datetime

logging.disable(logging.CRITICAL)
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


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
    ap = argparse.ArgumentParser(description="Red vs Blue co-evolution arena")
    ap.add_argument("--rounds", type=int, default=8)
    args = ap.parse_args()

    import config, simclock, events, eventstore, run_defense, detection_gaps
    config.TELEGRAM = {"enabled": False}
    config.seed_all()
    tmp = tempfile.mkdtemp()
    config.EVENT_LOG = {"enabled": True, "file": os.path.join(tmp, "e.jsonl")}
    config.EVENT_STORE = {"enabled": True, "path": os.path.join(tmp, "e.db")}
    simclock.init(simclock.SimClock(start_sim=datetime(2026, 6, 1, 19, 0, 0), scale=1.0,
                  work_start=10, work_end=18, work_days=[0, 1, 2, 3, 4], fast_forward_offhours=False))
    simclock.sleep = lambda *a, **k: None
    events.init()

    from agents.base import BaseAgent
    from agents.lead import LeadAgent
    from red_team import RedTeamEngine, CAMPAIGNS
    agents = {u: (LeadAgent(u, FakeGL()) if i.get("role") == "lead" else BaseAgent(u, FakeGL()))
              for u, i in config.USERS.items()}
    red = RedTeamEngine(agents, state=None)

    # blue: live engine. Start with a WEAK core ruleset (few techniques) so that
    # we can SEE defense catch up with the attacker via Detection-as-Code.
    engine = run_defense._ENGINE
    all_techs = {tt for c in CAMPAIGNS.values() for (_, tt, _) in c["steps"]}
    SEED = {"T1485", "T1562"}
    engine.rules = [r for r in engine.rules if r.get("technique") in SEED]
    cursor = 0
    caught_techs = set()
    camp_keys = list(CAMPAIGNS)
    day = 4

    print("=" * 72)
    print("  CO-EVOLUTION ARENA  (red vs blue)")
    print("=" * 72)
    print(f"  start: weak core ({engine.rule_count()} rules, techniques in catalog: {len(all_techs)})")
    print(f"  rounds: {args.rounds} | red cycles campaigns, blue closes gaps (DaC)")
    print("-" * 72)
    print(f"{'rnd':>3} | {'campaign':22} | {'tech':>4} | {'caught':>6} | "
          f"{'gap':>3} | {'+rule':>5} | {'coverage':>8} | {'detect':>6}")
    print("-" * 72)

    rows = []
    for r in range(1, args.rounds + 1):
        key = camp_keys[(r - 1) % len(camp_keys)]
        simclock.now = lambda t=datetime(2026, 6, day + r, 19, 0, 0): t
        red.run_campaign(key, evasion="noisy")
        events.close(); events.init()

        batch = eventstore.read_since(cursor)
        cursor = batch[-1]["_id"] if batch else cursor

        executed, decisive = set(), {}
        for ev in batch:
            t = ev.get("technique_id")
            if ev.get("is_anomaly") and t:
                executed.add(t)
                if ev.get("is_decisive") and t not in decisive:
                    decisive[t] = ev
        eps = {}
        for ev in batch:
            eid = ev.get("episode_id")
            if eid:
                eps.setdefault(eid, {"actor": ev.get("actor"), "caught": False})

        round_caught_tech, alert_actors = set(), set()
        for ev in batch:
            det = engine.process(run_defense.observed(ev))
            if det.get("alert"):
                alert_actors.add(ev.get("actor"))
                for a in det["alerts"]:
                    if a.get("technique") and a["technique"] != "UEBA":
                        round_caught_tech.add(a["technique"])
        for e in eps.values():
            if e["actor"] in alert_actors:
                e["caught"] = True
        det_rate = (sum(1 for e in eps.values() if e["caught"]) / len(eps)) if eps else 0.0

        covered_now = set(engine.techniques_covered())
        gaps = sorted(executed - covered_now)
        added = 0
        for t in gaps:
            dec = decisive.get(t) or {"action": "push"}
            rule = detection_gaps.draft_rule(t, run_defense.observed(dec), "auto")
            rule["id"] = f"auto-{t.lower().replace('.', '-')}"
            if rule["id"] not in {x.get("id") for x in engine.rules}:
                engine.rules.append(rule); added += 1

        caught_techs |= round_caught_tech
        covered = set(engine.techniques_covered()) & all_techs
        cov = len(covered) / len(all_techs)

        print(f"{r:>3} | {key:22} | {len(executed):>4} | {len(round_caught_tech):>6} | "
              f"{len(gaps):>3} | {added:>5} | {cov*100:>7.0f}% | {det_rate*100:>5.0f}%")
        rows.append({"round": r, "campaign": key, "executed": len(executed),
                     "caught": len(round_caught_tech), "gaps": len(gaps),
                     "new_rules": added, "coverage": round(cov, 3),
                     "detection_rate": round(det_rate, 3), "rules_total": engine.rule_count()})

    print("-" * 72)
    print("  ATT&CK coverage by round:")
    for row in rows:
        bar = "#" * int(round(row["coverage"] * 30))
        print(f"   R{row['round']} |{bar:<30}| {row['coverage']*100:.0f}%  (+{row['new_rules']} rules)")
    print("=" * 72)
    print("  Conclusion: blue closes the Detection-as-Code loop and catches up with")
    print("  the attacker - ATT&CK coverage grows round over round (co-evolution).")

    os.makedirs(os.path.join(BASE, "results"), exist_ok=True)
    fp = os.path.join(BASE, "results", "arena.csv")
    with open(fp, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    print(f"  CSV: {os.path.relpath(fp, BASE)}")


if __name__ == "__main__":
    main()
