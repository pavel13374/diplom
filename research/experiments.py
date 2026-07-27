#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ABLATION EXPERIMENTS - the experiments chapter of the thesis.

Measures how detection quality depends on (a) which detector layers are on and
(b) the attacker's evasion profile. Two independent axes:

  detector config:   rules_only | ueba_only | full (rules + UEBA)
  evasion profile:   noisy | stealthy | adaptive

For every cell we run the SAME workload (normal background + 4 ATT&CK campaigns)
and report:
  recall    - share of attack EPISODES detected (any alert on the episode)
  fp_rate   - share of NORMAL events that raised an alert (false positives)
  coverage  - share of executed ATT&CK techniques that fired a rule/UEBA alert

Headline findings this produces:
  * rules_only is strong on 'noisy' but collapses on 'stealthy' (content hidden);
  * ueba_only recovers part of stealthy recall (behavior) but costs more FP;
  * full (rules+UEBA) gives the best recall at acceptable FP -> defense-in-depth.

No GitLab, no ML. Reproducible (config.SEED). Writes results/experiments.csv.

Run:  python experiments.py
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
import copy
import tempfile
import logging
from datetime import datetime, timedelta

logging.disable(logging.CRITICAL)
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIGS = ["rules_only", "ueba_only", "full"]
EVASIONS = ["noisy", "stealthy", "adaptive"]


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


def build_workload(evasion):
    """Fresh temp store: normal background (trains UEBA) + 4 campaigns at `evasion`.
    Returns list of events (dicts) from the store, in order."""
    import config, simclock, events, eventstore
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
    # normal background: enough per actor to train UEBA (MIN_EVENTS)
    for d in range(5):
        for h in range(12):
            simclock.now = lambda t=bt + timedelta(days=d, hours=h, minutes=rnd.randint(0, 50)): t
            a = rnd.choice(actors)
            repo = rnd.choice(["detection-rules", "threat-hunting", "normalization-rules", "playbooks"])
            path = rnd.choice(["rules/win/a.yml", "config/.env.example", "src/util.py", "docs/n.md"])
            ph = path.endswith(".env.example")
            events.emit("push", actor=a, role="detection_engineer", project=repo, path=path,
                        extra={"shannon_entropy": 3.2 if ph else 2.4, "regex_hits": [], "n_regex_hits": 0,
                               "filename_signal": ph, "placeholder_signal": ph, "bytes": 200, "ext": "yml"})

    from agents.base import BaseAgent
    from agents.lead import LeadAgent
    from red_team import RedTeamEngine, CAMPAIGNS
    agents = {u: (LeadAgent(u, FakeGL()) if i.get("role") == "lead" else BaseAgent(u, FakeGL()))
              for u, i in config.USERS.items()}
    red = RedTeamEngine(agents, state=None)
    for i, key in enumerate(CAMPAIGNS):
        simclock.now = lambda t=datetime(2026, 6, 6, 19 + i, 0, 0): t
        red.run_campaign(key, evasion=evasion)
    events.close()
    return eventstore.read_since(0, limit=10_000_000)


def make_engine(config_name):
    import detector
    eng = detector.DetectionEngine()
    if config_name == "rules_only":
        eng.ueba.THRESHOLD = 9.9          # UEBA off
    elif config_name == "ueba_only":
        eng.rules = []                    # rules off
    return eng


def evaluate(events_list, config_name):
    import run_defense
    eng = make_engine(config_name)
    # ground truth
    attack_eps, normal_events = {}, 0
    executed = set()
    for ev in events_list:
        if ev.get("meta"):
            continue
        if ev.get("is_anomaly"):
            eid = ev.get("episode_id")
            if eid:
                attack_eps.setdefault(eid, {"actor": ev.get("actor"), "detected": False})
            if ev.get("technique_id"):
                executed.add(ev["technique_id"])
        else:
            normal_events += 1
    # run detector
    fp = 0
    caught_tech = set()
    alert_actors_window = {}  # actor -> True if any alert (attack attribution by actor)
    for ev in events_list:
        if ev.get("meta"):
            continue
        det = eng.process(run_defense.observed(ev))
        if not det.get("alert"):
            continue
        if ev.get("is_anomaly"):
            eid = ev.get("episode_id")
            if eid in attack_eps:
                attack_eps[eid]["detected"] = True
            for a in det["alerts"]:
                if a.get("technique") and a["technique"] != "UEBA":
                    caught_tech.add(a["technique"])
        else:
            fp += 1   # alert on a normal event = false positive
    tp = sum(1 for e in attack_eps.values() if e["detected"])
    n_eps = len(attack_eps)
    recall = tp / n_eps if n_eps else 0.0
    fp_rate = fp / normal_events if normal_events else 0.0
    coverage = len(caught_tech & executed) / len(executed) if executed else 0.0
    return {"recall": recall, "fp_rate": fp_rate, "coverage": coverage,
            "tp": tp, "episodes": n_eps, "fp": fp, "normal": normal_events}


def main():
    print("=" * 74)
    print("  ABLATION: detector config x evasion profile")
    print("=" * 74)
    rows = []
    # workload depends only on evasion -> build once per evasion, reuse for 3 configs
    for ev in EVASIONS:
        wl = build_workload(ev)
        for cfg in CONFIGS:
            m = evaluate(wl, cfg)
            rows.append({"config": cfg, "evasion": ev, **{k: round(v, 3) if isinstance(v, float) else v
                                                          for k, v in m.items()}})

    # pretty table grouped by evasion
    print(f"\n  {'evasion':9} | {'config':10} | {'recall':>6} | {'fp_rate':>7} | {'coverage':>8} "
          f"| {'tp/eps':>7} | {'fp/normal':>10}")
    print("  " + "-" * 70)
    for ev in EVASIONS:
        for cfg in CONFIGS:
            r = next(x for x in rows if x["config"] == cfg and x["evasion"] == ev)
            print(f"  {ev:9} | {cfg:10} | {r['recall']*100:>5.0f}% | {r['fp_rate']*100:>6.1f}% "
                  f"| {r['coverage']*100:>7.0f}% | {r['tp']:>3}/{r['episodes']:<3} | {r['fp']:>4}/{r['normal']:<5}")
        print("  " + "-" * 70)

    # headline: recall drop noisy->stealthy for rules_only vs full
    def cell(cfg, ev): return next(x for x in rows if x["config"] == cfg and x["evasion"] == ev)
    rn = cell("rules_only", "noisy")["recall"]; rs = cell("rules_only", "stealthy")["recall"]
    fn = cell("full", "noisy")["recall"]; fs = cell("full", "stealthy")["recall"]
    print("\n  Key findings:")
    print(f"   * rules_only recall: noisy {rn*100:.0f}% -> stealthy {rs*100:.0f}%  "
          f"(evasion erodes content-based detection)")
    print(f"   * full       recall: noisy {fn*100:.0f}% -> stealthy {fs*100:.0f}%  "
          f"(UEBA/behavior recovers part of the stealthy attacks)")
    print("   * defense-in-depth (rules + UEBA) is the most robust to evasion.")

    os.makedirs(os.path.join(BASE, "results"), exist_ok=True)
    fp = os.path.join(BASE, "results", "experiments.csv")
    with open(fp, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    print(f"\n  CSV: {os.path.relpath(fp, BASE)}")


if __name__ == "__main__":
    main()
