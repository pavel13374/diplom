#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PER-LAYER АТРИБУЦИЯ под уклонением — кто на самом деле ловит атаку.

Третий аргумент: при stealthy секрет «спрятан» (benign-путь + обфускация), и
сигнатурный слой L0 (правила/regex) по решающему шагу СЛЕП. Тогда recall тянет
только поведенческий слой L1 (UEBA). Считаем по эпизодам, каким слоем поймано:
  только L0 (правила) | только L1 (поведение) | оба | не поймано.

Показывает числом, что под уклонением вклад поведения становится решающим — то,
что сигнатурой не закрыть в принципе.

Запуск:  python experiments_layers.py   ->  results/layers.csv
Без GitLab (FakeGL), без ML, воспроизводимо (SEED).
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

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

import run_defense
import detector
from experiments import build_workload

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVASIONS = ["noisy", "stealthy", "adaptive"]


def attribute(events_list):
    """Свежий движок: СТРОГО по эпизоду — какой слой поймал именно его события.
    (Без подхвата по актору, чтобы фоновые L0-сработки не красили эпизод.)"""
    eng = detector.DetectionEngine()
    eps = {}
    for ev in events_list:
        if ev.get("meta"):
            continue
        det = eng.process(run_defense.observed(ev))      # порядок важен: UEBA учится на потоке
        eid = ev.get("episode_id")
        if ev.get("is_anomaly") and eid:
            e = eps.setdefault(eid, {"actor": ev.get("actor"), "rules": False, "ueba": False})
            if det.get("alert"):
                layers = {a.get("layer") for a in det["alerts"]}
                if "rules" in layers: e["rules"] = True
                if "ueba" in layers:  e["ueba"] = True
    return eps


def main():
    print("=" * 76)
    print("  PER-LAYER АТРИБУЦИЯ: кто ловит атаку под уклонением")
    print("=" * 76)
    print(f"  {'evasion':9} | {'эпизодов':>8} | {'recall':>6} | {'только L0':>9} | {'только L1':>9} | {'оба':>5} | {'упущено':>7}")
    print("-" * 76)
    rows = []
    for ev in EVASIONS:
        wl = build_workload(ev)
        eps = attribute(wl)
        n = len(eps)
        only_rules = sum(e["rules"] and not e["ueba"] for e in eps.values())
        only_ueba = sum(e["ueba"] and not e["rules"] for e in eps.values())
        both = sum(e["rules"] and e["ueba"] for e in eps.values())
        caught = sum(e["rules"] or e["ueba"] for e in eps.values())
        missed = n - caught
        recall = caught / n if n else 0.0
        print(f"  {ev:9} | {n:>8} | {recall*100:>5.0f}% | {only_rules:>9} | {only_ueba:>9} | {both:>5} | {missed:>7}")
        rows.append({"evasion": ev, "episodes": n, "recall": round(recall, 3),
                     "only_rules": only_rules, "only_behavior": only_ueba,
                     "both": both, "missed": missed})
    print("-" * 76)
    noisy = next(r for r in rows if r["evasion"] == "noisy")
    stealth = next(r for r in rows if r["evasion"] == "stealthy")

    def share_behavior(r):
        caught = r["only_rules"] + r["only_behavior"] + r["both"]
        return (r["only_behavior"] / caught) if caught else 0.0
    print(f"  Доля пойманных ТОЛЬКО поведением:  noisy {share_behavior(noisy)*100:.0f}%  ->  "
          f"stealthy {share_behavior(stealth)*100:.0f}%")
    print("=" * 76)
    print("  ВЫВОД: под stealthy сигнатурный слой по секрету слепнет, и решающий вклад")
    print("  в recall даёт ПОВЕДЕНЧЕСКИЙ слой (UEBA) — то, что регуляркой не покрыть.")

    os.makedirs(os.path.join(BASE, "results"), exist_ok=True)
    fp = os.path.join(BASE, "results", "layers.csv")
    with open(fp, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    print(f"  CSV: {os.path.relpath(fp, BASE)}")


if __name__ == "__main__":
    main()
