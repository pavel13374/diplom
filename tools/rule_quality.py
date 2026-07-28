#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
КАЧЕСТВО КАЖДОГО ПРАВИЛА В ОТДЕЛЬНОСТИ — рабочий инструмент detection engineering.

Зачем. Итоговая точность детектора складывается из точности отдельных правил, и
почти всегда весь шум производят два-три из них. Без разбивки по правилам это
не видно: общая precision «14%» ничего не подсказывает, а таблица ниже сразу
показывает, какое правило выбросить, какое сузить и какое трогать не надо.

Именно так и был найден главный дефект: правило mass-file-delete давало 96
срабатываний, из них ВЕРНЫХ НОЛЬ, — треть всего потока алертов приходилась на
одно сломанное условие.

Для каждого правила считается:
  сработок     — сколько раз правило подняло тревогу;
  TP / FP      — на атакующих и нормальных событиях (по разметке, постфактум);
  precision    — с доверительным интервалом Уилсона;
  вклад в шум  — какая доля ВСЕХ ложных срабатываний приходится на это правило;
  уник. эпизодов — сколько эпизодов атаки правило ловит В ОДИНОЧКУ
                   (если 0 — правило можно удалить без потери recall).

Запуск:  python tools/rule_quality.py [--seeds 1] [--evasion noisy]
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
import logging
import argparse
import collections

logging.disable(logging.CRITICAL)
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

import stats
import detector
import run_defense
from workload import build_workload

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    ap = argparse.ArgumentParser(description="Точность каждого правила по отдельности")
    ap.add_argument("--seeds", type=int, default=1)
    ap.add_argument("--evasion", default="noisy",
                    choices=["noisy", "stealthy", "adaptive"])
    args = ap.parse_args()

    hit = collections.defaultdict(lambda: {"tp": 0, "fp": 0})
    ep_by_rule = collections.defaultdict(set)     # rule -> {episode_id}
    ep_rules = collections.defaultdict(set)       # episode_id -> {rule}
    all_eps = set()

    for i in range(args.seeds):
        wl = build_workload(evasion=args.evasion, seed=42 + i * 17,
                            days=12, per_day=260)
        eng = detector.DetectionEngine()
        # Подавление дублей — часть боевого конвейера (run_defense.run).
        # Без него всплеск из 12 удалений считается как 8 отдельных тревог,
        # хотя аналитик увидит одну: измерение шума завышается в разы.
        supp = detector.Suppressor()
        for ev in wl:
            if ev.get("meta"):
                continue
            is_att = bool(ev.get("is_anomaly"))
            eid = ev.get("episode_id")
            if is_att and eid:
                all_eps.add((i, eid))
            det = eng.process(run_defense.observed(ev))
            if not det.get("alert"):
                continue
            for a in det["alerts"]:
                rid = a["rule_id"]
                if supp.is_duplicate(ev.get("actor"), rid, ev.get("ts_sim")):
                    continue
                hit[rid]["tp" if is_att else "fp"] += 1
                if is_att and eid:
                    ep_by_rule[rid].add((i, eid))
                    ep_rules[(i, eid)].add(rid)

    # эпизоды, которые ловит ТОЛЬКО одно правило
    solo = collections.Counter()
    for ep, rules in ep_rules.items():
        if len(rules) == 1:
            solo[next(iter(rules))] += 1

    total_fp = sum(v["fp"] for v in hit.values()) or 1
    rows = []
    for rid, v in hit.items():
        n = v["tp"] + v["fp"]
        prec = v["tp"] / n if n else 0.0
        lo, hi = stats.wilson(v["tp"], n) if n else (0.0, 0.0)
        rows.append({
            "rule_id": rid, "fires": n, "tp": v["tp"], "fp": v["fp"],
            "precision": round(prec, 4),
            "prec_lo": round(lo, 4), "prec_hi": round(hi, 4),
            "noise_share": round(v["fp"] / total_fp, 4),
            "episodes": len(ep_by_rule[rid]),
            "solo_episodes": solo.get(rid, 0),
        })
    rows.sort(key=lambda r: (-r["fp"], -r["fires"]))

    print("=" * 104)
    print(f"  КАЧЕСТВО ПРАВИЛ  (профиль: {args.evasion}, сидов: {args.seeds}, "
          f"эпизодов атаки: {len(all_eps)})")
    print("=" * 104)
    print(f"  {'правило':28} | {'сраб.':>6} | {'TP':>4} | {'FP':>5} | "
          f"{'precision (95% ДИ)':>22} | {'шум':>5} | {'эпиз':>5} | только он")
    print("  " + "-" * 100)
    for r in rows:
        flag = "❌" if r["precision"] < 0.05 else ("⚠ " if r["precision"] < 0.25 else "✅")
        pr = f"{r['precision']*100:.0f}% [{r['prec_lo']*100:.0f}–{r['prec_hi']*100:.0f}%]"
        print(f"  {flag}{r['rule_id']:26} | {r['fires']:>6} | {r['tp']:>4} | {r['fp']:>5} | "
              f"{pr:>22} | {r['noise_share']*100:>4.0f}% | {r['episodes']:>5} | "
              f"{r['solo_episodes']}")
    print("  " + "-" * 100)

    dead = [r["rule_id"] for r in rows if r["tp"] == 0 and r["fp"] > 0]
    useless = [r["rule_id"] for r in rows
               if r["solo_episodes"] == 0 and r["precision"] < 0.05]
    top_noise = [r for r in rows if r["noise_share"] > 0.10]
    print(f"  Всего сработок: {sum(r['fires'] for r in rows)} | "
          f"ложных: {total_fp} | правил: {len(rows)}")
    if dead:
        print(f"  ❌ НИ ОДНОГО ВЕРНОГО срабатывания: {dead}")
    if top_noise:
        print("  ⚠  Основные источники шума:")
        for r in top_noise:
            print(f"       {r['rule_id']:28} {r['noise_share']*100:>4.0f}% всего шума, "
                  f"уникальных эпизодов ловит {r['solo_episodes']}")
    if useless:
        print(f"  ⚠  Кандидаты на удаление (шумят и ничего не ловят в одиночку): {useless}")
    print("=" * 104)

    os.makedirs(os.path.join(BASE, "results"), exist_ok=True)
    fp = os.path.join(BASE, "results", "rule_quality.csv")
    with open(fp, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    print(f"  CSV: {os.path.relpath(fp, BASE)}")


if __name__ == "__main__":
    main()
