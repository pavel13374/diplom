#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ДИАГНОСТИКА СЛОЯ UEBA — какая компонента неожиданности несёт сигнал.

Зачем инструмент
----------------
Слой L1 складывает неожиданность нескольких компонент в один скор в битах:

    S(e) = Σ_k −log₂ P(x_k | actor)

Такое сложение выглядит математически безобидно («биты складываются»), но
СКРЫВАЕТ допущение: неожиданность является мерой улики лишь тогда, когда
альтернатива равномерна, то есть P(x | атака) не зависит от x. Если атака
систематически предпочитает ЧАСТЫЕ значения, знак вклада переворачивается —
компонента начинает свидетельствовать в пользу нормы, а сумма тянет скор не
туда. Со стороны это не видно: слой продолжает выдавать «биты», порог
продолжает считаться по квантилю, интерфейс продолжает показывать объяснение.

Ровно так и было: сумма из четырёх компонент давала ROC-AUC 0.451 — ХУЖЕ
СЛУЧАЙНОГО, при том что одна из компонент (час) сама по себе давала 0.577.

Что делает скрипт
-----------------
  1. Гоняет нагрузку через тот же UEBA, что и бой (detector.UEBA.components()).
  2. Меряет ROC-AUC и PR-AUC КАЖДОЙ компоненты по отдельности.
  3. Перебирает ВСЕ подмножества компонент и показывает качество суммы.
  4. Проверяет допущение о пуассоновости потока: считает Var/E счётчиков окна.
     При Var/E >> 1 (пачечный поток) хвост Пуассона переоценивает редкость
     обычной пачки, добавляя норме лишние биты.
  5. Сравнивает текущий config.UEBA_COMPONENTS с лучшим найденным подмножеством.

Скрипт НИЧЕГО не меняет — он только даёт основание для решения, какие
компоненты держать в сумме.

Запуск:
    python tools/ueba_components.py
    python tools/ueba_components.py --seeds 3 --days 14 --evasions stealthy,adaptive
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
import logging
import argparse
import itertools
import statistics
import collections

logging.disable(logging.CRITICAL)
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

import config
import detector
import run_defense
from workload import build_workload
from stats import roc_auc, pr_auc

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALL_COMPONENTS = ("repo", "action", "hour", "burst")

#: Почему для компоненты допустимо (или нет) считать альтернативу равномерной.
#: Это НЕ вывод из данных, а разбор постановки задачи — данные его лишь
#: подтверждают или опровергают.
RATIONALE = {
    "repo": "атака целится в конкретные репозитории, но не переворачивает знак",
    "action": "taxonomy.py СПЕЦИАЛЬНО уравнивает действия атаки и нормы -> "
              "P(action|атака) ≈ P(action|норма), допущение неверно",
    "hour": "атака может произойти в любой час -> равномерность защитима",
    "burst": "профили уклонения РАСТЯГИВАЮТ шаги -> атака тише нормы, "
             "допущение неверно и знак переворачивается",
}


def collect(seeds, evasions, days, per_day):
    """Компоненты неожиданности для каждого события + метка."""
    rows = []
    dispersion = collections.defaultdict(list)
    for seed in seeds:
        for ev_prof in evasions:
            wl = [r for r in build_workload(evasion=ev_prof, seed=seed,
                                            days=days, per_day=per_day)
                  if not r.get("meta")]
            eng = detector.DetectionEngine(use_ml=False)
            for r in wl:
                obs = eng.enricher.enrich(run_defense.observed(r))
                a = obs.get("actor")
                u = eng.ueba
                if a and u.actor[a]["n"] >= u.MIN_EVENTS:
                    comp, _ = u.components(obs)
                    rows.append((comp, 1 if r.get("is_anomaly") else 0))
                    # счётчик окна для проверки пуассоновости
                    t = detector._parse_ts(obs.get("ts_sim"))
                    if t is not None:
                        hi = t.timestamp(); lo = hi - u.VEL_WIN * 60
                        c = sum(1 for x in u.actor[a]["recent"]
                                if lo <= x.timestamp() <= hi) + 1
                        dispersion[a].append(c)
                # ВАЖНО: профиль обновляем через штатный путь, чтобы состояние
                # совпадало с боевым
                eng.process(run_defense.observed(r))
    return rows, dispersion


def score_subset(rows, subset):
    pos = [sum(c.get(k, 0.0) for k in subset) for c, y in rows if y == 1]
    neg = [sum(c.get(k, 0.0) for k in subset) for c, y in rows if y == 0]
    if not pos or not neg:
        return None
    return {"roc": roc_auc(pos, neg), "pr": pr_auc(pos, neg),
            "mean_pos": sum(pos) / len(pos), "mean_neg": sum(neg) / len(neg),
            "n_pos": len(pos), "n_neg": len(neg)}


def main():
    ap = argparse.ArgumentParser(description="Диагностика компонент UEBA")
    ap.add_argument("--seeds", type=int, default=2)
    ap.add_argument("--days", type=int, default=14)
    ap.add_argument("--per-day", type=int, default=300)
    ap.add_argument("--evasions", default="noisy,stealthy")
    ap.add_argument("--out", default=os.path.join("results", "ueba_components.json"))
    args = ap.parse_args()

    seeds = [1000 + i * 37 for i in range(args.seeds)]
    evasions = tuple(x.strip() for x in args.evasions.split(",") if x.strip())

    print("=" * 88)
    print("  ДИАГНОСТИКА КОМПОНЕНТ UEBA — что на самом деле несёт сигнал")
    print("=" * 88)
    print(f"  сиды {seeds}   профили {', '.join(evasions)}   "
          f"дней {args.days}   событий/день {args.per_day}")

    rows, dispersion = collect(seeds, evasions, args.days, args.per_day)
    n_pos = sum(y for _, y in rows)
    base = n_pos / max(1, len(rows))
    print(f"  событий со зрелым профилем: {len(rows)}   из них атак: {n_pos} "
          f"({base * 100:.2f}%)")
    print(f"  текущий config.UEBA_COMPONENTS = {tuple(config.UEBA_COMPONENTS)}")
    print("-" * 88)

    # ---------- 1. каждая компонента по отдельности ----------
    print("  КОМПОНЕНТЫ ПО ОТДЕЛЬНОСТИ")
    print(f"  {'компонента':10} {'ROC-AUC':>8} {'PR-AUC':>8} {'бит атака':>10} "
          f"{'бит норма':>10}  вывод")
    print("  " + "-" * 84)
    single = {}
    for k in ALL_COMPONENTS:
        s = score_subset(rows, (k,))
        if not s:
            continue
        single[k] = s
        verdict = ("несёт сигнал" if s["roc"] > 0.55 else
                   "РАБОТАЕТ ПРОТИВ" if s["roc"] < 0.45 else "не различает")
        print(f"  {k:10} {s['roc']:>8.4f} {s['pr']:>8.4f} {s['mean_pos']:>10.2f} "
              f"{s['mean_neg']:>10.2f}  {verdict}")
    print(f"  (база PR-AUC = доля класса = {base:.4f}; ROC 0.5 = слой слеп)")
    print()
    print("  Почему так — из ПОСТАНОВКИ, а не из данных:")
    for k in ALL_COMPONENTS:
        if k in single:
            print(f"    {k:8} {RATIONALE[k]}")

    # ---------- 2. все подмножества ----------
    print("-" * 88)
    print("  ВСЕ ПОДМНОЖЕСТВА (сумма компонент)")
    print(f"  {'подмножество':30} {'ROC-AUC':>9} {'PR-AUC':>9} {'x база':>7}")
    print("  " + "-" * 84)
    results = []
    avail = [k for k in ALL_COMPONENTS if k in single]
    for n in range(1, len(avail) + 1):
        for combo in itertools.combinations(avail, n):
            s = score_subset(rows, combo)
            if not s:
                continue
            results.append((combo, s))
    results.sort(key=lambda t: -t[1]["roc"])
    cur = tuple(config.UEBA_COMPONENTS)
    for combo, s in results:
        mark = "  <- текущая конфигурация" if set(combo) == set(cur) else ""
        print(f"  {'+'.join(combo):30} {s['roc']:>9.4f} {s['pr']:>9.4f} "
              f"{s['pr'] / base if base else 0:>6.2f}x{mark}")

    best_combo, best = results[0]
    cur_res = next((s for c, s in results if set(c) == set(cur)), None)
    print("  " + "-" * 84)
    print(f"  ЛУЧШЕЕ: {'+'.join(best_combo)}  ROC {best['roc']:.4f}")
    if cur_res:
        d = best["roc"] - cur_res["roc"]
        if d > 0.02:
            print(f"  [!] текущая конфигурация хуже лучшей на {d:.4f} ROC-AUC.")
            print(f"      Рассмотри UEBA_COMPONENTS = {best_combo}")
        else:
            print(f"  текущая конфигурация в пределах {d:.4f} от лучшей — менять нечего")
    full = next((s for c, s in results if set(c) == set(avail)), None)
    if full:
        print(f"  для сравнения, СУММА ВСЕХ компонент: ROC {full['roc']:.4f}"
              + ("  <- ХУЖЕ СЛУЧАЙНОГО" if full["roc"] < 0.5 else ""))

    # ---------- 3. проверка пуассоновости ----------
    print("-" * 88)
    print("  ДОПУЩЕНИЕ О ПУАССОНОВОСТИ ПОТОКА (для компоненты burst)")
    print("  У Пуассона Var = E. Если Var/E >> 1, поток пачечный (сессии), и")
    print("  хвост P(X>=c) переоценивает редкость ОБЫЧНОЙ пачки.")
    print()
    print(f"  {'актор':18} {'n':>6} {'E[c]':>7} {'Var[c]':>8} {'Var/E':>7}  вывод")
    print("  " + "-" * 84)
    allv = []
    for a, v in sorted(dispersion.items(), key=lambda kv: -len(kv[1])):
        if len(v) < 50:
            continue
        allv += v
        m = statistics.mean(v); var = statistics.pvariance(v)
        ratio = var / m if m else 0.0
        verdict = ("сверхдисперсия — Пуассон не годится" if ratio > 1.5
                   else "пуассон приемлем")
        print(f"  {a:18} {len(v):>6} {m:>7.2f} {var:>8.2f} {ratio:>7.2f}  {verdict}")
    if allv:
        m = statistics.mean(allv); var = statistics.pvariance(allv)
        print(f"  {'ПО ВСЕМ':18} {len(allv):>6} {m:>7.2f} {var:>8.2f} "
              f"{var / m if m else 0:>7.2f}")
        print()
        print("  Цена допущения (бит неожиданности для одного и того же события):")
        print(f"    {'c':>4} {'Пуассон':>10} {'эмпирика':>10}  расхождение")
        for c in (5, 10, 15, 20):
            pb = detector._surprisal(detector._poisson_sf(c, m))
            emp = sum(1 for x in allv if x >= c) / len(allv)
            eb = detector._surprisal(max(emp, 1e-12))
            print(f"    {c:>4} {pb:>9.1f}б {eb:>9.1f}б  {pb - eb:+.1f} бит")

    # ---------- сохранение ----------
    out = os.path.join(BASE, args.out) if not os.path.isabs(args.out) else args.out
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({
            "seeds": seeds, "evasions": list(evasions),
            "events": len(rows), "attack_events": n_pos, "base_rate": round(base, 5),
            "current_components": list(cur),
            "single": {k: {"roc_auc": round(v["roc"], 4), "pr_auc": round(v["pr"], 4),
                           "mean_attack": round(v["mean_pos"], 3),
                           "mean_normal": round(v["mean_neg"], 3),
                           "rationale": RATIONALE[k]}
                       for k, v in single.items()},
            "subsets": [{"components": list(c), "roc_auc": round(s["roc"], 4),
                         "pr_auc": round(s["pr"], 4)} for c, s in results],
            "best": list(best_combo),
            "dispersion_var_over_mean": (round(statistics.pvariance(allv) /
                                               statistics.mean(allv), 3)
                                         if allv and statistics.mean(allv) else None),
        }, fh, ensure_ascii=False, indent=2)
    print("=" * 88)
    print(f"  Результат: {os.path.relpath(out, BASE)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
