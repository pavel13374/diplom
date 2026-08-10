#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
КРИВАЯ «ПОЛНОТА ПРОТИВ НАГРУЗКИ НА АНАЛИТИКА».

Зачем не ROC
------------
ROC-кривая рисует recall против доли ложных срабатываний. Для SOC это неудобная
ось: «FPR 2%» ничего не говорит человеку, которому эти срабатывания разбирать.
Двухпроцентный FPR на потоке в 20 тысяч событий — это 400 тревог, то есть
несколько рабочих дней; на потоке в 200 событий — четыре штуки. Одна и та же
точка кривой означает совершенно разную нагрузку.

Осмысленная ось для SOC — ИНЦИДЕНТОВ В ДЕНЬ, которые доходят до очереди. Она
имеет прямой смысл («столько аналитик разберёт»), не зависит от объёма потока
и позволяет выбирать рабочую точку по ёмкости смены, а не по красоте метрики.

Что считает скрипт
------------------
Для набора порогов действия строит:
  • эпизодный recall с интервалом Уилсона — доля атак, дошедших до очереди;
  • инцидентов в симулированный день — собственно нагрузка;
  • precision инцидентов — какая доля очереди окажется ложной;
  • MTTD среди пойманных.

Оценка ведётся НА УРОВНЕ ИНЦИДЕНТА (корреляция + слияние по слоям), потому что
именно инцидент — единица работы аналитика. Пособытийная оценка завысила бы
нагрузку в разы: один инцидент состоит из нескольких алертов.

Результат: таблица, SVG-график в results/ и JSON. Рабочая точка текущей
конфигурации (config.FUSION_* и порог 0.6 из metrics.py) отмечена на графике.

Запуск:
    python research/workload_curve.py
    python research/workload_curve.py --seeds 3 --days 21 --capacity 12
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
import datetime

logging.disable(logging.CRITICAL)
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

import detector
import correlator
import run_defense
from workload import build_workload
from stats import wilson

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: Пороги действия, по которым строится кривая.
THRESHOLDS = [0.20, 0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90, 0.95]

#: Рабочая точка из metrics.py — «действенный инцидент».
CURRENT_THRESHOLD = 0.6


def collect(seeds, evasions, days, per_day):
    """Один прогон детектора; для каждого инцидента запоминаем всё нужное.

    Детектор гоняется ОДИН РАЗ, а пороги применяются к сохранённым рискам.
    Прогонять заново на каждый порог нельзя: детектор потоковый и с
    состоянием, второй проход по тем же данным даёт другие профили UEBA
    (ровно эта ошибка была в metrics.py).
    """
    incidents = []      # {risk, tp, start, ep_ids}
    ep_first = {}       # (run, episode) -> первое время события эпизода
    ep_all = set()
    span_days = 0.0

    for seed in seeds:
        for ev_prof in evasions:
            wl = [r for r in build_workload(evasion=ev_prof, seed=seed,
                                            days=days, per_day=per_day)
                  if not r.get("meta")]
            run_key = f"s{seed}:{ev_prof}"
            eng = detector.DetectionEngine()
            cor = correlator.Correlator()
            times = []
            # эпизоды и их начало
            for r in wl:
                if r.get("is_anomaly") and r.get("episode_id"):
                    k = (run_key, r["episode_id"])
                    ep_all.add(k)
                    t = _ts(r.get("ts_sim"))
                    if t and (k not in ep_first or t < ep_first[k]):
                        ep_first[k] = t
            # прогон
            inc_eps = {}
            for r in wl:
                obs = run_defense.observed(r)
                det = eng.process(obs)
                if r.get("ts_sim"):
                    times.append(r["ts_sim"])
                if not det.get("alert"):
                    continue
                iid = cor.add(obs, det)
                key = (run_key, iid)
                d = inc_eps.setdefault(key, {"eps": set(), "first_hit": {}})
                if r.get("is_anomaly") and r.get("episode_id"):
                    ek = (run_key, r["episode_id"])
                    d["eps"].add(ek)
                    t = _ts(r.get("ts_sim"))
                    if t and (ek not in d["first_hit"] or t < d["first_hit"][ek]):
                        d["first_hit"][ek] = t
            for (rk, iid), d in inc_eps.items():
                inc = cor.incidents[iid]
                incidents.append({
                    "risk": inc.get("risk", inc.get("max_risk", 0.0)),
                    "eps": d["eps"],
                    "first_hit": d["first_hit"],
                })
            span_days += _span(times)
    return incidents, ep_all, ep_first, max(span_days, 1.0 / 24)


#: Сколько меток времени не разобралось за прогон. Ноль ожидаем; всё, что
#: больше, означает несовместимую схему события и молча искажает и MTTD, и
#: знаменатель нагрузки.
_TS_BAD = {"n": 0, "sample": None}


def _ts(s):
    try:
        return datetime.datetime.strptime(s or "", "%Y-%m-%dT%H:%M:%S")
    except Exception:
        _TS_BAD["n"] += 1
        if _TS_BAD["sample"] is None:
            _TS_BAD["sample"] = repr(s)[:60]
        return None


def _span(ts_list):
    ok = [t for t in (_ts(x) for x in ts_list) if t]
    if len(ok) < 2:
        return 1.0
    return max((max(ok) - min(ok)).total_seconds() / 86400.0, 1.0 / 24)


def evaluate(incidents, ep_all, ep_first, span_days, thr):
    """Метрики очереди при заданном пороге действия."""
    queue = [i for i in incidents if i["risk"] >= thr]
    caught, mttd = set(), []
    tp = 0
    for i in queue:
        if i["eps"]:
            tp += 1
            for ek in i["eps"]:
                caught.add(ek)
                t0, t1 = ep_first.get(ek), i["first_hit"].get(ek)
                if t0 and t1:
                    mttd.append((t1 - t0).total_seconds() / 60.0)
    total = len(ep_all)
    lo, hi = wilson(len(caught), total)
    return {
        "threshold": thr,
        "incidents": len(queue),
        "per_day": len(queue) / span_days,
        "precision": tp / len(queue) if queue else 0.0,
        "recall": len(caught) / total if total else 0.0,
        "recall_ci": [lo, hi],
        "caught": len(caught), "episodes": total,
        "mttd_min": (sum(mttd) / len(mttd)) if mttd else None,
        "mttd_median_min": (sorted(mttd)[len(mttd) // 2] if mttd else None),
        "mttd_n": len(mttd),
    }


# ----------------------------------------------------------------------
def svg(points, capacity, out_path):
    """График recall(нагрузка) с интервалами и линией ёмкости смены."""
    W, H = 760, 460
    ml, mr, mt, mb = 70, 30, 40, 66
    pw, ph = W - ml - mr, H - mt - mb
    xs = [p["per_day"] for p in points]
    xmax = max(max(xs), capacity) * 1.12 or 1.0

    def X(v):
        return ml + pw * (v / xmax)

    def Y(v):
        return mt + ph * (1.0 - v)

    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" '
             f'width="{W}" height="{H}" font-family="system-ui,Segoe UI,sans-serif">',
             f'<rect width="{W}" height="{H}" fill="#ffffff"/>']
    # сетка
    for i in range(6):
        y = Y(i / 5.0)
        parts.append(f'<line x1="{ml}" y1="{y:.1f}" x2="{ml + pw}" y2="{y:.1f}" '
                     f'stroke="#e8e8ef" stroke-width="1"/>')
        parts.append(f'<text x="{ml - 10}" y="{y + 4:.1f}" font-size="11" '
                     f'fill="#6b7280" text-anchor="end">{int(i * 20)}%</text>')
    for i in range(6):
        v = xmax * i / 5.0
        x = X(v)
        parts.append(f'<line x1="{x:.1f}" y1="{mt}" x2="{x:.1f}" y2="{mt + ph}" '
                     f'stroke="#f2f2f7" stroke-width="1"/>')
        parts.append(f'<text x="{x:.1f}" y="{mt + ph + 18}" font-size="11" '
                     f'fill="#6b7280" text-anchor="middle">{v:.0f}</text>')
    # ёмкость смены
    xc = X(capacity)
    parts.append(f'<line x1="{xc:.1f}" y1="{mt}" x2="{xc:.1f}" y2="{mt + ph}" '
                 f'stroke="#dc2626" stroke-width="2" stroke-dasharray="6 4"/>')
    parts.append(f'<text x="{xc + 6:.1f}" y="{mt + 14}" font-size="11" fill="#dc2626">'
                 f'ёмкость смены: {capacity:g} инц./день</text>')
    # доверительная лента
    band_up = " ".join(f"{X(p['per_day']):.1f},{Y(p['recall_ci'][1]):.1f}" for p in points)
    band_dn = " ".join(f"{X(p['per_day']):.1f},{Y(p['recall_ci'][0]):.1f}"
                       for p in reversed(points))
    parts.append(f'<polygon points="{band_up} {band_dn}" fill="#6d28d9" opacity="0.13"/>')
    # кривая
    line = " ".join(f"{X(p['per_day']):.1f},{Y(p['recall']):.1f}" for p in points)
    parts.append(f'<polyline points="{line}" fill="none" stroke="#6d28d9" stroke-width="2.5"/>')
    for p in points:
        x, y = X(p["per_day"]), Y(p["recall"])
        cur = abs(p["threshold"] - CURRENT_THRESHOLD) < 1e-9
        parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{6 if cur else 4}" '
                     f'fill="{"#dc2626" if cur else "#6d28d9"}"/>')
        parts.append(f'<text x="{x:.1f}" y="{y - 11:.1f}" font-size="10" '
                     f'fill="#374151" text-anchor="middle">{p["threshold"]:.2f}</text>')
        if cur:
            parts.append(f'<text x="{x:.1f}" y="{y + 20:.1f}" font-size="11" '
                         f'font-weight="700" fill="#dc2626" text-anchor="middle">'
                         f'рабочая точка</text>')
    parts.append(f'<text x="{ml}" y="24" font-size="14" font-weight="700" fill="#111827">'
                 f'Полнота обнаружения против нагрузки на аналитика</text>')
    parts.append(f'<text x="{ml + pw / 2:.0f}" y="{H - 26}" font-size="12" '
                 f'fill="#374151" text-anchor="middle">инцидентов в очереди за '
                 f'симулированный день</text>')
    parts.append(f'<text x="18" y="{mt + ph / 2:.0f}" font-size="12" fill="#374151" '
                 f'text-anchor="middle" transform="rotate(-90 18 {mt + ph / 2:.0f})">'
                 f'эпизодный recall</text>')
    parts.append(f'<text x="{ml}" y="{H - 8}" font-size="10" fill="#6b7280">'
                 f'подписи у точек — порог действия; лента — 95% интервал Уилсона</text>')
    parts.append("</svg>")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(parts))


# ----------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Кривая полнота/нагрузка")
    ap.add_argument("--seeds", type=int, default=2)
    ap.add_argument("--days", type=int, default=14)
    ap.add_argument("--per-day", type=int, default=300)
    ap.add_argument("--evasions", default="noisy,stealthy")
    ap.add_argument("--capacity", type=float, default=10.0,
                    help="сколько инцидентов в день разбирает смена")
    ap.add_argument("--out", default=os.path.join("results", "workload_curve"))
    args = ap.parse_args()

    seeds = [1000 + i * 37 for i in range(args.seeds)]
    evasions = tuple(x.strip() for x in args.evasions.split(",") if x.strip())

    print("=" * 92)
    print("  ПОЛНОТА ПРОТИВ НАГРУЗКИ НА АНАЛИТИКА")
    print("=" * 92)
    print(f"  сиды {seeds}  профили {', '.join(evasions)}  дней {args.days}")
    print(f"  ёмкость смены: {args.capacity:g} инцидентов в день")
    print("  оценка НА УРОВНЕ ИНЦИДЕНТА — это единица работы аналитика,")
    print("  пособытийная оценка завысила бы нагрузку в разы.")
    print("-" * 92)

    incidents, ep_all, ep_first, span = collect(seeds, evasions, args.days, args.per_day)
    print(f"  инцидентов всего: {len(incidents)}   эпизодов атак: {len(ep_all)}   "
          f"sim-дней: {span:.1f}")
    print("-" * 92)

    points = [evaluate(incidents, ep_all, ep_first, span, t) for t in THRESHOLDS]

    print(f"  {'порог':>6} {'инц/день':>9} {'очередь':>8} {'precision':>10} "
          f"{'эпизодный recall':>22} {'MTTD мед.':>10}")
    print("  " + "-" * 88)
    for p in points:
        mark = "  <- текущая" if abs(p["threshold"] - CURRENT_THRESHOLD) < 1e-9 else ""
        over = "  !" if p["per_day"] > args.capacity else ""
        mttd = (f"{p['mttd_median_min']:.1f}" if p["mttd_median_min"] is not None
                else "—")
        print(f"  {p['threshold']:>6.2f} {p['per_day']:>9.1f}{over:<3}{p['incidents']:>6} "
              f"{p['precision'] * 100:>9.1f}% "
              f"{p['caught']:>4}/{p['episodes']:<4} = {p['recall'] * 100:>3.0f}% "
              f"[{p['recall_ci'][0] * 100:.0f}–{p['recall_ci'][1] * 100:.0f}%] "
              f"{mttd:>10}{mark}")
    print("  " + "-" * 88)
    print("  «!» — очередь превышает ёмкость смены: часть инцидентов не будет разобрана,")
    print("  и фактическая полнота окажется НИЖЕ расчётной.")

    # ---------------- рекомендация ----------------
    #
    # Критерий выбора двухступенчатый и в этом порядке:
    #   1) максимальная полнота среди укладывающихся в ёмкость смены;
    #   2) при РАВНОЙ полноте — минимальная нагрузка.
    #
    # Второй пункт обязателен. Кривая почти всегда имеет плато: полнота уже не
    # растёт, а очередь продолжает пухнуть. Без учёта нагрузки правило выбрало
    # бы самый левый порог этого плато и посоветовало бы «опустить порог, +0
    # п.п. полноты» — то есть удвоить работу аналитика ни за что.
    print()
    fit = [p for p in points if p["per_day"] <= args.capacity]
    if not fit:
        print(f"  [!] Ни один порог не укладывается в {args.capacity:g} инц./день.")
        print("      Нужно либо чинить точность слоёв, либо расширять смену.")
    else:
        top = max(p["recall"] for p in fit)
        # плато: те же эпизоды ловятся, нагрузка разная
        plateau = [p for p in fit if p["recall"] >= top - 1e-9]
        best = min(plateau, key=lambda p: p["per_day"])
        cur = next((p for p in points
                    if abs(p["threshold"] - CURRENT_THRESHOLD) < 1e-9), None)
        print(f"  ПРИ ЁМКОСТИ {args.capacity:g} инц./день максимум полноты: "
              f"{top * 100:.0f}%")
        if len(plateau) > 1:
            print(f"  Он достигается на плато порогов "
                  f"{min(p['threshold'] for p in plateau):.2f}–"
                  f"{max(p['threshold'] for p in plateau):.2f}: полнота одинаковая, "
                  f"нагрузка отличается в "
                  f"{max(p['per_day'] for p in plateau) / max(best['per_day'], 1e-9):.1f} раза.")
        print(f"  РЕКОМЕНДУЕМЫЙ порог: {best['threshold']:.2f} — "
              f"{best['per_day']:.1f} инц./день, precision {best['precision'] * 100:.1f}%")
        if cur:
            if cur["per_day"] > args.capacity:
                print(f"  Текущий порог {CURRENT_THRESHOLD} даёт {cur['per_day']:.1f} "
                      f"инц./день — СМЕНА НЕ СПРАВИТСЯ.")
            elif best["threshold"] > CURRENT_THRESHOLD + 1e-9:
                dl = cur["per_day"] - best["per_day"]
                dr = (cur["recall"] - best["recall"]) * 100
                dp = (best["precision"] - cur["precision"]) * 100
                print(f"  Текущий порог {CURRENT_THRESHOLD} можно ПОДНЯТЬ до "
                      f"{best['threshold']:.2f}: очередь −{dl:.1f} инц./день "
                      f"({dl / max(cur['per_day'], 1e-9) * 100:.0f}%), "
                      f"precision +{dp:.1f} п.п., полнота "
                      f"{'без потерь' if abs(dr) < 0.5 else f'−{dr:.0f} п.п.'}")
            elif best["threshold"] < CURRENT_THRESHOLD - 1e-9:
                dr = (best["recall"] - cur["recall"]) * 100
                print(f"  Текущий порог можно ОПУСТИТЬ до {best['threshold']:.2f}: "
                      f"+{dr:.0f} п.п. полноты в пределах ёмкости.")
            else:
                print(f"  Текущий порог {CURRENT_THRESHOLD} — разумная точка "
                      f"для этой ёмкости.")

    out_base = os.path.join(BASE, args.out) if not os.path.isabs(args.out) else args.out
    os.makedirs(os.path.dirname(out_base), exist_ok=True)
    svg(points, args.capacity, out_base + ".svg")
    with open(out_base + ".json", "w", encoding="utf-8") as f:
        json.dump({"seeds": seeds, "evasions": list(evasions),
                   "days": args.days, "per_day_events": args.per_day,
                   "capacity": args.capacity, "sim_days": round(span, 2),
                   "episodes": len(ep_all), "incidents_total": len(incidents),
                   "points": points}, f, ensure_ascii=False, indent=2)
    print("=" * 92)
    print(f"  График:  {os.path.relpath(out_base + '.svg', BASE)}")
    print(f"  Данные:  {os.path.relpath(out_base + '.json', BASE)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
