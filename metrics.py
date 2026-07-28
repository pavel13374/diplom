#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SOC-метрики платформы (для главы «эксперименты» диплома).

Считает по event-store + детектору:
  • Detection rate (эпизодный): доля аномальных эпизодов, где сработал детектор.
  • ATT&CK coverage: доля исполненных техник, покрытых правилами.
  • MTTD (Mean Time To Detect): среднее sim-время от первого события эпизода до
    первого алерта по нему (по актору/окну).
  • FP-rate: доля алертов, попавших на нормальные (benign) события.
  • Alerts/day: интенсивность алертов по sim-времени.

ВАЖНО про честность: detection rate и MTTD сопоставляют АЛЕРТЫ (blue, без меток) с
РАЗМЕТКОЙ (для оценки). Сам детектор меток не видит — это разбор постфактум.

Запуск:  python metrics.py [--json]
"""
import sys
import json
import argparse
import collections
from datetime import datetime

import config
import stats
import eventstore
import run_defense


def _parse(ts):
    try:
        return datetime.strptime(ts or "", "%Y-%m-%dT%H:%M:%S")
    except Exception:
        return None


def compute():
    eventstore.init()
    rows = eventstore.read_since(0, limit=10_000_000) if eventstore.enabled() else []
    if not rows:
        return None

    # прогон детектора по потоку (как делает защита)
    alerts = []                # (row, det)
    for r in rows:
        det = run_defense.process(r)
        if det.get("alert"):
            alerts.append((r, det))

    # --- эпизоды (по разметке — для оценки) ---
    episodes = collections.defaultdict(lambda: {"events": [], "techs": set(), "first": None})
    for r in rows:
        eid = r.get("episode_id")
        if not eid:
            continue
        ep = episodes[eid]
        ep["events"].append(r)
        if r.get("technique_id"):
            ep["techs"].add(r["technique_id"])
        t = _parse(r.get("ts_sim"))
        if t and (ep["first"] is None or t < ep["first"]):
            ep["first"] = t

    # детект эпизода = есть алерт по актору эпизода в окне эпизода
    alerts_by_actor = collections.defaultdict(list)
    for r, det in alerts:
        alerts_by_actor[r.get("actor")].append((_parse(r.get("ts_sim")), det["risk"]))

    detected = 0; mttd_vals = []
    for eid, ep in episodes.items():
        actor = ep["events"][0].get("actor")
        first = ep["first"]
        last = max((_parse(e.get("ts_sim")) for e in ep["events"] if _parse(e.get("ts_sim"))), default=first)
        hit = None
        for (t, risk) in alerts_by_actor.get(actor, []):
            if t and first and first <= t <= (last or first):
                hit = t if (hit is None or t < hit) else hit
        if hit is not None:
            detected += 1
            if first:
                mttd_vals.append((hit - first).total_seconds() / 60.0)

    n_ep = len(episodes)
    det_rate = detected / n_ep if n_ep else 0.0
    mttd = sum(mttd_vals) / len(mttd_vals) if mttd_vals else 0.0

    # --- ATT&CK coverage: покрытые правилами техники / ВСЯ матрица.
    #     Тот же честный знаменатель, что на странице «Покрытие» в консоли
    #     (раньше здесь было деление на «атакованные техники» — метрика
    #     всегда показывала ~100%, потому что мерила сама себя). ---
    from attack_matrix import all_techniques
    matrix = all_techniques()
    executed = set()
    for ep in episodes.values():
        executed |= ep["techs"]
    covered_rules = set(run_defense._ENGINE.techniques_covered())
    covered_in_matrix = covered_rules & matrix
    cov = len(covered_in_matrix) / len(matrix) if matrix else 0.0

    # --- FP-rate среди ДЕЙСТВЕННЫХ инцидентов (после корреляции) — то, что
    #     реально эскалируется аналитику. «Действенный» = подкреплён правилом
    #     (слой rules) ИЛИ риск >= 0.6 (medium+). Низкорисковые одиночные
    #     UEBA-срабатывания ниже порога действия и не считаются ложными
    #     тревогами, которые SOC «гоняет». Инцидент ложный, если его окно не
    #     пересекается ни с одним размеченным эпизодом атаки того же актора.
    #     (Раньше FP считался по всем сырым детектам и полз к ~75%, потом по
    #     всем инцидентам — но большинство инцидентов это доброкачественный
    #     поведенческий шум, не доходящий до эскалации.) ---
    import correlator
    cor = correlator.Correlator()
    for r, det in alerts:
        cor.add(r, det)
    incidents = list(cor.incidents.values())

    def _actionable(inc):
        if inc.get("max_risk", 0) >= 0.6:
            return True
        return any(a.get("layer") == "rules" for a in inc.get("alerts", []))

    ep_windows = collections.defaultdict(list)
    for ep in episodes.values():
        a = ep["events"][0].get("actor")
        f = ep["first"]
        lst = [_parse(e.get("ts_sim")) for e in ep["events"]]
        l = max([t for t in lst if t], default=f)
        if f:
            ep_windows[a].append((f, l or f))
    actionable = [inc for inc in incidents if _actionable(inc)]
    inc_fp = 0
    for inc in actionable:
        a = inc.get("actor")
        s = _parse(inc.get("start_ts")); e = _parse(inc.get("last_ts")) or s
        tp = any(s and wf and s <= wl and (e or s) >= wf
                 for (wf, wl) in ep_windows.get(a, []))
        if not tp:
            inc_fp += 1
    fp_rate = inc_fp / len(actionable) if actionable else 0.0
    # для обратной совместимости оставляем и сырой счётчик
    fp = sum(1 for r, _ in alerts if not r.get("is_anomaly"))

    # --- alerts/day (sim) ---
    times = [_parse(r.get("ts_sim")) for r, _ in alerts]
    times = [t for t in times if t]
    span_days = ((max(times) - min(times)).total_seconds() / 86400.0) if len(times) > 1 else 1.0
    per_day = len(alerts) / max(span_days, 1e-6)

    # --- статистика: интервалы вместо точечных оценок ---
    # Detection rate 74.5% на 55 эпизодах — это на самом деле «где-то между 61 и
    # 85%». Без интервала такая цифра создаёт ложную точность, и это первое,
    # к чему придирается рецензент.
    dr_lo, dr_hi = stats.wilson(detected, n_ep) if n_ep else (0.0, 0.0)
    fp_lo, fp_hi = (stats.wilson(inc_fp, len(actionable)) if actionable else (0.0, 0.0))
    prec_tp = sum(1 for r, _ in alerts if r.get("is_anomaly"))
    prec_lo, prec_hi = stats.wilson(prec_tp, len(alerts)) if alerts else (0.0, 0.0)
    mttd_lo, mttd_hi = stats.bootstrap_ci(mttd_vals) if len(mttd_vals) > 2 else (mttd, mttd)

    # --- PR-AUC по риску алертов: интегральное качество без привязки к порогу.
    #     Именно PR, а не ROC: доля атакующих событий здесь порядка процента, и
    #     при таком дисбалансе ROC-AUC выглядит отлично даже у слабого
    #     детектора (знаменатель FPR — огромное число нормальных событий). ---
    risk_pos, risk_neg = [], []
    for r in rows:
        det = run_defense.process(r)
        s = det.get("risk", 0.0)
        (risk_pos if r.get("is_anomaly") else risk_neg).append(s)
    pr = stats.pr_auc(risk_pos, risk_neg)
    roc = stats.roc_auc(risk_pos, risk_neg)
    pr_base = stats.baseline_pr(len(risk_pos), len(risk_neg))

    return {
        "events": len(rows), "anomaly_episodes": n_ep, "alerts": len(alerts),
        "detection_rate": round(det_rate, 3), "detected_episodes": detected,
        "attack_coverage": round(cov, 3),
        "mttd_sim_min": round(mttd, 1),
        "mttd_ci": [round(mttd_lo, 1), round(mttd_hi, 1)],
        "fp_rate": round(fp_rate, 3), "fp_incidents": inc_fp,
        "fp_rate_ci": [round(fp_lo, 3), round(fp_hi, 3)],
        "incidents": len(incidents), "actionable_incidents": len(actionable),
        "fp_alerts": fp,
        "precision": round(prec_tp / len(alerts), 3) if alerts else 0.0,
        "precision_ci": [round(prec_lo, 3), round(prec_hi, 3)],
        "detection_rate_ci": [round(dr_lo, 3), round(dr_hi, 3)],
        "pr_auc": round(pr, 3), "pr_baseline": round(pr_base, 4),
        "roc_auc": round(roc, 3),
        "alerts_per_sim_day": round(per_day, 1),
        "techniques_executed": len(executed),
        "techniques_in_matrix": len(matrix),
        "techniques_covered": len(covered_in_matrix),
    }


def main():
    ap = argparse.ArgumentParser(description="SOC metrics")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    m = compute()
    if not m:
        print("[!] Нет событий в event-store (запусти мир)."); sys.exit(1)
    if args.json:
        print(json.dumps(m, ensure_ascii=False, indent=2)); return
    def ci(key):
        lo, hi = m[key]
        return f"[{lo*100:.0f}–{hi*100:.0f}%]"

    print("=" * 68)
    print("SOC METRICS (эпизодная оценка по event-store)")
    print("=" * 68)
    print(f"  событий:                 {m['events']}")
    print(f"  аномальных эпизодов:     {m['anomaly_episodes']}")
    print(f"  алертов всего:           {m['alerts']}")
    print("-" * 68)
    print(f"  Detection rate:          {m['detection_rate']*100:.1f}% {ci('detection_rate_ci')}  "
          f"({m['detected_episodes']}/{m['anomaly_episodes']})")
    print(f"  Precision (события):     {m['precision']*100:.1f}% {ci('precision_ci')}")
    print(f"  ATT&CK coverage:         {m['attack_coverage']*100:.1f}%  "
          f"({m['techniques_covered']}/{m['techniques_in_matrix']} техник матрицы)")
    print(f"  MTTD (sim-минуты):       {m['mttd_sim_min']} "
          f"[{m['mttd_ci'][0]}–{m['mttd_ci'][1]}]")
    print(f"  FP-rate (действ. инц.):  {m['fp_rate']*100:.1f}% {ci('fp_rate_ci')}  "
          f"({m['fp_incidents']}/{m['actionable_incidents']} действенных инц.)")
    print(f"  Alerts / sim-день:       {m['alerts_per_sim_day']}")
    print("-" * 68)
    print(f"  PR-AUC:                  {m['pr_auc']:.3f}  "
          f"(база при этом дисбалансе: {m['pr_baseline']:.4f})")
    print(f"  ROC-AUC:                 {m['roc_auc']:.3f}  "
          "— смотреть на PR, а не сюда: при доле атак "
          f"{m['pr_baseline']*100:.1f}% ROC льстит детектору")
    print("=" * 68)
    print("  Интервалы — Уилсон 95% (для MTTD — bootstrap). Точечная оценка без")
    print("  интервала создаёт ложную точность: 74.5% на 55 эпизодах это 61–85%.")


if __name__ == "__main__":
    main()
