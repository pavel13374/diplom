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

    # --- ATT&CK coverage ---
    executed = set()
    for ep in episodes.values():
        executed |= ep["techs"]
    covered_rules = set(run_defense._ENGINE.techniques_covered())
    cov = len(executed & covered_rules) / len(executed) if executed else 0.0

    # --- FP-rate (алерты на нормальных событиях) ---
    fp = sum(1 for r, _ in alerts if not r.get("is_anomaly"))
    fp_rate = fp / len(alerts) if alerts else 0.0

    # --- alerts/day (sim) ---
    times = [_parse(r.get("ts_sim")) for r, _ in alerts]
    times = [t for t in times if t]
    span_days = ((max(times) - min(times)).total_seconds() / 86400.0) if len(times) > 1 else 1.0
    per_day = len(alerts) / max(span_days, 1e-6)

    return {
        "events": len(rows), "anomaly_episodes": n_ep, "alerts": len(alerts),
        "detection_rate": round(det_rate, 3), "detected_episodes": detected,
        "attack_coverage": round(cov, 3),
        "mttd_sim_min": round(mttd, 1),
        "fp_rate": round(fp_rate, 3), "fp_alerts": fp,
        "alerts_per_sim_day": round(per_day, 1),
        "techniques_executed": len(executed), "techniques_covered": len(executed & covered_rules),
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
    print("=" * 54)
    print("SOC METRICS (эпизодная оценка по event-store)")
    print("=" * 54)
    print(f"  событий:                 {m['events']}")
    print(f"  аномальных эпизодов:     {m['anomaly_episodes']}")
    print(f"  алертов всего:           {m['alerts']}")
    print("-" * 54)
    print(f"  Detection rate:          {m['detection_rate']*100:.1f}%  "
          f"({m['detected_episodes']}/{m['anomaly_episodes']})")
    print(f"  ATT&CK coverage:         {m['attack_coverage']*100:.1f}%  "
          f"({m['techniques_covered']}/{m['techniques_executed']} техник)")
    print(f"  MTTD (sim-минуты):       {m['mttd_sim_min']}")
    print(f"  FP-rate:                 {m['fp_rate']*100:.1f}%  ({m['fp_alerts']} алертов)")
    print(f"  Alerts / sim-день:       {m['alerts_per_sim_day']}")
    print("=" * 54)


if __name__ == "__main__":
    main()
