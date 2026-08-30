#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Detection-as-Code self-improvement (EPIC 5).

Purple-team debrief: сравнивает, какие техники ATT&CK РЕАЛЬНО исполнял red
(по разметке мира — это легитимно для разбора, ведь мы знаем свои атаки) с тем,
что ПОКРЫВАЮТ детект-правила. Находит «слепые зоны» (техника исполнена, но
правила нет) и авто-черновит новое detection-правило в detections/proposed/.

ВАЖНО: разметку здесь использует ТОЛЬКО анализ покрытия (debrief), а НЕ детектор.
Детектор (detector.py) меток мира не видит — это разные вещи.

Запуск:
    python detection_gaps.py                 # отчёт по слепым зонам
    python detection_gaps.py --propose       # + записать черновики правил
"""
import os
import sys
import json
import glob
import argparse
import collections

BASE = os.path.dirname(os.path.abspath(__file__))


def load_events():
    """Читаем события: предпочтительно из event-store, иначе из jsonl."""
    rows = []
    try:
        import eventstore
        eventstore.init()
        if eventstore.enabled():
            rows = eventstore.read_since(0, limit=10_000_000, include_meta=False)
    except Exception:
        rows = []
    if not rows:
        fp = os.path.join(BASE, "data", "events.jsonl")
        if os.path.exists(fp):
            for line in open(fp, encoding="utf-8"):
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                    if not (r.get("meta") or r.get("action") in ("anomaly", "activity")):
                        rows.append(r)
                except json.JSONDecodeError:
                    pass
    return rows


def covered_techniques():
    techs = set()
    for fp in glob.glob(os.path.join(BASE, "detections", "*.json")):
        try:
            with open(fp, encoding="utf-8") as fh:
                techs.add(json.load(fh).get("technique"))
        except Exception:
            pass
    techs.discard(None)
    return techs


def draft_rule(technique, decisive_ev, family):
    """Эвристический черновик правила по decisive-событию слепой зоны."""
    when = {"action": decisive_ev.get("action", "push")}
    if decisive_ev.get("n_real_hits") or decisive_ev.get("n_regex_hits"):
        # n_real_hits, а не n_regex_hits + placeholder_signal: последняя пара
        # выключалась одним словом «TODO» где угодно в файле, потому что
        # placeholder_signal считался по файлу целиком. Черновик правила не
        # должен воспроизводить уже исправленный дефект.
        when["n_real_hits"] = {">=": 1}
    elif decisive_ev.get("project") == "soc-secrets":
        when = {"project": "soc-secrets", "action": {"in": ["push", "branch_create", "mr_merge"]}}
    elif decisive_ev.get("path"):
        # берём узнаваемый кусок пути
        p = decisive_ev["path"]
        token = p.split("/")[0] if "/" in p else p
        when["path"] = {"contains": token}
    return {
        "id": f"proposed-{technique.lower().replace('.', '-')}",
        "title": f"[PROPOSED] Detection for {technique} ({family})",
        "technique": technique, "tactic": family,
        "severity": "high", "risk": 0.6,
        "when": when,
        "_note": "авто-черновик по слепой зоне; требует ревью аналитика",
    }


def main():
    ap = argparse.ArgumentParser(description="Detection coverage gaps + rule proposals")
    ap.add_argument("--propose", action="store_true", help="записать черновики в detections/proposed/")
    args = ap.parse_args()

    rows = load_events()
    if not rows:
        print("[!] Нет событий (запусти мир, чтобы накопить поток).")
        sys.exit(1)

    # техники, реально исполненные red (по разметке — debrief)
    executed = collections.Counter()
    decisive_by_tech = {}
    fam_by_tech = {}
    for r in rows:
        if r.get("is_anomaly") and r.get("technique_id"):
            t = r["technique_id"]
            executed[t] += 1
            fam_by_tech[t] = r.get("tactic") or r.get("family") or "?"
            if r.get("is_decisive") and t not in decisive_by_tech:
                decisive_by_tech[t] = r

    covered = covered_techniques()
    executed_set = set(executed)
    gaps = sorted(executed_set - covered)
    caught = sorted(executed_set & covered)

    print("=" * 64)
    print("DETECTION COVERAGE DEBRIEF (purple-team)")
    print("=" * 64)
    print(f"Техник исполнено red: {len(executed_set)} | покрыто правилами: {len(caught)} "
          f"| слепых зон: {len(gaps)}")
    cov = round(len(caught) / max(1, len(executed_set)) * 100)
    print(f"Покрытие по исполненным техникам: {cov}%")
    print("-" * 64)
    if caught:
        print("Покрыто (есть правило):")
        for t in caught:
            print(f"  ✅ {t:12} ({fam_by_tech.get(t,'?')}) · исполнено {executed[t]}")
    if gaps:
        print("\nСЛЕПЫЕ ЗОНЫ (исполнено, но нет правила) — кандидаты на новое правило:")
        for t in gaps:
            print(f"  ❌ {t:12} ({fam_by_tech.get(t,'?')}) · исполнено {executed[t]}")
    else:
        print("\nСлепых зон нет — все исполненные техники покрыты правилами.")

    if args.propose and gaps:
        outdir = os.path.join(BASE, "detections", "proposed")
        os.makedirs(outdir, exist_ok=True)
        n = 0
        for t in gaps:
            ev = decisive_by_tech.get(t) or {"action": "push"}
            rule = draft_rule(t, ev, fam_by_tech.get(t, "?"))
            json.dump(rule, open(os.path.join(outdir, rule["id"] + ".json"), "w", encoding="utf-8"),
                      ensure_ascii=False, indent=2)
            n += 1
        print(f"\nЗаписано черновиков правил: {n} → detections/proposed/")
        print("Проверь их и перенеси валидные в detections/ (тогда покрытие вырастет).")


if __name__ == "__main__":
    main()
