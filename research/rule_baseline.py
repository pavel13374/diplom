#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Rule-based baseline с ЧЕСТНОЙ оценкой на уровне ЭПИЗОДА (а не события).

Почему эпизод: одна аномалия = цепочка событий (branch→push→mr→merge), и в
изоляции branch_create секретного эпизода неотличим от нормального. Поэтому:
  • событийный recall занижен (правило бьёт по 1 из ~2.3 событий эпизода);
  • честная метрика — ЭПИЗОДНАЯ: эпизод пойман, если поймано хотя бы decisive-событие.

Правила (только наблюдаемые поля аудита, без таргетов):
  R1 self-approval/self-merge (approver/merger == автор MR)
  R2 merge без единого approve
  R3 прямое касание secrets-repo (push/merge/branch)
  R4 пакетные удаления одним актором в окне

Запуск:  python rule_baseline.py [--in data/events.jsonl] [--window 600]
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
import argparse
from collections import defaultdict
from datetime import datetime

SECRETS_PROJECTS = {"soc-secrets"}
# семейства, которые baseline в принципе НЕ должен ловить наблюдаемыми правилами
SOFT_FAMILY = {"process"}   # ловится правилами тривиально, не цель ML


def load_rows(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def is_meta(r):
    return r.get("meta") is True or r.get("action") in ("anomaly", "activity")


def parse_ts(r):
    try:
        return datetime.strptime(r.get("ts_sim", ""), "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None


def build_mr_index(rows):
    idx = defaultdict(lambda: {"author": None, "approvers": set(), "mergers": set()})
    for r in rows:
        mr = r.get("mr_iid")
        if mr is None:
            continue
        key = (r.get("project"), mr)
        a = r.get("action")
        if a == "mr_open" and idx[key]["author"] is None:
            idx[key]["author"] = r.get("actor")
        elif a == "mr_approve":
            idx[key]["approvers"].add(r.get("actor"))
        elif a == "mr_merge":
            idx[key]["mergers"].add(r.get("actor"))
    return idx


def predict(rows, window_s):
    mr_idx = build_mr_index(rows)
    del_times = defaultdict(list)
    for r in rows:
        if r.get("action") in ("mass_delete", "delete", "file_delete"):
            ts = parse_ts(r)
            if ts:
                del_times[r.get("actor")].append(ts)

    def burst(r):
        ts = parse_ts(r)
        if not ts:
            return False
        near = [t for t in del_times.get(r.get("actor"), [])
                if abs((t - ts).total_seconds()) <= window_s]
        return len(near) >= 3

    preds = []
    for r in rows:
        a = r.get("action"); proj = r.get("project"); actor = r.get("actor")
        mr = mr_idx.get((proj, r.get("mr_iid")))
        p = 0
        if mr and mr["author"]:
            if a == "mr_merge" and actor == mr["author"]:
                p = 1
            if a == "mr_approve" and actor == mr["author"]:
                p = 1
            if a == "mr_merge" and not mr["approvers"]:
                p = 1
        if proj in SECRETS_PROJECTS and a in ("push", "mr_merge", "branch_create", "file_delete"):
            p = 1
        if a in ("mass_delete", "delete", "file_delete") and burst(r):
            p = 1
        preds.append(p)
    return preds


def prf(tp, fp, fn):
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return prec, rec, f1


def main():
    ap = argparse.ArgumentParser(description="Rule-based baseline (эпизодная оценка)")
    ap.add_argument("--in", dest="inp", default="data/events.jsonl")
    ap.add_argument("--window", type=int, default=600)
    args = ap.parse_args()

    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    inp = args.inp if os.path.isabs(args.inp) else os.path.join(base, args.inp)
    if not os.path.exists(inp):
        print(f"[!] Нет файла событий: {inp}"); sys.exit(1)

    rows = [r for r in load_rows(inp) if not is_meta(r)]
    y_true = [1 if r.get("is_anomaly") else 0 for r in rows]
    y_pred = predict(rows, args.window)

    # --- событийные метрики (для сравнения) ---
    tp = fp = fn = tn = 0
    for t, p in zip(y_true, y_pred):
        if t and p: tp += 1
        elif p and not t: fp += 1
        elif t and not p: fn += 1
        else: tn += 1
    e_prec, e_rec, e_f1 = prf(tp, fp, fn)

    # --- эпизодные метрики ---
    episodes = {}  # eid -> {family, caught_decisive, caught_any, n}
    for r, p in zip(rows, y_pred):
        eid = r.get("episode_id")
        if not eid:
            continue
        ep = episodes.setdefault(eid, {"family": r.get("family") or "other",
                                       "caught_decisive": False, "caught_any": False,
                                       "has_decisive": False, "n": 0})
        ep["n"] += 1
        if p:
            ep["caught_any"] = True
        if r.get("is_decisive"):
            ep["has_decisive"] = True
            if p:
                ep["caught_decisive"] = True

    n_ep = len(episodes)
    caught_dec = sum(1 for e in episodes.values()
                     if (e["caught_decisive"] if e["has_decisive"] else e["caught_any"]))
    # эпизодный recall по семействам
    fam_tot = defaultdict(int); fam_hit = defaultdict(int)
    for e in episodes.values():
        f = e["family"]; fam_tot[f] += 1
        hit = e["caught_decisive"] if e["has_decisive"] else e["caught_any"]
        if hit:
            fam_hit[f] += 1

    print("=" * 70)
    print("RULE-BASED BASELINE  (наблюдаемые поля; ЭПИЗОДНАЯ оценка)")
    print("=" * 70)
    print(f"событий (без служебных): {len(rows)} | эпизодов: {n_ep}")
    print("-" * 70)
    print("СОБЫТИЙНЫЙ уровень (для сравнения — занижен из-за контекстных событий):")
    print(f"  TP={tp} FP={fp} FN={fn} TN={tn} | precision={e_prec:.3f} recall={e_rec:.3f} F1={e_f1:.3f}")
    print("-" * 70)
    print("ЭПИЗОДНЫЙ уровень (эпизод пойман = пойман decisive-событие):")
    print(f"  эпизодов поймано: {caught_dec}/{n_ep}  recall={caught_dec/n_ep if n_ep else 0:.3f}")
    print(f"  FP-событий (шум для аналитика): {fp}")
    print("-" * 70)
    print("RECALL по семействам (эпизодный):")
    for fam in sorted(fam_tot, key=lambda k: -fam_tot[k]):
        tot, hit = fam_tot[fam], fam_hit[fam]
        soft = "  [soft: ловится правилами, НЕ цель ML]" if fam in SOFT_FAMILY else ""
        bar = "#" * int(round(hit / tot * 20)) if tot else ""
        print(f"  {fam:14} {hit:3}/{tot:<3} recall={hit/tot if tot else 0:5.2f}  {bar}{soft}")
    print("-" * 70)
    blind = [f for f in fam_tot if fam_hit[f] == 0 and f not in SOFT_FAMILY]
    if blind:
        print("«Слепые зоны» baseline (recall=0) — здесь ценность ML:")
        print("  " + ", ".join(sorted(blind)))
    print("=" * 70)
    print("Вывод: baseline берёт process/secrets-repo тривиально, но «тонкие»")
    print("(secret_leak в обычных репо, exfil, pipeline) — слепые зоны для ML.")


if __name__ == "__main__":
    main()
