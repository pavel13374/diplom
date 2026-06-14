#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Rule-based baseline для честной демонстрации ценности ML.

Идея (важна для диплома): часть аномалий тривиально ловится ПРОСТЫМИ ПРАВИЛАМИ
по аудит-логу — это «правило, а не ML»:
    R1  self-approval:   approver/merger == автор MR
    R2  no-review merge:  MR смержён, но не было ни одного approve
    R3  secrets-repo:     прямое касание репозитория секретов (push/merge)
    R4  mass-delete:      пачка удалений одним актором в коротком окне

Эти правила НЕ используют поля-таргеты (is_anomaly/anomaly_type/secret_type...),
только наблюдаемые: actor, action, project, mr_iid, branch, ts.

Скрипт считает precision/recall/F1 baseline-а и РАЗБИВКУ recall по типам аномалий.
Вывод показывает: baseline почти идеально берёт self_approval_merge /
merge_without_review, но «слепой» на secret_*/exfil/pipeline — там и нужен ML.

Запуск:
    python rule_baseline.py                      # читает data/events.jsonl
    python rule_baseline.py --in data/events.jsonl --window 600
"""
import os
import sys
import json
import argparse
from collections import defaultdict
from datetime import datetime

# то, что rule-движку «видеть нельзя» (иначе это не baseline, а списывание)
FORBIDDEN = {"is_anomaly", "anomaly_type", "severity", "anomaly_subtype",
             "executed", "detail", "secret_type", "repo", "grantee",
             "deleted_count", "token_scope", "for_user", "quirk", "lookalike", "meta"}

SECRETS_PROJECTS = {"soc-secrets"}


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
    """(project, mr_iid) -> {author, approvers:set, mergers:set}."""
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
    """Возвращает list[int] предсказаний (0/1) по наблюдаемым правилам."""
    mr_idx = build_mr_index(rows)

    # R4: окно удалений по актору
    del_times = defaultdict(list)
    for r in rows:
        if r.get("action") in ("mass_delete", "delete"):
            ts = parse_ts(r)
            if ts:
                del_times[r.get("actor")].append(ts)

    def actor_in_delete_burst(r):
        ts = parse_ts(r)
        if not ts:
            return False
        near = [t for t in del_times.get(r.get("actor"), [])
                if abs((t - ts).total_seconds()) <= window_s]
        return len(near) >= 3

    preds = []
    for r in rows:
        a = r.get("action")
        proj = r.get("project")
        actor = r.get("actor")
        key = (proj, r.get("mr_iid"))
        mr = mr_idx.get(key)
        p = 0

        # R1 self-approval / self-merge
        if mr and mr["author"]:
            if a == "mr_merge" and actor == mr["author"]:
                p = 1
            if a == "mr_approve" and actor == mr["author"]:
                p = 1
            # R2 no-review merge
            if a == "mr_merge" and not mr["approvers"]:
                p = 1

        # R3 прямое касание репозитория секретов
        if proj in SECRETS_PROJECTS and a in ("push", "mr_merge", "branch_create"):
            p = 1

        # R4 пакетное удаление
        if a in ("mass_delete", "delete") and actor_in_delete_burst(r):
            p = 1

        preds.append(p)
    return preds


def prf(tp, fp, fn):
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return prec, rec, f1


def main():
    ap = argparse.ArgumentParser(description="Rule-based baseline по аудит-логу")
    ap.add_argument("--in", dest="inp", default="data/events.jsonl")
    ap.add_argument("--window", type=int, default=600, help="окно для mass-delete, сек")
    args = ap.parse_args()

    base = os.path.dirname(os.path.abspath(__file__))
    inp = args.inp if os.path.isabs(args.inp) else os.path.join(base, args.inp)
    if not os.path.exists(inp):
        print(f"[!] Нет файла событий: {inp}")
        sys.exit(1)

    raw = load_rows(inp)
    rows = [r for r in raw if not is_meta(r)]   # учимся/меряем на «обучающих» строках

    y_true = [1 if r.get("is_anomaly") else 0 for r in rows]
    y_pred = predict(rows, args.window)

    tp = fp = fn = tn = 0
    for t, p in zip(y_true, y_pred):
        if t and p:
            tp += 1
        elif p and not t:
            fp += 1
        elif t and not p:
            fn += 1
        else:
            tn += 1
    prec, rec, f1 = prf(tp, fp, fn)

    # recall по типам аномалий
    per_type_tot = defaultdict(int)
    per_type_hit = defaultdict(int)
    for r, p in zip(rows, y_pred):
        if r.get("is_anomaly"):
            at = r.get("anomaly_type") or "(unknown)"
            per_type_tot[at] += 1
            if p:
                per_type_hit[at] += 1

    print("=" * 66)
    print("RULE-BASED BASELINE  (только наблюдаемые поля аудит-лога)")
    print("=" * 66)
    print(f"строк (без служебных): {len(rows)} | позитивов: {sum(y_true)}")
    print(f"TP={tp}  FP={fp}  FN={fn}  TN={tn}")
    print(f"precision={prec:.3f}  recall={rec:.3f}  F1={f1:.3f}")
    print("-" * 66)
    print("RECALL по типам аномалий (что baseline ловит, что — нет):")
    for at in sorted(per_type_tot, key=lambda k: -per_type_tot[k]):
        tot = per_type_tot[at]
        hit = per_type_hit[at]
        bar = "█" * int(round(hit / tot * 20)) if tot else ""
        print(f"  {at:26} {hit:4}/{tot:<4} recall={hit/tot:5.2f}  {bar}")
    print("-" * 66)
    blind = [at for at in per_type_tot if per_type_hit[at] == 0]
    if blind:
        print("«Слепые зоны» baseline (recall=0) — здесь ценность ML:")
        print("  " + ", ".join(sorted(blind)))
    print("=" * 66)
    print("Вывод для диплома: правила тривиально берут self_approval_merge /")
    print("merge_without_review, но не видят поведенческие/секретные утечки —")
    print("их должен добавлять ML поверх baseline.")


if __name__ == "__main__":
    main()
