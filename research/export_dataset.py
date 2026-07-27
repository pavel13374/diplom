#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Экспорт обучающего датасета из data/events.jsonl БЕЗ утечки таргета.

  1. Выбрасывает служебные события (meta=true).
  2. Режет лик/служебные колонки (DROP_COLUMNS): таргеты, прямой лик,
     поля-только-аномалий, ID/служебные (run_id, seq, ts_real, labels, session_id).
  3. Разметка ОТДЕЛЬНО: _label, _anomaly_type, _episode_id, _is_decisive, _family.
  4. Политика пропусков: sentinel (-1 / "none" / false) + индикаторы has_content/has_diff.
  5. Сплит по ВРЕМЕНИ (хронологически).
  6. Снапшот: SHA256 + счётчики в meta.json (заморозка версии).

Запуск:
    python export_dataset.py
    python export_dataset.py --full-schema-only
    python export_dataset.py --version 1
    python export_dataset.py --in data/events.jsonl --out data/dataset --train 0.7 --val 0.15
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
import hashlib
import argparse

TARGET_COLUMNS = {"is_anomaly", "anomaly_type", "severity"}
LABEL_EXTRA = {"episode_id", "is_decisive", "family", "campaign_id", "campaign_name",
               "step_idx", "technique_id", "tactic", "evasion_profile"}
DIRECT_LEAK = {"anomaly_subtype", "executed", "detail", "message"}
ANOMALY_ONLY = {"secret_type", "repo", "grantee", "deleted_count",
                "token_scope", "for_user", "quirk", "lookalike"}
SERVICE_ID = {"meta", "activity", "run_id", "seq", "ts_real", "labels", "session_id"}
DROP_COLUMNS = TARGET_COLUMNS | LABEL_EXTRA | DIRECT_LEAK | ANOMALY_ONLY | SERVICE_ID

CONTENT_FEATURES = {"shannon_entropy", "has_high_entropy_token", "regex_hits",
                    "n_regex_hits", "filename_signal", "placeholder_signal"}
assert not (CONTENT_FEATURES & DROP_COLUMNS), "признаки контента не должны быть в drop-листе!"

SPARSE_NUMERIC = {"shannon_entropy": -1.0, "n_regex_hits": -1, "lines": -1, "bytes": -1,
                  "mr_iid": -1}
SPARSE_BOOL = {"has_high_entropy_token": False, "filename_signal": False,
               "placeholder_signal": False}
SPARSE_CATEG = {"ext": "none", "path": "none", "branch": "none", "target": "none"}


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
    if r.get("meta") is True:
        return True
    return r.get("action") in ("anomaly", "activity")


def has_full_schema(r):
    return r.get("session_id") not in (None, "")


def featurize(r):
    feats = {k: v for k, v in r.items() if k not in DROP_COLUMNS}
    feats["has_content"] = 1 if ("shannon_entropy" in r) else 0
    feats["has_diff"] = 1 if r.get("path") else 0
    for col, fill in SPARSE_NUMERIC.items():
        if feats.get(col) is None:
            feats[col] = fill
    for col, fill in SPARSE_BOOL.items():
        if feats.get(col) is None:
            feats[col] = fill
    for col, fill in SPARSE_CATEG.items():
        if feats.get(col) is None:
            feats[col] = fill
    if feats.get("regex_hits") is None:
        feats["regex_hits"] = []
    label = 1 if r.get("is_anomaly") else 0
    feats["_label"] = label
    feats["_anomaly_type"] = r.get("anomaly_type")
    feats["_episode_id"] = r.get("episode_id")
    feats["_is_decisive"] = bool(r.get("is_decisive"))
    feats["_family"] = r.get("family")
    feats["_campaign_id"] = r.get("campaign_id")
    feats["_technique_id"] = r.get("technique_id")
    feats["_tactic"] = r.get("tactic")
    return feats, label


def time_key(r):
    return (r.get("ts_sim") or "", r.get("seq") or 0)


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description="Экспорт ML-датасета без утечки таргета")
    ap.add_argument("--in", dest="inp", default="data/events.jsonl")
    ap.add_argument("--out", dest="out", default=None)
    ap.add_argument("--version", dest="version", default=None)
    ap.add_argument("--train", type=float, default=0.70)
    ap.add_argument("--val", type=float, default=0.15)
    ap.add_argument("--full-schema-only", action="store_true")
    args = ap.parse_args()

    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    inp = args.inp if os.path.isabs(args.inp) else os.path.join(base, args.inp)
    if args.out:
        out = args.out if os.path.isabs(args.out) else os.path.join(base, args.out)
    elif args.version:
        out = os.path.join(base, "data", f"dataset_v{args.version}")
    else:
        out = os.path.join(base, "data", "dataset")

    if not os.path.exists(inp):
        print(f"[!] Нет файла событий: {inp}")
        sys.exit(1)
    if args.train + args.val >= 1.0:
        print("[!] train + val должно быть < 1.0 (остаток уходит в test)")
        sys.exit(1)

    raw = load_rows(inp)
    total_raw = len(raw)
    clean = [r for r in raw if not is_meta(r)]
    dropped_meta = total_raw - len(clean)

    schema_dropped = 0
    if args.full_schema_only:
        before = len(clean)
        clean = [r for r in clean if has_full_schema(r)]
        schema_dropped = before - len(clean)

    clean.sort(key=time_key)
    n = len(clean)
    n_train = int(n * args.train)
    n_val = int(n * args.val)
    splits = {
        "train": clean[:n_train],
        "val":   clean[n_train:n_train + n_val],
        "test":  clean[n_train + n_val:],
    }

    os.makedirs(out, exist_ok=True)
    summary = {
        "source": os.path.relpath(inp, base),
        "rows_total_raw": total_raw,
        "rows_meta_dropped": dropped_meta,
        "rows_schema_dropped": schema_dropped,
        "full_schema_only": bool(args.full_schema_only),
        "rows_kept": n,
        "dropped_columns": sorted(DROP_COLUMNS),
        "label_fields": ["_label", "_anomaly_type", "_episode_id", "_is_decisive", "_family", "_campaign_id", "_technique_id", "_tactic"],
        "content_features": sorted(CONTENT_FEATURES),
        "sparsity_policy": {
            "numeric_fill": SPARSE_NUMERIC, "bool_fill": SPARSE_BOOL,
            "categ_fill": SPARSE_CATEG,
            "indicators": ["has_content", "has_diff"],
            "note": "content/diff-признаки есть только у push; остальное — sentinel.",
        },
        "split_strategy": "chronological by ts_sim (no future leakage)",
        "splits": {},
        "files": {},
    }

    for name, rows in splits.items():
        fp = os.path.join(out, f"{name}.jsonl")
        pos = 0
        episodes = set()
        with open(fp, "w", encoding="utf-8") as f:
            for r in rows:
                feats, label = featurize(r)
                pos += label
                if feats.get("_episode_id"):
                    episodes.add(feats["_episode_id"])
                f.write(json.dumps(feats, ensure_ascii=False) + "\n")
        summary["splits"][name] = {
            "rows": len(rows),
            "anomaly_events": pos,
            "normal_events": len(rows) - pos,
            "episodes": len(episodes),
            "anomaly_rate": round(pos / len(rows), 4) if rows else 0.0,
            "ts_from": rows[0].get("ts_sim") if rows else None,
            "ts_to": rows[-1].get("ts_sim") if rows else None,
        }
        summary["files"][f"{name}.jsonl"] = _sha256(fp)

    combined = "".join(summary["files"][k] for k in sorted(summary["files"]))
    summary["snapshot_sha256"] = hashlib.sha256(combined.encode()).hexdigest()[:16]
    summary["version"] = args.version

    with open(os.path.join(out, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(f"Источник:         {summary['source']}  ({total_raw} строк)")
    print(f"Служебных снято:  {dropped_meta}" +
          (f" | не полной схемы снято: {schema_dropped}" if args.full_schema_only else "") +
          f"  -> осталось {n}")
    print(f"Выкинуто колонок: {len(DROP_COLUMNS)}")
    print(f"Снапшот SHA:      {summary['snapshot_sha256']}")
    print("-" * 70)
    for name in ("train", "val", "test"):
        s = summary["splits"][name]
        print(f"{name:5} | rows {s['rows']:6} | anom-events {s['anomaly_events']:5} "
              f"| episodes {s['episodes']:4} ({s['anomaly_rate']*100:5.2f}%) "
              f"| {s['ts_from']} -> {s['ts_to']}")
    print("-" * 70)
    print(f"Готово: {os.path.relpath(out, base)}/  (train/val/test.jsonl + meta.json)")


if __name__ == "__main__":
    main()
