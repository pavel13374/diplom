#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Экспорт обучающего датасета из data/events.jsonl БЕЗ утечки таргета.

Что делает:
  1. Выбрасывает служебные события (meta=true: сводки аномалий action="anomaly"
     и маркеры планировщика action="activity"). Они нужны только для
     алертов/телеметрии — в обучающую выборку им нельзя.
  2. Режет лик-колонки:
       - таргеты:            is_anomaly, anomaly_type, severity
       - прямой лик разметки: anomaly_subtype, executed, detail, message
                              (в message часто прямым текстом «Мержу без ревью…»)
       - поля, появляющиеся ТОЛЬКО при аномалиях/косяках (косвенный лик):
                              secret_type, repo, grantee, deleted_count,
                              token_scope, for_user, quirk, lookalike
     Таргет сохраняется ОТДЕЛЬНО в полях _label (0/1) и _anomaly_type.
  3. Делит на train/val/test ПО ВРЕМЕНИ (хронологически, не случайно) —
     чтобы будущее не утекало в прошлое.

Запуск:
    python export_dataset.py
    python export_dataset.py --in data/events.jsonl --out data/dataset \
                             --train 0.7 --val 0.15
    (test = остаток; по умолчанию 0.70 / 0.15 / 0.15)

Результат:
    data/dataset/train.jsonl
    data/dataset/val.jsonl
    data/dataset/test.jsonl
    data/dataset/meta.json     (счётчики, баланс классов, границы по времени)
"""
import os
import sys
import json
import argparse

# ----- что считаем утечкой и выкидываем из фич -------------------------
TARGET_COLUMNS = {"is_anomaly", "anomaly_type", "severity"}
DIRECT_LEAK = {"anomaly_subtype", "executed", "detail", "message"}
ANOMALY_ONLY = {  # эти ключи проставляются только в аномалиях/косяках
    "secret_type", "repo", "grantee", "deleted_count",
    "token_scope", "for_user", "quirk", "lookalike",
}
SERVICE = {"meta", "activity"}
DROP_COLUMNS = TARGET_COLUMNS | DIRECT_LEAK | ANOMALY_ONLY | SERVICE


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
    """Служебная запись — не для обучения."""
    if r.get("meta") is True:
        return True
    # подстраховка для старых логов без поля meta
    return r.get("action") in ("anomaly", "activity")


def featurize(r):
    """Чистые фичи + отдельно вынесенный таргет (_label, _anomaly_type)."""
    feats = {k: v for k, v in r.items() if k not in DROP_COLUMNS}
    label = 1 if r.get("is_anomaly") else 0
    feats["_label"] = label
    feats["_anomaly_type"] = r.get("anomaly_type")  # для пер-типового анализа
    return feats, label


def time_key(r):
    return (r.get("ts_sim") or "", r.get("seq") or 0)


def main():
    ap = argparse.ArgumentParser(description="Экспорт ML-датасета без утечки таргета")
    ap.add_argument("--in", dest="inp", default="data/events.jsonl")
    ap.add_argument("--out", dest="out", default="data/dataset")
    ap.add_argument("--train", type=float, default=0.70)
    ap.add_argument("--val", type=float, default=0.15)
    args = ap.parse_args()

    base = os.path.dirname(os.path.abspath(__file__))
    inp = args.inp if os.path.isabs(args.inp) else os.path.join(base, args.inp)
    out = args.out if os.path.isabs(args.out) else os.path.join(base, args.out)

    if not os.path.exists(inp):
        print(f"[!] Нет файла событий: {inp}")
        sys.exit(1)
    if args.train + args.val >= 1.0:
        print("[!] train + val должно быть < 1.0 (остаток уходит в test)")
        sys.exit(1)

    raw = load_rows(inp)
    total_raw = len(raw)

    # 1) фильтруем служебные
    clean = [r for r in raw if not is_meta(r)]
    dropped_meta = total_raw - len(clean)

    # 2) сортируем по времени (хронологически)
    clean.sort(key=time_key)

    # 3) делим по времени
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
        "rows_kept": n,
        "dropped_columns": sorted(DROP_COLUMNS),
        "label_field": "_label (0=norm, 1=anomaly); _anomaly_type — тип (для анализа)",
        "split_strategy": "chronological by ts_sim (no future leakage)",
        "splits": {},
    }

    for name, rows in splits.items():
        fp = os.path.join(out, f"{name}.jsonl")
        pos = 0
        with open(fp, "w", encoding="utf-8") as f:
            for r in rows:
                feats, label = featurize(r)
                pos += label
                f.write(json.dumps(feats, ensure_ascii=False) + "\n")
        summary["splits"][name] = {
            "rows": len(rows),
            "anomalies": pos,
            "normal": len(rows) - pos,
            "anomaly_rate": round(pos / len(rows), 4) if rows else 0.0,
            "ts_from": rows[0].get("ts_sim") if rows else None,
            "ts_to": rows[-1].get("ts_sim") if rows else None,
        }

    with open(os.path.join(out, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    # отчёт
    print(f"Источник:        {summary['source']}  ({total_raw} строк)")
    print(f"Служебных снято: {dropped_meta}  → осталось {n}")
    print(f"Выкинуто колонок: {len(DROP_COLUMNS)} ({', '.join(sorted(DROP_COLUMNS))})")
    print("-" * 64)
    for name in ("train", "val", "test"):
        s = summary["splits"][name]
        print(f"{name:5} | строк {s['rows']:6} | аномалий {s['anomalies']:5} "
              f"({s['anomaly_rate']*100:5.2f}%) | {s['ts_from']} → {s['ts_to']}")
    print("-" * 64)
    print(f"Готово: {os.path.relpath(out, base)}/  (train/val/test.jsonl + meta.json)")


if __name__ == "__main__":
    main()
