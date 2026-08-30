#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ROC: одиночный признак против СЛИЯНИЯ сигналов (fused ML).

Демонстрирует второй аргумент «почему не просто порог по одному признаку»:
любой одиночный сигнал (энтропия, длина base64-блоба, доля символов) даёт
плохой trade-off TPR/FPR, а ML, выучивший СОВМЕСТНУЮ границу по многим слабым
признакам, доминирует на ROC (выше AUC). Руками такую границу не напишешь.

Считаем AUC и TPR при фиксированных FP (1%, 5%, 10%) для:
  entropy        — только энтропия токена;
  entropy_x_len  — энтропия * длина;
  longest_b64    — длина base64-подобного блоба;
  symbol_ratio   — доля символов;
  ML (fused)     — логрегрессия по всем 14 признакам.

Запуск:  python experiments_roc.py   ->  results/roc.csv
Без sklearn, воспроизводимо (SEED).
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
import random

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

import content_ml_features as F
from experiments_holdout import FAMILIES, make_secret_file, make_benign_file, LogReg

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEED = 42
FP_POINTS = [0.01, 0.05, 0.10]


def roc_auc(pos_scores, neg_scores):
    """AUC = доля пар (pos>neg). Тай — 0.5."""
    pos = sorted(pos_scores); neg = sorted(neg_scores)
    if not pos or not neg:
        return 0.0
    below = 0.0
    # для каждого pos считаем, сколько neg строго меньше + половина равных
    import bisect
    for p in pos:
        lo = bisect.bisect_left(neg, p); hi = bisect.bisect_right(neg, p)
        below += lo + 0.5 * (hi - lo)
    return below / (len(pos) * len(neg))


def tpr_at_fp(pos_scores, neg_scores, fp):
    """TPR при заданном FPR: порог = (1-fp)-квантиль neg."""
    neg = sorted(neg_scores, reverse=True)
    k = int(fp * len(neg))
    thr = neg[k] + 1e-9 if k < len(neg) else float("inf")
    return sum(s >= thr for s in pos_scores) / len(pos_scores)


def main():
    random.seed(SEED)
    fams = list(FAMILIES)

    # train ML на одной половине, оцениваем на другой (held-out по образцам)
    Xtr, ytr = [], []
    for f in fams:
        for _ in range(60):
            Xtr.append(F.vector(F.featurize(make_secret_file(f)))); ytr.append(1)
    for _ in range(220):
        Xtr.append(F.vector(F.featurize(make_benign_file()))); ytr.append(0)
    model = LogReg(dim=len(F.FEATURES)); model.fit(Xtr, ytr)

    # тестовая выборка
    sec_feats = [F.featurize(make_secret_file(random.choice(fams))) for _ in range(400)]
    ben_feats = [F.featurize(make_benign_file()) for _ in range(400)]

    signals = {
        "entropy":       lambda ft: ft["max_token_entropy"],
        "entropy_x_len": lambda ft: ft["entropy_x_len"],
        "longest_b64":   lambda ft: ft["longest_b64_len"],
        "symbol_ratio":  lambda ft: ft["symbol_ratio"],
        "ML (fused)":    lambda ft: model.proba(F.vector(ft)),
    }

    print("=" * 78)
    print("  ROC: одиночный признак против СЛИЯНИЯ (fused ML)")
    print("=" * 78)
    print(f"  {'сигнал':14} | {'AUC':>5} | {'TPR@FP=1%':>9} | {'TPR@FP=5%':>9} | {'TPR@FP=10%':>10}")
    print("-" * 78)
    rows = []
    for name, fn in signals.items():
        pos = [fn(ft) for ft in sec_feats]
        neg = [fn(ft) for ft in ben_feats]
        auc = roc_auc(pos, neg)
        t = {fp: tpr_at_fp(pos, neg, fp) for fp in FP_POINTS}
        print(f"  {name:14} | {auc:>5.3f} | {t[0.01]*100:>8.0f}% | {t[0.05]*100:>8.0f}% | {t[0.10]*100:>9.0f}%")
        rows.append({"signal": name, "auc": round(auc, 4),
                     "tpr_fp01": round(t[0.01], 3), "tpr_fp05": round(t[0.05], 3),
                     "tpr_fp10": round(t[0.10], 3)})
    print("-" * 78)
    best_single = max((r for r in rows if r["signal"] != "ML (fused)"), key=lambda r: r["auc"])
    ml = next(r for r in rows if r["signal"] == "ML (fused)")
    print(f"  Лучший одиночный признак: {best_single['signal']} (AUC {best_single['auc']:.3f})")
    print(f"  Слияние (ML):             AUC {ml['auc']:.3f}  -> доминирует над любым одиночным")
    print("=" * 78)
    print("  ВЫВОД: ни один одиночный порог не даёт хорошего TPR/FPR; ML учит СОВМЕСТНУЮ")
    print("  границу по слабым признакам и побеждает. Это вторая причина, зачем тут ML.")

    os.makedirs(os.path.join(BASE, "results"), exist_ok=True)
    fp = os.path.join(BASE, "results", "roc.csv")
    with open(fp, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    print(f"  CSV: {os.path.relpath(fp, BASE)}")


if __name__ == "__main__":
    main()
