#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ML-ДЕТЕКТОР (supervised) поверх размеченного датасета.

Учит классификатор «аномалия/норма» на ОСМЫСЛЕННЫХ числовых признаках события
(поведение + контент), и оценивает его так, как это важно для SOC:

  • ЭПИЗОДНЫЙ recall — поймали ли атаку (эпизод), а не каждый её шаг
    (нерешающие шаги вроде branch_create по контенту неотличимы от нормы —
    мерить по ним precision бессмысленно);
  • AUC на событиях — качество модели без привязки к порогу;
  • порог подбирается на VAL под бюджет ложных срабатываний (FP ≤ 2% на норме);
  • сравнение с сигнатурным baseline (regex) — у него высокая точность, но
    низкий recall (он и не должен ловить уклонение/новизну).

Если установлен scikit-learn — GradientBoosting; иначе встроенный логрег
(зависимостей нет). Анти-лик: на вход только наблюдаемые поля, метки (`_`) — отдельно.

Запуск:
    python export_dataset.py --version 1
    python train_model.py --data data/dataset_v1
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
import math
import argparse
import collections

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

ACTIONS = ["push", "branch_create", "mr_open", "mr_merge", "token_create",
           "repo_enum", "comment", "approve"]
FEATS = (["hour", "is_night", "is_weekend", "n_regex_hits", "entropy", "filename_sig",
          "placeholder_sig", "high_entropy_tok", "has_content", "bytes_log",
          "path_env", "path_secretdir", "proj_secrets", "night_x_secret"]
         + ["act_" + a for a in ACTIONS])
TARGET_FP = 0.02


def load(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try: rows.append(json.loads(line))
                except json.JSONDecodeError: pass
    return rows


def _num(r, k, d=0.0):
    v = r.get(k)
    return float(v) if isinstance(v, (int, float)) and v != -1 else d


def feat(r):
    path = str(r.get("path", "") or "").lower()
    nrh = max(0.0, _num(r, "n_regex_hits"))
    ent = max(0.0, _num(r, "shannon_entropy"))
    byt = _num(r, "bytes"); byt = math.log1p(byt) if byt > 0 else 0.0
    night = 1.0 if r.get("is_night") else 0.0
    secretish = 1.0 if (nrh > 0 or "env" in path) else 0.0
    act = str(r.get("action", ""))
    return [
        _num(r, "hour") / 23.0, night, 1.0 if r.get("is_weekend") else 0.0,
        nrh, ent / 8.0,
        1.0 if r.get("filename_signal") else 0.0,
        1.0 if r.get("placeholder_signal") else 0.0,
        1.0 if r.get("has_high_entropy_token") else 0.0,
        1.0 if r.get("has_content") else 0.0,
        byt / 12.0,
        1.0 if "env" in path else 0.0,
        1.0 if any(k in path for k in ("vault", "backup", "export", "secret", "dump")) else 0.0,
        1.0 if r.get("project") == "soc-secrets" else 0.0,
        night * secretish,
    ] + [1.0 if act == a else 0.0 for a in ACTIONS]


# ---------------- модель ----------------
class LogReg:
    def __init__(self, dim, lr=0.3, epochs=140, l2=1e-4):
        self.w = [0.0]*dim; self.b = 0.0; self.lr = lr; self.epochs = epochs; self.l2 = l2
        self.mu = [0.0]*dim; self.sd = [1.0]*dim

    def fit(self, X, y):
        import random
        n = len(X); d = len(X[0])
        self.mu = [sum(r[j] for r in X)/n for j in range(d)]
        self.sd = [math.sqrt(sum((r[j]-self.mu[j])**2 for r in X)/n) or 1.0 for j in range(d)]
        Xn = [[(r[j]-self.mu[j])/self.sd[j] for j in range(d)] for r in X]
        pos = sum(y) or 1; neg = n-pos or 1; wpos = n/(2*pos); wneg = n/(2*neg)
        idx = list(range(n))
        for _ in range(self.epochs):
            random.shuffle(idx)
            for i in idx:
                x = Xn[i]; yi = y[i]
                z = sum(wj*xj for wj, xj in zip(self.w, x)) + self.b
                p = 1/(1+math.exp(-max(-30, min(30, z))))
                g = (p-yi)*(wpos if yi else wneg)
                for j in range(d):
                    self.w[j] -= self.lr*(g*x[j] + self.l2*self.w[j])
                self.b -= self.lr*g

    def proba(self, x):
        z = sum(wj*((x[j]-self.mu[j])/self.sd[j]) for j, wj in enumerate(self.w)) + self.b
        return 1/(1+math.exp(-max(-30, min(30, z))))


def make_model(Xtr, ytr):
    try:
        from sklearn.ensemble import GradientBoostingClassifier
        clf = GradientBoostingClassifier(random_state=42)
        clf.fit(Xtr, ytr)
        return ("GradientBoosting (sklearn)", lambda x: float(clf.predict_proba([x])[0][1]))
    except Exception:
        m = LogReg(dim=len(Xtr[0])); m.fit(Xtr, ytr)
        return ("LogReg (чистый python)", m.proba)


def auc(pos, neg):
    import bisect
    if not pos or not neg: return 0.0
    negs = sorted(neg); below = 0.0
    for p in pos:
        lo = bisect.bisect_left(negs, p); hi = bisect.bisect_right(negs, p)
        below += lo + 0.5*(hi-lo)
    return below/(len(pos)*len(neg))


def thr_for_fp(scores_neg, target):
    s = sorted(scores_neg, reverse=True)
    k = int(target*len(s))
    return (s[k] + 1e-9) if k < len(s) else 1.01


def episodes(rows, score):
    eps = {}
    for r, sc in zip(rows, score):
        if r.get("_label") == 1 and r.get("_episode_id"):
            e = eps.setdefault(r["_episode_id"], {"max": 0.0, "fam": r.get("_family", "?")})
            e["max"] = max(e["max"], sc)
    return eps


def main():
    ap = argparse.ArgumentParser(description="ML detector")
    ap.add_argument("--data", default="data/dataset_v1")
    args = ap.parse_args()
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ddir = args.data if os.path.isabs(args.data) else os.path.join(base, args.data)
    trp, vap, tep = (os.path.join(ddir, f) for f in ("train.jsonl", "val.jsonl", "test.jsonl"))
    if not os.path.exists(trp):
        print(f"[!] Нет датасета в {ddir}. Сначала: python export_dataset.py --version 1")
        sys.exit(1)

    train = load(trp)
    val = load(vap) if os.path.exists(vap) else []
    test = load(tep) if os.path.exists(tep) else val
    Xtr = [feat(r) for r in train]; ytr = [int(r.get("_label", 0)) for r in train]

    name, score = make_model(Xtr, ytr)

    # порог на VAL под FP-бюджет
    vrows = val or train
    vneg = [score(feat(r)) for r in vrows if r.get("_label") == 0]
    thr = thr_for_fp(vneg, TARGET_FP)

    # оценка на TEST
    sc = [score(feat(r)) for r in test]
    pos = [s for s, r in zip(sc, test) if r.get("_label") == 1]
    neg = [s for s, r in zip(sc, test) if r.get("_label") == 0]
    a = auc(pos, neg)
    fp = sum(s >= thr for s in neg) / max(1, len(neg))

    eps = episodes(test, sc)
    caught = sum(1 for e in eps.values() if e["max"] >= thr)
    rec = caught / len(eps) if eps else 0.0
    fam = collections.defaultdict(lambda: [0, 0])
    for e in eps.values():
        fam[e["fam"]][1] += 1
        if e["max"] >= thr: fam[e["fam"]][0] += 1

    # baseline: сигнатура (n_regex_hits>0)
    def rx(r): return max(0.0, _num(r, "n_regex_hits")) > 0
    b_eps = {}
    for r in test:
        if r.get("_label") == 1 and r.get("_episode_id"):
            b_eps.setdefault(r["_episode_id"], False)
            if rx(r): b_eps[r["_episode_id"]] = True
    b_rec = sum(b_eps.values())/len(b_eps) if b_eps else 0.0
    b_fp = sum(1 for r in test if r.get("_label") == 0 and rx(r)) / max(1, len(neg))

    print("=" * 64)
    print(f"  ML-ДЕТЕКТОР · {name}")
    print("=" * 64)
    print(f"  train={len(train)}  test={len(test)}  признаков={len(FEATS)}  порог(FP≤{int(TARGET_FP*100)}%)={thr:.3f}")
    print("-" * 64)
    print(f"  Качество модели:   AUC (событийный) = {a:.3f}")
    print(f"  Эпизодный recall:  {caught}/{len(eps)} = {rec*100:.0f}%   при FP на норме {fp*100:.1f}%")
    print("-" * 64)
    print(f"  Сигнатурный baseline (regex):  recall {b_rec*100:.0f}%   FP {b_fp*100:.1f}%")
    print("  -> ML ловит больше атак при сопоставимом бюджете ложных срабатываний"
          if rec >= b_rec else "  -> baseline точечнее на этом срезе")
    print("-" * 64)
    print("  Эпизодный recall по семействам:")
    for f, (c, t) in sorted(fam.items()):
        print(f"    {f:16} {c}/{t}  = {(c/t if t else 0)*100:.0f}%")
    print("=" * 64)

    out = {"model": name, "auc": round(a, 3), "episode_recall": round(rec, 3),
           "fp_rate": round(fp, 3), "threshold": round(thr, 4),
           "baseline_recall": round(b_rec, 3), "baseline_fp": round(b_fp, 3),
           "by_family": {f: {"caught": c, "total": t} for f, (c, t) in fam.items()}}
    json.dump(out, open(os.path.join(ddir, "ml_metrics.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)
    print(f"  Метрики: {os.path.relpath(os.path.join(ddir,'ml_metrics.json'), base)}")


if __name__ == "__main__":
    main()
