#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ОБУЧЕНИЕ БОЕВОЙ МОДЕЛИ для слоя L2 детектора.

Раньше ML жил только в research/: работа доказывала, что модель обобщает лучше
регулярок, после чего продакшн-детектор работал на регулярках. Этот скрипт
закрывает разрыв — он производит файл models/runtime_model.json, который
подхватывает detector.MLScorer в потоке.

Что делает:
  1. Генерирует нагрузку (нормальный фон + ATT&CK-кампании) на НЕСКОЛЬКИХ сидах.
  2. Прогоняет события через detector.Enricher — чтобы оконные признаки
     (всплески) считались ТОЧНО ТАК ЖЕ, как в бою. Иначе классическое
     расхождение train/serve.
  3. Делит по ВРЕМЕНИ (не случайно): train — прошлое, val/test — будущее.
     Случайное разбиение потока событий завышает качество, потому что соседние
     события одного эпизода попадают в обе части.
  4. Учит логистическую регрессию с балансировкой классов и L2.
  5. Подбирает порог на VAL под бюджет ложных срабатываний (FP <= TARGET_FP).
  6. Калибрует выход методом Платта, чтобы `proba` означала настоящую
     P(атака | скор) — без этого fuse() складывал бы несопоставимые величины.
  7. Печатает качество на TEST: PR-AUC, ROC-AUC, эпизодный recall, Brier.

Запуск:  python research/train_runtime_model.py [--seeds 3] [--out models/runtime_model.json]
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
import random
import logging
import argparse
import datetime

logging.disable(logging.CRITICAL)
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

import ml_features
import detector
import run_defense
from workload import build_workload
from stats import pr_auc, roc_auc, wilson

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET_FP = 0.01          # бюджет ложных срабатываний слоя L2 на норме


# ----------------------------------------------------------------------
class LogReg:
    """Логистическая регрессия со стандартизацией и балансировкой классов.

    Без sklearn — чтобы стенд обучался на любой машине. Балансировка нужна
    из-за сильного дисбаланса: атакующих событий заметно меньше процента.
    """

    def __init__(self, dim, lr=0.15, epochs=90, l2=3e-4, seed=42):
        self.w = [0.0] * dim; self.b = 0.0
        self.lr = lr; self.epochs = epochs; self.l2 = l2
        self.mu = [0.0] * dim; self.sd = [1.0] * dim
        self.rnd = random.Random(seed)

    def _std(self, X):
        n = len(X); d = len(X[0])
        self.mu = [sum(r[j] for r in X) / n for j in range(d)]
        self.sd = [math.sqrt(sum((r[j] - self.mu[j]) ** 2 for r in X) / n) or 1.0
                   for j in range(d)]

    def _norm(self, x):
        return [(x[j] - self.mu[j]) / self.sd[j] for j in range(len(x))]

    def fit(self, X, y):
        self._std(X)
        Xn = [self._norm(r) for r in X]
        n = len(Xn); pos = sum(y) or 1; neg = n - pos or 1
        wpos = n / (2.0 * pos); wneg = n / (2.0 * neg)
        idx = list(range(n))
        for ep in range(self.epochs):
            self.rnd.shuffle(idx)
            lr = self.lr / (1.0 + 0.02 * ep)          # затухающий шаг
            for i in idx:
                x = Xn[i]; yi = y[i]
                z = sum(wj * xj for wj, xj in zip(self.w, x)) + self.b
                p = 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))
                g = (p - yi) * (wpos if yi else wneg)
                for j in range(len(self.w)):
                    self.w[j] -= lr * (g * x[j] + self.l2 * self.w[j])
                self.b -= lr * g

    def raw(self, x):
        z = sum(wj * xj for wj, xj in zip(self.w, self._norm(x))) + self.b
        return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))


def fit_platt(scores, labels, seed=1):
    """Калибровка Платта: сигмоида над сырым скором, обученная на валидации.

    После неё значение можно интерпретировать как вероятность атаки, и его
    корректно складывать с рисками других слоёв в fuse().
    """
    a, b = 1.0, 0.0
    rnd = random.Random(seed)
    idx = list(range(len(scores)))
    for ep in range(220):
        rnd.shuffle(idx)
        lr = 0.35 / (1.0 + 0.03 * ep)
        for i in idx:
            s = scores[i]; y = labels[i]
            z = a * s + b
            p = 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))
            g = p - y
            a -= lr * g * s
            b -= lr * g
    return {"a": a, "b": b}


def thr_for_fp(neg_scores, target):
    """Порог, дающий на норме долю срабатываний не выше target."""
    s = sorted(neg_scores, reverse=True)
    if not s:
        return 0.5
    k = int(target * len(s))
    return (s[k] + 1e-9) if k < len(s) else 1.01


def brier(scores, labels):
    return sum((s - y) ** 2 for s, y in zip(scores, labels)) / max(1, len(scores))


# ----------------------------------------------------------------------
def collect(seeds, evasions=("noisy", "stealthy", "adaptive")):
    """Собрать события, обогатив их РОВНО ТАК ЖЕ, как это делает бой."""
    rows = []
    for si, seed in enumerate(seeds):
        for ev_prof in evasions:
            wl = build_workload(evasion=ev_prof, seed=seed, days=14, per_day=320)
            enr = detector.Enricher()          # свой энричер на каждый прогон
            for r in wl:
                if r.get("meta"):
                    continue
                obs = enr.enrich(run_defense.observed(r))
                rows.append({
                    "x": ml_features.featurize(obs),
                    "y": 1 if r.get("is_anomaly") else 0,
                    "episode": r.get("episode_id"),
                    "ts": r.get("ts_sim") or "",
                    "run": f"{si}:{ev_prof}",
                })
    rows.sort(key=lambda r: (r["run"], r["ts"]))
    return rows


def split_by_time(rows, tr=0.6, va=0.2):
    """Хронологический сплит ВНУТРИ каждого прогона.

    Случайное перемешивание здесь недопустимо: события одного эпизода атаки
    идут подряд, и при случайном сплите часть эпизода оказалась бы в train, а
    часть в test — модель «узнавала» бы знакомую атаку, а не обобщала.
    """
    by_run = {}
    for r in rows:
        by_run.setdefault(r["run"], []).append(r)
    train, val, test = [], [], []
    for _, rs in by_run.items():
        n = len(rs)
        i1, i2 = int(n * tr), int(n * (tr + va))
        train += rs[:i1]; val += rs[i1:i2]; test += rs[i2:]
    return train, val, test


def episode_recall(rows, scores, thr):
    eps = {}
    for r, s in zip(rows, scores):
        if r["y"] == 1 and r["episode"]:
            eps[r["episode"]] = max(eps.get(r["episode"], 0.0), s)
    if not eps:
        return 0.0, 0, 0
    caught = sum(1 for v in eps.values() if v >= thr)
    return caught / len(eps), caught, len(eps)


def main():
    ap = argparse.ArgumentParser(description="Обучение боевой модели слоя L2")
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--out", default=os.path.join("models", "runtime_model.json"))
    args = ap.parse_args()

    print("=" * 74)
    print("  ОБУЧЕНИЕ БОЕВОЙ МОДЕЛИ (слой L2 детектора)")
    print("=" * 74)
    seeds = [42 + i * 17 for i in range(args.seeds)]
    print(f"  сиды: {seeds} | профили уклонения: noisy/stealthy/adaptive")
    rows = collect(seeds)
    train, val, test = split_by_time(rows)
    print(f"  событий: {len(rows)}  (train {len(train)} / val {len(val)} / test {len(test)})")
    print(f"  доля атак в train: {sum(r['y'] for r in train) / max(1, len(train)) * 100:.2f}%")
    print(f"  признаков: {len(ml_features.FEATURES)}")
    print("-" * 74)

    m = LogReg(dim=len(ml_features.FEATURES))
    m.fit([r["x"] for r in train], [r["y"] for r in train])

    v_raw = [m.raw(r["x"]) for r in val]
    v_y = [r["y"] for r in val]
    platt = fit_platt(v_raw, v_y)

    def calibrated(x):
        p = m.raw(x)
        z = platt["a"] * p + platt["b"]
        return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))

    v_cal = [calibrated(r["x"]) for r in val]
    thr = thr_for_fp([s for s, y in zip(v_cal, v_y) if y == 0], TARGET_FP)

    t_cal = [calibrated(r["x"]) for r in test]
    t_y = [r["y"] for r in test]
    pos = [s for s, y in zip(t_cal, t_y) if y == 1]
    neg = [s for s, y in zip(t_cal, t_y) if y == 0]

    pr = pr_auc(pos, neg)
    roc = roc_auc(pos, neg)
    fp = sum(1 for s in neg if s >= thr) / max(1, len(neg))
    tp = sum(1 for s in pos if s >= thr) / max(1, len(pos))
    prec = (sum(1 for s in pos if s >= thr) /
            max(1, sum(1 for s in t_cal if s >= thr)))
    rec_ep, caught, tot = episode_recall(test, t_cal, thr)
    lo, hi = wilson(caught, tot)

    print(f"  порог под FP<= {TARGET_FP * 100:.0f}%:      {thr:.4f}")
    print(f"  PR-AUC  (главная при дисбалансе): {pr:.3f}")
    print(f"  ROC-AUC (для сравнимости):        {roc:.3f}")
    print(f"  событийный TPR / FPR:             {tp * 100:.1f}% / {fp * 100:.2f}%")
    print(f"  событийная precision:             {prec * 100:.1f}%")
    print(f"  ЭПИЗОДНЫЙ recall:                 {caught}/{tot} = {rec_ep * 100:.0f}% "
          f"[95% ДИ {lo * 100:.0f}–{hi * 100:.0f}%]")
    print(f"  Brier score (калибровка):         {brier(t_cal, t_y):.4f}")
    print("-" * 74)
    top = sorted(zip(m.w, ml_features.FEATURES), reverse=True)[:8]
    print("  Самые весомые признаки:")
    for w, name in top:
        print(f"    {name:26} {w:+.3f}")
    print("=" * 74)

    out = os.path.join(BASE, args.out) if not os.path.isabs(args.out) else args.out
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump({
        "features": ml_features.FEATURES,
        "w": m.w, "b": m.b, "mu": m.mu, "sd": m.sd,
        "threshold": thr, "platt": platt,
        "trained_on": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "seeds": seeds,
        "metrics": {"pr_auc": round(pr, 4), "roc_auc": round(roc, 4),
                    "tpr": round(tp, 4), "fpr": round(fp, 4),
                    "precision": round(prec, 4),
                    "episode_recall": round(rec_ep, 4),
                    "episode_recall_ci": [round(lo, 4), round(hi, 4)],
                    "brier": round(brier(t_cal, t_y), 5)},
    }, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print(f"  Модель: {os.path.relpath(out, BASE)}")
    print("  Детектор подхватит её при следующем старте (слой L2).")


if __name__ == "__main__":
    main()
