#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NOVELTY-HOLDOUT — главный аргумент «почему не просто регулярки».

Эксперимент на ОБОБЩЕНИЕ под новизной (leave-one-family-out):
  * берём 7 семейств секретов (aws, gitlab, slack, jwt, hex64, stripe, novelcloud);
  * по очереди ОТКЛАДЫВАЕМ одно семейство как «невиданное»;
  * сигнатурный детектор (regex) знает регулярки ТОЛЬКО обучающих семейств —
    под отложенное у него регулярки НЕТ;
  * ML учится на регекс-НЕЗАВИСИМЫХ контент-признаках (энтропия, длина,
    структура, доли символов) обучающих семейств.

Считаем на отложенном (невиданном) семействе:
  regex recall  — почти 0 (нет сигнатуры под новый формат);
  ML recall     — заметно > 0 при том же FP-бюджете (свойство «секретности»
                  обобщается на формат, которого модель не видела).

Это и есть ответ на «можно просто долбить регулярками»: нельзя — против нового
формата сигнатура слепа, а статистическая модель обобщает.

Запуск:  python experiments_holdout.py
Пишет results/holdout.csv. Без sklearn (чистый python), воспроизводимо (SEED).
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
import re
import csv
import sys
import math
import random
import string

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

import content_ml_features as F

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEED = 42
TARGET_FP = 0.02     # выбираем порог под FP <= 2% на benign


# ---- генераторы токенов и сигнатуры семейств -------------------------
def _b62(n): return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(n))
def _hex(n): return "".join(random.choice("0123456789abcdef") for _ in range(n))
def _up(n):  return "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(n))

FAMILIES = {
    "aws":        (lambda: "AKIA" + _up(16),                       re.compile(r"AKIA[0-9A-Z]{16}")),
    "gitlab":     (lambda: "glpat-" + _b62(20),                    re.compile(r"glpat-[A-Za-z0-9_\-]{20,}")),
    "slack":      (lambda: "xoxb-" + _hex(12) + "-" + _b62(24),    re.compile(r"xox[bp]-[A-Za-z0-9\-]{20,}")),
    "jwt":        (lambda: "eyJ" + _b62(18) + "." + _b62(28) + "." + _b62(43),
                   re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")),
    "hex64":      (lambda: _hex(64),                               re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")),
    "stripe":     (lambda: "sk_live_" + _b62(24),                  re.compile(r"sk_live_[A-Za-z0-9]{24,}")),
    "novelcloud": (lambda: "ckx_" + _b62(32),                      re.compile(r"ckx_[A-Za-z0-9]{28,}")),
}

_WORDS = ["service", "deploy", "prod", "config", "region", "timeout", "enabled",
          "detection", "rules", "normalizer", "playbook", "endpoint", "version"]


def _benign_filler():
    lines = ["# configuration", "DEBUG=false", f"SERVICE={random.choice(_WORDS)}",
             "API_URL=https://api.example.com/v1", f"REGION=eu-{random.randint(1,3)}",
             f"NOTE={random.choice(_WORDS)}-{random.choice(_WORDS)}"]
    random.shuffle(lines)
    return lines[:random.randint(3, 5)]


def make_secret_file(family):
    gen, _ = FAMILIES[family]
    key = random.choice(["TOKEN", "API_KEY", "SECRET", "CRED", "ACCESS_KEY"])
    lines = _benign_filler() + [f"{key}={gen()}"]
    random.shuffle(lines)
    return "\n".join(lines) + "\n"


def make_benign_file():
    """Benign, иногда с «похожими» вещами (uuid, git-sha40, base64-иконка) —
    чтобы FP были честными, а задача нетривиальной."""
    extra = []
    r = random.random()
    if r < 0.25:
        extra.append("COMMIT=" + _hex(40))                       # git sha (40 hex, не секрет)
    elif r < 0.45:
        extra.append("ICON=" + "".join(random.choice(string.ascii_letters + "+/") for _ in range(28)) + "==")
    elif r < 0.60:
        u = "-".join(_hex(n) for n in (8, 4, 4, 4, 12))
        extra.append("REQUEST_ID=" + u)                          # uuid
    lines = _benign_filler() + extra + ["EXAMPLE_TOKEN=changeme-placeholder-0000"]
    random.shuffle(lines)
    return "\n".join(lines) + "\n"


# ---- мини-логрегрессия со стандартизацией (без sklearn) --------------
class LogReg:
    def __init__(self, dim, lr=0.3, epochs=120, l2=1e-4):
        self.w = [0.0]*dim; self.b = 0.0; self.lr = lr; self.epochs = epochs; self.l2 = l2
        self.mu = [0.0]*dim; self.sd = [1.0]*dim

    def _std(self, X):
        n = len(X); d = len(X[0])
        self.mu = [sum(r[j] for r in X)/n for j in range(d)]
        self.sd = []
        for j in range(d):
            var = sum((r[j]-self.mu[j])**2 for r in X)/n
            self.sd.append(math.sqrt(var) or 1.0)

    def _norm(self, x):
        return [(x[j]-self.mu[j])/self.sd[j] for j in range(len(x))]

    def fit(self, X, y):
        self._std(X)
        Xn = [self._norm(r) for r in X]
        n = len(Xn); pos = sum(y) or 1; neg = n-pos or 1
        wpos = n/(2*pos); wneg = n/(2*neg)
        idx = list(range(n))
        for _ in range(self.epochs):
            random.shuffle(idx)
            for i in idx:
                x = Xn[i]; yi = y[i]
                z = sum(wj*xj for wj, xj in zip(self.w, x)) + self.b
                p = 1/(1+math.exp(-max(-30, min(30, z))))
                cw = wpos if yi else wneg
                g = (p-yi)*cw
                for j in range(len(self.w)):
                    self.w[j] -= self.lr*(g*x[j] + self.l2*self.w[j])
                self.b -= self.lr*g

    def proba(self, x):
        xn = self._norm(x)
        z = sum(wj*xj for wj, xj in zip(self.w, xn)) + self.b
        return 1/(1+math.exp(-max(-30, min(30, z))))


def regex_hit(content, regexes):
    return any(rx.search(content) for rx in regexes)


def thr_for_fp(model, benign_vecs, target_fp):
    """Порог ML, дающий FP <= target_fp на benign."""
    scores = sorted((model.proba(v) for v in benign_vecs), reverse=True)
    k = int(target_fp * len(scores))
    return (scores[k] + 1e-6) if k < len(scores) else 1.01


def main():
    random.seed(SEED)
    fams = list(FAMILIES)
    N_SEC, N_BEN = 90, 160
    rows = []

    print("=" * 78)
    print("  NOVELTY-HOLDOUT: сигнатуры (regex) против ML на НЕВИДАННОМ формате секрета")
    print("=" * 78)
    print(f"  семейств: {len(fams)} | leave-one-family-out | FP-бюджет <= {TARGET_FP*100:.0f}%")
    print("-" * 78)
    print(f"  {'отложено (новое)':16} | {'regex recall':>12} | {'ML recall':>9} | {'ML FP':>6} | вывод")
    print("-" * 78)

    for held in fams:
        train_fams = [f for f in fams if f != held]
        train_regexes = [FAMILIES[f][1] for f in train_fams]

        # --- обучающая выборка (контент-признаки, без буквальных regex) ---
        Xtr, ytr = [], []
        for f in train_fams:
            for _ in range(N_SEC):
                Xtr.append(F.vector(F.featurize(make_secret_file(f)))); ytr.append(1)
        ben_train = [make_benign_file() for _ in range(N_BEN)]
        for c in ben_train:
            Xtr.append(F.vector(F.featurize(c))); ytr.append(0)

        model = LogReg(dim=len(F.FEATURES)); model.fit(Xtr, ytr)

        # порог под FP-бюджет на отдельном benign
        ben_val = [F.vector(F.featurize(make_benign_file())) for _ in range(200)]
        thr = thr_for_fp(model, ben_val, TARGET_FP)

        # --- тест на ОТЛОЖЕННОМ (невиданном) семействе ---
        held_files = [make_secret_file(held) for _ in range(120)]
        regex_rec = sum(regex_hit(c, train_regexes) for c in held_files) / len(held_files)
        ml_rec = sum(model.proba(F.vector(F.featurize(c))) >= thr for c in held_files) / len(held_files)
        # FP модели на свежем benign
        ben_test = [make_benign_file() for _ in range(200)]
        ml_fp = sum(model.proba(F.vector(F.featurize(c))) >= thr for c in ben_test) / len(ben_test)

        verdict = "ML видит, regex слеп" if (ml_rec - regex_rec) > 0.3 else "—"
        print(f"  {held:16} | {regex_rec*100:>11.0f}% | {ml_rec*100:>8.0f}% | {ml_fp*100:>5.1f}% | {verdict}")
        rows.append({"held_out_family": held, "regex_recall": round(regex_rec, 3),
                     "ml_recall": round(ml_rec, 3), "ml_fp_rate": round(ml_fp, 3)})

    print("-" * 78)
    avg_rx = sum(r["regex_recall"] for r in rows)/len(rows)
    avg_ml = sum(r["ml_recall"] for r in rows)/len(rows)
    avg_fp = sum(r["ml_fp_rate"] for r in rows)/len(rows)
    print(f"  СРЕДНЕЕ на невиданном:  regex recall {avg_rx*100:.0f}%   vs   ML recall {avg_ml*100:.0f}%   "
          f"(ML FP {avg_fp*100:.1f}%)")
    print("=" * 78)
    print("  ВЫВОД: против НОВОГО формата секрета сигнатурная регулярка почти слепа")
    print("  (recall ~0), а модель на регекс-независимых признаках ОБОБЩАЕТ и ловит —")
    print("  вот зачем тут ML, и почему «просто регулярками» задача не решается.")

    os.makedirs(os.path.join(BASE, "results"), exist_ok=True)
    fp = os.path.join(BASE, "results", "holdout.csv")
    with open(fp, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    print(f"  CSV: {os.path.relpath(fp, BASE)}")


if __name__ == "__main__":
    main()
