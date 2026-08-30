#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Проверка статистического аппарата оценки (stats.py).

Метрики в работе теперь снабжены доверительными интервалами и проверками
значимости, поэтому сам аппарат тоже должен быть покрыт тестами: ошибка в
формуле интервала обесценит все выводы разом.

Проверяются свойства, а не конкретные числа:
  • интервал Уилсона накрывает оценку и не вылезает за [0,1];
  • интервал сужается с ростом выборки;
  • PR-AUC у случайного классификатора ≈ доле положительного класса,
    а ROC-AUC ≈ 0.5 — это и есть иллюстрация, почему при дисбалансе смотрят
    на PR, а не на ROC;
  • Макнемар не видит различий там, где их нет, и видит там, где они есть;
  • поправка Холма монотонна и не уменьшает p-значения.

Запуск: python tests/test_stats.py
"""

# --- скрипт живёт в подпапке; движок проекта — в корне ---
import os as _os, sys as _sys
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
for _p in (_ROOT, _os.path.join(_ROOT, "tools"), _os.path.join(_ROOT, "research")):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
_os.chdir(_ROOT)
del _os, _sys

import sys
import random

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

import stats

OK = "✅"; BAD = "❌"
fails = []


def check(name, cond):
    print(f"  {OK if cond else BAD} {name}")
    if not cond:
        fails.append(name)


def test_wilson():
    lo, hi = stats.wilson(41, 55)
    p = 41 / 55
    check("Уилсон: интервал накрывает оценку", lo < p < hi)
    check("Уилсон: внутри [0,1]", 0.0 <= lo and hi <= 1.0)

    # вырожденные случаи, на которых нормальное приближение ломается
    lo0, hi0 = stats.wilson(0, 20)
    check("Уилсон при 0 успехов: нижняя = 0, верхняя > 0", lo0 == 0.0 and hi0 > 0.0)
    lo1, hi1 = stats.wilson(20, 20)
    check("Уилсон при 100%: верхняя = 1, нижняя < 1", hi1 == 1.0 and lo1 < 1.0)

    # с ростом выборки интервал сужается
    w_small = stats.wilson(5, 10)
    w_big = stats.wilson(500, 1000)
    check("Уилсон: интервал сужается с ростом n",
          (w_big[1] - w_big[0]) < (w_small[1] - w_small[0]))
    check("Уилсон: пустая выборка не падает", stats.wilson(0, 0) == (0.0, 0.0))


def test_auc_imbalance():
    """Главный методологический тезис: при дисбалансе ROC вводит в заблуждение."""
    rnd = random.Random(42)
    # случайный «детектор»: скоры не связаны с классом
    pos = [rnd.random() for _ in range(40)]
    neg = [rnd.random() for _ in range(4000)]
    roc = stats.roc_auc(pos, neg)
    pr = stats.pr_auc(pos, neg)
    base = stats.baseline_pr(len(pos), len(neg))
    check("ROC-AUC случайного ≈ 0.5", 0.42 < roc < 0.58)
    check("PR-AUC случайного ≈ доле класса", abs(pr - base) < 0.03)

    # идеальный детектор
    roc_p = stats.roc_auc([0.9] * 40, [0.1] * 4000)
    pr_p = stats.pr_auc([0.9] * 40, [0.1] * 4000)
    check("ROC-AUC идеального = 1", roc_p > 0.99)
    check("PR-AUC идеального = 1", pr_p > 0.98)

    # слабый детектор: ROC выглядит прилично, PR — нет
    pos_w = [rnd.gauss(0.6, 0.2) for _ in range(40)]
    neg_w = [rnd.gauss(0.4, 0.2) for _ in range(4000)]
    check("слабый детектор: ROC заметно выше PR",
          stats.roc_auc(pos_w, neg_w) - stats.pr_auc(pos_w, neg_w) > 0.3)


def test_mcnemar():
    same = [True] * 30 + [False] * 30
    b01, b10, p = stats.mcnemar(same, list(same))
    check("Макнемар: идентичные -> p = 1", p == 1.0 and b01 == 0 and b10 == 0)

    a = [False] * 40
    b = [True] * 30 + [False] * 10
    b01, b10, p = stats.mcnemar(a, b)
    check("Макнемар: явное различие -> p мал", p < 0.001 and b01 == 30 and b10 == 0)

    # симметричные расхождения = нет систематического различия
    a2 = [True] * 10 + [False] * 10
    b2 = [False] * 10 + [True] * 10
    _, _, p2 = stats.mcnemar(a2, b2)
    check("Макнемар: симметричные расхождения -> p велик", p2 > 0.5)

    try:
        stats.mcnemar([True], [True, False])
        check("Макнемар: разная длина -> ошибка", False)
    except ValueError:
        check("Макнемар: разная длина -> ошибка", True)


def test_holm():
    ps = [0.001, 0.02, 0.04, 0.9]
    adj = stats.holm(ps)
    check("Холм: p не уменьшаются", all(a >= b - 1e-12 for a, b in zip(adj, ps)))
    check("Холм: монотонность по рангу", adj[0] <= adj[1] <= adj[2] <= adj[3])
    check("Холм: не выходит за 1", all(a <= 1.0 for a in adj))


def test_calibration():
    # идеально откалиброванные прогнозы
    rnd = random.Random(7)
    scores, labels = [], []
    for _ in range(4000):
        p = rnd.random()
        scores.append(p)
        labels.append(1 if rnd.random() < p else 0)
    check("ECE откалиброванного мал", stats.ece(scores, labels) < 0.05)
    check("Brier откалиброванного ~1/6", 0.1 < stats.brier(scores, labels) < 0.25)

    # заведомо переуверенный прогноз
    bad = [0.99] * 2000 + [0.01] * 2000
    bad_y = [1 if i % 2 else 0 for i in range(4000)]
    check("ECE переуверенного велик", stats.ece(bad, bad_y) > 0.3)


def test_bootstrap():
    vals = [10.0] * 100
    lo, hi = stats.bootstrap_ci(vals, n_boot=200)
    check("bootstrap на константе даёт вырожденный интервал",
          abs(lo - 10.0) < 1e-9 and abs(hi - 10.0) < 1e-9)
    rnd = random.Random(3)
    noisy = [rnd.gauss(5.0, 1.0) for _ in range(400)]
    lo2, hi2 = stats.bootstrap_ci(noisy, n_boot=400)
    check("bootstrap накрывает среднее", lo2 < 5.0 < hi2)
    check("bootstrap на пустом не падает", stats.bootstrap_ci([]) == (0.0, 0.0))


def main():
    print("=" * 60)
    print("  ТЕСТЫ СТАТИСТИЧЕСКОГО АППАРАТА")
    print("=" * 60)
    test_wilson()
    test_auc_imbalance()
    test_mcnemar()
    test_holm()
    test_calibration()
    test_bootstrap()
    print("-" * 60)
    if fails:
        print(f"  {BAD} ПРОВАЛЕНО: {len(fails)} -> {fails}")
        return 1
    print(f"  {OK} Статистический аппарат корректен.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
