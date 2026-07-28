# -*- coding: utf-8 -*-
"""
СТАТИСТИЧЕСКИЙ АППАРАТ ОЦЕНКИ.

Раньше все числа в работе были точечными оценками из одного прогона с
SEED=42: «recall 74.5%» без разброса и без проверки, отличается ли одна
конфигурация от другой значимо. Этот модуль закрывает пробел.

Что здесь:
  wilson()          — доверительный интервал для доли (интервал Уилсона).
                      Для recall 41/55 нормальное приближение уже некорректно,
                      а Уилсон работает и на малых выборках, и у границ 0/1.
  bootstrap_ci()    — интервал для произвольной статистики (MTTD, AUC).
  roc_auc()         — AUC по ROC (доля правильно упорядоченных пар).
  pr_auc()          — площадь под кривой точность-полнота. ГЛАВНАЯ метрика при
                      сильном дисбалансе: при доле атак ~0.4% ROC-AUC выглядит
                      прекрасно даже у бесполезного детектора, потому что
                      знаменатель FPR — огромное число нормальных событий.
  pr_curve()        — точки кривой для графика.
  mcnemar()         — тест значимости различия ДВУХ детекторов на ОДНИХ И ТЕХ ЖЕ
                      объектах (парные наблюдения). Именно он нужен для
                      ablation-таблицы: «full лучше rules_only» — это факт или
                      случайность?
  reliability()     — данные для калибровочной кривой (насколько заявленная
                      вероятность соответствует наблюдаемой частоте).
  brier()           — интегральная мера качества калибровки.

Без зависимостей (stdlib), чтобы считалось везде.
"""
import math
import random
import bisect


# ----------------------------------------------------------------------
def wilson(successes, total, z=1.96):
    """Доверительный интервал Уилсона для доли (по умолчанию 95%).

    Почему не «p ± z·sqrt(p(1-p)/n)»: нормальное приближение даёт интервалы,
    вылезающие за [0,1], и врёт при малых n или p близко к границам — а именно
    такие случаи здесь и встречаются (recall на 55 эпизодах, FP-rate ~1%).

    Возвращает (нижняя, верхняя).
    """
    if total <= 0:
        return (0.0, 0.0)
    p = successes / total
    d = 1.0 + z * z / total
    centre = (p + z * z / (2 * total)) / d
    half = (z / d) * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total))
    return (max(0.0, centre - half), min(1.0, centre + half))


def fmt_ci(successes, total, pct=True):
    """«74.5% [61.2–84.7%]» — готовая строка для таблиц и отчётов."""
    if total <= 0:
        return "n/a"
    p = successes / total
    lo, hi = wilson(successes, total)
    if pct:
        return f"{p*100:.1f}% [{lo*100:.1f}–{hi*100:.1f}%]"
    return f"{p:.3f} [{lo:.3f}–{hi:.3f}]"


def bootstrap_ci(values, stat=None, n_boot=2000, alpha=0.05, seed=42):
    """Перцентильный bootstrap-интервал для произвольной статистики.

    Используется там, где аналитической формулы нет: MTTD, AUC, средний риск.
    """
    if not values:
        return (0.0, 0.0)
    stat = stat or (lambda v: sum(v) / len(v))
    rnd = random.Random(seed)
    n = len(values)
    boots = []
    for _ in range(n_boot):
        sample = [values[rnd.randrange(n)] for _ in range(n)]
        boots.append(stat(sample))
    boots.sort()
    lo = boots[int(alpha / 2 * n_boot)]
    hi = boots[min(n_boot - 1, int((1 - alpha / 2) * n_boot))]
    return (lo, hi)


# ----------------------------------------------------------------------
def roc_auc(pos_scores, neg_scores):
    """AUC = доля пар (положительный > отрицательный); совпадения считаем за 0.5."""
    if not pos_scores or not neg_scores:
        return 0.0
    neg = sorted(neg_scores)
    below = 0.0
    for p in pos_scores:
        lo = bisect.bisect_left(neg, p)
        hi = bisect.bisect_right(neg, p)
        below += lo + 0.5 * (hi - lo)
    return below / (len(pos_scores) * len(neg))


def _grouped(pos_scores, neg_scores):
    """Точки, сгруппированные по одинаковому скору (важно для «связок»)."""
    pts = [(s, 1) for s in pos_scores] + [(s, 0) for s in neg_scores]
    pts.sort(key=lambda x: -x[0])
    groups = []
    i = 0
    while i < len(pts):
        j = i
        p = n = 0
        while j < len(pts) and pts[j][0] == pts[i][0]:
            p += pts[j][1]; n += 1 - pts[j][1]
            j += 1
        groups.append((pts[i][0], p, n))
        i = j
    return groups


def pr_curve(pos_scores, neg_scores):
    """Точки (recall, precision) по убыванию порога.

    Кривая начинается в recall = 0 (порог выше максимума скоров) — без этой
    точки численное интегрирование теряет первый и самый важный участок.
    """
    P = len(pos_scores)
    if P == 0:
        return []
    tp = fp = 0
    out = [(0.0, 1.0)]
    for _, p, n in _grouped(pos_scores, neg_scores):
        tp += p; fp += n
        out.append((tp / P, tp / max(1, tp + fp)))
    return out


def pr_auc(pos_scores, neg_scores):
    """Средняя точность (average precision) — площадь под кривой точность-полнота.

    При дисбалансе 1:250 это единственная честная интегральная метрика:
    базовый уровень PR-AUC равен доле положительного класса, поэтому
    «PR-AUC 0.35» при базе 0.004 — это очень много, а «ROC-AUC 0.95» может не
    значить почти ничего.

    Считается как Σ (Rₖ − Rₖ₋₁)·Pₖ, а не трапециями: трапеции на PR-кривой
    систематически завышают площадь, потому что кривая между точками не
    линейна. Одинаковые скоры («связки») обрабатываются группой — иначе
    идеальный разделитель с одинаковыми скорами внутри классов давал бы 0.
    """
    P = len(pos_scores)
    if P == 0 or not neg_scores:
        return 0.0
    tp = fp = 0
    ap = 0.0
    prev_recall = 0.0
    for _, p, n in _grouped(pos_scores, neg_scores):
        tp += p; fp += n
        recall = tp / P
        precision = tp / max(1, tp + fp)
        ap += (recall - prev_recall) * precision
        prev_recall = recall
    return ap


def baseline_pr(pos_n, neg_n):
    """Базовый уровень PR-AUC = доля положительного класса."""
    tot = pos_n + neg_n
    return pos_n / tot if tot else 0.0


# ----------------------------------------------------------------------
def mcnemar(a_hits, b_hits, exact_limit=25):
    """Тест Макнемара для ПАРНЫХ наблюдений: значимо ли A отличается от B.

    a_hits/b_hits — списки булевых исходов ОДНОЙ И ТОЙ ЖЕ длины по одним и тем
    же объектам (например, «эпизод пойман» для двух конфигураций детектора).

    Считаются только расхождения:
        b01 — A промахнулся, B поймал
        b10 — A поймал, B промахнулся
    При малом числе расхождений применяется точный биномиальный тест, иначе —
    приближение хи-квадрат с поправкой Йейтса.

    Возвращает (b01, b10, p_value).
    """
    if len(a_hits) != len(b_hits):
        raise ValueError("парный тест требует выборок одинаковой длины")
    b01 = sum(1 for a, b in zip(a_hits, b_hits) if (not a) and b)
    b10 = sum(1 for a, b in zip(a_hits, b_hits) if a and (not b))
    n = b01 + b10
    if n == 0:
        return (0, 0, 1.0)
    if n <= exact_limit:
        # точный двусторонний биномиальный тест при p=0.5
        k = min(b01, b10)
        tail = sum(math.comb(n, i) for i in range(0, k + 1)) / (2.0 ** n)
        return (b01, b10, min(1.0, 2.0 * tail))
    chi2 = (abs(b01 - b10) - 1.0) ** 2 / n
    # p для хи-квадрат с 1 степенью свободы = erfc(sqrt(chi2/2))
    return (b01, b10, math.erfc(math.sqrt(chi2 / 2.0)))


def holm(pvalues):
    """Поправка Холма на множественные сравнения.

    Когда в ablation сравнивается несколько пар конфигураций, вероятность
    случайно получить «значимое» различие растёт. Холм контролирует
    групповую ошибку и, в отличие от Бонферрони, не так консервативен.

    Возвращает список скорректированных p в исходном порядке.
    """
    m = len(pvalues)
    order = sorted(range(m), key=lambda i: pvalues[i])
    adj = [0.0] * m
    prev = 0.0
    for rank, i in enumerate(order):
        val = min(1.0, (m - rank) * pvalues[i])
        prev = max(prev, val)
        adj[i] = prev
    return adj


# ----------------------------------------------------------------------
def reliability(scores, labels, bins=10):
    """Калибровочная кривая: (средний прогноз, наблюдаемая частота, n) по бинам.

    Если модель откалибрована, точки лежат на диагонали: среди событий, которым
    присвоено 0.7, атаками действительно оказываются примерно 70%.
    """
    out = []
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        sel = [(s, y) for s, y in zip(scores, labels)
               if (s >= lo and (s < hi or (b == bins - 1 and s <= hi)))]
        if not sel:
            continue
        out.append((sum(s for s, _ in sel) / len(sel),
                    sum(y for _, y in sel) / len(sel),
                    len(sel)))
    return out


def ece(scores, labels, bins=10):
    """Expected Calibration Error — взвешенное отклонение от диагонали."""
    rel = reliability(scores, labels, bins)
    n = len(scores) or 1
    return sum(cnt / n * abs(conf - acc) for conf, acc, cnt in rel)


def brier(scores, labels):
    """Среднеквадратичная ошибка вероятностного прогноза."""
    if not scores:
        return 0.0
    return sum((s - y) ** 2 for s, y in zip(scores, labels)) / len(scores)
