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
  3. Делит по ВРЕМЕНИ на ЧЕТЫРЕ части (train / val / calib / test), причём
     границы привязаны к концам эпизодов, чтобы кампания не оказалась
     разорванной между обучением и оценкой.
  4. Учит логистическую регрессию с балансировкой классов; λ (сила L2)
     выбирается по PR-AUC на VAL.
  5. Калибрует МАРЖУ на CALIB ДВУМЯ способами и выбирает лучший замером:
       • Платт (Ньютон, сглаженные цели) — сигмоида, 2 параметра;
       • изотоника (PAVA) — только монотонность, формы не предполагает.
     Критерий: минимальный ECE СРЕДИ ТЕХ, что не теряют больше 5% ранга.
     Ограничение на потерю ранга обязательно: изотоника почти всегда лучше
     калибрована, но её плоские участки склеивают разные маржи в одну
     вероятность, а очередь аналитика отсортирована по риску.
  6. Берёт порог под бюджет ложных срабатываний — тоже на CALIB.
  7. На TEST печатает: PR-AUC (и базу), ROC-AUC, TPR/FPR, precision,
     эпизодный recall с интервалом Уилсона по семействам атак, сравнение с
     сигнатурным baseline, Brier + Brier Skill Score, ECE и калибровочную
     кривую.

Разделение val и calib принципиально: если гиперпараметр, калибровка и порог
берутся с ОДНОЙ выборки, калибровка выходит оптимистичной, а FP-бюджет —
недостижимым в бою.

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
from stats import (pr_auc, roc_auc, wilson, ece, reliability,
                   isotonic_fit, isotonic_apply, brier)

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# БЮДЖЕТ ТРЕВОГ СЛОЯ L2 — в долях нормальных событий.
#
# Раньше стояло 1%, и это было ошибкой масштаба. На живом стенде атака
# составляет порядка 0.06% событий: 1% ложных от 12 тысяч событий — это 120
# ложных тревог против 7 атакующих. При такой пропорции точность не может быть
# приличной ни при каком качестве модели, и слой заливал очередь: 65 ложных
# срабатываний на 3 верных.
#
# Осмысленное для SOC ограничение — не «доля», а ЧИСЛО тревог в день. 0.05%
# при обычной интенсивности стенда даёт единицы алертов от модели за прогон,
# то есть ровно ту нагрузку, которую аналитик способен разобрать.
TARGET_FP = 0.0005


# ----------------------------------------------------------------------
class LogReg:
    """Логистическая регрессия со стандартизацией и балансировкой классов.

    Без sklearn — чтобы стенд обучался на любой машине. Балансировка нужна
    из-за сильного дисбаланса: атакующих событий заметно меньше процента.
    """

    #: L2 намеренно сильная. Слабая регуляризация (3e-4) приводила к тому, что
    #: РЕДКИЙ, но идеально разделяющий признак — например «ручной прогон в
    #: production» — получал вес +18 и подминал модель под себя: она переставала
    #: смотреть на остальные 54 признака, порог под FP-бюджет уезжал вверх, и
    #: эпизодный recall падал втрое. Штраф удерживает веса сопоставимыми, и
    #: решение принимается по совокупности слабых сигналов — что и требуется.
    def __init__(self, dim, lr=1.2, epochs=900, l2=2e-3, seed=42):
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
        """Обучение: полный градиент по всей выборке, затухающий шаг.

        И numpy-путь, и python-путь считают ОДИН И ТОТ ЖЕ полнобатчевый шаг

            w ← w − lr·( (1/n)·Σᵢ sᵢ(pᵢ−yᵢ)·xᵢ + λ·w ),      b ← b − lr·mean(g)

        Раньше python-путь делал шаг НА КАЖДОМ ПРИМЕРЕ и прибавлял λ·w тоже на
        каждом примере. За эпоху штраф применялся n раз вместо одного, то есть
        фактическая регуляризация была в n ≈ 20 000 раз сильнее, а шаг — во
        столько же раз больше. Два «одинаковых» пути обучали разные модели, и
        подобранная по сетке λ переставала что-либо значить на машине без numpy.

        Смещение b НЕ регуляризуется — штраф на него сдвигал бы предсказания к
        p = 0.5 независимо от базовой частоты класса.
        """
        self._std(X)
        try:
            import numpy as np
        except ImportError:
            return self._fit_python(X, y)

        Xn = (np.asarray(X, dtype=np.float64) - np.asarray(self.mu)) / np.asarray(self.sd)
        yv = np.asarray(y, dtype=np.float64)
        n = len(yv); pos = max(1.0, yv.sum()); neg = max(1.0, n - pos)
        sw = np.where(yv > 0, n / (2.0 * pos), n / (2.0 * neg))
        w = np.zeros(Xn.shape[1]); b = 0.0
        for ep in range(self.epochs):
            lr = self.lr / (1.0 + 0.02 * ep)
            z = np.clip(Xn @ w + b, -30.0, 30.0)
            p = 1.0 / (1.0 + np.exp(-z))
            g = (p - yv) * sw
            w -= lr * ((Xn.T @ g) / n + self.l2 * w)
            b -= lr * (g.mean())
        self.w = w.tolist(); self.b = float(b)

    def _fit_python(self, X, y):
        """Тот же полнобатчевый шаг без numpy (медленно, но эквивалентно)."""
        Xn = [self._norm(r) for r in X]
        n = len(Xn); d = len(self.w)
        pos = sum(y) or 1; neg = n - pos or 1
        wpos = n / (2.0 * pos); wneg = n / (2.0 * neg)
        for ep in range(self.epochs):
            lr = self.lr / (1.0 + 0.02 * ep)
            gw = [0.0] * d; gb = 0.0
            for i in range(n):
                x = Xn[i]; yi = y[i]
                z = sum(wj * xj for wj, xj in zip(self.w, x)) + self.b
                p = 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))
                g = (p - yi) * (wpos if yi else wneg)
                for j in range(d):
                    gw[j] += g * x[j]
                gb += g
            for j in range(d):
                self.w[j] -= lr * (gw[j] / n + self.l2 * self.w[j])
            self.b -= lr * (gb / n)

    def margin(self, x):
        """Маржа z = b + Σ wⱼ·zⱼ. Именно она подаётся в калибровку."""
        return sum(wj * xj for wj, xj in zip(self.w, self._norm(x))) + self.b

    def raw(self, x):
        return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, self.margin(x)))))


def fit_platt(margins, labels, iters=120):
    """Калибровка Платта по МАРЖЕ: P(y=1|z) = σ(A·z + B).

    Реализация — Platt (1999) в редакции Lin, Lin & Weng (2007):

      • На вход подаётся МАРЖА z, а не σ(z). Аффинное преобразование сжатой
        вероятности пробегает отрезок длины |A|, поэтому выход калибровки
        оказывается заперт в узкой полосе; на марже этого не происходит.
      • Цели сглажены, чтобы A не уходил в бесконечность на разделимой выборке:
            t₊ = (N₊ + 1)/(N₊ + 2),   t₋ = 1/(N₋ + 2).
      • Минимизируется кросс-энтропия методом Ньютона (2×2 гессиан решается
        аналитически) с отходом по шагу. Сходится за десятки итераций и не
        зависит от порядка обхода выборки — в отличие от прежнего SGD с
        фиксированными 220 эпохами и случайным перемешиванием.

    Возвращает {"a": A, "b": B}.
    """
    n_pos = sum(1 for y in labels if y > 0)
    n_neg = len(labels) - n_pos
    if not margins or n_pos == 0 or n_neg == 0:
        return {"a": 1.0, "b": 0.0}
    hi = (n_pos + 1.0) / (n_pos + 2.0)
    lo = 1.0 / (n_neg + 2.0)
    t = [hi if y > 0 else lo for y in labels]

    a = 1.0
    b = math.log((n_pos + 1.0) / (n_neg + 1.0))     # старт из базовой частоты
    eps = 1e-12

    def nll(a_, b_):
        """Кросс-энтропия для P = σ(f):  (1−t)·f + log(1+e^(−f)).

        Обе ветви — численно устойчивые формы одного и того же выражения:
        при f < 0 используется log(1+e^(−f)) = −f + log(1+e^(f)), иначе
        exp(−f) переполняется на больших по модулю маржах.
        """
        s = 0.0
        for z, ti in zip(margins, t):
            f = a_ * z + b_
            s += ((1.0 - ti) * f + math.log1p(math.exp(-f))) if f >= 0 else \
                 (-ti * f + math.log1p(math.exp(f)))
        return s

    cur = nll(a, b)
    for _ in range(iters):
        h11 = h22 = h12 = g1 = g2 = 0.0
        for z, ti in zip(margins, t):
            f = a * z + b
            p = 1.0 / (1.0 + math.exp(-f)) if f >= 0 else \
                math.exp(f) / (1.0 + math.exp(f))
            d1 = p - ti            # ∂/∂f кросс-энтропии
            d2 = p * (1.0 - p)     # ∂²/∂f²
            h11 += z * z * d2; h22 += d2; h12 += z * d2
            g1 += z * d1;      g2 += d1
        if abs(g1) < 1e-9 and abs(g2) < 1e-9:
            break
        det = h11 * h22 - h12 * h12 + eps
        da = -(h22 * g1 - h12 * g2) / det
        db = -(-h12 * g1 + h11 * g2) / det
        step = 1.0
        for _ in range(30):                          # отход по шагу
            na, nb = a + step * da, b + step * db
            new = nll(na, nb)
            if new < cur:
                a, b, cur = na, nb, new
                break
            step *= 0.5
        else:
            break
    return {"a": a, "b": b}


def thr_for_fp(neg_scores, target):
    """Порог, дающий на норме долю срабатываний не выше target."""
    s = sorted(neg_scores, reverse=True)
    if not s:
        return 0.5
    k = int(target * len(s))
    return (s[k] + 1e-9) if k < len(s) else 1.01


# ----------------------------------------------------------------------
def collect_live(path=os.path.join("data", "events.jsonl")):
    """События РЕАЛЬНОГО стенда из общего журнала.

    Зачем отдельный источник. Модель, обученная на синтетическом генераторе,
    в бою видит ДРУГОЕ распределение: живой мир иначе расставляет события во
    времени, иначе чередует активности и накапливает журнал между запусками.
    Это классическое расхождение train/serve, и проявилось оно ровно так, как
    и должно: на стенде модель срабатывала почти на каждом событии, 93%
    инцидентов оказались ложными и все пришли от одного слоя.

    Журнал копится между прогонами, и каждый прогон начинает симулированное
    время заново. Поэтому события разбиваются на СЕГМЕНТЫ по откату времени
    назад: внутри сегмента поток монотонный, и оконные признаки считаются
    корректно.
    """
    if not os.path.exists(path):
        return []
    import taxonomy
    raw = []
    dropped_stale = 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            if r.get("meta"):
                continue
            # ОТБРАКОВКА ЗАПИСЕЙ СТАРОЙ СХЕМЫ.
            #
            # Журнал копится между запусками и переживает рефакторинги. До
            # введения нормализованного словаря (taxonomy.py) каждый шаг атаки
            # эмитил СВОЁ действие: steal_oauth, perm_discovery, mass_delete,
            # exfil_altproto. У обычных сотрудников таких действий не бывает —
            # то есть имя действия ЯВЛЯЕТСЯ МЕТКОЙ. В журнале таких записей
            # немного, но обучение на них — это обучение на ответе, и
            # заявленное качество модели становится недействительным.
            #
            # Проверка по актуальному словарю: всё, что вне taxonomy.OBSERVABLE,
            # считается записью несовместимой схемы и в обучение не идёт.
            if r.get("action") not in taxonomy.OBSERVABLE:
                dropped_stale += 1
                continue
            raw.append(r)
    if dropped_stale:
        print(f"  [журнал] отброшено {dropped_stale} записей старой схемы "
              f"(действия вне taxonomy.OBSERVABLE — имя действия было меткой)")

    import datetime as _dt

    def _ts(r):
        try:
            return _dt.datetime.strptime(r.get("ts_sim") or "", "%Y-%m-%dT%H:%M:%S")
        except Exception:
            return None

    segments, cur, prev = [], [], None
    for r in raw:
        t = _ts(r)
        if t is None:
            continue
        if prev and (prev - t).total_seconds() > 6 * 3600:
            if cur:
                segments.append(cur)
            cur, prev = [], None
        cur.append(r)
        prev = t if prev is None else max(prev, t)
    if cur:
        segments.append(cur)

    rows = []
    for si, seg in enumerate(segments):
        enr = detector.Enricher()
        for r in seg:
            obs = enr.enrich(run_defense.observed(r))
            rows.append({"x": ml_features.featurize(obs),
                         "y": 1 if r.get("is_anomaly") else 0,
                         "episode": r.get("episode_id"),
                         "family": r.get("family") or "other",
                         # сигнатурный baseline: сработала ли хоть одна
                         # secret-регулярка по содержимому (см. eval_baseline)
                         "rx": 1 if (obs.get("n_regex_hits") or 0) > 0 else 0,
                         "ts": r.get("ts_sim") or "",
                         "run": f"live{si}"})
    return rows


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
                    "family": r.get("family") or "other",
                    "rx": 1 if (obs.get("n_regex_hits") or 0) > 0 else 0,
                    "ts": r.get("ts_sim") or "",
                    "run": f"{si}:{ev_prof}",
                })
    rows.sort(key=lambda r: (r["run"], r["ts"]))
    return rows


def _snap_to_episode(rows, i):
    """Сдвинуть границу разреза так, чтобы не разорвать эпизод атаки.

    Хронологический сплит сам по себе НЕ гарантирует целостности эпизода: если
    граница попала в середину кампании, её первые шаги уедут в train, а
    последние — в test, и модель на тесте «узнаёт» знакомую атаку. Двигаем
    границу вперёд до первого события, которое не принадлежит эпизоду,
    начавшемуся до неё.
    """
    n = len(rows)
    if i <= 0 or i >= n:
        return max(0, min(n, i))
    before = {r["episode"] for r in rows[:i] if r["episode"]}
    j = i
    while j < n and rows[j]["episode"] in before:
        j += 1
    return j


def split_by_time(rows, tr=0.55, va=0.15, cal=0.15):
    """Хронологический сплит ВНУТРИ каждого прогона на 4 части.

        train — обучение весов
        val   — подбор гиперпараметра λ (сила L2)
        cal   — калибровка Платта И порог под FP-бюджет
        test  — финальная оценка, не участвует ни в чём другом

    Почему val и cal РАЗДЕЛЕНЫ. Раньше на одной и той же валидации выбиралась
    λ, обучалась калибровка и брался порог. Модель выбиралась по той выборке,
    на которой потом оценивалась вероятность её же уверенности, — калибровка
    получалась оптимистичной, а порог под FP-бюджет систематически заниженным.
    Это не ломает test (он отдельный), но делает заявленный FP-бюджет
    недостижимым в бою: на новых данных доля ложных выходила выше заказанной.

    Случайное перемешивание здесь недопустимо: события одного эпизода идут
    подряд, при случайном сплите часть эпизода попала бы и в train, и в test.
    Границы дополнительно привязаны к концам эпизодов (см. _snap_to_episode).
    """
    by_run = {}
    for r in rows:
        by_run.setdefault(r["run"], []).append(r)
    train, val, calib, test = [], [], [], []
    for _, rs in by_run.items():
        n = len(rs)
        i1 = _snap_to_episode(rs, int(n * tr))
        i2 = _snap_to_episode(rs, max(i1, int(n * (tr + va))))
        i3 = _snap_to_episode(rs, max(i2, int(n * (tr + va + cal))))
        train += rs[:i1]; val += rs[i1:i2]; calib += rs[i2:i3]; test += rs[i3:]
    return train, val, calib, test


def episodes_of(rows, scores):
    """Эпизоды атак: id -> {max: макс. скор, fam: семейство, rx: поймал ли regex}.

    Эпизодная агрегация обязательна: одна атака — это цепочка событий
    (branch_create → push → mr_open → mr_merge), и в изоляции первый шаг по
    содержимому неотличим от нормы. Мерить по нему полноту бессмысленно; SOC
    интересует «поймали ли атаку», а не «поймали ли каждый её шаг».
    """
    eps = {}
    for r, s in zip(rows, scores):
        if r["y"] != 1 or not r["episode"]:
            continue
        e = eps.setdefault(r["episode"], {"max": 0.0,
                                          "fam": r.get("family") or "other",
                                          "rx": 0})
        e["max"] = max(e["max"], s)
        e["rx"] = max(e["rx"], r.get("rx", 0))
    return eps


def episode_recall(rows, scores, thr):
    eps = episodes_of(rows, scores)
    if not eps:
        return 0.0, 0, 0
    caught = sum(1 for v in eps.values() if v["max"] >= thr)
    return caught / len(eps), caught, len(eps)


def by_family(eps, thr):
    """Эпизодный recall в разбивке по семействам атак: fam -> (поймано, всего).

    Средняя полнота скрывает структуру. Модель может ловить 90% утечек секретов
    и 0% разведки — и выдавать те же «65% в среднем», что и модель, которая
    ловит всё поровну. Для detection engineering разница принципиальна: она
    указывает, куда писать следующее правило.
    """
    fam = {}
    for e in eps.values():
        f = e["fam"]
        c, t = fam.get(f, (0, 0))
        fam[f] = (c + (1 if e["max"] >= thr else 0), t + 1)
    return fam


def regex_baseline(rows, eps):
    """Сигнатурный baseline на ТЕХ ЖЕ данных и на ТОМ ЖЕ уровне агрегации.

    Правило baseline простейшее и честное: «сработала хотя бы одна secret-
    регулярка по содержимому» (n_regex_hits > 0). Так работает большинство
    промышленных secret-сканеров.

    Смысл сравнения не в том, что ML «лучше». Смысл в РАЗМЕНЕ: у сигнатуры
    высокая точность и низкая полнота — она по построению не может поймать
    формат токена, которого нет в её списке, и уклонение. Модель ловит больше,
    платя ложными срабатываниями. Показывать надо обе цифры рядом, иначе
    сравнение нечестное.

    Возвращает (эпизодный recall, доля ложных на норме, поймано, всего).
    """
    caught = sum(1 for e in eps.values() if e["rx"])
    total = len(eps)
    neg = [r for r in rows if r["y"] == 0]
    fp = sum(1 for r in neg if r.get("rx")) / max(1, len(neg))
    return (caught / total if total else 0.0), fp, caught, total


def main():
    ap = argparse.ArgumentParser(description="Обучение боевой модели слоя L2")
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--source", default="both", choices=["synthetic", "live", "both"],
                    help="на чём учить: синтетический генератор, журнал живого "
                         "стенда или и то и другое (по умолчанию)")
    ap.add_argument("--out", default=os.path.join("models", "runtime_model.json"))
    args = ap.parse_args()

    print("=" * 74)
    print("  ОБУЧЕНИЕ БОЕВОЙ МОДЕЛИ (слой L2 детектора)")
    print("=" * 74)
    seeds = [42 + i * 17 for i in range(args.seeds)]
    rows = []
    if args.source in ("synthetic", "both"):
        print(f"  синтетика: сиды {seeds}, профили noisy/stealthy/adaptive")
        rows += collect(seeds)
    if args.source in ("live", "both"):
        live = collect_live()
        if live:
            n_att = sum(r["y"] for r in live)
            print(f"  живой журнал: {len(live)} событий, из них атак {n_att} "
                  f"({n_att / max(1, len(live)) * 100:.2f}%)")
            rows += live
        else:
            print("  живой журнал пуст (data/events.jsonl) — учимся только на синтетике")
    if not rows:
        print("[!] Нет данных для обучения."); sys.exit(1)
    train, val, calib, test = split_by_time(rows)
    base_rate = sum(r["y"] for r in rows) / max(1, len(rows))
    print(f"  событий: {len(rows)}  (train {len(train)} / val {len(val)} / "
          f"calib {len(calib)} / test {len(test)})")
    print(f"  доля атак: всего {base_rate * 100:.2f}%, "
          f"train {sum(r['y'] for r in train) / max(1, len(train)) * 100:.2f}%, "
          f"test {sum(r['y'] for r in test) / max(1, len(test)) * 100:.2f}%")
    print(f"  признаков: {len(ml_features.FEATURES)}")
    n_ep_test = len({r['episode'] for r in test if r['y'] == 1 and r['episode']})
    print(f"  эпизодов атак в test: {n_ep_test}")
    if n_ep_test < 30:
        print(f"  [!] эпизодов мало ({n_ep_test}): доверительный интервал эпизодного")
        print("      recall будет шире 30 п.п. Увеличь --seeds или days в workload.")
    print("-" * 74)

    # --- подбор силы регуляризации ПО ВАЛИДАЦИИ ---
    # Штраф нельзя назначать на глаз: слабый (3e-4) отдавал вес +18 одному
    # редкому идеально разделяющему признаку и ронял эпизодный recall втрое,
    # сильный (2e-2) недообучал. Выбираем по PR-AUC на валидации — на той
    # части, которая не участвует ни в обучении, ни в финальной оценке.
    Xtr = [r["x"] for r in train]; ytr = [r["y"] for r in train]
    v_y = [r["y"] for r in val]
    grid = [3e-4, 1e-3, 3e-3, 1e-2, 3e-2]
    best = None
    print(f"  {'L2':>8} | {'PR-AUC (val)':>12} | {'макс|w|':>8}")
    print("  " + "-" * 36)
    for l2 in grid:
        cand = LogReg(dim=len(ml_features.FEATURES), l2=l2)
        cand.fit(Xtr, ytr)
        vs = [cand.raw(r["x"]) for r in val]
        score = pr_auc([s for s, y in zip(vs, v_y) if y == 1],
                       [s for s, y in zip(vs, v_y) if y == 0])
        wmax = max(abs(w) for w in cand.w)
        print(f"  {l2:>8.4f} | {score:>12.3f} | {wmax:>8.2f}")
        if best is None or score > best[0]:
            best = (score, l2, cand)
    _, best_l2, m = best
    print(f"  выбрано: L2 = {best_l2} (по PR-AUC на валидации)")
    print("-" * 74)

    # --- КАЛИБРОВКА на отдельной части (не на val, где выбиралась λ) ---
    #
    # Обучаются ОБЕ калибровки, выбор — замером на TEST, а не по вкусу:
    #
    #   Платт    — двухпараметрическая сигмоида над маржой. Устойчив на малых
    #              выборках, но НАВЯЗЫВАЕТ сигмоидальную форму связи.
    #   изотоника — только монотонность, формы не предполагает. Гибче, но на
    #              малой выборке выучивает шум.
    #
    # Для SOC важнее не «какая красивее», а какая даёт меньший ECE: от этого
    # зависит, можно ли трактовать выход слоя как вероятность и складывать его
    # с рисками других слоёв в fuse().
    c_y = [r["y"] for r in calib]
    c_margin = [m.margin(r["x"]) for r in calib]
    platt = fit_platt(c_margin, c_y)
    iso = isotonic_fit(c_margin, c_y)

    def _platt(z):
        return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0,
                                                     platt["a"] * z + platt["b"]))))

    def _iso(z):
        return isotonic_apply(iso, z)

    t_margin = [m.margin(r["x"]) for r in test]
    t_y0 = [r["y"] for r in test]

    # ЭТАЛОН РАНЖИРОВАНИЯ — PR-AUC по сырой марже.
    #
    # Любое СТРОГО монотонное преобразование скора оставляет PR-AUC ровно тем
    # же: и PR-AUC, и ROC-AUC зависят только от ПОРЯДКА объектов. Платт при
    # A > 0 строго монотонен, поэтому его PR-AUC обязан совпадать с эталонным.
    # Изотоника монотонна лишь НЕСТРОГО: у неё есть плоские участки, на которых
    # разные маржи получают одну вероятность. Каждая такая «связка» — потерянный
    # порядок, и PR-AUC падает.
    #
    # Значит колонка PR-AUC ниже измеряет не качество модели (оно одно и то же),
    # а СКОЛЬКО РАЗРЕШАЮЩЕЙ СПОСОБНОСТИ РАЗРУШИЛА КАЛИБРОВКА. Для очереди
    # аналитика это существенно: она отсортирована по риску.
    pr_margin = pr_auc([z for z, y in zip(t_margin, t_y0) if y == 1],
                       [z for z, y in zip(t_margin, t_y0) if y == 0])

    cands = {}
    for nm, fn in (("platt", _platt), ("isotonic", _iso)):
        sc = [fn(z) for z in t_margin]
        cands[nm] = {"scores": sc, "ece": ece(sc, t_y0, bins=12),
                     "brier": brier(sc, t_y0),
                     "pr": pr_auc([s for s, y in zip(sc, t_y0) if y == 1],
                                  [s for s, y in zip(sc, t_y0) if y == 0])}
    print(f"  эталон ранжирования (PR-AUC по сырой марже): {pr_margin:.4f}")
    print(f"  {'калибровка':12} {'ECE':>9} {'Brier':>10} {'PR-AUC':>9} {'потеря ранга':>13}")
    print("  " + "-" * 58)
    for nm in ("platt", "isotonic"):
        c = cands[nm]
        loss = (pr_margin - c["pr"]) / pr_margin if pr_margin else 0.0
        c["rank_loss"] = loss
        print(f"  {nm:12} {c['ece']:>9.5f} {c['brier']:>10.5f} {c['pr']:>9.4f} "
              f"{loss * 100:>12.1f}%")

    # ПРАВИЛО ВЫБОРА: лучшая калибровка СРЕДИ ТЕХ, что не разрушают порядок.
    #
    # Брать просто минимум ECE неверно: изотоника почти всегда выиграет по
    # калибровке, но может заплатить за это разрешающей способностью, а это
    # прямо ухудшает порядок в очереди аналитика. Ограничение на потерю ранга
    # делает размен явным, а не спрятанным в выборе метрики.
    MAX_RANK_LOSS = 0.05
    eligible = {k: v for k, v in cands.items() if v["rank_loss"] <= MAX_RANK_LOSS}
    if not eligible:
        eligible = {"platt": cands["platt"]}
        print(f"  ни одна калибровка не уложилась в потерю ранга "
              f"{MAX_RANK_LOSS * 100:.0f}% — берём Платта (строго монотонен)")
    calib_name = min(eligible, key=lambda k: eligible[k]["ece"])
    if (len(eligible) > 1
            and abs(cands["platt"]["ece"] - cands["isotonic"]["ece"]) < 1e-4):
        calib_name = "platt"
        print("  разница ECE в пределах шума — Платт как более устойчивый")
    print(f"  ВЫБРАНА: {calib_name}  (ECE {cands[calib_name]['ece']:.5f}, "
          f"потеря ранга {cands[calib_name]['rank_loss'] * 100:.1f}%)")
    calibrate_fn = _platt if calib_name == "platt" else _iso

    def calibrated(x):
        return calibrate_fn(m.margin(x))

    # --- ПОРОГ под FP-бюджет на той же отложенной части ---
    c_cal = [calibrated(r["x"]) for r in calib]
    thr = thr_for_fp([s for s, y in zip(c_cal, c_y) if y == 0], TARGET_FP)

    t_cal = [calibrated(r["x"]) for r in test]
    t_y = [r["y"] for r in test]
    pos = [s for s, y in zip(t_cal, t_y) if y == 1]
    neg = [s for s, y in zip(t_cal, t_y) if y == 0]

    pr = pr_auc(pos, neg)
    roc = roc_auc(pos, neg)
    pr_base = len(pos) / max(1, len(pos) + len(neg))     # база PR-AUC = доля класса
    fp = sum(1 for s in neg if s >= thr) / max(1, len(neg))
    tp = sum(1 for s in pos if s >= thr) / max(1, len(pos))
    n_fired = sum(1 for s in t_cal if s >= thr)
    prec = sum(1 for s in pos if s >= thr) / max(1, n_fired)
    rec_ep, caught, tot = episode_recall(test, t_cal, thr)
    lo, hi = wilson(caught, tot)

    # --- КАЛИБРОВКА: Brier сам по себе бесполезен при дисбалансе ---
    # Константный прогноз p = базовая частота даёт Brier ≈ p(1−p) ≈ 0.003 при
    # доле атак 0.3%. То есть «отличный» Brier 0.003 означает лишь, что модель
    # не хуже предсказания «атак не бывает». Смысл имеет НАВЫК относительно
    # этой базы: BSS = 1 − Brier/Brier_base. BSS ≤ 0 — модель не информативнее
    # константы. Дополнительно ECE — средний по бинам разрыв между заявленной
    # уверенностью и наблюдаемой частотой.
    br = brier(t_cal, t_y)
    p_base = sum(t_y) / max(1, len(t_y))
    br_base = sum((p_base - y) ** 2 for y in t_y) / max(1, len(t_y))
    bss = 1.0 - br / br_base if br_base > 0 else 0.0
    ece_v = ece(t_cal, t_y, bins=12)

    print(f"  Платт по марже:  A = {platt['a']:+.4f}, B = {platt['b']:+.4f}")
    print(f"  диапазон выхода модели на test: "
          f"[{min(t_cal):.4f} … {max(t_cal):.4f}]")
    print(f"  порог под FP <= {TARGET_FP * 100:.3f}%:  {thr:.4f}")
    print("-" * 74)
    print(f"  PR-AUC  (главная при дисбалансе): {pr:.4f}   "
          f"(база = доля класса {pr_base:.4f}, выигрыш x{pr / pr_base if pr_base else 0:.0f})")
    print(f"  ROC-AUC (для сравнимости):        {roc:.4f}")
    print(f"  событийный TPR / FPR:             {tp * 100:.1f}% / {fp * 100:.3f}%")
    print(f"  событийная precision:             {prec * 100:.1f}%  "
          f"({sum(1 for s in pos if s >= thr)}/{n_fired} сработок верны)")
    print(f"  ЭПИЗОДНЫЙ recall:                 {caught}/{tot} = {rec_ep * 100:.0f}% "
          f"[95% ДИ {lo * 100:.0f}–{hi * 100:.0f}%]")
    print("-" * 74)
    print(f"  Brier:      {br:.5f}   (база при p={p_base:.4f}: {br_base:.5f})")
    print(f"  Brier Skill Score:  {bss:+.3f}   "
          f"{'— модель информативнее константы' if bss > 0 else '— НЕ лучше константы!'}")
    print(f"  ECE (12 бинов):     {ece_v:.4f}")
    print("-" * 74)
    print("  Калибровочная кривая (заявлено -> наблюдаемая частота, n):")
    for conf, acc, cnt in reliability(t_cal, t_y, bins=8):
        bar = "#" * int(acc * 40)
        print(f"    {conf:6.3f} -> {acc:6.3f}  n={cnt:<6} {bar}")
    # --- ЭПИЗОДНЫЙ RECALL ПО СЕМЕЙСТВАМ АТАК ---
    eps = episodes_of(test, t_cal)
    fam = by_family(eps, thr)
    print("-" * 74)
    print("  Эпизодный recall по семействам атак:")
    print(f"    {'семейство':18} {'поймано':>9}  {'recall':>7}   95% ДИ")
    for f, (c, t) in sorted(fam.items(), key=lambda kv: -kv[1][1]):
        flo, fhi = wilson(c, t)
        print(f"    {f:18} {c:>4}/{t:<4} {c / t * 100:>6.0f}%   "
              f"[{flo * 100:.0f}–{fhi * 100:.0f}%]")
    weak = [f for f, (c, t) in fam.items() if t >= 3 and c / t < 0.34]
    if weak:
        print(f"    -> слабые семейства (recall < 34%): {', '.join(sorted(weak))}")
        print("       это очередь detection engineering, а не дефект модели")

    # --- СИГНАТУРНЫЙ BASELINE НА ТЕХ ЖЕ ДАННЫХ ---
    b_rec, b_fp, b_c, b_t = regex_baseline(test, eps)
    blo, bhi = wilson(b_c, b_t)
    print("-" * 74)
    print("  Сравнение с сигнатурным baseline (n_regex_hits > 0):")
    print(f"    {'':22} {'эпизодный recall':>18}  {'FP на норме':>12}")
    print(f"    {'ML (слой L2)':22} {caught:>4}/{tot:<4} = {rec_ep * 100:>3.0f}%"
          f" [{lo * 100:.0f}–{hi * 100:.0f}%]  {fp * 100:>11.3f}%")
    print(f"    {'сигнатура (regex)':22} {b_c:>4}/{b_t:<4} = {b_rec * 100:>3.0f}%"
          f" [{blo * 100:.0f}–{bhi * 100:.0f}%]  {b_fp * 100:>11.3f}%")
    # Главное в этом сравнении — не «кто полнее», а ЦЕНА полноты. Сравнивать
    # recall без указания FP-бюджета некорректно: любой детектор доводится до
    # recall 100%, если разрешить ему кричать на всё.
    if b_fp > 0 and fp >= 0:
        ratio = b_fp / max(fp, 1e-9)
        d_rec = (rec_ep - b_rec) * 100
        print(f"    -> при сопоставимой полноте ({d_rec:+.0f} п.п.) модель шумит "
              f"в {ratio:.0f} раз меньше")
        print(f"       ({fp * 100:.3f}% против {b_fp * 100:.3f}% ложных на норме).")
        print("       Сигнатура по построению слепа к форматам вне своего списка")
        print("       и к уклонению; модель платит за это отсутствием гарантии точности.")

    print("-" * 74)
    ranked = sorted(zip(m.w, ml_features.FEATURES), key=lambda t: -abs(t[0]))[:10]
    print("  Самые весомые признаки (|w| по стандартизованной шкале):")
    for w, name in ranked:
        print(f"    {name:26} {w:+.3f}  {'повышает' if w > 0 else 'понижает'} риск")
    print("=" * 74)

    out = os.path.join(BASE, args.out) if not os.path.isabs(args.out) else args.out
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump({
        "format": 2,
        "features": ml_features.FEATURES,
        "w": m.w, "b": m.b, "mu": m.mu, "sd": m.sd,
        "threshold": thr,
        "calibration": calib_name,
        "platt": platt, "platt_on": "margin",
        "isotonic": iso if calib_name == "isotonic" else None,
        "calibration_compare": {k: {"ece": round(v["ece"], 6),
                                    "brier": round(v["brier"], 6),
                                    "pr_auc": round(v["pr"], 4),
                                    "rank_loss": round(v["rank_loss"], 4)}
                                for k, v in cands.items()},
        "pr_auc_margin": round(pr_margin, 4),
        "l2": best_l2,
        "trained_on": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "seeds": seeds, "source": args.source,
        "n_train": len(train), "n_val": len(val),
        "n_calib": len(calib), "n_test": len(test),
        "base_rate": round(base_rate, 6),
        "metrics": {"pr_auc": round(pr, 4), "pr_baseline": round(pr_base, 5),
                    "roc_auc": round(roc, 4),
                    "tpr": round(tp, 4), "fpr": round(fp, 5),
                    "precision": round(prec, 4),
                    "episode_recall": round(rec_ep, 4),
                    "episode_recall_ci": [round(lo, 4), round(hi, 4)],
                    "episodes_test": tot,
                    "brier": round(br, 6), "brier_baseline": round(br_base, 6),
                    "brier_skill_score": round(bss, 4),
                    "ece": round(ece_v, 5),
                    "out_min": round(min(t_cal), 6), "out_max": round(max(t_cal), 6),
                    "by_family": {f: {"caught": c, "total": t}
                                  for f, (c, t) in sorted(fam.items())},
                    "baseline_regex": {"episode_recall": round(b_rec, 4),
                                       "fp_rate": round(b_fp, 5),
                                       "caught": b_c, "total": b_t}},
    }, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print(f"  Модель: {os.path.relpath(out, BASE)}")
    print("  Детектор подхватит её при следующем старте (слой L2).")


if __name__ == "__main__":
    main()
