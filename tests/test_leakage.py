#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ТЕСТ НА УТЕЧКУ РАЗМЕТКИ ЧЕРЕЗ ЗНАЧЕНИЯ ПРИЗНАКОВ.

Чем отличается от test_antileak.py
----------------------------------
`test_antileak` проверяет, что из события ВЫРЕЗАНЫ поля разметки: is_anomaly,
episode_id, technique_id и прочие «ответы». Эта проверка нужна, но её
недостаточно, и вот почему.

Раньше мир эмитил для каждого шага атаки собственное действие: `steal_oauth`,
`repo_enum`, `perm_discovery`, `mass_delete`, `exfil_altproto`. Ни одно из них
не встречалось у обычных сотрудников. Поля разметки при этом были честно
вырезаны — и test_antileak был зелёным. Но правило

    { "when": { "action": "steal_oauth" } }

не обнаруживало атаку, а ЧИТАЛО МЕТКУ под другим именем: знание «action ==
steal_oauth» полностью эквивалентно знанию «is_anomaly == true». Метрики,
измеренные на таком детекторе, не значили ничего.

Что проверяет этот тест
-----------------------
Для каждого наблюдаемого признака считается ВЗАИМНАЯ ИНФОРМАЦИЯ I(признак; метка)
и нормированная величина U = I / H(метка) — «неопределённость метки», снятая
одним признаком. Значения:

    U = 0    признак ничего не говорит о метке;
    U = 1    признак ПОЛНОСТЬЮ определяет метку — то есть является меткой.

Отдельно проверяется главное свойство: не должно существовать значения
признака, которое встречается ТОЛЬКО у атаки (или только у нормы) и при этом
встречается достаточно часто. Такое значение — метка-двойник.

Порог намеренно не нулевой: признаки ОБЯЗАНЫ нести информацию об атаке, иначе
детектирование невозможно. Недопустимо другое — когда одно значение признака
детерминирует ответ.

Запуск: python tests/test_leakage.py
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
import math
import random
import logging
import collections

logging.disable(logging.CRITICAL)
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

import run_defense
from workload import build_workload

OK = "✅"; BAD = "❌"

#: Доля событий, начиная с которой значение считается «часто встречающимся».
#: Значения реже этого — статистический шум, а не канал утечки.
MIN_SUPPORT = 0.002
#: Максимально допустимая доля снятой неопределённости для ОДНОГО признака.
MAX_UNCERTAINTY_COEFF = 0.35
#: Признаки, которые по своей природе близки к разметке и проверяются мягче —
#: их список должен оставаться коротким и осознанным.
EXPECTED_STRONG = set()


def _entropy(counter, n):
    h = 0.0
    for c in counter.values():
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def mutual_information(values, labels):
    """I(X; Y) в битах для дискретных X и Y."""
    n = len(values)
    if n == 0:
        return 0.0, 0.0
    cx = collections.Counter(values)
    cy = collections.Counter(labels)
    cxy = collections.Counter(zip(values, labels))
    hx = _entropy(cx, n)
    hy = _entropy(cy, n)
    hxy = _entropy(cxy, n)
    mi = hx + hy - hxy
    return max(0.0, mi), hy


def mi_corrected(values, labels, n_perm=12, seed=42):
    """Взаимная информация с поправкой на смещение по числу значений.

    Проблема. Выборочная оценка I(X;Y) СМЕЩЕНА ВВЕРХ, и тем сильнее, чем больше
    у X различных значений. Признак вроде `branch` (тысячи уникальных имён)
    показывает заметную «информацию» о метке даже когда связи нет вовсе —
    просто потому, что при большом числе категорий часть из них случайно
    оказывается в одном классе.

    Поправка. Оцениваем это смещение эмпирически: несколько раз перемешиваем
    метки (разрушая любую настоящую связь) и считаем I на перемешанных данных.
    Средняя величина — уровень шума для данной кардинальности. Значимой
    считается только надбавка над ним.

    Возвращает (I_скорректированная, H(Y), I_сырая, I_шум).
    """
    mi_raw, hy = mutual_information(values, labels)
    rnd = random.Random(seed)
    shuffled = list(labels)
    noise = 0.0
    for _ in range(n_perm):
        rnd.shuffle(shuffled)
        noise += mutual_information(values, shuffled)[0]
    noise /= max(1, n_perm)
    return max(0.0, mi_raw - noise), hy, mi_raw, noise


def _bucket(v):
    """Приводим значение к дискретной категории (числа — грубыми корзинами)."""
    if isinstance(v, bool) or v is None:
        return str(v)
    if isinstance(v, (int, float)):
        if v == 0:
            return "0"
        if v < 0:
            return "neg"
        return "1e%d" % int(math.log10(abs(v) + 1e-9))
    if isinstance(v, (list, tuple, set)):
        return "list:%d" % len(v)
    s = str(v)
    return s[:60]


def main():
    print("=" * 78)
    print("  ТЕСТ НА УТЕЧКУ РАЗМЕТКИ ЧЕРЕЗ ЗНАЧЕНИЯ ПРИЗНАКОВ")
    print("=" * 78)

    rows = []
    for evasion in ("noisy", "stealthy"):
        for r in build_workload(evasion=evasion, seed=42, days=10, per_day=220):
            if r.get("meta"):
                continue
            rows.append((run_defense.observed(r), 1 if r.get("is_anomaly") else 0))
    n = len(rows)
    n_pos = sum(y for _, y in rows)
    print(f"  событий: {n} | атакующих: {n_pos} ({n_pos / n * 100:.2f}%)")
    print("-" * 78)

    fields = collections.Counter()
    for ev, _ in rows:
        fields.update(ev.keys())
    fields = [f for f, c in fields.items()
              if c >= n * 0.01 and f not in ("_id", "ts_sim", "ts_real", "message")]

    fails = []
    report = []
    for f in sorted(fields):
        vals = [_bucket(ev.get(f)) for ev, _ in rows]
        labs = [y for _, y in rows]
        mi, hy, mi_raw, noise = mi_corrected(vals, labs)
        u = mi / hy if hy > 0 else 0.0
        u_raw = mi_raw / hy if hy > 0 else 0.0

        # ищем значения-детерминаторы: часто встречаются и бывают только у
        # одного класса
        per_val = collections.defaultdict(lambda: [0, 0])
        for v, y in zip(vals, labs):
            per_val[v][y] += 1

        # ПОЛЯ-ИДЕНТИФИКАТОРЫ проверяем только по скорректированной взаимной
        # информации. Имя ветки, номер MR, путь файла почти уникальны: любое
        # конкретное значение встречается у одного объекта, а значит
        # «встречается только у атаки» для них выполняется автоматически и
        # ничего не означает. Информативен здесь не отдельный идентификатор,
        # а совокупная связь — её и меряет MI с поправкой на кардинальность.
        cardinality = len(per_val) / n
        is_identifier = cardinality > 0.2

        determin = []
        if not is_identifier:
            determin = [(v, c0, c1) for v, (c0, c1) in per_val.items()
                        if (c0 + c1) >= MIN_SUPPORT * n and c0 == 0 and c1 > 0]

        report.append((u, f, len(determin), u_raw, is_identifier))
        if f not in EXPECTED_STRONG and u > MAX_UNCERTAINTY_COEFF:
            fails.append(f"{f}: снимает {u*100:.0f}% неопределённости метки")
        if determin:
            names = ", ".join(str(d[0]) for d in determin[:4])
            fails.append(f"{f}: значения только у атаки -> {names}")

    report.sort(reverse=True)
    print(f"  {'признак':22} | {'сырая':>7} | {'с поправкой':>11} | детерминаторов")
    print("-" * 78)
    for u, f, d, u_raw, ident in report[:18]:
        mark = BAD if (u > MAX_UNCERTAINTY_COEFF or d) else OK
        tag = "id-поле" if ident else str(d)
        print(f"  {mark} {f:20} | {u_raw*100:>6.1f}% | {u*100:>10.1f}% | {tag}")
    print("-" * 78)

    # отдельно и явно — самый важный признак
    acts = [ev.get("action") for ev, _ in rows]
    labs = [y for _, y in rows]
    per_act = collections.defaultdict(lambda: [0, 0])
    for a, y in zip(acts, labs):
        per_act[a][y] += 1
    only_attack = sorted(a for a, (c0, c1) in per_act.items() if c0 == 0 and c1 > 0)
    print(f"  Действий всего: {len(per_act)}")
    print(f"  Действий, встречающихся ТОЛЬКО у атаки: {len(only_attack)} "
          f"{only_attack if only_attack else ''}")
    print("=" * 78)

    if fails:
        print(f"  {BAD} УТЕЧКА ОБНАРУЖЕНА ({len(fails)}):")
        for x in fails:
            print(f"     - {x}")
        print()
        print("  Что делать: действие/атрибут, встречающийся только у атаки, —")
        print("  это метка под другим именем. Добавь такое же действие обычной")
        print("  команде (activities/ops_admin.py) или опиши шаг атаки")
        print("  действиями из taxonomy.OBSERVABLE.")
        return 1

    print(f"  {OK} Утечки нет: ни один наблюдаемый признак не определяет метку.")
    print("     Детектор обязан выводить технику из атрибутов, а не читать имя.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
