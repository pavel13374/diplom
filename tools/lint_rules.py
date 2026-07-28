#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ЛИНТЕР ПРАВИЛ ДЕТЕКТИРОВАНИЯ.

Правила лежат в detections/*.json и правятся руками — значит, их надо
проверять так же, как код. Линтер ловит ошибки, которые уже случались:

  • правило из ОДНОГО условия по `action` — это не детектор, а считыватель
    метки (см. taxonomy.py). Именно так были написаны 19 из 38 правил;
  • условие на действие, которого нет в нормализованном словаре — верный
    признак, что шаг атаки описан «говорящим» действием;
  • ссылка на технику вне модели угроз (attack_matrix.py) — покрытие
    посчиталось бы по несуществующему знаменателю;
  • отсутствующие обязательные поля, дублирующиеся id, risk вне [0,1];
  • отсутствие поля `rationale` — почему правило вообще срабатывает.

Запуск: python tools/lint_rules.py
Код возврата 1 при ошибках — годится для CI.
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
import glob

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

import taxonomy
from attack_matrix import all_techniques

REQUIRED = ("id", "title", "technique", "tactic", "severity", "risk", "when")
SEVERITIES = {"low", "medium", "high", "critical"}
VALID_OPS = {">=", ">", "<=", "<", "ne", "in", "nin",
             "contains", "contains_any", "is_null"}

#: Поля-агрегаты, которые добавляет detector.Enricher.
DERIVED = {"burst_file_delete_10m", "burst_branch_delete_30m", "burst_api_read_15m",
           "api_items_sum_15m", "distinct_api_paths_15m", "burst_any_30m",
           "distinct_projects_1h"}

#: Базовые поля события (events.emit) + признаки содержимого.
BASE_FIELDS = {"action", "actor", "role", "project", "branch", "path", "mr_iid",
               "target", "message", "hour", "weekday", "is_night", "is_weekend",
               "ts_sim", "lines", "bytes", "ext"}


def main():
    errors, warnings = [], []
    seen_ids = {}
    matrix = all_techniques()
    files = sorted(glob.glob(os.path.join("detections", "*.json")))

    print("=" * 74)
    print("  ЛИНТЕР ПРАВИЛ ДЕТЕКТИРОВАНИЯ")
    print("=" * 74)
    print(f"  файлов: {len(files)}")

    for fp in files:
        name = os.path.basename(fp)
        try:
            r = json.load(open(fp, encoding="utf-8"))
        except Exception as e:
            errors.append(f"{name}: не разбирается как JSON ({e})")
            continue

        for k in REQUIRED:
            if k not in r:
                errors.append(f"{name}: нет обязательного поля '{k}'")
        rid = r.get("id")
        if rid in seen_ids:
            errors.append(f"{name}: id '{rid}' уже занят файлом {seen_ids[rid]}")
        seen_ids[rid] = name

        if rid and os.path.splitext(name)[0] != rid:
            warnings.append(f"{name}: имя файла не совпадает с id '{rid}'")

        risk = r.get("risk")
        if not isinstance(risk, (int, float)) or not (0.0 < risk <= 1.0):
            errors.append(f"{name}: risk={risk} вне диапазона (0, 1]")

        if r.get("severity") not in SEVERITIES:
            errors.append(f"{name}: severity='{r.get('severity')}' вне {sorted(SEVERITIES)}")

        tech = r.get("technique")
        if tech and tech not in matrix:
            errors.append(f"{name}: техника {tech} отсутствует в модели угроз "
                          "(attack_matrix.py) — покрытие посчитается неверно")

        when = r.get("when") or {}
        if not when:
            errors.append(f"{name}: пустое условие when")

        # --- главная проверка: правило не должно быть тавтологией ---
        if len(when) == 1 and "action" in when:
            errors.append(
                f"{name}: правило состоит из ОДНОГО условия по action. "
                "Это не обнаружение, а чтение метки: добавь условия на "
                "наблюдаемые атрибуты (см. taxonomy.ATTRIBUTES)")

        for field, cond in when.items():
            if isinstance(cond, dict):
                for op in cond:
                    if op not in VALID_OPS:
                        errors.append(f"{name}: неизвестный оператор '{op}' в поле '{field}'")
            if field == "action":
                vals = []
                if isinstance(cond, str):
                    vals = [cond]
                elif isinstance(cond, dict) and "in" in cond:
                    vals = list(cond["in"])
                for v in vals:
                    if v not in taxonomy.OBSERVABLE:
                        errors.append(
                            f"{name}: действие '{v}' вне нормализованного словаря "
                            "(taxonomy.OBSERVABLE). Скорее всего это «говорящее» "
                            "действие, которого не бывает у обычной работы")
            elif (field not in BASE_FIELDS and field not in DERIVED
                    and field not in taxonomy.ATTRIBUTES):
                warnings.append(f"{name}: поле '{field}' не описано в "
                                "taxonomy.ATTRIBUTES — что оно значит в GitLab?")

        if not r.get("rationale"):
            warnings.append(f"{name}: нет поля 'rationale' — почему правило срабатывает "
                            "и почему не ловит норму")

    # --- сводка ---
    covered = {json.load(open(f, encoding="utf-8")).get("technique") for f in files}
    covered &= matrix
    print(f"  покрыто техник модели угроз: {len(covered)}/{len(matrix)} "
          f"({len(covered)/len(matrix)*100:.0f}%)")
    print(f"  слепые зоны: {sorted(matrix - covered)}")
    print("-" * 74)

    for w in warnings:
        print(f"  ⚠  {w}")
    for e in errors:
        print(f"  ❌ {e}")
    print("-" * 74)
    if errors:
        print(f"  ❌ ОШИБОК: {len(errors)}, предупреждений: {len(warnings)}")
        return 1
    print(f"  ✅ Все правила корректны (предупреждений: {len(warnings)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
