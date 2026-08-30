#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ТРАССИРУЕМОСТЬ: правило ↔ техника ATT&CK ↔ шаг атаки.

Зачем. Правило может быть синтаксически корректным (это проверяет
tools/lint_rules.py), ссылаться на существующую технику — и при этом не
срабатывать НИ РАЗУ, потому что условие не совпадает с тем, что на самом деле
эмитит мир. Ровно так и было с mass-file-delete: правило ловило `file_delete`,
а атака эмитила `mass_delete`, и техника T1485 числилась покрытой, ничего не
обнаруживая. Заявленное покрытие ATT&CK было завышено, и заметить это по
статике невозможно — нужен прогон.

Этот тест связывает три вещи, которые в проекте лежат отдельно:

    detections/*.json   —  что мы УМЕЕМ ловить
    red_team.CAMPAIGNS  —  что мы РЕАЛЬНО исполняем
    прогон детектора    —  что мы ФАКТИЧЕСКИ ловим

и требует, чтобы они сходились:

  1. каждое правило хотя бы раз срабатывает на корпусе — иначе это мёртвый код,
     который создаёт видимость покрытия;
  2. каждая ИСПОЛНЕННАЯ техника ловится хотя бы одним правилом — иначе цифра
     покрытия завышена;
  3. каждая техника из кампаний присутствует в модели угроз (attack_matrix);
  4. слепые зоны совпадают с ожидаемым списком — если правило добавили, а
     список не обновили, тест напомнит.

Запуск: python tests/test_rule_coverage.py
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
import logging
import collections

logging.disable(logging.CRITICAL)
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

import detector
import run_defense
from red_team import CAMPAIGNS
from attack_matrix import all_techniques
from workload import build_workload

OK = "✅"; BAD = "❌"
fails = []

#: Техники модели угроз, под которые правил ЕЩЁ НЕТ. Это очередь работ
#: detection engineering, а не ошибка: они честно горят как слепые зоны в
#: консоли. Список зафиксирован здесь, чтобы его нельзя было молча раздуть.
EXPECTED_BLIND = {
    "T1030",      # Data Transfer Size Limits
    "T1071.001",  # Web Protocols (C2)
    "T1074",      # Data Staged
    "T1078.004",  # Valid Accounts: Cloud
    "T1080",      # Taint Shared Content
    "T1199",      # Trusted Relationship
    "T1505",      # Server Software Component
    "T1518",      # Software Discovery
    "T1526",      # Cloud Service Discovery
    "T1550.001",  # Application Access Token
    "T1555",      # Credentials from Password Stores
    "T1565.001",  # Stored Data Manipulation
    "T1613",      # Container and Resource Discovery
}


def check(name, cond, detail=""):
    print(f"  {OK if cond else BAD} {name}")
    if not cond:
        fails.append(name)
        if detail:
            for line in str(detail).splitlines():
                print(f"      {line}")


def main():
    print("=" * 76)
    print("  ТРАССИРУЕМОСТЬ: правило ↔ техника ↔ шаг атаки")
    print("=" * 76)

    rules = [json.load(open(f, encoding="utf-8"))
             for f in sorted(glob.glob(os.path.join("detections", "*.json")))]
    rule_ids = {r["id"] for r in rules}
    rule_tech = {r["id"]: r.get("technique") for r in rules}
    matrix = all_techniques()

    # --- техники, которые кампании РЕАЛЬНО исполняют ---
    campaign_tech = set()
    for camp in CAMPAIGNS.values():
        for _method, tech, _tactic in camp["steps"]:
            campaign_tech.add(tech)

    print(f"  правил: {len(rules)} | техник в модели угроз: {len(matrix)} | "
          f"техник в кампаниях: {len(campaign_tech)}")
    print("-" * 76)

    # --- 3. техники кампаний должны быть в модели угроз ---
    outside = sorted(campaign_tech - matrix)
    check("все техники кампаний присутствуют в модели угроз", not outside,
          "вне attack_matrix.py: " + ", ".join(outside) if outside else "")

    # --- прогон по корпусу (все профили уклонения) ---
    fired = collections.Counter()
    tech_caught = collections.defaultdict(set)     # техника эпизода -> {правила}
    tech_executed = collections.Counter()
    for evasion in ("noisy", "stealthy", "adaptive"):
        wl = build_workload(evasion=evasion, seed=42, days=10, per_day=220)
        eng = detector.DetectionEngine()
        for ev in wl:
            if ev.get("meta"):
                continue
            tech = ev.get("technique_id")
            if ev.get("is_anomaly") and tech:
                tech_executed[tech] += 1
            det = eng.process(run_defense.observed(ev))
            if not det.get("alert"):
                continue
            for a in det["alerts"]:
                fired[a["rule_id"]] += 1
                if ev.get("is_anomaly") and tech:
                    tech_caught[tech].add(a["rule_id"])

    # --- 1. каждое правило хоть раз сработало ---
    silent = sorted(rule_ids - set(fired))
    check("каждое правило хотя бы раз срабатывает на корпусе", not silent,
          "молчат: " + ", ".join(silent) if silent else "")

    # --- 2. каждая исполненная техника поймана ---
    executed = set(tech_executed)
    missed = sorted(t for t in executed if not tech_caught.get(t))
    check("каждая ИСПОЛНЕННАЯ техника ловится хотя бы одним правилом", not missed,
          "исполняются, но не детектируются: " + ", ".join(missed) if missed else "")

    # --- 4. слепые зоны совпадают с зафиксированным списком ---
    covered_by_rules = {t for t in rule_tech.values() if t} & matrix
    blind = matrix - covered_by_rules
    new_blind = sorted(blind - EXPECTED_BLIND)
    closed = sorted(EXPECTED_BLIND - blind)
    check("список слепых зон не разросся", not new_blind,
          "появились новые непокрытые техники: " + ", ".join(new_blind)
          if new_blind else "")
    check("закрытые слепые зоны убраны из списка ожидаемых", not closed,
          "уже покрыты правилами, удали из EXPECTED_BLIND: " + ", ".join(closed)
          if closed else "")

    # --- отчёт ---
    print("-" * 76)
    print(f"  {'техника':12} | {'событий':>7} | правила, которые её ловят")
    print("  " + "-" * 72)
    for t in sorted(executed):
        rs = sorted(tech_caught.get(t, []))
        mark = OK if rs else BAD
        shown = ", ".join(rs[:3]) + (" …" if len(rs) > 3 else "")
        print(f"  {mark} {t:10} | {tech_executed[t]:>7} | {shown or '— НЕ ЛОВИТСЯ'}")

    print("-" * 76)
    print(f"  покрытие модели угроз правилами: {len(covered_by_rules)}/{len(matrix)} "
          f"({len(covered_by_rules)/len(matrix)*100:.0f}%)")
    print(f"  слепых зон (очередь detection engineering): {len(blind)}")
    fired_rules = set(fired) & rule_ids
    layers = sorted(set(fired) - rule_ids)
    print(f"  сработавших правил: {len(fired_rules)}/{len(rules)}"
          f"  (+ слои без файла правила: {', '.join(layers)})")
    print("=" * 76)

    if fails:
        print(f"  {BAD} ПРОВАЛЕНО: {len(fails)}")
        return 1
    print(f"  {OK} Правила, техники и шаги атаки сходятся.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
