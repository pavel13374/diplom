#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Юнит-тесты ядра детектора: операторы условий, fusion, подавление дублей.
Без сети и GitLab. Запуск: python test_detector.py
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
from datetime import datetime, timedelta

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

import detector

OK = "✅"; BAD = "❌"
fails = []


def check(name, cond):
    print(f"  {OK if cond else BAD} {name}")
    if not cond:
        fails.append(name)


def test_match_cond():
    mc = detector._match_cond
    check("ops: >= ", mc(5, {">=": 5}) and not mc(4, {">=": 5}))
    check("ops: >  ", mc(6, {">": 5}) and not mc(5, {">": 5}))
    check("ops: <= ", mc(5, {"<=": 5}) and not mc(6, {"<=": 5}))
    check("ops: <  ", mc(4, {"<": 5}) and not mc(5, {"<": 5}))
    check("ops: ne ", mc("a", {"ne": "b"}) and not mc("b", {"ne": "b"}))
    check("ops: in ", mc("push", {"in": ["push", "merge"]}) and not mc("x", {"in": ["push"]}))
    check("ops: nin", mc("x", {"nin": ["push"]}) and not mc("push", {"nin": ["push"]}))
    check("ops: contains-str ", mc("a/b/c", {"contains": "b"}) and not mc("a/c", {"contains": "b"}))
    check("ops: contains-list", mc(["x", "y"], {"contains": "x"}) and not mc(["y"], {"contains": "x"}))
    check("eq direct", mc("push", "push") and not mc("push", "merge"))
    check("type guard (str vs num)", not mc("hi", {">=": 5}))


def test_match_rule():
    mr = detector._match_rule
    ev = {"action": "push", "n_regex_hits": 2, "placeholder_signal": False}
    check("rule AND true", mr(ev, {"action": "push", "n_regex_hits": {">=": 1}}))
    check("rule AND false", not mr(ev, {"action": "push", "n_regex_hits": {">=": 3}}))
    check("rule missing field", not mr(ev, {"absent": 1}))


def test_fuse():
    f = detector.fuse
    check("fuse empty -> 0", f([]) == 0.0)
    check("fuse max mode", abs(f([{"risk": 0.6}, {"risk": 0.5}], mode="max") - 0.6) < 1e-6)
    # noisy_or: согласие двух слоёв выше каждого
    nor = f([{"risk": 0.6}, {"risk": 0.5}], mode="noisy_or")
    check("fuse noisy_or > max", nor > 0.6 and nor < 1.0)
    check("fuse single == risk", abs(f([{"risk": 0.42}], mode="noisy_or") - 0.42) < 1e-3)
    check("fuse capped < 1", f([{"risk": 0.99}, {"risk": 0.99}, {"risk": 0.99}], mode="noisy_or") <= 0.99)


def test_suppressor():
    s = detector.Suppressor(window_min=60)
    t0 = "2026-06-10T10:00:00"
    t1 = "2026-06-10T10:30:00"   # +30м -> в окне
    t2 = "2026-06-10T12:00:00"   # +2ч  -> вне окна
    check("first not dup", not s.is_duplicate("maria", "r1", t0))
    check("within window dup", s.is_duplicate("maria", "r1", t1))
    check("outside window not dup", not s.is_duplicate("maria", "r1", t2))
    check("other rule not dup", not s.is_duplicate("maria", "r2", t1))
    check("other actor not dup", not s.is_duplicate("dmitry", "r1", t1))


def test_ueba_behavior():
    u = detector.UEBA()
    u.THRESHOLD = 0.45
    # прогрев профиля «дневным» актором в одном репо
    base = datetime(2026, 6, 1, 11, 0, 0)
    for i in range(u.MIN_EVENTS + 2):
        ev = {"actor": "a", "project": "repo1", "action": "push", "hour": 11,
              "is_night": False, "ts_sim": (base + timedelta(minutes=i * 120)).strftime("%Y-%m-%dT%H:%M:%S")}
        u.score(ev); u.update(ev)
    # новый репо + ночь -> риск
    night = {"actor": "a", "project": "NEWrepo", "action": "push", "hour": 3,
             "is_night": True, "ts_sim": "2026-06-05T03:00:00"}
    risk, reasons = u.score(night)
    check("UEBA flags new-repo+offhours", risk >= 0.45 and len(reasons) >= 1)


def main():
    print("=" * 56)
    print("  ЮНИТ-ТЕСТЫ ДЕТЕКТОРА")
    print("=" * 56)
    test_match_cond()
    test_match_rule()
    test_fuse()
    test_suppressor()
    test_ueba_behavior()
    print("-" * 56)
    if fails:
        print(f"  {BAD} ПРОВАЛЕНО: {len(fails)} -> {fails}")
        return 1
    print(f"  {OK} Все юнит-тесты детектора прошли.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
