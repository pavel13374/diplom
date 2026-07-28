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

    # logodds (режим по умолчанию): тоже растёт от согласия слоёв, но с
    # затуханием — поправка на то, что слои НЕ независимы.
    lo = f([{"risk": 0.7}, {"risk": 0.6}], mode="logodds")
    check("fuse logodds > max", lo > 0.7)
    check("fuse logodds < noisy_or (учёт зависимости)",
          lo < f([{"risk": 0.7}, {"risk": 0.6}], mode="noisy_or"))
    # сигнал ровно 0.5 неинформативен и не должен ничего добавлять —
    # у лог-шансов это свойство встроено, у noisy-OR его нет
    check("logodds: сигнал 0.5 ничего не добавляет",
          abs(f([{"risk": 0.6}, {"risk": 0.5}], mode="logodds") - 0.6) < 1e-3)
    check("noisy_or: сигнал 0.5 всё равно поднимает риск (почему и не годится)",
          f([{"risk": 0.6}, {"risk": 0.5}], mode="noisy_or") > 0.6)
    check("fuse logodds single == risk",
          abs(f([{"risk": 0.42}], mode="logodds") - 0.42) < 1e-2)
    check("fuse logodds монотонен",
          f([{"risk": 0.8}, {"risk": 0.7}], mode="logodds") >
          f([{"risk": 0.6}, {"risk": 0.5}], mode="logodds"))


def test_enricher():
    """Оконные агрегаты: без них массовое удаление неотличимо от обычного.

    После нормализации словаря (taxonomy.py) и атака, и уборка репозитория
    эмитят одинаковые `file_delete` — «массовость» обязана вычисляться.
    """
    e = detector.Enricher()
    base = datetime(2026, 6, 1, 12, 0, 0)
    out = None
    for i in range(7):
        ev = {"actor": "a", "action": "file_delete", "project": "p",
              "ts_sim": (base + timedelta(seconds=i * 40)).strftime("%Y-%m-%dT%H:%M:%S")}
        out = e.enrich(ev)
    check("burst считает удаления в окне", out["burst_file_delete_10m"] == 7)

    # то же количество, но растянутое на часы -> всплеска нет
    e2 = detector.Enricher()
    for i in range(7):
        ev = {"actor": "b", "action": "file_delete", "project": "p",
              "ts_sim": (base + timedelta(hours=i)).strftime("%Y-%m-%dT%H:%M:%S")}
        out2 = e2.enrich(ev)
    check("растянутые удаления не всплеск", out2["burst_file_delete_10m"] == 1)

    # разные проекты за час
    e3 = detector.Enricher()
    for i, p in enumerate(["p1", "p2", "p3", "p1"]):
        ev = {"actor": "c", "action": "api_read", "project": p,
              "ts_sim": (base + timedelta(minutes=i)).strftime("%Y-%m-%dT%H:%M:%S")}
        out3 = e3.enrich(ev)
    check("distinct_projects_1h", out3["distinct_projects_1h"] == 3)
    check("burst_api_read_15m", out3["burst_api_read_15m"] == 4)

    # актор без метки времени не ломает обогащение
    safe = detector.Enricher().enrich({"actor": "z", "action": "push"})
    check("enrich без ts не падает", safe.get("burst_file_delete_10m") == 0)


def test_mass_delete_rule():
    """Регрессия на главный дефект: правило mass-file-delete раньше срабатывало
    на КАЖДОМ обычном удалении файла (96 ложных срабатываний, 0 верных)."""
    eng = detector.DetectionEngine(use_ml=False)
    base = datetime(2026, 6, 1, 12, 0, 0)

    def fired(n, gap_sec):
        e = detector.DetectionEngine(use_ml=False)
        hit = False
        for i in range(n):
            ev = {"actor": "u", "action": "file_delete", "project": "p", "hour": 12,
                  "ts_sim": (base + timedelta(seconds=i * gap_sec)).strftime("%Y-%m-%dT%H:%M:%S")}
            res = e.process(ev)
            if any(a["rule_id"] == "mass-file-delete" for a in res.get("alerts", [])):
                hit = True
        return hit

    check("одиночное удаление НЕ алерт", not fired(1, 60))
    check("обычная уборка (3 файла) НЕ алерт", not fired(3, 60))
    check("массовое удаление (8 за минуты) -> алерт", fired(8, 45))
    check("8 удалений за неделю НЕ алерт", not fired(8, 3600 * 24))
    # Число правил намеренно НЕ фиксируется: каталог пополняется, и тест,
    # завязанный на точное значение, ломается при каждом добавлении правила,
    # ничего при этом не проверяя по существу.
    check("движок грузит каталог правил", eng.rule_count() >= 38)


def test_layer_never_reduces_recall():
    """Добавление слоя не может УМЕНЬШИТЬ обнаружение.

    Регрессия на реальный дефект: подавление дублей проверяло только самый
    рисковый алерт события. Сработка ML часто оказывалась верхней по риску,
    попадала в окно подавления — и вместе с ней терялась сработка правила,
    которая дублем не была. В ablation это выглядело так, что «rules+ml» ловит
    меньше эпизодов, чем «rules», чего не может быть в принципе.
    """
    supp = detector.Suppressor(window_min=60)
    base = datetime(2026, 6, 1, 12, 0, 0)
    ts = base.strftime("%Y-%m-%dT%H:%M:%S")

    # алерт правила уже был -> он дубль; алерт ML новый
    supp.is_duplicate("u", "rule-a", ts)
    alerts = [{"rule_id": "rule-a", "risk": 0.5}, {"rule_id": "ml-content", "risk": 0.9}]
    fresh = [a for a in alerts
             if not supp.is_duplicate("u", a["rule_id"],
                                      (base + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%S"))]
    check("поалертное подавление сохраняет новый алерт", len(fresh) == 1)
    check("уцелел именно новый слой", fresh and fresh[0]["rule_id"] == "ml-content")

    # если дублями стали все — событие подавляется целиком
    supp2 = detector.Suppressor(window_min=60)
    supp2.is_duplicate("u", "rule-a", ts)
    supp2.is_duplicate("u", "ml-content", ts)
    fresh2 = [a for a in alerts
              if not supp2.is_duplicate("u", a["rule_id"],
                                        (base + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%S"))]
    check("полный дубль подавляется целиком", not fresh2)


def test_no_tautological_rules():
    """Ни одно правило не должно опираться ТОЛЬКО на имя действия.

    Правило вида {"action": "steal_oauth"} — не детектор, а считыватель метки:
    такого действия в нормальной работе не бывает по построению. См. taxonomy.py.
    """
    import json, glob, os
    bad = []
    for fp in glob.glob(os.path.join("detections", "*.json")):
        r = json.load(open(fp, encoding="utf-8"))
        when = r.get("when", {})
        if len(when) == 1 and "action" in when:
            bad.append(r.get("id"))
    check("нет правил из одного условия по action", not bad)
    if bad:
        print(f"      тавтологические правила: {bad}")


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


def _warm(u, actor="a", n=None, hour=11, repo="repo1", action="push"):
    """Прогрев профиля: обычный дневной актор в одном репозитории."""
    base = datetime(2026, 6, 1, hour, 0, 0)
    n = n if n is not None else u.MIN_EVENTS + 40
    for i in range(n):
        ev = {"actor": actor, "project": repo, "action": action, "hour": hour,
              "is_night": False,
              "ts_sim": (base + timedelta(minutes=i * 37)).strftime("%Y-%m-%dT%H:%M:%S")}
        u.score(ev); u.update(ev)


def test_ueba_silent_before_calibration():
    """До калибровки слой обязан МОЛЧАТЬ, а не работать по константе.

    На первых сотнях событий профили пусты, неожиданность высока у всех, и
    фиксированный порог давал лавину ложных тревог именно там, где данных
    меньше всего.
    """
    u = detector.UEBA()
    u.MIN_CALIB = 500
    _warm(u, n=60)
    weird = {"actor": "a", "project": "СОВСЕМ-НОВЫЙ", "action": "member_update",
             "hour": 4, "is_night": True, "ts_sim": "2026-06-09T04:00:00"}
    risk, _, bits = u.score(weird)
    check("до калибровки слой молчит", risk == 0.0)
    check("но неожиданность всё равно считается", bits > 0)
    check("порог до калибровки = бесконечность",
          u.threshold_bits() == float("inf"))


def test_ueba_behavior():
    """UEBA теперь вероятностный: скор = неожиданность события в БИТАХ."""
    u = detector.UEBA()
    u.MIN_CALIB = 50                  # быстрая калибровка, чтобы тест был коротким
    u.BUDGET = 0.02
    _warm(u, n=200)

    # знакомое поведение -> мало бит
    known = {"actor": "a", "project": "repo1", "action": "push", "hour": 11,
             "is_night": False, "ts_sim": "2026-06-05T11:00:00"}
    r_known, _, bits_known = u.score(known)

    # новый репозиторий + нетипичный час -> много бит
    night = {"actor": "a", "project": "NEWrepo", "action": "token_create", "hour": 3,
             "is_night": True, "ts_sim": "2026-06-05T03:00:00"}
    r_night, reasons, bits_night = u.score(night)

    check("знакомое поведение не даёт алерт", r_known == 0.0)
    check("неожиданное поведение даёт больше бит", bits_night > bits_known + 5)
    check("неожиданное поведение -> риск", r_night > 0.0 and len(reasons) >= 1)
    check("риск в [0,1]", 0.0 <= r_night <= 1.0)
    check("объяснение в битах", any("бит" in x for x in reasons))


def test_ueba_cold_start():
    """Актор без истории не должен скориться: не с чем сравнивать."""
    u = detector.UEBA()
    ev = {"actor": "новичок", "project": "p", "action": "push", "hour": 3,
          "is_night": True, "ts_sim": "2026-06-05T03:00:00"}
    risk, _, bits = u.score(ev)
    check("холодный старт -> нет скоринга", risk == 0.0 and bits == 0.0)


def test_ueba_circular_hours():
    """Час — циклическая величина: 23:00 и 01:00 соседи, а не края шкалы."""
    u = detector.UEBA()
    _warm(u, actor="ночной", hour=0)          # актор работает около полуночи
    p = u.actor["ночной"]["hours"]
    check("23:00 вероятнее 12:00 для ночного актора", p.prob(23) > p.prob(12))
    check("01:00 вероятнее 12:00 для ночного актора", p.prob(1) > p.prob(12))


def test_ueba_threshold_from_data():
    """Порог берётся как квантиль наблюдений под бюджет тревог, а не константой."""
    u = detector.UEBA()
    u.MIN_CALIB = 100
    u.BUDGET = 0.05
    for i in range(400):
        u.scores.append(float(i % 50))
    u._thr_dirty = True
    thr = u.threshold_bits()
    check("порог внутри диапазона наблюдений", 0.0 < thr <= 50.0)
    check("порог != константе fallback", abs(thr - u.FALLBACK_BITS) > 1e-9)


def test_ml_layer_optional():
    """Без файла модели слой L2 обязан молча выключаться, а не ронять систему."""
    m = detector.MLScorer(path="/nonexistent/model.json")
    check("нет модели -> слой выключен", not m.available())
    eng = detector.DetectionEngine(use_ml=False)
    res = eng.process({"actor": "u", "action": "push", "project": "p", "hour": 12,
                       "ts_sim": "2026-06-01T12:00:00", "n_regex_hits": 1,
                       "placeholder_signal": False})
    check("детектор работает без ML", res["alert"] is True)


def main():
    print("=" * 56)
    print("  ЮНИТ-ТЕСТЫ ДЕТЕКТОРА")
    print("=" * 56)
    test_match_cond()
    test_match_rule()
    test_fuse()
    test_suppressor()
    test_enricher()
    test_mass_delete_rule()
    test_layer_never_reduces_recall()
    test_no_tautological_rules()
    test_ueba_silent_before_calibration()
    test_ueba_behavior()
    test_ueba_cold_start()
    test_ueba_circular_hours()
    test_ueba_threshold_from_data()
    test_ml_layer_optional()
    print("-" * 56)
    if fails:
        print(f"  {BAD} ПРОВАЛЕНО: {len(fails)} -> {fails}")
        return 1
    print(f"  {OK} Все юнит-тесты детектора прошли.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
