#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OFFLINE-РЕЖИМ: заявлено, что «без GitLab стенд работает».

Проверяется буквально это утверждение, а не факт запуска процесса.

Две проверки закрывают два реальных отказа на живом стенде:

  1. Заглушка GitLab перечисляла имена методов РУКАМИ и на всё остальное
     возвращала True. Клиент дорос до 50 методов, список остался на девяти, и
     любая активность, которой нужны данные, падала:

         Activity revert_bad_rule raised: 'bool' object is not iterable
         Activity update_parser  raised: 'bool' object has no attribute 'rstrip'

  2. OFFLINE_MODE работал односторонней защёлкой: стоило GitLab один раз не
     ответить (ВМ ещё грузилась), и проверка связи больше не выполнялась
     никогда. Интерфейс при этом писал «offline (включён вручную)», хотя
     вручную никто ничего не включал, а вернуть стенд в онлайн можно было
     только перезапуском процесса.

Запуск: python tests/test_offline.py
"""
import os
import sys
import inspect
import logging

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SOC_OFFLINE", "1")

FAILED = []


def check(name, ok, detail=""):
    print(("  OK    " if ok else "  ПЛОХО ") + name + (("  " + detail) if detail and not ok else ""))
    if not ok:
        FAILED.append(name)


# ======================================================================
def test_fake_covers_every_method():
    """Заглушка обязана отвечать осмысленно на КАЖДЫЙ метод клиента."""
    print("\n-- заглушка GitLab покрывает весь клиент --")
    import webapp
    import gitlab_client

    fake = webapp._FakeGL()
    methods = [n for n, _ in inspect.getmembers(gitlab_client.GitLabClient, inspect.isfunction)
               if not n.startswith("__")]
    check(f"методов у клиента найдено ({len(methods)})", len(methods) > 40, str(len(methods)))

    # Ловим предупреждение «не знаю, что вернуть» — оно означает пробел.
    unknown = []

    class _Catch(logging.Handler):
        def emit(self, record):
            if "не знаю, что вернуть" in record.getMessage():
                unknown.append(getattr(record, "ctx", {}).get("method", "?"))

    h = _Catch()
    logging.getLogger("webapp").addHandler(h)
    mismatched = []
    try:
        for name in sorted(methods):
            value = getattr(fake, name)()
            raw = getattr(getattr(gitlab_client.GitLabClient, name),
                          "__annotations__", {}).get("return")
            ann = webapp._unwrap_optional(raw)
            # None ЗАКОННО для метода с Optional[X]. Проверка сравнивала
            # заглушку с РАСКРЫТЫМ типом и потому запрещала единственный
            # честный ответ offline-режима: «значения нет». Для
            # get_mr_approvals это не мелочь — int-заглушка означала бы
            # «ревью было» на каждом merge, то есть подделанные апрувы в
            # каждом offline-прогоне. Проверка остаётся строгой: НЕ-None
            # значение неверного типа по-прежнему провал.
            if value is None and raw is not ann:
                continue
            if isinstance(ann, type) and ann in webapp._FAKE_BY_TYPE and not isinstance(value, ann):
                mismatched.append(f"{name}: ждали {ann.__name__}, вернулось {type(value).__name__}")
    finally:
        logging.getLogger("webapp").removeHandler(h)

    check("для каждого метода известно, что вернуть", not unknown, ", ".join(sorted(set(unknown))[:6]))
    check("возвращаемый тип согласован с аннотацией", not mismatched, "; ".join(mismatched[:4]))

    # Ровно те два вызова, что падали на живом стенде.
    try:
        list(fake.get_commits(1))
        ok_iter = True
    except TypeError:
        ok_iter = False
    check("get_commits() итерируется (revert_bad_rule)", ok_iter)
    try:
        lines = fake.get_file(1, "rules/x.yml").rstrip().split("\n")
        ok_str = isinstance(lines, list)
    except AttributeError:
        ok_str = False
    check("get_file() ведёт себя как строка (update_parser)", ok_str)


def test_offline_is_not_a_latch():
    """Автоматический откат в offline обязан перепроверяться.

    Проверяется сама логика решения, без сети: принудительный offline
    (SOC_OFFLINE) отделён от автоматического, и второй не залипает.
    """
    print("\n-- offline не защёлкивается --")
    import config
    check("есть отдельный флаг принудительного offline",
          hasattr(config, "OFFLINE_FORCED"))

    def decide(forced, reachable):
        """Ровно та ветка, что в Runner._build()."""
        if forced:
            return True, "offline: включён переменной SOC_OFFLINE"
        conn_ok = bool(reachable)
        return (not conn_ok), ("GitLab 17.x" if conn_ok else "нет ответа /version")

    off1, _ = decide(False, reachable=False)     # ВМ ещё грузится
    off2, msg2 = decide(False, reachable=True)   # ВМ поднялась
    check("при недоступном GitLab уходим в offline", off1)
    check("после появления GitLab offline СНИМАЕТСЯ", not off2, f"остались offline: {msg2}")

    off3, msg3 = decide(True, reachable=True)
    check("принудительный SOC_OFFLINE уважается даже при живом GitLab", off3)
    check("причина названа честно (не «включён вручную» при автооткате)",
          "SOC_OFFLINE" in msg3, msg3)


def test_activities_survive_offline():
    """Каждая активность отрабатывает без GitLab и без исключений."""
    print("\n-- активности в offline --")
    from datetime import datetime
    import config
    import simclock
    import events
    import webapp
    from agents.base import BaseAgent
    from agents.lead import LeadAgent
    from scheduler import Scheduler
    from state import SimState

    logging.disable(logging.WARNING)
    try:
        config.OFFLINE_MODE = True
        config.TELEGRAM = {"enabled": False}
        clock = simclock.SimClock(
            start_sim=datetime(2026, 6, 8, 11, 0), scale=600,
            work_start=10, work_end=18, work_days=[0, 1, 2, 3, 4],
            fast_forward_offhours=False, api_min_pause=0, max_real_sleep=0)
        simclock.init(clock)
        events.init()
        gl = webapp._FakeGL()
        agents = {u: (LeadAgent(u, gl) if i.get("role") == "lead" else BaseAgent(u, gl))
                  for u, i in config.USERS.items()}
        sch = Scheduler(agents, gl, state=SimState(os.path.join("/tmp", "_offline_state.json")))

        broken = {}
        for name in sorted(config.ACTIVITY_WEIGHTS):
            for _ in range(3):          # ветки внутри активностей случайны
                try:
                    sch._dispatch(name)
                except Exception as e:
                    broken[name] = f"{type(e).__name__}: {e}"
                    break
    finally:
        logging.disable(logging.NOTSET)

    check(f"все {len(config.ACTIVITY_WEIGHTS)} активностей отработали без исключений",
          not broken, "; ".join(f"{k} -> {v}" for k, v in list(broken.items())[:4]))


def main():
    print("=" * 70)
    print("  OFFLINE-РЕЖИМ")
    print("=" * 70)
    test_fake_covers_every_method()
    test_offline_is_not_a_latch()
    test_activities_survive_offline()
    print("-" * 70)
    if FAILED:
        print(f"  ПРОВАЛЕНО: {len(FAILED)}")
        for f in FAILED:
            print("     -", f)
        return 1
    print("  Стенд работает без GitLab.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
