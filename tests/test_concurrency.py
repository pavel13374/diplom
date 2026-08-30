#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ПАРАЛЛЕЛИЗМ, ГРАНИЦЫ РОСТА И ЦЕЛОСТНОСТЬ ХРАНИЛИЩА.

Регрессия на дефекты, которые не видны при последовательном прогоне:

  1. ГОНКИ МЕЖДУ ПОТОКОМ ИНГЕСТА И ОБРАБОТЧИКАМИ HTTP.
     Замок `_LOCK` в консоли существовал, но две самые крупные изменяемые
     структуры трогались мимо него: `_ingestor` звал `_COR.add()` и дополнял
     `_COR.incidents[iid]["signals"]` вне замка, `_triage_worker` делал
     `list(_COR.incidents.items())` без замка вообще, а `/api/entities` обходил
     `detector.UEBA.actor` — defaultdict, который поток ингеста пополняет на
     КАЖДОМ событии. Результат — `RuntimeError: dictionary changed size during
     iteration` внутри обработчика, то есть 500 на дашборде под нагрузкой, и
     чтение инцидента в середине обновления (сработка уже добавлена, risk и
     severity ещё нет).

  2. НЕОГРАНИЧЕННЫЙ РОСТ ПРИ ЗАТОПЛЕНИИ ТРЕВОГАМИ.
     `Correlator.incidents` не чистился никогда, `alerts` внутри инцидента рос
     без предела, а `chain` пересортировывался НА КАЖДОМ добавлении: инцидент
     из n сработок стоил O(n² log n). Затопить тревоги под одним актором —
     доступное действие атакующего.

  3. ЗАХВАТ КОМАНДЫ НЕ БЫЛ АТОМАРНЫМ МЕЖДУ ПРОЦЕССАМИ.
     SELECT + UPDATE стояли под threading.Lock — замком ВНУТРИ процесса, тогда
     как весь смысл хранилища в том, что мир и консоль это РАЗНЫЕ процессы.

  4. ЗАПИСЬ СОСТОЯНИЯ БЫЛА НЕ АТОМАРНОЙ.
     open(path,"w") обрезает файл до записи; прерывание оставляло обрезанный
     JSON, а _load молча продолжал с пустыми значениями.

Запуск: python tests/test_concurrency.py
"""
import os as _os
import sys as _sys

_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)
_os.chdir(_ROOT)

import json
import time
import shutil
import logging
import tempfile
import threading

logging.disable(logging.CRITICAL)
try:
    _sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

OK, BAD = "✅", "❌"
FAILED = []


def check(name, ok, detail=""):
    print(f"  {OK if ok else BAD} {name}" + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        FAILED.append(name)


# ======================================================================
def test_ueba_snapshot_is_race_free():
    print("\n-- профили UEBA читаются без гонки --")
    import detector
    u = detector.UEBA()
    errors = []
    stop = threading.Event()

    def writer():
        i = 0
        while not stop.is_set():
            i += 1
            u.update({"actor": f"user{i % 300}", "project": f"repo{i % 40}",
                      "action": "push", "hour": i % 24,
                      "ts_sim": "2026-06-08T11:00:00"})

    def reader():
        while not stop.is_set():
            try:
                snap = u.profiles_snapshot()
                # обход снимка обязан быть безопасным даже во время записи
                sum(p["n"] for p in snap.values())
            except Exception as e:      # noqa: BLE001 — тест ловит любую гонку
                errors.append(repr(e))
                return

    ws = [threading.Thread(target=writer, daemon=True) for _ in range(2)]
    rs = [threading.Thread(target=reader, daemon=True) for _ in range(6)]
    for t in ws + rs:
        t.start()
    time.sleep(2.0)
    stop.set()
    for t in ws + rs:
        t.join(timeout=3)
    check("одновременное чтение и запись профилей не падает",
          not errors, "; ".join(errors[:3]))
    check("профили действительно накопились", len(u.profiles_snapshot()) > 50)


def test_correlator_is_bounded():
    print("\n-- затопление тревогами ограничено --")
    import correlator
    c = correlator.Correlator(window_min=100000)
    det = {"risk": 0.5, "alerts": [{"layer": "rules", "rule_id": "r", "risk": 0.5,
                                    "technique": "T1", "tactic": "X", "reason": "r"}]}
    t0 = time.time()
    for k in range(30000):
        c.add({"actor": "flood", "ts_sim": "2026-01-01T10:%02d:00" % (k % 60)}, det)
    dt = time.time() - t0
    inc = next(iter(c.incidents.values()))
    check(f"30 000 сработок обработаны за {dt:.1f}с (< 20с)", dt < 20.0, f"{dt:.1f}с")
    check(f"число сработок в инциденте ограничено ({len(inc['alerts'])})",
          len(inc["alerts"]) <= correlator.MAX_ALERTS_PER_INCIDENT)
    check(f"длина цепочки ограничена ({len(inc['chain'])})",
          len(inc["chain"]) <= correlator.MAX_CHAIN)
    check("отброшенное посчитано, а не потеряно молча",
          inc.get("alerts_dropped", 0) > 0)
    # цепочка обязана остаться в хронологии — её читает IR-отчёт
    ts = [str(x.get("ts") or "") for x in inc["chain"]]
    check("цепочка отсортирована по времени", ts == sorted(ts))


def test_correlator_evicts_incidents():
    print("\n-- словарь инцидентов не растёт бесконечно --")
    import correlator
    c = correlator.Correlator(window_min=1)
    det = {"risk": 0.5, "alerts": [{"layer": "rules", "rule_id": "r", "risk": 0.5,
                                    "technique": "T1", "tactic": "X", "reason": "r"}]}
    for k in range(correlator.MAX_INCIDENTS + 500):
        c.add({"actor": f"actor{k}", "ts_sim": "2026-01-01T10:00:00"}, det)
    check(f"инцидентов не больше предела ({len(c.incidents)} <= "
          f"{correlator.MAX_INCIDENTS})",
          len(c.incidents) <= correlator.MAX_INCIDENTS)
    check("карта открытых окон не рассинхронизировалась",
          all(iid in c.incidents for iid in c._open_by_actor.values()))


def test_correlator_window_survives_bad_timestamp():
    print("\n-- одно событие без времени не сливает всё в один инцидент --")
    import correlator
    c = correlator.Correlator(window_min=1)
    det = {"risk": 0.5, "alerts": [{"layer": "rules", "rule_id": "r", "risk": 0.5,
                                    "technique": "T1", "tactic": "X", "reason": "r"}]}
    i1 = c.add({"actor": "bob", "ts_sim": "2026-01-01T10:00:00"}, det)
    i2 = c.add({"actor": "bob", "ts_sim": None}, det)
    i3 = c.add({"actor": "bob", "ts_sim": "2030-01-01T10:00:00"}, det)
    check("событие без времени попало в текущий инцидент", i1 == i2)
    check("окно закрылось по разрыву в четыре года", i1 != i3, f"{i1} vs {i3}")
    check("событие без времени посчитано", c.incidents[i1].get("undated_events") == 1)


def test_severity_matches_action_threshold():
    print("\n-- уровень инцидента согласован с порогом действия --")
    import correlator
    import config
    for r in (0.05, 0.3, 0.45, 0.6, 0.69, 0.71, 0.8, 0.9, 0.99):
        sev = correlator.severity_for(r)
        act = correlator.actionable({"risk": r, "alerts": []})
        check(f"risk={r}: severity={sev}, в очереди={act}",
              (sev in ("high", "critical")) == act,
              f"порог {config.ACTION_THRESHOLD}")


# ======================================================================
def test_eventstore_init_is_idempotent():
    print("\n-- event-store: init() не течёт соединениями --")
    import config
    import eventstore
    tmp = tempfile.mkdtemp()
    config.EVENT_STORE = {"enabled": True, "path": _os.path.join(tmp, "e.db")}
    eventstore.init(force=True)
    first = eventstore._STATE["db"]
    for _ in range(100):
        eventstore.init()
    check("100 вызовов init() дают одно соединение",
          eventstore._STATE["db"] is first)
    other = _os.path.join(tmp, "other.db")
    eventstore.init(path=other)
    check("смена пути переоткрывает соединение",
          eventstore._STATE["db"] is not first and eventstore._STATE["path"] == other)
    eventstore.close()
    shutil.rmtree(tmp, ignore_errors=True)


def test_command_claim_is_exclusive():
    print("\n-- очередь команд: захват эксклюзивен --")
    import config
    import eventstore
    tmp = tempfile.mkdtemp()
    config.EVENT_STORE = {"enabled": True, "path": _os.path.join(tmp, "e.db")}
    eventstore.init(force=True)
    N = 120
    for i in range(N):
        eventstore.enqueue_command("noop", {"i": i})

    claimed = []
    lock = threading.Lock()

    def worker():
        while True:
            c = eventstore.claim_command()
            if not c:
                return
            with lock:
                claimed.append(c["id"])

    ts = [threading.Thread(target=worker, daemon=True) for _ in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(timeout=30)
    check(f"забрано ровно {N} команд", len(claimed) == N, str(len(claimed)))
    check("ни одна команда не забрана дважды", len(set(claimed)) == len(claimed))

    statuses = {c["status"] for c in eventstore.list_commands(N)}
    check("после захвата статус 'running', а не 'done'",
          statuses == {"running"}, str(statuses))
    eventstore.set_command_result(claimed[0], "ok")
    st = {c["id"]: c["status"] for c in eventstore.list_commands(N)}
    check("результат переводит команду в 'done'", st[claimed[0]] == "done")
    eventstore.set_command_result(claimed[1], "failed: нет прав")
    st = {c["id"]: c["status"] for c in eventstore.list_commands(N)}
    check("отказ переводит команду в 'failed'", st[claimed[1]] == "failed")

    eventstore.close()
    shutil.rmtree(tmp, ignore_errors=True)


def test_stats_is_cached():
    print("\n-- сводка журнала не сканирует таблицу на каждый опрос --")
    import config
    import eventstore
    tmp = tempfile.mkdtemp()
    config.EVENT_STORE = {"enabled": True, "path": _os.path.join(tmp, "e.db")}
    eventstore.init(force=True)
    for i in range(4000):
        eventstore.append({"actor": "u", "action": "push", "ts_sim": "2026-01-01T10:00:00"})
    eventstore.stats()
    t0 = time.time()
    for _ in range(300):
        eventstore.stats()
    dt = time.time() - t0
    check(f"300 вызовов stats() за {dt:.3f}с (< 1с)", dt < 1.0, f"{dt:.3f}с")
    before = eventstore.stats()["events"]
    eventstore.append({"actor": "u", "action": "push"})
    check("кэш инвалидируется новым событием",
          eventstore.stats()["events"] == before + 1)
    eventstore.close()
    shutil.rmtree(tmp, ignore_errors=True)


def test_state_save_is_atomic():
    print("\n-- состояние симуляции пишется атомарно --")
    from state import SimState
    tmp = tempfile.mkdtemp()
    p = _os.path.join(tmp, "state.json")
    st = SimState(p)
    st.data["sprint_number"] = 7
    st.save()
    check("файл создан и разбирается", json.load(open(p, encoding="utf-8"))["sprint_number"] == 7)
    check("временный файл не остался", not _os.path.exists(p + ".tmp"))
    st.data["sprint_number"] = 8
    st.save()
    check("предыдущее поколение сохранено в .bak", _os.path.exists(p + ".bak"))
    check("основной файл обновлён",
          json.load(open(p, encoding="utf-8"))["sprint_number"] == 8)

    # Обрезанный основной файл: читаем резервный, а не теряем состояние молча.
    with open(p, "w", encoding="utf-8") as f:
        f.write('{"rules": {"a"')
    st2 = SimState(p)
    check("битый файл состояния не приводит к тихой потере",
          st2.data["sprint_number"] == 7, str(st2.data["sprint_number"]))
    shutil.rmtree(tmp, ignore_errors=True)


def main():
    print("=" * 74)
    print("  ПАРАЛЛЕЛИЗМ, ГРАНИЦЫ РОСТА, ЦЕЛОСТНОСТЬ")
    print("=" * 74)
    test_ueba_snapshot_is_race_free()
    test_correlator_is_bounded()
    test_correlator_evicts_incidents()
    test_correlator_window_survives_bad_timestamp()
    test_severity_matches_action_threshold()
    test_eventstore_init_is_idempotent()
    test_command_claim_is_exclusive()
    test_stats_is_cached()
    test_state_save_is_atomic()
    print("-" * 74)
    if FAILED:
        print(f"  {BAD} ПРОВАЛЕНО: {len(FAILED)}")
        for f in FAILED:
            print(f"     - {f}")
        return 1
    print(f"  {OK} Параллельная работа, границы роста и целостность подтверждены.")
    return 0


if __name__ == "__main__":
    _sys.exit(main())
