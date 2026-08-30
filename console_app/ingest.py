# -*- coding: utf-8 -*-
"""Стрим-ингестор и фоновые воркеры

Часть консоли защиты. Вынесено из console.py: там 1841 строка держала
маршруты, ингест, триаж и сборку отчётов в одном файле, и правка одного
раздела требовала удерживать в голове все остальные.

Состояние и общие хелперы — в console_app.core, оно ЕДИНСТВЕННОЕ на процесс
и импортируется по имени: объекты (_COR, _STATE, _LOCK) создаются один раз
при импорте core и никогда не переприсваиваются, поэтому у всех разделов
общий экземпляр, а не копии.
"""

import sys
import time
import atexit
import threading
import config
import eventstore
import run_defense
from datetime import datetime, timedelta

# Общее состояние консоли — ЯВНО, а не через `import *`:
# видно, чем раздел пользуется, и статический анализ снова работает.
from .core import CURSOR, FP_MUTE_THRESHOLD, REPLAY_EVENTS, ROOT, \
    SNAPSHOT_PERIOD_S, _COR, _DEMO, _EXECM, _LOCK, _MUTED_CACHE, _SNAP, \
    _STATE, _SUPPRESS, _flog, _repo, muted_rules, _incident_ctx


#: Флаг остановки фоновых потоков.
#:
#: Потоки были `while True` без всякого выключателя: при выходе процесса их
#: убивали посреди работы, в том числе посреди записи в SQLite и посреди
#: обновления состояния коррелятора. WAL спасает от порчи базы, но курсор
#: ингеста при этом мог не успеть сохраниться, и часть событий переигрывалась
#: заново при следующем запуске.
STOP = threading.Event()


def stop_workers():
    """Попросить фоновые потоки завершиться (вызывается через atexit)."""
    STOP.set()


def _refresh_muted():
    """Раз в 10 секунд обновляем список заглушённых правил."""
    now = time.time()
    if now - _MUTED_CACHE["ts"] < 10:
        return
    _MUTED_CACHE["ts"] = now
    try:
        _MUTED_CACHE["rules"] = dict(muted_rules())
    except Exception:
        # если список молча не обновится, тюнинг по FP перестанет работать,
        # а в интерфейсе это будет выглядеть как «правило всё ещё шумит»
        _flog.error("не удалось обновить список заглушённых правил", exc_info=True)

def _replay_history(pos):
    """Восстановить алерты и инциденты после перезапуска консоли.

    Инциденты живут в памяти, а курсор ингеста переживает рестарт: без
    этого шага после перезапуска дашборд был пустым, хотя события в
    хранилище есть. Прогоняем последние REPLAY_EVENTS событий через тот
    же детектор и коррелятор — состояние восстанавливается, а живой
    курсор не двигается, поэтому новые события не теряются и не дублятся.

    Побочных эффектов нет: консоль не пишет алерты в стор (это делает
    процесс защиты), а id инцидентов детерминированы, поэтому ранее
    выставленные вердикты TP/FP снова прилипают к тем же инцидентам.
    """
    if pos <= 0:
        return 0
    # ОКНО РЕПЛЕЯ ПРИВЯЗАНО К БЛОКУ, А НЕ К ТЕКУЩЕМУ КУРСОРУ.
    #
    # Было `start = pos - REPLAY_EVENTS`: при каждом перезапуске окно сдвигалось
    # на столько событий, сколько мир успел записать. Инцидент, начало которого
    # выпало из окна, пересобирался с ДРУГОГО первого события, а его
    # идентификатор — хэш от (актор, время начала) — менялся вместе с ним.
    #
    # Практическое следствие, поймано при разборе: после перезапуска консоли ни
    # один из двадцати идентификаторов, по которым аналитик вёл работу, не
    # нашёлся. Вердикты TP/FP и заметки хранятся в сторе по идентификатору
    # инцидента — то есть работа аналитика осиротела молча.
    #
    # Округление начала окна вниз до границы блока делает окно устойчивым:
    # пока курсор растёт внутри блока, инциденты пересобираются с того же
    # события и сохраняют идентификаторы.
    _BLOCK = max(1, REPLAY_EVENTS // 4)
    start = max(0, ((pos - REPLAY_EVENTS) // _BLOCK) * _BLOCK)
    seen = 0
    cur = start
    try:
        while cur < pos:
            batch = eventstore.read_since(cur, limit=500)
            if not batch:
                break
            for ev in batch:
                if ev["_id"] > pos:
                    cur = pos
                    break
                cur = ev["_id"]
                try:
                    det = run_defense.process(ev)
                except Exception:
                    # Раньше событие просто пропускалось. Если детектор падает
                    # систематически (например после смены схемы признаков),
                    # консоль показывала бы «алертов нет» и ни одной ошибки.
                    _flog.error("детектор упал на событии — пропускаю",
                                exc_info=True,
                                extra={"ctx": {"event_id": ev.get("_id"),
                                               "actor": ev.get("actor"),
                                               "action": ev.get("action")}})
                    continue
                seen += 1
                # Переигранные события — тоже обработанные. Счётчик рос
                # только в живом цикле, поэтому после перезапуска консоли
                # на обзоре стояло «обработано защитой 0» рядом с
                # «алертов 13»: из нуля событий тринадцать алертов не
                # получаются, и показатель читался как сломанный.
                with _LOCK:
                    _STATE["processed"] += 1
                if not det.get("alert"):
                    continue
                top = max(det["alerts"], key=lambda a: a["risk"])
                if _SUPPRESS.is_duplicate(ev.get("actor"), top.get("rule_id"), ev.get("ts_sim")):
                    continue
                o = run_defense.observed(ev)
                # ВНУТРИ ЗАМКА: обработчики HTTP читают _COR.incidents, и
                # добавление инцидента параллельно их обходу давало
                # RuntimeError в маршруте, то есть 500 на дашборде.
                with _LOCK:
                    iid = _COR.add(o, det)
                    _STATE["alerts_total"] += 1
                    _STATE["alerts"].append({
                        "id": ev["_id"], "ts_sim": o.get("ts_sim"),
                        "actor": o.get("actor"), "action": o.get("action"),
                        "project": _repo(o.get("project")), "path": o.get("path"),
                        "risk": det["risk"], "reason": top["reason"],
                        "technique": top.get("technique"), "tactic": top.get("tactic"),
                        "incident": iid,
                    })
                    if o.get("actor"): _STATE["by_actor"][o["actor"]] += 1
                    _rp = _repo(o.get("project"))
                    if _rp: _STATE["by_repo"][_rp] += 1
                    for a2 in det["alerts"]:
                        if a2.get("tactic"): _STATE["by_tactic"][a2["tactic"]] += 1
                        if a2.get("technique"): _STATE["fired_tech"][a2["technique"]] += 1
                        if a2.get("rule_id"): _STATE["fired_rule"][a2["rule_id"]] += 1
    except Exception:
        _flog.error("реплей истории прерван", exc_info=True)
    return seen

def _ingestor():
    eventstore.init()
    pos = eventstore.get_cursor(CURSOR)
    _STATE["running"] = True
    try:
        n = _replay_history(pos)
        with _LOCK:
            inc = len(_COR.incidents); al = _STATE["alerts_total"]
        _flog.info("история восстановлена после рестарта",
                   extra={"ctx": {"replayed": n, "alerts": al, "incidents": inc}})
        print(f"[replay] переиграно событий: {n} | алертов: {al} | инцидентов: {inc}")
    except Exception:
        _flog.error("не удалось восстановить историю", exc_info=True)
    _flog.info("ингест консоли запущен", extra={"ctx": {"cursor": pos}})
    while not STOP.is_set():
        try:
            _refresh_muted()
            batch = eventstore.read_since(pos, limit=500)
            for ev in batch:
                pos = ev["_id"]
                with _LOCK:
                    _STATE["processed"] += 1
                try:
                    det = run_defense.process(ev)
                except Exception:
                    _flog.error("детектор упал на событии — пропускаю",
                                exc_info=True,
                                extra={"ctx": {"event_id": ev.get("_id"),
                                               "actor": ev.get("actor"),
                                               "action": ev.get("action")}})
                    continue
                if det.get("alert"):
                    # тюнинг аналитика: выкидываем сработки правил, подтверждённых как FP
                    # ПРИГЛУШЕНИЕ ПОНИЖАЕТ, А НЕ УДАЛЯЕТ.
                    #
                    # Раньше сработка приглушённого правила выбрасывалась до
                    # корреляции: улика исчезала целиком, а если приглушены были
                    # все — событие пропадало, и в интерфейсе оставался лишь
                    # общий счётчик muted_hits. Теперь сработка остаётся с
                    # пометкой muted и пониженным риском: очередь аналитика она
                    # не наполняет, но доказательство сохраняется.
                    _mut = _MUTED_CACHE["rules"]
                    if _mut:
                        _kept, _muted_n = [], 0
                        for a in det["alerts"]:
                            if _mut.get(a.get("rule_id"), 0) >= FP_MUTE_THRESHOLD:
                                _muted_n += 1
                                a = dict(a, muted=True,
                                         risk=round(min(a.get("risk", 0.0), 0.15), 3))
                            _kept.append(a)
                        if _muted_n:
                            with _LOCK:
                                _STATE["muted_hits"] = _STATE.get("muted_hits", 0) + _muted_n
                            det = dict(det, alerts=_kept,
                                       risk=max((a["risk"] for a in _kept), default=0.0))
                        if _kept and all(a.get("muted") for a in _kept):
                            continue
                    _top0 = max(det["alerts"], key=lambda a: a["risk"])
                    if _SUPPRESS.is_duplicate(ev.get("actor"), _top0.get("rule_id"), ev.get("ts_sim")):
                        with _LOCK:
                            _STATE["suppressed"] = _STATE.get("suppressed", 0) + 1
                        continue
                    o = run_defense.observed(ev)
                    top = max(det["alerts"], key=lambda a: a["risk"])
                    # наблюдаемые сигналы контента — кладём в инцидент для LLM-разбора
                    sig = {"shannon_entropy": o.get("shannon_entropy"),
                           # ДЛЯ ТРИАЖА ВАЖНЫ НЕ-ЗАГЛУШЕЧНЫЕ совпадения: раньше
                           # сюда шли все regex_hits, а «плейсхолдер» считался по
                           # файлу, поэтому одно слово вроде TODO превращало
                           # настоящий секрет в «похоже на пример».
                           "regex_hits": o.get("real_hits") or o.get("regex_hits") or [],
                           "placeholder_signal": bool(o.get("placeholder_signal")),
                           "filename_signal": bool(o.get("filename_signal")),
                           "evasion_kinds": o.get("evasion_kinds") or []}
                    # ВСЯ работа с коррелятором — под общим замком: слияние
                    # signals шло вне его, и обработчик HTTP мог увидеть
                    # инцидент с добавленной сработкой, но ещё не пересчитанными
                    # risk/severity.
                    with _LOCK:
                        iid = _COR.add(o, det)
                        inc = _COR.incidents[iid]
                        g = inc.setdefault("signals", {"regex": set(), "max_entropy": 0.0,
                                                       "placeholder": False, "filename": False,
                                                       "evasion": set()})
                        g.setdefault("evasion", set())
                        g["regex"].update(sig["regex_hits"])
                        if sig["shannon_entropy"]:
                            g["max_entropy"] = max(g["max_entropy"], sig["shannon_entropy"])
                        g["placeholder"] = g["placeholder"] or sig["placeholder_signal"]
                        g["filename"] = g["filename"] or sig["filename_signal"]
                        g["evasion"].update(sig["evasion_kinds"])
                        _STATE["alerts_total"] += 1
                        _STATE["alerts"].append({
                            "id": ev["_id"], "ts_sim": o.get("ts_sim"),
                            "actor": o.get("actor"), "action": o.get("action"),
                            "project": _repo(o.get("project")), "path": o.get("path"),
                            "risk": det["risk"], "reason": top["reason"],
                            "technique": top.get("technique"), "tactic": top.get("tactic"),
                            "incident": iid,
                        })
                        if o.get("actor"): _STATE["by_actor"][o["actor"]] += 1
                        _rp = _repo(o.get("project"))
                        if _rp: _STATE["by_repo"][_rp] += 1
                        for a in det["alerts"]:
                            if a.get("tactic"): _STATE["by_tactic"][a["tactic"]] += 1
                            if a.get("technique"): _STATE["fired_tech"][a["technique"]] += 1
                            if a.get("rule_id"): _STATE["fired_rule"][a["rule_id"]] += 1
            if batch:
                eventstore.set_cursor(CURSOR, pos)
            else:
                STOP.wait(1.5)
        except Exception:
            _flog.error("сбой цикла ингеста — повтор через 3с", exc_info=True,
                        extra={"ctx": {"cursor": pos}})
            STOP.wait(3)
    # Курсор сохраняем ПЕРЕД выходом: иначе последняя пачка переигрывается
    # заново при следующем запуске.
    try:
        eventstore.set_cursor(CURSOR, pos)
        _flog.info("ингест консоли остановлен", extra={"ctx": {"cursor": pos}})
    except Exception:
        _flog.error("не удалось сохранить курсор при остановке", exc_info=True)

def _run_triage(iid, force=False):
    i = _COR.get(iid)
    if not i:
        return None
    sig = (len(i.get("techniques", [])), len(i.get("alerts", [])))
    if not force and i.get("triage") and i.get("_triage_sig") == sig:
        return i["triage"]
    try:
        import llm_client
        res = llm_client.triage(_incident_ctx(iid, i))
    except Exception as e:
        res = {"error": str(e), "_source": "error"}
    with _LOCK:
        i["triage"] = res
        i["_triage_sig"] = sig
    return res

def _triage_worker():
    """\u0424\u043e\u043d\u043e\u0432\u044b\u0439 \u0430\u0432\u0442\u043e-\u0442\u0440\u0438\u0430\u0436 \u043a\u0430\u0436\u0434\u043e\u0433\u043e \u0438\u043d\u0446\u0438\u0434\u0435\u043d\u0442\u0430-\u043a\u0430\u043c\u043f\u0430\u043d\u0438\u0438."""
    if not getattr(config, "LLM_AUTO_TRIAGE", True):
        return
    min_risk = getattr(config, "LLM_AUTO_TRIAGE_MIN_RISK", 0.6)
    while not STOP.is_set():
        try:
            with _LOCK:
                pending = [(i["id"], i) for i in _COR.incidents.values()]
            for iid, i in pending:
                if i.get("is_campaign") or i.get("risk", i.get("max_risk", 0)) >= min_risk:
                    sig = (len(i.get("techniques", [])), len(i.get("alerts", [])))
                    if i.get("_triage_sig") != sig:
                        _run_triage(iid)
            STOP.wait(2.0)
        except Exception:
            _flog.error("сбой фонового авто-триажа", exc_info=True)
            STOP.wait(4.0)

def _take_metrics_snapshot():
    """Один прогон metrics.py и запись результата в историю."""
    import subprocess
    import os
    import json as _json
    base = ROOT
    _SNAP["running"] = True
    try:
        p = subprocess.run([sys.executable, os.path.join(base, "metrics.py"), "--json"],
                           cwd=base, capture_output=True, text=True, timeout=180)
        if p.returncode != 0:
            _SNAP["error"] = (p.stderr or "").strip()[-200:] or "metrics.py завершился с ошибкой"
            return False
        m = _json.loads(p.stdout)
        eventstore.add_metrics_snapshot({
            "detection_rate": m.get("detection_rate"), "mttd": m.get("mttd_sim_min"),
            "fp_rate": m.get("fp_rate"), "coverage": m.get("attack_coverage"),
            "alerts": m.get("alerts"), "incidents": m.get("incidents")})
        _SNAP["last"] = datetime.now().isoformat(timespec="seconds")
        _SNAP["count"] += 1
        _SNAP["error"] = None
        return True
    except Exception as e:
        _SNAP["error"] = str(e)[:200]
        _flog.warning("фоновый снапшот метрик не удался", exc_info=True)
        return False
    finally:
        _SNAP["running"] = False

def _metrics_snapshot_worker():
    """Фоновый пересчёт метрик — для трендов.

    Первый снапшот снимается почти сразу, а не через пять минут: раньше
    экран трендов первые пять минут после запуска показывал «снапшотов
    пока нет», и выглядело это как неработающий раздел.
    """
    if STOP.wait(20):
        return
    while not STOP.is_set():
        _take_metrics_snapshot()
        _SNAP["next"] = (datetime.now() + timedelta(seconds=SNAPSHOT_PERIOD_S)).isoformat(timespec="seconds")
        STOP.wait(SNAPSHOT_PERIOD_S)

def _demo_worker():
    """Генератор демо-потока.

    Путь был ROOT/make_demo.py, а файл лежит в tools/. Скрипт ниоткуда не
    импортируется, поэтому статически ошибка не проявлялась: кнопка «Шаг 1 —
    сгенерировать демо-поток» на экране онбординга НИКОГДА не работала, всегда
    возвращая FileNotFoundError. Новый пользователь, идущий по подсказанному
    самим продуктом пути, упирался в мёртвый элемент управления сразу, а для
    того, у кого нет своего GitLab, это единственный способ наполнить журнал.
    docker-entrypoint.sh при этом звал правильный путь — два места в проекте
    расходились между собой.
    """
    import os
    import subprocess
    base = ROOT
    script = os.path.join(base, "tools", "make_demo.py")
    if not os.path.exists(script):
        _DEMO["rc"] = -1
        _DEMO["msg"] = "не найден генератор демо: " + script
        _flog.error("демо-генератор отсутствует", extra={"ctx": {"path": script}})
        _DEMO["running"] = False
        return
    try:
        # БЕЗ --fresh. Этот ключ УДАЛЯЕТ data/events.db, а консоль держит её
        # открытой и читает из неё прямо сейчас: кнопка на экране онбординга
        # снесла бы журнал из-под работающего ингеста. Очистка перед первым
        # запуском — дело docker-entrypoint.sh, где стор заведомо пуст.
        # Демо ДОПОЛНЯЕТ поток, это и есть поведение make_demo.py по умолчанию.
        p = subprocess.run([sys.executable, script],
                           cwd=base, capture_output=True, text=True, timeout=600)
        _DEMO["rc"] = p.returncode
        _DEMO["msg"] = ("демо готово — события добавлены" if p.returncode == 0
                        else "ошибка make_demo: " + (p.stderr or p.stdout or "?")[-200:])
        if p.returncode != 0:
            _flog.error("генерация демо не удалась",
                        extra={"ctx": {"rc": p.returncode,
                                       "stderr": (p.stderr or "")[-400:]}})
    except Exception as e:
        _DEMO["rc"] = -1
        _DEMO["msg"] = f"ошибка: {e}"
        _flog.error("генерация демо упала", exc_info=True)
    finally:
        _DEMO["running"] = False

def _metrics_worker():
    import os
    import subprocess
    import json as _json
    base = ROOT
    try:
        p = subprocess.run([sys.executable, os.path.join(base, "metrics.py"), "--json"],
                           cwd=base, capture_output=True, text=True, timeout=240)
        if p.returncode == 0:
            _EXECM["data"] = _json.loads(p.stdout)
            _EXECM["err"] = ""
        else:
            _EXECM["err"] = (p.stderr or p.stdout or "?")[-200:]
    except Exception as e:
        _EXECM["err"] = str(e)
    finally:
        _EXECM["ts"] = time.time()
        _EXECM["running"] = False


# ----------------------------------------------------------------------
def start_workers():
    """Поднять фоновые потоки консоли.

    Вынесено из main() отдельной функцией: раньше потоки стартовали только при
    запуске из командной строки, а тесты и инструменты, поднимавшие приложение
    импортом, получали консоль без ингеста — и молча тестировали не то.
    Теперь точка одна, и она же выключаемая (create_app(start_workers=False)).

    Потоки демонические: консоль — интерактивный инструмент, при выходе она
    не должна ждать завершения чтения журнала.
    """
    eventstore.init()
    try:
        # Команда, захваченная упавшим процессом мира, иначе остаётся в
        # состоянии «выполняется» навсегда и не выполняется никогда.
        eventstore.reap_stale_commands()
    except Exception:
        _flog.error("не удалось вернуть в очередь зависшие команды", exc_info=True)
    atexit.register(stop_workers)
    for target, name in ((_ingestor, "ingestor"),
                         (_triage_worker, "triage"),
                         (_metrics_snapshot_worker, "metrics-snapshot")):
        threading.Thread(target=target, name=name, daemon=True).start()
