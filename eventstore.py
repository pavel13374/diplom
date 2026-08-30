"""
Event-store на SQLite — общий «backbone» между процессом «МИР» (пишет события)
и процессом «ЗАЩИТА» (читает поток по курсору). Тематически = лог SIEM.

Почему SQLite, а не просто jsonl:
  • атомарная дозапись, переживает рестарт обоих процессов;
  • чтение «с позиции» по монотонному id (курсор) без потерь/дублей;
  • WAL-режим = один писатель + много читателей одновременно (разные процессы).

Зависимостей нет (sqlite3 из stdlib). jsonl остаётся для совместимости/выгрузки.

Таблицы:
  events(id INTEGER PK AUTOINCREMENT, ts_real, ts_sim, actor, action, project,
         episode_id, campaign_id, is_anomaly, meta, payload JSON)
  cursors(name TEXT PK, pos INTEGER)   — позиции читателей (например, "defense")
"""
import os
import json
import sqlite3
import logging
import threading

_log = logging.getLogger("eventstore")

_LOCK = threading.Lock()
_STATE = {"db": None, "path": None, "enabled": False, "error": None}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_real     TEXT,
    ts_sim      TEXT,
    actor       TEXT,
    action      TEXT,
    project     TEXT,
    episode_id  TEXT,
    campaign_id TEXT,
    is_anomaly  INTEGER,
    meta        INTEGER,
    payload     TEXT
);
CREATE INDEX IF NOT EXISTS ix_events_actor    ON events(actor);
CREATE INDEX IF NOT EXISTS ix_events_action   ON events(action);
CREATE INDEX IF NOT EXISTS ix_events_episode  ON events(episode_id);
CREATE INDEX IF NOT EXISTS ix_events_campaign ON events(campaign_id);
-- Индексы под stats(): без них каждый опрос дашборда шёл полным перебором.
CREATE INDEX IF NOT EXISTS ix_events_meta      ON events(meta);
CREATE INDEX IF NOT EXISTS ix_events_anomaly   ON events(is_anomaly, meta);
CREATE TABLE IF NOT EXISTS cursors (
    name TEXT PRIMARY KEY,
    pos  INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS commands (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT,
    type    TEXT,
    payload TEXT,
    status  TEXT DEFAULT 'pending',
    result  TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id  INTEGER,
    ts_sim    TEXT,
    actor     TEXT,
    action    TEXT,
    project   TEXT,
    technique TEXT,
    tactic    TEXT,
    risk      REAL,
    reason    TEXT
);
CREATE TABLE IF NOT EXISTS incident_status (
    iid       INTEGER PRIMARY KEY,
    status    TEXT DEFAULT 'new',
    verdict   TEXT,
    reason    TEXT,
    owner     TEXT,
    updated   TEXT
);
CREATE TABLE IF NOT EXISTS metrics_history (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT,
    detection_rate REAL,
    mttd      REAL,
    fp_rate   REAL,
    coverage  REAL,
    alerts    INTEGER,
    incidents INTEGER
);
CREATE TABLE IF NOT EXISTS cases (
    id        TEXT PRIMARY KEY,
    payload   TEXT,
    updated   TEXT
);
CREATE TABLE IF NOT EXISTS annotations (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT,
    label     TEXT
);
"""


def init(path=None, enabled=True, force=False):
    """Открыть/создать БД. Идемпотентно.

    ПОЧЕМУ ИДЕМПОТЕНТНО. Раньше каждый вызов открывал НОВОЕ соединение и
    перетирал прежнее, не закрывая: два подряд init() давали два разных
    объекта. А зовут функцию отовсюду — events.init(), create_app() ->
    start_workers(), сам _ingestor(), run_defense.run(), почти каждый скрипт в
    tools/ и, что хуже всего, webapp.api_health НА КАЖДОМ ОПРОСЕ, если стор
    оказался закрыт. Брошенные соединения держат дескрипторы и снимки WAL,
    поэтому чекпойнт не проходит — правдоподобное объяснение тому, что на
    рабочей машине рядом с events.db на 66 МБ лежит -wal на 4 МБ.

    force=True нужен там, где переоткрытие осмысленно (api_fresh_start
    подменяет файл базы).
    """
    import config
    cfg = getattr(config, "EVENT_STORE", {}) or {}
    path = path or cfg.get("path", "data/events.db")
    if not os.path.isabs(path):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), path)
    with _LOCK:
        if not force and _STATE["db"] is not None and _STATE["path"] == path:
            try:
                _STATE["db"].execute("SELECT 1").fetchone()
                _STATE["enabled"] = bool(enabled and cfg.get("enabled", True))
                return path
            except Exception:
                # соединение испортилось — переоткроем ниже
                _log.warning("соединение с event-store нерабочее, переоткрываю",
                             exc_info=True)
        if _STATE["db"] is not None:
            try:
                _STATE["db"].close()
            except sqlite3.Error:
                pass
            _STATE["db"] = None
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            db = sqlite3.connect(path, check_same_thread=False, timeout=30)
            db.execute("PRAGMA journal_mode=WAL;")
            db.execute("PRAGMA synchronous=NORMAL;")
            db.executescript(_SCHEMA)
            db.commit()
        except Exception as ex:
            # НЕДОСТУПНАЯ БАЗА ДОЛЖНА БЫТЬ ВИДНА.
            #
            # Раньше исключение улетало наверх и глушилось у вызывающего, а
            # enabled() возвращал False. Внешне это неотличимо от «данных ещё
            # нет»: /api/stats отдавал store_events = 0, интерфейс рисовал
            # прочерки, и разобраться было нечем. Причина при этом бывает
            # вполне конкретной — например «disk I/O error» на сетевом диске,
            # где WAL не работает.
            _STATE["db"] = None
            _STATE["path"] = path
            _STATE["enabled"] = False
            _STATE["error"] = f"{type(ex).__name__}: {ex}"[:300]
            _log.error("event-store НЕ открыт — защита не увидит ни одного "
                       "события", exc_info=True,
                       extra={"ctx": {"path": path, "error": _STATE["error"]}})
            return path
        _STATE["db"] = db
        _STATE["path"] = path
        _STATE["enabled"] = bool(enabled and cfg.get("enabled", True))
        _STATE["error"] = None
    _log.info("event-store открыт", extra={"ctx": {
        "path": path, "enabled": _STATE["enabled"]}})
    return path


def last_error():
    """Причина недоступности стора (или None). Отдаётся в /api/health."""
    return _STATE.get("error")


def enabled():
    return _STATE["enabled"] and _STATE["db"] is not None


def append(rec: dict):
    """Записать событие (dict). Возвращает id или None."""
    if not enabled():
        return None
    try:
        with _LOCK:
            cur = _STATE["db"].execute(
                "INSERT INTO events (ts_real, ts_sim, actor, action, project, "
                "episode_id, campaign_id, is_anomaly, meta, payload) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (rec.get("ts_real"), rec.get("ts_sim"), rec.get("actor"),
                 rec.get("action"), rec.get("project"), rec.get("episode_id"),
                 rec.get("campaign_id"), 1 if rec.get("is_anomaly") else 0,
                 1 if rec.get("meta") else 0,
                 json.dumps(rec, ensure_ascii=False)))
            _STATE["db"].commit()
            return cur.lastrowid
    except Exception:
        _log.error("append не записал событие", exc_info=True, extra={"ctx": {
            "actor": rec.get("actor"), "action": rec.get("action")}})
        return None


def read_since(after_id=0, limit=1000, include_meta=False):
    """Вернуть события с id > after_id (по возрастанию). Для стрим-ингестора.
    Возвращает list[dict] с добавленным ключом _id (позиция в сторе)."""
    if not enabled():
        return []
    q = "SELECT id, payload FROM events WHERE id > ?"
    if not include_meta:
        q += " AND meta = 0"
    q += " ORDER BY id ASC LIMIT ?"
    with _LOCK:
        rows = _STATE["db"].execute(q, (after_id, limit)).fetchall()
    out = []
    for _id, payload in rows:
        try:
            r = json.loads(payload)
        except Exception:
            _log.warning("битый payload в event-store", extra={"ctx": {"id": _id}})
            r = {}
        r["_id"] = _id
        out.append(r)
    return out


def max_id():
    if not enabled():
        return 0
    with _LOCK:
        row = _STATE["db"].execute("SELECT COALESCE(MAX(id),0) FROM events").fetchone()
    return row[0] if row else 0


def count(actor=None, action=None):
    """Число событий, при желании с фильтром.

    Раньше сигнатура была count(where=None), и аргумент ПОЛНОСТЬЮ игнорировался:
    count() и count("actor=\'nobody\'") давали одно и то же число. Вызывающий,
    доверившийся сигнатуре, получал неверный ответ без всякой ошибки. Фильтр
    сделан настоящим и параметризованным (никакой склейки SQL из строк).
    """
    if not enabled():
        return 0
    q = "SELECT COUNT(*) FROM events WHERE 1=1"
    args = []
    if actor:
        q += " AND actor = ?"; args.append(actor)
    if action:
        q += " AND action = ?"; args.append(action)
    with _LOCK:
        row = _STATE["db"].execute(q, args).fetchone()
    return row[0] if row else 0


def get_cursor(name):
    if not enabled():
        return 0
    with _LOCK:
        row = _STATE["db"].execute("SELECT pos FROM cursors WHERE name=?", (name,)).fetchone()
    return row[0] if row else 0


def set_cursor(name, pos):
    if not enabled():
        return
    with _LOCK:
        _STATE["db"].execute(
            "INSERT INTO cursors(name,pos) VALUES(?,?) "
            "ON CONFLICT(name) DO UPDATE SET pos=excluded.pos", (name, int(pos)))
        _STATE["db"].commit()


#: Кэш stats(). Ключ — максимальный id: если новых событий нет, пересчитывать
#: нечего.
_STATS_CACHE = {"max_id": -1, "ts": 0.0, "data": None}
_STATS_TTL_S = 2.0


def stats():
    """Сводка по журналу. КЭШИРУЕТСЯ.

    Четыре полных прохода по таблице — COUNT(*), COUNT(*) с фильтром и два
    COUNT(DISTINCT) — на базе, которая на рабочей машине занимает 66 МБ. А
    зовут её из /api/stats, обоих /api/health и /api/onboarding, то есть с
    частотой опроса дашборда, на КАЖДУЮ открытую вкладку. Соединение общее и
    под общим замком с пишущим потоком, поэтому подсчёт ещё и притормаживал
    приём событий. Это самое правдоподобное объяснение тому, что консоль
    «тормозит тем сильнее, чем больше журнал».
    """
    if not enabled():
        return {"enabled": False, "error": _STATE.get("error")}
    import time as _t
    mid = max_id()
    c = _STATS_CACHE
    if c["data"] is not None and c["max_id"] == mid and (_t.time() - c["ts"]) < _STATS_TTL_S:
        return dict(c["data"])
    with _LOCK:
        db = _STATE["db"]
        total = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        anom = db.execute("SELECT COUNT(*) FROM events WHERE is_anomaly=1 AND meta=0").fetchone()[0]
        camp = db.execute("SELECT COUNT(DISTINCT campaign_id) FROM events WHERE campaign_id IS NOT NULL").fetchone()[0]
        eps = db.execute("SELECT COUNT(DISTINCT episode_id) FROM events WHERE episode_id IS NOT NULL").fetchone()[0]
    data = {"enabled": True, "path": _STATE["path"], "events": total,
            "anomaly_events": anom, "episodes": eps, "campaigns": camp}
    c.update(max_id=mid, ts=_t.time(), data=dict(data))
    return data


def last_event():
    """Последнее видимое (не meta) событие: {ts, action, actor} | None. Для статус-бара."""
    if not enabled():
        return None
    with _LOCK:
        row = _STATE["db"].execute(
            "SELECT ts_real, action, actor FROM events WHERE meta=0 "
            "ORDER BY id DESC LIMIT 1").fetchone()
    if not row:
        return None
    return {"ts": row[0], "action": row[1], "actor": row[2]}


def set_incident_status(iid, status=None, verdict=None, reason=None, owner=None):
    """Апдейт статуса инцидента (воркфлоу аналитика). Переживает рестарт консоли."""
    if not enabled():
        return
    import datetime as _dt
    now = _dt.datetime.now().isoformat(timespec="seconds")
    with _LOCK:
        row = _STATE["db"].execute("SELECT status,verdict,reason,owner FROM incident_status WHERE iid=?", (iid,)).fetchone()
        cur = dict(zip(("status", "verdict", "reason", "owner"), row)) if row else {}
        vals = {
            "status": status if status is not None else cur.get("status", "new"),
            "verdict": verdict if verdict is not None else cur.get("verdict"),
            "reason": reason if reason is not None else cur.get("reason"),
            "owner": owner if owner is not None else cur.get("owner"),
        }
        _STATE["db"].execute(
            "INSERT INTO incident_status(iid,status,verdict,reason,owner,updated) VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(iid) DO UPDATE SET status=excluded.status,verdict=excluded.verdict,"
            "reason=excluded.reason,owner=excluded.owner,updated=excluded.updated",
            (iid, vals["status"], vals["verdict"], vals["reason"], vals["owner"], now))
        _STATE["db"].commit()
    return {**vals, "updated": now}


def all_incident_status():
    if not enabled():
        return {}
    with _LOCK:
        rows = _STATE["db"].execute("SELECT iid,status,verdict,reason,owner,updated FROM incident_status").fetchall()
    return {r[0]: {"status": r[1], "verdict": r[2], "reason": r[3], "owner": r[4], "updated": r[5]} for r in rows}



# ----------------------------------------------------------------------
#  ДЕЛА (расследования)
# ----------------------------------------------------------------------
# Дело — это несколько инцидентов, собранных в одно расследование:
# ответственный, статус, приоритет, история действий, заметки.
#
# Раньше дела жили ТОЛЬКО в localStorage браузера. Получалась несогласованность,
# которая обнаруживается в худший момент: вердикты TP/FP хранились на сервере и
# честно переживали перезапуск, а собранное аналитиком расследование исчезало
# при открытии консоли с другой машины или после очистки данных сайта — без
# единого предупреждения.
#
# Хранится целиком как JSON, а не разложенным по колонкам: у дела свободная
# форма (список инцидентов, произвольная история действий), и раскладывать её
# по столбцам пришлось бы менять при каждом добавлении поля в интерфейсе.
# Запросов по внутренностям дела нет — только чтение и запись целиком.

def list_cases():
    """Все дела, свежие первыми."""
    if not enabled():
        return []
    import json as _j
    with _LOCK:
        rows = _STATE["db"].execute(
            "SELECT payload FROM cases ORDER BY updated DESC").fetchall()
    out = []
    for (payload,) in rows:
        try:
            out.append(_j.loads(payload))
        except Exception:
            logging.getLogger("eventstore").error("дело не разобралось из хранилища — пропущено", exc_info=True)
    return out


def save_case(case):
    """Создать или обновить дело. Ключ — case['id']."""
    if not enabled() or not isinstance(case, dict):
        return None
    cid = str(case.get("id") or "").strip()
    if not cid:
        return None
    import json as _j
    import datetime as _dt
    now = _dt.datetime.now().isoformat(timespec="seconds")
    case = dict(case)
    case["updated"] = now
    with _LOCK:
        _STATE["db"].execute(
            "INSERT INTO cases(id,payload,updated) VALUES(?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,updated=excluded.updated",
            (cid, _j.dumps(case, ensure_ascii=False), now))
        _STATE["db"].commit()
    return case


def delete_case(cid):
    if not enabled():
        return False
    with _LOCK:
        cur = _STATE["db"].execute("DELETE FROM cases WHERE id=?", (str(cid),))
        _STATE["db"].commit()
    return cur.rowcount > 0

def add_metrics_snapshot(m):
    if not enabled() or not m:
        return
    import datetime as _dt
    with _LOCK:
        _STATE["db"].execute(
            "INSERT INTO metrics_history(ts,detection_rate,mttd,fp_rate,coverage,alerts,incidents) "
            "VALUES(?,?,?,?,?,?,?)",
            (_dt.datetime.now().isoformat(timespec="seconds"), m.get("detection_rate"),
             m.get("mttd"), m.get("fp_rate"), m.get("coverage"), m.get("alerts"), m.get("incidents")))
        _STATE["db"].commit()


def metrics_history(limit=500):
    if not enabled():
        return []
    with _LOCK:
        rows = _STATE["db"].execute(
            "SELECT ts,detection_rate,mttd,fp_rate,coverage,alerts,incidents "
            "FROM metrics_history ORDER BY id ASC LIMIT ?", (limit,)).fetchall()
    cols = ["ts", "detection_rate", "mttd", "fp_rate", "coverage", "alerts", "incidents"]
    return [dict(zip(cols, r)) for r in rows]


def add_annotation(label):
    """Метка события на графике трендов (например «добавлено правило X»)."""
    if not enabled():
        return
    import datetime as _dt
    with _LOCK:
        _STATE["db"].execute("INSERT INTO annotations(ts,label) VALUES(?,?)",
                             (_dt.datetime.now().isoformat(timespec="seconds"), label))
        _STATE["db"].commit()


def annotations(limit=200):
    if not enabled():
        return []
    with _LOCK:
        rows = _STATE["db"].execute("SELECT ts,label FROM annotations ORDER BY id ASC LIMIT ?", (limit,)).fetchall()
    return [{"ts": r[0], "label": r[1]} for r in rows]


def enqueue_command(ctype, payload=None):
    """Поставить команду (например, запустить red-кампанию). Возвращает id."""
    if not enabled():
        return None
    import datetime as _dt
    with _LOCK:
        cur = _STATE["db"].execute(
            "INSERT INTO commands(ts,type,payload,status) VALUES(?,?,?,'pending')",
            (_dt.datetime.now().isoformat(timespec="seconds"), ctype,
             json.dumps(payload or {}, ensure_ascii=False)))
        _STATE["db"].commit()
        return cur.lastrowid


def claim_command():
    """Забрать старейшую pending-команду. Возвращает dict|None.

    ── Два дефекта, которые здесь исправлены ──────────────────────────────
    1. ЗАХВАТ БЫЛ НЕ АТОМАРНЫМ МЕЖДУ ПРОЦЕССАМИ. SELECT и UPDATE стояли под
       threading.Lock — замком ВНУТРИ ПРОЦЕССА. Но вся суть этого хранилища в
       том, что мир и консоль — РАЗНЫЕ процессы, ради чего и включён WAL. Два
       мира (или мир плюс скрипт из tools/) могли забрать одну команду и
       выполнить кампанию дважды, испортив разметку, по которой считаются
       метрики. Теперь захват — одно условное предложение внутри BEGIN
       IMMEDIATE: победитель ровно один, кто бы ни соревновался.

    2. СТАТУС СТАНОВИЛСЯ 'done' ДО ВЫПОЛНЕНИЯ. Экран запуска сценариев
       показывал кампанию завершённой в момент, когда её только сняли из
       очереди, а падение посреди выполнения оставляло её «выполненной» без
       результата. Введено состояние 'running'; в 'done'/'failed' переводит
       set_command_result.
    """
    if not enabled():
        return None
    import datetime as _dt
    now = _dt.datetime.now().isoformat(timespec="seconds")
    expire_stale_commands()
    with _LOCK:
        db = _STATE["db"]
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT id,type,payload FROM commands WHERE status='pending' "
                "ORDER BY id ASC LIMIT 1").fetchone()
            if not row:
                db.commit()
                return None
            cur = db.execute(
                "UPDATE commands SET status='running', result=? "
                "WHERE id=? AND status='pending'", ("claimed " + now, row[0]))
            db.commit()
            if cur.rowcount != 1:
                return None          # успел другой процесс
        except Exception:
            try:
                db.rollback()
            except sqlite3.Error:
                pass
            _log.error("не удалось забрать команду из очереди", exc_info=True)
            return None
    try:
        payload = json.loads(row[2]) if row[2] else {}
    except Exception:
        _log.warning("битый payload команды", extra={"ctx": {"id": row[0]}})
        payload = {}
    return {"id": row[0], "type": row[1], "payload": payload}


#: Сколько живёт НЕВЫПОЛНЕННАЯ команда. Запуск сценария и «Реагировать» —
#: интерактивные действия аналитика, а не отложенные задания: их смысл
#: пропадает вместе с моментом, когда человек их нажал.
COMMAND_TTL_S = 900


def expire_stale_commands(older_than_s=None):
    """Снять с очереди команды, которые никто не забрал вовремя.

    ОЧЕРЕДЬ РАЗБИРАЕТСЯ FIFO, И ЭТО БЫЛО ЛОВУШКОЙ. Пока мир остановлен,
    нажатия «Запустить» копятся; на живом стенде накопилось 44 команды
    возрастом до трёх суток. После запуска мира новая команда вставала в
    хвост этой очереди и по одной за итерацию ждала своего часа — с точки
    зрения аналитика кнопка просто не работала. А старые команды в это время
    ВЫПОЛНЯЛИСЬ: стенд проигрывал запросы трёхдневной давности как свежие.

    Обе беды лечит срок годности: невыполненная за COMMAND_TTL_S команда
    помечается просроченной и в работу не идёт.
    """
    if not enabled():
        return 0
    import datetime as _dt
    ttl = COMMAND_TTL_S if older_than_s is None else older_than_s
    cutoff = (_dt.datetime.now() - _dt.timedelta(seconds=ttl)).isoformat(timespec="seconds")
    with _LOCK:
        cur = _STATE["db"].execute(
            # В result кладём только объяснение. Статус хранится отдельным
            # полем и на экране уже переведён, поэтому префикс «failed: »
            # выводился вторым: строка читалась как
            # «ошибка · failed: команда просрочена…».
            "UPDATE commands SET status='failed', "
            "result='команда просрочена — мир не забрал её вовремя' "
            "WHERE status='pending' AND ts < ?", (cutoff,))
        _STATE["db"].commit()
    if cur.rowcount:
        _log.warning("просроченные команды сняты с очереди",
                     extra={"ctx": {"сколько": cur.rowcount, "срок_с": ttl}})
    return cur.rowcount


def pending_commands(limit=200):
    """Сколько команд ждёт исполнения — для показа глубины очереди."""
    if not enabled():
        return 0
    with _LOCK:
        row = _STATE["db"].execute(
            "SELECT COUNT(*) FROM commands WHERE status IN ('pending','running')"
        ).fetchone()
    return int(row[0]) if row else 0


def reap_stale_commands(older_than_s=1800):
    """Вернуть в очередь команды, зависшие в 'running' (процесс упал).

    Без этого падение мира посреди кампании навсегда оставляло команду
    захваченной, и повторно она не выполнялась никогда.
    """
    if not enabled():
        return 0
    import datetime as _dt
    cutoff = (_dt.datetime.now() - _dt.timedelta(seconds=older_than_s)) \
        .isoformat(timespec="seconds")
    with _LOCK:
        cur = _STATE["db"].execute(
            "UPDATE commands SET status='pending', result=NULL "
            "WHERE status='running' AND ts < ?", (cutoff,))
        _STATE["db"].commit()
    if cur.rowcount:
        _log.warning("возвращены в очередь зависшие команды",
                     extra={"ctx": {"сколько": cur.rowcount}})
    return cur.rowcount


def list_commands(limit=20):
    if not enabled():
        return []
    with _LOCK:
        rows = _STATE["db"].execute(
            "SELECT id,ts,type,payload,status,result FROM commands ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    out = []
    for r in rows:
        out.append({"id": r[0], "ts": r[1], "type": r[2],
                    "payload": r[3], "status": r[4], "result": r[5]})
    return out


def set_command_result(cid, result, status=None):
    """Записать результат и перевести команду в терминальное состояние."""
    if not enabled():
        return
    if status is None:
        status = "failed" if str(result or "").startswith("failed") else "done"
    with _LOCK:
        _STATE["db"].execute("UPDATE commands SET result=?, status=? WHERE id=?",
                             (result, status, cid))
        _STATE["db"].commit()


def append_alert(a):
    """Сохранить blue-алерт (для метрик/истории, переживает рестарт)."""
    if not enabled():
        return
    with _LOCK:
        _STATE["db"].execute(
            "INSERT INTO alerts(event_id,ts_sim,actor,action,project,technique,tactic,risk,reason) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (a.get("event_id"), a.get("ts_sim"), a.get("actor"), a.get("action"),
             a.get("project"), a.get("technique"), a.get("tactic"),
             float(a.get("risk", 0)), (a.get("reason") or "")[:300]))
        _STATE["db"].commit()


def list_alerts(limit=200):
    if not enabled():
        return []
    with _LOCK:
        rows = _STATE["db"].execute(
            "SELECT id,event_id,ts_sim,actor,action,project,technique,tactic,risk,reason "
            "FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    cols = ["id","event_id","ts_sim","actor","action","project","technique","tactic","risk","reason"]
    return [dict(zip(cols, r)) for r in rows]


def alert_count():
    if not enabled():
        return 0
    with _LOCK:
        return _STATE["db"].execute("SELECT COUNT(*) FROM alerts").fetchone()[0]


def close():
    with _LOCK:
        if _STATE["db"]:
            try:
                _STATE["db"].commit()
                _STATE["db"].close()
            except sqlite3.Error:
                _log.warning("не удалось корректно закрыть event-store", exc_info=True)
        _STATE["db"] = None
