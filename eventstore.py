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
_STATE = {"db": None, "path": None, "enabled": False}

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
CREATE TABLE IF NOT EXISTS annotations (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT,
    label     TEXT
);
"""


def init(path=None, enabled=True):
    """Открыть/создать БД. Вызывается и в «мире», и в «защите»."""
    import config
    cfg = getattr(config, "EVENT_STORE", {}) or {}
    path = path or cfg.get("path", "data/events.db")
    if not os.path.isabs(path):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), path)
    with _LOCK:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        db = sqlite3.connect(path, check_same_thread=False, timeout=30)
        db.execute("PRAGMA journal_mode=WAL;")
        db.execute("PRAGMA synchronous=NORMAL;")
        db.executescript(_SCHEMA)
        db.commit()
        _STATE["db"] = db
        _STATE["path"] = path
        _STATE["enabled"] = bool(enabled and cfg.get("enabled", True))
    _log.info("event-store открыт", extra={"ctx": {
        "path": path, "enabled": _STATE["enabled"]}})
    return path


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


def count(where=None):
    if not enabled():
        return 0
    q = "SELECT COUNT(*) FROM events"
    with _LOCK:
        row = _STATE["db"].execute(q).fetchone()
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


def stats():
    if not enabled():
        return {"enabled": False}
    with _LOCK:
        total = _STATE["db"].execute("SELECT COUNT(*) FROM events").fetchone()[0]
        anom = _STATE["db"].execute("SELECT COUNT(*) FROM events WHERE is_anomaly=1 AND meta=0").fetchone()[0]
        camp = _STATE["db"].execute("SELECT COUNT(DISTINCT campaign_id) FROM events WHERE campaign_id IS NOT NULL").fetchone()[0]
        eps = _STATE["db"].execute("SELECT COUNT(DISTINCT episode_id) FROM events WHERE episode_id IS NOT NULL").fetchone()[0]
    return {"enabled": True, "path": _STATE["path"], "events": total,
            "anomaly_events": anom, "episodes": eps, "campaigns": camp}


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
    """Забрать старейшую pending-команду и пометить done. Возвращает dict|None."""
    if not enabled():
        return None
    with _LOCK:
        row = _STATE["db"].execute(
            "SELECT id,type,payload FROM commands WHERE status='pending' ORDER BY id ASC LIMIT 1"
        ).fetchone()
        if not row:
            return None
        _STATE["db"].execute("UPDATE commands SET status='done' WHERE id=?", (row[0],))
        _STATE["db"].commit()
    try:
        payload = json.loads(row[2]) if row[2] else {}
    except Exception:
        payload = {}
    return {"id": row[0], "type": row[1], "payload": payload}


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


def set_command_result(cid, result):
    if not enabled():
        return
    with _LOCK:
        _STATE["db"].execute("UPDATE commands SET result=? WHERE id=?", (result, cid))
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
            except Exception:
                pass
        _STATE["db"] = None
