"""
Слой аудита событий симулятора.

Каждое значимое действие (push, ветка, MR, коммент, merge, approve, issue,
аномалия) пишется строкой JSON в data/events.jsonl. Время берётся из
СИМУЛЯЦИИ (sim_ts) — поэтому временны́е признаки (ночь, выходной, всплески)
корректны, несмотря на то, что коммиты в GitLab штампуются реальным временем.

У каждого события есть метки is_anomaly / anomaly_type / severity — это
«золотой стандарт» для будущего обучения ML. Подавляющее большинство событий
нормальные (is_anomaly=false), аномалии очень редки.

Аннотации: аномальные сценарии оборачивают свои действия в
    with events.tag(anomaly_type="secret_leak_commit", severity="high", ...):
        ...    # все события внутри получат эти метки
"""
import os
import json
import time
import threading
from collections import deque, Counter, defaultdict
from datetime import datetime

import simclock

_LOCK = threading.Lock()
_TL = threading.local()

_STATE = {
    "enabled": False,
    "file": None,
    "fh": None,
    "run_id": None,
    "seq": 0,
    "ring": deque(maxlen=600),     # для веб-хвоста
    "counts": Counter(),           # по action
    "anom_counts": Counter(),      # по anomaly_type
    "total": 0,
    "anomalies": 0,
    "by_actor": defaultdict(lambda: deque(maxlen=150)),
    "actor_counts": defaultdict(Counter),
    "actor_last": {},
    "heat": Counter(),              # "wd:hour" -> всего действий (ритм)
    "heat_anom": Counter(),         # "wd:hour" -> аномалий
    "anom_feed": deque(maxlen=300), # таймлайн инцидентов (по severity)
    "actor_repo": Counter(),        # "actor\x01repo" -> кол-во (граф UEBA)
    "session_id": None,             # id запуска процесса симулятора
    "actor_sessions": {},           # actor -> {"last": datetime, "n": int}
}

SESSION_GAP_MIN = 30                 # разрыв (sim-минут) → новая рабочая сессия актора



# ----------------------------------------------------------------------
def init(path=None, enabled=True):
    """Открывает файл журнала на дозапись. Вызывается при старте симуляции."""
    import config
    cfg = getattr(config, "EVENT_LOG", {}) or {}
    path = path or cfg.get("file", "data/events.jsonl")
    if not os.path.isabs(path):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), path)
    with _LOCK:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        try:
            _STATE["fh"] = open(path, "a", encoding="utf-8")
        except Exception:
            _STATE["fh"] = None
        _STATE["file"] = path
        _STATE["enabled"] = bool(enabled and cfg.get("enabled", True))
        _STATE["run_id"] = datetime.now().strftime("run-%Y%m%d-%H%M%S")
        import uuid
        _STATE["session_id"] = "sess-" + uuid.uuid4().hex[:12]
        _STATE["actor_sessions"] = {}
    return _STATE["run_id"]


def close():
    with _LOCK:
        if _STATE["fh"]:
            try:
                _STATE["fh"].flush(); _STATE["fh"].close()
            except Exception:
                pass
        _STATE["fh"] = None


# ----------------------------------------------------------------------
# Аннотации (контекст для разметки аномалий)
# ----------------------------------------------------------------------
def _stack():
    if not hasattr(_TL, "st"):
        _TL.st = []
    return _TL.st


class tag:
    def __init__(self, **kw):
        self.kw = kw

    def __enter__(self):
        _stack().append(self.kw)
        return self

    def __exit__(self, *a):
        st = _stack()
        if st:
            st.pop()
        return False


def _current_annotation():
    d = {}
    for x in _stack():
        d.update(x)
    return d


# ----------------------------------------------------------------------
def _project_name(project_id):
    import config
    try:
        return config.repo_name(project_id)
    except Exception:
        return str(project_id)


def emit(action, actor=None, role=None, project=None, project_id=None,
         path=None, branch=None, mr_iid=None, message=None, target=None,
         extra=None, anomaly_type=None, severity=None, is_anomaly=None):
    """Записать событие. Метки берутся из явных аргументов ИЛИ из активной аннотации."""
    if not _STATE["enabled"]:
        return
    ann = _current_annotation()
    a_type = anomaly_type or ann.get("anomaly_type")
    sev = severity or ann.get("severity")
    anom = is_anomaly
    if anom is None:
        anom = bool(a_type)

    now_sim = simclock.now()
    rec = {
        "run_id":    _STATE["run_id"],
        "session_id":  _STATE["session_id"],
        "actor_session": None,
        "ts_sim":    now_sim.strftime("%Y-%m-%dT%H:%M:%S"),
        "ts_real":   datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "hour":      now_sim.hour,
        "weekday":   now_sim.weekday(),
        "is_night":  not (_work_start() <= now_sim.hour < _work_end()),
        "is_weekend": now_sim.weekday() >= 5,
        "actor":     actor,
        "role":      role,
        "action":    action,
        "project":   project or (_project_name(project_id) if project_id is not None else None),
        "branch":    branch,
        "path":      path,
        "mr_iid":    mr_iid,
        "target":    target,
        "message":   (message or "")[:200] or None,
        "is_anomaly": anom,
        "meta": False,
        "anomaly_type": a_type,
        "severity":  sev,
    }
    # доп. метаданные из аннотации (secret_type и т.п.) и из extra
    for k, v in ann.items():
        if k not in ("anomaly_type", "severity"):
            rec[k] = v
    if extra:
        rec.update(extra)

    with _LOCK:
        _STATE["seq"] += 1
        rec["seq"] = _STATE["seq"]
        rec["actor_session"] = _actor_session_id(actor, now_sim)
        is_meta = bool(rec.get("meta"))
        if not is_meta:
            _hk = f"{rec['weekday']}:{rec['hour']}"
            _STATE["heat"][_hk] += 1
            if anom:
                _STATE["heat_anom"][_hk] += 1
            if actor and rec["project"]:
                _STATE["actor_repo"][actor + "\x01" + rec["project"]] += 1
        if is_meta and action == "anomaly":
            _STATE["anom_feed"].append({
                "ts_sim": rec["ts_sim"], "anomaly_type": a_type, "severity": sev,
                "actor": actor, "project": rec.get("repo") or rec.get("project"),
                "subtype": rec.get("anomaly_subtype")})
        _STATE["total"] += 1
        _STATE["counts"][action] += 1
        if anom:
            _STATE["anomalies"] += 1
            if a_type:
                _STATE["anom_counts"][a_type] += 1
        if _STATE["fh"]:
            try:
                _STATE["fh"].write(json.dumps(rec, ensure_ascii=False) + "\n")
                _STATE["fh"].flush()
            except Exception:
                pass
        # Служебные (meta) события — только в файл/телеметрию, в живую ленту не кладём,
        # чтобы схема ленты была единой: actor/role/action/project/ts у каждого события.
        if not is_meta:
            light = {"seq": rec["seq"], "ts_sim": rec["ts_sim"],
                     "session_id": rec["session_id"], "actor_session": rec["actor_session"],
                     "actor": actor, "role": role, "action": action,
                     "project": rec["project"], "path": path,
                     "branch": branch, "mr_iid": mr_iid, "message": rec.get("message"),
                     "is_anomaly": anom, "anomaly_type": a_type, "severity": sev,
                     "lookalike": rec.get("lookalike")}
            _STATE["ring"].append(light)
            if actor:
                _STATE["by_actor"][actor].append(light)
                ac = _STATE["actor_counts"][actor]
                ac["total"] += 1
                ac["act:" + action] += 1
                if anom:
                    ac["anomalies"] += 1
                _STATE["actor_last"][actor] = light


def _actor_session_id(actor, now_sim):
    """Per-actor рабочая сессия: новый id после разрыва > SESSION_GAP_MIN или смены дня."""
    if not actor:
        return "system"
    sess = _STATE["actor_sessions"]
    prev = sess.get(actor)
    new_seg = True
    if prev:
        gap_min = (now_sim - prev["last"]).total_seconds() / 60.0
        if gap_min <= SESSION_GAP_MIN and now_sim.date() == prev["last"].date():
            new_seg = False
    n = (prev["n"] + 1) if (prev and new_seg) else (prev["n"] if prev else 1)
    sess[actor] = {"last": now_sim, "n": n}
    return f"{actor}-s{n}"


def _work_start():
    import config
    return config.WORK_HOURS_START

def _work_end():
    import config
    return config.WORK_HOURS_END


# ----------------------------------------------------------------------
def stats():
    with _LOCK:
        return {
            "enabled": _STATE["enabled"],
            "file": _STATE["file"],
            "run_id": _STATE["run_id"],
            "total": _STATE["total"],
            "anomalies": _STATE["anomalies"],
            "by_action": dict(_STATE["counts"].most_common()),
            "by_anomaly": dict(_STATE["anom_counts"].most_common()),
        }


def tail(n=80):
    with _LOCK:
        items = list(_STATE["ring"])
    return items[-n:]


def actor_feed(username, n=80):
    with _LOCK:
        items = list(_STATE["by_actor"].get(username, []))
    return items[-n:]


def actors_summary():
    out = {}
    with _LOCK:
        for u, c in _STATE["actor_counts"].items():
            last = _STATE["actor_last"].get(u, {})
            out[u] = {
                "total": c.get("total", 0),
                "pushes": c.get("act:push", 0),
                        "mrs": c.get("act:mr_open", 0),
                "merges": c.get("act:mr_merge", 0),
                "issues": c.get("act:issue_open", 0),
                "anomalies": c.get("anomalies", 0),
                "last_action": last.get("action"),
                "last_project": last.get("project"),
                "last_path": last.get("path"),
                "last_ts": last.get("ts_sim"),
                "last_anomaly": last.get("anomaly_type"),
            }
    return out


# ----------------------------------------------------------------------
def insights():
    """Агрегаты для раздела «Аналитика»: heatmap, таймлайн аномалий, граф actor↔repo."""
    with _LOCK:
        heat = dict(_STATE["heat"]); heat_anom = dict(_STATE["heat_anom"])
        anom = list(_STATE["anom_feed"]); ar = dict(_STATE["actor_repo"])
    grid  = [[0]*24 for _ in range(7)]
    agrid = [[0]*24 for _ in range(7)]
    for k, v in heat.items():
        wd, h = k.split(":"); grid[int(wd)][int(h)] = v
    for k, v in heat_anom.items():
        wd, h = k.split(":"); agrid[int(wd)][int(h)] = v
    edges = []
    for k, v in ar.items():
        a, r = k.split("\x01", 1)
        edges.append({"actor": a, "repo": r, "n": v})
    edges.sort(key=lambda e: -e["n"])
    return {"heat": grid, "heat_anom": agrid,
            "anom_timeline": anom[-160:], "edges": edges}
