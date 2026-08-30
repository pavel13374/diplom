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
import threading
from collections import deque, Counter, defaultdict
from datetime import datetime

import logging

import simclock

# Молчаливая потеря события здесь означает, что защита его никогда не
# увидит, а на дашборде всё будет выглядеть штатно. Поэтому сбои записи
# логируются: процесс продолжает работать, но след остаётся.
_log = logging.getLogger("events")

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
    "last_real": None,
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
    "repo_counts": defaultdict(Counter),                 # repo -> Counter(action)
    "repo_recent": defaultdict(lambda: deque(maxlen=40)),# repo -> последние события
    "repo_open_mrs": defaultdict(dict),                  # repo -> {iid: {...}}
    "repo_files": defaultdict(set),                      # repo -> текущее множество путей (дерево)
    "repo_deleted": defaultdict(lambda: deque(maxlen=12)),# repo -> недавно удалённые файлы
}

SESSION_GAP_MIN = 30                 # разрыв (sim-минут) → новая рабочая сессия актора

#: Потолок отслеживаемых путей на репозиторий (страница «Репозитории» и так
#: показывает первые 80). Без него множество росло монотонно всё время работы.
MAX_TRACKED_FILES_PER_REPO = 5000



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
    try:
        import eventstore
        eventstore.init()
    except Exception:
        _log.error("не удалось инициализировать event-store: события не дойдут "
                   "до консоли защиты", exc_info=True)
    return _STATE["run_id"]


def close():
    with _LOCK:
        if _STATE["fh"]:
            try:
                _STATE["fh"].flush(); _STATE["fh"].close()
            except Exception:
                # Незакрытый буфер = ХВОСТ ЖУРНАЛА ПОТЕРЯН. Именно на этих
                # событиях обычно и заканчивается прогон, то есть теряется
                # самое свежее.
                _log.error("не удалось закрыть журнал событий — хвост записей "
                           "может быть потерян", exc_info=True,
                           extra={"ctx": {"file": _STATE.get("file")}})
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


def _norm_project(project, project_id):
    """Привести поле `project` к ИМЕНИ репозитория.

    Проблема, которую это чинит. Часть вызовов передаёт `project=<имя>`, часть —
    `project=<pid>` (число). Прежняя строка

        project or (_project_name(project_id) if project_id is not None else None)

    нормализовала только `project_id`: число, пришедшее в `project`, было
    истинным и попадало в журнал как есть. В накопленном журнале так записано
    60 событий с проектами «1», «3», «5», «6».

    Последствия не косметические:
      • признак ML `proj_secrets` сравнивает project == "soc-secrets" — для
        события с project == 6 он равен нулю, хотя это тот самый репозиторий;
      • UEBA считает «6» и «soc-secrets» РАЗНЫМИ репозиториями, поэтому
        обращение к хранилищу секретов выглядит как визит в новый репозиторий
        (лишние биты неожиданности) либо, наоборот, размывает профиль;
      • правила с условием по project молча не срабатывают;
      • в интерфейсе вместо названия виден голый id.

    Возвращает (имя, признак_странного_значения).
    """
    import config
    if project is None:
        return (_project_name(project_id) if project_id is not None else None), False
    if isinstance(project, bool):
        return str(project), True
    if isinstance(project, int):
        return _project_name(project), False
    s = str(project)
    if s.isdigit():
        return _project_name(int(s)), False
    known = set(getattr(config, "WORK_REPOS", {})) | set(getattr(config, "PROJECTS", {}))
    return s, (s not in known)


def emit(action, actor=None, role=None, project=None, project_id=None,
         path=None, branch=None, mr_iid=None, message=None, target=None,
         extra=None, anomaly_type=None, severity=None, is_anomaly=None,
         campaign_id=None, at_sim=None):
    """Записать событие. Метки берутся из явных аргументов ИЛИ из активной аннотации.

    at_sim — СИМУЛИРОВАННОЕ время события (datetime), если оно отличается от
    текущего показания часов. Нужно там, где действующее лицо само выбирает
    момент: атакующий, который лезет в production ночью, не ждёт, пока мир
    доиграет рабочий день.

    Важно, ЧТО ИМЕННО делает этот аргумент: он подменяет ОДИН источник времени,
    из которого дальше выводятся ВСЕ временные поля события — ts_sim, hour,
    weekday, is_night, is_weekend. Поэтому несогласованное событие («час 14, но
    is_night=true») получить нельзя в принципе. Отдельного аргумента для
    is_night нет и не должно быть: ровно так подделывают признак вместо того,
    чтобы моделировать поведение.
    """
    if not _STATE["enabled"]:
        return
    ann = _current_annotation()
    a_type = anomaly_type or ann.get("anomaly_type")
    sev = severity or ann.get("severity")
    anom = is_anomaly
    if anom is None:
        anom = bool(a_type)

    # СТОРОЖ СЛОВАРЯ ДЕЙСТВИЙ.
    #
    # taxonomy.validate() был написан ровно для того, чтобы «говорящее» имя
    # действия нельзя было добавить незаметно, — но НЕ ВЫЗЫВАЛСЯ НИГДЕ. Из-за
    # этого в журнале сохранились steal_oauth, perm_discovery, mass_delete,
    # exfil_altproto: имена, которых у обычного сотрудника не бывает, то есть
    # фактические метки. Обучение и оценка на таком журнале недействительны.
    #
    # По умолчанию не бросаем исключение (поток мира важнее строгости), но
    # пишем предупреждение и помечаем запись. TAXONOMY_STRICT=True превращает
    # это в ошибку — полезно в тестах и в CI.
    try:
        import taxonomy
        _known = action in taxonomy.ALL
    except Exception:
        _known = True
    if not _known:
        import config as _c
        if getattr(_c, "TAXONOMY_STRICT", False):
            raise ValueError(
                f"действие '{action}' вне нормализованного словаря (taxonomy.ALL). "
                "Добавь его в taxonomy.CORE/ADMIN и убедись, что обычная работа "
                "тоже его порождает — иначе имя действия станет меткой.")
        _log.error("действие вне словаря taxonomy — имя действия работает меткой",
                   extra={"ctx": {"action": action, "actor": actor,
                                  "подсказка": "см. taxonomy.py"}})

    now_sim = at_sim or simclock.now()
    proj_name, proj_odd = _norm_project(project, project_id)
    if proj_odd:
        # Не исключение: поток важнее строгости. Но в журнале это должно быть
        # ВИДНО — так в поле project оказывались имена веток
        # («incident-response-deletion_scheduled-18»), и никто этого не замечал.
        _log.warning("нераспознанный репозиторий в событии",
                    extra={"ctx": {"project": proj_name, "action": action,
                                   "actor": actor}})
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
        "project":   proj_name,
        "branch":    branch,
        "path":      path,
        "mr_iid":    mr_iid,
        "target":    target,
        "message":   (message or "")[:200] or None,
        "is_anomaly": anom,
        "meta": False,
        "episode_id": None,
        "campaign_id": campaign_id,
        "is_decisive": False,
        "family": None,
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
            _proj = rec["project"]
            if _proj:
                _STATE["repo_counts"][_proj][action] += 1
                _STATE["repo_recent"][_proj].append({
                    "ts_sim": rec["ts_sim"], "actor": actor, "action": action,
                    "path": path, "mr_iid": mr_iid, "message": rec.get("message"),
                    "is_anomaly": anom, "anomaly_type": a_type})
                if action == "push" and path:
                    # Множество путей репозитория росло неограниченно и жило всё
                    # время работы процесса мира. Держим потолок: страница
                    # «Репозитории» показывает первые 80 путей, полное дерево ей
                    # не нужно.
                    _files = _STATE["repo_files"][_proj]
                    if len(_files) < MAX_TRACKED_FILES_PER_REPO:
                        _files.add(path)
                if action == "file_delete" and path:
                    _STATE["repo_files"][_proj].discard(path)
                    _STATE["repo_deleted"][_proj].append({"path": path, "actor": actor,
                                                          "ts_sim": rec["ts_sim"]})
                if action == "mr_open" and mr_iid:
                    _STATE["repo_open_mrs"][_proj][mr_iid] = {
                        "iid": mr_iid, "title": (rec.get("message") or "")[:80],
                        "actor": actor, "ts_sim": rec["ts_sim"], "is_anomaly": anom}
                elif action in ("mr_merge", "mr_close") and mr_iid:
                    _STATE["repo_open_mrs"][_proj].pop(mr_iid, None)
        if is_meta and action == "anomaly":
            _STATE["anom_feed"].append({
                "ts_sim": rec["ts_sim"], "anomaly_type": a_type, "severity": sev,
                "actor": actor, "project": rec.get("repo") or rec.get("project"),
                "subtype": rec.get("anomaly_subtype")})
        _STATE["total"] += 1
        import time as _t; _STATE["last_real"] = _t.time()
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
                # Ключ "file", а не "path": последнего в _STATE нет, поэтому
                # единственное сообщение о ПОТЕРЕ события всегда называло None.
                _log.error("не удалось записать событие в журнал %s",
                           _STATE.get("file"), exc_info=True)
        try:
            import eventstore
            eventstore.append(rec)
        except Exception:
            _STATE["store_errors"] = _STATE.get("store_errors", 0) + 1
            _log.error("событие не попало в event-store (action=%s actor=%s): "
                       "защита его не увидит", rec.get("action"), rec.get("actor"),
                       exc_info=True)
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
        path = _STATE["file"]
        total = _STATE["total"]
        out = {
            "enabled": _STATE["enabled"],
            "file": path,
            "run_id": _STATE["run_id"],
            "total": total,
            "last_real": _STATE["last_real"],
            "anomalies": _STATE["anomalies"],
            "by_action": dict(_STATE["counts"].most_common()),
            "by_anomaly": dict(_STATE["anom_counts"].most_common()),
        }
    # Размер файла датасета: страница «Датасет» показывает, сколько уже
    # накоплено на диске. Читается вне замка — обращение к ФС может
    # подвиснуть, а держать общий замок на это время нельзя.
    size = None
    if path:
        try:
            size = os.path.getsize(path)
        except OSError:
            size = None
    out["size_bytes"] = size

    # ДАТАСЕТ ВИДЕН И ДО СТАРТА СИМУЛЯЦИИ.
    # _STATE заполняется только в init(), который зовут при запуске мира.
    # До этого страница «Датасет» показывала «событий записано 0» и
    # «событий пока нет», хотя data/events.jsonl лежал рядом на десятки
    # мегабайт и защита успешно по нему работала. Файл на диске — факт,
    # не зависящий от того, идёт ли прогон прямо сейчас.
    if not path:
        peek = _peek_dataset()
        if peek:
            out.update(peek)
    return out


# Разбор файла кэшируется по времени изменения: stats() зовут из опроса
# страницы несколько раз в минуту, а файл бывает в десятки мегабайт.
_PEEK = {"mtime": None, "data": None}


def _peek_dataset():
    """Размер и число строк журнала на диске, без открытия на дозапись."""
    import config as _cfg
    cfg = getattr(_cfg, "EVENT_LOG", {}) or {}
    p = cfg.get("file", "data/events.jsonl")
    if not os.path.isabs(p):
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), p)
    try:
        st = os.stat(p)
    except OSError:
        return None
    if _PEEK["mtime"] == st.st_mtime and _PEEK["data"]:
        return dict(_PEEK["data"], file=p, size_bytes=st.st_size)
    total = 0
    try:
        with open(p, "rb") as fh:
            for _ in fh:
                total += 1
    except OSError:
        return None
    data = {"total": total, "from_disk": True}
    _PEEK["mtime"] = st.st_mtime
    _PEEK["data"] = data
    return dict(data, file=p, size_bytes=st.st_size)


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


# ----------------------------------------------------------------------
def repo_streams(recent_n=14):
    """Состояние по каждому репозиторию для живой страницы «Репозитории»:
    счётчики, открытые MR (с подписью), последние события (файлы/MR)."""
    import config as _cfg
    with _LOCK:
        out = {}
        names = list(_cfg.WORK_REPOS.keys()) if getattr(_cfg, "WORK_REPOS", None) else []
        seen = set(names)
        for proj in list(_STATE["repo_counts"].keys()):
            if proj not in seen:
                names.append(proj); seen.add(proj)
        for proj in names:
            cnt = _STATE["repo_counts"].get(proj, Counter())
            recent = list(_STATE["repo_recent"].get(proj, []))[-recent_n:][::-1]
            open_mrs = list(_STATE["repo_open_mrs"].get(proj, {}).values())
            open_mrs = sorted(open_mrs, key=lambda m: m.get("ts_sim", ""), reverse=True)[:8]
            tree = sorted(_STATE["repo_files"].get(proj, ()))[:80]
            deleted = list(_STATE["repo_deleted"].get(proj, []))[-8:][::-1]
            out[proj] = {
                "files": len(_STATE["repo_files"].get(proj, ())),
                "tree": tree,
                "deleted_recent": deleted,
                "pushes": cnt.get("push", 0),
                "mr_open": cnt.get("mr_open", 0),
                "mr_merge": cnt.get("mr_merge", 0),
                "mr_close": cnt.get("mr_close", 0),
                "total": sum(cnt.values()),
                "open_mrs": open_mrs,
                "recent": recent,
            }
    return out
