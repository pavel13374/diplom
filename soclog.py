# -*- coding: utf-8 -*-
"""
SOCLOG — структурное JSON-логирование для поиска ошибок.

Даёт три вещи поверх обычного logging:
  1) logs/debug.jsonl  — КАЖДОЕ решение системы одной JSON-строкой с контекстом
     (event_id, rule_id, incident_id, risk, ...). Ротация, DEBUG-уровень.
  2) logs/errors.log   — только ERROR+ с полными трейсбеками. Этот файл
     присылается на разбор в первую очередь.
  3) кольцевой буфер последних записей + счётчики уровней — для /api/diag
     и страницы «Диагностика».

Использование:
    import soclog
    soclog.install()                       # один раз на процесс (идемпотентно)
    soclog.evt("detector", "alert",        # структурное событие
               rule_id="high-entropy-push", risk=0.6, actor="mila")
    soclog.evt("ingest", "batch", level="debug", n=120, cursor=4567)

Обычные logging.getLogger(...).error(...) тоже попадают в оба файла —
модуль вешает хендлеры на root-логгер.
"""
import os
import json
import logging
import re as _re
import threading
import traceback
from collections import Counter, deque
from datetime import datetime
from logging.handlers import RotatingFileHandler


def _process_tag():
    """Короткое имя процесса для имени лог-файла: console, webapp, metrics…

    Нужно, чтобы одновременно запущенные процессы не делили один файл: на
    Windows ротация чужого открытого файла невозможна в принципе.
    """
    import sys as _sys
    name = os.path.basename(getattr(_sys.modules.get("__main__"), "__file__", "") or "")
    name = os.path.splitext(name)[0] or "app"
    safe = "".join(ch if (ch.isalnum() or ch in "-_") else "-" for ch in name)
    return safe[:24] or "app"

_LOCK = threading.RLock()
_STATE = {"installed": False, "paths": {}}
_RING = deque(maxlen=500)          # последние структурные записи (для /api/diag)
_COUNTS = Counter()                # уровни за процесс
_LAST_ERRORS = deque(maxlen=60)    # последние ERROR+ (краткая форма)

_LEVELS = {"debug": logging.DEBUG, "info": logging.INFO,
           "warning": logging.WARNING, "error": logging.ERROR,
           "critical": logging.CRITICAL}


# =======================================================================
#  ИМЯ СЕРВИСА
# =======================================================================
# В журнале должно быть видно, КТО пишет: мир, защита, метрики, тест.
# Раньше этого не было нигде — ни в консоли, ни в simulator.log, — и при двух
# одновременно работающих процессах строки в общей консоли было не различить.
_SERVICE_NAMES = {"webapp": "world", "console": "defense", "main": "world",
                  "run_defense": "defense", "metrics": "metrics",
                  "launcher": "panel", "panel": "panel"}


def service_name():
    """Короткое имя сервиса: world / defense / metrics / <имя скрипта>."""
    env = os.environ.get("SOC_SERVICE")
    if env:
        return env[:12]
    tag = _process_tag()
    return _SERVICE_NAMES.get(tag, tag)[:12]


SERVICE = service_name()


# =======================================================================
#  МАСКИРОВАНИЕ СЕКРЕТОВ
# =======================================================================
# Журнал уходит в консоль, в файлы и в диагностический архив, который
# отдаётся кнопкой из веб-интерфейса. Токен, попавший туда хотя бы раз,
# считается скомпрометированным. Проверено на живом стенде: при сетевом сбое
# requests кладёт в текст исключения полный URL, и боевой токен Telegram
# уходил в logs/*.log целиком.
_SECRET_PATTERNS = [
    _re.compile(r"\b\d{6,12}:[A-Za-z0-9_\-]{30,}\b"),      # Telegram bot token
    _re.compile(r"/bot[^/\s]+"),                             # /bot<token> в URL
    _re.compile(r"\bglpat-[A-Za-z0-9_.\-]{10,}"),            # GitLab PAT
    _re.compile(r"\bgl(?:soat|rt)-[A-Za-z0-9_.\-]{10,}"),
    _re.compile(r"(?i)\b(?:private-token|authorization|x-api-key)\s*[:=]\s*\S+"),
]


def mask(text):
    """Заменить всё, что похоже на секрет, на <SECRET>. Идемпотентно."""
    if text is None:
        return text
    s = str(text)
    for rx in _SECRET_PATTERNS:
        s = rx.sub("<SECRET>", s)
    return s


def _mask_ctx(ctx):
    out = {}
    for k, v in (ctx or {}).items():
        if _re.search(r"(?i)token|secret|password|passwd|api[_-]?key", str(k)):
            out[k] = "<SECRET>"
        elif isinstance(v, str):
            out[k] = mask(v)
        else:
            out[k] = v
    return out


#: Порядок, в котором важные идентификаторы выводятся первыми.
_CTX_ORDER = ("incident_id", "alert_id", "event_id", "rule_id", "technique",
              "scenario", "campaign", "command_id", "actor", "project",
              "repository", "status", "verdict", "risk", "n", "ok")


def _fmt_ctx(ctx):
    """k=v через пробел: важные идентификаторы впереди, остальное следом."""
    if not ctx:
        return ""
    ctx = _mask_ctx(ctx)
    keys = [k for k in _CTX_ORDER if k in ctx]
    keys += sorted(k for k in ctx if k not in _CTX_ORDER)
    parts = []
    for k in keys:
        v = ctx[k]
        # Пустое значение в строке журнала — это шум: ueba_reasons=[]
        # ml_evidence=[] rules_hit=[] занимали половину ширины строки и
        # мешали увидеть то, что действительно сработало.
        if v is None or v == "" or (isinstance(v, (list, tuple, dict, set)) and not v):
            continue
        v = str(v)
        if len(v) > 120:
            v = v[:117] + "..."
        if " " in v:
            v = '"' + v + '"'
        parts.append(f"{k}={v}")
    return " ".join(parts)


_COLORS = {"DEBUG": "\033[90m", "INFO": "\033[36m", "WARNING": "\033[33m",
           "ERROR": "\033[31m", "CRITICAL": "\033[1;37;41m"}
_RESET = "\033[0m"


class _HumanFormatter(logging.Formatter):
    """Одна строка = время, уровень, сервис, компонент, событие, контекст.

        2026-08-30 00:31:12.345 INFO  defense  correlator     инцидент создан
            incident_id=84674023 actor=anna.smirnova alerts=6 risk=0.99

    Формат единый для консоли и для файлов: раньше их было три разных, и в
    simulator.log вообще не было имени компонента — по строке нельзя было
    понять, какая подсистема её написала.
    """

    def __init__(self, color=False, service=None):
        super().__init__()
        self.color = color
        self.service = service or SERVICE

    def format(self, record):
        ts = datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        lvl = record.levelname
        try:
            msg = record.getMessage()
        except Exception:
            msg = str(record.msg)
        msg = _ANSI_RE.sub("", mask(msg)).strip()
        ctx = getattr(record, "ctx", None)
        tail = _fmt_ctx(ctx) if isinstance(ctx, dict) else ""
        name = (record.name or "-")[:18]
        head = f"{ts} {lvl:<8} {self.service:<8} {name:<18} {msg}"
        if tail:
            head += "  " + tail
        if self.color:
            c = _COLORS.get(lvl, "")
            head = f"{c}{head}{_RESET}" if c else head
        if record.exc_info:
            head += "\n" + mask("".join(traceback.format_exception(*record.exc_info))).rstrip()
        elif record.exc_text:
            head += "\n" + mask(record.exc_text).rstrip()
        return head


class _AccessFilter(logging.Filter):
    """Строки доступа werkzeug: успешный опрос собственного API — это 90%
    журнала. Ошибки (4xx/5xx) пропускаем ВСЕГДА, успешные — по настройке
    SOC_LOG_ACCESS: all | errors (по умолчанию) | none."""

    def filter(self, record):
        if record.name != "werkzeug":
            return True
        mode = str(os.environ.get("SOC_LOG_ACCESS", "errors")).lower()
        if mode == "all":
            return True
        try:
            msg = _ANSI_RE.sub("", record.getMessage())
        except Exception:
            return True
        if not _NOISE_RE.search(msg):
            return True          # не строка доступа либо код 4xx/5xx
        return False if mode in ("errors", "none") else True


class _JsonFormatter(logging.Formatter):
    """Одна запись = одна JSON-строка: ts, level, module, event + контекст."""

    def format(self, record):
        d = {
            "ts": datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3],
            "level": record.levelname,
            "service": SERVICE,
            "module": record.name,
            "event": mask(record.getMessage()),
        }
        ctx = getattr(record, "ctx", None)
        if isinstance(ctx, dict):
            # Файл debug-*.jsonl отдаётся кнопкой «выгрузить диагностику» из
            # веб-интерфейса. Всё, что туда попадает, обязано быть без секретов.
            for k, v in _mask_ctx(ctx).items():
                if k not in d:
                    d[k] = v
        if record.exc_info:
            d["traceback"] = mask("".join(traceback.format_exception(*record.exc_info)))
        try:
            return json.dumps(d, ensure_ascii=False, default=str)
        except Exception:
            return json.dumps({"ts": d["ts"], "level": d["level"],
                               "module": d["module"], "event": str(d.get("event"))})


# Werkzeug раскрашивает строки доступа ANSI-кодами для терминала, а опрос
# собственного API интерфейсом — это 90% журнала и ноль смысла для аналитика.
_ANSI_RE = _re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# Любая успешная строка доступа werkzeug: опрос API, статика, редирект
# на форму входа. Продуктового смысла в них нет, а журнал они
# занимают целиком. Ошибки (4xx/5xx) остаются.
_NOISE_RE = _re.compile(r'"(?:GET|POST|HEAD|PUT|DELETE) /[^"]*" [23]\d\d ')


class _RingHandler(logging.Handler):
    """Кольцевой буфер + счётчики — отдаётся страницей «Диагностика»."""

    def emit(self, record):
        try:
            msg = record.getMessage()
        except Exception:
            msg = str(record.msg)
        # Werkzeug пишет строки доступа в цвете: в браузере ANSI-коды
        # выводились текстом («[32mGET / HTTP/1.1[0m»).
        msg = mask(_ANSI_RE.sub("", msg).strip())
        # Успешный опрос собственного API интерфейсом занимал почти весь
        # журнал. Счётчики уровней тоже считались по нему, поэтому «5380
        # DEBUG» отражало частоту поллинга, а не работу платформы.
        if not msg or _NOISE_RE.search(msg):
            return
        _COUNTS[record.levelname] += 1
        entry = {
            "ts": datetime.now().strftime("%H:%M:%S"),
            "level": record.levelname,
            "module": record.name,
            "event": msg,
        }
        ctx = getattr(record, "ctx", None)
        if isinstance(ctx, dict):
            entry["ctx"] = {k: v for k, v in list(_mask_ctx(ctx).items())[:12]}
        if record.exc_info:
            entry["traceback"] = mask("".join(
                traceback.format_exception(*record.exc_info)))[-1500:]
        with _LOCK:
            _RING.append(entry)
            if record.levelno >= logging.ERROR:
                _LAST_ERRORS.append(entry)


def install(base_dir=None):
    """Вешает JSON-, error- и ring-хендлеры на root-логгер. Идемпотентно."""
    with _LOCK:
        if _STATE["installed"]:
            return dict(_STATE["paths"])
        base = base_dir or os.path.dirname(os.path.abspath(__file__))
        logdir = os.path.join(base, "logs")
        os.makedirs(logdir, exist_ok=True)

        root = logging.getLogger()
        if root.level > logging.DEBUG:
            root.setLevel(logging.DEBUG)

        # ЛОГ-ФАЙЛ У КАЖДОГО ПРОЦЕССА СВОЙ.
        #
        # Мир (webapp.py) и защита (console.py) запускаются одновременно и
        # раньше писали в один и тот же logs/debug.jsonl. На Windows файл,
        # открытый одним процессом, нельзя переименовать из другого, поэтому
        # при достижении 10 МБ ротация падала:
        #
        #   PermissionError: [WinError 32] файл занят другим процессом
        #   'logs\\debug.jsonl' -> 'logs\\debug.jsonl.1'
        #
        # И падала не один раз, а на КАЖДОЙ записи в лог — консоль заливало
        # трейсбеками, за которыми не видно настоящих сообщений. На Linux это
        # не проявлялось: там переименование открытого файла разрешено, но
        # записи двух процессов всё равно перемешивались.
        #
        # Имя процесса берётся из имени запущенного скрипта, поэтому файлы
        # получаются понятные: debug-console.jsonl, debug-webapp.jsonl.
        who = _process_tag()
        jsonl = os.path.join(logdir, f"debug-{who}.jsonl")
        jh = RotatingFileHandler(jsonl, maxBytes=10 * 1024 * 1024,
                                 backupCount=5, encoding="utf-8", delay=True)
        jh.setLevel(logging.DEBUG)
        jh.setFormatter(_JsonFormatter())
        jh._soclog = True

        errlog = os.path.join(logdir, f"errors-{who}.log")
        eh = RotatingFileHandler(errlog, maxBytes=5 * 1024 * 1024,
                                 backupCount=3, encoding="utf-8", delay=True)
        eh.setLevel(logging.ERROR)
        eh.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s: %(message)s"))
        eh._soclog = True

        rh = _RingHandler()
        rh.setLevel(logging.DEBUG)
        rh._soclog = True

        # не дублируем, если install() зовут повторно после runlog.setup()
        have = {type(h).__name__ for h in root.handlers if getattr(h, "_soclog", False)}
        for h in (jh, eh, rh):
            if type(h).__name__ not in have:
                root.addHandler(h)

        _STATE["installed"] = True
        _STATE["paths"] = {"jsonl": jsonl, "errors": errlog}
    # лог — уже ВНЕ замка (emit ring-хендлера тоже берёт _LOCK)
    logging.getLogger("soclog").info(
        "structured logging on", extra={"ctx": {"jsonl": jsonl, "errors": errlog}})
    return dict(_STATE["paths"])


def install_console(level=None, color=None, stream=None):
    """Единый человекочитаемый вывод в stdout. Идемпотентно.

    Это то, что оператор видит в консоли START_PANEL и что попадает в
    logs/world.log и logs/defense.log. До этой функции консольного вывода у
    консоли защиты не было ВООБЩЕ: процесс писал только в debug-*.jsonl, и в
    окне панели по нему нельзя было понять ни что он делает, ни что сломалось.
    А у мира формат был свой, третий по счёту, без имени компонента.

    level  — по умолчанию config.LOG_LEVEL (SOC_DEBUG=1 включает DEBUG).
    color  — по умолчанию только если вывод в терминал (в трубу цвет не льём:
             панель раскрашивает строки сама и не должна разбирать чужие коды).
    """
    import sys as _sys
    stream = stream or _sys.stdout
    with _LOCK:
        root = logging.getLogger()
        for h in root.handlers:
            if getattr(h, "_soc_console", False):
                return h
        if level is None:
            if str(os.environ.get("SOC_DEBUG", "")).lower() in ("1", "true", "yes"):
                level = logging.DEBUG
            else:
                try:
                    import config as _c
                    level = getattr(logging, getattr(_c, "LOG_LEVEL", "INFO"), logging.INFO)
                except Exception:
                    level = logging.INFO
        if color is None:
            color = bool(getattr(stream, "isatty", lambda: False)()) and \
                str(os.environ.get("SOC_LOG_COLOR", "1")).lower() not in ("0", "no", "off")
        h = logging.StreamHandler(stream)
        h.setLevel(level)
        h.setFormatter(_HumanFormatter(color=color))
        h.addFilter(_AccessFilter())
        h._soc_console = True
        if root.level > level:
            root.setLevel(level)
        root.addHandler(h)
    logging.getLogger("soclog").info(
        "console logging on",
        extra={"ctx": {"service": SERVICE, "level": logging.getLevelName(level),
                       "color": bool(color),
                       "access": os.environ.get("SOC_LOG_ACCESS", "errors")}})
    return h


def install_file(name=None, level=None, max_bytes=10 * 1024 * 1024, backups=5,
                 base_dir=None):
    """Человекочитаемый файловый лог процесса: logs/app-<сервис>.log.

    Тот же формат, что в консоли — требование «console output and file logs
    must represent the same important events». Ротация и UTF-8 обязательны:
    без ротации файл рос без границ, а без явной кодировки на Windows падал
    на кириллице в сообщении.
    """
    with _LOCK:
        root = logging.getLogger()
        for h in root.handlers:
            if getattr(h, "_soc_file", False):
                return getattr(h, "baseFilename", None)
        base = base_dir or os.path.dirname(os.path.abspath(__file__))
        logdir = os.path.join(base, "logs")
        os.makedirs(logdir, exist_ok=True)
        path = os.path.join(logdir, name or f"app-{SERVICE}.log")
        if level is None:
            try:
                import config as _c
                level = getattr(logging, getattr(_c, "LOG_LEVEL", "INFO"), logging.INFO)
            except Exception:
                level = logging.INFO
        h = RotatingFileHandler(path, maxBytes=max_bytes, backupCount=backups,
                                encoding="utf-8", delay=True)
        h.setLevel(level)
        h.setFormatter(_HumanFormatter(color=False))
        h.addFilter(_AccessFilter())
        h._soc_file = True
        root.addHandler(h)
        _STATE["paths"]["app"] = path
    logging.getLogger("soclog").info("file logging on",
                                     extra={"ctx": {"path": path}})
    return path


def human_formatter(color=False, service=None):
    """Тот же формат для файловых хендлеров — консоль и файл должны совпадать."""
    return _HumanFormatter(color=color, service=service)


def evt(module, event, level="info", exc=False, **ctx):
    """Структурное событие: soclog.evt("detector","alert", rule_id=..., risk=...).
    exc=True — прикрепить текущий traceback (звать из except-блока)."""
    lg = logging.getLogger(module)
    lvl = _LEVELS.get(str(level).lower(), logging.INFO)
    lg.log(lvl, event, extra={"ctx": ctx}, exc_info=bool(exc))


def diag():
    """Снимок для /api/diag: счётчики, последние ошибки, хвост записей, пути."""
    with _LOCK:
        return {
            "counts": dict(_COUNTS),
            "recent": list(_RING)[-200:],
            "errors": list(_LAST_ERRORS),
            "paths": dict(_STATE["paths"]),
            "installed": _STATE["installed"],
        }


_STARTED_AT = datetime.now()


def tail_errors(n=200, current_run_only=True):
    """Хвост errors.log.

    По умолчанию отдаём только записи ТЕКУЩЕГО запуска. Файл живёт между
    перезапусками, и страница «Диагностика» показывала трейсбеки
    полугодовой давности как свежие: уже исправленная ошибка выглядела
    действующей. Отсечка — по метке времени в начале строки; строки
    продолжения трейсбека идут за своей шапкой.
    """
    p = _STATE["paths"].get("errors")
    if not p or not os.path.exists(p):
        return []
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return []
    if not current_run_only:
        return [mask(x) for x in lines[-n:]]

    stamp = _re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
    out, keep = [], False
    for ln in lines:
        m = stamp.match(ln)
        if m:
            try:
                ts = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
            except ValueError:
                ts = None
            keep = (ts is None) or (ts >= _STARTED_AT)
        if keep:
            out.append(mask(ln))
    return out[-n:]


# ======================================================================
#  ОШИБКИ ИНТЕРФЕЙСА
# ======================================================================
#: Кольцо клиентских ошибок. Браузерная ошибка раньше жила только в консоли
#: разработчика: пользователь видел тост «Сбой в интерфейсе» и не мог ничего
#: передать, кроме скриншота. Теперь она попадает СЮДА же, где серверные, и
#: выгружается одним файлом вместе с ними.
_CLIENT_ERRORS = deque(maxlen=500)


#: Сообщения браузера, которые в одиночном экземпляре означают оборванную
#: загрузку, а не дефект: скрипт не догрузился при перезапуске сервиса.
_CLIENT_TRANSIENT = ("Unexpected end of input", "Unexpected end of script",
                     "Failed to fetch", "NetworkError", "Load failed",
                     "The operation was aborted", "Importing a module script failed")
#: С какого повтора одинаковое сообщение перестаёт считаться случайностью.
_CLIENT_ESCALATE = 3
_CLIENT_SEEN = Counter()


def client_error(where, message, stack="", url="", ua="", app=""):
    """Записать ошибку, случившуюся в браузере."""
    rec = {
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "app": app or "?",
        "where": str(where)[:120],
        "message": str(message)[:600],
        "stack": str(stack)[:4000],
        "url": str(url)[:300],
        "ua": str(ua)[:200],
    }
    with _LOCK:
        _CLIENT_ERRORS.append(rec)
        _CLIENT_SEEN[rec["message"][:120]] += 1
        seen = _CLIENT_SEEN[rec["message"][:120]]
    # УРОВЕНЬ ПО СУЩЕСТВУ, А НЕ ВСЕГДА ERROR.
    #
    # Одиночный обрыв загрузки скрипта — не отказ приложения. На живом стенде
    # это ловится так: вкладка консоли открыта, оператор перезапускает
    # сервисы, браузер в этот момент дотягивает /static/ui.js и получает
    # обрезанный ответ -> «SyntaxError: Unexpected end of input» из
    # window.onerror. Приложение цело, сервер цел, лечится обновлением
    # страницы. Раньше это писалось как ERROR и — после подключения
    # уведомлений — будило оператора сообщением в Telegram.
    #
    # Правило: первое появление такой ошибки — WARNING; ПОВТОРЯЮЩАЯСЯ (с
    # третьего раза) — уже ERROR, потому что это перестало быть случайностью.
    # Всё остальное, что прислал браузер, по-прежнему ERROR сразу.
    transient = any(t in rec["message"] for t in _CLIENT_TRANSIENT)
    lvl = logging.ERROR
    if transient and seen < _CLIENT_ESCALATE:
        lvl = logging.WARNING
    logging.getLogger("ui").log(lvl, "ошибка интерфейса: %s", rec["message"],
                                extra={"ctx": {"where": rec["where"],
                                               "url": rec["url"], "app": rec["app"],
                                               "seen": seen}})
    return rec


def client_errors(n=200):
    with _LOCK:
        return list(_CLIENT_ERRORS)[-n:]


def bundle(app_name=""):
    """ВСЯ диагностика одним объектом — для выгрузки файлом.

    Смысл: чтобы отдать проблему на разбор, не нужно было собирать по кускам
    скриншоты, консоль браузера и три разных лога. Один файл содержит и
    серверную сторону, и клиентскую, и окружение.
    """
    import platform
    d = diag()
    d["client_errors"] = client_errors(300)
    d["errors_log_tail"] = tail_errors(300)
    d["app"] = app_name
    d["collected_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    d["started_at"] = _STARTED_AT.strftime("%Y-%m-%d %H:%M:%S")
    try:
        import config as _cfg
        d["env"] = {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "offline_mode": bool(getattr(_cfg, "OFFLINE_MODE", False)),
            "offline_forced": bool(getattr(_cfg, "OFFLINE_FORCED", False)),
            "gitlab_url": getattr(_cfg, "GITLAB_URL", ""),
        }
    except Exception:
        logging.getLogger("soclog").error("не удалось собрать окружение для выгрузки",
                                          exc_info=True)
        d["env"] = {}
    return d
