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


class _JsonFormatter(logging.Formatter):
    """Одна запись = одна JSON-строка: ts, level, module, event + контекст."""

    def format(self, record):
        d = {
            "ts": datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3],
            "level": record.levelname,
            "module": record.name,
            "event": record.getMessage(),
        }
        ctx = getattr(record, "ctx", None)
        if isinstance(ctx, dict):
            for k, v in ctx.items():
                if k not in d:
                    d[k] = v
        if record.exc_info:
            d["traceback"] = "".join(traceback.format_exception(*record.exc_info))
        try:
            return json.dumps(d, ensure_ascii=False, default=str)
        except Exception:
            return json.dumps({"ts": d["ts"], "level": d["level"],
                               "module": d["module"], "event": str(d.get("event"))})


import re as _re

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
        msg = _ANSI_RE.sub("", msg).strip()
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
            entry["ctx"] = {k: v for k, v in list(ctx.items())[:12]}
        if record.exc_info:
            entry["traceback"] = "".join(
                traceback.format_exception(*record.exc_info))[-1500:]
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
        return lines[-n:]

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
            out.append(ln)
    return out[-n:]
