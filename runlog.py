"""
Полное логирование прогона в отдельный файл.

При старте создаётся logs/run-<timestamp>.log на уровне DEBUG — туда пишется
ВСЁ: каждое действие, предупреждения, ошибки и трейсбеки. Этот файл можно
прислать на разбор. Параллельно считаются warning/error для отчёта.
"""
import os
import logging
from collections import Counter, deque
from datetime import datetime
from logging.handlers import RotatingFileHandler

_ACTIVE = {"path": None, "counter": None, "fh": None}


class CountingHandler(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.WARNING)
        self.counts = Counter()
        self.recent_errors = deque(maxlen=40)

    def emit(self, record):
        self.counts[record.levelname] += 1
        if record.levelno >= logging.ERROR:
            try:
                msg = record.getMessage()
            except Exception:
                msg = str(record.msg)
            self.recent_errors.append({
                "t": datetime.now().strftime("%H:%M:%S"),
                "level": record.levelname,
                "logger": record.name,
                "msg": msg[:300],
            })


def setup(base_dir=None):
    """Поднимает полный файловый лог прогона. Возвращает путь к файлу."""
    base_dir = base_dir or os.path.dirname(os.path.abspath(__file__))
    import config
    d = os.path.join(base_dir, getattr(config, "RUN_LOG_DIR", "logs"))
    os.makedirs(d, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = os.path.join(d, f"run-{ts}.log")

    fh = RotatingFileHandler(path, maxBytes=25 * 1024 * 1024, backupCount=3,
                             encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S"))

    ch = CountingHandler()

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)            # полный уровень в файл
    root.addHandler(fh)
    root.addHandler(ch)

    _ACTIVE.update(path=path, counter=ch, fh=fh)
    logging.getLogger("runlog").info(f"Полный лог прогона: {path}")
    return path


def path():
    return _ACTIVE["path"]


def stats():
    ch = _ACTIVE["counter"]
    if not ch:
        return {"warnings": 0, "errors": 0, "recent_errors": [], "path": _ACTIVE["path"]}
    return {
        "warnings": ch.counts.get("WARNING", 0),
        "errors": ch.counts.get("ERROR", 0) + ch.counts.get("CRITICAL", 0),
        "recent_errors": list(ch.recent_errors)[-12:],
        "path": _ACTIVE["path"],
    }
