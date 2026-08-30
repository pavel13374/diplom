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

    root = logging.getLogger()

    # ИДЕМПОТЕНТНОСТЬ. Каждый вызов добавлял НОВЫЙ файловый хендлер на 25 МБ и
    # новый счётчик, не убирая прежние, и при этом переводил корневой логгер в
    # DEBUG. Функцию зовут main.py, Runner.__init__ в webapp.py и тесты, так что
    # хендлеры множились, а logs/ рос без границ: на рабочей машине это 47 МБ в
    # восьми файлах run-*.log плюс 17 МБ debug-*.jsonl.
    for h in list(root.handlers):
        if getattr(h, "_runlog", False):
            root.removeHandler(h)
            try:
                h.close()
            except (OSError, ValueError):
                pass

    # 25 МБ × 3 архива на КАЖДЫЙ из десяти хранимых прогонов — до гигабайта
    # в logs/ в худшем случае. Для разбора хватает и десятой части: файл
    # пишется на DEBUG и десять мегабайт — это десятки тысяч строк.
    fh = RotatingFileHandler(path, maxBytes=10 * 1024 * 1024, backupCount=1,
                             encoding="utf-8", delay=True)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S"))
    fh._runlog = True

    ch = CountingHandler()
    ch._runlog = True

    # DEBUG в корне только по явному запросу: иначе весь процесс пишет отладку
    # во все приёмники, и debug-*.jsonl растёт десятками мегабайт за прогон.
    import config as _cfg
    want_debug = str(os.environ.get("SOC_DEBUG", "")).lower() in ("1", "true", "yes")
    root.setLevel(logging.DEBUG if want_debug
                  else getattr(logging, getattr(_cfg, "LOG_LEVEL", "INFO"), logging.INFO))
    if not want_debug:
        fh.setLevel(root.level)
    root.addHandler(fh)
    root.addHandler(ch)
    _prune_old_runs(d)

    _ACTIVE.update(path=path, counter=ch, fh=fh)
    logging.getLogger("runlog").info(f"Полный лог прогона: {path}")
    return path


#: Сколько файлов прогонов оставляем в logs/. Верхняя граница каталога:
#: KEEP_RUN_LOGS × (10 МБ + 1 архив) = 100 МБ на прогоны.
KEEP_RUN_LOGS = 5


def _prune_old_runs(d):
    """Не копить run-*.log бесконечно: каждый запуск создавал новый файл."""
    try:
        files = sorted((os.path.join(d, f) for f in os.listdir(d)
                        if f.startswith("run-") and f.endswith(".log")),
                       key=os.path.getmtime, reverse=True)
        for f in files[KEEP_RUN_LOGS:]:
            try:
                os.remove(f)
            except OSError:
                pass
    except OSError:
        pass


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
