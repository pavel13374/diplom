#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
КОНСОЛЬ ОПЕРАТОРА — единый живой журнал обоих сервисов.

Запускает «Мир» (webapp.py, :8787) и «Защиту» (console.py, :8788) и сводит их
вывод в ОДНО окно, построчно и без задержки, как `docker logs`:

    00:31:12.345 INFO  world    scheduler   активность выполнена  activity=new_detection_rule actor=maria.ivanova ok=True
    00:31:13.002 INFO  defense  correlator  инцидент создан       incident_id=84674023 actor=anna.smirnova alerts=6

Почему не окно на tkinter (launcher.py), которое было раньше:
  • текст в scrolledtext выделяется мышью плохо, а копируется кусками;
  • панель показывала два лога РАЗДЕЛЬНО, и порядок событий между сервисами
    восстановить было нельзя — а именно он и нужен: атака в мире и детект в
    защите разнесены на секунды;
  • при падении дочернего процесса трейсбек уходил в файл, а в окне
    оставалась пустая вкладка;
  • панель требует Tk, которого нет в части сборок Python.
Старое окно никуда не делось: `python panel.py --gui` или `START_PANEL.bat gui`.

Ctrl+C останавливает оба сервиса аккуратно: сначала terminate и ожидание,
потом kill. Вывод пишется и в консоль, и в logs/world.log, logs/defense.log.
"""
import os
import sys
import time
import signal
import threading
import logging
import subprocess
from logging.handlers import RotatingFileHandler

BASE = os.path.dirname(os.path.abspath(__file__))
LOGS = os.path.join(BASE, "logs")
PY = sys.executable or "python"

SERVICES = [
    {"key": "world",   "script": "webapp.py", "url": "http://127.0.0.1:8787",
     "color": "\033[36m", "log": "world.log"},
    {"key": "defense", "script": "console.py", "url": "http://127.0.0.1:8788",
     "color": "\033[35m", "log": "defense.log"},
]

RESET = "\033[0m"
DIM = "\033[90m"
BOLD = "\033[1m"
RED = "\033[31m"
YELLOW = "\033[33m"

_procs = {}
_stop = threading.Event()
_out_lock = threading.Lock()


def _enable_ansi():
    """Windows 10+: включить обработку ANSI в консоли, иначе цвета печатаются
    как «←[36m». На прочих системах ничего делать не нужно."""
    if os.name != "nt":
        return True
    try:
        import ctypes
        k = ctypes.windll.kernel32
        for handle in (-11, -12):          # stdout, stderr
            h = k.GetStdHandle(handle)
            mode = ctypes.c_uint32()
            if k.GetConsoleMode(h, ctypes.byref(mode)):
                k.SetConsoleMode(h, mode.value | 0x0004)  # VIRTUAL_TERMINAL_PROCESSING
        return True
    except Exception as e:
        # Не смертельно: журнал останется читаемым, просто без цвета.
        # Но молчать нельзя — иначе «почему всё серое» не выяснить.
        sys.stderr.write(f"[panel  ] цвет в консоли недоступен: {e}\n")
        return False


def _utf8_stdout():
    """Кириллица в консоли Windows без «????». Кодировка задаётся и процессу,
    и его детям (PYTHONUTF8/PYTHONIOENCODING в окружении ниже)."""
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
        except Exception as e:
            sys.stderr.write(f"[panel  ] не удалось включить UTF-8 для вывода: {e}\n")


def _child_env():
    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    # БЕЗ ЭТОГО ЖУРНАЛ ПОЯВЛЯЕТСЯ ПАЧКАМИ РАЗ В НЕСКОЛЬКО МИНУТ.
    # stdout, перенаправленный в трубу, Python буферизует блоками по 8 КиБ:
    # оператор видит строки не тогда, когда они произошли, а когда набралось
    # на буфер. Для журнала, за которым следят вживую, это делает его
    # бесполезным.
    env["PYTHONUNBUFFERED"] = "1"
    env.setdefault("SOC_LOG_COLOR", "0")   # цвет добавляет панель, не ребёнок
    return env


class _RotatingRawLog:
    """Файл с ротацией по размеру для СЫРЫХ строк.

    Обёртка вокруг RotatingFileHandler: панель пишет уже готовые строки, свой
    формат ей не нужен, а ротация — нужна.
    """

    def __init__(self, path, max_bytes, backups):
        self.path = path
        self._h = RotatingFileHandler(path, maxBytes=max_bytes,
                                      backupCount=backups, encoding="utf-8",
                                      delay=False)
        self._h.setFormatter(logging.Formatter("%(message)s"))
        self._lg = logging.getLogger("panel.raw." + os.path.basename(path))
        self._lg.propagate = False          # в общий журнал это не дублируем
        self._lg.setLevel(logging.INFO)
        for old in list(self._lg.handlers):
            self._lg.removeHandler(old)
        self._lg.addHandler(self._h)

    def write(self, text):
        for ln in str(text).splitlines():
            self._lg.info(ln)

    def flush(self):
        try:
            self._h.flush()
        except (ValueError, OSError):
            pass

    def close(self):
        self._h.close()


def _emit(line, color="", logfile=None):
    with _out_lock:
        sys.stdout.write((color + line + RESET if color else line) + "\n")
        sys.stdout.flush()
    if logfile is not None:
        try:
            logfile.write(line + "\n")
            logfile.flush()
        except Exception as e:
            # Файл journal мог быть удалён или занят. Сообщаем ОДИН раз:
            # поток строк важнее, чем падение из-за файла.
            if not getattr(logfile, "_warned", False):
                logfile._warned = True
                with _out_lock:
                    sys.stdout.write(f"{YELLOW}[panel  ] запись в файл журнала не удалась: {e}{RESET}\n")


def _pump(svc, proc, logfile):
    """Читает вывод сервиса построчно и печатает с меткой сервиса."""
    tag = f"{svc['key']:<7}"
    try:
        for raw in proc.stdout:
            if _stop.is_set() and not raw:
                break
            line = raw.rstrip("\r\n")
            if not line.strip():
                continue
            # Строки soclog уже содержат имя сервиса; для чужих (traceback,
            # print, werkzeug до установки логгера) ставим метку сами, чтобы
            # НИ ОДНА строка не осталась без источника.
            marked = line if f" {svc['key']:<8} " in line[:60] else f"[{tag}] {line}"
            color = svc["color"]
            up = line.upper()
            if " ERROR" in up or " CRITICAL" in up or up.startswith("TRACEBACK") \
                    or "Traceback (most recent" in line:
                color = RED
            elif " WARNING" in up:
                color = YELLOW
            _emit(marked, color, logfile)
    except Exception as e:
        _emit(f"[{tag}] панель: чтение вывода прервано: {e}", RED, logfile)
    finally:
        rc = proc.poll()
        if rc is not None and not _stop.is_set():
            _emit(f"[{tag}] !!! процесс завершился, код возврата {rc}", RED, logfile)


def _start(svc):
    os.makedirs(LOGS, exist_ok=True)
    path = os.path.join(LOGS, svc["log"])
    # РОТАЦИЯ, А НЕ БЕСКОНЕЧНЫЙ ФАЙЛ.
    #
    # Прежняя панель открывала logs/world.log на дозапись и не ограничивала
    # его ничем: на рабочей машине файл дорос до 15 МБ, а за неделю прогонов
    # рос бы дальше без предела. Здесь тот же RotatingFileHandler, что и у
    # остальных журналов проекта: 10 МБ × 5 архивов на сервис.
    lf = _RotatingRawLog(path, max_bytes=10 * 1024 * 1024, backups=5)
    lf.write(f"\n===== запуск {time.strftime('%Y-%m-%d %H:%M:%S')} (panel) =====\n")
    kwargs = {}
    if os.name == "nt":
        # Своя группа процессов: Ctrl+C в панели не должен убивать детей
        # раньше, чем панель успеет их остановить по-человечески.
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    p = subprocess.Popen(
        [PY, "-u", svc["script"]], cwd=BASE, env=_child_env(),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        bufsize=1, text=True, encoding="utf-8", errors="replace", **kwargs)
    _procs[svc["key"]] = {"proc": p, "log": lf, "svc": svc}
    t = threading.Thread(target=_pump, args=(svc, p, lf), daemon=True,
                         name=f"pump-{svc['key']}")
    t.start()
    return p


def _shutdown(sig=None, frame=None):
    if _stop.is_set():
        return
    _stop.set()
    _emit("", "")
    _emit("── остановка: сигнал получен, гашу сервисы ──", BOLD)
    for key, d in _procs.items():
        p = d["proc"]
        if p.poll() is not None:
            continue
        try:
            if os.name == "nt":
                p.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                p.terminate()
        except Exception as e:
            _emit(f"[{key:<7}] сигнал остановки не доставлен ({e}) — сниму принудительно",
                  YELLOW)
    # ЛЕСТНИЦА ОСТАНОВКИ. На Windows CTRL_BREAK_EVENT доходит не до всякого
    # процесса (например, если тот не создал своей группы), поэтому ждать
    # десять секунд и сразу убивать — плохо: состояние симуляции и курсор
    # ингеста не успеют записаться. Промежуточная ступень — terminate().
    soft = time.time() + 5
    for key, d in _procs.items():
        p = d["proc"]
        while p.poll() is None and time.time() < soft:
            time.sleep(0.2)
        if p.poll() is None:
            _emit(f"[{key:<7}] не отреагировал на сигнал — terminate()", DIM)
            try:
                p.terminate()
            except Exception as e:
                _emit(f"[{key:<7}] terminate не удался: {e}", YELLOW)
    hard = time.time() + 8
    for key, d in _procs.items():
        p = d["proc"]
        while p.poll() is None and time.time() < hard:
            time.sleep(0.2)
        if p.poll() is None:
            _emit(f"[{key:<7}] не остановился — снимаю принудительно", YELLOW)
            try:
                p.kill()
            except Exception as e:
                _emit(f"[{key:<7}] снять процесс не удалось: {e}", RED)
        else:
            _emit(f"[{key:<7}] остановлен, код возврата {p.poll()}", DIM)
    for d in _procs.values():
        try:
            d["log"].close()
        except Exception as e:
            _emit(f"[panel  ] файл журнала не закрыт: {e}", YELLOW)
    _emit("── все сервисы остановлены ──", BOLD)


def run_console():
    _enable_ansi()
    _utf8_stdout()
    os.makedirs(LOGS, exist_ok=True)

    print(BOLD + "=" * 78 + RESET)
    print(BOLD + "  SOC SIMULATOR · консоль оператора" + RESET)
    print("  Мир (среда команды):      http://127.0.0.1:8787")
    print("  Защита (консоль SOC):     http://127.0.0.1:8788")
    print("  Логин: admin · пароль печатается каждым сервисом ниже при старте")
    print(DIM + "  Журнал (это же окно пишется в файлы):" + RESET)
    print(DIM + "    logs/world.log      — поток мира,     logs/defense.log — поток защиты" + RESET)
    print(DIM + "    simulator.log       — журнал мира,    logs/app-defense.log — журнал защиты" + RESET)
    print(DIM + "    logs/errors-*.log   — только ошибки с трейсбеками" + RESET)
    print(DIM + "    logs/debug-*.jsonl  — структурные записи (машиночитаемо)" + RESET)
    print(DIM + "    logs/run-*.log      — полный лог прогона (хранится 10 последних)" + RESET)
    print(DIM + "  SOC_DEBUG=1 — уровень DEBUG · SOC_LOG_ACCESS=all — строки доступа HTTP" + RESET)
    print(DIM + "  Ctrl+C — корректная остановка обоих сервисов" + RESET)
    print(BOLD + "=" * 78 + RESET)
    print()

    signal.signal(signal.SIGINT, _shutdown)
    try:
        signal.signal(signal.SIGTERM, _shutdown)
    except (ValueError, AttributeError) as e:
        # На Windows SIGTERM ставится не всегда, а в не-главном потоке — никогда.
        # Ctrl+C (SIGINT) выше уже перехвачен, поэтому остановка всё равно
        # корректная; просто отмечаем, что этот путь недоступен.
        _emit(f"[panel  ] SIGTERM не перехватывается на этой платформе ({e}); "
              f"остановка — по Ctrl+C", DIM)

    for svc in SERVICES:
        _emit(f"[panel  ] запускаю {svc['key']} ({svc['script']}) → {svc['url']}", DIM)
        try:
            _start(svc)
        except Exception as e:
            _emit(f"[panel  ] НЕ УДАЛОСЬ ЗАПУСТИТЬ {svc['key']}: {e}", RED)
        time.sleep(0.4)

    try:
        while not _stop.is_set():
            dead = [k for k, d in _procs.items() if d["proc"].poll() is not None]
            if dead and len(dead) == len(_procs):
                _emit("[panel  ] все сервисы завершились — выходим", YELLOW)
                break
            time.sleep(0.5)
    except KeyboardInterrupt:
        # Ctrl+C: гасим сервисы в finally — это и есть штатный выход.
        _emit("[panel  ] получен Ctrl+C", DIM)
    finally:
        _shutdown()
    return 0


def main():
    if "--gui" in sys.argv or "gui" in sys.argv[1:]:
        import launcher
        return launcher.main() if hasattr(launcher, "main") else 0
    return run_console()


if __name__ == "__main__":
    sys.exit(main() or 0)
