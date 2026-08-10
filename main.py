#!/usr/bin/env python3
"""
SOC GitLab Simulator
Симулирует работу SOC-команды: коммиты, MR, code review, откаты,
issues, кампании, релизы — всё в таймлапсе по виртуальным часам.

Запуск:
    python3 main.py

Остановка:
    Ctrl+C — корректное завершение со статистикой
"""
import os
import sys
import time
import signal
import logging
from datetime import datetime
from logging.handlers import RotatingFileHandler

import config
import simclock
import events
import runlog
import telegram
import report
import bootstrap
import threading
from state         import SimState
from gitlab_client import GitLabClient
from agents.base   import BaseAgent
from agents.lead   import LeadAgent
from scheduler     import Scheduler


def init_clock():
    """Создаёт и активирует виртуальные часы (таймлапс)."""
    scale = config.compute_time_scale()
    if config.SIM_START:
        start_sim = datetime.fromisoformat(config.SIM_START)
    else:
        start_sim = datetime.now().replace(
            hour=config.WORK_HOURS_START, minute=0, second=0, microsecond=0)
    clock = simclock.SimClock(
        start_sim   = start_sim,
        scale       = scale,
        work_start  = config.WORK_HOURS_START,
        work_end    = config.WORK_HOURS_END,
        work_days   = config.WORK_DAYS,
        fast_forward_offhours = config.FAST_FORWARD_OFFHOURS,
        api_min_pause = config.API_MIN_PAUSE,
        max_real_sleep = config.MAX_REAL_SLEEP,
    )
    return simclock.init(clock), scale


def _h_console():
    h = logging.StreamHandler(sys.stdout); h.setLevel(logging.INFO); return h

def _h_simlog():
    h = RotatingFileHandler(config.LOG_FILE, maxBytes=10*1024*1024,
                            backupCount=5, encoding="utf-8")
    h.setLevel(logging.INFO); return h


# -----------------------------------------------------------------------
def setup_logging():
    """Логи процесса «мир».

    Три приёмника, у каждого своя роль:
      • консоль            — INFO, чтобы за прогоном было видно, что происходит;
      • simulator.log      — то же самое в файл с ротацией;
      • soclog (logs/*.jsonl, logs/errors*.log) — СТРУКТУРНЫЕ записи с
        контекстом и полные трейсбеки.

    Третьего не было. soclog.install() вызывался в console.py, webapp.py и
    run_defense.py, но НЕ в main.py — то есть ровно в том процессе, который
    ходит в GitLab и порождает события. Все ошибки записи в репозиторий,
    отказы API и сбои активностей падали в плоский simulator.log без контекста
    и без трейсбека, а страница «Диагностика» их не видела вовсе. Из-за этого
    357 отказов create_branch и 193 отказа по playbooks за прогон никак не
    проявились: счётчик ошибок в интерфейсе показывал ноль.
    """
    fmt = "%(asctime)s %(levelname)-8s %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"
    logging.basicConfig(
        level   = getattr(logging, config.LOG_LEVEL, logging.INFO),
        format  = fmt,
        datefmt = datefmt,
        handlers=[
            _h_console(),
            _h_simlog(),
        ],
    )
    try:
        import soclog
        paths = soclog.install()
        logging.getLogger(__name__).info(
            "структурные логи: %s", paths, extra={"ctx": {"paths": paths}})
    except Exception:
        logging.getLogger(__name__).error(
            "soclog не установлен — ошибки будут без контекста", exc_info=True)


logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------
def init_agents(gl: GitLabClient) -> dict:
    agents = {}
    for uname, info in config.USERS.items():
        agents[uname] = (LeadAgent(uname, gl) if info.get("role") == "lead"
                         else BaseAgent(uname, gl))
    logger.info(f"Инициализируем токены агентов ({len(agents)})...")
    ok = 0
    for username, agent in agents.items():
        try:
            if agent.token:
                ok += 1
        except Exception as e:
            logger.warning(f"  - {username} — токен не получен: {e}")
    logger.info(f"  токенов получено: {ok}/{len(agents)}")
    return agents


# -----------------------------------------------------------------------
_scheduler: Scheduler = None
_running = True


def handle_signal(sig, frame):
    global _running
    logger.info("\n[!] Получен сигнал завершения, останавливаемся...")
    _running = False


def _start_reporter(sched):
    def loop():
        import time as _t
        every = max(1, int(config.TELEGRAM.get("report_every_min", 60))) * 60
        start = _t.time()
        while _running:
            for _ in range(every):
                if not _running:
                    return
                _t.sleep(1)
            try:
                telegram.send(report.build_report(sched, title="Отчёт SOC-симулятора",
                                                  uptime_s=int(_t.time() - start)))
            except Exception:
                pass
    threading.Thread(target=loop, daemon=True).start()


# -----------------------------------------------------------------------
def main():
    global _scheduler, _running

    setup_logging()
    runlog.setup()
    signal.signal(signal.SIGINT,  handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    clock, scale = init_clock()
    logger.info("=" * 60)
    logger.info("  SOC GitLab Simulator")
    logger.info(f"  GitLab:        {config.GITLAB_URL}")
    logger.info(f"  Рабочие часы:  {config.WORK_HOURS_START:02d}:00-"
                f"{config.WORK_HOURS_END:02d}:00, дни {config.WORK_DAYS}")
    logger.info(f"  Off-hours:     режим '{config.OFF_HOURS_MODE}'")
    if config.TIMELAPSE_ENABLED:
        logger.info(f"  TIMELAPSE:     ВКЛ · scale x{scale:.1f} "
                    f"(1 рабочий день ~ {config.SIM_WORKDAY_REAL_MINUTES} реальных мин)")
    else:
        logger.info("  TIMELAPSE:     выкл (реальное время)")
    logger.info(f"  Старт sim:     {simclock.stamp()}")
    logger.info(f"  Активностей:   {len(config.ACTIVITY_WEIGHTS)} типов + ритм отдела")
    logger.info("=" * 60)

    gl = GitLabClient(config.GITLAB_URL, config.ADMIN_TOKEN, ssl_verify=False)

    logger.info("Проверка подключения к GitLab...")
    test = gl._api("GET", "/version")
    if not test:
        logger.error("Не удалось подключиться к GitLab. Проверь GITLAB_URL и ADMIN_TOKEN.")
        sys.exit(1)
    logger.info(f"GitLab {test.get('version', '?')} — подключение OK")
    logger.info("Инициализация среды (репозитории, сотрудники, права)...")
    bootstrap.ensure_environment(gl)

    state_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              config.STATE_FILE)
    state = SimState(state_path)
    rid = events.init()
    logger.info(f"Журнал событий: {rid}")

    agents = init_agents(gl)
    _scheduler = Scheduler(agents, gl, state=state)

    if config.TELEGRAM.get("send_start_stop"):
        telegram.send_async(f"▶️ SOC-симулятор запущен · {simclock.stamp()} · масштаб x{scale:.0f}")
    _start_reporter(_scheduler)
    logger.info("Симулятор запущен. Для остановки нажми Ctrl+C")
    logger.info("-" * 60)

    while _running:
        try:
            _scheduler.run_once()
        except KeyboardInterrupt:
            break
        except Exception as e:
            logger.exception(f"Неожиданная ошибка в главном цикле: {e}")
            time.sleep(5)

    logger.info("\n" + "=" * 60)
    logger.info("Симулятор остановлен.")
    try:
        if config.TELEGRAM.get("send_start_stop"):
            telegram.send(report.build_report(_scheduler, title="SOC-симулятор остановлен"))
    except Exception:
        pass
    try:
        state.save()
    except Exception:
        # Несохранённое состояние = потерянные правила, спринт и счётчики.
        # Следующий запуск начнёт с устаревшего файла и «забудет» прогон.
        logger.error("не удалось сохранить состояние симуляции — прогресс "
                     "прогона потерян", exc_info=True,
                     extra={"ctx": {"file": config.STATE_FILE}})
    if _scheduler:
        _scheduler.print_stats()
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
