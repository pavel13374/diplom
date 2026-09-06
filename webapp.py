#!/usr/bin/env python3
"""
Веб-админка SOC-симулятора (красивый дашборд со слайдерами и пояснениями).

Запуск:  python webapp.py   (или run.bat)
Открыть: http://127.0.0.1:8787   (пароль печатается в консоли при старте,
свой задаётся переменной окружения SOC_ADMIN_PASS)

Замечание про первую строку файла: здесь стоял `import os.path as _os_path`
ВЫШЕ shebang и этого литерала, из-за чего литерал переставал быть докстрингом
модуля и webapp.__doc__ был None. Ровно тот же дефект console.py в своём
докстринге объявляет исправленным — исправили в одном файле и оставили в
другом, хотя это самая крупная точка входа проекта.
"""
import os
import os.path as _os_path
import time
import logging
import threading
import collections
from datetime import datetime
from functools import wraps

from flask import Flask, request, session, redirect, url_for, jsonify, send_file

import config


# =======================================================================
#  ШАБЛОНЫ
# =======================================================================
# Раньше HTML страниц лежал прямо в этом файле строковыми константами: одна
# только DASH занимала 144 КБ (2100 строк) и делала модуль нечитаемым — логика
# ингеста, детектирования и корреляции терялась между разметкой и CSS.
# Теперь страницы лежат в templates/ обычными .html-файлами: их можно открыть
# в редакторе с подсветкой, отдать на правку вёрстки и посмотреть diff.
#
# Свой загрузчик, а не render_template Flask: шаблоны здесь статические
# (данные подтягивает JS через /api/*), поэтому движок шаблонов не нужен,
# а лишняя зависимость от структуры каталогов Flask — не нужна тем более.
_TPL_DIR = _os_path.join(_os_path.dirname(_os_path.abspath(__file__)),
                         "templates", "env")
_TPL_CACHE = {}


def _tpl(name):
    """Прочитать шаблон (с кэшем в памяти)."""
    # Кэш сбрасывается при правке файла: перезагрузчик Flask следит
    # только за .py, поэтому изменения вёрстки иначе не видны без
    # ручного перезапуска процесса.
    path = _os_path.join(_TPL_DIR, name)
    try:
        mtime = _os_path.getmtime(path)
    except OSError:
        mtime = 0
    hit = _TPL_CACHE.get(name)
    if hit and hit[0] == mtime:
        return hit[1]
    with open(path, encoding="utf-8") as f:
        text = f.read()
    text = websec.inject_csrf_meta(text)
    _TPL_CACHE[name] = (mtime, text)
    return text
import simclock
import events
import runlog
import soclog
import telegram
import report
from state import SimState
from gitlab_client import GitLabClient
from agents.base import BaseAgent
from agents.lead import LeadAgent
from scheduler import Scheduler

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


import re as _re

# Werkzeug раскрашивает свои строки ANSI-кодами для терминала. В браузере
# они выводились как текст: на экране было видно «[32mGET / HTTP/1.1[0m».
_ANSI_RE = _re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# Опрос собственного API интерфейсом — 90% строк журнала и ноль
# продуктового смысла. Успешные запросы к /api/ в ленту не идут,
# всё остальное (ошибки, редиректы, действия симуляции) остаётся.
# Любая успешная строка доступа werkzeug: опрос API, статика, редирект
# на форму входа. Продуктового смысла в них нет, а журнал они
# занимают целиком. Ошибки (4xx/5xx) остаются.
_NOISE_RE = _re.compile(r'"(?:GET|POST|HEAD|PUT|DELETE) /[^"]*" [23]\d\d ')


class RingLogHandler(logging.Handler):
    def __init__(self, maxlen=4000):
        super().__init__()
        self.buf = collections.deque(maxlen=maxlen)
        self._id = 0
        self._lock = threading.Lock()

    def emit(self, record):
        try:
            msg = record.getMessage()
        except Exception:
            msg = str(record.msg)
        msg = _ANSI_RE.sub("", msg).strip()
        if not msg or _NOISE_RE.search(msg):
            return
        with self._lock:
            self._id += 1
            self.buf.append({"id": self._id,
                             "t": datetime.now().strftime("%H:%M:%S"),
                             "level": record.levelname, "msg": msg})

    def since(self, last_id):
        with self._lock:
            return [e for e in self.buf if e["id"] > last_id]


def _gitlab_status():
    """Состояние связи с GitLab для статус-бара и диагностики.

    `by_op` — РАЗБИВКА ОТКАЗОВ ПО ОПЕРАЦИЯМ. Общий счётчик ошибок сам по себе
    бесполезен: «312 ошибок» ничего не говорит, а «create_branch: 357 из 3855»
    сразу указывает, что систематически падает создание веток (конфликт имён
    или нет прав в конкретном репозитории), и это надо чинить, а не листать лог.
    """
    try:
        from agents.base import GITLAB_STATUS
        by_op = dict(GITLAB_STATUS.get("by_op") or {})
        ok_by_op = dict(GITLAB_STATUS.get("ok_by_op") or {})
        worst = sorted(
            ({"op": op,
              "fail": n,
              "ok": ok_by_op.get(op, 0),
              "fail_pct": round(100.0 * n / max(1, n + ok_by_op.get(op, 0)), 1)}
             for op, n in by_op.items()),
            key=lambda d: -d["fail"])[:6]
        return {"errors": GITLAB_STATUS.get("errors", 0), "ok": GITLAB_STATUS.get("ok", 0),
                "last_error": GITLAB_STATUS.get("last_error", ""),
                "last_error_ts": GITLAB_STATUS.get("last_error_ts"),
                "by_op": worst}
    except Exception:
        logging.getLogger("webapp").error("не удалось прочитать статус GitLab", exc_info=True)
        return {"errors": 0, "ok": 0, "last_error": "", "last_error_ts": None,
                "by_op": []}


def _last_event_ago():
    try:
        lr = events.stats().get("last_real")
        if not lr:
            return None
        return int(time.time() - lr)
    except Exception:
        logging.getLogger("webapp").error(
            "не удалось определить возраст последнего события — статус «мир жив» "
            "будет неверным", exc_info=True)
        return None


#: Возврат для методов GitLabClient, у которых НЕТ аннотации типа.
#:
#: Перечислены явно и проверяются тестом (tests/test_offline.py): если в клиенте
#: появится новый неаннотированный метод, тест назовёт его по имени. Это не
#: «список известных имён» прежней заглушки, а закрытие ровно того зазора,
#: который не покрывают аннотации.
_FAKE_UNANNOTATED = {
    # Служебные обёртки сети: в offline их не зовут напрямую, но контракт
    # должен быть определён — иначе заглушка вернёт True туда, где ждут
    # Response/список, и падение случится по месту.
    "_request":           None,
    "_api":               {},
    "_api_paged":         ([], False),
    "_ok":                False,
    "create_named_token": True,
    "server_time":        None,          # None -> берётся локальное время
    # В offline числа апрувов НЕ СУЩЕСТВУЕТ, и придумывать его нельзя: ноль
    # апрувов — это алерт (merge-without-approval), а единица — молчаливое
    # «ревью было». None означает «неизвестно», и agents.base.merge_mr просто
    # не кладёт поле в событие. Аннотация Optional[int] сама по себе дала бы
    # int-заглушку (1) и подделала бы ревью на каждом merge в offline-прогоне.
    "get_mr_approvals":   None,
    "find_user":          1,
    "create_user":        1,
    "ensure_user":        (1, True),     # (id, created)
    "group_id":           1,
    "create_group":       1,
    "unblock_user":       True,
    "restore_group":      True,
    "restore_project":    True,
    "ensure_group":       (1, True),
    "get_project_id":     1,
    "ensure_project":     (1, True),
}

#: Нулевое значение по аннотации возврата.
#:
#: `str` пустой строкой, а НЕ None: вызывающий сразу делает `content.rstrip()`,
#: и None упал бы ровно так же, как раньше падало True.
_FAKE_BY_TYPE = {
    bool:  True,             # операция «удалась»: мир не должен считать это отказом
    int:   0,                # для create_* перекрывается ниже — там нужен живой iid
    list:  [],
    dict:  {},
    str:   "",
    tuple: (1, True),
}


def _unwrap_optional(ann):
    """Optional[X] / Union[X, None] -> X; остальное возвращается как есть.

    Отдельной функцией, потому что наивное `ann.__name__` на Optional[str] даёт
    строку «Optional», а не «str»: у typing-обобщений в Python 3.10+ есть
    собственный __name__. Из-за этого get_file — единственный метод клиента с
    Optional — не находил своё правило и проваливался в ветку «не знаю, верну
    True», то есть ровно в тот дефект, ради которого всё и переписывалось.
    """
    import typing
    if typing.get_origin(ann) is typing.Union:
        args = [a for a in typing.get_args(ann) if a is not type(None)]  # noqa: E721
        if len(args) == 1:
            return args[0]
    return ann


class _FakeGL:
    """Заглушка GitLab для OFFLINE-режима: вызовы безопасны и мгновенны.

    Ответ выводится ИЗ КОНТРАКТА НАСТОЯЩЕГО КЛИЕНТА (аннотации возврата у
    GitLabClient), а не из списка имён.

    Почему так. Прежняя заглушка перечисляла имена методов руками и на всё
    остальное возвращала `True`. Клиент с тех пор дорос до 51 метода, список
    остался на девяти, и каждый неучтённый метод отдавал булево значение туда,
    где ждут данные:

        revert_bad_rule:  for c in gl.get_commits(...)  -> 'bool' object is not iterable
        update_parser:    gl.get_file(...).rstrip()     -> 'bool' object has no attribute 'rstrip'

    То есть заявленное в README «без GitLab стенд работает» держалось ровно до
    первой активности, которой понадобились настоящие данные.

    Тот же приём, что и с ACTIONS в ml_features: рассинхрон не комментируется,
    а делается невозможным — источник правды один, и он проверяется тестом.
    """
    import random as _r

    #: Методы, создающие сущность: вызывающий кладёт результат как iid и потом
    #: обращается по нему, поэтому ноль здесь не годится.
    _CREATES = ("create_mr", "create_issue", "ensure_milestone")

    #: Правдоподобное содержимое репозитория.
    #:
    #: Пустой список — НЕ нейтральный ответ. Активности, которые работают по
    #: существующим файлам, при нём просто не делают ничего: mass_deletion
    #: (техника T1485, шаг кампании destructive_insider) выбирал жертв из
    #: list_files, получал пустоту и возвращал False. Шаг молча выпадал из
    #: кампании, а правило mass-file-delete не срабатывало ни разу — при том
    #: что README обещает работу стенда без GitLab.
    #:
    #: Мир и так синтетический, имена файлов в нём придуманы, поэтому
    #: правдоподобный список — не подделка, а ровно та же симуляция, что и
    #: остальная среда.
    _FILES = tuple(
        [f"rules/win/{n}.yml" for n in ("lsass_dump", "susp_powershell", "wmi_persist",
                                        "svc_install", "rdp_bruteforce", "sam_access")] +
        [f"rules/linux/{n}.yml" for n in ("sudo_abuse", "cron_persist", "ssh_key_add")] +
        [f"rules/cloud/{n}.yml" for n in ("iam_priv_esc", "s3_public", "key_create")] +
        [f"normalizers/{n}.py" for n in ("syslog", "windows_evtx", "cloudtrail")] +
        [f"playbooks/{n}.md" for n in ("ir_ransomware", "ir_phishing", "ir_insider")] +
        ["docs/onboarding.md", "docs/runbook.md", "README.md",
         "ci/deploy.yml", ".gitlab-ci.yml", "requirements.txt"])

    @staticmethod
    def _hexid():
        return "".join(_FakeGL._r.choice("0123456789abcdef") for _ in range(40))

    @staticmethod
    def _ret_for(name):
        import gitlab_client
        fn = getattr(gitlab_client.GitLabClient, name, None)
        if fn is None:
            # Метода нет и в настоящем клиенте — вызывающий ошибся именем.
            # Возвращаем None: пусть падает по месту, а не молча «работает».
            logging.getLogger("webapp").warning(
                "offline: обращение к несуществующему методу GitLab-клиента",
                extra={"ctx": {"method": name}})
            return None
        if name in _FakeGL._CREATES:
            return _FakeGL._r.randint(100, 9999)
        if name in _FAKE_UNANNOTATED:
            return _FAKE_UNANNOTATED[name]
        if name == "list_files":
            return list(_FakeGL._FILES)
        if name == "get_commits":
            # Список коммитов нужен revert_bad_rule: он ищет среди них feat-коммит.
            return [{"id": _FakeGL._hexid(), "short_id": _FakeGL._hexid()[:8],
                     "title": t, "message": t, "author_name": "offline",
                     "created_at": "2026-06-08T11:00:00.000Z"}
                    for t in ("feat: add lsass_dump rule",
                              "fix: tune threshold in cron_persist",
                              "feat(cloud): iam privilege escalation rule",
                              "docs: update runbook",
                              "chore: bump deps")]
        ann = _unwrap_optional(getattr(fn, "__annotations__", {}).get("return"))
        if ann in _FAKE_BY_TYPE:
            return _FAKE_BY_TYPE[ann]
        logging.getLogger("webapp").warning(
            "offline: не знаю, что вернуть за метод GitLab-клиента — верну True. "
            "Добавь метод в _FAKE_UNANNOTATED или проставь ему аннотацию возврата",
            extra={"ctx": {"method": name, "annotation": str(ann)}})
        return True

    def __getattr__(self, name):
        def f(*a, **k):
            return _FakeGL._ret_for(name)
        return f


class Runner:
    def __init__(self):
        self.thread = None
        self.running = False
        self.stop_flag = False
        self._start_lock = threading.Lock()
        self.gl = None
        self.state = None
        self.agents = None
        self.scheduler = None
        self.clock = None
        self.scale = 1.0
        self.started_real = None
        self.conn_ok = None
        self.conn_msg = ""
        #: Последняя подробная диагностика связи (gitlab_client.diagnose).
        self.diag = {}
        self.offline = False
        self._ollama_cache = {"ts": 0.0, "ok": False}
        self._srv = None
        self._srv_ts = 0
        self.series = collections.deque(maxlen=300)
        self._last_runs = 0
        self._sampler_thread = None
        self.log = RingLogHandler()
        self.log.setLevel(logging.INFO)
        self._report_thread = None
        root = logging.getLogger()
        root.setLevel(getattr(logging, config.LOG_LEVEL, logging.INFO))
        root.addHandler(self.log)
        # Вывод в stdout — ЕДИНЫМ форматом для всех процессов (soclog).
        # Раньше здесь стоял собственный формат "%H:%M:%S I name: msg": без
        # даты, без имени сервиса и без структурного контекста, а у консоли
        # защиты консольного вывода не было вовсе. В общей панели строки двух
        # процессов было не различить, а идентификаторы (инцидент, правило,
        # актор) не выводились никуда, кроме debug-*.jsonl.
        soclog.install_console()
        try:
            from logging.handlers import RotatingFileHandler
            fh = RotatingFileHandler(os.path.join(BASE_DIR, config.LOG_FILE),
                                     maxBytes=10 * 1024 * 1024, backupCount=5,
                                     encoding="utf-8")
            # Тот же формат, что в консоли. Раньше здесь не было даже
            # %(name)s: по строке simulator.log нельзя было понять, какая
            # подсистема её написала.
            fh.setFormatter(soclog.human_formatter())
            fh.setLevel(logging.INFO)
            root.addHandler(fh)
        except Exception:
            # Ирония в том, что провал НАСТРОЙКИ ЛОГОВ раньше глушился молча:
            # simulator.log просто не появлялся, и «почему нет логов» выяснять
            # было нечем. Пишем хотя бы в stderr — он уже настроен выше.
            logging.getLogger("webapp").error(
                "не удалось подключить файловый лог — записи будут только в "
                "консоли", exc_info=True)
        try:
            runlog.setup(BASE_DIR)
        except Exception:
            logging.getLogger("webapp").error(
                "runlog не настроен — журнал прогонов вестись не будет",
                exc_info=True)
        self.logger = logging.getLogger("webapp")

    def _build_agents(self):
        agents = {}
        for uname, info in config.USERS.items():
            agents[uname] = (LeadAgent(uname, self.gl) if info.get("role") == "lead"
                             else BaseAgent(uname, self.gl))
        self.logger.info(f"Инициализация токенов агентов ({len(agents)})...")
        for u, a in agents.items():
            try:
                _ = a.token
            except Exception as e:
                self.logger.warning(f"токен {u} не получен: {e}")
        return agents

    def _build(self):
        self.scale = config.compute_time_scale()
        if config.SIM_START:
            start_sim = datetime.fromisoformat(config.SIM_START)
        else:
            start_sim = config.default_sim_start()
        self.logger.info(f"Старт симуляции (sim-время): {start_sim:%a %Y-%m-%d %H:%M}")
        self.clock = simclock.SimClock(
            start_sim=start_sim, scale=self.scale,
            work_start=config.WORK_HOURS_START, work_end=config.WORK_HOURS_END,
            work_days=config.WORK_DAYS, fast_forward_offhours=config.FAST_FORWARD_OFFHOURS,
            api_min_pause=config.API_MIN_PAUSE, max_real_sleep=config.MAX_REAL_SLEEP)
        simclock.init(self.clock)
        self.gl = GitLabClient(config.GITLAB_URL, config.ADMIN_TOKEN, ssl_verify=config.gitlab_verify())
        # OFFLINE ПЕРЕПРОВЕРЯЕТСЯ НА КАЖДОМ ЗАПУСКЕ, А НЕ ЗАЩЁЛКИВАЕТСЯ.
        #
        # Было: если GitLab не ответил, config.OFFLINE_MODE становился True — и
        # при следующем запуске ветка `if OFFLINE_MODE` пропускала проверку
        # связи вообще. Флаг работал как односторонняя защёлка: поднять GitLab и
        # нажать «Запустить» было недостаточно, помогал только перезапуск
        # процесса. Типичный сценарий — мир стартовали, пока ВМ с GitLab ещё
        # грузилась.
        #
        # Хуже того, причина показывалась неверно: сообщение гласило «offline
        # (включён вручную)», хотя пользователь ничего не включал.
        #
        # Теперь принудительный offline (переменная окружения SOC_OFFLINE)
        # отделён от автоматического отката: первый уважается всегда, второй
        # каждый раз проверяется заново.
        if config.OFFLINE_FORCED:
            # Единственный способ оказаться без GitLab — попросить об этом явно
            # переменной окружения. Так работают тесты и research/-скрипты.
            self.conn_ok = False
            self.diag = {"ok": False, "reason": "offline: включён переменной SOC_OFFLINE",
                         "detail": "", "url": config.GITLAB_URL}
            self.conn_msg = self.diag["reason"]
        else:
            self.logger.info(f"Подключение к GitLab {config.GITLAB_URL} ...")
            self.diag = self.gl.diagnose()
            self.conn_ok = bool(self.diag.get("ok"))
            self.conn_msg = self.diag.get("reason") or "?"
            if self.conn_ok:
                self.logger.info("GitLab OK: %s (пользователь @%s)",
                                 self.conn_msg, self.diag.get("user"))
                if self.diag.get("detail"):
                    self.logger.warning("GitLab: %s", self.diag["detail"])
            else:
                self.logger.error("GitLab недоступен: %s — %s",
                                  self.conn_msg, self.diag.get("detail", ""))

        # МИР РАБОТАЕТ ТОЛЬКО ЧЕРЕЗ НАСТОЯЩИЙ GITLAB.
        #
        # Раньше при недоступном GitLab клиент молча подменялся заглушкой:
        # события продолжали писаться, счётчики росли, экран выглядел рабочим —
        # и отличить «стенд работает» от «стенд рисует пустоту» было нельзя.
        # Отсюда же брались падения активностей, которым нужны настоящие данные.
        #
        # Теперь отказ связи — это ОТКАЗ ЗАПУСКА с названной причиной, а не
        # тихий переход в другой режим. Заглушка осталась ровно для одного
        # случая — явно запрошенного SOC_OFFLINE (тесты и офлайн-эксперименты).
        if config.OFFLINE_FORCED:
            config.OFFLINE_MODE = True
            self.offline = True
            self.gl = _FakeGL()
            self.logger.warning("SOC_OFFLINE=1: GitLab не вызывается, события пишутся локально")
        elif not self.conn_ok:
            config.OFFLINE_MODE = False
            self.offline = False
            raise RuntimeError(
                f"GitLab недоступен ({config.GITLAB_URL}): {self.conn_msg}. "
                + (self.diag.get("detail") or "")
                + " Мир не запущен — исправьте связь и нажмите «Запустить» ещё раз.")
        else:
            config.OFFLINE_MODE = False
            self.offline = False
            self.logger.info("GitLab на связи: %s", self.conn_msg)

        if not config.OFFLINE_MODE:
            try:
                import bootstrap
                self.logger.info("Инициализация среды (репозитории, сотрудники, права)...")
                bootstrap.ensure_environment(self.gl)
            except Exception as e:
                self.logger.error("bootstrap не удался: %s", e, exc_info=True)
        self.state = SimState(os.path.join(BASE_DIR, config.STATE_FILE))
        events.init()
        self.agents = self._build_agents()
        self.scheduler = Scheduler(self.agents, self.gl, state=self.state)

    def _loop(self):
        self.logger.info("Симуляция запущена")
        while not self.stop_flag:
            try:
                self.scheduler.run_once()
            except Exception as e:
                self.logger.exception(f"Ошибка в цикле: {e}")
                time.sleep(2)
        self.running = False
        self.logger.info("Симуляция остановлена")

    def start(self):
        # ПОД ЗАМКОМ: проверка `if self.running` и присваивание были разными
        # операциями, а маршрут /api/start обслуживается многопоточным
        # сервером. Два одновременных нажатия «Запустить» поднимали ДВА цикла
        # симуляции на одном состоянии и одном журнале.
        with self._start_lock:
            if self.running:
                return False, "уже запущена"
            self.running = True          # занимаем место до долгой инициализации
        try:
            self._build()
        except Exception as e:
            self.logger.exception(f"Не удалось инициализировать: {e}")
            with self._start_lock:
                self.running = False
            return False, str(e)
        self.stop_flag = False
        self.started_real = time.time()
        self.series.clear()
        self._last_runs = 0
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        self._sampler_thread = threading.Thread(target=self._sampler, daemon=True)
        self._sampler_thread.start()
        if config.TELEGRAM.get('send_start_stop'):
            telegram.send_async(f'▶️ SOC-симулятор запущен (web) · scale x{self.scale:.0f}',
                                kind='lifecycle')
        self._report_thread = threading.Thread(target=self._reporter, daemon=True)
        self._report_thread.start()
        return True, "запущена"

    def stop(self):
        with self._start_lock:
            if not self.running:
                return False, "не запущена"
            self.stop_flag = True
        if self.state:
            try:
                self.state.save()
            except Exception:
                # Молчание здесь означало ПОТЕРЮ накопленного состояния прогона
                # (жизненный цикл правил, спринт, ротация дежурств) без единой
                # строки в логе — ровно в том месте, где его и надо сохранить.
                self.logger.error("не удалось сохранить состояние при остановке — "
                                  "прогресс прогона потерян", exc_info=True)
        # ХВОСТ ЖУРНАЛА ЗАКРЫВАЕТСЯ ЯВНО.
        #
        # events.close() не вызывался нигде на пути веб-панели: буфер файла
        # events.jsonl оставался незакрытым, и самые свежие записи прогона —
        # то есть обычно самые интересные — могли не дойти до диска.
        try:
            events.close()
        except Exception:
            self.logger.error("не удалось закрыть журнал событий — хвост записей "
                              "может быть потерян", exc_info=True)
        try:
            if config.TELEGRAM.get("send_start_stop"):
                telegram.send_async(report.build_report(self.scheduler, title="Мир (симуляция) остановлен"))
        except Exception:
            self.logger.warning("не удалось отправить отчёт об остановке", exc_info=True)
        return True, "остановка инициирована"

    def apply_live(self):
        if not self.clock:
            return
        self.scale = config.compute_time_scale()
        self.clock.set_scale(self.scale)
        self.clock.work_start = config.WORK_HOURS_START
        self.clock.work_end = config.WORK_HOURS_END
        self.clock.work_days = list(config.WORK_DAYS)
        self.clock.fast_forward_offhours = config.FAST_FORWARD_OFFHOURS
        self.clock.api_min_pause = config.API_MIN_PAUSE
        self.clock.max_real_sleep = config.MAX_REAL_SLEEP

    def _reporter(self):
        import time as _t
        every = max(1, int(config.TELEGRAM.get('report_every_min', 60))) * 60
        while not self.stop_flag:
            for _ in range(every):
                if self.stop_flag:
                    return
                _t.sleep(1)
            try:
                up = int(_t.time() - (self.started_real or _t.time()))
                telegram.send(report.build_report(self.scheduler, uptime_s=up),
                              kind="world_report")
            except Exception:
                # Молчаливый pass здесь означал: периодический отчёт перестал
                # уходить, и узнать об этом было неоткуда.
                self.logger.error("периодический отчёт мира в Telegram не "
                                  "отправлен", exc_info=True)

    def _server_time(self):
        if self.gl and (time.time() - self._srv_ts > 20):
            try:
                self._srv = self.gl.server_time()
            except Exception:
                self._srv = None
            self._srv_ts = time.time()
        return self._srv

    def _record_sample(self):
        if not self.scheduler:
            return
        runs = self.scheduler.stats.get("total_runs", 0)
        delta = max(0, runs - self._last_runs)
        self._last_runs = runs
        now_sim = simclock.now() if self.clock else datetime.now()
        self.series.append({
            "sim": now_sim.strftime("%a %H:%M"),
            "sim_full": now_sim.strftime("%Y-%m-%d %H:%M:%S"),
            "rt": datetime.now().strftime("%H:%M:%S"),
            "n": delta,
            "total": runs,
            "ok": self.scheduler.stats.get("total_ok", 0),
            "fail": self.scheduler.stats.get("total_fail", 0),
        })

    def _sampler(self):
        while not self.stop_flag:
            try:
                self._record_sample()
            except Exception:
                pass
            time.sleep(2.0)

    def _ollama_ok(self):
        """Доступна ли Ollama (кэш 15с, чтобы не дёргать на каждый опрос)."""
        now = time.time()
        if now - self._ollama_cache["ts"] > 15:
            try:
                import llm_client
                self._ollama_cache["ok"] = bool(llm_client.available())
            except Exception:
                self._ollama_cache["ok"] = False
            self._ollama_cache["ts"] = now
        return self._ollama_cache["ok"]

    def status(self):
        now_sim = simclock.now() if self.clock else None
        work = simclock.is_work_time() if self.clock else False
        oncall = self.state.current_oncall() if self.state else None
        pto = self.state.who_is_out_today() if self.state else None
        scale = self.scale if self.running else config.compute_time_scale()

        asum = events.actors_summary()
        team = []
        for uname, info in config.USERS.items():
            is_bot = info["role"] == "bot"
            working = bool(self.clock) and work and uname != pto
            a = asum.get(uname, {})
            team.append({"username": uname, "name": info["name"], "role": info["role"],
                         "oncall": uname == oncall, "pto": uname == pto,
                         "stats": a,
                         "working": working or (is_bot and self.running)})

        st = self.scheduler.stats if self.scheduler else {}
        acts = {k: v for k, v in st.items()
                if k not in ("total_runs", "total_ok", "total_fail", "skipped_offhours") and v}
        return {
            "running": self.running,
            "conn_ok": self.conn_ok, "conn_msg": self.conn_msg,
            "real_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "sim_time": now_sim.strftime("%a %Y-%m-%d %H:%M:%S") if now_sim else "—",
            "gitlab_time": self._server_time() or "—",
            "is_work": work,
            "timelapse": config.TIMELAPSE_ENABLED,
            "scale": round(scale, 2),
            "workday_min": config.SIM_WORKDAY_REAL_MINUTES,
            "work_hours": f"{config.WORK_HOURS_START:02d}:00–{config.WORK_HOURS_END:02d}:00",
            "offhours_mode": config.OFF_HOURS_MODE,
            "gitlab_dates": getattr(config, "GITLAB_DATES", "real"),
            "oncall": oncall, "pto": pto,
            "sprint": (self.state.data["sprint_number"] if self.state else None),
            "rules": (self.state.rule_count() if self.state else 0),
            "uptime": int(time.time() - self.started_real) if self.started_real and self.running else 0,
            # «Действий» на дашборде — это ok+fail, а НЕ total_runs.
            # total_runs считает итерации планировщика, среди которых есть
            # холостые: опрос очереди команд, обеденный перерыв, ночной
            # поллинг. Плитки стояли рядом и читались как разбиение целого
            # («Действий 6 = Успешно 5 + С ошибкой 0 + Пропущено 0»), хотя
            # им не были: одна итерация просто исчезала. Итерации остаются
            # в журнале планировщика, где они и нужны.
            "total_actions": st.get("total_ok", 0) + st.get("total_fail", 0),
            "total_runs": st.get("total_runs", 0),
            "total_ok": st.get("total_ok", 0),
            "total_fail": st.get("total_fail", 0),
            "offhours_skipped": st.get("skipped_offhours", 0),
            "last_activity": getattr(self.scheduler, "last_activity", None) if self.scheduler else None,
            "last_actor": getattr(self.scheduler, "last_actor", None) if self.scheduler else None,
            "last_ts": getattr(self.scheduler, "last_activity_ts", None) if self.scheduler else None,
            "team": team, "activities": acts,
            "events": events.stats(),
            "runlog": runlog.stats(),
            "telegram": telegram.enabled(),
            "offline": bool(getattr(config, "OFFLINE_MODE", False)),
            "ollama": self._ollama_ok(),
            "gitlab_status": _gitlab_status(),
            "last_event_ago": _last_event_ago(),
            "ff_offhours": config.FAST_FORWARD_OFFHOURS,
            "last_ff": getattr(self.scheduler, "last_ff", None) if self.scheduler else None,
            "time_mode": ("Реальное время 1:1" if not config.TIMELAPSE_ENABLED
                          else f"Ускорение ×{round(scale, 1)}"),
        }


runner = Runner()

import soclog
soclog.install()   # структурные JSON-логи + errors.log

import websec

app = Flask(__name__)
# Имя cookie у каждой консоли своё: cookie не разделяются по портам, поэтому
# с общим именем «session» две консоли на 127.0.0.1 перетирали друг другу
# атрибуты (в частности SameSite) и сталкивались с любым другим локальным
# Flask-приложением.
websec.setup_app(app, "sentinel_env")


@app.errorhandler(websec.BadArg)
def _bad_arg(e):
    return jsonify({"error": "bad_request", "field": e.name, "detail": e.detail}), 400


@app.errorhandler(Exception)
def _unhandled(e):
    """Любая необработанная ошибка — в errors.log с полным трейсбеком.

    Наружу уходит только идентификатор: текст исключения здесь регулярно
    содержит пути на диске, адрес GitLab и куски ответов API.
    """
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return e
    return websec.error_ref(logging.getLogger("webapp"), e)


#: Форма входа отправляется обычным POST без JS — токен в ней ещё неоткуда взять.
app.before_request(websec.csrf_protect(exempt_paths={"/login"}))


@app.after_request
def _sec_headers(resp):
    websec.issue_csrf(resp)
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers.setdefault("Content-Security-Policy",
                            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                            "script-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                            "connect-src 'self'")
    return resp


def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not session.get("user"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "auth"}), 401
            return redirect(url_for("login"))
        return f(*a, **k)
    return w


#: Ограничение подбора — ПО ИСТОЧНИКУ. Общий счётчик на процесс позволял
#: одному подбирающему блокировать вход настоящему аналитику.
_GUARD = websec.LoginGuard()


@app.route("/login", methods=["GET", "POST"])
def login():
    import hmac
    error = ""
    if request.method == "POST":
        wait = _GUARD.blocked_for()
        if wait:
            return _tpl("login.html").replace(
                "{{ERROR}}", f"Слишком много попыток — подождите {wait} с")
        # compare_digest на str требует ASCII: кириллица в поле роняла
        # вход с TypeError. Сравниваем байты.
        u_ok = hmac.compare_digest(request.form.get("username", "").encode("utf-8"),
                                   str(config.WEB_ADMIN_USER).encode("utf-8"))
        p_ok = hmac.compare_digest(request.form.get("password", "").encode("utf-8"),
                                   str(config.WEB_ADMIN_PASS).encode("utf-8"))
        if u_ok and p_ok:
            _GUARD.record_success()
            session.clear()          # новый идентификатор сессии после входа
            session["user"] = config.WEB_ADMIN_USER
            session.permanent = True
            return redirect(url_for("dashboard"))
        # Без блокирующего sleep: поток обработчика тут дороже, чем задержка
        # для подбирающего, — сервер многопоточный и без потолка числа потоков.
        _GUARD.record_failure()
        error = "Неверный логин или пароль"
    return _tpl("login.html").replace("{{ERROR}}", error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    return _tpl("dashboard.html")


@app.route("/api/status")
@login_required
def api_status():
    return jsonify(runner.status())


# --- Health: строка здоровья (GitLab / Ollama / Мир / события) -------------
_HEALTH_CACHE = {"ollama": None, "ollama_ts": 0.0, "ollama_reason": ""}


def _ollama_state():
    """(доступна, причина), кэш 30 с (сетевой вызов)."""
    now = time.time()
    if now - _HEALTH_CACHE["ollama_ts"] > 30:
        try:
            import llm_client
            ok, why, _m = llm_client.status()
            _HEALTH_CACHE["ollama"] = bool(ok)
            _HEALTH_CACHE["ollama_reason"] = why
        except Exception as e:
            _HEALTH_CACHE["ollama"] = False
            _HEALTH_CACHE["ollama_reason"] = f"проверка не выполнилась: {type(e).__name__}"
        _HEALTH_CACHE["ollama_ts"] = now
    return _HEALTH_CACHE["ollama"], _HEALTH_CACHE["ollama_reason"]


def _ollama_ok():
    return _ollama_state()[0]


@app.route("/api/gitlab/check", methods=["GET", "POST"])
@login_required
def api_gitlab_check():
    """Проверить связь с GitLab ПРЯМО СЕЙЧАС и назвать причину отказа.

    Отдельно от /api/health: health показывает состояние с момента запуска
    мира, а здесь связь проверяется заново — чтобы после «поднял ВМ» было
    видно результат, не перезапуская процесс.
    """
    from gitlab_client import GitLabClient
    gl = GitLabClient(config.GITLAB_URL, config.ADMIN_TOKEN, ssl_verify=config.gitlab_verify())
    d = gl.diagnose()
    runner.diag = d
    runner.conn_ok = bool(d.get("ok"))
    runner.conn_msg = d.get("reason") or "?"
    logging.getLogger("webapp").info("проверка связи с GitLab: %s", runner.conn_msg)
    return jsonify(d)


@app.route("/api/client-error", methods=["POST"])
@login_required
def api_client_error():
    """Приём ошибки, случившейся в браузере (см. console_app/system.py)."""
    import soclog as _sl
    d = request.get_json(silent=True) or {}
    rec = _sl.client_error(where=d.get("where", "?"), message=d.get("message", ""),
                           stack=d.get("stack", ""), url=d.get("url", ""),
                           ua=request.headers.get("User-Agent", ""), app="env")
    return jsonify({"ok": True, "ts": rec["ts"]})


@app.route("/api/diag/bundle")
@login_required
def api_diag_bundle():
    """ВСЯ диагностика одним JSON."""
    import soclog as _sl
    return jsonify(_sl.bundle("env"))


@app.route("/api/diag/bundle.json")
@login_required
def api_diag_bundle_file():
    import json as _j, soclog as _sl
    from flask import Response
    data = _j.dumps(_sl.bundle("env"), ensure_ascii=False, indent=2)
    return Response(data, mimetype="application/json",
                    headers={"Content-Disposition":
                             "attachment; filename=sentinel-diag-env.json"})


@app.route("/api/health")
@login_required
def api_health():
    import eventstore
    from agents.base import GITLAB_STATUS
    offline = bool(getattr(config, "OFFLINE_MODE", False))
    if offline:
        gl_state = "offline"
    elif runner.conn_ok is None:
        gl_state = "unknown"
    else:
        gl_state = "ok" if runner.conn_ok else "error"
    try:
        if not eventstore.enabled():
            eventstore.init()
    except Exception:
        logging.getLogger("webapp").error(
            "event-store недоступен: показатели журнала будут пустыми", exc_info=True)
    st = eventstore.stats()
    last = eventstore.last_event()
    age = None
    if last and last.get("ts"):
        try:
            age = max(0, int((datetime.now()
                              - datetime.fromisoformat(last["ts"])).total_seconds()))
        except Exception:
            age = None
    return jsonify({
        "gitlab": {"state": gl_state, "msg": runner.conn_msg,
                   # ПОДРОБНОСТИ ОТКАЗА уходят на экран целиком: раньше наверх
                   # доходило только «нет ответа /version», и по нему нельзя было
                   # понять, что чинить — адрес, токен, TLS или сеть.
                   "detail": (runner.diag or {}).get("detail", ""),
                   "status": (runner.diag or {}).get("status"),
                   "user": (runner.diag or {}).get("user"),
                   "url": config.GITLAB_URL,
                   "errors": GITLAB_STATUS["errors"], "ok_calls": GITLAB_STATUS["ok"],
                   "last_error": GITLAB_STATUS["last_error"]},
        "offline_mode": offline,
        "world": {"running": runner.running},
        "events": {"total": st.get("events", 0), "last": last, "last_age_s": age},
        "ollama": _ollama_state()[0],
        "ollama_reason": _ollama_state()[1],
        "ollama_model": getattr(config, "LLM", {}).get("model", ""),
    })


@app.route("/api/logs")
@login_required
def api_logs():
    since = websec.int_arg("since", 0, 0, 10 ** 9)
    return jsonify({"logs": runner.log.since(since)})


@app.route("/api/series")
@login_required
def api_series():
    return jsonify({"series": list(runner.series),
                    "scale": round(runner.scale if runner.running else config.compute_time_scale(), 2)})


@app.route("/api/actor")
@login_required
def api_actor():
    u = websec.bounded_str(request.args.get("u", ""), "u", 120)
    n = websec.int_arg("n", 80, 1, 500)
    return jsonify({"summary": events.actors_summary().get(u, {}),
                    "feed": events.actor_feed(u, n)})


@app.route("/api/events")
@login_required
def api_events():
    n = websec.int_arg("n", 120, 1, 600)
    return jsonify({"stats": events.stats(), "items": events.tail(n)})


@app.route("/api/insights")
@login_required
def api_insights():
    return jsonify(events.insights())


@app.route("/api/repos")
@login_required
def api_repos():
    return jsonify({"repos": events.repo_streams()})


#: Куда разрешено отдавать файлы. Второй рубеж к тому, что EVENT_LOG больше не
#: редактируется из веба: маршрут не должен доверять пути из конфигурации.
_DATA_DIR = os.path.realpath(os.path.join(BASE_DIR, "data"))


def _inside_data(path):
    try:
        rp = os.path.realpath(path)
    except OSError:
        return False
    return rp == _DATA_DIR or rp.startswith(_DATA_DIR + os.sep)


@app.route("/api/dataset")
@login_required
def api_dataset():
    """Выгрузка журнала событий.

    Путь берётся из конфигурации и ПРОВЕРЯЕТСЯ на принадлежность data/.
    Раньше проверки не было, а EVENT_LOG редактировался из веба, поэтому

        POST /api/config {"EVENT_LOG": {"file": "/etc/passwd"}}
        GET  /api/dataset

    отдавало любой файл, доступный процессу, — на машине, где рядом лежат
    .gitlab_token и .secret_key. Проверено экспериментально.
    """
    st = events.stats()
    f = st.get("file")
    if not f:
        return jsonify({"error": "нет файла журнала"}), 404
    if not _inside_data(f):
        logging.getLogger("webapp").error(
            "попытка отдать файл вне каталога данных",
            extra={"ctx": {"path": str(f)[:300], "разрешено": _DATA_DIR}})
        return jsonify({"error": "путь журнала вне каталога данных"}), 403
    if not os.path.exists(f):
        return jsonify({"error": "нет файла журнала"}), 404
    return send_file(f, as_attachment=True, download_name="events.jsonl")


@app.route("/api/runlog")
@login_required
def api_runlog():
    pth = runlog.path()
    if pth and os.path.exists(pth):
        return send_file(pth, as_attachment=True, download_name=os.path.basename(pth))
    return jsonify({"error": "нет файла лога (запустите симуляцию)"}), 404


@app.route("/api/tg_report", methods=["POST"])
@login_required
def api_tg_report():
    if not telegram.enabled():
        return jsonify({"ok": False, "msg": "Telegram не настроен"})
    import time as _t
    up = int(_t.time() - (runner.started_real or _t.time())) if runner.running else 0
    ok = telegram.send(report.build_report(runner.scheduler, title="Отчёт по запросу", uptime_s=up))
    return jsonify({"ok": ok, "msg": "отправлено в Telegram" if ok else "не удалось отправить"})


@app.route("/api/start", methods=["POST"])
@login_required
def api_start():
    ok, msg = runner.start()
    return jsonify({"ok": ok, "msg": msg})


@app.route("/api/stop", methods=["POST"])
@login_required
def api_stop():
    ok, msg = runner.stop()
    return jsonify({"ok": ok, "msg": msg})


@app.route("/api/config", methods=["GET", "POST"])
@login_required
def api_config():
    if request.method == "GET":
        # Секреты маскируются: раньше здесь открытым текстом уезжал админский
        # PAT GitLab (scope api — создание пользователей, impersonation-токенов,
        # чтение любого репозитория инстанса). Он попадал в DOM, в HAR и в
        # диагностическую выгрузку, которую продукт сам предлагает приложить.
        return jsonify(config.export_settings())
    data = request.get_json(force=True, silent=True) or {}
    rejected = config.apply_settings(data)
    config.save_settings()
    runner.apply_live()
    runner.logger.info("Параметры обновлены из админки",
                       extra={"ctx": {"ключей": len(data), "отвергнуто": rejected}})
    if rejected:
        return jsonify({"ok": False, "rejected": rejected,
                        "settings": config.export_settings()}), 400
    return jsonify({"ok": True, "settings": config.export_settings()})


@app.route("/api/reset_state", methods=["POST"])
@login_required
def api_reset_state():
    if (request.get_json(silent=True) or {}).get("confirm") != "RESET":
        return jsonify({"ok": False, "msg": "нужно подтверждение (введите RESET)"})
    if runner.running:
        return jsonify({"ok": False, "msg": "сначала останови симуляцию"})
    try:
        p = os.path.join(BASE_DIR, config.STATE_FILE)
        if os.path.exists(p):
            os.remove(p)
        return jsonify({"ok": True, "msg": "состояние сброшено"})
    except Exception as e:
        logging.getLogger("webapp").error("сброс состояния не удался",
                                          exc_info=True)
        return jsonify({"ok": False, "msg": str(e)})


@app.route("/api/reset_repos", methods=["POST"])
@login_required
def api_reset_repos():
    """Очистка контента репозиториев: закрыть MR, удалить ветки (кроме main),
    стереть файлы до README. Команда и сами проекты сохраняются."""
    if (request.get_json(silent=True) or {}).get("confirm") != "RESET":
        return jsonify({"ok": False, "msg": "нужно подтверждение (введите RESET)"})
    if runner.running:
        return jsonify({"ok": False, "msg": "сначала останови симуляцию"})
    try:
        gl = GitLabClient(config.GITLAB_URL, config.ADMIN_TOKEN, ssl_verify=config.gitlab_verify())
        repos = dict(config.PROJECTS)
        try:
            repos.update(gl.discover_projects(config.PROJECT_NAMESPACE) or {})
        except Exception:
            pass
        mr_n = br_n = fl_n = 0
        for name, pid in repos.items():
            for mr in gl.get_open_mrs(pid):
                iid = mr.get("iid")
                if iid and gl.close_mr(pid, iid):
                    mr_n += 1
            # Через клиент и СО ВСЕМИ страницами: здесь стоял свой запрос
            # в API мимо клиента, с per_page=100 и без листания, поэтому
            # чистка останавливалась на сотой ветке и всё равно
            # рапортовала об успешной полной очистке.
            for nm in gl.list_branches(pid):
                if nm not in ("main", "master") and gl.delete_branch(pid, nm):
                    br_n += 1
            victims = [f for f in gl.list_files(pid, "") if f.lower() != "readme.md"]
            if victims:
                actions = [{"action": "delete", "file_path": f} for f in victims]
                if gl.create_commit(pid, "main", "reset: wipe repository to README", actions):
                    fl_n += len(victims)
        # локальный стейт тоже сбрасываем — иначе ссылается на удалённые правила
        sp = os.path.join(BASE_DIR, config.STATE_FILE)
        if os.path.exists(sp):
            os.remove(sp)
        runner.logger.info(f"Сброс репозиториев: MR {mr_n}, веток {br_n}, файлов {fl_n}")
        return jsonify({"ok": True, "msg": f"очищено: MR {mr_n}, веток {br_n}, файлов {fl_n}. "
                        "Команда и репозитории сохранены."})
    except Exception as e:
        logging.getLogger("webapp").error("сброс репозиториев не удался",
                                          exc_info=True)
        return jsonify({"ok": False, "msg": str(e)})


@app.route("/api/fresh_start", methods=["POST"])
@login_required
def api_fresh_start():
    """ЕДИНАЯ КНОПКА «Чистый старт»: архивирует старые события, сбрасывает
    локальное состояние и (если не offline) чистит GitLab — за один клик.
    Старые данные не теряются: события уходят в data/archive/<timestamp>/."""
    if (request.get_json(silent=True) or {}).get("confirm") != "RESET":
        return jsonify({"ok": False, "msg": "нужно подтверждение (введите RESET)"})
    if runner.running:
        return jsonify({"ok": False, "msg": "сначала останови симуляцию"})
    steps = []
    ok_all = True

    # 1) Архив event-store (события/курсоры/алерты/статусы) — безопасно, с сохранением
    try:
        import eventstore
        try:
            eventstore.close()
        except Exception:
            pass
        import shutil
        data_dir = os.path.join(BASE_DIR, "data")
        movers = ["events.db", "events.db-wal", "events.db-shm", "events.jsonl"]
        present = [m for m in movers if os.path.exists(os.path.join(data_dir, m))]
        if present:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            dst = os.path.join(data_dir, "archive", ts)
            os.makedirs(dst, exist_ok=True)
            for m in present:
                shutil.move(os.path.join(data_dir, m), os.path.join(dst, m))
            steps.append(f"события заархивированы → data/archive/{ts}/ ({len(present)} файлов)")
        else:
            steps.append("event-store уже пуст")
    except Exception as e:
        ok_all = False
        steps.append(f"архив событий не удался: {e}")

    # 2) Сброс локального состояния (правила/спринты/ротации)
    try:
        sp = os.path.join(BASE_DIR, config.STATE_FILE)
        if os.path.exists(sp):
            os.remove(sp)
            steps.append("локальное состояние сброшено")
        else:
            steps.append("состояние уже чистое")
    except Exception as e:
        ok_all = False
        steps.append(f"сброс состояния не удался: {e}")

    # 3) Чистка GitLab — только если не offline и сервер доступен
    if getattr(config, "OFFLINE_MODE", False):
        steps.append("GitLab пропущен (offline-режим)")
    else:
        try:
            gl = GitLabClient(config.GITLAB_URL, config.ADMIN_TOKEN, ssl_verify=config.gitlab_verify())
            if not gl._api("GET", "/version"):
                steps.append("GitLab недоступен — пропущен")
            else:
                repos = dict(config.PROJECTS)
                try:
                    repos.update(gl.discover_projects(config.PROJECT_NAMESPACE) or {})
                except Exception:
                    pass
                mr_n = br_n = fl_n = 0
                for name, pid in repos.items():
                    for mr in gl.get_open_mrs(pid):
                        iid = mr.get("iid")
                        if iid and gl.close_mr(pid, iid):
                            mr_n += 1
                    # см. комментарий в api_reset_repos: листаем все страницы
                    for nm in gl.list_branches(pid):
                        if nm not in ("main", "master") and gl.delete_branch(pid, nm):
                            br_n += 1
                    victims = [f for f in gl.list_files(pid, "") if f.lower() != "readme.md"]
                    if victims:
                        actions = [{"action": "delete", "file_path": f} for f in victims]
                        if gl.create_commit(pid, "main", "reset: wipe repository to README", actions):
                            fl_n += len(victims)
                steps.append(f"GitLab очищен: MR {mr_n}, веток {br_n}, файлов {fl_n}")
        except Exception as e:
            ok_all = False
            steps.append(f"чистка GitLab не удалась: {e}")

    # 4) Пересоздать чистый event-store, чтобы консоль защиты сразу писала в него
    try:
        import eventstore
        eventstore.init()
        steps.append("новый чистый event-store готов")
    except Exception as e:
        steps.append(f"инициализация нового стора: {e}")

    runner.logger.info("Чистый старт: " + "; ".join(steps))
    return jsonify({"ok": ok_all, "msg": "Чистый старт выполнен.", "steps": steps})








def main():
    print("========================================================")
    print("  SOC Simulator — веб-панель")
    print(f"  Откройте: http://{config.WEB_HOST}:{config.WEB_PORT}")
    print(f"  Логин: {config.WEB_ADMIN_USER}")
    # Пароль печатаем ТОЛЬКО когда сгенерировали сами: заданный оператором
    # уезжал в журнал контейнера и в скриншот терминала без всякой нужды.
    if getattr(config, "WEB_PASS_IS_DEFAULT", False):
        print("  Пароль: admin  (дефолт стенда)")
        if config.WEB_HOST not in ("127.0.0.1", "localhost", "::1"):
            print("  ВНИМАНИЕ: дефолтный пароль и слушаем не петлю.")
            print("  Задайте SOC_ADMIN_PASS перед выносом наружу.")
    if getattr(config, "_WEB_PASS_GENERATED", False):
        print(f"  ПАРОЛЬ (сгенерирован): {config.WEB_ADMIN_PASS}")
        print("  (задайте свой: переменная окружения SOC_ADMIN_PASS)")
    if config.WEB_HOST not in ("127.0.0.1", "localhost", "::1"):
        print(f"  ВНИМАНИЕ: слушаем {config.WEB_HOST} — панель доступна из сети.")
    print("========================================================")
    app.run(host=config.WEB_HOST, port=config.WEB_PORT, threaded=True, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
