import os.path as _os_path
#!/usr/bin/env python3
"""
Веб-админка SOC-симулятора (красивый дашборд со слайдерами и пояснениями).

Запуск:  python webapp.py   (или run.bat)
Открыть: http://127.0.0.1:8787   (пароль печатается в консоли при старте,
свой задаётся переменной окружения SOC_ADMIN_PASS)
"""
import os
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
    _TPL_CACHE[name] = (mtime, text)
    return text
import simclock
import events
import runlog
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


class _FakeGL:
    """Заглушка GitLab для OFFLINE-режима: любые вызовы безопасны и мгновенны.
    Мир пишет события локально, реальный GitLab не дёргается."""
    import random as _r

    def __getattr__(self, name):
        def f(*a, **k):
            if name in ("create_mr", "create_issue"):
                return _FakeGL._r.randint(100, 9999)
            if name in ("get_open_mrs", "list_files", "discover_projects", "get_project_members"):
                return []
            if name in ("get_mr",):
                return {}
            if name in ("get_or_create_user_token", "create_named_token"):
                return "offline-token"
            if name in ("_api", "group_id", "get_project_id"):
                return None
            return True
        return f


class Runner:
    def __init__(self):
        self.thread = None
        self.running = False
        self.stop_flag = False
        self.gl = None
        self.state = None
        self.agents = None
        self.scheduler = None
        self.clock = None
        self.scale = 1.0
        self.started_real = None
        self.conn_ok = None
        self.conn_msg = ""
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
        # дублируем важные логи в stdout — чтобы они были видны в панели «Логи · Мир»
        if not any(getattr(h, "_soc_stdout", False) for h in root.handlers):
            import sys as _sys
            _sh = logging.StreamHandler(_sys.stdout)
            _sh.setLevel(logging.INFO)
            _sh.setFormatter(logging.Formatter("%(asctime)s %(levelname).1s %(name)s: %(message)s",
                                               "%H:%M:%S"))
            _sh._soc_stdout = True
            root.addHandler(_sh)
        try:
            from logging.handlers import RotatingFileHandler
            fh = RotatingFileHandler(os.path.join(BASE_DIR, config.LOG_FILE),
                                     maxBytes=10 * 1024 * 1024, backupCount=5,
                                     encoding="utf-8")
            fh.setFormatter(logging.Formatter(
                "%(asctime)s %(levelname)-7s %(message)s", "%Y-%m-%d %H:%M:%S"))
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
        self.gl = GitLabClient(config.GITLAB_URL, config.ADMIN_TOKEN, ssl_verify=False)
        if getattr(config, "OFFLINE_MODE", False):
            self.conn_ok = False
            self.conn_msg = "offline (включён вручную)"
        else:
            self.logger.info(f"Подключение к GitLab {config.GITLAB_URL} ...")
            try:
                v = self.gl._api("GET", "/version")
                if v:
                    self.conn_ok = True
                    self.conn_msg = f"GitLab {v.get('version', '?')}"
                    self.logger.info(f"GitLab OK: {self.conn_msg}")
                else:
                    self.conn_ok = False
                    self.conn_msg = "нет ответа /version (проверь URL/токен)"
                    self.logger.warning(self.conn_msg)
            except Exception as e:
                self.conn_ok = False
                self.conn_msg = f"ошибка: {e}"
                self.logger.warning(self.conn_msg)
        # Авто-offline: если GitLab недоступен (или включён вручную) — переходим в
        # offline (подменяем клиент на заглушку), чтобы мир не висел и НЕ молчал.
        if getattr(config, "OFFLINE_MODE", False) or not self.conn_ok:
            config.OFFLINE_MODE = True
            self.offline = True
            self.gl = _FakeGL()
            self.logger.warning("РЕЖИМ OFFLINE: события пишутся локально, GitLab не вызывается. "
                                + ("(включён вручную)" if self.conn_msg.startswith("offline") else "(GitLab недоступен)"))
        else:
            config.OFFLINE_MODE = False
            self.offline = False
        if not config.OFFLINE_MODE:
            try:
                import bootstrap
                self.logger.info("Инициализация среды (репозитории, сотрудники, права)...")
                bootstrap.ensure_environment(self.gl)
            except Exception as e:
                self.logger.warning(f"bootstrap не удался: {e}")
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
        if self.running:
            return False, "уже запущена"
        try:
            self._build()
        except Exception as e:
            self.logger.exception(f"Не удалось инициализировать: {e}")
            return False, str(e)
        self.stop_flag = False
        self.running = True
        self.started_real = time.time()
        self.series.clear()
        self._last_runs = 0
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        self._sampler_thread = threading.Thread(target=self._sampler, daemon=True)
        self._sampler_thread.start()
        if config.TELEGRAM.get('send_start_stop'):
            telegram.send_async(f'▶️ SOC-симулятор запущен (web) · scale x{self.scale:.0f}')
        self._report_thread = threading.Thread(target=self._reporter, daemon=True)
        self._report_thread.start()
        return True, "запущена"

    def stop(self):
        if not self.running:
            return False, "не запущена"
        self.stop_flag = True
        if self.state:
            try:
                self.state.save()
            except Exception:
                pass
        try:
            if config.TELEGRAM.get("send_start_stop"):
                telegram.send_async(report.build_report(self.scheduler, title="SOC-симулятор остановлен"))
        except Exception:
            pass
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
                telegram.send(report.build_report(self.scheduler, uptime_s=up))
            except Exception:
                pass

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

app = Flask(__name__)
app.secret_key = config.WEB_SECRET
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")


@app.errorhandler(Exception)
def _unhandled(e):
    """Любая необработанная ошибка — в errors.log с полным трейсбеком."""
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return e
    logging.getLogger("webapp").error(
        "необработанная ошибка в маршруте %s %s",
        request.method, request.path, exc_info=True,
        extra={"ctx": {"path": request.path, "method": request.method}})
    return jsonify({"error": "internal", "detail": str(e)[:300]}), 500


@app.after_request
def _sec_headers(resp):
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


_LOGIN_FAILS = {"n": 0, "until": 0.0}


@app.route("/login", methods=["GET", "POST"])
def login():
    import hmac
    error = ""
    if request.method == "POST":
        now = time.time()
        if now < _LOGIN_FAILS["until"]:
            return _tpl("login.html").replace("{{ERROR}}", "Слишком много попыток — подождите немного")
        u_ok = hmac.compare_digest(request.form.get("username", ""), config.WEB_ADMIN_USER)
        p_ok = hmac.compare_digest(request.form.get("password", ""), config.WEB_ADMIN_PASS)
        if u_ok and p_ok:
            _LOGIN_FAILS["n"] = 0
            session["user"] = config.WEB_ADMIN_USER
            session.permanent = True
            return redirect(url_for("dashboard"))
        _LOGIN_FAILS["n"] += 1
        if _LOGIN_FAILS["n"] >= 5:
            _LOGIN_FAILS["until"] = now + 15
            _LOGIN_FAILS["n"] = 0
        time.sleep(0.5)
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
_HEALTH_CACHE = {"ollama": None, "ollama_ts": 0.0}


def _ollama_ok():
    """Доступность Ollama, кэш 30 с (сетевой вызов)."""
    now = time.time()
    if now - _HEALTH_CACHE["ollama_ts"] > 30:
        try:
            import llm_client
            _HEALTH_CACHE["ollama"] = bool(llm_client.available())
        except Exception:
            _HEALTH_CACHE["ollama"] = False
        _HEALTH_CACHE["ollama_ts"] = now
    return _HEALTH_CACHE["ollama"]


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
                   "errors": GITLAB_STATUS["errors"], "ok_calls": GITLAB_STATUS["ok"],
                   "last_error": GITLAB_STATUS["last_error"]},
        "offline_mode": offline,
        "world": {"running": runner.running},
        "events": {"total": st.get("events", 0), "last": last, "last_age_s": age},
        "ollama": _ollama_ok(),
    })


@app.route("/api/logs")
@login_required
def api_logs():
    since = int(request.args.get("since", 0))
    return jsonify({"logs": runner.log.since(since)})


@app.route("/api/series")
@login_required
def api_series():
    return jsonify({"series": list(runner.series),
                    "scale": round(runner.scale if runner.running else config.compute_time_scale(), 2)})


@app.route("/api/actor")
@login_required
def api_actor():
    u = request.args.get("u", "")
    n = int(request.args.get("n", 80))
    return jsonify({"summary": events.actors_summary().get(u, {}),
                    "feed": events.actor_feed(u, n)})


@app.route("/api/events")
@login_required
def api_events():
    n = int(request.args.get("n", 120))
    return jsonify({"stats": events.stats(), "items": events.tail(n)})


@app.route("/api/insights")
@login_required
def api_insights():
    return jsonify(events.insights())


@app.route("/api/repos")
@login_required
def api_repos():
    return jsonify({"repos": events.repo_streams()})


@app.route("/api/dataset")
@login_required
def api_dataset():
    st = events.stats()
    f = st.get("file")
    if f and os.path.exists(f):
        return send_file(f, as_attachment=True, download_name="events.jsonl")
    return jsonify({"error": "нет файла журнала"}), 404


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
        return jsonify(config.export_settings())
    data = request.get_json(force=True, silent=True) or {}
    config.apply_settings(data)
    config.save_settings()
    runner.apply_live()
    runner.logger.info("Параметры обновлены из админки")
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
        gl = GitLabClient(config.GITLAB_URL, config.ADMIN_TOKEN, ssl_verify=False)
        repos = dict(config.PROJECTS)
        try:
            repos.update(gl.discover_projects(config.PROJECT_NAMESPACE) or {})
        except Exception:
            pass
        H = {"PRIVATE-TOKEN": config.ADMIN_TOKEN}
        mr_n = br_n = fl_n = 0
        for name, pid in repos.items():
            for mr in gl.get_open_mrs(pid):
                iid = mr.get("iid")
                if iid and gl.close_mr(pid, iid):
                    mr_n += 1
            try:
                r = gl.session.get(f"{gl.url}/api/v4/projects/{pid}/repository/branches",
                                   params={"per_page": 100}, headers=H, timeout=20)
                branches = r.json() if r.status_code == 200 else []
            except Exception:
                branches = []
            for b in branches:
                nm = b.get("name")
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
            gl = GitLabClient(config.GITLAB_URL, config.ADMIN_TOKEN, ssl_verify=False)
            if not gl._api("GET", "/version"):
                steps.append("GitLab недоступен — пропущен")
            else:
                repos = dict(config.PROJECTS)
                try:
                    repos.update(gl.discover_projects(config.PROJECT_NAMESPACE) or {})
                except Exception:
                    pass
                H = {"PRIVATE-TOKEN": config.ADMIN_TOKEN}
                mr_n = br_n = fl_n = 0
                for name, pid in repos.items():
                    for mr in gl.get_open_mrs(pid):
                        iid = mr.get("iid")
                        if iid and gl.close_mr(pid, iid):
                            mr_n += 1
                    try:
                        r = gl.session.get(f"{gl.url}/api/v4/projects/{pid}/repository/branches",
                                           params={"per_page": 100}, headers=H, timeout=20)
                        branches = r.json() if r.status_code == 200 else []
                    except Exception:
                        branches = []
                    for b in branches:
                        nm = b.get("name")
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
    if getattr(config, "_WEB_PASS_GENERATED", False):
        print(f"  Логин: {config.WEB_ADMIN_USER}  ·  ПАРОЛЬ (сгенерирован): {config.WEB_ADMIN_PASS}")
        print("  (задайте свой: переменная окружения SOC_ADMIN_PASS)")
    else:
        print(f"  Логин/пароль: {config.WEB_ADMIN_USER} / {config.WEB_ADMIN_PASS}")
    print("========================================================")
    app.run(host=config.WEB_HOST, port=config.WEB_PORT, threaded=True, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
