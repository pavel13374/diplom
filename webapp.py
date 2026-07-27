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
        with self._lock:
            self._id += 1
            self.buf.append({"id": self._id,
                             "t": datetime.now().strftime("%H:%M:%S"),
                             "level": record.levelname, "msg": msg})

    def since(self, last_id):
        with self._lock:
            return [e for e in self.buf if e["id"] > last_id]


def _gitlab_status():
    try:
        from agents.base import GITLAB_STATUS
        return {"errors": GITLAB_STATUS.get("errors", 0), "ok": GITLAB_STATUS.get("ok", 0),
                "last_error": GITLAB_STATUS.get("last_error", ""),
                "last_error_ts": GITLAB_STATUS.get("last_error_ts")}
    except Exception:
        return {"errors": 0, "ok": 0, "last_error": "", "last_error_ts": None}


def _last_event_ago():
    try:
        lr = events.stats().get("last_real")
        if not lr:
            return None
        return int(time.time() - lr)
    except Exception:
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
            pass
        try:
            runlog.setup(BASE_DIR)
        except Exception:
            pass
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
            return LOGIN_HTML.replace("{{ERROR}}", "Слишком много попыток — подождите немного")
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
    return LOGIN_HTML.replace("{{ERROR}}", error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    return DASH_HTML


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
                        f"Команда и репозитории сохранены."})
    except Exception as e:
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


LOGIN_HTML = """<!doctype html><html lang=ru><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>Вход</title>
<style>

*{box-sizing:border-box}
body{margin:0;font-family:'Inter',-apple-system,Segoe UI,Roboto,sans-serif;
 background:var(--surface-3);color:var(--ink);display:flex;min-height:100vh;align-items:center;justify-content:center}
.wrap{display:flex;width:760px;max-width:94vw;background:#fff;border-radius:20px;overflow:hidden;
 box-shadow:0 24px 70px rgba(27,31,42,.18);border:1px solid var(--line)}
.left{flex:1;padding:46px 40px;background:linear-gradient(160deg,var(--info),var(--info));color:#fff;display:flex;flex-direction:column;justify-content:center}
.left .logo{font-weight:800;font-size:22px;letter-spacing:.3px}
.left .tag{margin-top:14px;color:var(--info);font-size:14px;line-height:1.6}
.left ul{margin:22px 0 0;padding:0;list-style:none;color:var(--info);font-size:13px}
.left li{margin:9px 0;padding-left:22px;position:relative}
.left li:before{content:'';position:absolute;left:0;top:6px;width:8px;height:8px;border-radius:50%;background:var(--info)}
.right{flex:1;padding:46px 40px;display:flex;flex-direction:column;justify-content:center}
h1{font-size:21px;margin:0 0 6px}.sub{color:var(--muted);font-size:13px;margin:0 0 26px}
label{display:block;font-size:12px;color:var(--muted);margin:16px 0 7px;font-weight:600}
input{width:100%;padding:12px 13px;border-radius:11px;border:1px solid var(--line);background:var(--info-bg);font-size:14px}
input:focus{outline:none;border-color:var(--accent);background:#fff;box-shadow:0 0 0 4px #5b5bd61f}
button{width:100%;margin-top:26px;padding:13px;border:0;border-radius:11px;background:var(--accent);color:#fff;
 font-size:15px;font-weight:700;cursor:pointer;transition:.15s}button:hover{background:var(--info)}
.err{color:var(--critical);font-size:13px;margin-top:14px;min-height:18px;text-align:center}
.hint{margin-top:16px;text-align:center;color:var(--text-3);font-size:12px}
@media(max-width:680px){.left{display:none}}
</style><link rel="stylesheet" href="/static/design-system.css"><script src="/static/i18n.js" defer></script><script src="/static/ui.js" defer></script><link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='0.9em' font-size='90'>🌐</text></svg>"></head><body>
<div class=wrap>
 <div class=left>
   <div class=logo>Sentinel Env</div>
   <div class=tag>Рабочий день SOC-команды в GitLab:<br>коммиты, ревью, инциденты — и скрытые атаки.</div>
   <ul><li>Живая команда и её расписание</li><li>Полный журнал событий</li><li>Детект и разбор — на консоли защиты</li></ul>
 </div>
 <form class=right method=post>
   <h1>Вход в панель</h1><div class=sub>Авторизуйтесь для управления симуляцией</div>
   <label>Логин</label><input name=username autofocus autocomplete=off>
   <label>Пароль</label><input name=password type=password>
   <button type=submit>Войти</button>
   <div class=err>{{ERROR}}</div>
   <div class=hint>пароль печатается в консоли при старте (или задан через SOC_ADMIN_PASS)</div>
 </form>
</div></body></html>"""


DASH_HTML = r"""<!doctype html><html lang=ru><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>Sentinel Env — Team &amp; GitLab</title>
<style>

*{box-sizing:border-box}
body{margin:0;color:var(--ink);
 background:radial-gradient(900px 420px at 88% -12%,#e0e7ff70,transparent 60%),
            radial-gradient(760px 380px at -8% 34%,#ccfbf14d,transparent 55%),var(--bg);
 font-family:'Inter',-apple-system,Segoe UI,Roboto,sans-serif;font-size:14px}
.app{display:grid;min-height:100vh}
/* sidebar */
.side{background:linear-gradient(176deg,var(--info),var(--info));color:var(--info);display:flex;flex-direction:column;padding:20px 16px;position:sticky;top:0;height:100vh}
.brand{display:flex;align-items:center;gap:10px;font-weight:800;font-size:17px;color:#fff;padding:6px 8px 18px}
.brand .mk{width:30px;height:30px;border-radius:9px;background:linear-gradient(135deg,var(--info),var(--info));display:flex;align-items:center;justify-content:center;font-size:16px}
.nav{display:flex;flex-direction:column;gap:4px;margin-top:6px}
.nav a{display:flex;align-items:center;gap:11px;padding:11px 12px;border-radius:10px;color:var(--info);
 text-decoration:none;font-weight:600;font-size:13.5px;cursor:pointer;transition:.15s}
.nav a svg{width:18px;height:18px;opacity:.85}
.nav a:hover{background:#ffffff14;color:#fff}
.nav a.active{background:#ffffff1f;color:#fff}
.nav a.active svg{opacity:1}
.side-foot{margin-top:auto;border-top:1px solid #ffffff1f;padding-top:14px;font-size:12px;color:var(--info)}
.side-foot .st{display:flex;align-items:center;gap:8px;margin-bottom:10px}
.side-foot a{color:var(--info);text-decoration:none}.side-foot a:hover{color:#fff}
.run-dot{width:9px;height:9px;border-radius:50%;background:var(--text-3)}.run-dot.on{background:var(--success);box-shadow:0 0 0 4px #34d39933}
/* main */
.main{padding:0}
.topbar{position:sticky;top:0;z-index:10;background:#f4f5fbf2;backdrop-filter:blur(8px);
 border-bottom:1px solid var(--line);display:flex;align-items:center;gap:14px;padding:16px 28px}
.topbar h1{font-size:18px;margin:0;font-weight:700}
.grow{flex:1}
.pill{display:inline-flex;align-items:center;gap:7px;padding:5px 11px;border-radius:20px;font-size:12px;font-weight:600;border:1px solid var(--line);background:#fff}
.pill .d{width:7px;height:7px;border-radius:50%;background:var(--text-3)}
.pill.ok .d{background:var(--ok)}.pill.bad .d{background:var(--bad)}
.pill.warn{background:var(--warning-bg);border-color:var(--warning-border);color:var(--warning)}.pill.warn .d{background:var(--warn)}
.pill.ok .d{animation:hpulse 2s ease infinite}
@keyframes hpulse{0%,100%{opacity:1}50%{opacity:.45}}
.pill b{font-weight:700}
.banner{display:flex;align-items:center;flex-wrap:wrap;margin:14px 28px -8px;padding:11px 16px;border-radius:12px;
 background:linear-gradient(90deg,var(--warning-bg),var(--warning-bg));border:1px solid var(--warning-border);color:var(--warning);font-size:13px;
 box-shadow:var(--shadow);animation:bslide .3s ease}
.banner .bsub{color:var(--warning);font-size:12px}
@keyframes bslide{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
.ctx{display:flex;align-items:center;flex-wrap:wrap;gap:6px;margin:14px 28px -10px;padding:9px 15px;border-radius:11px;
 background:linear-gradient(90deg,var(--accent-bg),var(--info-bg));border:1px solid var(--accent-border);color:var(--accent-brand);font-size:12.5px;box-shadow:var(--shadow)}
.ctx a{color:var(--accent-brand);font-weight:700}
.ctx .x{margin-left:auto;cursor:pointer;color:var(--accent-brand);font-weight:800;padding:0 5px;border-radius:6px}
.ctx .x:hover{background:#4f46e522}
.pill.work{background:var(--accent-bg);border-color:var(--accent-border);color:var(--accent-brand)}.pill.work .d{background:var(--accent-brand)}
.pill.rest{background:var(--warning-bg);border-color:var(--warning-border);color:var(--warning)}.pill.rest .d{background:var(--warning)}
.btn{padding:9px 15px;border:1px solid var(--line);border-radius:10px;background:#fff;color:var(--ink);
 font-size:13px;font-weight:600;cursor:pointer;transition:.15s}
.btn:hover{border-color:var(--info-border)}
.btn.primary{background:linear-gradient(135deg,var(--info),var(--info));border-color:transparent;color:#fff;box-shadow:0 2px 8px #5b5bd644;transition:all .16s ease}
.btn.primary:hover{transform:translateY(-1px);box-shadow:0 4px 14px #5b5bd655;filter:brightness(1.04)}
.btn.danger{background:#fff;border-color:var(--critical-border);color:var(--bad)}.btn.danger:hover{background:var(--critical-bg)}
.dangerzone{border:1px solid var(--critical-border)!important;background:linear-gradient(180deg,var(--critical-bg),var(--critical-bg))!important}
.freshbox{display:flex;align-items:center;gap:16px;flex-wrap:wrap;background:#fff;border:1px solid var(--critical-border);border-radius:12px;padding:14px 16px}
.freshbox .btn.danger{background:linear-gradient(135deg,var(--critical),var(--critical));color:#fff;border-color:transparent;box-shadow:0 2px 8px #dc262644;white-space:nowrap}
.freshbox .btn.danger:hover{filter:brightness(1.06);transform:translateY(-1px)}
.dangerzone h2:before{background:linear-gradient(180deg,var(--critical),var(--critical))!important}
.content{padding:24px 28px 60px;max-width:1180px}
.view{display:none}.view.active{display:block;animation:vfade .3s ease}
@keyframes vfade{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.section-title{font-size:11px;font-weight:500;color:var(--soft);letter-spacing:.02em;margin:26px 2px 12px}
.sevdot{width:10px;height:10px;border-radius:50%;display:inline-block;margin-right:5px;vertical-align:middle}
.hmcell{width:17px;height:17px;border-radius:3px;display:inline-block}
.hmrow{display:flex;gap:2px;align-items:center;margin-bottom:2px}
.hmlab{width:34px;font-size:11px;color:var(--text-3);text-align:right;padding-right:6px}
.arnode{font-size:12px;fill:var(--line-strong)}
.repogrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(330px,100%),1fr));gap:16px}
.repocard{background:#fff;border:1px solid var(--line,var(--info-border));border-radius:16px;padding:16px 16px 14px;
  box-shadow:0 6px 20px rgba(27,31,42,.05);display:flex;flex-direction:column;min-height:300px}
.repocard.hot{box-shadow:0 0 0 2px var(--critical-border),0 6px 20px rgba(220,38,38,.12)}
.rc-head{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.rc-ava{width:34px;height:34px;border-radius:9px;display:flex;align-items:center;justify-content:center;
  color:#fff;font-weight:800;font-size:15px;flex:0 0 auto}
.rc-name{font-weight:700;font-size:14px;color:var(--surface-3)}
.rc-sub{font-size:11px;color:var(--text-3)}
.rc-stats{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px}
.rc-stat{font-size:11px;color:var(--line-strong);background:var(--info-bg);border-radius:7px;padding:3px 8px}
.rc-stat b{color:var(--surface-3)}
.rc-coltitle{font-size:11px;font-weight:500;letter-spacing:.02em;color:var(--text-3);margin:8px 0 5px}
.mritem{display:flex;align-items:center;gap:7px;font-size:12px;padding:5px 8px;border-radius:8px;
  background:var(--accent-bg);border:1px solid var(--info-border);margin-bottom:5px;animation:popin .35s ease}
.mritem .iid{font-family:ui-monospace,monospace;color:var(--accent-brand);font-weight:700}
.mritem.anom{background:var(--critical-bg);border-color:var(--critical-border)}
.rc-feed{display:flex;flex-direction:column;gap:4px;max-height:190px;overflow:hidden}
.fchip{display:flex;align-items:center;gap:7px;font-size:11.5px;padding:4px 8px;border-radius:7px;
  background:var(--info-bg);animation:slidein .4s ease}
.fchip .ic{width:16px;height:16px;border-radius:5px;flex:0 0 auto;display:flex;align-items:center;
  justify-content:center;font-size:10px;color:#fff;font-weight:700}
.fchip .txt{flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--line-strong)}
.fchip .who{color:var(--text-3);font-size:10px}
.fchip.anom{background:var(--critical-bg);outline:1px solid var(--critical-border)}
.ic-push{background:var(--success)}.ic-open{background:var(--accent-brand)}.ic-merge{background:var(--accent-brand)}
.ic-close{background:var(--critical)}.ic-branch{background:var(--info)}.ic-cmt{background:var(--info)}.ic-other{background:var(--info-bg);color:var(--info)}
@keyframes slidein{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
@keyframes popin{from{opacity:0;transform:scale(.96)}to{opacity:1;transform:none}}
.rc-tree{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px;line-height:1.5;
  max-height:170px;overflow:auto;background:var(--info-bg);border:1px solid var(--surface-3);border-radius:9px;padding:8px 10px}
.tfolder{color:var(--text-3);margin-top:3px}
.tfolder:first-child{margin-top:0}
.tfile{color:var(--line-strong);padding-left:14px;display:flex;align-items:center;gap:6px}
.tfile:before{content:'📄';font-size:10px}
.tfile.new{color:var(--success);animation:popin .4s ease}
.tfile.new:before{content:'🟢'}
.tfile.del{color:var(--critical);text-decoration:line-through;opacity:.55;animation:fadedel 1s ease}
.tfile.del:before{content:'🗑'}
@keyframes fadedel{from{opacity:1;background:var(--critical-bg)}to{opacity:.55;background:transparent}}
.tempty{color:var(--text-3)}
/* cards */
.clocks{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}
.clock{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:18px 20px;box-shadow:var(--shadow);
 transition:transform .18s ease,box-shadow .18s ease}
.clock:hover{transform:translateY(-2px);box-shadow:0 2px 4px rgba(16,24,40,.06),0 14px 34px rgba(91,91,214,.12)}
.clock .lab{font-size:12px;color:var(--muted);font-weight:600;display:flex;align-items:center;gap:8px}
.clock .lab .ic{width:26px;height:26px;border-radius:8px;display:flex;align-items:center;justify-content:center;background:var(--accent-soft);color:var(--accent)}
.clock .val{font-size:24px;font-weight:800;margin-top:12px;font-variant-numeric:tabular-nums;letter-spacing:.2px}
.clock .sub{font-size:12px;color:var(--soft);margin-top:4px}
.clock.sim{background:var(--info-bg);border:1px solid var(--info-border)}
.clock.sim .lab{color:var(--muted)}.clock.sim .lab .ic{background:var(--accent-soft);color:var(--accent)}
.clock.sim .val{color:var(--ink)}.clock.sim .sub{color:var(--soft)}
.kpis{display:grid;grid-template-columns:repeat(6,1fr);gap:14px;margin-top:16px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px;box-shadow:var(--shadow)}
.kpi .n{font-size:24px;font-weight:800;font-variant-numeric:tabular-nums}
.kpi .l{font-size:11.5px;color:var(--muted);margin-top:3px;font-weight:600}
.steps{display:grid;grid-template-columns:1fr 1fr;gap:10px 18px}
.step{display:flex;gap:10px;align-items:flex-start}
.obck{width:22px;height:22px;border-radius:50%;border:2px solid var(--line);display:flex;align-items:center;justify-content:center;font-weight:800;color:var(--success);flex:0 0 auto;font-size:12px}
.obck.on{background:var(--success-bg);border-color:var(--success)}
.obh{font-size:11.5px;color:var(--muted);margin-top:2px}
.step a{color:var(--accent);font-size:11.5px;text-decoration:none}
.insL{display:flex;gap:8px;flex-wrap:wrap;margin-top:4px}
.insL .i{background:var(--accent-bg);border:1px solid var(--info-border);color:var(--info);border-radius:8px;padding:4px 10px;font-size:12px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:16px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:20px;box-shadow:var(--shadow)}
.panel>h2{font-size:15px;margin:0 0 3px;font-weight:700}
.panel>.sub{font-size:12.5px;color:var(--muted);margin:0 0 16px;line-height:1.5}
.kv{display:grid;grid-template-columns:auto 1fr;gap:11px 16px;font-size:13.5px}
.kv b{color:var(--muted);font-weight:500}.kv span{text-align:right;font-weight:600}
.members{display:flex;flex-direction:column;gap:9px}
.member{display:flex;align-items:center;gap:12px;padding:9px 11px;border:1px solid var(--line);border-radius:11px}
.avatar{width:36px;height:36px;border-radius:10px;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700;font-size:13px;flex:none}
.m-name{font-weight:700}.m-role{font-size:12px;color:var(--muted)}
.badge{margin-left:auto;font-size:11px;font-weight:700;padding:3px 9px;border-radius:20px}
.badge.oc{background:var(--accent-bg);color:var(--accent-brand)}.badge.pt{background:var(--warning-bg);color:var(--warning)}
.badge.wk{background:var(--success-bg);color:var(--success)}
.acts{display:flex;flex-direction:column;gap:8px}
.act{display:grid;grid-template-columns:1fr auto;gap:4px;font-size:13px}
.act .bar{grid-column:1/3;height:6px;border-radius:6px;background:var(--surface-3);overflow:hidden}
.act .bar i{display:block;height:100%;background:linear-gradient(90deg,var(--info),var(--info));border-radius:6px}
.banner{margin-top:16px;background:#fff;border:1px solid var(--line);border-left:3px solid var(--accent);
 border-radius:12px;padding:14px 16px;font-size:13px;color:var(--line-strong);line-height:1.6;box-shadow:var(--shadow)}
.banner code{background:var(--info-bg);padding:1px 6px;border-radius:5px;font-size:12px}
/* config */
.cfg-intro{font-size:13.5px;color:var(--muted);margin:2px 2px 18px;line-height:1.6;max-width:780px}
.group{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);margin-bottom:16px;overflow:hidden}
.group>summary{list-style:none;cursor:pointer;padding:16px 20px;display:flex;align-items:center;gap:12px}
.group>summary::-webkit-details-marker{display:none}
.group .g-ic{width:34px;height:34px;border-radius:10px;background:var(--accent-soft);color:var(--accent);display:flex;align-items:center;justify-content:center;flex:none}
.group .g-tt{font-weight:700;font-size:15px}.group .g-sub{font-size:12.5px;color:var(--muted);margin-top:2px}
.group .g-chev{margin-left:auto;color:var(--soft);transition:.2s}.group[open] .g-chev{transform:rotate(180deg)}
.group .body{padding:6px 20px 22px;border-top:1px solid var(--line)}
.fields{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:20px 26px;margin-top:16px}
.field{display:flex;flex-direction:column;gap:7px}
.field .top{display:flex;justify-content:space-between;align-items:baseline}
.field label{font-size:13px;font-weight:700;color:var(--ink)}
.field .val{font-size:13px;font-weight:800;color:var(--accent);font-variant-numeric:tabular-nums;
 background:var(--accent-soft);padding:1px 9px;border-radius:7px}
.field .help{font-size:12px;color:var(--muted);line-height:1.5}
input[type=range]{accent-color:var(--accent);width:100%;height:6px;cursor:pointer}
.tin,select{padding:10px 12px;border:1px solid var(--line);border-radius:10px;background:var(--info-bg);font-size:13px;width:100%;color:var(--ink)}
.tin:focus,select:focus{outline:none;border-color:var(--accent);background:#fff;box-shadow:0 0 0 4px #5b5bd61a}
.switch-field{flex-direction:row;align-items:center;justify-content:space-between;gap:14px}
.sw-txt label{display:block}.sw-txt .help{margin-top:3px}
.switch{position:relative;width:46px;height:26px;flex:none}
.switch input{opacity:0;width:0;height:0}
.track{position:absolute;inset:0;background:var(--info-bg);border-radius:30px;transition:.2s}
.track:before{content:'';position:absolute;width:20px;height:20px;left:3px;top:3px;background:#fff;border-radius:50%;transition:.2s;box-shadow:0 1px 3px rgba(0,0,0,.2)}
.switch input:checked+.track{background:var(--accent)}
.switch input:checked+.track:before{transform:translateX(20px)}
.days{display:flex;gap:7px;flex-wrap:wrap}
.day{padding:8px 13px;border:1px solid var(--line);border-radius:9px;cursor:pointer;font-size:13px;font-weight:600;user-select:none;color:var(--muted)}
.day input{display:none}.day.act{background:var(--accent);border-color:var(--accent);color:#fff}
.presets{display:flex;gap:9px;flex-wrap:wrap;margin:4px 0 4px}
.chip{padding:8px 14px;border:1px solid var(--line);border-radius:20px;background:#fff;font-size:12.5px;font-weight:600;cursor:pointer;transition:.15s}
.chip:hover{border-color:var(--accent);color:var(--accent)}
.tlinfo{background:var(--info-bg);border:1px dashed var(--info-border);border-radius:11px;padding:12px 14px;font-size:13px;color:var(--line-strong);margin:14px 0 4px}
.savebar{position:sticky;bottom:0;display:flex;gap:14px;align-items:center;background:#f4f5fbf2;backdrop-filter:blur(6px);
 border-top:1px solid var(--line);padding:14px 2px;margin-top:8px}
.toast{color:var(--ok);font-size:13px;font-weight:600}
.people{display:grid;grid-template-columns:repeat(auto-fill,minmax(440px,1fr));gap:16px}
.pcard{background:var(--panel);border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow);overflow:hidden}
.phead{display:flex;align-items:center;gap:12px;padding:14px 16px;cursor:pointer}
.phead:hover{background:var(--info-bg)}
.pinfo{flex:1}.pinfo .m-name{font-weight:700}.pinfo .m-role{font-size:12px;color:var(--muted)}
.pmeta{display:flex;gap:10px;font-size:12px;color:var(--muted);font-variant-numeric:tabular-nums}
.pmeta b{color:var(--ink)}
.pchev{color:var(--soft);transition:.2s}.pcard.open .pchev{transform:rotate(180deg)}
.pbody{display:none;border-top:1px solid var(--line);padding:12px 16px;background:var(--info-bg)}
.pcard.open .pbody{display:block}
.pcur{font-size:13px;margin-bottom:10px;color:var(--line-strong)}
.feed{display:flex;flex-direction:column;gap:3px;max-height:320px;overflow:auto;font-size:12px}
.frow{display:grid;grid-template-columns:44px 92px 120px 1fr auto;gap:8px;align-items:center;padding:5px 8px;border-radius:7px;background:#fff;border:1px solid var(--line)}
.frow.anom{background:var(--critical-bg);border-color:var(--critical-border)}.frow.look{background:var(--warning-bg);border-color:var(--warning-border)}
.frow .mono{font-family:'JetBrains Mono',Consolas,monospace;color:var(--muted)}
.frow .path{color:var(--info)}.frow .atag{font-size:10px;font-weight:700;color:var(--critical)}
.pbadge{font-size:11px;font-weight:700;padding:3px 9px;border-radius:20px}
.pbadge.oc{background:var(--accent-bg);color:var(--accent-brand)}.pbadge.pt{background:var(--warning-bg);color:var(--warning)}
.pbadge.wk{background:var(--success-bg);color:var(--success)}.pbadge.idle{background:var(--info-bg);color:var(--text-3)}
.evtable{display:flex;flex-direction:column;gap:4px;max-height:420px;overflow:auto;margin-top:12px;font-size:12.5px}
.evrow{display:grid;grid-template-columns:120px 92px 132px 1fr auto;gap:10px;align-items:center;padding:6px 10px;border-radius:8px;background:var(--info-bg);border:1px solid var(--line)}
.evrow.anom{background:var(--critical-bg);border-color:var(--critical-border)}
.evrow.look{background:var(--warning-bg);border-color:var(--warning-border)}
.evrow .mono{font-family:'JetBrains Mono',Consolas,monospace;color:var(--muted)}
.evrow .atag{font-size:11px;font-weight:700;color:var(--critical)}
/* console */
.console{background:var(--info);border:1px solid var(--line);border-radius:var(--radius);height:480px;overflow:auto;padding:14px 16px;
 font-family:'JetBrains Mono','Cascadia Code',Consolas,monospace;font-size:12.5px;line-height:1.6}
.console .line{white-space:pre-wrap;word-break:break-word}
.lt{color:var(--text-1)}
.l-INFO{color:var(--info)}.l-WARNING{color:var(--warning)}.l-ERROR{color:var(--critical)}.l-DEBUG{color:var(--text-1)}
@media(max-width:1000px){.app{grid-template-columns:1fr}.side{position:static;height:auto;flex-direction:row;flex-wrap:wrap}.kpis{grid-template-columns:repeat(3,1fr)}.clocks,.grid2{grid-template-columns:1fr}}
::-webkit-scrollbar{width:9px;height:9px}
::-webkit-scrollbar-thumb{background:var(--info-bg);border-radius:6px;border:2px solid var(--surface-3)}
::-webkit-scrollbar-thumb:hover{background:var(--info-bg)}
::-webkit-scrollbar-track{background:transparent}
</style><link rel="stylesheet" href="/static/design-system.css"><script src="/static/i18n.js" defer></script><script src="/static/ui.js" defer></script><link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='0.9em' font-size='90'>🌐</text></svg>"></head><body>
<div class=app>
  <aside class=side>
    <div class=brand><span class=brand-mark></span><span class=brand-text><b>Sentinel Env</b><span class=sub>Team &amp; GitLab</span></span></div>
    <nav class=nav>
      <a class=active data-view=overview><svg viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2><rect x=3 y=3 width=7 height=7 rx=1 /><rect x=14 y=3 width=7 height=7 rx=1 /><rect x=14 y=14 width=7 height=7 rx=1 /><rect x=3 y=14 width=7 height=7 rx=1 /></svg> Обзор</a>
      <a data-view=config><svg viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2><line x1=4 y1=21 x2=4 y2=14 /><line x1=4 y1=10 x2=4 y2=3 /><line x1=12 y1=21 x2=12 y2=12 /><line x1=12 y1=8 x2=12 y2=3 /><line x1=20 y1=21 x2=20 y2=16 /><line x1=20 y1=12 x2=20 y2=3 /><line x1=1 y1=14 x2=7 y2=14 /><line x1=9 y1=8 x2=15 y2=8 /><line x1=17 y1=16 x2=23 y2=16 /></svg> Конфигурация</a>
      <a data-view=logs><svg viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2><polyline points="4 17 10 11 4 5"/><line x1=12 y1=19 x2=20 y2=19 /></svg> Журнал событий</a>
      <a data-view=data><svg viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2><ellipse cx=12 cy=5 rx=9 ry=3 /><path d="M3 5v14c0 1.7 4 3 9 3s9-1.3 9-3V5"/><path d="M3 12c0 1.7 4 3 9 3s9-1.3 9-3"/></svg> Данные · датасет</a>
      <a data-view=repos><svg viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2><path d="M3 7h18M3 12h18M3 17h18"/><circle cx=6 cy=7 r=0.6 fill=currentColor/><circle cx=6 cy=12 r=0.6 fill=currentColor/><circle cx=6 cy=17 r=0.6 fill=currentColor/></svg> Репозитории</a>
      <a data-view=insights><svg viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2><line x1=18 y1=20 x2=18 y2=10 /><line x1=12 y1=20 x2=12 y2=4 /><line x1=6 y1=20 x2=6 y2=14 /></svg> Аналитика</a>
      <a data-view=people><svg viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx=9 cy=7 r=4 /><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg> Сотрудники</a>
    </nav>
    <div class=side-foot>
      <div class=st><span class="run-dot" id=runDot></span><span id=runText>остановлена</span></div>
      <div>Вы вошли как <b style=color:#dfe1f5>admin</b></div>
      <div style=margin-top:6px><a href="/logout">Выйти из панели →</a></div>
    </div>
  </aside>

  <main class=main>
    <div class=topbar>
      <h1 id=pageTitle>Обзор</h1>
      <span class=grow></span>
      <span class="pill" id=hlGitlab title="Связь с GitLab"><span class=d></span><span>GitLab: <b id=hlGitlabT>—</b></span></span>
      <span class="pill" id=hlWorld title="Движок мира"><span class=d></span><span>Мир: <b id=hlWorldT>—</b></span></span>
      <span class="pill" id=hlEvents title="Событий в журнале и давность последнего"><span class=d></span><span>События: <b id=hlEventsT>—</b></span></span>
      <span class="pill" id=hlOllama hidden title="LLM (Ollama) для триажа на :8788"><span class=d></span><span>Ollama: <b id=hlOllamaT>—</b></span></span>
      <span class="pill rest" id=workPill><span class=d></span><span id=workTxt>—</span></span>
      <button class="btn primary" id=btnStart>Запустить</button>
      <button class="btn danger" id=btnStop>Остановить</button>
    </div>

    <div class=content>

      <!-- ОБЗОР -->
      <section class="view active" id=v-overview>
        <div class=clocks>
          <div class=clock><div class=lab><span class=ic>◷</span>Реальное время</div>
            <div class=val id=realTime>—</div><div class=sub>часы этого компьютера</div></div>
          <div class="clock sim"><div class=lab><span class=ic>⟳</span>Время симуляции</div>
            <div class=val id=simTime>—</div><div class=sub id=simSub>внутреннее время отдела</div></div>
          <div class=clock><div class=lab><span class=ic>⎇</span>Время GitLab-сервера</div>
            <div class=val id=glTime>—</div><div class=sub>им проставляются коммиты</div></div>
        </div>

        <div class=kpis>
          <div class=kpi><div class=n id=sSprint>—</div><div class=l>Спринт</div></div>
          <div class=kpi><div class=n id=sRules>—</div><div class=l>Активных правил</div></div>
          <div class=kpi><div class=n id=sRuns>—</div><div class=l>Действий</div></div>
          <div class=kpi><div class=n id=sOk>—</div><div class=l>Успешно</div></div>
          <div class=kpi><div class=n id=sFail>—</div><div class=l>С ошибкой</div></div>
          <div class=kpi><div class=n id=sSkip>—</div><div class=l>Пропущено ночью</div></div>
        </div>

        <div class=grid2>
          <div class=panel><h2>Состояние режима</h2>
            <div class=kv>
              <b>Статус дня</b><span id=dayStatus>—</span>
              <b>Рабочие часы</b><span id=workHours>—</span>
              <b title="Таймлапс: время симуляции идёт быстрее реального (например, рабочий день за 10 минут). Выключено — 1:1 с реальным.">Сжатие времени</b><span id=tl>—</span>
              <b title="off-hours: поведение ночью/в выходные. oncall — дежурный работает; idle — простой. Ночная активность = сигнал для детектора.">Вне рабочих часов</b><span id=ohm>—</span>
              <b>Даты в GitLab</b><span id=gld>—</span>
              <b>Текущее действие</b><span id=lastAct>—</span>
              <b>Время работы</b><span id=uptime>—</span>
            </div>
          </div>
          <div class=panel><h2>Команда</h2>
            <div class=members id=team></div>
            <div class=kv style=margin-top:14px>
              <b>Дежурный (on-call)</b><span id=oncall>—</span>
              <b>В отпуске</b><span id=pto>—</span></div>
          </div>
        </div>

        <div class=grid2>
          <div class=panel><h2>Поток событий по типам</h2>
            <div class=acts id=evActs style=margin-top:10px><div class=help style=color:#9aa0ad>пока пусто</div></div></div>
          <div class=panel><h2>Запись в GitLab</h2>
            <div style="margin-top:16px">
              <div style="display:flex;align-items:baseline;gap:10px">
                <div id=dPct style="font-size:38px;font-weight:800;font-variant-numeric:tabular-nums;line-height:1">—</div>
                <div class=sub style=margin:0>успешных вызовов</div>
              </div>
              <div class=btrack style="margin-top:10px;height:10px"><i id=dBar style="display:block;height:100%;width:0%"></i></div>
              <div style="display:flex;gap:22px;margin-top:14px;flex-wrap:wrap;font-size:13px">
                <div><div class=sub style=margin:0>успешно</div><b id=dOk style="font-size:19px;font-variant-numeric:tabular-nums">—</b></div>
                <div><div class=sub style=margin:0>с ошибкой</div><b id=dFail style="font-size:19px;font-variant-numeric:tabular-nums">—</b></div>
                <div style="border-left:1px solid var(--line);padding-left:22px"><div class=sub style=margin:0>событий в журнале</div><b id=dTot style="font-size:19px;font-variant-numeric:tabular-nums">—</b></div>
                <div><div class=sub style=margin:0>из них аномалий</div><b id=dAnom style="font-size:19px;font-variant-numeric:tabular-nums">—</b></div>
              </div>
            </div></div>
        </div>

        <div class=grid2>
          <div class=panel><h2>Распределение действий</h2>
            <div class=acts id=acts></div>
          </div>
        </div>
      </section>

      <!-- КОНФИГУРАЦИЯ -->
      <section class=view id=v-config>
        <div class=cfg-intro>Параметры симуляции. Изменения сохраняются в файл
          <code>web_config.json</code> и применяются немедленно — перезапуск не требуется.</div>
        <div id=cfg></div>
        <div class=savebar>
          <button class="btn primary" id=btnSave>Сохранить изменения</button>
          <span class=toast id=saveToast></span>
          <span class=grow></span>
          <button class="btn" id=btnReload>Сбросить форму к сохранённому</button>
        </div>

        <div class=panel style="margin-top:18px;border:1px solid #f2b8b3;background:#fef7f6">
          <h2 style=color:#b42318>Сброс состояния репозиториев</h2>
          <div class=sub>Откат к чистому проекту: закрываются все открытые MR, удаляются все
            ветки кроме <code>main</code>, контент репозиториев очищается до <code>README</code>.
            <b>Команда и сами репозитории сохраняются</b> — удаляется только наработанный контент.
            Локальное состояние правил тоже обнуляется. Доступно только при остановленной симуляции;
            при следующем старте репозитории будут засеяны заново.</div>
          <div style="display:flex;gap:10px;align-items:center;margin-top:12px;flex-wrap:wrap">
            <button class="btn danger" id=btnResetRepos>Очистить репозитории</button>
            <span class=toast id=resetReposToast></span>
          </div>
        </div>
      </section>

      <!-- ЖУРНАЛ -->
      <section class=view id=v-logs>
        <div class=panel style=margin-bottom:16px>
          <h2>Журнал событий</h2>
          <div class=console id=console></div>
          <div style="display:flex;gap:10px;align-items:center;margin-top:12px;flex-wrap:wrap">
            <a class="btn" id=btnRunlog href="/api/runlog">Скачать полный лог прогона</a>
            <button class="btn primary" id=btnTg>Отправить отчёт в Telegram</button>
            <span class=toast id=tgToast></span>
            <span class=grow></span>
            <span class=sub id=logCounts style=margin:0></span>
          </div>
        </div>
      </section>

      <section class=view id=v-people>
        <div class=cfg-intro>Нажмите на сотрудника, чтобы раскрыть живую ленту — что и куда он заливает в реальном времени.<br>
          <span class=sub>Статистика у карточки: ↑ — пуши (коммиты) · MR — merge request'ы · ⚠ — подозрительные (аномальные) действия. Считается по событиям, которые актор сгенерил с начала прогона.</span></div>
        <div class=people id=people></div>
      </section>

      <section class=view id=v-data>
        <div class=kpis style=grid-template-columns:repeat(4,1fr)>
          <div class=kpi><div class=n id=evTotal>—</div><div class=l>Событий записано</div></div>
          <div class=kpi><div class=n id=evAnom>—</div><div class=l>Аномалий (метки)</div></div>
          <div class=kpi><div class=n id=evRate>—</div><div class=l>Доля аномалий</div></div>
          <div class=kpi><div class=n id=evTypes>—</div><div class=l>Типов аномалий</div></div>
        </div>
        <div class=grid2>
          <div class=panel><h2>Аномалии по типам</h2>
            <div class=acts id=evByType></div></div>
          <div class=panel><h2>Датасет</h2>
            <div class=kv><b>Файл</b><span id=evFile>—</span><b>Запуск</b><span id=evRun>—</span></div>
            <div style=margin-top:14px><a class="btn primary" id=btnDataset href=/api/dataset>Скачать events.jsonl</a></div>
            <div class=sub style=margin-top:12px>Файл накапливается между запусками (каждая строка помечена run_id).</div></div>
        </div>
        <div class=panel style=margin-top:16px><h2>Последние события</h2>
          <div class=evtable id=evList></div></div>
      </section>

      <!-- РЕПОЗИТОРИИ (живая визуализация) -->
      <section class=view id=v-repos>
        <div class=cfg-intro>Живая карта репозиториев. Видно, как появляются файлы (пуши),
          как merge request'ы открываются и затем мёржатся или закрываются — каждое событие
          подписано автором и сообщением. Аномалии подсвечены красным.</div>
        <div class=repogrid id=repogrid></div>
      </section>

      <!-- АНАЛИТИКА -->
      <section class=view id=v-insights>
        <div class=panel style=margin-bottom:16px>
          <h2>Карта активности · часы × дни недели</h2>
          <div id=heatmap style=margin-top:14px;overflow-x:auto></div>
          <div style="display:flex;gap:14px;align-items:center;margin-top:10px;font-size:12px;color:#6b7180">
            <span>меньше</span>
            <span style="display:inline-flex;gap:3px">
              <i style="width:14px;height:14px;border-radius:3px;background:#f1f4fa;border:1px solid #e3e8f0"></i>
              <i style="width:14px;height:14px;border-radius:3px;background:#c7d2fe"></i>
              <i style="width:14px;height:14px;border-radius:3px;background:#818cf8"></i>
              <i style="width:14px;height:14px;border-radius:3px;background:#4f46e5"></i>
              <i style="width:14px;height:14px;border-radius:3px;background:#3730a3"></i>
            </span>
            <span>больше</span>
            <span style="margin-left:14px"><i style="width:14px;height:14px;border-radius:3px;border:2px solid #ef4444;display:inline-block;vertical-align:middle"></i> в этот час была аномалия (красная рамка на клетке)</span>
          </div>
        </div>

        <div>
          <div class=panel><h2>Таймлайн аномалий</h2>
            <div id=anomTimeline style=margin-top:12px></div>
            <div style="display:flex;gap:14px;margin-top:10px;font-size:12px;color:#6b7180;flex-wrap:wrap">
              <span><i class=sevdot style=background:#dc2626></i> critical</span>
              <span><i class=sevdot style=background:#f59e0b></i> high</span>
              <span><i class=sevdot style=background:#eab308></i> medium</span>
              <span><i class=sevdot style=background:#64748b></i> low</span>
            </div>
          </div>
        </div>

      </section>

    </div>
  </main>
</div>

<script>
const $=id=>document.getElementById(id);
async function jget(u){const r=await fetch(u);return r.json();}
async function jpost(u,b){const r=await fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:b?JSON.stringify(b):null});return r.json();}
function rid(k){return 'f_'+k.replace(/[^a-zA-Z0-9]/g,'_');}
function fmtUptime(s){if(!s)return '—';const h=(s/3600|0),m=(s%3600/60|0),x=s%60;return h+'ч '+m+'м '+x+'с';}
const PAL=['#5b5bd6','#0ea5a4','#e8590c','#7048e8','#1098ad','#d6336c'];
function colorFor(n){let h=0;for(const c of n)h=(h*31+c.charCodeAt(0))%PAL.length;return PAL[h];}
function initials(n){return n.split(' ').map(p=>p[0]).join('').slice(0,2).toUpperCase();}

/* навигация */
const TITLES={overview:'Обзор',config:'Конфигурация',logs:'Журнал событий',data:'Данные · датасет для ML',repos:'Репозитории · живая карта',insights:'Аналитика',people:'Сотрудники · слежение'};
document.querySelectorAll('.nav a').forEach(a=>a.onclick=()=>{
  document.querySelectorAll('.nav a').forEach(x=>x.classList.remove('active'));
  a.classList.add('active');
  const v=a.dataset.view;document.querySelectorAll('.view').forEach(s=>s.classList.remove('active'));
  $('v-'+v).classList.add('active');$('pageTitle').textContent=TITLES[v];
});

/* ---- описания параметров ---- */
const FEATURE_HELP={
 issues:"Создавать тикеты (баги, задачи, threat intel) с метками и привязкой к спринту.",
 ci_pipeline:"Имитировать CI: бот публикует статус сборки, при сбое автор досылает исправление.",
 draft_mrs:"Часть запросов на слияние сначала помечается черновиком, затем переводится в готовые.",
 emoji_reactions:"Реакции на комментарии и запросы слияния.",
 approvals:"Полноценные подтверждения через GitLab API, а не текстом.",
 releases:"По завершении спринта — тег, релиз и запись в CHANGELOG.",
 peer_review:"Часть ревью выполняет инженер, а не только руководитель.",
 campaigns:"Сюжетные цепочки реагирования: уязвимость → разведка → правило → плейбук.",
 standup:"Ежедневный созвон команды отдельным тикетом.",
 pto:"Сотрудники периодически отсутствуют (отпуск, больничный).",
 change_freeze_friday:"В пятницу после 14:00 рискованные изменения в прод не выкатываются.",
 lifecycle_state:"Выбирать цели по состоянию: донастраивать шумные правила, выводить мёртвые."
};
const PROB_HELP={
 ci_fail:"Доля сборок, завершающихся ошибкой и требующих исправления.",
 mr_abandoned:"Доля запросов слияния, закрытых без принятия.",
 mr_draft_first:"Доля запросов, начинающихся со статуса «черновик».",
 delayed_revert:"Доля откатов правил, выполняемых с задержкой.",
 peer_review:"Доля ревью, выполняемых инженером вместо руководителя.",
 emoji:"Частота реакций на события.",
 promote:"Доля стабильных правил, продвигаемых в продакшен."
};
const ACT_HELP={
 new_detection_rule:"Новое правило детектирования",fix_existing_rule:"Исправление правила",
 tune_threshold:"Донастройка порогов",refactor_rule:"Рефакторинг",update_parser:"Обновление парсера",
 update_playbook:"Обновление плейбука",add_test_sample:"Тестовый образец",threat_intel_update:"Threat intelligence",
 update_dashboard:"Обновление метрик",triage_false_positive:"Разбор ложного срабатывания",revert_bad_rule:"Откат правила",
 deprecate_rule:"Вывод правила из эксплуатации",recreate_fixed_rule:"Пересоздание правила",handle_incident:"Реагирование на инцидент",
 bulk_maintenance:"Массовое обслуживание",open_issue:"Заведение тикета",campaign:"Сюжетная кампания"
};

/* ---- контролы ---- */
function slider(k,label,help,min,max,step,unit,val){
 const id=rid(k);if(val==null)val=0;
 return '<div class=field><div class=top><label>'+label+'</label><span class=val id=o_'+id+'>'+val+unit+'</span></div>'+
  '<input id='+id+' type=range data-k="'+k+'" data-t=num data-unit="'+unit+'" min='+min+' max='+max+' step='+step+' value="'+val+'" '+
  'oninput="document.getElementById(\'o_'+id+'\').textContent=this.value+\''+unit+'\';recalc()">'+
  '<div class=help>'+help+'</div></div>';
}
function sliderN(k,label,help,min,max,step,val){
 const id=rid(k);const v=val||0;
 return '<div class=field><div class=top><label>'+label+'</label><span class=val id=o_'+id+'>'+(v?('×'+v):'авто')+'</span></div>'+
  '<input id='+id+' type=range data-k="'+k+'" data-t=numn min='+min+' max='+max+' step='+step+' value="'+v+'" '+
  'oninput="document.getElementById(\'o_'+id+'\').textContent=(this.value>0?(\'×\'+this.value):\'авто\');recalc()">'+
  '<div class=help>'+help+'</div></div>';
}
function toggle(k,label,help,val){
 return '<div class="field switch-field"><div class=sw-txt><label>'+label+'</label><div class=help>'+help+'</div></div>'+
  '<label class=switch><input type=checkbox data-k="'+k+'" data-t=bool '+(val?'checked':'')+' onchange=recalc()><span class=track></span></label></div>';
}
function sel(k,label,help,opts,val){
 return '<div class=field><label>'+label+'</label><select data-k="'+k+'" data-t=str onchange=recalc()>'+
  opts.map(o=>'<option '+(o===val?'selected':'')+'>'+o+'</option>').join('')+'</select><div class=help>'+help+'</div></div>';
}
function txt(k,label,help,val){
 return '<div class=field><label>'+label+'</label><input class=tin data-k="'+k+'" data-t=str value="'+(val==null?'':val)+'"><div class=help>'+help+'</div></div>';
}
function group(ic,title,subtitle,inner,open){
 return '<details class=group '+(open?'open':'')+'><summary><span class=g-ic>'+ic+'</span>'+
  '<span><div class=g-tt>'+title+'</div><div class=g-sub>'+subtitle+'</div></span>'+
  '<span class=g-chev>▾</span></summary><div class=body>'+inner+'</div></details>';
}

let CFG={};
function renderCfg(c){
 CFG=c;
 const wn=['Пн','Вт','Ср','Чт','Пт','Сб','Вс'];
 const days='<div class=field><label>Рабочие дни недели</label><div class=days>'+
   wn.map((d,i)=>'<label class="day '+((c.WORK_DAYS||[]).includes(i)?'act':'')+'"><input type=checkbox data-day='+i+' '+((c.WORK_DAYS||[]).includes(i)?'checked':'')+' onchange="this.parentNode.classList.toggle(\'act\',this.checked)">'+d+'</label>').join('')+
   '</div><div class=help>Дни, когда команда считается работающей.</div></div>';

 const tl=group('⏱','Сжатие времени','Насколько быстро идёт время внутри симуляции относительно реального.',
   '<div class=presets>'+
     '<button class=chip onclick="preset(\'real\')">Реальное время</button>'+
     '<button class=chip onclick="preset(\'wd60\')">Рабочий день = 1 час</button>'+
     '<button class=chip onclick="preset(\'wd30\')">Рабочий день = 30 минут</button>'+
     '<button class=chip onclick="preset(\'wd10\')">Ускоренный = 10 минут</button>'+
     '<button class=chip onclick="preset(\'week\')">Неделя = 1 час</button></div>'+
   '<div class=tlinfo id=tlInfo>—</div><div class=fields>'+
   toggle('TIMELAPSE_ENABLED','Сжатие времени включено','Время симуляции идёт быстрее реального. Выключено — один к одному.',c.TIMELAPSE_ENABLED)+
   slider('SIM_WORKDAY_REAL_MINUTES','Рабочий день за, минут','Сколько реального времени занимает один рабочий день симуляции (10:00–18:00). Меньше — быстрее.',5,480,5,' мин',c.SIM_WORKDAY_REAL_MINUTES)+
   sliderN('TIME_SCALE_OVERRIDE','Точный масштаб','Секунд симуляции за одну реальную секунду. 0 — рассчитать автоматически. 24 — сутки за час, 168 — неделя за час.',0,300,1,c.TIME_SCALE_OVERRIDE)+
   toggle('FAST_FORWARD_OFFHOURS','Пропускать ночи и выходные','Нерабочее время проматывается мгновенно; реальное время тратится только на рабочие часы.',c.FAST_FORWARD_OFFHOURS)+
   txt('SIM_START','Начало отсчёта','Дата и время старта симуляции. Пусто — сегодня, 10:00. Формат: 2026-06-01 10:00.',c.SIM_START)+
   '</div>',true);

 const wd=group('🗓','Рабочий день и неделя','Когда команда активна.','<div class=fields>'+
   slider('WORK_HOURS_START','Начало рабочего дня, час','Час, с которого начинается рабочий день.',0,23,1,' ч',c.WORK_HOURS_START)+
   slider('WORK_HOURS_END','Конец рабочего дня, час','Час окончания рабочего дня. После — нерабочее время.',1,24,1,' ч',c.WORK_HOURS_END)+
   days+
   toggle('LUNCH_BREAK.enabled','Обеденный перерыв','Короткая пауза активности в середине дня.',c.LUNCH_BREAK&&c.LUNCH_BREAK.enabled)+
   slider('LUNCH_BREAK.hour','Час начала обеда','Время начала обеденного перерыва.',10,17,1,' ч',c.LUNCH_BREAK&&c.LUNCH_BREAK.hour)+
   slider('LUNCH_BREAK.duration_min','Длительность обеда, минут','Продолжительность перерыва во внутреннем времени.',0,120,5,' мин',c.LUNCH_BREAK&&c.LUNCH_BREAK.duration_min)+
   '</div>');

 const oh=group('🌙','Нерабочее время','Поведение ночью и в выходные.','<div class=fields>'+
   sel('OFF_HOURS_MODE','Режим вне рабочих часов','«oncall» — дежурный изредка реагирует на инциденты. «idle» — полная тишина до следующего рабочего дня.',['oncall','idle'],c.OFF_HOURS_MODE)+
   slider('OFF_HOURS_ACTIVITY_PROBABILITY','Вероятность ночной активности','Шанс, что дежурный что-то выполнит ночью (для режима oncall). 0 — никогда.',0,1,0.01,'',c.OFF_HOURS_ACTIVITY_PROBABILITY)+
   slider('OFF_HOURS_POLL_SECONDS','Интервал проверки, секунд','Как часто проверять наступление рабочего дня (актуально без сжатия времени).',30,1800,30,' с',c.OFF_HOURS_POLL_SECONDS)+
   '</div>');

 const tempo=group('🏃','Темп работы','Частота и длительность действий.','<div class=fields>'+
   slider('SCENARIO_INTERVAL.min','Пауза между действиями (мин), сек','Минимальная пауза во внутреннем времени. Реальная = делится на масштаб.',5,600,5,' с',c.SCENARIO_INTERVAL&&c.SCENARIO_INTERVAL.min)+
   slider('SCENARIO_INTERVAL.max','Пауза между действиями (макс), сек','Максимальная пауза во внутреннем времени.',5,600,5,' с',c.SCENARIO_INTERVAL&&c.SCENARIO_INTERVAL.max)+
   slider('SPEED_MULTIPLIER','Множитель длительности действий','Масштабирует внутренние паузы (ревью, обсуждения). 1.0 — стандарт.',0.1,5,0.1,'×',c.SPEED_MULTIPLIER)+
   slider('MAX_OPEN_MRS','Лимит открытых запросов слияния','При достижении лимита команда сначала разбирает очередь, а не открывает новые.',1,20,1,'',c.MAX_OPEN_MRS)+
   '</div>');

 const rhythm=group('🔁','Долгосрочные циклы','Спринты и отсутствия сотрудников.','<div class=fields>'+
   slider('SPRINT_DAYS','Длина спринта, дней','По завершении спринта формируется релиз.',1,30,1,' дн',c.SPRINT_DAYS)+
   slider('PTO_PROBABILITY_PER_DAY','Вероятность отпуска в день','Шанс, что сотрудник отсутствует в конкретный день.',0,1,0.01,'',c.PTO_PROBABILITY_PER_DAY)+
   '</div>');

 const git=group('⎇','GitLab и время','Подключение и согласование дат.','<div class=fields>'+
   txt('GITLAB_URL','Адрес GitLab','URL сервера GitLab.',c.GITLAB_URL)+
   txt('ADMIN_TOKEN','Токен доступа','Personal access token со scope api.',c.ADMIN_TOKEN)+
   sel('GITLAB_DATES','Даты, записываемые в GitLab','«real» — реальное время сервера, согласовано с коммитами (рекомендуется). «sim» — время симуляции; учитывается только для admin-токена и не для будущих дат. Отметки коммитов всегда ставит сам GitLab.',['real','sim'],c.GITLAB_DATES)+
   '</div>');

 const feat=group('🧩','Элементы поведения','Какие части рабочего процесса включены.','<div class=fields>'+
   Object.keys(c.FEATURES||{}).map(k=>toggle('FEATURES:'+k,k,FEATURE_HELP[k]||'',c.FEATURES[k])).join('')+'</div>');

 const probs=group('🎲','Частота нештатных ситуаций','Насколько часто возникают сбои и отклонения.','<div class=fields>'+
   Object.keys(c.PROBS||{}).map(k=>slider('PROBS:'+k,k,PROB_HELP[k]||'',0,1,0.01,'',c.PROBS[k])).join('')+'</div>');

 const weights=group('⚖','Частота типов действий','Относительная вероятность выбора каждого сценария.','<div class=fields>'+
   Object.keys(c.ACTIVITY_WEIGHTS||{}).map(k=>slider('WEIGHT:'+k,(ACT_HELP[k]||k),'Внутренний ключ: '+k,0,0.4,0.01,'',c.ACTIVITY_WEIGHTS[k])).join('')+'</div>');

 $('cfg').innerHTML=tl+wd+oh+tempo+rhythm+git+feat+probs+weights;
 recalc();
}
function getv(k){const el=document.querySelector('[data-k="'+k+'"]');if(!el)return null;return el.dataset.t==='bool'?el.checked:el.value;}
function setv(k,val){const el=document.querySelector('[data-k="'+k+'"]');if(!el)return;
 if(el.dataset.t==='bool'){el.checked=!!val;}
 else{el.value=val;const o=$('o_'+rid(k));if(o)o.textContent=(el.dataset.t==='numn')?(val>0?('×'+val):'авто'):(val+(el.dataset.unit||''));}}
function preset(p){
 setv('TIMELAPSE_ENABLED',p!=='real');
 if(p==='wd60'){setv('SIM_WORKDAY_REAL_MINUTES',60);setv('TIME_SCALE_OVERRIDE',0);}
 if(p==='wd30'){setv('SIM_WORKDAY_REAL_MINUTES',30);setv('TIME_SCALE_OVERRIDE',0);}
 if(p==='wd10'){setv('SIM_WORKDAY_REAL_MINUTES',10);setv('TIME_SCALE_OVERRIDE',0);}
 if(p==='week'){setv('TIME_SCALE_OVERRIDE',168);}
 recalc();
}
function recalc(){
 const en=getv('TIMELAPSE_ENABLED');
 const wd=+getv('SIM_WORKDAY_REAL_MINUTES')||60;
 const ov=+getv('TIME_SCALE_OVERRIDE')||0;
 const hs=+getv('WORK_HOURS_START');const he=+getv('WORK_HOURS_END');
 const wh=Math.max(1,(isNaN(he)?18:he)-(isNaN(hs)?10:hs));
 let scale=!en?1:(ov>0?ov:(wh*3600)/(wd*60));
 const dayMin=(wh*3600/scale)/60,weekMin=dayMin*5;
 const el=$('tlInfo');if(el)el.innerHTML=en
  ?'Масштаб <b>×'+scale.toFixed(1)+'</b> · рабочий день ('+wh+' ч) проходит за <b>'+dayMin.toFixed(0)+' мин</b> реального времени · рабочая неделя — примерно <b>'+weekMin.toFixed(0)+' мин</b> (ночи и выходные мгновенно).'
  :'Сжатие времени выключено — внутреннее время идёт один к одному с реальным.';
}
async function save(){
 const upd={SCENARIO_INTERVAL:{},LUNCH_BREAK:{},FEATURES:{},PROBS:{},ACTIVITY_WEIGHTS:{}};
 document.querySelectorAll('[data-k]').forEach(el=>{
  const k=el.dataset.k,t=el.dataset.t;let v;
  if(t==='bool')v=el.checked;else if(t==='num')v=Number(el.value);
  else if(t==='numn')v=Number(el.value)>0?Number(el.value):null;else v=el.value;
  if(k.startsWith('FEATURES:'))upd.FEATURES[k.slice(9)]=v;
  else if(k.startsWith('PROBS:'))upd.PROBS[k.slice(6)]=v;
  else if(k.startsWith('WEIGHT:'))upd.ACTIVITY_WEIGHTS[k.slice(7)]=v;
  else if(k.indexOf('.')>0){const a=k.split('.');upd[a[0]][a[1]]=v;}
  else upd[k]=v;
 });
 const days=[];document.querySelectorAll('[data-day]').forEach(el=>{if(el.checked)days.push(+el.dataset.day)});
 upd.WORK_DAYS=days;
 const r=await jpost('/api/config',upd);
 $('saveToast').textContent=r.ok?'Сохранено и применено':'Ошибка сохранения';
 setTimeout(()=>$('saveToast').textContent='',2600);
 if(r.settings)CFG=r.settings;
}

async function tick(){
 let s;try{s=await jget('/api/status');}catch(e){return;}
 $('runDot').className='run-dot'+(s.running?' on':'');
 $('runText').textContent=s.running?'работает':'остановлена';
 $('workPill').className='pill '+(s.is_work?'work':'rest');
 $('workTxt').textContent=s.is_work?'рабочее время':'нерабочее время';
 $('realTime').textContent=s.real_time;$('simTime').textContent=s.sim_time;$('glTime').textContent=s.gitlab_time||'—';
 $('dayStatus').textContent=s.is_work?'рабочий день':'нерабочее время';
 $('workHours').textContent=s.work_hours;
 $('tl').textContent=(s.time_mode||(s.timelapse?('×'+s.scale):'Реальное время 1:1'))+(s.ff_offhours?' · ⏩ промотка нерабочих часов':'')+(s.last_ff?(' · '+s.last_ff):'');
 $('ohm').textContent=s.offhours_mode;
 $('gld').textContent=s.gitlab_dates+(s.gitlab_dates==='real'?' (реальное)':' (симуляция)');
 $('lastAct').textContent=s.last_activity?((ACT_HELP[s.last_activity]||s.last_activity)+' · '+(s.last_actor||'')):'—';
 $('uptime').textContent=fmtUptime(s.uptime);
 $('sSprint').textContent=s.sprint??'—';$('sRules').textContent=s.rules;
 $('sRuns').textContent=s.total_runs;$('sOk').textContent=s.total_ok;
 $('sFail').textContent=s.total_fail;$('sSkip').textContent=s.offhours_skipped;
 if(s.runlog){const rl=s.runlog;const lc=$('logCounts');if(lc)lc.innerHTML='⚠️ warnings: <b>'+(rl.warnings||0)+'</b> · ❌ errors: <b>'+(rl.errors||0)+'</b> · TG: '+(s.telegram?'вкл':'выкл');}
 $('oncall').textContent=s.oncall||'—';$('pto').textContent=s.pto||'никого';
 $('team').innerHTML=s.team.map(m=>{const st=m.stats||{};const la=st.last_action?((ACT_HELP[st.last_action]||st.last_action)+(st.last_project?(' · '+st.last_project):'')):'нет активности';
   return '<div class=member><div class=avatar style="background:'+colorFor(m.name)+'">'+initials(m.name)+'</div>'+
   '<div style=flex:1><div class=m-name>'+m.name+'</div><div class=m-role>'+m.role+' · '+la+'</div></div>'+
   (m.oncall?'<span class="badge oc">дежурный</span>':(m.pto?'<span class="badge pt">отпуск</span>':(m.working?'<span class="badge wk">на смене</span>':'')))+'</div>';}).join('');
 renderPeople(s.team);
 const a=s.activities||{},keys=Object.keys(a).sort((x,y)=>a[y]-a[x]);const mx=Math.max(1,...keys.map(k=>a[k]));
 $('acts').innerHTML=keys.length?keys.map(k=>'<div class=act><span>'+(ACT_HELP[k]||k)+'</span><b>'+a[k]+'</b><div class=bar><i style=width:'+(a[k]/mx*100)+'%></i></div></div>').join(''):'<div class="help empty">пока нет данных — запустите симуляцию</div>';
 // поток событий по типам (event-store)
 const ev=(s.events&&s.events.by_action)||{};const ek=Object.keys(ev).sort((x,y)=>ev[y]-ev[x]).slice(0,10);
 if(ek.length){const em=Math.max(1,...ek.map(k=>ev[k]));const EVN={push:'push (коммит файла)',mr_open:'открыт MR',mr_merge:'смёржен MR',mr_comment:'комментарий MR',mr_approve:'апрув MR',mr_close:'закрыт MR',branch_create:'создана ветка',issue_open:'открыт issue',issue_comment:'комментарий issue',issue_close:'закрыт issue',file_delete:'удалён файл',pipeline:'пайплайн CI',token_create:'создан токен',settings_change:'изменены настройки'};
  $('evActs').innerHTML=ek.map(k=>'<div class=act><span>'+(EVN[k]||k)+'</span><b>'+ev[k]+'</b><div class=bar><i style=width:'+(ev[k]/em*100)+'%></i></div></div>').join('');}
 // донат успешности GitLab-вызовов
 const ok=s.total_ok||0,fail=s.total_fail||0,tot=ok+fail;
 const pctOk=tot?Math.round(ok/tot*100):0;
 const C=2*Math.PI*15.9155;
 const pb=$('dPct');if(pb){pb.textContent=tot?(pctOk+'%'):'—';pb.style.color=tot?(pctOk>=90?'#15803d':pctOk>=60?'#b45309':'#b42318'):'#6b7789';}
 const bb=$('dBar');if(bb)bb.style.width=(tot?pctOk:0)+'%';
 $('dOk').textContent=ok;$('dFail').textContent=fail;
 $('dAnom').textContent=(s.events&&s.events.anomalies)!=null?s.events.anomalies:'—';
 $('dTot').textContent=(s.events&&s.events.total)!=null?s.events.total:'—';
}

function fmtAge(s){if(s==null)return'';if(s<60)return s+' с назад';if(s<3600)return Math.floor(s/60)+' мин назад';return Math.floor(s/3600)+' ч назад';}
function setPill(id,cls,txt){const p=$(id);if(!p)return;p.className='pill '+cls;$(id+'T').textContent=txt;}
async function pollHealth(){
 let h;try{h=await jget('/api/health');}catch(e){return;}
 const g=h.gitlab||{};
 if(h.offline_mode)setPill('hlGitlab','warn','offline');
 else if(g.state==='ok')setPill('hlGitlab','ok','на связи');
 else if(g.state==='error')setPill('hlGitlab','bad','ошибка');
 else setPill('hlGitlab','','—');
 $('hlGitlab').title='GitLab: '+(g.msg||'—')+(g.errors?(' · ошибок вызовов: '+g.errors):'');
 setPill('hlWorld',h.world.running?'ok':'',h.world.running?'работает':'остановлен');
 const ev=h.events||{};
 const fresh=ev.last_age_s!=null&&ev.last_age_s<180;
 setPill('hlEvents',ev.total>0?(fresh?'ok':''):'bad',(ev.total||0)+(ev.last_age_s!=null?(' · '+fmtAge(ev.last_age_s)):''));
 setPill('hlOllama',h.ollama?'ok':'warn',h.ollama?'готова':'нет');
}
/* ---------- профиль разработчика: риск-профиль в боковой панели ---------- */
async function devProfile(u){
 if(!window.dsDrawer)return;
 dsDrawer('Профиль · @'+u,'<div class=ds-skeleton style="width:70%"></div>');
 let d={};try{d=await jget('/api/actor?u='+encodeURIComponent(u)+'&n=60');}catch(e){}
 const s=d.summary||{},feed=d.feed||[];
 const anom=s.anomalies||0,total=s.total||0;
 const share=total?Math.round(anom/total*100):0;
 const lvl=anom>=5?'critical':(anom>=2?'high':(anom>=1?'medium':'low'));
 const LVL={critical:'высокий',high:'повышенный',medium:'умеренный',low:'обычный'};
 const M={critical:'b-crit',high:'b-high',medium:'b-med',low:'b-low'};
 const row=(k,v)=>'<div class=ds-kv-row><span class=ds-kv-k>'+k+'</span><span class=ds-kv-v>'+v+'</span></div>';
 const feedHtml=feed.length?feed.slice(0,25).map(function(e){
   const bad=e.is_anomaly||e.anomaly_type;
   return '<div class="ds-tl-item '+(bad?'critical':'info')+'">'+
    '<div class=ds-tl-time>'+esc((e.ts_sim||'').replace('T',' '))+'</div>'+
    '<div class=ds-tl-title>'+esc(e.action||'')+
      (e.project?' <span class=ds-feed-repo>'+esc(e.project)+'</span>':'')+'</div>'+
    (e.path?'<div class=ds-tl-desc><code>'+esc(e.path)+'</code></div>':'')+'</div>';}).join('')
  :'<div class="ds-empty">Событий пока нет</div>';
 dsDrawer('Профиль · @'+u,
  '<div class=ds-kv>'+
   row('Риск-профиль','<span class="badge '+M[lvl]+'">'+LVL[lvl]+'</span>')+
   row('Всего действий','<b class=num>'+total+'</b>')+
   row('Аномальных','<b class=num>'+anom+'</b> <span class=sub>('+share+'% от всех)</span>')+
   row('Пушей / MR / merge','<span class=num>'+(s.pushes||0)+' / '+(s.mrs||0)+' / '+(s.merges||0)+'</span>')+
   row('Открыто issue','<span class=num>'+(s.issues||0)+'</span>')+
   row('Последнее действие',esc(s.last_action||'—')+(s.last_project?(' &middot; '+esc(s.last_project)):''))+
   (s.last_path?row('Последний файл','<code>'+esc(s.last_path)+'</code>'):'')+
   row('Когда',esc((s.last_ts||'').replace('T',' ')||'—'))+
  '</div>'+
  '<div class=ds-drawer-sec><div class=t-label>Лента действий</div>'+
   '<div class=ds-timeline style=margin-top:10px>'+feedHtml+'</div></div>');}

/* ---------- здоровье репозитория ---------- */
function repoHealth(name,r){
 if(!window.dsDrawer)return;
 const anom=r.anomalies||0,ev=r.events||0;
 const risk=anom>=3?'critical':(anom>=1?'high':'low');
 const M={critical:'b-crit',high:'b-high',low:'b-low'};
 const L={critical:'требует внимания',high:'есть подозрительное',low:'спокойно'};
 const row=(k,v)=>'<div class=ds-kv-row><span class=ds-kv-k>'+k+'</span><span class=ds-kv-v>'+v+'</span></div>';
 dsDrawer('Репозиторий · '+name,
  '<div class=ds-kv>'+
   row('Состояние','<span class="badge '+M[risk]+'">'+L[risk]+'</span>')+
   row('Событий','<b class=num>'+ev+'</b>')+
   row('Аномальных','<b class=num>'+anom+'</b>')+
   row('Файлов в сессии','<span class=num>'+(r.files||0)+'</span>')+
   row('Открытых MR','<span class=num>'+((r.open_mrs||[]).length)+'</span>')+
   row('Удалено файлов','<span class=num>'+((r.deleted||[]).length)+'</span>')+
  '</div>'+
  '<div class=ds-drawer-sec><div class=t-label>Открытые merge request</div><div class=ds-ev-list>'+
   (((r.open_mrs||[]).length)?(r.open_mrs||[]).map(function(m){
     return '<div class=ds-ev-item><span>!'+esc(''+(m.iid||''))+' '+esc(m.title||'')+'</span>'+
            '<span class=sub>@'+esc(m.author||'')+'</span></div>';}).join('')
    :'<div class=sub>нет открытых MR</div>')+'</div></div>'+
  '<div class=ds-drawer-sec><div class=t-label>Последние файлы</div><div class=ds-ev-list>'+
   ((r.tree||[]).length?(r.tree||[]).slice(0,20).map(function(f){
     return '<div class=ds-ev-item><code>'+esc(f)+'</code></div>';}).join('')
    :'<div class=sub>файлов пока нет</div>')+'</div></div>');}

function cssId(u){return 'p_'+u.replace(/[^a-zA-Z0-9]/g,'_');}
const openUsers=new Set();let peopleSig='';
function statusBadge(m){return m.oncall?'<span class="pbadge oc">дежурный</span>':(m.pto?'<span class="pbadge pt">отпуск</span>':(m.working?'<span class="pbadge wk">на смене</span>':'<span class="pbadge idle">не на смене</span>'));}
function renderPeople(team){
 const sig=team.map(m=>m.username).join(',');
 if(sig!==peopleSig){peopleSig=sig;
  document.getElementById('people').innerHTML=team.map(m=>{const id=cssId(m.username);
   return '<div class="pcard" data-u="'+m.username+'" id="card_'+id+'">'+
    '<div class=phead><div class=avatar style="background:'+colorFor(m.name)+'">'+initials(m.name)+'</div>'+
    '<div class=pinfo><div class=m-name>'+m.name+'</div><div class=m-role>'+m.role+'</div></div>'+
    '<div class=pmeta id="meta_'+id+'"></div><div id="bdg_'+id+'"></div>'+
    '<button class="btn ghost ds-prof-btn" onclick="event.stopPropagation();devProfile(\''+escJs(m.username)+'\')">профиль</button>'+
    '<span class=pchev>&#9662;</span></div>'+
    '<div class=pbody id="body_'+id+'"></div></div>';}).join('');}
 team.forEach(m=>{const id=cssId(m.username);const st=m.stats||{};
  const meta=document.getElementById('meta_'+id);if(meta)meta.innerHTML='<span title="пуши/коммиты">&#8593; <b>'+(st.pushes||0)+'</b></span> &middot; <span title="merge request'ы">MR <b>'+(st.mrs||0)+'</b></span> &middot; <span title="подозрительные (аномальные) действия">&#9888; <b>'+(st.anomalies||0)+'</b></span>';
  const bdg=document.getElementById('bdg_'+id);if(bdg)bdg.innerHTML=statusBadge(m);
  const card=document.getElementById('card_'+id);if(card)card.classList.toggle('open',openUsers.has(m.username));});
}
function togglePerson(u){if(openUsers.has(u))openUsers.delete(u);else{openUsers.add(u);refreshActor(u);}
 const card=document.querySelector('.pcard[data-u="'+u+'"]');if(card)card.classList.toggle('open',openUsers.has(u));}
document.addEventListener('click',e=>{const h=e.target.closest?e.target.closest('.phead'):null;if(h){const c=h.closest('.pcard');if(c)togglePerson(c.dataset.u);}});
async function refreshActor(u){try{const d=await jget('/api/actor?u='+encodeURIComponent(u)+'&n=60');const id=cssId(u);
 const el=document.getElementById('body_'+id);if(!el)return;const s=d.summary||{};const feed=(d.feed||[]).slice().reverse();
 el.innerHTML='<div class=pcur>'+(s.last_action?('сейчас: <b>'+(ACT_HELP[s.last_action]||s.last_action)+'</b>'+(s.last_project?(' &#8594; '+s.last_project):'')+(s.last_path?(' / '+s.last_path):'')):'нет активности')+'</div>'+
  '<div class=feed>'+(feed.length?feed.map(e=>'<div class="frow '+(e.is_anomaly?'anom':(e.lookalike?'look':''))+'"><span class=mono>'+((e.ts_sim||'').slice(11,16))+'</span><span class=mono>'+(e.action||'')+'</span><span>'+(e.project||'')+'</span><span class="mono path">'+((e.path||e.message||'')+'').slice(0,46).replace(/</g,'&lt;')+'</span>'+(e.anomaly_type?'<span class=atag>'+e.anomaly_type+'</span>':'')+'</div>').join(''):'<div class=help style=color:#9aa0ad>пока нет событий</div>')+'</div>';
 }catch(e){}}
let lastLog=0;
async function pollLogs(){
 try{const d=await jget('/api/logs?since='+lastLog);
  if(d.logs&&d.logs.length){const box=$('console');const atB=box.scrollHeight-box.scrollTop-box.clientHeight<60;
   for(const e of d.logs){lastLog=e.id;const div=document.createElement('div');div.className='line l-'+e.level;
    div.innerHTML='<span class=lt>'+e.t+'</span>  '+e.msg.replace(/</g,'&lt;');box.appendChild(div);}
   while(box.childNodes.length>1500)box.removeChild(box.firstChild);if(atB)box.scrollTop=box.scrollHeight;}
 }catch(e){}
}
$('btnStart').onclick=async()=>{await jpost('/api/start');setTimeout(tick,300);};
$('btnStop').onclick=async()=>{await jpost('/api/stop');setTimeout(tick,300);};
if($('btnResetRepos'))$('btnResetRepos').onclick=async()=>{
 if(!confirm('Очистить контент всех репозиториев?\n\nБудут закрыты все MR, удалены ветки (кроме main) и стёрты файлы до README.\nКоманда и сами репозитории сохранятся. Действие необратимо.'))return;
 const b=$('btnResetRepos');b.disabled=true;const t=$('resetReposToast');t.textContent='очищаю репозитории…';
 const w=prompt('Это сотрёт весь наработанный контент репозиториев. Введите RESET:');if(w!=='RESET'){b.disabled=false;t.textContent='отменено';return;}
 try{const r=await jpost('/api/reset_repos',{confirm:w});t.textContent=r.msg||'';}catch(e){t.textContent='ошибка';}
 b.disabled=false;setTimeout(()=>{t.textContent='';},9000);};
if($('btnTg'))$('btnTg').onclick=async()=>{$('tgToast').textContent='отправляю…';const r=await jpost('/api/tg_report');$('tgToast').textContent=r.msg||'';setTimeout(()=>$('tgToast').textContent='',4000);};
$('btnSave').onclick=save;
$('btnReload').onclick=()=>jget('/api/config').then(renderCfg);
jget('/api/config').then(renderCfg);
tick();setInterval(tick,1500);
pollHealth();setInterval(pollHealth,5000);
pollLogs();setInterval(pollLogs,1000);
async function pollEvents(){try{const d=await jget('/api/events?n=120');const st=d.stats||{};
 $('evTotal').textContent=st.total||0;$('evAnom').textContent=st.anomalies||0;
 $('evRate').textContent=st.total?((st.anomalies/st.total*100).toFixed(1)+'%'):'0%';
 const bt=st.by_anomaly||{};const bk=Object.keys(bt);$('evTypes').textContent=bk.length;
 $('evFile').textContent=st.file||'—';$('evRun').textContent=st.run_id||'—';
 const mx=Math.max(1,...bk.map(k=>bt[k]));
 $('evByType').innerHTML=bk.length?bk.sort((a,b)=>bt[b]-bt[a]).map(k=>'<div class=act><span>'+k+'</span><b>'+bt[k]+'</b><div class=bar><i style="width:'+(bt[k]/mx*100)+'%;background:linear-gradient(90deg,#e8590c,#d6336c)"></i></div></div>').join(''):'<div class="help empty">аномалий пока нет</div>';
 const items=(d.items||[]).slice().reverse();
 $('evList').innerHTML=items.length?items.map(e=>{const cls=e.is_anomaly?'anom':(e.lookalike?'look':'');
  return '<div class="evrow '+cls+'"><span class=mono>'+(e.ts_sim||'').replace('T',' ').slice(5)+'</span>'+
   '<span>'+(e.actor||'')+'</span><span class=mono>'+(e.action||'')+'</span>'+
   '<span class=mono>'+((e.path||e.project||'')+'').slice(0,60)+'</span>'+
   '<span class=atag>'+(e.anomaly_type||(e.lookalike?'lookalike':''))+'</span></div>';}).join(''):'<div class=help style=color:#9aa0ad>событий пока нет — запустите симуляцию</div>';
}catch(e){}}
pollEvents();setInterval(pollEvents,2000);
setInterval(()=>openUsers.forEach(refreshActor),2000);

// ---------- Аналитика ----------
const DOW=['Пн','Вт','Ср','Чт','Пт','Сб','Вс'];
const SEVCOL={critical:'#dc2626',high:'#f59e0b',medium:'#eab308',low:'#64748b'};
function isDark(){return document.documentElement.getAttribute('data-theme')!=='light';}
function heatColor(v,mx){const t=v/mx;
 if(isDark()){ // на тёмном: пусто = фон панели, больше активности = ярче
  if(!v)return '#18212e';
  return t>0.75?'#93c5fd':t>0.5?'#60a5fa':t>0.25?'#3b82f6':'#1e40af';}
 if(!v)return '#f1f4fa';
 return t>0.75?'#3730a3':t>0.5?'#4f46e5':t>0.25?'#818cf8':'#c7d2fe';}
function drawHeat(grid,agrid){const el=$('heatmap');if(!el)return;
 let mx=1;grid.forEach(r=>r.forEach(v=>{if(v>mx)mx=v;}));
 let h='<div class=hmrow><div class=hmlab></div>'+Array.from({length:24},(_,x)=>'<div style="width:17px;font-size:9px;color:#9aa0ad;text-align:center">'+(x%3===0?x:'')+'</div>').join('')+'</div>';
 for(let d=0;d<7;d++){h+='<div class=hmrow><div class=hmlab>'+DOW[d]+'</div>';
  for(let x=0;x<24;x++){const v=grid[d][x],a=agrid[d][x];
   h+='<div class=hmcell title="'+DOW[d]+' '+x+':00 — '+v+' действий'+(a?(', '+a+' аномал.'):'')+'" style="background:'+heatColor(v,mx)+(a?';box-shadow:0 0 0 2px #ef4444 inset':'')+'"></div>';}
  h+='</div>';}
 el.innerHTML=h;}
function drawAnomTimeline(items){const el=$('anomTimeline');if(!el)return;
 if(!items||!items.length){el.innerHTML='<div class="help empty">аномалий пока нет</div>';return;}
 // ВАЖНО: ts_sim это ISO ("2026-07-21T08:59:06") — парсим КАК ЕСТЬ.
 // Раньше тут был .replace('T',' '), из-за чего Date.parse отдавал NaN и точки
 // не рисовались: оставалась только пустая линия.
 const ts=items.map(a=>{const v=Date.parse(a.ts_sim||'');return isNaN(v)?null:v;});
 const good=ts.filter(v=>v!==null);
 const mn=good.length?Math.min(...good):0, mx=good.length?Math.max(...good):1;
 const span=Math.max(1,mx-mn);
 const W=100,H=46;
 let dots='';
 items.forEach((a,i)=>{
  // координаты — в единицах viewBox (не в процентах): проценты внутри
  // растянутого viewBox вели себя непредсказуемо
  const x=ts[i]===null?(items.length<2?W/2:2+(i/(items.length-1))*96)
                      :2+((ts[i]-mn)/span)*96;
  const cy=20+(i%3-1)*9;
  const c=SEVCOL[a.severity]||'#eab308';
  const tip=(a.ts_sim||'')+' · '+(a.anomaly_type||a.subtype||'')+' · '+(a.severity||'')+' · '+(a.actor||'');
  dots+='<circle cx="'+x.toFixed(2)+'" cy="'+cy+'" r="2.6" fill="'+c+'" stroke="'+(isDark()?'#131a24':'#ffffff')+'" stroke-width="0.7"><title>'+tip+'</title></circle>';
 });
 el.innerHTML='<svg viewBox="0 0 '+W+' '+H+'" style="width:100%;height:64px;overflow:visible">'+
  '<line x1="2" y1="20" x2="98" y2="20" stroke="'+(isDark()?'#1f2a38':'#e3e8f0')+'" stroke-width="0.4"></line>'+dots+'</svg>'+
  '<div style="display:flex;justify-content:space-between;font-size:11px;color:#6b7789"><span>'+
  (items[0].ts_sim||'').replace('T',' ')+'</span><span>'+(items[items.length-1].ts_sim||'').replace('T',' ')+'</span></div>';}
async function pollInsights(){try{const d=await jget('/api/insights');
 drawHeat(d.heat||[],d.heat_anom||[]);drawAnomTimeline(d.anom_timeline||[]);
}catch(e){}}
pollInsights();setInterval(pollInsights,3000);

// ---------- Репозитории (живая карта) ----------
const ACT_ICON={push:['ic-push','+'],mr_open:['ic-open','MR'],mr_merge:['ic-merge','✓'],
 mr_close:['ic-close','✕'],branch_create:['ic-branch','⎇'],mr_comment:['ic-cmt','💬'],
 mr_approve:['ic-merge','👍'],issue_open:['ic-open','!'],issue_comment:['ic-cmt','💬'],issue_close:['ic-close','✕']};
const ACT_WORD={push:'файл',mr_open:'MR открыт',mr_merge:'MR смержен',mr_close:'MR закрыт',
 branch_create:'ветка',mr_comment:'коммент',mr_approve:'approve',issue_open:'issue',issue_comment:'коммент',issue_close:'issue закрыт'};
/* Экранирование значений, попадающих в разметку. Закрываем не только
   угловые скобки, но и кавычки с амперсандом: те же значения
   подставляются в атрибуты (title, href, onclick), где одинарной
   кавычки достаточно, чтобы разорвать разметку. Данные приходят из
   журнала как обычный текст, поэтому двойного экранирования не будет. */
const _ESC={'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'};
function esc(x){return (x==null?'':(''+x)).replace(/[&<>"']/g,c=>_ESC[c]);}
/* Значение внутри inline-обработчика. Браузер декодирует HTML-сущности
   ДО того, как разберёт JS, поэтому одного esc() мало: сначала
   экранируем как строку JS, потом как атрибут. */
function escJs(x){return esc(String(x==null?'':x).replace(/\\/g,'\\\\').replace(/'/g,"\\'"));}
function repoCard(name,d){
 const hot=(d.recent||[]).some(e=>e.is_anomaly);
 const mrs=(d.open_mrs||[]).map(m=>'<div class="mritem'+(m.is_anomaly?' anom':'')+'"><span class=iid>!'+m.iid+'</span>'+
   '<span class=txt style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(m.title||'merge request')+'</span>'+
   '<span class=who style="color:#9aa0ad;font-size:10px">@'+esc(m.actor||'')+'</span></div>').join('')
   || '<div class=rc-sub>нет открытых MR</div>';
 const feed=(d.recent||[]).map(e=>{const ic=ACT_ICON[e.action]||['ic-other','•'];
   const what=e.action==='push'?(e.path||'файл'):(e.message||ACT_WORD[e.action]||e.action);
   return '<div class="fchip'+(e.is_anomaly?' anom':'')+'"><span class="ic '+ic[0]+'">'+ic[1]+'</span>'+
    '<span class=txt>'+esc(what)+'</span><span class=who>@'+esc(e.actor||'')+' · '+((e.ts_sim||'').slice(11,16))+'</span></div>';}).join('')
   || '<div class=rc-sub>пока тихо</div>';
 return '<div class="repocard'+(hot?' hot':'')+'">'+
   '<div class=rc-head><div class=rc-ava style="background:'+colorFor(name)+'">'+name.slice(0,1).toUpperCase()+'</div>'+
     '<div><div class=rc-name>'+esc(name)+'</div><div class=rc-sub>'+(d.total||0)+' событий</div></div>'+
     '<span class=grow></span>'+
     '<button class="btn ghost ds-prof-btn" onclick="repoHealth(\''+escJs(name)+'\',_repoData[\''+escJs(name)+'\'])">здоровье</button>'+
     '</div>'+
   '<div class=rc-stats><span class=rc-stat>📄 <b>'+(d.files||0)+'</b> файлов</span>'+
     '<span class=rc-stat>↑ <b>'+(d.pushes||0)+'</b> пушей</span>'+
     '<span class=rc-stat>⇅ <b>'+(d.open_mrs||[]).length+'</b> откр. MR</span>'+
     '<span class=rc-stat>✓ <b>'+(d.mr_merge||0)+'</b></span>'+
     ((d.mr_close||0)?'<span class=rc-stat>✕ <b>'+d.mr_close+'</b></span>':'')+'</div>'+
   '<div class=rc-coltitle>Дерево файлов <span style="color:#c5cad6">(в этой сессии)</span></div>'+repoTree(d)+
   '<div class=rc-coltitle>Открытые merge request</div>'+mrs+
   '<div class=rc-coltitle>Последние события</div><div class=rc-feed>'+feed+'</div>'+
   '</div>';
}
function repoTree(d){
 const tree=d.tree||[]; const del=d.deleted_recent||[];
 const newset=new Set((d.recent||[]).filter(e=>e.action==='push'&&e.path).map(e=>e.path));
 if(!tree.length && !del.length) return '<div class="rc-tree tempty">пока пусто — файлы появятся при пушах</div>';
 const groups={};
 tree.forEach(p=>{const i=p.lastIndexOf('/');const dir=i<0?'/':p.slice(0,i);const f=i<0?p:p.slice(i+1);
   (groups[dir]=groups[dir]||[]).push([f,p]);});
 let html='';
 Object.keys(groups).sort().forEach(dir=>{
   html+='<div class=tfolder>'+(dir==='/'?'(корень)':'📁 '+esc(dir))+'</div>';
   groups[dir].forEach(([f,p])=>{ html+='<div class="tfile'+(newset.has(p)?' new':'')+'">'+esc(f)+'</div>'; });
 });
 del.forEach(x=>{ const p=x.path||''; const f=p.slice(p.lastIndexOf('/')+1);
   html+='<div class="tfile del" title="удалил @'+esc(x.actor||'')+'">'+esc(f)+'</div>'; });
 return '<div class=rc-tree>'+html+'</div>';
}
let repoSig='';
let _repoData={};
async function pollRepos(){try{const d=await jget('/api/repos');const r=d.repos||{};
 _repoData=r;   // нужен кнопке «здоровье» в карточке репозитория
 const names=Object.keys(r).filter(n=>r[n].total>0).sort((a,b)=>r[b].total-r[a].total);
 const rest=Object.keys(r).filter(n=>!r[n].total).sort();
 const order=names.concat(rest);
 const grid=$('repogrid');if(!grid)return;
 const sig=order.map(n=>n+':'+r[n].total+':'+(r[n].open_mrs||[]).length).join('|');
 if(sig===repoSig)return; repoSig=sig;
 grid.innerHTML=order.map(n=>repoCard(n,r[n])).join('')||'<div class=help style=color:#9aa0ad>запустите симуляцию — здесь появится живая карта</div>';
}catch(e){}}
pollRepos();setInterval(pollRepos,2500);
</script></body></html>"""


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
