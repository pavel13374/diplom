#!/usr/bin/env python3
"""
Веб-админка SOC-симулятора (красивый дашборд со слайдерами и пояснениями).

Запуск:  python webapp.py   (или run.bat)
Открыть: http://127.0.0.1:8787   (логин: admin / 123)
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
            start_sim = datetime.now().replace(
                hour=config.WORK_HOURS_START, minute=0, second=0, microsecond=0)
        self.clock = simclock.SimClock(
            start_sim=start_sim, scale=self.scale,
            work_start=config.WORK_HOURS_START, work_end=config.WORK_HOURS_END,
            work_days=config.WORK_DAYS, fast_forward_offhours=config.FAST_FORWARD_OFFHOURS,
            api_min_pause=config.API_MIN_PAUSE, max_real_sleep=config.MAX_REAL_SLEEP)
        simclock.init(self.clock)
        self.gl = GitLabClient(config.GITLAB_URL, config.ADMIN_TOKEN, ssl_verify=False)
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
        }


runner = Runner()

app = Flask(__name__)
app.secret_key = config.WEB_SECRET


def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not session.get("user"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "auth"}), 401
            return redirect(url_for("login"))
        return f(*a, **k)
    return w


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        if (request.form.get("username") == config.WEB_ADMIN_USER and
                request.form.get("password") == config.WEB_ADMIN_PASS):
            session["user"] = config.WEB_ADMIN_USER
            return redirect(url_for("dashboard"))
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
    if runner.running:
        return jsonify({"ok": False, "msg": "сначала останови симуляцию"})
    try:
        p = os.path.join(BASE_DIR, config.STATE_FILE)
        if os.path.exists(p):
            os.remove(p)
        return jsonify({"ok": True, "msg": "состояние сброшено"})
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)})


LOGIN_HTML = """<!doctype html><html lang=ru><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>SOC Simulator — вход</title>
<style>
:root{--accent:#5b5bd6;--ink:#1b1f2a;--muted:#6b7280;--line:#e7e9f0}
*{box-sizing:border-box}
body{margin:0;font-family:'Inter',-apple-system,Segoe UI,Roboto,sans-serif;
 background:#eef0f7;color:var(--ink);display:flex;min-height:100vh;align-items:center;justify-content:center}
.wrap{display:flex;width:760px;max-width:94vw;background:#fff;border-radius:20px;overflow:hidden;
 box-shadow:0 24px 70px rgba(27,31,42,.18);border:1px solid var(--line)}
.left{flex:1;padding:46px 40px;background:linear-gradient(160deg,#2a2c55,#1b1d35);color:#fff;display:flex;flex-direction:column;justify-content:center}
.left .logo{font-weight:800;font-size:22px;letter-spacing:.3px}
.left .tag{margin-top:14px;color:#b9bce0;font-size:14px;line-height:1.6}
.left ul{margin:22px 0 0;padding:0;list-style:none;color:#cfd2f0;font-size:13px}
.left li{margin:9px 0;padding-left:22px;position:relative}
.left li:before{content:'';position:absolute;left:0;top:6px;width:8px;height:8px;border-radius:50%;background:#6d6df0}
.right{flex:1;padding:46px 40px;display:flex;flex-direction:column;justify-content:center}
h1{font-size:21px;margin:0 0 6px}.sub{color:var(--muted);font-size:13px;margin:0 0 26px}
label{display:block;font-size:12px;color:var(--muted);margin:16px 0 7px;font-weight:600}
input{width:100%;padding:12px 13px;border-radius:11px;border:1px solid var(--line);background:#fafbff;font-size:14px}
input:focus{outline:none;border-color:var(--accent);background:#fff;box-shadow:0 0 0 4px #5b5bd61f}
button{width:100%;margin-top:26px;padding:13px;border:0;border-radius:11px;background:var(--accent);color:#fff;
 font-size:15px;font-weight:700;cursor:pointer;transition:.15s}button:hover{background:#4b4bc4}
.err{color:#dc2626;font-size:13px;margin-top:14px;min-height:18px;text-align:center}
.hint{margin-top:16px;text-align:center;color:#9aa0ad;font-size:12px}
@media(max-width:680px){.left{display:none}}
</style></head><body>
<div class=wrap>
 <div class=left>
   <div class=logo>SOC&nbsp;·&nbsp;Simulator</div>
   <div class=tag>Платформа управления симуляцией работы<br>SOC-команды в GitLab.</div>
   <ul><li>Сжатие времени и таймлапс</li><li>Полный журнал событий</li><li>Тонкая настройка поведения</li></ul>
 </div>
 <form class=right method=post>
   <h1>Вход в панель</h1><div class=sub>Авторизуйтесь для управления симуляцией</div>
   <label>Логин</label><input name=username autofocus autocomplete=off>
   <label>Пароль</label><input name=password type=password>
   <button type=submit>Войти</button>
   <div class=err>{{ERROR}}</div>
   <div class=hint>учётные данные по умолчанию — admin / 123</div>
 </form>
</div></body></html>"""


DASH_HTML = r"""<!doctype html><html lang=ru><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>SOC Simulator</title>
<style>
:root{
 --bg:#f4f5fb;--panel:#ffffff;--ink:#1b1f2a;--muted:#6b7280;--soft:#9aa0ad;
 --line:#e8eaf2;--accent:#5b5bd6;--accent-soft:#ececfb;--teal:#0ea5a4;
 --ok:#16a34a;--warn:#d97706;--bad:#dc2626;
 --shadow:0 1px 2px rgba(16,24,40,.04),0 6px 20px rgba(16,24,40,.06);
 --radius:14px;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
 font-family:'Inter',-apple-system,Segoe UI,Roboto,sans-serif;font-size:14px}
.app{display:grid;grid-template-columns:248px 1fr;min-height:100vh}
/* sidebar */
.side{background:linear-gradient(176deg,#26284e,#1a1c33);color:#cdd0ee;display:flex;flex-direction:column;padding:20px 16px;position:sticky;top:0;height:100vh}
.brand{display:flex;align-items:center;gap:10px;font-weight:800;font-size:17px;color:#fff;padding:6px 8px 18px}
.brand .mk{width:30px;height:30px;border-radius:9px;background:linear-gradient(135deg,#6d6df0,#0ea5a4);display:flex;align-items:center;justify-content:center;font-size:16px}
.nav{display:flex;flex-direction:column;gap:4px;margin-top:6px}
.nav a{display:flex;align-items:center;gap:11px;padding:11px 12px;border-radius:10px;color:#b6b9e0;
 text-decoration:none;font-weight:600;font-size:13.5px;cursor:pointer;transition:.15s}
.nav a svg{width:18px;height:18px;opacity:.85}
.nav a:hover{background:#ffffff14;color:#fff}
.nav a.active{background:#ffffff1f;color:#fff}
.nav a.active svg{opacity:1}
.side-foot{margin-top:auto;border-top:1px solid #ffffff1f;padding-top:14px;font-size:12px;color:#9a9ec9}
.side-foot .st{display:flex;align-items:center;gap:8px;margin-bottom:10px}
.side-foot a{color:#b6b9e0;text-decoration:none}.side-foot a:hover{color:#fff}
.run-dot{width:9px;height:9px;border-radius:50%;background:#6b7280}.run-dot.on{background:#34d399;box-shadow:0 0 0 4px #34d39933}
/* main */
.main{padding:0}
.topbar{position:sticky;top:0;z-index:10;background:#f4f5fbf2;backdrop-filter:blur(8px);
 border-bottom:1px solid var(--line);display:flex;align-items:center;gap:14px;padding:16px 28px}
.topbar h1{font-size:18px;margin:0;font-weight:700}
.grow{flex:1}
.pill{display:inline-flex;align-items:center;gap:7px;padding:5px 11px;border-radius:20px;font-size:12px;font-weight:600;border:1px solid var(--line);background:#fff}
.pill .d{width:7px;height:7px;border-radius:50%;background:#9aa0ad}
.pill.ok .d{background:var(--ok)}.pill.bad .d{background:var(--bad)}
.pill.work{background:#eef2ff;border-color:#dfe4ff;color:#3730a3}.pill.work .d{background:#4f46e5}
.pill.rest{background:#fff7ed;border-color:#fde7c8;color:#9a5b09}.pill.rest .d{background:#d97706}
.btn{padding:9px 15px;border:1px solid var(--line);border-radius:10px;background:#fff;color:var(--ink);
 font-size:13px;font-weight:600;cursor:pointer;transition:.15s}
.btn:hover{border-color:#cdd0e0}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}.btn.primary:hover{background:#4b4bc4}
.btn.danger{background:#fff;border-color:#f3c0c0;color:var(--bad)}.btn.danger:hover{background:#fef2f2}
.content{padding:24px 28px 60px;max-width:1180px}
.view{display:none}.view.active{display:block}
.section-title{font-size:13px;font-weight:700;color:var(--soft);text-transform:uppercase;letter-spacing:.06em;margin:26px 2px 12px}
.sevdot{width:10px;height:10px;border-radius:50%;display:inline-block;margin-right:5px;vertical-align:middle}
.hmcell{width:17px;height:17px;border-radius:3px;display:inline-block}
.hmrow{display:flex;gap:2px;align-items:center;margin-bottom:2px}
.hmlab{width:34px;font-size:11px;color:#6b7180;text-align:right;padding-right:6px}
.arnode{font-size:12px;fill:#42485a}
/* cards */
.clocks{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}
.clock{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:18px 20px;box-shadow:var(--shadow)}
.clock .lab{font-size:12px;color:var(--muted);font-weight:600;display:flex;align-items:center;gap:8px}
.clock .lab .ic{width:26px;height:26px;border-radius:8px;display:flex;align-items:center;justify-content:center;background:var(--accent-soft);color:var(--accent)}
.clock .val{font-size:24px;font-weight:800;margin-top:12px;font-variant-numeric:tabular-nums;letter-spacing:.2px}
.clock .sub{font-size:12px;color:var(--soft);margin-top:4px}
.clock.sim{background:linear-gradient(160deg,#2a2c55,#1b1d35);border:0;color:#fff}
.clock.sim .lab{color:#b9bce0}.clock.sim .lab .ic{background:#ffffff1f;color:#fff}
.clock.sim .val{color:#fff}.clock.sim .sub{color:#9a9ec9}
.kpis{display:grid;grid-template-columns:repeat(6,1fr);gap:14px;margin-top:16px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px;box-shadow:var(--shadow)}
.kpi .n{font-size:24px;font-weight:800;font-variant-numeric:tabular-nums}
.kpi .l{font-size:11.5px;color:var(--muted);margin-top:3px;font-weight:600}
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
.badge.oc{background:#ede9fe;color:#6d28d9}.badge.pt{background:#fff7ed;color:#b45309}
.badge.wk{background:#ecfdf3;color:#15803d}
.acts{display:flex;flex-direction:column;gap:8px}
.act{display:grid;grid-template-columns:1fr auto;gap:4px;font-size:13px}
.act .bar{grid-column:1/3;height:6px;border-radius:6px;background:#eef0f7;overflow:hidden}
.act .bar i{display:block;height:100%;background:linear-gradient(90deg,#6d6df0,#0ea5a4);border-radius:6px}
.banner{margin-top:16px;background:#fff;border:1px solid var(--line);border-left:3px solid var(--accent);
 border-radius:12px;padding:14px 16px;font-size:13px;color:#42485a;line-height:1.6;box-shadow:var(--shadow)}
.banner code{background:#f1f2f8;padding:1px 6px;border-radius:5px;font-size:12px}
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
.tin,select{padding:10px 12px;border:1px solid var(--line);border-radius:10px;background:#fafbff;font-size:13px;width:100%;color:var(--ink)}
.tin:focus,select:focus{outline:none;border-color:var(--accent);background:#fff;box-shadow:0 0 0 4px #5b5bd61a}
.switch-field{flex-direction:row;align-items:center;justify-content:space-between;gap:14px}
.sw-txt label{display:block}.sw-txt .help{margin-top:3px}
.switch{position:relative;width:46px;height:26px;flex:none}
.switch input{opacity:0;width:0;height:0}
.track{position:absolute;inset:0;background:#d7dae6;border-radius:30px;transition:.2s}
.track:before{content:'';position:absolute;width:20px;height:20px;left:3px;top:3px;background:#fff;border-radius:50%;transition:.2s;box-shadow:0 1px 3px rgba(0,0,0,.2)}
.switch input:checked+.track{background:var(--accent)}
.switch input:checked+.track:before{transform:translateX(20px)}
.days{display:flex;gap:7px;flex-wrap:wrap}
.day{padding:8px 13px;border:1px solid var(--line);border-radius:9px;cursor:pointer;font-size:13px;font-weight:600;user-select:none;color:var(--muted)}
.day input{display:none}.day.act{background:var(--accent);border-color:var(--accent);color:#fff}
.presets{display:flex;gap:9px;flex-wrap:wrap;margin:4px 0 4px}
.chip{padding:8px 14px;border:1px solid var(--line);border-radius:20px;background:#fff;font-size:12.5px;font-weight:600;cursor:pointer;transition:.15s}
.chip:hover{border-color:var(--accent);color:var(--accent)}
.tlinfo{background:#f8f9ff;border:1px dashed #cfd2ef;border-radius:11px;padding:12px 14px;font-size:13px;color:#42485a;margin:14px 0 4px}
.savebar{position:sticky;bottom:0;display:flex;gap:14px;align-items:center;background:#f4f5fbf2;backdrop-filter:blur(6px);
 border-top:1px solid var(--line);padding:14px 2px;margin-top:8px}
.toast{color:var(--ok);font-size:13px;font-weight:600}
.people{display:grid;grid-template-columns:repeat(auto-fill,minmax(440px,1fr));gap:16px}
.pcard{background:var(--panel);border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow);overflow:hidden}
.phead{display:flex;align-items:center;gap:12px;padding:14px 16px;cursor:pointer}
.phead:hover{background:#fafbff}
.pinfo{flex:1}.pinfo .m-name{font-weight:700}.pinfo .m-role{font-size:12px;color:var(--muted)}
.pmeta{display:flex;gap:10px;font-size:12px;color:var(--muted);font-variant-numeric:tabular-nums}
.pmeta b{color:var(--ink)}
.pchev{color:var(--soft);transition:.2s}.pcard.open .pchev{transform:rotate(180deg)}
.pbody{display:none;border-top:1px solid var(--line);padding:12px 16px;background:#fbfcff}
.pcard.open .pbody{display:block}
.pcur{font-size:13px;margin-bottom:10px;color:#42485a}
.feed{display:flex;flex-direction:column;gap:3px;max-height:320px;overflow:auto;font-size:12px}
.frow{display:grid;grid-template-columns:44px 92px 120px 1fr auto;gap:8px;align-items:center;padding:5px 8px;border-radius:7px;background:#fff;border:1px solid var(--line)}
.frow.anom{background:#fef2f2;border-color:#f3c0c0}.frow.look{background:#fff7ed;border-color:#fde7c8}
.frow .mono{font-family:'JetBrains Mono',Consolas,monospace;color:var(--muted)}
.frow .path{color:#475069}.frow .atag{font-size:10px;font-weight:700;color:#b42318}
.pbadge{font-size:11px;font-weight:700;padding:3px 9px;border-radius:20px}
.pbadge.oc{background:#ede9fe;color:#6d28d9}.pbadge.pt{background:#fff7ed;color:#b45309}
.pbadge.wk{background:#ecfdf3;color:#15803d}.pbadge.idle{background:#f1f2f8;color:#6b7280}
.evtable{display:flex;flex-direction:column;gap:4px;max-height:420px;overflow:auto;margin-top:12px;font-size:12.5px}
.evrow{display:grid;grid-template-columns:120px 92px 132px 1fr auto;gap:10px;align-items:center;padding:6px 10px;border-radius:8px;background:#fafbff;border:1px solid var(--line)}
.evrow.anom{background:#fef2f2;border-color:#f3c0c0}
.evrow.look{background:#fff7ed;border-color:#fde7c8}
.evrow .mono{font-family:'JetBrains Mono',Consolas,monospace;color:var(--muted)}
.evrow .atag{font-size:11px;font-weight:700;color:#b42318}
.spark-head{display:flex;align-items:baseline;gap:12px}
.spark-now{margin-left:auto;font-size:13px;font-weight:700;color:var(--accent);background:var(--accent-soft);padding:2px 11px;border-radius:8px}
.spark-wrap{margin-top:16px;height:130px;width:100%}
#spark{width:100%;height:100%;display:block}
.spark-axis{display:flex;justify-content:space-between;margin-top:10px;font-size:12px;color:var(--soft);font-variant-numeric:tabular-nums}
.spark-axis .mid{color:var(--muted)}
/* console */
.console{background:#14161f;border:1px solid #20232e;border-radius:var(--radius);height:480px;overflow:auto;padding:14px 16px;
 font-family:'JetBrains Mono','Cascadia Code',Consolas,monospace;font-size:12.5px;line-height:1.6}
.console .line{white-space:pre-wrap;word-break:break-word}
.lt{color:#5b6170}
.l-INFO{color:#c8cdda}.l-WARNING{color:#e0a83a}.l-ERROR{color:#f06565}.l-DEBUG{color:#5b6170}
@media(max-width:1000px){.app{grid-template-columns:1fr}.side{position:static;height:auto;flex-direction:row;flex-wrap:wrap}.kpis{grid-template-columns:repeat(3,1fr)}.clocks,.grid2{grid-template-columns:1fr}}
</style></head><body>
<div class=app>
  <aside class=side>
    <div class=brand><span class=mk>◆</span> SOC Simulator</div>
    <nav class=nav>
      <a class=active data-view=overview><svg viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2><rect x=3 y=3 width=7 height=7 rx=1/><rect x=14 y=3 width=7 height=7 rx=1/><rect x=14 y=14 width=7 height=7 rx=1/><rect x=3 y=14 width=7 height=7 rx=1/></svg> Обзор</a>
      <a data-view=config><svg viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2><line x1=4 y1=21 x2=4 y2=14/><line x1=4 y1=10 x2=4 y2=3/><line x1=12 y1=21 x2=12 y2=12/><line x1=12 y1=8 x2=12 y2=3/><line x1=20 y1=21 x2=20 y2=16/><line x1=20 y1=12 x2=20 y2=3/><line x1=1 y1=14 x2=7 y2=14/><line x1=9 y1=8 x2=15 y2=8/><line x1=17 y1=16 x2=23 y2=16/></svg> Конфигурация</a>
      <a data-view=logs><svg viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2><polyline points="4 17 10 11 4 5"/><line x1=12 y1=19 x2=20 y2=19/></svg> Журнал событий</a>
      <a data-view=data><svg viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2><ellipse cx=12 cy=5 rx=9 ry=3/><path d="M3 5v14c0 1.7 4 3 9 3s9-1.3 9-3V5"/><path d="M3 12c0 1.7 4 3 9 3s9-1.3 9-3"/></svg> Данные · датасет</a>
      <a data-view=insights><svg viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2><line x1=18 y1=20 x2=18 y2=10/><line x1=12 y1=20 x2=12 y2=4/><line x1=6 y1=20 x2=6 y2=14/></svg> Аналитика</a>
      <a data-view=people><svg viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx=9 cy=7 r=4/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg> Сотрудники</a>
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
      <span class="pill" id=connPill><span class=d></span><span id=connTxt>—</span></span>
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

        <div class=panel id=chartPanel style=margin-top:16px>
          <div class=spark-head><h2 style=margin:0>Динамика действий</h2>
            <span class=sub style=margin:0>число действий за интервал по времени симуляции</span>
            <span class=spark-now id=spkNow>нет данных</span></div>
          <div class=spark-wrap><svg id=spark viewBox="0 0 100 34" preserveAspectRatio=none></svg></div>
          <div class=spark-axis><span id=spkFrom>—</span><span class=mid id=spkMid></span><span id=spkTo>—</span></div>
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
            <div class=sub>Текущие параметры времени и работы команды.</div>
            <div class=kv>
              <b>Статус дня</b><span id=dayStatus>—</span>
              <b>Рабочие часы</b><span id=workHours>—</span>
              <b>Сжатие времени</b><span id=tl>—</span>
              <b>Вне рабочих часов</b><span id=ohm>—</span>
              <b>Даты в GitLab</b><span id=gld>—</span>
              <b>Текущее действие</b><span id=lastAct>—</span>
              <b>Время работы</b><span id=uptime>—</span>
            </div>
          </div>
          <div class=panel><h2>Команда</h2>
            <div class=sub>Кто сейчас на смене, дежурит и в отпуске.</div>
            <div class=members id=team></div>
            <div class=kv style=margin-top:14px>
              <b>Дежурный (on-call)</b><span id=oncall>—</span>
              <b>В отпуске</b><span id=pto>—</span></div>
          </div>
        </div>

        <div class=grid2>
          <div class=panel><h2>Распределение действий</h2>
            <div class=sub>Сколько раз выполнялся каждый тип активности.</div>
            <div class=acts id=acts></div>
          </div>
          <div class=panel><h2>О согласовании времени</h2>
            <div class=sub>Почему время симуляции и время GitLab различаются.</div>
            <div style="font-size:13px;color:#42485a;line-height:1.65">
              Симуляция идёт по ускоренному внутреннему времени, но отметки коммитов всегда
              ставит сам GitLab-сервер по своим часам — через API их изменить нельзя.
              Поэтому даты, записываемые в GitLab (даты правил, время создания тикетов),
              по умолчанию берутся из реального времени (<code>GITLAB_DATES = real</code>) —
              так история в GitLab остаётся согласованной. Внутреннее время используется
              для расписания, журнала и этого дашборда.
            </div>
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
      </section>

      <!-- ЖУРНАЛ -->
      <section class=view id=v-logs>
        <div class=panel style=margin-bottom:16px>
          <h2>Журнал событий</h2>
          <div class=sub>Поток действий симуляции в реальном времени. Также пишется в файл simulator.log.</div>
          <div class=console id=console></div>
          <div style="display:flex;gap:10px;align-items:center;margin-top:12px;flex-wrap:wrap">
            <a class="btn" id=btnRunlog href="/api/runlog">Скачать полный лог прогона</a>
            <button class="btn primary" id=btnTg>Отправить отчёт в Telegram</button>
            <span class=toast id=tgToast></span>
            <span class=grow></span>
            <span class=sub id=logCounts style=margin:0></span>
          </div>
        </div>
        <div class=panel><h2>Сброс состояния</h2>
          <div class=sub>Удаляет накопленную память (правила, спринты, ротации) — симуляция начнётся с чистого листа. Доступно только когда симуляция остановлена.</div>
          <button class="btn danger" id=btnReset>Сбросить состояние</button>
        </div>
      </section>

      <section class=view id=v-people>
        <div class=cfg-intro>Нажмите на сотрудника, чтобы раскрыть живую ленту — что и куда он заливает в реальном времени.</div>
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
            <div class=sub>Размеченные инциденты — будущий положительный класс для модели.</div>
            <div class=acts id=evByType></div></div>
          <div class=panel><h2>Датасет</h2>
            <div class=sub>Каждое действие пишется строкой JSON с sim-временем, актором и метками.</div>
            <div class=kv><b>Файл</b><span id=evFile>—</span><b>Запуск</b><span id=evRun>—</span></div>
            <div style=margin-top:14px><a class="btn primary" id=btnDataset href=/api/dataset>Скачать events.jsonl</a></div>
            <div class=sub style=margin-top:12px>Файл накапливается между запусками (каждая строка помечена run_id).</div></div>
        </div>
        <div class=panel style=margin-top:16px><h2>Последние события</h2>
          <div class=sub>Аномалии подсвечены красным, benign-лукалайки — янтарным.</div>
          <div class=evtable id=evList></div></div>
      </section>

      <!-- АНАЛИТИКА -->
      <section class=view id=v-insights>
        <div class=panel style=margin-bottom:16px>
          <h2>Карта активности · часы × дни недели</h2>
          <div class=sub>Ритм работы команды по времени симуляции. Темнее — больше действий;
            красная рамка — в этот час были аномалии. Видны рабочее окно и ночные всплески.</div>
          <div id=heatmap style=margin-top:14px;overflow-x:auto></div>
          <div style="display:flex;gap:14px;align-items:center;margin-top:10px;font-size:12px;color:#6b7180">
            <span>меньше</span>
            <span style="display:inline-flex;gap:3px">
              <i style="width:14px;height:14px;border-radius:3px;background:#eef0f7"></i>
              <i style="width:14px;height:14px;border-radius:3px;background:#c7d2fe"></i>
              <i style="width:14px;height:14px;border-radius:3px;background:#818cf8"></i>
              <i style="width:14px;height:14px;border-radius:3px;background:#4f46e5"></i>
              <i style="width:14px;height:14px;border-radius:3px;background:#312e81"></i>
            </span>
            <span>больше</span>
            <span style="margin-left:14px"><i style="width:14px;height:14px;border-radius:3px;border:2px solid #ef4444;display:inline-block;vertical-align:middle"></i> были аномалии</span>
          </div>
        </div>

        <div class=grid2>
          <div class=panel><h2>Таймлайн аномалий</h2>
            <div class=sub>Размеченные инциденты во времени симуляции, цвет — по severity.</div>
            <div id=anomTimeline style=margin-top:12px></div>
            <div style="display:flex;gap:14px;margin-top:10px;font-size:12px;color:#6b7180;flex-wrap:wrap">
              <span><i class=sevdot style=background:#dc2626></i> critical</span>
              <span><i class=sevdot style=background:#f59e0b></i> high</span>
              <span><i class=sevdot style=background:#eab308></i> medium</span>
              <span><i class=sevdot style=background:#64748b></i> low</span>
            </div>
          </div>
          <div class=panel><h2>Качество детектора</h2>
            <div class=sub>Метрики появятся, когда подключишь ML/правило-детектор
              (см. <code>rule_baseline.py</code> и <code>export_dataset.py</code>).</div>
            <div class=kpis style=grid-template-columns:repeat(2,1fr);margin-top:8px>
              <div class=kpi><div class=n id=mPrec>—</div><div class=l>Precision</div></div>
              <div class=kpi><div class=n id=mRec>—</div><div class=l>Recall</div></div>
              <div class=kpi><div class=n id=mF1>—</div><div class=l>F1</div></div>
              <div class=kpi><div class=n id=mAnom>—</div><div class=l>Инцидентов всего</div></div>
            </div>
            <div class=sub style=margin-top:12px>Пока детектор не подключён, заполнено
              только число размеченных инцидентов.</div>
          </div>
        </div>

        <div class=panel style=margin-top:16px>
          <h2>Кто в каком репозитории · actor ↔ repo</h2>
          <div class=sub>Двудольный граф взаимодействий — основа UEBA-нарратива.
            Толщина связи ∝ числу действий актора в репозитории.</div>
          <div id=arGraph style=margin-top:12px;overflow-x:auto></div>
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
const TITLES={overview:'Обзор',config:'Конфигурация',logs:'Журнал событий',data:'Данные · датасет для ML',insights:'Аналитика',people:'Сотрудники · слежение'};
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
 $('connPill').className='pill '+(s.conn_ok==null?'':(s.conn_ok?'ok':'bad'));
 $('connTxt').textContent=s.conn_ok==null?'не запущено':(s.conn_ok?'GitLab на связи':'GitLab недоступен');
 $('workPill').className='pill '+(s.is_work?'work':'rest');
 $('workTxt').textContent=s.is_work?'рабочее время':'нерабочее время';
 $('realTime').textContent=s.real_time;$('simTime').textContent=s.sim_time;$('glTime').textContent=s.gitlab_time||'—';
 $('dayStatus').textContent=s.is_work?'рабочий день':'нерабочее время';
 $('workHours').textContent=s.work_hours;
 $('tl').textContent=s.timelapse?('×'+s.scale+' · день ≈ '+s.workday_min+' мин'):'выключено';
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
 $('acts').innerHTML=keys.length?keys.map(k=>'<div class=act><span>'+(ACT_HELP[k]||k)+'</span><b>'+a[k]+'</b><div class=bar><i style=width:'+(a[k]/mx*100)+'%></i></div></div>').join(''):'<div class=help style=color:#9aa0ad>пока нет данных — запустите симуляцию</div>';
}
function drawSpark(series){
 const svg=$('spark');if(!svg)return;
 if(!series||!series.length){svg.innerHTML='';$('spkFrom').textContent='—';$('spkTo').textContent='—';$('spkNow').textContent='нет данных';return;}
 const W=100,H=34,pad=2,n=series.length,max=Math.max(1,...series.map(s=>s.n));
 const X=i=>n<=1?0:(i/(n-1))*W, Y=v=>H-pad-(v/max)*(H-2*pad);
 let line='';series.forEach((s,i)=>{line+=(i?'L':'M')+X(i).toFixed(2)+' '+Y(s.n).toFixed(2)+' ';});
 const area='M0 '+H+' '+series.map((s,i)=>'L'+X(i).toFixed(2)+' '+Y(s.n).toFixed(2)).join(' ')+' L'+W+' '+H+' Z';
 svg.innerHTML='<defs><linearGradient id=sg x1=0 y1=0 x2=0 y2=1>'+
  '<stop offset=0% stop-color=#5b5bd6 stop-opacity=0.35/><stop offset=100% stop-color=#5b5bd6 stop-opacity=0/></linearGradient></defs>'+
  '<path d="'+area+'" fill=url(#sg)/>'+
  '<path d="'+line+'" fill=none stroke=#5b5bd6 stroke-width=1 stroke-linejoin=round stroke-linecap=round vector-effect=non-scaling-stroke/>';
 $('spkFrom').textContent=series[0].sim;
 $('spkTo').textContent=series[n-1].sim;
 $('spkNow').textContent=series[n-1].n+' за интервал · всего '+series[n-1].total;
}
async function pollSeries(){try{const d=await jget('/api/series');drawSpark(d.series);if($('spkMid'))$('spkMid').textContent=d.scale?('масштаб ×'+d.scale):'';}catch(e){}}
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
    '<div class=pmeta id="meta_'+id+'"></div><div id="bdg_'+id+'"></div><span class=pchev>&#9662;</span></div>'+
    '<div class=pbody id="body_'+id+'"></div></div>';}).join('');}
 team.forEach(m=>{const id=cssId(m.username);const st=m.stats||{};
  const meta=document.getElementById('meta_'+id);if(meta)meta.innerHTML='&#8593; <b>'+(st.pushes||0)+'</b> &middot; MR <b>'+(st.mrs||0)+'</b> &middot; &#9888; <b>'+(st.anomalies||0)+'</b>';
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
$('btnReset').onclick=async()=>{const r=await jpost('/api/reset_state');alert(r.msg);};
if($('btnTg'))$('btnTg').onclick=async()=>{$('tgToast').textContent='отправляю…';const r=await jpost('/api/tg_report');$('tgToast').textContent=r.msg||'';setTimeout(()=>$('tgToast').textContent='',4000);};
$('btnSave').onclick=save;
$('btnReload').onclick=()=>jget('/api/config').then(renderCfg);
jget('/api/config').then(renderCfg);
tick();setInterval(tick,1500);
pollLogs();setInterval(pollLogs,1000);
async function pollEvents(){try{const d=await jget('/api/events?n=120');const st=d.stats||{};
 $('evTotal').textContent=st.total||0;$('evAnom').textContent=st.anomalies||0;
 $('evRate').textContent=st.total?((st.anomalies/st.total*100).toFixed(1)+'%'):'0%';
 const bt=st.by_anomaly||{};const bk=Object.keys(bt);$('evTypes').textContent=bk.length;
 $('evFile').textContent=st.file||'—';$('evRun').textContent=st.run_id||'—';
 const mx=Math.max(1,...bk.map(k=>bt[k]));
 $('evByType').innerHTML=bk.length?bk.sort((a,b)=>bt[b]-bt[a]).map(k=>'<div class=act><span>'+k+'</span><b>'+bt[k]+'</b><div class=bar><i style="width:'+(bt[k]/mx*100)+'%;background:linear-gradient(90deg,#e8590c,#d6336c)"></i></div></div>').join(''):'<div class=help style=color:#9aa0ad>аномалий пока нет</div>';
 const items=(d.items||[]).slice().reverse();
 $('evList').innerHTML=items.length?items.map(e=>{const cls=e.is_anomaly?'anom':(e.lookalike?'look':'');
  return '<div class="evrow '+cls+'"><span class=mono>'+(e.ts_sim||'').replace('T',' ').slice(5)+'</span>'+
   '<span>'+(e.actor||'')+'</span><span class=mono>'+(e.action||'')+'</span>'+
   '<span class=mono>'+((e.path||e.project||'')+'').slice(0,60)+'</span>'+
   '<span class=atag>'+(e.anomaly_type||(e.lookalike?'lookalike':''))+'</span></div>';}).join(''):'<div class=help style=color:#9aa0ad>событий пока нет — запустите симуляцию</div>';
}catch(e){}}
pollSeries();setInterval(pollSeries,2000);
pollEvents();setInterval(pollEvents,2000);
setInterval(()=>openUsers.forEach(refreshActor),2000);

// ---------- Аналитика ----------
const DOW=['Пн','Вт','Ср','Чт','Пт','Сб','Вс'];
const SEVCOL={critical:'#dc2626',high:'#f59e0b',medium:'#eab308',low:'#64748b'};
function heatColor(v,mx){if(!v)return '#eef0f7';const t=v/mx;
 return t>0.75?'#312e81':t>0.5?'#4f46e5':t>0.25?'#818cf8':'#c7d2fe';}
function drawHeat(grid,agrid){const el=$('heatmap');if(!el)return;
 let mx=1;grid.forEach(r=>r.forEach(v=>{if(v>mx)mx=v;}));
 let h='<div class=hmrow><div class=hmlab></div>'+Array.from({length:24},(_,x)=>'<div style="width:17px;font-size:9px;color:#9aa0ad;text-align:center">'+(x%3===0?x:'')+'</div>').join('')+'</div>';
 for(let d=0;d<7;d++){h+='<div class=hmrow><div class=hmlab>'+DOW[d]+'</div>';
  for(let x=0;x<24;x++){const v=grid[d][x],a=agrid[d][x];
   h+='<div class=hmcell title="'+DOW[d]+' '+x+':00 — '+v+' действий'+(a?(', '+a+' аномал.'):'')+'" style="background:'+heatColor(v,mx)+(a?';box-shadow:0 0 0 2px #ef4444 inset':'')+'"></div>';}
  h+='</div>';}
 el.innerHTML=h;}
function drawAnomTimeline(items){const el=$('anomTimeline');if(!el)return;
 if(!items||!items.length){el.innerHTML='<div class=help style=color:#9aa0ad>аномалий пока нет</div>';return;}
 const ts=items.map(a=>Date.parse((a.ts_sim||'').replace('T',' '))||0);
 const mn=Math.min(...ts),mx=Math.max(...ts),span=Math.max(1,mx-mn);
 const W=100,H=46;
 let dots='';items.forEach((a,i)=>{const x=((ts[i]-mn)/span)*96+2;
  const c=SEVCOL[a.severity]||'#eab308';
  dots+='<circle cx="'+x.toFixed(2)+'%" cy="'+(20+(i%3-1)*9)+'" r="4" fill="'+c+'"><title>'+(a.ts_sim||'')+' · '+(a.anomaly_type||a.subtype||'')+' · '+(a.severity||'')+' · '+(a.actor||'')+'</title></circle>';});
 el.innerHTML='<svg viewBox="0 0 '+W+' '+H+'" preserveAspectRatio=none style="width:100%;height:64px">'+
  '<line x1=2 y1=20 x2=98 y2=20 stroke=#e7e9f3 stroke-width=0.4 vector-effect=non-scaling-stroke/>'+dots+'</svg>'+
  '<div style="display:flex;justify-content:space-between;font-size:11px;color:#9aa0ad"><span>'+(items[0].ts_sim||'').replace('T',' ')+'</span><span>'+(items[items.length-1].ts_sim||'').replace('T',' ')+'</span></div>';}
function drawArGraph(edges){const el=$('arGraph');if(!el)return;
 if(!edges||!edges.length){el.innerHTML='<div class=help style=color:#9aa0ad>пока нет данных</div>';return;}
 edges=edges.slice(0,60);
 const actors=[...new Set(edges.map(e=>e.actor))],repos=[...new Set(edges.map(e=>e.repo))];
 const rowH=26,H=Math.max(actors.length,repos.length)*rowH+20,W=560,xa=150,xr=W-150;
 const ya={},yr={};actors.forEach((a,i)=>ya[a]=20+i*rowH);repos.forEach((r,i)=>yr[r]=20+i*rowH);
 const mxn=Math.max(...edges.map(e=>e.n));
 let svg='<svg viewBox="0 0 '+W+' '+H+'" style="width:100%;min-width:560px;height:'+H+'px">';
 edges.forEach(e=>{const w=0.6+(e.n/mxn)*3.2;
  svg+='<line x1='+xa+' y1='+ya[e.actor]+' x2='+xr+' y2='+yr[e.repo]+' stroke=#6366f1 stroke-opacity=0.28 stroke-width='+w.toFixed(2)+'><title>'+e.actor+' → '+e.repo+': '+e.n+'</title></line>';});
 actors.forEach(a=>{svg+='<circle cx='+xa+' cy='+ya[a]+' r=4 fill=#4f46e5/><text class=arnode x='+(xa-9)+' y='+(ya[a]+4)+' text-anchor=end>'+a+'</text>';});
 repos.forEach(r=>{svg+='<circle cx='+xr+' cy='+yr[r]+' r=4 fill=#0ea5e9/><text class=arnode x='+(xr+9)+' y='+(yr[r]+4)+'>'+r+'</text>';});
 el.innerHTML=svg+'</svg>';}
async function pollInsights(){try{const d=await jget('/api/insights');
 drawHeat(d.heat||[],d.heat_anom||[]);drawAnomTimeline(d.anom_timeline||[]);drawArGraph(d.edges||[]);
 if($('mAnom'))$('mAnom').textContent=(d.anom_timeline||[]).length;
}catch(e){}}
pollInsights();setInterval(pollInsights,3000);
</script></body></html>"""


def main():
    print("=" * 56)
    print("  SOC Simulator — веб-панель")
    print(f"  Откройте: http://{config.WEB_HOST}:{config.WEB_PORT}")
    print(f"  Логин/пароль: {config.WEB_ADMIN_USER} / {config.WEB_ADMIN_PASS}")
    print("=" * 56)
    app.run(host=config.WEB_HOST, port=config.WEB_PORT,
            threaded=True, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
