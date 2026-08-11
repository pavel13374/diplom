import os.path as _os_path
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PURPLE TEAM CONSOLE (контур «ЗАЩИТА») — порт 8788.

Полноценная SOC-консоль над общим event-store:
  • стрим-ингестор читает поток по курсору (переживает рестарт);
  • Detection Stack (detector.py: L0 правила + L1 UEBA + fusion) даёт алерты;
  • Correlator (correlator.py) склеивает алерты в ИНЦИДЕНТЫ с ATT&CK-цепочкой;
  • вкладки: Обзор/Scoreboard · Алерты · Инциденты · ATT&CK Coverage · Детекты · Red.

«Мир» (8787) не трогаем; управление — через очередь команд в event-store
(кнопка «Запустить кампанию» ставит команду, мир её исполняет).

АНТИ-ЛИК: детектор и корреляция работают только на наблюдаемых полях
(run_defense.observed срезает разметку мира).
"""
import sys
import time
import threading
from datetime import datetime, timedelta
import collections
import json

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

from flask import Flask, jsonify, request, session, redirect, url_for
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
                         "templates", "console")
_TPL_CACHE = {}


def _tpl(name):
    """Прочитать шаблон. Кэш в памяти, но сбрасывается при правке файла.

    Раньше кэш был вечным: перезагрузчик Flask перезапускает процесс
    только на изменение .py, поэтому правки вёрстки не появлялись в
    браузере до ручного перезапуска — и это выглядело так, будто
    правка не сработала.
    """
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
import eventstore
import run_defense
import correlator as correlator_mod
import detector as detector_mod
import red_team
import soclog

soclog.install()   # структурные JSON-логи + errors.log — до первого запроса
import logging as _logging
_flog = _logging.getLogger("console")

app = Flask(__name__)
app.secret_key = config.WEB_SECRET
CURSOR = "console"

# =======================================================================
#  АУТЕНТИФИКАЦИЯ
# =======================================================================
# Раньше консоль защиты была открыта полностью: 35 маршрутов без единой
# проверки, включая POST /api/red/launch (запуск атакующей кампании),
# POST /api/incident/<id>/respond (действия реагирования) и маршруты,
# запускающие подпроцессы. Консоль среды (webapp.py :8787) при этом логин
# требовала — то есть защищённой была витрина, а не пульт управления.
#
# Учётные данные общие с консолью среды (config.WEB_ADMIN_USER/PASS), чтобы
# аналитик не держал два пароля.
_LOGIN_FAILS = {"n": 0, "until": 0.0}

#: Маршруты, доступные без сессии.
_PUBLIC_PATHS = {"/login", "/logout", "/healthz"}


@app.before_request
def _require_auth():
    """Единая точка контроля доступа.

    Реализовано через before_request, а не декоратором на каждом маршруте:
    декоратор легко забыть на новом маршруте, и дыра появится незаметно.
    Здесь же закрыто всё по умолчанию — новый маршрут защищён автоматически.
    """
    p = request.path or "/"
    if p in _PUBLIC_PATHS or p.startswith("/static/"):
        return None
    if session.get("user"):
        return None
    if p.startswith("/api/"):
        return jsonify({"error": "auth", "detail": "требуется вход"}), 401
    return redirect(url_for("login"))


@app.after_request
def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "connect-src 'self'")
    return resp


@app.route("/healthz")
def healthz():
    return jsonify({"ok": True})


@app.route("/login", methods=["GET", "POST"])
def login():
    import hmac
    error = ""
    if request.method == "POST":
        now = time.time()
        if now < _LOGIN_FAILS["until"]:
            error = "Слишком много попыток — подождите немного"
        else:
            u_ok = hmac.compare_digest(request.form.get("username", ""),
                                       config.WEB_ADMIN_USER)
            p_ok = hmac.compare_digest(request.form.get("password", ""),
                                       config.WEB_ADMIN_PASS)
            if u_ok and p_ok:
                _LOGIN_FAILS["n"] = 0
                session["user"] = config.WEB_ADMIN_USER
                session.permanent = True
                return redirect(url_for("index"))
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





@app.errorhandler(Exception)
def _unhandled(e):
    """Любая необработанная ошибка — в errors.log с полным трейсбеком."""
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return e
    _flog.error("необработанная ошибка в маршруте %s %s",
                request.method, request.path, exc_info=True,
                extra={"ctx": {"path": request.path, "method": request.method,
                               "args": dict(request.args)}})
    return jsonify({"error": "internal", "detail": str(e)[:300]}), 500


@app.route("/api/diag")
def api_diag():
    """Диагностика: счётчики уровней, последние ошибки, хвост структурного лога."""
    d = soclog.diag()
    d["errors_log_tail"] = soclog.tail_errors(60)
    return jsonify(d)

_COR = correlator_mod.Correlator(window_min=180)
_SUPPRESS = detector_mod.Suppressor()   # против флуда UEBA-всплесков в ленте

# Detection Engineering: правила, которые аналитик подтвердил как ложные.
# 3+ подтверждённых FP -> правило глушится (алерты не поднимают инцидент).
FP_MUTE_THRESHOLD = 3


def rule_verdict_stats():
    """rule_id -> (сколько FP-инцидентов, сколько TP-инцидентов) по вердиктам.

    Считаем и подтверждения, и опровержения. Раньше считались только FP, и
    правило глушилось по трём отметкам независимо от того, сколько настоящих
    атак оно поймало. Многошаговая кампания поднимает пять-шесть правил
    разом, поэтому ТРИ ложных инцидента гасили сразу пять правил — включая
    те, что работают с точностью 87%. Аналитик, честно разметивший шум,
    выключал детект.
    """
    import collections as _c
    fp = _c.Counter(); tp = _c.Counter()
    try:
        stat = eventstore.all_incident_status()
    except Exception:
        return fp, tp
    with _LOCK:
        incs = list(_COR.incidents.values())
    for i in incs:
        v = (stat.get(i["id"]) or {}).get("verdict")
        if v not in ("fp", "tp"):
            continue
        seen = set()
        for a in i["alerts"]:
            rid = a.get("rule_id")
            if rid and rid not in seen:
                seen.add(rid)
                (fp if v == "fp" else tp)[rid] += 1
    return fp, tp


def muted_rules():
    """rule_id -> число подтверждённых FP, но только для правил, которые
    глушить безопасно.

    Правило считается шумным, если ложных отметок у него не меньше порога И
    при этом ложных строго больше, чем подтверждённых атак. Правило, которое
    поймало настоящую атаку столько же раз или чаще, не выключается: цена
    пропуска выше цены лишней тревоги.
    """
    fp, tp = rule_verdict_stats()
    out = type(fp)()
    for rid, n in fp.items():
        if n >= FP_MUTE_THRESHOLD and n > tp.get(rid, 0):
            out[rid] = n
    return out
_LOCK = threading.Lock()
_STATE = {
    "alerts": collections.deque(maxlen=800),
    "processed": 0, "alerts_total": 0,
    "by_actor": collections.Counter(),
    "by_repo": collections.Counter(),
    "by_tactic": collections.Counter(),
    "fired_tech": collections.Counter(),   # технике -> сколько раз сработала
    "fired_rule": collections.Counter(),   # rule_id -> сколько раз
    "muted_hits": 0,                       # сколько сработок отброшено FP-тюнингом
    "started": time.time(),
    "running": False,
    "mttd_sum": 0.0, "mttd_n": 0,
}

# ATT&CK-каталог для матрицы покрытия (тактика -> [(technique, name)])
#
# Матрица описывает МОДЕЛЬ УГРОЗ контура разработки: техники MITRE
# ATT&CK Enterprise, которые в принципе наблюдаемы по событиям git,
# CI/CD и GitLab API. Раньше здесь лежали ровно те 17 техник, под
# которые уже написаны правила, — из-за этого покрытие всегда
# показывало 100%: метрика считалась по самой себе.
#
# Теперь в матрице есть и техники БЕЗ правил. Они честно горят как
# слепые зоны и составляют очередь работ для detection engineering.
# Техники, принципиально ненаблюдаемые в этом контуре (фишинг,
# эндпоинт, сеть), сюда намеренно не включены: их отсутствие — это
# граница системы, а не пробел в правилах.
# Матрица вынесена в attack_matrix.py, чтобы дашборд и metrics.py считали
# покрытие по одному честному знаменателю (вся матрица, а не атакованное).
from attack_matrix import ATTACK  # noqa: E402


def _repo(v):
    """Имя репозитория для показа.

    В журнале есть старые события, где вместо названия лежит голый id
    проекта («6»): их писали до того, как справочник репозиториев стал
    полным. Реплей поднимает такие события заново, поэтому нормализуем
    на границе выдачи — в самом журнале ничего не переписываем.
    События без репозитория (например, создание API-токена) остаются
    пустыми: это честно, действие не привязано к коду.
    """
    if v is None or v == "":
        return None
    s = str(v)
    if s.isdigit():
        try:
            name = config.repo_name(int(s))
            if name and not str(name).isdigit():
                return name
        except Exception:
            pass
    return s


_MUTED_CACHE = {"rules": {}, "ts": 0.0}


def _refresh_muted():
    """Раз в 10 секунд обновляем список заглушённых правил."""
    now = time.time()
    if now - _MUTED_CACHE["ts"] < 10:
        return
    _MUTED_CACHE["ts"] = now
    try:
        _MUTED_CACHE["rules"] = dict(muted_rules())
    except Exception:
        # если список молча не обновится, тюнинг по FP перестанет работать,
        # а в интерфейсе это будет выглядеть как «правило всё ещё шумит»
        _flog.error("не удалось обновить список заглушённых правил", exc_info=True)


REPLAY_EVENTS = 6000   # сколько событий переигрывать при старте


def _replay_history(pos):
    """Восстановить алерты и инциденты после перезапуска консоли.

    Инциденты живут в памяти, а курсор ингеста переживает рестарт: без
    этого шага после перезапуска дашборд был пустым, хотя события в
    хранилище есть. Прогоняем последние REPLAY_EVENTS событий через тот
    же детектор и коррелятор — состояние восстанавливается, а живой
    курсор не двигается, поэтому новые события не теряются и не дублятся.

    Побочных эффектов нет: консоль не пишет алерты в стор (это делает
    процесс защиты), а id инцидентов детерминированы, поэтому ранее
    выставленные вердикты TP/FP снова прилипают к тем же инцидентам.
    """
    if pos <= 0:
        return 0
    start = max(0, pos - REPLAY_EVENTS)
    seen = 0
    cur = start
    try:
        while cur < pos:
            batch = eventstore.read_since(cur, limit=500)
            if not batch:
                break
            for ev in batch:
                if ev["_id"] > pos:
                    cur = pos
                    break
                cur = ev["_id"]
                try:
                    det = run_defense.process(ev)
                except Exception:
                    # Раньше событие просто пропускалось. Если детектор падает
                    # систематически (например после смены схемы признаков),
                    # консоль показывала бы «алертов нет» и ни одной ошибки.
                    _flog.error("детектор упал на событии — пропускаю",
                                exc_info=True,
                                extra={"ctx": {"event_id": ev.get("_id"),
                                               "actor": ev.get("actor"),
                                               "action": ev.get("action")}})
                    continue
                seen += 1
                # Переигранные события — тоже обработанные. Счётчик рос
                # только в живом цикле, поэтому после перезапуска консоли
                # на обзоре стояло «обработано защитой 0» рядом с
                # «алертов 13»: из нуля событий тринадцать алертов не
                # получаются, и показатель читался как сломанный.
                with _LOCK:
                    _STATE["processed"] += 1
                if not det.get("alert"):
                    continue
                top = max(det["alerts"], key=lambda a: a["risk"])
                if _SUPPRESS.is_duplicate(ev.get("actor"), top.get("rule_id"), ev.get("ts_sim")):
                    continue
                o = run_defense.observed(ev)
                iid = _COR.add(o, det)
                with _LOCK:
                    _STATE["alerts_total"] += 1
                    _STATE["alerts"].append({
                        "id": ev["_id"], "ts_sim": o.get("ts_sim"),
                        "actor": o.get("actor"), "action": o.get("action"),
                        "project": _repo(o.get("project")), "path": o.get("path"),
                        "risk": det["risk"], "reason": top["reason"],
                        "technique": top.get("technique"), "tactic": top.get("tactic"),
                        "incident": iid,
                    })
                    if o.get("actor"): _STATE["by_actor"][o["actor"]] += 1
                    _rp = _repo(o.get("project"))
                    if _rp: _STATE["by_repo"][_rp] += 1
                    for a2 in det["alerts"]:
                        if a2.get("tactic"): _STATE["by_tactic"][a2["tactic"]] += 1
                        if a2.get("technique"): _STATE["fired_tech"][a2["technique"]] += 1
                        if a2.get("rule_id"): _STATE["fired_rule"][a2["rule_id"]] += 1
    except Exception:
        _flog.error("реплей истории прерван", exc_info=True)
    return seen


def _ingestor():
    eventstore.init()
    pos = eventstore.get_cursor(CURSOR)
    _STATE["running"] = True
    try:
        n = _replay_history(pos)
        with _LOCK:
            inc = len(_COR.incidents); al = _STATE["alerts_total"]
        _flog.info("история восстановлена после рестарта",
                   extra={"ctx": {"replayed": n, "alerts": al, "incidents": inc}})
        print(f"[replay] переиграно событий: {n} | алертов: {al} | инцидентов: {inc}")
    except Exception:
        _flog.error("не удалось восстановить историю", exc_info=True)
    _flog.info("ингест консоли запущен", extra={"ctx": {"cursor": pos}})
    while True:
        try:
            _refresh_muted()
            batch = eventstore.read_since(pos, limit=500)
            for ev in batch:
                pos = ev["_id"]
                with _LOCK:
                    _STATE["processed"] += 1
                try:
                    det = run_defense.process(ev)
                except Exception:
                    _flog.error("детектор упал на событии — пропускаю",
                                exc_info=True,
                                extra={"ctx": {"event_id": ev.get("_id"),
                                               "actor": ev.get("actor"),
                                               "action": ev.get("action")}})
                    continue
                if det.get("alert"):
                    # тюнинг аналитика: выкидываем сработки правил, подтверждённых как FP
                    _mut = _MUTED_CACHE["rules"]
                    if _mut:
                        _kept = [a for a in det["alerts"]
                                 if _mut.get(a.get("rule_id"), 0) < FP_MUTE_THRESHOLD]
                        if not _kept:
                            with _LOCK:
                                _STATE["muted_hits"] = _STATE.get("muted_hits", 0) + 1
                            continue
                        if len(_kept) != len(det["alerts"]):
                            det = dict(det, alerts=_kept,
                                       risk=max(a["risk"] for a in _kept))
                    _top0 = max(det["alerts"], key=lambda a: a["risk"])
                    if _SUPPRESS.is_duplicate(ev.get("actor"), _top0.get("rule_id"), ev.get("ts_sim")):
                        with _LOCK:
                            _STATE["suppressed"] = _STATE.get("suppressed", 0) + 1
                        continue
                    o = run_defense.observed(ev)
                    iid = _COR.add(o, det)
                    top = max(det["alerts"], key=lambda a: a["risk"])
                    # наблюдаемые сигналы контента — кладём в инцидент для LLM-разбора
                    sig = {"shannon_entropy": o.get("shannon_entropy"),
                           "regex_hits": o.get("regex_hits") or [],
                           "placeholder_signal": bool(o.get("placeholder_signal")),
                           "filename_signal": bool(o.get("filename_signal"))}
                    _COR.incidents[iid].setdefault("signals", {"regex": set(), "max_entropy": 0.0,
                                                               "placeholder": False, "filename": False})
                    g = _COR.incidents[iid]["signals"]
                    g["regex"].update(sig["regex_hits"])
                    if sig["shannon_entropy"]: g["max_entropy"] = max(g["max_entropy"], sig["shannon_entropy"])
                    g["placeholder"] = g["placeholder"] or sig["placeholder_signal"]
                    g["filename"] = g["filename"] or sig["filename_signal"]
                    with _LOCK:
                        _STATE["alerts_total"] += 1
                        _STATE["alerts"].append({
                            "id": ev["_id"], "ts_sim": o.get("ts_sim"),
                            "actor": o.get("actor"), "action": o.get("action"),
                            "project": _repo(o.get("project")), "path": o.get("path"),
                            "risk": det["risk"], "reason": top["reason"],
                            "technique": top.get("technique"), "tactic": top.get("tactic"),
                            "incident": iid,
                        })
                        if o.get("actor"): _STATE["by_actor"][o["actor"]] += 1
                        _rp = _repo(o.get("project"))
                        if _rp: _STATE["by_repo"][_rp] += 1
                        for a in det["alerts"]:
                            if a.get("tactic"): _STATE["by_tactic"][a["tactic"]] += 1
                            if a.get("technique"): _STATE["fired_tech"][a["technique"]] += 1
                            if a.get("rule_id"): _STATE["fired_rule"][a["rule_id"]] += 1
            if batch:
                eventstore.set_cursor(CURSOR, pos)
            else:
                time.sleep(1.5)
        except Exception:
            _flog.error("сбой цикла ингеста — повтор через 3с", exc_info=True,
                        extra={"ctx": {"cursor": pos}})
            time.sleep(3)


def _engine():
    return run_defense._ENGINE


# ----------------------------------------------------------------------
@app.route("/api/stats")
def api_stats():
    st = eventstore.stats()
    with _LOCK:
        proc = _STATE["processed"]; al = _STATE["alerts_total"]
        by_actor = dict(_STATE["by_actor"].most_common(8))
        by_repo = dict(_STATE["by_repo"].most_common(8))
        by_tactic = dict(_STATE["by_tactic"].most_common())
        started = _STATE["started"]; running = _STATE["running"]
    cs = _COR.summary()
    eng = _engine()
    covered = set(eng.techniques_covered())
    all_tech = {t for _, lst in ATTACK for t, _ in lst}
    # Поведенческий слой помечает свои срабатывания псевдотехниками UEBA и
    # ML — в матрице ATT&CK их нет. Показатель «техник сработало» считал
    # их наравне с настоящими, и экран покрытия показывал 1, а обзор 2.
    fired = {t for t in _STATE["fired_tech"] if t in all_tech}
    cov_pct = round(len(covered & all_tech) / max(1, len(all_tech)) * 100)
    return jsonify({
        "store_events": st.get("events", 0), "processed": proc, "alerts": al,
        "incidents": cs["incidents"], "campaigns_detected": cs["campaigns"],
        "critical": cs["critical"],
        "rules": eng.rule_count(), "coverage_pct": cov_pct,
        "techniques_fired": len(fired),
        "by_actor": by_actor, "by_repo": by_repo, "by_tactic": by_tactic,
        "uptime": int(time.time() - started), "running": running,
    })


@app.route("/api/alerts")
def api_alerts():
    with _LOCK:
        return jsonify({"alerts": list(_STATE["alerts"])[-150:][::-1]})


@app.route("/api/incidents")
def api_incidents():
    out = []
    try:
        _st = eventstore.all_incident_status()
    except Exception:
        _st = {}
    for i in _COR.list(60):
        _s = _st.get(i["id"]) or {}
        out.append({
            "status": _s.get("status") or "new", "verdict": _s.get("verdict"),
            "id": i["id"], "actor": i["actor"], "severity": i["severity"],
            "max_risk": round(i.get("risk", i["max_risk"]), 2),
            "peak_event_risk": round(i["max_risk"], 2), "alerts": len(i["alerts"]),
            "tactics": i["tactics"], "techniques": i["techniques"][:8],
            "repos": i["repos"], "is_campaign": i.get("is_campaign", False),
            "start_ts": i["start_ts"], "last_ts": i["last_ts"],
            "triage": (i.get("triage") or {}).get("severity"),
        })
    return jsonify({"incidents": out})


def _jsonsafe(o):
    if isinstance(o, dict):
        return {k: _jsonsafe(v) for k, v in o.items()}
    if isinstance(o, (set, frozenset)):
        return sorted(_jsonsafe(x) for x in o)
    if isinstance(o, (list, tuple)):
        return [_jsonsafe(x) for x in o]
    return o


def _incident_ctx(iid, i):
    g = i.get("signals", {})
    return {
        "incident_id": iid, "title": f"\u0418\u043d\u0446\u0438\u0434\u0435\u043d\u0442 @{i['actor']}",
        "actor": i["actor"], "repos": i["repos"],
        "risk_score": round(i.get("risk", i["max_risk"]), 2),
        "shannon_entropy": round(g.get("max_entropy", 0.0), 2),
        "regex_hits": sorted(g.get("regex", set())),
        "n_regex_hits": len(g.get("regex", set())),
        "placeholder_signal": bool(g.get("placeholder")),
        "filename_signal": bool(g.get("filename")),
        "kill_chain_tactics": i["tactics"],
        "techniques": i["techniques"],
        "events": [{"tactic": c.get("tactic"), "technique": c.get("technique"),
                    "action": c.get("action")} for c in i.get("chain", [])][:20],
    }


_TACTIC_RU = {
    "reconnaissance": "разведка", "initial-access": "первичный доступ",
    "execution": "выполнение", "persistence": "закрепление",
    "privilege-escalation": "повышение привилегий", "defense-evasion": "обход защиты",
    "credential-access": "доступ к учётным данным", "discovery": "разведка внутри",
    "lateral-movement": "боковое перемещение", "collection": "сбор данных",
    "exfiltration": "вывод данных", "impact": "воздействие",
}


def _explain_incident(i, ctx, q=""):
    """Внятный разбор инцидента на русском из самих фактов (без LLM).

    Нужен, когда Ollama не запущена или ответила мусором: аналитик всё равно
    должен получить осмысленный ответ, а не «модель не дала ответа».
    """
    actor = ctx.get("actor") or "?"
    risk = ctx.get("risk_score") or 0
    repos = ctx.get("repos") or []
    tacts = [_TACTIC_RU.get(t, t) for t in (ctx.get("kill_chain_tactics") or [])]
    techs = ctx.get("techniques") or []
    alerts = i.get("alerts") or []
    reasons, seen = [], set()
    for a in alerts:
        r = (a.get("reason") or "").strip()
        if r and r not in seen:
            seen.add(r); reasons.append(r)
    first = alerts[0].get("ts_sim") if alerts else i.get("start_ts")
    last = alerts[-1].get("ts_sim") if alerts else i.get("last_ts")

    p = []
    p.append(f"Что случилось: сотрудник @{actor} попал под {len(alerts)} сработок детекта, "
             f"итоговый риск {risk}.")
    if first and last:
        p.append(f"Окно активности: с {str(first).replace('T', ' ')} по {str(last).replace('T', ' ')}.")
    if repos:
        p.append("Затронутые репозитории: " + ", ".join(repos[:6]) + ".")
    if tacts:
        p.append("Стадии ATT&CK: " + " → ".join(tacts[:6]) +
                 (" (" + ", ".join(techs[:5]) + ")" if techs else "") + ".")
    if reasons:
        p.append("Почему сработало: " + "; ".join(reasons[:5]) + ".")
    sig = []
    if ctx.get("n_regex_hits"):
        sig.append(f"совпадения по сигнатурам секретов: {', '.join(ctx.get('regex_hits') or [])}")
    if (ctx.get("shannon_entropy") or 0) >= 4.0:
        sig.append(f"высокая энтропия содержимого ({ctx['shannon_entropy']}) — похоже на ключ/токен")
    if ctx.get("filename_signal"):
        sig.append("подозрительное имя файла (.env/credentials/key)")
    if ctx.get("placeholder_signal"):
        sig.append("значение похоже на заглушку — возможен ложный сигнал")
    if sig:
        p.append("Признаки в содержимом: " + "; ".join(sig) + ".")

    verdict = ("Оценка: похоже на настоящую атаку (true positive) — риск высокий и есть цепочка стадий."
               if risk >= 0.7 or len(tacts) >= 2 else
               "Оценка: сигнал средний — нужен взгляд аналитика, возможен ложный срабатывание.")
    p.append(verdict)
    p.append("Что делать: отозвать токены @" + actor + ", проверить затронутые репозитории, "
             "заморозить доступ до разбора, собрать таймлайн по kill-chain.")
    return " ".join(p)


def _run_triage(iid, force=False):
    i = _COR.get(iid)
    if not i:
        return None
    sig = (len(i.get("techniques", [])), len(i.get("alerts", [])))
    if not force and i.get("triage") and i.get("_triage_sig") == sig:
        return i["triage"]
    try:
        import llm_client
        res = llm_client.triage(_incident_ctx(iid, i))
    except Exception as e:
        res = {"error": str(e), "_source": "error"}
    with _LOCK:
        i["triage"] = res
        i["_triage_sig"] = sig
    return res


def _triage_worker():
    """\u0424\u043e\u043d\u043e\u0432\u044b\u0439 \u0430\u0432\u0442\u043e-\u0442\u0440\u0438\u0430\u0436 \u043a\u0430\u0436\u0434\u043e\u0433\u043e \u0438\u043d\u0446\u0438\u0434\u0435\u043d\u0442\u0430-\u043a\u0430\u043c\u043f\u0430\u043d\u0438\u0438."""
    if not getattr(config, "LLM_AUTO_TRIAGE", True):
        return
    min_risk = getattr(config, "LLM_AUTO_TRIAGE_MIN_RISK", 0.6)
    while True:
        try:
            for iid, i in list(_COR.incidents.items()):
                if i.get("is_campaign") or i.get("risk", i.get("max_risk", 0)) >= min_risk:
                    sig = (len(i.get("techniques", [])), len(i.get("alerts", [])))
                    if i.get("_triage_sig") != sig:
                        _run_triage(iid)
            time.sleep(2.0)
        except Exception:
            _flog.error("сбой фонового авто-триажа", exc_info=True)
            time.sleep(4.0)


def _gl_base():
    ns = getattr(config, "PROJECT_NAMESPACE", "soc-team")
    return f"{getattr(config, 'GITLAB_URL', '').rstrip('/')}/{ns}"


def _alert_url(a):
    proj = a.get("project")
    if not proj:
        return None
    base = f"{_gl_base()}/{proj}/-"
    mr = a.get("mr_iid")
    if mr and mr != -1:
        return f"{base}/merge_requests/{mr}"
    path = a.get("path")
    if path and path != "none":
        br = a.get("branch") if (a.get("branch") and a.get("branch") != "none") else "main"
        return f"{base}/blob/{br}/{path}"
    br = a.get("branch")
    if br and br != "none":
        return f"{base}/commits/{br}"
    return f"{_gl_base()}/{proj}"


def _issues_url():
    return f"{_gl_base()}/playbooks/-/issues"


@app.route("/api/incident/<int:iid>")
def api_incident(iid):
    i = _COR.get(iid)
    if not i:
        return jsonify({"error": "not found"}), 404
    import ioc as ioc_mod
    data = _jsonsafe(i)
    for a in data.get("alerts", []):
        a["url"] = _alert_url(a)
    data["ioc"] = ioc_mod.flat(ioc_mod.from_incident(i))

    # ПОСЛУЖНОЙ СПИСОК ПРАВИЛ ЭТОГО ИНЦИДЕНТА.
    #
    # Измерено на живом стенде: из 21 разобранного инцидента аналитик
    # ошибся в четырёх, и ВСЕ ТРИ вердикта «ложное» оказались настоящими
    # атаками. Подтвердить атаку по экрану можно — там цепочка, слои,
    # техники. А чтобы её ОТКЛОНИТЬ, на экране не хватало главного: как
    # это правило вело себя раньше. Одиночное срабатывание правила,
    # которое до этого шесть раз показало настоящую атаку, — совсем не то
    # же самое, что срабатывание правила, которое ошибается через раз.
    # Цена ошибки здесь несимметрична: лишняя тревога стоит времени,
    # пропуск — инцидента, а три ложных вердикта ещё и глушат правило.
    try:
        fp_v, tp_v = rule_verdict_stats()
        with _LOCK:
            fired = dict(_STATE["fired_rule"])
        seen, track = set(), []
        for a in i.get("alerts", []):
            rid = a.get("rule_id")
            if not rid or rid in seen:
                continue
            seen.add(rid)
            tp, fp = tp_v.get(rid, 0), fp_v.get(rid, 0)
            track.append({"rule_id": rid, "fired": fired.get(rid, 0),
                          "tp": tp, "fp": fp,
                          "precision": (round(tp / (tp + fp), 2) if (tp + fp) else None)})
        track.sort(key=lambda x: -(x["tp"] + x["fp"]))
        data["rule_track"] = track
    except Exception:
        _flog.error("не удалось собрать послужной список правил", exc_info=True)
        data["rule_track"] = []
    # реальный результат «Реагировать» — из очереди команд (ставит мир)
    rc = i.get("_resp_cid")
    if rc and not i.get("responded"):
        try:
            for cmd in eventstore.list_commands(60):
                if cmd.get("id") == rc:
                    res = cmd.get("result") or ""
                    if res.startswith("http"):
                        i["responded"] = res
                    elif res.startswith("failed"):
                        i["_resp_error"] = res.replace("failed:", "").strip() or "не удалось"
                    break
        except Exception:
            _flog.error("не удалось прочитать результат команды реагирования",
                        exc_info=True, extra={"ctx": {"incident_id": i.get("id")}})
    data["responded"] = i.get("responded")
    data["resp_error"] = i.get("_resp_error")
    data["resp_pending"] = bool(i.get("_resp_cid") and not i.get("responded") and not i.get("_resp_error"))
    data["workflow"] = _incident_status(iid)
    return jsonify(data)


@app.route("/api/incident/<int:iid>/triage", methods=["POST"])
def api_incident_triage(iid):
    """LLM-разбор инцидента. Контекст строится ТОЛЬКО из blue-данных (наблюдаемое),
    метки мира не используются (анти-лик). Без Ollama — детерминированный фолбэк."""
    i = _COR.get(iid)
    if not i:
        return jsonify({"error": "not found"}), 404
    res = _run_triage(iid, force=True)
    return jsonify({"incident_id": iid, "triage": res})


@app.route("/api/incident/<int:iid>/respond", methods=["POST"])
def api_incident_respond(iid):
    """Реакция в песочнице: ставит команду миру завести IR-issue по инциденту."""
    i = _COR.get(iid)
    if not i:
        return jsonify({"error": "not found"}), 404
    if i.get("responded"):
        return jsonify({"ok": True, "already": True, "url": i["responded"],
                        "msg": "Реагирование уже запущено по этому инциденту."})
    cid = eventstore.enqueue_command("response", {
        "incident": iid, "actor": i["actor"], "tactics": i["tactics"],
        "severity": i["severity"], "repos": i["repos"]})
    i["_resp_cid"] = cid
    i.pop("_resp_error", None)
    return jsonify({"ok": True, "cid": cid, "pending": True,
                    "msg": "IR-issue заводится в GitLab (репозиторий playbooks). "
                           "Это автоматическая карточка-инцидент для дежурного."})


@app.route("/api/coverage")
def api_coverage():
    eng = _engine()
    covered = set(eng.techniques_covered())
    with _LOCK:
        fired = dict(_STATE["fired_tech"])
    eng = _engine()
    rules_by_tech = {}
    for r in eng.rules:
        t = r.get("technique")
        if t:
            rules_by_tech.setdefault(t, []).append({"id": r["id"], "title": r["title"],
                                                    "severity": r.get("severity")})
    grid = []
    for tactic, techs in ATTACK:
        cells = []
        for tid, name in techs:
            f = fired.get(tid, 0)
            state = ("fired" if f > 0 else ("covered" if tid in covered else "gap"))
            cells.append({"technique": tid, "name": name,
                          "covered": tid in covered, "fired": f, "state": state,
                          "rules": rules_by_tech.get(tid, [])})
        grid.append({"tactic": tactic, "techniques": cells})
    return jsonify({"grid": grid})


@app.route("/api/navigator")
def api_navigator():
    """Экспорт покрытия в формате MITRE ATT&CK Navigator layer (v4.5).
    Открывается в официальном attack.navigator: techniqueID + score + color."""
    eng = _engine()
    covered = set(eng.techniques_covered())
    with _LOCK:
        fired = dict(_STATE["fired_tech"])
    maxf = max(fired.values(), default=0)
    techs = []
    seen = set()
    for tactic, cells in ATTACK:
        for tid, name in cells:
            if tid in seen:
                continue
            seen.add(tid)
            f = fired.get(tid, 0)
            if f > 0:
                color = "#e23c3c"          # срабатывала (атака замечена)
            elif tid in covered:
                color = "#3b6fb0"          # есть правило, но не срабатывала
            else:
                color = "#2b3038"          # нет правила (слепая зона)
            techs.append({
                "techniqueID": tid, "score": f, "color": color,
                "comment": (f"сработок: {f}" if f else ("есть правило" if tid in covered else "нет правила")),
                "enabled": True, "metadata": [], "showSubtechniques": False,
            })
    layer = {
        "name": "SOC Simulator — покрытие детекта",
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Покрытие и сработки Detection Stack (Purple Team Console). "
                       "Красное — атака замечена, синее — есть правило, серое — слепая зона.",
        "techniques": techs,
        "gradient": {"colors": ["#ffffff", "#e23c3c"], "minValue": 0, "maxValue": max(1, maxf)},
        "legendItems": [{"label": "сработала (атака)", "color": "#e23c3c"},
                        {"label": "есть правило", "color": "#3b6fb0"},
                        {"label": "слепая зона", "color": "#2b3038"}],
        "showTacticRowBackground": True, "tacticRowBackground": "#205b8f",
        "selectTechniquesAcrossTactics": True, "sorting": 0, "hideDisabled": False,
    }
    from flask import Response
    import json as _j
    return Response(_j.dumps(layer, ensure_ascii=False, indent=2),
                    mimetype="application/json",
                    headers={"Content-Disposition": "attachment; filename=soc_attack_layer.json"})


def _entity_profile(actor):
    """UEBA-профиль актора из движка защиты (baseline) + недавние алерты."""
    eng = _engine()
    prof = eng.ueba.actor.get(actor) if hasattr(eng.ueba, "actor") else None
    with _LOCK:
        recent = [a for a in _STATE["alerts"] if a.get("actor") == actor][-25:]
        n_alerts = _STATE["by_actor"].get(actor, 0)
    out = {"actor": actor, "alerts_total": n_alerts, "recent_alerts": recent[::-1]}
    if prof:
        # Профиль UEBA стал вероятностным: часы теперь круговая оценка плотности
        # (_VonMisesHours), а репозитории и действия — мультиномиальные
        # распределения со сглаживанием (_Categorical). У этих объектов нет
        # интерфейса Counter, поэтому раньше страница «Сущности» падала с
        # AttributeError: '_VonMisesHours' object has no attribute 'items'.
        hours_hist = [(h, prof["hours"].counts[h]) for h in range(24)]
        out["baseline"] = {
            "events_seen": prof["n"],
            "top_hours": [h for h, c in sorted(hours_hist, key=lambda x: -x[1])[:4] if c],
            "top_repos": [r for r, _ in prof["repos"].c.most_common(5)],
            "top_actions": [a for a, _ in prof["actions"].c.most_common(5)],
            "hours_hist": hours_hist,
            # средняя интенсивность актора — то, относительно чего считается
            # пуассоновский хвост всплеска
            "rate_per_window": round(prof.get("rate_ewma") or 0.0, 2),
        }
    else:
        out["baseline"] = None
    # «почему подозрителен» — по тактикам/техникам из алертов + risk
    tactics = {}; maxrisk = 0.0
    for a in recent:
        if a.get("tactic"):
            tactics[a["tactic"]] = tactics.get(a["tactic"], 0) + 1
        maxrisk = max(maxrisk, a.get("risk", 0) or 0)
    out["tactics_hit"] = tactics
    out["max_risk"] = round(maxrisk, 2)
    out["risk_label"] = ("critical" if maxrisk >= 0.85 else "high" if maxrisk >= 0.6
                         else "medium" if maxrisk >= 0.4 else "low")
    return out


@app.route("/api/entities")
def api_entities():
    eng = _engine()
    with _LOCK:
        seen = dict(_STATE["by_actor"])
    profs = getattr(eng.ueba, "actor", {})
    actors = set(seen) | set(profs)
    out = []
    for a in sorted(actors):
        prof = profs.get(a)
        out.append({"actor": a, "alerts": seen.get(a, 0),
                    "events_seen": prof["n"] if prof else 0})
    out.sort(key=lambda x: (-x["alerts"], -x["events_seen"]))
    return jsonify({"entities": out})


@app.route("/api/entity/<actor>")
def api_entity(actor):
    return jsonify(_entity_profile(actor))


@app.route("/api/detections")
def api_detections():
    eng = _engine()
    with _LOCK:
        fired = dict(_STATE["fired_rule"])
    rules = []
    for r in eng.rules:
        rules.append({"id": r["id"], "title": r["title"], "technique": r.get("technique"),
                      "tactic": r.get("tactic"), "severity": r.get("severity"),
                      "risk": r.get("risk"), "fired": fired.get(r["id"], 0)})
    rules.sort(key=lambda x: -x["fired"])
    return jsonify({"rules": rules, "count": len(rules)})


@app.route("/api/red")
def api_red():
    red_team.RedTeamEngine({})
    camps = [{"key": k, "title": v["title"],
              "steps": [{"method": m, "technique": t, "tactic": ta} for m, t, ta in v["steps"]]}
             for k, v in red_team.CAMPAIGNS.items()]
    return jsonify({"campaigns": camps, "commands": eventstore.list_commands(12)})


@app.route("/api/red/launch", methods=["POST"])
def api_red_launch():
    body = request.get_json(force=True, silent=True) or {}
    key = body.get("key"); evasion = body.get("evasion", "noisy")
    tempo = body.get("tempo", "fast")
    if tempo not in ("fast", "realistic", "slow"):
        tempo = "fast"
    if key not in red_team.CAMPAIGNS:
        return jsonify({"ok": False, "msg": "unknown campaign"}), 400
    cid = eventstore.enqueue_command("campaign", {"key": key, "evasion": evasion, "tempo": tempo})
    camp = red_team.CAMPAIGNS[key]
    return jsonify({"ok": True, "cmd": cid, "launched_at": time.time(),
                    "key": key, "title": camp["title"], "steps": len(camp["steps"]),
                    "msg": f"кампания '{key}' поставлена в очередь (cmd #{cid})"})


@app.route("/api/red/result")
def api_red_result():
    """Результат запущенной кампании: статус команды + инциденты, впервые
    увиденные после запуска (по seen_real), со временем появления. Даёт
    аналитику обратную связь: детект действительно сработал."""
    try:
        ts = float(request.args.get("ts", "0"))
    except Exception:
        ts = 0.0
    cid = request.args.get("cmd", "")
    cmd_status = None; cmd_result = None
    try:
        for c in eventstore.list_commands(30):
            if str(c.get("id")) == str(cid):
                cmd_status = c.get("status"); cmd_result = c.get("result"); break
    except Exception:
        _flog.error("не удалось прочитать очередь команд — статус запуска "
                    "красной команды не обновится", exc_info=True,
                    extra={"ctx": {"command_id": cid}})
    # ЧТО ИМЕННО ПРИЛЕТЕЛО ПОСЛЕ ЗАПУСКА.
    #
    # Отбор шёл по seen_real инцидента — то есть по времени, когда инцидент
    # УВИДЕЛИ ВПЕРВЫЕ. Детекты, подклеившиеся к уже существующему инциденту
    # того же актора (окно корреляции — часы), в результат не попадали
    # вовсе, и экран запуска сценариев писал «детектов 0» после атаки,
    # которая на самом деле подняла пять тревог. На демонстрации это
    # выглядит как провал детектирования.
    #
    # Считаем по отметке реального времени каждого алерта: инцидент
    # попадает в результат, если после запуска в нём появился хотя бы один
    # детект, и показываем ровно количество новых, а не все за всю жизнь.
    cut = ts - 1
    incs = []
    for i in _COR.list(200):
        alerts = i.get("alerts", [])
        fresh = [a for a in alerts if (a.get("seen_real") or 0) >= cut]
        # Инциденты, поднятые до появления отметок (пережившие рестарт),
        # берём по прежнему признаку — иначе они исчезнут из результата.
        if not fresh and (i.get("seen_real") or 0) < cut:
            continue
        n_new = len(fresh) if fresh else len(alerts)
        last_seen = max([a.get("seen_real") or 0 for a in fresh] or
                        [i.get("touched_real") or i.get("seen_real") or 0])
        incs.append({
            "id": i["id"], "actor": i.get("actor"),
            "risk": round(i.get("max_risk", 0), 2),
            "severity": i.get("severity"),
            "techniques": i.get("techniques", [])[:8],
            "tactics": i.get("tactics", [])[:8],
            "n_alerts": n_new,
            "n_alerts_total": len(alerts),
            "is_new": (i.get("seen_real") or 0) >= cut,
            "is_campaign": bool(i.get("is_campaign")),
            "seen_real": last_seen,
            "start_ts": i.get("start_ts"),
        })
    incs.sort(key=lambda x: -(x["seen_real"] or 0))
    return jsonify({"cmd_status": cmd_status, "cmd_result": cmd_result,
                    "detections": sum(x["n_alerts"] for x in incs),
                    "incidents": incs})


def _ask_filter(q):
    """Простой структурный фильтр из вопроса (детерминированно, без LLM)."""
    import config
    ql = q.lower()
    f = {}
    for u, info in config.USERS.items():
        if u.split(".")[0] in ql or (info.get("name", "").lower() in ql):
            f["actor"] = u; break
    if any(w in ql for w in ("ноч", "night", "выходн", "weekend", "офф", "off-hour", "нерабоч")):
        f["is_night"] = True
    if any(w in ql for w in ("секрет", "secret", ".env", "токен", "token", "ключ", "key", "credential")):
        f["secret"] = True
    for act in ("push", "merge", "branch", "token", "mr", "delete", "удал"):
        if act in ql:
            f["action_kw"] = "mr_merge" if act == "merge" else ("token_create" if act == "token" else act)
            break
    for proj in ("detection-rules", "normalization-rules", "playbooks", "soc-infra",
                 "soc-secrets", "soc-automation", "cloud-detections", "edr-integration",
                 "threat-hunting", "siem-content"):
        if proj in ql:
            f["project"] = proj; break
    return f


def _plural_ru(n, one, few, many):
    """Согласование числительного: 1 событие, 2 события, 5 событий."""
    n = int(n)
    a, b = abs(n) % 10, abs(n) % 100
    if a == 1 and b != 11:
        word = one
    elif 2 <= a <= 4 and not (12 <= b <= 14):
        word = few
    else:
        word = many
    return f"{n} {word}"


def _ask_criteria(f):
    """Человеческое описание условий отбора для строки ответа."""
    if not f:
        return "по всему журналу, без дополнительных условий"
    parts = []
    if f.get("actor"):
        parts.append(f"актор @{f['actor']}")
    if f.get("project"):
        parts.append(f"репозиторий {f['project']}")
    if f.get("is_night"):
        parts.append("вне рабочих часов")
    if f.get("secret"):
        parts.append("признаки секрета в содержимом")
    if f.get("action_kw"):
        parts.append(f"действие содержит «{f['action_kw']}»")
    return "отбор: " + ", ".join(parts) if parts else "по всему журналу"


def _ask_match(ev, f):
    if f.get("actor") and ev.get("actor") != f["actor"]:
        return False
    if f.get("is_night") and not ev.get("is_night"):
        return False
    if f.get("project") and ev.get("project") != f["project"]:
        return False
    if f.get("action_kw") and f["action_kw"] not in str(ev.get("action", "")):
        return False
    if f.get("secret"):
        if not (ev.get("n_regex_hits") or "env" in str(ev.get("path", "")).lower()
                or ev.get("filename_signal")):
            return False
    return True


@app.route("/api/ask", methods=["POST"])
def api_ask():
    """AI-копайлот: вопрос на естественном языке -> фильтр по наблюдаемым событиям.
    Детерминированный фолбэк; при наличии LLM добавляется краткое резюме."""
    q = ((request.get_json(force=True, silent=True) or {}).get("q") or "").strip()
    if not q:
        return jsonify({"answer": "Задайте вопрос, например: «что делала maria ночью» "
                                  "или «покажи секреты в soc-infra».", "events": [], "count": 0})
    top = eventstore.max_id()
    rows = eventstore.read_since(max(0, top - 4000), limit=4000)
    rows = [run_defense.observed(r) for r in rows]   # анти-лик
    f = _ask_filter(q)
    matched = [r for r in rows if _ask_match(r, f)]
    # Условия описываем словами. Раньше строка собиралась как
    # "actor=maria.ivanova, is_night=True" — сырые имена полей плюс
    # питоновское True прямо в интерфейсе аналитика.
    answer = f"{_plural_ru(len(matched), 'событие', 'события', 'событий')} · {_ask_criteria(f)}."
    try:
        import llm_client
        if llm_client.available() and matched:
            sample = [{"ts": r.get("ts_sim"), "actor": r.get("actor"), "action": r.get("action"),
                       "project": r.get("project"), "path": r.get("path")} for r in matched[-40:]]
            out = llm_client.chat([
                {"role": "system", "content": "Ты SOC-аналитик. Отвечай ИСКЛЮЧИТЕЛЬНО на русском языке, кратко "
                 "(2-3 предложения), по делу, по этим событиям."},
                {"role": "user", "content": f"Вопрос: {q}\nСобытия (JSON): "
                 + json.dumps(sample, ensure_ascii=False)}], temperature=0.2)
            if out and not llm_client._has_cjk(out):
                answer = out.strip()
    except Exception:
        # LLM необязателен: ниже отдаётся ответ без него. Но молча — значит
        # «почему-то не работает» останется незамеченным.
        _flog.warning("LLM недоступен — отвечаем без него", exc_info=True)
    ev_out = [{"ts_sim": r.get("ts_sim"), "actor": r.get("actor"), "action": r.get("action"),
               "project": r.get("project"), "path": r.get("path"),
               "is_night": bool(r.get("is_night"))} for r in matched[-30:]][::-1]
    return jsonify({"answer": answer, "count": len(matched), "filter": f, "events": ev_out})


@app.route("/")
def index():
    return _tpl("dashboard.html")


@app.route("/executive")
def executive():
    """Страница «Для комиссии» — обзор платформы простым языком."""
    return _tpl("executive.html")


@app.route("/roi")
def roi():
    """ROI-калькулятор: окно экспозиции секрета в деньгах."""
    return _tpl("roi.html")


# === Воркфлоу аналитика: статусы инцидентов, SLA, вердикты ==================
_WF_STATUSES = ("new", "investigating", "contained", "closed")


def _incident_status(iid):
    return eventstore.all_incident_status().get(iid, {"status": "new", "verdict": None,
                                                      "reason": None, "owner": None, "updated": None})


@app.route("/api/incident/<int:iid>/status", methods=["POST"])
def api_incident_status(iid):
    b = request.get_json(silent=True) or {}
    st = eventstore.set_incident_status(
        iid, status=b.get("status"), verdict=b.get("verdict"),
        reason=b.get("reason"), owner=b.get("owner"))
    return jsonify({"incident_id": iid, "status": st})


@app.route("/api/workflow")
def api_workflow():
    """Очередь триажа: инциденты + статусы + SLA + сводка шумных правил."""
    stat = eventstore.all_incident_status()
    now = time.time()
    items = []
    with _LOCK:
        incs = list(_COR.incidents.values())
    for i in incs:
        s = stat.get(i["id"], {"status": "new", "verdict": None, "owner": None})
        seen = i.get("seen_real", now)
        age = int(now - seen)
        sev_rank = {"critical": 3, "high": 2, "medium": 1, "low": 0}.get(i["severity"], 0)
        # SLA: new>15мин=warn, >60мин=breach (только для незакрытых)
        sla = "ok"
        if s["status"] in ("new", "investigating"):
            if age > 3600:
                sla = "breach"
            elif age > 900:
                sla = "warn"
        items.append({
            "id": i["id"], "actor": i["actor"], "severity": i["severity"],
            "max_risk": round(i.get("risk", i["max_risk"]), 2),
            "peak_event_risk": round(i["max_risk"], 2), "alerts": len(i["alerts"]),
            "is_campaign": i.get("is_campaign", False),
            "tactics": i["tactics"], "repos": i["repos"],
            "status": s["status"], "verdict": s.get("verdict"), "owner": s.get("owner"),
            "age_s": age, "sla": sla,
            "triage": (i.get("triage") or {}).get("severity"),
            "_sort": (sev_rank, i.get("risk", i["max_risk"])),
        })
    items.sort(key=lambda x: x["_sort"], reverse=True)
    for x in items:
        del x["_sort"]
    counts = {k: 0 for k in _WF_STATUSES}
    for x in items:
        counts[x["status"]] = counts.get(x["status"], 0) + 1
    # шумные правила: сработки vs подтверждённые FP
    with _LOCK:
        fired = dict(_STATE["fired_rule"])
    fp_by_rule = collections.Counter()
    for i in incs:
        s = stat.get(i["id"], {})
        if s.get("verdict") == "fp":
            for a in i["alerts"]:
                if a.get("rule_id"):
                    fp_by_rule[a["rule_id"]] += 1
    muted = _MUTED_CACHE["rules"]
    # Показываем и подтверждения, чтобы было видно, почему шумное правило
    # всё ещё работает: оно ловит настоящие атаки не реже, чем ошибается.
    _fp_v, _tp_v = rule_verdict_stats()
    noisy = []
    for rid, cnt in sorted(fired.items(), key=lambda x: -x[1])[:12]:
        noisy.append({"rule_id": rid, "fired": cnt, "fp": fp_by_rule.get(rid, 0),
                      "tp": _tp_v.get(rid, 0),
                      "muted": rid in muted})
    return jsonify({"items": items, "counts": counts, "noisy_rules": noisy,
                    "muted_hits": _STATE.get("muted_hits", 0),
                    "fp_threshold": FP_MUTE_THRESHOLD})


# === Прозрачность LLM: контекст, хэш, чат, сравнение с fallback =============
@app.route("/api/incident/<int:iid>/llm")
def api_incident_llm(iid):
    """Что именно ушло в модель (blue-only) + вердикт + fallback для сравнения."""
    import hashlib
    import llm_client
    i = _COR.get(iid)
    if not i:
        return jsonify({"error": "not found"}), 404
    ctx = _incident_ctx(iid, i)
    ctx_json = json.dumps(ctx, ensure_ascii=False, indent=2)
    ctx_hash = hashlib.sha256(ctx_json.encode("utf-8")).hexdigest()[:16]
    fb = llm_client._fallback_triage(ctx)
    return jsonify({
        "incident_id": iid,
        "context": ctx, "context_json": ctx_json, "context_hash": ctx_hash,
        "context_fields": sorted(ctx.keys()),
        "leak_guard": "Контекст собран только из наблюдаемых (blue) полей. "
                      "Метки мира (campaign_id, is_anomaly, episode_id, technique_id разметки) "
                      "не входят — гарантия test_antileak.py.",
        "ollama_available": bool(llm_client.available()),
        "model": llm_client._model() if hasattr(llm_client, "_model") else None,
        "triage": i.get("triage"),
        "fallback": fb,
    })


@app.route("/api/incident/<int:iid>/ask", methods=["POST"])
def api_incident_ask(iid):
    """Чат по конкретному инциденту (контекст только этого инцидента)."""
    import llm_client
    i = _COR.get(iid)
    if not i:
        return jsonify({"error": "not found"}), 404
    q = (request.get_json(silent=True) or {}).get("q", "").strip()
    if not q:
        return jsonify({"answer": "пустой вопрос"})
    ctx = _incident_ctx(iid, i)
    if not llm_client.available():
        return jsonify({"answer": _explain_incident(i, ctx, q),
                        "source": "rules",
                        "note": "Ollama не запущена — разбор собран из фактов инцидента"})
    try:
        sysmsg = ("Ты SOC-аналитик. Отвечай кратко по-русски, ТОЛЬКО на основе данного JSON-контекста "
                  "инцидента, не выдумывай фактов вне него.")
        out = llm_client.chat([
            {"role": "system", "content": sysmsg},
            {"role": "user", "content": "Контекст инцидента:\n" + json.dumps(ctx, ensure_ascii=False) +
             "\n\nВопрос: " + q}], temperature=0.2)
        if out and not llm_client._has_cjk(out):
            return jsonify({"answer": out, "source": "llm"})
    except Exception as e:
        return jsonify({"answer": "ошибка LLM: " + str(e), "source": "error"})
    return jsonify({"answer": _explain_incident(i, ctx, q),
                    "source": "rules",
                    "note": "модель ответила невнятно — показан разбор по фактам инцидента"})


# === ROI-калькулятор: живой MTTD -> экономия ================================
@app.route("/api/roi")
def api_roi():
    """Живой MTTD из последнего снапшота метрик (без пересчёта)."""
    hist = eventstore.metrics_history(1000)
    mttd = None
    for h in reversed(hist):
        if h.get("mttd") is not None:
            mttd = h["mttd"]; break
    with _LOCK:
        inc = len(_COR.incidents)
    return jsonify({"mttd_sim_min": mttd, "incidents_seen": inc})



# === Тренды метрик: снапшот + история + аннотации + CSV =====================
@app.route("/api/metrics/snapshot", methods=["POST"])
def api_metrics_snapshot():
    """Пересчитать метрики немедленно, не дожидаясь фонового цикла."""
    if _SNAP.get("running"):
        return jsonify({"ok": True, "saved": False, "note": "пересчёт уже идёт"})
    if _EXECM["data"]:
        m = _EXECM["data"]
        eventstore.add_metrics_snapshot({
            "detection_rate": m.get("detection_rate"), "mttd": m.get("mttd_sim_min"),
            "fp_rate": m.get("fp_rate"), "coverage": m.get("attack_coverage"),
            "alerts": m.get("alerts"), "incidents": None})
        _SNAP["last"] = datetime.now().isoformat(timespec="seconds")
        _SNAP["count"] += 1
        return jsonify({"ok": True, "saved": True})
    threading.Thread(target=_take_metrics_snapshot, daemon=True).start()
    return jsonify({"ok": True, "saved": False, "note": "метрики считаются"})


@app.route("/api/trends")
def api_trends():
    # Вместе с историей отдаём состояние фонового пересчёта: когда цифры
    # обновлялись в последний раз и когда обновятся снова.
    nxt = _SNAP.get("next")
    left = None
    if nxt:
        try:
            left = max(0, int((datetime.fromisoformat(nxt) - datetime.now()).total_seconds()))
        except ValueError:
            left = None
    return jsonify({"history": eventstore.metrics_history(1000),
                    "annotations": eventstore.annotations(200),
                    "snapshot": {"last": _SNAP.get("last"), "next_in_s": left,
                                 "period_s": SNAPSHOT_PERIOD_S,
                                 "running": _SNAP.get("running"),
                                 "error": _SNAP.get("error"),
                                 "count": _SNAP.get("count", 0)}})


@app.route("/api/trends.csv")
def api_trends_csv():
    from flask import Response
    import io as _io
    import csv as _csv
    rows = eventstore.metrics_history(5000)
    buf = _io.StringIO()
    w = _csv.writer(buf)
    w.writerow(["ts", "detection_rate", "mttd", "fp_rate", "coverage", "alerts"])
    for h in rows:
        w.writerow([h["ts"], h["detection_rate"], h["mttd"], h["fp_rate"], h["coverage"], h["alerts"]])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=metrics_trends.csv"})


# Период пересчёта метрик и состояние последнего прогона. Состояние
# отдаётся в /api/trends, чтобы на экране было видно, когда цифры
# обновлялись и когда обновятся снова: без этого «70%» на графике
# невозможно ни с чем соотнести — может, посчитано минуту назад, а может,
# висит с прошлого запуска.
SNAPSHOT_PERIOD_S = 300
_SNAP = {"last": None, "next": None, "running": False, "error": None, "count": 0}


def _take_metrics_snapshot():
    """Один прогон metrics.py и запись результата в историю."""
    import subprocess
    import os
    import json as _json
    base = os.path.dirname(os.path.abspath(__file__))
    _SNAP["running"] = True
    try:
        p = subprocess.run([sys.executable, os.path.join(base, "metrics.py"), "--json"],
                           cwd=base, capture_output=True, text=True, timeout=180)
        if p.returncode != 0:
            _SNAP["error"] = (p.stderr or "").strip()[-200:] or "metrics.py завершился с ошибкой"
            return False
        m = _json.loads(p.stdout)
        eventstore.add_metrics_snapshot({
            "detection_rate": m.get("detection_rate"), "mttd": m.get("mttd_sim_min"),
            "fp_rate": m.get("fp_rate"), "coverage": m.get("attack_coverage"),
            "alerts": m.get("alerts"), "incidents": None})
        _SNAP["last"] = datetime.now().isoformat(timespec="seconds")
        _SNAP["count"] += 1
        _SNAP["error"] = None
        return True
    except Exception as e:
        _SNAP["error"] = str(e)[:200]
        _flog.warning("фоновый снапшот метрик не удался", exc_info=True)
        return False
    finally:
        _SNAP["running"] = False


def _metrics_snapshot_worker():
    """Фоновый пересчёт метрик — для трендов.

    Первый снапшот снимается почти сразу, а не через пять минут: раньше
    экран трендов первые пять минут после запуска показывал «снапшотов
    пока нет», и выглядело это как неработающий раздел.
    """
    time.sleep(20)
    while True:
        _take_metrics_snapshot()
        _SNAP["next"] = (datetime.now() + timedelta(seconds=SNAPSHOT_PERIOD_S)).isoformat(timespec="seconds")
        time.sleep(SNAPSHOT_PERIOD_S)


def _describe_alert(actor, a):
    """Человеческое описание одного события таймлайна атаки."""
    act = {"push": "коммит/пуш файла", "mr_open": "открыт merge request",
           "mr_merge": "смёржен MR", "mr_comment": "комментарий к MR",
           "mr_approve": "апрув MR", "branch_create": "создана ветка",
           "file_delete": "удалён файл", "token_create": "создан токен",
           "repo_enum": "перечисление репозиториев/секрет-путей",
           "issue_open": "заведён issue"}.get(a.get("action"), a.get("action") or "действие")
    tgt = a.get("project") or ""
    if a.get("path"):
        tgt += "/" + a["path"]
    layer = "поведенческий слой (UEBA)" if a.get("layer") == "ueba" else "сигнатурное правило"
    tech = a.get("technique")
    txt = f"@{actor} — {act}"
    if tgt:
        txt += f" в {tgt}"
    txt += f". Сработал {layer}: {a.get('reason') or ''}"
    if tech and tech != "UEBA":
        txt += f" (техника ATT&CK {tech}"
        if a.get("tactic"):
            txt += f", тактика {a['tactic']}"
        txt += ")"
    return txt


def _incident_report_html(iid, i):
    import html as _h
    import ioc as ioc_mod
    esc = lambda x: _h.escape(str(x if x is not None else ""))
    actor = i.get("actor", "?")
    alerts = sorted(i.get("alerts", []), key=lambda a: a.get("ts_sim") or "")
    iocs = ioc_mod.flat(ioc_mod.from_incident(i))
    tr = i.get("triage") or {}
    rows = []
    for n, a in enumerate(alerts, 1):
        url = _alert_url(a)
        link = (f'<a href="{esc(url)}" target="_blank">открыть в GitLab ↗</a>' if url else "")
        ts = esc((a.get("ts_sim") or "").replace("T", " "))
        rk = a.get("risk", 0)
        rows.append(
            f'<tr><td>{n}</td><td class=mono>{ts}</td>'
            f'<td>{esc(_describe_alert(actor, a))}</td>'
            f'<td class=rk>{rk}</td><td>{link}</td></tr>')
    iocrows = "".join(f"<tr><td>{esc(x['label'])}</td><td class=mono>{esc(x['value'])}</td></tr>"
                      for x in iocs) or "<tr><td>—</td><td>нет</td></tr>"
    chain = " → ".join(f"{esc(c.get('tactic'))}/{esc(c.get('technique'))}"
                       for c in i.get("chain", [])) or "—"
    # Раздел «Краткий разбор» печатался всегда — в том числе с текстом
    # «разбор не выполнялся». Пустой раздел в отчёте хуже отсутствующего:
    # он занимает место оглавления и выглядит как недоделка.
    narr = esc(tr.get("narrative") or "")
    narr_block = f"<h2>Краткий разбор</h2><p>{narr}</p>" if narr else ""
    sev = esc((i.get("severity") or "").upper())
    # вердикт и заметка аналитика — из журнала статусов инцидента
    try:
        _wf = eventstore.all_incident_status().get(iid) or {}
    except Exception:
        _wf = {}
    _VN = {"tp": "TRUE POSITIVE — подтверждённая атака",
           "fp": "FALSE POSITIVE — ложное срабатывание"}
    _SN = {"new": "новый", "investigating": "в работе",
           "contained": "локализовано", "closed": "закрыто"}
    verdict = esc(_VN.get(_wf.get("verdict"), "вердикт не выставлен"))
    status = esc(_SN.get(_wf.get("status"), _wf.get("status") or "новый"))
    owner = esc(_wf.get("owner") or "—")
    note = esc(_wf.get("reason") or "заметка не заполнена")
    vclass = {"tp": "v tp", "fp": "v fp"}.get(_wf.get("verdict"), "v")
    analyst_block = (
        "<h2>Заключение аналитика</h2>"
        f'<p><span class="{vclass}">{verdict}</span></p>'
        f"<table><tr><th scope=row>Статус</th><td>{status}</td></tr>"
        f"<tr><th scope=row>Аналитик</th><td>{owner}</td></tr></table>"
        f'<p class=note>{note}</p>')
    return f"""<!doctype html><html lang=ru><head><meta charset=utf-8>
<title>Инцидент #{iid}</title><style>
:root{{color-scheme:light}}
body{{font:14px/1.55 -apple-system,'Segoe UI',Roboto,Arial,sans-serif;
 max-width:880px;margin:32px auto;padding:0 20px;color:#141920;background:#fff}}
h1{{font-size:21px;font-weight:600;margin:0 0 4px;letter-spacing:-.01em}}
h2{{font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;
 color:#5A6472;margin:30px 0 8px;padding-bottom:6px;border-bottom:1px solid #DFE3E9}}
p{{margin:8px 0}}
.meta{{color:#5A6472;font-size:13px;margin-bottom:4px}}
table{{width:100%;border-collapse:collapse;font-size:13px;margin-top:6px}}
th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #E7EAEF;vertical-align:top}}
thead th,tr>th[scope=col]{{background:#F4F6F8;font-size:11px;text-transform:uppercase;
 letter-spacing:.06em;color:#5A6472;font-weight:600}}
th[scope=row]{{width:200px;color:#5A6472;font-weight:500}}
tbody tr:nth-child(even) td{{background:#FAFBFC}}
.mono{{font-family:ui-monospace,Consolas,monospace;font-size:12px}}
.rk{{font-weight:600;text-align:right;font-variant-numeric:tabular-nums}}
.sev{{display:inline-block;padding:3px 9px;border-radius:4px;font-size:11px;font-weight:600;
 letter-spacing:.06em;background:#FBE9EA;color:#A82530;border:1px solid #F0C7CB}}
.v{{display:inline-block;padding:5px 12px;border-radius:5px;font-size:12px;font-weight:600;
 background:#F1F3F6;color:#3B4453;border:1px solid #DFE3E9}}
.v.tp{{background:#FBE9EA;color:#A82530;border-color:#F0C7CB}}
.v.fp{{background:#E8F0FD;color:#14509C;border-color:#C6D9F7}}
.note{{white-space:pre-wrap;background:#F7F9FB;border:1px solid #E7EAEF;
 border-left:3px solid #C3CBD6;border-radius:5px;padding:12px 14px;margin-top:12px;color:#2B333F}}
.print{{margin:16px 0;padding:9px 12px;border-radius:5px;background:#F4F6F8;
 border:1px solid #E7EAEF;color:#5A6472;font-size:12px}}
@media print{{.print{{display:none}} body{{margin:0}}}}
</style></head><body>
<div class=print>Чтобы сохранить в PDF — Ctrl+P → «Сохранить как PDF».</div>
<h1>IR-отчёт · Инцидент #{iid}</h1>
<div class=meta><span class=sev>{sev}</span> · подозреваемый <b>@{esc(actor)}</b> ·
risk {i.get('max_risk')} · репозитории: {esc(', '.join(i.get('repos', [])))}</div>
{narr_block}
{analyst_block}
<h2>ATT&amp;CK kill-chain</h2><p class=mono>{chain}</p>
<h2>Таймлайн атаки</h2>
<table><tr><th scope=col>#</th><th scope=col>Время</th><th scope=col>Что произошло и почему сработало</th><th scope=col>Risk</th><th scope=col>Ссылка</th></tr>
{''.join(rows) or '<tr><td colspan=5>нет событий</td></tr>'}</table>
<h2>Индикаторы компрометации</h2>
<table><tr><th scope=col>Тип</th><th scope=col>Значение</th></tr>{iocrows}</table>
</body></html>"""


@app.route("/api/incident/<int:iid>/report")
def api_incident_report_html(iid):
    from flask import Response
    i = _COR.get(iid)
    if not i:
        return jsonify({"error": "not found"}), 404
    return Response(_incident_report_html(iid, i), mimetype="text/html; charset=utf-8")


# === PDF-отчёты ============================================================
@app.route("/api/incident/<int:iid>/report.pdf")
def api_incident_pdf(iid):
    from flask import Response
    i = _COR.get(iid)
    if not i:
        return jsonify({"error": "not found"}), 404
    try:
        import pdf_report
        data = pdf_report.incident_pdf(iid, i, _incident_ctx(iid, i))
    except ImportError:
        # reportlab нет — отдаём HTML-отчёт (печатается в PDF из браузера)
        return Response(_incident_report_html(iid, i), mimetype="text/html; charset=utf-8")
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return Response(data, mimetype="application/pdf",
                    headers={"Content-Disposition": f"inline; filename=incident_{iid}.pdf"})


@app.route("/api/report/full.pdf")
def api_full_pdf():
    from flask import Response
    with _LOCK:
        incs = list(_COR.incidents.values())
    try:
        import pdf_report
        data = pdf_report.full_pdf(incs, _EXECM.get("data"))
    except ImportError:
        return jsonify({"error": "PDF-модуль не установлен. Выполни: pip install reportlab "
                                 "(и перезапусти консоль)"}), 503
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return Response(data, mimetype="application/pdf",
                    headers={"Content-Disposition": "attachment; filename=soc_report_full.pdf"})


# --- Health: строка здоровья (Мир жив? / события / Ollama / авто-триаж) -----
_HEALTH = {"ollama": None, "ts": 0.0}


def _ollama_ok():
    if time.time() - _HEALTH["ts"] > 30:
        try:
            import llm_client
            _HEALTH["ollama"] = bool(llm_client.available())
        except Exception:
            _HEALTH["ollama"] = False
        _HEALTH["ts"] = time.time()
    return _HEALTH["ollama"]


@app.route("/api/health")
def api_health():
    import datetime as _dt
    st = eventstore.stats()
    last = eventstore.last_event()
    age = None
    if last and last.get("ts"):
        try:
            age = max(0, int((_dt.datetime.now()
                              - _dt.datetime.fromisoformat(last["ts"])).total_seconds()))
        except Exception:
            age = None
    with _LOCK:
        running = _STATE["running"]; processed = _STATE["processed"]
    # ПРИЧИНА, А НЕ НОЛЬ.
    #
    # При недоступном event-store всё это раньше отдавало нули, и «база не
    # открылась» выглядело точно так же, как «мир ещё не запускали». Теперь
    # ошибка доходит до интерфейса отдельным полем.
    store_err = None
    try:
        store_err = eventstore.last_error()
    except Exception:
        _flog.error("не удалось прочитать состояние event-store", exc_info=True)
    return jsonify({
        "world_alive": age is not None and age < 180,
        "events": {"total": st.get("events", 0), "last": last, "last_age_s": age},
        "store_ok": bool(st.get("enabled")),
        "store_error": store_err,
        "defense": {"running": running, "processed": processed},
        "ollama": _ollama_ok(),
        "auto_triage": bool(getattr(config, "LLM_AUTO_TRIAGE", True)),
    })


# ----------------------------------------------------------------------
# --- Онбординг: демо-генератор и статус 5 шагов «счастливого пути» ----------
_DEMO = {"running": False, "msg": "", "rc": None}


def _demo_worker():
    import os
    import subprocess
    base = os.path.dirname(os.path.abspath(__file__))
    try:
        p = subprocess.run([sys.executable, os.path.join(base, "make_demo.py")],
                           cwd=base, capture_output=True, text=True, timeout=300)
        _DEMO["rc"] = p.returncode
        _DEMO["msg"] = ("демо готово — события добавлены" if p.returncode == 0
                        else "ошибка make_demo: " + (p.stderr or p.stdout or "?")[-200:])
    except Exception as e:
        _DEMO["rc"] = -1
        _DEMO["msg"] = f"ошибка: {e}"
    finally:
        _DEMO["running"] = False


@app.route("/api/demo", methods=["GET", "POST"])
def api_demo():
    if request.method == "POST" and not _DEMO["running"]:
        _DEMO.update(running=True, msg="генерирую демо-поток (норма + 2 кампании)…", rc=None)
        threading.Thread(target=_demo_worker, daemon=True).start()
    return jsonify(_DEMO)


@app.route("/api/onboarding")
def api_onboarding():
    import datetime as _dt
    st = eventstore.stats()
    last = eventstore.last_event()
    age = None
    if last and last.get("ts"):
        try:
            age = max(0, int((_dt.datetime.now()
                              - _dt.datetime.fromisoformat(last["ts"])).total_seconds()))
        except Exception:
            age = None
    with _LOCK:
        alerts = _STATE["alerts_total"]
    _COR.summary()
    try:
        triaged = sum(1 for i in list(_COR.incidents.values()) if i.get("triage"))
    except Exception:
        triaged = 0
    return jsonify({
        "s1_world": (age is not None and age < 180) or _DEMO["running"],
        "s2_events": st.get("events", 0) > 0,
        "s3_campaign": st.get("campaigns", 0) > 0,
        "s4_alerts": alerts > 0,
        "s5_triage": triaged > 0,
        "demo": _DEMO,
    })


# --- Executive Overview: страница для комиссии + метрики в подпроцессе -----
_EXECM = {"running": False, "data": None, "ts": 0.0, "err": ""}


def _metrics_worker():
    import os
    import subprocess
    import json as _json
    base = os.path.dirname(os.path.abspath(__file__))
    try:
        p = subprocess.run([sys.executable, os.path.join(base, "metrics.py"), "--json"],
                           cwd=base, capture_output=True, text=True, timeout=240)
        if p.returncode == 0:
            _EXECM["data"] = _json.loads(p.stdout)
            _EXECM["err"] = ""
        else:
            _EXECM["err"] = (p.stderr or p.stdout or "?")[-200:]
    except Exception as e:
        _EXECM["err"] = str(e)
    finally:
        _EXECM["ts"] = time.time()
        _EXECM["running"] = False


@app.route("/api/executive")
def api_executive():
    if not _EXECM["running"] and (time.time() - _EXECM["ts"] > 120):
        _EXECM["running"] = True
        threading.Thread(target=_metrics_worker, daemon=True).start()
    holdout = []
    try:
        import csv
        import os
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results", "holdout.csv")
        with open(p, encoding="utf-8") as f:
            holdout = list(csv.DictReader(f))
    except Exception:
        holdout = []
    return jsonify({"metrics": _EXECM["data"], "computing": _EXECM["running"],
                    "metrics_err": _EXECM["err"], "holdout": holdout})


@app.route("/api/science")
def api_science():
    import csv
    import os
    base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
    out = {}
    for name in ("experiments", "roc", "layers", "arena", "holdout"):
        try:
            with open(os.path.join(base, name + ".csv"), encoding="utf-8") as f:
                out[name] = list(csv.DictReader(f))
        except Exception:
            _flog.debug("нет выгрузки эксперимента %s.csv", name)
            out[name] = []
    # JSON-выгрузки новых экспериментов: ablation, кривая нагрузки, компоненты UEBA
    for name in ("ablation", "workload_curve", "ueba_components"):
        try:
            with open(os.path.join(base, name + ".json"), encoding="utf-8") as f:
                out[name] = json.load(f)
        except FileNotFoundError:
            out[name] = None
        except Exception:
            _flog.error("не удалось прочитать results/%s.json", name, exc_info=True)
            out[name] = None
    return jsonify(out)


@app.route("/api/workload_curve.json")
def api_workload_curve():
    """Замер «полнота против нагрузки» — данными, а не картинкой.

    Раньше отдавался готовый SVG из results/. Картинка рисовалась на белом
    листе с зашитыми цветами: в тёмной теме это был белый прямоугольник
    посреди страницы, а масштаб и подписи не подстраивались ни под ширину
    панели, ни под данные. Отдаём числа, рисует консоль.

    Если замера нет — отдаём пустой список, а не 404: интерфейс покажет
    «ещё не построен» с командой запуска. Молчаливая ошибка в сети выглядит
    как поломка, хотя причина в том, что эксперимент просто не запускали.
    """
    import os
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "results", "workload_curve.json")
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return jsonify({"points": [], "reason": "не построен"})
    except Exception:
        _flog.error("не удалось прочитать results/workload_curve.json", exc_info=True)
        return jsonify({"points": [], "reason": "файл повреждён"})
    # Порог мог измениться после замера — берём актуальный, чтобы панель
    # отмечала «сейчас» там, где продукт действительно стоит сегодня.
    data["current_threshold"] = getattr(config, "ACTION_THRESHOLD", 0.6)
    return jsonify(data)


# ----------------------------------------------------------------------


# ----------------------------------------------------------------------






def main():
    eventstore.init()
    threading.Thread(target=_ingestor, daemon=True).start()
    threading.Thread(target=_triage_worker, daemon=True).start()
    threading.Thread(target=_metrics_snapshot_worker, daemon=True).start()
    port = getattr(config, "PURPLE_WEB_PORT", 8788)
    print("========================================================")
    print("  PURPLE TEAM CONSOLE (защита)")
    print(f"  Открой: http://127.0.0.1:{port}")
    print(f"  Вход: {config.WEB_ADMIN_USER} / {config.WEB_ADMIN_PASS}")
    print("  (задайте свой: переменная окружения SOC_ADMIN_PASS)")
    print("========================================================")
    app.run(host="127.0.0.1", port=port, threaded=True, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
