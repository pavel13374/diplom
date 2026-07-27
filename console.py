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
import collections
import json

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

from flask import Flask, jsonify, request
import config
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
CURSOR = "console"


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


def muted_rules():
    """rule_id -> сколько подтверждённых FP. Считается по вердиктам из БД."""
    import collections as _c
    cnt = _c.Counter()
    try:
        stat = eventstore.all_incident_status()
    except Exception:
        return cnt
    with _LOCK:
        incs = list(_COR.incidents.values())
    for i in incs:
        if (stat.get(i["id"]) or {}).get("verdict") == "fp":
            seen = set()
            for a in i["alerts"]:
                rid = a.get("rule_id")
                if rid and rid not in seen:
                    seen.add(rid); cnt[rid] += 1
    return cnt
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
ATTACK = [
    ("Reconnaissance",      [("T1087", "Account/Repo Discovery"),
                             ("T1593.003", "Search Code Repositories")]),
    ("Initial Access",      [("T1078", "Valid Accounts"),
                             ("T1195.002", "Supply Chain"),
                             ("T1195.001", "Compromise Software Dependencies"),
                             ("T1199", "Trusted Relationship")]),
    ("Execution",           [("T1059", "Command/Script Interpreter"),
                             ("T1072", "Software Deployment Tools"),
                             ("T1053", "Scheduled Task/Job")]),
    ("Persistence",         [("T1098.001", "Additional Cloud Credentials"),
                             ("T1098", "Account Manipulation"),
                             ("T1136.003", "Create Cloud Account"),
                             ("T1505", "Server Software Component")]),
    ("Privilege Escalation",[("T1098", "Account Manipulation"),
                             ("T1548", "Abuse Elevation Control"),
                             ("T1078.004", "Valid Accounts: Cloud")]),
    ("Defense Evasion",     [("T1562", "Impair Defenses"),
                             ("T1562.001", "Disable/Modify Tools"),
                             ("T1556", "Modify Auth Process"),
                             ("T1070.004", "Indicator Removal: File Deletion"),
                             ("T1027", "Obfuscated Files or Information"),
                             ("T1550.001", "Application Access Token")]),
    ("Credential Access",   [("T1552.001", "Credentials In Files"),
                             ("T1552", "Unsecured Credentials"),
                             ("T1552.004", "Private Keys"),
                             ("T1552.007", "Container API Credentials"),
                             ("T1528", "Steal Application Access Token"),
                             ("T1555", "Credentials from Password Stores")]),
    ("Discovery",           [("T1069", "Permission Groups Discovery"),
                             ("T1526", "Cloud Service Discovery"),
                             ("T1518", "Software Discovery"),
                             ("T1613", "Container and Resource Discovery")]),
    ("Lateral Movement",    [("T1021.004", "Remote Services: SSH"),
                             ("T1080", "Taint Shared Content")]),
    ("Collection",          [("T1213", "Data from Repositories"),
                             ("T1114.003", "Email Forwarding Rule"),
                             ("T1119", "Automated Collection"),
                             ("T1074", "Data Staged")]),
    ("Command and Control", [("T1102", "Web Service"),
                             ("T1071.001", "Web Protocols")]),
    ("Exfiltration",        [("T1567", "Exfil Over Web Service"),
                             ("T1537", "Transfer to Cloud Account"),
                             ("T1048", "Exfil Over Alternative Protocol"),
                             ("T1030", "Data Transfer Size Limits")]),
    ("Impact",              [("T1485", "Data Destruction"),
                             ("T1565.001", "Stored Data Manipulation"),
                             ("T1490", "Inhibit System Recovery")]),
]


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
                    continue
                seen += 1
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
    fired = set(_STATE["fired_tech"].keys())
    all_tech = {t for _, lst in ATTACK for t, _ in lst}
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
            "max_risk": round(i["max_risk"], 2), "alerts": len(i["alerts"]),
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
        "risk_score": round(i["max_risk"], 2),
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
                if i.get("is_campaign") or i.get("max_risk", 0) >= min_risk:
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
            pass
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
        hours = sorted(prof["hours"].items())
        out["baseline"] = {
            "events_seen": prof["n"],
            "top_hours": [h for h, _ in prof["hours"].most_common(4)],
            "top_repos": [r for r, _ in prof["repos"].most_common(5)],
            "top_actions": [a for a, _ in prof["actions"].most_common(5)],
            "hours_hist": hours,
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
    eng = red_team.RedTeamEngine({})
    camps = [{"key": k, "title": v["title"],
              "steps": [{"method": m, "technique": t, "tactic": ta} for m, t, ta in v["steps"]]}
             for k, v in red_team.CAMPAIGNS.items()]
    return jsonify({"campaigns": camps, "commands": eventstore.list_commands(12)})


@app.route("/api/red/launch", methods=["POST"])
def api_red_launch():
    body = request.get_json(force=True, silent=True) or {}
    key = body.get("key"); evasion = body.get("evasion", "noisy")
    if key not in red_team.CAMPAIGNS:
        return jsonify({"ok": False, "msg": "unknown campaign"}), 400
    cid = eventstore.enqueue_command("campaign", {"key": key, "evasion": evasion})
    return jsonify({"ok": True, "msg": f"кампания '{key}' поставлена в очередь (cmd #{cid})"})


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
    crit = [", ".join(f"{k}={v}" for k, v in f.items()) or "без явных условий"]
    answer = f"Найдено {len(matched)} событий (фильтр: {crit[0]})."
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
        pass
    ev_out = [{"ts_sim": r.get("ts_sim"), "actor": r.get("actor"), "action": r.get("action"),
               "project": r.get("project"), "path": r.get("path"),
               "is_night": bool(r.get("is_night"))} for r in matched[-30:]][::-1]
    return jsonify({"answer": answer, "count": len(matched), "filter": f, "events": ev_out})


@app.route("/")
def index():
    return DASH


@app.route("/executive")
def executive():
    """Страница «Для комиссии» — обзор платформы простым языком."""
    return EXEC_HTML


@app.route("/roi")
def roi():
    """ROI-калькулятор: окно экспозиции секрета в деньгах."""
    return ROI_HTML


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
    import datetime as _dt
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
            "max_risk": round(i["max_risk"], 2), "alerts": len(i["alerts"]),
            "is_campaign": i.get("is_campaign", False),
            "tactics": i["tactics"], "repos": i["repos"],
            "status": s["status"], "verdict": s.get("verdict"), "owner": s.get("owner"),
            "age_s": age, "sla": sla,
            "triage": (i.get("triage") or {}).get("severity"),
            "_sort": (sev_rank, i["max_risk"]),
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
    noisy = []
    for rid, cnt in sorted(fired.items(), key=lambda x: -x[1])[:12]:
        noisy.append({"rule_id": rid, "fired": cnt, "fp": fp_by_rule.get(rid, 0),
                      "muted": muted.get(rid, 0) >= FP_MUTE_THRESHOLD})
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
    if _EXECM["data"]:
        m = _EXECM["data"]
        eventstore.add_metrics_snapshot({
            "detection_rate": m.get("detection_rate"), "mttd": m.get("mttd_sim_min"),
            "fp_rate": m.get("fp_rate"), "coverage": m.get("attack_coverage"),
            "alerts": m.get("alerts"), "incidents": None})
        return jsonify({"ok": True, "saved": True})
    if not _EXECM["running"]:
        _EXECM["running"] = True
        threading.Thread(target=_metrics_worker, daemon=True).start()
    return jsonify({"ok": True, "saved": False, "note": "метрики считаются, повтори через 20с"})


@app.route("/api/trends")
def api_trends():
    return jsonify({"history": eventstore.metrics_history(1000),
                    "annotations": eventstore.annotations(200)})


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


def _metrics_snapshot_worker():
    """Фоновый снапшот метрик раз в N минут — для трендов."""
    import subprocess
    import os
    import json as _json
    base = os.path.dirname(os.path.abspath(__file__))
    while True:
        time.sleep(300)
        try:
            p = subprocess.run([sys.executable, os.path.join(base, "metrics.py"), "--json"],
                               cwd=base, capture_output=True, text=True, timeout=180)
            if p.returncode == 0:
                m = _json.loads(p.stdout)
                eventstore.add_metrics_snapshot({
                    "detection_rate": m.get("detection_rate"), "mttd": m.get("mttd_sim_min"),
                    "fp_rate": m.get("fp_rate"), "coverage": m.get("attack_coverage"),
                    "alerts": m.get("alerts"), "incidents": None})
        except Exception:
            _flog.warning("фоновый снапшот метрик не удался", exc_info=True)


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
    narr = esc(tr.get("narrative") or "разбор не выполнялся")
    sev = esc((i.get("severity") or "").upper())
    # вердикт и заметка аналитика — из журнала статусов инцидента
    try:
        _wf = eventstore.all_incident_status().get(iid) or {}
    except Exception:
        _wf = {}
    _VN = {"tp": "TRUE POSITIVE — подтверждённая атака",
           "fp": "FALSE POSITIVE — ложное срабатывание"}
    _SN = {"new": "новый", "investigating": "в работе",
           "contained": "сдержано", "closed": "закрыто"}
    verdict = esc(_VN.get(_wf.get("verdict"), "вердикт не выставлен"))
    status = esc(_SN.get(_wf.get("status"), _wf.get("status") or "новый"))
    owner = esc(_wf.get("owner") or "—")
    note = esc(_wf.get("reason") or "заметка не заполнена")
    analyst_block = (
        f"<h2>2. Заключение аналитика</h2>"
        f"<table><tr><th scope=row>Вердикт</th><td><b>{verdict}</b></td></tr>"
        f"<tr><th scope=row>Статус</th><td>{status}</td></tr>"
        f"<tr><th scope=row>Аналитик</th><td>{owner}</td></tr></table>"
        f"<p style='margin-top:10px;white-space:pre-wrap'>{note}</p>")
    return f"""<!doctype html><html lang=ru><head><meta charset=utf-8>
<title>Инцидент #{iid}</title><style>
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:900px;margin:24px auto;color:var(--info);padding:0 16px}}
h1{{font-size:22px}} h2{{font-size:15px;margin-top:26px;border-bottom:2px solid var(--info-border);padding-bottom:5px}}
.meta{{color:var(--text-3);font-size:13px}} table{{width:100%;border-collapse:collapse;font-size:13px;margin-top:8px}}
th,td{{text-align:left;padding:7px 9px;border-bottom:1px solid var(--info-border);vertical-align:top}}
th{{background:var(--surface-3);font-size:11px;text-transform:uppercase;color:var(--text-3)}}
.mono{{font-family:ui-monospace,Consolas,monospace;font-size:12px}} .rk{{font-weight:700}}
.sev{{display:inline-block;padding:2px 10px;border-radius:6px;background:var(--critical-bg);color:var(--critical);font-weight:700}}
.print{{margin:14px 0;color:var(--text-3);font-size:12px}} @media print{{.print{{display:none}}}}
</style></head><body>
<div class=print>💡 Чтобы сохранить в PDF — нажми Ctrl+P → «Сохранить как PDF».</div>
<h1>IR-отчёт · Инцидент #{iid}</h1>
<div class=meta><span class=sev>{sev}</span> · подозреваемый <b>@{esc(actor)}</b> ·
risk {i.get('max_risk')} · репозитории: {esc(', '.join(i.get('repos', [])))}</div>
<h2>1. Краткий разбор</h2><p>{narr}</p>
{analyst_block}
<h2>3. ATT&amp;CK kill-chain</h2><p class=mono>{chain}</p>
<h2>4. Таймлайн атаки — каждое событие</h2>
<table><tr><th scope=col>#</th><th scope=col>Время</th><th scope=col>Что произошло и почему сработало</th><th scope=col>Risk</th><th scope=col>Ссылка</th></tr>
{''.join(rows) or '<tr><td colspan=5>нет событий</td></tr>'}</table>
<h2>5. Индикаторы компрометации (IOC)</h2>
<table><tr><th scope=col>Тип</th><th scope=col>Значение</th></tr>{iocrows}</table>
<div class=meta style=margin-top:28px>Сгенерировано Sentinel SOC · анти-лик (только наблюдаемые данные).</div>
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
    return jsonify({
        "world_alive": age is not None and age < 180,
        "events": {"total": st.get("events", 0), "last": last, "last_age_s": age},
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
    cs = _COR.summary()
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
            out[name] = []
    return jsonify(out)


# ----------------------------------------------------------------------
DASH = r"""<!doctype html><html lang=ru><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>Sentinel SOC — Detection &amp; Response</title>
<style>

*{box-sizing:border-box}
body{margin:0;font-family:Inter,Segoe UI,Roboto,sans-serif;color:var(--ink);
 background:radial-gradient(900px 400px at 85% -10%,#ede9fe66,transparent 60%),
            radial-gradient(700px 380px at -10% 30%,#dbeafe55,transparent 55%),var(--bg)}
.app{display:grid;min-height:100vh}
/* ---- sidebar: тёмный градиент, как «пульт» ---- */
.side{background:linear-gradient(178deg,var(--accent-brand) 0%,var(--info) 55%,var(--info) 100%);color:var(--info);
 padding:18px 13px;display:flex;flex-direction:column;gap:4px;position:sticky;top:0;height:100vh}
.brand{font-weight:800;font-size:15.5px;padding:6px 8px 16px;color:#fff;letter-spacing:.01em}
.brand b{color:var(--text-1)}
.brand .sub{color:var(--info)}
.nav a{display:flex;gap:10px;align-items:center;padding:10px 12px;border-radius:10px;color:var(--info);cursor:pointer;
 font-size:13.5px;font-weight:600;transition:all .18s ease;border:1px solid transparent}
.nav a:hover{background:#ffffff12;color:#fff;transform:translateX(2px)}
.nav a.active{background:var(--surface-3);color:var(--text-1);border-color:transparent;box-shadow:inset 2px 0 0 var(--accent-brand)}
.side-foot{margin-top:auto;font-size:11px;color:var(--info);padding:10px 8px;border-top:1px solid #ffffff14}
.execlnk{display:flex;flex-direction:column;gap:2px;margin-top:10px;padding:10px 12px;border-radius:10px;color:var(--info);
 font-size:13px;font-weight:700;text-decoration:none;border:1px dashed #7c3aed77;background:#7c3aed14;transition:all .18s ease}
.execlnk:hover{background:#7c3aed2e;border-style:solid;transform:translateX(2px)}
.main{padding:18px 26px 48px;min-width:0}
.top{display:flex;align-items:center;gap:10px;margin-bottom:16px;flex-wrap:wrap}
.top h1{font-size:19px;margin:0;letter-spacing:-.01em}.grow{flex:1}.sub{color:var(--soft);font-size:12px}
.dot{width:8px;height:8px;border-radius:50%;background:var(--green);display:inline-block;margin-right:6px}
.view{display:none}.view.active{display:block;animation:fadeup .3s ease}
@keyframes fadeup{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
/* ---- KPI ---- */
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:16px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:14px 17px 12px;
 box-shadow:var(--shadow);position:relative;overflow:hidden;transition:transform .18s ease,box-shadow .18s ease}
.kpi:hover{transform:translateY(-2px);box-shadow:var(--shadow-lift)}
.kpi:before{content:'';position:absolute;inset:0 0 auto 0;height:3px;background:linear-gradient(90deg,var(--info-bg),var(--info-bg));opacity:.9}
.kpi.crit:before{background:linear-gradient(90deg,var(--critical),var(--critical-bg))}
.kpi.ok:before{background:linear-gradient(90deg,var(--success),var(--success))}
.kpi.acc:before{background:var(--accent-brand)}
.kpi .n{font-size:26px;font-weight:800;font-variant-numeric:tabular-nums;letter-spacing:-.02em}
.kpi .l{font-size:11px;color:var(--soft);letter-spacing:.02em;margin-top:3px;font-weight:500}
.kpi.crit .n{color:var(--red)}.kpi.ok .n{color:var(--green)}.kpi.acc .n{color:var(--accent)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:1100px){.grid2{grid-template-columns:1fr}.app{grid-template-columns:186px 1fr}.main{padding:14px 16px 40px}}
/* ---- карточки ---- */
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:18px;
 box-shadow:var(--shadow);transition:box-shadow .2s ease}
.card:hover{box-shadow:var(--shadow-lift)}
.card h2{margin:0 0 12px;font-size:13.5px;display:flex;align-items:center;gap:8px;letter-spacing:.01em}
.card h2:before{content:'';width:4px;height:15px;border-radius:3px;background:var(--accent-brand);flex:0 0 auto}
.feed{display:flex;flex-direction:column;gap:6px;max-height:66vh;overflow:auto}
.al{display:flex;align-items:center;gap:9px;font-size:12.5px;padding:8px 11px;border-radius:10px;background:var(--panel2);
 border:1px solid var(--line);border-left:3px solid var(--amber);animation:sl .35s ease;transition:background .15s}
.al:hover{background:var(--info-bg)}
.al.hi{border-left-color:var(--red);background:var(--critical-bg)}.al.lo{border-left-color:var(--info-border)}
@keyframes sl{from{opacity:0;transform:translateY(-5px)}to{opacity:1}}
.al .ts{color:var(--soft);font-family:ui-monospace,SFMono-Regular,monospace;font-size:11px}.al .who{font-weight:700}
.al .tech{background:var(--accent-bg);color:var(--accent-brand);border-radius:6px;padding:1px 7px;font-size:10.5px;font-weight:700}
.al .rk{margin-left:auto;font-weight:800;font-variant-numeric:tabular-nums}.al .rk.hi{color:var(--red)}.al .rk.md{color:var(--amber)}
.row{display:flex;justify-content:space-between;font-size:12.5px;padding:6px 2px;border-bottom:1px solid var(--line)}
.row:last-child{border-bottom:none}
.inc{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:13px;margin-bottom:9px;cursor:pointer;
 box-shadow:var(--shadow);transition:all .18s ease}
.inc:hover{border-color:var(--accent-border);transform:translateY(-1px);box-shadow:var(--shadow-lift)}
.inc .h{display:flex;align-items:center;gap:8px}.inc .a{font-weight:700}
.badge{border-radius:6px;padding:2px 8px;font-size:10.5px;font-weight:700;letter-spacing:.02em}
.b-crit{background:var(--critical-bg);color:var(--critical)}.b-high{background:var(--warning-bg);color:var(--warning)}.b-med{background:var(--info-bg);color:var(--info)}.b-low{background:var(--info-bg);color:var(--text-3)}
.b-camp{background:var(--accent-bg);color:var(--accent-brand)}
.chain{display:flex;flex-wrap:wrap;gap:5px;margin-top:8px}
.chip{background:var(--info-bg);border:1px solid var(--line);border-radius:7px;padding:3px 9px;font-size:11px;color:var(--text-3)}
.chip .t{color:var(--accent);font-weight:700}
/* ---- матрица ATT&CK ---- */
.matrix{display:flex;gap:9px;overflow-x:auto;padding-bottom:8px}
.mcol{min-width:150px;flex:0 0 auto}
.mcol .th{font-size:11px;color:var(--soft);letter-spacing:.02em;margin-bottom:7px;height:28px;font-weight:700}
.cell{border:1px solid var(--line);border-radius:10px;padding:9px 10px;margin-bottom:6px;background:var(--panel);
 box-shadow:0 1px 2px rgba(23,28,40,.04);transition:transform .15s ease,box-shadow .15s ease}
.cell:hover{transform:scale(1.03);box-shadow:var(--shadow-lift);position:relative;z-index:2}
.cell.cov{border-color:var(--info-border);background:linear-gradient(180deg,var(--info-bg),var(--info-bg))}
.cell.fired{border-color:var(--red);background:linear-gradient(180deg,var(--critical-bg),var(--critical-bg));box-shadow:0 0 0 1px #dc262633}
.cell .tid{font-family:ui-monospace,SFMono-Regular,monospace;font-size:11px;font-weight:700}
.cell .nm{font-size:10.5px;color:var(--soft);margin-top:2px}
.cell .ct{font-size:10px;margin-top:4px;color:var(--soft)}
/* ---- кнопки ---- */
.btn{background:var(--accent-brand);color:#fff;border:none;border-radius:10px;padding:9px 15px;
 font-weight:700;cursor:pointer;font-size:12.5px;box-shadow:0 2px 8px #7c3aed44;transition:all .16s ease}
.btn:hover{transform:translateY(-1px);box-shadow:0 4px 14px #7c3aed55;filter:brightness(1.05)}
.btn:active{transform:none}
.btn.ghost{background:var(--panel);color:var(--ink);border:1px solid var(--line);box-shadow:var(--shadow)}
.btn.ghost:hover{border-color:var(--accent-border);box-shadow:var(--shadow-lift)}
.rule{display:flex;align-items:center;gap:9px;padding:9px 10px;border-bottom:1px solid var(--line);font-size:12.5px;transition:background .15s}
.rule:hover{background:var(--panel2)}
.sel{background:var(--panel);border:1px solid var(--line);color:var(--ink);border-radius:9px;padding:8px 10px;font-size:12.5px}
.toast{color:var(--green);font-size:12px}
.live{display:inline-flex;align-items:center;gap:6px;background:var(--accent-bg);border:1px solid var(--accent-border);
 color:var(--accent-brand);border-radius:20px;padding:4px 12px;font-size:11px;font-weight:800;letter-spacing:.06em}
.live .d{width:7px;height:7px;border-radius:50%;background:var(--critical);animation:pulse 1.2s infinite}
.hpill{display:inline-flex;align-items:center;gap:6px;background:var(--panel);border:1px solid var(--line);border-radius:20px;
 padding:4px 11px;font-size:11.5px;font-weight:600;color:var(--soft);box-shadow:0 1px 2px rgba(23,28,40,.04)}
.hpill b{color:var(--ink);font-weight:700}
.hpill .d{width:7px;height:7px;border-radius:50%;background:var(--text-3);flex:0 0 auto}
.hpill.ok .d{background:var(--green);animation:pulse 2s infinite}
.hpill.warn{background:var(--warning-bg);border-color:var(--warning-border)}.hpill.warn .d{background:var(--amber)}
.hpill.bad{background:var(--critical-bg);border-color:var(--critical-border)}.hpill.bad .d{background:var(--red)}
.worldWarn{margin:-6px 0 14px;padding:11px 15px;border-radius:11px;background:linear-gradient(90deg,var(--warning-bg),var(--warning-bg));
 border:1px solid var(--warning-border);color:var(--warning);font-size:12.5px;animation:sl .3s ease;box-shadow:var(--shadow)}
.worldWarn code{background:#fde68a55;padding:1px 6px;border-radius:5px}
@keyframes pulse{0%{box-shadow:0 0 0 0 #dc262688}70%{box-shadow:0 0 0 7px #dc262600}100%{box-shadow:0 0 0 0 #dc262600}}
@keyframes flash{0%{color:#fff;text-shadow:0 0 14px var(--accent)}100%{}}
.kpi .n.flash{animation:flash .7s ease}
@keyframes blink{50%{background:var(--critical-bg);border-left-color:var(--critical)}}
.al.hi.blink{animation:blink 1.1s infinite}
.dlbtn{display:inline-block;text-decoration:none;margin-bottom:12px}
.kc{margin-top:10px;display:flex;flex-wrap:wrap;align-items:stretch;row-gap:10px}
.kcs{display:flex;transition:opacity .3s,transform .3s;min-width:0}
.kcb{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:8px 11px 7px;font-size:12px;
 width:172px;box-shadow:var(--shadow);display:flex;flex-direction:column;gap:3px}
.kct{font-size:11px;font-weight:500;letter-spacing:.02em}
.kcx{display:flex;align-items:center;gap:6px}.kcx b{font-family:ui-monospace,SFMono-Regular,monospace;font-size:12px}
.kcl{margin-left:auto;font-size:13px}
.kcf{display:flex;align-items:center;justify-content:space-between;margin-top:auto}
.kcf .rk{font-weight:800;font-size:11px;font-variant-numeric:tabular-nums}.kcf .rk.hi{color:var(--red)}.kcf .rk.md{color:var(--amber)}
.kcarrow{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:0 7px;color:var(--accent-brand);font-size:17px;font-weight:800}
.kcg{font-size:9.5px;color:var(--amber);font-weight:700;white-space:nowrap}
.kcsum{display:flex;gap:16px;flex-wrap:wrap;font-size:12px;color:var(--soft);background:var(--panel2);
 border:1px solid var(--line);border-radius:10px;padding:8px 13px;margin-top:8px}
.kcsum b{color:var(--ink)}
.kc.replaying .kcs{opacity:.22;transform:scale(.97)}.kc.replaying .kcs.on{opacity:1;transform:none}
.kcs.cur .kcb{border-color:var(--accent);box-shadow:0 0 0 1.5px var(--accent),0 6px 16px #7c3aed33}
.iocg{display:flex;flex-wrap:wrap;gap:6px;margin-top:6px}
.ioci{background:var(--panel2);border:1px solid var(--line);border-radius:7px;padding:3px 8px;font-size:11px}
.ioct{color:var(--soft);margin-right:6px}.iocv{font-family:ui-monospace,SFMono-Regular,monospace;color:var(--text-3)}
.askbox{display:flex;gap:8px;margin:4px 0 10px}
.askin{flex:1;background:var(--panel);border:1px solid var(--line);color:var(--ink);border-radius:10px;padding:10px 12px;font-size:13px;transition:all .15s}
.askin:focus{outline:none;border-color:var(--accent-brand);box-shadow:0 0 0 4px #7c3aed1c}
.rng{flex:1;accent-color:var(--accent)}
/* наука: выводы и легенды */
.sconcl{margin-top:12px;padding:11px 14px;border-radius:10px;background:var(--accent-bg);
 border:1px solid var(--accent-border);color:var(--accent-brand);font-size:12.5px;line-height:1.6}
.sleg{display:flex;gap:14px;flex-wrap:wrap;font-size:11px;color:var(--soft);margin:6px 0 2px}
.sleg i{display:inline-block;width:10px;height:10px;border-radius:3px;vertical-align:-1px;margin-right:4px}
/* бары с градиентом */
.brow{display:grid;grid-template-columns:minmax(90px,130px) 1fr 38px 40px;gap:8px;align-items:center;font-size:12px;padding:4px 0}
.brow .blab{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--line-strong);font-weight:600}
.brow b{text-align:right;font-variant-numeric:tabular-nums}
.brow .bpct{color:var(--soft);font-size:10.5px;text-align:right}
.btrack{height:15px;border-radius:5px;background:var(--info-bg);overflow:hidden}
.btrack i{display:block;height:100%;border-radius:5px;background:var(--accent-brand);transition:width .6s ease}
/* воркфлоу + тренды */
.wfcounts{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px}
.wfcount{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:9px 15px;box-shadow:var(--shadow);min-width:96px}
.wfcount .n{font-size:21px;font-weight:800}.wfcount .l{font-size:11px;color:var(--soft);letter-spacing:.05em}
.wfq{display:flex;flex-direction:column;gap:7px;max-height:70vh;overflow:auto}
.wfi{display:flex;align-items:center;gap:9px;padding:9px 11px;border:1px solid var(--line);border-radius:10px;background:var(--panel2);cursor:pointer;transition:all .14s}
.wfi:hover{border-color:var(--accent-border)}
.wfi.sel{border-color:var(--accent);box-shadow:0 0 0 1.5px var(--accent);background:var(--accent-bg)}
.wfi .who{font-weight:700;font-size:12.5px}
.wfi .meta{font-size:11px;color:var(--soft)}
.wfi .grow{flex:1}
.sla{font-size:10px;font-weight:800;padding:2px 7px;border-radius:20px}
.sla.ok{background:var(--success-bg);color:var(--success)}.sla.warn{background:var(--warning-bg);color:var(--warning)}.sla.breach{background:var(--critical-bg);color:var(--critical);animation:pulse 1.4s infinite}
.stpill{font-size:10px;font-weight:700;padding:2px 8px;border-radius:20px;background:var(--info-bg);color:var(--info)}
.stpill.investigating{background:var(--info-bg);color:var(--accent-brand)}.stpill.contained{background:var(--warning-bg);color:var(--warning)}.stpill.closed{background:var(--success-bg);color:var(--success)}
.vpill{font-size:10px;font-weight:800;padding:2px 7px;border-radius:6px}
.vpill.tp{background:var(--critical-bg);color:var(--critical)}.vpill.fp{background:var(--info-bg);color:var(--info)}
.tchart{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px;box-shadow:var(--shadow)}
.tchart h3{margin:0 0 3px;font-size:13px}.tchart .cur{font-size:22px;font-weight:800;letter-spacing:-.02em}
.wfstatus{margin-top:10px}
.wfline{display:flex;align-items:center;gap:5px;flex-wrap:wrap}
.wfstep{border:1px solid var(--line);background:var(--panel);color:var(--soft);border-radius:8px;padding:5px 11px;font-size:11.5px;font-weight:700;cursor:pointer;transition:all .14s}
.wfstep:hover{border-color:var(--accent-border)}.wfstep.on{background:var(--accent-brand);color:#fff;border-color:transparent}
.wfarr{color:var(--accent-border);font-weight:800}
.wfv{border:1px solid var(--line);border-radius:8px;padding:5px 11px;font-size:11.5px;font-weight:800;cursor:pointer;background:var(--panel)}
.wfv.tp{color:var(--critical);border-color:var(--critical-border)}.wfv.tp:hover{background:var(--critical-bg)}
.wfv.fp{color:var(--info)}.wfv.fp:hover{background:var(--info-bg)}
.llmctx{background:var(--accent-brand);color:var(--info);font-family:ui-monospace,SFMono-Regular,monospace;font-size:10.5px;line-height:1.5;
 padding:12px 14px;border-radius:9px;max-height:230px;overflow:auto;margin:8px 0 0;white-space:pre-wrap}
.cellpanel{margin-top:14px;padding:14px 16px;border:1px solid var(--accent-border);border-radius:12px;background:linear-gradient(180deg,var(--info-bg),var(--accent-bg));box-shadow:var(--shadow);animation:fadeup .25s ease}
/* контекстная плашка «что это за консоль» */
.ctx{display:flex;align-items:center;flex-wrap:wrap;gap:6px;background:linear-gradient(90deg,var(--accent-bg),var(--info-bg));
 border:1px solid var(--accent-border);color:var(--accent-brand);border-radius:11px;padding:9px 14px;font-size:12.5px;margin:-4px 0 14px;box-shadow:var(--shadow)}
.ctx a{color:var(--accent-brand);font-weight:700}
.ctx .x{margin-left:auto;cursor:pointer;color:var(--accent-brand);font-weight:800;padding:0 5px;border-radius:6px}
.ctx .x:hover{background:#7c3aed22}
/* онбординг-чеклист */
.obbar{height:7px;border-radius:5px;background:var(--info-bg);overflow:hidden;margin:2px 0 14px}
.obbar i{display:block;height:100%;width:0;border-radius:5px;background:var(--accent-brand);transition:width .5s ease}
.obsteps{display:grid;grid-template-columns:repeat(auto-fit,minmax(205px,1fr));gap:10px}
.ob{display:flex;gap:10px;align-items:flex-start;background:var(--panel2);border:1px solid var(--line);border-radius:11px;padding:11px 12px;transition:all .25s ease}
.ob .obn{width:24px;height:24px;border-radius:50%;background:var(--info-bg);color:var(--soft);font-weight:800;font-size:12px;
 display:flex;align-items:center;justify-content:center;flex:0 0 auto;transition:all .25s ease}
.ob b{font-size:12.5px}
.ob .sub{margin-top:2px;line-height:1.5}
.ob.done{background:var(--success-bg);border-color:var(--success-border)}
.ob.done .obn{background:var(--green);color:#fff}
.ob.done b{color:var(--success)}
.ob a{color:var(--accent);font-weight:700;cursor:pointer;text-decoration:none}
.ob a:hover{text-decoration:underline}
/* тултипы для терминов */
.tip{position:relative;border-bottom:1px dashed var(--accent-brand);cursor:help}
.tip .tipbox{position:absolute;left:50%;bottom:135%;transform:translateX(-50%);width:235px;background:var(--accent-brand);color:var(--info);
 font-size:11.5px;line-height:1.55;padding:9px 12px;border-radius:9px;box-shadow:0 10px 30px rgba(23,18,54,.35);
 opacity:0;pointer-events:none;transition:opacity .15s ease;z-index:30;font-weight:400;text-transform:none;letter-spacing:0}
.tip:hover .tipbox,.tip:focus .tipbox{opacity:1}
::-webkit-scrollbar{width:9px;height:9px}
::-webkit-scrollbar-thumb{background:var(--info-bg);border-radius:6px;border:2px solid var(--bg)}
::-webkit-scrollbar-thumb:hover{background:var(--info-bg)}
::-webkit-scrollbar-track{background:transparent}
</style><link rel="stylesheet" href="/static/design-system.css"><script src="/static/i18n.js" defer></script><script src="/static/ui.js" defer></script><link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='0.9em' font-size='90'>🛡</text></svg>"></head><body>
<div class=app>
  <aside class=side>
    <div class=brand><span class=brand-mark></span><span class=brand-text><b>Sentinel SOC</b><span class=sub>Detection &amp; Response</span></span></div>
    <nav class=nav id=nav>
      <a class=active data-v=overview>Обзор</a>
      <a data-v=alerts>Алерты</a>
      <a data-v=incidents>Инциденты</a>
      <a data-v=cases>Дела</a>
      <a data-v=workflow>Очередь триажа</a>
      <a data-v=attack>ATT&CK Coverage</a>
      <a data-v=detections>Детекты</a>
      <a data-v=entities>Сущности</a>
      <a data-v=risk>Профиль риска</a>
      <a data-v=red>Red Launcher</a>
      <a data-v=replay>Реплей прогона</a>
      <a data-v=trends>Тренды</a>
      <a data-v=diag>Диагностика</a>
    </nav>
    <div class=side-foot><span class=dot id=dot></span><span id=runtxt>—</span></div>
  </aside>
  <main class=main>
    <div class=top><h1 id=ttl>Обзор</h1>
      <span class=grow></span>
      <span class=hpill id=hWorld title="Пишет ли мир (:8787) события в event-store"><span class=d></span>Мир: <b id=hWorldT>—</b></span>
      <span class=hpill id=hEvents title="Событий в event-store и давность последнего"><span class=d></span>События: <b id=hEventsT>—</b></span>
      <span class=hpill id=hOllama hidden title="LLM (Ollama) для триажа"><span class=d></span>Ollama: <b id=hOllamaT>—</b></span>
      <span class=hpill id=hTriage title="Авто-триаж LLM новых инцидентов"><span class=d></span>Авто-триаж: <b id=hTriageT>—</b></span>
    </div>
    <div class=worldWarn id=worldWarn style="display:none">
      ⚠️ <b>Мир молчит</b> — новых событий нет <span id=worldWarnAge></span>.
      Проверь, что консоль среды (:8787) запущена и нажата кнопка «Запустить».
    </div>


    <section class="view active" id=v-overview>
      <div class=card id=obCard style="display:none">
        <h2>Быстрый старт <span class=sub id=obTtl>пройди 5 шагов — увидишь весь конвейер</span><span class=grow></span>
          <button class="btn ghost" id=obToggle onclick=obToggle() style="padding:5px 10px;font-size:11.5px">свернуть</button></h2>
        <div id=obBody>
          <div class=obbar><i id=obFill></i></div>
          <div class=obsteps>
            <div class=ob id=ob1><span class=obn>1</span><div><b>Мир пишет события</b>
              <div class=sub>Открой <a href="http://127.0.0.1:8787" target=_blank>консоль среды</a> и нажми
              «Запустить» — или <a onclick=runDemo()>сгенерируй демо-данные</a><span class=sub id=demoSt></span></div></div></div>
            <div class=ob id=ob2><span class=obn>2</span><div><b>События копятся</b>
              <div class=sub>git/CI-поток пишется в общий журнал (event-store), защита читает его по курсору —
              как <span class=tip tabindex=0>SIEM<span class=tipbox>Security Information & Event Management — система, собирающая события из всех источников в один поток для анализа. Здесь её роль играет event-store на SQLite.</span></span></div></div></div>
            <div class=ob id=ob3><span class=obn>3</span><div><b>Запусти кампанию</b>
              <div class=sub><a onclick="goView('red')">Red Launcher</a> — многошаговая атака по матрице
              <span class=tip tabindex=0>ATT&CK<span class=tipbox>MITRE ATT&CK — общепринятый каталог тактик и техник атакующих. По нему измеряется покрытие детекта.</span></span></div></div></div>
            <div class=ob id=ob4><span class=obn>4</span><div><b>Появились алерты</b>
              <div class=sub><a onclick="goView('alerts')">Лента алертов</a>: правила +
              <span class=tip tabindex=0>UEBA<span class=tipbox>User & Entity Behavior Analytics — профиль «нормального» поведения актора (часы, репозитории, действия); отклонения повышают риск.</span></span>
              сливаются в единый риск (<span class=tip tabindex=0>fusion<span class=tipbox>Слияние сигналов разных слоёв (сигнатуры + поведение) в один скор риска — устойчивее любого сигнала поодиночке.</span></span>)</div></div></div>
            <div class=ob id=ob5><span class=obn>5</span><div><b>Разбери инцидент</b>
              <div class=sub><a onclick="goView('incidents')">Открой инцидент</a> — восстановленный
              <span class=tip tabindex=0>kill-chain<span class=tipbox>Цепочка шагов атаки (разведка → доступ → кража…), восстановленная из алертов одного актора в окне времени.</span></span> —
              и нажми «LLM-разбор»</div></div></div>
          </div>
        </div>
      </div>
      <div class=kpis>
        <div class=kpi acc><div class=n id=kEv>—</div><div class=l>событий в сторе</div></div>
        <div class=kpi><div class=n id=kProc>—</div><div class=l>обработано защитой</div></div>
        <div class=kpi><div class=n id=kAl>—</div><div class=l>алертов</div></div>
        <div class=kpi crit><div class=n id=kInc>—</div><div class=l>инцидентов</div></div>
        <div class=kpi acc><div class=n id=kCamp>—</div><div class=l>кампаний выявлено</div></div>
        <div class=kpi ok><div class=n id=kCov>—</div><div class=l>покрытие ATT&CK</div></div>
      </div>
      <div class=ds-toolbar style=margin-top:4px>
        <span class=grow></span>
        <button class="btn ghost" onclick="execReport()">Отчёт по прогону</button>
        <button class="btn ghost" onclick="huntOpen()">Охота на угрозы</button>
      </div>
      <div class=ds-health id=dsHealth></div>

      <div class=grid2 style=margin-top:16px>
        <div class=card><h2>Живая активность</h2>
          <div class=ds-feed id=liveFeed></div></div>
        <div class=card><h2>Очередь инцидентов</h2>
          <div id=incQueue></div></div>
      </div>

      <div class=grid2 style=margin-top:16px>
        <div class=card><h2>Пульс алертов</h2>
          <svg id=alSpark viewBox="0 0 100 30" preserveAspectRatio=none style="width:100%;height:92px;display:block"></svg>
          <div class=sub id=alSparkSub style=margin-top:6px>—</div></div>
        <div class=card><h2>Распределение риска</h2>
          <div id=riskHist style=margin-top:6px><div class=sub>—</div></div></div>
      </div>

      <div class=grid2 style=margin-top:16px>
        <div class=card><h2>Топ репозиториев</h2><div id=byRepo></div></div>
        <div class=card><h2>Топ разработчиков под подозрением</h2><div id=byActor></div></div>
      </div>

      <div class=grid2 style=margin-top:16px>
        <div class=card><h2>Активность по тактикам ATT&CK</h2><div id=byTactic></div></div>
        <div class=card><h2>Покрытие детектами</h2><div id=covMini></div></div>
      </div>

      <div class=grid2 style=margin-top:16px>
        <div class=card><h2>Качество детекта</h2><div id=qualBox></div></div>
        <div class=card><h2>Вклад слоёв детекта</h2><div id=layerBox></div></div>
      </div>
      <div class=card style=margin-top:16px><h2>AI-копайлот</h2>
        <div class=ds-prompts id=askPrompts></div>
        <div class=askbox style=margin-top:10px><input class=askin id=askIn placeholder="Спросите у данных: что делала maria ночью · покажи секреты в soc-infra"
          onkeydown="if(event.key==='Enter')askQuery()"><button class=btn onclick=askQuery()>Спросить</button></div>
        <div id=askAns class=ds-answer></div>
        <div id=askEv class=feed style=max-height:34vh;margin-top:8px></div>
      </div>
    </section>

    <section class=view id=v-alerts>
      <div class=card>
        <h2>Лента детектов</h2>
        <div class=ds-toolbar id=alFilters>
          <div class=ds-search>
            <svg viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2 stroke-linecap=round><path d="M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM21 21l-4.3-4.3"/></svg>
            <input class=tin id=alSearch placeholder="Поиск: актёр, репозиторий, правило, техника…" oninput="alSearchGo()">
          </div>
          <button class="btn ghost af on" data-f="" onclick="alFilter('')">все</button>
          <button class="btn ghost af" data-f="crit" onclick="alFilter('crit')">critical</button>
          <button class="btn ghost af" data-f="hi" onclick="alFilter('hi')">high</button>
          <button class="btn ghost af" data-f="ueba" onclick="alFilter('ueba')">UEBA</button>
          <button class="btn ghost af" data-f="rules" onclick="alFilter('rules')">сигнатуры</button>
          <span class=grow></span>
          <span class=sub id=alCount></span>
        </div>
        <div class=ds-tablewrap>
          <table class=ds-table id=alTable>
            <thead><tr>
              <th scope=col data-k=ts style="width:130px">Время</th>
              <th scope=col data-k=sev style="width:96px">Severity</th>
              <th scope=col data-k=layer style="width:74px">Слой</th>
              <th scope=col data-k=actor style="width:150px">Разработчик</th>
              <th scope=col data-k=project style="width:170px">Репозиторий</th>
              <th scope=col data-k=tech style="width:110px">MITRE</th>
              <th scope=col data-k=reason>Правило / причина</th>
              <th scope=col data-k=risk style="width:76px;text-align:right">Риск</th>
            </tr></thead>
            <tbody id=alBody></tbody>
          </table>
        </div>
        <div class=ds-pager id=alPager></div>
      </div>
    </section>

    <section class=view id=v-incidents>
      <div class=grid2>
        <div class=card><h2>Инциденты</h2><div id=incList></div></div>
        <div class=card><h2 id=incTtl>Детали инцидента</h2><div id=incDetail class=sub>выберите инцидент слева</div></div>
      </div>
    </section>

    <section class=view id=v-cases>
      <div class=ds-toolbar>
        <div class=ds-search>
          <svg viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2 stroke-linecap=round><path d="M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM21 21l-4.3-4.3"/></svg>
          <input class=tin id=caseSearch placeholder="Поиск по делам, аналитику, акторам…" oninput="caseRender()">
        </div>
        <button class="btn ghost cf on" data-f="" onclick="caseFilter('')">все</button>
        <button class="btn ghost cf" data-f="open" onclick="caseFilter('open')">в работе</button>
        <button class="btn ghost cf" data-f="closed" onclick="caseFilter('closed')">закрытые</button>
        <span class=grow></span>
        <span class=sub id=caseCount></span>
        <button class=btn onclick="caseNew()">+ Новое дело</button>
      </div>
      <div class=grid2 style=margin-top:14px>
        <div class=card><h2>Дела</h2><div id=caseList></div></div>
        <div class=card><h2 id=caseTtl>Карточка дела</h2><div id=caseDetail class=sub>выберите дело слева или создайте новое</div></div>
      </div>
    </section>

    <section class=view id=v-risk>
      <div class=ds-covstrip id=riskStrip></div>
      <div class=grid2 style=margin-top:16px>
        <div class=card><h2>Разработчики по риску</h2><div id=riskDev></div></div>
        <div class=card><h2>Репозитории по риску</h2><div id=riskRepo></div></div>
      </div>
      <div class=card style=margin-top:16px><h2>Динамика риска во времени</h2><div id=riskDyn></div></div>
    </section>

    <section class=view id=v-replay>
      <div class=card>
        <h2>Реплей прогона</h2>
        <div class=ds-toolbar style=margin-top:4px>
          <button class=btn id=rpPlay onclick="rpToggle()">▶ Играть</button>
          <button class="btn ghost" onclick="rpSpeed()">скорость <b id=rpSpeedT>1×</b></button>
          <span class=rp-sep></span>
          <button class="btn ghost rw on" data-w="1d" onclick="rpWin('1d')">сутки</button>
          <button class="btn ghost rw" data-w="7d" onclick="rpWin('7d')">неделя</button>
          <button class="btn ghost rw" data-w="all" onclick="rpWin('all')">весь журнал</button>
          <button class="btn ghost" onclick="rpLoad(1)">обновить</button>
          <span class=grow></span>
          <span class=sub id=rpCount></span>
          <span class=rp-clock id=rpClock>—</span>
        </div>
        <div class=rp-wrap id=rpWrap><div class=sub style=padding:20px>загружаю прогон…</div></div>
        <input type=range id=rpRange min=0 max=1000 value=0 oninput="rpSeek(this.value)" class=rp-range
                 aria-label="Положение курсора на шкале прогона" title="Положение курсора на шкале прогона">
      </div>
      <div class=grid2 style=margin-top:16px>
        <div class=card><h2>Что произошло к этому моменту</h2><div id=rpFeed></div></div>
        <div class=card><h2>Состояние SOC на курсоре</h2><div id=rpState></div></div>
      </div>
    </section>

    <section class=view id=v-attack>
      <div class=ds-covstrip id=covStrip></div>
      <div class=card style=margin-top:16px><h2>Матрица покрытия ATT&amp;CK</h2>
        <div class=ds-legend>
          <span class=ds-leg><i class=ds-leg-box></i>слепая зона</span>
          <span class=ds-leg><i class="ds-leg-box cov"></i>покрыта правилом</span>
          <span class=ds-leg><i class="ds-leg-box fired"></i>срабатывала</span>
          <span class=sub style=margin-left:auto>клик по технике — детали и связанные инциденты</span>
        </div>
        <a class="btn dlbtn" href="/api/navigator" download>⬇ Скачать слой для ATT&amp;CK Navigator (JSON)</a>
        <span class=sub style=margin-left:10px>открой в mitre-attack.github.io/attack-navigator → Open Existing Layer</span>
        <div class=matrix id=matrix></div>
        <div id=cellPanel class=cellpanel style=display:none></div></div>
    </section>

    <section class=view id=v-detections>
      <div class=card><h2>Правила детектирования</h2>
        <div class=ds-toolbar id=ruleFilters>
          <div class=ds-search>
            <svg viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2 stroke-linecap=round><path d="M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM21 21l-4.3-4.3"/></svg>
            <input class=tin id=ruleSearch placeholder="Поиск по правилам, техникам, тактикам…" oninput="ruleSearchGo()">
          </div>
          <button class="btn ghost af on" data-f="" onclick="ruleFilter('')">все</button>
          <button class="btn ghost af" data-f="fired" onclick="ruleFilter('fired')">срабатывали</button>
          <button class="btn ghost af" data-f="silent" onclick="ruleFilter('silent')">молчат</button>
          <button class="btn ghost af" data-f="critical" onclick="ruleFilter('critical')">critical</button>
          <button class="btn ghost af" data-f="high" onclick="ruleFilter('high')">high</button>
          <span class=grow></span><span class=sub id=ruleCount></span>
        </div>
        <div id=rules></div></div>
    </section>

    <section class=view id=v-entities>
      <div class=grid2>
        <div class=card><h2>Сущности</h2><div id=entList></div></div>
        <div class=card><h2 id=entTtl>Профиль сущности</h2><div id=entDetail class=sub>выберите актора слева</div></div>
      </div>
    </section>

    <section class=view id=v-workflow>
      <div class=ctx style=margin-top:0>Как в реальном SOC: очередь по важности, статусы, SLA-таймеры.
        Горячие клавиши: <b>J/K</b> — навигация, <b>T</b> — TP, <b>F</b> — FP, <b>E</b> — эскалация, <b>Enter</b> — открыть.</div>
      <div class=wfcounts id=wfCounts></div>
      <div class=grid2 style="grid-template-columns:1.6fr 1fr">
        <div class=card><h2>Очередь инцидентов</h2>
          <div id=wfQueue class=wfq></div></div>
        <div class=card><h2>Самые шумные правила</h2>
          <div id=wfNoisy></div>
          <div class=sub style=margin-top:8px id=wfMuted></div></div>
      </div>
    </section>

    <section class=view id=v-trends>
      <div class=ctx style=margin-top:0>История метрик во времени (снапшоты раз в 5 мин + по кнопке). Вертикальные метки — события «добавлено правило / запущена кампания».
        <a onclick=snapNow() style=color:#6d28d9;font-weight:700;cursor:pointer>снять снапшот сейчас</a> ·
        <a href="/api/trends.csv" style=color:#6d28d9;font-weight:700>скачать CSV</a></div>
      <div class=grid2 id=trendGrid></div>
      <div class=sub id=trendNote style=margin-top:12px></div>
    </section>

    <section class=view id=v-red>
      <div class=card><h2>Сценарии атак</h2>
        <div style=display:flex;gap:10px;align-items:center;margin-bottom:14px>
          <select class=sel id=evasion aria-label="Профиль скрытности атаки" title="Профиль скрытности атаки"><option value=noisy>noisy (быстро, явно)</option>
            <option value=stealthy>stealthy (low-and-slow)</option></select>
          <span class=toast id=redToast></span></div>
        <div id=camps></div>
        <h2 style=margin-top:18px>Очередь команд</h2><div id=cmds class=sub></div>
      </div>
    </section>

    <section class=view id=v-diag>
      <div class=ctx style=margin-top:0>Здоровье платформы и журнал ошибок. Если что-то не работает —
        пришли на разбор файлы <code>logs/errors.log</code> и <code>logs/debug.jsonl</code>.</div>
      <div class=kpis id=diagCounts></div>
      <div class=card style=margin-bottom:16px><h2>Инфраструктура</h2>
        <div class=sub style=margin-bottom:10px>Служебные подсистемы. В рабочей части интерфейса их не показываем:
          аналитику важен поток событий и детекты, а не состояние конкретного сервиса.</div>
        <div class=ds-health id=diagInfra></div></div>
      <div class=grid2>
        <div class=card><h2>Журнал ошибок</h2>
          <div class=sub style=margin-bottom:8px>Файл <code>logs/errors.log</code> целиком, включая прошлые запуски. Счётчики выше относятся к текущей сессии — поэтому «ошибок нет» и записи ниже не противоречат друг другу.</div>
          <pre class=llmctx id=diagErrors style=max-height:44vh>—</pre></div>
        <div class=card><h2>Структурный лог</h2>
          <div style="display:flex;gap:8px;margin-bottom:8px">
            <select class=sel id=diagLvl onchange=pollDiag() aria-label="Уровень подробности лога" title="Уровень подробности лога">
              <option value="">все уровни</option><option>ERROR</option>
              <option>WARNING</option><option>INFO</option><option>DEBUG</option></select>
            <button class="btn ghost" onclick=pollDiag()>обновить</button></div>
          <div class=feed id=diagRecent style=max-height:40vh></div></div>
      </div>
    </section>
  </main>
</div>
<script>
const $=x=>document.getElementById(x);
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
async function jget(u){const r=await fetch(u);return r.json();}
async function jpost(u,b){const r=await fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})});return r.json();}
const TTL={overview:'Обзор',alerts:'Алерты',incidents:'Инциденты',cases:'Дела',workflow:'Очередь триажа',attack:'ATT&CK Coverage',detections:'Детекты',entities:'Сущности',risk:'Профиль риска команды',red:'Red Launcher',replay:'Реплей прогона',trends:'Тренды метрик',diag:'Диагностика'};
let view='overview';
document.querySelectorAll('#nav a').forEach(a=>a.onclick=()=>{
  document.querySelectorAll('#nav a').forEach(x=>x.classList.remove('active'));a.classList.add('active');
  view=a.dataset.v;document.querySelectorAll('.view').forEach(s=>s.classList.remove('active'));
  $('v-'+view).classList.add('active');$('ttl').textContent=TTL[view];refresh();});
function sevBadge(s){const m={critical:'b-crit',high:'b-high',medium:'b-med',low:'b-low'};return '<span class="badge '+(m[s]||'b-low')+'">'+s+'</span>';}
function rkcls(r){return r>=0.8?'hi':(r>=0.5?'md':'');}
function setN(id,v){const e=$(id);if(!e)return;if(e.textContent!==String(v)){e.textContent=v;e.classList.remove('flash');void e.offsetWidth;e.classList.add('flash');}}
function gapLabel(a,b){try{const da=new Date((a||'').replace(' ','T')),db=new Date((b||'').replace(' ','T'));const m=(db-da)/60000;if(m>=1440)return '+'+Math.round(m/1440)+'д';if(m>=60)return '+'+Math.round(m/60)+'ч';if(m>=2)return '+'+Math.round(m)+'м';return '';}catch(e){return '';}}
const TCOL={'Reconnaissance':'#0ea5e9','Initial Access':'#6366f1','Execution':'#8b5cf6','Persistence':'#a855f7','Privilege Escalation':'#d946ef','Defense Evasion':'#64748b','Credential Access':'#dc2626','Discovery':'#0891b2','Lateral Movement':'#4f46e5','Collection':'#d97706','Command and Control':'#9333ea','Exfiltration':'#b91c1c','Impact':'#7f1d1d','Behavioral':'#059669'};
function tcol(t){return TCOL[t]||'#7c3aed';}
function killchain(chain,alerts){if(!chain||!chain.length)return '<div class=sub>—</div>';
 // ХРОНОЛОГИЯ: шаги упорядочиваем по времени (в сторе порядок может быть иной)
 chain=chain.slice().sort((a,b)=>String(a.ts||'').localeCompare(String(b.ts||'')));
 // слой детекта на шаг: сопоставляем по ts+technique
 const lay={};(alerts||[]).forEach(a=>{lay[(a.ts_sim||'')+'|'+(a.technique||'')]=a.layer||'';});
 let ru=0,ue=0;(alerts||[]).forEach(a=>{if(a.layer==='ueba')ue++;else if(a.layer)ru++;});
 const t0=new Date((chain[0].ts||'').replace(' ','T')),t1=new Date((chain[chain.length-1].ts||'').replace(' ','T'));
 const dur=Math.max(0,Math.round((t1-t0)/60000));
 const durTxt=dur>=60?(Math.floor(dur/60)+' ч '+(dur%60)+' мин'):(dur+' мин');
 const tacs=[...new Set(chain.map(c=>c.tactic).filter(Boolean))];
 let h='<div class=kcsum><span>шагов: <b>'+chain.length+'</b></span><span>тактик: <b>'+tacs.length+'</b></span>'+
  '<span title="от первого до последнего шага атаки">развитие атаки: <b>'+durTxt+'</b></span>'+
  '<span>сигнатуры: <b>'+ru+'</b></span><span>поведение: <b>'+ue+'</b></span></div>';
 h+='<div class=kc id=kcwrap>';
 for(let n=0;n<chain.length;n++){const c=chain[n];const d=(c.ts||'').replace('T',' ').slice(5,16);
  const L=lay[(c.ts||'')+'|'+(c.technique||'')];
  const col=tcol(c.tactic);
  h+='<div class=kcs id=kcs-'+n+'><div class=kcb style="border-top:3px solid '+col+'">'+
   '<div class=kct style="color:'+col+'">'+esc(c.tactic||'?')+'</div>'+
   '<div class=kcx><b>'+esc(c.technique||'')+'</b>'+(L?('<span class=kcl title="какой слой детекта увидел шаг">'+(L==='ueba'?'<span class="ly u">UEBA</span>':'<span class="ly r">RULE</span>')+'</span>'):'')+'</div>'+
   '<div class=sub>'+esc(c.action||'')+'</div>'+
   '<div class=kcf><span class=sub>'+d+'</span><span class="rk '+rkcls(c.risk||0)+'">'+(c.risk!=null?c.risk:'')+'</span></div></div></div>';
  if(n<chain.length-1){const g=gapLabel(c.ts,chain[n+1].ts);
   h+='<div class=kcarrow>'+(g?'<span class=kcg title="пауза между шагами атаки (dwell)">'+g+'</span>':'')+'→</div>';}}
 return h+'</div>';}
function cssv(name,fb){try{var v=getComputedStyle(document.documentElement).getPropertyValue(name).trim();return v||fb;}catch(e){return fb;}}
function bars(o){const k=Object.keys(o||{});if(!k.length)return '<div class="help empty">данных пока нет — запусти кампанию во вкладке Red Launcher</div>';
 const mx=Math.max(...k.map(x=>o[x])),tot=k.reduce((a,x)=>a+o[x],0)||1;
 return k.map(x=>'<div class=brow><span class=blab title="'+esc(x)+'">'+esc(x)+'</span>'+
  '<div class=btrack><i style="width:'+(o[x]/mx*100)+'%"></i></div><b>'+o[x]+'</b>'+
  '<span class=bpct>'+Math.round(o[x]/tot*100)+'%</span></div>').join('');}

/* ============================================================
   THREAT HUNTING — гипотеза → запрос → результат → правило.
   Запросы сохраняются в localStorage: перезапуск не теряет работу.
   ============================================================ */
const HUNT_KEY='soc_hunts';
const HUNT_PRESET=[
 {n:'Секреты в коммитах',q:'секрет',hint:'что детект уже ловит по сигнатурам'},
 {n:'Ночная активность',q:'нераб',hint:'действия вне рабочего окна'},
 {n:'Обход ревью',q:'ревью',hint:'самоапрув и merge без апрува'},
 {n:'Работа с токенами',q:'токен',hint:'создание и утечка токенов'},
 {n:'Массовые удаления',q:'удал',hint:'кандидаты на Impact/T1485'},
 {n:'Доступ к vault',q:'vault',hint:'касание репозитория секретов'}];
function huntLoad(){try{return JSON.parse(localStorage.getItem(HUNT_KEY)||'[]');}catch(e){return [];}}
function huntSave(list){try{localStorage.setItem(HUNT_KEY,JSON.stringify(list));}catch(e){}}

function huntOpen(){
 if(!window.dsDrawer)return;
 const saved=huntLoad();
 const presetHtml=HUNT_PRESET.map(function(p,i){
  return '<div class=ds-ev-item style=cursor:pointer onclick="huntRun('+JSON.stringify(p.q).replace(/"/g,'&quot;')+')">'+
   '<span><b>'+esc(p.n)+'</b><div class=sub>'+esc(p.hint)+'</div></span>'+
   '<span class=sub>&rarr;</span></div>';}).join('');
 const savedHtml=saved.length?saved.map(function(h,i){
  return '<div class=ds-ev-item><span style=cursor:pointer onclick="huntRun('+JSON.stringify(h.q).replace(/"/g,'&quot;')+')">'+
   '<b>'+esc(h.n)+'</b><div class=sub>'+esc(h.q)+'</div></span>'+
   '<button class="btn ghost" style=padding:3px_8px onclick="huntDel('+i+')">удалить</button></div>';}).join('')
  :'<div class=sub>сохранённых запросов пока нет</div>';
 dsDrawer('Threat Hunting',
  '<div class=sub>Проверка гипотезы по потоку детектов. Нашли закономерность — сохраните запрос '+
   'и заведите правило в Detection-as-Code.</div>'+
  '<div class=ds-drawer-sec><div class=t-label>Свой запрос</div>'+
   '<div style="display:flex;gap:8px;margin-top:8px">'+
    '<input class=tin id=huntQ placeholder="актёр, репозиторий, техника, путь…" style=flex:1 '+
     'onkeydown="if(event.key===\'Enter\')huntRun($(\'huntQ\').value)">'+
    '<button class=btn onclick="huntRun($(\'huntQ\').value)">Искать</button></div>'+
   '<div style="display:flex;gap:8px;margin-top:8px;align-items:center">'+
    '<input class=tin id=huntName placeholder="название гипотезы" style=flex:1>'+
    '<button class="btn ghost" onclick="huntAdd()">Сохранить запрос</button></div>'+
   '<div id=huntRes class=sub style=margin-top:10px></div></div>'+
  '<div class=ds-drawer-sec><div class=t-label>Готовые гипотезы</div>'+
   '<div class=ds-ev-list>'+presetHtml+'</div></div>'+
  '<div class=ds-drawer-sec><div class=t-label>Сохранённые запросы</div>'+
   '<div class=ds-ev-list id=huntSaved>'+savedHtml+'</div></div>');}

async function huntRun(q){
 q=(q||'').toLowerCase().trim();if(!q)return;
 const box=$('huntRes');
 let al=[];try{al=(await jget('/api/alerts')).alerts||[];}catch(e){}
 const hits=al.filter(a=>((a.actor||'')+' '+(a.project||'')+' '+(a.reason||'')+' '+
   (a.technique||'')+' '+(a.action||'')+' '+(a.path||'')).toLowerCase().indexOf(q)>=0);
 const byTech={},byActor={};
 hits.forEach(a=>{if(a.technique)byTech[a.technique]=(byTech[a.technique]||0)+1;
                  if(a.actor)byActor[a.actor]=(byActor[a.actor]||0)+1;});
 const top=o=>Object.keys(o).sort((x,y)=>o[y]-o[x]).slice(0,4).map(k=>k+' ('+o[k]+')').join(', ')||'—';
 if(box)box.innerHTML='<b style=color:var(--text-1)>Найдено: '+hits.length+'</b> из '+al.length+' детектов'+
  '<div style=margin-top:6px>Техники: '+esc(top(byTech))+'</div>'+
  '<div>Разработчики: '+esc(top(byActor))+'</div>'+
  (hits.length?'<button class="btn ghost" style=margin-top:10px onclick="dsDrawerClose();goView(\'alerts\');'+
    'setTimeout(function(){$(\'alSearch\').value='+JSON.stringify(q)+';alSearchGo();},200)">Открыть в ленте детектов</button>':'');
 if($('huntQ'))$('huntQ').value=q;}

function huntAdd(){
 const q=($('huntQ')&&$('huntQ').value||'').trim();
 const nm=($('huntName')&&$('huntName').value||'').trim()||q;
 if(!q)return;
 const list=huntLoad();list.unshift({n:nm,q:q});huntSave(list.slice(0,20));
 if(window.toast)toast('Запрос сохранён','success');
 huntOpen();}
function huntDel(i){const l=huntLoad();l.splice(i,1);huntSave(l);huntOpen();}

/* ---------- Executive-отчёт по прогону: собирается на клиенте ---------- */
/* Демо-данные из онбординга: просим сервер сгенерировать поток
   (норма + две кампании) и показываем ход дела рядом со ссылкой. */
let _demoT=null;
async function runDemo(){
 const st=$('demoSt');
 const say=t=>{if(st)st.textContent=t?(' — '+t):'';};
 try{
  const r=await jpost('/api/demo',{});
  say(r.msg||'запускаю…');
  if(window.toast)toast('Генерирую демо-данные','info');
  if(_demoT)clearInterval(_demoT);
  _demoT=setInterval(async()=>{
   let d;try{d=await jget('/api/demo');}catch(e){return;}
   say(d.msg||'');
   if(!d.running){clearInterval(_demoT);_demoT=null;
    if(window.toast)toast(d.rc?('Демо-данные: '+(d.msg||'ошибка')):'Демо-данные готовы',d.rc?'error':'success',4000);}
  },2000);
 }catch(e){say('не удалось запустить');
  if(window.toast)toast('Не удалось запустить генерацию','error');}}

/* общая печатная вёрстка для отчётов, открываемых в новом окне */
const RPT_CSS=
 'body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:960px;margin:24px auto;color:#1f2733;padding:0 16px}'+
 'h1{font-size:23px} h2{font-size:15px;margin-top:26px;border-bottom:2px solid #e4e8f0;padding-bottom:5px}'+
 '.meta{color:#6b7480;font-size:13px}'+
 'table{width:100%;border-collapse:collapse;font-size:13px;margin-top:8px}'+
 'th,td{text-align:left;padding:7px 9px;border-bottom:1px solid #eef2f7;vertical-align:top}'+
 'th{background:#f6f8fc;font-size:11px;text-transform:uppercase;color:#6b7480;width:38%}'+
 '.kpis{display:flex;gap:14px;flex-wrap:wrap;margin-top:12px}'+
 '.k{border:1px solid #e4e8f0;border-radius:10px;padding:12px 16px;min-width:130px}'+
 '.k b{display:block;font-size:26px;font-family:ui-monospace,Consolas,monospace}'+
 '.k span{font-size:11px;font-weight:500;color:#6b7480;letter-spacing:.02em}'+
 '.mono{font-family:ui-monospace,Consolas,monospace;font-size:12px}'+
 '.print{margin:14px 0;color:#6b7480;font-size:12px}@media print{.print{display:none}}';

async function execReport(){
 if(window.toast)toast('Собираю отчёт по прогону…','info');
 let s={},wf={},cov={},al=[],inc=[],det={};
 try{s=await jget('/api/stats');}catch(e){}
 try{wf=await jget('/api/workflow');}catch(e){}
 try{cov=await jget('/api/coverage');}catch(e){}
 try{al=(await jget('/api/alerts')).alerts||[];}catch(e){}
 try{inc=(await jget('/api/incidents')).incidents||[];}catch(e){}
 try{det=await jget('/api/detections');}catch(e){}

 const items=(wf.items||[]);
 const tp=items.filter(x=>x.verdict==='tp').length;
 const fp=items.filter(x=>x.verdict==='fp').length;
 const judged=tp+fp;
 const prec=judged?Math.round(tp/judged*100):null;
 const closed=items.filter(x=>x.status==='closed').length;
 // MTTD: медиана «возраст инцидента на момент решения» недоступна,
 // берём честный прокси — сколько инцидент прожил до текущего момента
 const ages=items.map(x=>x.age_s||0).sort((a,b)=>a-b);
 const med=ages.length?ages[Math.floor(ages.length/2)]:0;

 let gaps=[],covN=0,totN=0,fired=0;
 (cov.grid||[]).forEach(c=>c.techniques.forEach(t=>{totN++;if(t.covered)covN++;if(t.fired)fired++;
   if(!t.covered)gaps.push(t.technique+' '+t.name);}));

 const rules=(det.rules||[]);
 const firedRules=rules.filter(r=>r.fired>0).sort((a,b)=>b.fired-a.fired);
 const sevCount={critical:0,high:0,medium:0,low:0};
 al.forEach(a=>{const r=a.risk||0;
  sevCount[r>=0.85?'critical':(r>=0.7?'high':(r>=0.5?'medium':'low'))]++;});

 const E=x=>String(x==null?'':x).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
 const row=(k,v)=>'<tr><th scope=row>'+k+'</th><td>'+v+'</td></tr>';
 const now=new Date().toLocaleString('ru-RU');

 const html='<!doctype html><html lang=ru><head><meta charset=utf-8>'+
 '<title>Отчёт по прогону — Sentinel SOC</title><style>'+RPT_CSS+'</style></head><body>'+
 '<div class=print>Чтобы сохранить в PDF — Ctrl+P → «Сохранить как PDF».</div>'+
 '<h1>Отчёт по прогону · Sentinel SOC</h1>'+
 '<div class=meta>Сформирован '+E(now)+' · платформа обнаружения угроз в процессе разработки</div>'+
 '<div class=kpis>'+
  '<div class=k><b>'+(s.store_events||0)+'</b><span>событий</span></div>'+
  '<div class=k><b>'+(s.alerts||0)+'</b><span>детектов</span></div>'+
  '<div class=k><b>'+(s.incidents||0)+'</b><span>инцидентов</span></div>'+
  '<div class=k><b>'+(s.campaigns_detected||0)+'</b><span>кампаний</span></div>'+
  '<div class=k><b>'+(s.coverage_pct||0)+'%</b><span>покрытие ATT&amp;CK</span></div>'+
 '</div>'+
 '<h2>1. Что происходило</h2><table>'+
  row('Событий обработано защитой',(s.processed||0))+
  row('Поднято детектов',(s.alerts||0))+
  row('Сгруппировано в инциденты',(s.incidents||0))+
  row('Из них многошаговых кампаний',(s.campaigns_detected||0))+
  row('Активных правил детектирования',(s.rules||0))+
 '</table>'+
 '<h2>2. Качество детектирования</h2><table>'+
  row('Инцидентов разобрано аналитиком',judged+' из '+items.length)+
  row('Подтверждено как атака (TP)',tp)+
  row('Признано ложным (FP)',fp)+
  row('Точность на разобранных',prec==null?'нет разобранных инцидентов':(prec+'%'))+
  row('Закрыто инцидентов',closed)+
  row('Медианное время жизни инцидента',med<3600?(Math.round(med/60)+' мин'):(Math.round(med/360)/10+' ч'))+
 '</table>'+
 '<h2>3. Распределение детектов по критичности</h2><table>'+
  row('Критические (≥0.85)',sevCount.critical)+
  row('Высокие (0.7–0.85)',sevCount.high)+
  row('Средние (0.5–0.7)',sevCount.medium)+
  row('Низкие (&lt;0.5)',sevCount.low)+
 '</table>'+
 '<h2>4. Покрытие MITRE ATT&amp;CK</h2><table>'+
  row('Техник в матрице',totN)+
  row('Покрыто правилами',covN+' ('+(totN?Math.round(covN/totN*100):0)+'%)')+
  row('Срабатывало в этом прогоне',fired)+
  row('Слепые зоны',gaps.length?('<span class=mono>'+E(gaps.join(', '))+'</span>'):'нет')+
 '</table>'+
 '<h2>5. Сработавшие правила</h2><table><tr><th scope=row>Правило</th><td>Сработок</td></tr>'+
  (firedRules.length?firedRules.map(r=>'<tr><th scope=row>'+E(r.title)+' <span class=mono>'+E(r.technique||'')+
     '</span></th><td>'+r.fired+'</td></tr>').join(''):'<tr><th scope=row>—</th><td>ни одно правило не срабатывало</td></tr>')+
 '</table>'+
 '<h2>6. Инциденты</h2><table><tr><th scope=row>Инцидент</th><td>Детали</td></tr>'+
  (inc.length?inc.map(i=>'<tr><th scope=row>#'+i.id+' · @'+E(i.actor)+'</th><td>'+
     E(i.severity)+' · риск '+i.max_risk+' · '+i.alerts+' детектов · '+
     E((i.tactics||[]).join(' → '))+(i.verdict?(' · вердикт '+E(i.verdict.toUpperCase())):'')+
     '</td></tr>').join(''):'<tr><th scope=row>—</th><td>инцидентов нет</td></tr>')+
 '</table>'+
 '<h2>7. Вывод</h2><p>'+
  (s.incidents?('За прогон система обработала '+(s.processed||0)+' событий разработки, подняла '+
   (s.alerts||0)+' детектов и собрала их в '+(s.incidents||0)+' инцидент(ов). '+
   (s.campaigns_detected?('Из них '+s.campaigns_detected+' — многошаговые атаки, восстановленные в цепочку ATT&CK. '):'')+
   (prec!=null?('Точность на разобранных аналитиком инцидентах — '+prec+'%. '):'')+
   'Покрытие матрицы ATT&CK — '+(s.coverage_pct||0)+'%.')
   :'В этом прогоне инцидентов не зафиксировано.')+
 '</p><div class=meta style=margin-top:28px>Sentinel SOC · отчёт построен только по наблюдаемым данным (анти-лик).</div>'+
 '</body></html>';

 const w=window.open('','_blank');
 if(!w){if(window.toast)toast('Браузер заблокировал окно отчёта','error');return;}
 w.document.write(html);w.document.close();
 if(window.toast)toast('Отчёт готов — Ctrl+P для сохранения в PDF','success',4000);}

/* Согласование числительного: «1 алерт», «2 алерта», «5 алертов».
   Без него интерфейс выдаёт «1 алертов» и сразу читается как черновик. */
function plural(n,one,few,many){
 n=Math.abs(Number(n)||0);
 const d=n%10, dd=n%100;
 const w=(dd>10&&dd<20)?many:(d===1?one:(d>=2&&d<=4?few:many));
 return n+' '+w;}
function nAlerts(n){return plural(n,'детект','детекта','детектов');}
function nInc(n){return plural(n,'инцидент','инцидента','инцидентов');}
function nTac(n){return plural(n,'тактика','тактики','тактик');}
function nRepo(n){return plural(n,'репозиторий','репозитория','репозиториев');}
function nEv(n){return plural(n,'событие','события','событий');}
function nTech(n){return plural(n,'техника','техники','техник');}
function nRule(n){return plural(n,'правило','правила','правил');}

function fmtNum(n){return (n==null?'—':(''+n).replace(/\B(?=(\d{3})+(?!\d))/g,' '));}
function healthTile(name,state,val,hint){
 const cls=state==='ok'?'ok':(state==='warn'?'warn':(state==='bad'?'bad':''));
 return '<div class="ds-h-tile '+cls+'" title="'+esc(hint||'')+'">'+
  '<span class=ds-h-dot></span><div class=ds-h-body>'+
  '<div class=ds-h-name>'+esc(name)+'</div><div class=ds-h-val>'+esc(val)+'</div></div></div>';}

async function pollHealthStrip(s){
 let h={};try{h=await jget('/api/health');}catch(e){}
 const ev=h.events||{},df=h.defense||{},age=ev.last_age_s;
 const ageTxt=age==null?'нет данных':(age<60?age+' с назад':Math.floor(age/60)+' мин назад');
 // «обработано» считается за текущую сессию консоли, а стор копится между
 // запусками — вычитать одно из другого нельзя, получался фиктивный лаг.
 const fresh=(age!=null&&age<180);
 const box=$('dsHealth');if(!box)return;
 box.innerHTML=[
  healthTile('GitLab / Мир',h.world_alive?'ok':'bad',h.world_alive?'пишет':'молчит','Пишет ли консоль среды события в общий журнал'),
  healthTile('Симуляция',h.world_alive?'ok':'warn',ageTxt,'Давность последнего события'),
  healthTile('Журнал событий',(ev.total||0)>0?'ok':'warn',fmtNum(ev.total||0)+' соб.','Общий журнал событий'),
  healthTile('Детектор',df.running?'ok':'bad',nRule(s.rules||0),'Стрим-детектор: правила + UEBA'),
  healthTile('Приём событий',df.running?(fresh?'ok':'warn'):'bad',fmtNum(df.processed||0)+' обраб.','Обработано защитой за текущую сессию'),
  healthTile('Поведение (UEBA)',(s.techniques_fired||0)>0?'ok':'',nTech(s.techniques_fired||0),'Сработавшие техники ATT&CK'),
  healthTile('Модель (LLM)',h.ollama?'ok':'warn',h.ollama?'готова':'офлайн','Локальная модель для триажа'),
  healthTile('Авто-триаж',h.auto_triage?'ok':'',h.auto_triage?'включён':'выключен','Автоматический разбор инцидентов')
 ].join('');}

let _feedSeen={};
function feedIcon(k){
 const P={alert:'M12 9v4M12 17h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z',
  inc:'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z',
  ai:'M12 2v4M12 18v4M4.9 4.9l2.9 2.9M16.2 16.2l2.9 2.9M2 12h4M18 12h4M4.9 19.1l2.9-2.9M16.2 7.8l2.9-2.9'};
 return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="'+(P[k]||P.alert)+'"/></svg>';}

function renderLiveFeed(alerts,incs){
 const box=$('liveFeed');if(!box)return;const items=[];
 (alerts||[]).slice(0,14).forEach(a=>{items.push({t:a.ts_sim||'',cls:(a.risk>=0.6?'critical':'info'),ic:'alert',
  html:'<b>@'+esc(a.actor||'?')+'</b> — '+esc(a.reason||'сработало правило')+
   (a.project?' <span class=ds-feed-repo>'+esc(a.project)+'</span>':''),key:'a'+a.id});});
 (incs||[]).slice(0,6).forEach(i=>{
  items.push({t:i.last_ts||i.start_ts||'',cls:'critical',ic:'inc',
   html:'Инцидент <b>#'+i.id+'</b> по <b>@'+esc(i.actor)+'</b> · риск '+i.max_risk+
    (i.is_campaign?' <span class="badge b-camp">campaign</span>':''),key:'i'+i.id});
  if(i.triage)items.push({t:i.last_ts||'',cls:'ai',ic:'ai',
   html:'AI-разбор инцидента <b>#'+i.id+'</b> — оценка <b>'+esc(i.triage)+'</b>',key:'t'+i.id});});
 items.sort((x,y)=>(y.t||'').localeCompare(x.t||''));
 if(!items.length){box.innerHTML='<div class="ds-empty">Пока тихо — запустите кампанию в Red Launcher</div>';return;}
 box.innerHTML=items.slice(0,18).map(it=>{const isNew=!_feedSeen[it.key];_feedSeen[it.key]=1;
  return '<div class="ds-feed-item '+it.cls+(isNew?' is-new':'')+'">'+
   '<span class=ds-feed-ic>'+feedIcon(it.ic)+'</span>'+
   '<span class=ds-feed-txt>'+it.html+'</span>'+
   '<span class=ds-feed-time>'+esc((it.t||'').replace('T',' ').slice(11,16))+'</span></div>';}).join('');}

function renderIncQueue(items){
 const box=$('incQueue');if(!box)return;
 if(!items||!items.length){box.innerHTML='<div class="ds-empty">Очередь пуста</div>';return;}
 box.innerHTML=items.slice(0,6).map(x=>
  '<div class=ds-q-item onclick="goView(\'incidents\');setTimeout(function(){openInc('+x.id+');},150)">'+
   sevBadge(x.severity)+'<div class=ds-q-main>'+
   '<div class=ds-q-who>@'+esc(x.actor)+(x.is_campaign?' <span class="badge b-camp">campaign</span>':'')+'</div>'+
   '<div class=ds-q-meta>'+nAlerts(x.alerts)+' · '+nTac((x.tactics||[]).length)+' · риск '+x.max_risk+'</div></div>'+
   '<span class="sla '+esc(x.sla||'ok')+'">'+(x.age_s<3600?Math.floor(x.age_s/60)+'м':Math.floor(x.age_s/3600)+'ч')+'</span>'+
   (x.verdict?'<span class="vpill '+esc(x.verdict)+'">'+(x.verdict==='tp'?'TP':'FP')+'</span>':'')+'</div>').join('');}

function renderLayers(alerts){
 const box=$('layerBox');if(!box)return;
 const a=alerts||[];
 if(!a.length){box.innerHTML='<div class="ds-empty">Детектов пока нет</div>';return;}
 let rules=0,ueba=0;
 a.forEach(x=>{if(x.technique==='UEBA')ueba++;else rules++;});
 const tot=a.length,pr=Math.round(rules/tot*100),pu=100-pr;
 box.innerHTML=
  '<div class=brow><span class=blab>Сигнатурные правила</span>'+
   '<div class=btrack><i style="width:'+pr+'%;background:var(--info)"></i></div>'+
   '<b>'+rules+'</b><span class=bpct>'+pr+'%</span></div>'+
  '<div class=brow><span class=blab>Поведенческий слой (UEBA)</span>'+
   '<div class=btrack><i style="width:'+pu+'%;background:var(--success)"></i></div>'+
   '<b>'+ueba+'</b><span class=bpct>'+pu+'%</span></div>'+
  '<div class=sub style=margin-top:10px>Сигнатуры ловят известное содержимое, UEBA — нетипичное '+
  'поведение. Вместе они закрывают разные классы атак.</div>';}

function renderQuality(wf){
 const box=$('qualBox');if(!box)return;
 const items=(wf&&wf.items)||[];
 const tp=items.filter(x=>x.verdict==='tp').length;
 const fp=items.filter(x=>x.verdict==='fp').length;
 const judged=tp+fp;
 if(!judged){box.innerHTML='<div class="ds-empty">Разберите инциденты (TP / FP) — здесь появятся '+
   'точность детекта и вклад в тюнинг правил</div>';return;}
 const prec=Math.round(tp/judged*100);
 const noisy=(wf.noisy_rules||[]).filter(r=>r.fp>0);
 box.innerHTML=
  '<div class=ds-cov><div class=ds-cov-num style="color:var(--info)">'+prec+'%</div>'+
  '<div class=ds-cov-bar><i style="width:'+prec+'%;background:var(--info)"></i></div></div>'+
  '<div class=ds-cov-legend>'+
   '<span>подтверждено TP: <b>'+tp+'</b></span>'+
   '<span>ложных FP: <b>'+fp+'</b></span>'+
   '<span>разобрано: <b>'+judged+'</b> из '+items.length+'</span>'+
   (wf.muted_hits?('<span>отклонено тюнингом: <b>'+wf.muted_hits+'</b></span>'):'')+
  '</div>'+
  (noisy.length?('<div class=sub style=margin-top:10px>Правила с подтверждёнными FP: '+
    noisy.map(r=>esc(r.rule_id)+' ('+r.fp+')').join(', ')+'</div>'):'');}

function renderCovMini(s){
 const box=$('covMini');if(!box)return;const pct=s.coverage_pct||0;
 box.innerHTML='<div class=ds-cov><div class=ds-cov-num>'+pct+'%</div>'+
  '<div class=ds-cov-bar><i style="width:'+pct+'%"></i></div></div>'+
  '<div class=ds-cov-legend><span>правил: <b>'+(s.rules||0)+'</b></span>'+
  '<span>техник сработало: <b>'+(s.techniques_fired||0)+'</b></span>'+
  '<span>инцидентов: <b>'+(s.incidents||0)+'</b></span></div>';}

async function pollOverview(){const s=await jget('/api/stats');
 setN('kEv',s.store_events);setN('kProc',s.processed);setN('kAl',s.alerts);
 setN('kInc',s.incidents);setN('kCamp',s.campaigns_detected);setN('kCov',s.coverage_pct+'%');
 $('runtxt').textContent=s.running?('работает · '+Math.floor(s.uptime/60)+'м'):'ждёт поток';
 $('byTactic').innerHTML=bars(s.by_tactic);
 $('byActor').innerHTML=bars(s.by_actor);
 if($('byRepo'))$('byRepo').innerHTML=bars(s.by_repo);
 renderCovMini(s);
 try{await pollHealthStrip(s);}catch(e){}
 let alerts=[],incs=[],wf=null;
 try{alerts=(await jget('/api/alerts')).alerts||[];}catch(e){}
 try{incs=(await jget('/api/incidents')).incidents||[];}catch(e){}
 try{wf=await jget('/api/workflow');}catch(e){}
 try{drawPulse(alerts);}catch(e){}
 try{renderLiveFeed(alerts,incs);}catch(e){}
 try{renderIncQueue(wf&&wf.items);}catch(e){}
 try{renderQuality(wf);}catch(e){}
 try{renderLayers(alerts);}catch(e){}}
function drawPulse(al){
 // спарклайн: алерты по 30-мин слотам сим-времени
 const slots={},order=[];
 al.slice().reverse().forEach(a=>{const t=(a.ts_sim||'');if(t.length<16)return;
  const key=t.slice(0,13)+(t.charAt(14)>='3'?':30':':00');
  if(!(key in slots)){slots[key]=0;order.push(key);}slots[key]++;});
 const svg=$('alSpark');if(svg){
  const vals=order.map(k=>slots[k]);
  if(!vals.length){svg.innerHTML='';$('alSparkSub').textContent='алертов пока нет — запусти кампанию';}
  else{const W=100,H=30,p=2,n=vals.length,mx=Math.max(...vals,1);
   const X=i=>n<=1?W/2:(i/(n-1))*W, Y=v=>H-p-(v/mx)*(H-2*p);
   let line='';vals.forEach((v,i)=>{line+=(i?'L':'M')+X(i).toFixed(1)+' '+Y(v).toFixed(1)+' ';});
   const area='M0 '+H+' '+vals.map((v,i)=>'L'+X(i).toFixed(1)+' '+Y(v).toFixed(1)).join(' ')+' L'+W+' '+H+' Z';
   // Мало точек -> заливка превращалась в сплошной прямоугольник и читалась
   // как «баг». Рисуем столбики: на разреженных данных понятнее, чем площадь.
   if(n<6){const bw=Math.min(5.5,Math.max(1.2,(W/n)*0.32));
    svg.innerHTML=vals.map((v,i)=>{const h=Math.max(0.8,(v/mx)*(H-2*p));
     return '<rect x="'+(X(i)-bw/2).toFixed(1)+'" y="'+(H-p-h).toFixed(1)+'" width="'+bw.toFixed(1)+'" height="'+h.toFixed(1)+'" fill="'+cssv("--info","#3b82f6")+'" rx="1"></rect>';}).join('')+
     '<line x1="0" y1="'+(H-p)+'" x2="'+W+'" y2="'+(H-p)+'" stroke="'+cssv("--line","#1f2a38")+'" stroke-width="0.4"></line>';}
   else{svg.innerHTML='<path d="'+area+'" fill="'+cssv("--info","#3b82f6")+'" fill-opacity="0.12"></path>'+
    '<path d="'+line+'" fill="none" stroke="'+cssv("--info","#3b82f6")+'" stroke-width="1.4" stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke"></path>';}
   $('alSparkSub').textContent='последние '+nAlerts(al.length)+' · '+order[0].replace('T',' ')+' → '+order[order.length-1].replace('T',' ')+' · пик '+mx+' за 30 мин';}}
 // гистограмма риска
 const b=[['критический (≥0.85)',0,'#dc2626'],['высокий (0.7–0.85)',0,'#ea580c'],['средний (0.5–0.7)',0,'#d97706'],['низкий (<0.5)',0,'#64748b']];
 al.forEach(a=>{const r=a.risk||0;if(r>=0.85)b[0][1]++;else if(r>=0.7)b[1][1]++;else if(r>=0.5)b[2][1]++;else b[3][1]++;});
 const mx2=Math.max(...b.map(x=>x[1]),1),tot=al.length||1;
 $('riskHist').innerHTML=al.length?b.map(x=>'<div class=brow><span class=blab>'+x[0]+'</span>'+
  '<div class=btrack><i style="width:'+(x[1]/mx2*100)+'%;background:'+x[2]+'"></i></div><b>'+x[1]+'</b>'+
  '<span class=bpct>'+Math.round(x[1]/tot*100)+'%</span></div>').join(''):'<div class="help empty">алертов пока нет</div>';}
let _alF='';
function alFilter(f){_alF=f;_alPage=0;document.querySelectorAll('#alFilters .af').forEach(b=>b.classList.toggle('on',b.dataset.f===f));pollAlerts();}
function skeletonRows(cols,rows){let h='';
 for(let r=0;r<(rows||6);r++){h+='<tr>';for(let c=0;c<cols;c++)h+='<td><div class=ds-skeleton style="width:'+(40+((r*7+c*13)%50))+'%"></div></td>';h+='</tr>';}
 return h;}
let _alSort={k:'ts',dir:'desc'},_alQ='',_alPage=0,_alRows=[],_AL_PER=25,_alLoaded=false;
function alSevOf(r){return r>=0.85?'critical':(r>=0.7?'high':(r>=0.5?'medium':'low'));}
function alSevBadge(r){const s=alSevOf(r);const M={critical:'b-crit',high:'b-high',medium:'b-med',low:'b-low'};
 return '<span class="badge '+M[s]+'">'+s+'</span>';}
function alSearchGo(){_alQ=($('alSearch').value||'').toLowerCase().trim();_alPage=0;renderAlerts();}
function alSortBy(k){if(_alSort.k===k)_alSort.dir=(_alSort.dir==='asc'?'desc':'asc');
 else{_alSort.k=k;_alSort.dir=(k==='ts'||k==='risk')?'desc':'asc';}_alPage=0;renderAlerts();}
function alPage(d){_alPage=Math.max(0,_alPage+d);renderAlerts();}

function renderAlerts(){
 const all=_alRows;
 let rows=all.filter(a=>{
  if(_alF==='crit')return (a.risk||0)>=0.85;
  if(_alF==='hi')return (a.risk||0)>=0.6;
  if(_alF==='ueba')return a.technique==='UEBA';
  if(_alF==='rules')return a.technique&&a.technique!=='UEBA';
  return true;});
 if(_alQ)rows=rows.filter(a=>((a.actor||'')+' '+(a.project||'')+' '+(a.reason||'')+' '+
   (a.technique||'')+' '+(a.action||'')+' '+(a.path||'')).toLowerCase().indexOf(_alQ)>=0);
 const K=_alSort.k,dir=_alSort.dir==='asc'?1:-1;
 const val=a=>K==='ts'?(a.ts_sim||''):K==='risk'?(a.risk||0):K==='sev'?(a.risk||0):
   K==='layer'?(a.technique==='UEBA'?'UEBA':'RULE'):(''+(a[K==='tech'?'technique':K]||''));
 rows=rows.slice().sort((x,y)=>{const A=val(x),B=val(y);
  return (typeof A==='number'?(A-B):(''+A).localeCompare(''+B))*dir;});

 const total=rows.length,pages=Math.max(1,Math.ceil(total/_AL_PER));
 if(_alPage>=pages)_alPage=pages-1;
 const page=rows.slice(_alPage*_AL_PER,(_alPage+1)*_AL_PER);
 $('alCount').textContent=(_alF||_alQ)?('показано '+total+' из '+all.length):(all.length+' детектов');

 document.querySelectorAll('#alTable thead th').forEach(th=>{
  const k=th.getAttribute('data-k');
  th.setAttribute('data-sort',k===_alSort.k?_alSort.dir:'');
  th.onclick=()=>alSortBy(k);});

 $('alBody').innerHTML=page.map((a,i)=>{
  const idx=_alPage*_AL_PER+i;
  return '<tr onclick="openAlert('+idx+')">'+
   '<td class=num style="color:var(--text-4)">'+esc((a.ts_sim||'').replace('T',' ').slice(5,16))+'</td>'+
   '<td>'+alSevBadge(a.risk||0)+'</td>'+
   '<td>'+(a.technique==='UEBA'?'<span class="ly u">UEBA</span>':'<span class="ly r">RULE</span>')+'</td>'+
   '<td style="color:var(--text-1);font-weight:600">@'+esc(a.actor||'—')+'</td>'+
   '<td class=num>'+esc(a.project||'—')+'</td>'+
   '<td>'+(a.technique&&a.technique!=='UEBA'?'<span class=tech>'+esc(a.technique)+'</span>':'<span class=sub>—</span>')+'</td>'+
   '<td>'+esc(a.reason||'')+'</td>'+
   '<td style="text-align:right"><span class="rk '+rkcls(a.risk)+'">'+a.risk+'</span></td></tr>';}).join('')
  ||'<tr><td colspan=8><div class="ds-empty">'+(all.length?'под фильтр ничего не попало':'детектов пока нет — запустите кампанию в Red Launcher')+'</div></td></tr>';

 $('alPager').innerHTML=total>_AL_PER?
  ('<button class="btn ghost" onclick="alPage(-1)"'+(_alPage<=0?' disabled':'')+'>← назад</button>'+
   '<span class=sub>страница '+(_alPage+1)+' из '+pages+'</span>'+
   '<button class="btn ghost" onclick="alPage(1)"'+(_alPage>=pages-1?' disabled':'')+'>вперёд →</button>'):'';
 _alSorted=rows;}

let _alSorted=[];
function openAlert(i){
 const a=_alSorted[i];if(!a)return;
 const sev=alSevOf(a.risk||0);
 dsDrawer('Детект · @'+esc(a.actor||'?'),
  '<div class=ds-kv>'+
   kvRow('Severity',alSevBadge(a.risk||0))+
   kvRow('Риск','<b class="rk '+rkcls(a.risk)+'">'+a.risk+'</b>')+
   kvRow('Слой',a.technique==='UEBA'?'поведенческий (UEBA)':'сигнатурное правило')+
   kvRow('Время',esc((a.ts_sim||'').replace('T',' ')))+
   kvRow('Разработчик','@'+esc(a.actor||'—'))+
   kvRow('Репозиторий',esc(a.project||'—'))+
   kvRow('Действие',esc(a.action||'—'))+
   (a.path?kvRow('Файл','<code>'+esc(a.path)+'</code>'):'')+
   (a.technique?kvRow('MITRE ATT&CK','<span class=tech>'+esc(a.technique)+'</span>'+(a.tactic?' · '+esc(a.tactic):'')):'')+
   kvRow('Инцидент',a.incident?('<a onclick="dsDrawerClose();goView(\'incidents\');setTimeout(function(){openInc('+a.incident+');},150)">#'+a.incident+' — открыть расследование</a>'):'<span class=sub>не сгруппирован</span>')+
  '</div>'+
  '<div class=ds-drawer-sec><div class=t-label>Причина срабатывания</div>'+
   '<div class=ds-answer style="margin-top:8px">'+esc(a.reason||'')+'</div></div>'+
  '<div class=ds-drawer-sec><div class=t-label>Быстрые действия</div>'+
   '<div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap">'+
   (a.incident?'<button class=btn onclick="dsDrawerClose();goView(\'incidents\');setTimeout(function(){openInc('+a.incident+');},150)">Открыть инцидент</button>':'')+
   '<button class="btn ghost" onclick="alFilterActor(\''+escJs(a.actor||'')+'\')">Все детекты @'+esc(a.actor||'')+'</button>'+
   '<button class="btn ghost" onclick="alFilterRepo(\''+escJs(a.project||'')+'\')">Все детекты в '+esc(a.project||'')+'</button>'+
   '</div></div>');}
async function saveNote(id){
 const el=$('incNote');if(!el)return;
 const st=$('noteSt');if(st)st.textContent='сохраняю…';
 try{await jpost('/api/incident/'+id+'/status',{reason:el.value});
  if(st)st.textContent='сохранено';
  if(window.toast)toast('Заметка расследования сохранена','success');
  if(_incData)_incData.workflow=Object.assign({},_incData.workflow||{},{reason:el.value});
 }catch(e){if(st)st.textContent='ошибка';if(window.toast)toast('Не удалось сохранить заметку','error');}}

function kvRow(k,v){return '<div class=ds-kv-row><span class=ds-kv-k>'+k+'</span><span class=ds-kv-v>'+v+'</span></div>';}
function alFilterActor(a){dsDrawerClose();$('alSearch').value=a;alSearchGo();}
function alFilterRepo(r){dsDrawerClose();$('alSearch').value=r;alSearchGo();}

async function pollAlerts(){
 if(!_alLoaded&&$('alBody')&&!$('alBody').innerHTML)$('alBody').innerHTML=skeletonRows(8,6);
 const d=await jget('/api/alerts');_alRows=d.alerts||[];_alLoaded=true;renderAlerts();}
async function pollIncidents(){const d=await jget('/api/incidents');
 $('incList').innerHTML=(d.incidents||[]).map(i=>'<div class=inc onclick="openInc('+i.id+')"><div class=h>'+
   '<span class=a>@'+esc(i.actor)+'</span>'+sevBadge(i.severity)+(i.is_campaign?'<span class="badge b-camp">CAMPAIGN</span>':'')+(i.triage?'<span class="badge b-camp">LLM: '+esc(i.triage)+'</span>':'')+
   (i.verdict?'<span class="vpill '+esc(i.verdict)+'" title="ваш вердикт">'+(i.verdict==='tp'?'✔ TP':'✘ FP')+'</span>':'')+
   (i.status&&i.status!=='new'?'<span class="stpill '+esc(i.status)+'">'+esc(i.status)+'</span>':'')+
   '<span class=grow></span><span class=sub>риск '+i.max_risk+'</span></div>'+
   '<div class=sub style=margin-top:5px>'+i.alerts+' алертов · '+esc((i.repos||[]).join(', '))+'</div>'+
   '<div class=chain>'+(i.tactics||[]).map(t=>'<span class=chip>'+esc(t)+'</span>').join('')+'</div></div>').join('')
   ||'<div class="help empty">инцидентов пока нет — запусти атаку в Red Launcher</div>';}
let _incTab='timeline', _incData=null;

function incTabs(){
 const T=[['timeline','Таймлайн'],['killchain','Kill-chain'],['evidence','Доказательства'],
          ['ai','AI-разбор'],['mitre','MITRE'],['actions','Действия']];
 return '<div class=ds-tabs id=incTabs>'+T.map(function(t){
  return '<button class="ds-tab'+(_incTab===t[0]?' on':'')+'" onclick="incGo(\''+t[0]+'\')">'+t[1]+'</button>';}).join('')+'</div>';}

function incGo(t){_incTab=t;renderIncBody();
 document.querySelectorAll('#incTabs .ds-tab').forEach(function(b){
  b.classList.toggle('on',b.textContent===({timeline:'Таймлайн',killchain:'Kill-chain',
   evidence:'Доказательства',ai:'AI-разбор',mitre:'MITRE',actions:'Действия'})[t]);});}

function incTimeline(i){
 const rows=(i.alerts||[]);
 if(!rows.length)return '<div class="ds-empty">Событий нет</div>';
 return '<div class=ds-timeline>'+rows.map(function(a){
  const cls=a.risk>=0.85?'critical':(a.risk>=0.6?'high':'info');
  return '<div class="ds-tl-item '+cls+'">'+
   '<div class=ds-tl-time>'+esc((a.ts_sim||'').replace('T',' '))+'</div>'+
   '<div class=ds-tl-title>'+esc(a.action||'')+
    (a.technique?' <span class=tech>'+esc(a.technique)+'</span>':'')+
    ' <span class="rk '+rkcls(a.risk)+'">'+a.risk+'</span></div>'+
   '<div class=ds-tl-desc>'+esc(a.reason||'')+
    (a.path?' · <code>'+esc(a.path)+'</code>':'')+
    (a.url?' · <a href="'+esc(a.url)+'" target=_blank>открыть в GitLab ↗</a>':'')+'</div></div>';}).join('')+'</div>';}

function incEvidence(i){
 const files={},repos=(i.repos||[]);
 (i.alerts||[]).forEach(function(a){if(a.path)files[a.path]=(files[a.path]||0)+1;});
 const fk=Object.keys(files);
 return '<div class=ds-ev-grid>'+
  '<div><div class=t-label>Затронутые репозитории</div><div class=ds-ev-list>'+
   (repos.length?repos.map(function(r){return '<div class=ds-ev-item><code>'+esc(r)+'</code></div>';}).join(''):'<div class=sub>—</div>')+'</div></div>'+
  '<div><div class=t-label>Затронутые файлы</div><div class=ds-ev-list>'+
   (fk.length?fk.map(function(f){return '<div class=ds-ev-item><code>'+esc(f)+'</code><span class=sub>'+files[f]+'×</span></div>';}).join(''):'<div class=sub>—</div>')+'</div></div>'+
  '</div>'+
  '<div class=ds-drawer-sec><div class=t-label>Индикаторы компрометации ('+((i.ioc||[]).length)+')</div>'+
   '<div class=iocg style=margin-top:8px>'+(i.ioc||[]).map(function(x){
     return '<div class=ioci><span class=ioct>'+esc(x.label)+'</span><span class=iocv>'+esc(x.value)+'</span></div>';}).join('')+'</div></div>';}

function incMitre(i){
 const ch=(i.chain||[]);
 if(!ch.length)return '<div class="ds-empty">Техники не определены</div>';
 return '<table class=ds-table><thead><tr><th scope=col style="width:60px">Шаг</th><th scope=col style="width:180px">Тактика</th>'+
  '<th scope=col style="width:140px">Техника</th><th scope=col>Действие</th></tr></thead><tbody>'+
  ch.map(function(c,n){return '<tr><td class=num>'+(n+1)+'</td>'+
   '<td><span class=chip><span class=t>'+esc(c.tactic||'?')+'</span></span></td>'+
   '<td class=num>'+esc(c.technique||'—')+'</td>'+
   '<td class=sub>'+esc(c.action||'')+'</td></tr>';}).join('')+'</tbody></table>';}

function incActions(i){
 return '<div class=ds-act-grid>'+
  '<button class=btn onclick="triage('+i.id+')">Запустить LLM-разбор</button>'+
  '<button class="btn ghost" onclick="llmPanel('+i.id+')">Что видела модель</button>'+
  '<a class="btn ghost" href="/api/incident/'+i.id+'/report" target=_blank style=text-decoration:none>Отчёт (PDF)</a>'+
  '<button class="btn ghost" onclick="casePick('+i.id+')">Приобщить к делу</button>'+
  (i.responded?'<a class="btn ghost" href="'+esc(i.responded)+'" target=_blank style=text-decoration:none>IR-issue заведён ↗</a>':
   (i.resp_pending?'<span class="btn ghost" style="opacity:.7">IR заводится…</span>':
    '<button class="btn ghost" id=respBtn onclick="respond('+i.id+')">'+(i.resp_error?'Повторить IR':'Реагировать — завести IR')+'</button>'))+
  '</div>'+
  (i.resp_error?'<div class=sub style="color:var(--critical);margin-top:8px">не удалось: '+esc(i.resp_error)+'</div>':'')+
  '<span class=toast id=incToast></span>'+
  '<div class=ds-drawer-sec><div class=t-label>Заметка расследования</div>'+
   '<div class=sub style=margin:6px_0_8px>Вывод аналитика. Попадает в отчёт по инциденту.</div>'+
   '<textarea class=tin id=incNote rows=4 style="width:100%;resize:vertical" '+
    'placeholder="Что установлено, почему такой вердикт, что сделано…">'+
    esc(((i.workflow||{}).reason)||'')+'</textarea>'+
   '<div style="display:flex;gap:8px;align-items:center;margin-top:8px">'+
    '<button class=btn onclick="saveNote('+i.id+')">Сохранить заметку</button>'+
    '<span class=sub id=noteSt></span></div></div>'+
  '<div class=ds-drawer-sec><div class=t-label>Рекомендованные действия</div>'+
   '<ul class=ds-reco>'+
   '<li>Отозвать токены и ключи учётной записи <b>@'+esc(i.actor)+'</b></li>'+
   '<li>Проверить затронутые репозитории: '+esc((i.repos||[]).join(', ')||'—')+'</li>'+
   '<li>Заморозить доступ до завершения разбора</li>'+
   '<li>Собрать таймлайн kill-chain и приложить к тикету</li></ul></div>'+
  '<div id=llmBox></div>';}

function renderIncBody(){
 const i=_incData;if(!i)return;const box=$('incBody');if(!box)return;
 if(_incTab==='timeline')box.innerHTML=incTimeline(i);
 else if(_incTab==='killchain')box.innerHTML=
  '<div style="display:flex;gap:8px;align-items:center;margin-bottom:10px">'+
   '<button class="btn ghost" id=playBtn onclick="playInc('+((i.chain||[]).length)+')">▶ Реплей атаки</button>'+
   '<input type=range class=rng id=rng min=0 max="'+(Math.max(0,(i.chain||[]).length-1))+
    '" value="'+(Math.max(0,(i.chain||[]).length-1))+'" oninput="scrub(+this.value)"></div>'+
   killchain(i.chain,i.alerts);
 else if(_incTab==='evidence')box.innerHTML=incEvidence(i);
 else if(_incTab==='mitre')box.innerHTML=incMitre(i);
 else if(_incTab==='actions'){box.innerHTML=incActions(i);}
 else if(_incTab==='ai'){box.innerHTML='<div id=triageBox></div><div id=llmBox></div>';showTriage(i.triage);}}

async function openInc(id){const i=await jget('/api/incident/'+id);if(i.error)return;
 _incData=i;_openId=i.id;
 $('incTtl').textContent='Инцидент #'+i.id+' · @'+i.actor;
 $('incDetail').innerHTML=
  '<div class=ds-inc-head>'+sevBadge(i.severity)+
   (i.is_campaign?' <span class="badge b-camp">многошаговая</span>':'')+
   ' <span class=ds-inc-risk>риск '+Math.round(i.max_risk*100)/100+'</span>'+
   ' <span class=sub>'+((i.alerts||[]).length)+' событий · '+((i.repos||[]).length)+' репозиториев</span></div>'+
  '<div class=wfstatus id=wfStatus></div>'+
  incTabs()+
  '<div id=incBody class=ds-tabbody></div>';
 renderIncBody();
 renderWfStatus(i.id,i.workflow);}
let _openId=null;
function renderWfStatus(id,wf){const box=$('wfStatus');if(!box)return;wf=wf||{status:'new'};
 const CN={new:'новый',investigating:'в работе',contained:'сдержано',closed:'закрыто'};
 const steps=['new','investigating','contained','closed'];
 box.innerHTML='<div class=wfline>'+steps.map(s=>'<button class="wfstep'+(wf.status===s?' on':'')+'" onclick="setStatus('+id+',\''+s+'\')">'+CN[s]+'</button>').join('<span class=wfarr>›</span>')+
  '<span class=grow></span>'+
  '<button class="wfv tp'+(wf.verdict==='tp'?' on':'')+'" onclick="setStatus('+id+',\'closed\',\'tp\')">✔ TP</button>'+
  '<button class="wfv fp'+(wf.verdict==='fp'?' on':'')+'" onclick="setStatus('+id+',\'closed\',\'fp\')">✘ FP</button></div>'+
  (wf.verdict
    ? '<div class=vbanner><span class="vpill '+wf.verdict+'">'+(wf.verdict==='tp'?'✔ TP — подтверждённая атака':'✘ FP — ложное срабатывание')+'</span>'+
      (wf.verdict==='fp'?'<span class=sub>правила из этого инцидента получают +1 FP; после 3 подтверждений правило глушится (см. «Очередь триажа» → «Самые шумные правила»)</span>':'<span class=sub>инцидент закрыт как настоящая атака</span>')+
      (wf.updated?'<span class=sub style=margin-left:auto>'+wf.updated.replace('T',' ')+'</span>':'')+'</div>'
    : '<div class=sub style=margin-top:5px>вердикт не выставлен — нажмите TP или FP</div>');}
async function setStatus(id,status,verdict){await jpost('/api/incident/'+id+'/status',{status:status,verdict:verdict||null});
 if(window.toast){const CN={new:'новый',investigating:'в работе',contained:'сдержано',closed:'закрыто'};
  toast(verdict?('Инцидент #'+id+' закрыт как '+verdict.toUpperCase()):('Статус инцидента #'+id+': '+(CN[status]||status)),
        verdict==='tp'?'error':(verdict==='fp'?'warning':'success'));}
 const i=await jget('/api/incident/'+id);renderWfStatus(id,i.workflow);
 try{await pollIncidents();}catch(e){}
 try{if(typeof pollWorkflow==='function')await pollWorkflow();}catch(e){}}
async function llmPanel(id){const box=$('llmBox');
 if(box.dataset.open==='1'){box.dataset.open='';box.innerHTML='';return;}
 box.dataset.open='1';box.innerHTML='<div class=sub style=margin-top:10px>загружаю контекст…</div>';
 let d;try{d=await jget('/api/incident/'+id+'/llm');}catch(e){box.innerHTML='<div class=sub>ошибка</div>';return;}
 box.innerHTML='<div class=card style="margin-top:10px;background:var(--panel2);border-color:var(--line2)">'+
  '<div style=display:flex;align-items:center;gap:8px><b>Вход модели</b>'+
   '<span class="badge '+(d.ollama_available?'b-med':'b-low')+'">'+(d.ollama_available?'Ollama: '+esc(d.model||'on'):'Ollama не запущена')+'</span>'+
   '<span class=grow></span><span class=sub>hash '+esc(d.context_hash)+'</span></div>'+
  '<div class=sub style="margin:6px 0">Это ровно тот JSON, который уходит в модель. Здесь нет разметки симулятора — '+
   'ни «это атака», ни типа аномалии: '+esc(d.leak_guard)+'</div>'+
  '<div class=sub style=margin-bottom:4px>полей: <b>'+d.context_fields.length+'</b> — '+d.context_fields.map(esc).join(', ')+'</div>'+
  '<pre class=llmctx>'+esc(d.context_json)+'</pre>'+
  '<div class=sub style=margin-top:8px>Вывод модели — на кнопке <b>«LLM-разбор»</b>.</div>'+
  '<div class=askbox style=margin-top:12px><input class=askin id=incAskIn placeholder="спроси про этот инцидент: почему это TP? кто ещё затронут?" onkeydown="if(event.key===\'Enter\')incAsk('+id+')"><button class=btn onclick=incAsk('+id+')>Спросить</button></div>'+
  '<div id=incAskAns class=sub></div></div>';}
async function incAsk(id){const q=$('incAskIn').value.trim();if(!q)return;$('incAskAns').textContent='думаю…';
 const r=await jpost('/api/incident/'+id+'/ask',{q:q});$('incAskAns').innerHTML='<b>'+esc(r.answer||'')+'</b> <span class=sub>('+esc(r.source||'')+')</span>';}

function showTriage(t){const box=$('triageBox');if(!box)return;
 if(!t){box.innerHTML='<div class=sub style=margin-top:10px>\u0410\u0432\u0442\u043e-\u0440\u0430\u0437\u0431\u043e\u0440 LLM \u0432\u044b\u043f\u043e\u043b\u043d\u044f\u0435\u0442\u0441\u044f \u0432 \u0444\u043e\u043d\u0435\u2026</div>';return;}
 box.innerHTML='<div class=card style="margin-top:10px;background:var(--panel2)"><div class=sub>LLM-\u0440\u0430\u0437\u0431\u043e\u0440 \u00b7 \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a: '+esc(t._source||'?')+'</div>'+
  '<div style=margin-top:6px>'+sevBadge(t.severity||'low')+' <b>'+esc(t.title||'')+'</b> <span class=sub>TP: '+(t.is_true_positive?'\u0434\u0430':'\u043d\u0435\u0442')+' \u00b7 conf '+(t.confidence||'')+'</span></div>'+
  '<div style=margin-top:8px>'+esc(t.narrative||'')+'</div>'+
  ((t.recommended_actions||[]).length?'<div style=margin-top:8px><b>\u0414\u0435\u0439\u0441\u0442\u0432\u0438\u044f:</b><ul>'+(t.recommended_actions||[]).map(a=>'<li>'+esc(a)+'</li>').join('')+'</ul></div>':'')+
  (t.benign_explanation?'<div class=sub style=margin-top:6px>benign: '+esc(t.benign_explanation)+'</div>':'')+'</div>';}
async function triage(id){showTriage(null);const r=await jpost('/api/incident/'+id+'/triage',{});showTriage(r.triage||{});}
async function refreshOpenTriage(){if(_openId==null)return;try{const i=await jget('/api/incident/'+_openId);if(i&&i.triage)showTriage(i.triage);}catch(e){}}
setInterval(refreshOpenTriage,3000);
async function respond(id){const t0=$('incToast');if(t0)t0.textContent='IR заводится в GitLab…';
 if(window.toast)toast('Завожу IR-issue в GitLab…','info');
 await jpost('/api/incident/'+id+'/respond',{});
 let n=0;const t=setInterval(async()=>{n++;let i;try{i=await jget('/api/incident/'+id);}catch(e){return;}
  if(i.responded||i.resp_error||n>12){clearInterval(t);if(_openId==id)openInc(id);
   const tt=$('incToast');
   if(tt)tt.textContent=i.responded?'IR-issue заведён':(i.resp_error?('не удалось: '+i.resp_error):'');
   if(window.toast){if(i.responded)toast('IR-issue заведён в GitLab','success');
    else if(i.resp_error)toast('Не удалось завести IR: '+i.resp_error,'error',5000);}}},1800);}
let _cov={};
function covSummary(grid){
 /* Считаем по УНИКАЛЬНЫМ техникам: одна и та же техника у MITRE может
    стоять в нескольких тактиках (T1098 — и Persistence, и Privilege
    Escalation). Если считать ячейки, процент здесь разойдётся с
    цифрой на дашборде. */
 const seen={},gaps=[];let total=0,cov=0,fired=0;
 (grid||[]).forEach(col=>col.techniques.forEach(c=>{
  if(seen[c.technique])return;
  seen[c.technique]=1;total++;
  if(c.fired)fired++; if(c.covered)cov++;
  if(!c.covered)gaps.push(c.technique+' · '+c.name);}));
 const pct=total?Math.round(cov/total*100):0;
 const box=$('covStrip');if(!box)return;
 box.innerHTML=
  '<div class=ds-covcard><div class=ds-covcard-n>'+pct+'%</div><div class=ds-covcard-l>покрытие</div></div>'+
  '<div class=ds-covcard><div class=ds-covcard-n>'+total+'</div><div class=ds-covcard-l>техник в матрице</div></div>'+
  '<div class=ds-covcard><div class="ds-covcard-n ok">'+cov+'</div><div class=ds-covcard-l>покрыто правилами</div></div>'+
  '<div class=ds-covcard><div class="ds-covcard-n crit">'+fired+'</div><div class=ds-covcard-l>срабатывало</div></div>'+
  '<div class=ds-covcard><div class="ds-covcard-n warn">'+(total-cov)+'</div><div class=ds-covcard-l>слепых зон</div></div>';}

async function pollAttack(){const d=await jget('/api/coverage');_cov={};
 covSummary(d.grid);
 $('matrix').innerHTML=(d.grid||[]).map(col=>'<div class=mcol><div class=th>'+esc(col.tactic)+'</div>'+
   col.techniques.map(c=>{_cov[c.technique]={...c,tactic:col.tactic};
    return '<div class="cell '+(c.fired?'fired':(c.covered?'cov':''))+'" onclick="cellInfo(\''+c.technique+'\')"><div class=tid>'+esc(c.technique)+'</div>'+
     '<div class=nm>'+esc(c.name)+'</div><div class=ct>'+(c.fired?('&#9650; '+c.fired+' срабат.'):(c.covered?'есть правило':'слепая зона'))+'</div></div>';}).join('')+
   '</div>').join('');}
async function cellInfo(tid){const c=_cov[tid];if(!c)return;
 // связанные инциденты: те, в цепочке которых встречается эта техника
 let rel=[];
 try{const inc=(await jget('/api/incidents')).incidents||[];
  rel=inc.filter(i=>(i.techniques||[]).indexOf(tid)>=0);}catch(e){}
 const rulesHtml=(c.rules||[]).length
  ? (c.rules||[]).map(r=>'<div class=ds-ev-item><span>'+esc(r.title)+'</span>'+sevBadge(r.severity||'low')+'</div>').join('')
  : '<div class="ds-empty">Правил нет — слепая зона, кандидат на новое правило</div>';
 const relHtml=rel.length
  ? rel.map(i=>'<div class=ds-ev-item style=cursor:pointer onclick="dsDrawerClose();goView(\'incidents\');setTimeout(function(){openInc('+i.id+');},150)">'+
      '<span>#'+i.id+' · @'+esc(i.actor)+'</span>'+sevBadge(i.severity)+'</div>').join('')
  : '<div class=sub>инцидентов с этой техникой пока нет</div>';
 dsDrawer(esc(tid)+' · '+esc(c.name),
  '<div class=ds-kv>'+
   kvRow('Тактика',esc(c.tactic))+
   kvRow('Статус',c.fired?('<span class="badge b-crit">срабатывала ×'+c.fired+'</span>'):
     (c.covered?'<span class="badge b-med">покрыта правилом</span>':'<span class="badge b-low">слепая зона</span>'))+
   kvRow('Покрывающих правил',((c.rules||[]).length))+
   kvRow('MITRE','<a href="https://attack.mitre.org/techniques/'+esc(tid.replace(".","/"))+'/" target=_blank>открыть в ATT&CK ↗</a>')+
  '</div>'+
  '<div class=ds-drawer-sec><div class=t-label>Правила детектирования</div>'+
   '<div class=ds-ev-list>'+rulesHtml+'</div></div>'+
  '<div class=ds-drawer-sec><div class=t-label>Связанные инциденты ('+rel.length+')</div>'+
   '<div class=ds-ev-list>'+relHtml+'</div></div>');}

function cellInfoOld(tid){const c=_cov[tid];if(!c)return;const p=$('cellPanel');p.style.display='block';
 const rules=(c.rules||[]).map(r=>'<div class=brow style=grid-template-columns:1fr_auto><span class=blab>'+esc(r.title)+'</span>'+sevBadge(r.severity||'low')+'</div>').join('')||'<div class=sub>правил нет — это слепая зона, кандидат на новое правило</div>';
 p.innerHTML='<div style=display:flex;align-items:center;gap:9px><b style=font-family:ui-monospace>'+esc(tid)+'</b> <span>'+esc(c.name)+'</span>'+
  '<span class="badge '+(c.fired?'b-crit':(c.covered?'b-med':'b-low'))+'">'+(c.fired?('срабатывала ×'+c.fired):(c.covered?'покрыта':'слепая зона'))+'</span>'+
  '<span class=grow></span><a class=tech href="https://attack.mitre.org/techniques/'+esc(tid.replace(".","/"))+'/" target=_blank style=text-decoration:none>MITRE ↗</a>'+
  '<span class=x onclick="$(\'cellPanel\').style.display=\'none\'" style=cursor:pointer;font-weight:800;color:#7c3aed;padding:0_6px>✕</span></div>'+
  '<div class=sub style=margin:8px_0_4px>тактика: '+esc(c.tactic)+' · покрывающих правил: '+((c.rules||[]).length)+'</div>'+rules;
 p.scrollIntoView({behavior:'smooth',block:'nearest'});}
let _rules=[],_ruleQ='',_ruleF='';
function ruleSearchGo(){_ruleQ=($('ruleSearch').value||'').toLowerCase().trim();renderRules();}
function ruleFilter(f){_ruleF=f;
 document.querySelectorAll('#ruleFilters .af').forEach(b=>b.classList.toggle('on',b.dataset.f===f));
 renderRules();}
function renderRules(){
 let rows=_rules.slice();
 if(_ruleF==='fired')rows=rows.filter(r=>r.fired>0);
 else if(_ruleF==='silent')rows=rows.filter(r=>!r.fired);
 else if(_ruleF)rows=rows.filter(r=>(r.severity||'')===_ruleF);
 if(_ruleQ)rows=rows.filter(r=>((r.title||'')+' '+(r.id||'')+' '+(r.technique||'')+' '+
   (r.tactic||'')).toLowerCase().indexOf(_ruleQ)>=0);
 $('ruleCount').textContent='показано '+rows.length+' из '+_rules.length;
 $('rules').innerHTML=rows.map((r,i)=>
   '<div class=rule style=cursor:pointer onclick="openRule('+_rules.indexOf(r)+')">'+
   '<span class=tech>'+esc(r.technique||'—')+'</span><b>'+esc(r.title)+'</b>'+
   '<span class=grow></span>'+sevBadge(r.severity)+
   '<span class=sub>риск '+r.risk+'</span>'+
   '<span class="badge '+(r.fired?'b-crit':'b-low')+'">'+(r.fired?('×'+r.fired):'0')+'</span></div>').join('')
  ||'<div class="ds-empty">Под фильтр ничего не попало</div>';}
function openRule(i){
 const r=_rules[i];if(!r)return;
 dsDrawer('Правило · '+esc(r.title),
  '<div class=ds-kv>'+
   kvRow('Идентификатор','<code>'+esc(r.id)+'</code>')+
   kvRow('Severity',sevBadge(r.severity))+
   kvRow('Базовый риск','<b class=num>'+r.risk+'</b>')+
   kvRow('MITRE',r.technique?('<span class=tech>'+esc(r.technique)+'</span>'+(r.tactic?' · '+esc(r.tactic):'')):'—')+
   kvRow('Сработок',r.fired?('<b class=num>'+r.fired+'</b>'):'<span class=sub>ни разу</span>')+
  '</div>'+
  '<div class=ds-drawer-sec><div class=t-label>Что это значит</div>'+
   '<div class=ds-answer style="margin-top:8px">'+
   (r.fired?('Правило сработало '+r.fired+' раз(а). Проверьте связанные детекты — если это шум, отметьте инциденты как FP: после трёх подтверждений правило перестанет поднимать инциденты.')
          :'Правило активно, но пока ни разу не срабатывало. Это нормально для редких техник — проверить можно кампанией в Red Launcher.')+
   '</div></div>'+
  '<div class=ds-drawer-sec><div class=t-label>Действия</div>'+
   '<div class=ds-act-grid style=margin-top:8px>'+
   '<button class=btn onclick="dsDrawerClose();goView(\'alerts\');setTimeout(function(){$(\'alSearch\').value='+JSON.stringify(r.technique||r.title)+';alSearchGo();},200)">Показать детекты правила</button>'+
   '<button class="btn ghost" onclick="dsDrawerClose();goView(\'attack\')">Открыть матрицу ATT&CK</button>'+
   '</div></div>');}

async function pollDetections(){const d=await jget('/api/detections');_rules=d.rules||[];renderRules();}
function scrub(k){const w=$('kcwrap');if(!w)return;w.classList.add('replaying');const n=w.querySelectorAll('.kcs').length;for(let i=0;i<n;i++){const e=$('kcs-'+i);if(!e)continue;e.classList.toggle('on',i<=k);e.classList.toggle('cur',i===k);}const r=$('rng');if(r)r.value=k;}
let _playT=null;
function playInc(max){const btn=$('playBtn');if(_playT){clearInterval(_playT);_playT=null;if(btn)btn.textContent='▶ Реплей атаки';return;}if(btn)btn.textContent='⏸ Пауза';let k=0;scrub(0);_playT=setInterval(()=>{k++;if(k>=max){clearInterval(_playT);_playT=null;if(btn)btn.textContent='▶ Реплей атаки';scrub(Math.max(0,max-1));return;}scrub(k);},750);}
const ASK_PROMPTS=['что делала maria ночью','покажи секреты в soc-infra','кто трогал .gitlab-ci.yml',
 'какие удаления файлов были','кто создавал токены','активность вне рабочих часов'];
function renderPrompts(){const b=$('askPrompts');if(!b||b.dataset.done)return;b.dataset.done='1';
 b.innerHTML=ASK_PROMPTS.map(function(p){return '<button class="chip ds-prompt" onclick="askPreset(this)">'+esc(p)+'</button>';}).join('');}
function askPreset(el){$('askIn').value=el.textContent;askQuery();}
async function askQuery(){const q=$('askIn').value.trim();if(!q)return;$('askAns').textContent='ищу…';const r=await jpost('/api/ask',{q:q});
 $('askAns').innerHTML='<b>'+esc(r.answer||'')+'</b>';
 $('askEv').innerHTML=(r.events||[]).map(e=>'<div class="al lo"><span class=ts>'+esc((e.ts_sim||'').replace('T',' ').slice(5,16))+'</span><span class=who>@'+esc(e.actor)+'</span><span>'+esc(e.action)+'→'+esc(e.project)+'</span>'+(e.path?'<span class=sub>'+esc(e.path)+'</span>':'')+(e.is_night?'<span class=tech title="событие вне рабочих часов команды">вне работы</span>':'')+'</div>').join('')||'<div class=sub>ничего не найдено</div>';}
let _wfSel=0,_wfIds=[];
async function pollWorkflow(){let d;try{d=await jget('/api/workflow');}catch(e){return;}
 const CN={new:'новый',investigating:'в работе',contained:'сдержан',closed:'закрыт'};
 $('wfCounts').innerHTML=['new','investigating','contained','closed'].map(k=>
  '<div class=wfcount><div class=n>'+(d.counts[k]||0)+'</div><div class=l>'+CN[k]+'</div></div>').join('')+
  '<div class=wfcount><div class=n>'+d.items.length+'</div><div class=l>всего</div></div>';
 _wfIds=d.items.map(x=>x.id);if(_wfSel>=_wfIds.length)_wfSel=Math.max(0,_wfIds.length-1);
 const fmtAgeM=s=>s<3600?Math.floor(s/60)+'м':Math.floor(s/3600)+'ч';
 $('wfQueue').innerHTML=d.items.map((x,idx)=>{
  return '<div class="wfi'+(idx===_wfSel?' sel':'')+'" data-id='+x.id+' onclick="wfPick('+idx+')" ondblclick="openInc('+x.id+');goView(\'incidents\')">'+
   sevBadge(x.severity)+'<div><div class=who>@'+esc(x.actor)+(x.is_campaign?' <span class="badge b-camp">campaign</span>':'')+'</div>'+
   '<div class=meta>риск '+x.max_risk+' · '+plural(x.alerts,'детект','детекта','детектов')+' · '+plural((x.tactics||[]).length,'тактика','тактики','тактик')+(x.owner?' · 👤'+esc(x.owner):'')+'</div></div>'+
   '<span class=grow></span>'+
   (x.verdict?'<span class="vpill '+x.verdict+'">'+x.verdict.toUpperCase()+'</span>':'')+
   '<span class="stpill '+x.status+'">'+esc(CN[x.status]||x.status)+'</span>'+
   '<span class="sla '+x.sla+'" title="SLA-таймер">'+fmtAgeM(x.age_s)+'</span></div>';}).join('')||'<div class="help empty">очередь пуста — запусти кампанию</div>';
 const mxf=Math.max(1,...d.noisy_rules.map(r=>r.fired));
 $('wfNoisy').innerHTML=d.noisy_rules.map(r=>'<div class=brow><span class=blab title="'+esc(r.rule_id)+'">'+esc(r.rule_id)+
  (r.muted?' <span class="vpill fp" title="правило заглушено вашими FP — новые сработки отбрасываются">заглушено</span>':'')+'</span>'+
  '<div class=btrack><i style="width:'+(r.fired/mxf*100)+'%;background:'+(r.muted?'#94a3b8':(r.fp>0?'#dc2626':'#5457d6'))+'"></i></div>'+
  '<b>'+r.fired+'</b><span class=bpct>'+(r.fp>0?'FP '+r.fp:'')+'</span></div>').join('')||'<div class=sub>—</div>';
 const mh=$('wfMuted');if(mh)mh.innerHTML=d.muted_hits?('Отклонено FP-тюнингом: <b>'+d.muted_hits+'</b> сработок. Правило глушится после <b>'+d.fp_threshold+'</b> подтверждённых FP.'):('Пометьте инцидент как FP (клавиша <b>F</b>) — после <b>'+(d.fp_threshold||3)+'</b> подтверждений правило перестаёт поднимать инциденты.');}
function wfPick(idx){_wfSel=idx;document.querySelectorAll('.wfi').forEach((e,i)=>e.classList.toggle('sel',i===idx));}
async function wfSet(status,verdict){const id=_wfIds[_wfSel];if(id==null)return;
 await jpost('/api/incident/'+id+'/status',{status:status,verdict:verdict});pollWorkflow();}
document.addEventListener('keydown',e=>{if(view!=='workflow')return;if(/input|textarea/i.test((e.target.tagName||'')))return;
 const k=e.key.toLowerCase();
 if(k==='j'){_wfSel=Math.min(_wfIds.length-1,_wfSel+1);wfPick(_wfSel);}
 else if(k==='k'){_wfSel=Math.max(0,_wfSel-1);wfPick(_wfSel);}
 else if(k==='t'){wfSet('closed','tp');}
 else if(k==='f'){wfSet('closed','fp');}
 else if(k==='e'){wfSet('investigating',null);}
 else if(e.key==='Enter'){const id=_wfIds[_wfSel];if(id!=null){openInc(id);goView('incidents');}}});
async function snapNow(){$('trendNote').textContent='считаю снапшот…';await jpost('/api/metrics/snapshot',{});setTimeout(()=>{ _trDone=false;pollTrends();},1500);}
let _trDone=false;
async function pollTrends(){let d;try{d=await jget('/api/trends');}catch(e){return;}
 const H=d.history||[];
 if(!H.length){$('trendGrid').innerHTML='<div class="help empty">Снапшотов пока нет. Нажмите «снять снапшот сейчас» в подсказке над карточками — метрики посчитаются по текущему прогону.</div>';return;}
 const defs=[['detection_rate','Доля обнаруженных атак',cssv('--accent-brand','#6366F1'),1],['coverage','Покрытие ATT&CK',cssv('--info','#3B82F6'),1],['fp_rate','Доля ложных срабатываний',cssv('--critical','#DC2626'),1],['mttd','Время до обнаружения, мин',cssv('--success','#10B981'),0]];
 $('trendGrid').innerHTML=defs.map(df=>{
  const vals=H.map(h=>h[df[0]]).filter(v=>v!=null);if(!vals.length)return '';
  const isPct=df[3], W=100,Ht=34,p=3,n=vals.length;
  const mx=isPct?1:Math.max(...vals,0.01),mn=0;
  const X=i=>n<=1?W/2:p+(i/(n-1))*(W-2*p),Y=v=>Ht-p-((v-mn)/((mx-mn)||1))*(Ht-2*p);
  let line='';vals.forEach((v,i)=>{line+=(i?'L':'M')+X(i).toFixed(1)+' '+Y(v).toFixed(1)+' ';});
  const last=vals[vals.length-1],cur=isPct?Math.round(last*100)+'%':(Math.round(last*10)/10);
  const first=vals[0],delta=isPct?Math.round((last-first)*100)+' п.п.':(Math.round((last-first)*10)/10);
  return '<div class=tchart><h3>'+df[1]+'</h3><div class=cur style=color:'+df[2]+'>'+cur+'</div>'+
   '<svg viewBox="0 0 100 38" preserveAspectRatio=none style="width:100%;height:80px;display:block"><path d="'+line+'" fill=none stroke='+df[2]+' stroke-width=1.4 stroke-linejoin=round vector-effect=non-scaling-stroke />'+
   vals.map((v,i)=>'<circle cx='+X(i).toFixed(1)+' cy='+Y(v).toFixed(1)+' r=1 fill='+df[2]+'/>').join('')+'</svg>'+
   '<div class=sub>'+n+' точек · Δ '+delta+'</div></div>';}).join('');
 $('trendNote').textContent=H.length+' снапшотов · '+(d.annotations||[]).length+' меток событий · последний '+((H[H.length-1].ts||'').replace('T',' '));}
function hoursHist(hh){if(!hh||!hh.length)return '';
 const m={};hh.forEach(x=>{m[x[0]]=x[1];});
 const mx=Math.max(...hh.map(x=>x[1]),1);
 let h='<div class=sub style="margin-top:8px">суточный профиль активности (0–23ч):</div><div style="display:flex;gap:2px;align-items:flex-end;height:38px;margin-top:4px">';
 for(let i=0;i<24;i++){const v=m[i]||0;const night=(i>=22||i<7);
  h+='<div title="'+i+':00 — '+v+' соб." style="flex:1;border-radius:2px 2px 0 0;min-height:2px;height:'+Math.max(4,v/mx*100)+'%;background:'+(v?(night?'#ffa94d':'#7048e8'):'#20263a')+'"></div>';}
 h+='</div><div class=sub style="display:flex;justify-content:space-between;font-size:9.5px"><span>0</span><span>6</span><span>12</span><span>18</span><span>23</span></div>';
 return h;}
async function pollEntities(){const d=await jget('/api/entities');
 $('entList').innerHTML=(d.entities||[]).map(e=>'<div class=inc onclick="openEnt(\''+escJs(e.actor)+'\')"><div class=h>'+
   '<span class=a>@'+esc(e.actor)+'</span><span class=grow></span><span class=sub>'+e.alerts+' алертов · '+e.events_seen+' соб.</span></div></div>').join('')||'<div class=sub>нет данных</div>';}
async function openEnt(a){const e=await jget('/api/entity/'+encodeURIComponent(a));const b=e.baseline;
 const why=Object.keys(e.tactics_hit||{}).map(t=>'<span class=chip>'+esc(t)+' ×'+e.tactics_hit[t]+'</span>').join(' ')||'<span class=sub>—</span>';
 $('entTtl').textContent='@'+a;
 $('entDetail').innerHTML='<div>'+sevBadge(e.risk_label)+' <span class=sub>пиковый риск '+e.max_risk+' · '+e.alerts_total+' алертов</span></div>'+
  (b?('<div style=margin-top:10px><b>Базлайн (UEBA):</b> '+b.events_seen+' событий</div>'+
   hoursHist(b.hours_hist)+
   '<div class=sub style=margin-top:4px>типичные часы: '+(b.top_hours||[]).join(', ')+'</div>'+
   '<div class=sub>репозитории: '+esc((b.top_repos||[]).join(', '))+'</div>'+
   '<div class=sub>действия: '+esc((b.top_actions||[]).join(', '))+'</div>'):'<div class=sub style=margin-top:10px>базлайн ещё не накоплен</div>')+
  '<div style=margin-top:10px><b>Почему подозрителен:</b><div class=chain style=margin-top:6px>'+why+'</div></div>'+
  '<div style=margin-top:10px><b>Недавние алерты:</b></div><div class=feed style=max-height:34vh;margin-top:6px>'+
  (e.recent_alerts||[]).map(x=>'<div class="al '+rkcls(x.risk)+'"><span class=ts>'+esc((x.ts_sim||'').replace('T',' ').slice(5,16))+'</span><span>'+esc(x.action)+'→'+esc(x.project)+'</span>'+(x.technique?'<span class=tech>'+esc(x.technique)+'</span>':'')+'<span class="rk '+rkcls(x.risk)+'">'+x.risk+'</span></div>').join('')+'</div>';}
async function pollRed(){const d=await jget('/api/red');
 $('camps').innerHTML=(d.campaigns||[]).map(c=>'<div class=inc><div class=h><span class=a>'+esc(c.title)+'</span>'+
   '<span class=grow></span><button class=btn onclick="launch(\''+c.key+'\')">▶ Запустить</button></div>'+
   '<div class=chain style=margin-top:8px>'+c.steps.map((s,n)=>'<span class=chip><b>'+(n+1)+'.</b> <span class=t>'+esc(s.tactic)+'</span> '+esc(s.technique)+'</span>').join(' → ')+'</div></div>').join('');
 /* Очередь читается человеком: служебные слова переводим, снейк-кейс
    сценария разворачиваем в название, «3/4 steps» — в «шаг 3 из 4». */
 const CMD_T={campaign:'кампания',response:'реагирование',reset:'сброс'};
 const CMD_S={done:'выполнено',queued:'в очереди',running:'выполняется',
              failed:'ошибка',error:'ошибка',pending:'ожидает'};
 const SCEN={insider_secret_theft:'кража секрета инсайдером',
             review_bypass_sabotage:'обход ревью и саботаж',
             ci_token_exfil:'вынос CI-токена',
             recon_to_exfil:'разведка и вынос данных',
             supply_chain:'атака на цепочку поставок'};
 const human=r=>{
   if(!r)return '';
   if(/^https?:\/\//.test(r))return '<a href="'+esc(r)+'" target=_blank>открыть issue ↗</a>';
   let m=r.match(/^([a-z_]+):\s*(\d+)\/(\d+)\s*steps?$/i);
   if(m)return esc(SCEN[m[1]]||m[1].replace(/_/g,' '))+' · шаг '+m[2]+' из '+m[3];
   m=r.match(/^([a-z_]+)$/i);
   if(m)return esc(SCEN[m[1]]||m[1].replace(/_/g,' '));
   return esc(r);};
 $('cmds').innerHTML=(d.commands||[]).map(c=>{
   const st=CMD_S[String(c.status||'').toLowerCase()]||esc(c.status||'');
   const parts=String(c.result||'').split('·').map(x=>x.trim()).filter(Boolean);
   const tail=parts.map(human).filter(Boolean).join(' · ');
   return '<div class=row><span class=mono>#'+c.id+'</span> <span>'+
     esc(CMD_T[c.type]||c.type||'')+'</span><span class=grow></span><b>'+st+
     (tail?(' · '+tail):'')+'</b></div>';}).join('')||'<div class="help empty">команд нет</div>';}
async function launch(key){const ev=$('evasion').value;$('redToast').textContent='ставлю в очередь…';
 const r=await jpost('/api/red/launch',{key:key,evasion:ev});$('redToast').textContent=r.msg||'';
 if(window.toast){if(r.ok)toast('Кампания запущена ('+ev+') — детекты появятся через ~30 с','success',4500);
  else toast('Не удалось запустить: '+(r.msg||'ошибка'),'error');}
 setTimeout(()=>{$('redToast').textContent='';pollRed();},4000);}
/* Состояние служебных подсистем. Раньше Ollama висела в верхней панели
   рядом с рабочими показателями — это шум: аналитику не нужно знать про
   конкретный сервис, ему нужен поток событий и детекты. Инфраструктура
   переехала сюда, в диагностику, где ей и место. */
async function pollInfra(){
 const box=$('diagInfra');if(!box)return;
 let h={},s={};
 try{h=await jget('/api/health');}catch(e){}
 try{s=await jget('/api/stats');}catch(e){}
 const ev=h.events||{};
 const rows=[
  ['GitLab',        h.gitlab!==false?'ok':'bad', h.gitlab!==false?'на связи':'нет связи'],
  ['Симуляция',     h.world_alive?'ok':(ev.total>0?'warn':'bad'), h.world_alive?'пишет':'молчит'],
  ['Event store',   ev.total>0?'ok':'bad', fmtNum(ev.total||0)+' соб.'],
  ['Детектор',      (s.rules||0)>0?'ok':'warn', nRule(s.rules||0)],
  ['Приём событий', (s.processed||0)>0?'ok':'warn', fmtNum(s.processed||0)+' обраб.'],
  ['Поведение (UEBA)', (s.techniques_fired||0)>0?'ok':'warn', nTech(s.techniques_fired||0)],
  ['LLM (Ollama)',  h.ollama?'ok':'warn', h.ollama?'готова':'недоступна'],
  ['Авто-триаж',    h.auto_triage?'ok':'', h.auto_triage?'включён':'выключен']];
 box.innerHTML=rows.map(r=>healthTile(r[0],r[1],r[2],'')).join('');}

async function pollDiag(){let d;try{d=await jget('/api/diag');}catch(e){return;}
 const c=d.counts||{};
 $('diagCounts').innerHTML=[['ERROR','crit'],['WARNING',''],['INFO','acc'],['DEBUG','']].map(x=>
  '<div class="kpi '+x[1]+'"><div class=n>'+(c[x[0]]||0)+'</div><div class=l>'+x[0]+'</div></div>').join('')+
  '<div class=kpi ok><div class=n>'+((d.errors||[]).length?'⚠':'✓')+'</div><div class=l>'+((d.errors||[]).length?'есть ошибки':'ошибок нет')+'</div></div>';
 await pollInfra();
 const tail=(d.errors_log_tail||[]).join('');
 $('diagErrors').textContent=tail||'файл пуст — ошибок не зафиксировано';
 const lvl=$('diagLvl').value;
 const rows=(d.recent||[]).filter(r=>!lvl||r.level===lvl).slice(-120).reverse();
 $('diagRecent').innerHTML=rows.map(r=>'<div class="al '+(r.level==='ERROR'?'hi':(r.level==='DEBUG'?'lo':''))+'">'+
  '<span class=ts>'+esc(r.ts)+'</span><span class=tech>'+esc(r.level)+'</span><span class=who>'+esc(r.module)+'</span>'+
  '<span>'+esc(r.event)+'</span>'+(r.ctx?'<span class=sub style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:420px">'+esc(JSON.stringify(r.ctx))+'</span>':'')+'</div>').join('')
  ||'<div class=sub>записей нет</div>';}
/* ============================================================
   ДЕЛА (Case Management). Несколько инцидентов — одно
   расследование: ответственный, статус, приоритет, история
   действий. Хранится в браузере: бэкенд и модели данных
   не меняются, дело живёт на рабочем месте аналитика.
   ============================================================ */
const CASE_KEY='soc_cases';
const CASE_ST={open:'в работе',hold:'ожидает',contained:'локализовано',closed:'закрыто'};
const CASE_PR={low:'низкий',medium:'средний',high:'высокий',critical:'критический'};
let _cases=null,_caseSel=null,_caseInc=[],_caseF='';

function caseLoad(){if(_cases)return _cases;
 try{_cases=JSON.parse(localStorage.getItem(CASE_KEY)||'[]');}catch(e){_cases=[];}
 if(!Array.isArray(_cases))_cases=[];return _cases;}
function caseFlush(){try{localStorage.setItem(CASE_KEY,JSON.stringify(_cases||[]));}catch(e){}}
function caseNow(){const d=new Date(),p=n=>String(n).padStart(2,'0');
 return d.getFullYear()+'-'+p(d.getMonth()+1)+'-'+p(d.getDate())+' '+p(d.getHours())+':'+p(d.getMinutes());}
function caseById(id){return caseLoad().filter(c=>c.id===id)[0]||null;}
function caseNote(c,t){c.log=c.log||[];c.log.unshift({ts:caseNow(),t:t});if(c.log.length>80)c.log.length=80;}
function casePrCls(p){return p==='critical'?'b-crit':(p==='high'?'b-high':(p==='medium'?'b-med':'b-low'));}
function caseFilter(f){_caseF=f;
 document.querySelectorAll('#v-cases .cf').forEach(b=>b.classList.toggle('on',b.dataset.f===f));caseRender();}

function caseNew(){
 const l=caseLoad();let n=1001;
 l.forEach(c=>{const v=parseInt(String(c.id).replace(/\D/g,''),10);if(v>=n)n=v+1;});
 const c={id:'CASE-'+n,title:'Новое дело',owner:'',status:'open',prio:'medium',
          created:caseNow(),incidents:[],log:[]};
 caseNote(c,'дело заведено');
 l.unshift(c);caseFlush();_caseSel=c.id;caseRender();caseOpen(c.id);
 if(window.toast)toast('Заведено дело '+c.id,'success');
 return c;}

function caseDel(id){
 if(!confirm('Удалить дело '+id+'? История действий пропадёт.'))return;
 _cases=caseLoad().filter(c=>c.id!==id);caseFlush();
 if(_caseSel===id){_caseSel=null;
  const b=$('caseDetail');if(b){b.className='sub';b.innerHTML='выберите дело слева или создайте новое';}
  const t=$('caseTtl');if(t)t.textContent='Карточка дела';}
 caseRender();if(window.toast)toast('Дело удалено','info');}

function caseIncMap(){const m={};(_caseInc||[]).forEach(i=>m[i.id]=i);return m;}
function caseAgg(c){
 const m=caseIncMap(),act={},tac={},rep={};let risk=0,al=0,crit=0,known=0;
 (c.incidents||[]).forEach(id=>{const i=m[id];if(!i)return;known++;
  if(i.actor)act[i.actor]=1;
  (i.tactics||[]).forEach(t=>tac[t]=1);
  (i.repos||[]).forEach(r=>rep[r]=1);
  risk=Math.max(risk,i.max_risk||0);al+=(i.alerts||0);
  if(i.severity==='critical')crit++;});
 return {actors:Object.keys(act),tactics:Object.keys(tac),repos:Object.keys(rep),
         risk:risk,alerts:al,crit:crit,known:known,total:(c.incidents||[]).length};}

function caseRender(){
 const box=$('caseList');if(!box)return;
 const el=$('caseSearch'),q=((el&&el.value)||'').toLowerCase().trim();
 const all=caseLoad();let l=all.slice();
 if(_caseF==='open')l=l.filter(c=>c.status!=='closed');
 else if(_caseF==='closed')l=l.filter(c=>c.status==='closed');
 if(q)l=l.filter(c=>(c.id+' '+(c.title||'')+' '+(c.owner||'')+' '+caseAgg(c).actors.join(' ')).toLowerCase().indexOf(q)>=0);
 const cnt=$('caseCount');if(cnt)cnt.textContent=l.length+' из '+all.length;
 if(!l.length){box.innerHTML='<div class="help empty">'+
   (all.length?'по фильтру ничего не нашлось':
    'дел пока нет. Нажмите «Новое дело» — или откройте инцидент и нажмите «Приобщить к делу»')+'</div>';return;}
 box.innerHTML=l.map(c=>{const a=caseAgg(c);
  return '<div class="ds-q-item'+(c.id===_caseSel?' sel':'')+'" onclick="caseOpen(\''+c.id+'\')">'+
   '<div class=ds-q-main><div class=ds-q-who>'+esc(c.title||c.id)+'</div>'+
    '<div class=ds-q-meta>'+esc(c.id)+' · '+(c.incidents||[]).length+' инц. · '+nAlerts(a.alerts)+
     (c.owner?(' · '+esc(c.owner)):' · без ответственного')+
     (a.actors.length?(' · '+esc(a.actors.slice(0,2).join(', '))):'')+'</div></div>'+
   '<div class=case-tags>'+
    '<span class="badge '+casePrCls(c.prio)+'">'+esc(CASE_PR[c.prio]||c.prio||'')+'</span>'+
    '<span class="case-st '+esc(c.status||'')+'">'+esc(CASE_ST[c.status]||c.status||'')+'</span></div></div>';}).join('');}

function caseOpen(id){
 _caseSel=id;caseRender();
 const c=caseById(id),box=$('caseDetail');if(!box)return;
 if(!c){box.className='sub';box.innerHTML='дело не найдено';return;}
 const t=$('caseTtl');if(t)t.textContent=c.id;
 const a=caseAgg(c),m=caseIncMap();
 const opt=(o,cur)=>Object.keys(o).map(k=>'<option value="'+k+'"'+(k===cur?' selected':'')+'>'+o[k]+'</option>').join('');
 const at=x=>esc(x).replace(/"/g,'&quot;');
 box.className='';
 box.innerHTML=
  '<div class=case-row>'+
   '<div style=flex:2><label class=t-label>Название</label>'+
    '<input class=tin id=cfTitle value="'+at(c.title||'')+'" placeholder="Например: утечка токенов через soc-infra"></div>'+
   '<div><label class=t-label>Ответственный</label>'+
    '<input class=tin id=cfOwner value="'+at(c.owner||'')+'" placeholder="аналитик"></div>'+
  '</div>'+
  '<div class=case-row style=margin-top:10px>'+
   '<div><label class=t-label>Статус</label><select class=tin id=cfStatus>'+opt(CASE_ST,c.status)+'</select></div>'+
   '<div><label class=t-label>Приоритет</label><select class=tin id=cfPrio>'+opt(CASE_PR,c.prio)+'</select></div>'+
  '</div>'+
  '<div style="display:flex;gap:8px;align-items:center;margin-top:12px">'+
   '<button class=btn onclick="caseSaveForm(\''+c.id+'\')">Сохранить</button>'+
   '<button class="btn ghost" onclick="caseReport(\''+c.id+'\')">Сводка по делу</button>'+
   '<span class=grow></span>'+
   '<button class="btn ghost danger" onclick="caseDel(\''+c.id+'\')">Удалить</button></div>'+
  '<div class=ds-drawer-sec><div class=t-label>Сводка</div><div class=ds-kv>'+
   kvRow('Инцидентов в деле',(c.incidents||[]).length+(a.known<a.total?(' (в текущем окне видно '+a.known+')'):''))+
   kvRow('Детектов суммарно',a.alerts)+
   kvRow('Пиковый риск',a.risk?a.risk.toFixed(2):'—')+
   kvRow('Критичных инцидентов',a.crit)+
   kvRow('Фигуранты',a.actors.length?esc(a.actors.join(', ')):'—')+
   kvRow('Репозитории',a.repos.length?esc(a.repos.join(', ')):'—')+
   kvRow('Тактики',a.tactics.length?esc(a.tactics.join(' → ')):'—')+
   kvRow('Заведено',esc(c.created||'—'))+'</div></div>'+
  '<div class=ds-drawer-sec><div class=t-label>Инциденты</div>'+caseIncList(c,m)+
   '<div style=margin-top:10px><button class="btn ghost" onclick="caseAddOpen(\''+c.id+'\')">+ Приобщить инцидент</button></div></div>'+
  '<div class=ds-drawer-sec><div class=t-label>История действий</div>'+
   '<div style="display:flex;gap:8px;margin:8px 0">'+
    '<input class=tin id=cfLog style=flex:1 placeholder="Опросили владельца сервиса, отозвали токен…" '+
     'onkeydown="if(event.key===\'Enter\')caseAddLog(\''+c.id+'\')">'+
    '<button class=btn onclick="caseAddLog(\''+c.id+'\')">Записать</button></div>'+
   caseLogHtml(c)+'</div>';}

function caseIncList(c,m){
 if(!(c.incidents||[]).length)
  return '<div class="help empty">инцидентов нет — приобщите их кнопкой ниже или из карточки инцидента</div>';
 return '<div class=ds-ev-list>'+(c.incidents||[]).map(id=>{const i=m[id];
  return '<div class=case-inc><span class=case-inc-id>#'+esc(id)+'</span>'+
   (i?(sevBadge(i.severity)+'<span class=sub>@'+esc(i.actor||'')+' · '+(i.alerts||0)+' детектов · риск '+
       (i.max_risk||0).toFixed(2)+'</span>')
     :'<span class=sub>вне текущего окна выдачи</span>')+
   '<span class=grow></span>'+
   (i?'<button class="btn ghost xs" onclick="caseGoInc('+id+')">открыть</button>':'')+
   '<button class="btn ghost xs" onclick="caseUnlink(\''+c.id+'\','+id+')">убрать</button></div>';}).join('')+'</div>';}

function caseLogHtml(c){
 if(!(c.log||[]).length)return '<div class=sub>записей нет</div>';
 return '<div class=ds-timeline>'+(c.log||[]).map(e=>
  '<div class="ds-tl-item info"><div class=ds-tl-time>'+esc(e.ts)+'</div>'+
  '<div class=ds-tl-desc>'+esc(e.t)+'</div></div>').join('')+'</div>';}

function caseGoInc(id){goView('incidents');setTimeout(()=>{try{openInc(id);}catch(e){}},150);}
function caseUnlink(cid,iid){const c=caseById(cid);if(!c)return;
 c.incidents=(c.incidents||[]).filter(x=>x!==iid);
 caseNote(c,'инцидент #'+iid+' исключён из дела');caseFlush();caseOpen(cid);}
function caseAddLog(cid){const c=caseById(cid);if(!c)return;
 const el=$('cfLog'),t=((el&&el.value)||'').trim();if(!t)return;
 caseNote(c,t);caseFlush();caseOpen(cid);
 if(window.toast)toast('Запись добавлена','success',1400);}

function caseSaveForm(cid){const c=caseById(cid);if(!c)return;
 const t=(($('cfTitle')||{}).value||'').trim()||c.id,
       o=(($('cfOwner')||{}).value||'').trim(),
       s=($('cfStatus')||{}).value||c.status,
       p=($('cfPrio')||{}).value||c.prio;
 const ch=[];
 if(t!==c.title)ch.push('название → «'+t+'»');
 if(o!==(c.owner||''))ch.push('ответственный → '+(o||'не назначен'));
 if(s!==c.status)ch.push('статус → '+(CASE_ST[s]||s));
 if(p!==c.prio)ch.push('приоритет → '+(CASE_PR[p]||p));
 c.title=t;c.owner=o;c.status=s;c.prio=p;
 if(ch.length)caseNote(c,ch.join('; '));
 caseFlush();caseOpen(cid);
 if(window.toast)toast(ch.length?'Дело обновлено':'Изменений нет','success',1500);}

function caseAddOpen(cid){
 const c=caseById(cid);if(!c)return;
 const have={};(c.incidents||[]).forEach(x=>have[x]=1);
 const free=(_caseInc||[]).filter(i=>!have[i.id]);
 const body=free.length
  ?('<div class=ds-ev-list>'+free.map(i=>'<div class=case-inc><span class=case-inc-id>#'+i.id+'</span>'+
     sevBadge(i.severity)+'<span class=sub>@'+esc(i.actor||'')+' · '+(i.alerts||0)+' детектов · риск '+
     (i.max_risk||0).toFixed(2)+((i.repos||[]).length?(' · '+esc(i.repos.join(', '))):'')+'</span>'+
     '<span class=grow></span><button class="btn xs" onclick="caseLink(\''+cid+'\','+i.id+')">приобщить</button></div>').join('')+'</div>')
  :'<div class="help empty">все инциденты из текущей выдачи уже в деле</div>';
 dsDrawer('Приобщить инцидент к '+esc(cid),body);}

function caseLink(cid,iid){const c=caseById(cid);if(!c)return;
 c.incidents=c.incidents||[];
 if(c.incidents.indexOf(iid)<0){c.incidents.push(iid);
  caseNote(c,'инцидент #'+iid+' приобщён к делу');caseFlush();}
 if(window.dsDrawerClose)dsDrawerClose();
 caseOpen(cid);
 if(window.toast)toast('Инцидент #'+iid+' в деле '+cid,'success');}

async function casePick(iid){
 try{_caseInc=(await jget('/api/incidents')).incidents||[];}catch(e){}
 const l=caseLoad();
 const rows=l.map(c=>'<div class=case-inc><span class=case-inc-id>'+esc(c.id)+'</span>'+
   '<span>'+esc(c.title||'')+'</span><span class=sub>'+(c.incidents||[]).length+' инц. · '+
   esc(CASE_ST[c.status]||c.status||'')+'</span><span class=grow></span>'+
   ((c.incidents||[]).indexOf(iid)>=0?'<span class=sub>уже в деле</span>'
    :'<button class="btn xs" onclick="caseLink(\''+c.id+'\','+iid+')">приобщить</button>')+'</div>').join('');
 dsDrawer('Инцидент #'+iid+' → дело',
  (l.length?('<div class=ds-ev-list>'+rows+'</div>'):'<div class="help empty">дел ещё нет</div>')+
  '<div style=margin-top:14px><button class=btn onclick="caseNewWith('+iid+')">Завести новое дело с этим инцидентом</button></div>');}

function caseNewWith(iid){
 const c=caseNew();if(!c)return;
 c.incidents=[iid];caseNote(c,'инцидент #'+iid+' приобщён к делу');caseFlush();
 if(window.dsDrawerClose)dsDrawerClose();
 if(window.toast)toast('Заведено дело '+c.id+' с инцидентом #'+iid,'success');}

function caseReport(cid){
 const c=caseById(cid);if(!c)return;
 const a=caseAgg(c),m=caseIncMap();
 const E=x=>String(x==null?'':x).replace(/[&<>]/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[ch]));
 const rows=(c.incidents||[]).map(id=>{const i=m[id];
  return '<tr><th scope=row>#'+E(id)+'</th><td>'+(i?(E(i.severity)+' · @'+E(i.actor)+' · риск '+i.max_risk+
   ' · '+(i.alerts||0)+' детектов · '+E((i.tactics||[]).join(' → '))):'вне текущего окна выдачи')+'</td></tr>';}).join('')
  ||'<tr><th scope=row>—</th><td>инцидентов в деле нет</td></tr>';
 const log=(c.log||[]).map(e=>'<tr><th scope=row>'+E(e.ts)+'</th><td>'+E(e.t)+'</td></tr>').join('')
  ||'<tr><th scope=row>—</th><td>записей нет</td></tr>';
 const html='<!doctype html><html lang=ru><head><meta charset=utf-8>'+
  '<title>'+E(c.id)+' — сводка по делу</title><style>'+RPT_CSS+'</style></head><body>'+
  '<div class=print>Чтобы сохранить в PDF — Ctrl+P → «Сохранить как PDF».</div>'+
  '<h1>'+E(c.title||c.id)+'</h1>'+
  '<div class=meta>'+E(c.id)+' · заведено '+E(c.created||'')+' · сформировано '+E(caseNow())+'</div>'+
  '<div class=kpis>'+
   '<div class=k><b>'+(c.incidents||[]).length+'</b><span>инцидентов</span></div>'+
   '<div class=k><b>'+a.alerts+'</b><span>детектов</span></div>'+
   '<div class=k><b>'+(a.risk?a.risk.toFixed(2):'—')+'</b><span>пиковый риск</span></div>'+
   '<div class=k><b>'+a.crit+'</b><span>критичных</span></div></div>'+
  '<h2>1. Карточка дела</h2><table>'+
   '<tr><th scope=row>Статус</th><td>'+E(CASE_ST[c.status]||c.status||'')+'</td></tr>'+
   '<tr><th scope=row>Приоритет</th><td>'+E(CASE_PR[c.prio]||c.prio||'')+'</td></tr>'+
   '<tr><th scope=row>Ответственный аналитик</th><td>'+E(c.owner||'не назначен')+'</td></tr>'+
   '<tr><th scope=row>Фигуранты</th><td>'+E(a.actors.join(', ')||'—')+'</td></tr>'+
   '<tr><th scope=row>Затронутые репозитории</th><td>'+E(a.repos.join(', ')||'—')+'</td></tr>'+
   '<tr><th scope=row>Тактики ATT&amp;CK</th><td>'+E(a.tactics.join(' → ')||'—')+'</td></tr></table>'+
  '<h2>2. Инциденты в деле</h2><table>'+rows+'</table>'+
  '<h2>3. История действий</h2><table>'+log+'</table>'+
  '<div class=meta style=margin-top:28px>Sentinel SOC · сводка построена только по наблюдаемым данным.</div>'+
  '</body></html>';
 const w=window.open('','_blank');
 if(!w){if(window.toast)toast('Браузер заблокировал окно','error');return;}
 w.document.write(html);w.document.close();
 if(window.toast)toast('Сводка готова — Ctrl+P для PDF','success',3500);}

async function caseSync(){
 try{_caseInc=(await jget('/api/incidents')).incidents||[];}catch(e){}
 const ae=document.activeElement;
 if(ae&&ae.closest&&ae.closest('#v-cases')&&/^(INPUT|TEXTAREA|SELECT)$/.test(ae.tagName))return;
 caseRender();}

/* ============================================================
   РЕПЛЕЙ ПРОГОНА. Вся история на одной шкале: детекты,
   тактики, инциденты. Видно, как атака разворачивалась во
   времени и в какой момент её увидел SOC.
   ============================================================ */
const RP_SPEEDS=[1,2,4,8];
const RP_ROWS=3;
let _rp=null,_rpRaw=null,_rpT=null,_rpPos=0,_rpSp=1,_rpPlaying=false,_rpWin='1d';

function rpTs(s){try{const d=new Date(String(s||'').replace(' ','T'));const t=d.getTime();return isNaN(t)?0:t;}catch(e){return 0;}}
function rpFmt(ms){if(!ms)return '—';const d=new Date(ms),p=n=>String(n).padStart(2,'0');
 return p(d.getDate())+'.'+p(d.getMonth()+1)+' '+p(d.getHours())+':'+p(d.getMinutes());}
function rpDur(ms){const m=Math.max(0,Math.round(ms/60000));
 if(m<60)return m+' мин';const h=Math.floor(m/60);
 if(h<24)return h+' ч '+(m%60)+' м';return Math.floor(h/24)+' д '+(h%24)+' ч';}

async function rpLoad(force){
 if(_rpRaw&&!force){rpBuild();return;}
 const w=$('rpWrap');if(!w)return;
 let al=[],inc=[];
 try{al=(await jget('/api/alerts')).alerts||[];}catch(e){}
 try{inc=(await jget('/api/incidents')).incidents||[];}catch(e){}
 _rpRaw={
  ev:al.map(a=>({t:rpTs(a.ts_sim),risk:a.risk||0,actor:a.actor||'',repo:a.project||'',
     tech:a.technique||'',tac:a.tactic||'',reason:a.reason||'',act:a.action||'',inc:a.incident}))
    .filter(x=>x.t>0).sort((a,b)=>a.t-b.t),
  inc:inc.map(i=>({id:i.id,a:rpTs(i.start_ts),b:rpTs(i.last_ts),sev:i.severity||'low',
     actor:i.actor||'',n:i.alerts||0,camp:i.is_campaign})).filter(x=>x.a>0).sort((a,b)=>a.a-b.a)};
 rpBuild();}

/* Окно времени. В журнале обычно лежит несколько прогонов, разнесённых
   на недели: на общей шкале детекты сбиваются в редкие кучки, а между
   ними пустота. Поэтому по умолчанию показываем сутки — плотную
   картину последнего прогона, а всю историю смотрим кнопкой. */
function rpWin(v){
 _rpWin=v;_rpPos=0;
 document.querySelectorAll('#v-replay .rw').forEach(b=>b.classList.toggle('on',b.dataset.w===v));
 rpBuild();}

function rpBuild(){
 const w=$('rpWrap');if(!w||!_rpRaw)return;
 const empty=t=>{_rp=null;w.innerHTML='<div class="help empty">'+t+'</div>';
  const f=$('rpFeed');if(f)f.innerHTML='<div class="help empty">нет данных в этом окне</div>';
  const st=$('rpState');if(st)st.innerHTML='<div class="help empty">нет данных в этом окне</div>';};
 if(!_rpRaw.ev.length&&!_rpRaw.inc.length)
  return empty('пока нечего проигрывать — запустите кампанию во вкладке Red Launcher');

 const last=Math.max.apply(null,[].concat(_rpRaw.ev.map(e=>e.t),_rpRaw.inc.map(i=>i.b||i.a)));
 const SPAN={'1d':864e5,'7d':6048e5};
 const from=SPAN[_rpWin]?(last-SPAN[_rpWin]):-Infinity;
 const ev=_rpRaw.ev.filter(e=>e.t>=from);
 const ic=_rpRaw.inc.filter(i=>(i.b||i.a)>=from);
 const cnt=$('rpCount');
 if(cnt)cnt.textContent=ev.length+' детектов · '+ic.length+' инцидентов'+
   (ev.length<_rpRaw.ev.length?(' (всего в журнале '+_rpRaw.ev.length+')'):'');
 if(!ev.length&&!ic.length)return empty('в этом окне детектов нет — возьмите период шире');

 const all=[].concat(ev.map(e=>e.t),ic.map(i=>i.a),ic.map(i=>i.b||i.a)).filter(Boolean);
 let t0=Math.min.apply(null,all),t1=Math.max.apply(null,all);
 if(t1<=t0)t1=t0+60000;
 /* поля по краям: в нулевой позиции прогон ещё не начался, поэтому
    видно, как события появляются, а первая точка не липнет к рамке */
 const pad=Math.max(60000,(t1-t0)*0.03);
 _rp={ev:ev,inc:ic,t0:t0-pad,t1:t1+pad,first:t0,tacs:ev.filter(e=>e.tac)};
 rpDraw();rpSeek(_rpPos||0);}

function rpDraw(){
 const w=$('rpWrap');if(!w||!_rp)return;
 const span=_rp.t1-_rp.t0;
 const pc=t=>Math.max(0,Math.min(100,(t-_rp.t0)/span*100));
 let ticks='';
 for(let k=0;k<=4;k++)ticks+='<span class=rp-tick style="left:'+(k*25)+'%">'+rpFmt(_rp.t0+span*k/4)+'</span>';
 const dots=_rp.ev.map(e=>'<i class="rp-dot '+alSevOf(e.risk)+'" style="left:'+pc(e.t)+'%" title="'+
   esc(e.actor+' · '+(e.tech||e.reason||''))+'"></i>').join('');
 const tacs=_rp.tacs.map(e=>'<i class=rp-tac style="left:'+pc(e.t)+'%;background:'+tcol(e.tac)+
   '" title="'+esc(e.tac)+'"></i>').join('');
 /* Инциденты часто перекрываются во времени: раскладываем их по трём
    рядам, иначе полосы наезжают друг на друга и видно только верхнюю.
    Номер пишем, только если полоса достаточно широкая, — иначе он
    превращается в кашу; в подсказке он есть всегда. */
 const rowEnd=new Array(RP_ROWS).fill(-99);
 const bars=_rp.inc.map(i=>{
   const l=pc(i.a),wd=Math.max(1.2,pc(i.b||i.a)-l);
   let k=-1;
   for(let j=0;j<RP_ROWS;j++){if(l>rowEnd[j]+0.4){k=j;break;}}
   if(k<0)k=rowEnd.indexOf(Math.min.apply(null,rowEnd));
   rowEnd[k]=l+wd;
   return '<span class="rp-bar '+esc(i.sev)+'" style="left:'+l+'%;width:'+wd+'%;top:'+(3+k*12)+
    'px" title="#'+i.id+' · @'+esc(i.actor)+' · '+i.n+' детектов" onclick="caseGoInc('+i.id+')">'+
    (wd>=4?('#'+i.id):'')+'</span>';}).join('');
 w.innerHTML=
  '<div class=rp-lane><span class=rp-lane-n>Детекты</span><div class=rp-track>'+dots+'<b class=rp-head></b></div></div>'+
  '<div class=rp-lane><span class=rp-lane-n>Тактики</span><div class=rp-track>'+tacs+'<b class=rp-head></b></div></div>'+
  '<div class=rp-lane><span class=rp-lane-n>Инциденты</span><div class="rp-track tall">'+bars+'<b class=rp-head></b></div></div>'+
  '<div class=rp-axis>'+ticks+'</div>';}

function rpSeek(v){
 _rpPos=Math.max(0,Math.min(1000,Number(v)||0));
 const r=$('rpRange');if(r&&Number(r.value)!==_rpPos)r.value=_rpPos;
 if(!_rp)return;
 const cur=_rp.t0+(_rp.t1-_rp.t0)*(_rpPos/1000);
 const w=$('rpWrap');if(!w)return;
 w.querySelectorAll('.rp-head').forEach(e=>e.style.left=(_rpPos/10)+'%');
 const c=$('rpClock');
 if(c)c.textContent=rpFmt(cur)+' · '+rpDur(Math.max(0,cur-_rp.first))+' от первого детекта';
 const dots=w.querySelectorAll('.rp-dot');
 for(let i=0;i<dots.length&&i<_rp.ev.length;i++)dots[i].classList.toggle('past',_rp.ev[i].t<=cur);
 const tel=w.querySelectorAll('.rp-tac');
 for(let i=0;i<tel.length&&i<_rp.tacs.length;i++)tel[i].classList.toggle('past',_rp.tacs[i].t<=cur);
 const bars=w.querySelectorAll('.rp-bar');
 for(let i=0;i<bars.length&&i<_rp.inc.length;i++)bars[i].classList.toggle('past',_rp.inc[i].a<=cur);
 rpSide(cur);}

function rpTile(k,v){return '<div class=rp-tile><b>'+v+'</b><span>'+k+'</span></div>';}

function rpSide(cur){
 const seen=_rp.ev.filter(e=>e.t<=cur);
 const opened=_rp.inc.filter(i=>i.a<=cur);
 const f=$('rpFeed');
 if(f)f.innerHTML=seen.length
  ?('<div class=ds-timeline>'+seen.slice(-14).reverse().map(e=>
     '<div class="ds-tl-item '+alSevOf(e.risk)+'"><div class=ds-tl-time>'+rpFmt(e.t)+'</div>'+
     '<div class=ds-tl-title>@'+esc(e.actor)+(e.act?(' · '+esc(e.act)):'')+'</div>'+
     '<div class=ds-tl-desc>'+esc(e.reason||'')+(e.tech?(' · '+esc(e.tech)):'')+
     (e.repo?(' · '+esc(e.repo)):'')+'</div></div>').join('')+'</div>')
  :'<div class="help empty">на этот момент детектов ещё не было — двигайте курсор вправо</div>';
 /* «ведущий» считаем по числу детектов, а ничью разводим пиковым
    риском: две тактики по два срабатывания — не одно и то же */
 const acts={},tacs={},repos={};
 const bump=(o,k,r)=>{if(!k)return;const e=o[k]||(o[k]={n:0,r:0});e.n++;e.r=Math.max(e.r,r||0);};
 seen.forEach(e=>{bump(acts,e.actor,e.risk);bump(tacs,e.tac,e.risk);bump(repos,e.repo,e.risk);});
 const top=o=>{const k=Object.keys(o).sort((a,b)=>o[b].n-o[a].n||o[b].r-o[a].r);
  return k.length?(k[0]+' · '+o[k[0]].n):'—';};
 const crit=opened.filter(i=>i.sev==='critical').length;
 const st=$('rpState');
 if(st)st.innerHTML='<div class=rp-tiles>'+
   rpTile('детектов',seen.length)+rpTile('инцидентов',opened.length)+
   rpTile('критичных',crit)+rpTile('прошло',rpDur(Math.max(0,cur-_rp.first)))+'</div>'+
  '<div class=ds-kv style=margin-top:14px>'+
   kvRow('Самый активный',esc(top(acts)))+
   kvRow('Ведущая тактика',esc(top(tacs)))+
   kvRow('Горячий репозиторий',esc(top(repos)))+
   kvRow('Первый детект',seen.length?rpFmt(seen[0].t):'—')+'</div>'+
  (opened.length?('<div class=ds-drawer-sec><div class=t-label>Инциденты, открытые к этому моменту</div>'+
    '<div class=ds-ev-list>'+opened.slice(-6).reverse().map(i=>
     '<div class=case-inc><span class=case-inc-id>#'+i.id+'</span>'+sevBadge(i.sev)+
     '<span class=sub>@'+esc(i.actor)+' · '+i.n+' детектов</span><span class=grow></span>'+
     '<button class="btn ghost xs" onclick="caseGoInc('+i.id+')">открыть</button></div>').join('')+'</div></div>'):'');}

function rpToggle(){
 if(!_rp){rpLoad(1);return;}
 _rpPlaying=!_rpPlaying;
 const b=$('rpPlay');if(b)b.textContent=_rpPlaying?'⏸ Пауза':'▶ Играть';
 if(_rpT){clearInterval(_rpT);_rpT=null;}
 if(!_rpPlaying)return;
 if(_rpPos>=1000)rpSeek(0);
 _rpT=setInterval(()=>{
  const n=_rpPos+_rpSp*2;
  if(n>=1000){rpSeek(1000);_rpPlaying=true;rpToggle();return;}
  rpSeek(n);},80);}

function rpSpeed(){
 _rpSp=RP_SPEEDS[(RP_SPEEDS.indexOf(_rpSp)+1)%RP_SPEEDS.length];
 const t=$('rpSpeedT');if(t)t.textContent=_rpSp+'×';
 if(_rpPlaying){rpToggle();rpToggle();}}

/* ============================================================
   ПРОФИЛЬ РИСКА КОМАНДЫ. Кто и какие репозитории тянут риск.
   Считается только по наблюдаемым данным — детекты и
   инциденты; меток симулятора здесь нет (анти-лик).
   ============================================================ */
let _riskDev=[],_riskRep=[],_riskAl=[];

/* Оценка 0–100. Важный момент: пиковый и средний риск домножаются на
   «уверенность» — долю от четырёх наблюдений. Иначе один-единственный
   детект с риском 0.99 давал бы человеку 60 очков и он оказывался бы
   рядом с настоящим фигурантом кампании, у которого пятнадцать
   детектов по пяти техникам. Одно срабатывание — это ещё не профиль. */
function riskConf(n){return Math.min(1,n/4);}
function riskScore(d){
 const c=riskConf(d.n);
 return Math.round(Math.min(1,d.max)*40*c + Math.min(1,d.avg)*20*c +
   Math.min(1,d.n/20)*15 + Math.min(1,d.tech/5)*10 +
   Math.min(1,d.inc/3)*10 + (d.crit?5:0));}
function riskCls(v){return v>=70?'critical':(v>=45?'high':(v>=25?'medium':'low'));}
function riskBadgeCls(v){return {critical:'b-crit',high:'b-high',medium:'b-med',low:'b-low'}[riskCls(v)];}

async function pollRisk(){
 let al=[],inc=[];
 try{al=(await jget('/api/alerts')).alerts||[];}catch(e){}
 try{inc=(await jget('/api/incidents')).incidents||[];}catch(e){}
 _riskAl=al;
 const byA={},byR={};
 const mk=()=>({n:0,sum:0,max:0,tech:{},tac:{},inc:{},peers:{},crit:0,last:''});
 al.forEach(a=>{
  const r=a.risk||0;
  const put=(key,m,peer)=>{if(!key)return;const o=m[key]||(m[key]=mk());
   o.n++;o.sum+=r;o.max=Math.max(o.max,r);
   if(a.technique)o.tech[a.technique]=1;
   if(a.tactic)o.tac[a.tactic]=1;
   if(a.incident!=null)o.inc[a.incident]=1;
   if(peer)o.peers[peer]=1;
   if((a.ts_sim||'')>o.last)o.last=a.ts_sim||'';};
  put(a.actor,byA,a.project);
  put(a.project,byR,a.actor);});
 inc.forEach(i=>{
  if(i.severity==='critical'){
   const o=byA[i.actor];if(o)o.crit=1;
   (i.repos||[]).forEach(rp=>{const q=byR[rp];if(q)q.crit=1;});}});
 const rows=m=>Object.keys(m).map(k=>{const o=m[k];
   const d={key:k,n:o.n,avg:o.sum/Math.max(1,o.n),max:o.max,
     tech:Object.keys(o.tech).length,tac:Object.keys(o.tac).length,
     inc:Object.keys(o.inc).length,peers:Object.keys(o.peers).length,
     crit:o.crit,last:o.last};
   d.score=riskScore(d);return d;}).sort((a,b)=>b.score-a.score||b.n-a.n);
 _riskDev=rows(byA);_riskRep=rows(byR);
 riskTable('riskDev',_riskDev,'разработчик','репозиториев');
 riskTable('riskRepo',_riskRep,'репозиторий','участников');
 riskStrip(inc);
 riskDyn(al);}

function riskTable(id,rows,c1,c2){
 const box=$(id);if(!box)return;
 if(!rows.length){box.innerHTML='<div class="help empty">данных пока нет — детекты ещё не появлялись</div>';return;}
 box.innerHTML='<div class=ds-tablewrap><table class=ds-table><thead><tr>'+
  '<th scope=col>'+c1+'</th><th scope=col>риск</th><th scope=col class=num>детектов</th><th scope=col class=num>инц.</th>'+
  '<th scope=col class=num>техник</th><th scope=col class=num>'+c2+'</th></tr></thead><tbody>'+
  rows.slice(0,12).map(d=>'<tr onclick="riskDrill(\''+encodeURIComponent(d.key)+'\')">'+
   '<td><b>'+esc(d.key)+'</b></td>'+
   '<td><div class=rk-cell><span class="rk-bar '+riskCls(d.score)+'"><i style="width:'+d.score+'%"></i></span>'+
    '<b class="rk-n '+riskCls(d.score)+'">'+d.score+'</b></div></td>'+
   '<td class=num>'+d.n+'</td><td class=num>'+d.inc+'</td>'+
   '<td class=num>'+d.tech+'</td><td class=num>'+d.peers+'</td></tr>').join('')+
  '</tbody></table></div><div class=sub style=margin-top:8px>Клик по строке — детали и последние детекты.</div>';}

function riskStrip(inc){
 const box=$('riskStrip');if(!box)return;
 const hi=_riskDev.filter(d=>d.score>=70).length;
 const avg=_riskDev.length?Math.round(_riskDev.reduce((s,d)=>s+d.score,0)/_riskDev.length):0;
 const worstD=_riskDev[0],worstR=_riskRep[0];
 box.innerHTML=
  '<div class=ds-covcard><div class="ds-covcard-n '+(hi?'crit':'ok')+'">'+hi+
   (_riskDev.length?('<span style="font-size:15px;color:var(--text-3)"> из '+_riskDev.length+'</span>'):'')+
   '</div><div class=ds-covcard-l>в критической зоне</div></div>'+
  '<div class=ds-covcard><div class=ds-covcard-n>'+avg+'</div><div class=ds-covcard-l>средний риск команды</div></div>'+
  '<div class=ds-covcard><div class=ds-covcard-n style=font-size:17px>'+esc(worstD?worstD.key:'—')+
   '</div><div class=ds-covcard-l>наибольший риск</div></div>'+
  '<div class=ds-covcard><div class=ds-covcard-n style=font-size:17px>'+esc(worstR?worstR.key:'—')+
   '</div><div class=ds-covcard-l>самый затронутый репозиторий</div></div>'+
  '<div class=ds-covcard><div class="ds-covcard-n '+((inc||[]).length?'warn':'ok')+'">'+(inc||[]).length+
   '</div><div class=ds-covcard-l>инцидентов в работе</div></div>';}

function riskDrill(k){
 k=decodeURIComponent(k);
 const d=_riskDev.filter(x=>x.key===k)[0]||_riskRep.filter(x=>x.key===k)[0];
 if(!d)return;
 const mine=_riskAl.filter(a=>a.actor===k||a.project===k).slice(0,18);
 dsDrawer(esc(k)+' <span class="badge '+riskBadgeCls(d.score)+'">риск '+d.score+'</span>',
  '<div class=ds-kv>'+
   kvRow('Детектов',d.n)+kvRow('Средний риск',d.avg.toFixed(2))+
   kvRow('Пиковый риск',d.max.toFixed(2))+kvRow('Инцидентов',d.inc)+
   kvRow('Уникальных техник',d.tech)+kvRow('Тактик',d.tac)+
   kvRow('Последняя активность',esc(d.last||'—'))+'</div>'+
  '<div class=ds-drawer-sec><div class=t-label>Как считается</div>'+
   '<div class=sub>Оценка 0–100 складывается из пикового риска (40), среднего риска (20), '+
   'объёма детектов (15), разнообразия техник (10), числа инцидентов (10) и признака критичности (5). '+
   'Первые два слагаемых умножаются на уверенность — здесь '+Math.round(riskConf(d.n)*100)+'% '+
   '(она достигает 100% от четырёх детектов), поэтому одно случайное срабатывание не поднимает человека наверх. '+
   'Все слагаемые берутся из наблюдаемых данных, разметка симулятора не используется.</div></div>'+
  '<div class=ds-drawer-sec><div class=t-label>Последние детекты</div>'+
   (mine.length?('<div class=ds-timeline>'+mine.map(a=>
     '<div class="ds-tl-item '+alSevOf(a.risk||0)+'"><div class=ds-tl-time>'+esc(a.ts_sim||'')+'</div>'+
     '<div class=ds-tl-title>@'+esc(a.actor||'')+(a.action?(' · '+esc(a.action)):'')+'</div>'+
     '<div class=ds-tl-desc>'+esc(a.reason||'')+(a.project?(' · '+esc(a.project)):'')+'</div></div>').join('')+'</div>')
    :'<div class=sub>нет записей</div>')+'</div>');}

function riskDyn(al){
 const box=$('riskDyn');if(!box)return;
 const top=_riskDev.slice(0,5);
 const ts=al.map(a=>rpTs(a.ts_sim)).filter(x=>x>0);
 if(!top.length||!ts.length){
  box.innerHTML='<div class="help empty">динамика появится, когда наберётся история детектов</div>';return;}
 const t0=Math.min.apply(null,ts),t1=Math.max.apply(null,ts);
 const N=24,span=Math.max(1,t1-t0),w=100/N;
 box.innerHTML='<div class=sub style=margin-bottom:12px>Пиковый риск по '+N+
  ' интервалам от первого до последнего детекта ('+rpFmt(t0)+' → '+rpFmt(t1)+'). '+
  'Столбик — максимум риска, который человек показал в этом окне.</div>'+
  top.map(d=>{
   const buck=new Array(N).fill(0);
   al.forEach(a=>{if(a.actor!==d.key)return;const t=rpTs(a.ts_sim);if(!t)return;
    const k=Math.min(N-1,Math.floor((t-t0)/span*N));
    buck[k]=Math.max(buck[k],a.risk||0);});
   const bars=buck.map((v,i)=>v?('<rect x="'+(i*w).toFixed(2)+'" y="'+((1-v)*40).toFixed(2)+
     '" width="'+(w*0.74).toFixed(2)+'" height="'+Math.max(1.5,v*40).toFixed(2)+
     '" class="'+alSevOf(v)+'" />'):'').join('');
   return '<div class=rk-dyn><span class=rk-dyn-n>'+esc(d.key)+'</span>'+
    '<svg viewBox="0 0 100 40" preserveAspectRatio=none class=rk-dyn-svg>'+bars+'</svg>'+
    '<b class="rk-n '+riskCls(d.score)+'">'+d.score+'</b></div>';}).join('');}

async function refresh(){try{
 if(view==='overview'){renderPrompts();await pollOverview();}
 else if(view==='alerts'){await pollOverview();await pollAlerts();}
 else if(view==='incidents'){await pollOverview();await pollIncidents();}
 else if(view==='attack')await pollAttack();
 else if(view==='detections')await pollDetections();
 else if(view==='entities')await pollEntities();
 else if(view==='cases')await caseSync();
 else if(view==='risk')await pollRisk();
 else if(view==='replay')await rpLoad(false);
 else if(view==='red')await pollRed();
 else if(view==='workflow')await pollWorkflow();
 else if(view==='trends')await pollTrends();
 else if(view==='diag')await pollDiag();
 await pollOverview();
}catch(e){}}
refresh();setInterval(refresh,2500);
function fmtAge(s){if(s==null)return'';if(s<60)return s+' с назад';if(s<3600)return Math.floor(s/60)+' мин назад';return Math.floor(s/3600)+' ч назад';}
function setHp(id,cls,txt){const p=$(id);if(!p)return;p.className='hpill '+cls;$(id+'T').textContent=txt;}
async function pollHealth(){let h;try{h=await jget('/api/health');}catch(e){return;}
 const ev=h.events||{};
 setHp('hWorld',h.world_alive?'ok':(ev.total>0?'warn':'bad'),h.world_alive?'пишет':'молчит');
 setHp('hEvents',ev.total>0?'ok':'bad',(ev.total||0)+(ev.last_age_s!=null?(' · '+fmtAge(ev.last_age_s)):''));
 setHp('hOllama',h.ollama?'ok':'warn',h.ollama?'готова':'нет');
 setHp('hTriage',h.auto_triage?(h.ollama?'ok':'warn'):'',h.auto_triage?'вкл':'выкл');
 const w=$('worldWarn');if(w){const bad=!h.world_alive&&ev.total>0;w.style.display=bad?'block':'none';
  if(bad)$('worldWarnAge').textContent=ev.last_age_s!=null?('уже '+fmtAge(ev.last_age_s).replace(' назад','')):'';}}
pollHealth();setInterval(pollHealth,5000);
function goView(v){const a=document.querySelector('.nav a[data-v='+v+']');if(a)a.click();}
function obToggle(){const b=$('obBody');const opening=b.style.display==='none';b.style.display=opening?'':'none';
 $('obToggle').textContent=opening?'свернуть':'развернуть';try{localStorage.setItem('pt_ob_min',opening?'':'1')}catch(e){}}
try{if(localStorage.getItem('pt_ob_min')){$('obBody').style.display='none';$('obToggle').textContent='развернуть';}}catch(e){}
try{if(location.hash){const v=location.hash.slice(1);if(document.querySelector('#nav a[data-v='+v+']'))goView(v);}}catch(e){}
</script></body></html>"""

# ----------------------------------------------------------------------
EXEC_HTML = r"""<!doctype html><html lang=ru><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>Обзор для комиссии — SOC Purple-Team Platform</title>
<style>

*{box-sizing:border-box}
body{margin:0;font-family:Inter,Segoe UI,Roboto,sans-serif;color:var(--ink);
 background:radial-gradient(1000px 460px at 85% -12%,#ede9fe70,transparent 60%),
            radial-gradient(760px 400px at -8% 30%,#dbeafe55,transparent 55%),var(--bg)}
.wrap{max-width:1060px;margin:0 auto;padding:34px 26px 70px}
.crumb{font-size:12.5px;color:var(--soft);margin-bottom:20px}
.crumb a{color:var(--accent);font-weight:700;text-decoration:none}
h1{font-size:30px;letter-spacing:-.02em;margin:0 0 10px;line-height:1.25}
h1 b{background:linear-gradient(90deg,var(--accent-brand),var(--info));-webkit-background-clip:text;background-clip:text;color:transparent}
.lead{font-size:16.5px;color:var(--line-strong);line-height:1.65;max-width:840px;margin:0 0 26px}
h2{font-size:15px;font-weight:600;letter-spacing:0;color:var(--text-1);margin:38px 0 14px;display:flex;align-items:center;gap:9px}
h2:before{content:'';width:5px;height:16px;border-radius:3px;background:var(--accent-brand)}
/* конвейер */
.pipe{display:flex;align-items:stretch;gap:0;flex-wrap:wrap}
.pnode{flex:1;min-width:150px;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:15px 14px;
 box-shadow:var(--shadow);transition:transform .18s ease,box-shadow .18s ease;position:relative}
.pnode:hover{transform:translateY(-3px);box-shadow:0 2px 4px rgba(23,28,40,.06),0 16px 36px rgba(124,58,237,.14)}
.pnode .ic{font-size:22px}
.pnode b{display:block;font-size:13.5px;margin:7px 0 4px}
.pnode .d{font-size:11.5px;color:var(--soft);line-height:1.5}
.parr{display:flex;align-items:center;padding:0 7px;color:var(--accent-brand);font-size:20px;font-weight:800}
/* факты */
.facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:14px}
.fact{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:17px 18px;box-shadow:var(--shadow)}
.fact .n{font-size:24px;font-weight:800;letter-spacing:-.02em;color:var(--red)}
.fact .t{font-size:13px;line-height:1.55;margin-top:6px}
.fact .src{font-size:11px;color:var(--soft);margin-top:8px}
/* метрики */
.mets{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}
.met{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:17px 18px;box-shadow:var(--shadow);position:relative;overflow:hidden}
.met:before{content:'';position:absolute;inset:0 0 auto 0;height:3px;background:var(--accent-brand)}
.met .n{font-size:30px;font-weight:800;letter-spacing:-.02em;font-variant-numeric:tabular-nums}
.met .l{font-size:12px;font-weight:700;margin-top:2px}
.met .d{font-size:11.5px;color:var(--soft);line-height:1.5;margin-top:6px}
.met .n.ok{color:var(--green)}.met .n.acc{color:var(--accent)}
.computing{font-size:12.5px;color:var(--soft);margin-top:10px}
/* holdout-график */
.hold{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:20px;box-shadow:var(--shadow)}
.hrow{display:grid;grid-template-columns:110px 1fr 1fr;gap:10px;align-items:center;margin-bottom:9px;font-size:12px}
.hrow .fam{font-family:ui-monospace,SFMono-Regular,monospace;font-weight:700;color:var(--line-strong)}
.hbar{height:17px;border-radius:5px;background:var(--info-bg);overflow:hidden;position:relative}
.hbar i{display:block;height:100%;width:0;border-radius:5px;transition:width .8s ease}
.hbar.rg i{background:var(--info-bg)}.hbar.ml i{background:var(--accent-brand)}
.hbar span{position:absolute;right:7px;top:1.5px;font-size:10.5px;font-weight:700;color:var(--line-strong)}
.hleg{display:flex;gap:18px;font-size:11.5px;color:var(--soft);margin:4px 0 14px}
.hleg i{display:inline-block;width:11px;height:11px;border-radius:3px;vertical-align:-1px;margin-right:5px}
.concl{margin-top:14px;padding:12px 15px;border-radius:11px;background:var(--accent-bg);
 border:1px solid var(--accent-border);color:var(--accent-brand);font-size:13px;line-height:1.6}
/* CTA */
.cta{display:flex;gap:12px;margin-top:34px;flex-wrap:wrap}
.btn{display:inline-flex;align-items:center;gap:8px;background:var(--accent-brand);color:#fff;border:none;
 border-radius:12px;padding:13px 22px;font-weight:700;cursor:pointer;font-size:14px;text-decoration:none;
 box-shadow:0 2px 10px #7c3aed44;transition:all .16s ease}
.btn:hover{transform:translateY(-1px);box-shadow:0 5px 16px #7c3aed55}
.btn.ghost{background:var(--panel);color:var(--ink);border:1px solid var(--line);box-shadow:var(--shadow)}
.btn.ghost:hover{border-color:var(--accent-border)}
.note{font-size:11.5px;color:var(--soft);margin-top:26px;line-height:1.6}
@media(max-width:760px){.pipe{flex-direction:column}.parr{transform:rotate(90deg);justify-content:center;padding:2px 0}}
</style><link rel="stylesheet" href="/static/design-system.css"><link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='0.9em' font-size='90'>🛡</text></svg>"></head><body><div class=wrap>
<div class=crumb><a href="/">← Sentinel SOC</a> · Purple Team Platform · обзор простым языком</div>
<h1>Система сама замечает <b>кражу секретов</b> в конвейере разработки — и объясняет, что случилось</h1>
<p class=lead>Пароли, токены и ключи (секреты) регулярно утекают через git-репозитории и CI/CD-конвейеры.
Платформа наблюдает за поведением всех участников разработки, ловит цепочки подозрительных действий,
собирает их в инциденты и объясняет каждый инцидент человеческим языком.</p>

<h2>Как это работает</h2>
<div class=pipe>
  <div class=pnode><span class=ic>01</span><b>Атакующий</b><div class=d>инсайдер или взломанный аккаунт крадёт токены, ключи, код</div></div>
  <div class=parr>→</div>
  <div class=pnode><span class=ic>02</span><b>События CI/CD</b><div class=d>каждый push, ветка, MR и настройка пишутся в единый журнал</div></div>
  <div class=parr>→</div>
  <div class=pnode><span class=ic>03</span><b>Детектор</b><div class=d>3 слоя: правила + профиль поведения каждого сотрудника (UEBA) + ML</div></div>
  <div class=parr>→</div>
  <div class=pnode><span class=ic>04</span><b>Инцидент</b><div class=d>разрозненные сработки склеиваются в цепочку шагов атаки (kill-chain)</div></div>
  <div class=parr>→</div>
  <div class=pnode><span class=ic>05</span><b>Объяснение</b><div class=d>LLM пишет вердикт: что произошло, насколько серьёзно, что делать</div></div>
</div>

<h2>Почему это важно</h2>
<div class=facts>
  <div class=fact><div class=n>12,8 млн</div><div class=t>секретов утекло в публичные GitHub-репозитории за один год — в 4 раза больше, чем четырьмя годами ранее</div><div class=src>GitGuardian, State of Secrets Sprawl 2024</div></div>
  <div class=fact><div class=n>CircleCI, 2023</div><div class=t>компрометация CI-платформы: тысячам компаний пришлось экстренно ротировать все секреты всех проектов</div><div class=src>инцидент января 2023, официальный отчёт CircleCI</div></div>
  <div class=fact><div class=n>дни и недели</div><div class=t>утёкший ключ часто остаётся действительным — никто не замечает утечку, пока им не воспользуются</div><div class=src>поэтому важно ловить кражу в момент, а не постфактум</div></div>
</div>

<h2>Живые показатели этой установки</h2>
<div class=mets id=mets>
  <div class=met><div class="n acc" id=mDet>—</div><div class=l>обнаружение атак</div><div class=d>доля атакующих эпизодов, на которые детектор поднял тревогу</div></div>
  <div class=met><div class="n ok" id=mMttd>—</div><div class=l>время до обнаружения</div><div class=d>от первого шага атаки до первого алерта (MTTD, сим-время)</div></div>
  <div class=met><div class="n" id=mFp>—</div><div class=l>ложные тревоги</div><div class=d>доля алертов, поднятых на нормальной работе команды (чем меньше, тем лучше)</div></div>
  <div class=met><div class="n acc" id=mCov>—</div><div class=l>покрытие ATT&CK</div><div class=d>доля техник атакующих (по матрице MITRE ATT&CK), которые платформа умеет замечать</div></div>
</div>
<div class=computing id=metSt>считаю метрики по всему журналу событий…</div>

<h2>Почему не просто «поиск по шаблону»</h2>
<div class=hold>
  <div style="font-size:13.5px;line-height:1.6;margin-bottom:10px">Секреты нового, незнакомого формата.
  Классический поиск по шаблонам (regex) знает только то, что в него заложили. Проверка: прячем от детектора
  один формат секретов при обучении — и смотрим, найдёт ли он его.</div>
  <div class=hleg><span><i style=background:#cbd0e0></i>поиск по шаблонам (regex)</span>
    <span><i style="background:linear-gradient(90deg,#a855f7,#7c3aed)"></i>ML-детектор платформы</span></div>
  <div id=holdRows><div style="color:#6d7585;font-size:12px">загружаю results/holdout.csv… (если пусто — запусти <code>python research/experiments_holdout.py</code>)</div></div>
  <div class=concl id=holdConcl style=display:none></div>
</div>

<div class=cta>
  <a class=btn href="/#red">Показать живую атаку</a>
  <a class="btn ghost" href="/">Открыть Sentinel SOC</a>
  <a class="btn ghost" href="http://127.0.0.1:8787" target=_blank>Консоль среды (:8787)</a>
</div>

<p class=note>Оценка честная: детектор не видит разметку симулятора (какое событие — атака), метрики считаются
постфактум сопоставлением алертов с разметкой. Внешние цифры — из публичных отчётов, проверь актуальность перед защитой.</p>
</div>
<script>
const $=x=>document.getElementById(x);
async function jget(u){const r=await fetch(u);return r.json();}
function pct(v){return Math.round((v||0)*100)+'%';}
async function poll(){
 let d;try{d=await jget('/api/executive');}catch(e){return;}
 const m=d.metrics;
 if(m){
  $('mDet').textContent=pct(m.detection_rate);
  $('mMttd').textContent=(m.mttd_sim_min!=null?m.mttd_sim_min:'—')+' мин';
  $('mFp').textContent=pct(m.fp_rate);
  $('mFp').className='n '+(m.fp_rate<=0.15?'ok':'');
  $('mCov').textContent=pct(m.attack_coverage);
  $('metSt').textContent='по '+m.events+' событиям · '+m.anomaly_episodes+' атакующих эпизодов · '+m.alerts+' алертов';
 } else {
  $('metSt').textContent=d.computing?'считаю метрики по всему журналу событий… (10–30 сек)':(d.metrics_err?('не удалось: '+d.metrics_err):'нет данных — запусти мир или демо');
 }
 const rows=d.holdout||[];
 if(rows.length){
  $('holdRows').innerHTML=rows.map(r=>{
   const rg=Math.round(parseFloat(r.regex_recall||0)*100), ml=Math.round(parseFloat(r.ml_recall||0)*100);
   return '<div class=hrow><span class=fam>'+r.held_out_family+'</span>'+
    '<div class="hbar rg"><i style=width:'+rg+'%></i><span>'+rg+'%</span></div>'+
    '<div class="hbar ml"><i style=width:'+ml+'%></i><span>'+ml+'%</span></div></div>';}).join('');
  const win=rows.filter(r=>parseFloat(r.ml_recall)>parseFloat(r.regex_recall)).length;
  const c=$('holdConcl');c.style.display='block';
  c.innerHTML='<b>Вывод:</b> на '+win+' из '+rows.length+' незнакомых форматов ML-детектор находит секреты, которые поиск по шаблонам не находит вовсе — модель обобщает на новое, сигнатуры нет.';
 }
 if(!m&&!window._t2)window._t2=setInterval(poll,3000);
 if(m&&window._t2){clearInterval(window._t2);window._t2=null;}
}
poll();
</script></body></html>"""


ROI_HTML = r"""<!doctype html><html lang=ru><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>ROI — окно экспозиции секрета</title>
<style>

*{box-sizing:border-box}
body{margin:0;font-family:Inter,Segoe UI,Roboto,sans-serif;color:var(--ink);
 background:radial-gradient(1000px 460px at 85% -12%,#ede9fe70,transparent 60%),var(--bg)}
.wrap{max-width:920px;margin:0 auto;padding:34px 26px 70px}
.crumb{font-size:12.5px;color:var(--soft);margin-bottom:18px}.crumb a{color:var(--accent);font-weight:700;text-decoration:none}
h1{font-size:26px;margin:0 0 8px;letter-spacing:-.02em}
.lead{font-size:15px;color:var(--line-strong);line-height:1.6;margin:0 0 24px;max-width:760px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:20px 22px;box-shadow:0 1px 2px rgba(23,28,40,.05),0 8px 24px rgba(23,28,40,.06);margin-bottom:18px}
h2{font-size:15px;font-weight:600;letter-spacing:0;color:var(--text-1);margin:0 0 14px}
.ctrl{display:grid;grid-template-columns:1fr;gap:15px}
.field label{font-size:12.5px;font-weight:700;display:flex;justify-content:space-between}
.field label b{color:var(--accent);font-variant-numeric:tabular-nums}
.field input[type=range]{width:100%;accent-color:var(--accent);margin-top:7px}
.field .h{font-size:11px;color:var(--soft);margin-top:2px}
.big{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:4px}
.stat{background:linear-gradient(180deg,var(--info-bg),var(--accent-bg));border:1px solid var(--accent-border);border-radius:13px;padding:18px}
.stat .l{font-size:12px;color:var(--soft);font-weight:600}
.stat .v{font-size:30px;font-weight:800;letter-spacing:-.02em;margin-top:4px}
.stat.win .v{color:var(--green)}
.stat .s{font-size:11.5px;color:var(--soft);margin-top:5px}
.bar2{margin-top:16px}
.brow{display:flex;align-items:center;gap:10px;margin-bottom:9px;font-size:12.5px}
.brow .lab{width:180px;color:var(--line-strong);font-weight:600}
.btrack{flex:1;height:22px;border-radius:6px;background:var(--info-bg);overflow:hidden}
.btrack i{display:block;height:100%;border-radius:6px;transition:width .5s ease}
.assum{font-size:12px;color:var(--soft);line-height:1.7}
.assum code{background:var(--accent-bg);padding:1px 5px;border-radius:4px}
.btn{display:inline-flex;gap:8px;align-items:center;background:var(--accent-brand);color:#fff;
 border:none;border-radius:11px;padding:11px 18px;font-weight:700;font-size:13.5px;text-decoration:none;box-shadow:0 2px 10px #7c3aed44}
</style><link rel="stylesheet" href="/static/design-system.css"><link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='0.9em' font-size='90'>🛡</text></svg>"></head><body><div class=wrap>
<div class=crumb><a href="/">← Sentinel SOC</a> · оценка эффекта в деньгах</div>
<h1>Сколько стоит «окно экспозиции» секрета</h1>
<p class=lead>Утёкший ключ опасен ровно столько, сколько он остаётся незамеченным и действительным.
Платформа сокращает это окно с дней (до планового ротейта) до минут (MTTD — время до обнаружения).
Двигай ползунки — оценка пересчитывается вживую.</p>

<div class=card><h2>Параметры</h2>
<div class=ctrl>
  <div class=field><label>Инцидентов с утечкой секрета в год <b id=vN>12</b></label>
    <input type=range id=n min=1 max=200 value=12><div class=h>сколько раз в год у вас реально утекает секрет</div></div>
  <div class=field><label>Средний ущерб от одной полноценной компрометации, $ <b id=vC>250 000</b></label>
    <input type=range id=c min=10000 max=2000000 step=10000 value=250000><div class=h>дефолт — порядок публичных оценок стоимости утечки данных (проверь актуальную цифру перед защитой)</div></div>
  <div class=field><label>Окно БЕЗ системы — дней до планового ротейта <b id=vD>14</b></label>
    <input type=range id=d min=1 max=90 value=14><div class=h>сколько живёт скомпрометированный секрет, пока его не заметят/не сменят по расписанию</div></div>
  <div class=field><label>Доля ущерба, зависящая от времени экспозиции <b id=vK>70%</b></label>
    <input type=range id=k min=0 max=100 value=70><div class=h>часть ущерба, которую можно предотвратить быстрым обнаружением (остальное — мгновенный эффект утечки)</div></div>
</div></div>

<div class=card><h2>Оценка</h2>
<div class=big>
  <div class=stat><div class=l>Окно экспозиции сейчас → с системой</div><div class=v id=oWin>—</div><div class=s id=oWinS></div></div>
  <div class="stat win"><div class=l>Оценочная экономия в год</div><div class=v id=oSave>—</div><div class=s>предотвращённая, зависящая от времени часть ущерба</div></div>
</div>
<div class=bar2>
  <div class=brow><span class=lab>Ущерб без системы</span><div class=btrack><i id=b1 style="background:#dc2626"></i></div><b id=bl1></b></div>
  <div class=brow><span class=lab>Остаточный ущерб с системой</span><div class=btrack><i id=b2 style="background:#16a34a"></i></div><b id=bl2></b></div>
</div>
<div class=s style="font-size:11.5px;color:var(--soft);margin-top:10px" id=mttdNote>MTTD берётся из живых метрик платформы…</div>
</div>

<div class=card><h2>Допущения (важно для честности)</h2>
<div class=assum>
Модель линейная и намеренно простая: ущерб, зависящий от времени, считается пропорционально длительности экспозиции.
Экономия = <code>N × C × k × (1 − MTTD_дней / D)</code>, где MTTD переведён из сим-минут в дни.
Это оценка порядка величины, а не бухгалтерский расчёт: реальные потери зависят от типа секрета, прав доступа и скорости злоумышленника.
Внешняя цифра ущерба — порядок публичных отчётов (например, IBM Cost of a Data Breach); подставь свою и сверь перед защитой.
</div></div>

<a class=btn href="/">← Вернуться в консоль</a>
</div>
<script>
const $=x=>document.getElementById(x);
let MTTD_MIN=1;
function fmt(n){return n.toLocaleString('ru-RU',{maximumFractionDigits:0});}
function calc(){
 const n=+$('n').value,c=+$('c').value,d=+$('d').value,k=+$('k').value/100;
 $('vN').textContent=n;$('vC').textContent=fmt(c)+' $'.replace(' ','');$('vC').textContent=fmt(c);
 $('vD').textContent=d;$('vK').textContent=Math.round(k*100)+'%';
 const mttdDays=MTTD_MIN/60/24;
 const winCut=Math.max(0,1-mttdDays/d);
 const base=n*c*k;                 // зависящая от времени часть ущерба/год без системы
 const save=base*winCut;
 const resid=base-save;
 $('oWin').textContent=d+' дн → '+(MTTD_MIN<60?Math.round(MTTD_MIN)+' мин':(MTTD_MIN/60).toFixed(1)+' ч');
 $('oWinS').textContent='сокращение окна на '+Math.round(winCut*100)+'%';
 $('oSave').textContent='$'+fmt(save);
 const mx=Math.max(base,1);
 $('b1').style.width='100%';$('bl1').textContent='$'+fmt(base);
 $('b2').style.width=(resid/mx*100)+'%';$('bl2').textContent='$'+fmt(resid);
}
['n','c','d','k'].forEach(id=>$(id).addEventListener('input',calc));
async function pull(){try{const r=await fetch('/api/roi');const d=await r.json();
 if(d.mttd_sim_min!=null){MTTD_MIN=Math.max(0.1,d.mttd_sim_min);
  $('mttdNote').textContent='MTTD из живых метрик: '+d.mttd_sim_min+' сим-мин ('+d.incidents_seen+' инцидентов в этом прогоне).';}
 else $('mttdNote').textContent='Время до обнаружения появится, когда наберётся хотя бы один снапшот метрик.';
 calc();}catch(e){calc();}}
pull();
</script></body></html>"""


def main():
    eventstore.init()
    threading.Thread(target=_ingestor, daemon=True).start()
    threading.Thread(target=_triage_worker, daemon=True).start()
    threading.Thread(target=_metrics_snapshot_worker, daemon=True).start()
    port = getattr(config, "PURPLE_WEB_PORT", 8788)
    print("========================================================")
    print("  PURPLE TEAM CONSOLE (защита)")
    print(f"  Открой: http://127.0.0.1:{port}")
    print("========================================================")
    app.run(host="127.0.0.1", port=port, threaded=True, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
