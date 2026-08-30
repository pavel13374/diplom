# -*- coding: utf-8 -*-
"""ATT&CK-покрытие, профили акторов, Red Launcher

Часть консоли защиты. Вынесено из console.py: там 1841 строка держала
маршруты, ингест, триаж и сборку отчётов в одном файле, и правка одного
раздела требовала удерживать в голове все остальные.

Состояние и общие хелперы — в console_app.core, оно ЕДИНСТВЕННОЕ на процесс
и импортируется по имени: объекты (_COR, _STATE, _LOCK) создаются один раз
при импорте core и никогда не переприсваиваются, поэтому у всех разделов
общий экземпляр, а не копии.
"""

import time
import eventstore
import red_team
from flask import Blueprint, jsonify, request
from attack_matrix import ATTACK

# Общее состояние консоли — ЯВНО, а не через `import *`:
# видно, чем раздел пользуется, и статический анализ снова работает.
import websec
from .core import _COR, _LOCK, _STATE, _engine, _flog


bp = Blueprint("attack", __name__)

@bp.route("/api/coverage")
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

@bp.route("/api/navigator")
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
    # Через снимок: eng.ueba.actor — defaultdict, который поток ингеста
    # пополняет на КАЖДОМ событии, а этот код исполняется в потоке HTTP.
    prof = eng.ueba.profiles_snapshot().get(actor)
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
        hours_hist = [(h, round(prof["hours"][h], 2)) for h in range(24)]
        out["baseline"] = {
            "events_seen": prof["n"],
            "top_hours": [h for h, c in sorted(hours_hist, key=lambda x: -x[1])[:4] if c],
            "top_repos": prof["top_repos"],
            "top_actions": prof["top_actions"],
            "hours_hist": hours_hist,
            # средняя интенсивность актора — то, относительно чего считается
            # пуассоновский хвост всплеска
            "rate_per_window": round(prof.get("rate_ewma") or 0.0, 2),
            # СКОЛЬКО НАБЛЮДЕНИЙ НЕ ПОШЛО В БАЗОВУЮ ЛИНИЮ.
            # Событие, на котором сработало правило, в базу не берётся (иначе
            # достаточно повторять подозрительное действие, чтобы оно перестало
            # быть подозрительным). Большая доля пропусков у актора — сама по
            # себе подсказка аналитику.
            "learned": prof.get("learned"),
            "skipped": prof.get("skipped"),
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

@bp.route("/api/entities")
def api_entities():
    eng = _engine()
    with _LOCK:
        seen = dict(_STATE["by_actor"])
    profs = eng.ueba.profiles_snapshot()
    actors = set(seen) | set(profs)
    out = []
    for a in sorted(actors):
        prof = profs.get(a)
        out.append({"actor": a, "alerts": seen.get(a, 0),
                    "events_seen": prof["n"] if prof else 0})
    out.sort(key=lambda x: (-x["alerts"], -x["events_seen"]))
    return jsonify({"entities": out})

@bp.route("/api/entity/<actor>")
def api_entity(actor):
    return jsonify(_entity_profile(actor))

@bp.route("/api/red")
def api_red():
    red_team.RedTeamEngine({})
    camps = [{"key": k, "title": v["title"],
              "steps": [{"method": m, "technique": t, "tactic": ta} for m, t, ta in v["steps"]]}
             for k, v in red_team.CAMPAIGNS.items()]
    return jsonify({"campaigns": camps, "commands": eventstore.list_commands(12)})

@bp.route("/api/red/launch", methods=["POST"])
def api_red_launch():
    body = request.get_json(force=True, silent=True) or {}
    key = body.get("key")
    # evasion НЕ ПРОВЕРЯЛСЯ, в отличие от tempo. Любая строка ставилась в
    # очередь, доезжала до run_campaign и записывалась в КАЖДОЕ порождённое
    # событие как evasion_profile — поле разметки, по которому metrics.py и
    # research/ стратифицируют результаты. Произвольные значения создавали
    # фантомные страты и делали сравнение прогонов недействительным.
    evasion = body.get("evasion", "noisy")
    if evasion not in red_team.EVASIONS:
        return jsonify({"ok": False,
                        "msg": "неизвестный профиль уклонения: "
                               + ", ".join(sorted(red_team.EVASIONS))}), 400
    tempo = body.get("tempo", "fast")
    if tempo not in ("fast", "realistic", "slow"):
        tempo = "fast"
    if key not in red_team.CAMPAIGNS:
        return jsonify({"ok": False, "msg": "unknown campaign"}), 400
    # Просроченные команды снимаем ДО постановки новой: иначе свежий запуск
    # встаёт в хвост очереди из нажатий, сделанных при остановленном мире, и
    # ждёт, пока мир по одной разберёт весь этот хвост.
    eventstore.expire_stale_commands()
    cid = eventstore.enqueue_command("campaign", {"key": key, "evasion": evasion, "tempo": tempo})
    camp = red_team.CAMPAIGNS[key]
    ahead = max(0, eventstore.pending_commands() - 1)
    msg = f"кампания «{camp['title']}» поставлена в очередь"
    if ahead:
        msg += f"; перед ней {ahead} в работе"
    # ЗАПУСК АТАКИ — СОБЫТИЕ, КОТОРОЕ ОБЯЗАНО БЫТЬ В ЖУРНАЛЕ.
    # Раньше постановка кампании в очередь не логировалась вовсе: по журналу
    # нельзя было понять, кто и когда запустил атаку, и почему через минуту
    # посыпались алерты.
    _flog.info("красная команда: кампания поставлена в очередь",
               extra={"ctx": {"command_id": cid, "scenario": key,
                              "title": camp["title"], "steps": len(camp["steps"]),
                              "evasion": evasion, "tempo": tempo,
                              "queue_ahead": ahead}})
    return jsonify({"ok": True, "cmd": cid, "launched_at": time.time(),
                    "key": key, "title": camp["title"], "steps": len(camp["steps"]),
                    "queue_ahead": ahead, "msg": msg})

@bp.route("/api/red/result")
def api_red_result():
    """Результат запущенной кампании: статус команды + инциденты, впервые
    увиденные после запуска (по seen_real), со временем появления. Даёт
    аналитику обратную связь: детект действительно сработал."""
    try:
        ts = float(request.args.get("ts", "0"))
    except (TypeError, ValueError):
        ts = 0.0
    cid = websec.bounded_str(request.args.get("cmd", ""), "cmd", 32)
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
    with _LOCK:
        _snap = _COR.list(200)
    for i in _snap:
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

