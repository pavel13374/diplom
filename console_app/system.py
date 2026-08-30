# -*- coding: utf-8 -*-
"""Диагностика, здоровье, онбординг, демо

Часть консоли защиты. Вынесено из console.py: там 1841 строка держала
маршруты, ингест, триаж и сборку отчётов в одном файле, и правка одного
раздела требовала удерживать в голове все остальные.

Состояние и общие хелперы — в console_app.core, оно ЕДИНСТВЕННОЕ на процесс
и импортируется по имени: объекты (_COR, _STATE, _LOCK) создаются один раз
при импорте core и никогда не переприсваиваются, поэтому у всех разделов
общий экземпляр, а не копии.
"""

import time
import threading
import json
import config
import eventstore
import soclog
from flask import Blueprint, jsonify, request

# Общее состояние консоли — ЯВНО, а не через `import *`:
# видно, чем раздел пользуется, и статический анализ снова работает.
from .core import _DEMO, _HEALTH, _LOCK, _STATE, _flog, incidents_snapshot

# Демо-прогон крутится фоновым потоком из ingest.
from .ingest import _demo_worker


bp = Blueprint("system", __name__)

@bp.route("/api/diag")
def api_diag():
    """Диагностика: счётчики уровней, последние ошибки, хвост структурного лога."""
    d = soclog.diag()
    d["errors_log_tail"] = soclog.tail_errors(60)
    # ТИХИЕ ДЕГРАДАЦИИ — В ДИАГНОСТИКУ.
    # Нераспознанная метка времени обнуляет ВСЕ оконные агрегаты события
    # (всплески удалений, интенсивность чтений API, число репозиториев), а
    # отвергнутое правило отсутствует в каталоге. И то и другое раньше нигде
    # не показывалось.
    try:
        import detector
        from .core import _engine
        d["ts_parse_failures"] = detector.ts_failures()
        d["rejected_rules"] = _engine().rejected_rules()
    except Exception:
        _flog.error("не удалось собрать показатели деградации", exc_info=True)
    return jsonify(d)

def _ollama_state():
    """(доступна, причина). Причина нужна ровно так же, как в проверке GitLab:
    плитка «Ollama» показывала красный кружок и НИ СЛОВА о том, сервис не
    запущен, адрес не тот или модель не скачана."""
    if time.time() - _HEALTH["ts"] > 30:
        try:
            import llm_client
            ok, why, _m = llm_client.status()
            _HEALTH["ollama"] = bool(ok)
            _HEALTH["ollama_reason"] = why
        except Exception as e:
            _HEALTH["ollama"] = False
            _HEALTH["ollama_reason"] = f"проверка не выполнилась: {type(e).__name__}"
        _HEALTH["ts"] = time.time()
    return _HEALTH["ollama"], _HEALTH.get("ollama_reason", "")


def _ollama_ok():
    return _ollama_state()[0]

@bp.route("/api/telegram")
def api_telegram():
    """Состояние интеграции. Токена здесь нет — только признак и подсказка."""
    import telegram
    st = telegram.state()
    return jsonify(st)


@bp.route("/api/telegram/test", methods=["POST"])
def api_telegram_test():
    """Проверка связи и тестовое сообщение — кнопкой, а не из консоли."""
    import telegram
    ok_ping, who = telegram.ping()
    sent = False
    if ok_ping:
        sent = telegram.send("✅ <b>Проверка связи</b>\nСообщение отправлено "
                             "консолью защиты вручную.",
                             kind="test", dedup=False)
    _flog.info("проверка Telegram по кнопке",
               extra={"ctx": {"ping_ok": ok_ping, "sent": sent, "bot": who}})
    return jsonify({"ping": ok_ping, "bot": who, "sent": sent,
                    "state": telegram.state()})


@bp.route("/api/telegram/report", methods=["POST"])
def api_telegram_report():
    """Отправить сводку SOC немедленно (те же числа, что на экране)."""
    from . import notify
    ok = notify.send_summary("Сводка SOC (по запросу оператора)",
                             kind="soc_report_manual", silent=False)
    return jsonify({"sent": bool(ok)})


@bp.route("/api/health")
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
    # СОСТОЯНИЕ GITLAB — ЧЕСТНОЕ, А НЕ «ВСЕГДА ЗЕЛЁНОЕ».
    #
    # Этот ответ поля `gitlab` не содержал вовсе, а страница диагностики
    # рисовала плитку по условию `h.gitlab !== false`. В JavaScript
    # `undefined !== false` истинно, поэтому плитка ВСЕГДА показывала
    # «GitLab · на связи», зелёным, при любом положении дел — в том числе в
    # offline-режиме, где к GitLab вообще не обращаются. Консоль защиты
    # утверждала о состоянии внешней системы то, чего не проверяла.
    #
    # Консоль защиты по устройству к GitLab не ходит (её единственный вход —
    # журнал событий), поэтому честных состояний здесь три: «offline»,
    # «не проверяется этим процессом» и — когда мир пишет события — их
    # свежесть. Врать зелёным нельзя.
    if bool(getattr(config, "OFFLINE_MODE", False)) or \
            bool(getattr(config, "OFFLINE_FORCED", False)):
        gl = {"state": "offline",
              "detail": "SOC_OFFLINE: мир пишет события локально, GitLab не вызывается"}
    else:
        gl = {"state": "unknown",
              "detail": "связь с GitLab проверяет консоль среды (:%s)"
                        % getattr(config, "WEB_PORT", 8787)}
    return jsonify({
        "gitlab": gl,
        "world_alive": age is not None and age < 180,
        "events": {"total": st.get("events", 0), "last": last, "last_age_s": age},
        "store_ok": bool(st.get("enabled")),
        "store_error": store_err,
        "defense": {"running": running, "processed": processed},
        "ollama": _ollama_state()[0],
        "ollama_reason": _ollama_state()[1],
        "ollama_model": getattr(config, "LLM", {}).get("model", ""),
        "auto_triage": bool(getattr(config, "LLM_AUTO_TRIAGE", True)),
        # Состояние канала уведомлений — рядом с прочей инфраструктурой.
        # Раньше про Telegram в диагностике не было НИЧЕГО: включён ли он,
        # доходят ли сообщения и почему не доходят, выяснялось только чтением
        # логов. Токена здесь нет — только признак и подсказка вида "8717…46".
        "telegram": _telegram_health(),
    })


def _telegram_health():
    try:
        import telegram
        st = telegram.state()
        return {"enabled": st.get("enabled"), "sent": st.get("sent"),
                "failed": st.get("failed"), "retries": st.get("retries"),
                "suppressed": (st.get("suppressed_flood", 0)
                               + st.get("suppressed_dup", 0)),
                "last_ok_ts": st.get("last_ok_ts"),
                "last_error": st.get("last_error"),
                "token_hint": st.get("token_hint"),
                "reason": st.get("disabled_reason")}
    except Exception:
        _flog.error("не удалось прочитать состояние Telegram", exc_info=True)
        return {"enabled": False, "reason": "ошибка чтения состояния"}

@bp.route("/api/demo", methods=["GET", "POST"])
def api_demo():
    if request.method == "POST" and not _DEMO["running"]:
        _DEMO.update(running=True, msg="генерирую демо-поток (норма + 2 кампании)…", rc=None)
        threading.Thread(target=_demo_worker, daemon=True).start()
    return jsonify(_DEMO)

@bp.route("/api/onboarding")
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
    try:
        # Под замком: словарь инцидентов пополняет поток ингеста.
        triaged = sum(1 for i in incidents_snapshot() if i.get("triage"))
    except Exception:
        _flog.error("не удалось посчитать разобранные инциденты", exc_info=True)
        triaged = 0
    return jsonify({
        "s1_world": (age is not None and age < 180) or _DEMO["running"],
        "s2_events": st.get("events", 0) > 0,
        "s3_campaign": st.get("campaigns", 0) > 0,
        "s4_alerts": alerts > 0,
        "s5_triage": triaged > 0,
        "demo": _DEMO,
    })



# ----------------------------------------------------------------------
@bp.route("/api/client-error", methods=["POST"])
def api_client_error():
    """Приём ошибки, случившейся в браузере.

    Без этого маршрута клиентская ошибка жила только в консоли разработчика:
    пользователь видел тост «Сбой в интерфейсе» и не мог передать ничего,
    кроме скриншота. Теперь она ложится рядом с серверными и уходит в общую
    выгрузку /api/diag/bundle.
    """
    d = request.get_json(silent=True) or {}
    rec = soclog.client_error(
        where=d.get("where", "?"), message=d.get("message", ""),
        stack=d.get("stack", ""), url=d.get("url", ""),
        ua=request.headers.get("User-Agent", ""), app="console")
    return jsonify({"ok": True, "ts": rec["ts"]})


@bp.route("/api/diag/bundle")
def api_diag_bundle():
    """ВСЯ диагностика одним JSON — чтобы приложить к обращению целиком."""
    return jsonify(soclog.bundle("console"))


@bp.route("/api/diag/bundle.json")
def api_diag_bundle_file():
    """То же, но файлом на скачивание."""
    from flask import Response
    data = json.dumps(soclog.bundle("console"), ensure_ascii=False, indent=2)
    return Response(data, mimetype="application/json",
                    headers={"Content-Disposition":
                             "attachment; filename=sentinel-diag-console.json"})
