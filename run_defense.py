#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ПРОЦЕСС «ЗАЩИТА» (Defense/SOC) — стрим-ингестор event-store.

Читает поток событий из общего SQLite-стора ПО КУРСОРУ (позиция переживает
рестарт: ни потерь, ни дублей). Для каждого нового события прогоняет лёгкий
потоковый детектор и печатает алерты. Это каркас EPIC 0 — полноценный
Detection Stack (rules+UEBA+ML) встаёт сюда же в EPIC 2.

АНТИ-ЛИК: защита НЕ использует разметку (is_anomaly/anomaly_type/family/...).
Детектор смотрит только на наблюдаемые поля события.

Запуск:  python run_defense.py            (бесконечный tail)
         python run_defense.py --once     (обработать накопленное и выйти)
         python run_defense.py --reset-cursor   (читать с начала)
"""
import sys
import time
import argparse
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

import logging

import eventstore
import detector
import soclog

log = logging.getLogger("ingest")

CURSOR = "defense"

# поля, которые защите видеть НЕЛЬЗЯ (разметка мира) — анти-лик
#
# Список расширен по результатам tests/test_leakage.py: помимо явных меток
# сюда попали поля, которые метку не называют, но однозначно её выдают.
LEAK = {
    # --- явные метки мира ---
    "is_anomaly", "anomaly_type", "family", "is_decisive", "severity",
    "episode_id", "campaign_id", "campaign_name", "step_idx",
    "technique_id", "tactic", "evasion_profile",
    "secret_type", "anomaly_subtype", "detail",
    "persona", "motive", "dwell_days",
    # --- метки-двойники, найденные тестом на взаимную информацию ---
    # actor_session: идентификатор «рабочей сессии» актора, который симулятор
    # нарезает по паузам. У шагов кампании он общий и уникальный, поэтому поле
    # снимало 100% неопределённости метки — то есть было меткой.
    "actor_session", "session_id", "run_id", "seq",
    # repo/grantee/for_user/token_scope-детали проставляются через events.tag
    # ТОЛЬКО в аномальных сценариях: само наличие поля выдавало атаку.
    "repo", "grantee", "for_user", "deleted_count", "quirk", "lookalike",
    # gitlab_ok/gitlab_error — телеметрия обращения к API самого стенда,
    # а не наблюдаемое свойство события в GitLab.
    "gitlab_ok", "gitlab_error", "project_id",
    # служебное
    "labels", "activity", "executed",
}

_ENGINE = detector.DetectionEngine()
_SUPPRESS = detector.Suppressor()


def observed(ev):
    """Только наблюдаемые поля (срезаем разметку мира)."""
    return {k: v for k, v in ev.items() if k not in LEAK}


def process(ev):
    """Полный результат детектора (L0 rules + L1 UEBA + fusion)."""
    return _ENGINE.process(observed(ev))


def detect(ev):
    """Совместимый вид: (is_alert, reason, risk). Под капотом — DetectionEngine."""
    res = _ENGINE.process(observed(ev))
    if not res["alert"]:
        return False, "", 0.0
    top = max(res["alerts"], key=lambda a: a["risk"])
    tech = ("[" + top["technique"] + "] ") if top.get("technique") else ""
    return True, tech + top["reason"], res["risk"]


def run(once=False, poll=2.0):
    soclog.install()
    eventstore.init()
    if not eventstore.enabled():
        print("[!] Event-store недоступен (config.EVENT_STORE.enabled?).")
        log.error("event-store недоступен — ингест не запущен")
        return
    pos = eventstore.get_cursor(CURSOR)
    st = eventstore.stats()
    print(f"Event-store: {st.get('events')} событий | курсор defense = {pos}")
    print("Жду поток... (Ctrl+C для выхода)\n")
    log.info("ингест запущен", extra={"ctx": {"cursor": pos,
             "store_events": st.get("events"), "once": once}})
    processed = alerts = suppressed = errors = 0
    try:
        while True:
            batch = eventstore.read_since(pos, limit=500)   # meta уже отфильтрованы
            if batch:
                log.debug("batch", extra={"ctx": {"n": len(batch),
                          "cursor_from": pos, "cursor_to": batch[-1]["_id"],
                          "lag": (st.get("events") or 0) - batch[-1]["_id"]}})
            for ev in batch:
                pos = ev["_id"]
                processed += 1
                try:
                    # ВАЖНО: process() зовём РОВНО ОДИН РАЗ на событие —
                    # повторный вызов дважды обновлял бы UEBA-профиль актора.
                    res = process(ev)
                except Exception:
                    errors += 1
                    log.error("детектор упал на событии — пропускаю",
                              exc_info=True,
                              extra={"ctx": {"event_id": ev.get("_id"),
                                             "actor": ev.get("actor"),
                                             "action": ev.get("action")}})
                    continue
                if res.get("alert"):
                    top = max(res["alerts"], key=lambda a: a["risk"]) if res.get("alerts") else {}
                    risk = res["risk"]
                    tech = ("[" + top["technique"] + "] ") if top.get("technique") else ""
                    reason = tech + top.get("reason", "")
                    # подавление дублей (alert fatigue): тот же actor+rule в окне
                    if _SUPPRESS.is_duplicate(ev.get("actor"), top.get("rule_id"), ev.get("ts_sim")):
                        suppressed += 1
                        log.debug("алерт подавлен как дубль",
                                  extra={"ctx": {"event_id": ev.get("_id"),
                                                 "actor": ev.get("actor"),
                                                 "rule_id": top.get("rule_id")}})
                        continue
                    alerts += 1
                    try:
                        eventstore.append_alert({
                            "event_id": ev.get("_id"), "ts_sim": ev.get("ts_sim"),
                            "actor": ev.get("actor"), "action": ev.get("action"),
                            "project": ev.get("project"), "technique": top.get("technique"),
                            "tactic": top.get("tactic"), "risk": risk, "reason": reason})
                    except Exception:
                        log.error("не удалось записать алерт в event-store",
                                  exc_info=True,
                                  extra={"ctx": {"event_id": ev.get("_id")}})
                    ts = (ev.get("ts_sim") or "").replace("T", " ")[5:]
                    print(f"  ALERT risk={risk:.2f} | {ts} | @{ev.get('actor')} "
                          f"{ev.get('action')} -> {ev.get('project')} | {reason}")
            if batch:
                eventstore.set_cursor(CURSOR, pos)
            if once:
                break
            if not batch:
                time.sleep(poll)
    except KeyboardInterrupt:
        pass
    eventstore.set_cursor(CURSOR, pos)
    log.info("ингест остановлен", extra={"ctx": {"processed": processed,
             "alerts": alerts, "suppressed": suppressed,
             "errors": errors, "cursor": pos}})
    print(f"\nОбработано новых событий: {processed} | алертов: {alerts} | "
          f"подавлено дублей: {suppressed} | ошибок: {errors} | курсор={pos}")


def main():
    ap = argparse.ArgumentParser(description="Defense stream ingestor")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--reset-cursor", action="store_true")
    ap.add_argument("--poll", type=float, default=2.0)
    args = ap.parse_args()
    eventstore.init()
    if args.reset_cursor:
        eventstore.set_cursor(CURSOR, 0)
        print("Курсор defense сброшен в 0 (читаем с начала).")
    run(once=args.once, poll=args.poll)


if __name__ == "__main__":
    main()
