"""
Сборка текстового отчёта о работе симулятора (для Telegram / лога).
"""
import html


def _esc(x):
    return html.escape(str(x))


def build_report(scheduler=None, title="Отчёт SOC-симулятора", uptime_s=0):
    import simclock
    import events
    import runlog

    st = scheduler.stats if scheduler else {}
    ev = events.stats()
    rl = runlog.stats()
    actors = events.actors_summary()

    skip = ("total_runs", "total_ok", "total_fail", "skipped_offhours")
    acts = {k: v for k, v in st.items() if k not in skip and v}
    top_acts = sorted(acts.items(), key=lambda x: -x[1])[:8]

    by_anom = ev.get("by_anomaly", {})
    top_anom = sorted(by_anom.items(), key=lambda x: -x[1])[:8]

    L = [f"<b>{_esc(title)}</b>"]
    L.append(f"🕒 sim: {_esc(simclock.stamp())}")
    if uptime_s:
        h, m = uptime_s // 3600, (uptime_s % 3600) // 60
        L.append(f"⏱ uptime: {h}ч {m}м")
    L.append("")
    L.append(f"Действий: <b>{st.get('total_runs', 0)}</b> · "
             f"ок {st.get('total_ok', 0)} · ошибок {st.get('total_fail', 0)} · "
             f"ночью пропущено {st.get('skipped_offhours', 0)}")
    L.append(f"Событий в журнале: <b>{ev.get('total', 0)}</b> · "
             f"аномалий <b>{ev.get('anomalies', 0)}</b>")
    if scheduler and getattr(scheduler, "state", None):
        try:
            L.append(f"Спринт #{scheduler.state.data['sprint_number']} · "
                     f"правил {scheduler.state.rule_count()}")
        except Exception:
            pass
    L.append(f"⚠️ warnings: {rl.get('warnings', 0)} · ❌ errors: {rl.get('errors', 0)}")

    if top_anom:
        L.append("")
        L.append("<b>Аномалии по типам:</b>")
        for k, v in top_anom:
            L.append(f"  • {_esc(k)}: {v}")

    if top_acts:
        L.append("")
        L.append("<b>Топ активностей:</b>")
        for k, v in top_acts:
            L.append(f"  • {_esc(k)}: {v}")

    if actors:
        L.append("")
        L.append("<b>Сотрудники:</b>")
        for u, a in sorted(actors.items(), key=lambda x: -x[1].get("total", 0)):
            if u == "soc-bot":
                continue
            L.append(f"  • {_esc(u)}: {a.get('total',0)} действ. "
                     f"(push {a.get('pushes',0)}, MR {a.get('mrs',0)}, "
                     f"⚠ {a.get('anomalies',0)})")

    errs = rl.get("recent_errors", [])
    if errs:
        L.append("")
        L.append("<b>Последние ошибки:</b>")
        for e in errs[-6:]:
            L.append(f"  {_esc(e['t'])} {_esc(e['msg'][:140])}")

    return "\n".join(L)


def build_anomaly_alert(anom_type, actor, severity="", detail=""):
    import simclock
    sev = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(severity, "⚠️")
    txt = (f"{sev} <b>Аномалия:</b> {_esc(anom_type)}\n"
           f"Кто: {_esc(actor)} · {_esc(simclock.stamp())}")
    if detail:
        txt += f"\n{_esc(detail)}"
    return txt
