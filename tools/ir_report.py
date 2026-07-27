#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Генератор IR-отчётов (markdown) — в формате реального incident report.

Берёт поток из event-store, прогоняет защиту (detector + correlator) и для
каждого инцидента пишет профессиональный отчёт в reports/:
  • Executive summary (LLM-нарратив, если есть Ollama; иначе детерминированный);
  • severity и метаданные, затронутые активы;
  • ATT&CK kill-chain mapping (с разрывами времени = dwell);
  • таймлайн алертов;
  • IOC-таблица (индикаторы компрометации);
  • рекомендации, привязанные к наблюдаемым тактикам.

Анти-лик: отчёт строится из blue-алертов (наблюдаемое), без меток мира.

Запуск:
    python ir_report.py            # все инциденты
    python ir_report.py --top 3    # топ-3 по риску
    python ir_report.py --id 7     # один инцидент
"""

# --- скрипт живёт в подпапке; движок проекта — в корне ---
import os as _os, sys as _sys
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
for _p in (_ROOT, _os.path.join(_ROOT, "tools"), _os.path.join(_ROOT, "research")):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
_os.chdir(_ROOT)
del _os, _sys
import os
import sys
import argparse
from datetime import datetime

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

import ioc as ioc_mod

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def build_incidents():
    import eventstore, run_defense, correlator as cm, config
    eventstore.init()
    cor = cm.Correlator(window_min=getattr(config, "CORRELATION_WINDOW_MIN", 180))
    for ev in eventstore.read_since(0, limit=10_000_000):
        det = run_defense.process(ev)
        if det.get("alert"):
            cor.add(run_defense.observed(ev), det)
    return cor


def _parse(ts):
    try:
        return datetime.strptime(ts or "", "%Y-%m-%dT%H:%M:%S")
    except Exception:
        return None


def _gap(a, b):
    da, db = _parse(a), _parse(b)
    if not da or not db:
        return ""
    m = (db - da).total_seconds() / 60
    if m >= 1440: return f"+{round(m/1440)}д"
    if m >= 60:   return f"+{round(m/60)}ч"
    if m >= 2:    return f"+{round(m)}м"
    return ""


def _narrative(inc):
    """Exec summary: LLM-триаж (если доступен), иначе детерминированный фолбэк."""
    incident = {
        "incident_id": inc["id"], "title": f"Инцидент @{inc['actor']}",
        "actor": inc["actor"], "repos": inc["repos"],
        "risk_score": round(inc["max_risk"], 2),
        "kill_chain_tactics": inc["tactics"], "techniques": inc["techniques"],
        "events": [{"tactic": c.get("tactic"), "technique": c.get("technique"),
                    "action": c.get("action")} for c in inc.get("chain", [])][:20],
    }
    try:
        import llm_client
        res = llm_client.triage(incident)
        return res.get("narrative") or "", res.get("_source", "?"), res
    except Exception:
        return "", "error", {}


def _recommendations(inc):
    tac = set(inc.get("tactics", []))
    recs = []
    if {"Credential Access", "Collection"} & tac:
        recs.append("Немедленно отозвать и ротировать затронутые токены/секреты; включить Secret Push Protection на secret-пути.")
    if "Exfiltration" in tac:
        recs.append("Проверить исходящий трафик/артефакты сборки; заблокировать каналы выгрузки, проверить внешние реестры.")
    if "Defense Evasion" in tac:
        recs.append("Восстановить ослабленные контроли пайплайна и protected branches; сверить историю изменений `.gitlab-ci.yml`.")
    if "Impact" in tac:
        recs.append("Заморозить затронутые репозитории; восстановить удалённое из бэкапа; проверить целостность веток.")
    if "Persistence" in tac:
        recs.append("Аннулировать лишние/неизвестные access-токены; пересмотреть членство и права в группах.")
    if "Reconnaissance" in tac:
        recs.append("Зафиксировать разведку как ранний сигнал; усилить мониторинг по этому актору на ближайшие дни.")
    recs.append("Собрать полный таймлайн и артефакты; зафиксировать IOC ниже в тикете.")
    if inc.get("is_campaign"):
        recs.append("ЭСКАЛАЦИЯ: подтверждена многошаговая атака (несколько тактик ATT&CK) — привлечь IR-дежурного.")
    return recs


def render(inc):
    iocs = ioc_mod.from_incident(inc)
    narrative, src, triage = _narrative(inc)
    sev = inc["severity"].upper()
    # хронологический порядок (демо-данные могут идти не по времени)
    inc = dict(inc)
    inc["alerts"] = sorted(inc.get("alerts", []), key=lambda a: a.get("ts_sim") or "")
    inc["chain"] = sorted(inc.get("chain", []), key=lambda c: c.get("ts") or "")
    times = [a.get("ts_sim") for a in inc["alerts"] if a.get("ts_sim")]
    win_lo, win_hi = (times[0], times[-1]) if times else (inc["start_ts"], inc["last_ts"])
    inc["start_ts"], inc["last_ts"] = win_lo, win_hi
    span = _gap(win_lo, win_hi)
    md = []
    md.append(f"# IR-отчёт · Инцидент #{inc['id']}")
    md.append("")
    md.append(f"**Классификация:** {'МНОГОШАГОВАЯ КАМПАНИЯ' if inc.get('is_campaign') else 'ОДИНОЧНЫЙ ИНЦИДЕНТ'} · "
              f"**Severity:** {sev} · **Risk:** {round(inc['max_risk'],2)} · "
              f"**Сформирован:** {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    md.append("")
    md.append("## 1. Краткая сводка (для руководства)")
    md.append("")
    if narrative:
        md.append(f"{narrative}")
        md.append("")
        md.append(f"_Источник разбора: {src}._")
    else:
        md.append(f"Зафиксирована подозрительная активность учётной записи **@{inc['actor']}** "
                  f"с максимальным риском {round(inc['max_risk'],2)} "
                  f"({'многошаговая ATT&CK-кампания' if inc.get('is_campaign') else 'одиночный инцидент'}). "
                  f"Затронуто репозиториев: {len(inc['repos'])}. Тактик ATT&CK: {len(inc['tactics'])}.")
    md.append("")

    md.append("## 2. Затронутые активы")
    md.append("")
    md.append(f"- **Учётная запись (подозреваемый):** @{inc['actor']}")
    md.append(f"- **Репозитории:** {', '.join(inc['repos']) or '—'}")
    md.append(f"- **Окно атаки (sim):** {inc['start_ts']} → {inc['last_ts']}"
              + (f"  (растянуто на {span} — dwell time)" if span and ('д' in span or 'ч' in span) else ""))
    md.append(f"- **Алертов:** {len(inc['alerts'])} · **Тактик:** {len(inc['tactics'])} · "
              f"**Техник:** {len(inc['techniques'])}")
    md.append("")

    md.append("## 3. ATT&CK kill-chain")
    md.append("")
    if inc["chain"]:
        md.append("| # | Тактика | Техника | Действие | Risk | Время (sim) | Δ |")
        md.append("|---|---|---|---|---|---|---|")
        prev = None
        for n, c in enumerate(inc["chain"], 1):
            ts = (c.get("ts") or "").replace("T", " ")
            gap = _gap(prev, c.get("ts")) if prev else ""
            prev = c.get("ts")
            md.append(f"| {n} | {c.get('tactic','?')} | `{c.get('technique','')}` | "
                      f"{c.get('action','')} | {c.get('risk')} | {ts} | {gap} |")
    else:
        md.append("_нет данных_")
    md.append("")

    md.append("## 4. Таймлайн алертов")
    md.append("")
    md.append("| Время (sim) | Действие | Путь | Техника | Risk | Причина |")
    md.append("|---|---|---|---|---|---|")
    for a in inc["alerts"]:
        ts = (a.get("ts_sim") or "").replace("T", " ")
        md.append(f"| {ts} | {a.get('action','')} | {a.get('path','') or ''} | "
                  f"{a.get('technique','')} | {a.get('risk')} | {a.get('reason','')} |")
    md.append("")

    md.append("## 5. Индикаторы компрометации (IOC)")
    md.append("")
    md.append(ioc_mod.table_md(iocs))
    md.append("")

    md.append("## 6. Рекомендованные действия")
    md.append("")
    for r in _recommendations(inc):
        md.append(f"- [ ] {r}")
    md.append("")
    md.append(f"_Сгенерировано автоматически {datetime.now().strftime('%Y-%m-%d %H:%M')} · "
              f"Purple Team Console · анти-лик (только наблюдаемые данные)._")
    return "\n".join(md)


def main():
    ap = argparse.ArgumentParser(description="IR report generator")
    ap.add_argument("--id", type=int, default=None)
    ap.add_argument("--top", type=int, default=0, help="только топ-N по риску")
    args = ap.parse_args()

    cor = build_incidents()
    if not cor.incidents:
        print("[!] Инцидентов нет (запусти мир/защиту или make_demo.py --fresh).")
        sys.exit(1)

    outdir = os.path.join(BASE, "reports")
    os.makedirs(outdir, exist_ok=True)

    if args.id:
        incs = [cor.get(args.id)]
        if not incs[0]:
            print(f"[!] Инцидент #{args.id} не найден."); sys.exit(1)
    else:
        incs = cor.list(args.top or 100)

    n = 0
    for inc in incs:
        fp = os.path.join(outdir, f"incident_{inc['id']}.md")
        open(fp, "w", encoding="utf-8").write(render(inc))
        n += 1
        print(f"  -> reports/incident_{inc['id']}.md  (@{inc['actor']}, {inc['severity']}, "
              f"{len(inc['tactics'])} тактик, {ioc_mod.count(ioc_mod.from_incident(inc))} IOC)")
    print(f"\nГотово: {n} отчётов в reports/")


if __name__ == "__main__":
    main()
