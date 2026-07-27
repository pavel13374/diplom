#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Оффлайн-оценка LLM-триажа (цифры для главы LLM в дипломе).

Что делает:
  • из размеченных эпизодов строит leak-free инциденты (incident_builder) и
    прогоняет через triage();
  • собирает benign-«инциденты» из нормальных сессий (в т.ч. .env.example) как
    негативы;
  • считает: recall триажа на аномалиях (доля «is_true_positive=true»),
    точность на benign (доля «false»), отдельно — на benign-двойниках
    (placeholder_signal), согласованность severity;
  • сравнивает LLM и детерминированный фолбэк — показывает, что добавляет LLM.

Метки используются ТОЛЬКО для оценки, в инцидент (вход triage) они не попадают.

Запуск:  python eval_triage.py [--in data/events.jsonl] [--max-benign 60]
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
import json
import argparse
from collections import defaultdict

import config
import incident_builder as ib
import llm_client as lc


def _load_raw(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
                if not (r.get("meta") or r.get("action") in ("anomaly", "activity")):
                    rows.append(r)
            except json.JSONDecodeError:
                pass
    return rows


def _assert_no_leak(inc):
    flat = json.dumps(inc, ensure_ascii=False)
    for bad in ("is_anomaly", "anomaly_type", '"family"', '"severity"', "is_decisive", "secret_type"):
        if bad in flat:
            raise AssertionError(f"ЛИК в инциденте: {bad}")


def _benign_sessions(rows, max_n):
    """Нормальные события группируем по actor_session; берём сессии >=2 событий."""
    by_sess = defaultdict(list)
    for r in rows:
        if r.get("is_anomaly"):
            continue
        sid = r.get("actor_session")
        if sid and sid != "system":
            by_sess[sid].append(r)
    sessions = [evs for evs in by_sess.values() if len(evs) >= 2]
    # приоритет — сессии с placeholder-пушами (benign-двойники)
    sessions.sort(key=lambda evs: (not any(e.get("placeholder_signal") for e in evs), -len(evs)))
    return sessions[:max_n]


def _run(triage_fn, incidents):
    """incidents: list[(inc, truth_tp, truth_sev)]. Возвращает метрики."""
    res = {"tp_caught": 0, "tp_total": 0, "bn_correct": 0, "bn_total": 0,
           "bn_double_correct": 0, "bn_double_total": 0, "sev_ok": 0, "sev_total": 0}
    SEV_ORD = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    for inc, truth_tp, truth_sev, is_double in incidents:
        out = triage_fn(inc)
        said_tp = bool(out.get("is_true_positive"))
        if truth_tp:
            res["tp_total"] += 1
            if said_tp:
                res["tp_caught"] += 1
            # severity: засчитываем, если не занизил более чем на 1 уровень
            if truth_sev and out.get("severity") in SEV_ORD:
                res["sev_total"] += 1
                if SEV_ORD[out["severity"]] >= SEV_ORD.get(truth_sev, 0) - 1:
                    res["sev_ok"] += 1
        else:
            res["bn_total"] += 1
            if not said_tp:
                res["bn_correct"] += 1
            if is_double:
                res["bn_double_total"] += 1
                if not said_tp:
                    res["bn_double_correct"] += 1
    return res


def _pct(a, b):
    return f"{(a/b*100 if b else 0):5.1f}%  ({a}/{b})"


def main():
    ap = argparse.ArgumentParser(description="Оффлайн-оценка LLM-триажа")
    ap.add_argument("--in", dest="inp", default="data/events.jsonl")
    ap.add_argument("--max-benign", type=int, default=60)
    args = ap.parse_args()
    config.seed_all()

    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    inp = args.inp if os.path.isabs(args.inp) else os.path.join(base, args.inp)
    if not os.path.exists(inp):
        print(f"[!] Нет файла событий: {inp}"); sys.exit(1)

    rows = _load_raw(inp)
    eps = ib.episodes_from_rows(rows)

    incidents = []   # (inc, truth_tp, truth_sev, is_double)
    for eid, evs in eps.items():
        sev = next((e.get("severity") for e in evs if e.get("severity")), "medium")
        inc = ib.build_incident(evs, incident_id=eid)
        _assert_no_leak(inc)
        incidents.append((inc, True, sev, False))

    for evs in _benign_sessions(rows, args.max_benign):
        inc = ib.build_incident(evs, incident_id="benign")
        _assert_no_leak(inc)
        is_double = any(e.get("placeholder_signal") for e in evs)
        incidents.append((inc, False, None, is_double))

    n_anom = sum(1 for _, tp, *_ in incidents if tp)
    n_benign = len(incidents) - n_anom
    print("=" * 68)
    print("ОФФЛАЙН-ОЦЕНКА ТРИАЖА")
    print("=" * 68)
    print(f"аномальных эпизодов: {n_anom} | benign-сессий: {n_benign}")
    print(f"LLM доступна: {'ДА' if lc.available() else 'НЕТ (LLM-колонка = фолбэк)'}")
    print(f"анти-лик: пройден (метки в инцидент не попали)")
    print("-" * 68)

    runs = [("fallback", lc._fallback_triage)]
    if lc.available():
        runs.append(("LLM:" + config.LLM.get("model", "?"), lc.triage))

    print(f"{'метрика':36}" + "".join(f"{n:>16}" for n, _ in runs))
    metrics = {n: _run(fn, incidents) for n, fn in runs}
    rows_out = [
        ("recall на аномалиях (TP→TP)", lambda m: _pct(m["tp_caught"], m["tp_total"])),
        ("точность на benign (→ не TP)", lambda m: _pct(m["bn_correct"], m["bn_total"])),
        ("benign-двойники (.env.example)", lambda m: _pct(m["bn_double_correct"], m["bn_double_total"])),
        ("severity не занижен", lambda m: _pct(m["sev_ok"], m["sev_total"])),
    ]
    for label, f in rows_out:
        print(f"{label:36}" + "".join(f"{f(metrics[n]):>16}" for n, _ in runs))
    print("=" * 68)
    if not lc.available():
        print("Подними Ollama (setup_llm.bat) и повтори — появится колонка LLM")
        print("для сравнения «LLM vs фолбэк».")


if __name__ == "__main__":
    main()
