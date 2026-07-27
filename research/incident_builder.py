"""
Мост «детектор → инцидент» для LLM-триажа.

Из событий эпизода (или произвольного окна) собирает контекст инцидента в виде
словаря, который понимает llm_client.triage(): актор, события, агрегаты контента,
наблюдаемые поведенческие сигналы и эвристический risk_score.

АНТИ-ЛИК (критично): в incident НЕ кладём метки разметки —
is_anomaly / anomaly_type / _anomaly_type / family / severity / is_decisive /
secret_type / detail. LLM должна объяснять по НАБЛЮДАЕМЫМ сигналам, а не
пересказывать готовый ответ. Здесь же мы фильтруем эти поля явным белым списком.

risk_score — пока эвристика по наблюдаемым сигналам (заглушка до полноценного
UEBA-движка). Когда появится детектор, он подставит свой score сюда же.
"""

# --- скрипт живёт в подпапке; движок проекта — в корне ---
import os as _os, sys as _sys
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
for _p in (_ROOT, _os.path.join(_ROOT, "tools"), _os.path.join(_ROOT, "research")):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
_os.chdir(_ROOT)
del _os, _sys
import json

# Поля события, которые РАЗРЕШЕНО показывать (наблюдаемые аналитиком/сканером).
OBSERVABLE_EVENT_FIELDS = [
    "ts_sim", "hour", "is_night", "is_weekend", "actor", "role", "action",
    "project", "branch", "path", "mr_iid", "message",
    "shannon_entropy", "has_high_entropy_token", "regex_hits", "n_regex_hits",
    "filename_signal", "placeholder_signal", "actor_session",
]
# Поля, которые НИКОГДА не попадают в контекст (лик разметки).
LEAK_FIELDS = {"is_anomaly", "anomaly_type", "_anomaly_type", "family", "_family",
               "severity", "is_decisive", "_is_decisive", "secret_type",
               "anomaly_subtype", "detail", "executed", "repo", "grantee",
               "token_scope", "for_user", "quirk", "lookalike", "meta"}


def _clean_event(r):
    return {k: r.get(k) for k in OBSERVABLE_EVENT_FIELDS if r.get(k) is not None}


def _heuristic_risk(agg, signals):
    """Эвристический risk 0..1 по НАБЛЮДАЕМЫМ сигналам (заглушка до UEBA)."""
    s = 0.0
    hits = agg.get("regex_hits") or []
    ent = agg.get("max_shannon_entropy", 0) or 0
    placeholder = agg.get("any_placeholder", False)
    if hits and ent >= 4.0 and not placeholder:
        s += 0.5
    elif ent >= 4.0 and not placeholder:
        s += 0.2
    if agg.get("any_high_entropy") and not placeholder:
        s += 0.1
    if signals.get("touched_secrets_repo"):
        s += 0.2
    if agg.get("any_filename_signal") and not placeholder:
        s += 0.15
    if signals.get("off_hours"):
        s += 0.15
    if signals.get("weekend"):
        s += 0.1
    if signals.get("distinct_actions", 0) >= 4:
        s += 0.1
    if placeholder and not hits:
        s = min(s, 0.15)   # benign-двойник
    return round(min(1.0, s), 2)


def build_incident(rows, incident_id=None, detector_risk=None):
    """rows — список событий одного эпизода/окна. Возвращает incident-словарь
    БЕЗ полей разметки. detector_risk — если есть, перекрывает эвристику."""
    if not rows:
        return {}
    rows = sorted(rows, key=lambda r: (r.get("ts_sim") or "", r.get("seq") or 0))

    actors = {}
    repos = set()
    pushes = [r for r in rows if r.get("action") == "push"]
    ents = [r.get("shannon_entropy") for r in pushes if r.get("shannon_entropy") is not None]
    regex = []
    for r in pushes:
        regex += (r.get("regex_hits") or [])
    for r in rows:
        if r.get("actor"):
            actors[r["actor"]] = actors.get(r["actor"], 0) + 1
        if r.get("project"):
            repos.add(r["project"])

    agg = {
        "n_events": len(rows),
        "max_shannon_entropy": round(max(ents), 3) if ents else 0.0,
        "any_high_entropy": any(r.get("has_high_entropy_token") for r in pushes),
        "regex_hits": sorted(set(regex)),
        "n_regex_hits": len(set(regex)),
        "any_filename_signal": any(r.get("filename_signal") for r in pushes),
        "any_placeholder": any(r.get("placeholder_signal") for r in pushes),
    }
    signals = {
        "off_hours": any(r.get("is_night") for r in rows),
        "weekend": any(r.get("is_weekend") for r in rows),
        "touched_secrets_repo": any(r.get("project") == "soc-secrets" for r in rows),
        "distinct_actions": len({r.get("action") for r in rows}),
        "distinct_repos": len(repos),
        "actions_sequence": [r.get("action") for r in rows],
    }
    main_actor = max(actors, key=actors.get) if actors else None
    risk = float(detector_risk) if detector_risk is not None else _heuristic_risk(agg, signals)

    inc = {
        "incident_id": incident_id,
        "actor": main_actor,
        "repos": sorted(repos),
        "risk_score": risk,
        # плоские агрегаты — их же ждёт фолбэк-триаж
        "shannon_entropy": agg["max_shannon_entropy"],
        "regex_hits": agg["regex_hits"],
        "n_regex_hits": agg["n_regex_hits"],
        "placeholder_signal": agg["any_placeholder"],
        "filename_signal": agg["any_filename_signal"],
        "aggregates": agg,
        "signals": signals,
        "title": _title(main_actor, repos, signals, agg),
        "events": [_clean_event(r) for r in rows][:20],
    }
    # финальная страховка от лика
    for k in list(inc.keys()):
        if k in LEAK_FIELDS:
            inc.pop(k, None)
    return inc


def _title(actor, repos, signals, agg):
    repo = (sorted(repos)[0] if repos else "?")
    if signals.get("touched_secrets_repo"):
        return f"Активность в secrets-репозитории ({actor})"
    if agg.get("regex_hits") and not agg.get("any_placeholder"):
        return f"Подозрение на секрет в коммите ({actor} → {repo})"
    return f"Поведенческая аномалия активности ({actor} → {repo})"


def episodes_from_rows(rows):
    """Группирует события по episode_id (только аномальные эпизоды)."""
    eps = {}
    for r in rows:
        eid = r.get("episode_id")
        if eid:
            eps.setdefault(eid, []).append(r)
    return eps


def load_events(path):
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
