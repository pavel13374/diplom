# -*- coding: utf-8 -*-
"""
IOC-экстрактор: из инцидента вытаскивает индикаторы компрометации в структуру,
пригодную для IR-отчёта и для карточки инцидента в консоли.

«Ощущение STIX/IOC»: индикаторы сгруппированы по типам (учётка, репозиторий,
путь к файлу, ветка, действие, ATT&CK-техника/тактика, временное окно). Всё —
из наблюдаемых blue-данных (анти-лик), без меток мира.
"""

TYPE_LABEL = {
    "account":   "Учётная запись",
    "repository": "Репозиторий",
    "file_path": "Путь к файлу",
    "branch":    "Ветка",
    "action":    "Действие",
    "technique": "ATT&CK техника",
    "tactic":    "ATT&CK тактика",
    "time":      "Временное окно",
}


def from_incident(inc: dict) -> dict:
    alerts = inc.get("alerts", []) or []
    paths = sorted({a.get("path") for a in alerts if a.get("path")})
    actions = sorted({a.get("action") for a in alerts if a.get("action")})
    branches = sorted({p for p in paths if "/" in (p or "") and (p.split("/")[0] in ("feature", "chore", "hotfix", "review"))})
    return {
        "account":   [inc.get("actor")] if inc.get("actor") else [],
        "repository": list(inc.get("repos", []) or []),
        "file_path": paths,
        "branch":    branches,
        "action":    actions,
        "technique": list(inc.get("techniques", []) or []),
        "tactic":    list(inc.get("tactics", []) or []),
        "time":      [f"{inc.get('start_ts')} → {inc.get('last_ts')}"] if inc.get("start_ts") else [],
    }


def flat(iocs: dict) -> list:
    """Плоский список {type,label,value} для таблиц/JSON."""
    out = []
    for t, vals in iocs.items():
        for v in vals:
            if v:
                out.append({"type": t, "label": TYPE_LABEL.get(t, t), "value": v})
    return out


def count(iocs: dict) -> int:
    return sum(len([v for v in vals if v]) for vals in iocs.values())


def table_md(iocs: dict) -> str:
    rows = ["| Тип индикатора | Значение |", "|---|---|"]
    for item in flat(iocs):
        rows.append(f"| {item['label']} | `{item['value']}` |")
    if len(rows) == 2:
        rows.append("| — | _нет индикаторов_ |")
    return "\n".join(rows)
