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
    # Поведенческий слой и модель НЕ ИМЕЮТ техники ATT&CK: в поле technique у
    # них стоят служебные значения UEBA и ML. Раньше они выводились здесь под
    # подписью «ATT&CK техника» — то есть карточка инцидента утверждала, что
    # UEBA есть техника из матрицы MITRE. Коррелятор их из kill-chain как раз
    # исключает, и экран сам себе противоречил: цепочка пустая, а «техника»
    # показана.
    "layer":     "Сработавший слой (не ATT&CK)",
    "time":      "Временное окно",
}

#: Служебные значения technique/tactic у слоёв без техники ATT&CK.
#: Тот же набор, что correlator._LAYER_SENTINELS.
LAYER_SENTINELS = ("ML", "UEBA")
LAYER_TACTICS = ("Behavioral",)

#: Человеческие названия слоёв — «UEBA» аналитику ни о чём не говорит.
LAYER_LABEL = {"UEBA": "UEBA — поведенческое отклонение от профиля актора",
               "ML": "ML — оценка обученной модели"}


def from_incident(inc: dict) -> dict:
    alerts = inc.get("alerts", []) or []
    paths = sorted({a.get("path") for a in alerts if a.get("path")})
    actions = sorted({a.get("action") for a in alerts if a.get("action")})
    # ВЕТКА БЕРЁТСЯ ИЗ ПОЛЯ branch, А НЕ УГАДЫВАЕТСЯ ПО ПУТИ.
    # Раньше «веткой» объявлялся ЛЮБОЙ путь к файлу, первый сегмент которого
    # совпал с feature/chore/hotfix/review: то есть индикатор «ветка» показывал
    # имя файла, а настоящее имя ветки, лежащее в алерте рядом, не показывал
    # никогда.
    branches = sorted({a.get("branch") for a in alerts
                       if a.get("branch") and a.get("branch") != "none"})
    techs = [t for t in (inc.get("techniques") or []) if t not in LAYER_SENTINELS]
    tactics = [t for t in (inc.get("tactics") or []) if t not in LAYER_TACTICS]
    layers = [LAYER_LABEL.get(t, t) for t in (inc.get("techniques") or [])
              if t in LAYER_SENTINELS]
    return {
        "account":   [inc.get("actor")] if inc.get("actor") else [],
        "repository": list(inc.get("repos", []) or []),
        "file_path": paths,
        "branch":    branches,
        "action":    actions,
        "technique": techs,
        "tactic":    tactics,
        "layer":     layers,
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
