# -*- coding: utf-8 -*-
"""
ПЕРСОНЫ АТАКУЮЩИХ (threat model: КТО и ЗАЧЕМ, а не безликая «аномалия»).

Каждая персона задаёт мотив, предпочитаемые ATT&CK-кампании, профиль уклонения,
время суток и «dwell time» (на сколько sim-дней растягивается атака). Это делает
противника правдоподобным: одно и то же действие от разных персон выглядит и
тянется по-разному, как в реальной модели угроз.

ВАЖНО (анти-лик): персона/мотив — это «правда мира». Они кладутся в разметку
события и СРЕЗАЮТСЯ перед детектором (см. run_defense.LEAK). Защита их не видит.
"""
import random

# kind -> профиль
PERSONAS = {
    "disgruntled_insider": {
        "title": "Обиженный инсайдер (увольняется)",
        "motive": "месть и вынос данных перед уходом",
        "campaigns": ["insider_secret_theft", "review_bypass_sabotage"],
        "evasion": ["noisy", "adaptive"],
        "time": "late",          # под конец дня / вечер: спешит, пока есть доступ
        "dwell_days": (0, 1),    # действует быстро
        "roles": ["detection_engineer", "ml_engineer"],
        "is_attack": True,
    },
    "compromised_account": {
        "title": "Скомпрометированный аккаунт",
        "motive": "захваченная учётка действует нетипично для владельца",
        "campaigns": ["ci_token_to_exfil"],
        "evasion": ["stealthy"],
        "time": "offhours",      # ночью/в выходные — не как обычно этот юзер
        "dwell_days": (0, 2),
        "roles": ["detection_engineer", "ml_engineer", "lead"],
        "is_attack": True,
    },
    "external_via_token": {
        "title": "Внешний злоумышленник через утёкший токен (APT)",
        "motive": "recon → доступ → эксфильтрация, low-and-slow",
        "campaigns": ["supply_chain_recon"],
        "evasion": ["stealthy", "adaptive"],
        "time": "offhours",
        "dwell_days": (3, 9),    # сидит неделями (реалистичный dwell time)
        "roles": ["detection_engineer", "ml_engineer"],
        "is_attack": True,
    },
    "careless_dev": {
        "title": "Небрежный разработчик (случайная утечка)",
        "motive": "НЕ атака: случайно закоммитил реальный секрет",
        "campaigns": [],                 # одиночная аномалия, не кампания
        "single_anomaly": "secret_in_commit",
        "evasion": ["noisy"],            # не прячет — он не злоумышленник
        "time": "work",
        "dwell_days": (0, 0),
        "roles": ["detection_engineer", "ml_engineer"],
        "is_attack": False,
    },
}

# базовые веса; ночью смещаем к compromised/external, днём — к insider/careless
_BASE_W = {"disgruntled_insider": 0.30, "compromised_account": 0.30,
           "external_via_token": 0.20, "careless_dev": 0.20}


def pick_kind(offhours=False):
    w = dict(_BASE_W)
    if offhours:
        w["compromised_account"] *= 2.0
        w["external_via_token"] *= 2.2
        w["careless_dev"] *= 0.3
        w["disgruntled_insider"] *= 0.7
    kinds = list(w); weights = [w[k] for k in kinds]
    return random.choices(kinds, weights=weights, k=1)[0]


def _pick_actor(agents, profile):
    """Выбрать актора подходящей роли (бота не трогаем)."""
    want = set(profile.get("roles", []))
    pool = []
    for username, ag in agents.items():
        role = getattr(ag, "role", None)
        if role == "bot":
            continue
        if not want or role in want:
            pool.append(username)
    if not pool:
        pool = [u for u, ag in agents.items() if getattr(ag, "role", None) != "bot"] or list(agents)
    return random.choice(pool) if pool else None


def assign(agents, offhours=False, kind=None):
    """Вернуть назначение атаки: какая персона, кто актор, какая кампания/одиночная
    аномалия, профиль уклонения и dwell_days."""
    kind = kind or pick_kind(offhours=offhours)
    p = PERSONAS[kind]
    return {
        "kind": kind,
        "title": p["title"],
        "motive": p["motive"],
        "actor": _pick_actor(agents, p),
        "campaign": random.choice(p["campaigns"]) if p["campaigns"] else None,
        "single_anomaly": p.get("single_anomaly"),
        "evasion": random.choice(p["evasion"]),
        "dwell_days": random.randint(*p["dwell_days"]),
        "is_attack": p["is_attack"],
    }


def list_personas():
    return [{"kind": k, "title": v["title"], "motive": v["motive"],
             "is_attack": v["is_attack"]} for k, v in PERSONAS.items()]
