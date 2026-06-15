"""
Конфигурация SOC симулятора — «единый пульт».
Все настройки в одном месте.

Таймлапс сжимает время отдела (см. блок TIMELAPSE).
SCENARIO_INTERVAL — как часто запускаются сценарии.
WORK_HOURS_START/END — рабочие часы.
"""

# =======================================================================
#  ПОДКЛЮЧЕНИЕ К GITLAB
# =======================================================================
GITLAB_URL  = "https://gitlab.polenov.ru"
ADMIN_TOKEN = "glpat-mC78ra0fuJHR7aa2npn0D286MQp1OnoH.01.0w0ula1pu"

PROJECTS = {
    "detection-rules":     1,
    "normalization-rules": 2,
    "playbooks":           3,
    "ml-anomaly-engine":   4,
    "soc-infra":           5,
    "soc-secrets":         6,
}

USERS = {
    "alex.petrov":   {"id": 36, "name": "Alex Petrov",   "email": "alex.petrov@soc.local",   "role": "lead"},
    "maria.ivanova": {"id": 37, "name": "Maria Ivanova", "email": "maria.ivanova@soc.local", "role": "detection_engineer"},
    "dmitry.kozlov": {"id": 38, "name": "Dmitry Kozlov", "email": "dmitry.kozlov@soc.local", "role": "detection_engineer"},
    "anna.smirnova": {"id": 39, "name": "Anna Smirnova", "email": "anna.smirnova@soc.local", "role": "ml_engineer"},
    "soc-bot":       {"id": 40, "name": "SOC Bot",       "email": "soc-bot@soc.local",       "role": "bot"},
}


# =======================================================================
#  СКОРОСТЬ / ТАЙМИНГ
# =======================================================================
SPEED_MULTIPLIER = 1.0

BASE_DELAYS = {
    "between_commits":    12,
    "review_wait":        25,
    "merge_wait":         15,
    "between_activities": 45,
    "agent_think":         8,
    "revert_delay":       30,
    "incident_step":      18,
}
DELAYS = {k: v * SPEED_MULTIPLIER for k, v in BASE_DELAYS.items()}

SCENARIO_INTERVAL = {"min": 40, "max": 120}

LUNCH_BREAK = {"enabled": True, "hour": 13, "duration_min": 45}


# =======================================================================
#  РАБОЧИЕ ЧАСЫ
# =======================================================================
WORK_HOURS_START = 10
WORK_HOURS_END   = 18
WORK_DAYS        = [0, 1, 2, 3, 4]

OFF_HOURS_MODE = "oncall"   # "oncall" | "idle"
OFF_HOURS_ACTIVITY_PROBABILITY = 0.04
OFF_HOURS_ALLOWED_ACTIVITIES = [
    "fix_existing_rule", "revert_bad_rule", "handle_incident", "triage_false_positive",
]
OFF_HOURS_POLL_SECONDS = 300


# =======================================================================
#  ВЕРОЯТНОСТИ АКТИВНОСТЕЙ
# =======================================================================
ACTIVITY_WEIGHTS = {
    "new_detection_rule":     0.12,
    "fix_existing_rule":      0.10,
    "tune_threshold":         0.08,
    "refactor_rule":          0.06,
    "update_parser":          0.09,
    "update_playbook":        0.07,
    "add_test_sample":        0.05,
    "threat_intel_update":    0.06,
    "update_dashboard":       0.04,
    "triage_false_positive":  0.05,
    "revert_bad_rule":        0.05,
    "deprecate_rule":         0.05,
    "recreate_fixed_rule":    0.05,
    "handle_incident":        0.03,
    "bulk_maintenance":       0.02,
    "open_issue":             0.06,
    "campaign":               0.03,
    "ci_variable_update":     0.04,
    "dependency_bump":        0.04,
    "docs_wiki":              0.04,
    "benign_quirk":           0.06,
    # тематические сценарии для специализированных репозиториев
    "hunt_query":             0.09,
    "cloud_detection":        0.09,
    "siem_content":           0.08,
    "edr_rule":               0.08,
    "automation_script":      0.08,
    "ir_runbook":             0.07,
}


# =======================================================================
#  ПРОЧЕЕ
# =======================================================================
PROTECTED_BRANCHES = ["main", "master"]
MAX_OPEN_MRS = 30

LOG_LEVEL = "INFO"
LOG_FILE  = "simulator.log"

# =======================================================================
#  ВЕБ-АДМИНКА
# =======================================================================
WEB_HOST = "127.0.0.1"
WEB_PORT = 8787
WEB_ADMIN_USER = "admin"
WEB_ADMIN_PASS = "123"
WEB_SECRET     = "soc-sim-secret-change-me"

# Полный лог каждого прогона (DEBUG, со всеми ошибками) — папка logs/
RUN_LOG_DIR = "logs"

# =======================================================================
#  TELEGRAM-ОТЧЁТЫ
# =======================================================================
TELEGRAM = {
    "enabled":          True,
    "token":            "8717621147:AAGd2snyzC4TOfTDCXgyKXx8MimMA_nsmzM",
    "chat_id":          "465642891",
    "report_every_min": 60,     # периодический отчёт, РЕАЛЬНЫЕ минуты
    "send_start_stop":  True,    # сообщать о старте/остановке
    "send_anomalies":   True,    # алерт на каждую аномалию (с антифлудом)
    "anomaly_min_gap":  20,      # антифлуд алертов аномалий, сек
}


# =======================================================================
#  ТАЙМЛАПС  (сжатие времени: «сутки за час»)
# =======================================================================
TIMELAPSE_ENABLED = True
SIM_WORKDAY_REAL_MINUTES = 60     # реальных минут на один sim рабочий день
TIME_SCALE_OVERRIDE = None        # прямой масштаб (sim-сек/реал-сек); None=авто
SIM_START = None                  # None = сегодня 10:00; либо "2026-06-01 10:00"
FAST_FORWARD_OFFHOURS = True
API_MIN_PAUSE  = 0.4
MAX_REAL_SLEEP = 8.0

# Источник дат, которые ПИШУТСЯ в GitLab (rule date/modified, issue created_at):
#   "real" — реальное время сервера (всё согласовано с таймстампами коммитов; безопасно)
#   "sim"  — симулированное время (нарратив; created_at учитывается только admin-токеном
#            и не для будущих дат, поэтому может игнорироваться)
GITLAB_DATES = "real"


def compute_time_scale() -> float:
    if not TIMELAPSE_ENABLED:
        return 1.0
    if TIME_SCALE_OVERRIDE:
        return float(TIME_SCALE_OVERRIDE)
    work_seconds = max(1, (WORK_HOURS_END - WORK_HOURS_START)) * 3600
    real_seconds = max(60, SIM_WORKDAY_REAL_MINUTES * 60)
    return work_seconds / real_seconds


# =======================================================================
#  ФИЧИ РЕАЛИЗМА
# =======================================================================
FEATURES = {
    "issues":               True,
    "ci_pipeline":          True,
    "draft_mrs":            True,
    "emoji_reactions":      True,
    "approvals":            True,
    "releases":             True,
    "peer_review":          True,
    "campaigns":            True,
    "standup":              True,
    "pto":                  True,
    "change_freeze_friday": True,
    "lifecycle_state":      True,
}

PROBS = {
    "ci_fail":        0.20,
    "mr_abandoned":   0.06,
    "mr_draft_first": 0.30,
    "delayed_revert": 0.12,
    "peer_review":    0.35,
    "emoji":          0.50,
    "promote":        0.30,
}

SPRINT_DAYS = 14
ONCALL_ROTATION = ["maria.ivanova", "dmitry.kozlov", "anna.smirnova"]
PTO_PROBABILITY_PER_DAY = 0.05

STATE_FILE = ".sim_state.json"

# =======================================================================
#  ЧЛЕНСТВО / РЕПОЗИТОРИИ
# =======================================================================
GRANT_OWNER = True            # на первом старте выдать инженерам права Owner
OWNER_ACCESS_LEVEL = 50       # 50=Owner, 40=Maintainer (фолбэк автоматический)
AUTO_DISCOVER_PROJECTS = True # подхватить существующие репозитории namespace
PROJECT_NAMESPACE = "soc-team"
# Кому выдаём Owner и кто считается «рабочим составом» репозиториев
TEAM_USERS = ["alex.petrov", "maria.ivanova", "dmitry.kozlov", "anna.smirnova"]
# Рабочий пул репозиториев (расширяется автодискавери на старте). name -> id
WORK_REPOS = dict(PROJECTS)

# Создавать НОВЫХ сотрудников и репозитории на первом старте (идемпотентно).
CREATE_USERS = True
CREATE_REPOS = True

# Новые сотрудники (заводятся в GitLab, если их ещё нет). Команда станет больше.
NEW_USERS = [
    {"username": "sergey.volkov",  "name": "Sergey Volkov",  "role": "detection_engineer"},
    {"username": "olga.novak",     "name": "Olga Novak",     "role": "threat_hunter"},
    {"username": "pavel.morozov",  "name": "Pavel Morozov",  "role": "detection_engineer"},
    {"username": "irina.belova",   "name": "Irina Belova",   "role": "soc_analyst"},
    {"username": "nikita.orlov",   "name": "Nikita Orlov",   "role": "devops"},
    {"username": "elena.kuzmina",  "name": "Elena Kuzmina",  "role": "ml_engineer"},
]

# Новые репозитории (создаются в группе PROJECT_NAMESPACE, если их нет).
NEW_REPOS = ["threat-hunting", "cloud-detections", "siem-content",
             "edr-integration", "soc-automation", "incident-response"]

# Где какая работа ведётся (распределение, чтобы не всё в detection-rules).
RULE_REPOS    = ["detection-rules", "threat-hunting", "cloud-detections",
                 "edr-integration", "siem-content"]
PARSER_REPOS  = ["normalization-rules", "siem-content"]
PLAYBOOK_REPOS = ["playbooks", "incident-response"]

# =======================================================================
#  ЖУРНАЛ СОБЫТИЙ (датасет для будущего ML)
# =======================================================================
EVENT_LOG = {
    "enabled": True,
    "file":    "data/events.jsonl",   # каждое действие — строкой JSON
}

# =======================================================================
#  АНОМАЛИИ (редкие размеченные инциденты для обучения детектора)
# =======================================================================
# Доля итераций, которые становятся аномалией вместо обычного действия.
ANOMALY_RATE          = 0.05   # в рабочее время
ANOMALY_RATE_OFFHOURS = 0.30   # ночью/в выходные доля выше (тревожный сигнал)

# Типы аномалий и их относительные веса. Секреты держим РЕДКИМИ.
# ВАЖНО (для диплома): self_approval_merge / merge_without_review — это «правило, а не
# ML» (сигнал = approver==author / нет approve). Раньше они доминировали в позитивном
# классе и модель училась бы одному булеву полю. Веса перебалансированы: тривиальные
# срезаны, «тонкие» (secret_*, exfil, pipeline) подняты. Тривиальные ловит rule_baseline.py.
ANOMALIES = {
    # --- утечки секретов («тонкие» — основной интерес для ML) ---
    "secret_in_commit":      {"enabled": True, "weight": 1.0},
    "secret_in_ci":          {"enabled": True, "weight": 0.9},
    "secret_in_mr_comment":  {"enabled": True, "weight": 0.6},
    "secret_exfil_vault":    {"enabled": True, "weight": 0.8},
    "hardcoded_token":       {"enabled": True, "weight": 0.9},
    # --- права и доступы (тривиальные — срезаны, их берёт rule-based baseline) ---
    "self_approval_merge":   {"enabled": True, "weight": 0.4},
    "merge_without_review":  {"enabled": True, "weight": 0.4},
    "direct_push_protected": {"enabled": True, "weight": 0.6},
    "weaken_protection":     {"enabled": True, "weight": 0.6},
    "grant_secret_access":   {"enabled": True, "weight": 0.8},
    "rogue_token":           {"enabled": True, "weight": 0.7},
    # --- разрушительные действия ---
    "mass_deletion":         {"enabled": True, "weight": 0.6},
    # --- пайплайны / токены / эксфильтрация («тонкие» — подняты) ---
    "pipeline_token_leak":       {"enabled": True, "weight": 1.0},
    "disable_pipeline_security": {"enabled": True, "weight": 0.9},
    "artifact_secret_exposure":  {"enabled": True, "weight": 0.9},
    "commit_to_secrets_repo":    {"enabled": True, "weight": 0.9},
    "data_exfiltration":         {"enabled": True, "weight": 1.0},
}
# Множитель частоты именно секретных утечек (чтобы делать их ещё реже).
SECRET_RATE_MULT = 0.5


def scenario_pause_seconds():
    import random
    base = random.uniform(SCENARIO_INTERVAL["min"], SCENARIO_INTERVAL["max"])
    return base * SPEED_MULTIPLIER


def set_discovered(d):
    """Добавляет найденные репозитории в рабочий пул."""
    WORK_REPOS.update(d or {})

def _present(names):
    return [n for n in names if n in WORK_REPOS]

def populated_rule_repo(gl):
    """Репозиторий c правилами (для активностей, правящих существующее).
    Если нигде нет — detection-rules."""
    import random
    names = _present(RULE_REPOS)
    random.shuffle(names)
    for n in names:
        try:
            if gl.list_files(WORK_REPOS[n], "rules"):
                return WORK_REPOS[n]
        except Exception:
            pass
    return PROJECTS["detection-rules"]

def rule_repo_id():
    import random
    names = _present(RULE_REPOS) or ["detection-rules"]
    return WORK_REPOS.get(random.choice(names), PROJECTS["detection-rules"])

def parser_repo_id():
    import random
    names = _present(PARSER_REPOS) or ["normalization-rules"]
    return WORK_REPOS.get(random.choice(names), PROJECTS["normalization-rules"])

def playbook_repo_id():
    import random
    names = _present(PLAYBOOK_REPOS) or ["playbooks"]
    return WORK_REPOS.get(random.choice(names), PROJECTS["playbooks"])

def add_user(username, uid, name=None, role="detection_engineer", email=None):
    USERS[username] = {"id": uid, "name": name or username,
                       "email": email or username + "@soc.local", "role": role}

def lead_username():
    for u, i in USERS.items():
        if i.get("role") == "lead":
            return u
    return "alex.petrov"

def lead_id():
    return USERS.get(lead_username(), {}).get("id", USERS["alex.petrov"]["id"])

def engineer_usernames():
    roles = ("detection_engineer", "threat_hunter", "soc_analyst", "ml_engineer", "devops")
    return [u for u, i in USERS.items() if i.get("role") in roles]

def random_work_repo():
    import random
    name = random.choice(list(WORK_REPOS))
    return name, WORK_REPOS[name]

def repo_name(pid):
    for n, i in WORK_REPOS.items():
        if i == pid:
            return n
    return str(pid)


# =======================================================================
#  ПЕРСИСТЕНТНЫЕ ПРАВКИ ИЗ ВЕБ-АДМИНКИ (web_config.json)
# =======================================================================
import os as _os
import json as _json

WEB_CONFIG_FILE = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "web_config.json")

EDITABLE_SCALARS = [
    "GITLAB_URL", "ADMIN_TOKEN",
    "TIMELAPSE_ENABLED", "SIM_WORKDAY_REAL_MINUTES", "TIME_SCALE_OVERRIDE",
    "SIM_START", "FAST_FORWARD_OFFHOURS", "API_MIN_PAUSE", "MAX_REAL_SLEEP",
    "WORK_HOURS_START", "WORK_HOURS_END",
    "OFF_HOURS_MODE", "OFF_HOURS_ACTIVITY_PROBABILITY", "OFF_HOURS_POLL_SECONDS",
    "SPEED_MULTIPLIER", "MAX_OPEN_MRS", "SPRINT_DAYS", "PTO_PROBABILITY_PER_DAY",
    "LOG_LEVEL", "GITLAB_DATES", "ANOMALY_RATE", "ANOMALY_RATE_OFFHOURS", "SECRET_RATE_MULT",
]
EDITABLE_DICTS = ["SCENARIO_INTERVAL", "FEATURES", "PROBS", "ACTIVITY_WEIGHTS", "LUNCH_BREAK", "ANOMALIES", "EVENT_LOG"]


def export_settings() -> dict:
    g = globals()
    out = {k: g.get(k) for k in EDITABLE_SCALARS}
    for k in EDITABLE_DICTS:
        v = g.get(k)
        out[k] = dict(v) if isinstance(v, dict) else v
    out["WORK_DAYS"] = list(WORK_DAYS)
    return out


def apply_settings(updates: dict):
    g = globals()
    for k, v in (updates or {}).items():
        if k in EDITABLE_SCALARS:
            g[k] = v
        elif k in EDITABLE_DICTS and isinstance(g.get(k), dict) and isinstance(v, dict):
            g[k].clear(); g[k].update(v)
        elif k == "WORK_DAYS" and isinstance(v, list):
            g["WORK_DAYS"][:] = v


def save_settings():
    try:
        with open(WEB_CONFIG_FILE, "w", encoding="utf-8") as f:
            _json.dump(export_settings(), f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False


def _load_web_config():
    if _os.path.exists(WEB_CONFIG_FILE):
        try:
            with open(WEB_CONFIG_FILE, encoding="utf-8") as f:
                apply_settings(_json.load(f))
        except Exception:
            pass


_load_web_config()
