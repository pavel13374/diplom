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

# Токен НЕ хардкодится (config.py под git!). Порядок:
#   1) переменная окружения GITLAB_ADMIN_TOKEN;
#   2) файл .gitlab_token рядом с config.py (в .gitignore).
import os as _os_tok


def _load_admin_token():
    t = _os_tok.environ.get("GITLAB_ADMIN_TOKEN", "").strip()
    if t:
        return t
    p = _os_tok.path.join(_os_tok.path.dirname(_os_tok.path.abspath(__file__)),
                          ".gitlab_token")
    try:
        with open(p, encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return ""


ADMIN_TOKEN = _load_admin_token()

# Offline/dry-run: мир пишет события БЕЗ реального GitLab. Авто-включается, если
# GitLab недоступен (чтобы не висеть на таймаутах и не «молчать»).
import os as _os0
OFFLINE_MODE = _os0.environ.get("SOC_OFFLINE", "").lower() in ("1", "true", "yes")

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
# Глобальный seed для воспроизводимости ML/оценки (НЕ для самого симулятора —
# его специально оставляем варьирующимся, чтобы данные были разнообразны).
SEED = 42

def seed_all(seed=None):
    """Сеет random и numpy (если есть). Зови в ML/eval-скриптах перед обучением."""
    import random as _r
    s = SEED if seed is None else seed
    _r.seed(s)
    try:
        import numpy as _np
        _np.random.seed(s)
    except Exception:
        pass
    return s


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
NIGHT_NOISE_PROB = 0.12   # доля ночных тиков с ЛЕГИТИМНОЙ активностью (кранч/дежурный) — честные FP


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
    # новые ТИПЫ рабочих процессов
    "iterative_review":       0.06,
    "dependency_audit":       0.05,
    "sprint_retro":           0.03,
    # ШТАТНАЯ АДМИНИСТРАТИВНАЯ РАБОТА (activities/ops_admin.py).
    # Эти действия обязаны быть у нормальной команды: без них token_create,
    # deploy_key_add, hook_create, schedule_create, pipeline_run,
    # member_update, force_push и api_read встречались бы ТОЛЬКО у атакующего,
    # и имя действия работало бы меткой вместо признака (см. taxonomy.py).
    "api_browsing":           0.10,
    "pipeline_run":           0.06,
    "token_rotation":         0.04,
    "branch_cleanup":         0.04,
    "rebase_force_push":      0.03,
    "nightly_schedule":       0.02,
    "webhook_setup":          0.02,
    "deploy_key_rotation":    0.02,
    "membership_change":      0.02,
    "production_deploy":      0.02,
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
PURPLE_WEB_PORT = 8788   # Purple Team Console (контур «защита»)

# =======================================================================
#  BLUE DETECTION STACK (контур защиты)
# =======================================================================
DETECTIONS_DIR = "detections"     # папка с правилами Detection-as-Code (*.json)
LOAD_PROPOSED  = False            # подхватывать ли detections/proposed/ (после ревью)

# --- L1: вероятностный UEBA (detector.UEBA) ---
# Скор события — суммарная НЕОЖИДАННОСТЬ в битах (surprisal), а не сумма
# зашитых весов. Поэтому здесь нет «порога риска»: порог берётся как квантиль
# наблюдаемого распределения под заданный БЮДЖЕТ ТРЕВОГ.
UEBA_MIN_EVENTS = 30              # событий в профиле актора до начала скоринга
# Бюджет тревог поведенческого слоя. 0.4% от 12 тысяч событий прогона — это
# полсотни алертов, что для одного слоя уже перебор. 0.1% даёт около десятка:
# столько аналитик реально разбирает, и столько же стоит показывать.
UEBA_ALERT_BUDGET = 0.001
UEBA_MIN_CALIB = 400              # наблюдений до калибровки; до неё слой МОЛЧИТ
UEBA_SCALE_BITS = 6.0             # +6 бит сверх порога -> риск 0.5
UEBA_VELOCITY_WINDOW_MIN = 30     # окно для оценки интенсивности актора (sim-мин)

# --- L2: ML (detector.MLScorer) ---
ML_ENABLED = True                 # выключить -> система работает на L0+L1
# Потолок риска для ОДИНОЧНОЙ сработки модели. Держим ниже порога
# «действенного» инцидента (0.6): модель сама по себе очередь не наполняет —
# она поднимает приоритет, когда СОГЛАСНА с правилом или с поведенческим
# слоем, и тогда слияние лог-шансов выводит риск за порог. Это и есть
# эшелонированная защита: слой добавляет уверенности, а не тревог.
ML_RISK_CAP = 0.55

# --- слияние рисков ---
# logodds: сумма лог-шансов с затуханием γ^i. Поправка на то, что слои НЕ
# независимы: правило, UEBA и ML смотрят на одно событие и срабатывают по
# коррелирующим причинам, а noisy_or при зависимых источниках систематически
# завышает риск (два сигнала по 0.6 давали 0.84).
FUSION_MODE = "logodds"           # logodds | noisy_or | max
FUSION_DECAY = 0.5                # вес i-го по величине сигнала = FUSION_DECAY^i

# --- корреляция и шум ---
CORRELATION_WINDOW_MIN = 180      # окно склейки алертов в инцидент (sim-мин)
ALERT_SUPPRESS_MIN = 60           # окно подавления дублей (actor+rule) против alert fatigue

import os as _os, secrets as _secrets
WEB_ADMIN_USER = _os.environ.get("SOC_ADMIN_USER", "admin")
# Пароль: из переменной окружения SOC_ADMIN_PASS; иначе — случайный на запуск
# (печатается в консоль). Для демо можно оставить дефолт SOC_ADMIN_PASS=admin.
WEB_ADMIN_PASS = _os.environ.get("SOC_ADMIN_PASS") or _secrets.token_urlsafe(9)
_WEB_PASS_GENERATED = "SOC_ADMIN_PASS" not in _os.environ
# Секрет сессии: из окружения или файла .secret_key (не в git), иначе генерим
def _load_secret():
    env = _os.environ.get("SOC_WEB_SECRET")
    if env:
        return env
    p = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), ".secret_key")
    try:
        if _os.path.exists(p):
            return open(p).read().strip()
        s = _secrets.token_hex(32)
        open(p, "w").write(s)
        return s
    except Exception:
        return _secrets.token_hex(32)
WEB_SECRET = _load_secret()

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
#  ЛОКАЛЬНАЯ LLM (Ollama) — слой объяснимого триажа инцидентов
# =======================================================================
# Установка: запусти setup_llm.bat (поставит Ollama и скачает модель).
# Если LLM недоступна — система работает на правилах/ML, триаж даёт фолбэк.
LLM = {
    "enabled": True,
    "host":    "http://localhost:11434",   # локальный Ollama
    "model":   "qwen2.5:7b-instruct",      # под 16+ ГБ RAM / GPU; послабее ПК: qwen2.5:3b-instruct
    "timeout": 60,
}

# Авто-триаж инцидентов: LLM сам разбирает каждую кампанию (без кнопки)
LLM_AUTO_TRIAGE = True
LLM_AUTO_TRIAGE_MIN_RISK = 0.6
LLM_CHATTER = True            # живые реплики стендапов/ревью через LLM (фолбэк — банки фраз)


# =======================================================================
#  ТАЙМЛАПС  (сжатие времени: «сутки за час»)
# =======================================================================
TIMELAPSE_ENABLED = False   # по умолчанию ВЫКЛ — время идёт 1:1 с реальным (не «бежит само»)
SIM_WORKDAY_REAL_MINUTES = 60     # реальных минут на один sim рабочий день
TIME_SCALE_OVERRIDE = None        # прямой масштаб (sim-сек/реал-сек); None=авто
SIM_START = None                  # None = сегодня 10:00; либо "2026-06-01 10:00"
FAST_FORWARD_OFFHOURS = False   # НЕ проматывать ночь — время идёт ровно 1:1 с реальным
API_MIN_PAUSE  = 0.4
MAX_REAL_SLEEP = 8.0

# Источник дат, которые ПИШУТСЯ в GitLab (rule date/modified, issue created_at):
#   "real" — реальное время сервера (всё согласовано с таймстампами коммитов; безопасно)
#   "sim"  — симулированное время (нарратив; created_at учитывается только admin-токеном
#            и не для будущих дат, поэтому может игнорироваться)
GITLAB_DATES = "real"


def default_sim_start():
    """Ближайший БУДНИЙ день 10:00 — чтобы старт симуляции не «прыгал» вечером/в выходные."""
    from datetime import datetime, timedelta
    now = datetime.now()
    d = now.replace(hour=WORK_HOURS_START, minute=0, second=0, microsecond=0)
    if now.weekday() not in WORK_DAYS or now.hour >= WORK_HOURS_END:
        d = d + timedelta(days=1)
        while d.weekday() not in WORK_DAYS:
            d = d + timedelta(days=1)
    return d


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

# Event-store (SQLite) — backbone между «миром» и «защитой» (стрим по курсору).
EVENT_STORE = {
    "enabled": True,
    "path":    "data/events.db",
}

# =======================================================================
#  АНОМАЛИИ (редкие размеченные инциденты для обучения детектора)
# =======================================================================
# Доля итераций, которые становятся аномалией вместо обычного действия.
ANOMALY_RATE          = 0.10   # в рабочее время (редко — чтобы было видно каждую атаку)
ANOMALY_RATE_OFFHOURS = 0.18   # ночью чуть выше, но не «паровоз»
# Доля аномалий, которые разворачиваются в МНОГОШАГОВУЮ кампанию (Red Team).
CAMPAIGN_RATE = 0.20
ATTACK_AUTO = False           # False = атаки ТОЛЬКО вручную (Red Launcher). True = редкие авто-атаки

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
    "self_approval_merge":   {"enabled": True, "weight": 0.25},  # process: мягкий сигнал, ловится правилами
    "merge_without_review":  {"enabled": True, "weight": 0.25},  # process: пересекается с нормой (~28%)
    "direct_push_protected": {"enabled": True, "weight": 0.6},
    "weaken_protection":     {"enabled": True, "weight": 0.6},
    "grant_secret_access":   {"enabled": True, "weight": 0.8},
    "rogue_token":           {"enabled": True, "weight": 0.7},
    # --- разрушительные действия ---
    "mass_deletion":         {"enabled": True, "weight": 0.6},
    # --- разведка ---
    "recon_enumeration":     {"enabled": True, "weight": 0.4},
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
    """Имя репозитория по id. Ищем во ВСЕХ известных словарях: раньше
    смотрели только в WORK_REPOS, и для остальных репо в ленте детектов
    вместо названия показывался голый id («6»)."""
    for src in (WORK_REPOS, PROJECTS):
        for n, i in (src or {}).items():
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
            # МЕРЖ, а не замена: сохранённые из веба значения накладываются поверх,
            # но НОВЫЕ ключи из кода (новые активности/аномалии/фичи) не теряются.
            g[k].update(v)
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
