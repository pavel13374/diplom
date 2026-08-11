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
    # ml-anomaly-engine числился в PROJECTS и в онбординге, но НИ ОДНА
    # активность в него не писала: 1.3% событий против 14% у соседей.
    "ml_engine_work":         0.08,
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
    # РАСШИРЕННАЯ РУТИНА КОМАНДЫ (activities/team_routine.py).
    # Хвост распределения был пуст: на push приходилась четверть всех
    # событий. Живая команда ставит теги, ведёт ревью, чинит сборки,
    # правит вики и состав участников — и делает это постоянно.
    "review_cycle":           0.09,
    "pipeline_care":          0.07,
    "backlog_grooming":       0.06,
    "docs_upkeep":            0.05,
    "hotfix_port":            0.04,
    "cross_repo_sweep":       0.04,
    "access_upkeep":          0.03,
    "security_hygiene":       0.03,
    "release_tagging":        0.03,
    "experiment_fork":        0.02,
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
# Строгий режим словаря действий: events.emit() бросает исключение на действие
# вне taxonomy.ALL, а не только пишет в лог. Включать в тестах и CI — так
# «говорящее» имя действия (steal_oauth, mass_delete) физически не сможет
# попасть в журнал и стать меткой.
TAXONOMY_STRICT = False

DETECTIONS_DIR = "detections"     # папка с правилами Detection-as-Code (*.json)
LOAD_PROPOSED  = False            # подхватывать ли detections/proposed/ (после ревью)

# --- L1: вероятностный UEBA (detector.UEBA) ---
# Скор события — суммарная НЕОЖИДАННОСТЬ в битах (surprisal), а не сумма
# зашитых весов. Поэтому здесь нет «порога риска»: порог берётся как квантиль
# наблюдаемого распределения под заданный БЮДЖЕТ ТРЕВОГ.
UEBA_MIN_EVENTS = 30              # событий в профиле актора до начала скоринга
# БЮДЖЕТ ТРЕВОГ поведенческого слоя — доля событий, доходящая до очереди.
#
# Величина подобрана ЗАМЕРОМ, а не на глаз (tools/ueba_components.py,
# 20 329 событий, 228 эпизодов, компоненты repo+hour):
#
#   бюджет  сработок  на атаке  точность  эпизодов  из них ТОЛЬКО этим слоем
#    0.001         5         3     60.0%     3/228                        0
#    0.004        29         7     24.1%     5/228                        0
#    0.01        112        16     14.3%    14/228                        2
#    0.03        234        40     17.1%    32/228                        8
#    0.05        416        48     11.5%    35/228                        9
#
# При 0.001 слой практически МОЛЧИТ: пять срабатываний на двадцать тысяч
# событий. Точность при этом отличная (60% против базовой частоты 3% — выигрыш
# в 20 раз), но на полноту он не влияет никак, и в ablation вклад слоя
# статистически неотличим от нуля. Слой, который не меняет решение, не нужен.
#
# 0.01 — примерно 2 алерта в симулированный день от одного слоя: столько
# аналитик разбирает не глядя, а два эпизода слой находит САМ, без правил.
UEBA_ALERT_BUDGET = 0.001   # доля событий, доходящих до аналитика (0.1%)
# Рабочая точка выбрана по измеренной кривой на живом журнале (46 473
# события, 132 эпизода атак). Бюджет прямо управляет нагрузкой смены:
#
#   бюджет   обнаружение   эпизодов   ложные   алертов
#    1.0%        76.5%      101/132    64.4%      322
#    0.4%        75.8%      100/132    37.0%      197
#    0.2%        75.0%       99/132    30.8%      155
#    0.1%        74.2%       98/132    24.0%      137   <- выбрано
#   0.05%        72.7%       96/132    24.0%      125
#
# Ниже 0.1% доля ложных больше не падает, а эпизоды продолжают теряться —
# это и есть колено кривой. Три пропущенных эпизода из 132 против
# сокращения ложных инцидентов с 29 до 6 и потока тревог вдвое.
UEBA_MIN_CALIB = 400              # наблюдений до калибровки; до неё слой МОЛЧИТ
UEBA_SCALE_BITS = 6.0             # +6 бит сверх порога -> риск 0.5
UEBA_VELOCITY_WINDOW_MIN = 30     # окно для оценки интенсивности актора (sim-мин)
UEBA_RECALIB_EVERY = 200          # как часто пересчитывать квантиль порога (событий)
UEBA_MIN_RATE = 1.0               # нижняя граница λ пуассоновской модели всплеска
# КОМПОНЕНТЫ, ВХОДЯЩИЕ В СУММУ НЕОЖИДАННОСТИ.
#
# Неожиданность −log₂P(x|норма) равна отношению правдоподобий (то есть является
# мерой улики) только если P(x|атака) РАВНОМЕРНО. Замер по компонентам
# (tools/ueba_components.py, 20 320 событий) показал ROC-AUC:
#
#     hour 0.577 | action 0.494 | repo 0.492 | burst 0.400 | сумма всех 0.451
#
# «action» не различает по построению: taxonomy.py специально сделан так, чтобы
# атака и норма описывались одними и теми же действиями. «burst» работает
# ПРОТИВ: профили уклонения растягивают шаги во времени, атакующий тише обычной
# работы, плюс поток пачечный (Var/E ≈ 4.2) и пуассоновский хвост при
# сверхдисперсии добавляет норме несколько бит шума.
#
# Интенсивность не выброшена — она осталась признаком слоя L2 (burst_*), где
# знак выучивается по данным (модель дала burst_any вес −1.15).
UEBA_COMPONENTS = ("repo", "hour")
# Требуемый запас над порогом, в битах. 1 бит = событие вдвое менее вероятно,
# чем граничное. Защищает от алертов «на волосок выше квантиля»: порог оценён
# по конечной выборке и сам имеет погрешность.
UEBA_MIN_EXCESS_BITS = 1.0

# --- L2: ML (detector.MLScorer) ---
ML_ENABLED = True                 # выключить -> система работает на L0+L1
# Потолок риска для ОДИНОЧНОЙ сработки модели. Держим ниже порога
# «действенного» инцидента (0.6): модель сама по себе очередь не наполняет —
# она поднимает приоритет, когда СОГЛАСНА с правилом или с поведенческим
# слоем, и тогда слияние лог-шансов выводит риск за порог. Это и есть
# эшелонированная защита: слой добавляет уверенности, а не тревог.
ML_RISK_CAP = 0.55

# --- слияние рисков ---
# logodds: наивный Байес в лог-шансах. Складываются НЕ апостериорные риски
# слоёв, а их СВИДЕТЕЛЬСТВА (log-likelihood ratio) поверх общего приора:
#
#     logit P = logit π + Σ γ^i · (logit pᵢ − logit π)
#
# Затухание γ^i — поправка на зависимость слоёв: правило, UEBA и ML смотрят на
# одно событие и срабатывают по коррелирующим причинам, а noisy_or при
# зависимых источниках систематически завышает риск (два сигнала по 0.6 -> 0.84).
FUSION_MODE = "logodds"           # logodds | noisy_or | max
FUSION_DECAY = 0.5                # вес i-го по величине сигнала = FUSION_DECAY^i
# Приор π — базовая частота атакующих событий в потоке. НЕ подбирается на глаз:
# это доля is_anomaly в журнале (tools/estimate_prior.py). Без вычитания приора
# сложение лог-шансов считало бы его n раз, и каждый ДОПОЛНИТЕЛЬНЫЙ слой
# ПОНИЖАЛ бы риск события — ровно этот дефект и был найден на ревью.
FUSION_PRIOR = 0.01

# ПОРОГ ДЕЙСТВИЯ — граница, за которой инцидент попадает в очередь аналитика.
#
# Значение 0.6 стояло без обоснования: круглое число посередине шкалы. Замер
# (research/workload_curve.py, 3 сида, оба профиля скрытности, 342 эпизода
# атак, 46 сим-дней):
#
#   порог  очередь/день  настоящих в очереди  полнота
#    0.20      10.5            17.7%          258/342  =  75%
#    0.40       9.5            19.6%          258/342  =  75%
#    0.60       8.6            21.6%          258/342  =  75%   <- было
#    0.70       6.3            29.7%          258/342  =  75%   <- стало
#    0.80       5.3            34.1%          256/342  =  75%
#    0.90       3.0            56.5%          245/342  =  72%
#    0.95       2.2            68.9%          227/342  =  66%
#
# На отрезке 0.20–0.70 полнота НЕ МЕНЯЕТСЯ: пойманы одни и те же 258 эпизодов.
# Слияние по слоям даёт почти двухмодальное распределение риска, и между
# модами лежит один шум. Значит 0.70 достаётся бесплатно: очередь на четверть
# короче, доля настоящих атак в ней в полтора раза выше, полнота та же.
#
# Плата начинается за 0.70: 0.80 стоит двух эпизодов, 0.90 — тринадцати.
# 0.80 внутри разброса между прогонами, но правило выбора простое —
# максимальная полнота, при равной полноте минимальная очередь.
ACTION_THRESHOLD = 0.70

# Пускать ли инцидент со сработавшим правилом мимо порога.
#
# Замер: обход поднимал очередь с 6.3 до 10.5 инцидента в день (+67%), долю
# настоящих атак в ней ронял с 29.7% до 17.8%, а полнота оставалась той же —
# 258 эпизодов из 342. Срабатывания правил и без того перекрывают порог по
# слитому риску; мимо него проходили только слабые, ничем не подтверждённые.
# Подробности — в correlator.actionable.
RULE_BYPASSES_THRESHOLD = False

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
    # --- вторая линия и смежные роли ---
    # Без них у команды не бывает целых классов штатных действий: правки прав,
    # релизы, документация, ревью архитектуры. А если действие встречается
    # ТОЛЬКО у атакующего, его имя работает меткой, а не признаком.
    {"username": "viktor.orlov",   "name": "Viktor Orlov",   "role": "security_architect"},
    {"username": "daria.sokolova", "name": "Daria Sokolova", "role": "incident_responder"},
    {"username": "artem.lebedev",  "name": "Artem Lebedev",  "role": "incident_responder"},
    {"username": "ksenia.morozova","name": "Ksenia Morozova","role": "compliance"},
    {"username": "roman.zaytsev",  "name": "Roman Zaytsev",  "role": "sre"},
    {"username": "polina.egorova", "name": "Polina Egorova", "role": "qa_engineer"},
    {"username": "gleb.nikitin",   "name": "Gleb Nikitin",   "role": "junior_analyst"},
    {"username": "vera.pavlova",   "name": "Vera Pavlova",   "role": "tech_writer"},
    {"username": "timur.hasanov",  "name": "Timur Hasanov",  "role": "contractor"},
]

# АКТИВНОСТЬ РАСПРЕДЕЛЕНА НЕРАВНОМЕРНО.
#
# Раньше исполнитель выбирался равновероятно из всех инженеров, и все давали
# примерно одинаковый поток. В живой команде так не бывает: пара человек
# делает половину коммитов, стажёр и подрядчик — единицы. Для поведенческого
# слоя это принципиально: он строит базовую линию НА ЧЕЛОВЕКА, и когда все
# одинаковы, любое отклонение выглядит подозрительным. Отсюда и шум UEBA.
#
# Вес — относительная доля действий. Роль без записи получает 1.0.
ACTOR_WEIGHT = {
    "maria.ivanova":  3.0,   # ядро команды, тянет основной поток правил
    "dmitry.kozlov":  2.6,
    "pavel.morozov":  2.2,
    "sergey.volkov":  1.8,
    "alex.petrov":    1.6,   # тимлид: много ревью и мало коммитов
    "elena.kuzmina":  1.4,
    "anna.smirnova":  1.3,
    "olga.novak":     1.2,
    "nikita.orlov":   1.2,
    "roman.zaytsev":  1.1,
    "irina.belova":   1.0,
    "daria.sokolova": 0.9,
    "viktor.orlov":   0.8,
    "artem.lebedev":  0.8,
    "polina.egorova": 0.7,
    "vera.pavlova":   0.5,
    "ksenia.morozova": 0.4,
    "gleb.nikitin":   0.35,  # стажёр
    "timur.hasanov":  0.3,   # подрядчик, работает эпизодически
}

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


def repo_id(name, fallback="detection-rules"):
    """ЕДИНСТВЕННАЯ точка получения id репозитория по имени.

    Почему это отдельная функция, а не `PROJECTS[name]`
    --------------------------------------------------
    `PROJECTS` — это id того GitLab-инстанса, на котором проект запускался
    ПЕРВЫЙ РАЗ. После пересоздания репозиториев (tools/reset_gitlab.py, ручное
    удаление, перенос на другой сервер) id меняются. Автодискавери на старте
    находит настоящие id и кладёт их в `WORK_REPOS` — но `PROJECTS` при этом
    остаётся со старыми значениями.

    Активности, читавшие `PROJECTS[...]` напрямую, продолжали ходить по
    устаревшим id. На накопленном журнале это видно как систематические отказы
    ровно у них и ни у кого больше:

        DashboardActivity  (PROJECTS["detection-rules"]) docs/*  100 из 109 отказов
        IncidentActivity   (PROJECTS["playbooks"])       ir/*     197 из 197 отказов
        BulkMaintenance    (PROJECTS["detection-rules"]) chore/*   28 из  69 отказов
        активности через *_repo_id()                              0 отказов

    Всего 571 молчаливый отказ за прогон: события в журнал писались (с
    gitlab_ok=false), в GitLab не появлялось ничего, а в интерфейсе счётчик
    ошибок показывал ноль, потому что _fail() ничего не логировал.

    Порядок разрешения: рабочий пул (актуальные id) -> статическая карта ->
    фолбэк. Промах логируется — молчаливый возврат устаревшего id и был
    причиной проблемы.
    """
    if name in WORK_REPOS:
        return WORK_REPOS[name]
    if name in PROJECTS:
        import logging
        logging.getLogger("config").warning(
            "репозиторий взят из статической карты PROJECTS — id может быть "
            "устаревшим", extra={"ctx": {"repo": name, "id": PROJECTS[name],
                                         "подсказка": "не сработал автодискавери?"}})
        return PROJECTS[name]
    if fallback and fallback in WORK_REPOS:
        return WORK_REPOS[fallback]
    return PROJECTS.get(fallback or "detection-rules", 1)

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
            import logging as _lg
            _lg.getLogger("config").warning(
                "не удалось прочитать дерево репозитория — пропускаю",
                exc_info=True, extra={"ctx": {"repo": n, "id": WORK_REPOS.get(n)}})
    return repo_id("detection-rules")

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
        import logging as _lg
        _lg.getLogger("config").error("не удалось сохранить %s — правки из "
                                      "админки потеряются при перезапуске",
                                      WEB_CONFIG_FILE, exc_info=True)
        return False


def _load_web_config():
    if _os.path.exists(WEB_CONFIG_FILE):
        try:
            with open(WEB_CONFIG_FILE, encoding="utf-8") as f:
                apply_settings(_json.load(f))
        except Exception:
            # Молчание здесь означает «настройки из веб-админки НЕ ПРИМЕНИЛИСЬ,
            # но никто не узнал»: мир поедет на значениях по умолчанию, а
            # пользователь будет уверен, что его правки в силе.
            import logging as _lg
            _lg.getLogger("config").error(
                "не удалось применить %s — работаем на значениях по умолчанию",
                WEB_CONFIG_FILE, exc_info=True)


_load_web_config()
