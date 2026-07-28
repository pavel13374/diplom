# -*- coding: utf-8 -*-
"""
ОБЩИЙ ГЕНЕРАТОР НАГРУЗКИ для офлайн-экспериментов.

Раньше каждый экспериментальный скрипт лепил свой фон, и лепил его вырожденно:
четыре фиксированных пути и ДВА значения энтропии (3.2 / 2.4). На таком фоне
любой классификатор показывает 100% — это артефакт генератора, а не свойство
модели. Здесь фон собран из распределений, а не из констант:

  • энтропия — из нормального распределения, СВОЁ для каждого типа файла
    (yml/py/md/json/lock/min.js/svg), плюс тяжёлый хвост у минифицированного
    JS и base64-иконок;
  • размеры — логнормальные;
  • есть benign-двойники секретов: git SHA-40, UUID, base64-иконка,
    .env.example с плейсхолдером, lock-файлы с хэшами;
  • часы активности — смесь: рабочий день + редкие поздние коммиты;
  • интенсивность по акторам разная (кто-то пишет много, кто-то мало).

Именно на таком фоне метрики честные: задача перестаёт быть тривиальной.

Используется experiments.py, experiments_layers.py, tools/verify_ml.py.
"""

# --- скрипт живёт в подпапке; движок проекта — в корне ---
import os as _os, sys as _sys
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
for _p in (_ROOT, _os.path.join(_ROOT, "tools"), _os.path.join(_ROOT, "research")):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
del _os, _sys

import os
import math
import random
import string
import tempfile
from datetime import datetime, timedelta

def _cfg_actors_repos():
    """Акторы и репозитории берём ИЗ КОНФИГА, а не из своего списка.

    Иначе получается утечка: атакующий выбирается из config.USERS и ходит по
    config.WORK_REPOS, а нормальный фон живёт в другом наборе имён — и тогда
    «actor == alex.petrov» или «project == soc-secrets» встречаются только у
    атаки и работают меткой. Это ловит tests/test_leakage.py.
    """
    try:
        import config
        actors = [u for u in config.USERS if u != "soc-bot"]
        repos = list(config.WORK_REPOS)
        if actors and repos:
            return actors, repos
    except Exception:
        pass
    return (["maria.ivanova", "dmitry.kozlov", "anna.smirnova", "alex.petrov"],
            ["detection-rules", "normalization-rules", "playbooks", "soc-infra"])


ACTORS, REPOS = _cfg_actors_repos()

#: Роли берём из конфига по тем же соображениям: раньше роль ml_engineer
#: встречалась только у атакующего.
def _role_of(actor):
    try:
        import config
        return (config.USERS.get(actor) or {}).get("role", "detection_engineer")
    except Exception:
        return "detection_engineer"


#: Префиксы веток. Список намеренно совпадает с тем, что использует красная
#: команда (activities/anomaly.py: unique_branch): если бы атака ходила по
#: своим веткам, а норма по своим, имя ветки стало бы меткой — это ловит
#: tests/test_leakage.py.
BRANCH_PREFIXES = [
    "feat/metrics", "feat/fast", "feat/self", "fix/typo", "chore/config",
    "chore/cleanup", "chore/deps", "chore/access", "chore/minify",
    "ci/debug", "ci/speedup", "ci/deploy", "ci/sync",
    "deploy/registry", "build/release", "backup/prod", "export/data",
    "add/secret", "rules/update",
]


def _branch(rnd):
    """Имя ветки в том же формате, что и у agents.base.unique_branch:
    «префикс-NNNNN». Формат общий для нормы и атаки."""
    return f"{rnd.choice(BRANCH_PREFIXES)}-{rnd.randint(10000, 99999)}"

# тип файла -> (путь-шаблон, mu энтропии, sigma, mu log-размера)
FILE_KINDS = [
    ("rules/{a}/{b}.yml",        0.34, 4.05, 0.35, 6.6),
    ("src/{b}.py",               0.20, 4.35, 0.30, 7.1),
    ("docs/{b}.md",              0.14, 4.15, 0.28, 7.3),
    ("config/{b}.json",          0.10, 4.60, 0.35, 6.2),
    ("config/.env.example",      0.05, 4.30, 0.25, 5.2),
    ("package-lock.json",        0.05, 5.35, 0.30, 9.4),   # хэши -> высокая энтропия
    ("static/{b}.min.js",        0.05, 5.55, 0.35, 9.1),   # минификация -> высокая
    ("static/icons/{b}.svg",     0.04, 5.10, 0.40, 8.2),   # base64-иконки
    ("ci/{b}.gitlab-ci.yml",     0.02, 4.20, 0.30, 6.0),
    ("requirements.txt",         0.02, 3.60, 0.30, 5.8),   # манифест зависимостей
]

_API_PATHS_BENIGN = ["/projects", "/members", "/search",
                     "/registry/repositories", "/jobs", "/pipelines",
                     "/repository/tree", "/issues"]

_WORDS = ["service", "deploy", "prod", "config", "region", "timeout", "enabled",
          "detection", "rules", "normalizer", "playbook", "endpoint", "version",
          "parser", "sigma", "hunt", "triage", "enrich", "alert", "case"]


def _hex(rnd, n):
    return "".join(rnd.choice("0123456789abcdef") for _ in range(n))


def _b64(rnd, n):
    return "".join(rnd.choice(string.ascii_letters + string.digits + "+/") for _ in range(n))


def _pick_kind(rnd):
    r = rnd.random()
    acc = 0.0
    for tpl, w, mu, sd, lmu in FILE_KINDS:
        acc += w
        if r <= acc:
            return tpl, mu, sd, lmu
    tpl, w, mu, sd, lmu = FILE_KINDS[0]
    return tpl, mu, sd, lmu


def benign_push_features(rnd):
    """Один нормальный push: путь + НАБЛЮДАЕМЫЕ признаки содержимого.

    Набор ключей обязан ПОЛНОСТЬЮ совпадать с тем, что возвращает
    content_features.analyze() для атакующих пушей. Иначе само наличие поля
    становится меткой: у атаки `generated_signal=False`, а у нормы поля нет
    вовсе — и признак «поле присутствует» безошибочно указывает на атаку.
    Ровно это поймал tests/test_leakage.py после добавления новых признаков.
    """
    tpl, mu, sd, lmu = _pick_kind(rnd)
    path = tpl.format(a=rnd.choice(["win", "lin", "cloud", "net"]),
                      b=rnd.choice(_WORDS))
    # Часть нормальных файлов не содержит токенов длиной 16+, и энтропия
    # честно равна нулю (короткие конфиги, манифесты, changelog). Без этого
    # значение 0 встречалось бы только у атаки и работало меткой.
    if rnd.random() < 0.12:
        ent = 0.0
    else:
        ent = max(1.2, min(7.9, rnd.gauss(mu, sd)))
    size = int(math.exp(rnd.gauss(lmu, 0.8)))
    ext = path.rsplit(".", 1)[-1] if "." in path else ""

    placeholder = path.endswith(".env.example")
    filename_sig = any(k in path for k in ("env", "cred", "secret", "key"))

    # benign-двойники: длинный высокоэнтропийный токен БЕЗ секрета
    high_tok = False
    if "lock" in path or "min.js" in path or "svg" in path:
        high_tok = True                       # хэши/минификация/base64
    elif rnd.random() < 0.08:
        high_tok = True                       # git SHA-40 или UUID в конфиге

    # Признаки, выводимые из пути, считаем ТЕМ ЖЕ кодом, что и бой. Своя
    # копия критерия рано или поздно разойдётся с оригиналом, и разойдётся
    # молча: у нормы признака не будет, у атаки будет — и «поле присутствует»
    # снова станет меткой (это ловит tests/test_leakage.py).
    import content_features as _cf
    generated = bool(_cf._GENERATED_RE.search(path))
    sec_content = bool(_cf._SECURITY_CONTENT_RE.search(path))
    deps = any(path.endswith(k) for k in ("requirements.txt", "package.json",
                                          "go.mod", "pom.xml"))

    # СЕКРЕТ-СИГНАТУРА В НОРМАЛЬНОМ КОММИТЕ.
    # Это не оплошность генератора, а обязательное свойство: в реальности
    # regex регулярно срабатывает на примерах в документации, тестовых
    # фикстурах, отозванных ключах в changelog. Если бы n_regex_hits >= 1
    # встречалось ТОЛЬКО у атаки, правило secret-signature-commit имело бы
    # точность 100% по построению, а не по заслугам — и это была бы та же
    # утечка метки, только через содержимое.
    regex_hits = []
    if rnd.random() < 0.012:
        regex_hits = [rnd.choice(["gitlab_pat", "aws_akia", "jwt", "slack_token"])]
        # чаще всего рядом стоит явный маркер примера, но не всегда:
        # «настоящий на вид секрет в документации» — самый трудный случай
        if rnd.random() < 0.7:
            placeholder = True

    # выгрузка на внешний хост в обычном CI-скрипте (публичные зеркала, CDN)
    net_sink = rnd.random() < 0.004

    return {
        "path": path,
        "extra": {
            "shannon_entropy": round(ent, 3),
            "regex_hits": regex_hits,
            "n_regex_hits": len(regex_hits),
            "filename_signal": filename_sig,
            "placeholder_signal": placeholder,
            "has_high_entropy_token": high_tok,
            "generated_signal": generated,
            "net_sink_signal": net_sink,
            "obfuscation_signal": False,   # обычный код не исполняет base64-строки
            "security_content": sec_content,
            "deps_manifest": deps,
            "bytes": size,
            "lines": max(1, size // 40),
            "ext": ext,
        },
    }


def _work_hour(rnd):
    """Час активности: в основном рабочий день, изредка поздний вечер."""
    r = rnd.random()
    if r < 0.86:
        return rnd.randint(10, 18)            # рабочий день
    if r < 0.97:
        return rnd.choice([9, 19, 20])        # края дня
    return rnd.choice([7, 8, 21, 22, 23])     # редкие поздние


def emit_benign_background(events, simclock, seed=42, days=12, per_day=140,
                           start=datetime(2026, 6, 1, 10, 0, 0)):
    """Нормальный фон: разнообразные действия разных акторов по распределениям.

    Важно: сюда входят и «административные» действия (token_create,
    deploy_key_add, hook_create, schedule_create, pipeline_run, member_update,
    api_read, force_push) — те самые, которые раньше встречались ТОЛЬКО у
    атакующего и потому работали как метка. Теперь их делает и обычная команда.
    """
    rnd = random.Random(seed)
    # у акторов разная интенсивность (кто-то коммитит втрое больше)
    weights = {a: rnd.uniform(0.5, 2.0) for a in ACTORS}
    total_w = sum(weights.values())

    for d in range(days):
        emitted = 0
        while emitted < per_day:
            a = rnd.choices(ACTORS, weights=[weights[x] / total_w for x in ACTORS])[0]
            h = _work_hour(rnd)
            base = start + timedelta(days=d, hours=h - start.hour,
                                     minutes=rnd.randint(0, 59), seconds=rnd.randint(0, 59))
            # РАБОЧАЯ СЕССИЯ: люди работают очередями, а не по одному событию в
            # час. Без этого признак «всплеск активности» отличал бы атаку от
            # нормы тривиально — не потому, что атака бурная, а потому, что
            # фон был искусственно ровным. Модель тогда училась бы на артефакте
            # генератора, а не на поведении.
            burst_n = 1
            r0 = rnd.random()
            if r0 < 0.22:
                burst_n = rnd.randint(3, 9)         # плотная сессия правок
            elif r0 < 0.45:
                burst_n = rnd.randint(2, 3)
            for k in range(burst_n):
                if emitted >= per_day:
                    break
                emitted += 1
                t = base + timedelta(seconds=k * rnd.randint(20, 180))
                simclock.now = lambda _t=t: _t
                _emit_one(events, rnd, a, k)


def _pick_repo(rnd):
    """Репозиторий с весами: в soc-secrets обычная команда тоже заходит, но
    редко. Если бы не заходила никогда, `project == soc-secrets` был бы
    меткой атаки, а не признаком."""
    w = [0.05 if r == "soc-secrets" else 1.0 for r in REPOS]
    return rnd.choices(REPOS, weights=w)[0]


def _emit_one(events, rnd, a, k=0):
    """Одно нормальное событие внутри рабочей сессии актора."""
    repo = _pick_repo(rnd)
    r = rnd.random()

    if r < 0.44:
        f = benign_push_features(rnd)
        # Часть обычных пушей идёт прямо в main: правки документации, релизные
        # хвосты, работа лида. Без этого «push в защищённую ветку» стал бы
        # исключительным признаком атаки.
        to_main = rnd.random() < 0.06
        f["extra"]["protected_branch"] = to_main
        events.emit("push", actor=a, role=_role_of(a), project=repo,
                    path=f["path"], branch=("main" if to_main else _branch(rnd)),
                    extra=f["extra"])
    elif r < 0.54:
        events.emit("branch_create", actor=a, role=_role_of(a),
                    project=repo, branch=_branch(rnd))
    elif r < 0.63:
        events.emit("mr_open", actor=a, role=_role_of(a),
                    project=repo, mr_iid=rnd.randint(100, 9999))
    elif r < 0.70:
        events.emit("mr_comment", actor=a, role=_role_of(a),
                    project=repo, mr_iid=rnd.randint(100, 9999),
                    extra={"n_regex_hits": 0})
    elif r < 0.76:
        events.emit("mr_approve", actor=a, role=_role_of(a),
                    project=repo, mr_iid=rnd.randint(100, 9999))
    elif r < 0.83:
        # merge: чаще всего с апрувом и не своим (норма процесса)
        events.emit("mr_merge", actor=a, role=_role_of(a),
                    project=repo, mr_iid=rnd.randint(100, 9999),
                    extra={"approvals_count": 0 if rnd.random() < 0.10 else rnd.randint(1, 2),
                           "self_merged": rnd.random() < 0.12,
                           "protected_branch": rnd.random() < 0.25})
    elif r < 0.875:
        # Уборка репозитория. Изредка команда чистит МНОГО файлов за раз
        # (удаление устаревшего набора правил) — это честный сложный
        # отрицательный пример для правила о массовом удалении.
        n = rnd.randint(1, 3) if rnd.random() < 0.94 else rnd.randint(6, 14)
        # Удаления идут ОДНИМ коммитом в одну ветку — как и у атаки. Иначе
        # «много удалений на одной ветке» было бы признаком атаки само по себе.
        br = _branch(rnd)
        for _i in range(n):
            events.emit("file_delete", actor=a, role=_role_of(a), branch=br,
                        project=repo, path="rules/old/" + rnd.choice(_WORDS) + ".yml")
    elif r < 0.925:
        # Просмотр через API. Иногда человек листает много страниц подряд —
        # без этого правило о разведке отличало бы атаку тривиально.
        n = rnd.randint(1, 2) if rnd.random() < 0.75 else rnd.randint(5, 11)
        for _i in range(n):
            events.emit("api_read", actor=a, role=_role_of(a),
                        project=_pick_repo(rnd),
                        extra={"api_path": rnd.choice(_API_PATHS_BENIGN),
                               "items_returned": rnd.randint(1, 60) if rnd.random() < 0.85
                                   else rnd.randint(60, 220),
                               "query_len": rnd.randint(3, 14)})
    elif r < 0.932:
        # выгрузка архива репозитория делается и в обычной работе
        # (локальная копия, миграция, аудит) — иначе этот путь API был бы
        # исключительным признаком атаки
        events.emit("api_read", actor=a, role=_role_of(a), project=_pick_repo(rnd),
                    extra={"api_path": "/repository/archive",
                           "items_returned": rnd.randint(20, 150),
                           "bytes": int(math.exp(rnd.gauss(13.0, 1.6)))})
    elif r < 0.945:
        events.emit("token_create", actor=a, role=_role_of(a), project=repo,
                    extra={"token_scope": rnd.choice(["read_api", "read_repository"]),
                           "expires_days": rnd.choice([30, 60, 90]),
                           "for_self": True})
    elif r < 0.962:
        events.emit("pipeline_run", actor=a, role=_role_of(a), project=repo,
                    extra={"manual_trigger": rnd.random() < 0.3,
                           "target_env": "production" if rnd.random() < 0.15 else "staging",
                           "protected_branch": rnd.random() < 0.2})
    elif r < 0.972:
        events.emit("schedule_create", actor=a, role=_role_of(a), project=repo,
                    extra={"cron": "0 3 * * *", "is_night_cron": True,
                           "protected_branch": rnd.random() < 0.2,
                           "target_env": "staging"})
    elif r < 0.980:
        events.emit("hook_create", actor=a, role=_role_of(a), project=repo,
                    extra={"hook_host": rnd.choice(["ci.internal", "siem.internal"]),
                           "external_host": False})
    elif r < 0.986:
        events.emit("deploy_key_add", actor=a, role=_role_of(a), project=repo,
                    extra={"key_write_access": rnd.random() < 0.3,
                           "external_host": False})
    elif r < 0.992:
        events.emit("member_update", actor=a, role=_role_of(a), project=repo,
                    extra={"access_level": rnd.choice([20, 30, 40]),
                           "self_grant": False,
                           "new_member": rnd.random() < 0.5,
                           "target_user": rnd.choice(ACTORS)})
    elif r < 0.997:
        # Удаление слитых веток — тот же тип события, что у «уничтожения
        # резервных копий», но по незащищённым feature-веткам.
        for _i in range(rnd.randint(1, 4)):
            events.emit("branch_delete", actor=a, role=_role_of(a),
                        project=repo, branch=_branch(rnd),
                        extra={"protected_branch": False})
    else:
        events.emit("force_push", actor=a, role=_role_of(a), project=repo,
                    branch=_branch(rnd),
                    extra={"protected_branch": False,
                           "commits_dropped": rnd.randint(0, 2)})


class FakeGL:
    """Заглушка GitLab-клиента для офлайн-прогонов.

    get_mr возвращает ОСМЫСЛЕННЫЕ метаданные merge request, а не пустой словарь.
    Раньше он отдавал {}, из-за чего в событие merge не попадали
    approvals_count / target_branch, и правила merge-without-approval и
    self-merged-mr в офлайн-экспериментах не срабатывали НИ РАЗУ — выглядело
    как «правило не ловит атаку», а на деле нечему было ловить.
    """
    _r = random.Random(7)

    def __init__(self, username=None):
        self.username = username

    def get_mr(self, project_id=None, mr_iid=None, *a, **k):
        return {
            "author": {"username": self.username},
            "target_branch": "main",
            "approvals_count": 0,
            "approved_by": [],
        }

    def __getattr__(self, n):
        def f(*a, **k):
            if n in ("create_mr", "create_issue"):
                return FakeGL._r.randint(100, 9999)
            if n == "get_open_mrs":
                return []
            if n == "list_files":
                return [f"rules/r{i}.yml" for i in range(14)]
            if n == "get_or_create_user_token":
                return "t"
            return True
        return f


def build_workload(evasion="noisy", seed=42, days=12, per_day=140, campaigns=None):
    """Свежий временный стор: нормальный фон + ATT&CK-кампании профиля `evasion`.

    Возвращает список событий из стора по порядку.
    """
    import config, simclock, events, eventstore
    config.OFFLINE_MODE = True
    config.TELEGRAM = {"enabled": False}
    config.seed_all()
    tmp = tempfile.mkdtemp()
    config.EVENT_LOG = {"enabled": True, "file": os.path.join(tmp, "e.jsonl")}
    config.EVENT_STORE = {"enabled": True, "path": os.path.join(tmp, "e.db")}
    start = datetime(2026, 6, 1, 10, 0, 0)
    simclock.init(simclock.SimClock(start_sim=start, scale=1.0,
                                    work_start=10, work_end=18,
                                    work_days=[0, 1, 2, 3, 4],
                                    fast_forward_offhours=False))
    simclock.sleep = lambda *a, **k: None
    events.init()

    emit_benign_background(events, simclock, seed=seed, days=days,
                           per_day=per_day, start=start)

    from agents.base import BaseAgent
    from agents.lead import LeadAgent
    from red_team import RedTeamEngine, CAMPAIGNS
    agents = {u: (LeadAgent(u, FakeGL(u)) if i.get("role") == "lead" else BaseAgent(u, FakeGL(u)))
              for u, i in config.USERS.items()}
    red = RedTeamEngine(agents, state=None)
    keys = list(campaigns or CAMPAIGNS)
    # Порядок кампаний перемешиваем сидом. Без этого кампания с индексом i
    # всегда попадала на один и тот же день, а хронологический сплит
    # train/val/test оказывался разделением ПО ТИПУ АТАКИ: модель обучалась на
    # одних кампаниях и проверялась на других, никогда не виденных. Это
    # интересная и более трудная задача, но она должна ставиться ЯВНО
    # (см. research/experiments_holdout.py — leave-one-family-out), а не
    # получаться случайно из-за порядка словаря.
    random.Random(seed).shuffle(keys)
    # Кампании раскладываем РАВНОМЕРНО по всему периоду.
    #
    # Раньше здесь было datetime(..., 19 + i, ...) — при 12 кампаниях падало
    # с «hour must be in 0..23». Затем стояло `2 + i % (days-3)`, и при 15
    # кампаниях они кучковались в начале: хронологический сплит train/val/test
    # получал непропорциональный набор атак, и качество на валидации и на
    # тесте расходилось в разы. Равномерная раскладка даёт каждой части
    # представительную выборку кампаний.
    n = max(1, len(keys) - 1)
    for i, key in enumerate(keys):
        day_idx = 1 + int(i * (days - 2) / n)
        hour = 9 + (i * 5) % 11          # разные часы, чтобы не совпадали
        day = start + timedelta(days=day_idx, hours=hour - start.hour)
        simclock.now = lambda _t=day: _t
        red.run_campaign(key, evasion=evasion)
    events.close()
    return eventstore.read_since(0, limit=10_000_000)
