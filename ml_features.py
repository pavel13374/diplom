# -*- coding: utf-8 -*-
"""
ЕДИНЫЙ НАБОР ПРИЗНАКОВ СОБЫТИЯ для ML-слоя.

Единственная точка, где событие превращается в числовой вектор:
  • research/train_runtime_model.py — обучение, калибровка, оценка;
  • detector.MLScorer (слой L2)     — инференс в потоке.

Почему это важно
----------------
Исторически вектор признаков был описан внутри `research/train_model.py`, а
боевой детектор ML вообще не использовал: «доказали, что ML обобщает лучше
регулярок» и «система работает на регулярках» жили в разных файлах и никак не
сходились. Потом появился этот модуль — но старая реализация НЕ БЫЛА УДАЛЕНА и
продолжала жить своей жизнью: 22 признака против 63, свой список действий с
`repo_enum`, `comment`, `approve`, которых в taxonomy.py нет вовсе. Числа,
полученные тем скриптом, выглядели как метрики того же детектора, но были
несопоставимы. Сейчас реализация одна, и это проверяется тестом
`tests/test_generated_content.py::test_single_feature_implementation` —
семантически, по пересечению словарей, а не по именам файлов.

Отдельно: `research/content_ml_features.py` — это ДРУГОЕ признаковое
пространство (только по содержимому файла, без привязки к событию) для
самостоятельного вопроса «отличим ли секрет по статистике текста без
регулярок». Оно не дубликат и не участвует в боевом инференсе.

АНТИ-ЛИК: на вход подаются только наблюдаемые поля события (те, что остаются
после run_defense.observed()). Ни одна метка мира сюда не попадает — это
проверяется тестом tests/test_antileak.py.
"""
import math

#: Действия из нормализованного словаря (taxonomy.py), которые кодируем one-hot.
#:
#: ВЫВОДИТСЯ ИЗ taxonomy.OBSERVABLE, а не перечисляется руками.
#:
#: Здесь дважды был написанный вручную список, и он дважды разошёлся со
#: словарём. Первый раз: в taxonomy добавили issue_open / issue_comment /
#: issue_close, а сюда — нет, и 634 события живого журнала (2% потока)
#: получали НУЛЕВОЙ вектор действия — для модели они были неотличимы друг от
#: друга и от любого неизвестного действия. Предупреждающий комментарий об
#: этом стоял ровно на этом месте — и не помешал случиться тому же во второй
#: раз: коммит «добавлено 24 типа действий» расширил словарь до 45 значений,
#: список остался на 21, и МОДЕЛЬ ПЕРЕСТАЛА РАЗЛИЧАТЬ БОЛЕЕ ПОЛОВИНЫ СЛОВАРЯ:
#: все 24 новых действия сваливались в один признак act_unknown.
#:
#: Вывод: комментария недостаточно, рассинхрон должен быть НЕВОЗМОЖЕН.
#: taxonomy.py — модуль без единого импорта (чистые данные), цикла здесь нет,
#: поэтому список берётся из него напрямую. Порядок — sorted(), то есть
#: детерминированный: модель хранит список признаков рядом с весами, и
#: MLScorer._load сверяет его целиком перед тем, как включить слой.
import taxonomy

ACTIONS = sorted(taxonomy.OBSERVABLE)

#: Порядок признаков зафиксирован — модель сохраняется вместе с этим списком
#: и при загрузке сверяется (см. MLScorer._load).
FEATURES = [
    # время
    "hour_norm", "is_night", "is_weekend",
    # содержимое
    "n_regex_hits", "entropy_norm", "filename_sig", "placeholder_sig",
    "high_entropy_tok", "has_content", "bytes_log",
    # путь
    "path_env", "path_secretdir", "path_ci", "path_deps",
    "obfuscation_sig", "net_sink_sig", "generated_sig", "security_content",
    # проект
    "proj_secrets",
    # взаимодействия
    "night_x_secret", "entropy_x_nosig",
    # атрибуты административных действий
    "token_scope_api", "token_no_expiry", "token_not_self",
    "key_write", "hook_external", "night_cron",
    "access_owner", "self_grant", "manual_prod",
    "protected_branch", "commits_dropped_log",
    "api_items_log", "api_path_sensitive",
    "dep_new_pinned",
    # merge-процесс
    "no_approvals", "self_merged",
    # оконные агрегаты (заполняет detector.Enricher)
    "burst_delete", "burst_api", "burst_any", "distinct_projects",
    # действие вне словаря: сигнал «данные не той версии», а не тихий ноль
    "act_unknown",
] + ["act_" + a for a in ACTIONS]

_SENSITIVE_API = ("/oauth", "/members", "/search", "/repository/archive", "/tokens")

#: Каталоги, само нахождение файла в которых — признак работы с секретами.
_SECRET_DIRS = ("vault", "backup", "export", "secret", "secrets", "dump", "dumps",
                "credential", "credentials")


def _in_secret_dir(path, security_content):
    """Лежит ли файл В КАТАЛОГЕ секретов.

    Сопоставление по СЕГМЕНТАМ пути, а не подстрокой, и с вычетом рабочих
    продуктов SOC-команды.

    Почему это переписано. Признак считался как «одно из слов встречается
    где-либо в пути», и на живом стенде это оказалось разрушительно: команда
    целыми днями пишет правила детектирования ПРО кражу учётных данных, и
    каждый такой коммит попадал под признак —

        rules/credential_access/golden_ticket_anomalous_tgt.yml   -> secretdir=1
        rules/defender/defender-credential-file-access.yml        -> secretdir=1
        playbooks/ir_credential_theft.md                          -> secretdir=1

    то есть ровно то же значение, что у vault/prod-secrets.yml. В прогоне на
    настоящем GitLab из 50 алертов 46 оказались такими: очередь аналитика
    забита нормальной работой, а доля слоёв перекошена (модель 92%, правила
    6%) не потому, что модель хороша, а потому что она реагирует на слово
    «credential» в имени файла.

    Признак security_content уже отвечает на вопрос «это рабочий продукт
    SOC-команды» — правило, гипотеза, плейбук, документация. Здесь он и
    вычитается: файл в каталоге секретов остаётся уликой, файл ПРО секреты —
    нет.
    """
    segs = [s for s in str(path or "").lower().replace("\\", "/").split("/") if s]
    if not segs:
        return 0.0
    # последний сегмент — имя файла, его в расчёт каталога не берём
    dirs = segs[:-1]
    if not any(d in _SECRET_DIRS for d in dirs):
        return 0.0
    return 0.0 if security_content else 1.0


def _num(r, k, d=0.0):
    """Число из поля; sentinel -1 (политика пропусков экспорта) трактуем как «нет»."""
    v = r.get(k)
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if isinstance(v, (int, float)) and v != -1:
        return float(v)
    return d


def _flag(r, k):
    return 1.0 if r.get(k) else 0.0


def featurize(r):
    """Событие (наблюдаемые поля) -> список чисел в порядке FEATURES."""
    path = str(r.get("path") or "").lower()
    action = str(r.get("action") or "")
    api_path = str(r.get("api_path") or "").lower()

    nrh = max(0.0, _num(r, "n_regex_hits"))
    ent = max(0.0, _num(r, "shannon_entropy"))
    byt = _num(r, "bytes")
    byt_log = math.log1p(byt) if byt > 0 else 0.0
    night = _flag(r, "is_night")
    secretish = 1.0 if (nrh > 0 or "env" in path) else 0.0

    expires = r.get("expires_days")
    no_expiry = 1.0 if (expires is None and action == "token_create") else 0.0

    access = _num(r, "access_level")
    dropped = _num(r, "commits_dropped")
    items = _num(r, "items_returned")

    vec = [
        _num(r, "hour") / 23.0,
        night,
        _flag(r, "is_weekend"),

        nrh,
        ent / 8.0,
        _flag(r, "filename_signal"),
        _flag(r, "placeholder_signal"),
        _flag(r, "has_high_entropy_token"),
        _flag(r, "has_content") or (1.0 if byt > 0 else 0.0),
        byt_log / 12.0,

        1.0 if "env" in path else 0.0,
        _in_secret_dir(path, _flag(r, "security_content")),
        1.0 if ("gitlab-ci" in path or path.startswith("ci/")) else 0.0,
        1.0 if any(k in path for k in ("requirements", "package.json", "go.mod", "pom.xml")) else 0.0,
        _flag(r, "obfuscation_signal"),
        _flag(r, "net_sink_signal"),
        _flag(r, "generated_signal"),
        _flag(r, "security_content"),

        1.0 if r.get("project") == "soc-secrets" else 0.0,

        night * secretish,
        (ent / 8.0) * (1.0 if nrh == 0 else 0.0),      # высокая энтропия БЕЗ сигнатуры

        1.0 if r.get("token_scope") in ("api", "sudo") else 0.0,
        no_expiry,
        1.0 if (action == "token_create" and r.get("for_self") is False) else 0.0,
        _flag(r, "key_write_access"),
        _flag(r, "external_host"),
        _flag(r, "is_night_cron"),
        1.0 if access >= 50 else 0.0,
        _flag(r, "self_grant"),
        1.0 if (r.get("manual_trigger") and r.get("target_env") == "production") else 0.0,
        _flag(r, "protected_branch"),
        math.log1p(max(0.0, dropped)) / 4.0,
        math.log1p(max(0.0, items)) / 6.0,
        1.0 if any(k in api_path for k in _SENSITIVE_API) else 0.0,
        1.0 if (_flag(r, "dependency_added") and _flag(r, "dependency_pinned_new")) else 0.0,

        1.0 if (action == "mr_merge" and _num(r, "approvals_count", -1) == 0) else 0.0,
        _flag(r, "self_merged"),

        math.log1p(max(0.0, _num(r, "burst_file_delete_10m"))) / 3.0,
        math.log1p(max(0.0, _num(r, "burst_api_read_15m"))) / 3.0,
        math.log1p(max(0.0, _num(r, "burst_any_30m"))) / 4.0,
        math.log1p(max(0.0, _num(r, "distinct_projects_1h"))) / 3.0,

        0.0 if action in _ACTION_SET else 1.0,       # act_unknown
    ] + [1.0 if action == a else 0.0 for a in ACTIONS]

    return vec


_ACTION_SET = frozenset(ACTIONS)

assert len(featurize({})) == len(FEATURES), (
    f"рассинхрон FEATURES({len(FEATURES)}) и featurize({len(featurize({}))})")


def check_taxonomy():
    """ACTIONS должен совпадать с taxonomy.OBSERVABLE.

    Теперь ACTIONS ВЫВОДИТСЯ из словаря, поэтому расхождение невозможно по
    построению, и функция всегда возвращает две пустые группы. Она оставлена
    намеренно: её зовут tests/ и tools/doctor.py, и если кто-то однажды снова
    заменит вывод на ручной список, проверка сразу станет содержательной.
    """
    missing = sorted(taxonomy.OBSERVABLE - _ACTION_SET)
    extra = sorted(_ACTION_SET - taxonomy.OBSERVABLE)
    return missing, extra


assert not any(check_taxonomy()), "ACTIONS разошёлся с taxonomy.OBSERVABLE"
