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
#: Список ОБЯЗАН совпадать с taxonomy.OBSERVABLE — это проверяется ассертом
#: ниже и тестом tests/test_detector.py. Раньше рассинхрон был: в taxonomy
#: добавили issue_open / issue_comment / issue_close, а сюда — нет. 634 события
#: живого журнала (2% потока) получали НУЛЕВОЙ вектор действия: для модели они
#: были неотличимы друг от друга и от любого неизвестного действия. Молчаливый
#: рассинхрон такого рода — самый дешёвый способ потерять сигнал.
ACTIONS = ["push", "force_push", "file_delete", "branch_create", "branch_delete",
           "mr_open", "mr_merge", "mr_approve", "mr_comment", "mr_close",
           "issue_open", "issue_comment", "issue_close",
           "api_read", "token_create", "deploy_key_add", "hook_create",
           "schedule_create", "pipeline_run", "member_update", "release_publish"]

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
_SECRET_DIRS = ("vault", "backup", "export", "secret", "dump", "credential")


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
        1.0 if any(k in path for k in _SECRET_DIRS) else 0.0,
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

    Отдельной функцией, а не голым импортом на уровне модуля: ml_features
    подтягивает детектор в инференсе, и жёсткая зависимость создала бы цикл.
    Зовётся из tests/ и tools/doctor.py.
    """
    import taxonomy
    missing = sorted(taxonomy.OBSERVABLE - _ACTION_SET)
    extra = sorted(_ACTION_SET - taxonomy.OBSERVABLE)
    return missing, extra
