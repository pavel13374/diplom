# -*- coding: utf-8 -*-
"""
ЕДИНЫЙ НАБОР ПРИЗНАКОВ СОБЫТИЯ для ML-слоя.

Раньше вектор признаков был описан внутри `research/train_model.py`, а боевой
детектор ML вообще не использовал. Из-за этого «доказали, что ML лучше регулярок»
и «система работает на регулярках» жили в разных файлах и никак не сходились.

Теперь featurize() один на всех:
  • research/train_model.py       — обучение и оффлайн-оценка;
  • detector.MLScorer (слой L2)   — инференс в потоке.

Так гарантировано, что обучение и применение видят ОДИН И ТОТ ЖЕ вектор:
классическая причина расхождения train/serve здесь исключена конструктивно.

АНТИ-ЛИК: на вход подаются только наблюдаемые поля события (те, что остаются
после run_defense.observed()). Ни одна метка мира сюда не попадает — это
проверяется тестом tests/test_antileak.py.
"""
import math

#: Действия из нормализованного словаря (taxonomy.py), которые кодируем one-hot.
ACTIONS = ["push", "force_push", "file_delete", "branch_create", "branch_delete",
           "mr_open", "mr_merge", "mr_approve", "mr_comment", "mr_close",
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
    "obfuscation_sig", "net_sink_sig", "generated_sig",
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
    ] + [1.0 if action == a else 0.0 for a in ACTIONS]

    return vec


assert len(featurize({})) == len(FEATURES), (
    f"рассинхрон FEATURES({len(FEATURES)}) и featurize({len(featurize({}))})")
