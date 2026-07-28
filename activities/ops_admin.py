# -*- coding: utf-8 -*-
"""
ШТАТНАЯ АДМИНИСТРАТИВНАЯ РАБОТА команды.

Зачем этот модуль. Раньше действия `token_create`, `deploy_key_add`,
`hook_create`, `schedule_create`, `pipeline_run`, `member_update`,
`force_push`, `branch_delete`, `api_read` встречались в журнале ТОЛЬКО у
атакующего. Из-за этого правило вида {"action": "token_create"} работало не
детектором, а считывателем метки: в реальном GitLab такие действия делает вся
команда каждый день.

Здесь обычные сотрудники делают ровно те же действия — но с нормальными
атрибутами:

  токены       — себе, read-only, с истечением;
  deploy-ключи — read-only, на внутренний хост;
  вебхуки      — на внутренний SIEM/CI, не наружу;
  расписания   — ночные сборки (это нормально) на НЕзащищённой ветке;
  пайплайны    — по push, в staging;
  права        — Reporter/Developer другим людям, не Owner себе;
  force-push   — после rebase своей ветки, без потери истории;
  api_read     — обычный просмотр списков с небольшой выдачей.

Именно перекрытие распределений делает задачу настоящей: детектор обязан
разделять по атрибутам, а не по имени действия.
"""
import random
import logging

import config
import events

logger = logging.getLogger(__name__)

_INTERNAL_HOOK_HOSTS = ["siem.soc.internal", "ci.soc.internal",
                        "alerts.soc.internal", "grafana.soc.internal"]

_API_PATHS = ["/projects", "/members", "/search", "/repository/tree",
              "/jobs", "/pipelines", "/registry/repositories", "/issues"]


def _repo():
    pool = [n for n in config.WORK_REPOS if n != "soc-secrets"] or ["detection-rules"]
    return random.choice(pool)


class TokenRotation:
    """Плановая ротация личного read-токена. Норма: себе, read_api, со сроком."""

    def __init__(self, author, lead=None, state=None):
        self.author = author

    def run(self):
        events.emit("token_create", actor=self.author.username, role=self.author.role,
                    project=_repo(), message="chore: rotate personal read token",
                    extra={"token_scope": random.choice(["read_api", "read_repository"]),
                           "expires_days": random.choice([30, 60, 90]),
                           "for_self": True, "for_user": self.author.username})
        logger.info(f"[{self.author.username}] ротация личного токена")
        return True


class DeployKeyRotation:
    """Обновление deploy-ключа раннера. Норма: read-only, внутренний хост."""

    def __init__(self, author, lead=None, state=None):
        self.author = author

    def run(self):
        events.emit("deploy_key_add", actor=self.author.username, role=self.author.role,
                    project=_repo(), message="ci: rotate runner deploy key",
                    extra={"key_write_access": False, "external_host": False,
                           "hook_host": "runner.soc.internal"})
        return True


class WebhookSetup:
    """Вебхук на внутренний сервис (уведомления в SIEM/чат). Норма."""

    def __init__(self, author, lead=None, state=None):
        self.author = author

    def run(self):
        events.emit("hook_create", actor=self.author.username, role=self.author.role,
                    project=_repo(), message="ci: notify internal SIEM on push",
                    extra={"hook_host": random.choice(_INTERNAL_HOOK_HOSTS),
                           "external_host": False, "on_push": True})
        return True


class NightlyBuildSchedule:
    """Ночная сборка по расписанию — совершенно нормальная практика.

    Важно для честности: ночной cron сам по себе НЕ признак атаки, поэтому
    правило не должно срабатывать на `is_night_cron` в отрыве от контекста.
    """

    def __init__(self, author, lead=None, state=None):
        self.author = author

    def run(self):
        events.emit("schedule_create", actor=self.author.username, role=self.author.role,
                    project=_repo(), branch="develop",
                    message="ci: nightly regression build",
                    extra={"cron": random.choice(["0 2 * * *", "30 3 * * 1-5", "0 4 * * 0"]),
                           "is_night_cron": True, "protected_branch": False,
                           "target_env": "staging"})
        return True


class PipelineRun:
    """Обычный прогон пайплайна: по push, в staging."""

    def __init__(self, author, lead=None, state=None):
        self.author = author

    def run(self):
        manual = random.random() < 0.25
        events.emit("pipeline_run", actor=self.author.username, role=self.author.role,
                    project=_repo(), branch="feature/build",
                    message="ci: pipeline run",
                    extra={"manual_trigger": manual, "target_env": "staging",
                           "protected_branch": False})
        return True


class ProductionDeploy:
    """Штатный релиз в production — тоже норма, но реже и с защищённой ветки.

    Нужен именно для того, чтобы правило «ручной прогон в production» не было
    бесплатным: у нормы такое тоже бывает.
    """

    def __init__(self, author, lead=None, state=None):
        self.author = author

    def run(self):
        proj = _repo()
        events.emit("pipeline_run", actor=self.author.username, role=self.author.role,
                    project=proj, branch="main", message="release: deploy to production",
                    extra={"manual_trigger": True, "target_env": "production",
                           "protected_branch": True})
        events.emit("release_publish", actor=self.author.username, role=self.author.role,
                    project=proj, branch="main", message="release: publish tag",
                    extra={"target_env": "production"})
        return True


class MembershipChange:
    """Выдача прав новому участнику. Норма: Reporter/Developer, другому человеку."""

    def __init__(self, author, lead=None, state=None):
        self.author = author

    def run(self):
        others = [u for u in config.USERS if u != self.author.username]
        events.emit("member_update", actor=self.author.username, role=self.author.role,
                    project=_repo(), message="access: onboard team member",
                    extra={"access_level": random.choice([20, 30]),
                           "self_grant": False,
                           "target_user": random.choice(others) if others else "new.member",
                           "new_member": True})
        return True


class RebaseForcePush:
    """Force-push после rebase своей ветки — рутина, не атака.

    Отличие от переписывания истории: НЕзащищённая ветка и коммиты не теряются.
    """

    def __init__(self, author, lead=None, state=None):
        self.author = author

    def run(self):
        events.emit("force_push", actor=self.author.username, role=self.author.role,
                    project=_repo(), branch=self.author.unique_branch("feature/rebase"),
                    message="rebase onto main",
                    extra={"protected_branch": False, "commits_dropped": 0})
        return True


class BranchCleanup:
    """Удаление слитых веток. Тоже серия branch_delete, как у inhibit_recovery,
    но по незащищённым feature-веткам."""

    def __init__(self, author, lead=None, state=None):
        self.author = author

    def run(self):
        proj = _repo()
        for _ in range(random.randint(1, 3)):
            events.emit("branch_delete", actor=self.author.username, role=self.author.role,
                        project=proj, branch=self.author.unique_branch("feature/merged"),
                        message="chore: delete merged branch",
                        extra={"protected_branch": False})
        return True


class ApiBrowsing:
    """Обычный просмотр списков через API/UI: небольшая выдача, рабочее время."""

    def __init__(self, author, lead=None, state=None):
        self.author = author

    def run(self):
        for _ in range(random.randint(1, 3)):
            events.emit("api_read", actor=self.author.username, role=self.author.role,
                        project=_repo(), message="GET listing",
                        extra={"api_path": random.choice(_API_PATHS),
                               "items_returned": random.randint(1, 25),
                               "query_len": random.randint(3, 12)})
        return True


#: Реестр для планировщика: имя активности -> класс
BENIGN_ADMIN = {
    "token_rotation":      TokenRotation,
    "deploy_key_rotation": DeployKeyRotation,
    "webhook_setup":       WebhookSetup,
    "nightly_schedule":    NightlyBuildSchedule,
    "pipeline_run":        PipelineRun,
    "production_deploy":   ProductionDeploy,
    "membership_change":   MembershipChange,
    "rebase_force_push":   RebaseForcePush,
    "branch_cleanup":      BranchCleanup,
    "api_browsing":        ApiBrowsing,
}
