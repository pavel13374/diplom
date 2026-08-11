# -*- coding: utf-8 -*-
"""
ШТАТНАЯ РАБОТА РАСШИРЕННОЙ КОМАНДЫ.

Зачем этот модуль. В журнале на `push` приходилась четверть всех событий, а
хвост распределения был пуст: `file_delete` — 0.4%, `api_read` — 0.6%. Живой
GitLab так не выглядит. Команда ставит теги, открывает черновики MR, просит
ревью, снимает аппрувы после правок, черри-пикает хотфиксы, откатывает
коммиты, правит вики, заводит сниппеты, вешает метки, двигает вехи, перезапускает
упавшие пайплайны, выкачивает артефакты, меняет состав участников и правила
защиты веток.

Две причины, почему это важно не для красоты.

1. Если действие встречается ТОЛЬКО у атакующего, его имя работает меткой, а
   не признаком. `member_add`, `protected_branch_update`, `artifact_download`
   были ровно в таком положении.
2. Поведенческий слой строит базовую линию на человека. Чем беднее нормальный
   репертуар, тем чаще обычная работа выглядит редкой — и тем больше ложных
   тревог. Часть шума UEBA росла именно отсюда.

Роли здесь разные не для разнообразия: архитектор правит защиту веток,
техписатель живёт в вики, QA перезапускает пайплайны, комплаенс смотрит
состав участников. Разные люди — разные распределения, как в жизни.
"""
import random
import logging

import config
import events

logger = logging.getLogger(__name__)


def _repo(exclude_secrets=True):
    pool = [n for n in config.WORK_REPOS if not (exclude_secrets and n == "soc-secrets")]
    return random.choice(pool or ["detection-rules"])


def _repos(n):
    pool = [x for x in config.WORK_REPOS if x != "soc-secrets"] or ["detection-rules"]
    return random.sample(pool, k=min(n, len(pool)))


class ReleaseTagging:
    """Тег и релиз на стабильном коммите — работа релиз-менеджера или SRE."""

    def __init__(self, author, lead=None, state=None):
        self.author = author

    def run(self):
        repo = _repo()
        ver = f"v{random.randint(1, 4)}.{random.randint(0, 12)}.{random.randint(0, 9)}"
        events.emit("tag_create", actor=self.author.username, role=self.author.role,
                    project=repo, message=f"release: {ver}",
                    extra={"tag": ver, "protected_branch": True, "on_default_branch": True})
        if random.random() < 0.7:
            events.emit("release_publish", actor=self.author.username, role=self.author.role,
                        project=repo, message=f"release {ver} notes",
                        extra={"tag": ver, "assets": random.randint(0, 3)})
        logger.info(f"[{self.author.username}] релиз {ver} в {repo}")
        return True


class ReviewCycle:
    """Полный цикл ревью: черновик → запрос ревью → правки → снятие аппрува."""

    def __init__(self, author, lead=None, state=None):
        self.author = author
        self.lead = lead

    def run(self):
        repo = _repo()
        iid = random.randint(100, 999)
        events.emit("mr_draft", actor=self.author.username, role=self.author.role,
                    project=repo, mr_iid=iid, message="draft: работа начата",
                    extra={"draft": True})
        reviewer = getattr(self.lead, "username", None) or self.author.username
        events.emit("mr_review_request", actor=self.author.username, role=self.author.role,
                    project=repo, mr_iid=iid, message="просьба посмотреть",
                    extra={"reviewer": reviewer})
        # Аппрув сняли после новых правок — обычное дело, а выглядит как
        # «откат согласования», если такого в норме не встречается.
        if random.random() < 0.35:
            events.emit("mr_unapprove", actor=reviewer, role="lead",
                        project=repo, mr_iid=iid, message="снял аппрув: появились правки",
                        extra={"reason": "new_commits"})
        logger.info(f"[{self.author.username}] цикл ревью MR !{iid} в {repo}")
        return True


class HotfixPort:
    """Перенос хотфикса в релизную ветку и откат неудачного коммита."""

    def __init__(self, author, lead=None, state=None):
        self.author = author

    def run(self):
        repo = _repo()
        if random.random() < 0.6:
            events.emit("cherry_pick", actor=self.author.username, role=self.author.role,
                        project=repo, branch=random.choice(["release/1.4", "release/1.5"]),
                        message="cherry-pick: hotfix в релизную ветку",
                        extra={"from_branch": "main", "commits": 1})
        else:
            events.emit("revert_commit", actor=self.author.username, role=self.author.role,
                        project=repo, branch="main",
                        message="revert: откат неудачного изменения",
                        extra={"reverted_commits": 1, "protected_branch": True})
        logger.info(f"[{self.author.username}] перенос или откат коммита в {repo}")
        return True


class DocsUpkeep:
    """Вики и сниппеты: живая документация команды."""

    def __init__(self, author, lead=None, state=None):
        self.author = author

    def run(self):
        repo = _repo()
        if random.random() < 0.65:
            events.emit("wiki_edit", actor=self.author.username, role=self.author.role,
                        project=repo, message="wiki: обновил раздел",
                        extra={"page": random.choice(["Onboarding", "Runbook", "Detection-Guide",
                                                      "Escalation", "Architecture"]),
                               "words_added": random.randint(20, 400)})
        else:
            events.emit("snippet_create", actor=self.author.username, role=self.author.role,
                        project=repo, message="snippet: полезный запрос",
                        extra={"lines": random.randint(5, 60),
                               "visibility": "internal"})
        logger.info(f"[{self.author.username}] документация в {repo}")
        return True


class BacklogGrooming:
    """Метки и вехи — рутина планирования, которой в журнале не было вовсе."""

    def __init__(self, author, lead=None, state=None):
        self.author = author

    def run(self):
        repo = _repo()
        for _ in range(random.randint(1, 4)):
            events.emit("label_change", actor=self.author.username, role=self.author.role,
                        project=repo, message="triage: метки",
                        extra={"label": random.choice(["bug", "detection", "tech-debt",
                                                       "false-positive", "urgent", "research"]),
                               "added": random.random() < 0.7})
        if random.random() < 0.4:
            events.emit("milestone_update", actor=self.author.username, role=self.author.role,
                        project=repo, message="планирование спринта",
                        extra={"milestone": f"Sprint {random.randint(30, 48)}"})
        logger.info(f"[{self.author.username}] разбор бэклога в {repo}")
        return True


class PipelineBabysitting:
    """QA и SRE нянчат сборки: перезапуск, отмена, выгрузка артефактов."""

    def __init__(self, author, lead=None, state=None):
        self.author = author

    def run(self):
        repo = _repo()
        r = random.random()
        if r < 0.45:
            events.emit("pipeline_retry", actor=self.author.username, role=self.author.role,
                        project=repo, message="перезапуск упавшей сборки",
                        extra={"failed_job": random.choice(["sigma-lint", "rule-tests",
                                                            "ecs-validate", "unit"]),
                               "attempt": random.randint(2, 3)})
        elif r < 0.7:
            events.emit("artifact_download", actor=self.author.username, role=self.author.role,
                        project=repo, message="скачал артефакты сборки",
                        extra={"size_mb": random.randint(1, 40), "internal": True})
        elif r < 0.9:
            events.emit("environment_deploy", actor=self.author.username, role=self.author.role,
                        project=repo, message="выкатка в staging",
                        extra={"target_env": "staging", "manual_trigger": False})
        else:
            events.emit("pipeline_cancel", actor=self.author.username, role=self.author.role,
                        project=repo, message="отменил сборку: не та ветка",
                        extra={"reason": "wrong_branch"})
        logger.info(f"[{self.author.username}] работа со сборками в {repo}")
        return True


class AccessHousekeeping:
    """Штатная работа с доступами: состав участников и защита веток.

    Без неё `member_add`, `member_remove` и `protected_branch_update`
    встречались бы только в атаке, и правило по имени действия ловило бы
    метку. Здесь всё то же самое, но с нормальными атрибутами: права не выше
    Developer, защита ветки усиливается, а не снимается.
    """

    def __init__(self, author, lead=None, state=None):
        self.author = author

    def run(self):
        repo = _repo()
        r = random.random()
        team = [u for u in config.USERS if config.USERS[u].get("role") != "bot"]
        who = random.choice(team) if team else self.author.username
        if r < 0.4:
            events.emit("member_add", actor=self.author.username, role=self.author.role,
                        project=repo, message=f"добавил {who} в проект",
                        extra={"for_user": who, "access_level": random.choice([20, 30]),
                               "self_grant": False})
        elif r < 0.6:
            events.emit("member_remove", actor=self.author.username, role=self.author.role,
                        project=repo, message=f"убрал {who}: сменил команду",
                        extra={"for_user": who, "self_grant": False})
        elif r < 0.85:
            events.emit("protected_branch_update", actor=self.author.username, role=self.author.role,
                        project=repo, branch="main",
                        message="усилил защиту ветки",
                        extra={"push_access": "maintainer", "merge_access": "maintainer",
                               "weakened": False, "protected_branch": True})
        else:
            events.emit("variable_update", actor=self.author.username, role=self.author.role,
                        project=repo, message="обновил переменную CI",
                        extra={"masked": True, "protected": True,
                               "key": random.choice(["SIEM_URL", "REGISTRY", "TIMEOUT"])})
        logger.info(f"[{self.author.username}] работа с доступами в {repo}")
        return True


class SecurityHygiene:
    """Гигиена: отзыв старых токенов, снятие ненужных ключей и вебхуков."""

    def __init__(self, author, lead=None, state=None):
        self.author = author

    def run(self):
        repo = _repo()
        r = random.random()
        if r < 0.45:
            events.emit("token_revoke", actor=self.author.username, role=self.author.role,
                        project=repo, message="отозвал просроченный токен",
                        extra={"for_self": True, "age_days": random.randint(60, 400)})
        elif r < 0.75:
            events.emit("deploy_key_remove", actor=self.author.username, role=self.author.role,
                        project=repo, message="снял неиспользуемый deploy-ключ",
                        extra={"unused_days": random.randint(30, 300)})
        else:
            events.emit("hook_delete", actor=self.author.username, role=self.author.role,
                        project=repo, message="убрал вебхук на мёртвый сервис",
                        extra={"host": "old-ci.soc.internal", "external": False})
        logger.info(f"[{self.author.username}] гигиена доступов в {repo}")
        return True


class CrossRepoSweep:
    """Обход нескольких репозиториев: проверка единообразия настроек.

    Команда действительно ходит по всем проектам — раньше почти вся работа
    оседала в двух-трёх репозиториях, и «редкий репозиторий для актора»
    срабатывал на нормальном расширении зоны ответственности.
    """

    def __init__(self, author, lead=None, state=None):
        self.author = author

    def run(self):
        for repo in _repos(random.randint(3, 6)):
            events.emit("api_read", actor=self.author.username, role=self.author.role,
                        project=repo, message="сверка настроек проекта",
                        extra={"api_path": random.choice(["/projects", "/protected_branches",
                                                          "/variables", "/hooks"]),
                               "items_returned": random.randint(1, 25)})
            if random.random() < 0.3:
                events.emit("mirror_sync", actor=self.author.username, role=self.author.role,
                            project=repo, message="синхронизация зеркала",
                            extra={"direction": "pull", "internal": True})
        logger.info(f"[{self.author.username}] обход репозиториев")
        return True


class ExperimentFork:
    """Форк под эксперимент — обычная практика исследователя."""

    def __init__(self, author, lead=None, state=None):
        self.author = author

    def run(self):
        repo = _repo()
        events.emit("fork_repo", actor=self.author.username, role=self.author.role,
                    project=repo, message="форк под эксперимент",
                    extra={"visibility": "internal", "for_self": True})
        events.emit("branch_create", actor=self.author.username, role=self.author.role,
                    project=repo, branch=f"exp/{random.randint(100,999)}",
                    message="ветка эксперимента", extra={"protected_branch": False})
        logger.info(f"[{self.author.username}] эксперимент на форке {repo}")
        return True


# Активность -> класс и роли, которым эта работа свойственна.
# Роли важны не для красоты: разные люди дают разные распределения, и
# поведенческий слой учится на человеке, а не на «команде вообще».
TEAM_ROUTINE = {
    "release_tagging":   {"cls": ReleaseTagging,
                          "roles": ("sre", "devops", "lead")},
    "review_cycle":      {"cls": ReviewCycle,
                          "roles": ("detection_engineer", "ml_engineer",
                                    "junior_analyst", "qa_engineer")},
    "hotfix_port":       {"cls": HotfixPort,
                          "roles": ("detection_engineer", "sre", "devops")},
    "docs_upkeep":       {"cls": DocsUpkeep,
                          "roles": ("tech_writer", "soc_analyst", "junior_analyst")},
    "backlog_grooming":  {"cls": BacklogGrooming,
                          "roles": ("lead", "soc_analyst", "incident_responder")},
    "pipeline_care":     {"cls": PipelineBabysitting,
                          "roles": ("qa_engineer", "sre", "devops")},
    "access_upkeep":     {"cls": AccessHousekeeping,
                          "roles": ("security_architect", "lead", "compliance")},
    "security_hygiene":  {"cls": SecurityHygiene,
                          "roles": ("security_architect", "devops", "sre")},
    "cross_repo_sweep":  {"cls": CrossRepoSweep,
                          "roles": ("compliance", "security_architect", "threat_hunter")},
    "experiment_fork":   {"cls": ExperimentFork,
                          "roles": ("ml_engineer", "threat_hunter", "contractor")},
}
