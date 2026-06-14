"""
Дополнительные НОРМАЛЬНЫЕ сценарии — для разнообразия датасета.
CI-переменные, бамп зависимостей, правки документации/wiki.
Всё штатное (is_anomaly=false) — это «фон», на котором редкие аномалии заметны.
"""
import random
import logging
from datetime import date
from config import PROJECTS, USERS, DELAYS
from activities import flow
import simclock
import config

logger = logging.getLogger(__name__)


class CiVariableUpdate:
    """Обновление списка CI/CD-переменных (masked/protected) — без значений секретов."""
    def __init__(self, author, lead):
        self.author = author; self.lead = lead
        self.pid = config.WORK_REPOS[random.choice([n for n in config.WORK_REPOS if n != "soc-secrets"])]

    def run(self):
        names = random.sample(
            ["SIEM_API_URL", "SLACK_WEBHOOK", "REGISTRY_HOST", "DEPLOY_ENV",
             "RUNNER_TAG", "SENTRY_DSN", "ARTIFACT_BUCKET", "TZ"], k=random.randint(2, 4))
        body = "# CI/CD variables (masked & protected, values stored in GitLab settings)\n"
        for n in names:
            body += f"{n}:\n  masked: true\n  protected: true\n  scope: production\n"
        branch = self.author.unique_branch("ci/vars")
        if not self.author.create_branch(self.pid, branch):
            return False
        self.author.think()
        self.author.push_file(self.pid, ".ci/variables.yml", body,
                              "ci: document masked CI/CD variables", branch)
        self.author.commit_pause()
        iid = self.author.create_mr(self.pid, branch, "ci: update CI/CD variables",
                                    "Документируем masked-переменные деплоя.",
                                    USERS["alex.petrov"]["id"])
        if not iid:
            return False
        self.lead.think(DELAYS["agent_think"])
        return flow.approve_and_merge(self.lead, self.author, self.pid, iid, branch=branch,
                                      approve_comment="Переменные masked/protected. Approve.")


class DependencyBump:
    """Бамп версий зависимостей (как Dependabot)."""
    def __init__(self, author, lead):
        self.author = author; self.lead = lead
        self.pid = config.WORK_REPOS[random.choice([n for n in config.WORK_REPOS if n != "soc-secrets"])]

    def run(self):
        pkgs = random.sample(
            ["pyyaml", "requests", "sigma-cli", "elasticsearch", "pandas", "fastapi",
             "urllib3", "pydantic", "numpy", "scikit-learn"], k=random.randint(2, 4))
        lines = [f"{p}=={random.randint(1,3)}.{random.randint(0,20)}.{random.randint(0,9)}"
                 for p in pkgs]
        content = "# dependencies\n" + "\n".join(lines) + "\n"
        branch = self.author.unique_branch("chore/deps")
        if not self.author.create_branch(self.pid, branch):
            return False
        self.author.think()
        self.author.push_file(self.pid, "requirements.txt", content,
                              "chore(deps): bump dependencies", branch)
        self.author.commit_pause()
        iid = self.author.create_mr(self.pid, branch, "chore(deps): bump dependencies",
                                    "Плановое обновление зависимостей.",
                                    USERS["alex.petrov"]["id"])
        if not iid:
            return False
        self.lead.think(DELAYS["agent_think"])
        return flow.approve_and_merge(self.lead, self.author, self.pid, iid, branch=branch,
                                      approve_comment="CI зелёный, обновления безопасны. Merge.")


class DocsWiki:
    """Правки документации / README / wiki-страниц."""
    def __init__(self, author, lead):
        self.author = author; self.lead = lead
        self.pid = config.WORK_REPOS[random.choice([n for n in config.WORK_REPOS if n != "soc-secrets"])]

    def run(self):
        topic = random.choice(["onboarding", "runbook", "architecture", "faq",
                               "naming-conventions", "alert-triage", "incident-response",
                               "siem-pipeline", "detection-coverage", "oncall-rotation",
                               "data-sources", "log-retention", "escalation-matrix",
                               "mitre-mapping", "tuning-guide", "deployment", "glossary"])
        content = (f"# {topic.title().replace('-', ' ')}\n\n"
                   f"_Обновлено {simclock.content_date_iso()} · {self.author.name}_\n\n"
                   "## Обзор\n\nПрактическое руководство для команды SOC.\n\n"
                   "## Шаги\n\n1. Контекст\n2. Действия\n3. Проверка\n\n"
                   "## Ссылки\n\n- Внутренняя вики\n- Confluence\n")
        branch = self.author.unique_branch(f"docs/{topic[:12]}")
        if not self.author.create_branch(self.pid, branch):
            return False
        self.author.think()
        self.author.push_file(self.pid, f"docs/{topic}.md", content,
                              f"docs: update {topic} guide", branch)
        self.author.commit_pause()
        iid = self.author.create_mr(self.pid, branch, f"docs: update {topic}",
                                    "Обновление документации.", USERS["alex.petrov"]["id"])
        if not iid:
            return False
        self.lead.think(DELAYS["agent_think"])
        return flow.approve_and_merge(self.lead, self.author, self.pid, iid, branch=branch,
                                      approve_comment="Полезное обновление доков. Merge.")
