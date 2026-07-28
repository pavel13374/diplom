"""
SOC Lead агент — Alex Petrov.
Апрувит MR'ы, запрашивает правки, иногда сам пишет правила и инфраструктурные вещи.
"""
import random
import logging
from agents.base import BaseAgent
from content import comments, commit_messages
from config import PROJECTS, DELAYS
from activities import flow

logger = logging.getLogger(__name__)


class LeadAgent(BaseAgent):

    def review_and_merge_mr(self, project_id: int, mr_iid: int,
                             author_agent) -> bool:
        """
        Проводит code review MR:
        - с вероятностью 70% просит правки → автор фиксит → approve
        - с вероятностью 30% сразу approve
        """
        self.think(DELAYS["review_wait"])

        mr = self.gl.get_mr(project_id, mr_iid)
        if not mr or mr.get("state") != "opened":
            self.warn(f"MR !{mr_iid} уже не открыт")
            return False

        branch = mr.get("source_branch", "")
        title  = mr.get("title", "")

        # Иногда MR сначала Draft, потом Ready
        flow.maybe_draft_first(author_agent, project_id, mr_iid, title)
        # Иногда MR закрывают без мёржа (передумали/дубль)
        if flow.maybe_abandon(author_agent, self, project_id, mr_iid):
            return False

        needs_changes = random.random() < 0.70

        if needs_changes:
            # Запрашиваем правки
            review_comment = comments.lead_initial_review(has_issues=True)
            self.comment_mr(project_id, mr_iid, review_comment)
            self.think(DELAYS["agent_think"])

            # Автор отвечает и фиксит
            response = comments.engineer_response(to_review_request=True)
            author_agent.comment_mr(project_id, mr_iid, response)
            author_agent.think(DELAYS["between_commits"])

            # Автор пушит исправление в ту же ветку
            branch = mr.get("source_branch", "")
            if branch:
                rule_slug = branch.split("/")[-1]
                fix_msg = commit_messages.fix_message(rule_slug)
                # Небольшое изменение файла (добавляем комментарий с датой)
                self._push_minor_fix(project_id, branch, fix_msg, author_agent)

            author_agent.think(DELAYS["agent_think"])

            # Иногда второй раунд правок
            if random.random() < 0.30:
                second_comment = random.choice([
                    "Почти готово, но ещё один момент: " + comments.lead_initial_review(True),
                    "Хорошо. Последнее — " + comments.lead_initial_review(True),
                ])
                self.comment_mr(project_id, mr_iid, second_comment)
                author_agent.think(DELAYS["between_commits"])
                response2 = comments.engineer_response(True)
                author_agent.comment_mr(project_id, mr_iid, response2)
                author_agent.think(DELAYS["between_commits"])

            # Финальный approve формируется ниже
            self.think(DELAYS["agent_think"])
            approve_text = comments.lead_approve()

        else:
            # Сразу approve
            approve_text = comments.lead_initial_review(has_issues=False)

        # CI → эмодзи → настоящий approve → merge
        return flow.approve_and_merge(
            self, author_agent, project_id, mr_iid,
            branch=branch, approve_comment=approve_text,
            emoji=random.choice(["thumbsup", "rocket", "white_check_mark"]),
        )

    def _push_minor_fix(self, project_id: int, branch: str,
                        message: str, author_agent) -> bool:
        """Находит файл в ветке и делает минорное изменение."""
        files = self.gl.list_files(project_id, "rules", ref=branch)
        if not files:
            files = self.gl.list_files(project_id, "", ref=branch)

        # Берём первый YAML файл
        yaml_files = [f for f in files if f.endswith(".yml") and "rules/" in f]
        if not yaml_files:
            return False

        target = yaml_files[0]
        content = self.gl.get_file(project_id, target, ref=branch)
        if not content:
            return False

        # Добавляем/обновляем modified: дату
        from datetime import date
        today = date.today().isoformat()
        if "modified:" in content:
            lines = content.split("\n")
            new_lines = []
            for line in lines:
                if line.startswith("modified:"):
                    new_lines.append(f"modified: {today}")
                else:
                    new_lines.append(line)
            new_content = "\n".join(new_lines)
        else:
            new_content = content.replace(
                "date: ", "date: "
            )
            # Вставляем modified после date:
            lines = content.split("\n")
            new_lines = []
            for line in lines:
                new_lines.append(line)
                if line.startswith("date:"):
                    new_lines.append(f"modified: {today}")
            new_content = "\n".join(new_lines)

        return author_agent.push_file(project_id, target, new_content,
                                      message, branch)

    def update_soc_infra(self) -> bool:
        """Lead периодически обновляет soc-infra конфиги."""
        pid    = PROJECTS["soc-infra"]
        branch = self.unique_branch("chore/infra-update")

        updates = [
            {
                "path": "gitlab-runner/config.toml",
                "content": self._runner_config(),
                "msg": "chore(infra): update GitLab Runner concurrent limit",
            },
            {
                "path": "docs/onboarding.md",
                "content": self._onboarding_doc(),
                "msg": "docs: update team onboarding guide",
            },
            {
                "path": "docs/sla.md",
                "content": self._sla_doc(),
                "msg": "docs: update incident SLA table",
            },
        ]

        choice = random.choice(updates)
        self.create_branch(pid, branch)
        self.think()
        self.push_file(pid, choice["path"], choice["content"],
                       choice["msg"], branch)
        self.think()
        mr_iid = self.create_mr(
            pid, branch,
            f"chore: infra maintenance — {choice['msg'][:50]}",
            "Плановое обслуживание инфраструктуры SOC-команды.",
            self.user_id,
        )
        if mr_iid:
            self.think(DELAYS["review_wait"])
            self.comment_mr(pid, mr_iid, "Self-review: всё корректно. Merge.")
            self.merge_mr(pid, mr_iid)
        return bool(mr_iid)

    def _runner_config(self) -> str:
        random.choice([4, 6, 8])
        return """concurrent = {concurrent}
check_interval = 0
shutdown_timeout = 0

[session_server]
  session_timeout = 1800

[[runners]]
  name = "soc-runner-01"
  url = "https://gitlab.polenov.ru"
  token = "__REGISTER_ME__"
  executor = "docker"
  [runners.docker]
    image = "python:3.11-slim"
    privileged = false
    disable_entrypoint_overwrite = false
    disable_cache = false
    volumes = ["/cache", "/var/run/docker.sock:/var/run/docker.sock"]
    shm_size = 0

[[runners]]
  name = "soc-runner-02"
  url = "https://gitlab.polenov.ru"
  token = "__REGISTER_ME__"
  executor = "docker"
  [runners.docker]
    image = "python:3.11-slim"
    privileged = false
    volumes = ["/cache"]
"""

    def _onboarding_doc(self) -> str:
        return """# SOC Team Onboarding Guide

**Обновлено:** {date.today().isoformat()}
**Автор:** {self.name}

## Репозитории

| Репо                  | Назначение                          | Доступ         |
|-----------------------|-------------------------------------|----------------|
| detection-rules       | Sigma правила корреляции            | Developer      |
| normalization-rules   | Парсеры и нормализаторы             | Developer      |
| playbooks             | Плейбуки реагирования               | Developer      |
| ml-anomaly-engine     | ML-система (anna.smirnova)          | Developer      |
| soc-infra             | Инфраструктура                      | Maintainer     |
| soc-secrets           | Секреты — ТОЛЬКО Lead + CI/CD       | Owner/Bot      |

## Workflow

1. Создай ветку `feat/<название>` от `main`
2. Напиши правило + тестовый семпл
3. Открой MR → assignee: alex.petrov
4. CI должен быть зелёным прежде чем просить review
5. После merge — мониторим first 14 days

## Инструменты

- Sigma CLI: `pip install sigma-cli`
- Тестирование: `python3 tests/test_rules.py`
- Валидация: `python3 tests/validate_rules.py`

## Контакты

- Lead: @alex.petrov (Telegram: @alexsoc)
- On-call: ротация еженедельно, расписание в Confluence
"""

    def _sla_doc(self) -> str:
        return """# Incident Response SLA

## Метрики

| Severity | MTTD     | MTTR     | Эскалация      |
|----------|----------|----------|----------------|
| Critical | < 5 мин  | < 15 мин | CISO + CTO     |
| High     | < 15 мин | < 1 час  | SOC Lead       |
| Medium   | < 1 час  | < 4 часа | Detection Eng  |
| Low      | < 4 часа | < 24 ч   | Self-assigned  |

## Определения

**MTTD** — Mean Time To Detect (от возникновения до обнаружения)
**MTTR** — Mean Time To Respond (от обнаружения до сдерживания)

## Дежурства

- Будни 09:00-21:00 МСК — полная команда
- Ночь и выходные — on-call ротация (1 человек)
- Critical ночью — автоматический звонок через PagerDuty
"""
