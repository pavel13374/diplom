"""
Активность: массовое техническое обслуживание.
Раз в какое-то время команда делает «большой» MR: миграция схемы,
массовое обновление тегов/ECS, добавление CI-гейта и т.п.
"""
import random
import logging
from datetime import date
from config import PROJECTS, USERS, DELAYS
from content import commit_messages as cm

logger = logging.getLogger(__name__)


class BulkMaintenanceActivity:
    """Крупное обслуживание репозитория правил (делает обычно Lead/anna)."""

    def __init__(self, author_agent, lead_agent):
        self.author = author_agent
        self.lead   = lead_agent
        self.pid    = PROJECTS["detection-rules"]

    def run(self) -> bool:
        kind = random.choice([
            ("ci_gate",   "ci/sigma-lint-gate"),
            ("schema",    "chore/sigma-2.0-migration"),
            ("ecs_bump",  "chore/ecs-8.11-mapping"),
            ("tag_norm",  "chore/tag-normalization"),
        ])
        change, branch_base = kind
        branch = self.author.unique_branch(branch_base)
        self.author.log(f"Bulk maintenance: {change}")

        if not self.author.create_branch(self.pid, branch):
            return False
        self.author.think()

        if change == "ci_gate":
            path = ".gitlab-ci.yml"
            content = self._ci_yaml()
            title = "chore(ci): add sigma-lint gate to pipeline"
        else:
            path = f"docs/migrations/{date.today().isoformat()}_{change}.md"
            content = self._migration_doc(change)
            title = cm.bulk_message()

        if not self.author.push_file(self.pid, path, content,
                                     cm.bulk_message(), branch):
            return False
        self.author.commit_pause()

        # Имитация затронутых файлов в описании
        affected = random.randint(8, 60)
        lead_id = USERS["alex.petrov"]["id"]
        mr_iid  = self.author.create_mr(
            self.pid, branch, title,
            f"## Массовое обслуживание\n\n**Тип:** {change}\n"
            f"**Затронуто файлов:** ~{affected}\n\n"
            f"Большой технический MR. Прошу внимательный review — "
            f"меняется поведение для всего набора правил.\n\n"
            f"- [x] CI зелёный\n- [ ] Прогон sigma check на всём наборе\n"
            f"- [ ] Бэкап ветки сделан",
            lead_id,
        )
        if not mr_iid:
            return False

        # Крупные MR ревьюят дольше и тщательнее
        self.lead.think(DELAYS["review_wait"] * 1.5)
        self.lead.comment_mr(self.pid, mr_iid,
                             "Большое изменение — прогнал локально, регрессий не вижу. "
                             "Мержим в начале дня, мониторим pipeline.")
        self.lead.think(DELAYS["merge_wait"])
        return self.lead.merge_mr(self.pid, mr_iid)

    def _ci_yaml(self) -> str:
        return """stages:
  - validate
  - test
  - deploy

sigma-lint:
  stage: validate
  image: python:3.11-slim
  before_script:
    - pip install sigma-cli pyyaml
  script:
    - sigma check rules/
    - python3 tests/validate_rules.py
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'

rule-tests:
  stage: test
  image: python:3.11-slim
  script:
    - python3 tests/test_rules.py
  needs: ["sigma-lint"]

deploy-staging:
  stage: deploy
  script:
    - echo "Deploying validated rules to staging SIEM"
  rules:
    - if: '$CI_COMMIT_BRANCH == "main"'
"""

    def _migration_doc(self, change: str) -> str:
        return f"""# Migration: {change}

**Дата:** {date.today().isoformat()}
**Автор:** {self.author.name}

## Что меняется
Массовое обновление набора правил: `{change}`.

## План
1. Прогон скрипта миграции на копии репозитория
2. Валидация через `sigma check`
3. Code review всей командой
4. Merge в начале рабочего дня + мониторинг pipeline

## Откат
В случае проблем — revert MR, ветка-бэкап сохранена.
"""
