"""
Активность: депрекейт и удаление устаревшего правила.
Правило отжило своё → создаём ветку, удаляем файл правила,
кладём заметку в архив, открываем MR на удаление, lead апрувит.
"""
import random
import logging
import config
from datetime import date
from config import PROJECTS, USERS, DELAYS
from content import commit_messages as cm, comments

logger = logging.getLogger(__name__)


class DeprecateRuleActivity:
    """Выводим правило из эксплуатации (удаление + архивная заметка)."""

    def __init__(self, author_agent, lead_agent, state=None, target=None):
        self.author = author_agent
        self.lead   = lead_agent
        self.state  = state
        self.target = target
        self.pid    = config.populated_rule_repo(author_agent.gl)

    def run(self) -> bool:
        all_files  = self.author.gl.list_files(self.pid, "rules")
        rule_files = [f for f in all_files if f.endswith(".yml")]
        # Не трогаем совсем свежий репозиторий — оставляем минимум правил
        if len(rule_files) < 8:
            self.author.log("Too few rules to deprecate, skipping")
            return False

        if self.target and self.target in rule_files:
            target = self.target
        else:
            target = random.choice(rule_files)
        slug   = target.split("/")[-1].replace(".yml", "")
        reason = comments.deprecation_reason()

        branch = self.author.unique_branch(f"chore/deprecate-{slug[:18]}")
        self.author.log(f"Deprecating rule: {slug}")

        if not self.author.create_branch(self.pid, branch):
            return False
        self.author.think()

        # Удаляем правило и кладём архивную заметку одним коммитом
        archive_path = f"archive/{slug}_DEPRECATED.md"
        note = self._archive_note(slug, target, reason)
        actions = [
            {"action": "delete", "file_path": target},
            {"action": "create", "file_path": archive_path, "content": note},
        ]
        ok = self.author.gl.create_commit(
            self.pid, branch, cm.deprecate_message(slug),
            actions, self.author.token,
        )
        if not ok:
            self.author.warn("deprecate commit failed")
            return False
        self.author.commit_pause()

        lead_id = USERS["alex.petrov"]["id"]
        mr_iid  = self.author.create_mr(
            self.pid, branch,
            f"chore({slug}): deprecate and remove rule",
            f"## Депрекейт правила `{slug}`\n\n**Причина:** {reason}\n\n"
            f"Правило удалено из `rules/`, заметка перенесена в `archive/`.\n\n"
            f"- [x] Подтверждено отсутствие активных алертов\n"
            f"- [ ] Запись добавлена в CHANGELOG",
            lead_id,
        )
        if not mr_iid:
            return False

        self.lead.think(DELAYS["review_wait"])
        from activities import flow
        ok = flow.approve_and_merge(
            self.lead, self.author, self.pid, mr_iid, branch=branch,
            approve_comment=comments.deprecation_review(), emoji="wave",
        )
        if ok and self.state:
            self.state.remove_rule(slug)
        return ok

    def _archive_note(self, slug: str, path: str, reason: str) -> str:
        return f"""# DEPRECATED: {slug}

**Удалено:** {date.today().isoformat()}
**Автор депрекейта:** {self.author.name}
**Бывший путь:** `{path}`

## Причина вывода из эксплуатации

{reason}

## Заметки

- История правила доступна в git log.
- При необходимости восстановления — создать новую ветку и переоткрыть
  через активность recreate с учётом причины депрекейта.
"""
