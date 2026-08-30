"""
Активность: откат проблемного правила.
Самый реалистичный сценарий — правило задеплоили, оно шумит, откатываем.
"""
import random
import logging
from datetime import datetime, timezone

import config
from config import USERS, DELAYS
from content import commit_messages as cm, comments

logger = logging.getLogger(__name__)


class RevertRuleActivity:
    """
    Правило оказалось плохим — Lead или инженер откатывает его.
    Создаёт revert-коммит прямо в main или через быстрый MR.
    """

    def __init__(self, author_agent, lead_agent, state=None,
                 target_slug=None, reason=None):
        self.author = author_agent
        self.lead   = lead_agent
        self.state  = state
        self.target_slug = target_slug   # отложенный revert из стейта
        self.preset_reason = reason
        self.pid    = config.repo_id("detection-rules")

    def run(self) -> bool:
        # Отложенный revert по конкретному правилу из стейта
        if self.target_slug:
            sha   = "deadbeefcafe"
            title = f"feat: {self.target_slug} detection rule"
        else:
            # Получаем последние коммиты — ищем недавно задеплоенное правило
            commits = self.lead.gl.get_commits(self.pid, per_page=15)
            feat_commits = [
                c for c in commits
                if any(c.get("title", "").startswith(p)
                       for p in ["feat:", "feat("])
            ]
            if not feat_commits:
                self.lead.log("No recent feat commits to revert, skipping")
                return False

            target = random.choice(feat_commits[:5])
            sha    = target.get("id", "")
            title  = target.get("title", "unknown")
            if not sha:
                return False

        self.lead.log(f"Reverting bad rule: {title[:60]}")

        # Lead объясняет причину в комментарии (имитируем через commit в infra)
        reason    = self.preset_reason or comments.revert_reason()
        followup  = comments.revert_followup()

        # Создаём revert через ветку для реалистичности
        branch    = self.lead.unique_branch("revert")
        revert_msg = cm.revert_message({"tactic": "detection", "title": title[:40]})

        if not self.lead.create_branch(self.pid, branch):
            return False
        self.lead.think()

        # Добавляем revert-файл с объяснением
        revert_note_path = f"docs/reverts/{sha[:8]}_revert_note.md"
        revert_note = self._revert_note(title, sha, reason, followup)
        self.lead.push_file(self.pid, revert_note_path,
                            revert_note, revert_msg, branch)
        self.lead.commit_pause()

        # Открываем MR с пометкой revert
        mr_iid = self.lead.create_mr(
            self.pid, branch,
            f"revert: {title[:60]}",
            f"**Причина отката:**\n\n{reason}\n\n**Следующие шаги:**\n\n{followup}",
            USERS["alex.petrov"]["id"],
        )
        if not mr_iid:
            return False

        # Автор реагирует
        self.author.think(DELAYS["agent_think"])
        self.author.comment_mr(self.pid, mr_iid, followup)

        # Lead быстро мержит revert
        self.lead.think(DELAYS["agent_think"])
        self.lead.react(self.pid, mr_iid, "fire")
        self.lead.comment_mr(self.pid, mr_iid,
                              "Откатываем срочно, разбираться будем потом.")
        ok = self.lead.merge_mr(self.pid, mr_iid)
        if ok and self.state:
            slug = self.target_slug or title.split(":")[-1].strip()[:40]
            self.state.clear_revert(slug)
            # правило ушло с прода — помечаем как откатанное (кандидат на recreate)
            if self.state.get_rule(slug):
                self.state.update_rule(slug, status="reverted", noisy=True)
        return ok

    def _revert_note(self, title: str, sha: str,
                     reason: str, followup: str) -> str:
        return f"""# Revert Note: {title[:60]}

**Commit SHA:** `{sha[:12]}`
**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}
**Author:** {self.lead.name}

## Причина отката

{reason}

## Следующие шаги

{followup}

## TODO

- [ ] Исправить проблему в новой ветке
- [ ] Провести повторное тестирование на prod-данных
- [ ] Открыть новый MR с исправленной версией
"""
