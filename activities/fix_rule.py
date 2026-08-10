"""
Активность: фикс существующего правила.
Находит правило в main, создаёт hotfix/feat ветку, вносит улучшение.
"""
import random
import logging
import config
from config import USERS, DELAYS
from content import commit_messages as cm, comments, rules as rc

logger = logging.getLogger(__name__)


class FixRuleActivity:
    """Инженер замечает проблему в правиле и фиксит её."""

    def __init__(self, author_agent, lead_agent, state=None, target=None):
        self.author = author_agent
        self.lead   = lead_agent
        self.state  = state
        self.target = target
        self.pid    = config.populated_rule_repo(author_agent.gl)

    def run(self) -> bool:
        # Получаем список существующих правил
        all_files = self.author.gl.list_files(self.pid, "rules")
        rule_files = [f for f in all_files if f.endswith(".yml")]
        if not rule_files:
            self.author.log("No existing rules to fix, skipping")
            return False

        if self.target and self.target in rule_files:
            target_path = self.target
        else:
            target_path = random.choice(rule_files)
        slug        = target_path.split("/")[-1].replace(".yml", "")
        content     = self.author.gl.get_file(self.pid, target_path)
        if not content:
            return False

        fix_type = random.choice([
            "add_filter",
            "add_reference",
            "tighten_level",
            "add_fp",
            "add_modified_date",
        ])

        branch_prefix = "hotfix" if random.random() < 0.5 else "fix"
        branch = self.author.unique_branch(f"{branch_prefix}/{slug[:20]}")

        self.author.log(f"Fixing rule: {slug} ({fix_type})")

        # 1. Создаём ветку
        if not self.author.create_branch(self.pid, branch):
            return False
        self.author.think()

        # 2. Применяем фикс
        new_content = rc.generate_rule_update(content, fix_type, self.author.username)
        fix_what    = random.choice([
            "system accounts", "backup agents", "package managers",
            "monitoring tools", "helpdesk processes",
        ])
        msg = cm.fix_message(slug, fix_what)
        if not self.author.push_file(self.pid, target_path, new_content, msg, branch):
            return False
        self.author.commit_pause()

        # 3. Иногда добавляем доп. коммит — обновляем тестовый семпл
        if random.random() < 0.40:
            sample_path = f"tests/samples/{slug}_updated.json"
            sample      = self._updated_sample(slug)
            self.author.push_file(
                self.pid, sample_path, sample,
                f"test({slug}): add updated sample covering fix scenario",
                branch,
            )
            self.author.commit_pause()

        # 4. Открываем MR
        is_hotfix   = branch_prefix == "hotfix"
        title       = f"{'🔥 ' if is_hotfix else ''}fix({slug}): {fix_what} filter"
        lead_id     = USERS["alex.petrov"]["id"]
        desc        = self._mr_desc(slug, fix_type, fix_what, is_hotfix)

        mr_iid = self.author.create_mr(self.pid, branch, title, desc, lead_id)
        if not mr_iid:
            return False

        # 5. Review — hotfix'ы апрувятся быстрее
        if is_hotfix:
            self.lead.think(DELAYS["agent_think"])
            from activities import flow
            ok = flow.approve_and_merge(
                self.lead, self.author, self.pid, mr_iid, branch=branch,
                approve_comment=comments.hotfix_review(), emoji="fire",
            )
        else:
            ok = self.lead.review_and_merge_mr(self.pid, mr_iid, self.author)

        if ok and self.state and self.state.get_rule(slug):
            r = self.state.get_rule(slug)
            self.state.update_rule(
                slug, noisy=False,
                fp_rate=max(0, r.get("fp_rate", 10) - random.randint(5, 15)),
            )
        return ok

    def _updated_sample(self, slug: str) -> str:
        import json
        return json.dumps({
            "EventID":         "4688",
            "Computer":        f"WORKSTATION-{random.randint(1,20):02d}",
            "SubjectUserName": random.choice(["jsmith", "kdavis", "mwilson"]),
            "NewProcessName":  f"C:\\Windows\\Temp\\tool_{slug[:10]}.exe",
            "CommandLine":     "--scan --output C:\\temp\\out.txt",
            "expected_match":  True,
            "rule":            slug,
            "note":            "Updated after false positive fix",
        }, indent=2)

    def _mr_desc(self, slug: str, fix_type: str,
                 fix_what: str, is_hotfix: bool) -> str:
        urgency = "🔥 **HOTFIX — требует срочного merge**\n\n" if is_hotfix else ""
        return f"""{urgency}## Фикс правила `{slug}`

**Тип изменения:** {fix_type.replace('_', ' ')}
**Причина:** {fix_what} вызывают ложные срабатывания в prod

### Изменения
- Добавлен фильтр для исключения {fix_what}
- Обновлена дата `modified:`
- Добавлен тестовый семпл для покрытия сценария фикса

### Проверка
- [ ] False positive rate снизится
- [ ] Легитимные атаки всё ещё детектируются
"""
