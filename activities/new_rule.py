"""
Активность: создание нового Sigma-правила.
Полный цикл: ветка → коммиты → MR → review → merge.
"""
import random
import logging
import config
from config import DELAYS, USERS
from content import rules as rc, commit_messages as cm, comments
import simclock

logger = logging.getLogger(__name__)


class NewRuleActivity:
    """
    Один Detection Engineer создаёт новое правило.
    Lead проводит code review.
    """

    def __init__(self, author_agent, lead_agent, state=None, technique=None):
        self.author = author_agent
        self.lead   = lead_agent
        self.state  = state
        self.technique = technique     # можно зафиксировать технику (кампании)
        self.pid    = config.rule_repo_id()

    def run(self) -> bool:
        technique = self.technique or rc.random_technique()
        if not self.technique:
            try:
                existing = {f.split('/')[-1].replace('.yml','')
                            for f in self.author.gl.list_files(self.pid, 'rules')
                            if f.endswith('.yml')}
                for _ in range(10):
                    if rc.make_slug(technique['title']) not in existing:
                        break
                    technique = rc.random_technique()
            except Exception:
                pass
        rule_path = rc.get_rule_path(technique)
        slug      = rule_path.split("/")[-1].replace(".yml", "")
        branch    = self.author.unique_branch("feat", slug[:25])

        self.author.log(f"Starting new rule: {technique['title']}")

        # 1. Создаём ветку
        if not self.author.create_branch(self.pid, branch):
            return False
        self.author.think()

        # 2. Первая версия правила — experimental
        rule_content = rc.generate_sigma_rule(
            technique, self.author.username, status="experimental"
        )
        msg = cm.feat_message(technique)
        if not self.author.push_file(self.pid, rule_path, rule_content, msg, branch):
            return False
        self.author.commit_pause()

        # 3. Тестовый семпл
        sample_path    = f"tests/samples/{slug}.json"
        sample_content = rc.generate_test_sample(technique)
        sample_msg     = f"test({slug}): add sample log for validation"
        self.author.push_file(self.pid, sample_path, sample_content,
                               sample_msg, branch)
        self.author.commit_pause()

        # 4. Иногда автор сам сразу добавляет доп. фикс перед MR
        if random.random() < 0.40:
            self.author.think()
            improved = rc.generate_sigma_rule(
                technique, self.author.username, status="experimental",
                extra_filters=[random.choice([
                    'SubjectUserName|endswith: "$"',
                    'ParentImage|contains: "\\\\msiexec.exe"',
                    'Image|startswith: "C:\\\\Windows\\\\System32\\\\"',
                ])]
            )
            fix_msg = cm.fix_message(slug, "initial filter for known false positives")
            self.author.push_file(self.pid, rule_path, improved, fix_msg, branch)
            self.author.commit_pause()

        # 5. Открываем MR
        lead_id = USERS["alex.petrov"]["id"]
        desc    = self._mr_description(technique)
        mr_iid  = self.author.create_mr(
            self.pid, branch,
            cm.feat_message(technique),
            desc, lead_id,
        )
        if not mr_iid:
            return False

        # 6. Иногда anna добавляет комментарий от себя
        if random.random() < 0.25:
            anna_agents = [a for a in [self.lead] if a.username == "anna.smirnova"]
            if not anna_agents:
                self.author.think(3)
                self.lead.comment_mr(self.pid, mr_iid,
                                     comments.anna_comment())

        # 7. Lead проводит review
        merged = self.lead.review_and_merge_mr(self.pid, mr_iid, self.author)

        # 8. Регистрируем правило в стейте (жизненный цикл)
        if merged and self.state:
            self.state.register_rule(
                slug, rule_path, technique["tactic"],
                status="experimental", author=self.author.username,
            )

        # 9. После merge — иногда сразу продвигаем до stable
        if merged and random.random() < 0.30:
            self._schedule_promote(technique, rule_path, slug)

        return merged

    def _mr_description(self, technique: dict) -> str:
        lines = [
            "## Новое правило детекции",
            "",
            f"**Техника:** {technique['title']}",
            f"**MITRE ATT&CK:** [{technique['id']}](https://attack.mitre.org/techniques/{technique['id'].replace('.', '/')})",
            f"**Tactic:** {technique['tactic']}",
            f"**Severity:** {technique['level']}",
            "",
            "### Описание",
            technique['description'],
            "",
            "### Тестирование",
            "- [ ] Правило протестировано на семплах логов",
            "- [ ] False positives проверены",
            "- [ ] CI pipeline зелёный",
            "",
            "### Checklist",
            "- [x] Sigma-формат валиден",
            "- [x] UUID уникален",
            "- [x] MITRE теги добавлены",
            "- [x] Тестовый семпл добавлен",
        ]
        return "\n".join(lines)

    def _schedule_promote(self, technique: dict, rule_path: str, slug: str):
        """Через некоторое время продвигаем правило до stable."""
        promote_delay = DELAYS["between_activities"] * 2
        logger.info(f"Scheduling promote for {slug} in {promote_delay}s (sim)")
        simclock.sleep(promote_delay)

        branch = self.author.unique_branch("chore/promote", slug[:20])
        if not self.author.create_branch(self.pid, branch):
            return

        content = self.gl_get_and_promote(rule_path)
        if not content:
            return

        self.author.push_file(
            self.pid, rule_path, content,
            cm.promote_message(slug), branch
        )
        self.author.think()

        lead_id = USERS["alex.petrov"]["id"]
        mr_iid = self.author.create_mr(
            self.pid, branch,
            f"chore({slug}): promote to stable after clean run",
            f"Правило {slug} работает 2 недели без false positives. Продвигаем в stable.",
            lead_id,
        )
        if mr_iid:
            self.lead.think(DELAYS["review_wait"])
            self.lead.comment_mr(self.pid, mr_iid,
                                  "Подтверждаю — за 14 дней 0 ложных срабатываний. Approve.")
            self.lead.merge_mr(self.pid, mr_iid)
            if self.state:
                self.state.update_rule(slug, status="stable", fp_rate=random.randint(0, 4))

    def gl_get_and_promote(self, rule_path: str) -> str:
        content = self.author.gl.get_file(self.pid, rule_path)
        if not content:
            return ""
        return rc.generate_rule_update(content, "promote_stable", self.author.username)
