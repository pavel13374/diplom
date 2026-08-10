"""
Активность: пересоздание ранее откатанного/депрекейтнутого правила.
«Создают снова исправленные» — возвращаем детекцию техники, но уже с
учётом прошлых ошибок: с timeframe, порогом и корреляцией.
"""
import random
import logging
import config
from config import USERS, DELAYS
from content import rules as rc, commit_messages as cm, comments

logger = logging.getLogger(__name__)


class RecreateRuleActivity:
    """Re-introduce исправленной версии правила после rework."""

    def __init__(self, author_agent, lead_agent, state=None):
        self.author = author_agent
        self.lead   = lead_agent
        self.state  = state
        self.pid    = config.rule_repo_id()

    def run(self) -> bool:
        # Берём технику, для которой правила сейчас НЕТ (как будто было откатано),
        # либо любую — и делаем "v2" с улучшениями.
        existing = self.author.gl.list_files(self.pid, "rules")
        existing_slugs = {
            f.split("/")[-1].replace(".yml", "") for f in existing if f.endswith(".yml")
        }

        technique = None
        for _ in range(12):
            t = rc.random_technique()
            if rc.make_slug(t["title"]) not in existing_slugs:
                technique = t
                break
        if technique is None:
            technique = rc.random_technique()

        rule_path = rc.get_rule_path(technique)
        slug      = rule_path.split("/")[-1].replace(".yml", "")
        branch    = self.author.unique_branch("feat/recreate", slug[:18])

        self.author.log(f"Recreating fixed rule: {technique['title']}")

        if not self.author.create_branch(self.pid, branch):
            return False
        self.author.think()

        # Улучшенная версия: stable + дополнительные фильтры (учли прошлые грабли)
        improved = rc.generate_sigma_rule(
            technique, self.author.username, status="stable",
            extra_filters=[
                random.choice([
                    'SubjectUserName|endswith: "$"',
                    'ParentImage|contains: "\\\\ccmexec.exe"',
                    'Image|startswith: "C:\\\\Program Files\\\\"',
                ]),
                'User|contains: "svc-"',
            ],
        )
        msg = cm.recreate_message(slug)
        if not self.author.push_file(self.pid, rule_path, improved, msg, branch):
            return False
        self.author.commit_pause()

        # Тестовый семпл + негативный кейс
        sample_path = f"tests/samples/{slug}_v2.json"
        self.author.push_file(
            self.pid, sample_path, rc.generate_test_sample(technique),
            f"test({slug}): add v2 sample after rework", branch,
        )
        self.author.commit_pause()

        lead_id = USERS["alex.petrov"]["id"]
        mr_iid  = self.author.create_mr(
            self.pid, branch,
            f"feat({slug}): re-introduce rule v2 after rework",
            self._mr_desc(technique, slug),
            lead_id,
        )
        if not mr_iid:
            return False

        self.author.think(3)
        self.author.comment_mr(self.pid, mr_iid, comments.recreate_comment())
        self.lead.think(DELAYS["review_wait"])
        from activities import flow
        ok = flow.approve_and_merge(
            self.lead, self.author, self.pid, mr_iid, branch=branch,
            approve_comment=comments.recreate_review(), emoji="rocket",
        )
        if ok and self.state:
            self.state.register_rule(
                slug, rule_path, technique["tactic"],
                status="stable", author=self.author.username,
            )
        return ok

    def _mr_desc(self, technique: dict, slug: str) -> str:
        return f"""## Пересоздание правила (v2): {technique['title']}

Правило ранее выводилось из эксплуатации из-за шума/проблем.
Возвращаем детекцию техники **{technique['id']}** с учётом post-mortem.

### Что исправлено по сравнению с v1
- Добавлены фильтры легитимных сервисных аккаунтов
- Сужено условие срабатывания (корреляция по родителю/пользователю)
- Добавлен v2-семпл и негативный кейс

### Проверка
- [x] Прогон на 2 неделях prod-логов
- [x] FP-рейт в норме
- [ ] Деплой в staging на 3 дня перед прод
"""
