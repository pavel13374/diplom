"""
Активность: работа с Issues (тикетами).
SOC живёт в тикетах: баг-репорты на FP, фич-реквесты на новые детекты,
задачи из threat intel/пентеста. Лейблы, спринт-майлстоны, триаж,
иногда — закрытие через MR (Closes #N).
"""
import random
import logging
from config import PROJECTS, USERS, DELAYS, FEATURES
from content import rules as rc, comments, commit_messages as cm
from activities import flow

logger = logging.getLogger(__name__)

ISSUE_KINDS = [
    {
        "type": "bug", "color": "#d9534f",
        "titles": [
            "FP: правило {slug} шумит на легитимных админ-скриптах",
            "Ложные срабатывания {slug} от backup-агента",
            "{slug} триггерит на сервисных учётках — нужен фильтр",
        ],
        "labels": ["type::bug", "detection::false-positive"],
    },
    {
        "type": "feature", "color": "#5cb85c",
        "titles": [
            "Нужна детекция: {tech}",
            "Добавить правило под технику {tid}",
            "Закрыть пробел в покрытии: {tactic}",
        ],
        "labels": ["type::feature", "detection::coverage-gap"],
    },
    {
        "type": "intel", "color": "#f0ad4e",
        "titles": [
            "TI-задача: добавить IOC по {actor}",
            "Разобрать кампанию {actor} и смапить на правила",
            "Сигнатуры под {cve}",
        ],
        "labels": ["type::threat-intel"],
    },
    {
        "type": "hardening", "color": "#428bca",
        "titles": [
            "Снизить FP-рейт топ-шумных правил за спринт",
            "Перевести правила {tactic} в ECS-формат",
            "Покрыть тестами правила без негативных семплов",
        ],
        "labels": ["type::tech-debt"],
    },
]

SEVERITY_LABELS = ["severity::low", "severity::medium", "severity::high", "severity::critical"]


class IssueActivity:
    """Создание/триаж тикетов в трекере detection-rules."""

    def __init__(self, author_agent, lead_agent, state=None):
        self.author = author_agent
        self.lead   = lead_agent
        self.state  = state
        self.pid    = PROJECTS["detection-rules"]

    def run(self) -> bool:
        if not FEATURES.get("issues"):
            return False

        kind = random.choice(ISSUE_KINDS)
        tech = rc.random_technique()
        slug_src = None

        # для bug — берём реальное правило из стейта/репо
        if kind["type"] == "bug":
            noisy = self.state.pick_noisy() if self.state else None
            if noisy:
                slug_src = noisy["slug"]
            else:
                ymls = [f for f in self.author.gl.list_files(self.pid, "rules")
                        if f.endswith(".yml")]
                slug_src = (random.choice(ymls).split("/")[-1].replace(".yml", "")
                            if ymls else "some_rule")

        title = random.choice(kind["titles"]).format(
            slug=slug_src or "rule", tech=tech["title"], tid=tech["id"],
            tactic=tech["tactic"], actor=comments.random_actor(),
            cve=comments.random_cve(),
        )

        labels = list(kind["labels"]) + [random.choice(SEVERITY_LABELS), "status::needs-triage"]

        # спринт-майлстон
        milestone_id = 0
        sprint_no = None
        if self.state:
            sprint_no, _ = self.state.ensure_sprint()
            milestone_id = self.author.gl.ensure_milestone(
                self.pid, f"Sprint {sprint_no}", self.author.token)

        self.author.log(f"Открываю issue ({kind['type']}): {title[:50]}")
        desc = self._issue_body(kind["type"], title, tech, slug_src, sprint_no)
        iid = self.author.create_issue(self.pid, title, desc, labels=labels,
                                       milestone_id=milestone_id)
        if not iid:
            return False

        # Триаж лидом/дежурным
        self.lead.think(DELAYS["agent_think"])
        self.lead.comment_issue(self.pid, iid, self._triage_comment(kind["type"]))
        self.lead.gl.update_issue(
            self.pid, iid,
            {"labels": ",".join(l for l in labels if l != "status::needs-triage")
                      + ",status::accepted"},
            self.lead.token)
        self.lead.react and self.lead.gl.award_emoji(
            self.pid, "issues", iid, "eyes", self.lead.token)

        # Иногда сразу чиним багу через MR (Closes #N), иначе — в backlog
        if kind["type"] == "bug" and slug_src and random.random() < 0.5:
            return self._resolve_via_mr(iid, slug_src)

        logger.info(f"[{self.author.username}] issue #{iid} в backlog спринта {sprint_no}")
        return True

    # ------------------------------------------------------------------
    def _resolve_via_mr(self, issue_iid: int, slug: str) -> bool:
        ymls = [f for f in self.author.gl.list_files(self.pid, "rules")
                if f.endswith(".yml")]
        target = next((f for f in ymls if slug in f), None)
        if not target:
            return True  # тикет остаётся открытым

        content = self.author.gl.get_file(self.pid, target)
        if not content:
            return True
        branch = self.author.unique_branch(f"fix/issue-{issue_iid}")
        if not self.author.create_branch(self.pid, branch):
            return True
        self.author.think()
        fixed = rc.generate_rule_update(content, "add_fp", self.author.username)
        self.author.push_file(self.pid, target, fixed,
                              cm.fix_message(slug, "triaged benign source"), branch)
        self.author.commit_pause()

        mr_iid = self.author.create_mr(
            self.pid, branch,
            f"fix({slug}): suppress false positive (Closes #{issue_iid})",
            f"Фикс по тикету #{issue_iid}.\n\nДобавлен фильтр легитимного источника.\n\n"
            f"Closes #{issue_iid}",
            USERS["alex.petrov"]["id"])
        if not mr_iid:
            return True

        self.lead.think(DELAYS["review_wait"])
        ok = flow.approve_and_merge(self.lead, self.author, self.pid, mr_iid,
                                    branch=branch,
                                    approve_comment="Фикс закрывает тикет. Approve.")
        if ok and self.state and self.state.get_rule(slug):
            r = self.state.get_rule(slug)
            self.state.update_rule(slug, noisy=False,
                                   fp_rate=max(0, r.get("fp_rate", 10) - 10))
        return ok

    # ------------------------------------------------------------------
    def _issue_body(self, t, title, tech, slug, sprint_no) -> str:
        sp = f"\n**Спринт:** Sprint {sprint_no}" if sprint_no else ""
        if t == "bug":
            return (f"## Баг: ложные срабатывания\n\n**Правило:** `{slug}`{sp}\n\n"
                    "### Наблюдение\nЗа последние дни правило даёт повышенный FP-рейт.\n\n"
                    "### Ожидаемо\nЛегитимные источники не должны триггерить.\n\n"
                    "- [ ] Подтвердить FP на примерах\n- [ ] Добавить фильтр\n- [ ] Обновить тест")
        if t == "feature":
            return (f"## Запрос детекции{sp}\n\n**Техника:** {tech['title']} ({tech['id']})\n"
                    f"**Tactic:** {tech['tactic']}\n\n{tech['description']}\n\n"
                    "- [ ] Написать правило\n- [ ] Тестовый + негативный семпл\n- [ ] Плейбук")
        if t == "intel":
            return (f"## Threat Intel{sp}\n\nРазобрать актуальную активность и "
                    "смапить индикаторы на наши правила.\n\n"
                    "- [ ] Собрать IOC\n- [ ] Обновить blocklist\n- [ ] Связать с правилами C2")
        return (f"## Технический долг{sp}\n\nПлановая задача на улучшение качества "
                "набора правил.\n\n- [ ] Оценить объём\n- [ ] Выполнить\n- [ ] Обновить метрики")

    def _triage_comment(self, t) -> str:
        return {
            "bug":     "Подтверждаю приоритет. Берём в спринт, нужен фильтр без потери TP.",
            "feature": "Согласен, пробел в покрытии реальный. Ставлю в спринт.",
            "intel":   "Актуально. Дежурный по TI берёт в работу.",
            "hardening": "Полезно для качества. Уходит в backlog спринта.",
        }.get(t, "Принято, берём в работу.")
