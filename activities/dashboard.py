"""
Активность: обновление дашбордов и метрик покрытия.
Команда поддерживает ATT&CK coverage matrix, FP-рейт отчёты, MTTR-панели.
"""
import random
import logging
from collections import Counter
from datetime import date
import config
from config import PROJECTS, USERS, DELAYS
from content import commit_messages as cm, comments

logger = logging.getLogger(__name__)


class DashboardActivity:
    """Обновление метрик/дашборда покрытия в detection-rules/metrics."""

    def __init__(self, author_agent, lead_agent):
        self.author = author_agent
        self.lead   = lead_agent
        self.pid    = config.repo_id("detection-rules")

    def run(self) -> bool:
        # Считаем покрытие по тактикам на основе реально лежащих правил
        files = self.author.gl.list_files(self.pid, "rules")
        ymls  = [f for f in files if f.endswith(".yml")]
        tactics = Counter()
        for f in ymls:
            parts = f.split("/")
            if len(parts) >= 2:
                tactics[parts[1]] += 1

        kind = random.choice(["coverage", "fp_report", "mttr"])
        if kind == "coverage":
            path    = "metrics/attack_coverage.md"
            content = self._coverage_doc(tactics, len(ymls))
            msg     = "docs(metrics): update ATT&CK coverage matrix"
            title   = "docs(metrics): refresh ATT&CK coverage"
        elif kind == "fp_report":
            path    = f"metrics/fp_report_{date.today().strftime('%Y%W')}.md"
            content = self._fp_report(ymls)
            msg     = "docs(metrics): weekly false-positive report"
            title   = "docs(metrics): weekly FP-rate report"
        else:
            path    = "metrics/mttr.md"
            content = self._mttr_doc()
            msg     = cm.dashboard_message()
            title   = "feat(dashboard): update MTTR-by-severity panel"

        branch = self.author.unique_branch("docs/metrics")
        self.author.log(f"Updating dashboard: {kind}")

        if not self.author.create_branch(self.pid, branch):
            return False
        self.author.think()
        if not self.author.push_file(self.pid, path, content, msg, branch):
            return False
        self.author.commit_pause()

        lead_id = USERS["alex.petrov"]["id"]
        mr_iid  = self.author.create_mr(
            self.pid, branch, title,
            f"Плановое обновление метрик команды.\n\n{comments.dashboard_note()}",
            lead_id,
        )
        if not mr_iid:
            return False

        self.lead.think(DELAYS["agent_think"])
        self.lead.comment_mr(self.pid, mr_iid,
                             random.choice(["Полезные цифры. Merge.",
                                            "Approve, держим метрики в актуальном виде.",
                                            "LGTM."]))
        return self.lead.merge_mr(self.pid, mr_iid)

    def _coverage_doc(self, tactics: Counter, total: int) -> str:
        rows = "\n".join(
            f"| {t.replace('_',' ').title():22} | {c:3} |"
            for t, c in sorted(tactics.items(), key=lambda x: -x[1])
        ) or "| (нет данных) | 0 |"
        return f"""# ATT&CK Coverage Matrix

**Обновлено:** {date.today().isoformat()}
**Всего правил:** {total}

| Tactic                 | Rules |
|------------------------|-------|
{rows}

> Цель квартала: покрыть >=80% актуальных техник из карты угроз компании.
> Провалы по тактикам с малым числом правил — в backlog на разработку.
"""

    def _fp_report(self, ymls: list) -> str:
        sample = random.sample(ymls, k=min(6, len(ymls))) if ymls else []
        rows = "\n".join(
            f"| {s.split('/')[-1].replace('.yml',''):34} | {random.randint(0,80):3} | "
            f"{random.choice(['↓','↑','→'])} |"
            for s in sample
        ) or "| (нет правил) | 0 | → |"
        return f"""# Weekly False-Positive Report

**Неделя:** {date.today().strftime('%Y-W%W')}
**Автор:** {self.author.name}

| Rule                               | FP/нед | Тренд |
|------------------------------------|--------|-------|
{rows}

## Выводы
- Топ-шумные правила вынесены в backlog на тюнинг.
- Правила с 0 FP за 30 дней — кандидаты на promote → production.
"""

    def _mttr_doc(self) -> str:
        return f"""# MTTR / MTTD Dashboard

**Обновлено:** {date.today().isoformat()}

| Severity | MTTD   | MTTR    | SLA      | Статус |
|----------|--------|---------|----------|--------|
| Critical | {random.randint(2,6)} мин | {random.randint(8,15)} мин | < 15 мин | ✅ |
| High     | {random.randint(5,15)} мин | {random.randint(20,55)} мин | < 1 час  | ✅ |
| Medium   | {random.randint(20,55)} мин | {random.randint(1,3)} ч | < 4 часа | ✅ |
| Low      | {random.randint(1,4)} ч | {random.randint(4,20)} ч | < 24 ч  | ✅ |

> Источник: тикет-система IR. Пересчёт еженедельно.
"""
