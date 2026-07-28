"""
Активность: триаж ложного срабатывания.
Аналитик разбирает алерт, фиксирует вердикт, при необходимости —
заводит быстрый фикс-фильтр в правило.
"""
import random
import logging
import config
from datetime import datetime
from config import PROJECTS, USERS, DELAYS
from content import rules as rc, commit_messages as cm, comments

logger = logging.getLogger(__name__)


class TriageFalsePositiveActivity:
    """Разбор алерта: вердикт FP/TP + опциональный hotfix-фильтр."""

    def __init__(self, author_agent, lead_agent):
        self.author = author_agent
        self.lead   = lead_agent
        self.pid    = config.populated_rule_repo(author_agent.gl)

    def run(self) -> bool:
        files = self.author.gl.list_files(self.pid, "rules")
        ymls  = [f for f in files if f.endswith(".yml")]
        if not ymls:
            return False

        target = random.choice(ymls)
        slug   = target.split("/")[-1].replace(".yml", "")
        verdict = random.choices(
            ["false_positive", "true_positive", "benign_true"],
            weights=[0.6, 0.2, 0.2],
        )[0]

        branch = self.author.unique_branch(f"triage/{slug[:18]}")
        self.author.log(f"Triage alert for {slug}: {verdict}")

        if not self.author.create_branch(self.pid, branch):
            return False
        self.author.think()

        # Заметка триажа
        note_path = f"triage/{datetime.now().strftime('%Y%m%d')}_{slug[:20]}.md"
        note = self._triage_note(slug, verdict)
        if not self.author.push_file(self.pid, note_path, note,
                                     f"docs(triage): verdict for {slug} alert", branch):
            return False
        self.author.commit_pause()

        # Если FP — заодно правим правило (быстрый фильтр)
        did_fix = False
        if verdict == "false_positive":
            content = self.author.gl.get_file(self.pid, target)
            if content:
                fixed = rc.generate_rule_update(content, "add_fp", self.author.username)
                self.author.push_file(
                    self.pid, target, fixed,
                    cm.fix_message(slug, "triaged benign source"), branch,
                )
                self.author.commit_pause()
                did_fix = True

        lead_id = USERS["alex.petrov"]["id"]
        vmap = {"false_positive": "False Positive",
                "true_positive": "True Positive",
                "benign_true": "Benign True Positive"}
        mr_iid = self.author.create_mr(
            self.pid, branch,
            f"docs(triage): {slug} — {vmap[verdict]}",
            f"## Триаж алерта `{slug}`\n\n**Вердикт:** {vmap[verdict]}\n\n"
            + ("Добавлен фильтр легитимного источника.\n" if did_fix else "")
            + f"\n{comments.incident_status_note()}",
            lead_id,
        )
        if not mr_iid:
            return False

        self.lead.think(DELAYS["agent_think"])
        if verdict == "true_positive":
            self.lead.comment_mr(self.pid, mr_iid,
                                 "True positive — эскалируем в IR. Заметку мержим.")
        else:
            self.lead.comment_mr(self.pid, mr_iid,
                                 random.choice(["Согласен с вердиктом. Merge.",
                                                "Ок, фильтр разумный. Approve."]))
        return self.lead.merge_mr(self.pid, mr_iid)

    def _triage_note(self, slug: str, verdict: str) -> str:
        host = f"WORKSTATION-{random.randint(1,40):02d}"
        user = random.choice(["jsmith", "alee", "mwilson", "kdavis", "svc-backup", "svc-sccm"])
        return """# Alert Triage: {slug}

**Время:** {datetime.now().strftime('%Y-%m-%d %H:%M')}
**Аналитик:** {self.author.name}
**Хост:** {host}
**Пользователь:** {user}
**Вердикт:** {verdict.replace('_', ' ').title()}

## Анализ
{comments.incident_status_note()}

## Действия
- [{'x' if verdict=='false_positive' else ' '}] Добавлен фильтр в правило
- [{'x' if verdict=='true_positive' else ' '}] Эскалация в IR
- [x] Вердикт зафиксирован в тикете
"""
