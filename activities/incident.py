"""
Активность: отработка инцидента (on-call).
Создаём отчёт по инциденту в playbooks/incidents, проходим по этапам
containment → investigation → eradication, lead закрывает с lessons learned.
Эта активность также используется как «ночное дежурство» вне рабочих часов.
"""
import random
import logging
from datetime import datetime
from config import PROJECTS, USERS, DELAYS
from content import commit_messages as cm, comments

logger = logging.getLogger(__name__)


class IncidentActivity:
    """Полный мини-цикл реагирования на инцидент."""

    def __init__(self, author_agent, lead_agent):
        self.author = author_agent
        self.lead   = lead_agent
        self.pid    = PROJECTS["playbooks"]

    def run(self) -> bool:
        title = comments.incident_title()
        sev   = comments.incident_severity()
        inc_id = f"INC-{random.randint(1000, 9999)}"

        slug   = title.lower().split()[0]
        branch = self.author.unique_branch(f"ir/{inc_id.lower()}")
        self.author.log(f"Handling incident {inc_id} ({sev}): {title}")

        if not self.author.create_branch(self.pid, branch):
            return False
        self.author.think()

        report_path = f"incidents/{datetime.now().strftime('%Y%m')}/{inc_id}.md"
        report = self._incident_report(inc_id, title, sev)
        if not self.author.push_file(self.pid, report_path, report,
                                     cm.incident_message(sev), branch):
            return False
        self.author.commit_pause()

        lead_id = USERS["alex.petrov"]["id"]
        mr_iid  = self.author.create_mr(
            self.pid, branch,
            f"docs(ir): {inc_id} — {title[:50]} [{sev}]",
            f"## {inc_id}: {title}\n\n**Severity:** {sev}\n\n"
            "Отчёт по инциденту, отработанному дежурным.\n\n"
            f"{comments.incident_status_note()}",
            lead_id,
        )
        if not mr_iid:
            return False

        # Несколько шагов расследования как комментарии в MR
        steps = random.randint(2, 4)
        for _ in range(steps):
            self.author.think(DELAYS["incident_step"])
            self.author.comment_mr(self.pid, mr_iid, comments.incident_status_note())

        self.lead.think(DELAYS["agent_think"])
        if sev in ("High", "Critical"):
            self.lead.comment_mr(self.pid, mr_iid,
                                 "Подтверждаю severity. Запускаем IR-процесс, "
                                 "пострадавшие системы под наблюдением. Merge отчёта.")
        else:
            self.lead.comment_mr(self.pid, mr_iid,
                                 random.choice(["Отработано корректно. Merge.",
                                                "Closed. Lessons learned добавь в плейбук.",
                                                "Approve, инцидент закрыт."]))
        return self.lead.merge_mr(self.pid, mr_iid)

    def _incident_report(self, inc_id: str, title: str, sev: str) -> str:
        host = f"WORKSTATION-{random.randint(1,40):02d}"
        return """# Incident Report {inc_id}

**Заголовок:** {title}
**Severity:** {sev}
**Обнаружено:** {datetime.now().strftime('%Y-%m-%d %H:%M')}
**Дежурный:** {self.author.name}
**Затронутый хост:** {host}

---

## 1. Обнаружение
Сработала детекция SOC. Алерт принят в работу дежурным аналитиком.

## 2. Сдерживание (Containment)
- [x] Хост изолирован через EDR
- [x] Сессии пользователя завершены
- [ ] Сетевые индикаторы добавлены в blocklist

## 3. Расследование (Investigation)
- Собран триаж-пакет (процессы, сетевые соединения, автозагрузка)
- Построен таймлайн за 48 часов до алерта
- Проверка lateral movement: {random.choice(['не выявлено', 'выявлено, расширяем scope'])}

## 4. Устранение (Eradication)
- Удалён механизм закрепления
- Скомпрометированные учётки заблокированы, секреты ротированы

## 5. Восстановление и выводы
- Severity: {sev}
- Lessons learned: {comments.incident_status_note()}
"""
