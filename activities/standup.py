"""
Активность: утренний стендап.
Создаёт дневной тикет «Daily Standup {дата}» и каждый присутствующий
инженер оставляет свой апдейт. Lead подводит итог. PTO-сотрудник
не участвует (он в отпуске/болеет).
"""
import logging
import config
from config import FEATURES
from content import comments
import simclock

logger = logging.getLogger(__name__)


class StandupActivity:
    def __init__(self, agents: dict, lead_agent, state=None):
        self.agents = agents
        self.lead   = lead_agent
        self.state  = state
        self.pid    = config.repo_id("soc-infra")

    def run(self) -> bool:
        if not FEATURES.get("standup"):
            return False

        day = simclock.today_iso()
        out_today = self.state.who_is_out_today() if self.state else None
        oncall = self.state.current_oncall() if self.state else None

        title = f"Daily Standup — {day}"
        body = (f"## Стендап {day}\n\n"
                f"**On-call:** @{oncall or 'n/a'}\n"
                + (f"**Отсутствует (PTO):** @{out_today}\n" if out_today else "")
                + "\nКаждый — что сделано / план на день / блокеры.")
        iid = self.lead.create_issue(self.pid, title, body,
                                     labels=["type::standup"])
        if not iid:
            return False

        # Инженеры отмечаются (кроме того, кто в PTO)
        import config
        for uname in config.engineer_usernames():
            if uname == out_today:
                continue
            agent = self.agents.get(uname)
            if not agent:
                continue
            agent.think(2)
            agent.comment_issue(self.pid, iid,
                                f"**{agent.name}:** {comments.standup_note()}")

        self.lead.think(3)
        self.lead.comment_issue(
            self.pid, iid,
            f"**{self.lead.name}:** Спасибо. Приоритет дня — разгрести FP-баги "
            "из спринта и закрыть review-очередь. "
            + (f"@{oncall} на дежурстве." if oncall else ""))
        # Стендап закрываем к концу дня
        self.lead.close_issue(self.pid, iid)
        logger.info(f"[standup] проведён стендап #{iid} ({day})")
        return True
