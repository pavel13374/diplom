"""
Активность: сюжетная кампания (storyline).
Связывает несколько действий в одну историю реагирования:
выходит CVE / активизируется группировка → threat intel → новое правило
детекта → обновление плейбука → запись в дашборд/постмортем.

Переиспользует существующие активности, чтобы всё выглядело как реальная
скоординированная работа отдела вокруг одного тикета.
"""
import random
import logging
from config import PROJECTS, USERS, DELAYS, FEATURES
from content import rules as rc, comments
from activities import flow
import simclock

logger = logging.getLogger(__name__)


class CampaignActivity:
    """Многошаговая кампания вокруг одной угрозы."""

    def __init__(self, agents: dict, lead_agent, state=None):
        self.agents = agents
        self.lead   = lead_agent
        self.state  = state
        self.pid    = PROJECTS["detection-rules"]

    def _eng(self):
        return random.choice([self.agents["maria.ivanova"],
                              self.agents["dmitry.kozlov"]])

    def run(self) -> bool:
        if not FEATURES.get("campaigns"):
            return False

        actor = comments.random_actor()
        cve   = comments.random_cve()
        tech  = rc.random_technique()
        camp_id = self.state.next_campaign() if self.state else random.randint(1, 99)
        anna  = self.agents["anna.smirnova"]
        eng   = self._eng()

        logger.info(f"[campaign #{camp_id}] {actor} / {cve} → {tech['title']}")

        # 1. Трекинг-тикет кампании
        issue_iid = self.lead.create_issue(
            self.pid,
            f"[Campaign #{camp_id}] {actor} — {cve}",
            f"## Координация реагирования\n\n**Группировка:** {actor}\n"
            f"**Уязвимость:** {cve}\n**Ключевая техника:** {tech['title']} ({tech['id']})\n\n"
            f"### План\n- [ ] Threat intel: IOC\n- [ ] Правило детекта\n"
            f"- [ ] Плейбук реагирования\n- [ ] Дашборд/постмортем",
            labels=["type::campaign", f"severity::{random.choice(['high','critical'])}"])
        if not issue_iid:
            return False

        # 2. Threat intel — добавляем IOC (anna)
        from activities.threat_intel import ThreatIntelActivity
        anna.comment_issue(self.pid, issue_iid,
                           f"Беру threat intel. {comments.threat_intel_comment()}")
        ThreatIntelActivity(anna, self.lead).run()
        simclock.sleep(DELAYS["between_commits"])

        # 3. Правило детекта под ключевую технику (инженер)
        from activities.new_rule import NewRuleActivity
        eng.comment_issue(self.pid, issue_iid,
                          f"Пишу правило под {tech['id']} по индикаторам кампании.")
        NewRuleActivity(eng, self.lead, state=self.state, technique=tech).run()
        simclock.sleep(DELAYS["between_commits"])

        # 4. Плейбук реагирования
        from activities.update_playbook import UpdatePlaybookActivity
        UpdatePlaybookActivity(eng, self.lead).run()
        simclock.sleep(DELAYS["between_commits"])

        # 5. Итог в тикете + закрытие
        self.lead.think(DELAYS["agent_think"])
        self.lead.react(self.pid, issue_iid, "rocket", target_type="issues") \
            if hasattr(self.lead, "react") else None
        self.lead.comment_issue(
            self.pid, issue_iid,
            f"Кампания #{camp_id} отработана: IOC добавлены, правило на проде, "
            f"плейбук обновлён. Мониторим срабатывания по {actor.split(' ')[0]}.")
        self.lead.close_issue(self.pid, issue_iid)
        logger.info(f"[campaign #{camp_id}] завершена")
        return True
