"""
Активность: релиз набора правил в конце спринта.
Обновляет CHANGELOG, ставит git-тег и создаёт GitLab Release.
"""
import random
import logging
import config
from config import USERS, FEATURES
from activities import flow
import simclock

logger = logging.getLogger(__name__)


class ReleaseActivity:
    def __init__(self, lead_agent, state=None):
        self.lead  = lead_agent
        self.state = state
        self.pid   = config.repo_id("detection-rules")

    def run(self) -> bool:
        if not FEATURES.get("releases"):
            return False

        version = self.state.next_release() if self.state else f"v1.{random.randint(1,99)}.0"
        sprint_no = self.state.data["sprint_number"] if self.state else "?"
        rule_count = self.state.rule_count() if self.state else 0
        date = simclock.today_iso()

        branch = self.lead.unique_branch("release/notes")
        if not self.lead.create_branch(self.pid, branch):
            return False
        self.lead.think()

        entry = self._changelog(version, sprint_no, rule_count, date)
        existing = self.lead.gl.get_file(self.pid, "CHANGELOG.md") or "# Changelog\n"
        self.lead.push_file(self.pid, "CHANGELOG.md", entry + "\n" + existing,
                            f"docs(changelog): release {version}", branch)
        self.lead.commit_pause()

        mr_iid = self.lead.create_mr(
            self.pid, branch,
            f"release: {version} (Sprint {sprint_no})",
            f"Релиз набора правил **{version}** по итогам спринта {sprint_no}.\n\n"
            f"Активных правил: {rule_count}.",
            USERS["alex.petrov"]["id"])
        if not mr_iid:
            return False

        ok = flow.approve_and_merge(self.lead, self.lead, self.pid, mr_iid,
                                    branch=branch,
                                    approve_comment=f"Release {version} готов. Merge.")
        if ok:
            # тег + GitLab Release (best-effort)
            self.lead.gl.create_tag(self.pid, version, "main",
                                    f"Release {version}", self.lead.token)
            self.lead.gl.create_release(self.pid, version,
                                        f"{version} — Sprint {sprint_no}",
                                        self._changelog(version, sprint_no, rule_count, date),
                                        self.lead.token)
            logger.info(f"[release] выпущен {version}")
        return ok

    def _changelog(self, version, sprint_no, rule_count, date) -> str:
        return (f"## {version} — {date} (Sprint {sprint_no})\n\n"
                f"- Активных детект-правил: {rule_count}\n"
                "- Добавлены новые правила, тюнинг порогов, обновления плейбуков\n"
                "- Threat intel: свежие IOC интегрированы\n")
