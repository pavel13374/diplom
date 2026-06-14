"""
Базовый класс SOC-агента.
Каждый агент — отдельный персонаж с характером и токеном.
Каждое успешное действие пишется в журнал событий (events.emit) для датасета.
"""
import time
import random
import logging
from typing import Optional
from gitlab_client import GitLabClient
from config import DELAYS, USERS
import simclock
import events

logger = logging.getLogger(__name__)


class BaseAgent:
    def __init__(self, username: str, gl: GitLabClient):
        self.username = username
        self.gl       = gl
        self.info     = USERS[username]
        self.name     = self.info["name"]
        self.email    = self.info["email"]
        self.role     = self.info["role"]
        self.user_id  = self.info["id"]
        self._token: Optional[str] = None

    # ------------------------------------------------------------------
    @property
    def token(self) -> str:
        if not self._token:
            self._token = self.gl.get_or_create_user_token(self.user_id, self.username)
        return self._token

    def _emit(self, action, **kw):
        try:
            events.emit(action, actor=self.username, role=self.role, **kw)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Базовые операции — делегируют в GitLabClient со своим токеном
    # ------------------------------------------------------------------
    def push_file(self, project_id: int, path: str, content: str,
                  message: str, branch: str = "main") -> bool:
        ok = self.gl.push_file(project_id, path, content, message, branch, self.token)
        if ok:
            logger.info(f"[{self.username}] pushed {path} -> {message[:60]}")
            ext = path.rsplit(".", 1)[-1] if "." in path else ""
            self._emit("push", project_id=project_id, path=path, branch=branch,
                       message=message,
                       extra={"lines": content.count(chr(10)) + 1,
                              "bytes": len(content), "ext": ext})
        return ok

    def create_branch(self, project_id: int, branch: str, ref: str = "main") -> bool:
        ok = self.gl.create_branch(project_id, branch, ref, self.token)
        if ok:
            logger.info(f"[{self.username}] created branch {branch}")
            self._emit("branch_create", project_id=project_id, branch=branch)
        return ok

    def create_mr(self, project_id: int, source: str, title: str,
                  description: str = "", assignee_id: int = 0) -> int:
        iid = self.gl.create_mr(project_id, source, title, description, assignee_id, self.token)
        if iid:
            logger.info(f"[{self.username}] opened MR !{iid}: {title[:60]}")
            self._emit("mr_open", project_id=project_id, branch=source, mr_iid=iid,
                       message=title)
        return iid

    def comment_mr(self, project_id: int, mr_iid: int, body: str) -> bool:
        ok = self.gl.comment_mr(project_id, mr_iid, body, self.token)
        if ok:
            logger.info(f"[{self.username}] commented MR !{mr_iid}: {body[:60]}")
            self._emit("mr_comment", project_id=project_id, mr_iid=mr_iid, message=body)
        return ok

    def merge_mr(self, project_id: int, mr_iid: int) -> bool:
        ok = self.gl.merge_mr(project_id, mr_iid, self.token)
        if ok:
            logger.info(f"[{self.username}] merged MR !{mr_iid}")
            self._emit("mr_merge", project_id=project_id, mr_iid=mr_iid)
        return ok

    # ------------------------------------------------------------------
    # Расширенные операции (approvals, emoji, issues, MR-апдейты)
    # ------------------------------------------------------------------
    def approve_mr(self, project_id: int, mr_iid: int) -> bool:
        ok = self.gl.approve_mr(project_id, mr_iid, self.token)
        if ok:
            logger.info(f"[{self.username}] approved MR !{mr_iid}")
            self._emit("mr_approve", project_id=project_id, mr_iid=mr_iid)
        return ok

    def react(self, project_id: int, mr_iid: int, name: str = "thumbsup",
              target_type: str = "merge_requests") -> bool:
        import config
        if not config.FEATURES.get("emoji_reactions"):
            return False
        if random.random() > config.PROBS.get("emoji", 0.5):
            return False
        return self.gl.award_emoji(project_id, target_type, mr_iid, name, self.token)

    def set_mr_title(self, project_id: int, mr_iid: int, title: str) -> bool:
        return self.gl.update_mr(project_id, mr_iid, {"title": title}, self.token)

    def close_mr(self, project_id: int, mr_iid: int) -> bool:
        ok = self.gl.update_mr(project_id, mr_iid, {"state_event": "close"}, self.token)
        if ok:
            logger.info(f"[{self.username}] closed MR !{mr_iid} (без merge)")
            self._emit("mr_close", project_id=project_id, mr_iid=mr_iid)
        return ok

    def create_issue(self, project_id: int, title: str, description: str = "",
                     labels=None, milestone_id: int = 0, assignee_id: int = 0) -> int:
        import config
        from datetime import datetime
        created_at = None
        if getattr(config, "GITLAB_DATES", "real") == "sim":
            t = simclock.now()
            if t <= datetime.now():
                created_at = t.isoformat()
        iid = self.gl.create_issue(project_id, title, description, labels,
                                   milestone_id, assignee_id,
                                   created_at=created_at, user_token=self.token)
        if iid:
            logger.info(f"[{self.username}] opened issue #{iid}: {title[:60]}")
            self._emit("issue_open", project_id=project_id, mr_iid=iid, message=title,
                       extra={"labels": labels or []})
        return iid

    def comment_issue(self, project_id: int, issue_iid: int, body: str) -> bool:
        ok = self.gl.comment_issue(project_id, issue_iid, body, self.token)
        if ok:
            self._emit("issue_comment", project_id=project_id, mr_iid=issue_iid, message=body)
        return ok

    def close_issue(self, project_id: int, issue_iid: int) -> bool:
        ok = self.gl.update_issue(project_id, issue_iid, {"state_event": "close"}, self.token)
        if ok:
            self._emit("issue_close", project_id=project_id, mr_iid=issue_iid)
        return ok

    # ------------------------------------------------------------------
    # Утилиты
    # ------------------------------------------------------------------
    def think(self, base: float = None):
        delay = base or DELAYS["agent_think"]
        simclock.sleep(delay * random.uniform(0.5, 1.5))

    def commit_pause(self):
        simclock.sleep(DELAYS["between_commits"] * random.uniform(0.8, 1.2))

    def review_pause(self):
        simclock.sleep(DELAYS["review_wait"] * random.uniform(0.7, 1.5))

    def unique_branch(self, prefix: str, suffix: str = "") -> str:
        ts = int(time.time()) % 100000
        s  = f"-{suffix}" if suffix else ""
        return f"{prefix}{s}-{ts}"

    def log(self, msg: str):
        logger.info(f"[{self.username}] {msg}")

    def warn(self, msg: str):
        logger.warning(f"[{self.username}] {msg}")
