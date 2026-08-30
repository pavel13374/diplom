"""
«Косяки» и benign-лукалайки — нормальные, но шумные/похожие-на-аномалию события.
Это ВАЖНЫЕ hard-negatives: .env.example, тестовые ключи, base64-ассеты,
большие файлы, коммит не в ту ветку, отладочный print. is_anomaly=false,
но помечены lookalike/quirk — чтобы детектор учился не путать их с утечками.
"""
import random
import logging
from config import USERS, DELAYS
from content import secrets_bank as sb
from activities import flow
import events
import config

logger = logging.getLogger(__name__)


class BenignQuirk:
    def __init__(self, author, lead, state=None):
        self.author = author; self.lead = lead; self.state = state

    def run(self):
        kind = random.choice([
            "env_example", "test_key", "base64_asset",
            "large_file", "wrong_branch", "debug_print",
        ])
        return getattr(self, "_" + kind)()

    def _repo(self, *names):
        if names:
            return config.repo_id(names[0])
        pool = [n for n in config.WORK_REPOS if n != "soc-secrets"]
        return config.WORK_REPOS[random.choice(pool)]

    # --- лукалайки секретов (норма!) ---
    def _env_example(self):
        pid = self._repo()
        label, content = sb.benign_env_example()
        return self._commit(pid, ".env.example", content,
                            "docs: add .env.example template", lookalike=label)

    def _test_key(self):
        pid = self._repo()
        label, content = sb.benign_test_key()
        return self._commit(pid, "tests/fixtures/credentials.env", content,
                            "test: add fixture with dummy credentials", lookalike=label)

    def _base64_asset(self):
        pid = self._repo()
        label, content = sb.benign_base64_icon()
        return self._commit(pid, "assets/icon_b64.txt", content,
                            "chore: embed base64 icon asset", lookalike=label)

    # --- обычные косяки ---
    def _large_file(self):
        pid = self._repo()
        big = "# large generated sample log\n" + ("sample line of telemetry data\n" * 1500)
        return self._commit(pid, "tests/samples/big_capture.log", big,
                            "test: add large capture sample", quirk="large_file")

    def _wrong_branch(self):
        pid = self._repo()
        # коммит «не в ту ветку», потом исправление
        wrong = self.author.unique_branch("wip/experiment")
        if not self.author.create_branch(pid, wrong):
            return False
        self.author.push_file(pid, "wip/scratch.md", "experimental scratch, wrong branch\n",
                              "wip: scratch (wrong branch oops)", wrong)
        self.author.comment_pause() if hasattr(self.author, "comment_pause") else self.author.commit_pause()
        events.emit("quirk", actor=self.author.username, role=self.author.role,
                    project=None, message="committed to wrong branch", extra={"quirk": "wrong_branch"})
        return True

    def _debug_print(self):
        pid = self._repo("normalization-rules", "ml-anomaly-engine")
        code = ("def normalize(event):\n"
                "    print('DEBUG:', event)   # FIXME: remove debug print before merge\n"
                "    return {k.lower(): v for k, v in event.items()}\n")
        return self._commit(pid, "parsers/debug_helper.py", code,
                            "feat: add normalize helper", quirk="debug_print")

    # --- общий путь: ветка → push(с меткой) → MR → merge ---
    def _commit(self, pid, path, content, msg, lookalike=None, quirk=None):
        branch = self.author.unique_branch("chore/q")
        if not self.author.create_branch(pid, branch):
            return False
        self.author.think(2)
        extra = {}
        if lookalike:
            extra["lookalike"] = lookalike
        if quirk:
            extra["quirk"] = quirk
        with events.tag(**extra):
            ok = self.author.push_file(pid, path, content, msg, branch)
        if not ok:
            return False
        self.author.commit_pause()
        iid = self.author.create_mr(pid, branch, msg, "Рутинное изменение.",
                                    USERS["alex.petrov"]["id"])
        if not iid:
            return False
        self.lead.think(DELAYS["agent_think"])
        return flow.approve_and_merge(self.lead, self.author, pid, iid, branch=branch,
                                      approve_comment="Ок, мелочь. Merge.")
