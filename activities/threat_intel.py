"""
Активность: обновление threat intelligence.
Подтягиваем свежие IOC (домены, хеши, IP, CVE-сигнатуры) в репозиторий
правил — отдельный intel-файл + ссылка из правила.
"""
import json
import random
import hashlib
import logging
import config
from datetime import date
from config import PROJECTS, USERS, DELAYS
from content import commit_messages as cm, comments

logger = logging.getLogger(__name__)


def _fake_sha256(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _fake_domain() -> str:
    words = ["secure", "update", "cloud", "cdn", "mail", "vpn", "login",
             "api", "sync", "node", "gw", "portal"]
    tlds  = ["com", "net", "ru", "xyz", "top", "info", "io"]
    return f"{random.choice(words)}-{random.randint(100,999)}.{random.choice(tlds)}"


def _fake_ip() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


class ThreatIntelActivity:
    """Anna/инженер добавляет свежие IOC из TI-фида."""

    def __init__(self, author_agent, lead_agent):
        self.author = author_agent
        self.lead   = lead_agent
        self.pid    = config.rule_repo_id()

    def run(self) -> bool:
        actor = comments.random_actor()
        cve   = comments.random_cve()
        kind  = random.choice(["actor", "cve", "feed"])

        n_iocs = random.randint(5, 40)
        iocs = {
            "domains": [_fake_domain() for _ in range(random.randint(2, 8))],
            "ips":     [_fake_ip() for _ in range(random.randint(2, 8))],
            "hashes":  [_fake_sha256(f"{actor}{i}") for i in range(random.randint(2, 6))],
        }

        slug   = actor.split(" ")[0].lower().replace("(", "").replace(")", "")
        branch = self.author.unique_branch(f"intel/{slug[:18]}")
        self.author.log(f"Threat intel update: {actor} / {cve} ({n_iocs} IOCs)")

        if not self.author.create_branch(self.pid, branch):
            return False
        self.author.think()

        intel_path = f"intel/{date.today().strftime('%Y%m')}/{slug}.json"
        intel_doc  = json.dumps({
            "source":     random.choice(["MISP", "internal-TI", "vendor-feed", "OSINT"]),
            "actor":      actor,
            "related_cve": cve,
            "added":      date.today().isoformat(),
            "analyst":    self.author.name,
            "tlp":        random.choice(["TLP:GREEN", "TLP:AMBER", "TLP:CLEAR"]),
            "indicators": iocs,
        }, indent=2)

        if not self.author.push_file(
            self.pid, intel_path, intel_doc,
            cm.intel_message(actor=actor, cve=cve), branch,
        ):
            return False
        self.author.commit_pause()

        # Blocklist-обновление для C2-доменов
        if random.random() < 0.6:
            blocklist = "\n".join(iocs["domains"] + iocs["ips"]) + "\n"
            self.author.push_file(
                self.pid, "intel/blocklist.txt",
                f"# updated {date.today().isoformat()} by {self.author.name}\n{blocklist}",
                f"feat(intel): extend C2 blocklist from {actor.split(' ')[0]} report",
                branch,
            )
            self.author.commit_pause()

        lead_id = USERS["alex.petrov"]["id"]
        mr_iid  = self.author.create_mr(
            self.pid, branch,
            f"feat(intel): add {actor.split(' ')[0]} indicators ({n_iocs} IOCs)",
            f"## Threat Intel: {actor}\n\n"
            f"**Связанная уязвимость:** {cve}\n"
            f"**Индикаторов добавлено:** {n_iocs}\n\n"
            f"Источник: TI-фид. Индикаторы смаппены на правила C2/exfiltration.\n\n"
            f"- [x] IOC провалидированы (не пересекаются с легитимной инфрой)\n"
            f"- [ ] Blocklist синхронизирован с proxy",
            lead_id,
        )
        if not mr_iid:
            return False

        self.author.think(3)
        self.author.comment_mr(self.pid, mr_iid, comments.threat_intel_comment())
        self.lead.think(DELAYS["agent_think"])
        self.lead.comment_mr(self.pid, mr_iid,
                             random.choice(["Полезно, апрувлю. Merge.",
                                            "Indicators выглядят валидными. LGTM.",
                                            "Approve. Синкнем с proxy после merge."]))
        return self.lead.merge_mr(self.pid, mr_iid)
