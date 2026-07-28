"""
Активность: обновление парсера нормализации логов.
"""
import random
import logging
import config
from config import USERS, DELAYS
from content import commit_messages as cm, comments

logger = logging.getLogger(__name__)

PARSER_UPDATES = [
    {
        "path": "parsers/windows/security_events.conf",
        "msg_type": "fix",
        "what": "EventID 4648 explicit credential logon",
        "content_snippet": """
    # EventID 4648 — Explicit credentials logon (RunAs, PtH indicator)
    if [EventID] == "4648" {{
      mutate {{
        add_field => {{ "event.category" => "authentication"
                       "event.action"   => "explicit_credentials_logon"
                       "event.outcome"  => "success" }}
        rename    => {{ "SubjectUserName"  => "user.name"
                       "TargetUserName"   => "target.user.name"
                       "TargetServerName" => "destination.hostname" }}
      }}
    }}
""",
    },
    {
        "path": "parsers/windows/sysmon.conf",
        "msg_type": "feat",
        "what": "EventID 7 ImageLoad for DLL hijacking detection",
        "content_snippet": """
    # EventID 7 — Image Loaded (DLL load)
    if [EventID] == "7" {{
      mutate {{
        add_field => {{ "event.category" => "library"
                       "event.action"   => "image_loaded" }}
        rename    => {{ "Image"       => "process.executable"
                       "ImageLoaded" => "dll.path"
                       "Hashes"      => "dll.hash"
                       "Signed"      => "dll.signed"
                       "Signature"   => "dll.signature" }}
      }}
    }}
""",
    },
    {
        "path": "parsers/linux/auditd.conf",
        "msg_type": "feat",
        "what": "USER_AUTH and USER_CMD event types",
        "content_snippet": """
    # USER_AUTH — sudo/su authentication events
    if [audit.type] == "USER_AUTH" {{
      mutate {{
        add_field => {{ "event.category" => "authentication"
                       "event.action"   => "user_auth"
                       "event.module"   => "auditd" }}
      }}
    }}

    # USER_CMD — command executed via sudo
    if [audit.type] == "USER_CMD" {{
      mutate {{
        add_field => {{ "event.category" => "process"
                       "event.action"   => "sudo_command" }}
      }}
    }}
""",
    },
    {
        "path": "parsers/network/cisco_asa.conf",
        "msg_type": "feat",
        "what": "AnyConnect VPN connection events",
        "content_snippet": """
    # VPN connect/disconnect events
    if [cisco.mnemonic] == "VPNC_5_CONNECT" {{
      mutate {{
        add_field => {{ "event.category" => "network"
                       "event.action"   => "vpn_connected"
                       "network.type"   => "vpn" }}
      }}
    }}
    if [cisco.mnemonic] == "VPNC_5_DISCONNECT" {{
      mutate {{
        add_field => {{ "event.category" => "network"
                       "event.action"   => "vpn_disconnected" }}
      }}
    }}
""",
    },
    {
        "path": "parsers/cloud/aws_cloudtrail.conf",
        "msg_type": "feat",
        "what": "S3 and EC2 IMDS access event categorization",
        "content_snippet": """
    # Categorize S3 data events
    if [event.action] in ["GetObject", "PutObject", "DeleteObject"] {{
      mutate {{
        add_field => {{ "event.category" => "file"
                       "cloud.storage"  => "s3" }}
      }}
    }}

    # Detect IMDS access (potential credential theft)
    if [source.ip] == "169.254.169.254" {{
      mutate {{
        add_field => {{ "event.category"  => "cloud_metadata"
                       "threat.indicator" => "imds_access" }}
      }}
    }}
""",
    },
    {
        "path": "parsers/windows/security_events.conf",
        "msg_type": "fix",
        "what": "timestamp parsing for events without milliseconds",
        "content_snippet": """
    # Fix timestamp fallback — some events lack milliseconds
    date {{
      match  => ["TimeCreated", "ISO8601", "yyyy-MM-dd'T'HH:mm:ssZ"]
      target => "@timestamp"
      timezone => "UTC"
    }}
""",
    },
]


class UpdateParserActivity:
    """Anna или Detection Engineer обновляет парсер."""

    def __init__(self, author_agent, lead_agent):
        self.author = author_agent
        self.lead   = lead_agent
        self.pid    = config.parser_repo_id()

    def run(self) -> bool:
        update = random.choice(PARSER_UPDATES)
        path   = update["path"]
        what   = update["what"]

        # Читаем текущее содержимое парсера
        existing = self.author.gl.get_file(self.pid, path)
        if not existing:
            self.author.log(f"Parser {path} not found, skipping")
            return False

        source = path.split("/")[-1].replace(".conf", "")
        slug   = source[:20]
        branch = self.author.unique_branch(
            f"{update['msg_type']}/parser-{slug}"
        )

        self.author.log(f"Updating parser: {path} — {what}")

        # 1. Создаём ветку
        if not self.author.create_branch(self.pid, branch):
            return False
        self.author.think()

        # 2. Обновляем парсер — добавляем блок в конец перед последней скобкой
        new_content = self._inject_snippet(existing, update["content_snippet"])
        msg = cm.parser_message(source, what)
        if not self.author.push_file(self.pid, path, new_content, msg, branch):
            return False
        self.author.commit_pause()

        # 3. Иногда добавляем docs/changelog
        if random.random() < 0.35:
            changelog = self._changelog_entry(source, what)
            self.author.push_file(
                self.pid,
                f"docs/changelog/{source}.md",
                changelog,
                f"docs({source}): update changelog for {what[:40]}",
                branch,
            )
            self.author.commit_pause()

        # 4. MR
        lead_id = USERS["alex.petrov"]["id"]
        mr_iid  = self.author.create_mr(
            self.pid, branch,
            f"{update['msg_type']}(parsers/{source}): {what[:60]}",
            self._mr_desc(source, what),
            lead_id,
        )
        if not mr_iid:
            return False

        # 5. Review
        self.lead.think(DELAYS["review_wait"])
        if random.random() < 0.50:
            self.lead.comment_mr(self.pid, mr_iid, comments.parser_review())
            self.author.think(DELAYS["agent_think"])
            self.author.comment_mr(self.pid, mr_iid,
                                    comments.engineer_response(True))
            self.author.think(DELAYS["between_commits"])

        self.lead.comment_mr(self.pid, mr_iid,
                              random.choice(["LGTM. Merge.", "Approve.",
                                             "Выглядит хорошо. Merge."]))
        return self.lead.merge_mr(self.pid, mr_iid)

    def _inject_snippet(self, content: str, snippet: str) -> str:
        """Добавляет сниппет перед последней закрывающей скобкой."""
        lines = content.rstrip().split("\n")
        # Ищем последний } блок filter
        for i in range(len(lines) - 1, -1, -1):
            if lines[i].strip() == "}":
                lines.insert(i, snippet)
                break
        return "\n".join(lines)

    def _changelog_entry(self, source: str, what: str) -> str:
        return """# Changelog: {source} parser

## {date.today().isoformat()}

### Added
- {what}
- Updated ECS field mapping
- Author: {self.author.name}

## История

Смотри git log для полной истории изменений.
"""

    def _mr_desc(self, source: str, what: str) -> str:
        return """## Обновление парсера `{source}`

### Изменения
- Добавлена поддержка: **{what}**
- ECS маппинг обновлён

### Тестирование
- [ ] Проверено на реальных семплах из prod
- [ ] Существующие события парсируются без регрессии

### Влияние
Требуется рестарт Logstash pipeline после деплоя.
"""
