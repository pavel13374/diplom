"""
Банк commit messages в стиле conventional commits.
Реалистичные сообщения от разных членов команды.
"""
import random

# -----------------------------------------------------------------------
# Feat commits
# -----------------------------------------------------------------------
FEAT_TEMPLATES = [
    "feat({tactic}): add {title} detection rule",
    "feat(rules): add {title} — MITRE {tid}",
    "feat(detection): implement {title}",
    "feat: new rule for {tactic} — {title}",
    "feat({tactic}): detect {title}",
    "feat(sigma): add {title} rule ({tid})",
    "feat({tactic}): coverage for {title} ({tid})",
    "feat(rules): {title} — initial detection logic",
    "feat(detection): {title} via behavioral signature",
    "feat({tactic}): add correlation-ready {title} rule",
    "feat(rules): onboard {title} from threat report",
]

# -----------------------------------------------------------------------
# Fix commits
# -----------------------------------------------------------------------
FIX_TEMPLATES = [
    "fix({rule}): reduce false positives — add {what} filter",
    "fix(rules): tighten condition for {rule}",
    "fix({rule}): update detection for {what}",
    "fix: correct {rule} — {what} was not properly filtered",
    "fix({rule}): add whitelist for {what}",
    "fix(sigma): fix {rule} condition logic",
    "fix({rule}): patch false positive on {what}",
    "fix: hotfix {rule} — {what} causing noise in prod",
    "fix({rule}): exclude {what} from selection",
    "fix({rule}): narrow scope after triage of {what}",
    "fix(sigma): correct field name in {rule}",
    "fix({rule}): handle edge case for {what}",
    "fix({rule}): align condition with data schema",
]

FIX_WHAT_POOL = [
    "system accounts",
    "service accounts",
    "legacy hosts",
    "backup agents",
    "antivirus processes",
    "helpdesk scripts",
    "monitoring agents",
    "SCCM/Ansible deployments",
    "internal IP ranges",
    "known-good parent processes",
    "package manager operations",
    "domain controller processes",
    "scheduled maintenance",
    "vendor management tools",
    "CI/CD runner processes",
    "EDR sensor processes",
    "patch management agents",
    "vulnerability scanners",
    "service desk automation",
    "container runtime processes",
    "cloud agent daemons",
    "log shipper agents",
    "database backup jobs",
    "certificate renewal jobs",
]

# -----------------------------------------------------------------------
# Refactor commits
# -----------------------------------------------------------------------
REFACTOR_TEMPLATES = [
    "refactor({rule}): split into specific sub-rules for better coverage",
    "refactor(rules): standardize {rule} to Sigma 1.0.3 format",
    "refactor({rule}): replace regex with keyword matching",
    "refactor: cleanup {rule} — remove duplicate selection blocks",
    "refactor({rule}): optimize condition performance",
    "refactor(detection): restructure {rule} detection logic",
    "style({rule}): fix indentation and formatting",
    "refactor({rule}): extract shared selection to template",
    "refactor(rules): unify naming convention for {rule}",
    "refactor({rule}): convert to modular detection blocks",
    "style(rules): normalize YAML quoting in {rule}",
]

# -----------------------------------------------------------------------
# Docs/test commits
# -----------------------------------------------------------------------
DOCS_TEMPLATES = [
    "docs({rule}): add detailed description and references",
    "docs: update false positives for {rule}",
    "docs({rule}): add MITRE ATT&CK reference links",
    "test({rule}): add negative test sample",
    "test: add lab-validated sample for {rule}",
    "test({rule}): add edge case test coverage",
    "docs(playbooks): update {rule} response steps",
    "docs: add investigation commands to {rule} playbook",
    "docs({rule}): document tuning history and rationale",
    "test({rule}): add positive sample from lab replay",
    "test({rule}): cover false-positive scenario",
    "docs({rule}): add data-source requirements",
    "docs(rules): link related rules to {rule}",
]

# -----------------------------------------------------------------------
# Chore commits
# -----------------------------------------------------------------------
CHORE_TEMPLATES = [
    "chore: update rule IDs to v4 UUID format",
    "chore(ci): fix pipeline timeout for large rule sets",
    "chore: bump Sigma schema to 1.0.3",
    "chore(parsers): update ECS field mapping to 8.x",
    "chore: remove deprecated logsource fields",
    "chore(infra): update GitLab Runner config",
    "chore: regenerate rule IDs for conflicting entries",
    "chore(deps): update sigma-cli to latest",
    "chore(ci): cache sigma-cli deps in pipeline",
    "chore(rules): sort fields for deterministic diffs",
    "chore(infra): rotate runner registration token",
    "chore(deps): bump pyyaml and jsonschema",
    "chore(repo): add CODEOWNERS for rules/",
]

# -----------------------------------------------------------------------
# Revert commits
# -----------------------------------------------------------------------
REVERT_TEMPLATES = [
    'Revert "feat({tactic}): add {title} detection rule"',
    'Revert "feat(rules): add {title} — high false positive rate"',
    'revert: rollback {title} — production issues',
    'revert({rule}): undo noisy detection, needs rework',
]

# -----------------------------------------------------------------------
# Promote commits
# -----------------------------------------------------------------------
PROMOTE_TEMPLATES = [
    "fix({rule}): promote to stable after 2-week clean run",
    "fix({rule}): promote to production — 0 FP in 30 days",
    "chore({rule}): update status: experimental → stable",
    "chore({rule}): graduate to production after validation",
    "chore({rule}): status experimental → test",
    "fix({rule}): promote after analyst sign-off",
    "chore({rule}): enable in prod ruleset",
]

# -----------------------------------------------------------------------
# Parser commits
# -----------------------------------------------------------------------
PARSER_TEMPLATES = [
    "feat(parsers/{source}): add {source} log normalizer",
    "fix(parsers/{source}): fix timestamp parsing for {what}",
    "feat(parsers/{source}): add ECS {field} field mapping",
    "refactor(parsers/{source}): optimize grok pattern performance",
    "fix(parsers/{source}): handle malformed {what} events",
    "feat(parsers): add {source} support",
    "fix(parsers/{source}): correct {field} field extraction",
]

PARSER_SOURCES = [
    "windows_security", "sysmon", "linux_auditd",
    "palo_alto", "cisco_asa", "aws_cloudtrail",
    "azure_monitor", "crowdstrike", "zeek_dns",
    "nginx_access", "apache_access",
    "okta_system", "gsuite_admin", "o365_audit",
    "kubernetes_audit", "docker_daemon", "fortinet_fgt",
    "juniper_srx", "f5_asm", "suricata_eve", "osquery",
]

PARSER_FIELDS = [
    "user.name", "source.ip", "destination.port",
    "process.executable", "event.action", "host.hostname",
    "network.bytes", "url.path", "error.code",
    "user.domain", "destination.ip", "process.parent.name",
    "file.hash.sha256", "dns.question.name", "http.response.status_code",
    "cloud.account.id", "event.outcome", "rule.name",
]

# -----------------------------------------------------------------------
# Playbook commits
# -----------------------------------------------------------------------
PLAYBOOK_TEMPLATES = [
    "docs(playbooks): add {tactic} incident response steps",
    "docs(playbooks): update {tactic} containment procedure",
    "fix(playbooks): add regulatory notification (152-FZ)",
    "docs(playbooks): add IOC section for {tactic}",
    "feat(playbooks): add {tactic} investigation commands",
    "docs(playbooks): update SLA escalation criteria",
    "fix(playbooks): correct evidence collection procedure",
    "docs(playbooks): add post-incident lessons learned",
    "docs(playbooks): add decision tree for {tactic}",
    "feat(playbooks): add automation hooks for {tactic}",
    "fix(playbooks): update contact/escalation matrix",
    "docs(playbooks): add evidence chain-of-custody steps",
]

# -----------------------------------------------------------------------
# Функции
# -----------------------------------------------------------------------

def feat_message(technique: dict) -> str:
    tpl = random.choice(FEAT_TEMPLATES)
    return tpl.format(
        tactic=technique["tactic"],
        title=technique["title"],
        tid=technique["id"],
    )


def fix_message(rule_slug: str, what: str = None) -> str:
    tpl = random.choice(FIX_TEMPLATES)
    return tpl.format(
        rule=rule_slug,
        what=what or random.choice(FIX_WHAT_POOL),
    )


def refactor_message(rule_slug: str) -> str:
    return random.choice(REFACTOR_TEMPLATES).format(rule=rule_slug)


def docs_message(rule_slug: str) -> str:
    return random.choice(DOCS_TEMPLATES).format(rule=rule_slug)


def chore_message() -> str:
    return random.choice(CHORE_TEMPLATES)


def revert_message(technique: dict) -> str:
    slug = technique["title"].lower().replace(" ", "_")[:30]
    return random.choice(REVERT_TEMPLATES).format(
        tactic=technique["tactic"],
        title=technique["title"],
        rule=slug,
    )


def promote_message(rule_slug: str) -> str:
    return random.choice(PROMOTE_TEMPLATES).format(rule=rule_slug)


def parser_message(source: str = None, what: str = None, field: str = None) -> str:
    tpl = random.choice(PARSER_TEMPLATES)
    return tpl.format(
        source=source or random.choice(PARSER_SOURCES),
        what=what or random.choice(FIX_WHAT_POOL),
        field=field or random.choice(PARSER_FIELDS),
    )


def playbook_message(tactic: str = None) -> str:
    tactics = [
        "credential_access", "lateral_movement",
        "ransomware", "exfiltration", "persistence",
    ]
    return random.choice(PLAYBOOK_TEMPLATES).format(
        tactic=tactic or random.choice(tactics)
    )


# =======================================================================
#  РАСШИРЕНИЕ — новые типы коммитов
# =======================================================================
FEAT_TEMPLATES += [
    "feat({tactic}): add high-confidence rule for {title}",
    "feat(rules): {title} detection with correlation ({tid})",
    "feat(hunting): add hunting query for {title}",
]

FIX_TEMPLATES += [
    "fix({rule}): correct ECS field mapping breaking correlation",
    "fix({rule}): add timeframe to stop single-event noise",
    "fix({rule}): exclude {what} per prod observation",
    "fix(sigma): repair invalid YAML indentation in {rule}",
]

TUNE_TEMPLATES = [
    "tune({rule}): raise threshold to reduce false positives",
    "tune({rule}): widen timeframe to {n}m for burst tolerance",
    "tune({rule}): add allowlist for {what}",
    "perf({rule}): replace regex with keyword match",
    "tune({rule}): lower severity until baseline established",
    "tune({rule}): recalibrate after 7-day FP review",
    "tune({rule}): add time-of-day baseline",
    "tune({rule}): suppress known-good {what}",
    "perf({rule}): index-friendly field ordering",
]

DEPRECATE_TEMPLATES = [
    "chore({rule}): deprecate — superseded by EDR detection",
    "remove({rule}): delete stale rule with no data source",
    "chore({rule}): archive rule after 90d zero true positives",
    "remove(rules): drop {rule} — replaced by upstream SigmaHQ",
    "chore({rule}): mark deprecated, schedule removal",
]

RECREATE_TEMPLATES = [
    "feat({rule}): re-introduce rule v2 after rework",
    "feat({rule}): restore detection with corrected logic",
    "feat({rule}): reimplement after post-mortem fixes",
    "feat({rule}): bring back {rule} with threshold + correlation",
]

INTEL_TEMPLATES = [
    "feat(intel): add {actor} IOCs to detection set",
    "feat(intel): incorporate {cve} exploitation signatures",
    "chore(intel): refresh threat-intel indicators ({n} new)",
    "feat({rule}): add IOC hashes from latest TI report",
    "feat(intel): update C2 user-agent blocklist",
    "feat(intel): add {actor} TTP mapping",
    "chore(intel): expire stale indicators",
    "feat(intel): import STIX bundle from feed",
]

DASHBOARD_TEMPLATES = [
    "docs(metrics): update ATT&CK coverage matrix",
    "docs(metrics): refresh weekly FP-rate report",
    "feat(dashboard): add MTTR-by-severity panel",
    "docs(metrics): update detection heatmap",
    "chore(metrics): regenerate coverage report for sprint",
]

INCIDENT_TEMPLATES = [
    "docs(ir): add incident report INC-{n}",
    "docs(ir): post-mortem for INC-{n}",
    "docs(ir): timeline and IOCs for {sev} incident",
    "chore(ir): close INC-{n} with lessons learned",
    "docs(ir): add containment summary for INC-{n}",
    "docs(ir): root-cause analysis for {sev} incident",
]

BULK_TEMPLATES = [
    "chore(rules): migrate all rules to Sigma 2.0 schema",
    "chore(rules): bulk-update ECS mapping to 8.11",
    "chore(rules): normalize tags across rule set",
    "chore(ci): add sigma-lint gate to pipeline",
    "chore(rules): regenerate UUIDs for {n} conflicting rules",
    "chore(repo): archive deprecated rules to /archive",
]


def tune_message(rule_slug: str, what: str = None) -> str:
    return random.choice(TUNE_TEMPLATES).format(
        rule=rule_slug,
        what=what or random.choice(FIX_WHAT_POOL),
        n=random.choice([3, 5, 10, 15]),
    )


def deprecate_message(rule_slug: str) -> str:
    return random.choice(DEPRECATE_TEMPLATES).format(rule=rule_slug)


def recreate_message(rule_slug: str) -> str:
    return random.choice(RECREATE_TEMPLATES).format(rule=rule_slug)


def intel_message(rule_slug: str = "rules", actor: str = None,
                  cve: str = None) -> str:
    return random.choice(INTEL_TEMPLATES).format(
        rule=rule_slug,
        actor=(actor or "APT").split(" ")[0],
        cve=(cve or "CVE").split(" ")[0],
        n=random.randint(5, 80),
    )


def dashboard_message() -> str:
    return random.choice(DASHBOARD_TEMPLATES)


def incident_message(sev: str = "High") -> str:
    return random.choice(INCIDENT_TEMPLATES).format(
        n=random.randint(1000, 9999), sev=sev,
    )


def bulk_message() -> str:
    return random.choice(BULK_TEMPLATES).format(n=random.randint(3, 40))
