"""
Тематические сценарии для специализированных репозиториев, чтобы они
не стояли пустыми с одним README. Каждый сценарий наполняет «свой» репозиторий
доменным контентом и проходит штатный MR-цикл (ветка → push → MR → review → merge).

Все действия штатные (is_anomaly=false) — это богатый «фон» для будущего ML.

Репозитории:
    threat-hunting     → гипотезы и hunt-запросы (KQL/SPL/EQL/osquery)
    cloud-detections   → облачные детект-правила (AWS/Azure/GCP), в rules/
    siem-content       → корреляции и saved searches, dashboards
    edr-integration    → поведенческие EDR-правила (IOA), в rules/
    soc-automation     → SOAR-автоматизации (enrichment/containment)
    incident-response  → runbooks и postmortem'ы
"""
import json
import random
import logging
from datetime import date

import config
from config import DELAYS
from activities import flow

logger = logging.getLogger(__name__)


def _repo(name, *fallbacks):
    """ID репозитория по имени; если нет — первый доступный фолбэк; иначе detection-rules."""
    if name in config.WORK_REPOS:
        return config.WORK_REPOS[name]
    for fb in fallbacks:
        if fb in config.WORK_REPOS:
            return config.WORK_REPOS[fb]
    return config.repo_id("detection-rules")


def _slug(s):
    out = "".join(c if c.isalnum() else "-" for c in s.lower()).strip("-")
    while "--" in out:
        out = out.replace("--", "-")
    return out[:40]


class _MixinCycle:
    """Общий MR-цикл: ветка → коммиты(actions) → MR → approve+merge."""

    def _do(self, branch_hint, files, title, desc, approve_comment, emoji="thumbsup"):
        branch = self.author.unique_branch(branch_hint)
        if not self.author.create_branch(self.pid, branch):
            return False
        self.author.think()
        for i, (path, content, msg) in enumerate(files):
            if not self.author.push_file(self.pid, path, content, msg, branch):
                if i == 0:
                    return False
                break
            self.author.commit_pause()
        iid = self.author.create_mr(self.pid, branch, title, desc, config.lead_id())
        if not iid:
            return False
        self.author.think(3)
        self.lead.think(DELAYS["review_wait"])
        return flow.approve_and_merge(self.lead, self.author, self.pid, iid,
                                      branch=branch, approve_comment=approve_comment,
                                      emoji=emoji)


# =======================================================================
#  THREAT HUNTING
# =======================================================================
class HuntQueryActivity(_MixinCycle):
    """Гипотеза охоты + запрос на конкретном языке."""

    HYPOTHESES = [
        ("Persistence via scheduled tasks", "T1053.005", "Аномальные schtasks на серверах вне окна обслуживания"),
        ("LSASS memory access", "T1003.001", "Нестандартные процессы, открывающие дескриптор lsass.exe"),
        ("DNS tunneling exfil", "T1071.004", "Длинные TXT-запросы к редким доменам"),
        ("Suspicious WMI subscriptions", "T1546.003", "Постоянные WMI event consumers"),
        ("Rare parent-child chains", "T1059", "office → cmd/powershell за пределами VBA-макросов"),
        ("Token impersonation", "T1134", "Процессы с изменённым integrity level"),
        ("RDP lateral movement", "T1021.001", "Всплески 4624 type=10 между рабочими станциями"),
        ("Service creation by non-admins", "T1543.003", "7045 от непривилегированных учёток"),
        ("Cloud metadata access", "T1552.005", "Запросы к 169.254.169.254 из контейнеров"),
        ("Credential dumping via comsvcs", "T1003", "rundll32 comsvcs.dll MiniDump"),
        ("Kerberoasting", "T1558.003", "Массовые TGS-запросы RC4 от одной учётки"),
        ("Golden ticket usage", "T1558.001", "TGT с аномально долгим сроком жизни"),
        ("Container escape attempts", "T1611", "Доступ к /proc/host или privileged-флаги"),
        ("Cloud key in process args", "T1552.001", "AKIA/секреты в командной строке"),
        ("Browser credential theft", "T1555.003", "Чтение Login Data из профиля Chrome"),
        ("Scheduled task via at.exe", "T1053.002", "Создание заданий через устаревший at"),
        ("Defender exclusions added", "T1562.001", "Set-MpPreference ExclusionPath"),
        ("AS-REP roasting", "T1558.004", "Запросы AS-REP для учёток без preauth"),
        ("DCSync replication", "T1003.006", "DRSUAPI-репликация от не-DC хоста"),
        ("NTDS.dit extraction", "T1003.003", "Доступ к ntds.dit через VSS"),
        ("Pass-the-ticket", "T1550.003", "Использование украденного TGT на другом хосте"),
        ("SMB exec lateral", "T1021.002", "Запуск служб через ADMIN$/IPC$"),
        ("Cloud snapshot exfil", "T1537", "Шеринг снапшота диска во внешний аккаунт"),
        ("OAuth consent grant", "T1528", "Согласие на подозрительное OAuth-приложение"),
        ("Mailbox forwarding rule", "T1114.003", "Создание скрытого правила пересылки почты"),
        ("Reverse shell over HTTPS", "T1071.001", "Долгоживущие beacon-соединения с jitter"),
        ("Living-off-the-land curl", "T1105", "curl/certutil загрузка с внешнего IP"),
        ("Disabled audit logging", "T1562.002", "auditpol /clear или отключение логов"),
        ("Privileged group change", "T1098", "Массовые изменения членства Domain Admins"),
        ("Webshell on IIS", "T1505.003", "w3wp.exe порождает cmd/powershell"),
        ("Sysmon tampering", "T1562.001", "Выгрузка/остановка драйвера Sysmon"),
        ("USB mass storage", "T1052.001", "Подключение нового съёмного носителя"),
        ("Anomalous SaaS download", "T1567.002", "Массовая выгрузка из облачного хранилища"),
        ("Time-stomping artifacts", "T1070.006", "Изменение временных меток файлов"),
    ]
    LANGS = ["kql", "spl", "eql", "osquery"]

    def __init__(self, author, lead):
        self.author = author
        self.lead = lead
        self.pid = _repo("threat-hunting", "detection-rules")

    def _query(self, lang, tech):
        if lang == "kql":
            return (f"// Hunt for {tech}\nDeviceProcessEvents\n"
                    "| where Timestamp > ago(7d)\n"
                    "| where InitiatingProcessFileName in~ ('winword.exe','excel.exe','outlook.exe')\n"
                    "| where FileName in~ ('cmd.exe','powershell.exe','wscript.exe')\n"
                    "| summarize count() by DeviceName, AccountName, bin(Timestamp, 1h)\n"
                    f"| where count_ > {random.randint(3,9)}\n")
        if lang == "spl":
            return (f"`comment(\"Hunt {tech}\")`\nindex=edr sourcetype=process\n"
                    "| stats count values(process) as procs by host, user\n"
                    f"| where count > {random.randint(5,15)}\n"
                    "| sort - count\n")
        if lang == "eql":
            return ("process where parent.name in (\"winword.exe\",\"excel.exe\") and\n"
                    "  process.name in (\"cmd.exe\",\"powershell.exe\")\n")
        return ("SELECT name, path, pid, parent FROM processes\n"
                "WHERE path LIKE '%\\\\Temp\\\\%' AND on_disk = 0;\n")

    def run(self):
        title_h, tech, desc_h = random.choice(self.HYPOTHESES)
        lang = random.choice(self.LANGS)
        slug = _slug(f"{title_h}-{lang}")
        ext = {"kql": "kql", "spl": "spl", "eql": "eql", "osquery": "sql"}[lang]
        hyp_md = (f"# Hunt: {title_h}\n\n"
                  f"**MITRE:** {tech}\n**Дата:** {date.today().isoformat()}\n"
                  f"**Аналитик:** {self.author.name}\n**Язык:** {lang.upper()}\n\n"
                  f"## Гипотеза\n{desc_h}\n\n"
                  "## Источники данных\nEDR process telemetry, Windows Security, DNS logs\n\n"
                  "## Шаги\n1. Базлайн за 30 дней.\n2. Выделить отклонения.\n"
                  "3. Триаж кандидатов, эскалация TP в IR.\n\n"
                  "## Результат\n- [ ] Найдены аномалии\n- [ ] Создано детект-правило\n")
        files = [
            (f"hunts/{date.today().strftime('%Y%m')}_{slug}.md", hyp_md,
             f"hunt: hypothesis for {title_h} ({tech})"),
            (f"hunts/queries/{slug}.{ext}", self._query(lang, tech),
             f"hunt: add {lang.upper()} query for {tech}"),
        ]
        return self._do(
            f"hunt/{slug[:24]}", files,
            f"hunt({tech}): {title_h}",
            f"## Hunt-гипотеза `{title_h}`\n\n**MITRE:** {tech}\n\n{desc_h}\n\n"
            f"Добавлен {lang.upper()}-запрос и план охоты.",
            "Гипотеза обоснована, запрос корректный. Запускаем хант.", emoji="eyes")


# =======================================================================
#  CLOUD DETECTIONS
# =======================================================================
class CloudDetectionActivity(_MixinCycle):
    """Облачное детект-правило (Sigma-like) в rules/<cloud>/."""

    CASES = [
        ("aws", "CloudTrail", "Root account used", "T1078.004",
         "eventName в обход IAM от root-учётки"),
        ("aws", "CloudTrail", "S3 bucket made public", "T1530",
         "PutBucketPolicy/PutBucketAcl с public-grant"),
        ("aws", "CloudTrail", "Security group opened to world", "T1562.007",
         "AuthorizeSecurityGroupIngress 0.0.0.0/0 на 22/3389"),
        ("aws", "CloudTrail", "CloudTrail disabled", "T1562.008",
         "StopLogging / DeleteTrail"),
        ("azure", "AzureActivity", "Conditional Access policy modified", "T1556",
         "изменение CA-политик вне change-window"),
        ("azure", "SigninLogs", "Impossible travel sign-in", "T1078",
         "успешные входы из разных стран за минуты"),
        ("gcp", "AuditLog", "Service account key created", "T1098.001",
         "iam.serviceAccountKeys.create для критичных SA"),
        ("gcp", "AuditLog", "Firewall rule allow-all", "T1562.007",
         "compute.firewalls.insert с 0.0.0.0/0"),
        ("aws", "CloudTrail", "IAM policy attached to user", "T1098.001",
         "AttachUserPolicy с AdministratorAccess"),
        ("aws", "CloudTrail", "GuardDuty disabled", "T1562.008",
         "DeleteDetector / StopMonitoringMembers"),
        ("aws", "CloudTrail", "KMS key scheduled for deletion", "T1485",
         "ScheduleKeyDeletion для рабочего ключа"),
        ("azure", "AuditLogs", "App registration secret added", "T1098.001",
         "Добавление client secret к service principal"),
        ("azure", "SigninLogs", "Legacy auth protocol used", "T1110",
         "Вход по IMAP/POP/SMTP в обход MFA"),
        ("gcp", "AuditLog", "IAM role granted to allUsers", "T1098",
         "setIamPolicy с member=allUsers"),
        ("gcp", "AuditLog", "VM serial port enabled", "T1078",
         "Включение serial-console на инстансе"),
        ("aws", "CloudTrail", "Access key created for root", "T1098.001",
         "CreateAccessKey для root-учётки"),
        ("aws", "CloudTrail", "Lambda function policy public", "T1190",
         "AddPermission с Principal=* для Lambda"),
        ("aws", "CloudTrail", "EBS snapshot shared publicly", "T1537",
         "ModifySnapshotAttribute add group=all"),
        ("aws", "CloudTrail", "Password policy weakened", "T1556",
         "UpdateAccountPasswordPolicy снижает требования"),
        ("aws", "CloudTrail", "Config recorder stopped", "T1562.008",
         "StopConfigurationRecorder отключает аудит"),
        ("azure", "AuditLogs", "Global Admin role assigned", "T1098.003",
         "Назначение роли Global Administrator"),
        ("azure", "SigninLogs", "MFA disabled for user", "T1556.006",
         "Отключение MFA в политике пользователя"),
        ("azure", "AuditLogs", "Key Vault secret bulk read", "T1552.001",
         "Массовое чтение секретов Key Vault"),
        ("azure", "AuditLogs", "Storage account key rotated by unknown", "T1098",
         "RegenerateKey из нетипичного источника"),
        ("gcp", "AuditLog", "Bucket made public", "T1530",
         "storage.setIamPermissions allUsers:objectViewer"),
        ("gcp", "AuditLog", "Cloud Function deployed", "T1648",
         "Деплой функции с публичным триггером"),
        ("gcp", "AuditLog", "Audit logs config changed", "T1562.008",
         "SetIamPolicy убирает audit log configs"),
        ("gcp", "AuditLog", "Compute instance with broad scope", "T1078",
         "Создание VM со scope cloud-platform"),
        ("aws", "CloudTrail", "AssumeRole from new account", "T1078.004",
         "sts:AssumeRole из внешнего account-id"),
        ("azure", "SigninLogs", "Token replay detected", "T1550.001",
         "Повтор токена с другого устройства/гео"),
    ]

    def __init__(self, author, lead):
        self.author = author
        self.lead = lead
        self.pid = _repo("cloud-detections", "detection-rules")

    def run(self):
        cloud, source, title_c, tech, desc_c = random.choice(self.CASES)
        slug = _slug(f"{cloud}-{title_c}")
        level = random.choice(["medium", "high", "critical"])
        rule = (f"title: {title_c}\n"
                f"id: {slug}\n"
                "status: experimental\n"
                f"description: {desc_c}\n"
                f"author: {self.author.name}\n"
                f"date: {date.today().isoformat()}\n"
                f"logsource:\n  product: {cloud}\n  service: {source.lower()}\n"
                f"detection:\n  selection:\n    eventSource: {cloud}\n"
                f"    eventName: '{title_c.split()[0]}*'\n"
                "  condition: selection\n"
                f"level: {level}\n"
                f"tags:\n  - attack.{tech.lower()}\n  - cloud.{cloud}\n"
                "falsepositives:\n  - Authorized administrative change\n")
        files = [(f"rules/{cloud}/{slug}.yml", rule,
                  f"detect({cloud}): {title_c} [{tech}]")]
        return self._do(
            f"cloud/{slug[:24]}", files,
            f"detect({cloud}): {title_c}",
            f"## Облачное правило `{title_c}`\n\n**Облако:** {cloud.upper()} · "
            f"**Источник:** {source}\n**MITRE:** {tech} · **Severity:** {level}\n\n{desc_c}",
            f"{cloud.upper()}-правило валидно, FP покрыты. Merge.", emoji="cloud")


# =======================================================================
#  SIEM CONTENT
# =======================================================================
class SiemContentActivity(_MixinCycle):
    """Корреляции / saved searches / дашборды для SIEM."""

    CORRS = [
        ("Brute force then success", "много 4625 затем 4624 с того же src", "high"),
        ("New admin + GPO change", "добавление в Domain Admins и правка GPO", "critical"),
        ("Disabled AV then exec", "остановка Defender и запуск из Temp", "high"),
        ("Mass file rename (ransomware)", "всплеск переименований с расширением", "critical"),
        ("VPN from new ASN + data pull", "вход из нового ASN и крупная выгрузка", "high"),
        ("Service account interactive logon", "type=2/10 от сервисной учётки", "medium"),
        ("Password spray", "много 4625 на разные учётки с одного src", "high"),
        ("Account created then privileged", "4720 затем 4728 в течение часа", "high"),
        ("Off-hours admin activity", "действия Domain Admin ночью/в выходные", "medium"),
        ("Multiple geo logins", "успешные входы из 3+ стран за день", "high"),
        ("Sudden data egress spike", "рост исходящего трафика хоста x10", "high"),
        ("New service binary unsigned", "7045 с неподписанным бинарём", "high"),
        ("Lateral RDP chain", "цепочка 4624 type=10 по 3+ хостам за час", "high"),
        ("Kerberos anomaly burst", "всплеск 4769 RC4 от одной учётки", "high"),
        ("GPO modified off-hours", "правка GPO вне окна изменений", "high"),
        ("Mass account lockouts", "массовые 4740 за короткое окно", "medium"),
        ("Suspicious parent spawn", "office→powershell на множестве хостов", "high"),
        ("Cloud + on-prem combo", "новый облачный вход и AD-эскалация подряд", "critical"),
        ("DNS exfil pattern", "длинные TXT-запросы к одному домену", "high"),
        ("AV tamper then download", "стоп Defender затем загрузка из инета", "critical"),
        ("Privileged logon new host", "админ-вход на нехарактерный хост", "medium"),
        ("Repeated failed sudo", "много неудачных sudo на Linux-хосте", "medium"),
        ("Service restart storm", "массовые перезапуски служб на сервере", "low"),
        ("New scheduled task spread", "одинаковые задания на множестве хостов", "high"),
    ]

    def __init__(self, author, lead):
        self.author = author
        self.lead = lead
        self.pid = _repo("siem-content", "normalization-rules", "detection-rules")

    def run(self):
        name, desc_s, sev = random.choice(self.CORRS)
        slug = _slug(name)
        window = random.choice([5, 10, 15, 30])
        thr = random.randint(3, 12)
        corr = (f"name: {name}\n"
                f"description: {desc_s}\n"
                f"severity: {sev}\n"
                f"schedule: '*/{random.choice([5,10,15])} * * * *'\n"
                f"window_minutes: {window}\n"
                "logic:\n"
                "  - source: windows_security\n    where: EventID in [4625,4624]\n"
                "  - group_by: [src_ip, target_user]\n"
                f"  - having: failed_count >= {thr} AND success_count >= 1\n"
                "actions:\n  - create_alert\n  - notify: soc-oncall\n")
        dashboard = json.dumps({
            "title": f"{name} — overview",
            "panels": [
                {"type": "timechart", "metric": "events_per_min"},
                {"type": "table", "fields": ["src_ip", "target_user", "count"]},
                {"type": "single", "metric": "open_alerts"},
            ],
            "refresh": "5m",
        }, indent=2, ensure_ascii=False)
        files = [
            (f"content/correlation/{slug}.yml", corr,
             f"siem: correlation '{name}'"),
            (f"content/dashboards/{slug}.json", dashboard,
             f"siem: dashboard for '{name}'"),
        ]
        return self._do(
            f"siem/{slug[:24]}", files,
            f"siem({sev}): correlation '{name}'",
            f"## SIEM-контент `{name}`\n\n**Severity:** {sev} · окно {window} мин · "
            f"порог {thr}\n\n{desc_s}\n\nДобавлены корреляция и дашборд.",
            "Корреляция и порог адекватны. Approve.", emoji="bar_chart")


# =======================================================================
#  EDR INTEGRATION
# =======================================================================
class EdrRuleActivity(_MixinCycle):
    """Поведенческое EDR-правило (custom IOA) в rules/."""

    VENDORS = ["crowdstrike", "defender", "sentinelone"]
    BEHAVIORS = [
        ("Credential dumping via comsvcs", "T1003", "rundll32 comsvcs.dll *MiniDump*"),
        ("Encoded PowerShell", "T1059.001", "powershell -enc <base64>"),
        ("BITS job abuse", "T1197", "bitsadmin /transfer из внешнего URL"),
        ("Shadow copy deletion", "T1490", "vssadmin delete shadows /all"),
        ("LOLBin proxy execution", "T1218", "mshta/regsvr32 с удалённым payload"),
        ("Suspicious child of services.exe", "T1543.003", "нетипичный дочерний процесс"),
        ("WMI process call create", "T1047", "wmic process call create из remote"),
        ("Credential access via reg save", "T1003.002", "reg save HKLM\\SAM"),
        ("Clear event logs", "T1070.001", "wevtutil cl / Clear-EventLog"),
        ("Disable firewall", "T1562.004", "netsh advfirewall set allprofiles state off"),
        ("Remote service via sc", "T1021.002", "sc \\\\host create с binPath"),
        ("Renamed system binary", "T1036.003", "powershell под именем svchost.exe"),
        ("Process hollowing", "T1055.012", "запись в память дочернего процесса"),
        ("Token theft via handle", "T1134.001", "DuplicateToken от привилегированного процесса"),
        ("Registry run key persist", "T1547.001", "запись в HKCU/HKLM Run"),
        ("Scheduled task created", "T1053.005", "создание задания через COM/schtasks"),
        ("DLL search order hijack", "T1574.001", "подмена DLL в каталоге приложения"),
        ("Parent PID spoofing", "T1134.004", "несоответствие parent/child PID"),
        ("Suspicious driver load", "T1543.003", "загрузка неподписанного драйвера"),
        ("Office spawns script host", "T1059.005", "winword→wscript/cscript"),
        ("Credential file access", "T1552.001", "чтение .aws/credentials, .ssh/id_rsa"),
        ("Clipboard data capture", "T1115", "массовое чтение буфера обмена"),
        ("Screen capture tool", "T1113", "запуск утилит скриншотов в фоне"),
        ("Net recon burst", "T1087", "серия net user/net group/whoami"),
    ]

    def __init__(self, author, lead):
        self.author = author
        self.lead = lead
        self.pid = _repo("edr-integration", "detection-rules")

    def run(self):
        vendor = random.choice(self.VENDORS)
        title_e, tech, pattern = random.choice(self.BEHAVIORS)
        slug = _slug(f"{vendor}-{title_e}")
        rule = (f"title: {title_e}\n"
                f"id: {slug}\n"
                f"vendor: {vendor}\n"
                "type: custom_ioa\n"
                f"description: {pattern}\n"
                f"author: {self.author.name}\n"
                f"date: {date.today().isoformat()}\n"
                f"detection:\n  process_pattern: \"{pattern}\"\n"
                f"  action: {random.choice(['detect','block','quarantine'])}\n"
                f"severity: {random.choice(['high','critical'])}\n"
                f"tags:\n  - attack.{tech.lower()}\n  - edr.{vendor}\n")
        readme = (f"# EDR rule: {title_e}\n\nVendor: **{vendor}**, MITRE {tech}.\n\n"
                  f"Паттерн: `{pattern}`.\nПротестировано в режиме detect перед block.\n")
        files = [
            (f"rules/{vendor}/{slug}.yml", rule, f"edr({vendor}): {title_e} [{tech}]"),
            (f"rules/{vendor}/{slug}.md", readme, f"docs(edr): notes for {title_e}"),
        ]
        return self._do(
            f"edr/{slug[:24]}", files,
            f"edr({vendor}): {title_e}",
            f"## EDR IOA `{title_e}`\n\n**Vendor:** {vendor} · **MITRE:** {tech}\n\n"
            f"Паттерн: `{pattern}`. Сначала detect, после валидации — block.",
            "IOA корректен, режим detect на обкатку. Merge.", emoji="shield")


# =======================================================================
#  SOC AUTOMATION (SOAR)
# =======================================================================
class AutomationActivity(_MixinCycle):
    """SOAR-автоматизация: enrichment/containment/notify."""

    PLAYS = [
        ("ip-reputation-enrich", "enrichment", "обогащение IP через TI-фиды"),
        ("isolate-host", "containment", "изоляция хоста через EDR API"),
        ("disable-user", "containment", "блокировка учётки в AD/Azure"),
        ("phishing-triage", "triage", "разбор репорта о фишинге из почты"),
        ("auto-ticket", "notify", "создание тикета и нотификация дежурного"),
        ("hash-lookup", "enrichment", "проверка хэша в sandbox/TI"),
        ("block-ioc-edr", "containment", "добавление IOC в blocklist EDR"),
        ("revoke-sessions", "containment", "отзыв активных сессий пользователя"),
        ("snapshot-host", "forensics", "снятие образа диска/памяти хоста"),
        ("enrich-domain", "enrichment", "WHOIS/passive DNS по домену"),
        ("notify-slack", "notify", "оповещение канала дежурных в Slack"),
        ("quarantine-email", "containment", "карантин фишингового письма у получателей"),
        ("geo-enrich-ip", "enrichment", "гео/ASN-обогащение IP-адреса"),
        ("disable-oauth-app", "containment", "отзыв подозрительного OAuth-приложения"),
        ("reset-ad-password", "containment", "сброс пароля учётки в AD"),
        ("pull-edr-timeline", "forensics", "выгрузка таймлайна процесса из EDR"),
        ("block-domain-dns", "containment", "блокировка домена на DNS-резолвере"),
        ("enrich-cve", "enrichment", "обогащение по CVE из NVD"),
        ("create-jira-incident", "notify", "создание инцидента в трекере"),
        ("collect-memory-dump", "forensics", "снятие дампа памяти процесса"),
        ("revoke-api-key", "containment", "отзыв скомпрометированного API-ключа"),
        ("enrich-user-context", "enrichment", "HR/AD-контекст по пользователю"),
        ("quarantine-file-edr", "containment", "карантин файла через EDR API"),
        ("page-oncall", "notify", "эскалация дежурному через PagerDuty"),
        ("sandbox-detonate", "enrichment", "детонация вложения в песочнице"),
        ("rotate-leaked-secret", "containment", "ротация утёкшего секрета в Vault"),
    ]

    def __init__(self, author, lead):
        self.author = author
        self.lead = lead
        self.pid = _repo("soc-automation", "playbooks", "detection-rules")

    def run(self):
        name, kind, desc_a = random.choice(self.PLAYS)
        slug = _slug(name)
        func = name.replace("-", "_")
        script = (f'"""SOAR action: {name} ({kind})\n{desc_a}\n'
                  'Секреты берутся из переменных окружения раннера (masked).\n"""\n'
                  "import os\nimport requests\n\n"
                  "API = os.environ.get(\"SOAR_API_URL\", \"\")\n"
                  "TOKEN = os.environ.get(\"SOAR_TOKEN\", \"\")  # masked CI variable\n\n"
                  f"def {func}(entity: str) -> dict:\n"
                  f"    headers = {{\"Authorization\": f\"Bearer {{TOKEN}}\"}}\n"
                  f"    resp = requests.post(f\"{{API}}/{kind}/{slug}\",\n"
                  f"                         json={{\"entity\": entity}}, headers=headers, timeout=30)\n"
                  "    resp.raise_for_status()\n"
                  "    return resp.json()\n\n\n"
                  "if __name__ == \"__main__\":\n"
                  f"    import sys\n    print({func}(sys.argv[1] if len(sys.argv) > 1 else \"test\"))\n")
        play = (f"name: {name}\nkind: {kind}\ndescription: {desc_a}\n"
                f"trigger: alert.type == '{kind}'\n"
                f"steps:\n  - run: automations/{slug}.py\n  - on_success: notify_oncall\n"
                "  - on_failure: escalate\n"
                f"owner: {self.author.name}\n")
        files = [
            (f"automations/{slug}.py", script, f"automation: {name} ({kind})"),
            (f"playbooks/{slug}.yml", play, f"soar: playbook for {name}"),
        ]
        return self._do(
            f"auto/{slug[:24]}", files,
            f"automation({kind}): {name}",
            f"## SOAR-автоматизация `{name}`\n\n**Тип:** {kind}\n\n{desc_a}\n\n"
            "Секреты — только из masked CI-переменных, не в коде.",
            "Логика и обработка ошибок ок, секреты в env. Approve.", emoji="robot")


# =======================================================================
#  INCIDENT RESPONSE
# =======================================================================
class IrRunbookActivity(_MixinCycle):
    """Runbook или postmortem для incident-response."""

    RUNBOOKS = [
        ("Ransomware outbreak", "T1486", ["Изолировать хосты", "Снять образы", "Найти patient zero", "Восстановить из бэкапа"]),
        ("Business email compromise", "T1078", ["Сбросить пароль/сессии", "Проверить правила пересылки", "Уведомить финансы"]),
        ("Web shell on server", "T1505.003", ["Снять веб-логи", "Удалить шелл", "Закрыть уязвимость", "Ротация секретов"]),
        ("Data exfiltration", "T1041", ["Заблокировать канал", "Оценить объём", "Привлечь юристов/комплаенс"]),
        ("Credential leak in repo", "T1552.001", ["Отозвать секрет", "Ротация", "Аудит доступа", "Скан истории git"]),
        ("Insider data theft", "T1052", ["Заблокировать доступ", "Снять DLP-логи", "Привлечь HR/юристов", "Оценить объём"]),
        ("Supply chain compromise", "T1195", ["Зафиксировать версию пакета", "Откатить деплой", "Проверить артефакты", "Ротация ключей CI"]),
        ("DDoS attack", "T1498", ["Включить WAF/anti-DDoS", "Связаться с провайдером", "Масштабировать", "Постмортем"]),
        ("Privilege escalation", "T1068", ["Изолировать хост", "Снять артефакты", "Закрыть уязвимость", "Ротация учёток"]),
        ("Malware on endpoint", "T1059", ["Карантин файла", "Изоляция хоста", "Сканирование сети", "Восстановление"]),
        ("Phishing campaign", "T1566", ["Отозвать письма", "Заблокировать отправителя", "Сбросить пароли кликнувших", "Уведомить сотрудников"]),
        ("Account takeover", "T1078", ["Сбросить сессии", "Включить MFA", "Проверить правила почты", "Аудит действий"]),
        ("Cloud key compromise", "T1552", ["Отозвать ключ", "Ротация", "Аудит CloudTrail", "Проверить ресурсы"]),
        ("Lateral movement detected", "T1021", ["Изолировать хосты", "Сбросить пароли", "Найти точку входа", "Заблокировать SMB/RDP"]),
        ("DNS tunneling exfil", "T1071.004", ["Заблокировать домен", "Изолировать хост", "Оценить объём", "Снять PCAP"]),
        ("Privilege escalation AD", "T1068", ["Снять артефакты", "Закрыть уязвимость", "Сбросить krbtgt дважды", "Аудит групп"]),
        ("Insider exfiltration", "T1052", ["Заблокировать доступ", "DLP-логи", "Юристы/HR", "Сохранить доказательства"]),
        ("Crypto-mining on servers", "T1496", ["Остановить процесс", "Найти точку входа", "Патч", "Мониторинг нагрузки"]),
        ("S3 data exposure", "T1530", ["Закрыть бакет", "Оценить доступ", "Ротация данных", "Уведомить комплаенс"]),
        ("Supply chain package", "T1195.002", ["Снять версию", "Откатить", "Аудит зависимостей", "Ротация CI-ключей"]),
    ]

    def __init__(self, author, lead):
        self.author = author
        self.lead = lead
        self.pid = _repo("incident-response", "playbooks")

    def run(self):
        make_pm = random.random() < 0.4
        title_i, tech, steps = random.choice(self.RUNBOOKS)
        slug = _slug(title_i)
        if make_pm:
            sev = random.choice(["SEV1", "SEV2", "SEV3"])
            body = (f"# Postmortem: {title_i}\n\n"
                    f"**ID:** INC-{random.randint(1000,9999)} · **Severity:** {sev}\n"
                    f"**Дата:** {date.today().isoformat()} · **Автор:** {self.author.name}\n\n"
                    f"## Краткое описание\nИнцидент класса «{title_i}» (MITRE {tech}).\n\n"
                    f"## Таймлайн\n- T0 обнаружение\n- T+{random.randint(5,40)}m сдерживание\n"
                    f"- T+{random.randint(1,8)}h устранение\n\n"
                    "## Причина\nНедостаточное покрытие детектами на раннем этапе.\n\n"
                    "## Что сделали\n" + "".join(f"- {s}\n" for s in steps) +
                    "\n## Уроки и действия\n- [ ] Новое детект-правило\n"
                    "- [ ] Обновить runbook\n- [ ] Тренинг команды\n")
            path = f"postmortems/{date.today().isoformat()}_{slug}.md"
            commit = f"postmortem: {title_i} ({tech})"
            ttl = f"postmortem: {title_i}"
            cmt = "Постмортем без поиска виноватых, action items заведены. Merge."
        else:
            body = (f"# Runbook: {title_i}\n\n**MITRE:** {tech}\n"
                    f"**Владелец:** {self.author.name} · {date.today().isoformat()}\n\n"
                    f"## Когда применять\nПри подтверждённом инциденте «{title_i}».\n\n"
                    "## Шаги реагирования\n" +
                    "".join(f"{i+1}. {s}\n" for i, s in enumerate(steps)) +
                    "\n## Эскалация\nSEV1/2 → IR-lead + менеджмент.\n\n"
                    "## Контакты\n- Дежурный SOC\n- IR-команда\n- Юристы (при утечке ПДн)\n")
            path = f"runbooks/{slug}.md"
            commit = f"runbook: {title_i} ({tech})"
            ttl = f"runbook: {title_i}"
            cmt = "Шаги полные, эскалация описана. Approve."
        files = [(path, body, commit)]
        return self._do(
            f"ir/{slug[:24]}", files, ttl,
            f"## {'Postmortem' if make_pm else 'Runbook'} `{title_i}`\n\n"
            f"**MITRE:** {tech}\n\nДокумент реагирования на инцидент.",
            cmt, emoji="rotating_light")


# =======================================================================
#  ML-ANOMALY-ENGINE
# =======================================================================
class MlEngineActivity(_MixinCycle):
    """Работа ML-инженера в ml-anomaly-engine.

    Зачем добавлено. Репозиторий числился в PROJECTS и в онбординг-документе
    как «ML-система (anna.smirnova)», но НИ ОДНА активность в него не писала:
    единственное упоминание в коде — фолбэк в activities/quirks.py. На живом
    прогоне он получил 1.3% событий против 14-15% у соседних репозиториев, то
    есть выглядел заброшенным — при том, что тема ML заявлена ключевой.

    Что делает: полный цикл ML-инженера — спецификация признаков, ноутбук
    обучения, model card, отчёт об оценке, конфиг дрейфа. Это ровно те
    артефакты, которые лежат в настоящем репозитории детекционной ML-модели,
    и они дают контентные признаки (высокая энтропия в весах, .env-подобные
    конфиги), на которых детектору есть чему учиться.
    """

    TASKS = [
        ("feature-spec", "Спецификация признаков события"),
        ("training", "Обучение модели аномалий"),
        ("evaluation", "Оценка качества на holdout"),
        ("model-card", "Model card выпущенной версии"),
        ("drift-monitor", "Мониторинг дрейфа признаков"),
        ("threshold-tuning", "Пересчёт порога под бюджет тревог"),
        ("feature-importance", "Разбор вкладов признаков"),
        ("data-quality", "Проверки качества датасета"),
    ]

    FAMILIES = ["secret_leak", "mass_deletion", "recon", "exfiltration",
                "priv_escalation", "supply_chain", "pipeline_abuse"]

    def __init__(self, author, lead):
        self.author = author
        self.lead = lead
        self.pid = _repo("ml-anomaly-engine", "detection-rules")

    def _metrics(self):
        """Правдоподобные метрики: PR-AUC заметно ниже ROC-AUC при дисбалансе."""
        roc = round(random.uniform(0.86, 0.97), 3)
        base = round(random.uniform(0.004, 0.03), 4)
        pr = round(min(roc - 0.2, base * random.uniform(8, 30)), 3)
        return roc, pr, base

    def run(self):
        kind, title_t = random.choice(self.TASKS)
        ver = f"v{random.randint(1, 4)}.{random.randint(0, 9)}"
        roc, pr, base = self._metrics()
        today = date.today().isoformat()
        files = []

        if kind == "feature-spec":
            rows = "\n".join(
                f"| `{n}` | {t} | {d} |" for n, t, d in [
                    ("hour_norm", "float", "час события / 23"),
                    ("is_night", "bool", "вне рабочих часов"),
                    ("n_regex_hits", "int", "сработавших secret-сигнатур"),
                    ("entropy_norm", "float", "энтропия Шеннона / 8"),
                    ("burst_any_30m", "int", "событий актора за 30 минут"),
                    ("distinct_projects_1h", "int", "разных репозиториев за час"),
                    ("token_scope_api", "bool", "scope токена api|sudo"),
                ])
            files.append((
                "docs/feature_spec.md",
                f"# Feature spec {ver}\n\n**Обновлено:** {today} · **Автор:** {self.author.name}\n\n"
                "Вектор признаков события. Порядок ЗАФИКСИРОВАН и сохраняется вместе\n"
                "с моделью: при загрузке список сверяется, иначе слой выключается.\n\n"
                "| Признак | Тип | Смысл |\n|---------|-----|-------|\n" + rows +
                "\n\n## Анти-лик\nНа вход подаются только наблюдаемые поля события.\n"
                "Метки мира (is_anomaly, family, episode_id) в вектор не попадают —\n"
                "проверяется тестом на взаимную информацию.\n",
                f"docs(features): spec {ver}"))

        elif kind == "training":
            files.append((
                "notebooks/train_anomaly.py",
                '"""Обучение детектора аномалий. Запуск: python notebooks/train_anomaly.py"""\n'
                "import json\nimport numpy as np\nfrom sklearn.linear_model import LogisticRegression\n"
                "from sklearn.metrics import average_precision_score, roc_auc_score\n\n"
                "SEED = 42\n"
                f"TARGET_FP = {round(random.uniform(0.0005, 0.005), 4)}\n\n\n"
                "def load(path):\n"
                "    with open(path, encoding='utf-8') as f:\n"
                "        return [json.loads(line) for line in f if line.strip()]\n\n\n"
                "def split_by_time(rows, tr=0.6, va=0.2):\n"
                '    """Хронологический сплит: события эпизода идут подряд,\n'
                '    случайное перемешивание завысило бы качество."""\n'
                "    n = len(rows)\n"
                "    i1, i2 = int(n * tr), int(n * (tr + va))\n"
                "    return rows[:i1], rows[i1:i2], rows[i2:]\n\n\n"
                "def main():\n"
                "    rows = load('data/events.jsonl')\n"
                "    train, val, test = split_by_time(rows)\n"
                "    clf = LogisticRegression(class_weight='balanced', max_iter=2000,\n"
                "                             random_state=SEED)\n"
                "    clf.fit([r['x'] for r in train], [r['y'] for r in train])\n"
                "    p = clf.predict_proba([r['x'] for r in test])[:, 1]\n"
                "    y = [r['y'] for r in test]\n"
                "    print('PR-AUC ', round(average_precision_score(y, p), 4))\n"
                "    print('ROC-AUC', round(roc_auc_score(y, p), 4))\n\n\n"
                "if __name__ == '__main__':\n    main()\n",
                f"feat(training): pipeline {ver}"))

        elif kind == "evaluation":
            fam = "\n".join(f"| {f} | {random.randint(3,20)} | {random.randint(40,95)}% |"
                            for f in random.sample(self.FAMILIES, k=4))
            files.append((
                f"reports/eval_{ver}.md",
                f"# Оценка модели {ver}\n\n**Дата:** {today} · **Автор:** {self.author.name}\n\n"
                "## Метрики на holdout\n\n"
                f"| Метрика | Значение | Комментарий |\n|---------|----------|-------------|\n"
                f"| PR-AUC | {pr} | база = доля класса {base} |\n"
                f"| ROC-AUC | {roc} | при дисбалансе льстит модели |\n"
                f"| Brier | {round(random.uniform(0.004, 0.02), 4)} | сравнивать с константой |\n"
                f"| ECE | {round(random.uniform(0.003, 0.04), 4)} | калибровка по 10 бинам |\n\n"
                "> ROC-AUC приводится только для сравнимости с литературой. Решение\n"
                "> принимается по PR-AUC: при доле атак меньше процента знаменатель\n"
                "> FPR огромен, и ROC остаётся высоким даже у бесполезной модели.\n\n"
                "## Эпизодный recall по семействам\n\n"
                "| Семейство | Эпизодов | Recall |\n|-----------|----------|--------|\n" + fam +
                "\n\n## Выводы\n- Порог подобран под бюджет тревог, а не по F1.\n"
                "- Интервалы — Уилсон 95%; точечная оценка без интервала вводит в заблуждение.\n",
                f"docs(eval): holdout report {ver}"))

        elif kind == "model-card":
            files.append((
                f"models/CARD_{ver}.md",
                f"# Model card — anomaly-detector {ver}\n\n"
                f"**Выпущена:** {today} · **Владелец:** {self.author.name}\n\n"
                "## Назначение\nПриоритизация событий git/CI по вероятности вредоносности.\n"
                "Слой L2 детекционного конвейера; сама по себе тревог не создаёт —\n"
                "поднимает приоритет, когда согласна с правилом или поведенческим слоем.\n\n"
                "## Данные\nЖурнал событий стенда, хронологический сплит.\n"
                f"Доля положительного класса: {base}.\n\n"
                f"## Качество\nPR-AUC {pr} (база {base}), ROC-AUC {roc}.\n\n"
                "## Ограничения\n"
                "- Обучена на одном контуре; на другом наборе репозиториев требуется переобучение.\n"
                "- Не различает намерение: легитимная миграция и массовое удаление выглядят похоже.\n"
                "- Калибровка действительна, пока базовая частота атак не изменилась.\n\n"
                "## Переобучение\nПри дрейфе признаков или падении PR-AUC ниже базовой линии.\n",
                f"docs(model): card {ver}"))

        elif kind == "drift-monitor":
            files.append((
                "monitoring/drift.yml",
                f"# Мониторинг дрейфа признаков\nversion: {ver}\nupdated: {today}\n"
                f"owner: {self.author.name}\n\n"
                "reference_window: 14d\ncurrent_window: 1d\n\nchecks:\n"
                "  - feature: entropy_norm\n    test: population_stability_index\n"
                f"    warn: {round(random.uniform(0.1, 0.2), 2)}\n"
                f"    alert: {round(random.uniform(0.25, 0.4), 2)}\n"
                "  - feature: burst_any_30m\n    test: kolmogorov_smirnov\n"
                "    warn: 0.05\n    alert: 0.01\n"
                "  - feature: act_push\n    test: chi_square\n    warn: 0.05\n    alert: 0.01\n\n"
                "on_alert:\n  - notify: soc-ml\n  - action: retrain_candidate\n",
                f"feat(monitoring): drift checks {ver}"))

        elif kind == "threshold-tuning":
            files.append((
                "configs/threshold.json",
                json.dumps({
                    "version": ver, "updated": today, "owner": self.author.username,
                    "policy": "alert_budget",
                    "target_fp_rate": round(random.uniform(0.0005, 0.003), 5),
                    "rationale": ("Порог задаётся бюджетом тревог аналитика, а не "
                                  "максимумом F1: F1 неявно приравнивает цену FP и FN, "
                                  "что для SOC неверно."),
                    "threshold": round(random.uniform(0.4, 0.9), 4),
                    "expected_alerts_per_day": random.randint(2, 12),
                }, ensure_ascii=False, indent=2) + "\n",
                f"chore(threshold): recalibrate {ver}"))

        elif kind == "feature-importance":
            rows = "\n".join(
                f"| `{n}` | {round(random.uniform(-1.2, 1.2), 3):+} |" for n in
                random.sample(["entropy_norm", "burst_any_30m", "n_regex_hits",
                               "is_night", "token_scope_api", "self_merged",
                               "distinct_projects_1h", "path_secretdir",
                               "obfuscation_sig", "net_sink_sig"], k=7))
            files.append((
                f"reports/importance_{ver}.md",
                f"# Вклады признаков — {ver}\n\n**Дата:** {today} · **Автор:** {self.author.name}\n\n"
                "Модель линейная, поэтому вклад признака в маржу равен `w·z` и\n"
                "раскладывает скор ТОЧНО, а не приближённо.\n\n"
                "| Признак | Вес (станд. шкала) |\n|---------|--------------------|\n" + rows +
                "\n\n> Отрицательный вес — признак СНИЖАЕТ риск. Это не ошибка:\n"
                "> модель обязана уметь оправдывать событие, иначе она детектор шума.\n",
                f"docs(explain): feature importance {ver}"))

        else:  # data-quality
            files.append((
                "tests/test_dataset.py",
                '"""Проверки качества датасета перед обучением."""\n'
                "import json\nimport collections\n\n"
                "LEAKY = {'is_anomaly', 'family', 'episode_id', 'anomaly_type'}\n\n\n"
                "def test_no_label_columns(rows):\n"
                "    bad = [k for r in rows[:200] for k in r.get('x_named', {}) if k in LEAKY]\n"
                "    assert not bad, f'метка в признаках: {sorted(set(bad))}'\n\n\n"
                "def test_class_balance(rows):\n"
                "    p = sum(r['y'] for r in rows) / max(1, len(rows))\n"
                "    assert 0.0001 < p < 0.2, f'подозрительная доля класса: {p}'\n\n\n"
                "def test_no_duplicate_events(rows):\n"
                "    c = collections.Counter(json.dumps(r['x']) for r in rows)\n"
                "    top = c.most_common(1)[0][1] if c else 0\n"
                "    assert top < len(rows) * 0.1, 'дубликаты вектора признаков'\n",
                f"test(data): dataset quality checks {ver}"))

        return self._do(
            f"ml/{kind}-{ver}", files,
            f"ml({kind}): {title_t} {ver}",
            f"## {title_t}\n\n**Версия:** {ver}\n\n"
            f"Метрики на holdout: PR-AUC {pr} (база {base}), ROC-AUC {roc}.\n\n"
            "Обрати внимание на PR-AUC, а не на ROC: при доле атак меньше процента\n"
            "ROC-AUC высок даже у слабой модели.",
            "Метрики честные, база класса указана. Approve.", emoji="brain")
