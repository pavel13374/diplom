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
from datetime import date, datetime

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
    return config.PROJECTS["detection-rules"]


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
    ]
    LANGS = ["kql", "spl", "eql", "osquery"]

    def __init__(self, author, lead):
        self.author = author
        self.lead = lead
        self.pid = _repo("threat-hunting", "detection-rules")

    def _query(self, lang, tech):
        if lang == "kql":
            return (f"// Hunt for {tech}\nDeviceProcessEvents\n"
                    f"| where Timestamp > ago(7d)\n"
                    f"| where InitiatingProcessFileName in~ ('winword.exe','excel.exe','outlook.exe')\n"
                    f"| where FileName in~ ('cmd.exe','powershell.exe','wscript.exe')\n"
                    f"| summarize count() by DeviceName, AccountName, bin(Timestamp, 1h)\n"
                    f"| where count_ > {random.randint(3,9)}\n")
        if lang == "spl":
            return (f"`comment(\"Hunt {tech}\")`\nindex=edr sourcetype=process\n"
                    f"| stats count values(process) as procs by host, user\n"
                    f"| where count > {random.randint(5,15)}\n"
                    f"| sort - count\n")
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
                  f"## Источники данных\nEDR process telemetry, Windows Security, DNS logs\n\n"
                  f"## Шаги\n1. Базлайн за 30 дней.\n2. Выделить отклонения.\n"
                  f"3. Триаж кандидатов, эскалация TP в IR.\n\n"
                  f"## Результат\n- [ ] Найдены аномалии\n- [ ] Создано детект-правило\n")
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
                f"status: experimental\n"
                f"description: {desc_c}\n"
                f"author: {self.author.name}\n"
                f"date: {date.today().isoformat()}\n"
                f"logsource:\n  product: {cloud}\n  service: {source.lower()}\n"
                f"detection:\n  selection:\n    eventSource: {cloud}\n"
                f"    eventName: '{title_c.split()[0]}*'\n"
                f"  condition: selection\n"
                f"level: {level}\n"
                f"tags:\n  - attack.{tech.lower()}\n  - cloud.{cloud}\n"
                f"falsepositives:\n  - Authorized administrative change\n")
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
                f"logic:\n"
                f"  - source: windows_security\n    where: EventID in [4625,4624]\n"
                f"  - group_by: [src_ip, target_user]\n"
                f"  - having: failed_count >= {thr} AND success_count >= 1\n"
                f"actions:\n  - create_alert\n  - notify: soc-oncall\n")
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
                f"type: custom_ioa\n"
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
                  f'Секреты берутся из переменных окружения раннера (masked).\n"""\n'
                  f"import os\nimport requests\n\n"
                  f"API = os.environ.get(\"SOAR_API_URL\", \"\")\n"
                  f"TOKEN = os.environ.get(\"SOAR_TOKEN\", \"\")  # masked CI variable\n\n"
                  f"def {func}(entity: str) -> dict:\n"
                  f"    headers = {{\"Authorization\": f\"Bearer {{TOKEN}}\"}}\n"
                  f"    resp = requests.post(f\"{{API}}/{kind}/{slug}\",\n"
                  f"                         json={{\"entity\": entity}}, headers=headers, timeout=30)\n"
                  f"    resp.raise_for_status()\n"
                  f"    return resp.json()\n\n\n"
                  f"if __name__ == \"__main__\":\n"
                  f"    import sys\n    print({func}(sys.argv[1] if len(sys.argv) > 1 else \"test\"))\n")
        play = (f"name: {name}\nkind: {kind}\ndescription: {desc_a}\n"
                f"trigger: alert.type == '{kind}'\n"
                f"steps:\n  - run: automations/{slug}.py\n  - on_success: notify_oncall\n"
                f"  - on_failure: escalate\n"
                f"owner: {self.author.name}\n")
        files = [
            (f"automations/{slug}.py", script, f"automation: {name} ({kind})"),
            (f"playbooks/{slug}.yml", play, f"soar: playbook for {name}"),
        ]
        return self._do(
            f"auto/{slug[:24]}", files,
            f"automation({kind}): {name}",
            f"## SOAR-автоматизация `{name}`\n\n**Тип:** {kind}\n\n{desc_a}\n\n"
            f"Секреты — только из masked CI-переменных, не в коде.",
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
                    f"## Причина\nНедостаточное покрытие детектами на раннем этапе.\n\n"
                    f"## Что сделали\n" + "".join(f"- {s}\n" for s in steps) +
                    f"\n## Уроки и действия\n- [ ] Новое детект-правило\n"
                    f"- [ ] Обновить runbook\n- [ ] Тренинг команды\n")
            path = f"postmortems/{date.today().isoformat()}_{slug}.md"
            commit = f"postmortem: {title_i} ({tech})"
            ttl = f"postmortem: {title_i}"
            cmt = "Постмортем без поиска виноватых, action items заведены. Merge."
        else:
            body = (f"# Runbook: {title_i}\n\n**MITRE:** {tech}\n"
                    f"**Владелец:** {self.author.name} · {date.today().isoformat()}\n\n"
                    f"## Когда применять\nПри подтверждённом инциденте «{title_i}».\n\n"
                    f"## Шаги реагирования\n" +
                    "".join(f"{i+1}. {s}\n" for i, s in enumerate(steps)) +
                    f"\n## Эскалация\nSEV1/2 → IR-lead + менеджмент.\n\n"
                    f"## Контакты\n- Дежурный SOC\n- IR-команда\n- Юристы (при утечке ПДн)\n")
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
