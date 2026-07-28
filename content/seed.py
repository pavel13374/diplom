"""
Стартовый посев репозиториев. Чтобы специализированные репозитории не стояли
пустыми (один README) и у modify-активностей (fix/tune/triage) сразу была цель.

Посев идёт ПРЯМО в main под админ-токеном (без MR) на старте симулятора и только
если соответствующая папка ещё пуста — повторные запуски ничего не перезаписывают.
"""
import json
import random
from datetime import date


def _rule_yml(title, mitre, product, service, level="medium"):
    sid = "".join(c if c.isalnum() else "-" for c in title.lower()).strip("-")[:40]
    return (f"title: {title}\n"
            f"id: {sid}\n"
            "status: stable\n"
            f"description: Detects {title.lower()}\n"
            f"date: {date.today().isoformat()}\n"
            f"logsource:\n  product: {product}\n  service: {service}\n"
            f"detection:\n  selection:\n    EventID: {random.randint(1,5000)}\n"
            "  condition: selection\n"
            f"level: {level}\n"
            f"tags:\n  - attack.{mitre.lower()}\n")


def _hunt_md(title, mitre, lang):
    return (f"# Hunt: {title}\n\n**MITRE:** {mitre}\n**Язык:** {lang.upper()}\n\n"
            f"## Гипотеза\nИщем признаки техники {mitre} в телеметрии EDR/SIEM.\n\n"
            "## Шаги\n1. Базлайн 30 дней.\n2. Отклонения.\n3. Триаж и эскалация.\n")


def _runbook_md(title, mitre, steps):
    return (f"# Runbook: {title}\n\n**MITRE:** {mitre} · {date.today().isoformat()}\n\n"
            "## Шаги реагирования\n" + "".join(f"{i+1}. {s}\n" for i, s in enumerate(steps)) +
            "\n## Эскалация\nSEV1/2 → IR-lead + менеджмент.\n")


def _automation_py(name, kind):
    fn = name.replace("-", "_")
    return (f'"""SOAR action: {name} ({kind}). Секреты — из masked env раннера."""\n'
            "import os, requests\n\n"
            "API = os.environ.get('SOAR_API_URL', '')\n"
            "TOKEN = os.environ.get('SOAR_TOKEN', '')\n\n"
            f"def {fn}(entity):\n"
            f"    r = requests.post(f'{{API}}/{kind}/{name}', json={{'entity': entity}},\n"
            f"                      headers={{'Authorization': f'Bearer {{TOKEN}}'}}, timeout=30)\n"
            "    r.raise_for_status()\n    return r.json()\n")


# repo -> (key_dir_для_проверки_пустоты, [(path, content), ...])
def build():
    return {
        "threat-hunting": ("hunts", [
            ("hunts/README.md", "# Threat Hunting\n\nГипотезы и hunt-запросы команды.\n"),
            (f"hunts/{date.today().strftime('%Y%m')}_lsass_access.md",
             _hunt_md("LSASS memory access", "T1003.001", "kql")),
            ("hunts/queries/dns_tunneling.spl",
             "index=dns | stats count by query | where len(query) > 60\n"),
            ("hunts/queries/rare_parent_child.eql",
             'process where parent.name in ("winword.exe","excel.exe")\n'),
        ]),
        "cloud-detections": ("rules", [
            ("rules/README.md", "# Cloud Detections\n\nSigma-правила для AWS/Azure/GCP.\n"),
            ("rules/aws/root_account_used.yml",
             _rule_yml("Root account used", "T1078.004", "aws", "cloudtrail", "high")),
            ("rules/aws/s3_made_public.yml",
             _rule_yml("S3 bucket made public", "T1530", "aws", "cloudtrail", "high")),
            ("rules/azure/impossible_travel.yml",
             _rule_yml("Impossible travel sign-in", "T1078", "azure", "signinlogs", "medium")),
        ]),
        "siem-content": ("content", [
            ("content/README.md", "# SIEM Content\n\nКорреляции и дашборды.\n"),
            ("content/correlation/brute_force_success.yml",
             "name: Brute force then success\nseverity: high\nwindow_minutes: 10\n"
             "logic:\n  - where: EventID in [4625,4624]\n  - having: failed>=8 and success>=1\n"),
            ("content/dashboards/auth_overview.json",
             json.dumps({"title": "Auth overview", "panels": ["timechart", "table"]}, indent=2)),
        ]),
        "edr-integration": ("rules", [
            ("rules/README.md", "# EDR Integration\n\nПоведенческие IOA-правила.\n"),
            ("rules/crowdstrike/comsvcs_minidump.yml",
             _rule_yml("Credential dumping via comsvcs", "T1003", "windows", "edr", "high")),
            ("rules/defender/encoded_powershell.yml",
             _rule_yml("Encoded PowerShell", "T1059.001", "windows", "edr", "high")),
        ]),
        "soc-automation": ("automations", [
            ("automations/README.md", "# SOC Automation\n\nSOAR-автоматизации.\n"),
            ("automations/ip_reputation_enrich.py", _automation_py("ip-reputation-enrich", "enrichment")),
            ("automations/isolate_host.py", _automation_py("isolate-host", "containment")),
            ("playbooks/phishing_triage.yml",
             "name: phishing-triage\nkind: triage\nsteps:\n  - run: automations/ip_reputation_enrich.py\n"),
        ]),
        "incident-response": ("runbooks", [
            ("runbooks/README.md", "# Incident Response\n\nRunbooks и postmortem'ы.\n"),
            ("runbooks/ransomware.md",
             _runbook_md("Ransomware outbreak", "T1486",
                         ["Изолировать хосты", "Снять образы", "Найти patient zero", "Восстановить из бэкапа"])),
            ("runbooks/bec.md",
             _runbook_md("Business email compromise", "T1078",
                         ["Сбросить сессии", "Проверить правила пересылки", "Уведомить финансы"])),
        ]),
    }
