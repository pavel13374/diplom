"""
Активность: обновление плейбуков реагирования.
"""
import random
import logging
import config
from config import PROJECTS, USERS, DELAYS
from content import commit_messages as cm

logger = logging.getLogger(__name__)

PLAYBOOK_UPDATES = [
    {
        "path": "playbooks/credential_access/lsass_dump_response.md",
        "change": "add_impacket_ioc",
        "desc": "Add Impacket tool IOCs to investigation section",
    },
    {
        "path": "playbooks/ransomware/ransomware_response.md",
        "change": "update_sla",
        "desc": "Update notification SLA to match new regulatory requirements",
    },
    {
        "path": "playbooks/exfiltration/dns_exfiltration_response.md",
        "change": "add_investigation_commands",
        "desc": "Add DNS query analysis commands to investigation steps",
    },
    {
        "path": "playbooks/lateral_movement/pass_the_hash_response.md",
        "change": "add_crowdstrike_steps",
        "desc": "Add EDR isolation steps via CrowdStrike API",
    },
]

NEW_PLAYBOOKS = [
    {
        "path": "playbooks/persistence/registry_run_key.md",
        "title": "Registry Run Key Persistence",
        "tactic": "persistence",
        "mitre": "T1547.001",
    },
    {
        "path": "playbooks/defense_evasion/defender_disabled.md",
        "title": "Windows Defender Disabled",
        "tactic": "defense_evasion",
        "mitre": "T1562.001",
    },
    {
        "path": "playbooks/execution/powershell_encoded.md",
        "title": "Suspicious PowerShell Execution",
        "tactic": "execution",
        "mitre": "T1059.001",
    },
    {
        "path": "playbooks/impact/event_log_cleared.md",
        "title": "Windows Event Log Cleared",
        "tactic": "defense_evasion",
        "mitre": "T1070.001",
    },
]


class UpdatePlaybookActivity:
    """Lead или Detection Engineer обновляет плейбук."""

    def __init__(self, author_agent, lead_agent):
        self.author = author_agent
        self.lead   = lead_agent
        self.pid    = config.playbook_repo_id()

    def run(self) -> bool:
        # С вероятностью 50% — новый плейбук, иначе обновление существующего
        if random.random() < 0.50:
            return self._new_playbook()
        else:
            return self._update_existing()

    def _new_playbook(self) -> bool:
        pb     = random.choice(NEW_PLAYBOOKS)
        branch = self.author.unique_branch(f"feat/playbook-{pb['tactic'][:15]}")

        self.author.log(f"Adding new playbook: {pb['title']}")

        if not self.author.create_branch(self.pid, branch):
            return False
        self.author.think()

        content = self._generate_playbook(pb)
        msg     = cm.playbook_message(pb["tactic"])
        if not self.author.push_file(self.pid, pb["path"], content, msg, branch):
            return False
        self.author.commit_pause()

        lead_id = USERS["alex.petrov"]["id"]
        mr_iid  = self.author.create_mr(
            self.pid, branch,
            f"feat(playbooks): add {pb['title']} response guide",
            f"Новый плейбук для **{pb['title']}**.\n\nMITRE ATT&CK: {pb['mitre']}",
            lead_id,
        )
        if not mr_iid:
            return False

        self.lead.think(DELAYS["review_wait"])
        if random.random() < 0.40:
            self.lead.comment_mr(self.pid, mr_iid,
                                  "Добавь раздел с командами для forensics — полезно при расследовании.")
            self.author.think(DELAYS["agent_think"])
            self.author.comment_mr(self.pid, mr_iid,
                                    "Добавил раздел Investigation Commands. Посмотри обновлённую версию.")
            self.author.think(DELAYS["between_commits"])
            updated = content + self._forensics_appendix()
            self.author.push_file(self.pid, pb["path"], updated,
                                   "docs(playbooks): add forensics commands section", branch)
            self.author.commit_pause()

        self.lead.comment_mr(self.pid, mr_iid, "LGTM. Merge.")
        return self.lead.merge_mr(self.pid, mr_iid)

    def _update_existing(self) -> bool:
        update  = random.choice(PLAYBOOK_UPDATES)
        path    = update["path"]
        existing = self.author.gl.get_file(self.pid, path)
        if not existing:
            return self._new_playbook()

        slug   = path.split("/")[-1].replace(".md", "")
        branch = self.author.unique_branch(f"docs/playbook-{slug[:20]}")

        self.author.log(f"Updating playbook: {path}")

        if not self.author.create_branch(self.pid, branch):
            return False
        self.author.think()

        updated = existing + f"\n\n---\n\n## Обновление ({__import__('datetime').date.today().isoformat()})\n\n{update['desc']}\n\n*Автор: {self.author.name}*\n"
        msg = cm.playbook_message()
        if not self.author.push_file(self.pid, path, updated, msg, branch):
            return False
        self.author.commit_pause()

        lead_id = USERS["alex.petrov"]["id"]
        mr_iid  = self.author.create_mr(
            self.pid, branch,
            f"docs(playbooks): {update['desc'][:60]}",
            f"Обновление плейбука: {update['desc']}",
            lead_id,
        )
        if not mr_iid:
            return False

        self.lead.think(DELAYS["review_wait"])
        self.lead.comment_mr(self.pid, mr_iid, "Approve.")
        return self.lead.merge_mr(self.pid, mr_iid)

    def _generate_playbook(self, pb: dict) -> str:
        from datetime import date
        severity = random.choice(["High", "Critical", "Medium"])
        return """# Playbook: {pb['title']}

**Severity:** {severity}
**MITRE ATT&CK:** {pb['mitre']}
**Author:** {self.author.name}
**Created:** {date.today().isoformat()}

---

## Описание

Обнаружено событие типа **{pb['title']}**.
Требуется немедленное расследование и сдерживание.

---

## Шаги реагирования

### 1. Сдерживание (0–15 мин)

- [ ] Изолировать затронутый хост от сети
- [ ] Зафиксировать время обнаружения и источник алерта
- [ ] Уведомить SOC Lead если severity High/Critical

### 2. Расследование (15–60 мин)

- [ ] Собрать артефакты: процессы, сетевые соединения, файлы
- [ ] Проверить временную шкалу событий за 48 часов до алерта
- [ ] Идентифицировать пользователя и хост-источник
- [ ] Поискать lateral movement с данного хоста

### 3. Устранение

- [ ] Устранить механизм закрепления
- [ ] Заблокировать скомпрометированную учётную запись
- [ ] Ротировать секреты если были доступны

### 4. Восстановление

- [ ] Проверить целостность системы
- [ ] Восстановить из бэкапа при необходимости
- [ ] Провести post-mortem в течение 72 часов

---

## Связанные правила

- `detection-rules/{pb['tactic']}/`

---

## Индикаторы компрометации

```
Тип события:  {pb['title']}
MITRE:         {pb['mitre']}
Источники:     Windows Event Log, Sysmon, EDR
```
"""

    def _forensics_appendix(self) -> str:
        return """
## Investigation Commands

### Windows — сбор артефактов

```powershell
# Список запущенных процессов с путями
Get-Process | Select-Object Name, Id, Path, StartTime | Export-Csv processes.csv

# Сетевые соединения
netstat -ano | findstr ESTABLISHED

# Задачи планировщика
schtasks /query /fo LIST /v | findstr /i "task name|run as|status"

# Последние изменения в реестре Run keys
Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
Get-ItemProperty "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"

# Локальные пользователи
net user
Get-LocalUser | Where-Object {$_.Enabled -eq $true}
```

### Linux — сбор артефактов

```bash
# Запущенные процессы
ps auxf > /tmp/ir_processes.txt

# Сетевые соединения
ss -tupan > /tmp/ir_netstat.txt

# Cron задачи
crontab -l; ls -la /etc/cron*

# Последние входы
last -50; lastlog
```
"""
