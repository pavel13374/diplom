"""
Новые ТИПЫ рабочих процессов (не просто наполнение банков) — дают новые паттерны
поведения для будущего UEBA:

  IterativeReviewActivity  — многораундовое код-ревью: автор открывает MR,
        ревьюер просит правки, автор пушит доп. коммиты и отвечает (2-3 итерации),
        затем approve+merge. Паттерн «диалог + серия мелких коммитов в одну ветку».
  DependencyAuditActivity  — security-аудит зависимостей: находим уязвимые пакеты
        (с CVE), бампим версии, прикладываем отчёт. Паттерн «advisory → fix».
  SprintRetroActivity      — ретроспектива спринта: лид заводит issue с разделами,
        команда комментирует. Паттерн «коллаборация многих в одном тикете».

Все действия штатные (is_anomaly=false) — богатый фон для детектора.
"""
import random
import logging
from datetime import date

import config
from config import DELAYS
from activities import flow

logger = logging.getLogger(__name__)


# =======================================================================
#  Многораундовое код-ревью
# =======================================================================
class IterativeReviewActivity:
    """MR с несколькими раундами правок по замечаниям ревьюера."""

    REVIEW_NOTES = [
        "Добавь ссылку на MITRE-технику в описание.",
        "Условие слишком широкое — сузь по родительскому процессу.",
        "Вынеси повторяющийся селект в общий блок.",
        "Не хватает негативного тест-семпла, добавь.",
        "Уточни severity — для prod это скорее medium.",
        "Поле не из ECS, приведи к схеме.",
        "Добавь раздел false positives с примерами.",
        "Тайминг агрегации great, но уменьши окно до 10m.",
    ]
    AUTHOR_REPLIES = [
        "Поправил, посмотри ещё раз.",
        "Согласен, сузил условие по parent_image.",
        "Вынес селект в template, переиспользую.",
        "Добавил негативный семпл и прогнал тесты — зелёные.",
        "Снизил severity до medium, обновил мету.",
        "Привёл поле к ECS (process.parent.name).",
        "Дописал секцию FP с примерами легитимных источников.",
        "Уменьшил окно до 10m, перекалибровал порог.",
    ]
    FILES = [
        ("rules/review", "yml", "detection rule"),
        ("content/correlation", "yml", "correlation"),
        ("hunts", "md", "hunt note"),
    ]

    def __init__(self, author, lead):
        self.author = author
        self.lead = lead
        self.pid = config.populated_rule_repo(author.gl)

    def run(self) -> bool:
        topic = random.choice([
            "suspicious_powershell", "lateral_smb", "cloud_iam_change",
            "dns_exfil", "service_install", "token_theft", "webshell_drop"])
        sub, ext, kind = random.choice(self.FILES)
        slug = f"{topic}_{random.randint(100,999)}"
        path = f"{sub}/{slug}.{ext}"
        branch = self.author.unique_branch(f"review/{topic[:16]}")

        if not self.author.create_branch(self.pid, branch):
            return False
        self.author.think()

        body = (f"# {kind}: {topic}\n\n"
                f"status: draft\nauthor: {self.author.name}\ndate: {date.today().isoformat()}\n"
                f"detection:\n  selection:\n    image|endswith: '\\\\{topic}.exe'\n"
                "  condition: selection\nlevel: high\n")
        if not self.author.push_file(self.pid, path, body,
                                     f"feat({kind}): draft {topic}", branch):
            return False
        self.author.commit_pause()

        title = f"feat({kind}): {topic.replace('_',' ')}"
        mr = self.author.create_mr(self.pid, branch, title,
                                   f"Черновик правила `{topic}`. Прошу ревью.", config.lead_id())
        if not mr:
            return False

        # 2-3 раунда замечаний/правок
        rounds = random.randint(2, 3)
        notes = random.sample(self.REVIEW_NOTES, rounds)
        for i in range(rounds):
            self.lead.think(DELAYS["agent_think"])
            self.lead.comment_mr(self.pid, mr, f"🔎 {notes[i]}")
            self.author.think(DELAYS["agent_think"])
            body += f"# review fix {i+1}: {notes[i][:40]}\n"
            self.author.push_file(self.pid, path, body,
                                  f"fix(review): round {i+1} — address feedback", branch)
            self.author.commit_pause()
            self.author.comment_mr(self.pid, mr, random.choice(self.AUTHOR_REPLIES))

        self.lead.think(DELAYS["review_wait"])
        return flow.approve_and_merge(self.lead, self.author, self.pid, mr, branch=branch,
                                      approve_comment="Теперь хорошо, спасибо за итерации. Merge.",
                                      emoji="rocket")


# =======================================================================
#  Security-аудит зависимостей
# =======================================================================
class DependencyAuditActivity:
    """Аудит зависимостей: найдены уязвимые пакеты (CVE) → бамп + отчёт."""

    VULNS = [
        ("requests", "2.19.1", "2.32.3", "CVE-2023-32681", "high", "утечка заголовков при redirect"),
        ("pyyaml", "5.1", "6.0.1", "CVE-2020-14343", "critical", "произвольное исполнение при load"),
        ("urllib3", "1.25.2", "2.2.2", "CVE-2023-43804", "high", "утечка cookie на redirect"),
        ("jinja2", "2.10", "3.1.4", "CVE-2024-22195", "medium", "XSS через xmlattr"),
        ("cryptography", "3.2", "42.0.8", "CVE-2023-50782", "high", "Bleichenbacher timing"),
        ("flask", "1.0", "3.0.3", "CVE-2023-30861", "high", "кэширование cookie сессии"),
        ("aiohttp", "3.7.4", "3.9.5", "CVE-2024-23334", "high", "directory traversal"),
        ("pillow", "8.1.0", "10.3.0", "CVE-2023-44271", "medium", "DoS при обработке шрифтов"),
        ("lxml", "4.6.2", "5.2.2", "CVE-2022-2309", "medium", "NULL deref в обработке"),
        ("paramiko", "2.7.1", "3.4.0", "CVE-2023-48795", "high", "Terrapin SSH-атака"),
    ]

    def __init__(self, author, lead):
        self.author = author
        self.lead = lead
        name = random.choice([n for n in config.WORK_REPOS if n != "soc-secrets"])
        self.pid = config.WORK_REPOS[name]

    def run(self) -> bool:
        picks = random.sample(self.VULNS, k=random.randint(2, 4))
        branch = self.author.unique_branch("security/dep-audit")
        if not self.author.create_branch(self.pid, branch):
            return False
        self.author.think()

        # отчёт об аудите
        rep = (f"# Dependency Security Audit — {date.today().isoformat()}\n\n"
               f"Аудитор: {self.author.name}\nИнструмент: pip-audit / safety\n\n"
               "| Пакет | Текущая | Исправлено в | CVE | Severity | Описание |\n"
               "|---|---|---|---|---|---|\n")
        for pkg, cur, fix, cve, sev, desc in picks:
            rep += f"| {pkg} | {cur} | {fix} | {cve} | {sev} | {desc} |\n"
        rep += "\n## Действия\n- Обновить пакеты до исправленных версий\n- Перепрогнать тесты\n"
        apath = f"security/audit_{date.today().strftime('%Y%m%d')}_{random.randint(10,99)}.md"
        if not self.author.push_file(self.pid, apath, rep,
                                     "security: dependency audit report", branch):
            return False
        self.author.commit_pause()

        # бамп версий
        reqs = "# pinned secure versions\n" + "".join(f"{p}=={fix}\n" for p, _, fix, *_ in picks)
        self.author.push_file(self.pid, "requirements.txt", reqs,
                              "fix(deps): bump vulnerable packages to patched versions", branch)
        self.author.commit_pause()

        crit = [p for p in picks if p[4] == "critical"]
        title = f"security(deps): patch {len(picks)} vulnerable packages"
        desc = ("## Аудит зависимостей\n\nОбновлены уязвимые пакеты:\n"
                + "".join(f"- `{p[0]}` {p[1]}→{p[2]} ({p[3]}, {p[4]})\n" for p in picks)
                + ("\n⚠️ Есть **critical** — катим вне очереди.\n" if crit else ""))
        mr = self.author.create_mr(self.pid, branch, title, desc, config.lead_id())
        if not mr:
            return False
        self.author.think(3)
        self.author.comment_mr(self.pid, mr, "Прогнал pip-audit повторно — чисто.")
        self.lead.think(DELAYS["agent_think"])
        return flow.approve_and_merge(self.lead, self.author, self.pid, mr, branch=branch,
                                      approve_comment="Критичные CVE закрыты, тесты зелёные. Merge.",
                                      emoji="shield")


# =======================================================================
#  Ретроспектива спринта
# =======================================================================
class SprintRetroActivity:
    """Лид заводит issue ретро, команда комментирует (коллаборация многих)."""

    GOOD = [
        "Закрыли бэклог детектов по облаку.",
        "MTTR по SEV2 снизился на 20%.",
        "Наладили hunt-ритм — 2 гипотезы в неделю.",
        "Меньше флапающих правил после тюнинга.",
        "Хорошо отработала ротация on-call.",
    ]
    BAD = [
        "Много FP по правилу lateral movement.",
        "Пайплайн долго гоняет тесты на больших наборах.",
        "Не успели с парсером для o365.",
        "Документация плейбуков отстаёт.",
        "Были конфликты MR из-за параллельных правок.",
    ]
    ACTIONS = [
        "Завести шаблон негативных семплов.",
        "Разбить большой rule-set на модули для CI.",
        "Назначить владельца парсеров o365.",
        "Ввести правило: маленькие MR, частый merge.",
        "Добавить дашборд FP-рейта на ретро.",
    ]

    def __init__(self, agents, lead, state=None):
        self.agents = agents
        self.lead = lead
        self.state = state
        self.pid = config.playbook_repo_id()

    def run(self) -> bool:
        sprint = (self.state.ensure_sprint()[0] if self.state else random.randint(1, 30))
        title = f"Sprint {sprint} — ретроспектива"
        body = ("## Ретроспектива спринта\n\n"
                "**Что прошло хорошо:**\n" + "".join(f"- {x}\n" for x in random.sample(self.GOOD, 3)) +
                "\n**Что улучшить:**\n" + "".join(f"- {x}\n" for x in random.sample(self.BAD, 3)) +
                "\n**Action items:**\n" + "".join(f"- [ ] {x}\n" for x in random.sample(self.ACTIONS, 3)) +
                "\nКоманда — добавьте свои пункты в комментариях.")
        iid = self.lead.create_issue(self.pid, title, body, labels=["type::retro"])
        if not iid:
            return False

        notes = [
            "Согласен по FP — возьму тюнинг на следующей неделе.",
            "Могу заняться парсером o365.",
            "Давайте действительно дробить MR — меньше конфликтов.",
            "Добавлю негативные семплы в шаблон.",
            "По облаку коврередж вырос, продолжим в том же темпе.",
            "Предлагаю авто-линт в pre-commit, ловить раньше.",
        ]
        for uname in config.engineer_usernames():
            agent = self.agents.get(uname)
            if not agent:
                continue
            if random.random() < 0.6:   # не все отмечаются
                agent.think(2)
                agent.comment_issue(self.pid, iid, f"**{agent.name}:** {random.choice(notes)}")
        if random.random() < 0.7:
            self.lead.comment_issue(self.pid, iid, "Спасибо всем. Action items занёс в бэклог.")
        return True
