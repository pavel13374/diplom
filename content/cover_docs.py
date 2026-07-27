"""
Правдоподобное «прикрытие» для аномальных активностей.

Зачем: раньше атакующий коммитил файлы вида `docs/change_ab12.md` с текстом
"self-approved change\n" — по такому файлу видно, что это симуляция, а не
работа человека. Настоящий инсайдер маскируется под обычную задачу: правит
changelog, дополняет раннбук, чинит опечатку в доке.

Здесь генерируются такие «обычные» файлы: осмысленный путь, связный текст,
нормальный commit message в conventional-commits. Никаких меток симулятора
в содержимом — иначе это была бы подсказка детектору.
"""
import random
from datetime import date

# --- куски настоящей рабочей документации SOC-команды ---------------------

# (slug каталога, заголовок, [(slug файла, тема)]) — пути только латиницей
_AREAS = [
    ("triage", "Триаж алертов", [("duty-queue", "очередь дежурного"),
                                 ("severity", "приоритизация по severity"),
                                 ("escalation-l2", "эскалация на L2"),
                                 ("first-response-sla", "SLA первичного разбора")]),
    ("onboarding", "Онбординг источников", [("new-source", "подключение нового источника"),
                                            ("parsing-check", "проверка парсинга"),
                                            ("ecs-mapping", "маппинг полей в ECS"),
                                            ("event-loss", "контроль потери событий")]),
    ("runbook", "Раннбуки реагирования", [("host-isolation", "изоляция хоста"),
                                          ("triage-package", "сбор триажного пакета"),
                                          ("credential-revoke", "отзыв учётных данных"),
                                          ("service-owner-notify", "уведомление владельца сервиса")]),
    ("tuning", "Тюнинг правил", [("fp-reduction", "снижение FP"),
                                 ("thresholds", "калибровка порогов"),
                                 ("service-accounts", "исключения для сервисных учёток"),
                                 ("legacy-review", "ревизия старых правил")]),
    ("coverage", "Покрытие ATT&CK", [("tactic-review", "ревизия покрытия по тактикам"),
                                     ("persistence-gaps", "пробелы в Persistence"),
                                     ("quarter-priorities", "приоритеты на квартал"),
                                     ("threat-model-sync", "сверка с threat model")]),
]

_FIXES = [
    ("уточнил формулировку в разделе «{sec}»", "docs: уточнить раздел {sec}"),
    ("поправил опечатку в примере команды", "docs: исправить опечатку в примере"),
    ("добавил ссылку на связанный раннбук", "docs: добавить ссылку на раннбук"),
    ("обновил таблицу владельцев сервисов", "docs: обновить владельцев сервисов"),
    ("привёл пути к логам к актуальным", "docs: актуализировать пути к логам"),
    ("дополнил чек-лист проверки перед закрытием", "docs: дополнить чек-лист закрытия"),
]

_CHANGELOG = [
    "поднял версию парсера до {v}",
    "добавил обработку поля `{f}`",
    "убрал дублирование событий при ретрае",
    "перевёл timestamp в UTC",
    "добавил тест на пустой payload",
]

_FIELDS = ["src_ip", "dst_port", "user_agent", "process_guid", "parent_image",
           "event_code", "session_id", "rule_name"]


def _v():
    return f"1.{random.randint(2, 9)}.{random.randint(0, 9)}"


def cover_doc(author: str = "", seed_key: str = ""):
    """Обычная правка документации: (путь, содержимое, commit message)."""
    if seed_key:
        random.seed(hash(seed_key) & 0xFFFF)
    slug, title, topics = random.choice(_AREAS)
    body_fix, msg = random.choice(_FIXES)
    fslug, sec = random.choice(topics)
    today = date.today().isoformat()

    content = (
        f"# {title}\n\n"
        f"_Обновлено: {today}_\n\n"
        f"## {sec.capitalize()}\n\n"
        f"{_para(sec)}\n\n"
        f"## Порядок действий\n\n"
        f"1. Проверить источник события и полноту полей.\n"
        f"2. Сопоставить с текущими правилами детектирования.\n"
        f"3. Зафиксировать решение в тикете дежурного.\n"
        f"4. При подтверждении — эскалировать по матрице ответственности.\n\n"
        f"## Заметки\n\n"
        f"- {body_fix.format(sec=sec)}\n"
        f"- открытые вопросы выносим на еженедельный разбор\n"
    )
    path = f"docs/{slug}/{fslug}.md"
    return path, content, msg.format(sec=sec)


def _para(sec):
    return (f"Раздел описывает, как команда работает с задачей «{sec}». "
            f"Ориентируемся на текущие SLA: первичный разбор — 15 минут, "
            f"полный разбор инцидента — 4 часа. Если событие не покрыто правилом, "
            f"заводим задачу на Detection Engineering и фиксируем пробел в матрице покрытия.")


def cover_changelog(component: str = "parser"):
    """Запись в changelog: (путь, содержимое, commit message)."""
    v = _v()
    items = random.sample(_CHANGELOG, k=min(3, len(_CHANGELOG)))
    lines = "\n".join("- " + i.format(v=v, f=random.choice(_FIELDS)) for i in items)
    content = (f"# Changelog — {component}\n\n"
               f"## {v} — {date.today().isoformat()}\n\n{lines}\n")
    return (f"docs/changelog/{component}.md", content,
            f"docs({component}): changelog {v}")


def cover_hotfix(service: str = "collector"):
    """Мелкий «срочный» фикс конфигурации: (путь, содержимое, commit message)."""
    to = random.choice([15, 20, 30, 45, 60])
    retries = random.randint(2, 5)
    content = (f"# {service} — runtime config\n"
               f"timeout_seconds: {to}\n"
               f"max_retries: {retries}\n"
               f"batch_size: {random.choice([250, 500, 1000])}\n"
               f"queue: {service}-events\n"
               f"# поднял таймаут: на пике коллектор не успевал подтверждать батч\n")
    return (f"config/{service}.yml", content,
            f"fix({service}): поднять таймаут до {to}s")
