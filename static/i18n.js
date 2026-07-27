/* ============================================================
   SENTINEL I18N — переключение языка интерфейса RU ⇄ EN.

   Что переводится: оболочка продукта — навигация, заголовки,
   кнопки, подписи, шапки таблиц, пустые состояния.

   Что НЕ переводится: данные. Имена разработчиков, названия
   репозиториев, тексты коммитов, причины срабатывания правил —
   это содержимое журнала, а не интерфейс. Настоящие продукты
   тоже не переводят данные, только оболочку.

   Как устроено: словарь сопоставляет русскую строку английской.
   Совпадение только полное, по очищенному от пробелов тексту, —
   поэтому произвольные данные никогда не будут задеты случайно.
   Консоли перерисовывают разметку каждые 2.5 секунды, поэтому
   перевод переприменяется через MutationObserver.

   Возврат на русский делается перезагрузкой страницы: разметка
   и так собирается заново из данных, а обратный словарь
   пришлось бы держать вторым и он бы рассинхронизировался.
   ============================================================ */
(function () {
  'use strict';

  var KEY = 'soc_lang';

  /* ---------- словарь: русская строка → английская ---------- */
  var DICT = {
    /* --- навигация и разделы --- */
    'Обзор': 'Overview',
    'Алерты': 'Alerts',
    'Инциденты': 'Incidents',
    'Дела': 'Cases',
    'Очередь триажа': 'Triage Queue',
    'Детекты': 'Detections',
    'Сущности': 'Entities',
    'Профиль риска': 'Risk Profile',
    'Профиль риска команды': 'Team Risk Profile',
    'Реплей прогона': 'Run Replay',
    'Тренды': 'Trends',
    'Тренды метрик': 'Metric Trends',
    'Диагностика': 'Diagnostics',
    'Журнал событий': 'Event Log',
    'Репозитории': 'Repositories',
    'Сотрудники': 'People',
    'Конфигурация': 'Configuration',
    'Данные · датасет': 'Data · Dataset',
    'Аналитика': 'Analytics',
    'Среда': 'Environment',
    'Система': 'System',
    'Данные': 'Data',
    'SOC': 'SOC',
    'Purple Team': 'Purple Team',

    /* --- топбар и состояние --- */
    'Мир:': 'Simulation:',
    'События:': 'Events:',
    'Авто-триаж:': 'Auto-triage:',
    'Связь с GitLab': 'GitLab connection',
    'Движок мира': 'Simulation engine',
    'Мир пишет события': 'Simulation is emitting events',
    'Мир молчит': 'Simulation is silent',
    'Событий в журнале и давность последнего': 'Events in log and age of the latest',
    'Событий в event-store и давность последнего': 'Events in store and age of the latest',
    'Пишет ли мир (:8787) события в event-store': 'Whether the simulation (:8787) writes to the event store',
    'Авто-триаж LLM новых инцидентов': 'LLM auto-triage of new incidents',
    'работает': 'running',
    'остановлен': 'stopped',
    'на связи': 'connected',
    'нет связи': 'disconnected',
    'готова': 'ready',
    'пишет': 'emitting',
    'молчит': 'silent',
    'включён': 'enabled',
    'выключен': 'disabled',
    'вкл': 'on',
    'выкл': 'off',
    'рабочее время': 'working hours',
    'вне рабочих часов': 'after hours',
    'рабочий день': 'working day',

    /* --- KPI и сводки --- */
    'Событий в сторе': 'Events in store',
    'Обработано защитой': 'Processed by defense',
    'Алертов': 'Alerts',
    'Инцидентов': 'Incidents',
    'Кампаний выявлено': 'Campaigns detected',
    'Покрытие ATT&CK': 'ATT&CK coverage',
    'покрытие ATT&CK': 'ATT&CK coverage',
    'покрытие': 'coverage',
    'техник в матрице': 'techniques in matrix',
    'покрыто правилами': 'covered by rules',
    'срабатывало': 'triggered',
    'слепых зон': 'blind spots',
    'Активных правил': 'Active rules',
    'Событий записано': 'Events recorded',
    'Действий': 'Actions',
    'Успешно': 'Succeeded',
    'С ошибкой': 'Failed',
    'Пропущено ночью': 'Skipped at night',
    'Спринт': 'Sprint',
    'Доля аномалий': 'Anomaly share',
    'Аномалий (метки)': 'Anomalies (labels)',
    'Типов аномалий': 'Anomaly types',
    'Датасет': 'Dataset',

    /* --- дашборд --- */
    'Живая активность': 'Live activity',
    'Очередь инцидентов': 'Incident queue',
    'Пульс алертов': 'Alert pulse',
    'Распределение риска': 'Risk distribution',
    'Распределение действий': 'Action distribution',
    'Качество детекта': 'Detection quality',
    'Вклад слоёв детекта': 'Detection layer contribution',
    'Покрытие детектами': 'Detection coverage',
    'Топ разработчиков под подозрением': 'Top suspected developers',
    'Топ репозиториев': 'Top repositories',
    'Самые шумные правила': 'Noisiest rules',
    'Активность по тактикам ATT&CK': 'Activity by ATT&CK tactic',
    'Лента детектов': 'Detection feed',
    'Лента алертов': 'Alert feed',
    'Лента действий': 'Action feed',
    'Поток событий по типам': 'Event stream by type',
    'Состояние режима': 'Mode status',
    'Команда': 'Team',
    'Реальное время': 'Real time',
    'Время симуляции': 'Simulation time',
    'Время GitLab-сервера': 'GitLab server time',
    'Статус дня': 'Day status',
    'Рабочие часы': 'Working hours',
    'Сжатие времени': 'Time compression',
    'Вне рабочих часов': 'After hours',
    'Даты в GitLab': 'Dates in GitLab',
    'Текущее действие': 'Current action',
    'Время работы': 'Uptime',
    'Живые показатели этой установки': 'Live metrics of this deployment',
    'Живая команда и её расписание': 'The team and its schedule',

    /* --- таблица алертов --- */
    'Время': 'Time',
    'Слой': 'Layer',
    'Разработчик': 'Developer',
    'Репозиторий': 'Repository',
    'Техника': 'Technique',
    'Тактика': 'Tactic',
    'Тактики': 'Tactics',
    'Правило': 'Rule',
    'Правило / причина': 'Rule / reason',
    'Причина срабатывания': 'Trigger reason',
    'Риск': 'Risk',
    'Действие': 'Action',
    'Действия': 'Actions',
    'Статус': 'Status',
    'Значение': 'Value',
    'Тип': 'Type',
    'Файл': 'File',
    'Шаг': 'Step',
    'Ссылка': 'Link',
    'Оценка': 'Score',
    'Вердикт': 'Verdict',
    'Аналитик': 'Analyst',
    'Приоритет': 'Priority',
    'Название': 'Title',
    'Сработок': 'Triggers',
    'Детали': 'Details',
    'вперёд →': 'next →',
    '← назад': '← back',
    'все': 'all',
    'срабатывали': 'triggered',
    'молчат': 'silent',
    'закрытые': 'closed',
    'в работе': 'in progress',
    'открыть': 'open',
    'убрать': 'remove',
    'удалить': 'delete',
    'приобщить': 'attach',
    'обновить': 'refresh',
    'свернуть': 'collapse',
    'профиль': 'profile',
    'здоровье': 'health',
    'риск': 'risk',
    'детектов': 'detections',
    'инц.': 'inc.',
    'техник': 'techniques',
    'сигнатуры': 'signatures',

    /* --- инциденты и расследование --- */
    'Детали инцидента': 'Incident details',
    'Заметка расследования': 'Investigation note',
    'Рекомендованные действия': 'Recommended actions',
    'Затронутые репозитории': 'Affected repositories',
    'Затронутые файлы': 'Affected files',
    'Запустить LLM-разбор': 'Run LLM analysis',
    'Что видела модель': 'What the model saw',
    'Отчёт (PDF)': 'Report (PDF)',
    'Приобщить к делу': 'Attach to case',
    'Сохранить заметку': 'Save note',
    'Отозвать токены и ключи учётной записи': 'Revoke the account tokens and keys',
    'Заморозить доступ до завершения разбора': 'Freeze access until the review is complete',
    'Что произошло и почему сработало': 'What happened and why it triggered',
    'Почему подозрителен:': 'Why it is suspicious:',
    'Вход модели': 'Model input',
    'Вывод:': 'Conclusion:',
    'Базлайн (UEBA):': 'Baseline (UEBA):',
    'SLA-таймер': 'SLA timer',
    'ваш вердикт': 'your verdict',
    'Атакующий': 'Attacker',
    'Детектор': 'Detector',
    'Объяснение': 'Explanation',

    /* --- дела --- */
    'Карточка дела': 'Case details',
    'Сводка по делу': 'Case summary',
    'История действий': 'Action history',
    'Ответственный': 'Owner',
    'Ответственный аналитик': 'Responsible analyst',
    'Фигуранты': 'Involved actors',
    'Сводка': 'Summary',
    '+ Новое дело': '+ New case',
    '+ Приобщить инцидент': '+ Attach incident',
    'Завести новое дело с этим инцидентом': 'Open a new case with this incident',
    'Записать': 'Add entry',
    'Сохранить': 'Save',
    'Удалить': 'Delete',
    'Инциденты в деле': 'Incidents in case',
    'Инциденты, открытые к этому моменту': 'Incidents open at this point',
    'ожидает': 'on hold',
    'локализовано': 'contained',
    'закрыто': 'closed',
    'низкий': 'low',
    'средний': 'medium',
    'высокий': 'high',
    'критический': 'critical',

    /* --- реплей --- */
    'Что произошло к этому моменту': 'What happened up to this point',
    'Состояние SOC на курсоре': 'SOC state at cursor',
    '▶ Играть': '▶ Play',
    '⏸ Пауза': '⏸ Pause',
    'скорость': 'speed',
    'сутки': '24 hours',
    'неделя': 'week',
    'весь журнал': 'entire log',
    'прошло': 'elapsed',
    'критичных': 'critical',
    'Самый активный': 'Most active',
    'Ведущая тактика': 'Leading tactic',
    'Горячий репозиторий': 'Hottest repository',
    'Первый детект': 'First detection',
    'Детекты': 'Detections',

    /* --- профиль риска --- */
    'Разработчики по риску': 'Developers by risk',
    'Репозитории по риску': 'Repositories by risk',
    'Динамика риска во времени': 'Risk over time',
    'в критической зоне': 'in critical zone',
    'средний риск команды': 'team average risk',
    'наибольший риск': 'highest risk',
    'самый затронутый репозиторий': 'most affected repository',
    'инцидентов в работе': 'incidents in progress',
    'Как считается': 'How it is calculated',
    'Последние детекты': 'Latest detections',
    'Профиль сущности': 'Entity profile',
    'Поведенческий слой (UEBA)': 'Behavioral layer (UEBA)',
    'Сигнатурные правила': 'Signature rules',

    /* --- ATT&CK --- */
    'слепая зона': 'blind spot',
    'покрыта правилом': 'covered by a rule',
    'Показать детекты правила': 'Show rule detections',
    'Открыть матрицу ATT&CK': 'Open the ATT&CK matrix',
    'Техники не определены': 'No techniques identified',
    'Правила детектирования': 'Detection rules',

    /* --- Red Launcher / охота --- */
    'Очередь команд': 'Command queue',
    'Готовые гипотезы': 'Preset hypotheses',
    'Свой запрос': 'Custom query',
    'Сохранённые запросы': 'Saved queries',
    'Сохранить запрос': 'Save query',
    'название гипотезы': 'hypothesis name',
    'Запустить': 'Start',
    'Остановить': 'Stop',
    'Запуск': 'Launch',
    'Показать живую атаку': 'Show the live attack',
    '▶ Реплей атаки': '▶ Replay attack',
    '▶ Запустить': '▶ Start',
    'Отчёт по прогону': 'Run report',
    'Отчёт по запросу': 'On-demand report',
    'Быстрые действия': 'Quick actions',
    'Быстрый старт': 'Quick start',

    /* --- пустые состояния и подсказки --- */
    'Очередь пуста': 'The queue is empty',
    'Событий нет': 'No events',
    'Событий пока нет': 'No events yet',
    'Детектов пока нет': 'No detections yet',
    'нет данных': 'no data',
    'записей нет': 'no entries',
    'Под фильтр ничего не попало': 'Nothing matches the filter',
    'вне текущего окна выдачи': 'outside the current window',
    'выберите дело слева или создайте новое': 'select a case on the left or create a new one',
    'Поиск по делам, аналитику, акторам…': 'Search cases, analysts, actors…',
    'Поиск по правилам, техникам, тактикам…': 'Search rules, techniques, tactics…',
    'Поиск: актёр, репозиторий, правило, техника…': 'Search: actor, repository, rule, technique…',
    'актёр, репозиторий, техника, путь…': 'actor, repository, technique, path…',
    'Например: утечка токенов через soc-infra': 'For example: token leak via soc-infra',
    'Опросили владельца сервиса, отозвали токен…': 'Interviewed the service owner, revoked the token…',
    'Что установлено, почему такой вердикт, что сделано…': 'What was established, why this verdict, what was done…',
    'Искать': 'Search',
    'Спросить': 'Ask',
    'Параметры': 'Settings',
    'Сохранить изменения': 'Save changes',
    'Сбросить форму к сохранённому': 'Reset the form to the saved state',

    /* --- вход --- */
    'Вход': 'Sign in',
    'Войти': 'Sign in',
    'Вход в панель': 'Sign in to the console',
    'Логин': 'Username',
    'Пароль': 'Password',
    'Вы вошли как': 'Signed in as',
    'Выйти из панели →': 'Sign out →',
    'Авторизуйтесь для управления симуляцией': 'Sign in to control the simulation',

    /* --- прочее --- */
    'Дерево файлов': 'File tree',
    'Последние файлы': 'Recent files',
    'Последние события': 'Recent events',
    'Последние ошибки': 'Recent errors',
    'Открытые merge request': 'Open merge requests',
    'События CI/CD': 'CI/CD events',
    'Полный журнал событий': 'Full event log',
    'Структурный лог': 'Structured log',
    'Скачать events.jsonl': 'Download events.jsonl',
    'Скачать полный лог прогона': 'Download the full run log',
    'Отправить отчёт в Telegram': 'Send the report to Telegram',
    'Очистить репозитории': 'Clear repositories',
    'Сброс состояния репозиториев': 'Reset repository state',
    'Рабочие дни недели': 'Working days',
    'Дежурный (on-call)': 'On call',
    'Аномалии по типам': 'Anomalies by type',
    'Таймлайн аномалий': 'Anomaly timeline',
    'Карта активности · часы × дни недели': 'Activity map · hours × weekdays',
    'Недавние алерты:': 'Recent alerts:',
    'Как это работает': 'How it works',
    'Что это значит': 'What this means',
    'Почему это важно': 'Why it matters',

    /* --- онбординг, подсказки и подписи консолей --- */
    'пройди 5 шагов — увидишь весь конвейер': 'five steps walk you through the whole pipeline',
    'Мир пишет события': 'The simulation emits events',
    'Открой': 'Open',
    'консоль среды': 'the environment console',
    'и нажми «Запустить» — или': 'and press “Start” — or',
    'сгенерируй демо-данные': 'generate demo data',
    'События копятся': 'Events accumulate',
    'git/CI-поток пишется в общий журнал (event-store), защита читает его по курсору — как': 'the git/CI stream is written to a shared log (event store); the defense reads it by cursor, like a',
    'Запусти кампанию': 'Launch a campaign',
    '— многошаговая атака по матрице': '— a multi-step attack mapped to',
    'Появились алерты': 'Alerts appear',
    ': правила +': ': rules +',
    'Система сама замечает': 'The system notices on its own',
    'кражу секретов': 'secret theft',
    'Разбери инцидент': 'Investigate an incident',
    'Открой инцидент': 'Open an incident',
    '— и нажми «LLM-разбор»': '— and press “Run LLM analysis”',
    '— восстановленный': '— reconstructed',
    'Детект и разбор — на консоли защиты': 'Detection and analysis live in the defense console',
    'Запись в GitLab': 'Written to GitLab',
    'каждый push, ветка, MR и настройка пишутся в единый журнал': 'every push, branch, merge request and setting is written to a single log',
    'разрозненные сработки склеиваются в цепочку шагов атаки (kill-chain)': 'scattered detections are stitched into an attack kill chain',
    'LLM пишет вердикт: что произошло, насколько серьёзно, что делать': 'the LLM writes the verdict: what happened, how serious it is, what to do',
    'ML-детектор платформы': 'the platform ML detector',
    'инсайдер или взломанный аккаунт крадёт токены, ключи, код': 'an insider or a compromised account steals tokens, keys and code',
    'сливаются в единый риск (': 'are fused into a single risk score (',
    'Слияние сигналов разных слоёв (сигнатуры + поведение) в один скор риска — устойчивее одиночного признака.': 'Fusing signals from different layers (signatures plus behavior) into one risk score is more robust than any single feature.',
    'MITRE ATT&CK — общепринятый каталог тактик и техник атакующих. По нему измеряется покрытие детекта.': 'MITRE ATT&CK is the common catalogue of adversary tactics and techniques. Detection coverage is measured against it.',
    'User & Entity Behavior Analytics — профиль «нормального» поведения актора (часы, репозитории, действия); отклонение поднимает риск.': 'User & Entity Behavior Analytics — a profile of what is normal for an actor (hours, repositories, actions); deviation raises risk.',
    'Security Information & Event Management — система, собирающая события безопасности со всей инфраструктуры.': 'Security Information & Event Management — a system that collects security events across the infrastructure.',
    'Цепочка шагов атаки (разведка → доступ → кража…), восстановленная из алертов одного актора.': 'The chain of attack steps (recon → access → theft…) reconstructed from one actor’s alerts.',
    'поиск по шаблонам (regex)': 'pattern matching (regex)',
    'Почему не просто «поиск по шаблону»': 'Why not just pattern matching',
    'событий в сторе': 'events in store',
    'событий в журнале': 'events in log',
    'обработано защитой': 'processed by defense',
    'алертов': 'alerts',
    'инцидентов': 'incidents',
    'кампаний выявлено': 'campaigns detected',
    'обнаружение атак': 'attack detection',
    'ложные тревоги': 'false alarms',
    'время до обнаружения': 'time to detect',
    'доля атакующих эпизодов, на которые детектор поднял тревогу': 'share of attack episodes the detector alerted on',
    'доля алертов, поднятых на нормальной работе команды (чем меньше, тем лучше)': 'share of alerts raised on normal team activity (lower is better)',
    'доля техник атакующих (по матрице MITRE ATT&CK), которые платформа умеет замечать': 'share of adversary techniques (per MITRE ATT&CK) the platform can spot',
    'от первого шага атаки до первого алерта (MTTD, сим-время)': 'from the first attack step to the first alert (MTTD, simulated time)',
    'Доля обнаруженных атак': 'Attack detection rate',
    'Доля ложных срабатываний': 'False positive rate',
    'Время до обнаружения, мин': 'Time to detect, min',
    'больше': 'higher',
    'меньше': 'lower',
    'успешно': 'succeeded',
    'с ошибкой': 'failed',
    'нет': 'no',
    'пока пусто': 'empty so far',
    'нет событий': 'no events',
    'остановлена': 'stopped',
    'все уровни': 'all levels',
    'скачать CSV': 'download CSV',
    'снять снапшот сейчас': 'take a snapshot now',
    'считаю метрики по всему журналу событий…': 'computing metrics over the whole event log…',
    'загружаю прогон…': 'loading the run…',
    'из них аномалий': 'of them anomalies',
    'успешных вызовов': 'successful calls',
    'часы этого компьютера': 'this machine’s clock',
    'внутреннее время отдела': 'the team’s internal time',
    'им проставляются коммиты': 'commits are stamped with it',
    'дни и недели': 'days and weeks',
    'В отпуске': 'On leave',
    'Инфраструктура': 'Infrastructure',
    'Журнал ошибок': 'Error log',
    'Инцидент': 'Incident',
    'Охота на угрозы': 'Threat hunting',
    'Сценарии атак': 'Attack scenarios',
    'Матрица покрытия ATT&CK': 'ATT&CK coverage matrix',
    'выберите инцидент слева': 'select an incident on the left',
    'выберите актора слева': 'select an actor on the left',
    'открыть в GitLab ↗': 'open in GitLab ↗',
    '← Вернуться в консоль': '← Back to the console',
    'Открыть Sentinel SOC': 'Open Sentinel SOC',
    'клик по технике — детали и связанные инциденты': 'click a technique for details and related incidents',
    'срабатывала': 'triggered',
    'в этот час была аномалия (красная рамка на клетке)': 'there was an anomaly in this hour (red outline on the cell)',
    'Статистика у карточки:': 'Card stats:',
    '— пуши (коммиты) ·': '— pushes (commits) ·',
    '— merge request’ы ·': '— merge requests ·',
    '— подозрительные (аномальные) действия. Считается по событиям, которые актор совершил за прогон.': '— suspicious (anomalous) actions. Counted over the events the actor produced during the run.',
    'Нажмите на сотрудника, чтобы раскрыть живую ленту — что и куда он заливает в реальном времени.': 'Click a person to expand the live feed — what they are pushing and where, in real time.',
    'Параметры симуляции. Изменения сохраняются в файл': 'Simulation settings. Changes are saved to',
    'и применяются немедленно — перезапуск не требуется.': 'and applied immediately — no restart needed.',
    'Файл накапливается между запусками (каждая строка помечена run_id).': 'The file accumulates across runs (every line carries a run_id).',
    'Команда и сами репозитории сохраняются': 'The team and the repositories themselves are kept',
    'пароль печатается в консоли при старте (или задан через SOC_ADMIN_PASS)': 'the password is printed to the console at startup (or set via SOC_ADMIN_PASS)',
    '— новых событий нет': '— no new events',
    '— навигация,': '— navigate,',
    '— эскалация,': '— escalate,',
    '— открыть.': '— open.',
    'Рабочий день SOC-команды в GitLab:': 'A SOC team’s working day in GitLab:',
    'коммиты, ревью, инциденты — и скрытые атаки.': 'commits, reviews, incidents — and hidden attacks.',
    'Здоровье платформы и журнал ошибок. Если что-то не работает — пришли на разбор файлы': 'Platform health and the error log. If something is broken, send these files for review:',
    '💡 Чтобы сохранить в PDF — нажми Ctrl+P → «Сохранить как PDF».': '💡 To save as PDF press Ctrl+P → “Save as PDF”.',
    'открой в mitre-attack.github.io/attack-navigator → Open Existing Layer': 'open at mitre-attack.github.io/attack-navigator → Open Existing Layer',
    '⬇ Скачать слой для ATT&CK Navigator (JSON)': '⬇ Download ATT&CK Navigator layer (JSON)'
,
    'Проверь, что консоль среды (:8787) запущена и нажата кнопка «Запустить».': 'Check that the environment console (:8787) is running and “Start” has been pressed.',
    'AI-копайлот': 'AI copilot',
    'Как в реальном SOC: очередь по важности, статусы, SLA-таймеры. Горячие клавиши:': 'Just like a real SOC: a queue by priority, statuses, SLA timers. Shortcuts:',
    'Как в реальном SOC: очередь по важности, статусы, SLA-таймеры.': 'Just like a real SOC: a queue by priority, statuses, SLA timers.',
    'Мир молчит, а события есть': 'The simulation is silent while events exist',
    'История метрик во времени (снапшоты раз в 5 мин + по кнопке). Вертикальные метки — события «добавлено правило / запущена кампания».': 'Metric history over time (snapshots every 5 min plus on demand). Vertical marks are “rule added / campaign launched” events.',
    'Служебные подсистемы. В рабочей части интерфейса их не показываем: аналитику важен поток событий и детекты, а не состояние конкретного сервиса.': 'Infrastructure subsystems. They are kept out of the working area: an analyst needs the event stream and detections, not the state of a particular service.',
    'Файл logs/errors.log целиком, включая прошлые запуски. Счётчики выше относятся к текущей сессии — поэтому «ошибок нет» и записи ниже не противоречат друг другу.': 'The whole logs/errors.log file, including previous runs. The counters above cover the current session — that is why “no errors” and the entries below do not contradict each other.',
    'Оценка 0–100 складывается из пикового риска (40), среднего риска (20), объёма детектов (15), разнообразия техник (10), числа инцидентов (10) и признака критичности (5).': 'The 0–100 score combines peak risk (40), average risk (20), detection volume (15), technique variety (10), incident count (10) and a criticality flag (5).'
,
    'Security Information & Event Management — система, собирающая события из всех источников в один поток для анализа. Здесь её роль играет event-store на SQLite.': 'Security Information & Event Management — a system that gathers events from every source into one stream for analysis. Here that role is played by a SQLite event store.',
    'User & Entity Behavior Analytics — профиль «нормального» поведения актора (часы, репозитории, действия); отклонения повышают риск.': 'User & Entity Behavior Analytics — a profile of what is normal for an actor (hours, repositories, actions); deviations raise the risk.',
    'Слияние сигналов разных слоёв (сигнатуры + поведение) в один скор риска — устойчивее любого сигнала поодиночке.': 'Fusing signals from different layers (signatures plus behavior) into one risk score is more robust than any single signal alone.',
    'Цепочка шагов атаки (разведка → доступ → кража…), восстановленная из алертов одного актора в окне времени.': 'The chain of attack steps (recon → access → theft…) reconstructed from one actor’s alerts within a time window.',
    'noisy (быстро, явно)': 'noisy (fast, obvious)',
    'stealthy (медленно, скрытно)': 'stealthy (slow, covert)',
    'moderate (средне)': 'moderate',
    'Проверь, что консоль среды (:8787) запущена и нажата кнопка «Запустить».': 'Check that the environment console (:8787) is running and “Start” has been pressed.',
    'Перейти к содержимому': 'Skip to content',
    'Свернуть меню': 'Collapse menu',
    'Развернуть меню': 'Expand menu',
    'GitLab / Мир': 'GitLab / Simulation',
    'Приём событий': 'Ingest',
    'Поведение (UEBA)': 'Behavior (UEBA)',
    'Модель (LLM)': 'Model (LLM)',
    'Авто-триаж': 'Auto-triage',
    'офлайн': 'offline',
    'Детектор': 'Detector',
    'Симуляция': 'Simulation',
    'Инфраструктура': 'Infrastructure',
    'нерабочее время': 'after hours',
    'рабочее время': 'working hours',
    'рабочий день': 'working day',
    'нет активности': 'no activity',
    'никого': 'none',
    'реальное': 'real',
    'real (реальное)': 'real',
    'sim (симуляция)': 'sim',
    'Дежурный (on-call)': 'On call (on-call)',
    'критический (≥0.85)': 'critical (≥0.85)',
    'высокий (0.7–0.85)': 'high (0.7–0.85)',
    'средний (0.5–0.7)': 'medium (0.5–0.7)',
    'низкий (<0.5)': 'low (<0.5)',
    'критический': 'critical',
    'высокий': 'high',
    'средний': 'medium',
    'низкий': 'low',
    'правил:': 'rules:',
    'техник сработало:': 'techniques fired:',
    'инцидентов:': 'incidents:',
    'подтверждено TP:': 'confirmed TP:',
    'ложных FP:': 'false FP:',
    'разобрано:': 'triaged:',
    'вклад сигнатур': 'signature contribution',
    'вклад поведения': 'behavior contribution',
    'CI печатает токены/env в лог': 'CI prints tokens/env to the log',
    'MR смёржен без единого апрува': 'MR merged without a single approval',
    'MR смёржен своим же автором (обход обязательного ревью)': 'MR merged by its own author (bypassing mandatory review)',
    'Выдача доступа к секретам': 'Secrets access granted',
    'Высокоэнтропийный секрет (без сигнатуры)': 'High-entropy secret (no signature)',
    'Доступ к secrets-репо в нерабочее время': 'Access to the secrets repo after hours',
    'Изменение .gitlab-ci.yml (потенц. отравление)': '.gitlab-ci.yml change (possible poisoning)',
    'Касание vault-репозитория секретов': 'Touching the secrets vault repository',
    'Крупный закодированный архив (эксфильтрация)': 'Large encoded blob (exfiltration)',
    'Ослабление branch-protection': 'Weakening branch protection',
    'Отключение сканеров в CI': 'Disabling scanners in CI',
    'Перебор/листинг репозиториев и секрет-путей': 'Enumerating repositories and secret paths',
    'Подозрительный бамп зависимости (supply-chain)': 'Suspicious dependency bump (supply chain)',
    'Правка policy-файла (права/протекции)': 'Policy file edit (permissions/protections)',
    'Приватный ключ в коммите': 'Private key in a commit',
    'Сбор данных из репозитория (vault export)': 'Data collection from the repo (vault export)',
    'Секрет в комментарии MR': 'Secret in an MR comment',
    'Сигнатура секрета в коммите': 'Secret signature in a commit',
    'Скрытое правило пересылки почты': 'Hidden mail forwarding rule',
    'Создан дополнительный API-токен': 'An extra API token was created',
    'Удаление файла (кандидат на массовое)': 'File deletion (mass-delete candidate)',
    'Экспорт «бэкапа секретов» в обычный репо': 'Exporting a “secrets backup” to a normal repo',
    'Тема: тёмная — нажмите для светлой': 'Theme: dark — click for light',
    'Тема: светлая — нажмите для яркой': 'Theme: light — click for bright',
    'Тема: яркая — нажмите для тёмной': 'Theme: bright — click for dark',
    'AI-разбор инцидента': 'AI analysis of incident',
    'оценка': 'assessment',
    'Поиск инцидентов, сущностей, правил или команда…': 'Search incidents, entities, rules, or a command…',
    'Поиск инцидентов, сущностей, прав': 'Search incidents, entities, rules',
    'по': 'by',
    'Пока тихо — запустите кампанию в Red Launcher': 'Quiet for now — launch a campaign in Red Launcher',
    'что делала maria ночью': 'what did maria do at night',
    'покажи секреты в soc-infra': 'show secrets in soc-infra',
    'кто трогал .gitlab-ci.yml': 'who touched .gitlab-ci.yml',
    'какие удаления файлов были': 'what file deletions happened',
    'кто создавал токены': 'who created tokens',
    'активность вне рабочих часов': 'after-hours activity',
    'Спросите у данных: что делала maria ночью · покажи секреты в soc-infra': 'Ask the data: what did maria do at night · show secrets in soc-infra',
    'Поиск по разделам и командам…': 'Search sections and commands…',
    'поведение. Вместе они закрывают разные классы атак.': 'behavior. Together they cover different classes of attacks.',
    'Правила с подтверждёнными FP': 'Rules with confirmed FPs',
    'Правила с подтверждёнными FP:': 'Rules with confirmed FPs:',
    'целиком, включая прошлые запуски. Счётчики выше относятся к текущей сессии — поэтому «ошибок нет» и записи ниже не противоречат друг другу.': 'in full, including previous runs. The counters above refer to the current session — that is why “no errors” and the entries below do not contradict each other.',
    '. Проверь, что консоль среды (:8787) запущена и нажата кнопка «Запустить».': '. Check that the environment console (:8787) is running and “Start” has been pressed.',
    'Закрыть': 'Close',
    'Сигнатуры ловят известное содержимое, UEBA — нетипичное поведение. Вместе они закрывают разные классы атак.': 'Signatures catch known content, UEBA catches atypical behavior. Together they cover different classes of attacks.',
    'новый': 'new',
    'сдержан': 'contained',
    'закрыт': 'closed',
    'всего': 'total',
    'новые': 'new',
    'сдержано': 'contained',
    'Пометьте инцидент как FP (клавиша': 'Mark the incident as FP (key',
    ') — после': ') — after',
    'подтверждений правило перестаёт поднимать инциденты.': 'confirmations the rule stops raising incidents.',
    'подтверждений правило перестанет поднимать инциденты.': 'confirmations the rule will stop raising incidents.',
    'Отклонено FP-тюнингом:': 'Suppressed by FP tuning:',
    'сработок. Правило глушится после': 'triggers. The rule is muted after',
    'подтверждённых FP.': 'confirmed FPs.',
    'Горячие клавиши:': 'Shortcuts:',
    'CI-токен → отключение защиты → эксфильтрация': 'CI token → disabling defenses → exfiltration',
    'Инсайдер: лишний токен → секрет в коммите → вынос': 'Insider: extra token → secret in a commit → exfiltration',
    'Разведка → лишний токен → отравленный CI → вынос': 'Recon → extra token → poisoned CI → exfiltration',
    'Обход ревью → отравленный CI → разрушение': 'Review bypass → poisoned CI → destruction',
    'реагирование': 'response',
    'кампания': 'campaign',
    'сброс': 'reset',
    'выполнено': 'done',
    'в очереди': 'queued',
    'выполняется': 'running',
    'ошибка': 'error',
    'есть правило': 'rule exists',
    'нет правила': 'no rule',
    'разработчик': 'developer',
    'репозиторий': 'repository',
    'репозиториев': 'repositories',
    'участников': 'participants',
    'Клик по строке — детали и последние детекты.': 'Click a row for details and recent detections.',
    'на этот момент детектов ещё не было — двигайте курсор вправо': 'no detections yet at this point — move the cursor to the right',
    'кража секрета инсайдером': 'insider secret theft',
    'обход ревью и саботаж': 'review bypass & sabotage',
    'вынос CI-токена': 'CI token exfiltration',
    'разведка и вынос данных': 'recon & data exfiltration',
    'атака на цепочку поставок': 'supply-chain attack',
    'активность в нетипичный для актора час': 'activity in an hour atypical for the actor',
    'открыть issue ↗': 'open issue ↗',
    'ошибок нет': 'no errors',
    'недоступна': 'unavailable',
    'недоступен': 'unavailable',
    'нетипично для актора': 'atypical for the actor',
    'Ошибок нет': 'No errors',
    'есть ошибки': 'errors present',
    'Таймлайн': 'Timeline',
    'Доказательства': 'Evidence',
    'AI-разбор': 'AI analysis',
    'вердикт не выставлен — нажмите TP или FP': 'no verdict set — press TP or FP',
    'вердикт не выставлен': 'no verdict set',
    'нажмите TP или FP': 'press TP or FP',
    'Захват облака → ключи реестра → вынос': 'Cloud takeover → registry keys → exfiltration',
    'Обход защиты → плановое CI-задание → вынос': 'Defense bypass → scheduled CI job → exfiltration',
    'SSH deploy-ключ → секрет → сбор из vault': 'SSH deploy key → secret → collection from vault',
    'Инсайдер: разведка → массовое удаление → срыв восстановления': 'Insider: recon → mass deletion → recovery inhibition',
    'захват облака': 'cloud takeover',
    'обход защиты и плановое задание ci': 'defense bypass & scheduled CI job',
    'Плановое CI-задание с полезной нагрузкой': 'Scheduled CI job with a payload',
    'Учётные данные контейнерного реестра в манифесте': 'Container registry credentials in a manifest',
    'Удаление резервных веток и тегов': 'Deletion of backup branches and tags',
    'Добавлен внешний SSH deploy-ключ': 'External SSH deploy key added',
    'Поиск по коду в поисках секретов': 'Code search for secrets',
    'Подмена зависимости (supply-chain)': 'Dependency poisoning (supply chain)',
    'Злоупотребление средством развёртывания': 'Abuse of a deployment tool',
    'Создан облачный служебный аккаунт': 'Cloud service account created',
    'Повышение прав через обход контроля': 'Elevation via control bypass',
    'Переписывание истории и удаление следов': 'History rewrite / indicator removal',
    'Обфусцированный код в коммите': 'Obfuscated code committed',
    'Кража OAuth/приложенческого токена': 'Application access token theft',
    'Перечисление прав и групп доступа': 'Permission and group enumeration',
    'Автоматический сбор данных из репозиториев': 'Automated collection from repos',
    'Управление через внешний веб-сервис': 'C2 via external web service',
    'Вынос по альтернативному протоколу': 'Exfiltration over alternative protocol',
    'Supply-chain: поиск → подмена зависимости → C2 → вынос': 'Supply chain: search → dependency poisoning → C2 → exfiltration',
    'Повышение прав → облачный аккаунт → сбор → вынос': 'Privilege escalation → cloud account → collection → exfiltration',
    'Разведка прав → кража OAuth → обфускация → зачистка следов': 'Permission recon → OAuth theft → obfuscation → track cleanup',
    'Злоупотребление деплоем → сбор → вынос по scp': 'Deploy abuse → collection → scp exfiltration',
    'живая карта': 'live map',
    '(в этой сессии)': '(this session)',
    'нет открытых MR': 'no open MRs',
    'Открытые MR': 'Open MRs',
    'Недавние события': 'Recent events',
    'файлов': 'files',
    'пушей': 'pushes',
    'откр. MR': 'open MRs',
    'событий': 'events',
    'MR смержен': 'MR merged',
    'MR открыт': 'MR opened',
    'MR закрыт': 'MR closed',
    'issue закрыт': 'issue closed',
    'ветка': 'branch',
    'коммент': 'comment',
    '(корень)': '(root)',
    'пока тихо': 'quiet so far',
    'пока пусто — файлы появятся при пушах': 'empty so far — files appear on push',
    // Названия активностей (ACT_HELP) и типов событий (EVN) на Обзоре среды —
    // это ярлыки консоли, а не данные из журнала, поэтому переводим.
    'Новое правило детектирования': 'New detection rule',
    'Исправление правила': 'Rule fix',
    'Донастройка порогов': 'Threshold tuning',
    'Рефакторинг': 'Refactoring',
    'Обновление парсера': 'Parser update',
    'Обновление плейбука': 'Playbook update',
    'Тестовый образец': 'Test sample',
    'Обновление метрик': 'Metrics update',
    'Разбор ложного срабатывания': 'False-positive triage',
    'Откат правила': 'Rule rollback',
    'Вывод правила из эксплуатации': 'Rule deprecation',
    'Пересоздание правила': 'Rule recreation',
    'Реагирование на инцидент': 'Incident response',
    'Массовое обслуживание': 'Bulk maintenance',
    'Заведение тикета': 'Issue creation',
    'Сюжетная кампания': 'Scripted campaign',
    'push (коммит файла)': 'push (file commit)',
    'открыт MR': 'MR opened',
    'смёржен MR': 'MR merged',
    'комментарий MR': 'MR comment',
    'апрув MR': 'MR approve',
    'закрыт MR': 'MR closed',
    'создана ветка': 'branch created',
    'открыт issue': 'issue opened',
    'комментарий issue': 'issue comment',
    'закрыт issue': 'issue closed',
    'удалён файл': 'file deleted',
    'пайплайн CI': 'CI pipeline',
    'создан токен': 'token created',
    'изменены настройки': 'settings changed',
    'дежурный': 'on-call',
    'отпуск': 'on leave',
    'на смене': 'on shift',
    'не на смене': 'off shift',
    'слежение': 'tracking',
    'пуши/коммиты': 'pushes/commits',
    'подозрительные (аномальные) действия': 'suspicious (anomalous) actions',
    'merge request\'ы': 'merge requests',
    'Статистика у карточки: ↑ — пуши (коммиты) · MR — merge request\'ы · ⚠ — подозрительные (аномальные) действия. Считается по событиям, которые актор сгенерил с начала прогона.': 'Card stats: ↑ — pushes (commits) · MR — merge requests · ⚠ — suspicious (anomalous) actions. Counted over events the actor generated since the run started.',
    'Живая карта репозиториев. Видно, как появляются файлы (пуши), как merge request\'ы открываются и затем мёржатся или закрываются — каждое событие подписано автором и сообщением. Аномалии подсвечены красным.': 'A live map of the repositories. You can see files appear (pushes), merge requests open and then get merged or closed — every event is signed by author and message. Anomalies are highlighted in red.'
  };

  /* --- составные подписи: собираются из чисел и слов ---
     Число может содержать разделители тысяч (пробел, тонкая шпация),
     поэтому в шаблоне числа — символьный класс, а не \d+. Замена
     бывает функцией: английское число/множественное считается по n. */
  var NUM = '([\\d \\u00a0\\u202f.]+?)';
  function one(n) { return String(n).replace(/\D/g, '') === '1'; }
  function pl(n, s, p) { return n + (one(n) ? ' ' + s : ' ' + p); }
  var RULES = [
    [new RegExp('^' + NUM + 'детект(?:а|ов)?$'), function (m, n) { return pl(n.trim(), 'detection', 'detections'); }],
    [new RegExp('^' + NUM + 'алерт(?:а|ов)?$'),  function (m, n) { return pl(n.trim(), 'alert', 'alerts'); }],
    [new RegExp('^' + NUM + 'тактик(?:а|и)?$'),  function (m, n) { return pl(n.trim(), 'tactic', 'tactics'); }],
    [new RegExp('^' + NUM + 'инцидент(?:а|ов)?$'), function (m, n) { return pl(n.trim(), 'incident', 'incidents'); }],
    [new RegExp('^' + NUM + 'правил(?:а|о)?$'),  function (m, n) { return pl(n.trim(), 'rule', 'rules'); }],
    [new RegExp('^' + NUM + 'техник(?:а|и)?$'),  function (m, n) { return pl(n.trim(), 'technique', 'techniques'); }],
    [new RegExp('^' + NUM + 'событ(?:ие|ия|ий)$'), function (m, n) { return pl(n.trim(), 'event', 'events'); }],
    [new RegExp('^' + NUM + 'репозитори(?:й|я|ев)$'), function (m, n) { return pl(n.trim(), 'repository', 'repositories'); }],
    [new RegExp('^' + NUM + 'инц\\.$'), '$1inc.'],
    [new RegExp('^' + NUM + 'обраб\\.$'), '$1processed'],
    [new RegExp('^' + NUM + 'соб\\.$'), '$1ev.'],
    [/^риск\s+([\d.]+)$/, 'risk $1'],
    [/^пиковый риск\s+([\d.]+)$/, 'peak risk $1'],
    [/^макс риск\s+([\d.]+)$/, 'max risk $1'],
    [/^оценка\s+(.+)$/, 'assessment $1'],
    [/^последние\s+(\d+)\s+детект(?:а|ов)?$/, 'last $1 detections'],
    [/^пик\s+(\d+)\s+за\s+(\d+)\s*мин$/, 'peak $1 in $2 min'],
    [/^AI-разбор инцидента\s+#?(\S+)$/, 'AI analysis of incident #$1'],
    [/^Инцидент\s+#(\S+)$/, 'Incident #$1'],
    [/^(\d+)\s*мин\s+назад$/, '$1 min ago'],
    [/^(\d+)\s*с\s+назад$/, '$1 s ago'],
    [/^(\d+)\s*ч\s+назад$/, '$1 h ago'],
    [/^(\d+)\s*мин$/, '$1 min'],
    [/^(\d+)\s*м$/, '$1m'],
    [/^(\d+)\s*ч\s+(\d+)\s*м$/, '$1 h $2 m'],
    [/^(\d+)\s*ч\s+(\d+)\s*м\s+(\d+)\s*с$/, '$1h $2m $3s'],
    [/^(\d+)\s*д\s+(\d+)\s*ч$/, '$1 d $2 h'],
    [/^(\d+)\s+из\s+(\d+)$/, '$1 of $2'],
    [/^из\s+(\d+)$/, 'of $1'],
    [/^Ускорение\s+×([\d.]+)$/, 'Speed-up ×$1'],
    [/^▲\s*(\d+)\s*срабат\.$/, '▲ $1 fired'],
    [/^показано\s+(\d+)\s+из\s+(\d+)$/, 'shown $1 of $2'],
    [/^(\d+)\s+точек$/, '$1 points'],
    [/^Δ\s*(-?\d+)\s*п\.п\.$/, 'Δ $1 pp'],
    [/^(\d+)\s+инцидентов\s+\(всего в журнале\s+(\d+)\)$/, '$1 incidents (of $2 in the log)'],
    [/^(\d+)\s*мин\s+от первого детекта$/, '$1 min from first detection'],
    [/^(\d+)\s*ч\s+(\d+)\s*м\s+от первого детекта$/, '$1 h $2 m from first detection'],
    [/^(\d+)\s*д\s+(\d+)\s*ч\s+от первого детекта$/, '$1 d $2 h from first detection'],
    [/^Пиковый риск по (\d+) интервалам от первого до последнего детекта \(([^)]+)\)\. Столбик — максимум риска, который человек показал в этом окне\.$/, 'Peak risk across $1 intervals from the first to the last detection ($2). Each bar is the highest risk the person showed in that window.'],
    [/^новый для @(\S+) репозиторий (\S+)$/, 'new repository $2 for @$1'],
    [/^нетипичное действие (\S+)$/, 'atypical action $1'],
    [/^всплеск активности \((\d+) за (\d+)м\)$/, 'activity spike ($1 in $2m)'],
    [/^(\d+)\s+снапшот(?:а|ов)?$/, '$1 snapshots'],
    [/^(\d+)\s+мет(?:ка|ки|ок)\s+событий$/, '$1 event marks'],
    [/^последний\s+(.+)$/, 'latest $1'],
    [/^страница\s+(\d+)\s+из\s+(\d+)$/, 'page $1 of $2'],
    [new RegExp('^'+NUM+'файл(?:а|ов)?$'), function(m,n){return pl(n.trim(),'file','files');}],
    [new RegExp('^'+NUM+'пуш(?:а|ей|ов)?$'), function(m,n){return pl(n.trim(),'push','pushes');}],
    [/^(\d+)\s+откр\.\s*MR$/, '$1 open MRs'],
    [/^шаг\s+(\d+)\s+из\s+(\d+)$/, 'step $1 of $2'],
    [/^Speed-up\s+×([\d.]+)$/, 'Speed-up ×$1']
  ];

  var ATTRS = ['title', 'placeholder', 'aria-label'];
  var SKIP = { SCRIPT: 1, STYLE: 1, NOSCRIPT: 1, CODE: 1, PRE: 1 };
  var SEP = / · | — | → | \| |; |, | \/ |: /;

  // одна смысловая единица: точный словарь, затем правила
  function tr1(t) {
    if (DICT.hasOwnProperty(t)) return DICT[t];
    for (var i = 0; i < RULES.length; i++) {
      if (RULES[i][0].test(t)) return t.replace(RULES[i][0], RULES[i][1]);
    }
    return null;
  }

  function translate(s) {
    // Внутренние переносы схлопываем: в разметке длинная фраза может быть
    // разбита на несколько строк, и без этого она не находилась в словаре.
    // Кроме переносов нормализуем типографские апострофы/кавычки к прямым:
    // в разметке встречается и «request'ы» (U+0027), и «request’ы» (U+2019),
    // а ключ в словаре один — без этого длинная фраза не находится.
    var t = String(s).replace(/\s+/g, ' ').replace(/[‘’]/g, "'").trim();
    if (!t) return null;
    var whole = tr1(t);
    if (whole !== null) return whole;
    // Ведущий маркер ленты/списка: «— причина», «· пункт». В разметке
    // причина срабатывания — отдельный текстовый узел вида «— <причина>».
    var mk = t.match(/^([—·]\s+)([\s\S]+)$/);
    if (mk) { var inner = tr1(mk[2]); if (inner !== null) return mk[1] + inner; }
    // Хвостовой маркер: «текст ·» / «текст —». Так бывает, когда за узлом
    // сразу идёт элемент (ссылка): разделитель остаётся в конце текстового
    // узла без следующего сегмента внутри него.
    var mkE = t.match(/^([\s\S]+?)(\s[—·])$/);
    if (mkE) { var innerE = tr1(mkE[1]); if (innerE !== null) return innerE + mkE[2]; }
    // Составная строка («1 детект · 1 тактика · риск 0.7») переводится по
    // сегментам: делим по разделителям, переводим каждую единицу отдельно.
    // Данные (имена, репозитории, время) не совпадут ни со словарём, ни с
    // правилами — и останутся как есть.
    if (SEP.test(t)) {
      var parts = t.split(/( · | — | → | \| |; |, | \/ |: )/);
      var changed = false;
      for (var i = 0; i < parts.length; i++) {
        if (i % 2 === 1) continue;              // разделитель
        var seg = parts[i].trim();
        if (!seg) continue;
        var r = tr1(seg);
        if (r !== null) { parts[i] = parts[i].replace(seg, r); changed = true; }
      }
      if (changed) return parts.join('');
    }
    return null;
  }

  // Перевод одного текстового узла с сохранением окружающих пробелов.
  function ttext(node) {
    var raw = node.nodeValue;
    if (!raw || !/\S/.test(raw)) return;
    if (node.parentNode && SKIP[node.parentNode.nodeName]) return;
    var tr = translate(raw);
    if (tr === null) return;
    node.nodeValue = raw.match(/^\s*/)[0] + tr + raw.match(/\s*$/)[0];
  }

  // Перевод узла: текстовый — сам, элемент — атрибуты и всё поддерево.
  function tnode(node) {
    if (!node) return;
    if (node.nodeType === 3) { ttext(node); return; }
    if (node.nodeType !== 1 || SKIP[node.nodeName]) return;
    walk(node);
  }

  function walk(root) {
    if (!root || root.nodeType !== 1) { if (root && root.nodeType === 3) ttext(root); return; }
    // атрибуты самого элемента и потомков
    var self = root.getAttribute ? [root] : [];
    var els = self.concat(root.querySelectorAll ? [].slice.call(root.querySelectorAll('*')) : []);
    for (var i = 0; i < els.length; i++) {
      for (var a = 0; a < ATTRS.length; a++) {
        var v = els[i].getAttribute(ATTRS[a]);
        if (!v) continue;
        var tr = translate(v);
        if (tr !== null && tr !== v) els[i].setAttribute(ATTRS[a], tr);
      }
    }
    // текстовые узлы
    var tw = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode: function (n) {
        var p = n.parentNode;
        if (!p || SKIP[p.nodeName]) return NodeFilter.FILTER_REJECT;
        return n.nodeValue && /\S/.test(n.nodeValue)
          ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
      }
    });
    var nodes = [], n;
    while ((n = tw.nextNode())) nodes.push(n);
    for (var k = 0; k < nodes.length; k++) ttext(nodes[k]);
  }

  /* Перевод выполняется СИНХРОННО в колбэке наблюдателя. Колбэк
     MutationObserver — это микрозадача: она выполняется после текущего кода,
     но ДО того, как браузер отрисует кадр. Значит, если перевести узлы прямо
     здесь (а не отложенно через setTimeout), русский текст заменяется на
     английский раньше, чем его успеют нарисовать — мигания нет. Обрабатываем
     только изменившиеся узлы, поэтому это быстро даже при частых обновлениях. */
  var observer = null;
  function onMutations(records) {
    if (!observer) return;
    observer.disconnect();          // свои же правки не должны будить наблюдатель
    try {
      for (var i = 0; i < records.length; i++) {
        var r = records[i];
        if (r.type === 'characterData') ttext(r.target);
        else if (r.type === 'childList') {
          for (var j = 0; j < r.addedNodes.length; j++) tnode(r.addedNodes[j]);
        }
      }
    } finally {
      observer.observe(document.body, { childList: true, subtree: true, characterData: true });
    }
  }

  function currentLang() {
    try { return localStorage.getItem(KEY) === 'en' ? 'en' : 'ru'; } catch (e) { return 'ru'; }
  }

  function setLang(l) {
    try { localStorage.setItem(KEY, l === 'en' ? 'en' : 'ru'); } catch (e) {}
    location.reload();
  }

  function start() {
    if (currentLang() !== 'en') return;
    document.documentElement.setAttribute('lang', 'en');
    walk(document.body);
    if (window.MutationObserver) {
      observer = new MutationObserver(onMutations);
      observer.observe(document.body, {
        childList: true, subtree: true, characterData: true
      });
    }
  }

  window.socLang = currentLang;
  window.socSetLang = setLang;
  window.socT = function (s) {
    if (currentLang() !== 'en') return s;
    var t = translate(s);
    return t === null ? s : t;
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();
