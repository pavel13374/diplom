"""
Наблюдаемые признаки контента файла для обучения детектора секретов.

ВАЖНО: эти признаки считаются для КАЖДОГО пуша — и нормального, и аномального.
Их видит и настоящий secret-scanner, поэтому это честные ФИЧИ, а не разметка.
Разметка (secret_type / is_anomaly / anomaly_type) живёт отдельно и в drop-листе
экспорта. Здесь — только то, что вычислимо из самого содержимого/пути.

analyze(content, path) -> dict:
    shannon_entropy        float  макс. энтропия Шеннона по токенам длины >= 16
    has_high_entropy_token bool   есть токен длины >= 20 с энтропией >= 4.0
    regex_hits             list   имена сработавших паттернов (секрет-сигнатуры)
    n_regex_hits           int    len(regex_hits)
    real_hits              list   сигнатуры, чьё СОВПАДЕНИЕ не похоже на заглушку
    n_real_hits            int    len(real_hits)
    filename_signal        bool   путь похож на секрет-файл (.env/secret/.pem/...)
    placeholder_signal     bool   ВСЕ найденные секреты — заглушки (см. ниже)
    evasion_signal         bool   секрет виден только после нормализации
    evasion_kinds          list   чем именно он был скрыт
    truncated              bool   файл проанализирован не целиком (см. лимиты)

────────────────────────────────────────────────────────────────────────────
ПОЧЕМУ ЗАГЛУШКА ОПРЕДЕЛЯЕТСЯ ПО КАЖДОМУ СОВПАДЕНИЮ, А НЕ ПО ФАЙЛУ

`placeholder_signal` был признаком ФАЙЛА: истина, если где угодно в содержимом
встретилось слово example/changeme/dummy/todo, четыре икса подряд или
что-нибудь в угловых скобках. Четыре самых ценных правила требуют
`placeholder_signal: false`, системная подсказка LLM прямо называет плейсхолдер
«не инцидентом», а `_fallback_triage` гасит по нему признак секрета.

Замер через боевой DetectionEngine:

    настоящий glpat-токен                     risk 0.92  (secret-signature-commit)
    он же + строка "# TODO: rotate later"     risk 0.00  (ни одной сработки)
    он же + "html = '<div>hi</div>'"          risk 0.00
    он же + "user = 'your_name'"              risk 0.00

То есть одно слово в файле выключало обнаружение секретов целиком. Это и
готовое уклонение (правила лежат в репозитории, их видно), и крупный источник
пропусков в обычной работе: `todo` и угловые скобки есть в огромной доле
исходников.

Теперь заглушечность решается ДЛЯ КАЖДОГО СОВПАДЕНИЯ: смотрим на сам
совпавший фрагмент и на его строку, а не на файл. `placeholder_signal`
сохранён (на него ссылаются правила, признаки ML и обученная модель), но
означает теперь «ВСЕ найденные секреты — заглушки», поэтому больше не может
спрятать настоящий.

────────────────────────────────────────────────────────────────────────────
ПОЧЕМУ ЕСТЬ ВТОРОЙ ПРОХОД ПО НОРМАЛИЗОВАННОМУ ТЕКСТУ

Токены для энтропии резались по `[^A-Za-z0-9+/_-]+`, и считались только куски
длиной от 16. Поэтому:

    'TOKEN = "glpat-" + "Ab3xK9mQ7zR2pL5wT8vN"'   сигнатур нет, энтропия 0.00
    'T = "Z2xwYXQt…"'   (base64 того же токена)   сигнатур нет
    'TOKEN = "glpat<U+200B>-…"' (нулевая ширина)  сигнатур нет

Конкатенация строк — первое, что пробует любой человек, и она была бесплатной.
Нормализация (склейка соседних литералов, раскодирование escape-ов, снятие
невидимых символов, свёртка гомоглифов, декодирование base64) выполняется
ДОПОЛНИТЕЛЬНО к обычному проходу, результаты объединяются, а сам факт
«нашлось только после нормализации» становится отдельной уликой
(`evasion_signal`) — аналитику важно знать не только что секрет есть, но и что
его прятали.
"""
import re
import math
import base64
import binascii
import unicodedata

_TOKEN_RE = re.compile(r"[^A-Za-z0-9+/_\-]+")  # делим и по =, чтобы KEY=VALUE распадался

# =====================================================================
#  ЛИМИТЫ РАБОТЫ
# =====================================================================
# analyze() принимала содержимое любого размера: _TOKEN_RE.split материализует
# весь список токенов, а shannon_entropy строит словарь по каждому символу.
# Замер: 5 МБ одним токеном — 1.42 c, 200 000 коротких токенов — 1.51 c, и
# стоимость линейна по размеру файла, который выбирает автор коммита. Анализ
# синхронен внутри push_file и внутри цикла ингеста, поэтому один большой файл
# останавливает конвейер целиком — а пока он стоит, не проверяется ничего.
MAX_ANALYZE_BYTES = 1024 * 1024        # выше — смотрим голову и хвост
HEAD_TAIL_BYTES = 256 * 1024           # по столько с каждого конца
MAX_NORMALIZE_BYTES = 256 * 1024       # нормализация дороже — её окно меньше
MAX_B64_BLOBS = 24                     # сколько закодированных блоков раскрываем
MAX_B64_BLOB_BYTES = 64 * 1024

# Секрет-сигнатуры (как у gitleaks/trufflehog, упрощённо).
#
# Набор был из восьми паттернов и покрывал ровно те форматы, которые порождает
# сам симулятор. Замер на корпусе правдоподобных настоящих учётных данных: ни
# одной сработки на github_pat_/gho_/AIza/sk_live_/sk-proj-/npm_/xoxe-/ASIA/
# AccountKey= — то есть на большей части того, что реально утекает сегодня.
# Эти форматы уходили в «высокую энтропию», а она и слабее (риск 0.62 против
# 0.92), и обходится проще.
_PATTERNS = {
    "gitlab_pat":   re.compile(r"glpat-[0-9A-Za-z_\-]{20,}"),
    # Токены CI-джобы и деплой-токены GitLab: формат отличается от PAT.
    "gitlab_ci_token": re.compile(r"\bglcbt-[0-9A-Za-z_\-]{20,}|\bgldt-[0-9A-Za-z_\-]{20,}"),
    "aws_akia":     re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    # Секретный ключ AWS распознаётся только рядом с именем переменной: сама по
    # себе 40-символьная base64-строка встречается в норме постоянно.
    "aws_secret":   re.compile(
        r"aws_?secret_?access_?key\W{0,10}([A-Za-z0-9/+=]{40})", re.IGNORECASE),
    "private_key":  re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |PGP |OPENSSH |ENCRYPTED |)PRIVATE KEY(?: BLOCK)?-----"),
    "jwt":          re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    "slack_token":  re.compile(r"xox[baprse]-[0-9A-Za-z\-]{10,}|\bxapp-[0-9]-[A-Za-z0-9\-]{20,}"),
    # ghp_ (classic PAT), gho_ (OAuth), ghu_/ghs_ (app), ghr_ (refresh),
    # github_pat_ (fine-grained). Раньше был только ghp_.
    "github_pat":   re.compile(
        r"\bgh[pousr]_[0-9A-Za-z]{20,}\b|\bgithub_pat_[0-9A-Za-z_]{30,}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "stripe_key":   re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{20,}\b"),
    # OpenAI / Anthropic и совместимые. Требуем длинный хвост, чтобы не ловить
    # безобидное «sk-» в тексте.
    "llm_api_key":  re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_\-]{32,}\b"),
    "npm_token":    re.compile(r"\bnpm_[0-9A-Za-z]{30,}\b"),
    "pypi_token":   re.compile(r"\bpypi-AgEIcHlwaS5vcmc[0-9A-Za-z_\-]{20,}"),
    "azure_storage_key": re.compile(r"AccountKey\s*=\s*[A-Za-z0-9+/]{60,}={0,2}"),
    "twilio_sid":   re.compile(r"\bAC[0-9a-fA-F]{32}\b"),
    "sendgrid_key": re.compile(r"\bSG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b"),
    "db_url":       re.compile(r"(?:postgres|postgresql|mysql|mongodb)(?:\+\w+)?://[^\s:@/]+:[^\s:@/]+@"),
    # Учётные данные, встроенные в URI ЛЮБОЙ схемы: https://user:token@host.
    #
    # Настоящие сканеры секретов (gitleaks: generic credential in URI) держат
    # это отдельным правилом, и не зря: приватный индекс пакетов, git-remote с
    # токеном и вебхук с ключом в адресе — самые частые формы утечки, которые
    # не ловятся ни одной сигнатурой конкретного вендора, потому что значение
    # внутри URI произвольно и не имеет опознавательного префикса.
    #
    # db_url оставлен отдельно НАМЕРЕННО: он ловит тот же синтаксис, но
    # сообщает больше — «утекла строка подключения к БД». Совпадение двух
    # сигнатур на одном фрагменте повышает n_regex_hits, и это правильно:
    # два независимых основания подозревать секрет — сильнее одного.
    #
    # Схемы перечислены явно, а не `[a-z]+`, чтобы под правило не попадали
    # безобидные строки вида «время 10:30@ужин» и markdown-ссылки.
    "uri_credential": re.compile(
        r"(?:https?|ftp|git|ssh|svn|redis|amqp|smtp)://[^\s:@/]+:[^\s:@/]{6,}@"),
}

_FILENAME_RE = re.compile(r"(?:^|/|\.)(?:env|secret|secrets|credential|credentials|"
                          r"id_rsa|id_dsa|id_ecdsa)\b|\.pem$|\.key$|\.env", re.IGNORECASE)

# ЗАГЛУШКА — ПРИЗНАК ФРАГМЕНТА, А НЕ ФАЙЛА.
#
# Из набора убрана альтернатива `<[^>\n]{1,40}>`: под неё попадал ЛЮБОЙ
# html-тег и любая обобщённая аннотация типа `List<int>` — то есть почти любой
# исходник. Осталась явная форма заглушки в скобках (<TOKEN>, <your-key>) и
# слова с границами, чтобы `todo` не срабатывал внутри `mastodon`.
_PLACEHOLDER_RE = re.compile(
    r"\b(?:example|changeme|change_me|placeholder|dummy|redacted|sample|"
    r"fake|notreal|test[-_]?only|todo|fixme)\b|"
    r"your[-_][a-z]|"
    r"<[A-Za-z0-9_\- ]{1,30}>|"
    r"\{\{[^}\n]{1,40}\}\}|"
    r"\$\{[A-Za-z_][A-Za-z0-9_]{0,40}\}|"
    r"x{6,}|"
    r"\bредактируй\b|\bзамени\b", re.IGNORECASE)

#: Заглушечность САМОГО совпадения. Здесь набор шире (в токене-примере часто
#: стоит EXAMPLE/XXXX/000000), и границы слов не нужны — мы уже внутри секрета.
_MATCH_PLACEHOLDER_RE = re.compile(
    r"example|changeme|change_me|placeholder|dummy|redacted|sample|fake|"
    r"your[-_]?(?:key|token|secret|password)|xxxx|X{4,}|"
    r"1234567890|abcdef0123|deadbeef|<[^>\n]{1,40}>|\{\{|\$\{",
    re.IGNORECASE)

#: Учебные пары «логин:пароль» и хосты, которыми пишут ПРИМЕР строки
#: подключения. Нужны потому, что заглушечность теперь решается по самому
#: совпадению: `postgres://user:password@localhost:5432/db` не содержит слова
#: «example» внутри матча, а это заведомо не секрет.
_DUMMY_CRED_RE = re.compile(
    r"://(?:user|username|admin|root|login|foo|test|demo|dbuser|myuser)"
    r":(?:password|passwd|pass|secret|changeme|123456|mypassword|"
    r"your[-_]?password|token|xxx+|\*+)@|"
    r"@(?:localhost|127\.0\.0\.1|host|hostname|example\.(?:com|org|net)|"
    r"db|database|server|myhost)\b",
    re.IGNORECASE)

#: Файл, само ИМЯ которого объявляет его шаблоном. Признак путевой, поэтому
#: подделать его дописыванием слова в произвольный файл нельзя — надо назвать
#: файл шаблоном, а это уже наблюдаемое действие.
_TEMPLATE_PATH_RE = re.compile(
    r"\.(?:example|sample|template|dist|tpl)$|"
    r"\.(?:example|sample|template|dist)\.[A-Za-z0-9]+$|"
    r"(?:^|/)(?:example|sample|template)s?/", re.IGNORECASE)

#: Учебные значения из официальной документации — заглушки по определению.
_KNOWN_DUMMIES = {
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "ASIAIOSFODNN7EXAMPLE",
}

# Файлы, высокая энтропия которых ОЖИДАЕМА и секретом не является:
# lock-файлы (хэши зависимостей), минифицированный JS, встроенные base64-иконки,
# собранные артефакты. Без этого признака правило «высокая энтропия» ловило
# package-lock.json и *.min.js — это была основная статья ложных срабатываний.
_GENERATED_RE = re.compile(
    r"(?:^|/)(?:dist|build|vendor|node_modules|assets|static|public|img|images|fonts)/|"
    r"[-.]lock(?:\.json|\.yaml|\.yml)?$|"
    r"\.min\.(?:js|css)$|\.map$|\.svg$|package-lock\.json$|yarn\.lock$|"
    r"poetry\.lock$|Cargo\.lock$|go\.sum$|"
    # бинарные ресурсы. Имя вида *_b64 намеренно НЕ учитывается: атака
    # выгружает данные в export/dump_b64.txt, и по одному лишь суффиксу
    # выгрузка стала бы неотличима от иконки. Решает каталог, а не имя.
    r"\.(?:png|jpe?g|gif|ico|woff2?|ttf|pdf)$",
    re.IGNORECASE)

# Признак «канала наружу» в содержимом: выгрузка на внешний хост по scp/dns/curl.
# Нужен для T1048 (Exfiltration Over Alternative Protocol): у такого файла
# энтропия обычная, и по ней его не отличить — отличает именно структура.
_NET_SINK_RE = re.compile(
    r"(?:scp|rsync|sftp)\s+[^\s]+\s+[\w.-]+@[\w.-]+:|"
    r"dig\s+(?:\+\w+\s+)*[^\s]*\$\(|"
    r"nslookup\s+[^\s]*\$\(|"
    r"curl\s+(?:-[a-zA-Z]+\s+)*(?:https?://)?[\w.-]*(?:attacker|exfil|webhook\.site|"
    r"requestbin|ngrok|pastebin)|"
    r"(?:https?://|@)[\w.-]*(?:attacker|exfil|ngrok|pastebin)[\w.-]*",
    re.IGNORECASE)

# СТРУКТУРА ОБФУСКАЦИИ — для T1027 (Obfuscated Files or Information).
#
# Одной энтропии здесь мало, и это принципиально: атакующий прячет полезную
# нагрузку именно в минифицированном JS, где высокая энтропия ЛЕГИТИМНА и
# правило по энтропии обязано молчать (generated_signal). Отличает вредонос не
# «случайность» текста, а конструкция исполнения закодированной строки:
# eval(atob(...)), new Function(atob(...)), exec(base64.b64decode(...)).
_OBFUSCATION_RE = re.compile(
    r"eval\s*\(\s*(?:atob|unescape|decodeURIComponent|String\.fromCharCode)|"
    r"new\s+Function\s*\(\s*(?:atob|unescape)|"
    r"(?:exec|eval)\s*\(\s*(?:base64\.)?b64decode|"
    r"exec\s*\(\s*__import__\s*\(\s*['\"]base64|"
    r"\|\s*base64\s+-d\s*\|\s*(?:sh|bash)|"
    r"IEX\s*\(\s*\[System\.Text\.Encoding\]",
    re.IGNORECASE)

# ОТЛАДОЧНЫЙ ВЫВОД CI, СВЕТЯЩИЙ СЕКРЕТЫ — для T1552.004.
#
# Правило ci-debug-token-leak проверяло СООБЩЕНИЕ КОММИТА на слово «debug».
# Сообщение пишет автор коммита: слово можно не писать (и правило слепо) или,
# наоборот, писать на каждой правке CI (и правило шумит, а три отметки
# «ложное» его глушат — см. политику подавления). Условие обязано быть в
# СОДЕРЖИМОМ.
# Намеренно НЕ включены «set -x» и голое «env |»: они встречаются в обычных
# сборочных скриптах постоянно, и правило с ними давало бы поток ложных
# срабатываний — а три отметки «ложное» приглушают правило (см. политику
# приглушения). Оставлены только конструкции, которые печатают ИМЕННО
# учётные данные или включают полную трассировку CI.
_CI_DEBUG_RE = re.compile(
    r"CI_DEBUG_TRACE\s*:\s*[\"']?(?:true|1)|"
    r"CI_DEBUG_SERVICES\s*:\s*[\"']?(?:true|1)|"
    r"\bprintenv\b\s*(?:\||>|$)|"
    r"\becho\s+[\"']?\$\{?(?:CI_JOB_TOKEN|CI_REGISTRY_PASSWORD|CI_DEPLOY_PASSWORD"
    r"|[A-Z_]*(?:TOKEN|SECRET|PASSWORD|APIKEY|API_KEY))\}?",
    re.IGNORECASE)

# СОБСТВЕННЫЙ КОНТЕНТ SOC-КОМАНДЫ.
#
# Специфика именно этого контура: команда пишет ПРАВИЛА ДЕТЕКТИРОВАНИЯ, гипотезы
# для охоты и плейбуки — то есть тексты, которые ОПИСЫВАЮТ атакующие техники и
# потому набиты их приметами. Правило про «реестр контейнеров» срабатывало на
# файле rules/persistence/registry_run_key_modification.yml, а правило про
# пересылку почты — на hunts/mailbox-forwarding-rule.md. Формально в пути есть
# нужное слово; по сути это рабочий продукт аналитика.
#
# Признак нужен, чтобы правила по ключевым словам в пути не ловили описание
# техники вместо самой техники. Это известная беда репозиториев detection
# engineering: они полны строк, на которые реагируют сканеры.
_SECURITY_CONTENT_RE = re.compile(
    r"(?:^|/)(?:rules|detections|sigma|hunts|hunting|playbooks|runbooks|"
    r"docs|wiki|research|threat[-_]intel)/|"
    r"\.(?:md|rst|adoc)$|"
    r"(?:^|/)tests?/fixtures?/", re.IGNORECASE)

# Манифесты зависимостей — для T1195.001 (подмена зависимости)
_DEPS_RE = re.compile(
    r"(?:^|/)(?:requirements[\w.-]*\.txt|package\.json|go\.mod|pom\.xml|"
    r"Gemfile|build\.gradle|Cargo\.toml)$", re.IGNORECASE)


def shannon_entropy(s: str) -> float:
    """Энтропия Шеннона строки (бит/символ)."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    ent = 0.0
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


# =====================================================================
#  НОРМАЛИЗАЦИЯ (второй проход)
# =====================================================================
#: Невидимые символы: нулевая ширина, метки направления письма, BOM, word joiner.
_INVISIBLE_RE = re.compile(r"[​-‏  ‪-‮⁠-⁤﻿]")

#: Соседние строковые литералы, склеенные конкатенацией или просто соседством.
#: Покрывает "a" + "b" (Python/JS/Java/C#), "a" "b" (Python/C), 'a' . 'b' (PHP).
_CONCAT_RE = re.compile(
    r"(['\"])([^'\"\n]{0,200}?)\1\s*(?:[+.]\s*|\n\s*)(['\"])([^'\"\n]{0,200}?)\3")

#: Перенос строки обратным слэшем — так секрет режут в shell, в .env, в
#: Makefile и в C-подобных языках. Пропускать его нельзя: именно этим приёмом
#: пользуются профили уклонения stealthy/adaptive самого стенда, и до
#: нормализации `glpat-Ab3xK9 \<перевод строки>mQ7zR2pL5wT8` не давал НИ ОДНОЙ
#: сигнатуры и НИ ОДНОГО высокоэнтропийного токена.
_LINE_CONT_RE = re.compile(r"[ \t]*\\[ \t]*\r?\n[ \t]*")

_HEX_ESC_RE = re.compile(r"\\x([0-9A-Fa-f]{2})")
_UNI_ESC_RE = re.compile(r"\\u([0-9A-Fa-f]{4})")
_PCT_ESC_RE = re.compile(r"%([0-9A-Fa-f]{2})")
_B64_RUN_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")

#: Кириллические и греческие двойники латиницы. Полной таблицы confusables из
#: Unicode здесь нет намеренно: нужна не общая нормализация текста, а свёртка
#: ровно тех символов, которыми подменяют буквы в токенах.
_HOMOGLYPHS = str.maketrans({
    "а": "a", "А": "A", "в": "b", "В": "B", "е": "e", "Е": "E", "ё": "e",
    "к": "k", "К": "K", "м": "m", "М": "M", "н": "h", "Н": "H", "о": "o",
    "О": "O", "р": "p", "Р": "P", "с": "c", "С": "C", "т": "t", "Т": "T",
    "у": "y", "У": "Y", "х": "x", "Х": "X", "і": "i", "І": "I", "ѕ": "s",
    "ј": "j", "Ј": "J", "Ѕ": "S",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    "ο": "o", "ν": "v", "ρ": "p", "τ": "t", "χ": "x",
})


def _join_literals(text: str) -> str:
    """"glpat-" + "abc"  ->  "glpat-abc". Повторяем, пока склеивается."""
    for _ in range(6):          # цепочка из семи кусков схлопнется за шесть шагов
        new = _CONCAT_RE.sub(lambda m: m.group(1) + m.group(2) + m.group(4) + m.group(1), text)
        if new == text:
            break
        text = new
    return text


def _decode_escapes(text: str) -> str:
    def _h(m):
        try:
            return chr(int(m.group(1), 16))
        except ValueError:
            return m.group(0)
    text = _HEX_ESC_RE.sub(_h, text)
    text = _UNI_ESC_RE.sub(_h, text)
    return _PCT_ESC_RE.sub(_h, text)


def _decode_b64_blobs(text: str, out_limit=MAX_B64_BLOBS):
    """Раскрытые base64-блоки отдельным текстом (не подменяя исходный).

    Секрет, положенный в коммит закодированным, не ловится ни одной сигнатурой
    и по энтропии неотличим от иконки. Раскрываем ограниченное число блоков
    ограниченного размера — иначе это сам по себе вектор истощения ресурсов.
    """
    parts = []
    for i, m in enumerate(_B64_RUN_RE.finditer(text)):
        if i >= out_limit:
            break
        blob = m.group(0)
        if len(blob) > MAX_B64_BLOB_BYTES:
            continue
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
        except (ValueError, binascii.Error):
            continue
        try:
            s = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if s and sum(ch.isprintable() for ch in s) / len(s) > 0.9:
            parts.append(s)
    return "\n".join(parts)


def normalize(content: str):
    """(нормализованный текст, набор применённых приёмов).

    Работает на ограниченном окне: нормализация дороже обычного прохода, а
    входные данные выбирает автор коммита.
    """
    kinds = set()
    if not content:
        return "", kinds
    text = content[:MAX_NORMALIZE_BYTES]

    stripped = _INVISIBLE_RE.sub("", text)
    if stripped != text:
        kinds.add("invisible_chars")
        text = stripped

    folded = unicodedata.normalize("NFKC", text).translate(_HOMOGLYPHS)
    if folded != text:
        kinds.add("homoglyphs")
        text = folded

    unwrapped = _LINE_CONT_RE.sub("", text)
    if unwrapped != text:
        kinds.add("line_continuation")
        text = unwrapped

    joined = _join_literals(text)
    if joined != text:
        kinds.add("string_concat")
        text = joined

    unescaped = _decode_escapes(text)
    if unescaped != text:
        kinds.add("escapes")
        text = unescaped

    decoded = _decode_b64_blobs(text)
    if decoded:
        kinds.add("base64")
        text = text + "\n" + decoded
    return text, kinds


# =====================================================================
#  СОПОСТАВЛЕНИЕ СИГНАТУР
# =====================================================================
def _line_of(text: str, pos: int) -> str:
    a = text.rfind("\n", 0, pos) + 1
    b = text.find("\n", pos)
    return text[a:(b if b != -1 else len(text))]


def _is_placeholder_match(text: str, m, template_file: bool = False) -> bool:
    """Похоже ли на заглушку ИМЕННО ЭТО совпадение (а не файл целиком).

    Основания, по убыванию надёжности:
      1) совпавший фрагмент — известное значение из документации;
      2) внутри самого фрагмента стоит маркер заглушки (EXAMPLE/XXXX/${...})
         либо учебная пара логин:пароль / учебный хост;
      3) маркер стоит на ТОЙ ЖЕ СТРОКЕ — то есть относится к этому значению,
         а не к соседним двумстам строкам файла;
      4) файл НАЗВАН шаблоном (.env.example, config.dist) И значение при этом
         низкоэнтропийное. Имя файла — путевой признак: чтобы им
         воспользоваться, надо назвать файл шаблоном, а это само по себе
         наблюдаемо. Настоящий высокоэнтропийный токен, положенный в
         .env.example, заглушкой НЕ считается.
    """
    frag = m.group(0)
    if frag in _KNOWN_DUMMIES:
        return True
    if _MATCH_PLACEHOLDER_RE.search(frag) or _DUMMY_CRED_RE.search(frag):
        return True
    line = _line_of(text, m.start())
    if len(line) <= 400 and _PLACEHOLDER_RE.search(line):
        return True
    if template_file and shannon_entropy(frag) < 4.2:
        return True
    return False


def _scan(text: str, template_file: bool = False):
    """(все имена сигнатур, имена НЕ-заглушечных сигнатур)."""
    all_hits, real_hits = [], []
    if not text:
        return all_hits, real_hits
    for name, rx in _PATTERNS.items():
        matched = False
        real = False
        for m in rx.finditer(text):
            matched = True
            if not _is_placeholder_match(text, m, template_file):
                real = True
                break
        if matched:
            all_hits.append(name)
            if real:
                real_hits.append(name)
    return all_hits, real_hits


def _entropy_stats(text: str):
    max_ent = 0.0
    high_token = False
    for tok in _TOKEN_RE.split(text):
        if len(tok) >= 16:
            e = shannon_entropy(tok)
            if e > max_ent:
                max_ent = e
            if len(tok) >= 20 and e >= 4.0:
                high_token = True
    return max_ent, high_token


def analyze(content, path="") -> dict:
    content = content or ""
    path = path or ""

    # Ограничение объёма: у файла, выбранного автором коммита, размера нет.
    truncated = False
    if len(content) > MAX_ANALYZE_BYTES:
        truncated = True
        content = content[:HEAD_TAIL_BYTES] + "\n…\n" + content[-HEAD_TAIL_BYTES:]

    # энтропия по «словам»-токенам длины >= 16
    max_ent, high_token = _entropy_stats(content)

    template_file = bool(_TEMPLATE_PATH_RE.search(path))
    hits, real = _scan(content, template_file)

    # ВТОРОЙ ПРОХОД по нормализованному тексту. Именно дополнительный: если
    # нормализация что-то испортит, обычный проход всё равно отработал.
    norm_text, kinds = normalize(content)
    n_hits, n_real = _scan(norm_text, template_file)
    n_ent, n_high = _entropy_stats(norm_text)

    hidden = sorted(set(n_hits) - set(hits))
    hits = sorted(set(hits) | set(n_hits))
    real = sorted(set(real) | set(n_real))
    if n_ent > max_ent:
        max_ent = n_ent
    high_token = high_token or n_high

    evasion = bool(hidden) or (n_high and not high_token)
    evasion_kinds = sorted(kinds) if evasion else []

    return {
        "shannon_entropy":        round(max_ent, 3),
        "has_high_entropy_token": high_token,
        "regex_hits":             hits,
        "n_regex_hits":           len(hits),
        # Сигнатуры, чьё совпадение НЕ выглядит заглушкой. Именно они означают
        # «в файле лежит настоящий секрет».
        "real_hits":              real,
        "n_real_hits":            len(real),
        "filename_signal":        bool(_FILENAME_RE.search(path)),
        # ЗНАЧЕНИЕ ИЗМЕНИЛОСЬ: не «где-то в файле есть слово example», а «ВСЕ
        # найденные секреты — заглушки». Пока признак был файловым, одно слово
        # выключало четыре правила, LLM-триаж и признак модели разом.
        # Файл вообще без сигнатур считается заглушечным по прежнему признаку —
        # так поведение на .env.example с плейсхолдерами не меняется.
        "placeholder_signal":     (len(real) == 0) if hits
                                  else bool(_PLACEHOLDER_RE.search(content)),
        # энтропия ожидаема по типу файла (lock/минификация/base64-иконка)
        "generated_signal":       bool(_GENERATED_RE.search(path)),
        # в содержимом есть выгрузка на внешний хост (scp/dns/curl)
        "net_sink_signal":        bool(_NET_SINK_RE.search(content)),
        # файл является манифестом зависимостей
        "deps_manifest":          bool(_DEPS_RE.search(path)),
        # в содержимом есть исполнение закодированной строки (обфускация)
        "obfuscation_signal":     bool(_OBFUSCATION_RE.search(content)),
        # CI печатает переменные окружения / включает отладочную трассировку
        "ci_debug_signal":        bool(_CI_DEBUG_RE.search(content)),
        # файл — рабочий продукт SOC-команды (правило, гипотеза, плейбук, доки),
        # где упоминание техники ОЖИДАЕМО и само по себе не является угрозой
        "security_content":       bool(_SECURITY_CONTENT_RE.search(path)),
        # файл назван шаблоном (.env.example, config.dist, examples/…)
        "template_path":          template_file,
        # секрет виден ТОЛЬКО после нормализации — это улика сама по себе:
        # обычный код не прячет свои строки
        "evasion_signal":         evasion,
        "evasion_kinds":          evasion_kinds,
        "hidden_hits":            hidden,
        # файл проанализирован не целиком — важно не выдавать частичный
        # просмотр за полный
        "truncated":              truncated,
    }
