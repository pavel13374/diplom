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
    filename_signal        bool   путь похож на секрет-файл (.env/secret/.pem/...)
    placeholder_signal     bool   контент содержит плейсхолдеры (EXAMPLE/CHANGEME/...)
"""
import re
import math

_TOKEN_RE = re.compile(r"[^A-Za-z0-9+/_\-]+")  # делим и по =, чтобы KEY=VALUE распадался

# Секрет-сигнатуры (как у gitleaks/trufflehog, упрощённо)
_PATTERNS = {
    "gitlab_pat":   re.compile(r"glpat-[0-9A-Za-z_\-]{20,}"),
    "aws_akia":     re.compile(r"AKIA[0-9A-Z]{16}"),
    "private_key":  re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    "jwt":          re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    "slack_token":  re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    "github_pat":   re.compile(r"ghp_[0-9A-Za-z]{20,}"),
    "db_url":       re.compile(r"(?:postgres|postgresql|mysql|mongodb)://[^\s:@/]+:[^\s:@/]+@"),
}

_FILENAME_RE = re.compile(r"(?:^|/|\.)(?:env|secret|secrets|credential|credentials|"
                          r"id_rsa|id_dsa|id_ecdsa)\b|\.pem$|\.key$|\.env", re.IGNORECASE)

_PLACEHOLDER_RE = re.compile(
    r"example|changeme|change_me|placeholder|dummy|your[-_]|<[^>\n]{1,40}>|"
    r"x{4,}|todo|редактируй|замени", re.IGNORECASE)

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


def analyze(content, path="") -> dict:
    content = content or ""
    path = path or ""

    # энтропия по «словам»-токенам длины >= 16
    max_ent = 0.0
    high_token = False
    for tok in _TOKEN_RE.split(content):
        if len(tok) >= 16:
            e = shannon_entropy(tok)
            if e > max_ent:
                max_ent = e
            if len(tok) >= 20 and e >= 4.0:
                high_token = True

    hits = [name for name, rx in _PATTERNS.items() if rx.search(content)]

    return {
        "shannon_entropy":        round(max_ent, 3),
        "has_high_entropy_token": high_token,
        "regex_hits":             hits,
        "n_regex_hits":           len(hits),
        "filename_signal":        bool(_FILENAME_RE.search(path)),
        "placeholder_signal":     bool(_PLACEHOLDER_RE.search(content)),
        # энтропия ожидаема по типу файла (lock/минификация/base64-иконка)
        "generated_signal":       bool(_GENERATED_RE.search(path)),
        # в содержимом есть выгрузка на внешний хост (scp/dns/curl)
        "net_sink_signal":        bool(_NET_SINK_RE.search(content)),
        # файл является манифестом зависимостей
        "deps_manifest":          bool(_DEPS_RE.search(path)),
        # в содержимом есть исполнение закодированной строки (обфускация)
        "obfuscation_signal":     bool(_OBFUSCATION_RE.search(content)),
        # файл — рабочий продукт SOC-команды (правило, гипотеза, плейбук, доки),
        # где упоминание техники ОЖИДАЕМО и само по себе не является угрозой
        "security_content":       bool(_SECURITY_CONTENT_RE.search(path)),
    }
