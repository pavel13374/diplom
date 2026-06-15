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
    }
