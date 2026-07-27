# -*- coding: utf-8 -*-
"""
РЕГЕКС-НЕЗАВИСИМЫЕ контент-признаки «секретности».

Ключевая идея диплома: секрет — это не «строка, совпавшая с известным regex»,
а статистическое свойство контента (высокая энтропия, длинный токен смешанного
алфавита, base64/hex-структура). Эти признаки НЕ привязаны к конкретному формату
токена, поэтому модель на них ОБОБЩАЕТСЯ на форматы, которых не видела, — там, где
сигнатурная регулярка даёт нулевой recall.

featurize(content) -> dict признаков; vector(feats) -> список чисел (для ML).
Зависимостей нет (stdlib).
"""

# --- скрипт живёт в подпапке; движок проекта — в корне ---
import os as _os, sys as _sys
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
for _p in (_ROOT, _os.path.join(_ROOT, "tools"), _os.path.join(_ROOT, "research")):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
_os.chdir(_ROOT)
del _os, _sys
import re
import math

_TOKEN_RE = re.compile(r"[^A-Za-z0-9_\-+/=\.]+")
_HEX_RE = re.compile(r"[0-9a-fA-F]{16,}")
_B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")

# порядок признаков фиксирован (для ML-вектора)
FEATURES = [
    "file_entropy", "max_token_entropy", "max_token_len", "n_long_tokens",
    "top_token_charset", "digit_ratio", "alpha_ratio", "symbol_ratio",
    "upper_ratio", "mean_token_len", "has_b64_padding", "longest_hex_len",
    "longest_b64_len", "entropy_x_len",
]


def shannon_entropy(s: str) -> float:
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


def featurize(content: str) -> dict:
    content = content or ""
    toks = [t for t in _TOKEN_RE.split(content) if t]
    long_toks = [t for t in toks if len(t) >= 16]

    # энтропия и самый «секретный» токен
    max_ent = 0.0; top_tok = ""
    for t in long_toks:
        e = shannon_entropy(t)
        if e > max_ent:
            max_ent = e; top_tok = t
    max_len = max((len(t) for t in toks), default=0)

    # доли классов символов по всему контенту
    n = len(content) or 1
    digits = sum(c.isdigit() for c in content)
    alphas = sum(c.isalpha() for c in content)
    uppers = sum(c.isupper() for c in content)
    symbols = sum((not c.isalnum()) and (not c.isspace()) for c in content)

    longest_hex = max((len(m.group()) for m in _HEX_RE.finditer(content)), default=0)
    longest_b64 = max((len(m.group()) for m in _B64_RE.finditer(content)), default=0)
    has_pad = 1.0 if re.search(r"[A-Za-z0-9+/]{16,}={1,2}", content) else 0.0

    feats = {
        "file_entropy":      round(shannon_entropy(content), 4),
        "max_token_entropy": round(max_ent, 4),
        "max_token_len":     float(max_len),
        "n_long_tokens":     float(len(long_toks)),
        "top_token_charset": float(len(set(top_tok))),
        "digit_ratio":       round(digits / n, 4),
        "alpha_ratio":       round(alphas / n, 4),
        "symbol_ratio":      round(symbols / n, 4),
        "upper_ratio":       round(uppers / n, 4),
        "mean_token_len":    round(sum(len(t) for t in toks) / (len(toks) or 1), 3),
        "has_b64_padding":   has_pad,
        "longest_hex_len":   float(longest_hex),
        "longest_b64_len":   float(longest_b64),
        "entropy_x_len":     round(max_ent * max_len, 3),  # «высокая энтропия И длинный» сразу
    }
    return feats


def vector(feats: dict) -> list:
    return [float(feats.get(k, 0.0)) for k in FEATURES]
