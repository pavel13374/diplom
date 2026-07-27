# -*- coding: utf-8 -*-
"""
ЖИВАЯ БОЛТОВНЯ КОМАНДЫ через LLM (стендапы, code review, апрувы).

Вместо одних только банков фраз реплики генерит локальная LLM (Ollama) в
контексте SOC-команды — лента ревью/стендапов читается как живые люди, а не
рандом. Генерация буферизованная (просим у модели сразу пачку вариантов и
раздаём по одному) — это амортизирует задержку. Если Ollama недоступна или
LLM_CHATTER=False — прозрачный фолбэк на банки фраз (comments.py).
"""

import collections
import logging

logger = logging.getLogger("chatter")

_BUF = collections.defaultdict(collections.deque)
_BUF_SIZE = 6

_SYS = ("Ты — инженер SOC-команды (detection engineering в GitLab): пишешь правила "
        "детекта, нормализацию, разбираешь инциденты, делаешь code review. Пиши "
        "кратко и естественно по-русски, без кавычек, без нумерации, без префиксов.")

_PROMPTS = {
    "standup": "Реплика для дейли-стендапа: что делал вчера / план на сегодня "
               "(правило детекта, нормализатор, разбор инцидента, ревью, тюнинг порога). "
               "1 предложение.",
    "review_request": "Комментарий ревьюера к merge request с новым detection-правилом: "
                      "придирка по делу (шумные фильтры, нехватка тестов, ATT&CK-ссылка, "
                      "уровень severity, окно агрегации). 1-2 предложения.",
    "review_response": "Ответ инженера на замечание ревьюера к его detection-правилу: "
                       "согласие/уточнение/что поправил. 1 предложение.",
    "approve": "Короткий апрув merge request в команде (по делу, без формальностей).",
}


def _generate(kind, n=_BUF_SIZE):
    try:
        import llm_client
        if not llm_client.available():
            return []
        user = (_PROMPTS.get(kind, _PROMPTS["standup"])
                + f"\n\nВыдай {n} РАЗНЫХ вариантов, по одному на строку.")
        out = llm_client.chat([{"role": "system", "content": _SYS},
                               {"role": "user", "content": user}], temperature=0.9)
        if not out:
            return []
        lines = []
        for ln in out.splitlines():
            ln = ln.strip().lstrip("-*0123456789.) \t").strip().strip('"').strip()
            if len(ln) > 3 and not any((0x4E00 <= ord(c) <= 0x9FFF) for c in ln):
                lines.append(ln)
        return lines[:n]
    except Exception as e:
        logger.warning(f"chatter generation failed: {e}")
        return []


def line(kind, fallback_fn):
    """Реплика заданного типа: из LLM-буфера, иначе из банка (fallback_fn)."""
    try:
        import config
        if getattr(config, "LLM_CHATTER", True):
            buf = _BUF[kind]
            if not buf:
                for l in _generate(kind):
                    buf.append(l)
            if buf:
                return buf.popleft()
    except Exception:
        pass
    return fallback_fn()
