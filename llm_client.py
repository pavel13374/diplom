"""
Клиент к локальной open-source LLM через Ollama (http://localhost:11434).

Зачем: слой объяснимого триажа поверх детектора — на инцидент LLM выдаёт
человекочитаемый нарратив, severity, флаг benign-двойника и рекомендованные
действия реагирования. ML/правила остаются детектором, LLM — аналитик-объяснитель.

Зависимостей нет (только stdlib). Если Ollama не запущена/не установлена —
available() вернёт False, а triage() — безопасный фолбэк (severity по входному
риску, без падения системы). Так диплом работает и без LLM, и с ней.

Установка LLM: см. setup_llm.bat (ставит Ollama и тянет модель).
"""
import json
import time
import logging
import urllib.request
import urllib.error

logger = logging.getLogger("llm")


def _cfg():
    import config
    return getattr(config, "LLM", {}) or {}


def _host():
    import os
    return (os.environ.get("OLLAMA_HOST") or _cfg().get("host", "http://localhost:11434")).rstrip("/")


def _model():
    return _cfg().get("model", "qwen2.5:3b-instruct")


def _timeout():
    return float(_cfg().get("timeout", 60))


def enabled():
    return bool(_cfg().get("enabled", True))


# ----------------------------------------------------------------------
def _get(path):
    req = urllib.request.Request(_host() + path, method="GET")
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read().decode("utf-8"))


def _post(path, payload):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(_host() + path, data=data,
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=_timeout()) as r:
        return json.loads(r.read().decode("utf-8"))


def available():
    """True, если Ollama отвечает (можно вызывать перед использованием)."""
    if not enabled():
        return False
    try:
        _get("/api/tags")
        return True
    except Exception:
        return False


def list_models():
    try:
        data = _get("/api/tags")
        return [m.get("name") for m in data.get("models", [])]
    except Exception:
        return []


def has_model(name=None):
    name = name or _model()
    models = list_models()
    # сопоставление с учётом тега :latest
    base = name.split(":")[0]
    return any(m == name or m.split(":")[0] == base for m in models)


# ----------------------------------------------------------------------
def _has_cjk(text):
    """Есть ли в тексте иероглифы/японский/корейский — признак ответа не на русском."""
    for ch in (text or ""):
        o = ord(ch)
        if (0x4E00 <= o <= 0x9FFF) or (0x3040 <= o <= 0x30FF) or (0xAC00 <= o <= 0xD7AF):
            return True
    return False


def chat(messages, json_mode=False, temperature=0.2, model=None):
    """Низкоуровневый вызов /api/chat. Возвращает текст ответа или None."""
    payload = {
        "model": model or _model(),
        "messages": messages,
        "stream": False,
        "options": {"temperature": temperature},
    }
    if json_mode:
        payload["format"] = "json"
    t0 = time.time()
    try:
        resp = _post("/api/chat", payload)
        out = (resp.get("message") or {}).get("content", "")
        logger.info("LLM chat ok", extra={"ctx": {
            "model": payload["model"], "latency_s": round(time.time() - t0, 2),
            "chars_out": len(out), "json_mode": json_mode}})
        return out
    except urllib.error.URLError as e:
        logger.warning("LLM недоступна: %s" % e, extra={"ctx": {
            "model": payload["model"], "latency_s": round(time.time() - t0, 2)}})
        return None
    except Exception as e:
        logger.warning("LLM ошибка: %s" % e, extra={"ctx": {
            "model": payload["model"], "latency_s": round(time.time() - t0, 2)}})
        return None


# ----------------------------------------------------------------------
TRIAGE_SYSTEM = (
    "Пиши ВСЁ на русском языке (severity-метки оставляй латиницей). "
    "Ты — старший аналитик SOC. Анализируешь инцидент в CI/CD (GitLab) по "
    "поведенческим сигналам и контенту коммитов. Отвечай СТРОГО в JSON по схеме:\n"
    '{"severity": "low|medium|high|critical", "is_true_positive": true/false, '
    '"confidence": 0.0-1.0, "title": "краткий заголовок", '
    '"narrative": "2-4 предложения: что произошло и почему подозрительно", '
    '"recommended_actions": ["действие1", "действие2"], '
    '"benign_explanation": "если это ложное срабатывание — почему, иначе пустая строка"}\n'
    "Учитывай: высокая энтропия + срабатывание secret-regex + касание secrets-repo + "
    "ослабление пайплайна + выдача доступа = вероятная компрометация секрета. "
    "Файлы вида .env.example с плейсхолдерами (placeholder_signal) — это НЕ инцидент."
)


def triage(incident: dict) -> dict:
    """Объяснимый триаж инцидента. incident — словарь контекста (актор, события,
    отклонения от базлайна, content-features, оценка риска). Возвращает структуру
    с severity/narrative/actions. Без LLM — детерминированный фолбэк."""
    fallback = _fallback_triage(incident)
    if not available():
        logger.info("triage: LLM недоступна — детерминированный fallback",
                    extra={"ctx": {"incident_id": incident.get("incident_id")
                                   or incident.get("id")}})
        return fallback
    try:
        user = ("Контекст инцидента (JSON):\n" + json.dumps(incident, ensure_ascii=False, indent=2)
                + "\n\nВыдай результат строго в JSON по схеме.")
        out = chat([{"role": "system", "content": TRIAGE_SYSTEM},
                    {"role": "user", "content": user}], json_mode=True, temperature=0.1)
        if not out:
            return fallback
        if _has_cjk(out):
            fallback["_note"] = "LLM ответила не на русском — использован детерминированный разбор"
            return fallback
        data = json.loads(out)
        data["_source"] = "llm:" + _model()
        # нормализация полей
        data.setdefault("severity", fallback["severity"])
        data.setdefault("recommended_actions", fallback["recommended_actions"])
        return data
    except Exception as e:
        logger.warning(f"triage parse failed: {e}")
        fallback["_note"] = "llm output unparseable, used fallback"
        return fallback


def _fallback_triage(incident: dict) -> dict:
    """Детерминированный триаж без LLM (по входным сигналам)."""
    score = float(incident.get("risk_score", 0) or 0)
    hits = incident.get("regex_hits") or []
    ent = float(incident.get("shannon_entropy", 0) or 0)
    placeholder = bool(incident.get("placeholder_signal"))
    secret_signal = bool(hits) and ent >= 4.0 and not placeholder
    if secret_signal or score >= 0.8:
        sev = "critical" if (secret_signal and score >= 0.8) else "high"
        tp = True
    elif score >= 0.5:
        sev, tp = "medium", True
    else:
        sev, tp = "low", False
    if placeholder and not hits:
        tp = False; sev = "low"
    actions = []
    if tp:
        actions = ["Отозвать затронутый токен/секрет", "Закрыть подозрительный MR",
                   "Включить push-protection на secret-путь", "Завести инцидент-issue"]
    return {
        "severity": sev, "is_true_positive": tp,
        "confidence": round(min(0.95, 0.5 + score / 2), 2),
        "title": incident.get("title") or "Подозрительная активность в CI/CD",
        "narrative": ("Эвристический триаж без LLM: " +
                      ("сигнатуры секрета + высокая энтропия вне плейсхолдеров." if secret_signal
                       else f"итоговый риск {score:.2f} по поведенческим сигналам.")),
        "recommended_actions": actions,
        "benign_explanation": ("Похоже на benign-двойник (.env.example/плейсхолдеры)."
                               if (placeholder and not hits) else ""),
        "_source": "fallback",
    }


# ----------------------------------------------------------------------
RULE_SYSTEM = (
    "Ты — detection engineer. По НАБЛЮДАЕМЫМ полям пропущенного события CI/CD "
    "(GitLab) пишешь detection-правило для слепой зоны ATT&CK. Отвечай СТРОГО в "
    "JSON по схеме (тексты title — на русском):\n"
    '{"id": "kebab-id", "title": "...", "technique": "Txxxx", "tactic": "...", '
    '"severity": "low|medium|high|critical", "risk": 0.0-1.0, '
    '"when": { ПОЛЕ: ЗНАЧЕНИЕ | {ОПЕРАТОР: АРГ} }}\n'
    "Разрешённые поля when — ТОЛЬКО наблюдаемые: action, project, path, hour, "
    "is_night, ext, bytes, n_regex_hits, shannon_entropy, filename_signal, "
    "placeholder_signal. Разрешённые операторы: >=, >, <=, <, ne, in, nin, contains. "
    "Правило должно срабатывать на переданном событии и быть НЕ слишком широким "
    "(не лови всё подряд). Никаких полей-меток мира (is_anomaly/technique_id/...)."
)

# поля, которыми правилу МОЖНО оперировать (наблюдаемые)
_RULE_ALLOWED_FIELDS = {
    "action", "project", "path", "hour", "is_night", "ext", "bytes",
    "n_regex_hits", "shannon_entropy", "filename_signal", "placeholder_signal",
}


def _rule_valid(rule, observed_ev):
    """Правило валидно, если: структура ок, поля when разрешены, и оно реально
    срабатывает на пропущенном событии (через тот же матчер, что у детектора)."""
    try:
        if not isinstance(rule, dict) or "when" not in rule or not isinstance(rule["when"], dict):
            return False
        if not rule["when"]:
            return False
        for field in rule["when"]:
            if field not in _RULE_ALLOWED_FIELDS:
                return False
        import detector
        return bool(detector._match_rule(observed_ev, rule["when"]))
    except Exception:
        return False


def author_rule(observed_ev: dict, technique: str = None, tactic: str = None) -> dict:
    """LLM синтезирует detection-правило под слепую зону по НАБЛЮДАЕМОМУ событию.
    Анти-лик: на вход идут только наблюдаемые поля. Если LLM недоступна или её
    правило не валидно/не срабатывает — фолбэк на эвристический черновик
    (detection_gaps.draft_rule). Возвращает правило-dict с пометкой источника."""
    import detection_gaps
    fallback = detection_gaps.draft_rule(technique or "T0000", observed_ev, tactic or "?")
    fallback["_source"] = "fallback:template"
    if not available():
        return fallback
    try:
        ctx = {k: observed_ev.get(k) for k in _RULE_ALLOWED_FIELDS if observed_ev.get(k) is not None}
        user = ("Пропущенное (наблюдаемое) событие:\n" + json.dumps(ctx, ensure_ascii=False, indent=2)
                + f"\n\nТехника ATT&CK для покрытия: {technique or '?'} ({tactic or '?'}). "
                "Выдай ОДНО правило строго по схеме.")
        out = chat([{"role": "system", "content": RULE_SYSTEM},
                    {"role": "user", "content": user}], json_mode=True, temperature=0.1)
        if not out:
            return fallback
        rule = json.loads(out)
        if technique and not rule.get("technique"):
            rule["technique"] = technique
        if tactic and not rule.get("tactic"):
            rule["tactic"] = tactic
        if _rule_valid(rule, observed_ev):
            rule.setdefault("id", "llm-" + (technique or "rule").lower().replace(".", "-"))
            rule["_source"] = "llm:" + _model()
            return rule
        fallback["_note"] = "LLM-правило не прошло валидацию/не сработало — взят шаблон"
        return fallback
    except Exception as e:
        logger.warning(f"author_rule failed: {e}")
        return fallback
