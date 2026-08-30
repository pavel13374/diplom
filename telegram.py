# -*- coding: utf-8 -*-
"""
Отправка сообщений в Telegram-бота.

Конфигурация — `config.TELEGRAM` (enabled, token, chat_id). Токен и chat_id
приходят из окружения (SOC_TELEGRAM_TOKEN / SOC_TELEGRAM_CHAT_ID) либо из
git-ignored файлов `.telegram_token` / `.telegram_chat`. В исходниках их нет.

Что здесь важного, кроме самой отправки:

  • ТОКЕН НЕ ПОПАДАЕТ В ЖУРНАЛ. Раньше здесь стояло
    `logger.warning(f"telegram send failed: {e}")`, а requests кладёт в текст
    исключения ПОЛНЫЙ URL запроса — вместе с токеном:

        telegram send failed: HTTPSConnectionPool(host='api.telegram.org', ...
        url: /bot8717621147:AAGd2sny…/sendMessage (Caused by ProxyError(...))

    То есть каждый сетевой сбой писал боевой токен в logs/*.log, в
    debug-*.jsonl, в лог прогона и в диагностический архив, который отдаётся
    по кнопке из веб-интерфейса. Теперь всё, что уходит в лог, проходит через
    mask().

  • ПОВТОРЫ. Одна сетевая неудача больше не теряет сообщение: три попытки с
    нарастающей паузой. Код 429 обрабатывается отдельно — Telegram сам
    сообщает, сколько ждать (`parameters.retry_after`), и мы ждём столько.

  • АНТИФЛУД ПО ВИДУ СООБЩЕНИЯ. Было одно общее «время последней отправки» на
    весь модуль: алерт об аномалии с интервалом 20 с глушил ЛЮБОЕ другое
    сообщение, включая отчёт о запуске и уведомление об остановке. Теперь у
    каждого вида (`kind`) свой счётчик.

  • ДЕДУПЛИКАЦИЯ. Одинаковый текст, отправленный дважды подряд в пределах
    окна, уходит один раз: перезапуски и повторные попытки давали в чате
    сдвоенные сообщения.

  • НИЧЕГО НЕ ГЛОТАЕТСЯ МОЛЧА. Каждый отказ пишется в журнал с причиной и
    контекстом; счётчики доступны в state() для страницы «Диагностика».
"""
import re
import time
import logging
import threading

logger = logging.getLogger("telegram")

#: Время последней отправки по видам сообщений (антифлуд).
_LAST_BY_KIND = {}
#: Последние отправленные тексты (хэш -> время) для дедупликации.
_RECENT = {}
_LOCK = threading.RLock()

#: Счётчики и последняя ошибка — для /api/diag и страницы «Диагностика».
_STATE = {
    "sent": 0, "failed": 0, "suppressed_flood": 0, "suppressed_dup": 0,
    "retries": 0, "last_ok_ts": 0.0, "last_error": None, "last_error_ts": 0.0,
    "disabled_reason": None,
}

#: Сколько секунд считать одинаковый текст дубликатом.
DEDUP_WINDOW_S = 120
#: Попыток на сообщение (первая + повторы).
ATTEMPTS = 3
#: Таймаут одного запроса, секунды (connect, read). Настраивается: маршрут до
#: api.telegram.org бывает медленным, и на живом стенде пять секунд на
#: установку соединения уже давали редкие ReadTimeout при работающем в целом
#: канале. Терять сообщение из-за медленного маршрута незачем — повторы есть,
#: но лучше не доводить до них.
def _timeouts():
    import os
    try:
        c = float(os.environ.get("SOC_TELEGRAM_CONNECT_TIMEOUT", 10))
        r = float(os.environ.get("SOC_TELEGRAM_READ_TIMEOUT", 20))
        return (max(1.0, c), max(1.0, r))
    except (TypeError, ValueError):
        return (10.0, 20.0)


TIMEOUT = _timeouts()

_TOKEN_RE = re.compile(r"\b\d{6,12}:[A-Za-z0-9_\-]{30,}\b")
_BOT_PATH_RE = re.compile(r"/bot[^/\s]+")


def mask(text):
    """Убрать из текста всё, что похоже на токен бота.

    Две формы: сам токен `123456789:AA…` и путь `/bot<токен>` из URL, который
    requests подставляет в текст исключения.
    """
    if not text:
        return text
    s = str(text)
    s = _BOT_PATH_RE.sub("/bot<TOKEN>", s)
    s = _TOKEN_RE.sub("<TOKEN>", s)
    tok = (_cfg() or {}).get("token")
    if tok:
        s = s.replace(str(tok), "<TOKEN>")
    return s


#: Базовый адрес Bot API. Вынесен из кода, чтобы (а) канал можно было
#: проверить локальным имитатором, не выходя в сеть, и (б) стенд в закрытом
#: контуре мог ходить через свой прокси. По умолчанию — настоящий Telegram.
def api_base():
    import os
    return (os.environ.get("SOC_TELEGRAM_API_BASE")
            or "https://api.telegram.org").rstrip("/")


def _cfg():
    import config
    return getattr(config, "TELEGRAM", {}) or {}


def enabled():
    c = _cfg()
    ok = bool(c.get("enabled") and c.get("token") and c.get("chat_id"))
    if not ok and _STATE["disabled_reason"] is None:
        if not c.get("token"):
            _STATE["disabled_reason"] = "нет токена (SOC_TELEGRAM_TOKEN или .telegram_token)"
        elif not c.get("chat_id"):
            _STATE["disabled_reason"] = "нет chat_id (SOC_TELEGRAM_CHAT_ID или .telegram_chat)"
        else:
            _STATE["disabled_reason"] = "выключено в конфигурации"
    return ok


def state():
    """Снимок для диагностики. Токена здесь нет и быть не может."""
    c = _cfg()
    tok = c.get("token") or ""
    with _LOCK:
        d = dict(_STATE)
    d["enabled"] = bool(c.get("enabled") and tok and c.get("chat_id"))
    d["token_set"] = bool(tok)
    d["token_hint"] = (tok[:4] + "…" + str(len(tok))) if tok else None
    d["chat_id_set"] = bool(c.get("chat_id"))
    d["last_error"] = mask(d.get("last_error"))
    return d


def _note_fail(reason, **ctx):
    with _LOCK:
        _STATE["failed"] += 1
        _STATE["last_error"] = mask(reason)
        _STATE["last_error_ts"] = time.time()
    logger.warning("telegram: сообщение не отправлено",
                   extra={"ctx": dict({"reason": mask(reason)}, **ctx)})


def send(text, silent=False, min_interval=0.0, kind="default", dedup=True):
    """Отправить сообщение. Возвращает True только при подтверждении Telegram.

    min_interval — антифлуд В ПРЕДЕЛАХ ВИДА `kind`, а не на весь модуль.
    dedup — не повторять тот же текст в пределах DEDUP_WINDOW_S.
    """
    if not enabled():
        logger.debug("telegram: отправка пропущена — интеграция выключена",
                     extra={"ctx": {"kind": kind, "reason": _STATE["disabled_reason"]}})
        return False

    now = time.time()
    if min_interval:
        with _LOCK:
            if now - _LAST_BY_KIND.get(kind, 0.0) < min_interval:
                _STATE["suppressed_flood"] += 1
                logger.debug("telegram: подавлено антифлудом",
                             extra={"ctx": {"kind": kind, "min_interval": min_interval}})
                return False
            _LAST_BY_KIND[kind] = now

    if dedup:
        key = (kind, hash(text))
        with _LOCK:
            for k, t in list(_RECENT.items()):
                if now - t > DEDUP_WINDOW_S:
                    _RECENT.pop(k, None)
            if now - _RECENT.get(key, 0.0) < DEDUP_WINDOW_S:
                _STATE["suppressed_dup"] += 1
                logger.debug("telegram: подавлен дубликат",
                             extra={"ctx": {"kind": kind}})
                return False
            _RECENT[key] = now

    c = _cfg()
    url = f"{api_base()}/bot{c['token']}/sendMessage"
    payload = {"chat_id": c["chat_id"], "text": str(text)[:4000],
               "parse_mode": "HTML", "disable_web_page_preview": True,
               "disable_notification": bool(silent)}

    try:
        import requests
    except ImportError:
        _note_fail("не установлен пакет requests", kind=kind)
        return False

    last = "неизвестно"
    for attempt in range(1, ATTEMPTS + 1):
        try:
            r = requests.post(url, json=payload, timeout=_timeouts())
        except Exception as e:
            # ВАЖНО: текст исключения содержит URL с токеном — маскируем.
            last = f"{type(e).__name__}: {mask(e)}"
            if attempt < ATTEMPTS:
                with _LOCK:
                    _STATE["retries"] += 1
                logger.debug("telegram: попытка не удалась, повторяю",
                             extra={"ctx": {"kind": kind, "attempt": attempt,
                                            "error": last}})
                time.sleep(min(2 ** attempt, 8))
                continue
            _note_fail(last, kind=kind, attempts=attempt)
            return False

        if r.status_code == 200:
            with _LOCK:
                _STATE["sent"] += 1
                _STATE["last_ok_ts"] = time.time()
            logger.info("telegram: сообщение отправлено",
                        extra={"ctx": {"kind": kind, "chars": len(str(text)),
                                       "silent": bool(silent), "attempt": attempt}})
            return True

        if r.status_code == 429:
            # Telegram сам говорит, сколько ждать. Раньше 429 считался обычной
            # ошибкой, сообщение терялось, а следующее прилетало в ту же стену.
            wait = 5
            try:
                wait = int((r.json().get("parameters") or {}).get("retry_after", 5))
            except Exception as e:
                logger.debug("telegram: retry_after не разобран, беру 5 с",
                             extra={"ctx": {"error": f"{type(e).__name__}: {e}"}})
            wait = max(1, min(wait, 60))
            if attempt < ATTEMPTS:
                with _LOCK:
                    _STATE["retries"] += 1
                logger.warning("telegram: лимит частоты, жду",
                               extra={"ctx": {"kind": kind, "retry_after_s": wait,
                                              "attempt": attempt}})
                time.sleep(wait)
                continue

        # 4xx (кроме 429) повторять бессмысленно: неверный chat_id, отозванный
        # токен, битая разметка HTML — всё это не пройдёт и со второй попытки.
        body = mask((r.text or ""))[:200]
        last = f"HTTP {r.status_code}: {body}"
        if 500 <= r.status_code < 600 and attempt < ATTEMPTS:
            with _LOCK:
                _STATE["retries"] += 1
            time.sleep(min(2 ** attempt, 8))
            continue
        _note_fail(last, kind=kind, status=r.status_code, attempts=attempt)
        return False

    _note_fail(last, kind=kind, attempts=ATTEMPTS)
    return False


def send_async(text, **kw):
    """Отправка в фоне. Поток именованный — иначе его не видно в диагностике."""
    t = threading.Thread(target=send, args=(text,), kwargs=kw,
                         daemon=True, name="telegram-send")
    t.start()
    return t


def ping():
    """Проверка связи: getMe. Возвращает (ok, описание) — без токена в тексте."""
    if not enabled():
        return False, _STATE["disabled_reason"] or "выключено"
    try:
        import requests
        r = requests.get(f"{api_base()}/bot{_cfg()['token']}/getMe",
                         timeout=_timeouts())
        if r.status_code != 200:
            return False, f"HTTP {r.status_code}: {mask(r.text)[:120]}"
        d = (r.json() or {}).get("result") or {}
        return True, f"@{d.get('username', '?')} (id {d.get('id', '?')})"
    except Exception as e:
        return False, f"{type(e).__name__}: {mask(e)}"
