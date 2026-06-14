"""
Отправка отчётов в Telegram-бота.
Конфиг — config.TELEGRAM (enabled, token, chat_id). Работает на машине, где
запущен симулятор, через Bot API (никаких внешних зависимостей кроме requests).
"""
import time
import logging
import threading

logger = logging.getLogger("telegram")
_LAST = {"t": 0.0}
_LOCK = threading.Lock()


def _cfg():
    import config
    return getattr(config, "TELEGRAM", {}) or {}


def enabled():
    c = _cfg()
    return bool(c.get("enabled") and c.get("token") and c.get("chat_id"))


def send(text, silent=False, min_interval=0.0):
    """Шлёт сообщение. min_interval — антифлуд (сек) между сообщениями."""
    if not enabled():
        return False
    if min_interval:
        with _LOCK:
            if time.time() - _LAST["t"] < min_interval:
                return False
            _LAST["t"] = time.time()
    c = _cfg()
    try:
        import requests
        r = requests.post(
            f"https://api.telegram.org/bot{c['token']}/sendMessage",
            json={"chat_id": c["chat_id"], "text": text[:4000],
                  "parse_mode": "HTML", "disable_web_page_preview": True,
                  "disable_notification": bool(silent)},
            timeout=15)
        if r.status_code != 200:
            logger.warning(f"telegram send {r.status_code}: {r.text[:150]}")
        return r.status_code == 200
    except Exception as e:
        logger.warning(f"telegram send failed: {e}")
        return False


def send_async(text, **kw):
    threading.Thread(target=send, args=(text,), kwargs=kw, daemon=True).start()
