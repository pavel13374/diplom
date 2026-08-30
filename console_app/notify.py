# -*- coding: utf-8 -*-
"""
УВЕДОМЛЕНИЯ В TELEGRAM ИЗ КОНСОЛИ ЗАЩИТЫ.

Ключевое требование: цифры в чате обязаны совпадать с цифрами на экране.
Поэтому здесь НЕТ СВОЕЙ СТАТИСТИКИ. Сводка собирается вызовом ровно тех же
функций, что обслуживают веб-интерфейс:

    overview.build_stats()   -> то же, что отдаёт GET /api/stats
    incidents.build_workflow() -> то же, что отдаёт GET /api/workflow
    attack.build_coverage()  -> то же, что отдаёт GET /api/coverage

Раньше единственным отчётом в Telegram был report.build_report() из процесса
МИРА: он считал активности планировщика и события журнала и ничего не знал ни
об алертах, ни об инцидентах, ни о вердиктах. То есть в чат уходила статистика
симуляции, а на экране была статистика детектирования — два разных набора
чисел, которые невозможно было сверить между собой.

Что отсюда уходит в чат:
  • старт и остановка консоли;
  • периодическая сводка SOC (период — config.TELEGRAM["report_every_min"]);
  • ошибки: ERROR и CRITICAL, с агрегацией и антифлудом.
"""
import html
import time
import logging
import threading

import telegram
from .core import _SNAP, _EXECM

log = logging.getLogger("notify")

_STARTED = time.time()
_WORKER = {"thread": None, "stop": None}


def _esc(x):
    return html.escape(str(x))


def _cfg():
    import config
    return getattr(config, "TELEGRAM", {}) or {}


def _fmt_uptime(sec):
    sec = int(max(0, sec))
    h, m = sec // 3600, (sec % 3600) // 60
    return f"{h}ч {m}м" if h else f"{m}м"


def soc_summary(title="Сводка SOC"):
    """HTML-текст сводки. Все числа — из общих с интерфейсом функций."""
    from .overview import build_stats
    from .incidents import build_workflow

    st = build_stats()
    wf = build_workflow()
    counts = wf.get("counts", {})
    items = wf.get("items", [])

    tp = sum(1 for i in items if i.get("verdict") == "tp")
    fp = sum(1 for i in items if i.get("verdict") == "fp")
    reviewed = tp + fp
    open_n = sum(v for k, v in counts.items() if k != "closed")

    L = [f"<b>{_esc(title)}</b>"]
    L.append(f"⏱ аптайм консоли: {_fmt_uptime(st.get('uptime', 0))}")
    L.append("")
    L.append(f"События: <b>{st.get('store_events', 0)}</b> в хранилище · "
             f"обработано защитой <b>{st.get('processed', 0)}</b>")
    L.append(f"Алерты: <b>{st.get('alerts', 0)}</b> · "
             f"инциденты <b>{st.get('incidents', 0)}</b> "
             f"(критических {st.get('critical', 0)}, кампаний "
             f"{st.get('campaigns_detected', 0)})")
    L.append(f"Очередь: открыто <b>{open_n}</b> · закрыто {counts.get('closed', 0)}")
    if reviewed:
        L.append(f"Вердикты: TP <b>{tp}</b> · FP <b>{fp}</b> · "
                 f"точность {round(tp / reviewed * 100)}% (разобрано {reviewed})")
    else:
        L.append("Вердикты: ещё ни один инцидент не разобран")
    L.append(f"ATT&amp;CK: покрытие <b>{st.get('coverage_pct', 0)}%</b> "
             f"({st.get('techniques_covered', 0)} из {st.get('techniques_total', 0)} техник) · "
             f"срабатывало {st.get('techniques_fired', 0)}")
    L.append(f"Правил в движке: {st.get('rules', 0)}")

    # Detection rate / MTTD / FP rate — из последнего снимка метрик, то есть
    # ровно из того, что рисует экран «Тренды». Своего пересчёта здесь нет.
    m = _EXECM.get("data") or {}
    if m:
        L.append("")
        L.append(f"Полнота детектирования: <b>{round((m.get('detection_rate') or 0) * 100, 1)}%</b> · "
                 f"MTTD {m.get('mttd_sim_min', '—')} sim-мин · "
                 f"FP rate {round((m.get('fp_rate') or 0) * 100, 1)}%")
        L.append(f"<i>по снимку метрик от {_esc(_SNAP.get('last') or '—')}</i>")
    elif _SNAP.get("error"):
        L.append("")
        L.append(f"⚠️ пересчёт метрик не удался: {_esc(str(_SNAP['error'])[:150])}")

    noisy = [r for r in wf.get("noisy_rules", []) if r.get("fp")]
    if noisy:
        L.append("")
        L.append("Правила с подтверждёнными FP: " +
                 ", ".join(f"{_esc(r['rule_id'])} ({r['fp']})" for r in noisy[:5]))
    return "\n".join(L)


def send_summary(title="Сводка SOC", kind="soc_report", silent=True):
    """Собрать и отправить сводку. Ошибки не глотаем — они в журнале."""
    try:
        text = soc_summary(title)
    except Exception:
        log.error("не удалось собрать сводку для Telegram — сообщение не "
                  "отправлено", exc_info=True)
        return False
    ok = telegram.send(text, silent=silent, kind=kind)
    log.info("сводка SOC отправлена в Telegram" if ok
             else "сводку SOC отправить не удалось",
             extra={"ctx": {"kind": kind, "ok": ok}})
    return ok


# =======================================================================
#  ОШИБКИ -> TELEGRAM
# =======================================================================
class TelegramErrorHandler(logging.Handler):
    """ERROR и CRITICAL уходят в чат — с агрегацией, а не по строке на ошибку.

    Без агрегации один циклический сбой (например, недоступная база в цикле
    ингеста) отправил бы сотни сообщений за минуту и был бы заглушён самим
    Telegram по лимиту частоты. Здесь: первое сообщение сразу, дальше — не
    чаще раза в WINDOW секунд, с числом подавленных.
    """

    WINDOW = 300

    def __init__(self):
        super().__init__(level=logging.ERROR)
        self._last = 0.0
        self._suppressed = 0
        self._lock = threading.Lock()

    def emit(self, record):
        # Собственные сообщения telegram-модуля сюда не пускаем: иначе отказ
        # отправки породит попытку отправить сообщение об отказе отправки.
        if record.name in ("telegram", "notify"):
            return
        try:
            if not telegram.enabled():
                return
            now = time.time()
            with self._lock:
                if now - self._last < self.WINDOW:
                    self._suppressed += 1
                    return
                extra_n = self._suppressed
                self._suppressed = 0
                self._last = now
            # ТОЛЬКО ТЕКСТ СООБЩЕНИЯ. self.format() у logging.Formatter
            # ДОПИСЫВАЕТ трейсбек к сообщению, и он уходил в чат дважды:
            # один раз внутри обрезанного до 600 символов текста, второй —
            # блоком <pre> ниже. Читать это было невозможно.
            msg = record.getMessage()
            ctx = getattr(record, "ctx", None)
            lines = [f"🔴 <b>{_esc(record.levelname)}</b> · {_esc(record.name)}",
                     _esc(telegram.mask(msg))[:600]]
            if isinstance(ctx, dict) and ctx:
                lines.append("<i>" + _esc(telegram.mask(
                    " ".join(f"{k}={v}" for k, v in list(ctx.items())[:8]))) + "</i>")
            if record.exc_info:
                import traceback
                tb = telegram.mask("".join(traceback.format_exception(*record.exc_info)))
                lines.append("<pre>" + _esc(tb[-700:]) + "</pre>")
            if extra_n:
                lines.append(f"<i>(ранее подавлено ещё {extra_n} ошибок)</i>")
            telegram.send_async("\n".join(lines), kind="error", dedup=True)
        except Exception:
            # Обработчик логов не имеет права падать: иначе logging начнёт
            # печатать собственные трейсбеки поверх настоящих сообщений.
            # Штатный способ сообщить о сбое обработчика — handleError():
            # он уважает logging.raiseExceptions и не молчит в отладке.
            self.handleError(record)


def start_worker():
    """Стартовое уведомление + периодическая сводка. Идемпотентно."""
    if _WORKER["thread"] and _WORKER["thread"].is_alive():
        return _WORKER["thread"]
    if not telegram.enabled():
        log.info("Telegram выключен — уведомления не отправляются",
                 extra={"ctx": {"reason": telegram.state().get("disabled_reason")}})
        return None

    cfg = _cfg()
    if cfg.get("send_start_stop", True):
        ok, who = telegram.ping()
        log.info("Telegram: проверка связи",
                 extra={"ctx": {"ok": ok, "bot": who}})
        telegram.send_async(f"🟢 <b>Консоль защиты запущена</b>\n"
                            f"Интерфейс: http://127.0.0.1:8788",
                            kind="lifecycle", silent=True)

    stop = threading.Event()
    every = max(1, int(cfg.get("report_every_min", 60))) * 60

    def loop():
        while not stop.wait(every):
            try:
                send_summary("Периодическая сводка SOC")
            except Exception:
                log.error("периодическая сводка в Telegram не отправлена",
                          exc_info=True)

    t = threading.Thread(target=loop, daemon=True, name="tg-reporter")
    t.start()
    _WORKER.update(thread=t, stop=stop)

    root = logging.getLogger()
    if not any(isinstance(h, TelegramErrorHandler) for h in root.handlers):
        h = TelegramErrorHandler()
        root.addHandler(h)
        log.info("ошибки уровня ERROR+ будут дублироваться в Telegram",
                 extra={"ctx": {"window_s": TelegramErrorHandler.WINDOW}})
    return t


def stop_worker(reason="остановлена"):
    if _WORKER.get("stop"):
        _WORKER["stop"].set()
    if telegram.enabled() and _cfg().get("send_start_stop", True):
        try:
            telegram.send(f"🔴 <b>Консоль защиты {_esc(reason)}</b>\n"
                          f"аптайм {_fmt_uptime(time.time() - _STARTED)}",
                          kind="lifecycle", silent=True)
        except Exception:
            log.warning("уведомление об остановке не отправлено", exc_info=True)
