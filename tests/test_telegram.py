#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
КАНАЛ TELEGRAM И СОГЛАСОВАННОСТЬ ЧИСЕЛ.

Две вещи, которые ломались молча и потому проверяются здесь:

1. КАНАЛ. Отправка шла одной попыткой без повторов, лимит частоты 429 считался
   обычной ошибкой (сообщение терялось), антифлуд был один на весь модуль
   (алерт аномалии глушил уведомление о старте), а текст исключения от requests
   содержит ПОЛНЫЙ URL с токеном — и уходил в журнал как есть.
   Проверяется на локальном имитаторе Bot API: в сеть тест не ходит.

2. ЧИСЛА. Сводка в чат обязана строиться теми же функциями, что отдают
   /api/stats и /api/workflow. Раньше в Telegram уходил отчёт из процесса
   МИРА (активности планировщика), а на экране была статистика ЗАЩИТЫ —
   два разных набора чисел, которые невозможно сверить.
"""
import os
import sys
import json
import time
import threading
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

FAILED = []


def check(name, cond, detail=""):
    print(("  OK    " if cond else "  ПЛОХО ") + name + (f"  {detail}" if detail else ""))
    if not cond:
        FAILED.append(name)


# ======================================================================
#  ИМИТАТОР BOT API
# ======================================================================
CALLS = []
MODE = {"v": "ok"}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        return

    def _reply(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        CALLS.append(("GET", self.path, None))
        if self.path.endswith("/getMe"):
            return self._reply(200, {"ok": True,
                                     "result": {"id": 1, "username": "soc_test_bot"}})
        self._reply(404, {"ok": False})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        CALLS.append(("POST", self.path, body))
        m = MODE["v"]
        if m == "fail500":
            return self._reply(500, {"ok": False, "description": "Internal"})
        if m == "rate":
            MODE["v"] = "ok"
            return self._reply(429, {"ok": False, "parameters": {"retry_after": 1}})
        if m == "bad_chat":
            return self._reply(400, {"ok": False,
                                     "description": "Bad Request: chat not found"})
        self._reply(200, {"ok": True, "result": {"message_id": len(CALLS)}})


def _posts():
    return [c for c in CALLS if c[0] == "POST"]


def test_channel():
    print("\n-- канал: повторы, лимит частоты, антифлуд, дедупликация --")
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    os.environ["SOC_TELEGRAM_API_BASE"] = f"http://127.0.0.1:{port}"
    os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"

    import config
    # Тестовые значения: настоящий токен для теста не нужен и не используется.
    config.TELEGRAM = dict(config.TELEGRAM or {}, enabled=True,
                           token="123456789:TESTTESTTESTTESTTESTTESTTESTTESTTES",
                           chat_id="42")
    import telegram
    telegram._STATE.update(sent=0, failed=0, suppressed_flood=0,
                           suppressed_dup=0, retries=0)
    telegram._RECENT.clear()
    telegram._LAST_BY_KIND.clear()

    CALLS.clear(); MODE["v"] = "ok"
    check("обычная отправка проходит", telegram.send("привет", kind="t1") is True)
    body = _posts()[0][2]
    check("chat_id проставлен", str(body.get("chat_id")) == "42")
    check("токен идёт в URL, а не в теле", "TESTTEST" not in json.dumps(body))

    CALLS.clear()
    telegram.send("дубль", kind="t2")
    telegram.send("дубль", kind="t2")
    check("одинаковый текст не уходит дважды", len(_posts()) == 1, len(_posts()))

    CALLS.clear()
    telegram.send("a1", kind="anomaly", min_interval=60)
    telegram.send("a2", kind="anomaly", min_interval=60)
    n_anom = len(_posts())
    telegram.send("важное", kind="lifecycle", min_interval=60)
    check("антифлуд действует внутри вида", n_anom == 1, n_anom)
    check("и НЕ глушит другой вид", len(_posts()) == 2, len(_posts()))

    CALLS.clear(); MODE["v"] = "rate"
    t0 = time.time()
    ok429 = telegram.send("после 429", kind="t4")
    dt = time.time() - t0
    check("429: сообщение всё же доставлено", ok429 is True)
    check("429: была вторая попытка", len(_posts()) == 2, len(_posts()))
    check("429: подождали retry_after", dt >= 0.9, f"{dt:.1f}s")

    CALLS.clear(); MODE["v"] = "fail500"
    check("5xx: возвращает False", telegram.send("500", kind="t5") is False)
    check("5xx: ровно три попытки", len(_posts()) == 3, len(_posts()))

    CALLS.clear(); MODE["v"] = "bad_chat"
    check("4xx: возвращает False", telegram.send("плохой чат", kind="t6") is False)
    check("4xx: НЕ повторяет", len(_posts()) == 1, len(_posts()))
    check("4xx: причина сохранена в state()",
          "chat not found" in (telegram.state().get("last_error") or ""))

    MODE["v"] = "ok"
    st = telegram.state()
    check("в state() токена нет", "TESTTEST" not in json.dumps(st, ensure_ascii=False))
    ok, who = telegram.ping()
    check("ping отвечает", ok and "soc_test_bot" in who, who)
    srv.shutdown()


def test_token_never_logged():
    print("\n-- токен не попадает в журнал --")
    import telegram
    import soclog
    leak = ("HTTPSConnectionPool(host='api.telegram.org', port=443): Max retries "
            "exceeded with url: /bot8717621147:AAGd2snyzC4TOfTDCXgyKXx8MimMA_nsmzM"
            "/sendMessage (Caused by ProxyError(...))")
    check("telegram.mask убирает токен из текста исключения",
          "AAGd2sny" not in telegram.mask(leak))
    check("soclog.mask убирает токен", "AAGd2sny" not in soclog.mask(leak))
    check("soclog.mask убирает PAT GitLab",
          "glpat-" not in soclog.mask("token glpat-abcdefghijklmnop here"))
    check("ключи вида *token* в контексте маскируются",
          "<SECRET>" in soclog._fmt_ctx({"api_token": "abcdef123456"}))


def test_stats_single_source():
    print("\n-- числа сводки == числа /api/stats и /api/workflow --")
    import eventstore
    import console_app
    from console_app import notify
    from console_app.overview import build_stats
    from console_app.incidents import build_workflow

    app = console_app.create_app(start_workers=False)
    c = app.test_client()
    with c.session_transaction() as s:
        s["user"] = "admin"

    api_stats = json.loads(c.get("/api/stats").data)
    api_wf = json.loads(c.get("/api/workflow").data)
    direct = build_stats()
    for k in ("store_events", "processed", "alerts", "incidents", "critical",
              "campaigns_detected", "rules", "coverage_pct", "techniques_fired",
              "techniques_covered", "techniques_total"):
        check(f"обработчик и источник совпадают: {k}",
              direct.get(k) == api_stats.get(k),
              f"{direct.get(k)} vs {api_stats.get(k)}")
    check("workflow: счётчики совпадают",
          build_workflow()["counts"] == api_wf["counts"])

    text = notify.soc_summary("Проверка")
    import re
    def num(rx):
        m = re.search(rx, text)
        return int(m.group(1)) if m else None
    check("в сводке те же события", num(r"События: <b>(\d+)</b>") == api_stats["store_events"])
    check("в сводке те же алерты", num(r"Алерты: <b>(\d+)</b>") == api_stats["alerts"])
    check("в сводке те же инциденты", num(r"инциденты <b>(\d+)</b>") == api_stats["incidents"])
    check("в сводке то же покрытие", num(r"покрытие <b>(\d+)%</b>") == api_stats["coverage_pct"])
    check("в сводке те же техники", num(r"срабатывало (\d+)") == api_stats["techniques_fired"])
    check("в сводке то же число правил", num(r"Правил в движке: (\d+)") == api_stats["rules"])
    tp = sum(1 for i in api_wf["items"] if i.get("verdict") == "tp")
    fp = sum(1 for i in api_wf["items"] if i.get("verdict") == "fp")
    if tp or fp:
        tg_tp = num(r"TP <b>(\d+)</b>")
        tg_fp = num(r"FP <b>(\d+)</b>")
        check("в сводке те же TP", tg_tp == tp, f"{tg_tp} vs {tp}")
        check("в сводке те же FP", tg_fp == fp, f"{tg_fp} vs {fp}")


def main():
    logging.disable(logging.INFO)
    print("=" * 70)
    print("  TELEGRAM: КАНАЛ И СОГЛАСОВАННОСТЬ СТАТИСТИКИ")
    print("=" * 70)
    test_channel()
    test_token_never_logged()
    test_stats_single_source()
    print("-" * 70)
    if FAILED:
        print(f"  ПРОВАЛЕНО: {len(FAILED)} -> {FAILED[:5]}")
        return 1
    print("  Канал Telegram надёжен, числа в чате берутся из общего источника.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
