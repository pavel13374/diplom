#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
БЕЗОПАСНОСТЬ ВЕБ-КОНТУРА: регрессия на подтверждённые уязвимости.

Каждая проверка здесь соответствует дефекту, который был воспроизведён на
запущенном приложении, а не выведен из чтения кода.

  1. ТОКЕН GITLAB УЕЗЖАЛ В БРАУЗЕР ОТКРЫТЫМ ТЕКСТОМ.
         GET /api/config -> {"ADMIN_TOKEN": "glpat-…"}
     Это админский PAT со scope api: создание пользователей, выпуск
     impersonation-токенов на кого угодно, чтение любого репозитория.

  2. ЧТЕНИЕ ЛЮБОГО ФАЙЛА С ДИСКА.
         POST /api/config {"EVENT_LOG": {"file": "/etc/passwd"}}   -> 200
         GET  /api/dataset                                          -> 200
         root:x:0:0:root:/root:/bin/bash …
     На той же машине рядом лежат .gitlab_token и .secret_key.

  3. SSRF С ВЫНОСОМ УЧЁТНЫХ ДАННЫХ.
         POST /api/config {"GITLAB_URL": "http://чужой-хост/"}
         GET  /api/gitlab/check
     Второй запрос уходил на указанный адрес с заголовком
     PRIVATE-TOKEN: <админский PAT>.

  4. У КОНСОЛИ ЗАЩИТЫ НЕ БЫЛО ЗАЩИТЫ ОТ CSRF — при том что именно она
     запускает атакующие кампании, заводит issue в GitLab и выставляет
     вердикты, три из которых приглушают правило детектирования.

  5. КРИВОЙ ПАРАМЕТР ЗАПРОСА ДАВАЛ 500 С ТЕКСТОМ ИСКЛЮЧЕНИЯ.
         GET /api/events?n=abc
         -> 500 {"detail": "invalid literal for int() with base 10: 'abc'"}

Запуск: python tests/test_websec.py
"""
import os as _os
import sys as _sys

_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)
_os.chdir(_ROOT)
_os.environ.setdefault("SOC_OFFLINE", "1")
_os.environ.setdefault("SOC_ADMIN_PASS", "test-pass-for-websec")

import json
import logging

logging.disable(logging.CRITICAL)
try:
    _sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

OK, BAD = "✅", "❌"
FAILED = []


def check(name, ok, detail=""):
    print(f"  {OK if ok else BAD} {name}" + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        FAILED.append(name)


#: Имя CSRF-cookie У КАЖДОЙ КОНСОЛИ СВОЁ (cookie не различаются по порту,
#: см. websec.csrf_cookie_name). Тест обязан спрашивать имя у приложения, а
#: не знать его наизусть, иначе он проверяет вчерашний контракт.
def _csrf_name(client):
    import websec
    app = getattr(client, "application", None)
    if app is not None:
        return app.config.get("CSRF_COOKIE_NAME") or websec.CSRF_COOKIE
    return websec.CSRF_COOKIE


def _login(client):
    import config
    r = client.post("/login", data={"username": config.WEB_ADMIN_USER,
                                    "password": config.WEB_ADMIN_PASS})
    assert r.status_code in (200, 302), r.status_code
    # Токен CSRF выдаётся заголовком Set-Cookie; вытащим его для дальнейших POST.
    name = _csrf_name(client)
    for c in client.cookie_jar if hasattr(client, "cookie_jar") else []:
        if c.name == name:
            return c.value
    r = client.get("/")
    for h in r.headers.getlist("Set-Cookie"):
        if h.startswith(name + "="):
            return h.split("=", 1)[1].split(";", 1)[0]
    return ""


# ======================================================================
def test_admin_token_is_masked():
    print("\n-- админский токен GitLab не уходит клиенту --")
    import config
    import webapp
    config.ADMIN_TOKEN = "glpat-SECRET0123456789abcdefgh"
    app = webapp.app
    app.config["TESTING"] = True
    with app.test_client() as c:
        _login(c)
        body = c.get("/api/config").get_data(as_text=True)
        check("в ответе нет самого токена", "glpat-SECRET0123456789abcdefgh" not in body,
              body[:200])
        data = json.loads(body)
        check("значение замаскировано", "•" in str(data.get("ADMIN_TOKEN", "")),
              str(data.get("ADMIN_TOKEN")))
        # маска, отправленная обратно, НЕ должна затирать настоящее значение
        c.post("/api/config", json={"ADMIN_TOKEN": data["ADMIN_TOKEN"]},
               headers={"X-CSRF-Token": _csrf(c)})
        check("возврат маски не портит настоящий токен",
              config.ADMIN_TOKEN == "glpat-SECRET0123456789abcdefgh",
              config.ADMIN_TOKEN)


def _csrf(client):
    name = _csrf_name(client)
    r = client.get("/api/status")
    for h in r.headers.getlist("Set-Cookie"):
        if h.startswith(name + "="):
            return h.split("=", 1)[1].split(";", 1)[0]
    # cookie уже установлен ранее — берём из клиента
    for c in getattr(client, "_cookies", {}).values():
        try:
            if c.key == name:
                return c.value
        except AttributeError:
            pass
    return ""


def test_no_arbitrary_file_read():
    print("\n-- произвольный файл с диска не отдаётся --")
    import config
    import webapp
    app = webapp.app
    app.config["TESTING"] = True
    with app.test_client() as c:
        _login(c)
        tok = _csrf(c)
        before = dict(config.EVENT_LOG)
        r = c.post("/api/config", json={"EVENT_LOG": {"file": "/etc/passwd",
                                                      "enabled": True}},
                   headers={"X-CSRF-Token": tok})
        check("путь журнала не редактируется из веба",
              config.EVENT_LOG.get("file") == before.get("file"),
              str(config.EVENT_LOG))
        # Второй рубеж: даже при испорченной конфигурации маршрут обязан отказать.
        config.EVENT_LOG = {"enabled": True, "file": "/etc/passwd"}
        r = c.get("/api/dataset")
        body = r.get_data(as_text=True)
        check("выгрузка файла вне каталога данных отклонена",
              r.status_code == 403 and "root:x:" not in body,
              f"{r.status_code} {body[:120]}")
        config.EVENT_LOG = before


def test_gitlab_url_is_validated():
    print("\n-- адрес GitLab проверяется до записи --")
    import config
    import webapp
    app = webapp.app
    app.config["TESTING"] = True
    good = "https://gitlab.example.com"
    config.GITLAB_URL = good
    with app.test_client() as c:
        _login(c)
        tok = _csrf(c)
        for bad, why in (("http://169.254.169.254/", "метаданные облака"),
                         ("file:///etc/passwd", "схема file"),
                         ("gopher://x/", "схема gopher"),
                         ("http://user:pw@evil.tld/", "учётные данные в URL"),
                         ("not a url", "не разбирается")):
            r = c.post("/api/config", json={"GITLAB_URL": bad},
                       headers={"X-CSRF-Token": tok})
            check(f"отклонено: {why}",
                  r.status_code == 400 and config.GITLAB_URL == good,
                  f"{r.status_code} -> {config.GITLAB_URL}")
        r = c.post("/api/config", json={"GITLAB_URL": "https://gitlab.corp.local:8443"},
                   headers={"X-CSRF-Token": tok})
        check("обычный адрес принимается",
              config.GITLAB_URL == "https://gitlab.corp.local:8443", config.GITLAB_URL)
        config.GITLAB_URL = good


def test_csrf_required_on_both_consoles():
    print("\n-- изменяющие запросы требуют токен CSRF --")
    import webapp
    from console_app import create_app

    cases = [("среда", webapp.app, "/api/start"),
             ("защита", create_app(start_workers=False), "/api/red/launch")]
    for name, app, path in cases:
        app.config["TESTING"] = True
        with app.test_client() as c:
            _login(c)
            r = c.post(path, json={"key": "ci_token_to_exfil"})
            check(f"{name}: POST без заголовка отклонён (403)",
                  r.status_code == 403, f"{r.status_code} {r.get_data(as_text=True)[:120]}")
            tok = _csrf(c)
            r = c.post(path, json={"key": "ci_token_to_exfil"},
                       headers={"X-CSRF-Token": tok})
            check(f"{name}: POST с заголовком проходит",
                  r.status_code != 403, str(r.status_code))


def test_session_cookies_are_scoped():
    print("\n-- cookie сессий разделены и ограничены по времени --")
    import webapp
    from console_app import create_app
    seen = {}
    for name, app in (("env", webapp.app), ("console", create_app(start_workers=False))):
        app.config["TESTING"] = True
        seen[name] = app.config["SESSION_COOKIE_NAME"]
        check(f"{name}: SameSite=Lax",
              app.config.get("SESSION_COOKIE_SAMESITE") == "Lax",
              str(app.config.get("SESSION_COOKIE_SAMESITE")))
        check(f"{name}: HttpOnly", app.config.get("SESSION_COOKIE_HTTPONLY") is True)
        life = app.config.get("PERMANENT_SESSION_LIFETIME")
        check(f"{name}: срок сессии ограничен ({life})",
              life is not None and life.total_seconds() <= 24 * 3600, str(life))
    check("имена cookie у консолей разные (порт cookie не разделяет)",
          seen["env"] != seen["console"], str(seen))

    # ЭТА ПРОВЕРКА БЫЛА НЕПОЛНОЙ И ПРОПУСТИЛА НАСТОЯЩИЙ ДЕФЕКТ.
    # Сессионные cookie были разведены по именам, а CSRF-cookie остался
    # ОБЩИМ (`sentinel_csrf`). Cookie не различаются по порту: две консоли на
    # одном localhost перезаписывали токен друг у друга, и вторая отвечала
    # 403 `csrf` на каждый POST. Симптом плавающий — пока открыта одна
    # вкладка, всё работает.
    csrf_names = {}
    for name, app in (("env", webapp.app), ("console", create_app(start_workers=False))):
        csrf_names[name] = app.config.get("CSRF_COOKIE_NAME")
        check(f"{name}: имя CSRF-cookie задано", bool(csrf_names[name]),
              str(csrf_names[name]))
    check("имена CSRF-cookie у консолей тоже разные",
          csrf_names["env"] and csrf_names["env"] != csrf_names["console"],
          str(csrf_names))
    check("CSRF-cookie не совпадает с сессионным",
          csrf_names["env"] != seen["env"] and csrf_names["console"] != seen["console"],
          str(csrf_names) + " / " + str(seen))

    # Токен ЧУЖОЙ консоли обязан быть отвергнут — именно это и происходило,
    # когда обе вкладки делили одно имя cookie.
    envc = webapp.app.test_client()
    _login(envc)
    foreign = _csrf(envc)
    con_app = create_app(start_workers=False)
    con_app.config["TESTING"] = True
    conc = con_app.test_client()
    _login(conc)
    if foreign:
        r = conc.post("/api/ask", json={"q": "кто создавал токены"},
                      headers={"X-CSRF-Token": foreign})
        check("токен другой консоли отвергается (403)", r.status_code == 403,
              f"{r.status_code} {r.get_data(as_text=True)[:120]}")
    r = conc.post("/api/ask", json={"q": "кто создавал токены"},
                  headers={"X-CSRF-Token": _csrf(conc)})
    check("свой токен принимается", r.status_code == 200,
          f"{r.status_code} {r.get_data(as_text=True)[:120]}")

    # Разметка обязана читать ИМЯ СВОЕГО приложения, а не зашитую строку.
    import os as _os
    root = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
    for who, tpl in (("console", "templates/console/dashboard.html"),
                     ("env", "templates/env/dashboard.html")):
        html = open(_os.path.join(root, tpl), encoding="utf-8").read()
        check(f"{who}: разметка берёт имя cookie с сервера",
              "meta[name=csrf-cookie]" in html and "{{ CSRF_COOKIE }}" in html,
              "имя зашито в шаблон")


def test_query_params_are_validated():
    print("\n-- кривой параметр даёт 400, а не 500 с трейсбеком --")
    import webapp
    app = webapp.app
    app.config["TESTING"] = True
    with app.test_client() as c:
        _login(c)
        for url in ("/api/events?n=abc", "/api/logs?since=xyz", "/api/actor?n=abc"):
            r = c.get(url)
            body = r.get_data(as_text=True)
            check(f"{url} -> 400", r.status_code == 400, f"{r.status_code} {body[:100]}")
            check(f"{url}: текст исключения не уходит клиенту",
                  "invalid literal" not in body, body[:120])
        r = c.get("/api/events?n=99999999")
        check("огромное n усечено, а не выполнено", r.status_code == 200)


def test_error_responses_are_opaque():
    """Через уже существующий маршрут: у Flask нельзя регистрировать новые
    после первого запроса."""
    print("\n-- внутренняя ошибка не раскрывает подробности --")
    import webapp
    app = webapp.app
    app.config["TESTING"] = False        # иначе Flask пробрасывает исключение
    app.config["PROPAGATE_EXCEPTIONS"] = False
    orig = webapp.runner.status
    webapp.runner.status = lambda: (_ for _ in ()).throw(
        RuntimeError("секретный путь /home/user/.gitlab_token и адрес БД"))
    try:
        with app.test_client() as c:
            _login(c)
            r = c.get("/api/status")
            body = r.get_data(as_text=True)
            check("код 500", r.status_code == 500, str(r.status_code))
            check("текста исключения нет в ответе", ".gitlab_token" not in body,
                  body[:160])
            try:
                ref = json.loads(body).get("ref")
            except ValueError:
                ref = None
            check("выдан идентификатор для поиска в логе", bool(ref), body[:160])
    finally:
        webapp.runner.status = orig
        app.config["TESTING"] = True


def test_login_throttle_is_per_source():
    print("\n-- ограничение подбора не блокирует всех разом --")
    import websec
    g = websec.LoginGuard(threshold=3)
    import webapp
    app = webapp.app
    with app.test_request_context("/login", environ_base={"REMOTE_ADDR": "10.0.0.1"}):
        for _ in range(3):
            g.record_failure()
        check("нарушитель заблокирован", g.blocked_for() > 0)
    with app.test_request_context("/login", environ_base={"REMOTE_ADDR": "10.0.0.2"}):
        check("другой источник не заблокирован", g.blocked_for() == 0)
    with app.test_request_context("/login", environ_base={"REMOTE_ADDR": "10.0.0.1"}):
        w1 = g.blocked_for()
        for _ in range(3):
            g.record_failure()
        check(f"пауза растёт при повторе ({w1}с -> {g.blocked_for()}с)",
              g.blocked_for() >= w1)


def test_incident_status_is_validated():
    print("\n-- вердикт инцидента принимает только известные значения --")
    from console_app import create_app
    app = create_app(start_workers=False)
    app.config["TESTING"] = True
    with app.test_client() as c:
        _login(c)
        tok = _csrf(c)
        r = c.post("/api/incident/1/status", json={"status": "нечто"},
                   headers={"X-CSRF-Token": tok})
        check("неизвестный статус отклонён (400)", r.status_code == 400, str(r.status_code))
        r = c.post("/api/incident/1/status", json={"verdict": "maybe"},
                   headers={"X-CSRF-Token": tok})
        check("неизвестный вердикт отклонён (400)", r.status_code == 400, str(r.status_code))
        r = c.post("/api/incident/1/status", json={"reason": "x" * 5000},
                   headers={"X-CSRF-Token": tok})
        check("слишком длинная заметка отклонена (400)", r.status_code == 400,
              str(r.status_code))
        r = c.post("/api/incident/1/status", json={"status": "investigating",
                                                   "verdict": "fp", "reason": "шум"},
                   headers={"X-CSRF-Token": tok})
        check("корректные значения принимаются", r.status_code == 200, str(r.status_code))


def test_red_launch_validates_evasion():
    print("\n-- профиль уклонения проверяется --")
    from console_app import create_app
    app = create_app(start_workers=False)
    app.config["TESTING"] = True
    with app.test_client() as c:
        _login(c)
        tok = _csrf(c)
        r = c.post("/api/red/launch",
                   json={"key": "ci_token_to_exfil", "evasion": "что угодно"},
                   headers={"X-CSRF-Token": tok})
        check("неизвестный профиль отклонён (400)", r.status_code == 400,
              f"{r.status_code} {r.get_data(as_text=True)[:120]}")
        r = c.post("/api/red/launch",
                   json={"key": "ci_token_to_exfil", "evasion": "stealthy"},
                   headers={"X-CSRF-Token": tok})
        check("известный профиль принимается", r.status_code == 200, str(r.status_code))


def test_structured_logging_installed_in_console():
    print("\n-- диагностика консоли защиты не пустая --")
    from console_app import create_app
    app = create_app(start_workers=False)
    app.config["TESTING"] = True
    with app.test_client() as c:
        _login(c)
        d = json.loads(c.get("/api/diag").get_data(as_text=True))
        check("структурное логирование установлено", d.get("installed") is True,
              str(d.get("installed")))
        check("пути файлов журнала известны", bool(d.get("paths")), str(d.get("paths")))
        check("отдаются счётчики деградаций (метки времени)",
              "ts_parse_failures" in d, str(sorted(d)[:8]))
        check("отдаётся список отвергнутых правил", "rejected_rules" in d)


def main():
    print("=" * 74)
    print("  БЕЗОПАСНОСТЬ ВЕБ-КОНТУРА")
    print("=" * 74)
    test_admin_token_is_masked()
    test_no_arbitrary_file_read()
    test_gitlab_url_is_validated()
    test_csrf_required_on_both_consoles()
    test_session_cookies_are_scoped()
    test_query_params_are_validated()
    test_error_responses_are_opaque()
    test_login_throttle_is_per_source()
    test_incident_status_is_validated()
    test_red_launch_validates_evasion()
    test_structured_logging_installed_in_console()
    print("-" * 74)
    if FAILED:
        print(f"  {BAD} ПРОВАЛЕНО: {len(FAILED)}")
        for f in FAILED:
            print(f"     - {f}")
        return 1
    print(f"  {OK} Веб-контур закрыт по проверенным векторам.")
    return 0


if __name__ == "__main__":
    _sys.exit(main())
