#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
СМОУК-ТЕСТ ОБЕИХ КОНСОЛЕЙ: маршруты, API, контроль доступа, целостность разметки.

Зачем. У консолей 55 маршрутов и ни одного теста: раньше единственным способом
узнать, что страница отдаёт 500, было открыть её руками. При этом консоли —
самая крупная часть проекта (console.py + webapp.py + шаблоны), и именно её
показывают на защите.

Тест поднимает обе консоли в тестовом клиенте Flask (без сети и без реального
GitLab) и проверяет:

  1. КОНТРОЛЬ ДОСТУПА — каждый маршрут без сессии либо ведёт на логин, либо
     отдаёт 401. Ни один не должен молча пускать: раньше консоль защиты была
     открыта полностью, включая запуск атакующих кампаний.
  2. ДОСТУПНОСТЬ — после входа каждый GET-маршрут отдаёт 200, а не 500.
  3. ВАЛИДНОСТЬ JSON — каждый /api/* отдаёт разбираемый JSON.
  4. ЦЕЛОСТНОСТЬ РАЗМЕТКИ — все файлы, на которые ссылаются страницы
     (css/js/svg), существуют; нет ссылок на несуществующие маршруты.
  5. ЗАГОЛОВКИ БЕЗОПАСНОСТИ на месте.

Запуск: python tests/test_routes.py
"""

# --- скрипт живёт в подпапке; движок проекта — в корне ---
import os as _os, sys as _sys
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
for _p in (_ROOT, _os.path.join(_ROOT, "tools"), _os.path.join(_ROOT, "research")):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
_os.chdir(_ROOT)
_os.environ.setdefault("SOC_OFFLINE", "1")
_os.environ.setdefault("SOC_ADMIN_PASS", "test-pass-for-routes")
del _os, _sys

import os
import re
import sys
import json
import logging

logging.disable(logging.CRITICAL)
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

OK = "✅"; BAD = "❌"
fails = []

#: Маршруты, которые обязаны быть доступны без входа.
PUBLIC = {"/login", "/logout", "/healthz", "/static/<path:filename>"}

#: Маршруты, которые меняют состояние мира или файлов — в смоуке не дёргаем,
#: проверяем только что они закрыты от анонима.
SKIP_GET = {"/logout"}


def check(name, cond, detail=""):
    print(f"  {OK if cond else BAD} {name}")
    if not cond:
        fails.append(name)
        if detail:
            for line in str(detail).splitlines()[:6]:
                print(f"      {line}")


def _routes(app):
    """Все маршруты приложения: (правило, методы)."""
    out = []
    for r in app.url_map.iter_rules():
        if r.endpoint == "static":
            continue
        out.append((str(r.rule), set(r.methods) - {"HEAD", "OPTIONS"}))
    return sorted(out)


def _concrete(rule):
    """Подставить правдоподобные значения вместо <параметров>."""
    if "<" not in rule:
        return rule
    s = re.sub(r"<int:[^>]+>", "1", rule)
    s = re.sub(r"<path:[^>]+>", "design-system.css", s)
    s = re.sub(r"<[^>]+>", "maria.ivanova", s)
    return s


def probe(module_name, title):
    print()
    print("=" * 72)
    print(f"  {title}")
    print("=" * 72)

    mod = __import__(module_name)
    app = mod.app
    app.config["TESTING"] = True
    routes = _routes(app)
    gets = [(r, m) for r, m in routes if "GET" in m]
    posts = [(r, m) for r, m in routes if "POST" in m]
    print(f"  маршрутов: {len(routes)}  (GET {len(gets)} / POST {len(posts)})")
    print("-" * 72)

    # --- 1. контроль доступа ---
    leaky = []
    with app.test_client() as c:
        for rule, methods in routes:
            if rule in PUBLIC:
                continue
            url = _concrete(rule)
            m = "GET" if "GET" in methods else "POST"
            resp = c.open(url, method=m, json={} if m == "POST" else None)
            # без сессии допустимы: редирект на логин (302) или 401
            if resp.status_code not in (301, 302, 401, 403):
                leaky.append(f"{m} {url} -> {resp.status_code}")
    check("без входа ни один маршрут не отдаёт содержимое", not leaky,
          "\n".join(leaky))

    # --- вход ---
    import config
    with app.test_client() as c:
        r = c.post("/login", data={"username": config.WEB_ADMIN_USER,
                                   "password": config.WEB_ADMIN_PASS})
        check("вход по паролю работает", r.status_code in (200, 302),
              f"POST /login -> {r.status_code}")

        # --- 2. GET-маршруты отдают 200 ---
        broken, api_bad, degraded = [], [], []
        html_pages = []
        for rule, methods in gets:
            if rule in SKIP_GET or rule in ("/static/<path:filename>",):
                continue
            url = _concrete(rule)
            resp = c.get(url)
            if resp.status_code >= 500:
                # 503 + ВНЯТНАЯ ПРИЧИНА — это не поломка, а корректный отказ
                # необязательной возможности.
                #
                # `/api/report/full.pdf` без установленного reportlab отдаёт
                # 503 с текстом «выполни pip install reportlab». Считать это
                # провалом неверно: маршрут делает ровно то, что должен, а
                # альтернатива — притвориться, что всё хорошо, и отдать
                # пустой файл. Провалом остаётся любой 5xx БЕЗ объяснения и
                # любой 500.
                body = resp.get_data(as_text=True)
                explained = (resp.status_code == 503
                             and any(w in body.lower()
                                     for w in ("install", "не установл",
                                               "недоступ", "unavailable")))
                if explained:
                    degraded.append(f"GET {url} -> 503: "
                                    + body.strip()[:110].replace("\n", " "))
                else:
                    broken.append(f"GET {url} -> {resp.status_code}")
                continue
            if resp.status_code != 200:
                # 404 на несуществующий id — нормально, 4xx кроме 401 допустим
                if resp.status_code == 401:
                    broken.append(f"GET {url} -> 401 (после входа)")
                continue
            ctype = resp.headers.get("Content-Type", "")
            if not any(t in ctype for t in ("json", "text", "html", "xml", "csv")):
                # бинарный ответ (PDF-отчёт, выгрузка) — достаточно кода 200
                continue
            body = resp.get_data(as_text=True)
            # Не всякий /api/* — JSON: часть маршрутов отдаёт выгрузку
            # (например /api/trends.csv). Ориентируемся на Content-Type,
            # а не на префикс пути.
            if "json" in ctype:
                try:
                    json.loads(body)
                except Exception as e:
                    api_bad.append(f"GET {url}: {e}")
            elif rule.startswith("/api/") and not any(
                    t in ctype for t in ("csv", "svg", "pdf")):
                # csv/svg/pdf под /api/ — это выгрузки и графики
                # (/api/trends.csv, /api/workload_curve.svg, /api/*/report.pdf).
                # Проверять их на JSON бессмысленно, важно лишь что не 5xx.
                api_bad.append(f"GET {url}: неожиданный Content-Type {ctype!r}")
            elif "<html" in body.lower() or "<!doctype" in body.lower():
                html_pages.append((url, body))

        check("ни один GET-маршрут не падает с 5xx", not broken, "\n".join(broken))
        if degraded:
            # Не провал, но и не молчание: возможность выключена, и это должно
            # быть видно в выводе, а не «просто зелено».
            print(f"      ⚠️  недоступных необязательных возможностей: {len(degraded)}")
            for d in degraded:
                print(f"         {d}")
        check("каждый /api/* отдаёт валидный JSON", not api_bad, "\n".join(api_bad))
        check("html-страницы отдаются", len(html_pages) >= 1,
              f"страниц получено: {len(html_pages)}")

        # --- 3. заголовки безопасности ---
        h = c.get("/login").headers
        need = ["X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy"]
        absent = [x for x in need if x not in h]
        check("заголовки безопасности выставлены", not absent, "нет: " + ", ".join(absent))

        # --- 4. целостность ссылок на статику ---
        #
        # Проверяется ДВА разных утверждения, и путать их нельзя:
        #   а) файл лежит на диске;
        #   б) приложение отдаёт его по HTTP.
        #
        # Раньше было только (а), и этого оказалось мало. Flask выводит папку
        # статики из __name__, поэтому после переезда сборки приложения в пакет
        # console_app она стала искаться в console_app/static — файлы на диске
        # были на месте, тест был зелёным, а консоль отдавала 404 на КАЖДЫЙ
        # файл: страница логина рендерилась голым HTML без стилей и логотипа.
        missing_static, unknown_links, not_served = [], [], []
        known = {str(r.rule) for r in app.url_map.iter_rules()}
        for url, body in html_pages:
            for src in set(re.findall(r'(?:href|src)=["\']?(/[^"\'>\s]+)', body)):
                if src.startswith("/static/"):
                    p = os.path.join(*src.strip("/").split("/"))
                    if not os.path.isfile(p):
                        missing_static.append(f"{url}: нет файла {src}")
                    elif c.get(src).status_code != 200:
                        not_served.append(f"{src}: {c.get(src).status_code}")
                elif src.startswith("/api/"):
                    continue
                else:
                    # отбрасываем и параметры, и якорь: «/#red» — это корень
                    # плюс переход к разделу на той же странице
                    base = src.split("?")[0].split("#")[0].rstrip("/") or "/"
                    if base not in known and not any(
                            re.fullmatch(k.replace("<int:iid>", r"\d+")
                                          .replace("<actor>", r"[^/]+"), base)
                            for k in known):
                        unknown_links.append(f"{url}: ссылка на {src}")
        check("все файлы статики, на которые ссылается разметка, существуют",
              not missing_static, "\n".join(missing_static))
        check("статика реально отдаётся по HTTP, а не только лежит на диске",
              not not_served, "\n".join(sorted(set(not_served))[:8]))
        check("нет ссылок на несуществующие маршруты", not unknown_links,
              "\n".join(unknown_links))

    return len(routes)


def probe_ask():
    """Панель «Запрос к данным»: обещания интерфейса и умения разборщика.

    Здесь уже была тихая деградация: интерфейс предлагал шесть готовых
    вопросов-кнопок, а разборщик понимал три. Из оставшихся двух возвращали
    ВЕСЬ ЖУРНАЛ (пустой фильтр читался как «условий нет»), а один —
    гарантированный ноль, потому что русское «удал» сравнивалось с английским
    `file_delete`. Ошибочный ответ выглядел как настоящий.

    Тест связывает обещание с умением: каждая кнопка обязана дать хотя бы одно
    условие отбора, а неразобранный вопрос обязан получить отказ.
    """
    print()
    print("-" * 72)
    print("  ПАНЕЛЬ «ЗАПРОС К ДАННЫМ»")
    print("-" * 72)
    from console_app import overview

    tpl = os.path.join(_ROOT, "templates", "console", "dashboard.html")
    with open(tpl, encoding="utf-8") as f:
        src = f.read()
    m = re.search(r"const ASK_PROMPTS=\[(.*?)\];", src, re.S)
    check("список подсказок найден в разметке", bool(m))
    prompts = re.findall(r"'([^']+)'", m.group(1)) if m else []
    check("подсказок не меньше пяти", len(prompts) >= 5, f"нашлось {len(prompts)}")

    dumb = [q for q in prompts if not overview._ask_filter(q)]
    check("каждая предложенная кнопка даёт условие отбора", not dumb,
          "без условий: " + "; ".join(dumb))

    # Действие сопоставляется со ЗНАЧЕНИЯМИ из taxonomy, а не с подстрокой.
    import taxonomy
    bad_actions = []
    for q in prompts + ["кто удалял ветки", "какие вебхуки создавали", "кто менял права"]:
        for a in (overview._ask_filter(q).get("actions") or []):
            if a not in taxonomy.ALL:
                bad_actions.append(f"{q}: {a}")
    check("действия в фильтре есть в словаре taxonomy", not bad_actions,
          "; ".join(bad_actions))

    refused = ["привет", "как дела", "спасибо", "ааа"]
    still = [q for q in refused if overview._ask_filter(q)]
    check("вопрос не по делу получает отказ, а не весь журнал", not still,
          "разобрано как запрос: " + "; ".join(still))


def main():
    print("=" * 72)
    print("  СМОУК-ТЕСТ КОНСОЛЕЙ")
    print("=" * 72)
    total = 0
    total += probe("console", "КОНСОЛЬ ЗАЩИТЫ (console.py, :8788)")
    total += probe("webapp", "КОНСОЛЬ СРЕДЫ (webapp.py, :8787)")
    probe_ask()

    print()
    print("-" * 72)
    if fails:
        print(f"  {BAD} ПРОВАЛЕНО: {len(fails)}")
        return 1
    print(f"  {OK} Обе консоли отвечают, {total} маршрутов проверено, "
          f"доступ закрыт по умолчанию.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
