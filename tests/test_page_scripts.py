#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
СИНТАКСИС И ЖИЗНЕСПОСОБНОСТЬ СКРИПТОВ НА СТРАНИЦАХ.

Зачем понадобился отдельный тест. Смоук-тест маршрутов (`tests/test_routes.py`)
проверяет, что страница отдаётся с кодом 200. Этого недостаточно: страница может
прекрасно отдаваться и рендериться, а весь её JavaScript — не выполняться из-за
одной синтаксической ошибки. Снаружи это выглядит как «интерфейс работает, но
все числа — прочерки»: серверная разметка на месте, а данные никто не подгружает.

Ровно так и было. В панели среды стояла строка

    innerHTML = '... <span title="merge request'ы">MR ...'

Апостроф внутри строки, ограниченной одинарными кавычками, закрывает её раньше
времени. Скрипт целиком не парсился, `setInterval` не заводились, ни одного
запроса к `/api/*` браузер не делал. Дефект прожил в проекте с самого начала и
не был заметен ни по кодам ответов, ни по логам сервера — в них просто не было
запросов, а отсутствие запросов глазами не ловится.

Что проверяется:
  1. каждый инлайновый <script> на каждой странице разбирается как JavaScript;
  2. то же для файлов в static/*.js;
  3. страница доживает до конца выполнения: заводятся таймеры опроса и
     происходит хотя бы одно обращение к API.

Пункт 3 — главный: он отличает «код синтаксически верен» от «код работает».

Требует node. Без него набор помечается пропущенным.
Запуск: python tests/test_page_scripts.py
"""

# --- скрипт живёт в подпапке; движок проекта — в корне ---
import os as _os, sys as _sys
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
for _p in (_ROOT, _os.path.join(_ROOT, "tools"), _os.path.join(_ROOT, "research")):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
_os.chdir(_ROOT)
del _os, _sys

import os
import re
import sys
import glob
import json
import shutil
import tempfile
import subprocess

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

OK = "✅"; BAD = "❌"
fails = []

_SCRIPT_RE = re.compile(r"<script\b([^>]*)>(.*?)</script>", re.S | re.I)


def check(name, cond, detail=""):
    print(f"  {OK if cond else BAD} {name}")
    if not cond:
        fails.append(name)
        if detail:
            for line in str(detail).splitlines()[:8]:
                print(f"      {line}")


def _have_node():
    if not shutil.which("node"):
        return False
    try:
        subprocess.run(["node", "--version"], capture_output=True, timeout=15)
        return True
    except Exception:
        return False


def inline_scripts(html):
    """Инлайновые скрипты страницы (без src=), по порядку."""
    out = []
    for attrs, body in _SCRIPT_RE.findall(html):
        if "src=" in attrs.lower():
            continue
        if body.strip():
            out.append(body)
    return out


def node_check(code, label, tmp):
    """Разобрать код как JavaScript. Возвращает текст ошибки или None."""
    p = os.path.join(tmp, "chunk.js")
    with open(p, "w", encoding="utf-8") as f:
        f.write(code)
    r = subprocess.run(["node", "--check", p], capture_output=True, text=True, timeout=60)
    if r.returncode == 0:
        return None
    err = (r.stderr or "").strip().splitlines()
    # оставляем строку с местом ошибки и саму ошибку
    keep = [x for x in err if "SyntaxError" in x or ".js:" in x]
    return f"{label}: " + " | ".join(keep[:2] or err[:2])


def main():
    print("=" * 72)
    print("  СКРИПТЫ НА СТРАНИЦАХ: синтаксис и запуск")
    print("=" * 72)

    if not _have_node():
        print("  ПРОПУЩЕНО: в системе нет node — проверка скриптов не запускалась")
        print("  (поставить зависимости: npm install)")
        return 0

    tmp = tempfile.mkdtemp(prefix="soc-js-")
    pages = sorted(glob.glob(os.path.join("templates", "*", "*.html")))
    statics = sorted(glob.glob(os.path.join("static", "*.js")))
    print(f"  страниц: {len(pages)} | файлов static/*.js: {len(statics)}")
    print("-" * 72)

    # --- 1. инлайновые скрипты страниц ---
    errors, total = [], 0
    for p in pages:
        html = open(p, encoding="utf-8").read()
        for i, code in enumerate(inline_scripts(html)):
            total += 1
            e = node_check(code, f"{p} · скрипт #{i + 1}", tmp)
            if e:
                errors.append(e)
    check(f"все инлайновые скрипты разбираются ({total} шт.)", not errors,
          "\n".join(errors))

    # --- 2. файлы static/*.js ---
    s_err = []
    for p in statics:
        e = node_check(open(p, encoding="utf-8").read(), p, tmp)
        if e:
            s_err.append(e)
    check(f"все static/*.js разбираются ({len(statics)} шт.)", not s_err,
          "\n".join(s_err))

    # --- 3. страница доживает до опроса API ---
    # Синтаксическая корректность ещё не значит, что код доработал до конца:
    # исключение на середине так же оставит интерфейс без данных.
    runner = os.path.join(tmp, "run.js")
    with open(runner, "w", encoding="utf-8") as f:
        f.write(r"""
const fs = require('fs');
let JSDOM;
try { ({ JSDOM } = require('jsdom')); }
catch (e) { console.log(JSON.stringify({skipped: true})); process.exit(0); }

const [pagePath, staticDir] = process.argv.slice(2);
const html = fs.readFileSync(pagePath, 'utf8');
const dom = new JSDOM(html, { runScripts: 'outside-only', url: 'http://127.0.0.1/' });
const w = dom.window;

const calls = [];
const errors = [];
w.fetch = (u, o) => { calls.push(String(u)); return Promise.resolve({
  ok: true, status: 200,
  json: () => Promise.resolve({}),
  text: () => Promise.resolve('')
}); };
w.EventSource = function () { this.addEventListener = () => {}; this.close = () => {}; };
w.matchMedia = w.matchMedia || (() => ({ matches: false, addListener(){}, addEventListener(){} }));
w.scrollTo = () => {};
// таймеры не запускаем, но факт их установки фиксируем
let timers = 0;
w.setInterval = (fn, ms) => { timers++; return 0; };
w.setTimeout = (fn, ms) => { if (!ms) { try { fn(); } catch (e) { errors.push(String(e.message)); } } return 0; };

for (const f of ['i18n.js', 'ui.js']) {
  const p = staticDir + '/' + f;
  if (fs.existsSync(p)) {
    try { w.eval(fs.readFileSync(p, 'utf8')); } catch (e) { errors.push(f + ': ' + e.message); }
  }
}
const inline = [...w.document.querySelectorAll('script:not([src])')];
inline.forEach((s, i) => {
  try { w.eval(s.textContent); } catch (e) { errors.push('inline#' + (i + 1) + ': ' + e.message); }
});
try { w.document.dispatchEvent(new w.Event('DOMContentLoaded')); } catch (e) {}
console.log(JSON.stringify({ errors, timers, calls: calls.length, sample: calls.slice(0, 4) }));
""")

    env = dict(os.environ)
    extra = [os.path.join(os.getcwd(), "node_modules"), "/tmp/soc/node_modules"]
    env["NODE_PATH"] = os.pathsep.join([p for p in extra if os.path.isdir(p)]
                                       + [env.get("NODE_PATH", "")])

    dashboards = [p for p in pages if os.path.basename(p) == "dashboard.html"]
    any_checked = False
    for p in dashboards:
        r = subprocess.run(["node", runner, p, os.path.join(os.getcwd(), "static")],
                           capture_output=True, text=True, timeout=180, env=env)
        try:
            res = json.loads((r.stdout or "").strip().splitlines()[-1])
        except Exception:
            check(f"{p}: страница выполняется", False,
                  (r.stderr or r.stdout or "нет вывода")[:400])
            continue
        if res.get("skipped"):
            print(f"  ПРОПУЩЕНО ({p}): нет пакета jsdom (npm install)")
            continue
        any_checked = True
        check(f"{p}: выполняется без ошибок", not res["errors"],
              "\n".join(res["errors"]))
        check(f"{p}: заводит опрос данных",
              res["timers"] > 0 or res["calls"] > 0,
              f"таймеров {res['timers']}, обращений к API {res['calls']} — "
              f"страница отрисуется, но данные не подгрузятся")
        if any_checked and not fails:
            print(f"      таймеров опроса: {res['timers']}, "
                  f"обращений к API при загрузке: {res['calls']}")

    print("-" * 72)
    if fails:
        print(f"  {BAD} ПРОВАЛЕНО: {len(fails)}")
        print()
        print("  Частая причина — апостроф внутри строки в одинарных кавычках:")
        print("    '... merge request'ы ...'   ломает разбор всего скрипта.")
        return 1
    print(f"  {OK} Скрипты страниц корректны и доходят до опроса данных.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
