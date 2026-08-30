"""
Запускает проверку доступности интерфейса.

Шаблоны обеих консолей — обычные строки в модулях, поэтому сервер
поднимать не нужно: берём разметку напрямую, кладём во временные
файлы и отдаём node-скрипту, который разбирает её в настоящем DOM.

Если в системе нет node или пакета jsdom, проверка помечается как
пропущенная, а не как провал: это делает прогон переносимым на
машину, где фронтенд-инструментов нет.
"""
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def _have_node():
    try:
        subprocess.run(["node", "--version"], capture_output=True, timeout=15)
        return True
    except Exception:
        return False


def main():
    if not _have_node():
        print("  ПРОПУЩЕНО: в системе нет node — проверка доступности не запускалась")
        # Код 2 = «проверка не выполнялась». Ноль здесь означал бы
        # успех, и сводка run_tests.py показывала [PASS] на непроверенном.
        return 2

    os.environ.setdefault("SOC_OFFLINE", "1")

    # Страницы вынесены из .py в templates/ — берём файлы напрямую и не
    # импортируем консоли ради разметки (импорт поднимал event-store и
    # фоновые потоки только чтобы прочитать строку).
    # ФОРМЫ ВХОДА ТОЖЕ ПРОВЕРЯЮТСЯ.
    #
    # Раньше грузились только дашборды, и до страниц логина проверка не
    # доходила. Из-за этого в templates/env/login.html подписи полей стояли
    # обычными <label> без for/id: экранный диктор объявлял поле логина и поле
    # пароля безымянными текстовыми полями. На консоли защиты та же форма была
    # размечена правильно — то есть расхождение между двумя страницами жило,
    # потому что его нечем было заметить.
    tpl = [
        ("console.html", os.path.join(ROOT, "templates", "console", "dashboard.html")),
        ("world.html", os.path.join(ROOT, "templates", "env", "dashboard.html")),
        ("console-login.html", os.path.join(ROOT, "templates", "console", "login.html")),
        ("env-login.html", os.path.join(ROOT, "templates", "env", "login.html")),
    ]
    missing = [p for _, p in tpl if not os.path.isfile(p)]
    if missing:
        print("  не найдены шаблоны страниц: %s" % missing)
        return 1

    tmp = tempfile.mkdtemp(prefix="soc-a11y-")
    paths = []
    for name, src in tpl:
        p = os.path.join(tmp, name)
        with open(src, encoding="utf-8") as f:
            html = f.read()
        with open(p, "w", encoding="utf-8") as f:
            f.write(html)
        paths.append(p)

    script = os.path.join(ROOT, "tests", "test_a11y.js")
    env = dict(os.environ)
    # jsdom может лежать рядом с проектом или в кэше песочницы
    extra = [os.path.join(ROOT, "node_modules"), "/tmp/soc/node_modules"]
    env["NODE_PATH"] = os.pathsep.join([p for p in extra if os.path.isdir(p)] +
                                       [env.get("NODE_PATH", "")])
    if not any(os.path.isdir(d) for d in extra):
        # jsdom не установлен: node-скрипты сообщат об этом и выйдут нулём.
        # Возвращаем «пропуск», иначе сводка покажет PASS на непроверенном.
        print("  ПРОПУЩЕНО: нет пакета jsdom (npm install jsdom)")
        return 2
    rc = subprocess.run(["node", script] + paths, env=env, timeout=180).returncode
    i18n = os.path.join(ROOT, "tests", "test_i18n.js")
    rc2 = subprocess.run(["node", i18n], env=env, timeout=120).returncode
    return rc or rc2


if __name__ == "__main__":
    sys.exit(main())
