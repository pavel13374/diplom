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
        return 0

    os.environ.setdefault("SOC_OFFLINE", "1")
    try:
        import console
        import webapp
    except Exception as e:
        print("  не удалось импортировать консоли: %s" % e)
        return 1

    tmp = tempfile.mkdtemp(prefix="soc-a11y-")
    paths = []
    for name, html in (("console.html", console.DASH), ("world.html", webapp.DASH_HTML)):
        p = os.path.join(tmp, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(html)
        paths.append(p)

    script = os.path.join(ROOT, "tests", "test_a11y.js")
    env = dict(os.environ)
    # jsdom может лежать рядом с проектом или в кэше песочницы
    extra = [os.path.join(ROOT, "node_modules"), "/tmp/soc/node_modules"]
    env["NODE_PATH"] = os.pathsep.join([p for p in extra if os.path.isdir(p)] +
                                       [env.get("NODE_PATH", "")])
    rc = subprocess.run(["node", script] + paths, env=env, timeout=180).returncode
    i18n = os.path.join(ROOT, "tests", "test_i18n.js")
    rc2 = subprocess.run(["node", i18n], env=env, timeout=120).returncode
    return rc or rc2


if __name__ == "__main__":
    sys.exit(main())
