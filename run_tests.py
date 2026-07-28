#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RUN TESTS — единый прогон проверок платформы.

Запускает по очереди:
  • компиляцию всех .py;
  • test_detector.py (правила, окна, вероятностный UEBA, слияние рисков);
  • selftest.py   (полный конвейер: store→detector→correlator→triage→commands→export→baseline→metrics);
  • test_antileak.py (защита не видит ПОЛЕЙ разметки мира);
  • test_leakage.py  (ни одно ЗНАЧЕНИЕ наблюдаемого признака не определяет
    метку — проверка на «метки-двойники» вроде эксклюзивных имён действий);
  • test_stats.py    (корректность статистического аппарата оценки).

Печатает сводку и возвращает 0, если всё зелёное.

Запуск:  python run_tests.py
"""
import os
import sys
import glob
import subprocess

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

BASE = os.path.dirname(os.path.abspath(__file__))


def run(cmd, name):
    print(f"\n>>> {name}")
    r = subprocess.run(cmd, cwd=BASE)
    ok = r.returncode == 0
    print(f"<<< {name}: {'OK' if ok else 'FAIL'}")
    return ok


def compile_all():
    print("\n>>> Компиляция всех .py")
    import py_compile
    fails = []
    for f in sorted(glob.glob(os.path.join(BASE, "**", "*.py"), recursive=True)):
        try:
            py_compile.compile(f, doraise=True)
        except Exception as e:
            fails.append((os.path.relpath(f, BASE), str(e).splitlines()[-1]))
    if fails:
        for f, e in fails:
            print(f"   FAIL {f}: {e}")
    print(f"<<< Компиляция: {'OK' if not fails else str(len(fails)) + ' ошибок'}")
    return not fails


def main():
    results = []
    results.append(("compile", compile_all()))
    results.append(("unit-detector", run([sys.executable, "tests/test_detector.py"], "tests/test_detector.py")))
    results.append(("selftest", run([sys.executable, "tests/selftest.py"], "tests/selftest.py")))
    results.append(("antileak", run([sys.executable, "tests/test_antileak.py"], "tests/test_antileak.py")))
    results.append(("leakage", run([sys.executable, "tests/test_leakage.py"], "tests/test_leakage.py")))
    results.append(("stats", run([sys.executable, "tests/test_stats.py"], "tests/test_stats.py")))
    results.append(("rule-coverage", run([sys.executable, "tests/test_rule_coverage.py"], "tests/test_rule_coverage.py")))
    results.append(("i18n-rules", run([sys.executable, "tests/test_i18n_rules.py"], "tests/test_i18n_rules.py")))
    results.append(("routes", run([sys.executable, "tests/test_routes.py"], "tests/test_routes.py")))
    results.append(("realmon", run([sys.executable, "tests/test_realmon.py"], "tests/test_realmon.py")))
    results.append(("llm-fallback", run([sys.executable, "tests/test_llm.py"], "tests/test_llm.py")))
    results.append(("contrast", run([sys.executable, "tests/test_contrast.py"], "tests/test_contrast.py")))
    results.append(("a11y", run([sys.executable, "tests/run_a11y.py"], "tests/run_a11y.py")))

    print("\n" + "=" * 50)
    print("  СВОДКА ТЕСТОВ")
    print("=" * 50)
    for name, ok in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    allok = all(ok for _, ok in results)
    print("=" * 50)
    print("  ✅ ВСЁ ЗЕЛЁНОЕ" if allok else "  ❌ Есть провалы")
    return 0 if allok else 1


if __name__ == "__main__":
    sys.exit(main())
