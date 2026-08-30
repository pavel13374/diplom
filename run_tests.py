#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RUN TESTS — единый прогон проверок платформы.

Запускает по очереди:
  • компиляцию всех .py;
  • test_detector.py (правила, окна, вероятностный UEBA, слияние рисков);
  • test_generated_content.py (СОДЕРЖИМОЕ, уходящее в GitLab: шаблоны, Sigma,
    IR-отчёт — плюс статические проверки на потерянный префикс f и выброшенные
    вычисления);
  • selftest.py   (полный конвейер: store→detector→correlator→triage→commands→export→baseline→metrics);
  • test_antileak.py (защита не видит ПОЛЕЙ разметки мира);
  • test_leakage.py  (ни одно ЗНАЧЕНИЕ наблюдаемого признака не определяет
    метку — проверка на «метки-двойники» вроде эксклюзивных имён действий);
  • test_stats.py    (корректность статистического аппарата оценки);
  • test_math_regressions.py (регрессии численного аппарата: пуассоновский
    хвост, пол неожиданности, квантиль Уилсона, синхронность признаков);
  • test_evasion.py    (устойчивость к уклонению: заглушки-шум, склейка строк,
    кодирование, невидимые символы, форматы токенов, лимит объёма,
    отравление базовой линии, схема правил);
  • test_concurrency.py (гонки между ингестом и HTTP, границы роста при
    затоплении тревогами, атомарность захвата команд и записи состояния);
  • test_websec.py     (маскирование токена, чтение файлов, SSRF, CSRF,
    валидация параметров, непрозрачность ошибок).

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


#: Код возврата «проверка не выполнялась» (нет jsdom и т.п.).
SKIP_RC = 2


def run(cmd, name):
    """Возвращает "pass" | "fail" | "skip".

    ПРОПУСК БОЛЬШЕ НЕ СЧИТАЕТСЯ УСПЕХОМ. Без пакета jsdom tests/run_a11y.py и
    tests/test_page_scripts.py печатали «ПРОПУЩЕНО» и выходили с кодом 0,
    поэтому сводка показывала [PASS] a11y — при том что не проверялось ничего.
    Наблюдалось на чистой машине буквально так:

        >>> tests/run_a11y.py
          ПРОПУЩЕНО: нет пакета jsdom (npm install jsdom)
        <<< tests/run_a11y.py: OK
        [PASS] a11y

    Сами проверки исправны: после установки jsdom обе проходят. Неисправна была
    отчётность — а зелёная батарея, не проверившая ничего, хуже красной.
    """
    print(f"\n>>> {name}")
    r = subprocess.run(cmd, cwd=BASE)
    if r.returncode == SKIP_RC:
        print(f"<<< {name}: SKIP")
        return "skip"
    ok = r.returncode == 0
    print(f"<<< {name}: {'OK' if ok else 'FAIL'}")
    return "pass" if ok else "fail"


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
    strict = "--strict" in sys.argv
    results.append(("compile", "pass" if compile_all() else "fail"))
    results.append(("unit-detector", run([sys.executable, "tests/test_detector.py"], "tests/test_detector.py")))
    # ПРОДУКТ, а не движок: то, что реально уходит в репозитории GitLab.
    # Без этой проверки батарея была зелёной в момент, когда в коммиты
    # заливались буквальные «{pb['title']}» вместо подставленных значений.
    results.append(("generated-content", run([sys.executable, "tests/test_generated_content.py"],
                                             "tests/test_generated_content.py")))
    results.append(("selftest", run([sys.executable, "tests/selftest.py"], "tests/selftest.py")))
    results.append(("antileak", run([sys.executable, "tests/test_antileak.py"], "tests/test_antileak.py")))
    results.append(("leakage", run([sys.executable, "tests/test_leakage.py"], "tests/test_leakage.py")))
    results.append(("stats", run([sys.executable, "tests/test_stats.py"], "tests/test_stats.py")))
    # Регрессии на КОНКРЕТНЫЕ найденные дефекты численного аппарата:
    # пуассоновский хвост, пол неожиданности, точный квантиль Уилсона,
    # синхронность словаря действий с вектором признаков.
    results.append(("math-regressions", run([sys.executable, "tests/test_math_regressions.py"],
                                            "tests/test_math_regressions.py")))
    results.append(("offline", run([sys.executable, "tests/test_offline.py"], "tests/test_offline.py")))
    results.append(("rule-coverage", run([sys.executable, "tests/test_rule_coverage.py"], "tests/test_rule_coverage.py")))
    results.append(("i18n-rules", run([sys.executable, "tests/test_i18n_rules.py"], "tests/test_i18n_rules.py")))
    results.append(("routes", run([sys.executable, "tests/test_routes.py"], "tests/test_routes.py")))
    results.append(("page-scripts", run([sys.executable, "tests/test_page_scripts.py"], "tests/test_page_scripts.py")))
    results.append(("realmon", run([sys.executable, "tests/test_realmon.py"], "tests/test_realmon.py")))
    results.append(("llm-fallback", run([sys.executable, "tests/test_llm.py"], "tests/test_llm.py")))
    results.append(("contrast", run([sys.executable, "tests/test_contrast.py"], "tests/test_contrast.py")))
    results.append(("design-system", run([sys.executable, "tests/test_design_system.py"], "tests/test_design_system.py")))
    results.append(("a11y", run([sys.executable, "tests/run_a11y.py"], "tests/run_a11y.py")))
    # Регрессии на конкретные подтверждённые дефекты этого прохода: уклонение
    # от детектора секретов, гонки и границы роста, дыры веб-контура.
    results.append(("evasion", run([sys.executable, "tests/test_evasion.py"],
                                   "tests/test_evasion.py")))
    results.append(("concurrency", run([sys.executable, "tests/test_concurrency.py"],
                                       "tests/test_concurrency.py")))
    results.append(("websec", run([sys.executable, "tests/test_websec.py"],
                                  "tests/test_websec.py")))
    results.append(("telegram", run([sys.executable, "tests/test_telegram.py"],
                                    "tests/test_telegram.py")))

    print("\n" + "=" * 50)
    print("  СВОДКА ТЕСТОВ")
    print("=" * 50)
    for name, st in results:
        print(f"  [{ {'pass': 'PASS', 'fail': 'FAIL', 'skip': 'SKIP'}[st] }] {name}")
    failed = [n for n, st in results if st == "fail"]
    skipped = [n for n, st in results if st == "skip"]
    print("=" * 50)
    if skipped:
        print(f"  ПРОПУЩЕНО ({len(skipped)}): {', '.join(skipped)}")
        print("  Пропуск — не успех: проверка не выполнялась "
              "(обычно нет npm-пакета jsdom).")
    if failed:
        print(f"  ❌ Провалов: {len(failed)} — {', '.join(failed)}")
        return 1
    if skipped and strict:
        print("  ❌ --strict: пропущенные проверки считаются провалом")
        return 1
    print("  ✅ ВСЁ ЗЕЛЁНОЕ" if not skipped else "  ⚠ Зелёное, но не всё проверено")
    return 0


if __name__ == "__main__":
    sys.exit(main())
