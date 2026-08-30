#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
УСТОЙЧИВОСТЬ ДЕТЕКТОРА К УКЛОНЕНИЮ.

Этот файл — регрессия на конкретные найденные дыры, а не общая проверка
«детектор работает». Каждый блок закрывает измеренный дефект.

  1. ОДНО СЛОВО ВЫКЛЮЧАЛО ОБНАРУЖЕНИЕ СЕКРЕТОВ.
     `placeholder_signal` считался ПО ВСЕМУ ФАЙЛУ, а четыре самых ценных
     правила требуют `placeholder_signal: false`. Замер через боевой
     DetectionEngine:

         настоящий glpat-токен                 risk 0.92
         он же + строка "# TODO: rotate later" risk 0.00   (ни одной сработки)
         он же + "html = '<div>hi</div>'"      risk 0.00
         он же + "user = 'your_name'"          risk 0.00

  2. СКЛЕЙКА СТРОК БЫЛА БЕСПЛАТНЫМ ОБХОДОМ.
     Энтропия считалась по токенам, нарезанным по `[^A-Za-z0-9+/_-]`, и только
     длиной от 16. Поэтому `"glpat-" + "Ab3xK9mQ7zR2pL5wT8vN"` давал энтропию
     0.00 и ноль сигнатур — то есть отключал СРАЗУ ОБА слоя, сигнатурный и
     энтропийный. То же с base64, \\xNN-escape, символами нулевой ширины,
     кириллическими двойниками латиницы и переносом обратным слэшем (последним
     пользуется профиль уклонения самого стенда).

  3. НАБОР СИГНАТУР ОТСТАЛ ОТ РЕАЛЬНОСТИ.
     Восемь паттернов покрывали ровно то, что порождает симулятор. На корпусе
     правдоподобных настоящих учётных данных не срабатывало ничего для
     github_pat_/gho_/AIza/sk_live_/sk-proj-/npm_/xoxe-/ASIA/AccountKey=.

  4. АНАЛИЗ СОДЕРЖИМОГО БЫЛ БЕЗ ПОТОЛКА.
     Размер файла выбирает автор коммита, а analyze() синхронен внутри push_file
     и внутри цикла ингеста: один большой файл останавливал конвейер целиком.

  5. БАЗОВУЮ ЛИНИЮ ПОВЕДЕНИЯ МОЖНО БЫЛО ОБУЧИТЬ САМОМУ.
     Профиль UEBA пополнялся КАЖДЫМ событием, включая те, на которых только
     что сработало правило.

Запуск: python tests/test_evasion.py
"""
import os as _os
import sys as _sys

_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)
_os.chdir(_ROOT)

import re
import time
import base64
import logging

logging.disable(logging.CRITICAL)
try:
    _sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

import detector
import content_features as cf

OK, BAD = "✅", "❌"
FAILED = []


def check(name, ok, detail=""):
    print(f"  {OK if ok else BAD} {name}" + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        FAILED.append(name)


SECRET_LINE = 'GITLAB_TOKEN = "glpat-Ab3xK9mQ7zR2pL5wT8vN"\n'


def _engine():
    return detector.DetectionEngine(use_ml=False)


def _detect(content, path="deploy/config.py"):
    """Полный путь: признаки содержимого -> движок. Возвращает (rule_ids, risk)."""
    feats = cf.analyze(content, path)
    ev = {"action": "push", "actor": "mallory", "project": "soc-infra", "path": path,
          "ts_sim": "2026-06-08T11:00:00", "hour": 11, "is_night": False,
          "bytes": len(content), "message": "chore: update config",
          "has_content": True, **feats}
    res = _engine().process(ev)
    return sorted(a["rule_id"] for a in res.get("alerts", [])), res.get("risk", 0.0)


# ======================================================================
def test_placeholder_noise_does_not_hide_real_secret():
    print("\n-- шум-заглушка не прячет настоящий секрет --")
    base_rules, base_risk = _detect(SECRET_LINE)
    check("настоящий токен обнаружен", "secret-signature-commit" in base_rules,
          str(base_rules))

    noises = {
        "# TODO: rotate later": "слово TODO",
        "html = '<div>hi</div>'": "любой html-тег",
        "user = 'your_name'": "your_",
        "mask = 'xxxxxxxx'": "иксы",
        "# see config.example for the format": "слово example",
        "PLACEHOLDER = 'changeme'": "changeme",
        "note = 'dummy value below'": "dummy",
    }
    for noise, why in noises.items():
        rules, risk = _detect(SECRET_LINE + noise + "\n")
        check(f"секрет виден рядом с «{why}»",
              "secret-signature-commit" in rules and risk >= base_risk * 0.9,
              f"правила={rules} risk={risk}")


def test_benign_template_stays_quiet():
    """Обратная сторона: benign-двойники обязаны оставаться тихими.

    Если бы правка просто убрала признак заглушки, .env.example с примерами
    начал бы давать critical на каждом коммите — то есть один дефект сменился
    бы другим, более заметным.
    """
    print("\n-- benign-двойники по-прежнему молчат --")
    tpl = ("# .env.example — шаблон\n"
           "AWS_ACCESS_KEY_ID=<your-key-here>\n"
           "AWS_SECRET_ACCESS_KEY=changeme\n"
           "DATABASE_URL=postgres://user:password@localhost:5432/db\n"
           "API_KEY=REPLACE_ME\n")
    rules, risk = _detect(tpl, "config/.env.example")
    check("шаблон .env.example не поднимает тревогу", not rules, str(rules))

    doc = ("Пример конфигурации AWS для документации:\n\n"
           "    AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
    rules, _ = _detect(doc, "docs/aws-setup.md")
    check("учебный ключ из документации не поднимает тревогу", not rules, str(rules))

    # А вот НАСТОЯЩИЙ высокоэнтропийный токен в файле-шаблоне — поднимает:
    # имя файла не должно быть индульгенцией.
    rules, _ = _detect("GITLAB_TOKEN=glpat-Ab3xK9mQ7zR2pL5wT8vN\n", "config/.env.example")
    check("настоящий токен в .env.example всё же обнаружен",
          "secret-signature-commit" in rules, str(rules))


def test_split_and_encoded_secrets_are_detected():
    print("\n-- секрет, спрятанный приёмом уклонения --")
    tok = "glpat-Ab3xK9mQ7zR2pL5wT8vN"
    variants = {
        "склейка строковых литералов": 'T = "glpat-" + "Ab3xK9mQ7zR2pL5wT8vN"\n',
        "соседние литералы":           'T = ("glpat-Ab3xK9mQ7z"\n     "R2pL5wT8vN")\n',
        "перенос обратным слэшем":     re.sub(r"([A-Za-z0-9_\-]{12})", r"\1 \\\n",
                                              f"GITLAB_TOKEN={tok}\n"),
        "base64":                      'DATA = "%s"\n' % base64.b64encode(
                                            tok.encode()).decode(),
        "\\xNN-escape":                'T = "' + "".join("\\x%02x" % ord(c)
                                            for c in tok[:6]) + tok[6:] + '"\n',
        "процентное кодирование":      "T=glpat%2DAb3xK9mQ7zR2pL5wT8vN\n",
        "символ нулевой ширины":       'T = "glpat​-Ab3xK9mQ7zR2pL5wT8vN"\n',
        "кириллические двойники":      'T = "glра t-Ab3xK9mQ7zR2pL5wT8vN"\n'.replace(" ", ""),
    }
    for name, content in variants.items():
        feats = cf.analyze(content, "deploy/config.py")
        rules, risk = _detect(content)
        check(f"{name}: секрет найден",
              feats["n_real_hits"] >= 1, f"hits={feats['regex_hits']}")
        check(f"{name}: уклонение отмечено как улика",
              feats["evasion_signal"] and "secret-obfuscated-evasion" in rules,
              f"kinds={feats['evasion_kinds']} rules={rules}")


def test_known_formats_are_detected():
    print("\n-- форматы учётных данных, встречающиеся сегодня --")
    cases = {
        "github_pat":       "github_pat_11ABCDEFG0abcdefghijkl_0123456789abcdefghijklmnopqrstuvwxyzABCD",
        "github_pat (gho)": "tok=gho_16C7e42F292c6912E7710c838347Ae178B4a",
        "google_api_key":   "k = 'AIzaSyD-9v8QqRt3LmNbVcXzAsDfGhJkLpOiUyT'",
        "stripe_key":       "STRIPE=sk_live_51H8xk2LabcdefghijklmnopqrsTUVWXYZ0123",
        "llm_api_key":      "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH",
        "npm_token":        "//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz0123456789",
        "slack_token":      "xoxe-1-abcdefghijklmnopqrstuvwx",
        "azure_storage_key": "AccountName=x;AccountKey="
                             "aGVsbG93b3JsZGhlbGxvd29ybGRoZWxsb3dvcmxkaGVsbG93b3JsZGhlbGxvd29ybGQ=;",
        "aws_akia":         "ASIAY34FZKBOKMUTVV7A",
        "private_key":      "-----BEGIN OPENSSH PRIVATE KEY-----",
        "gitlab_pat":       "glpat-Ab3xK9mQ7zR2pL5wT8vN",
        "jwt":              "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27u",
    }
    for label, content in cases.items():
        want = label.split(" (")[0]
        hits = cf.analyze(content, "app/config.py")["regex_hits"]
        check(f"{label} распознан", want in hits, f"получено {hits}")


def test_large_input_is_bounded():
    print("\n-- большой файл не останавливает конвейер --")
    blob = base64.b64encode(_os.urandom(20 * 1024 * 1024)).decode()
    t0 = time.time()
    r = cf.analyze(blob, "export/dump.txt")
    dt = time.time() - t0
    check(f"27 МБ разобраны за {dt:.2f}с (< 2с)", dt < 2.0, f"{dt:.2f}с")
    check("частичный просмотр отмечен признаком truncated", r["truncated"])

    t0 = time.time()
    cf.analyze("A" * 5_000_000, "x.txt")
    check(f"5 МБ одним токеном за {time.time() - t0:.2f}с (< 2с)",
          time.time() - t0 < 2.0)


def test_ci_debug_rule_is_content_based():
    """Правило не должно зависеть от СООБЩЕНИЯ КОММИТА — его пишет автор."""
    print("\n-- отладка CI определяется по содержимому, а не по сообщению --")
    ci_bad = 'variables:\n  CI_DEBUG_TRACE: "true"\n\nbuild:\n  script:\n    - make\n'
    rules, _ = _detect(ci_bad, ".gitlab-ci.yml")
    check("CI_DEBUG_TRACE обнаружен при нейтральном сообщении",
          "ci-debug-token-leak" in rules, str(rules))

    ci_echo = "deploy:\n  script:\n    - echo $CI_JOB_TOKEN | docker login\n"
    rules, _ = _detect(ci_echo, ".gitlab-ci.yml")
    check("печать CI_JOB_TOKEN обнаружена", "ci-debug-token-leak" in rules, str(rules))

    ci_ok = "stages:\n  - build\n\nbuild:\n  script:\n    - set -x\n    - make all\n"
    rules, _ = _detect(ci_ok, ".gitlab-ci.yml")
    check("обычная правка CI со словом debug в сообщении не срабатывает",
          "ci-debug-token-leak" not in rules, str(rules))


def test_baseline_poisoning_is_resisted():
    """Событие, поднявшее правило, не должно учить базовую линию.

    Иначе достаточно повторять подозрительное действие, чтобы оно перестало
    быть подозрительным: две сотни безобидных обращений в 03:00 к целевому
    репозиторию сводят обе входящие в скор компоненты (repo, hour) к нулю бит,
    и к моменту настоящей операции слой слеп.
    """
    print("\n-- базовую линию нельзя обучить собственной атакой --")

    def _profile(trust_attack):
        """Обычная дневная работа + 300 «подготовительных» ночных обращений."""
        u = detector.UEBA()
        for i in range(600):
            u.update({"actor": "mallory", "project": "detection-rules",
                      "action": "push", "hour": 11 + (i % 6),
                      "ts_sim": "2026-06-08T11:00:00"}, trust=True)
        for _ in range(300):
            u.update({"actor": "mallory", "project": "soc-secrets",
                      "action": "api_read", "hour": 3,
                      "ts_sim": "2026-06-08T03:00:00"}, trust=trust_attack)
        return u

    hardened = _profile(trust_attack=False)   # как сейчас: сработки не учат
    naive = _profile(trust_attack=True)       # как было: учит всё подряд

    p = hardened.actor["mallory"]
    check("наблюдения со сработкой правила не пополнили профиль",
          p["skipped"] == 300 and abs(p["learned"] - 600.0) < 1e-6,
          f"learned={p['learned']} skipped={p['skipped']}")

    def bits(u, key):
        a = u.actor["mallory"]
        if key == "repo":
            return detector._surprisal(a["repos"].prob("soc-secrets", u.vocab_repos))
        return detector._surprisal(a["hours"].prob(3))

    for key, label in (("repo", "хранилище секретов"), ("hour", "час 03:00")):
        hb, nb = bits(hardened, key), bits(naive, key)
        check(f"{label}: подготовка не сделала его обычным "
              f"({hb:.1f} бит против {nb:.1f} при наивном обучении)",
              hb > nb + 1.5, f"{hb:.2f} vs {nb:.2f}")

    # Движок сам решает, чему доверять.
    eng = _engine()
    for _ in range(5):
        eng.process({"action": "push", "actor": "eve", "project": "soc-infra",
                     "path": "deploy/.env", "ts_sim": "2026-06-08T11:00:00",
                     "hour": 11, "n_real_hits": 1, "n_regex_hits": 1,
                     "placeholder_signal": False})
    check("движок не учит базовую линию на сработках правил",
          eng.ueba.actor["eve"]["learned"] == 0.0,
          str(eng.ueba.actor["eve"]["learned"]))


def test_rule_schema_is_validated():
    """Сломанное правило не должно ронять конвейер и не должно молчать тихо."""
    print("\n-- правила проверяются при загрузке --")
    import json
    import tempfile
    d = tempfile.mkdtemp()
    json.dump({"id": "no-title", "when": {"action": "push"}},
              open(_os.path.join(d, "a.json"), "w"))
    json.dump({"id": "typo-op", "title": "t", "when": {"bytes": {"gte": 10}}},
              open(_os.path.join(d, "b.json"), "w"))
    json.dump({"id": "good", "title": "ok", "when": {"action": "push"}, "risk": 0.4},
              open(_os.path.join(d, "c.json"), "w"))
    eng = detector.DetectionEngine(rules_dir=d, use_ml=False)
    ids = {r["id"] for r in eng.rules}
    check("правило без title отвергнуто", "no-title" not in ids)
    check("правило с неизвестным оператором отвергнуто", "typo-op" not in ids)
    check("исправное правило загружено", "good" in ids)
    rej = {r.get("id") for r in eng.rejected_rules()}
    check("отвергнутые правила названы и видны", {"no-title", "typo-op"} <= rej, str(rej))
    res = eng.process({"action": "push", "actor": "a", "bytes": 9999,
                       "ts_sim": "2026-06-01T10:00:00"})
    check("движок не падает на событии", res["alert"] is True)


def test_timestamp_formats():
    print("\n-- разбор меток времени --")
    good = ("2026-01-01T10:00:00", "2026-01-01T10:00:00.123456",
            "2026-01-01T10:00:00Z", "2026-01-01 10:00:00",
            "2026-01-01T10:00:00+03:00")
    for t in good:
        check(f"формат {t!r} разбирается", detector.parse_ts(t) is not None)
    for bad in (None, {"a": 1}, [], ""):
        check(f"{bad!r} -> None без исключения", detector.parse_ts(bad) is None)
    import correlator
    check("correlator._parse(int) не бросает исключение",
          correlator._parse(12345) is not None or True)

    # Главное следствие: с меткой любого из форматов оконные агрегаты СЧИТАЮТСЯ.
    e = detector.Enricher()
    out = None
    for i in range(4):
        out = e.enrich({"actor": "u", "action": "file_delete", "project": "p",
                        "ts_sim": f"2026-01-01T10:0{i}:00.500000"})
    check("агрегаты считаются на метке с микросекундами",
          out["burst_file_delete_10m"] == 4, str(out.get("burst_file_delete_10m")))


def main():
    print("=" * 74)
    print("  УСТОЙЧИВОСТЬ К УКЛОНЕНИЮ И КАЧЕСТВО ОБНАРУЖЕНИЯ СЕКРЕТОВ")
    print("=" * 74)
    test_placeholder_noise_does_not_hide_real_secret()
    test_benign_template_stays_quiet()
    test_split_and_encoded_secrets_are_detected()
    test_known_formats_are_detected()
    test_large_input_is_bounded()
    test_ci_debug_rule_is_content_based()
    test_baseline_poisoning_is_resisted()
    test_rule_schema_is_validated()
    test_timestamp_formats()
    print("-" * 74)
    if FAILED:
        print(f"  {BAD} ПРОВАЛЕНО: {len(FAILED)}")
        for f in FAILED:
            print(f"     - {f}")
        return 1
    print(f"  {OK} Детектор устойчив к проверенным приёмам уклонения.")
    return 0


if __name__ == "__main__":
    _sys.exit(main())
