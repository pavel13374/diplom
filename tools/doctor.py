#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DOCTOR — проверка окружения перед запуском платформы.

Печатает чек-лист: версия Python, нужные пакеты, свободны ли порты 8787/8788,
доступность GitLab (из config), наличие Ollama (для LLM-разбора).

Запуск:  python doctor.py
"""

# --- скрипт живёт в подпапке; движок проекта — в корне ---
import os as _os, sys as _sys
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
for _p in (_ROOT, _os.path.join(_ROOT, "tools"), _os.path.join(_ROOT, "research")):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
_os.chdir(_ROOT)
del _os, _sys
import sys
import socket

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


def line(ok, name, detail=""):
    mark = "OK " if ok else "-- "
    print(f"  [{mark}] {name}" + (f": {detail}" if detail else ""))


def port_free(p):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.3)
    try:
        free = s.connect_ex(("127.0.0.1", p)) != 0
    finally:
        s.close()
    return free


def main():
    print("=" * 56)
    print("  DOCTOR — проверка окружения")
    print("=" * 56)

    v = sys.version_info
    line(v >= (3, 8), "Python >= 3.8", f"{v.major}.{v.minor}.{v.micro}")

    print("\n  Пакеты:")
    for mod, need in [("flask", True), ("requests", True), ("sklearn", False),
                      ("numpy", False), ("pandas", False)]:
        try:
            __import__(mod)
            try:
                import importlib.metadata as _md
                ver = _md.version(mod if mod != "sklearn" else "scikit-learn")
            except Exception:
                ver = "ok"
            line(True, mod, ver)
        except Exception:
            line(False, mod, "не установлен" + ("  (нужен для сайтов)" if need else "  (нужен для ML)"))

    print("\n  Порты (должны быть свободны):")
    line(port_free(8787), "8787 (Environment Console)")
    line(port_free(8788), "8788 (Purple Team Console)")

    print("\n  GitLab (из config):")
    try:
        import config
        url = config.GITLAB_URL
        tok = bool(config.ADMIN_TOKEN and config.ADMIN_TOKEN.startswith("glpat-"))
        line(bool(url), "GITLAB_URL", url)
        line(tok, "ADMIN_TOKEN задан", "glpat-..." if tok else "проверь токен")
        try:
            import urllib.request, ssl
            ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url.rstrip("/") + "/api/v4/version",
                                         headers={"PRIVATE-TOKEN": config.ADMIN_TOKEN})
            with urllib.request.urlopen(req, timeout=4, context=ctx) as r:
                import json
                ver = json.loads(r.read()).get("version", "?")
            line(True, "GitLab отвечает", f"v{ver}")
        except Exception as e:
            line(False, "GitLab недоступен", str(e)[:60])
    except Exception as e:
        line(False, "config", str(e)[:60])

    print("\n  LLM (Ollama, опционально):")
    try:
        import llm_client
        ok = llm_client.available()
        line(ok, "Ollama", (", ".join(llm_client.list_models()) or "нет моделей") if ok
             else "не запущена (LLM-разбор будет на фолбэке) — setup_llm.bat")
    except Exception as e:
        line(False, "llm_client", str(e)[:50])

    print("\n  Детекты:")
    try:
        import detector
        e = detector.DetectionEngine()
        line(e.rule_count() > 0, "правила загружены", f"{e.rule_count()} шт, {len(e.techniques_covered())} техник")
    except Exception as ex:
        line(False, "detector", str(ex)[:50])

    print("\n  Event-store и данные:")
    try:
        import os
        import eventstore
        eventstore.init()
        ok = eventstore.enabled()
        st = eventstore.stats() if ok else {}
        line(ok, "events.db открыт",
             f"{st.get('events', 0)} событий" if ok
             else "не открылся — проверь data/ и config.EVENT_STORE")
        if ok:
            for cur in ("defense", "console"):
                try:
                    pos = eventstore.get_cursor(cur)
                    lag = max(0, (st.get("events") or 0) - (pos or 0))
                    line(lag < 5000, f"курсор «{cur}»",
                         f"позиция {pos}, отставание {lag}"
                         + ("" if lag < 5000 else " — читатель давно не работал"))
                except Exception as ex2:
                    line(False, f"курсор «{cur}»", str(ex2)[:50])
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        dd = os.path.join(base, "data")
        line(os.access(dd, os.W_OK) if os.path.isdir(dd) else False,
             "data/ доступна на запись",
             dd if os.path.isdir(dd) else "папки нет — создастся при старте")
    except Exception as ex:
        line(False, "eventstore", str(ex)[:60])

    print("\n  Конвейер (смоук офлайн):")
    try:
        import run_defense
        _probe = {"action": "push", "actor": "_doctor", "project": "soc/secrets-vault",
                  "ts_sim": "2026-01-01T03:00:00", "shannon_entropy": 5.5,
                  "placeholder_signal": False, "n_regex_hits": 0,
                  "is_anomaly": True, "campaign_id": "_doctor"}
        res = run_defense.process(_probe)
        line(bool(res.get("alert")), "детектор ловит эталонное событие",
             f"risk={res.get('risk')}" if res.get("alert")
             else "эталон не пойман — правила изменялись?")
        leak_ok = "campaign_id" not in run_defense.observed(_probe)
        line(leak_ok, "анти-лик: observed() срезает разметку",
             "ок" if leak_ok else "!!! разметка мира видна детектору")
    except Exception as ex:
        line(False, "конвейер", str(ex)[:60])

    print("\n  Логи:")
    try:
        import soclog
        paths = soclog.install()
        line(True, "структурный лог", paths.get("jsonl", ""))
        errs = soclog.tail_errors(5)
        line(not errs, "errors.log",
             "пустой — ошибок не было" if not errs
             else f"{len(errs)} последних строк — пришли файл на разбор")
    except Exception as ex:
        line(False, "soclog", str(ex)[:50])

    print("=" * 56)
    print("  Готово. Если что-то [--], см. подсказки выше.")
    print("  Для разбора проблем присылай: logs/errors.log и logs/debug.jsonl")


if __name__ == "__main__":
    main()
