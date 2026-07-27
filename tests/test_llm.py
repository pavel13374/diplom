#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Проверка подключения локальной LLM (Ollama) и слоя триажа.

Запуск:  python test_llm.py
Если Ollama не запущена — покажет инструкцию и продемонстрирует фолбэк-триаж
(система работает и без LLM).
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
import json
try:                       # чистый UTF-8 в консоли Windows
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass
import config
import llm_client as lc


def main():
    print("=" * 60)
    print("  Проверка локальной LLM для SOC-симулятора")
    print("=" * 60)
    print(f"  host:  {config.LLM.get('host')}")
    print(f"  model: {config.LLM.get('model')}")
    print("-" * 60)

    ok = lc.available()
    print(f"Ollama: {'YES' if ok else 'NO'}")
    print(f"Ollama доступна:   {'ДА' if ok else 'НЕТ'}")
    if ok:
        models = lc.list_models()
        print(f"Доступные модели:  {', '.join(models) or '(пусто)'}")
        if not lc.has_model():
            print(f"[!] Нужная модель {config.LLM['model']} не скачана.")
            print(f"    Выполни:  ollama pull {config.LLM['model']}")
    else:
        print("Ollama не отвечает. Чтобы включить LLM-триаж:")
        print("  1) установи Ollama:  https://ollama.com/download/windows")
        print(f"  2) скачай модель:    ollama pull {config.LLM['model']}")
        print("  3) запусти снова:    python test_llm.py")
        print("\n(Симулятор и детектор работают и без LLM — ниже фолбэк-триаж.)")

    leak = {
        "title": "push секрета в deploy/.env",
        "actor": "maria.ivanova", "repo": "soc-infra",
        "risk_score": 0.88, "regex_hits": ["gitlab_pat", "aws_akia"],
        "shannon_entropy": 4.6, "placeholder_signal": False,
        "events": ["weaken_pipeline_security", "push deploy/.env",
                   "grant_secret_access", "off-hours"],
    }
    benign = {
        "title": "push config/.env.example",
        "actor": "dmitry.kozlov", "repo": "detection-rules",
        "risk_score": 0.15, "regex_hits": [],
        "shannon_entropy": 3.2, "placeholder_signal": True,
        "events": ["push config/.env.example"],
    }

    for name, inc in [("УТЕЧКА (ожидаем high/critical, TP)", leak),
                      ("BENIGN .env.example (ожидаем low, не TP)", benign)]:
        print("\n" + "-" * 60)
        print(f"Кейс: {name}")
        res = lc.triage(inc)
        print(f"  источник:   {res.get('_source')}")
        print(f"  severity:   {res.get('severity')}  | TP: {res.get('is_true_positive')}"
              f"  | conf: {res.get('confidence')}")
        print(f"  заголовок:  {res.get('title')}")
        print(f"  нарратив:   {res.get('narrative')}")
        acts = res.get("recommended_actions") or []
        if acts:
            print("  действия:   " + "; ".join(acts))
        if res.get("benign_explanation"):
            print(f"  benign:     {res['benign_explanation']}")

    print("\n" + "=" * 60)
    print("Готово." + ("  LLM активна." if ok else "  Работает фолбэк (без LLM)."))


if __name__ == "__main__":
    main()
