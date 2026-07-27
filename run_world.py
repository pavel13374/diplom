#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ПРОЦЕСС «МИР» (World) — запуск симулятора SOC-команды.

Это тот же симулятор, что и main.py, но как явная точка входа контура «мир»
в архитектуре Purple Team (мир пишет события в event-store, защита их читает).
Веб-консоль среды по-прежнему поднимается отдельно (run.bat → webapp), а это —
консольный движок мира.

Запуск:  python run_world.py   (или run_world.bat)
"""
import sys
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

import main

if __name__ == "__main__":
    print("=" * 60)
    print("  ПРОЦЕСС «МИР» (World) — симулятор SOC-команды")
    print("  Пишет поток событий в event-store (data/events.db).")
    print("  Защита читается отдельно:  python run_defense.py")
    print("=" * 60)
    main.main()
