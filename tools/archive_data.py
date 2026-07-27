#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Архивация старых данных перед чистым прогоном (EPIC 0.3).

Переносит data/events.jsonl и data/events.db (+ -wal/-shm) в
data/archive/<timestamp>/, чтобы новый поток собирался с чистого листа —
с полной схемой и разметкой episode_id/campaign_id.

Запуск:  python archive_data.py
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
import shutil
from datetime import datetime

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(BASE, "data")


def main():
    targets = ["events.jsonl", "events.db", "events.db-wal", "events.db-shm"]
    present = [t for t in targets if os.path.exists(os.path.join(DATA, t))]
    if not present:
        print("Нечего архивировать — data/ уже чистая.")
        return
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    dst = os.path.join(DATA, "archive", ts)
    os.makedirs(dst, exist_ok=True)
    for t in present:
        shutil.move(os.path.join(DATA, t), os.path.join(dst, t))
        print(f"  → {t}  перемещён в data/archive/{ts}/")
    print(f"\nГотово. Старые данные в data/archive/{ts}/.")
    print("Запусти мир заново (run_world.py / run.bat) — соберётся чистый поток.")


if __name__ == "__main__":
    main()
