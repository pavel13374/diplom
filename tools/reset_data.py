#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
СБРОС ДАННЫХ — чистый перезапуск стенда.

Удаляет накопленную «жизнь» симуляции, чтобы начать с нуля (без того, чтобы
симуляция «уехала вперёд»): журнал событий, логи, отчёты, результаты, черновики
правил. Конфиг и сам код НЕ трогает.

  python reset_data.py            # спросит подтверждение
  python reset_data.py --yes      # без вопросов (для кнопки в панели)
  python reset_data.py --yes --gitlab   # + откат репозиториев в GitLab (если настроен)
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
import sys
import glob
import shutil
import argparse

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _rm(path):
    try:
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
        elif os.path.exists(path):
            os.remove(path)
        return True
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser(description="Сброс данных стенда")
    ap.add_argument("--yes", action="store_true", help="без подтверждения")
    ap.add_argument("--gitlab", action="store_true", help="также откатить репозитории в GitLab (безопасно: MR/ветки)")
    ap.add_argument("--gitlab-full", dest="gitlab_full", action="store_true", help="ПОЛНЫЙ снос GitLab: ВСЕ репозитории и sim-пользователи")
    args = ap.parse_args()

    targets = {
        "журнал событий":   ["data/events.db", "data/events.db-wal", "data/events.db-shm",
                             "data/events.jsonl"],
        "снапшоты датасета": glob.glob(os.path.join(BASE, "data", "dataset_v*")),
        "логи":             glob.glob(os.path.join(BASE, "logs", "*.log"))
                            + glob.glob(os.path.join(BASE, "logs", "*.log.*")),
        "IR-отчёты":        glob.glob(os.path.join(BASE, "reports", "*.md")),
        "результаты":       glob.glob(os.path.join(BASE, "results", "*.csv")),
        "черновики правил":  glob.glob(os.path.join(BASE, "detections", "proposed", "*.json")),
    }

    print("=" * 56)
    print("  СБРОС ДАННЫХ СТЕНДА (код и настройки не трогаем)")
    print("=" * 56)
    total = sum(len(v) if isinstance(v, list) else 1 for v in targets.values())
    for name, items in targets.items():
        items = items if isinstance(items, list) else items
        print(f"  • {name}")
    if not args.yes:
        ans = input("\nУдалить всё перечисленное? [y/N] ").strip().lower()
        if ans not in ("y", "yes", "д", "да"):
            print("Отменено."); return

    removed = 0
    for name, items in targets.items():
        lst = items if isinstance(items, list) else [os.path.join(BASE, items)]
        for it in lst:
            p = it if os.path.isabs(it) else os.path.join(BASE, it)
            if _rm(p):
                removed += 1
    # пустые папки оставляем на месте
    for d in ("data", "logs", "reports", "results"):
        os.makedirs(os.path.join(BASE, d), exist_ok=True)

    print(f"\n  Удалено объектов: {removed}.  Стенд очищен — можно запускать заново.")

    if args.gitlab or args.gitlab_full:
        import subprocess, sys as _sys
        flags = ["--full", "--yes"] if args.gitlab_full else ["--all", "--yes"]
        print("\n  " + ("ПОЛНЫЙ снос GitLab (все репо + sim-юзеры)…" if args.gitlab_full
                         else "Откат GitLab (MR/ветки/файлы)…"))
        try:
            subprocess.run([_sys.executable, os.path.join(BASE, "tools", "reset_gitlab.py")] + flags,
                           cwd=BASE, timeout=600)
        except Exception as e:
            print(f"  (GitLab-сброс пропущен: {e})")
        print("  При следующем СТАРТЕ мира всё пересоздастся автоматически "
              "(репозитории, сотрудники, права).")


if __name__ == "__main__":
    main()
