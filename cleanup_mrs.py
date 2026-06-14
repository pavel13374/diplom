#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Утилита разовой чистки открытых MR во ВСЕХ репозиториях команды.

Зачем: если от прошлых прогонов накопились незамерживаемые MR (конфликты,
удалённые ветки, Draft) — они дают 405 при merge и забивают очередь.
Эта утилита покрывает не только базовые проекты, но и созданные репозитории
(через автодискавери namespace).

Запуск:
    python cleanup_mrs.py            # пробует смержить, иначе закрывает
    python cleanup_mrs.py --purge    # сразу закрывает всё, без попыток merge (быстро)
    python cleanup_mrs.py --purge --del-branches   # ещё и удаляет ветки закрытых MR
"""
import sys
import config
from gitlab_client import GitLabClient
import urllib3
urllib3.disable_warnings()

PURGE = "--purge" in sys.argv
DEL_BRANCHES = "--del-branches" in sys.argv

gl = GitLabClient(config.GITLAB_URL, config.ADMIN_TOKEN, ssl_verify=False)

# Собираем полный список репозиториев: базовые + автодискавери namespace
repos = dict(config.PROJECTS)
try:
    found = gl.discover_projects(config.PROJECT_NAMESPACE) or {}
    repos.update(found)
    print(f"Найдено репозиториев в namespace '{config.PROJECT_NAMESPACE}': {len(found)}")
except Exception as e:
    print(f"Автодискавери не удался ({e}); работаю по базовым проектам.")

print(f"Режим: {'PURGE (только закрытие)' if PURGE else 'merge-иначе-close'}"
      f"{' + удаление веток' if DEL_BRANCHES else ''}\n")

merged = closed = branches = 0
for name, pid in repos.items():
    mrs = gl.get_open_mrs(pid)
    if not mrs:
        print(f"  {name}: нет открытых MR")
        continue
    print(f"  {name}: {len(mrs)} открытых MR")
    for mr in mrs:
        iid = mr.get("iid")
        title = (mr.get("title", "") or "")[:50]
        src = mr.get("source_branch")
        ok = False
        if not PURGE:
            if mr.get("draft") or mr.get("work_in_progress") or title.lower().startswith(("draft:", "wip:")):
                try: gl.mark_mr_ready(pid, iid)
                except Exception: pass
            ok = gl.merge_mr(pid, iid)
        if ok:
            merged += 1
            print(f"    ✓ merged  !{iid}: {title}")
        else:
            if gl.close_mr(pid, iid):
                closed += 1
                print(f"    ✗ closed  !{iid}: {title}")
            if DEL_BRANCHES and src and src not in ("main", "master"):
                try:
                    if gl.delete_branch(pid, src):
                        branches += 1
                except Exception:
                    pass

print(f"\nИтого: смержено {merged}, закрыто {closed}"
      + (f", удалено веток {branches}" if DEL_BRANCHES else ""))
print("Очередь очищена — можно запускать симулятор с чистого листа.")
