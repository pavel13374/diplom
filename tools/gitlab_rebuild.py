#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ПОЛНАЯ ПЕРЕСБОРКА GITLAB — чистый лист без «pending deletion».

Что делает:
  1) возвращает группу soc-team из запланированного удаления (restore);
  2) НАСОВСЕМ удаляет ВСЕ проекты в группе (в т.ч. висящие *-deletion_scheduled-*);
  3) создаёт заново 12 репозиториев, всех сотрудников (разблокирует), выдаёт им
     доступ Owner и сеет стартовый контент — через штатный bootstrap.

После этого группа чистая, репозитории нормальные, команда пишет в них, а не в
удаляемые. Требуется АДМИН-токен (config.ADMIN_TOKEN).

  python gitlab_rebuild.py          # спросит подтверждение
  python gitlab_rebuild.py --yes    # без вопросов
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
import argparse

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

import config
from gitlab_client import GitLabClient
import urllib3
urllib3.disable_warnings()

gl = GitLabClient(config.GITLAB_URL, config.ADMIN_TOKEN, ssl_verify=False)
H = {"PRIVATE-TOKEN": config.ADMIN_TOKEN}
NS = config.PROJECT_NAMESPACE


def list_all_projects(gid):
    out, page = [], 1
    while True:
        d = gl._api("GET", f"/groups/{gid}/projects",
                    params={"per_page": 100, "page": page, "include_subgroups": True})
        if not isinstance(d, list) or not d:
            break
        out += d
        if len(d) < 100:
            break
        page += 1
    return out


def perm_delete(pid, full_path):
    params = {"permanently_remove": "true"}
    if full_path:
        params["full_path"] = full_path
    try:
        r = gl.session.delete(f"{gl.url}/api/v4/projects/{pid}", params=params, headers=H, timeout=30)
        if r.status_code in (200, 202, 204):
            return True
        r2 = gl.session.delete(f"{gl.url}/api/v4/projects/{pid}", headers=H, timeout=25)
        return r2.status_code in (200, 202, 204)
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser(description="Полная пересборка GitLab-среды")
    ap.add_argument("--yes", action="store_true")
    args = ap.parse_args()

    print("=" * 60)
    print("  ПОЛНАЯ ПЕРЕСБОРКА GITLAB")
    print("=" * 60)
    print(f"  GitLab:   {config.GITLAB_URL}")
    print(f"  группа:   {NS}")
    print("  Действия: восстановить группу → снести ВСЕ проекты НАСОВСЕМ →")
    print("            создать 12 репозиториев, сотрудников, доступы, контент.")
    if not args.yes:
        if input("\nПродолжить? [y/N] ").strip().lower() not in ("y", "yes", "д", "да"):
            print("Отменено."); return

    # 1) группа: вернуть из scheduled или создать
    gid = gl.group_id(NS)
    if gid:
        if gl.restore_group(gid):
            print(f"  ↺ группа {NS} восстановлена из запланированного удаления")
    else:
        gid, created = gl.ensure_group(NS, "SOC Team",
                                       "Security Operations Center — Detection as Code")
        print(f"  + группа {NS} создана (id {gid})" if created else f"  группа id {gid}")
    if not gid:
        print("  ✗ не удалось получить/создать группу — проверь права токена (нужен admin).")
        return

    # 2) снести ВСЕ проекты насовсем
    projs = list_all_projects(gid)
    print(f"\n  проектов в группе: {len(projs)} — удаляю насовсем…")
    killed = 0
    for pr in projs:
        if perm_delete(pr["id"], pr.get("path_with_namespace")):
            killed += 1
            print(f"    ✗ {pr.get('path_with_namespace')}")
    print(f"  удалено проектов: {killed}/{len(projs)}")

    # 3) создать всё заново штатным bootstrap (репо + юзеры + доступы + контент)
    print("\n  Пересоздаю среду (репозитории, сотрудники, доступы)…")
    config.WORK_REPOS = dict(config.PROJECTS)   # сброс дискавери
    import bootstrap
    summary = bootstrap.ensure_environment(gl)
    print("\n" + "=" * 60)
    print(f"  ГОТОВО: репозиториев {summary.get('repos')}, "
          f"новых {summary.get('new_repos')}, сотрудников {summary.get('users')}, "
          f"доступов {summary.get('members')}")
    print("  Теперь запускай мир (START_PANEL.bat → Запустить → Start).")
    print("=" * 60)


if __name__ == "__main__":
    main()
