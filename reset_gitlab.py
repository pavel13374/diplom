#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Откат GitLab к чистому состоянию для симулятора.

По умолчанию (безопасный режим) — убирает накопленный «мусор» прогонов:
    • закрывает ВСЕ открытые merge request'ы во всех репозиториях;
    • удаляет все ветки, кроме main/master.

Дополнительные уровни (флагами):
    --files        очистить файлы репозиториев до одного README.md
    --nuke-repos   удалить созданные репозитории (config.NEW_REPOS)
    --nuke-users   удалить созданных сотрудников (config.NEW_USERS)
    --local        удалить локальное состояние: .sim_state.json, data/events.jsonl, logs/
    --all          = --files --local  (репозитории и юзеры НЕ трогает)
    --yes          не спрашивать подтверждение

Примеры:
    python reset_gitlab.py                 # закрыть MR + удалить ветки
    python reset_gitlab.py --files --local # ещё и очистить файлы и локальный стейт
    python reset_gitlab.py --all
    python reset_gitlab.py --nuke-repos --nuke-users --yes   # полный снос созданного
"""
import os
import sys
import shutil
import config
from gitlab_client import GitLabClient
import urllib3
urllib3.disable_warnings()

ARGS = set(sys.argv[1:])
DO_FILES = "--files" in ARGS or "--all" in ARGS
DO_LOCAL = "--local" in ARGS or "--all" in ARGS
DO_NUKE_REPOS = "--nuke-repos" in ARGS
DO_NUKE_USERS = "--nuke-users" in ARGS
YES = "--yes" in ARGS

BASE = os.path.dirname(os.path.abspath(__file__))
gl = GitLabClient(config.GITLAB_URL, config.ADMIN_TOKEN, ssl_verify=False)
H = {"PRIVATE-TOKEN": config.ADMIN_TOKEN}


def all_repos():
    repos = dict(config.PROJECTS)
    try:
        repos.update(gl.discover_projects(config.PROJECT_NAMESPACE) or {})
    except Exception as e:
        print(f"  (автодискавери не удался: {e})")
    return repos


def close_mrs(pid):
    n = 0
    for mr in gl.get_open_mrs(pid):
        iid = mr.get("iid")
        if iid and gl.close_mr(pid, iid):
            n += 1
    return n


def delete_branches(pid):
    n = 0
    try:
        r = gl.session.get(f"{gl.url}/api/v4/projects/{pid}/repository/branches",
                           params={"per_page": 100}, headers=H, timeout=20)
        branches = r.json() if r.status_code == 200 else []
    except Exception:
        branches = []
    for b in branches:
        name = b.get("name")
        if name in ("main", "master"):
            continue
        if gl.delete_branch(pid, name):
            n += 1
    return n


def wipe_files(pid):
    """Удаляет все файлы кроме README.md одним коммитом в main."""
    files = gl.list_files(pid, "")
    victims = [f for f in files if f.lower() != "readme.md"]
    if not victims:
        return 0
    actions = [{"action": "delete", "file_path": f} for f in victims]
    ok = gl.create_commit(pid, "main", "reset: wipe repository to README", actions)
    return len(victims) if ok else 0


def nuke_repo(pid):
    r = gl.session.delete(f"{gl.url}/api/v4/projects/{pid}", headers=H, timeout=20)
    return r.status_code in (200, 202, 204)


def find_user_id(username):
    try:
        r = gl.session.get(f"{gl.url}/api/v4/users", params={"username": username},
                           headers=H, timeout=15)
        data = r.json() if r.status_code == 200 else []
        return data[0]["id"] if data else None
    except Exception:
        return None


def nuke_user(username):
    uid = find_user_id(username)
    if not uid:
        return False
    r = gl.session.delete(f"{gl.url}/api/v4/users/{uid}",
                          params={"hard_delete": "true"}, headers=H, timeout=20)
    return r.status_code in (200, 202, 204)


def main():
    plan = ["закрыть открытые MR", "удалить ветки (кроме main)"]
    if DO_FILES:      plan.append("ОЧИСТИТЬ файлы репозиториев до README")
    if DO_NUKE_REPOS: plan.append(f"УДАЛИТЬ репозитории: {', '.join(config.NEW_REPOS)}")
    if DO_NUKE_USERS: plan.append(f"УДАЛИТЬ сотрудников: {', '.join(u['username'] for u in config.NEW_USERS)}")
    if DO_LOCAL:      plan.append("удалить локальный стейт (.sim_state.json, data/events.jsonl, logs/)")

    print("GitLab:", config.GITLAB_URL)
    print("Будет выполнено:")
    for p in plan:
        print("  •", p)
    if not YES:
        ans = input("\nПродолжить? [y/N] ").strip().lower()
        if ans not in ("y", "yes", "д", "да"):
            print("Отменено.")
            return

    repos = all_repos()
    print(f"\nРепозиториев: {len(repos)}")
    tot_mr = tot_br = tot_files = 0
    for name, pid in repos.items():
        mr = close_mrs(pid)
        br = delete_branches(pid)
        fl = wipe_files(pid) if DO_FILES else 0
        tot_mr += mr; tot_br += br; tot_files += fl
        print(f"  {name:20} MR закрыто {mr:3} · веток удалено {br:3}"
              + (f" · файлов удалено {fl:3}" if DO_FILES else ""))

    if DO_NUKE_REPOS:
        for name in config.NEW_REPOS:
            pid = repos.get(name) or config.WORK_REPOS.get(name)
            if pid and nuke_repo(pid):
                print(f"  ✗ удалён репозиторий {name}")

    if DO_NUKE_USERS:
        for u in config.NEW_USERS:
            if nuke_user(u["username"]):
                print(f"  ✗ удалён сотрудник {u['username']}")

    if DO_LOCAL:
        for rel in (config.STATE_FILE, "data/events.jsonl"):
            fp = os.path.join(BASE, rel)
            if os.path.exists(fp):
                os.remove(fp); print(f"  ✗ удалён {rel}")
        logs = os.path.join(BASE, "logs")
        if os.path.isdir(logs):
            shutil.rmtree(logs, ignore_errors=True); print("  ✗ очищена папка logs/")

    print(f"\nИтого: закрыто MR {tot_mr}, удалено веток {tot_br}"
          + (f", удалено файлов {tot_files}" if DO_FILES else ""))
    print("Откат завершён. Можно запускать симулятор с чистого листа (run.bat).")


if __name__ == "__main__":
    main()
