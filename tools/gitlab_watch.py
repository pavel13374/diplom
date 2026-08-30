#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
НАБЛЮДАТЕЛЬ ЗА РЕАЛЬНЫМ GITLAB — «поймай меня сам».

Следит за твоим настоящим GitLab и превращает ТВОИ РУЧНЫЕ действия (пуши,
коммиты, удаления файлов) в события для детектора. После этого всё, что ты
сделаешь руками в GitLab (например, закоммитишь файл с секретом или удалишь кучу
файлов ночью), попадёт в тот же журнал и защита на :8788 тебя ЗАМЕТИТ.

Как это работает:
  • опрашивает Events API (action=pushed) по всем репозиториям namespace;
  • для каждого нового пуша берёт diff коммита, считает признаки контента
    (энтропия, секрет-regex, имя файла) — как для обычного события;
  • пишет событие с временем коммита (важно для off-hours) и автором;
  • детектор (правила + UEBA) на :8788 это разбирает — БЕЗ всякой «разметки»,
    сам решает, атака это или нет.

Запуск:
    python gitlab_watch.py           # следить непрерывно (Ctrl+C — выход)
    python gitlab_watch.py --once    # один проход по свежим коммитам
    python gitlab_watch.py --since-now   # игнорировать историю, ловить только НОВОЕ

Требуется доступ к GitLab (config.GITLAB_URL/ADMIN_TOKEN).
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
import json
import time
import argparse
from datetime import datetime

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

import config
import simclock
import events
from gitlab_client import GitLabClient

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_FP = os.path.join(BASE, "data", ".gitlab_watch.json")


def _load_state():
    try:
        return json.load(open(STATE_FP, encoding="utf-8"))
    except Exception:
        return {"seen": {}}


def _save_state(st):
    try:
        os.makedirs(os.path.dirname(STATE_FP), exist_ok=True)
        json.dump(st, open(STATE_FP, "w", encoding="utf-8"))
    except Exception:
        pass


def _added_content(diff_text):
    """Собрать добавленные строки из diff одного файла в «контент»."""
    lines = []
    for ln in (diff_text or "").splitlines():
        if ln.startswith("+") and not ln.startswith("+++"):
            lines.append(ln[1:])
    return "\n".join(lines)


def _role_of(username):
    info = config.USERS.get(username)
    return info.get("role") if info else "external"


def _emit_commit(gl, pid, pname, ev):
    """По одному push-событию: взять diff коммита и эмитить push/file_delete."""
    pd = ev.get("push_data") or {}
    sha = pd.get("commit_to")
    ref = (pd.get("ref") or "").replace("refs/heads/", "") or "main"
    actor = ev.get("author_username") or ev.get("author", {}).get("username") or "unknown"
    when = ev.get("created_at") or datetime.now().isoformat()
    try:
        dt = datetime.fromisoformat(when.replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        dt = datetime.now()
    if not sha:
        return 0
    try:
        diffs = gl._api("GET", f"/projects/{pid}/repository/commits/{sha}/diff")
    except Exception as e:
        print(f"  (diff {pname}@{sha[:8]} не получен: {e})")
        return 0
    if not isinstance(diffs, list):
        return 0

    # ВРЕМЯ коммита — чтобы off-hours/ночь считались правильно
    simclock.now = lambda d=dt: d
    n = 0
    for d in diffs:
        path = d.get("new_path") or d.get("old_path") or "?"
        if d.get("deleted_file"):
            events.emit("file_delete", actor=actor, role=_role_of(actor),
                        project=pname, path=path, branch=ref, message=f"commit {sha[:8]}",
                        extra={"source": "gitlab_watch", "gitlab_ok": True})
            n += 1
            continue
        content = _added_content(d.get("diff", ""))
        extra = {"source": "gitlab_watch", "gitlab_ok": True,
                 "bytes": len(content), "lines": content.count("\n") + 1,
                 "ext": path.rsplit(".", 1)[-1] if "." in path else ""}
        try:
            import content_features
            extra.update(content_features.analyze(content, path))
        except Exception:
            pass
        events.emit("push", actor=actor, role=_role_of(actor),
                    project=pname, path=path, branch=ref, message=f"commit {sha[:8]}",
                    extra=extra)
        n += 1
        if extra.get("n_regex_hits"):
            print(f"  🔴 СЕКРЕТ в {pname}/{path} (автор @{actor}) — детектор это увидит!")
    return n


def scan(gl, projects, st, since_now=False):
    total = 0
    for pname, pid in projects.items():
        try:
            evs = gl._api("GET", f"/projects/{pid}/events",
                          params={"action": "pushed", "per_page": 20})
        except Exception as e:
            print(f"  (события {pname} не получены: {e})")
            continue
        if not isinstance(evs, list):
            continue
        seen = set(st["seen"].get(str(pid), []))
        for ev in reversed(evs):   # от старых к новым
            pd = ev.get("push_data") or {}
            sha = pd.get("commit_to")
            if not sha or sha in seen:
                continue
            if since_now and str(pid) not in st["seen"]:
                # первый проход в режиме since-now: просто запомнить, не эмитить
                seen.add(sha); continue
            total += _emit_commit(gl, pid, pname, ev)
            seen.add(sha)
        st["seen"][str(pid)] = list(seen)[-200:]
    return total


def main():
    ap = argparse.ArgumentParser(description="Watch real GitLab -> events for detector")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--since-now", action="store_true", help="ловить только новое, историю игнорировать")
    ap.add_argument("--interval", type=int, default=15)
    args = ap.parse_args()

    events.init()
    # часы нужны только для штампа времени; реальное время коммита подставляем сами
    try:
        simclock.init(simclock.SimClock(start_sim=datetime.now(), scale=1.0,
                      work_start=config.WORK_HOURS_START, work_end=config.WORK_HOURS_END,
                      work_days=config.WORK_DAYS, fast_forward_offhours=False))
    except Exception:
        pass

    gl = GitLabClient(config.GITLAB_URL, config.ADMIN_TOKEN, ssl_verify=config.gitlab_verify())
    projects = dict(config.PROJECTS)
    try:
        projects.update(gl.discover_projects(config.PROJECT_NAMESPACE) or {})
    except Exception:
        pass

    print("=" * 60)
    print("  НАБЛЮДАТЕЛЬ ЗА GITLAB — «поймай меня сам»")
    print("=" * 60)
    print(f"  GitLab: {config.GITLAB_URL}")
    print(f"  репозиториев под наблюдением: {len(projects)}")
    print("  Сделай что-нибудь руками в GitLab (см. подсказки ниже) —")
    print("  и смотри Purple Team Console на :8788 → Алерты / Инциденты.")
    print("-" * 60)
    print("  ЧТО ПОПРОБОВАТЬ, ЧТОБЫ ТЕБЯ ПОЙМАЛИ:")
    print("   1) закоммить файл config/prod.env со строкой вида")
    print("      AWS_SECRET_ACCESS_KEY=AKIA1234567890ABCDEFGHIJ")
    print("   2) добавь приватный ключ id_rsa (-----BEGIN PRIVATE KEY-----)")
    print("   3) сделай пуш поздно вечером/в выходной в непривычный репозиторий")
    print("   4) удали разом много файлов одним коммитом")
    print("=" * 60)

    st = _load_state()
    if args.since_now:
        scan(gl, projects, st, since_now=True); _save_state(st)
        print("Запомнил текущее состояние. Теперь ловлю только НОВЫЕ коммиты.")
    while True:
        try:
            n = scan(gl, projects, st)
            _save_state(st)
            if n:
                print(f"[{datetime.now():%H:%M:%S}] новых событий из GitLab: {n} "
                      "(смотри :8788)")
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[watch] ошибка: {e}")
        if args.once:
            break
        time.sleep(max(5, args.interval))
    print("Наблюдатель остановлен.")


if __name__ == "__main__":
    main()
