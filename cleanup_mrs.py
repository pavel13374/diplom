#!/usr/bin/env python3
"""
Утилита: закрывает все открытые MR перед запуском симулятора.
Запускать один раз если накопились незамерженные MR от предыдущих скриптов.
"""
import config
from gitlab_client import GitLabClient
import urllib3
urllib3.disable_warnings()

gl = GitLabClient(config.GITLAB_URL, config.ADMIN_TOKEN, ssl_verify=False)

print("Закрываем открытые MR...")
total = 0
for name, pid in config.PROJECTS.items():
    mrs = gl.get_open_mrs(pid)
    if mrs:
        print(f"  {name}: {len(mrs)} открытых MR")
        for mr in mrs:
            iid = mr.get("iid")
            title = mr.get("title", "")[:50]
            # Пробуем смержить, если не получается — закрываем
            ok = gl.merge_mr(pid, iid)
            if ok:
                print(f"    ✓ Merged  !{iid}: {title}")
            else:
                gl.close_mr(pid, iid)
                print(f"    ✗ Closed  !{iid}: {title}")
            total += 1
    else:
        print(f"  {name}: нет открытых MR")

print(f"\nИтого обработано: {total} MR")
