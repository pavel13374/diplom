"""
Инициализация среды GitLab на первом старте (идемпотентно):
  * автодискавери существующих репозиториев;
  * создание НОВЫХ репозиториев (NEW_REPOS) в группе;
  * создание НОВЫХ сотрудников (NEW_USERS) и добавление их в команду;
  * настройка проектов для надёжного merge;
  * выдача Owner всем участникам команды во всех репозиториях.

Если что-то уже существует — пропускается. Возвращает краткую сводку.
"""
import logging
import config

logger = logging.getLogger("bootstrap")


def ensure_environment(gl):
    summary = {"repos": 0, "new_repos": 0, "users": 0, "new_users": 0, "members": 0}

    # 1) подхватить существующие репозитории
    if config.AUTO_DISCOVER_PROJECTS:
        try:
            disc = gl.discover_projects(config.PROJECT_NAMESPACE)
            config.set_discovered(disc)
        except Exception as e:
            logger.warning(f"discover failed: {e}")

    # 2) создать недостающие репозитории
    if config.CREATE_REPOS:
        gid = None
        try:
            gid, gcreated = gl.ensure_group(config.PROJECT_NAMESPACE, "SOC Team",
                                            "Security Operations Center — Detection as Code")
            if gcreated:
                logger.info(f"Создана группа: {config.PROJECT_NAMESPACE} (id {gid})")
            elif not gid:
                logger.warning(f"Не удалось найти/создать группу {config.PROJECT_NAMESPACE} "
                               f"— нужны права на создание групп у токена")
        except Exception as e:
            logger.warning(f"ensure_group failed: {e}")
        # ВСЕ репозитории: базовые (config.PROJECTS) + тематические (NEW_REPOS).
        # Базовые тоже пересоздаём, если их снесли полным сбросом.
        wanted = list(config.PROJECTS.keys())
        wanted += [n for n in config.NEW_REPOS if n not in wanted]
        for name in wanted:
            try:
                pid, created = gl.ensure_project(name, config.PROJECT_NAMESPACE, gid)
                if pid:
                    config.set_discovered({name: pid})
                    if created:
                        summary["new_repos"] += 1
                        logger.info(f"Создан репозиторий: {name} (id {pid})")
            except Exception as e:
                logger.warning(f"ensure_project {name} failed: {e}")
    summary["repos"] = len(config.WORK_REPOS)

    # 3) создать недостающих сотрудников
    if config.CREATE_USERS:
        # ВСЕ участники команды: базовые (из config.USERS, кроме бота) + новые.
        # Пересоздаём, если были удалены полным сбросом; иначе идемпотентно.
        team = [{"username": u, "name": i.get("name", u), "email": i.get("email"),
                 "role": i.get("role")} for u, i in list(config.USERS.items())
                if i.get("role") != "bot"]
        team += [u for u in config.NEW_USERS if u["username"] not in config.USERS]
        for u in team:
            uname = u["username"]
            try:
                uid, created = gl.ensure_user(uname, u.get("name") or uname, u.get("email"))
                if uid:
                    config.add_user(uname, uid, name=u.get("name"), role=u.get("role"))
                    if gl.unblock_user(uid):
                        logger.info(f"Разблокирован сотрудник: {uname}")
                    if created:
                        summary["new_users"] += 1
                        logger.info(f"Создан сотрудник: {uname} ({u.get('name')}, {u.get('role')})")
            except Exception as e:
                logger.warning(f"ensure_user {uname} failed: {e}")

    # пересобрать состав команды и ротацию on-call
    config.TEAM_USERS = [u for u, i in config.USERS.items() if i.get("role") != "bot"]
    eng = [u for u in config.engineer_usernames()]
    if eng:
        config.ONCALL_ROTATION = eng
    summary["users"] = len([u for u in config.USERS if config.USERS[u].get("role") != "bot"])

    # 4) настроить проекты + выдать Owner всем
    try:
        summary["settings"] = gl.bootstrap_projects(config.WORK_REPOS.values())
    except Exception as e:
        logger.warning(f"bootstrap_projects failed: {e}")
    if config.GRANT_OWNER:
        uids = [config.USERS[u]["id"] for u in config.TEAM_USERS
                if u in config.USERS and config.USERS[u].get("id")]
        try:
            summary["members"] = gl.ensure_members(config.WORK_REPOS.values(), uids,
                                                   config.OWNER_ACCESS_LEVEL)
        except Exception as e:
            logger.warning(f"ensure_members failed: {e}")

    # 5) посеять стартовый контент в пустые специализированные репозитории
    try:
        summary["seeded"] = seed_repos(gl)
    except Exception as e:
        logger.warning(f"seed_repos failed: {e}")

    logger.info(f"Среда готова: репозиториев {summary['repos']} "
                f"(новых {summary['new_repos']}), сотрудников {summary['users']} "
                f"(новых {summary['new_users']}), назначений прав {summary['members']}")
    return summary


def seed_repos(gl):
    """Засевает стартовый контент в специализированные репозитории, если их
    профильная папка ещё пуста. Пишет прямо в main под админ-токеном (без MR)."""
    from content import seed as seedmod
    seeded = 0
    plan = seedmod.build()
    for name, (key_dir, files) in plan.items():
        pid = config.WORK_REPOS.get(name)
        if not pid:
            continue
        try:
            if gl.list_files(pid, key_dir):
                continue  # уже не пустой — не трогаем
        except Exception:
            pass
        pushed = 0
        for path, content in files:
            try:
                if gl.push_file(pid, path, content, f"seed: initial {path}", "main"):
                    pushed += 1
            except Exception:
                pass
        if pushed:
            seeded += 1
            logger.info(f"Посев репозитория {name}: добавлено файлов {pushed}")
    return seeded
