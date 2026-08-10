"""
GitLab API клиент.
Все операции с GitLab проходят через этот модуль.
"""
import time
import logging
import requests
import urllib.parse
from typing import Optional

logger = logging.getLogger(__name__)


class GitLabClient:
    def __init__(self, url: str, token: str, ssl_verify: bool = False):
        self.url     = url.rstrip("/")
        self.token   = token
        self.verify  = ssl_verify
        self.session = requests.Session()
        self.session.verify = ssl_verify
        self.session.headers.update({"PRIVATE-TOKEN": token})
        if not ssl_verify:
            import urllib3
            urllib3.disable_warnings()

    # ------------------------------------------------------------------
    # Вспомогательные методы
    # ------------------------------------------------------------------
    def _api(self, method: str, path: str, **kwargs) -> dict:
        url = f"{self.url}/api/v4{path}"
        for attempt in range(3):
            try:
                r = self.session.request(method, url, timeout=30, **kwargs)
                if r.status_code == 429:
                    wait = int(r.headers.get("Retry-After", 10))
                    logger.warning(f"Rate limited, waiting {wait}s")
                    time.sleep(wait)
                    continue
                if r.status_code in (403, 404):
                    # «нет доступа / не найдено» — это НОРМАЛЬНО для проверок
                    # существования (get_project_id/group_id): без ретраев и без ERROR.
                    logger.debug(f"{method} {path}: {r.status_code}")
                    return {}
                r.raise_for_status()
                return r.json() if r.text else {}
            except requests.exceptions.HTTPError as e:
                if attempt == 2:
                    logger.error(f"API error {method} {path}: {e} — {r.text[:200]}")
                    return {}
                time.sleep(2 ** attempt)
            except Exception as e:
                logger.error(f"Request failed {method} {path}: {e}")
                return {}
        return {}

    def _encode(self, path: str) -> str:
        return urllib.parse.quote(path, safe="")

    def create_named_token(self, user_id, name, scopes=None):
        """Создаёт ещё один impersonation-токен пользователю (аномалия rogue token)."""
        import datetime as _dt
        data = self._api("POST", f"/users/{user_id}/impersonation_tokens", json={
            "name": name,
            "scopes": scopes or ["api"],
            "expires_at": (_dt.date.today() + _dt.timedelta(days=90)).isoformat(),
        })
        return bool(data.get("token"))

    def server_time(self):
        """Время GitLab-сервера из HTTP-заголовка Date (или None)."""
        try:
            r = self.session.get(f"{self.url}/api/v4/version", timeout=10)
            return r.headers.get("Date")
        except Exception:
            logger.warning("не удалось получить время сервера GitLab", exc_info=True,
                           extra={"ctx": {"url": self.url}})
            return None

    # ------------------------------------------------------------------
    # Файлы в репозитории
    # ------------------------------------------------------------------
    def file_exists(self, project_id: int, path: str, ref: str = "main") -> bool:
        r = self.session.get(
            f"{self.url}/api/v4/projects/{project_id}/repository/files/{self._encode(path)}",
            params={"ref": ref},
            timeout=15,
        )
        return r.status_code == 200

    def get_file(self, project_id: int, path: str, ref: str = "main") -> Optional[str]:
        """Содержимое файла. 404 (нет файла) -> None без ERROR в лог."""
        url = f"{self.url}/api/v4/projects/{project_id}/repository/files/{self._encode(path)}"
        try:
            r = self.session.get(url, params={"ref": ref}, timeout=20)
            if r.status_code != 200:
                return None
            import base64
            return base64.b64decode(r.json().get("content", "")).decode("utf-8")
        except Exception:
            logger.warning("не удалось прочитать файл из GitLab", exc_info=True,
                           extra={"ctx": {"project_id": project_id, "path": path,
                                          "ref": ref}})
            return None

    def push_file(self, project_id: int, path: str, content: str,
                  message: str, branch: str = "main",
                  user_token: Optional[str] = None) -> bool:
        headers = {"PRIVATE-TOKEN": user_token or self.token,
                   "Content-Type": "application/json"}
        encoded = self._encode(path)
        exists  = self.file_exists(project_id, path, branch)
        method  = "PUT" if exists else "POST"
        url     = f"{self.url}/api/v4/projects/{project_id}/repository/files/{encoded}"

        import json
        payload = json.dumps({
            "branch":         branch,
            "content":        content,
            "commit_message": message,
        })
        r = self.session.request(method, url, data=payload,
                                 headers=headers, timeout=30)
        ok = r.status_code in (200, 201)
        if not ok:
            logger.warning(f"push_file failed ({r.status_code}): {r.text[:200]}")
        return ok

    def list_files(self, project_id: int, path: str = "",
                   ref: str = "main", recursive: bool = True) -> list:
        """Список файлов. 404 (пустой репозиторий / нет пути) -> [] без ошибок в лог."""
        params = {"ref": ref, "recursive": str(recursive).lower(), "per_page": 100}
        if path:
            params["path"] = path
        try:
            r = self.session.get(
                f"{self.url}/api/v4/projects/{project_id}/repository/tree",
                params=params, timeout=20)
            if r.status_code == 200:
                return [f["path"] for f in r.json() if f.get("type") == "blob"]
            logger.warning("листинг дерева отклонён",
                           extra={"ctx": {"project_id": project_id, "path": path,
                                          "status": r.status_code,
                                          "body": r.text[:200]}})
        except Exception:
            logger.warning("листинг дерева не удался", exc_info=True,
                           extra={"ctx": {"project_id": project_id, "path": path}})
        return []

    # ------------------------------------------------------------------
    # Ветки
    # ------------------------------------------------------------------
    def branch_exists(self, project_id: int, branch: str) -> bool:
        r = self.session.get(
            f"{self.url}/api/v4/projects/{project_id}/repository/branches/{self._encode(branch)}",
            timeout=15,
        )
        return r.status_code == 200

    def create_branch(self, project_id: int, branch: str,
                      ref: str = "main",
                      user_token: Optional[str] = None) -> bool:
        headers = {"PRIVATE-TOKEN": user_token or self.token}
        r = self.session.post(
            f"{self.url}/api/v4/projects/{project_id}/repository/branches",
            json={"branch": branch, "ref": ref},
            headers=headers, timeout=15,
        )
        ok = r.status_code in (200, 201)
        if not ok and "already exists" not in r.text:
            logger.warning(f"create_branch failed: {r.text[:150]}")
        return ok

    def delete_branch(self, project_id: int, branch: str,
                      user_token: Optional[str] = None) -> bool:
        headers = {"PRIVATE-TOKEN": user_token or self.token}
        r = self.session.delete(
            f"{self.url}/api/v4/projects/{project_id}/repository/branches/{self._encode(branch)}",
            headers=headers, timeout=15,
        )
        return r.status_code == 204

    # ------------------------------------------------------------------
    # Merge Requests
    # ------------------------------------------------------------------
    def create_mr(self, project_id: int, source: str, title: str,
                  description: str = "", assignee_id: int = 0,
                  user_token: Optional[str] = None) -> int:
        headers = {"PRIVATE-TOKEN": user_token or self.token}
        payload = {
            "source_branch":          source,
            "target_branch":          "main",
            "title":                  title,
            "description":            description,
            "remove_source_branch":   True,
        }
        if assignee_id:
            payload["assignee_id"] = assignee_id
        r = self.session.post(
            f"{self.url}/api/v4/projects/{project_id}/merge_requests",
            json=payload, headers=headers, timeout=15,
        )
        if r.status_code in (200, 201):
            return r.json().get("iid", 0)
        logger.warning(f"create_mr failed: {r.text[:150]}")
        return 0

    def comment_mr(self, project_id: int, mr_iid: int, body: str,
                   user_token: Optional[str] = None) -> bool:
        headers = {"PRIVATE-TOKEN": user_token or self.token}
        r = self.session.post(
            f"{self.url}/api/v4/projects/{project_id}/merge_requests/{mr_iid}/notes",
            json={"body": body}, headers=headers, timeout=15,
        )
        return r.status_code in (200, 201)

    def merge_mr(self, project_id: int, mr_iid: int,
                 user_token: Optional[str] = None) -> bool:
        """Надёжный merge: пробуем токеном автора, при ошибке прав/состояния
        (401/403/405/406/409/422) ждём и повторяем админ-токеном.
        405 обычно = «пайплайн должен пройти», поэтому проекты заранее
        настраиваются через ensure_project_settings()."""
        url = f"{self.url}/api/v4/projects/{project_id}/merge_requests/{mr_iid}/merge"
        # Ждём, пока GitLab досчитает mergeability. Мержить при
        # merge_status=checking бессмысленно: сервер стабильно отвечает 405,
        # и в статистике мира копились «ошибки» на ровном месте.
        for _ in range(6):
            try:
                _mr = self.get_mr(project_id, mr_iid) or {}
            except Exception:
                logger.warning("не удалось дождаться mergeability — пробуем мержить "
                               "как есть", exc_info=True,
                               extra={"ctx": {"project_id": project_id,
                                              "mr_iid": mr_iid}})
                break
            if str(_mr.get("merge_status") or "") not in ("checking", "unchecked", ""):
                break
            time.sleep(1.2)
        attempts = [user_token or self.token, self.token]
        last = ""
        for i, tok in enumerate(attempts):
            r = self.session.put(url, json={"should_remove_source_branch": True},
                                 headers={"PRIVATE-TOKEN": tok}, timeout=15)
            if r.status_code in (200, 201):
                return True
            last = r.text[:150]
            if r.status_code == 405:
                # mergeability ещё пересчитывается — короткая пауза и ретрай
                time.sleep(2)
                r2 = self.session.put(url, json={"should_remove_source_branch": True},
                                      headers={"PRIVATE-TOKEN": self.token}, timeout=15)
                if r2.status_code in (200, 201):
                    return True
                last = r2.text[:150]
                # ветка могла отстать от main — пробуем rebase и ещё раз merge
                try:
                    if self.rebase_mr(project_id, mr_iid):
                        r3 = self.session.put(url, json={"should_remove_source_branch": True},
                                              headers={"PRIVATE-TOKEN": self.token}, timeout=15)
                        if r3.status_code in (200, 201):
                            return True
                        last = r3.text[:150]
                except Exception:
                    logger.warning("повторный merge после rebase не удался",
                                   exc_info=True,
                                   extra={"ctx": {"project_id": project_id,
                                                  "mr_iid": mr_iid}})
            elif r.status_code not in (401, 403, 406, 409, 422):
                break  # иные ошибки повтором не лечатся
        why = ""
        try:
            d = self.get_mr(project_id, mr_iid) or {}
            why = (f" [state={d.get('state')}, merge_status={d.get('merge_status')}"
                   f", draft={d.get('draft') or d.get('work_in_progress')}"
                   f", conflicts={d.get('has_conflicts')}, src={d.get('source_branch')}]")
        except Exception:
            logger.debug("не удалось дочитать состояние MR для диагностики",
                         exc_info=True,
                         extra={"ctx": {"project_id": project_id, "mr_iid": mr_iid}})
        logger.warning("merge_mr не удался",
                       extra={"ctx": {"project_id": project_id, "mr_iid": mr_iid,
                                      "последняя_ошибка": str(last)[:200],
                                      "состояние": why}})
        return False

    def rebase_mr(self, project_id: int, mr_iid: int) -> bool:
        """Асинхронный rebase MR на target. Возвращает True, если прошёл без
        конфликта (помогает «отставшим» от main веткам стать mergeable)."""
        url = f"{self.url}/api/v4/projects/{project_id}/merge_requests/{mr_iid}/rebase"
        r = self.session.put(url, headers={"PRIVATE-TOKEN": self.token}, timeout=15)
        if r.status_code not in (200, 202):
            return False
        for _ in range(6):                       # ждём завершения rebase
            time.sleep(1.2)
            d = self.get_mr(project_id, mr_iid) or {}
            if not d.get("rebase_in_progress"):
                return not d.get("merge_error")
        return False

    def ensure_project_settings(self, project_id: int) -> bool:
        """Делает merge надёжным: снимает требование успешного пайплайна и
        резолва дискуссий (иначе без раннера merge -> 405). Вызывается один раз
        на старте под админ-токеном."""
        r = self.session.put(
            f"{self.url}/api/v4/projects/{project_id}",
            json={
                "only_allow_merge_if_pipeline_succeeds": False,
                "only_allow_merge_if_all_discussions_are_resolved": False,
                "remove_source_branch_after_merge": True,
                "merge_method": "merge",
            },
            headers={"PRIVATE-TOKEN": self.token}, timeout=15,
        )
        return r.status_code in (200, 201)

    def bootstrap_projects(self, project_ids) -> int:
        ok = 0
        for pid in project_ids:
            try:
                if self.ensure_project_settings(pid):
                    ok += 1
            except Exception as e:
                logger.warning(f"bootstrap project {pid} failed: {e}")
        return ok

    # ------------------------------------------------------------------
    # Членство в проектах (выдача прав Owner)
    # ------------------------------------------------------------------
    def ensure_member(self, project_id, user_id, access_level=50) -> bool:
        """Идемпотентно делает пользователя участником проекта с нужным уровнем.
        Если уже есть с >= уровнем — ничего не делает. 50=Owner, 40=Maintainer."""
        cur = self.session.get(
            f"{self.url}/api/v4/projects/{project_id}/members/{user_id}", timeout=15)
        if cur.status_code == 200:
            try:
                if cur.json().get("access_level", 0) >= access_level:
                    return True
            except Exception:
                logger.warning("не удалось разобрать текущий уровень доступа — "
                               "выставляем заново", exc_info=True,
                               extra={"ctx": {"project_id": project_id,
                                              "user_id": user_id}})
            # повысить уровень
            r = self.session.put(
                f"{self.url}/api/v4/projects/{project_id}/members/{user_id}",
                json={"access_level": access_level},
                headers={"PRIVATE-TOKEN": self.token}, timeout=15)
            return r.status_code in (200, 201)
        # добавить нового участника
        for lvl in (access_level, 40):
            r = self.session.post(
                f"{self.url}/api/v4/projects/{project_id}/members",
                json={"user_id": user_id, "access_level": lvl},
                headers={"PRIVATE-TOKEN": self.token}, timeout=15)
            if r.status_code in (200, 201):
                return True
            if r.status_code == 409:   # уже участник
                return True
        return False

    def ensure_members(self, project_ids, user_ids, access_level=50) -> int:
        cnt = 0
        for pid in project_ids:
            for uid in user_ids:
                try:
                    if self.ensure_member(pid, uid, access_level):
                        cnt += 1
                except Exception as e:
                    logger.warning(f"ensure_member {uid}@{pid} failed: {e}")
        return cnt

    # ------------------------------------------------------------------
    # Пользователи (создание новых сотрудников)
    # ------------------------------------------------------------------
    def find_user(self, username):
        data = self._api("GET", "/users", params={"username": username})
        if isinstance(data, list) and data:
            return data[0].get("id")
        return None

    def create_user(self, username, name, email=None, role="engineer"):
        import secrets
        email = email or f"{username}@soc.local"
        data = self._api("POST", "/users", json={
            "email": email, "username": username, "name": name,
            "password": "Sim_" + secrets.token_urlsafe(12) + "!1",
            "skip_confirmation": True,
        })
        return data.get("id")

    def ensure_user(self, username, name, email=None):
        """Возвращает id пользователя (создаёт, если нет). Нужны admin-права."""
        uid = self.find_user(username)
        if uid:
            return uid, False
        uid = self.create_user(username, name, email)
        return uid, bool(uid)

    # ------------------------------------------------------------------
    # Группы и создание репозиториев
    # ------------------------------------------------------------------
    def group_id(self, namespace):
        data = self._api("GET", f"/groups/{self._encode(namespace)}")
        return data.get("id") if isinstance(data, dict) else None

    def create_group(self, path, name=None, description=""):
        """Создать группу (namespace). Нужны права на создание групп."""
        try:
            r = self._api("POST", "/groups", json={
                "name": name or path, "path": path,
                "description": description, "visibility": "private"})
            return r.get("id") if isinstance(r, dict) else None
        except Exception:
            logger.error("не удалось создать группу — репозитории будут создаваться "
                         "вне группы или не создадутся вовсе", exc_info=True,
                         extra={"ctx": {"path": path, "name": name}})
            return None

    def unblock_user(self, uid):
        """Снять блокировку с пользователя (после пересоздания он может быть blocked)."""
        try:
            r = self.session.post(f"{self.url}/api/v4/users/{uid}/unblock",
                                  headers={"PRIVATE-TOKEN": self.token}, timeout=15)
            return r.status_code in (200, 201, 204)
        except Exception:
            logger.warning("не удалось разблокировать пользователя", exc_info=True,
                           extra={"ctx": {"user_id": uid}})
            return False

    def restore_group(self, gid):
        """Отменить запланированное удаление группы (вернуть из scheduled)."""
        try:
            r = self.session.post(f"{self.url}/api/v4/groups/{gid}/restore",
                                  headers={"PRIVATE-TOKEN": self.token}, timeout=15)
            return r.status_code in (200, 201, 204)
        except Exception:
            logger.warning("не удалось восстановить группу", exc_info=True,
                           extra={"ctx": {"group_id": gid}})
            return False

    def restore_project(self, pid):
        try:
            r = self.session.post(f"{self.url}/api/v4/projects/{pid}/restore",
                                  headers={"PRIVATE-TOKEN": self.token}, timeout=15)
            return r.status_code in (200, 201, 204)
        except Exception:
            logger.warning("не удалось восстановить проект", exc_info=True,
                           extra={"ctx": {"project_id": pid}})
            return False

    def ensure_group(self, namespace, name=None, description=""):
        """Вернуть (id, created). Создаёт группу, если её нет."""
        gid = self.group_id(namespace)
        if gid:
            return gid, False
        gid = self.create_group(namespace, name, description)
        return gid, bool(gid)

    def get_project_id(self, namespace, name):
        data = self._api("GET", f"/projects/{self._encode(namespace + '/' + name)}")
        return data.get("id") if isinstance(data, dict) else None

    def ensure_project(self, name, namespace, namespace_id=None):
        """Возвращает (id, created). Создаёт репозиторий с README, если его нет."""
        pid = self.get_project_id(namespace, name)
        if pid:
            return pid, False
        payload = {"name": name, "path": name, "initialize_with_readme": True,
                   "visibility": "private", "default_branch": "main"}
        if namespace_id:
            payload["namespace_id"] = namespace_id
        data = self._api("POST", "/projects", json=payload)
        return data.get("id"), bool(data.get("id"))

    # ------------------------------------------------------------------
    # Автодискавери существующих репозиториев
    # ------------------------------------------------------------------
    def discover_projects(self, namespace=None) -> dict:
        """Возвращает {path: id} проектов (по namespace, иначе все видимые)."""
        found = {}
        data = None
        if namespace:
            data = self._api("GET", f"/groups/{self._encode(namespace)}/projects",
                             params={"per_page": 100, "simple": True,
                                     "include_subgroups": True, "archived": False})
        if not isinstance(data, list) or not data:
            data = self._api("GET", "/projects",
                             params={"per_page": 100, "simple": True, "membership": False})
        if isinstance(data, list):
            for pr in data:
                pwn = pr.get("path_with_namespace", "")
                if namespace and not pwn.startswith(namespace + "/"):
                    continue
                name = pr.get("path") or pr.get("name", "")
                # НЕ подхватывать репозитории, запланированные на удаление
                if ("deletion_scheduled" in name or "deletion_scheduled" in pwn
                        or pr.get("marked_for_deletion_on") or pr.get("marked_for_deletion_at")):
                    continue
                if name and pr.get("id"):
                    found[name] = pr["id"]
        return found

    def close_mr(self, project_id: int, mr_iid: int,
                 user_token: Optional[str] = None) -> bool:
        headers = {"PRIVATE-TOKEN": user_token or self.token}
        r = self.session.put(
            f"{self.url}/api/v4/projects/{project_id}/merge_requests/{mr_iid}",
            json={"state_event": "close"},
            headers=headers, timeout=15,
        )
        return r.status_code in (200, 201)

    def mark_mr_ready(self, project_id: int, mr_iid: int,
                      user_token: Optional[str] = None) -> bool:
        """Снимает статус Draft/WIP с MR (через очистку префикса заголовка),
        чтобы его можно было смержить."""
        mr = self.get_mr(project_id, mr_iid) or {}
        title = str(mr.get("title", "") or "")
        new = title
        for pref in ("Draft: ", "Draft:", "WIP: ", "WIP:"):
            if new.lower().startswith(pref.lower()):
                new = new[len(pref):].lstrip()
                break
        if new == title and not (mr.get("draft") or mr.get("work_in_progress")):
            return True  # уже ready
        headers = {"PRIVATE-TOKEN": user_token or self.token}
        r = self.session.put(
            f"{self.url}/api/v4/projects/{project_id}/merge_requests/{mr_iid}",
            json={"title": new or "ready"}, headers=headers, timeout=15)
        return r.status_code in (200, 201)

    def get_open_mrs(self, project_id: int) -> list:
        data = self._api("GET",
            f"/projects/{project_id}/merge_requests",
            params={"state": "opened", "per_page": 50})
        return data if isinstance(data, list) else []

    def get_mr(self, project_id: int, mr_iid: int) -> dict:
        return self._api("GET",
            f"/projects/{project_id}/merge_requests/{mr_iid}")

    # ------------------------------------------------------------------
    # Impersonation tokens
    # ------------------------------------------------------------------
    def get_or_create_user_token(self, user_id: int, username: str) -> str:
        # Сначала пробуем получить существующий активный токен
        tokens = self._api("GET", f"/users/{user_id}/impersonation_tokens",
                           params={"state": "active"})
        if isinstance(tokens, list):
            for t in tokens:
                if t.get("name") == "simulator-token":
                    tok = t.get("token")
                    if tok:
                        return tok

        # Создаём новый
        data = self._api("POST", f"/users/{user_id}/impersonation_tokens",
                         json={
                             "name":       "simulator-token",
                             "scopes":     ["api"],
                             "expires_at": (__import__("datetime").date.today() + __import__("datetime").timedelta(days=364)).isoformat(),
                         })
        tok = data.get("token", "")
        if tok:
            logger.info(f"Created impersonation token for {username}")
        else:
            logger.error(f"Failed to create token for {username}: {data}")
        return tok

    # ------------------------------------------------------------------
    # Коммиты (batch)
    # ------------------------------------------------------------------
    def create_commit(self, project_id: int, branch: str, message: str,
                      actions: list, user_token: Optional[str] = None) -> bool:
        """
        actions = [{"action": "create"|"update"|"delete",
                    "file_path": "...", "content": "..."}]
        """
        headers = {"PRIVATE-TOKEN": user_token or self.token}
        r = self.session.post(
            f"{self.url}/api/v4/projects/{project_id}/repository/commits",
            json={"branch": branch, "commit_message": message, "actions": actions},
            headers=headers, timeout=30,
        )
        ok = r.status_code in (200, 201)
        if not ok:
            logger.warning(f"create_commit failed: {r.text[:200]}")
        return ok

    # ------------------------------------------------------------------
    # Реверт коммита
    # ------------------------------------------------------------------
    def revert_commit(self, project_id: int, sha: str, branch: str = "main",
                      user_token: Optional[str] = None) -> bool:
        headers = {"PRIVATE-TOKEN": user_token or self.token}
        r = self.session.post(
            f"{self.url}/api/v4/projects/{project_id}/repository/commits/{sha}/revert",
            json={"branch": branch},
            headers=headers, timeout=15,
        )
        return r.status_code in (200, 201)

    def get_commits(self, project_id: int, ref: str = "main",
                    per_page: int = 20) -> list:
        data = self._api("GET",
            f"/projects/{project_id}/repository/commits",
            params={"ref_name": ref, "per_page": per_page})
        return data if isinstance(data, list) else []

    # ------------------------------------------------------------------
    # Merge Request — расширенные операции
    # ------------------------------------------------------------------
    def update_mr(self, project_id: int, mr_iid: int, fields: dict,
                  user_token: Optional[str] = None) -> bool:
        headers = {"PRIVATE-TOKEN": user_token or self.token}
        r = self.session.put(
            f"{self.url}/api/v4/projects/{project_id}/merge_requests/{mr_iid}",
            json=fields, headers=headers, timeout=15,
        )
        return r.status_code in (200, 201)

    def approve_mr(self, project_id: int, mr_iid: int,
                   user_token: Optional[str] = None) -> bool:
        """Настоящий approve через Approvals API (нужен токен апрувера)."""
        headers = {"PRIVATE-TOKEN": user_token or self.token}
        r = self.session.post(
            f"{self.url}/api/v4/projects/{project_id}/merge_requests/{mr_iid}/approve",
            headers=headers, timeout=15,
        )
        return r.status_code in (200, 201)

    def award_emoji(self, project_id: int, target_type: str, target_iid: int,
                    name: str, user_token: Optional[str] = None) -> bool:
        """target_type: 'merge_requests' | 'issues'. name: 'thumbsup','rocket'..."""
        headers = {"PRIVATE-TOKEN": user_token or self.token}
        r = self.session.post(
            f"{self.url}/api/v4/projects/{project_id}/{target_type}/{target_iid}/award_emoji",
            json={"name": name}, headers=headers, timeout=15,
        )
        return r.status_code in (200, 201)

    # ------------------------------------------------------------------
    # Issues
    # ------------------------------------------------------------------
    def create_issue(self, project_id: int, title: str, description: str = "",
                     labels=None, milestone_id: int = 0, assignee_id: int = 0,
                     created_at: Optional[str] = None,
                     user_token: Optional[str] = None) -> int:
        headers = {"PRIVATE-TOKEN": user_token or self.token}
        payload = {"title": title, "description": description}
        if labels:
            payload["labels"] = ",".join(labels)
        if milestone_id:
            payload["milestone_id"] = milestone_id
        if assignee_id:
            payload["assignee_id"] = assignee_id
        if created_at:
            payload["created_at"] = created_at   # учитывается только для admin
        r = self.session.post(
            f"{self.url}/api/v4/projects/{project_id}/issues",
            json=payload, headers=headers, timeout=15,
        )
        if r.status_code in (200, 201):
            return r.json().get("iid", 0)
        logger.warning(f"create_issue failed: {r.text[:150]}")
        return 0

    def comment_issue(self, project_id: int, issue_iid: int, body: str,
                      user_token: Optional[str] = None) -> bool:
        headers = {"PRIVATE-TOKEN": user_token or self.token}
        r = self.session.post(
            f"{self.url}/api/v4/projects/{project_id}/issues/{issue_iid}/notes",
            json={"body": body}, headers=headers, timeout=15,
        )
        return r.status_code in (200, 201)

    def update_issue(self, project_id: int, issue_iid: int, fields: dict,
                     user_token: Optional[str] = None) -> bool:
        headers = {"PRIVATE-TOKEN": user_token or self.token}
        r = self.session.put(
            f"{self.url}/api/v4/projects/{project_id}/issues/{issue_iid}",
            json=fields, headers=headers, timeout=15,
        )
        return r.status_code in (200, 201)

    def get_open_issues(self, project_id: int) -> list:
        data = self._api("GET", f"/projects/{project_id}/issues",
                         params={"state": "opened", "per_page": 50})
        return data if isinstance(data, list) else []

    # ------------------------------------------------------------------
    # Labels / Milestones
    # ------------------------------------------------------------------
    def ensure_label(self, project_id: int, name: str, color: str = "#428BCA",
                     user_token: Optional[str] = None) -> bool:
        headers = {"PRIVATE-TOKEN": user_token or self.token}
        r = self.session.post(
            f"{self.url}/api/v4/projects/{project_id}/labels",
            json={"name": name, "color": color}, headers=headers, timeout=15,
        )
        return r.status_code in (200, 201, 409)  # 409 = уже есть

    def ensure_milestone(self, project_id: int, title: str,
                         user_token: Optional[str] = None) -> int:
        # ищем существующий
        data = self._api("GET", f"/projects/{project_id}/milestones",
                         params={"title": title})
        if isinstance(data, list) and data:
            return data[0].get("id", 0)
        headers = {"PRIVATE-TOKEN": user_token or self.token}
        r = self.session.post(
            f"{self.url}/api/v4/projects/{project_id}/milestones",
            json={"title": title}, headers=headers, timeout=15,
        )
        if r.status_code in (200, 201):
            return r.json().get("id", 0)
        return 0

    # ------------------------------------------------------------------
    # Tags / Releases
    # ------------------------------------------------------------------
    def create_tag(self, project_id: int, tag: str, ref: str = "main",
                   message: str = "", user_token: Optional[str] = None) -> bool:
        headers = {"PRIVATE-TOKEN": user_token or self.token}
        r = self.session.post(
            f"{self.url}/api/v4/projects/{project_id}/repository/tags",
            json={"tag_name": tag, "ref": ref, "message": message},
            headers=headers, timeout=15,
        )
        return r.status_code in (200, 201)

    def create_release(self, project_id: int, tag: str, name: str,
                       description: str, user_token: Optional[str] = None) -> bool:
        headers = {"PRIVATE-TOKEN": user_token or self.token}
        r = self.session.post(
            f"{self.url}/api/v4/projects/{project_id}/releases",
            json={"tag_name": tag, "name": name, "description": description},
            headers=headers, timeout=15,
        )
        ok = r.status_code in (200, 201)
        if not ok:
            logger.warning(f"create_release failed: {r.text[:150]}")
        return ok
