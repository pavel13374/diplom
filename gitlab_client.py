"""
GitLab API клиент.
Все операции с GitLab проходят через этот модуль.
"""
import time
import random
import logging
import requests
import urllib.parse
from typing import Optional

logger = logging.getLogger(__name__)


#: Сколько страниц максимум пролистываем в одном перечислении и сколько
#: элементов суммарно. Верхняя граница нужна против репозитория/инстанса,
#: который отвечает бесконечным списком: без неё сканирование одного проекта
#: могло бы не завершиться никогда.
MAX_PAGES = 50
MAX_ITEMS = 5000

#: Верхняя граница ожидания по Retry-After. GitLab за прокси может прислать
#: сутки; блокировать на них поток ингеста нельзя.
MAX_RETRY_AFTER_S = 120


def _retry_after_seconds(value, default=10.0):
    """Retry-After в обеих формах, разрешённых RFC 9110: секунды и HTTP-дата.

    Раньше здесь стоял голый int(): на форме-дате он бросал ValueError, общий
    except его глушил, и ОТВЕТ О ПРЕВЫШЕНИИ ЛИМИТА превращался в «данных нет».
    То есть при активном rate limiting репозиторий выглядел пустым.
    """
    if value is None:
        return default
    s = str(value).strip()
    try:
        return max(0.0, min(float(s), MAX_RETRY_AFTER_S))
    except ValueError:
        pass
    try:
        from email.utils import parsedate_to_datetime
        import datetime as _dt
        when = parsedate_to_datetime(s)
        if when is None:
            return default
        now = _dt.datetime.now(when.tzinfo) if when.tzinfo else _dt.datetime.now()
        return max(0.0, min((when - now).total_seconds(), MAX_RETRY_AFTER_S))
    except (TypeError, ValueError, OverflowError):
        return default


#: Адреса, по которым уже сказали, что проверка TLS выключена.
_TLS_WARNED = set()


class GitLabClient:
    """Клиент GitLab.

    ssl_verify=None означает «взять из конфигурации» (config.gitlab_verify()).
    Явные True/False остаются для тестов и для осознанного обхода.
    """

    def __init__(self, url: str, token: str, ssl_verify=None):
        self.url     = (url or "").rstrip("/")
        self.token   = token
        if ssl_verify is None:
            try:
                import config as _cfg
                ssl_verify = _cfg.gitlab_verify()
            except Exception:
                ssl_verify = True
        self.verify  = ssl_verify
        self.session = requests.Session()
        self.session.verify = ssl_verify
        self.session.headers.update({"PRIVATE-TOKEN": token})
        if ssl_verify is False:
            # Глушим предупреждения ТОЛЬКО когда проверку выключили осознанно,
            # и один раз говорим об этом вслух: администраторский PAT уходит по
            # непроверенному каналу, и это должно быть видно в журнале, а не
            # спрятано вместе с предупреждением urllib3.
            #
            # Именно ОДИН раз на адрес: клиент создаётся в нескольких местах
            # (мир, ресинк, инструменты), и предупреждение на каждый экземпляр
            # превращается в фон, который перестают читать.
            import urllib3
            urllib3.disable_warnings()
        if ssl_verify is False and self.url not in _TLS_WARNED:
            _TLS_WARNED.add(self.url)
            logger.warning(
                "проверка TLS-сертификата GitLab ОТКЛЮЧЕНА — токен уходит по "
                "непроверенному каналу",
                extra={"ctx": {"url": self.url,
                               "подсказка": "SOC_GITLAB_CA_BUNDLE=<path.pem> "
                                            "лучше, чем SOC_GITLAB_VERIFY_TLS=off"}})

    # ------------------------------------------------------------------
    # Вспомогательные методы
    # ------------------------------------------------------------------
    def _request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Единая политика сети: таймаут, ретраи, 429, никаких исключений наверх.

        Возвращает Response или None.

        Раньше _api() применял эту политику, а примерно тридцать методов ходили
        через self.session.* напрямую: без ретраев, без обработки 429 и с
        исключением, улетающим в вызывающего, который ждёт bool. Сеть моргнула —
        активность «упала», а причина не отличалась от «GitLab отказал».
        """
        kwargs.setdefault("timeout", 30)
        delay = 1.0
        last = None
        for attempt in range(3):
            try:
                r = self.session.request(method, url, **kwargs)
            except (requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout) as e:
                # Именно эти отказы и осмысленно повторять — раньше они,
                # наоборот, возвращали пустоту сразу, а повторялся HTTPError.
                last = e
                if attempt == 2:
                    logger.warning("сеть GitLab: %s %s — %s", method, url, e,
                                   extra={"ctx": {"attempt": attempt + 1}})
                    return None
                time.sleep(delay + random.uniform(0, 0.3))
                delay *= 2
                continue
            except requests.exceptions.RequestException as e:
                logger.warning("запрос к GitLab не выполнен: %s %s — %s",
                               method, url, e)
                return None
            if r.status_code == 429:
                wait = _retry_after_seconds(r.headers.get("Retry-After"))
                logger.warning("GitLab rate limit, ждём %.1fs", wait,
                               extra={"ctx": {"url": url, "attempt": attempt + 1}})
                time.sleep(wait)
                continue
            if r.status_code >= 500 and attempt < 2:
                time.sleep(delay + random.uniform(0, 0.3))
                delay *= 2
                continue
            return r
        if last is not None:
            logger.warning("GitLab недоступен после ретраев: %s", last)
        return None

    @staticmethod
    def _ok(r, extra=()) -> bool:
        return r is not None and r.status_code in ((200, 201) + tuple(extra))

    def _api(self, method: str, path: str, **kwargs) -> dict:
        url = f"{self.url}/api/v4{path}"
        r = self._request(method, url, **kwargs)
        if r is None:
            return {}
        if r.status_code in (403, 404):
            # «нет доступа / не найдено» — это НОРМАЛЬНО для проверок
            # существования (get_project_id/group_id): без ретраев и без ERROR.
            logger.debug(f"{method} {path}: {r.status_code}")
            return {}
        if r.status_code >= 400:
            logger.error("API error %s %s: %s", method, path, r.status_code,
                         extra={"ctx": {"status": r.status_code,
                                        "body": (r.text or "")[:200]}})
            return {}
        try:
            return r.json() if r.text else {}
        except ValueError:
            logger.error("GitLab вернул не-JSON на %s %s", method, path,
                         extra={"ctx": {"content_type": r.headers.get("Content-Type"),
                                        "body": (r.text or "")[:200]}})
            return {}

    def _api_paged(self, path: str, params=None, max_items=MAX_ITEMS) -> tuple:
        """Перечисление СО ВСЕМИ страницами. Возвращает (items, truncated).

        Пагинации в клиенте не было вообще: каждый листинг брал per_page=100 и
        возвращал первую страницу. Для продукта, который ищет секреты в
        репозиториях, это тихая слепая зона неограниченного размера —
        репозиторий из 300 файлов сканировался на треть, и НИГДЕ не было
        сказано, что просмотр неполный. Тем же способом терялись проекты
        инстанса, открытые MR и ветки при чистке.
        """
        params = dict(params or {})
        params.setdefault("per_page", 100)
        out = []
        page = 1
        while page <= MAX_PAGES:
            params["page"] = page
            r = self._request("GET", f"{self.url}/api/v4{path}", params=params)
            if r is None or r.status_code >= 400:
                if page == 1:
                    logger.debug("листинг %s отклонён: %s", path,
                                 r.status_code if r is not None else "нет ответа")
                break
            try:
                chunk = r.json()
            except ValueError:
                break
            if not isinstance(chunk, list) or not chunk:
                break
            out.extend(chunk)
            if len(out) >= max_items:
                logger.warning("листинг обрезан по лимиту элементов",
                               extra={"ctx": {"path": path, "limit": max_items}})
                return out[:max_items], True
            nxt = r.headers.get("X-Next-Page") or ""
            if not nxt.strip():
                return out, False
            try:
                page = int(nxt)
            except ValueError:
                return out, False
        truncated = page > MAX_PAGES
        if truncated:
            logger.warning("листинг обрезан по лимиту страниц",
                           extra={"ctx": {"path": path, "limit": MAX_PAGES}})
        return out, truncated

    def diagnose(self) -> dict:
        """ПОЧЕМУ связь с GitLab не работает — конкретно, а не «нет ответа».

        Обычный _api() возвращает пустой словарь на ЛЮБОЙ отказ: и на протухший
        токен (401), и на неверный адрес, и на отказ TLS, и на таймаут. Наверху
        от этого оставалось только «нет ответа /version (проверь URL/токен)» —
        сообщение, по которому нельзя понять, что чинить.

        Здесь ошибка НЕ глушится: возвращается код ответа, класс исключения и
        первые строки тела. Зовётся при старте мира и кнопкой «Проверить связь».

        Возвращает {ok, reason, detail, url, status, version, user}.
        """
        import requests as _rq
        out = {"ok": False, "reason": "", "detail": "", "url": self.url,
               "status": None, "version": None, "user": None}
        if not self.url:
            out["reason"] = "не задан адрес GitLab"
            out["detail"] = "GITLAB_URL пуст — впишите адрес в web_config.json"
            return out
        if not self.token:
            out["reason"] = "не задан токен"
            out["detail"] = "ADMIN_TOKEN пуст — впишите токен в web_config.json"
            return out
        try:
            # НАМЕРЕННО через session, а не через _request: _request гасит
            # исключения и ретраит, а diagnose существует ровно для того,
            # чтобы НАЗВАТЬ причину — отказ TLS, таймаут, DNS.
            r = self.session.get(f"{self.url}/api/v4/version", timeout=15)
            out["status"] = r.status_code
            if r.status_code == 200:
                data = r.json()
                out["ok"] = True
                out["version"] = data.get("version")
                out["reason"] = f"GitLab {data.get('version', '?')}"
                # Кто мы под этим токеном и хватает ли прав.
                try:
                    u = self.session.get(f"{self.url}/api/v4/user", timeout=15)
                    if u.status_code == 200:
                        d = u.json()
                        out["user"] = d.get("username")
                        if not d.get("is_admin"):
                            out["detail"] = (f"токен принадлежит @{d.get('username')} "
                                             "без прав администратора: часть операций "
                                             "(создание пользователей, групп) будет отказывать")
                except _rq.RequestException:
                    logger.warning("не удалось прочитать /user", exc_info=True)
                return out
            if r.status_code == 401:
                out["reason"] = "токен не принят (401)"
                out["detail"] = ("ADMIN_TOKEN недействителен или просрочен. "
                                 "Создайте новый personal access token со scope api "
                                 "и впишите в web_config.json")
            elif r.status_code == 403:
                out["reason"] = "доступ запрещён (403)"
                out["detail"] = "токен есть, но прав не хватает — нужен scope api"
            elif r.status_code in (404, 502, 503):
                out["reason"] = f"GitLab отвечает {r.status_code}"
                out["detail"] = ("адрес указывает не на GitLab либо сервис ещё "
                                 "поднимается: " + (r.text or "")[:200])
            else:
                out["reason"] = f"неожиданный ответ {r.status_code}"
                out["detail"] = (r.text or "")[:200]
        except _rq.exceptions.SSLError as e:
            out["reason"] = "отказ TLS"
            # Названия причины мало: у пользователя лабораторный GitLab с
            # самоподписанным сертификатом, и он должен из сообщения понять,
            # что делать, а не идти искать переменную окружения по исходникам.
            out["detail"] = (
                f"сертификат не принят: {e}. "
                "Если это ваш собственный GitLab с самоподписанным "
                "сертификатом — укажите корневой сертификат "
                "(SOC_GITLAB_CA_BUNDLE=<путь к ca.pem>) либо выключите проверку "
                "для этого адреса: GITLAB_VERIFY_TLS=off в настройках "
                "(или SOC_GITLAB_VERIFY_TLS=off)")
        except _rq.exceptions.ConnectTimeout:
            out["reason"] = "таймаут подключения"
            out["detail"] = "адрес есть, но соединение не устанавливается — проверьте сеть и порт"
        except _rq.exceptions.ConnectionError as e:
            out["reason"] = "нет соединения"
            out["detail"] = f"хост недоступен (DNS/сеть/порт): {e}"
        except Exception as e:
            out["reason"] = f"{type(e).__name__}"
            out["detail"] = str(e)[:300]
        logger.warning("диагностика GitLab: %s — %s", out["reason"], out["detail"])
        return out

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
            r = self._request("GET", f"{self.url}/api/v4/version", timeout=10)
            return r.headers.get("Date") if r is not None else None
        except Exception:
            logger.warning("не удалось получить время сервера GitLab", exc_info=True,
                           extra={"ctx": {"url": self.url}})
            return None

    # ------------------------------------------------------------------
    # Файлы в репозитории
    # ------------------------------------------------------------------
    def file_exists(self, project_id: int, path: str, ref: str = "main") -> bool:
        r = self._request("GET", 
            f"{self.url}/api/v4/projects/{project_id}/repository/files/{self._encode(path)}",
            params={"ref": ref},
            timeout=15,
        )
        return r is not None and r.status_code == 200

    def get_file(self, project_id: int, path: str, ref: str = "main") -> Optional[str]:
        """Содержимое файла. 404 (нет файла) -> None без ERROR в лог."""
        url = f"{self.url}/api/v4/projects/{project_id}/repository/files/{self._encode(path)}"
        try:
            r = self._request("GET", url, params={"ref": ref}, timeout=20)
            if r is None or r.status_code != 200:
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
        ok = self._ok(r)
        if not ok:
            logger.warning("push_file failed", extra={"ctx": {
                "project_id": project_id, "path": path, "branch": branch,
                "status": (r.status_code if r is not None else None),
                "body": ((r.text or "") if r is not None else "нет ответа")[:200]}})
        return ok

    def list_files(self, project_id: int, path: str = "",
                   ref: str = "main", recursive: bool = True) -> list:
        """ВСЕ файлы дерева, а не первая страница.

        Раньше здесь стоял per_page=100 без листания страниц: репозиторий из
        трёхсот файлов просматривался на треть, причём молча — ни в ответе, ни
        в интерфейсе не было признака, что просмотр неполный. Для продукта,
        который ищет секреты в репозиториях, это слепая зона без границ.
        """
        files, truncated = self.list_files_ex(project_id, path, ref, recursive)
        return files

    def list_files_ex(self, project_id: int, path: str = "",
                      ref: str = "main", recursive: bool = True) -> tuple:
        """(файлы, обрезано_ли). Отдельный метод, чтобы вызывающий, которому
        важна полнота просмотра, мог об этом узнать и сказать аналитику."""
        params = {"ref": ref, "recursive": str(recursive).lower()}
        if path:
            params["path"] = path
        items, truncated = self._api_paged(
            f"/projects/{project_id}/repository/tree", params=params)
        if truncated:
            logger.warning("дерево репозитория просмотрено НЕ ПОЛНОСТЬЮ",
                           extra={"ctx": {"project_id": project_id, "path": path,
                                          "получено": len(items)}})
        return [f["path"] for f in items
                if isinstance(f, dict) and f.get("type") == "blob"], truncated

    # ------------------------------------------------------------------
    # Ветки
    # ------------------------------------------------------------------
    def branch_exists(self, project_id: int, branch: str) -> bool:
        r = self._request("GET", 
            f"{self.url}/api/v4/projects/{project_id}/repository/branches/{self._encode(branch)}",
            timeout=15,
        )
        return r is not None and r.status_code == 200

    def create_branch(self, project_id: int, branch: str,
                      ref: str = "main",
                      user_token: Optional[str] = None) -> bool:
        headers = {"PRIVATE-TOKEN": user_token or self.token}
        r = self._request("POST", 
            f"{self.url}/api/v4/projects/{project_id}/repository/branches",
            json={"branch": branch, "ref": ref},
            headers=headers, timeout=15,
        )
        ok = self._ok(r)
        body = (r.text or "") if r is not None else "нет ответа"
        if not ok and "already exists" not in body:
            logger.warning("create_branch failed",
                           extra={"ctx": {"project_id": project_id,
                                          "branch": branch, "body": body[:150]}})
        return ok

    def delete_branch(self, project_id: int, branch: str,
                      user_token: Optional[str] = None) -> bool:
        headers = {"PRIVATE-TOKEN": user_token or self.token}
        r = self._request("DELETE", 
            f"{self.url}/api/v4/projects/{project_id}/repository/branches/{self._encode(branch)}",
            headers=headers, timeout=15,
        )
        return r is not None and r.status_code == 204

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
        r = self._request("POST", 
            f"{self.url}/api/v4/projects/{project_id}/merge_requests",
            json=payload, headers=headers, timeout=15,
        )
        if self._ok(r):
            return r.json().get("iid", 0)
        logger.warning("create_mr failed", extra={"ctx": {
            "project_id": project_id, "source": source,
            "body": ((r.text or "") if r is not None else "нет ответа")[:150]}})
        return 0

    def comment_mr(self, project_id: int, mr_iid: int, body: str,
                   user_token: Optional[str] = None) -> bool:
        headers = {"PRIVATE-TOKEN": user_token or self.token}
        r = self._request("POST", 
            f"{self.url}/api/v4/projects/{project_id}/merge_requests/{mr_iid}/notes",
            json={"body": body}, headers=headers, timeout=15,
        )
        return self._ok(r)

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
            r = self._request("PUT", url, json={"should_remove_source_branch": True},
                                 headers={"PRIVATE-TOKEN": tok}, timeout=15)
            if self._ok(r):
                return True
            last = ((r.text or "") if r is not None else "нет ответа")[:150]
            status = r.status_code if r is not None else 0
            if status == 405:
                # mergeability ещё пересчитывается — короткая пауза и ретрай
                time.sleep(2)
                r2 = self._request("PUT", url, json={"should_remove_source_branch": True},
                                      headers={"PRIVATE-TOKEN": self.token}, timeout=15)
                if self._ok(r2):
                    return True
                last = ((r2.text or "") if r2 is not None else "нет ответа")[:150]
                # ветка могла отстать от main — пробуем rebase и ещё раз merge
                try:
                    if self.rebase_mr(project_id, mr_iid):
                        r3 = self._request("PUT", url, json={"should_remove_source_branch": True},
                                              headers={"PRIVATE-TOKEN": self.token}, timeout=15)
                        if self._ok(r3):
                            return True
                        last = ((r3.text or "") if r3 is not None else "нет ответа")[:150]
                except Exception:
                    logger.warning("повторный merge после rebase не удался",
                                   exc_info=True,
                                   extra={"ctx": {"project_id": project_id,
                                                  "mr_iid": mr_iid}})
            elif status not in (401, 403, 406, 409, 422):
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
        r = self._request("PUT", url, headers={"PRIVATE-TOKEN": self.token}, timeout=15)
        if not self._ok(r, (202,)):
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
        r = self._request("PUT", 
            f"{self.url}/api/v4/projects/{project_id}",
            json={
                "only_allow_merge_if_pipeline_succeeds": False,
                "only_allow_merge_if_all_discussions_are_resolved": False,
                "remove_source_branch_after_merge": True,
                "merge_method": "merge",
            },
            headers={"PRIVATE-TOKEN": self.token}, timeout=15,
        )
        return self._ok(r)

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
        cur = self._request("GET", 
            f"{self.url}/api/v4/projects/{project_id}/members/{user_id}", timeout=15)
        if cur is not None and cur.status_code == 200:
            try:
                if cur.json().get("access_level", 0) >= access_level:
                    return True
            except Exception:
                logger.warning("не удалось разобрать текущий уровень доступа — "
                               "выставляем заново", exc_info=True,
                               extra={"ctx": {"project_id": project_id,
                                              "user_id": user_id}})
            # повысить уровень
            r = self._request("PUT", 
                f"{self.url}/api/v4/projects/{project_id}/members/{user_id}",
                json={"access_level": access_level},
                headers={"PRIVATE-TOKEN": self.token}, timeout=15)
            return self._ok(r)
        # добавить нового участника
        for lvl in (access_level, 40):
            r = self._request("POST", 
                f"{self.url}/api/v4/projects/{project_id}/members",
                json={"user_id": user_id, "access_level": lvl},
                headers={"PRIVATE-TOKEN": self.token}, timeout=15)
            if self._ok(r):
                return True
            if r is not None and r.status_code == 409:   # уже участник
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
            r = self._request("POST", f"{self.url}/api/v4/users/{uid}/unblock",
                                  headers={"PRIVATE-TOKEN": self.token}, timeout=15)
            return self._ok(r, (204,))
        except Exception:
            logger.warning("не удалось разблокировать пользователя", exc_info=True,
                           extra={"ctx": {"user_id": uid}})
            return False

    def restore_group(self, gid):
        """Отменить запланированное удаление группы (вернуть из scheduled)."""
        try:
            r = self._request("POST", f"{self.url}/api/v4/groups/{gid}/restore",
                                  headers={"PRIVATE-TOKEN": self.token}, timeout=15)
            return self._ok(r, (204,))
        except Exception:
            logger.warning("не удалось восстановить группу", exc_info=True,
                           extra={"ctx": {"group_id": gid}})
            return False

    def restore_project(self, pid):
        try:
            r = self._request("POST", f"{self.url}/api/v4/projects/{pid}/restore",
                                  headers={"PRIVATE-TOKEN": self.token}, timeout=15)
            return self._ok(r, (204,))
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
            data, _ = self._api_paged(
                f"/groups/{self._encode(namespace)}/projects",
                params={"simple": True, "include_subgroups": True, "archived": False})
        if not isinstance(data, list) or not data:
            data, _ = self._api_paged("/projects",
                                      params={"simple": True, "membership": False})
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

    def list_branches(self, project_id: int) -> list:
        """Все ветки проекта. Появился, потому что маршруты сброса в webapp.py
        ходили в API мимо клиента и останавливались на первой сотне веток,
        сообщая при этом об успешной полной очистке."""
        items, truncated = self._api_paged(
            f"/projects/{project_id}/repository/branches")
        if truncated:
            logger.warning("список веток обрезан",
                           extra={"ctx": {"project_id": project_id}})
        return [b.get("name") for b in items
                if isinstance(b, dict) and b.get("name")]

    def close_mr(self, project_id: int, mr_iid: int,
                 user_token: Optional[str] = None) -> bool:
        headers = {"PRIVATE-TOKEN": user_token or self.token}
        r = self._request("PUT", 
            f"{self.url}/api/v4/projects/{project_id}/merge_requests/{mr_iid}",
            json={"state_event": "close"},
            headers=headers, timeout=15,
        )
        return self._ok(r)

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
        r = self._request("PUT", 
            f"{self.url}/api/v4/projects/{project_id}/merge_requests/{mr_iid}",
            json={"title": new or "ready"}, headers=headers, timeout=15)
        return self._ok(r)

    def get_open_mrs(self, project_id: int) -> list:
        # Со всеми страницами: с per_page=50 без листания «открытых MR» больше
        # полусотни просто не существовало — ни для счётчика бэклога, ни для
        # чистки репозиториев.
        items, _ = self._api_paged(f"/projects/{project_id}/merge_requests",
                                   params={"state": "opened"})
        return items

    def get_mr(self, project_id: int, mr_iid: int) -> dict:
        return self._api("GET",
            f"/projects/{project_id}/merge_requests/{mr_iid}")

    def get_mr_approvals(self, project_id: int, mr_iid: int) -> Optional[int]:
        """Сколько апрувов у MR на момент вызова.

        ОТДЕЛЬНАЯ РУЧКА, А НЕ ПОЛЕ ОБЪЕКТА MR. Объект merge request в
        GitLab API НЕ содержит ни `approvals_count`, ни `approved_by` —
        они живут в /merge_requests/:iid/approvals. Код в
        agents/base.merge_mr читал их из get_mr() и всегда получал None,
        поэтому поле `approvals_count` не попадало НИ В ОДНО событие
        mr_merge, а правила merge-without-approval и self-merged-mr —
        единственные, что закрывают T1562 Impair Defenses, — не могли
        сработать ни разу за всю историю журнала (проверено на 78 682
        событиях: поле отсутствует в 100% mr_merge).

        Возвращает int, либо None — если GitLab недоступен или ответ без
        нужных полей. None означает «неизвестно» и поле в событие не
        пишется: выдумывать ноль нельзя, ноль апрувов — это алерт.
        """
        data = self._api("GET",
            f"/projects/{project_id}/merge_requests/{mr_iid}/approvals")
        if not isinstance(data, dict) or not data:
            return None
        n = data.get("approvals_count")
        if n is None:
            by = data.get("approved_by")
            if by is None:
                return None
            n = len(by)
        try:
            return int(n)
        except (TypeError, ValueError):
            return None

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
        r = self._request("POST", 
            f"{self.url}/api/v4/projects/{project_id}/repository/commits",
            json={"branch": branch, "commit_message": message, "actions": actions},
            headers=headers, timeout=30,
        )
        ok = self._ok(r)
        if not ok:
            logger.warning("create_commit failed", extra={"ctx": {
                "project_id": project_id, "branch": branch,
                "actions": len(actions),
                "body": ((r.text or "") if r is not None else "нет ответа")[:200]}})
        return ok

    # ------------------------------------------------------------------
    # Реверт коммита
    # ------------------------------------------------------------------
    def revert_commit(self, project_id: int, sha: str, branch: str = "main",
                      user_token: Optional[str] = None) -> bool:
        headers = {"PRIVATE-TOKEN": user_token or self.token}
        r = self._request("POST", 
            f"{self.url}/api/v4/projects/{project_id}/repository/commits/{sha}/revert",
            json={"branch": branch},
            headers=headers, timeout=15,
        )
        return self._ok(r)

    def get_commits(self, project_id: int, ref: str = "main",
                    per_page: int = 20, limit: int = None) -> list:
        """История коммитов. per_page сохранён как «сколько взять» для
        совместимости с вызывающими; limit листает дальше первой страницы."""
        items, _ = self._api_paged(f"/projects/{project_id}/repository/commits",
                                   params={"ref_name": ref,
                                           "per_page": min(100, max(1, per_page))},
                                   max_items=limit or per_page)
        return items

    # ------------------------------------------------------------------
    # Merge Request — расширенные операции
    # ------------------------------------------------------------------
    def update_mr(self, project_id: int, mr_iid: int, fields: dict,
                  user_token: Optional[str] = None) -> bool:
        headers = {"PRIVATE-TOKEN": user_token or self.token}
        r = self._request("PUT", 
            f"{self.url}/api/v4/projects/{project_id}/merge_requests/{mr_iid}",
            json=fields, headers=headers, timeout=15,
        )
        return self._ok(r)

    def approve_mr(self, project_id: int, mr_iid: int,
                   user_token: Optional[str] = None) -> bool:
        """Настоящий approve через Approvals API (нужен токен апрувера)."""
        headers = {"PRIVATE-TOKEN": user_token or self.token}
        r = self._request("POST", 
            f"{self.url}/api/v4/projects/{project_id}/merge_requests/{mr_iid}/approve",
            headers=headers, timeout=15,
        )
        return self._ok(r)

    def award_emoji(self, project_id: int, target_type: str, target_iid: int,
                    name: str, user_token: Optional[str] = None) -> bool:
        """target_type: 'merge_requests' | 'issues'. name: 'thumbsup','rocket'..."""
        headers = {"PRIVATE-TOKEN": user_token or self.token}
        r = self._request("POST", 
            f"{self.url}/api/v4/projects/{project_id}/{target_type}/{target_iid}/award_emoji",
            json={"name": name}, headers=headers, timeout=15,
        )
        return self._ok(r)

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
        r = self._request("POST", 
            f"{self.url}/api/v4/projects/{project_id}/issues",
            json=payload, headers=headers, timeout=15,
        )
        if self._ok(r):
            return r.json().get("iid", 0)
        logger.warning("create_issue failed", extra={"ctx": {
            "project_id": project_id,
            "body": ((r.text or "") if r is not None else "нет ответа")[:150]}})
        return 0

    def comment_issue(self, project_id: int, issue_iid: int, body: str,
                      user_token: Optional[str] = None) -> bool:
        headers = {"PRIVATE-TOKEN": user_token or self.token}
        r = self._request("POST", 
            f"{self.url}/api/v4/projects/{project_id}/issues/{issue_iid}/notes",
            json={"body": body}, headers=headers, timeout=15,
        )
        return self._ok(r)

    def update_issue(self, project_id: int, issue_iid: int, fields: dict,
                     user_token: Optional[str] = None) -> bool:
        headers = {"PRIVATE-TOKEN": user_token or self.token}
        r = self._request("PUT", 
            f"{self.url}/api/v4/projects/{project_id}/issues/{issue_iid}",
            json=fields, headers=headers, timeout=15,
        )
        return self._ok(r)

    def get_open_issues(self, project_id: int) -> list:
        items, _ = self._api_paged(f"/projects/{project_id}/issues",
                                   params={"state": "opened"})
        return items

    # ------------------------------------------------------------------
    # Labels / Milestones
    # ------------------------------------------------------------------
    def ensure_label(self, project_id: int, name: str, color: str = "#428BCA",
                     user_token: Optional[str] = None) -> bool:
        headers = {"PRIVATE-TOKEN": user_token or self.token}
        r = self._request("POST", 
            f"{self.url}/api/v4/projects/{project_id}/labels",
            json={"name": name, "color": color}, headers=headers, timeout=15,
        )
        return self._ok(r, (409,))  # 409 = уже есть

    def ensure_milestone(self, project_id: int, title: str,
                         user_token: Optional[str] = None) -> int:
        # ищем существующий
        data = self._api("GET", f"/projects/{project_id}/milestones",
                         params={"title": title})
        if isinstance(data, list) and data:
            return data[0].get("id", 0)
        headers = {"PRIVATE-TOKEN": user_token or self.token}
        r = self._request("POST", 
            f"{self.url}/api/v4/projects/{project_id}/milestones",
            json={"title": title}, headers=headers, timeout=15,
        )
        if self._ok(r):
            return r.json().get("id", 0)
        return 0

    # ------------------------------------------------------------------
    # Tags / Releases
    # ------------------------------------------------------------------
    def create_tag(self, project_id: int, tag: str, ref: str = "main",
                   message: str = "", user_token: Optional[str] = None) -> bool:
        headers = {"PRIVATE-TOKEN": user_token or self.token}
        r = self._request("POST", 
            f"{self.url}/api/v4/projects/{project_id}/repository/tags",
            json={"tag_name": tag, "ref": ref, "message": message},
            headers=headers, timeout=15,
        )
        return self._ok(r)

    def create_release(self, project_id: int, tag: str, name: str,
                       description: str, user_token: Optional[str] = None) -> bool:
        headers = {"PRIVATE-TOKEN": user_token or self.token}
        r = self._request("POST", 
            f"{self.url}/api/v4/projects/{project_id}/releases",
            json={"tag_name": tag, "name": name, "description": description},
            headers=headers, timeout=15,
        )
        ok = self._ok(r)
        if not ok:
            logger.warning("create_release failed", extra={"ctx": {
                "project_id": project_id, "tag": tag,
                "body": ((r.text or "") if r is not None else "нет ответа")[:150]}})
        return ok
