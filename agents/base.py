"""
Базовый класс SOC-агента.
Каждый агент — отдельный персонаж с характером и токеном.

ВАЖНО (исправление «мир молчит при недоступном GitLab»): событие в журнал
пишется ВСЕГДА — и при успешном вызове GitLab, и при сбое. У каждого события есть
наблюдаемый флаг gitlab_ok и, при сбое, причина (gitlab_error). Так лента мира не
пустует, а ошибки GitLab видны. Счётчик ошибок — в GITLAB_STATUS (для UI).
"""
import random
import logging
import itertools
from typing import Optional
from gitlab_client import GitLabClient
from config import DELAYS, USERS
import config
import simclock
import events

logger = logging.getLogger("world.agent")

# Глобальный статус связи с GitLab (для статус-бара 8787)
GITLAB_STATUS = {"errors": 0, "ok": 0, "last_error": "", "last_error_ts": None,
                 "by_op": {}, "ok_by_op": {}}


def _fail(what, err, ctx=None):
    """Учесть отказ GitLab И ОСТАВИТЬ СЛЕД.

    Раньше функция только увеличивала счётчик. Отказ вида «пустой ответ/отказ»
    (то есть GitLab ответил, но не тем) не логировался ВООБЩЕ. За один прогон
    так молча провалились 357 create_branch, 193 операции по playbooks и 53 по
    soc-infra: в журнале событий они видны как gitlab_ok=false, а в логах — нет
    ни строки, и разобраться, ПОЧЕМУ, было нечем.

    Разбивка по операциям (GITLAB_STATUS["by_op"]) отдаётся в /api/diag, чтобы
    систематический сбой одной операции был виден сразу, а не растворялся в
    общем счётчике ошибок.
    """
    GITLAB_STATUS["errors"] += 1
    GITLAB_STATUS["by_op"][what] = GITLAB_STATUS["by_op"].get(what, 0) + 1
    GITLAB_STATUS["last_error"] = f"{what}: {err}"
    import datetime as _dt
    GITLAB_STATUS["last_error_ts"] = _dt.datetime.now().isoformat(timespec="seconds")
    logger.warning("GitLab: операция не удалась",
                   extra={"ctx": {"op": what, "error": str(err)[:200],
                                  "всего_ошибок": GITLAB_STATUS["errors"],
                                  "по_операции": GITLAB_STATUS["by_op"][what],
                                  **(ctx or {})}})


def _ok(what=None):
    GITLAB_STATUS["ok"] += 1
    if what:
        GITLAB_STATUS["ok_by_op"][what] = GITLAB_STATUS["ok_by_op"].get(what, 0) + 1


def _offline():
    import config
    return bool(getattr(config, "OFFLINE_MODE", False))


class BaseAgent:
    def __init__(self, username: str, gl: GitLabClient):
        self.username = username
        self.gl       = gl
        self.info     = USERS[username]
        self.name     = self.info["name"]
        self.email    = self.info["email"]
        self.role     = self.info["role"]
        self.user_id  = self.info["id"]
        self._token: Optional[str] = None

    # ------------------------------------------------------------------
    @property
    def token(self) -> str:
        if not self._token:
            if _offline():
                self._token = "offline-token"
            else:
                try:
                    self._token = self.gl.get_or_create_user_token(self.user_id, self.username)
                except Exception as e:
                    _fail("get_token", e)
                    self._token = "no-token"
        return self._token

    def _emit(self, action, gitlab_ok=True, gitlab_error=None, extra=None, **kw):
        e = dict(extra or {})
        e["gitlab_ok"] = bool(gitlab_ok)
        # ЧЕСТНАЯ ПОМЕТКА OFFLINE. В offline _call возвращает «успех», ничего не
        # сделав, поэтому события шли с gitlab_ok=True и статус-бар показывал
        # безупречный процент успеха в режиме, где НИ ОДНОЙ операции не
        # выполнялось. Симуляция здесь намеренная, а вот выдавать её за
        # состояние связи — нет. Поле служебное (в LEAK-списке анти-лика оно
        # рядом с gitlab_ok), детектор его не видит.
        if _offline():
            e["simulated"] = True
        if gitlab_error:
            e["gitlab_error"] = str(gitlab_error)[:200]
        try:
            events.emit(action, actor=self.username, role=self.role, extra=e, **kw)
        except Exception:
            # раньше здесь было молчаливое pass: событие терялось без следов
            logger.exception(f"[{self.username}] не удалось записать событие {action}")

    def _call(self, fn_name, *args):
        """Вызов GitLab с учётом offline и перехватом ошибок.
        Возвращает (result, ok, error_str).

        В offline вызова не происходит вовсе, поэтому счётчики GITLAB_STATUS
        НЕ трогаются: иначе режим «GitLab не вызывается» выглядел бы как
        «GitLab отвечает безупречно», и по строке состояния их было не
        различить.
        """
        if _offline():
            return None, True, None
        try:
            res = getattr(self.gl, fn_name)(*args, self.token)
            ok = bool(res)
            if ok:
                _ok(fn_name)
            else:
                # «Пустой ответ» — самый частый и самый незаметный отказ:
                # исключения нет, значит и трейсбека нет. Логируем аргументы,
                # чтобы было видно, ЧТО именно не создалось (обычно это
                # конфликт имени ветки или отсутствие прав в репозитории).
                _fail(fn_name, "пустой ответ/отказ",
                      {"actor": self.username,
                       "args": [str(a)[:80] for a in args]})
            return res, ok, (None if ok else f"{fn_name}: пустой ответ/отказ")
        except Exception as ex:
            _fail(fn_name, ex, {"actor": self.username,
                                "args": [str(a)[:80] for a in args]})
            logger.warning("[%s] GitLab %s упал: %s", self.username, fn_name, ex,
                           exc_info=True)
            return None, False, str(ex)

    # ------------------------------------------------------------------
    def push_file(self, project_id: int, path: str, content: str,
                  message: str, branch: str = "main", extra: dict = None) -> bool:
        """`extra` — дополнительные НАБЛЮДАЕМЫЕ атрибуты события (например,
        dependency_added для правки манифеста зависимостей). Метки мира сюда
        класть нельзя: они срезаются анти-ликом и в детектор не попадут."""
        res, ok, err = self._call("push_file", project_id, path, content, message, branch)
        ext = path.rsplit(".", 1)[-1] if "." in path else ""
        feats = {"lines": content.count(chr(10)) + 1, "bytes": len(content), "ext": ext}
        try:
            import content_features
            feats.update(content_features.analyze(content, path))
        except Exception:
            logger.error("не удалось посчитать признаки содержимого для %s — "
                         "детектор недосчитается сигналов", path, exc_info=True)
        # Защищённость ветки — наблюдаемый атрибут: в GitLab он виден в
        # настройках проекта и в аудите. Без него правило про прямой push в
        # main не может отличить обход ревью от работы в своей ветке.
        feats["protected_branch"] = branch in getattr(config, "PROTECTED_BRANCHES",
                                                      ["main", "master"])
        if extra:
            feats.update(extra)
        self._emit("push", gitlab_ok=ok, gitlab_error=err, project_id=project_id,
                   path=path, branch=branch, message=message, extra=feats)
        (logger.info if ok else logger.warning)(
            f"[{self.username}] push {path} -> {message[:50]}" + ("" if ok else f"  ✗ {err}"))
        return ok

    def commit_changes(self, project_id: int, branch: str, message: str,
                       deletes=(), creates=()) -> bool:
        actions = [{"action": "delete", "file_path": p} for p in deletes]
        actions += [{"action": "create", "file_path": p, "content": c} for p, c in creates]
        if not actions:
            return False
        res, ok, err = self._call("create_commit", project_id, branch, message, actions)
        for p in deletes:
            self._emit("file_delete", gitlab_ok=ok, gitlab_error=err, project_id=project_id,
                       path=p, branch=branch, message=message)
        for p, c in creates:
            ext = p.rsplit(".", 1)[-1] if "." in p else ""
            extra = {"lines": (c or "").count(chr(10)) + 1, "bytes": len(c or ""), "ext": ext}
            try:
                import content_features
                extra.update(content_features.analyze(c or "", p))
            except Exception:
                logger.error("не удалось посчитать признаки содержимого для %s — "
                             "детектор недосчитается сигналов", p, exc_info=True)
            self._emit("push", gitlab_ok=ok, gitlab_error=err, project_id=project_id,
                       path=p, branch=branch, message=message, extra=extra)
        (logger.info if ok else logger.warning)(
            f"[{self.username}] commit {branch} ({len(actions)} действий)" + ("" if ok else f"  ✗ {err}"))
        return ok

    def create_branch(self, project_id: int, branch: str, ref: str = "main") -> bool:
        res, ok, err = self._call("create_branch", project_id, branch, ref)
        self._emit("branch_create", gitlab_ok=ok, gitlab_error=err,
                   project_id=project_id, branch=branch)
        return ok

    def create_mr(self, project_id: int, source: str, title: str,
                  description: str = "", assignee_id: int = 0) -> int:
        iid, ok, err = self._call("create_mr", project_id, source, title, description, assignee_id)
        if _offline():
            iid = random.randint(100, 9999)
        self._emit("mr_open", gitlab_ok=ok, gitlab_error=err, project_id=project_id,
                   branch=source, mr_iid=iid or 0, message=title)
        return iid or 0

    def _content_features(self, text, path=""):
        """Наблюдаемые признаки текста — те же, что у настоящего secret-scanner.

        Считаются для ЛЮБОГО текста, а не только для содержимого файлов:
        комментарий к merge request — такой же канал утечки секрета, как и
        коммит, и настоящий сканер проверяет его наравне с кодом.
        """
        feats = {"bytes": len(text or ""), "lines": (text or "").count("\n") + 1}
        try:
            import content_features
            feats.update(content_features.analyze(text or "", path))
        except Exception:
            logger.error("не удалось посчитать признаки содержимого — "
                         "детектор недосчитается сигналов", exc_info=True)
        return feats

    def comment_mr(self, project_id: int, mr_iid: int, body: str) -> bool:
        # Признаки содержимого обязательны: без них правило secret-in-mr-comment
        # не могло сработать НИ РАЗУ — поле n_regex_hits в событии просто
        # отсутствовало, и секрет, вставленный в обсуждение, был невидим.
        # Нашлось тестом tests/test_rule_coverage.py (правило молчало на всём
        # корпусе), а не глазами.
        res, ok, err = self._call("comment_mr", project_id, mr_iid, body)
        self._emit("mr_comment", gitlab_ok=ok, gitlab_error=err,
                   project_id=project_id, mr_iid=mr_iid, message=body,
                   extra=self._content_features(body))
        return ok

    def merge_mr(self, project_id: int, mr_iid: int) -> bool:
        # Наблюдаемые метаданные ревью — ровно то, что видно в GitLab API любому
        # SIEM: автор MR и совпадает ли он с тем, кто мержит. Пишем их для ВСЕХ
        # merge-событий (и нормальных, и аномальных) — иначе само наличие поля
        # было бы подсказкой детектору (анти-лик).
        _meta = {}
        try:
            _mr = self.gl.get_mr(project_id, mr_iid) or {}
            _author = ((_mr.get("author") or {}).get("username")) or None
            _meta["mr_author"] = _author
            _meta["self_merged"] = bool(_author and _author == self.username)
            # Апрувы берём ИЗ ОТДЕЛЬНОЙ РУЧКИ /approvals, а не из объекта MR.
            # Объект merge request в GitLab API не содержит ни
            # approvals_count, ни approved_by — прежний код читал их отсюда и
            # всегда получал None. Следствие, найденное проверкой журнала: за
            # всю историю (78 682 события) поле approvals_count не попало НИ В
            # ОДНО событие mr_merge, поэтому правила merge-without-approval и
            # self-merged-mr — единственные, что закрывают T1562 Impair
            # Evasion/Defenses, — не срабатывали никогда, а экран покрытия
            # считал технику закрытой.
            _ac = _mr.get("approvals_count")
            if _ac is None and _mr.get("approved_by") is not None:
                _ac = len(_mr.get("approved_by") or [])
            if _ac is None:
                try:
                    _ac = self.gl.get_mr_approvals(project_id, mr_iid)
                except Exception:
                    logger.warning("не удалось получить апрувы MR !%s в проекте %s",
                                   mr_iid, project_id, exc_info=True)
                    _ac = None
            if _ac is not None:
                _meta["approvals_count"] = int(_ac)
            # Целевая ветка защищена? Правила self-merged-mr и
            # merge-without-approval требуют именно этого контекста: merge
            # своей мелкой правки в feature-ветку инцидентом не является.
            _tgt = _mr.get("target_branch") or "main"
            _meta["target_branch"] = _tgt
            _meta["protected_branch"] = _tgt in getattr(config, "PROTECTED_BRANCHES",
                                                        ["main", "master"])
        except Exception:
            # без этих полей не сработают правила self-merged-mr и
            # merge-without-approval — обход ревью останется незамеченным
            logger.warning("не удалось получить автора и апрувы MR !%s в проекте %s",
                           mr_iid, project_id, exc_info=True)
        res, ok, err = self._call("merge_mr", project_id, mr_iid)
        # ВАЖНО: только через extra — events.emit() принимает фиксированный набор
        # именованных аргументов, любой лишний kwarg = TypeError и потеря события.
        self._emit("mr_merge", gitlab_ok=ok, gitlab_error=err, extra=_meta,
                   project_id=project_id, mr_iid=mr_iid)
        if ok or _offline():
            return True
        # Неустранимо (конфликт) — закрываем MR и удаляем ветку, чтобы не копились.
        try:
            mr = self.gl.get_mr(project_id, mr_iid) or {}
            src = mr.get("source_branch")
            if self.gl.close_mr(project_id, mr_iid, self.token):
                self._emit("mr_close", gitlab_ok=True, project_id=project_id, mr_iid=mr_iid,
                           message="closed: unmergeable (conflict)")
            if src and src not in ("main", "master"):
                self.gl.delete_branch(project_id, src, self.token)
        except Exception:
            pass
        return False

    # ------------------------------------------------------------------
    def approve_mr(self, project_id: int, mr_iid: int) -> bool:
        res, ok, err = self._call("approve_mr", project_id, mr_iid)
        self._emit("mr_approve", gitlab_ok=ok, gitlab_error=err,
                   project_id=project_id, mr_iid=mr_iid)
        return ok

    def react(self, project_id: int, mr_iid: int, name: str = "thumbsup",
              target_type: str = "merge_requests") -> bool:
        import config
        if not config.FEATURES.get("emoji_reactions"):
            return False
        if random.random() > config.PROBS.get("emoji", 0.5):
            return False
        if _offline():
            return True
        try:
            return self.gl.award_emoji(project_id, target_type, mr_iid, name, self.token)
        except Exception as e:
            _fail("award_emoji", e); return False

    def set_mr_title(self, project_id: int, mr_iid: int, title: str) -> bool:
        if _offline():
            return True
        try:
            return self.gl.update_mr(project_id, mr_iid, {"title": title}, self.token)
        except Exception as e:
            _fail("update_mr", e); return False

    def close_mr(self, project_id: int, mr_iid: int) -> bool:
        res, ok, err = (None, True, None) if _offline() else (
            self.gl.update_mr(project_id, mr_iid, {"state_event": "close"}, self.token), True, None)
        try:
            if not _offline():
                ok = bool(self.gl.update_mr(project_id, mr_iid, {"state_event": "close"}, self.token))
        except Exception as e:
            _fail("close_mr", e); ok = False; err = str(e)
        self._emit("mr_close", gitlab_ok=ok, gitlab_error=err, project_id=project_id, mr_iid=mr_iid)
        return ok

    def create_issue(self, project_id: int, title: str, description: str = "",
                     labels=None, milestone_id: int = 0, assignee_id: int = 0) -> int:
        import config
        from datetime import datetime
        created_at = None
        if getattr(config, "GITLAB_DATES", "real") == "sim":
            t = simclock.now()
            if t <= datetime.now():
                created_at = t.isoformat()
        iid = 0; ok = True; err = None
        if _offline():
            iid = random.randint(100, 9999)
        else:
            try:
                iid = self.gl.create_issue(project_id, title, description, labels,
                                           milestone_id, assignee_id,
                                           created_at=created_at, user_token=self.token)
                ok = bool(iid)
                if ok:
                    _ok("create_issue")
                else:
                    # 82% отказов этой операции за прогон приходились на
                    # активности с устаревшим id репозитория; чтобы это было
                    # видно, в контекст кладём project_id и заголовок
                    _fail("create_issue", "пустой ответ/отказ",
                          {"actor": self.username, "project_id": project_id,
                           "title": title[:60]})
                    err = "create_issue: пустой ответ/отказ"
            except Exception as e:
                _fail("create_issue", e, {"actor": self.username,
                                          "project_id": project_id})
                ok = False; err = str(e)
        self._emit("issue_open", gitlab_ok=ok, gitlab_error=err, project_id=project_id,
                   mr_iid=iid or 0, message=title, extra={"labels": labels or []})
        return iid or 0

    def comment_issue(self, project_id: int, issue_iid: int, body: str) -> bool:
        # Комментарий к задаче — такой же канал утечки, как и к merge request.
        res, ok, err = self._call("comment_issue", project_id, issue_iid, body)
        self._emit("issue_comment", gitlab_ok=ok, gitlab_error=err,
                   project_id=project_id, mr_iid=issue_iid, message=body,
                   extra=self._content_features(body))
        return ok

    def close_issue(self, project_id: int, issue_iid: int) -> bool:
        if _offline():
            ok, err = True, None
        else:
            try:
                ok = bool(self.gl.update_issue(project_id, issue_iid, {"state_event": "close"}, self.token))
                err = None if ok else "close_issue: отказ"
            except Exception as e:
                _fail("close_issue", e); ok = False; err = str(e)
        self._emit("issue_close", gitlab_ok=ok, gitlab_error=err,
                   project_id=project_id, mr_iid=issue_iid)
        return ok

    # ------------------------------------------------------------------
    def think(self, base: float = None):
        delay = base or DELAYS["agent_think"]
        simclock.sleep(delay * random.uniform(0.5, 1.5))

    def commit_pause(self):
        simclock.sleep(DELAYS["between_commits"] * random.uniform(0.8, 1.2))

    def review_pause(self):
        simclock.sleep(DELAYS["review_wait"] * random.uniform(0.7, 1.5))

    #: Счётчик веток на процесс. Раньше суффикс брался из int(time.time()),
    #: и при быстром офлайн-прогоне все ветки одной кампании получали ОДИН И
    #: ТОТ ЖЕ номер: имя ветки становилось устойчивым признаком атаки
    #: (ловится tests/test_leakage.py). Плюс ветки конфликтовали между собой.
    #:
    #: Начало отсчёта тоже бралось от часов — и это ломало воспроизводимость
    #: экспериментов: имя ветки попадает в содержимое события, а по содержимому
    #: работают правила энтропии и сигнатур. Один и тот же сид давал разный
    #: датасет от запуска к запуску (замерено: 889–896 событий вместо
    #: постоянного числа). Отсчёт начинается от config.SEED — номера остаются
    #: разными внутри прогона и одинаковыми между прогонами.
    _branch_seq = itertools.count(getattr(config, "SEED", 42) % 100000)

    def unique_branch(self, prefix: str, suffix: str = "") -> str:
        n = next(BaseAgent._branch_seq) % 100000
        s = f"-{suffix}" if suffix else ""
        return f"{prefix}{s}-{n}"

    def log(self, msg: str):
        logger.info(f"[{self.username}] {msg}")

    def warn(self, msg: str):
        logger.warning(f"[{self.username}] {msg}")
