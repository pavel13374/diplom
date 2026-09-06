# -*- coding: utf-8 -*-
"""
ОБЩИЕ ПРИМИТИВЫ БЕЗОПАСНОСТИ ДЛЯ ОБЕИХ КОНСОЛЕЙ.

Модуль появился потому, что защита была распределена между двумя приложениями
НЕРАВНОМЕРНО, и притом в обратную сторону относительно их возможностей.

Наблюдалось на живых процессах:

    :8787 (среда)    Set-Cookie: session=…; HttpOnly; Path=/; SameSite=Lax
    :8788 (защита)   Set-Cookie: session=…; HttpOnly; Path=/

У консоли защиты не было ни SameSite, ни какой-либо защиты от CSRF — при том
что именно она умеет:

  • POST /api/red/launch            поставить атакующую кампанию, которую мир
                                    исполнит против настоящего GitLab;
  • POST /api/incident/<id>/respond завести issue в GitLab;
  • POST /api/incident/<id>/status  выставить вердикт, а три вердикта «ложное»
                                    молча выключают правило детектирования;
  • POST /api/demo, /api/metrics/snapshot   запустить подпроцесс.

Довод «слушает только 127.0.0.1» здесь не работает: браузер аналитика И ЕСТЬ
127.0.0.1. Любая открытая им страница могла управлять SOC-консолью.

Плюс cookie не разделяются по портам: обе консоли писали cookie с одинаковым
именем `session`, одним путём и одним ключом подписи, поэтому атрибуты
перетирались — какое приложение записало последним, такой SameSite и
действовал для обоих.

Здесь собраны:
  • setup_app()      единая настройка сессии и cookie для приложения;
  • csrf_protect()   двойная отправка токена (cookie + заголовок);
  • int_arg()        разбор числового параметра запроса с границами;
  • error_ref()      непрозрачный ответ об ошибке с идентификатором для лога.
"""
import re
import time
import uuid
import hmac
import logging
import secrets
import threading
from datetime import timedelta

from flask import request, session, jsonify

import config

log = logging.getLogger("websec")

#: Методы, меняющие состояние. GET/HEAD/OPTIONS проверке не подлежат.
UNSAFE_METHODS = ("POST", "PUT", "PATCH", "DELETE")

#: Имя по умолчанию — только для вызовов вне приложения (тесты, утилиты).
#: Настоящее имя ВСЕГДА берётся из конфигурации приложения, см. setup_app().
CSRF_COOKIE = "sentinel_csrf"
CSRF_HEADER = "X-CSRF-Token"
CSRF_SESSION_KEY = "_csrf"


def csrf_cookie_name(app=None):
    """Имя CSRF-cookie ЭТОГО приложения.

    ── Почему имя обязано быть разным у двух консолей ────────────────────
    Cookie не различаются по порту. Консоль среды (:8787) и консоль защиты
    (:8788) живут на одном хосте `localhost`, поэтому один и тот же
    `sentinel_csrf` они друг у друга ПЕРЕЗАПИСЫВАЛИ. Сессионные cookie были
    разведены по именам (`sentinel_env` / `sentinel_console`) — у каждой
    консоли свой токен в своей сессии, — а cookie с токеном остался общим.

    Дальше происходило вот что: открыта одна вкладка со средой и одна с
    защитой; та, что обновилась последней, клала в `sentinel_csrf` СВОЙ
    токен; вторая консоль отправляла его заголовком, сравнивала со своим — и
    отвечала 403 `csrf` на каждый POST. Симптом плавающий: пока открыта одна
    вкладка, всё работает.
    """
    try:
        from flask import current_app
        a = app or current_app
        return a.config.get("CSRF_COOKIE_NAME") or CSRF_COOKIE
    except Exception:
        return CSRF_COOKIE


#: Шаблоны обеих консолей грузятся СВОИМ загрузчиком (см. webapp._tpl и
#: console_app.core._tpl), а не через render_template: они статические, и
#: Jinja в них не выполняется. Поэтому имя cookie подставляется точечно —
#: одной заменой, а не введением шаблонизатора ради одной строки.
_CSRF_META_RE = re.compile(r'(<meta name=csrf-cookie content=")[^"]*(")')


def inject_csrf_meta(html, app=None):
    """Подставить в разметку имя CSRF-cookie ЭТОГО приложения."""
    name = csrf_cookie_name(app)
    return _CSRF_META_RE.sub(lambda m: m.group(1) + name + m.group(2), html, count=1)


def setup_app(app, cookie_name):
    """Единая настройка сессии. Вызывать сразу после создания Flask-приложения."""
    app.secret_key = config.WEB_SECRET
    csrf_cookie = cookie_name + "_csrf"
    # Разметка не должна знать имя наизусть: иначе переименование cookie на
    # сервере молча ломает отправку токена с клиента.
    app.jinja_env.globals["CSRF_COOKIE"] = csrf_cookie
    app.config.update(
        CSRF_COOKIE_NAME=csrf_cookie,
        SESSION_COOKIE_NAME=cookie_name,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        # Secure выставляем только под HTTPS: на http://127.0.0.1 браузер
        # просто не сохранит такой cookie, и войти станет нельзя.
        SESSION_COOKIE_SECURE=bool(getattr(config, "WEB_HTTPS", False)),
        PERMANENT_SESSION_LIFETIME=timedelta(
            hours=max(1, int(getattr(config, "SESSION_LIFETIME_HOURS", 8)))),
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,   # тело запроса ограничено
    )
    return app


def issue_csrf(resp):
    """Положить токен в сессию и в читаемый JS-ом cookie (double submit)."""
    tok = session.get(CSRF_SESSION_KEY)
    if not tok:
        tok = secrets.token_urlsafe(24)
        session[CSRF_SESSION_KEY] = tok
    resp.set_cookie(csrf_cookie_name(), tok, samesite="Lax", httponly=False,
                    secure=bool(getattr(config, "WEB_HTTPS", False)), path="/")
    return resp


def csrf_ok():
    """Совпадает ли токен из заголовка с токеном сессии."""
    if request.method not in UNSAFE_METHODS:
        return True
    want = session.get(CSRF_SESSION_KEY)
    if not want:
        # Сессии ещё нет — значит и защищать нечего: аутентификация всё равно
        # отклонит запрос раньше.
        return True
    got = request.headers.get(CSRF_HEADER) or ""
    if not got:
        # Форма входа отправляется обычным POST без JS.
        got = request.form.get("csrf_token", "")
    return hmac.compare_digest(str(got).encode("utf-8"), str(want).encode("utf-8"))


def csrf_protect(exempt_paths=()):
    """before_request-обработчик. Возвращает функцию для регистрации."""
    exempt = set(exempt_paths)

    def _check():
        if request.method not in UNSAFE_METHODS:
            return None
        if (request.path or "/") in exempt:
            return None
        if csrf_ok():
            return None
        log.warning("запрос отклонён проверкой CSRF",
                    extra={"ctx": {"path": request.path, "method": request.method,
                                   "origin": request.headers.get("Origin", ""),
                                   "referer": request.headers.get("Referer", "")}})
        return jsonify({"error": "csrf",
                        "detail": "нет или неверен заголовок " + CSRF_HEADER}), 403
    return _check


# ======================================================================
#  ВАЛИДАЦИЯ ПАРАМЕТРОВ
# ======================================================================
class BadArg(ValueError):
    """Некорректный параметр запроса — превращается в 400, а не в 500."""

    def __init__(self, name, detail):
        super().__init__(detail)
        self.name = name
        self.detail = detail


def int_arg(name, default, lo=0, hi=10000, src=None):
    """Числовой параметр с границами.

    Раньше во всех трёх местах стоял голый int(request.args.get(...)):

        GET /api/events?n=abc  -> 500 {"detail":"invalid literal for int()..."}
        GET /api/logs?since=xyz -> 500 (то же)

    То есть кривая ссылка давала ошибку сервера, текст исключения уезжал в
    браузер, а в errors.log ложился полный трейсбек — значит поток таких
    запросов ещё и топил настоящие ошибки. Отрицательные и неограниченно
    большие значения принимались молча.
    """
    raw = (src if src is not None else request.args).get(name)
    if raw is None or raw == "":
        return default
    try:
        v = int(str(raw).strip())
    except (TypeError, ValueError):
        raise BadArg(name, f"параметр {name} должен быть целым числом")
    return max(lo, min(hi, v))


_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,80}$")


def safe_id(value, name="id"):
    v = str(value or "").strip()
    if not _SAFE_ID_RE.match(v):
        raise BadArg(name, f"{name} содержит недопустимые символы или слишком длинный")
    return v


def bounded_str(value, name, limit):
    v = "" if value is None else str(value)
    if len(v) > limit:
        raise BadArg(name, f"{name} длиннее {limit} символов")
    return v


def one_of(value, name, allowed, allow_none=True):
    if value is None and allow_none:
        return None
    if value not in allowed:
        raise BadArg(name, f"{name} должен быть одним из: {', '.join(map(str, allowed))}")
    return value


# ======================================================================
#  ОШИБКИ
# ======================================================================
def error_ref(logger, exc):
    """Непрозрачный ответ + идентификатор, по которому ошибка ищется в логе.

    Было: `jsonify({"error": "internal", "detail": str(e)[:300]})`. Текст
    исключений в этом коде регулярно содержит пути на диске, адрес GitLab и
    куски тела ответа API (gitlab_client логирует r.text[:200], и эти строки
    расходятся дальше). Отдавать это в браузер — бесплатная разведка.
    """
    ref = uuid.uuid4().hex[:12]
    logger.error("необработанная ошибка [%s] %s %s", ref,
                 request.method, request.path, exc_info=True,
                 extra={"ctx": {"ref": ref, "path": request.path,
                                "method": request.method}})
    body = {"error": "internal", "ref": ref,
            "detail": "внутренняя ошибка; идентификатор для лога: " + ref}
    if getattr(config, "DEBUG_ERRORS", False):
        body["debug"] = str(exc)[:300]
    return jsonify(body), 500


# ======================================================================
#  ОГРАНИЧЕНИЕ ПОПЫТОК ВХОДА
# ======================================================================
class LoginGuard:
    """Ограничение подбора пароля ПО ИСТОЧНИКУ, а не одним счётчиком на процесс.

    Было: `_LOGIN_FAILS = {"n": 0, "until": 0.0}` — один счётчик на всё
    приложение. Пять неудач откуда угодно блокировали ВСЕХ на 15 секунд, после
    чего счётчик сбрасывался в ноль. То есть подбирающий держал устойчивые
    ~20 попыток в минуту и заодно мог по желанию не пускать аналитика. Плюс
    time.sleep(0.5) на каждой неудаче занимал поток обработчика, а сервер
    многопоточный без ограничения числа потоков.
    """

    #: 15 c -> 60 c -> 300 c: повторяющийся подбор становится всё дороже.
    BACKOFF = (15, 60, 300)
    MAX_TRACKED = 4096

    def __init__(self, threshold=5):
        self.threshold = threshold
        self._lock = threading.Lock()
        self._by_src = {}

    @staticmethod
    def _src():
        return request.headers.get("X-Forwarded-For", "").split(",")[0].strip() \
            or (request.remote_addr or "?")

    def blocked_for(self):
        """Сколько секунд осталось ждать этому источнику (0 — можно пробовать)."""
        with self._lock:
            rec = self._by_src.get(self._src())
            if not rec:
                return 0
            return max(0, int(rec["until"] - time.time()))

    def record_failure(self):
        now = time.time()
        src = self._src()
        with self._lock:
            if len(self._by_src) > self.MAX_TRACKED:
                # чистим самые старые, чтобы словарь не рос неограниченно
                for k in sorted(self._by_src, key=lambda k: self._by_src[k]["ts"])[:1024]:
                    self._by_src.pop(k, None)
            rec = self._by_src.setdefault(src, {"n": 0, "until": 0.0, "step": 0, "ts": now})
            rec["ts"] = now
            rec["n"] += 1
            if rec["n"] >= self.threshold:
                wait = self.BACKOFF[min(rec["step"], len(self.BACKOFF) - 1)]
                rec["until"] = now + wait
                rec["step"] += 1
                rec["n"] = 0
                log.warning("вход заблокирован после серии неудачных попыток",
                            extra={"ctx": {"источник": src, "пауза_с": wait,
                                           "ступень": rec["step"]}})
                return wait
        return 0

    def record_success(self):
        with self._lock:
            self._by_src.pop(self._src(), None)
