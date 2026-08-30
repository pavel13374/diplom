# -*- coding: utf-8 -*-
"""Вход, сессия и заголовки безопасности

Часть консоли защиты. Вынесено из console.py: там 1841 строка держала
маршруты, ингест, триаж и сборку отчётов в одном файле, и правка одного
раздела требовала удерживать в голове все остальные.

Состояние и общие хелперы — в console_app.core, оно ЕДИНСТВЕННОЕ на процесс
и импортируется по имени: объекты (_COR, _STATE, _LOCK) создаются один раз
при импорте core и никогда не переприсваиваются, поэтому у всех разделов
общий экземпляр, а не копии.
"""

import config
import websec
from flask import Blueprint, jsonify, request, session, redirect, url_for

# Общее состояние консоли — ЯВНО, а не через `import *`:
# видно, чем раздел пользуется, и статический анализ снова работает.
from .core import _PUBLIC_PATHS, _flog, _tpl

#: Ограничение подбора — ПО ИСТОЧНИКУ. Общий счётчик на процесс (прежний
#: _LOGIN_FAILS) блокировал сразу всех: пять неудач откуда угодно закрывали
#: вход настоящему аналитику, а подбирающий держал ~20 попыток в минуту.
_GUARD = websec.LoginGuard()


bp = Blueprint("security", __name__)

@bp.before_app_request
def _require_auth():
    """Единая точка контроля доступа.

    Реализовано через before_request, а не декоратором на каждом маршруте:
    декоратор легко забыть на новом маршруте, и дыра появится незаметно.
    Здесь же закрыто всё по умолчанию — новый маршрут защищён автоматически.
    """
    p = request.path or "/"
    if p in _PUBLIC_PATHS or p.startswith("/static/"):
        return None
    if session.get("user"):
        return None
    if p.startswith("/api/"):
        return jsonify({"error": "auth", "detail": "требуется вход"}), 401
    return redirect(url_for("security.login"))

@bp.after_app_request
def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "connect-src 'self'")
    return resp

@bp.route("/healthz")
def healthz():
    return jsonify({"ok": True})

@bp.route("/login", methods=["GET", "POST"])
def login():
    import hmac
    error = ""
    if request.method == "POST":
        wait = _GUARD.blocked_for()
        if wait:
            error = f"Слишком много попыток — подождите {wait} с"
        else:
            u_ok = hmac.compare_digest(request.form.get("username", ""),
                                       config.WEB_ADMIN_USER)
            p_ok = hmac.compare_digest(request.form.get("password", ""),
                                       config.WEB_ADMIN_PASS)
            if u_ok and p_ok:
                _GUARD.record_success()
                session.clear()      # новый идентификатор сессии после входа
                session["user"] = config.WEB_ADMIN_USER
                session.permanent = True
                return redirect(url_for("overview.index"))
            _GUARD.record_failure()
            error = "Неверный логин или пароль"
    return _tpl("login.html").replace("{{ERROR}}", error)

@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("security.login"))

@bp.app_errorhandler(Exception)
def _unhandled(e):
    """Любая необработанная ошибка — в errors.log с полным трейсбеком."""
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return e
    # Наружу — только идентификатор: текст исключения здесь содержит пути на
    # диске, адрес GitLab и куски ответов API.
    return websec.error_ref(_flog, e)

