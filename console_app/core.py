# -*- coding: utf-8 -*-
"""ОБЩЕЕ СОСТОЯНИЕ И ХЕЛПЕРЫ КОНСОЛИ ЗАЩИТЫ.

Единственное место, где живут объекты, общие для всех разделов: коррелятор,
накопленная статистика потока, замок, кэш приглушённых правил, загрузчик
шаблонов. Разделы (console_app/*.py) импортируют их отсюда по имени.

Почему это безопасно при импорте по имени, а не через геттеры: ни один объект
здесь НЕ ПЕРЕПРИСВАИВАЕТСЯ после создания. Меняется только их содержимое
(_STATE — словарь, _COR — объект со своими полями). Проверка в console.py
раньше держалась на том же допущении, просто неявно: в файле не было ни одного
оператора global.
"""
import os.path as _os_path
import sys
import time
import threading
import collections


import config
import websec
import eventstore
import run_defense
import correlator as correlator_mod
import detector as detector_mod
import logging as _logging

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

#: Общая поверхность консоли. Перечислено ЯВНО, потому что `import *`
#: по умолчанию не переносит имена с подчёркиванием, а состояние здесь
#: именно такое (_COR, _STATE, _LOCK). Список заодно документирует, чем
#: разделы имеют право пользоваться.
__all__ = [
    "ROOT", "_incident_ctx", "_TPL_DIR", "_TPL_CACHE", "_tpl", "_flog", "CURSOR",
    "_PUBLIC_PATHS", "_COR", "_SUPPRESS", "FP_MUTE_THRESHOLD", "incidents_snapshot",
    "rule_verdict_stats", "muted_rules", "_LOCK", "_STATE", "_repo",
    "_MUTED_CACHE", "REPLAY_EVENTS", "_engine", "_jsonsafe", "_TACTIC_RU",
    "_WF_STATUSES", "SNAPSHOT_PERIOD_S", "_SNAP", "_HEALTH", "_DEMO",
    "_EXECM"
]

# =======================================================================
#  ШАБЛОНЫ
# =======================================================================
# Раньше HTML страниц лежал прямо в этом файле строковыми константами: одна
# только DASH занимала 144 КБ (2100 строк) и делала модуль нечитаемым — логика
# ингеста, детектирования и корреляции терялась между разметкой и CSS.
# Теперь страницы лежат в templates/ обычными .html-файлами: их можно открыть
# в редакторе с подсветкой, отдать на правку вёрстки и посмотреть diff.
#
# Свой загрузчик, а не render_template Flask: шаблоны здесь статические
# (данные подтягивает JS через /api/*), поэтому движок шаблонов не нужен,
# а лишняя зависимость от структуры каталогов Flask — не нужна тем более.
#: Корень ПРОЕКТА, а не пакета. Пакет лежит на уровень глубже, поэтому
#: dirname(__file__) указывал бы в console_app/ — и шаблоны, и results/
#: искались бы не там. Единственная точка вычисления корня на всю консоль.
ROOT = _os_path.dirname(_os_path.dirname(_os_path.abspath(__file__)))

_TPL_DIR = _os_path.join(ROOT, "templates", "console")

_TPL_CACHE = {}

def _tpl(name):
    """Прочитать шаблон. Кэш в памяти, но сбрасывается при правке файла.

    Раньше кэш был вечным: перезагрузчик Flask перезапускает процесс
    только на изменение .py, поэтому правки вёрстки не появлялись в
    браузере до ручного перезапуска — и это выглядело так, будто
    правка не сработала.
    """
    path = _os_path.join(_TPL_DIR, name)
    try:
        mtime = _os_path.getmtime(path)
    except OSError:
        mtime = 0
    hit = _TPL_CACHE.get(name)
    if hit and hit[0] == mtime:
        return hit[1]
    with open(path, encoding="utf-8") as f:
        text = f.read()
    text = websec.inject_csrf_meta(text)
    _TPL_CACHE[name] = (mtime, text)
    return text

_flog = _logging.getLogger("console")

CURSOR = "console"

# =======================================================================
#  АУТЕНТИФИКАЦИЯ
# =======================================================================
# Раньше консоль защиты была открыта полностью: 35 маршрутов без единой
# проверки, включая POST /api/red/launch (запуск атакующей кампании),
# POST /api/incident/<id>/respond (действия реагирования) и маршруты,
# запускающие подпроцессы. Консоль среды (webapp.py :8787) при этом логин
# требовала — то есть защищённой была витрина, а не пульт управления.
#
# Учётные данные общие с консолью среды (config.WEB_ADMIN_USER/PASS), чтобы
# аналитик не держал два пароля.
#: Ограничение подбора пароля живёт в websec.LoginGuard (по источнику), а не
#: одним счётчиком на процесс: прежний вариант позволял одному подбирающему
#: закрыть вход всем остальным.

#: Маршруты, доступные без сессии.
_PUBLIC_PATHS = {"/login", "/logout", "/healthz"}

_COR = correlator_mod.Correlator(window_min=180)

_SUPPRESS = detector_mod.Suppressor()   # против флуда UEBA-всплесков в ленте

# Detection Engineering: правила, которые аналитик подтвердил как ложные.
# 3+ подтверждённых FP -> правило приглушается.
FP_MUTE_THRESHOLD = 3

#: Вердикты СТАРЕЮТ: приглушение по трём отметкам, поставленным полгода назад,
#: не должно действовать вечно.
FP_VERDICT_TTL_DAYS = 30

#: Правила, которые НЕ приглушаются автоматически НИКОГДА.
#:
#: Приглушение было выключателем детектирования, доступным через обычный шум:
#: три вердикта «ложное» — и правило больше не срабатывает, бессрочно, для всех
#: акторов и репозиториев, молча. Правило ci-debug-token-leak при этом
#: срабатывало по слову «debug» в СООБЩЕНИИ КОММИТА, то есть атакующий мог сам
#: вызвать три безобидных срабатывания и добиться, чтобы аналитик его выключил.
#: Замысел (автотюнинг шумных правил) верный, реализация была без пола, без
#: срока и без области действия.
NEVER_MUTE_SEVERITY = ("critical",)
NEVER_MUTE_RISK = 0.8

def incidents_snapshot():
    """Снимок инцидентов ПОД ЗАМКОМ — для обработчиков HTTP.

    Маршруты читали _COR.incidents напрямую, пока поток ингеста его пополнял:
    `list(_COR.incidents.values())` и `set(profs)` на живом словаре дают
    RuntimeError «dictionary changed size during iteration», а глобальный
    обработчик ошибок превращает это в 500 на дашборде. Плюс до правки часть
    записи (слияние signals) вообще шла вне замка, поэтому обработчик мог
    увидеть инцидент с уже добавленной сработкой, но ещё не пересчитанным
    risk/severity.
    """
    with _LOCK:
        return list(_COR.incidents.values())


def rule_verdict_stats():
    """rule_id -> (сколько FP-инцидентов, сколько TP-инцидентов) по вердиктам.

    Считаем и подтверждения, и опровержения. Раньше считались только FP, и
    правило глушилось по трём отметкам независимо от того, сколько настоящих
    атак оно поймало. Многошаговая кампания поднимает пять-шесть правил
    разом, поэтому ТРИ ложных инцидента гасили сразу пять правил — включая
    те, что работают с точностью 87%. Аналитик, честно разметивший шум,
    выключал детект.
    """
    import collections as _c
    fp = _c.Counter(); tp = _c.Counter()
    try:
        stat = eventstore.all_incident_status()
    except Exception:
        # Отказ хранилища здесь не безобиден: без вердиктов «живая точность»
        # на дашборде молча схлопывается в ноль, и это читается как «детектор
        # ничего не ловит», а не как «база недоступна».
        _flog.error("не удалось прочитать вердикты инцидентов — "
                    "точность детектирования будет показана без них",
                    exc_info=True)
        return fp, tp
    import datetime as _dt
    cutoff = _dt.datetime.now() - _dt.timedelta(days=FP_VERDICT_TTL_DAYS)
    incs = incidents_snapshot()
    for i in incs:
        st = stat.get(i["id"]) or {}
        v = st.get("verdict")
        if v not in ("fp", "tp"):
            continue
        # Устаревшие вердикты в приглушение не идут: правило, признанное
        # шумным месяц назад, могло быть с тех пор переписано.
        upd = st.get("updated")
        if upd:
            try:
                if _dt.datetime.fromisoformat(upd) < cutoff:
                    continue
            except (TypeError, ValueError):
                pass
        seen = set()
        for a in i["alerts"]:
            rid = a.get("rule_id")
            if rid and rid not in seen:
                seen.add(rid)
                (fp if v == "fp" else tp)[rid] += 1
    return fp, tp

def _rule_meta():
    """rule_id -> (severity, risk) из загруженного каталога."""
    try:
        return {r["id"]: (r.get("severity", "medium"), float(r.get("risk", 0.5)))
                for r in _engine().rules}
    except Exception:
        _flog.error("не удалось прочитать каталог правил для политики "
                    "приглушения", exc_info=True)
        return {}


def muted_rules():
    """rule_id -> число СВЕЖИХ подтверждённых FP для правил, которые можно
    приглушать.

    Правило считается шумным, если ложных отметок не меньше порога И ложных
    строго больше, чем подтверждённых атак. Правило, поймавшее настоящую атаку
    столько же раз или чаще, не трогаем: цена пропуска выше цены лишней тревоги.

    Сверх того — два ограничения, которых не было:
      • правила уровня critical и правила с риском >= NEVER_MUTE_RISK не
        приглушаются никогда. Для них шум разбирает человек, а не автомат:
        выключить «приватный ключ в коммите» тремя кликами нельзя;
      • вердикты старше FP_VERDICT_TTL_DAYS не учитываются (см. выше).
    """
    fp, tp = rule_verdict_stats()
    meta = _rule_meta()
    out = type(fp)()
    for rid, n in fp.items():
        sev, risk = meta.get(rid, ("medium", 0.5))
        if sev in NEVER_MUTE_SEVERITY or risk >= NEVER_MUTE_RISK:
            continue
        if n >= FP_MUTE_THRESHOLD and n > tp.get(rid, 0):
            out[rid] = n
    return out

_LOCK = threading.Lock()

_STATE = {
    "alerts": collections.deque(maxlen=800),
    "processed": 0, "alerts_total": 0,
    "by_actor": collections.Counter(),
    "by_repo": collections.Counter(),
    "by_tactic": collections.Counter(),
    "fired_tech": collections.Counter(),   # технике -> сколько раз сработала
    "fired_rule": collections.Counter(),   # rule_id -> сколько раз
    "muted_hits": 0,                       # сколько сработок отброшено FP-тюнингом
    "started": time.time(),
    "running": False,
    "mttd_sum": 0.0, "mttd_n": 0,
}

def _repo(v):
    """Имя репозитория для показа.

    В журнале есть старые события, где вместо названия лежит голый id
    проекта («6»): их писали до того, как справочник репозиториев стал
    полным. Реплей поднимает такие события заново, поэтому нормализуем
    на границе выдачи — в самом журнале ничего не переписываем.
    События без репозитория (например, создание API-токена) остаются
    пустыми: это честно, действие не привязано к коду.
    """
    if v is None or v == "":
        return None
    s = str(v)
    if s.isdigit():
        try:
            name = config.repo_name(int(s))
            if name and not str(name).isdigit():
                return name
        except (ValueError, KeyError):
            # Ожидаемый исход: id нет в справочнике (репозиторий пересоздали
            # или удалили). Показываем сам id — это честнее прочерка.
            pass
        except Exception:
            # Всё остальное — неожиданно и должно быть видно, иначе поле
            # «репозиторий» тихо деградирует до чисел по всему интерфейсу.
            _flog.error("сбой разрешения имени репозитория по id",
                        exc_info=True, extra={"ctx": {"id": s}})
    return s

_MUTED_CACHE = {"rules": {}, "ts": 0.0}

REPLAY_EVENTS = 6000   # сколько событий переигрывать при старте

def _engine():
    return run_defense._ENGINE

def _jsonsafe(o):
    if isinstance(o, dict):
        return {k: _jsonsafe(v) for k, v in o.items()}
    if isinstance(o, (set, frozenset)):
        return sorted(_jsonsafe(x) for x in o)
    if isinstance(o, (list, tuple)):
        return [_jsonsafe(x) for x in o]
    return o

_TACTIC_RU = {
    "reconnaissance": "разведка", "initial-access": "первичный доступ",
    "execution": "выполнение", "persistence": "закрепление",
    "privilege-escalation": "повышение привилегий", "defense-evasion": "обход защиты",
    "credential-access": "доступ к учётным данным", "discovery": "разведка внутри",
    "lateral-movement": "боковое перемещение", "collection": "сбор данных",
    "exfiltration": "вывод данных", "impact": "воздействие",
}

# === Воркфлоу аналитика: статусы инцидентов, SLA, вердикты ==================
_WF_STATUSES = ("new", "investigating", "contained", "closed")

# Период пересчёта метрик и состояние последнего прогона. Состояние
# отдаётся в /api/trends, чтобы на экране было видно, когда цифры
# обновлялись и когда обновятся снова: без этого «70%» на графике
# невозможно ни с чем соотнести — может, посчитано минуту назад, а может,
# висит с прошлого запуска.
SNAPSHOT_PERIOD_S = 300

_SNAP = {"last": None, "next": None, "running": False, "error": None, "count": 0}

# --- Health: строка здоровья (Мир жив? / события / Ollama / авто-триаж) -----
_HEALTH = {"ollama": None, "ts": 0.0}

# ----------------------------------------------------------------------
# --- Онбординг: демо-генератор и статус 5 шагов «счастливого пути» ----------
_DEMO = {"running": False, "msg": "", "rc": None}

# --- Executive Overview: страница для комиссии + метрики в подпроцессе -----
_EXECM = {"running": False, "data": None, "ts": 0.0, "err": ""}


# ----------------------------------------------------------------------
def _incident_ctx(iid, i):
    """Контекст инцидента для триажа — ТОЛЬКО наблюдаемые поля (анти-лик).

    Живёт в core, а не в разделе инцидентов, потому что нужен обеим сторонам:
    маршруту ручного разбора (incidents) и фоновому авто-триажу (ingest).
    Пока функция лежала в incidents, а звали её из ingest, между разделами
    был цикл — и `from .core import *` его прятал: имя разрешалось в рантайме
    через звёздочку, статический анализ молчал, а падало бы только на живом
    инциденте. Функция чистая (зависит лишь от аргументов), поэтому переезд
    в общий модуль ничего не тянет за собой.
    """
    g = i.get("signals", {})
    return {
        "incident_id": iid, "title": f"\u0418\u043d\u0446\u0438\u0434\u0435\u043d\u0442 @{i['actor']}",
        "actor": i["actor"], "repos": i["repos"],
        "risk_score": round(i.get("risk", i["max_risk"]), 2),
        "shannon_entropy": round(g.get("max_entropy", 0.0), 2),
        # regex здесь — уже НЕ-ЗАГЛУШЕЧНЫЕ совпадения (см. ingest): триаж не
        # должен считать настоящий токен примером из-за слова в соседней строке.
        "regex_hits": sorted(g.get("regex", set())),
        "real_hits": sorted(g.get("regex", set())),
        "n_regex_hits": len(g.get("regex", set())),
        "placeholder_signal": bool(g.get("placeholder")),
        "filename_signal": bool(g.get("filename")),
        # Чем секрет был скрыт от сканера — самостоятельная улика: обычный код
        # не прячет свои строки.
        "evasion_kinds": sorted(g.get("evasion", set())),
        "kill_chain_tactics": i["tactics"],
        "techniques": i["techniques"],
        # НА ЧЁМ ОСНОВАН ВЕРДИКТ. Без этих чисел фолбэк-разбор писал одну и ту
        # же фразу «итоговый риск X по поведенческим сигналам» — в том числе
        # инцидентам, где поведенческий слой не срабатывал НИ РАЗУ, а весь
        # риск дали правила. Аналитик читал объяснение, прямо противоречащее
        # вкладке Kill-chain («ПОВЕДЕНИЕМ 0»).
        "n_alerts": len(i.get("alerts") or []),
        "n_rule_alerts": sum(1 for a in (i.get("alerts") or [])
                             if (a.get("layer") or "") not in ("ueba", "ml")),
        "n_behaviour_alerts": sum(1 for a in (i.get("alerts") or [])
                                  if (a.get("layer") or "") in ("ueba", "ml")),
        "n_events": len({(a.get("ts_sim"), a.get("action"), a.get("path"))
                         for a in (i.get("alerts") or [])}),
        "events": [{"tactic": c.get("tactic"), "technique": c.get("technique"),
                    "action": c.get("action")} for c in i.get("chain", [])][:20],
    }
