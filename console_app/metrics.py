# -*- coding: utf-8 -*-
"""Тренды, ROI, сводка для руководства, наука

Часть консоли защиты. Вынесено из console.py: там 1841 строка держала
маршруты, ингест, триаж и сборку отчётов в одном файле, и правка одного
раздела требовала удерживать в голове все остальные.

Состояние и общие хелперы — в console_app.core, оно ЕДИНСТВЕННОЕ на процесс
и импортируется по имени: объекты (_COR, _STATE, _LOCK) создаются один раз
при импорте core и никогда не переприсваиваются, поэтому у всех разделов
общий экземпляр, а не копии.
"""

import time
import json
import threading
import config
import eventstore
from datetime import datetime
from flask import Blueprint, jsonify

# Общее состояние консоли — ЯВНО, а не через `import *`:
# видно, чем раздел пользуется, и статический анализ снова работает.
from .core import ROOT, SNAPSHOT_PERIOD_S, _COR, _EXECM, _LOCK, _SNAP, \
    _flog


# Фоновый пересчёт сводки живёт в ingest вместе с остальными воркерами:
# здесь он только запускается по требованию первого запроса.
# Фоновый пересчёт сводки и снятие снимка метрик живут в ingest вместе с
# остальными воркерами; здесь они запускаются по требованию из маршрутов.
from .ingest import _metrics_worker, _take_metrics_snapshot

bp = Blueprint("metrics", __name__)

# === ROI-калькулятор: живой MTTD -> экономия ================================
@bp.route("/api/roi")
def api_roi():
    """Живой MTTD из последнего снапшота метрик (без пересчёта)."""
    hist = eventstore.metrics_history(1000)
    mttd = None
    for h in reversed(hist):
        if h.get("mttd") is not None:
            mttd = h["mttd"]; break
    with _LOCK:
        inc = len(_COR.incidents)
    return jsonify({"mttd_sim_min": mttd, "incidents_seen": inc})

# === Тренды метрик: снапшот + история + аннотации + CSV =====================
@bp.route("/api/metrics/snapshot", methods=["POST"])
def api_metrics_snapshot():
    """Пересчитать метрики немедленно, не дожидаясь фонового цикла."""
    if _SNAP.get("running"):
        return jsonify({"ok": True, "saved": False, "note": "пересчёт уже идёт"})
    if _EXECM["data"]:
        m = _EXECM["data"]
        eventstore.add_metrics_snapshot({
            "detection_rate": m.get("detection_rate"), "mttd": m.get("mttd_sim_min"),
            "fp_rate": m.get("fp_rate"), "coverage": m.get("attack_coverage"),
            "alerts": m.get("alerts"), "incidents": m.get("incidents")})
        _SNAP["last"] = datetime.now().isoformat(timespec="seconds")
        _SNAP["count"] += 1
        return jsonify({"ok": True, "saved": True})
    threading.Thread(target=_take_metrics_snapshot, daemon=True).start()
    return jsonify({"ok": True, "saved": False, "note": "метрики считаются"})

@bp.route("/api/trends")
def api_trends():
    # Вместе с историей отдаём состояние фонового пересчёта: когда цифры
    # обновлялись в последний раз и когда обновятся снова.
    nxt = _SNAP.get("next")
    left = None
    if nxt:
        try:
            left = max(0, int((datetime.fromisoformat(nxt) - datetime.now()).total_seconds()))
        except ValueError:
            left = None
    return jsonify({"history": eventstore.metrics_history(1000),
                    "annotations": eventstore.annotations(200),
                    "snapshot": {"last": _SNAP.get("last"), "next_in_s": left,
                                 "period_s": SNAPSHOT_PERIOD_S,
                                 "running": _SNAP.get("running"),
                                 "error": _SNAP.get("error"),
                                 "count": _SNAP.get("count", 0)}})

@bp.route("/api/trends.csv")
def api_trends_csv():
    from flask import Response
    import io as _io
    import csv as _csv
    rows = eventstore.metrics_history(5000)
    buf = _io.StringIO()
    w = _csv.writer(buf)
    w.writerow(["ts", "detection_rate", "mttd", "fp_rate", "coverage", "alerts"])
    for h in rows:
        w.writerow([h["ts"], h["detection_rate"], h["mttd"], h["fp_rate"], h["coverage"], h["alerts"]])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=metrics_trends.csv"})

@bp.route("/api/executive")
def api_executive():
    if not _EXECM["running"] and (time.time() - _EXECM["ts"] > 120):
        _EXECM["running"] = True
        threading.Thread(target=_metrics_worker, daemon=True).start()
    holdout = []
    try:
        import csv
        import os
        p = os.path.join(ROOT, "results", "holdout.csv")
        with open(p, encoding="utf-8") as f:
            holdout = list(csv.DictReader(f))
    except Exception:
        holdout = []
    return jsonify({"metrics": _EXECM["data"], "computing": _EXECM["running"],
                    "metrics_err": _EXECM["err"], "holdout": holdout})

@bp.route("/api/science")
def api_science():
    import csv
    import os
    base = os.path.join(ROOT, "results")
    out = {}
    for name in ("experiments", "roc", "layers", "arena", "holdout"):
        try:
            with open(os.path.join(base, name + ".csv"), encoding="utf-8") as f:
                out[name] = list(csv.DictReader(f))
        except Exception:
            _flog.debug("нет выгрузки эксперимента %s.csv", name)
            out[name] = []
    # JSON-выгрузки новых экспериментов: ablation, кривая нагрузки, компоненты UEBA
    for name in ("ablation", "workload_curve", "ueba_components"):
        try:
            with open(os.path.join(base, name + ".json"), encoding="utf-8") as f:
                out[name] = json.load(f)
        except FileNotFoundError:
            out[name] = None
        except Exception:
            _flog.error("не удалось прочитать results/%s.json", name, exc_info=True)
            out[name] = None
    return jsonify(out)

@bp.route("/api/workload_curve.json")
def api_workload_curve():
    """Замер «полнота против нагрузки» — данными, а не картинкой.

    Раньше отдавался готовый SVG из results/. Картинка рисовалась на белом
    листе с зашитыми цветами: в тёмной теме это был белый прямоугольник
    посреди страницы, а масштаб и подписи не подстраивались ни под ширину
    панели, ни под данные. Отдаём числа, рисует консоль.

    Если замера нет — отдаём пустой список, а не 404: интерфейс покажет
    «ещё не построен» с командой запуска. Молчаливая ошибка в сети выглядит
    как поломка, хотя причина в том, что эксперимент просто не запускали.
    """
    import os
    p = os.path.join(ROOT,
                     "results", "workload_curve.json")
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return jsonify({"points": [], "reason": "не построен"})
    except Exception:
        _flog.error("не удалось прочитать results/workload_curve.json", exc_info=True)
        return jsonify({"points": [], "reason": "файл повреждён"})
    # Порог мог измениться после замера — берём актуальный, чтобы панель
    # отмечала «сейчас» там, где продукт действительно стоит сегодня.
    data["current_threshold"] = getattr(config, "ACTION_THRESHOLD", 0.6)
    return jsonify(data)

