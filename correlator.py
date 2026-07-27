"""
Корреляционный движок (EPIC 3) — склеивает blue-алерты в ИНЦИДЕНТЫ.

Логика: алерты одного актора в пределах временно́го окна (по sim-времени) =
один инцидент. Инцидент копит ATT&CK-цепочку (тактики/техники по порядку),
максимальный risk, затронутые репозитории. Если в цепочке ≥2 РАЗНЫХ тактик —
это многошаговая атака (kill-chain), помечаем как campaign-like.

ВАЖНО: корреляция работает на blue-АЛЕРТАХ детектора (наблюдаемое), а НЕ на
campaign_id из мира — то есть защита сама восстанавливает цепочку, честно.
"""
import logging
import itertools
import time as _time
from datetime import datetime

log = logging.getLogger("correlator")

_ids = itertools.count(1)


def _stable_iid(actor, start_ts):
    """Стабильный id инцидента: одинаковый после рестарта консоли.

    Инциденты живут в памяти, а вердикты TP/FP — в SQLite по id. Если id
    выдавать счётчиком, после рестарта тот же инцидент получал новый номер и
    выставленный вердикт «терялся». Хэш от (актор + время начала) это чинит.
    """
    import hashlib
    h = hashlib.sha1(f"{actor}|{start_ts}".encode("utf-8")).hexdigest()
    return int(h[:8], 16) % 90000000 + 1000


def _parse(ts):
    try:
        return datetime.strptime(ts or "", "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None


class Correlator:
    def __init__(self, window_min=180):
        self.window_min = window_min
        self.incidents = {}            # iid -> incident dict
        self._open_by_actor = {}       # actor -> iid (последний открытый)

    def add(self, ev, det):
        """ev — наблюдаемое событие (с ts_sim/actor/...); det — результат
        detector.process() (alert=True). Возвращает incident_id."""
        actor = ev.get("actor") or "unknown"
        ts = ev.get("ts_sim")
        t = _parse(ts)
        iid = self._open_by_actor.get(actor)
        inc = self.incidents.get(iid) if iid else None

        # закрыть окно, если прошло больше window_min
        if inc is not None and t is not None:
            last = _parse(inc["last_ts"])
            if last and (t - last).total_seconds() > self.window_min * 60:
                log.debug("окно инцидента закрыто по таймауту",
                          extra={"ctx": {"incident_id": inc["id"], "actor": actor,
                                         "gap_min": round((t - last).total_seconds() / 60, 1),
                                         "window_min": self.window_min}})
                inc = None

        _new = inc is None
        if inc is None:
            iid = _stable_iid(actor, ts)
            while iid in self.incidents:      # редкая коллизия хэша
                iid += 1
            inc = {
                "id": iid, "actor": actor, "start_ts": ts, "last_ts": ts,
                "max_risk": 0.0, "alerts": [], "tactics": [], "techniques": [],
                "repos": [], "chain": [], "seen_real": _time.time(),
            }
            self.incidents[iid] = inc
            self._open_by_actor[actor] = iid

        inc["last_ts"] = ts
        inc["max_risk"] = max(inc["max_risk"], det.get("risk", 0))
        proj = ev.get("project")
        if proj and proj not in inc["repos"]:
            inc["repos"].append(proj)
        for a in det.get("alerts", []):
            inc["alerts"].append({
                "ts_sim": ts, "action": ev.get("action"), "project": proj,
                "path": ev.get("path"), "branch": ev.get("branch"), "mr_iid": ev.get("mr_iid"),
                "risk": a["risk"], "technique": a.get("technique"),
                "tactic": a.get("tactic"), "reason": a.get("reason"),
                "layer": a.get("layer"), "rule_id": a.get("rule_id"),
            })
            tac = a.get("tactic"); tech = a.get("technique")
            if tac and tac not in inc["tactics"]:
                inc["tactics"].append(tac)
            if tech and tech not in inc["techniques"]:
                inc["techniques"].append(tech)
            inc["chain"].append({"ts": ts, "tactic": tac, "technique": tech,
                                 "action": ev.get("action"), "risk": a["risk"]})
        inc["is_campaign"] = len([x for x in inc["tactics"] if x != "Behavioral"]) >= 2
        inc["severity"] = ("critical" if inc["max_risk"] >= 0.85 else
                           "high" if inc["max_risk"] >= 0.6 else
                           "medium" if inc["max_risk"] >= 0.4 else "low")
        log.log(logging.INFO if _new else logging.DEBUG,
                "инцидент открыт" if _new else "инцидент продлён",
                extra={"ctx": {"incident_id": iid, "actor": actor,
                               "severity": inc["severity"],
                               "max_risk": round(inc["max_risk"], 3),
                               "alerts": len(inc["alerts"]),
                               "tactics": inc["tactics"],
                               "is_campaign": inc["is_campaign"],
                               "why": "первый алерт актора в окне" if _new
                                      else "алерт того же актора в пределах окна",
                               "rule_ids": [a.get("rule_id") for a in det.get("alerts", [])]}})
        return iid

    def list(self, limit=50):
        out = sorted(self.incidents.values(),
                     key=lambda i: (-i["max_risk"], -len(i["alerts"])))
        return out[:limit]

    def get(self, iid):
        return self.incidents.get(int(iid))

    def summary(self):
        inc = list(self.incidents.values())
        return {
            "incidents": len(inc),
            "campaigns": sum(1 for i in inc if i.get("is_campaign")),
            "critical": sum(1 for i in inc if i.get("severity") == "critical"),
        }
