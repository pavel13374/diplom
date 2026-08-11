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

    @staticmethod
    def _incident_risk(inc):
        """Риск ИНЦИДЕНТА — слияние по слоям, а не максимум по событиям.

        Почему максимума недостаточно
        -----------------------------
        Слияние рисков (detector.fuse) работает ПОСОБЫТИЙНО: оно складывает
        свидетельства слоёв, сработавших на ОДНОМ И ТОМ ЖЕ событии. Но
        многошаговая кампания по построению растянута по событиям: правило
        срабатывает на шаге «push секрета», поведенческий слой — на шаге
        «ночной доступ к чужому репозиторию», модель — на шаге «выгрузка».
        Пособытийное слияние эти свидетельства НИКОГДА не встретит.

        Практическое следствие было измерено в research/ablation.py: слой L1
        находил эпизоды, которых не находили правила, но ни одно его
        срабатывание в одиночку не дотягивало до порога действия 0.6, а
        `max_risk` по определению не умеет складывать. Вклад слоя выходил
        статистически неотличимым от нуля — не потому, что слой слеп, а
        потому, что его свидетельство некуда было положить.

        Как считается
        -------------
        Внутри инцидента берётся МАКСИМУМ по каждому слою отдельно, и эти
        максимумы сливаются той же формулой, что и пособытийно:

            logit R = logit π + Σ_i γ^i · (logit r_i − logit π)

        Максимум внутри слоя, а не сумма: два срабатывания одного правила на
        соседних шагах — это одно свидетельство, повторённое дважды, и считать
        его дважды значило бы вернуть ту же ошибку двойного учёта приора,
        из-за которой формула слияния переписывалась.

        Инцидент из одного слоя получает ровно свой риск — совместимо с
        прежним поведением там, где сливать нечего.
        """
        best = {}
        for a in inc.get("alerts", []):
            layer = a.get("layer") or "unknown"
            best[layer] = max(best.get(layer, 0.0), float(a.get("risk", 0.0)))
        # свидетельства слоёв, не породившие тревогу (см. add())
        for layer, r in (inc.get("evidence") or {}).items():
            best[layer] = max(best.get(layer, 0.0), float(r))
        if not best:
            return float(inc.get("max_risk", 0.0))
        try:
            import detector
            return detector.fuse([{"risk": r} for r in best.values()])
        except Exception:
            log.error("не удалось слить риск инцидента — беру максимум",
                      exc_info=True, extra={"ctx": {"incident_id": inc.get("id")}})
            return max(best.values())

    def add(self, ev, det):
        """ev — наблюдаемое событие (с ts_sim/actor/...); det — результат
        detector.process() (alert=True). Возвращает incident_id."""
        actor = ev.get("actor") or "unknown"
        ts = ev.get("ts_sim")
        t = _parse(ts)
        iid = self._open_by_actor.get(actor)
        inc = self.incidents.get(iid) if iid else None

        # ЗАКРЫТЬ ОКНО, ЕСЛИ РАЗРЫВ БОЛЬШЕ window_min — В ЛЮБУЮ СТОРОНУ.
        #
        # Сравнение шло только вперёд: (t - last) > window. Симулированное
        # время не монотонно — при перезапуске мира оно откатывается назад, и
        # тогда разрыв получался отрицательным, условие не выполнялось, окно
        # не закрывалось. События разных симулированных дней склеивались в
        # один инцидент: в живом стенде нашёлся такой с началом 14 сентября,
        # концом 11 августа и семью репозиториями. Цепочка атаки в нём
        # бессмысленна, а метрика ложных срабатываний считает его окно
        # пересекающимся почти с любым эпизодом.
        if inc is not None and t is not None:
            last = _parse(inc["last_ts"])
            if last and abs((t - last).total_seconds()) > self.window_min * 60:
                log.debug("окно инцидента закрыто по разрыву во времени",
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
                "max_risk": 0.0, "alerts": [], "evidence": {},
                "tactics": [], "techniques": [],
                "repos": [], "chain": [], "seen_real": _time.time(),
            }
            self.incidents[iid] = inc
            self._open_by_actor[actor] = iid

        # Границы окна — минимум и максимум, а не «последнее присвоенное».
        # Внутри окна события тоже приходят не строго по возрастанию
        # симулированного времени.
        if _parse(ts) and _parse(inc["last_ts"]) and _parse(ts) < _parse(inc["last_ts"]):
            inc["start_ts"] = min(inc["start_ts"], ts)
        else:
            inc["last_ts"] = ts
        if _parse(ts) and _parse(inc["start_ts"]) and _parse(ts) < _parse(inc["start_ts"]):
            inc["start_ts"] = ts
        inc["max_risk"] = max(inc["max_risk"], det.get("risk", 0))
        proj = ev.get("project")
        if proj and proj not in inc["repos"]:
            inc["repos"].append(proj)

        # СВИДЕТЕЛЬСТВА БЕЗ ТРЕВОГИ.
        #
        # Слой ML участвует в решении двумя способами: собственной тревогой
        # (выше порога FP-бюджета) и «свидетельством» — когда его вероятность
        # заметно выше приора, но до порога не дотягивает. Свидетельство входит
        # в ПОСОБЫТИЙНОЕ слияние, но в очередь аналитика не попадает.
        #
        # Раньше корреляция читала только det["alerts"], поэтому риск инцидента
        # считался без свидетельств и оказывался НИЖЕ риска события, из которого
        # инцидент состоит. На ablation это было видно как потеря четырёх
        # эпизодов при переходе от пособытийной оценки к инцидентной — величина,
        # которая по построению не может быть отрицательной.
        #
        # Свидетельства складываем в inc["evidence"] — они учитываются в риске,
        # но не показываются как отдельные детекты в таймлайне.
        for e in det.get("evidence", []):
            layer = e.get("layer") or "evidence"
            prev = inc.setdefault("evidence", {}).get(layer, 0.0)
            inc["evidence"][layer] = max(prev, float(e.get("risk", 0.0)))

        for a in det.get("alerts", []):
            inc["alerts"].append({
                # ts_sim — время СИМУЛЯЦИИ, оно скачет и сжато относительно
                # реального. Чтобы ответить на вопрос «что прилетело после
                # того, как я нажал „Запустить“», нужна отметка реального
                # времени: экран запуска сценариев отбирал инциденты по
                # первому появлению и не видел детекты, подклеившиеся к уже
                # существующему инциденту того же актора.
                "seen_real": _time.time(),
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
        inc["touched_real"] = _time.time()
        inc["is_campaign"] = len([x for x in inc["tactics"] if x != "Behavioral"]) >= 2
        inc["risk"] = self._incident_risk(inc)
        inc["severity"] = ("critical" if inc["risk"] >= 0.85 else
                           "high" if inc["risk"] >= 0.6 else
                           "medium" if inc["risk"] >= 0.4 else "low")
        log.log(logging.INFO if _new else logging.DEBUG,
                "инцидент открыт" if _new else "инцидент продлён",
                extra={"ctx": {"incident_id": iid, "actor": actor,
                               "severity": inc["severity"],
                               "risk": round(inc["risk"], 3),
                               "max_risk": round(inc["max_risk"], 3),
                               "layers": sorted({a.get("layer")
                                                 for a in inc["alerts"]
                                                 if a.get("layer")}),
                               "alerts": len(inc["alerts"]),
                               "tactics": inc["tactics"],
                               "is_campaign": inc["is_campaign"],
                               "why": "первый алерт актора в окне" if _new
                                      else "алерт того же актора в пределах окна",
                               "rule_ids": [a.get("rule_id") for a in det.get("alerts", [])]}})
        return iid

    def list(self, limit=50):
        out = sorted(self.incidents.values(),
                     key=lambda i: (-i.get("risk", i["max_risk"]), -len(i["alerts"])))
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
