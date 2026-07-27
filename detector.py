"""
Blue Detection Stack — потоковый детектор для контура «защита».

Слои:
  L0  Rules Engine — правила из detections/*.json (Detection-as-Code): условие по
      НАБЛЮДАЕМЫМ полям события → alert + привязка к MITRE ATT&CK.
  L1  UEBA — профили акторов (часы, репозитории, действия); скорит новизну
      поведения (новый репо, off-hours, редкое действие) без меток.
  Fusion — объединяет сработки в один скоринг события.

АНТИ-ЛИК: на вход подаются только наблюдаемые поля (см. run_defense.observed),
метки мира (is_anomaly/anomaly_type/family/...) детектор не видит и не использует.

Зависимостей нет (json/stdlib). Правила — JSON, чтобы работало без pyyaml.
"""
import os
import json
import glob
import logging
import collections

log = logging.getLogger("detector")

RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "detections")


# ----------------------------------------------------------------------
def _match_cond(value, cond):
    """Одно условие поля: прямое значение или {op: arg}."""
    if isinstance(cond, dict):
        for op, arg in cond.items():
            if op == ">=":
                if not (isinstance(value, (int, float)) and value >= arg): return False
            elif op == ">":
                if not (isinstance(value, (int, float)) and value > arg): return False
            elif op == "<=":
                if not (isinstance(value, (int, float)) and value <= arg): return False
            elif op == "<":
                if not (isinstance(value, (int, float)) and value < arg): return False
            elif op == "ne":
                if value == arg: return False
            elif op == "in":
                if value not in arg: return False
            elif op == "nin":
                if value in arg: return False
            elif op == "contains":
                if value is None: return False
                if isinstance(value, (list, tuple, set)):
                    if arg not in value: return False
                else:
                    if arg not in str(value): return False
            else:
                return False
        return True
    return value == cond


def _match_rule(event, when):
    for field, cond in when.items():
        if not _match_cond(event.get(field), cond):
            return False
    return True


# ----------------------------------------------------------------------
def _cfg(name, default):
    try:
        import config
        return getattr(config, name, default)
    except Exception:
        return default


def _parse_ts(ts):
    from datetime import datetime
    try:
        return datetime.strptime(ts or "", "%Y-%m-%dT%H:%M:%S")
    except Exception:
        return None


class UEBA:
    """Поведенческие профили акторов (учится на потоке, без меток).
    Сигналы: новизна репо, off-hours, редкое действие, ВСПЛЕСК активности (velocity)."""

    def __init__(self):
        self.MIN_EVENTS = _cfg("UEBA_MIN_EVENTS", 12)
        self.THRESHOLD = _cfg("UEBA_THRESHOLD", 0.45)
        self.VEL_WIN = _cfg("UEBA_VELOCITY_WINDOW_MIN", 30)
        self.VEL_SPIKE = _cfg("UEBA_VELOCITY_SPIKE", 14)
        self.actor = collections.defaultdict(lambda: {
            "n": 0, "hours": collections.Counter(),
            "repos": collections.Counter(), "actions": collections.Counter(),
            "recent": collections.deque(maxlen=64)})

    def score(self, ev):
        """Скор новизны ДО обновления профиля. Возвращает (risk, reasons)."""
        a = ev.get("actor")
        if not a:
            return 0.0, []
        p = self.actor[a]
        if p["n"] < self.MIN_EVENTS:
            return 0.0, []
        risk = 0.0; reasons = []
        proj = ev.get("project")
        if proj and p["repos"].get(proj, 0) == 0:
            risk += 0.3; reasons.append(f"новый для @{a} репозиторий {proj}")
        hr = ev.get("hour")
        if ev.get("is_night") and p["hours"].get(hr, 0) <= 1:
            risk += 0.2; reasons.append("активность в нетипичный для актора час")
        act = ev.get("action")
        if act and p["actions"].get(act, 0) == 0:
            risk += 0.2; reasons.append(f"нетипичное действие {act}")
        # velocity: всплеск событий в окне
        t = _parse_ts(ev.get("ts_sim"))
        if t:
            near = [x for x in p["recent"] if abs((t - x).total_seconds()) <= self.VEL_WIN * 60]
            if len(near) + 1 >= self.VEL_SPIKE:
                # всплеск — слабый вспомогательный сигнал: сам по себе это не инцидент,
                # иначе он забивает ленту одинаковыми алертами risk=0.5
                risk += 0.15; reasons.append(f"всплеск активности ({len(near)+1} за {self.VEL_WIN}м)")
        return min(1.0, risk), reasons

    def update(self, ev):
        a = ev.get("actor")
        if not a:
            return
        p = self.actor[a]
        p["n"] += 1
        if ev.get("hour") is not None: p["hours"][ev["hour"]] += 1
        if ev.get("project"): p["repos"][ev["project"]] += 1
        if ev.get("action"): p["actions"][ev["action"]] += 1
        t = _parse_ts(ev.get("ts_sim"))
        if t: p["recent"].append(t)


# ----------------------------------------------------------------------
def fuse(alerts, mode=None):
    """Слияние рисков нескольких сработок в один скоринг события.
      max       — берём максимум (консервативно);
      noisy_or  — 1 - prod(1 - r): согласие НЕСКОЛЬКИХ слоёв повышает уверенность
                  (правило + UEBA про одно и то же -> риск выше каждого по
                  отдельности). По умолчанию noisy_or."""
    if not alerts:
        return 0.0
    mode = mode or _cfg("FUSION_MODE", "noisy_or")
    risks = [float(a.get("risk", 0.0)) for a in alerts]
    if mode == "max":
        return min(0.99, max(risks))
    prod = 1.0
    for r in risks:
        prod *= (1.0 - max(0.0, min(1.0, r)))
    return round(min(0.99, 1.0 - prod), 4)


class Suppressor:
    """Подавление дублей (alert fatigue): одинаковый (actor, rule_id) в пределах
    окна считается повтором и подавляется. Состояние — в памяти процесса."""

    def __init__(self, window_min=None):
        self.window = window_min if window_min is not None else _cfg("ALERT_SUPPRESS_MIN", 60)
        self._last = {}

    def is_duplicate(self, actor, rule_id, ts):
        t = _parse_ts(ts) if isinstance(ts, str) else ts
        key = (actor, rule_id)
        prev = self._last.get(key)
        self._last[key] = t
        if prev is None or t is None:
            return False
        return abs((t - prev).total_seconds()) <= self.window * 60


# ----------------------------------------------------------------------
class DetectionEngine:
    def __init__(self, rules_dir=None):
        if rules_dir is None:
            d = _cfg("DETECTIONS_DIR", "detections")
            rules_dir = d if os.path.isabs(d) else os.path.join(
                os.path.dirname(os.path.abspath(__file__)), d)
        self.rules = self._load(rules_dir)
        self.ueba = UEBA()

    def _load(self, rules_dir):
        rules, seen = [], set()
        dirs = [rules_dir]
        if _cfg("LOAD_PROPOSED", False):
            dirs.append(os.path.join(rules_dir, "proposed"))
        for d in dirs:
            for fp in sorted(glob.glob(os.path.join(d, "*.json"))):
                try:
                    r = json.load(open(fp, encoding="utf-8"))
                    if r.get("id") and r["id"] not in seen:
                        seen.add(r["id"]); rules.append(r)
                    elif not r.get("id"):
                        log.warning("правило без id пропущено",
                                    extra={"ctx": {"file": fp}})
                except Exception as e:
                    log.error("правило не загрузилось: %s (%s)", fp, e,
                              extra={"ctx": {"file": fp}})
        log.info("загружено правил: %d", len(rules),
                 extra={"ctx": {"rules": sorted(seen)}})
        return rules

    def rule_count(self):
        return len(self.rules)

    def techniques_covered(self):
        return sorted({r.get("technique") for r in self.rules if r.get("technique")})

    def process(self, ev):
        """Прогнать событие через L0+L1. Возвращает dict со списком сработок.
        Профиль UEBA обновляется ПОСЛЕ скоринга."""
        alerts = []
        # L0 — правила
        for r in self.rules:
            if _match_rule(ev, r.get("when", {})):
                alerts.append({
                    "layer": "rules", "rule_id": r["id"], "title": r["title"],
                    "technique": r.get("technique"), "tactic": r.get("tactic"),
                    "severity": r.get("severity", "medium"), "risk": float(r.get("risk", 0.5)),
                    "reason": r["title"],
                })
        # L1 — UEBA
        u_risk, u_reasons = self.ueba.score(ev)
        if u_risk >= self.ueba.THRESHOLD:
            alerts.append({
                "layer": "ueba", "rule_id": "ueba-behavior",
                "title": "Поведенческая аномалия (UEBA)",
                "technique": "UEBA", "tactic": "Behavioral",
                "severity": "medium" if u_risk < 0.6 else "high", "risk": round(u_risk, 2),
                "reason": "; ".join(u_reasons) or "отклонение от базлайна актора",
            })
        self.ueba.update(ev)

        _ctx = {"actor": ev.get("actor"), "action": ev.get("action"),
                "project": ev.get("project"), "ts_sim": ev.get("ts_sim"),
                "event_id": ev.get("_id")}
        if not alerts:
            log.debug("no-alert", extra={"ctx": {**_ctx,
                      "ueba_risk": round(u_risk, 3),
                      "rules_checked": len(self.rules)}})
            return {"alert": False, "risk": 0.0, "alerts": []}
        risk = fuse(alerts)
        techs = sorted({a["technique"] for a in alerts if a.get("technique")})
        tactics = sorted({a["tactic"] for a in alerts if a.get("tactic")})
        log.info("alert", extra={"ctx": {**_ctx,
                 "rules_hit": [a["rule_id"] for a in alerts if a["layer"] == "rules"],
                 "layer_risks": {a["rule_id"]: a["risk"] for a in alerts},
                 "ueba_risk": round(u_risk, 3), "ueba_reasons": u_reasons,
                 "fused_risk": round(risk, 3),
                 "techniques": techs, "tactics": tactics}})
        return {"alert": True, "risk": round(risk, 2), "alerts": alerts,
                "techniques": techs, "tactics": tactics}
