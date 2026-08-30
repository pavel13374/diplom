"""
Персистентное состояние симулятора — «память отдела».

Хранит жизненный цикл правил (статус, возраст, FP-история), номер спринта,
индекс on-call ротации, счётчики Issue/релизов, отпуска. Благодаря этому
активности перестают быть случайными: тюнят ИМЕННО шумное правило,
промоутят ИМЕННО давно чистое, депрекейтят ИМЕННО мёртвое.

Состояние best-effort: если правила нет в стейте — активности откатываются
к выбору из реального репозитория (обратная совместимость).
"""
import os
import json
import random
import logging
from datetime import datetime, date
from typing import Optional

import config
import simclock

logger = logging.getLogger(__name__)


def _parse(d: str) -> Optional[date]:
    try:
        return datetime.fromisoformat(d).date()
    except Exception:
        try:
            return datetime.strptime(d, "%Y-%m-%d").date()
        except Exception:
            return None


class SimState:
    def __init__(self, path: str):
        self.path = path
        self.data = {
            "rules":         {},   # slug -> {...}
            "sprint_start":  None, # iso date старта спринта
            "sprint_number": 1,
            "oncall_index":  0,
            "issue_seq":     1000,
            "release_seq":   0,
            "campaign_seq":  0,
            "pto":           {},   # iso_date -> username
            "pending_reverts": [], # [{slug, due_iso, reason}]
        }
        self._load()

    # ------------------------------------------------------------------
    def _load(self):
        """Читаем основной файл, при неудаче — резервный.

        Ошибка разбора логируется как ERROR, а не WARNING: это ПОТЕРЯ
        накопленного состояния, а не мелкая неприятность, и она обязана быть
        видна на странице диагностики.
        """
        for path, kind in ((self.path, "основной"), (self.path + ".bak", "резервный")):
            if not os.path.exists(path):
                continue
            try:
                with open(path, encoding="utf-8") as f:
                    loaded = json.load(f)
                if not isinstance(loaded, dict):
                    raise ValueError("состояние не является объектом JSON")
                self.data.update(loaded)
                logger.info("[State] загружено (%s): %d правил, спринт #%s", kind,
                            len(self.data["rules"]), self.data["sprint_number"])
                return
            except Exception:
                logger.error("[State] не удалось прочитать %s файл состояния — "
                             "пробую следующий", kind, exc_info=True,
                             extra={"ctx": {"file": path}})

    def save(self):
        """АТОМАРНАЯ запись: временный файл -> fsync -> замена.

        Раньше было open(path, "w"), то есть файл сначала обрезался, а потом
        наполнялся. Прерывание в этот момент оставляло обрезанный файл;
        _load ловил ошибку разбора, писал WARNING и продолжал с пустыми
        значениями — то есть потеря была МОЛЧАЛИВОЙ. А в файле лежит жизненный
        цикл правил, номер спринта, ротация дежурств и отложенные откаты, то
        есть та самая «память отдела», без которой активности снова становятся
        случайными.

        save() зовётся ещё и на каждом инкременте счётчика (next_issue_id,
        next_release, set_pto), поэтому окно уязвимости было широким.
        """
        tmp = self.path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False, indent=2)
                f.flush()
                os.fsync(f.fileno())
            if os.path.exists(self.path):
                try:
                    # одно поколение резерва: если новый файл окажется битым,
                    # есть куда откатиться
                    os.replace(self.path, self.path + ".bak")
                except OSError:
                    pass
            os.replace(tmp, self.path)
        except Exception:
            logger.error("[State] не удалось сохранить состояние — прогресс "
                         "прогона будет потерян", exc_info=True,
                         extra={"ctx": {"file": self.path}})
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Правила
    # ------------------------------------------------------------------
    def register_rule(self, slug, path, tactic, status="experimental",
                      author=""):
        self.data["rules"][slug] = {
            "path":     path,
            "tactic":   tactic,
            "status":   status,
            "author":   author,
            "created":  simclock.today_iso(),
            "modified": simclock.today_iso(),
            "fp_rate":  random.randint(0, 12),
            "noisy":    False,
            "tunes":    0,
        }
        self.save()

    def update_rule(self, slug, **kw):
        r = self.data["rules"].get(slug)
        if r:
            r.update(kw)
            r["modified"] = simclock.today_iso()
            self.save()

    def remove_rule(self, slug):
        if slug in self.data["rules"]:
            del self.data["rules"][slug]
            self.save()

    def get_rule(self, slug):
        return self.data["rules"].get(slug)

    def _age_days(self, r) -> int:
        c = _parse(r.get("created", ""))
        return (simclock.today() - c).days if c else 0

    # --- умный выбор целей --------------------------------------------
    def pick_noisy(self) -> Optional[dict]:
        cand = [
            {"slug": s, **r} for s, r in self.data["rules"].items()
            if not r.get("deprecated") and (r.get("noisy") or r.get("fp_rate", 0) >= 25)
        ]
        return max(cand, key=lambda x: x.get("fp_rate", 0)) if cand else None

    def pick_promotable(self) -> Optional[dict]:
        cand = [
            {"slug": s, **r} for s, r in self.data["rules"].items()
            if not r.get("deprecated")
            and r.get("status") in ("experimental", "stable")
            and r.get("fp_rate", 99) < 8
            and self._age_days(r) >= 10
        ]
        return random.choice(cand) if cand else None

    def pick_deprecatable(self) -> Optional[dict]:
        cand = [
            {"slug": s, **r} for s, r in self.data["rules"].items()
            if not r.get("deprecated")
            and self._age_days(r) >= 25
            and r.get("fp_rate", 0) == 0
            and r.get("status") != "production"
        ]
        return random.choice(cand) if cand else None

    def rule_count(self) -> int:
        return sum(1 for r in self.data["rules"].values() if not r.get("deprecated"))

    # ------------------------------------------------------------------
    # Отложенные реверты
    # ------------------------------------------------------------------
    def schedule_revert(self, slug, reason, delay_days=1):
        due = (simclock.today()).fromordinal(simclock.today().toordinal() + delay_days)
        self.data["pending_reverts"].append({
            "slug": slug, "reason": reason, "due_iso": due.isoformat(),
        })
        self.save()

    def due_reverts(self):
        today = simclock.today()
        due = [p for p in self.data["pending_reverts"]
               if (_parse(p["due_iso"]) or today) <= today]
        return due

    def clear_revert(self, slug):
        self.data["pending_reverts"] = [
            p for p in self.data["pending_reverts"] if p["slug"] != slug
        ]
        self.save()

    # ------------------------------------------------------------------
    # Спринты
    # ------------------------------------------------------------------
    def ensure_sprint(self):
        """Возвращает (number, start_date); крутит счётчик при необходимости."""
        start = _parse(self.data.get("sprint_start") or "")
        today = simclock.today()
        if start is None:
            start = today
            self.data["sprint_start"] = start.isoformat()
            self.save()
        # Не «отматываем» спринты, но если прошёл срок — двигаем вперёд
        while (today - start).days >= config.SPRINT_DAYS:
            self.data["sprint_number"] += 1
            start = start.fromordinal(start.toordinal() + config.SPRINT_DAYS)
            self.data["sprint_start"] = start.isoformat()
            self.save()
        return self.data["sprint_number"], start

    # ------------------------------------------------------------------
    # On-call ротация
    # ------------------------------------------------------------------
    def current_oncall(self) -> str:
        rot = config.ONCALL_ROTATION
        if not rot:
            return "alex.petrov"
        return rot[self.data["oncall_index"] % len(rot)]

    def advance_oncall(self):
        self.data["oncall_index"] += 1
        self.save()

    # ------------------------------------------------------------------
    # Счётчики
    # ------------------------------------------------------------------
    def next_issue_id(self) -> int:
        self.data["issue_seq"] += 1
        self.save()
        return self.data["issue_seq"]

    def next_release(self) -> str:
        self.data["release_seq"] += 1
        self.save()
        major = 1
        return f"v{major}.{self.data['release_seq']}.0"

    def next_campaign(self) -> int:
        self.data["campaign_seq"] += 1
        self.save()
        return self.data["campaign_seq"]

    # ------------------------------------------------------------------
    # PTO (отпуска/болезни)
    # ------------------------------------------------------------------
    def set_pto(self, username: str):
        self.data["pto"][simclock.today_iso()] = username
        self.save()

    def who_is_out_today(self) -> Optional[str]:
        return self.data["pto"].get(simclock.today_iso())
