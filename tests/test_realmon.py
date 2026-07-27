#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Доказательство «реального мониторинга».

Вопрос комиссии: система ловит только свои же сценарии или действительно
следит за настоящим GitLab? Этот тест отвечает на него без сети.

Мы собираем событие ровно так, как его строит наблюдатель за реальным
GitLab (tools/gitlab_watch.py) из ручного коммита человека:
  • берём СОДЕРЖИМОЕ файла с секретом (как из diff коммита);
  • считаем те же признаки content_features (энтропия, secret-regex);
  • эмулируем push — и НИ ОДНОЙ метки симулятора: нет anomaly_type,
    нет campaign_id, нет is_anomaly.

Затем прогоняем событие через тот же детектор (run_defense) и коррелятор,
что и живая консоль защиты, и требуем:
  • детектор поднял алерт по тактике Credential Access (T1552*);
  • решение принято ТОЛЬКО по наблюдаемым признакам (метки отсутствуют);
  • из алерта собрался инцидент — как увидел бы аналитик на :8788.

Если тест зелёный — «поймай меня сам» работает: закоммить секрет руками
в GitLab при запущенном наблюдателе, и защита заведёт инцидент.

Запуск:  python tests/test_realmon.py
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (_ROOT, os.path.join(_ROOT, "tools")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
os.chdir(_ROOT)
os.environ.setdefault("SOC_OFFLINE", "1")

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

import content_features
import run_defense
import correlator

OK, BAD = "✅", "❌"
fails = []


def check(name, cond, extra=""):
    print(f"  {OK if cond else BAD} {name}" + ("" if cond else f"   << {extra}"))
    if not cond:
        fails.append(name)


# --- содержимое, которое человек мог бы закоммитить руками ---
# Настоящий секрет: без слов example/placeholder/dummy, иначе сработает
# честная эвристика «это шаблон, а не утечка».
SECRET_FILE = (
    "# runtime configuration for the billing service\n"
    "DATABASE_URL=postgres://svc_billing:7kQ2r9WmZ4pX1aVt@db.internal:5432/billing\n"
    "STRIPE_SECRET_KEY=sk_live_51McQ8pLv3RtY6uHnJ2kWfB0aZ\n"
    "GITLAB_TOKEN=glpat-xZ9fKq2mNvBw7Lp3RtY6\n"
)


def build_manual_push():
    """Событие ровно как у наблюдателя за реальным GitLab: push + признаки
    содержимого, БЕЗ каких-либо меток симулятора."""
    feats = content_features.analyze(SECRET_FILE, "config/prod.env")
    ev = {
        "action": "push",
        "actor": "pavel",                 # реальный человек, не персонаж симулятора
        "role": "engineer",
        "project": "billing",
        "path": "config/prod.env",
        "branch": "main",
        "message": "commit a1b2c3d4",
        "ts_sim": "2026-07-22T14:30:00",
        "_id": 999001,
    }
    ev.update(feats)
    return ev


def main():
    print("=" * 60)
    print("  РЕАЛЬНЫЙ МОНИТОРИНГ — «поймай меня сам»")
    print("=" * 60)

    ev = build_manual_push()

    # 1. Признаки посчитаны как для настоящего коммита
    check("секрет виден в признаках содержимого",
          ev.get("n_regex_hits", 0) >= 1 and ev.get("shannon_entropy", 0) >= 4.0,
          f"regex={ev.get('n_regex_hits')} entropy={ev.get('shannon_entropy')}")
    check("это не benign-плейсхолдер", ev.get("placeholder_signal") is False,
          str(ev.get("placeholder_signal")))

    # 2. Событие НЕ содержит ни одной метки симулятора
    leak = [k for k in ("anomaly_type", "is_anomaly", "campaign_id", "severity",
                        "anomaly_subtype", "family") if k in ev]
    check("в событии нет меток симулятора (детектор судит вслепую)", not leak, ", ".join(leak))

    # 3. Детектор поднимает алерт по наблюдаемому
    obs = run_defense.observed(ev)
    check("после среза служебных полей меток тоже нет",
          not any(k in obs for k in ("anomaly_type", "is_anomaly", "campaign_id")))
    res = run_defense.process(ev)
    check("детектор поднял алерт", bool(res.get("alert")), str(res.get("risk")))
    techs = [a.get("technique") for a in res.get("alerts", [])]
    check("сработала тактика Credential Access (T1552*)",
          any(str(t).startswith("T1552") for t in techs), ", ".join(map(str, techs)))
    check("риск выше среднего", res.get("risk", 0) >= 0.5, str(res.get("risk")))

    # 4. Из алерта собирается инцидент — как на консоли защиты
    cor = correlator.Correlator()
    iid = cor.add(obs, res)
    incidents = cor.list(10)
    check("инцидент создан", iid is not None and len(incidents) >= 1, f"iid={iid}")
    if incidents:
        inc = incidents[0]
        check("инцидент указывает на реального автора",
              inc.get("actor") == "pavel", inc.get("actor"))
        check("в инциденте есть техника Credential Access",
              any(str(t).startswith("T1552") for t in inc.get("techniques", [])),
              ", ".join(map(str, inc.get("techniques", []))))

    # 5. Контроль: чистый коммит без секретов НЕ поднимает алерт
    clean = build_manual_push()
    clean_feats = content_features.analyze(
        "# service readme\nRun `make deploy` to ship.\nSee docs/ for details.\n", "README.md")
    clean.update({"path": "README.md", "n_regex_hits": 0, "_id": 999002})
    clean.update(clean_feats)
    check("обычный коммит без секретов не тревожит",
          not run_defense.process(clean).get("alert"))

    print("\n" + "=" * 60)
    if fails:
        print(f"  {BAD} провалено: {len(fails)}")
        return 1
    print("  ✅ реальный мониторинг доказан: секрет, внесённый руками,\n"
          "     обнаружен по наблюдаемым признакам и превращён в инцидент.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
