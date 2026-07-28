#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ДОКАЗАТЕЛЬСТВО, ЧТО ML ЛОВИТ АТАКИ.

Одной командой: генерит нормальную работу команды + 4 разных ATT&CK-кампании,
делит данные по времени (train/test), обучает ML-детектор и показывает, СКОЛЬКО
эпизодов каждой атаки он поймал на ОТЛОЖЕННЫХ данных (которых при обучении не
видел). Работает offline (без GitLab), воспроизводимо.

  python verify_ml.py

В конце — список 4 атак и как запустить их вживую через Red Launcher на :8788.
"""

# --- скрипт живёт в подпапке; движок проекта — в корне ---
import os as _os, sys as _sys
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
for _p in (_ROOT, _os.path.join(_ROOT, "tools"), _os.path.join(_ROOT, "research")):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
_os.chdir(_ROOT)
del _os, _sys
import os
import sys
import logging
import collections

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

logging.disable(logging.CRITICAL)
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CAMPAIGNS = ["ci_token_to_exfil", "insider_secret_theft",
             "supply_chain_recon", "review_bypass_sabotage"]
NICE = {
    "ci_token_to_exfil":      "Кража CI-токена → отключение защиты → вынос данных",
    "insider_secret_theft":   "Инсайдер: лишний токен → секрет в коммите → вынос",
    "supply_chain_recon":     "Разведка → доступ → отравленный CI → вынос",
    "review_bypass_sabotage": "Обход ревью → отравленный CI → разрушение",
}


from workload import build_workload


def generate():
    """Нагрузка из общего генератора research/workload.py.

    Раньше здесь был свой фон: четыре фиксированных пути и ДВА значения
    энтропии (3.2 / 2.4). На таком фоне модель показывала 44/44 эпизодов и
    0.0% ложных срабатываний — это был артефакт генератора, а не свойство
    модели. Общий генератор даёт распределения, benign-двойники секретов
    (SHA-40, UUID, base64-иконки, lock-файлы) и рабочие сессии, поэтому
    цифры ниже честные и заметно скромнее.
    """
    return build_workload(evasion="noisy", seed=42, days=14, per_day=300,
                          campaigns=CAMPAIGNS)


def main():
    import detector, run_defense, ml_features, stats
    from train_runtime_model import LogReg, thr_for_fp

    raw = [r for r in generate() if not r.get("meta")]
    # Признаки считаем ТЕМ ЖЕ конвейером, что и бой: анти-лик + оконные
    # агрегаты. Иначе обучение и применение видят разные векторы.
    enr = detector.Enricher()
    rows = []
    for r in raw:
        obs = enr.enrich(run_defense.observed(r))
        rows.append({"x": ml_features.featurize(obs),
                     "y": 1 if r.get("is_anomaly") else 0,
                     "episode_id": r.get("episode_id"),
                     "campaign_name": r.get("campaign_name"),
                     "ts": r.get("ts_sim") or ""})
    rows.sort(key=lambda r: r["ts"])
    cut = int(len(rows) * 0.7)
    train, test = rows[:cut], rows[cut:]

    m = LogReg(dim=len(ml_features.FEATURES))
    m.fit([r["x"] for r in train], [r["y"] for r in train])
    name = "LogReg (боевые признаки ml_features)"
    score = lambda x: m.raw(x)
    neg = [score(r["x"]) for r in train if r["y"] == 0]
    thr = thr_for_fp(neg, 0.02)

    # эпизоды теста по кампаниям
    eps = {}
    for r in test:
        if r["y"] == 1 and r["episode_id"]:
            e = eps.setdefault(r["episode_id"],
                               {"camp": r["campaign_name"] or "—", "max": 0.0})
            e["max"] = max(e["max"], score(r["x"]))
    by = collections.defaultdict(lambda: [0, 0])
    for e in eps.values():
        by[e["camp"]][1] += 1
        if e["max"] >= thr:
            by[e["camp"]][0] += 1
    caught = sum(v[0] for v in by.values()); total = sum(v[1] for v in by.values())
    fp = sum(score(r["x"]) >= thr for r in test if r["y"] == 0)
    negn = sum(1 for r in test if r["y"] == 0)

    print("=" * 66)
    print("  ПРОВЕРКА: ЛОВИТ ЛИ ML АТАКИ (на отложенных данных)")
    print("=" * 66)
    print(f"  модель: {name}")
    print(f"  событий: {len(rows)} (train {len(train)} / test {len(test)}) | порог FP≤2%")
    print("-" * 66)
    print(f"  {'Атака (кампания)':40} | эпизодов | поймано")
    print("-" * 66)
    for key in CAMPAIGNS:
        c, t = by.get(key, [0, 0])
        mark = "✅" if (t and c == t) else ("⚠️" if c else "❌")
        print(f"  {mark} {NICE[key][:37]:37} | {t:>7}  | {c}/{t}")
    print("-" * 66)
    lo, hi = stats.wilson(caught, max(1, total))
    print(f"  ИТОГ на отложенных: поймано {caught}/{total} эпизодов атак "
          f"({round(caught/max(1,total)*100)}%, 95% ДИ {lo*100:.0f}–{hi*100:.0f}%) "
          f"при FP {round(fp/max(1,negn)*100,1)}% на норме")
    pos_s = [score(r["x"]) for r in test if r["y"] == 1]
    neg_s = [score(r["x"]) for r in test if r["y"] == 0]
    print(f"  PR-AUC {stats.pr_auc(pos_s, neg_s):.3f} "
          f"(база {stats.baseline_pr(len(pos_s), len(neg_s)):.4f}) | "
          f"ROC-AUC {stats.roc_auc(pos_s, neg_s):.3f}")
    print("=" * 66)
    print("  Вывод: ML обучен только на ПРОШЛОМ, а ловит атаки в БУДУЩЕМ (test),")
    print("  которого не видел — значит он выучил признаки, а не запомнил примеры.")
    print("  Цифры даны с доверительным интервалом: точечная оценка на нескольких")
    print("  десятках эпизодов без интервала создаёт ложную точность.")
    print()
    print("  Как повторить это вживую на своём GitLab (:8788 → Red Launcher):")
    for i, key in enumerate(CAMPAIGNS, 1):
        print(f"    {i}. «{key}» — {NICE[key]}")
    print("  Запусти любую → смотри Алерты → Инциденты → «LLM-разбор».")


if __name__ == "__main__":
    main()
