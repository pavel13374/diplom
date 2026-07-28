#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ABLATION: КОНФИГУРАЦИЯ ДЕТЕКТОРА × ПРОФИЛЬ УКЛОНЕНИЯ — глава экспериментов.

Что меряется. Как качество обнаружения зависит от (а) включённых слоёв детектора
и (б) поведения атакующего. Две независимые оси:

  слои детектора:    rules | ueba | ml | rules+ueba | rules+ml | full
  профиль уклонения: noisy | stealthy | adaptive

Что изменилось по сравнению с прежней версией
---------------------------------------------
1. Скрипт вообще не запускался: в нём было `datetime(..., 19 + i, ...)`, а
   кампаний стало 12 — на пятой итерации падало с «hour must be in 0..23».
2. Фон был вырожденным (4 пути, 2 значения энтропии) — на таком фоне любые
   метрики бессмысленны. Теперь общий генератор research/workload.py с
   распределениями, benign-двойниками секретов и рабочими сессиями.
3. Один прогон с SEED=42 заменён на НЕСКОЛЬКО СИДОВ, а точечные оценки — на
   доверительные интервалы Уилсона.
4. Добавлен ТЕСТ ЗНАЧИМОСТИ (Макнемар на парных исходах по эпизодам) с
   поправкой Холма: «full лучше rules» — теперь проверяемое утверждение,
   а не наблюдение за двумя числами.
5. Добавлен слой ML — раньше он существовал только в research/ и в
   ablation не участвовал.

Метрики на ячейку:
  recall    — доля ЭПИЗОДОВ атаки, по которым был хоть один алерт;
  precision — доля алертов, попавших в события атаки;
  fp_rate   — доля НОРМАЛЬНЫХ событий, поднявших тревогу;
  alerts/1k — нагрузка на аналитика.

Запуск:  python research/experiments.py [--seeds 3]
Пишет results/experiments.csv и results/significance.csv
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
import csv
import logging
import argparse

logging.disable(logging.CRITICAL)
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

import detector
import run_defense
import stats
from workload import build_workload, FakeGL   # noqa: F401  (общий генератор)

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: Конфигурации слоёв: (имя, включены ли rules / ueba / ml)
CONFIGS = [
    ("rules",       True,  False, False),
    ("ueba",        False, True,  False),
    ("ml",          False, False, True),
    ("rules+ueba",  True,  True,  False),
    ("rules+ml",    True,  False, True),
    ("full",        True,  True,  True),
]
EVASIONS = ["noisy", "stealthy", "adaptive"]


def make_engine(use_rules, use_ueba, use_ml):
    eng = detector.DetectionEngine(use_ml=use_ml)
    if not use_rules:
        eng.rules = []
    if not use_ueba:
        eng.ueba.disable()
    return eng


def evaluate(events_list, cfg):
    """Прогон одной конфигурации по потоку. Возвращает метрики и ПОЭПИЗОДНЫЕ
    исходы — они нужны для парного теста значимости.

    ВАЖНО: здесь воспроизводится ПОЛНЫЙ боевой конвейер, включая подавление
    дублей (detector.Suppressor). Без него измерение врёт: одна уборка
    репозитория на 12 файлов давала 8 отдельных «ложных срабатываний», хотя
    аналитик увидел бы одну тревогу. Так шум завышался в разы, а вместе с ним
    и оценка бесполезности правил.
    """
    _, use_rules, use_ueba, use_ml = cfg
    eng = make_engine(use_rules, use_ueba, use_ml)
    supp = detector.Suppressor()

    episodes = {}
    normal = 0
    fp = tp = 0
    for ev in events_list:
        if ev.get("meta"):
            continue
        is_att = bool(ev.get("is_anomaly"))
        eid = ev.get("episode_id")
        if is_att and eid:
            episodes.setdefault(eid, False)
        if not is_att:
            normal += 1

        det = eng.process(run_defense.observed(ev))
        if not det.get("alert"):
            continue
        # Подавление поалертное — как в боевом конвейере. Если проверять только
        # самый рисковый алерт, включение слоя ML снижает полноту: его сработка
        # становится верхней, попадает в окно подавления и утаскивает с собой
        # сработку правила. Добавление слоя не может ухудшать обнаружение.
        fresh = [a for a in det["alerts"]
                 if not supp.is_duplicate(ev.get("actor"), a.get("rule_id"),
                                          ev.get("ts_sim"))]
        if not fresh:
            continue
        if is_att:
            tp += 1
            if eid:
                episodes[eid] = True
        else:
            fp += 1

    n_eps = len(episodes)
    caught = sum(1 for v in episodes.values() if v)
    alerts = tp + fp
    return {
        "recall": caught / n_eps if n_eps else 0.0,
        "precision": tp / alerts if alerts else 0.0,
        "fp_rate": fp / normal if normal else 0.0,
        "alerts_per_1k": alerts / max(1, (normal + tp)) * 1000,
        "caught": caught, "episodes": n_eps,
        "tp": tp, "fp": fp, "normal": normal,
        "_outcomes": episodes,
    }


def main():
    ap = argparse.ArgumentParser(description="Ablation: слои × уклонение")
    ap.add_argument("--seeds", type=int, default=3)
    args = ap.parse_args()
    seeds = [42 + i * 17 for i in range(args.seeds)]

    print("=" * 96)
    print("  ABLATION: слои детектора × профиль уклонения")
    print("=" * 96)
    print(f"  сидов: {len(seeds)} {seeds} | доверительные интервалы: Уилсон 95%")
    print()

    rows = []
    # накопленные поэпизодные исходы: (evasion, config) -> {episode_id: bool}
    outcomes = {}

    for evasion in EVASIONS:
        agg = {c[0]: {"caught": 0, "episodes": 0, "tp": 0, "fp": 0, "normal": 0,
                      "alerts": 0} for c in CONFIGS}
        for seed in seeds:
            wl = build_workload(evasion=evasion, seed=seed, days=12, per_day=260)
            for cfg in CONFIGS:
                m = evaluate(wl, cfg)
                a = agg[cfg[0]]
                a["caught"] += m["caught"]; a["episodes"] += m["episodes"]
                a["tp"] += m["tp"]; a["fp"] += m["fp"]; a["normal"] += m["normal"]
                a["alerts"] += m["tp"] + m["fp"]
                key = (evasion, cfg[0])
                store = outcomes.setdefault(key, {})
                for eid, hit in m["_outcomes"].items():
                    store[f"{seed}:{eid}"] = hit

        print(f"  ── профиль уклонения: {evasion} " + "─" * (72 - len(evasion)))
        print(f"  {'слои':12} | {'recall (95% ДИ)':>24} | {'precision':>20} "
              f"| {'FP на норме':>12} | алертов/1k")
        print("  " + "-" * 92)
        for name, *_ in CONFIGS:
            a = agg[name]
            rec = stats.fmt_ci(a["caught"], a["episodes"])
            prec = stats.fmt_ci(a["tp"], max(1, a["alerts"]))
            fpr = a["fp"] / max(1, a["normal"])
            per1k = a["alerts"] / max(1, a["normal"] + a["tp"]) * 1000
            print(f"  {name:12} | {rec:>24} | {prec:>20} | {fpr*100:>11.2f}% | {per1k:>7.1f}")
            rows.append({"evasion": evasion, "config": name,
                         "recall": round(a["caught"] / max(1, a["episodes"]), 4),
                         "recall_lo": round(stats.wilson(a["caught"], max(1, a["episodes"]))[0], 4),
                         "recall_hi": round(stats.wilson(a["caught"], max(1, a["episodes"]))[1], 4),
                         "precision": round(a["tp"] / max(1, a["alerts"]), 4),
                         "fp_rate": round(fpr, 5),
                         "alerts_per_1k": round(per1k, 2),
                         "caught": a["caught"], "episodes": a["episodes"],
                         "tp": a["tp"], "fp": a["fp"], "normal": a["normal"]})
        print()

    # ---------------- значимость различий ----------------
    print("=" * 96)
    print("  ЗНАЧИМОСТЬ РАЗЛИЧИЙ (тест Макнемара на парных исходах по эпизодам)")
    print("=" * 96)
    print("  Сравниваются ОДНИ И ТЕ ЖЕ эпизоды: считаются только расхождения —")
    print("  сколько эпизодов поймала одна конфигурация и упустила другая.")
    print()
    pairs = [("rules", "rules+ueba"), ("rules", "rules+ml"),
             ("rules", "full"), ("rules+ueba", "full"), ("ueba", "ml")]
    sig_rows = []
    raw_p = []
    meta = []
    for evasion in EVASIONS:
        for a_name, b_name in pairs:
            A = outcomes.get((evasion, a_name), {})
            B = outcomes.get((evasion, b_name), {})
            keys = sorted(set(A) & set(B))
            if not keys:
                continue
            a_hits = [A[k] for k in keys]
            b_hits = [B[k] for k in keys]
            b01, b10, p = stats.mcnemar(a_hits, b_hits)
            raw_p.append(p)
            meta.append((evasion, a_name, b_name, b01, b10, len(keys)))

    adj = stats.holm(raw_p) if raw_p else []
    print(f"  {'уклонение':10} | {'A':11} | {'B':11} | {'B поймал, A нет':>15} "
          f"| {'A поймал, B нет':>15} | {'p (Холм)':>9} | вывод")
    print("  " + "-" * 92)
    for (evasion, a_name, b_name, b01, b10, n), p_adj in zip(meta, adj):
        verdict = ("B значимо лучше" if (p_adj < 0.05 and b01 > b10) else
                   "A значимо лучше" if (p_adj < 0.05 and b10 > b01) else
                   "различие незначимо")
        print(f"  {evasion:10} | {a_name:11} | {b_name:11} | {b01:>15} "
              f"| {b10:>15} | {p_adj:>9.4f} | {verdict}")
        sig_rows.append({"evasion": evasion, "config_a": a_name, "config_b": b_name,
                         "b_only": b01, "a_only": b10, "n_pairs": n,
                         "p_holm": round(p_adj, 6), "verdict": verdict})

    print()
    print("  Как читать. «Различие незначимо» — честный результат, а не неудача:")
    print("  он означает, что на этом объёме данных превосходство одной")
    print("  конфигурации над другой статистически не подтверждается.")
    print("=" * 96)

    os.makedirs(os.path.join(BASE, "results"), exist_ok=True)
    fp1 = os.path.join(BASE, "results", "experiments.csv")
    with open(fp1, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    print(f"  CSV: {os.path.relpath(fp1, BASE)}")
    if sig_rows:
        fp2 = os.path.join(BASE, "results", "significance.csv")
        with open(fp2, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(sig_rows[0].keys()))
            w.writeheader(); w.writerows(sig_rows)
        print(f"  CSV: {os.path.relpath(fp2, BASE)}")


if __name__ == "__main__":
    main()
