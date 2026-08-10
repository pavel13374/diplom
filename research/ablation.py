#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ABLATION — вклад каждого слоя детектора со СТАТИСТИЧЕСКОЙ ЗНАЧИМОСТЬЮ.

Вопрос, на который отвечает скрипт: даёт ли каждый слой измеримый вклад, или
часть конвейера существует только на схеме архитектуры.

Что сравнивается (одна и та же нагрузка, четыре конфигурации):

    full        L0 правила + L1 UEBA + L2 модель
    no_ml       L0 + L1                         (выключен слой ML)
    no_ueba     L0 +      L2                    (выключен поведенческий слой)
    rules_only  L0                              (только сигнатуры)

Почему так, а не «обучили и сравнили точности»
-----------------------------------------------
1. НАГРУЗКА ОДНА И ТА ЖЕ. Конфигурации видят ПОБИТОВО одинаковый поток
   событий: сравнение парное, объекты одни и те же. Сравнивать конфигурации на
   разных выборках нельзя — разброс между прогонами того же порядка, что и
   разница между конфигурациями.

2. ЗНАЧИМОСТЬ СЧИТАЕТСЯ ПАРНЫМ ТЕСТОМ. Для парных бинарных исходов
   («эпизод пойман / не пойман» у двух конфигураций на одних эпизодах)
   корректен тест Макнемара, а не критерий для независимых долей: последний
   игнорирует, что промахи в основном совпадают, и завышает p-значение.
   Макнемар смотрит только на РАСХОЖДЕНИЯ (b01, b10) — ровно ту информацию,
   которая отличает конфигурации.

3. ПОПРАВКА НА МНОЖЕСТВЕННОСТЬ. Сравнений шесть (C(4,2)). При α = 0.05
   вероятность получить хотя бы одно «значимое» различие случайно — около 26%,
   а не 5%. Поправка Холма контролирует групповую ошибку и, в отличие от
   Бонферрони, не так консервативна.

4. МЕТРИКА — PR-AUC, а не ROC-AUC. Доля атакующих событий здесь порядка
   процента; при таком дисбалансе ROC-AUC высок даже у слабого детектора,
   потому что знаменатель FPR — огромное число нормальных событий. База PR-AUC
   равна доле положительного класса и печатается рядом.

5. ИНТЕРВАЛЫ ВЕЗДЕ. Точечная оценка «recall 65%» без интервала создаёт ложную
   точность. Для долей — Уилсон, для PR-AUC — перцентильный bootstrap.

Запуск:
    python research/ablation.py                       # 3 сида, порог 0.6
    python research/ablation.py --seeds 5 --days 21
    python research/ablation.py --threshold 0.5 --out results/ablation.json
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
import json
import logging
import argparse
import datetime
import itertools

logging.disable(logging.CRITICAL)
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

import detector
import run_defense
from workload import build_workload
from stats import pr_auc, roc_auc, wilson, bootstrap_ci, mcnemar, holm, baseline_pr

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: Порог «действенного» инцидента — тот же, что в metrics.py. Ниже него алерт
#: до аналитика не доходит, поэтому и полноту надо мерить на нём.
DEFAULT_THRESHOLD = 0.6

CONFIGS = [
    ("full",       {"rules": True,  "ueba": True,  "ml": True},
     "L0 правила + L1 UEBA + L2 модель"),
    ("no_ml",      {"rules": True,  "ueba": True,  "ml": False},
     "без слоя ML"),
    ("no_ueba",    {"rules": True,  "ueba": False, "ml": True},
     "без поведенческого слоя"),
    ("rules_only", {"rules": True,  "ueba": False, "ml": False},
     "только сигнатуры"),
]


# ----------------------------------------------------------------------
def make_engine(cfg):
    """Движок с выключенными слоями согласно конфигурации.

    Слои гасятся ПОСЛЕ создания, а не разными классами: так гарантировано, что
    отличается ровно одно — набор активных слоёв, а не порядок инициализации
    или версия правил.
    """
    eng = detector.DetectionEngine(use_ml=cfg["ml"])
    if not cfg["rules"]:
        eng.rules = []
    if not cfg["ueba"]:
        eng.ueba.disable()
    return eng


def build_stream(seeds, evasions, days, per_day):
    """Поток событий: список (ключ_прогона, событие). Строится ОДИН РАЗ.

    Все конфигурации получат один и тот же список — это условие парности.
    """
    stream = []
    for seed in seeds:
        for ev_prof in evasions:
            wl = build_workload(evasion=ev_prof, seed=seed, days=days, per_day=per_day)
            run_key = f"s{seed}:{ev_prof}"
            for r in wl:
                if r.get("meta"):
                    continue
                stream.append((run_key, r))
    return stream


def run_config(cfg_flags, stream):
    """Прогнать поток через конфигурацию. Возвращает риски и эпизодные оценки.

    Энричер и профили UEBA — свои на каждый ПРОГОН (run_key), потому что
    прогоны независимы: у каждого своя шкала симулированного времени, и общая
    оконная история склеила бы события, разнесённые на недели.

    Эпизод оценивается ДВУМЯ способами, и разница между ними содержательна:

      ep_max  — максимум ПОСОБЫТИЙНОГО риска. Так меряют, когда решение
                принимается по одному событию.
      ep_inc  — риск ИНЦИДЕНТА, накрывшего эпизод (корреляция + слияние по
                слоям). Так работает очередь аналитика: он видит инцидент, а не
                событие.

    Второй способ — единственный, в котором слой может проявить себя, если он
    срабатывает на ДРУГОМ шаге кампании, чем остальные слои. Пособытийный
    максимум такие свидетельства не складывает по определению.
    """
    import correlator
    engines = {}
    cors = {}
    risks = []
    ep_max = {}
    ep_inc = {}
    alerts = 0
    times = []
    for run_key, r in stream:
        eng = engines.get(run_key)
        if eng is None:
            eng = engines[run_key] = make_engine(cfg_flags)
            cors[run_key] = correlator.Correlator()
        obs = run_defense.observed(r)
        det = eng.process(obs)
        risk = det.get("risk", 0.0)
        risks.append(risk)
        if r.get("ts_sim"):
            times.append(r["ts_sim"])
        iid = None
        if det.get("alert"):
            alerts += 1
            iid = cors[run_key].add(obs, det)
        if r.get("is_anomaly") and r.get("episode_id"):
            k = (run_key, r["episode_id"])
            ep_max[k] = max(ep_max.get(k, 0.0), risk)
            if iid is not None:
                inc = cors[run_key].incidents[iid]
                ep_inc[k] = max(ep_inc.get(k, 0.0),
                                inc.get("risk", inc.get("max_risk", 0.0)))
    span = _span_days(times)
    n_inc = sum(len(c.incidents) for c in cors.values())
    return {"risks": risks, "ep_max": ep_max, "ep_inc": ep_inc,
            "alerts": alerts, "incidents": n_inc, "span_days": span}


def _span_days(ts_list):
    """Длительность потока в симулированных сутках (для алертов в день).

    Знаменатель — весь поток, а не разброс времён алертов: иначе чем ТИШЕ
    детектор, тем выше оказывается его «шумность» (см. metrics.py).
    """
    if len(ts_list) < 2:
        return 1.0
    fmt = "%Y-%m-%dT%H:%M:%S"
    ok, bad = [], 0
    for t in ts_list:
        try:
            ok.append(datetime.datetime.strptime(t, fmt))
        except Exception:
            bad += 1
    if bad:
        # Неразобранные метки времени сокращают знаменатель «алертов в день»
        # и тихо завышают показатель шумности — тот же класс ошибки, что уже
        # был найден в metrics.py.
        print(f"    [!] меток времени не разобрано: {bad} из {len(ts_list)}")
    if len(ok) < 2:
        return 1.0
    return max((max(ok) - min(ok)).total_seconds() / 86400.0, 1.0 / 24)


# ----------------------------------------------------------------------
def evaluate(res, stream, ep_keys, thr):
    """Метрики одной конфигурации."""
    labels = [1 if r.get("is_anomaly") else 0 for _, r in stream]
    pos = [s for s, y in zip(res["risks"], labels) if y == 1]
    neg = [s for s, y in zip(res["risks"], labels) if y == 0]

    pr = pr_auc(pos, neg)
    roc = roc_auc(pos, neg)
    base = baseline_pr(len(pos), len(neg))

    # bootstrap-интервал PR-AUC: пересэмплируем ПАРЫ (скор, метка).
    # Аналитической формулы для average precision нет, поэтому только бутстрап.
    pairs = list(zip(res["risks"], labels))

    def _ap(sample):
        p = [s for s, y in sample if y == 1]
        n = [s for s, y in sample if y == 0]
        return pr_auc(p, n) if p and n else 0.0

    pr_lo, pr_hi = bootstrap_ci(pairs, stat=_ap, n_boot=400, seed=42)

    # ПОСОБЫТИЙНАЯ полнота (максимум риска по шагам эпизода)
    hits_ev = [1 if res["ep_max"].get(k, 0.0) >= thr else 0 for k in ep_keys]
    # ИНЦИДЕНТНАЯ полнота — то, что реально видит аналитик в очереди
    hits = [1 if res["ep_inc"].get(k, 0.0) >= thr else 0 for k in ep_keys]
    caught, total = sum(hits), len(ep_keys)
    caught_ev = sum(hits_ev)
    rec_lo, rec_hi = wilson(caught, total)

    fired_pos = sum(1 for s in pos if s >= thr)
    fired = fired_pos + sum(1 for s in neg if s >= thr)
    prec = fired_pos / max(1, fired)
    fpr = sum(1 for s in neg if s >= thr) / max(1, len(neg))

    return {
        "pr_auc": round(pr, 4), "pr_ci": [round(pr_lo, 4), round(pr_hi, 4)],
        "pr_baseline": round(base, 5),
        "pr_lift": round(pr / base, 1) if base else 0.0,
        "roc_auc": round(roc, 4),
        "episode_recall": round(caught / total, 4) if total else 0.0,
        "episode_ci": [round(rec_lo, 4), round(rec_hi, 4)],
        "caught": caught, "episodes": total,
        "episode_recall_event_level": round(caught_ev / total, 4) if total else 0.0,
        "caught_event_level": caught_ev,
        "incidents": res["incidents"],
        "event_precision": round(prec, 4),
        "event_fpr": round(fpr, 5),
        "alerts": res["alerts"],
        "alerts_per_day": round(res["alerts"] / res["span_days"], 1),
        "_hits": hits,
    }


def significance(metrics, thr_names):
    """Попарный Макнемар + поправка Холма по вектору «эпизод пойман»."""
    pairs = list(itertools.combinations(thr_names, 2))
    raw = []
    for a, b in pairs:
        ha = [bool(x) for x in metrics[a]["_hits"]]
        hb = [bool(x) for x in metrics[b]["_hits"]]
        b01, b10, p = mcnemar(ha, hb)
        raw.append({"a": a, "b": b, "b01": b01, "b10": b10, "p": p})
    adj = holm([r["p"] for r in raw])
    for r, pa in zip(raw, adj):
        r["p_holm"] = pa
    return raw


# ----------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Ablation слоёв детектора")
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--days", type=int, default=14)
    ap.add_argument("--per-day", type=int, default=300)
    ap.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD,
                    help="порог действенного инцидента (как в metrics.py)")
    ap.add_argument("--evasions", default="noisy,stealthy,adaptive")
    ap.add_argument("--out", default=os.path.join("results", "ablation.json"))
    args = ap.parse_args()

    seeds = [1000 + i * 37 for i in range(args.seeds)]
    evasions = tuple(x.strip() for x in args.evasions.split(",") if x.strip())

    print("=" * 96)
    print("  ABLATION СЛОЁВ ДЕТЕКТОРА — вклад каждого слоя со значимостью")
    print("=" * 96)
    print(f"  сиды: {seeds}   профили: {', '.join(evasions)}   "
          f"дней: {args.days}   событий/день: {args.per_day}")
    print(f"  порог действенного инцидента: risk >= {args.threshold}")

    stream = build_stream(seeds, evasions, args.days, args.per_day)
    n_pos = sum(1 for _, r in stream if r.get("is_anomaly"))
    ep_keys = sorted({(k, r["episode_id"]) for k, r in stream
                      if r.get("is_anomaly") and r.get("episode_id")})
    print(f"  событий: {len(stream)}   из них атакующих: {n_pos} "
          f"({n_pos / max(1, len(stream)) * 100:.2f}%)   эпизодов: {len(ep_keys)}")
    if len(ep_keys) < 30:
        print(f"  [!] эпизодов мало ({len(ep_keys)}): интервалы будут широкими, "
              f"а Макнемар — маломощным. Увеличь --seeds или --days.")
    print("-" * 96)

    metrics = {}
    ml_available = None
    for name, flags, descr in CONFIGS:
        print(f"  прогон: {name:11} ({descr}) ...", end="", flush=True)
        eng_probe = make_engine(flags)
        if flags["ml"] and ml_available is None:
            ml_available = bool(eng_probe.ml and eng_probe.ml.available())
        res = run_config(flags, stream)
        metrics[name] = evaluate(res, stream, ep_keys, args.threshold)
        metrics[name]["описание"] = descr
        print(f" готово ({res['alerts']} алертов)")

    if ml_available is False:
        print()
        print("  [!] Модель слоя L2 не загружена — конфигурации full и no_ueba")
        print("      фактически совпадают с no_ml и rules_only.")
        print("      Сначала: python research/train_runtime_model.py")

    # ---------------- таблица ----------------
    print("-" * 96)
    print(f"  {'конфигурация':12} {'PR-AUC (95% ДИ)':>24} {'x база':>7} "
          f"{'ROC':>6} {'эпизодный recall':>22} {'алертов/день':>13}")
    print("  " + "-" * 92)
    for name, _, _ in CONFIGS:
        m = metrics[name]
        pr_txt = f"{m['pr_auc']:.3f} [{m['pr_ci'][0]:.3f}–{m['pr_ci'][1]:.3f}]"
        rec_txt = (f"{m['caught']}/{m['episodes']} = {m['episode_recall'] * 100:.0f}% "
                   f"[{m['episode_ci'][0] * 100:.0f}–{m['episode_ci'][1] * 100:.0f}%]")
        print(f"  {name:12} {pr_txt:>24} {m['pr_lift']:>6.1f}x "
              f"{m['roc_auc']:>6.3f} {rec_txt:>22} {m['alerts_per_day']:>13.1f}")
    print("  " + "-" * 92)
    print(f"  база PR-AUC (доля класса): {metrics['full']['pr_baseline']:.5f}")
    print()
    print("  Полнота считается ПО ИНЦИДЕНТУ (корреляция + слияние по слоям) —")
    print("  это то, что видит аналитик. Для сравнения пособытийная полнота:")
    for name, _, _ in CONFIGS:
        m = metrics[name]
        d = m["caught"] - m["caught_event_level"]
        print(f"    {name:12} по инциденту {m['caught']:>4}/{m['episodes']:<4}  "
              f"по событию {m['caught_event_level']:>4}/{m['episodes']:<4}  "
              f"разница {d:+d} эпизодов")
    print(f"  {'конфигурация':12} {'precision событий':>19} {'FPR событий':>13}")
    for name, _, _ in CONFIGS:
        m = metrics[name]
        print(f"  {name:12} {m['event_precision'] * 100:>18.1f}% "
              f"{m['event_fpr'] * 100:>12.3f}%")

    # ---------------- значимость ----------------
    sig = significance(metrics, [c[0] for c in CONFIGS])
    print("-" * 96)
    print("  ЗНАЧИМОСТЬ РАЗЛИЧИЙ — тест Макнемара по вектору «эпизод пойман»")
    print("  (парные наблюдения: одни и те же эпизоды, одна и та же нагрузка)")
    print()
    print(f"  {'сравнение':26} {'b01':>5} {'b10':>5} {'p':>9} {'p (Холм)':>10}  вывод")
    print("  " + "-" * 92)
    for r in sig:
        verdict = ("значимо" if r["p_holm"] < 0.05 else
                   "на грани" if r["p_holm"] < 0.10 else "не значимо")
        arrow = ""
        if r["p_holm"] < 0.05:
            arrow = f" ({r['b']} ловит больше)" if r["b01"] > r["b10"] \
                else f" ({r['a']} ловит больше)"
        print(f"  {r['a'] + ' vs ' + r['b']:26} {r['b01']:>5} {r['b10']:>5} "
              f"{r['p']:>9.4f} {r['p_holm']:>10.4f}  {verdict}{arrow}")
    print()
    print("  b01 — поймал только второй, b10 — только первый. Совпадающие исходы")
    print("  тест не учитывает: они не несут информации о РАЗЛИЧИИ конфигураций.")
    print("  Поправка Холма — на 6 сравнений; без неё вероятность случайного")
    print("  «значимого» результата была бы около 26%, а не 5%.")

    # ---------------- вклад слоёв ----------------
    print("-" * 96)
    print("  ВКЛАД СЛОЁВ (изменение относительно full):")
    f = metrics["full"]
    for name, _, descr in CONFIGS[1:]:
        m = metrics[name]
        d_pr = m["pr_auc"] - f["pr_auc"]
        d_rec = (m["episode_recall"] - f["episode_recall"]) * 100
        s = next((x for x in sig
                  if {x["a"], x["b"]} == {"full", name}), None)
        mark = "" if s is None else (
            "  [значимо]" if s["p_holm"] < 0.05 else "  [не значимо]")
        print(f"    {name:11} ({descr:26}) PR-AUC {d_pr:+.4f}   "
              f"эпизодный recall {d_rec:+.0f} п.п.{mark}")

    # ---------------- вывод словами ----------------
    print("-" * 96)
    print("  ВЫВОД")
    s_full_rules = next((x for x in sig
                         if {x["a"], x["b"]} == {"full", "rules_only"}), None)
    if s_full_rules and s_full_rules["p_holm"] < 0.05:
        d = (metrics["full"]["episode_recall"] -
             metrics["rules_only"]["episode_recall"]) * 100
        print(f"  Полный стек ловит на {d:.0f} п.п. больше эпизодов, чем одни сигнатуры")
        print(f"  ({metrics['full']['caught']}/{metrics['full']['episodes']} против "
              f"{metrics['rules_only']['caught']}/{metrics['rules_only']['episodes']}), "
              f"p = {s_full_rules['p_holm']:.4f} после поправки Холма.")
    else:
        print("  Полный стек НЕ отличается от одних сигнатур значимо.")
        print("  Это не значит, что слои бесполезны — возможно, не хватает мощности")
        print("  (эпизодов мало). Увеличь --seeds и посмотри снова.")
    weak = []
    for name in ("no_ml", "no_ueba"):
        s = next((x for x in sig if {x["a"], x["b"]} == {"full", name}), None)
        if s and s["p_holm"] >= 0.05:
            weak.append(name.replace("no_", ""))
    if weak:
        print()
        print(f"  Слои без значимого индивидуального вклада: {', '.join(weak)}.")
        print("  Возможные причины, в порядке правдоподобия:")
        print("    1) бюджет тревог слоя настолько узкий, что он почти молчит")
        print("       (см. config.UEBA_ALERT_BUDGET и замер в tools/ueba_components.py);")
        print("    2) слой ловит те же эпизоды, что и правила, — вклад перекрывается;")
        print("    3) эпизодов мало для обнаружения различия такого размера.")
        print("  Утверждать «слой не нужен» по этим данным НЕЛЬЗЯ: отсутствие")
        print("  значимости — не доказательство отсутствия эффекта.")

    # ---------------- сохранение ----------------
    out = os.path.join(BASE, args.out) if not os.path.isabs(args.out) else args.out
    os.makedirs(os.path.dirname(out), exist_ok=True)
    payload = {
        "generated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "seeds": seeds, "evasions": list(evasions), "days": args.days,
        "per_day": args.per_day, "threshold": args.threshold,
        "events": len(stream), "attack_events": n_pos, "episodes": len(ep_keys),
        "ml_layer_available": ml_available,
        "configs": {k: {kk: vv for kk, vv in v.items() if kk != "_hits"}
                    for k, v in metrics.items()},
        "significance": sig,
        "note": ("Сравнение парное: все конфигурации видят один и тот же поток "
                 "событий. Значимость — тест Макнемара по вектору «эпизод пойман» "
                 "с поправкой Холма на 6 сравнений."),
    }
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    print("=" * 96)
    print(f"  Результат: {os.path.relpath(out, BASE)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
