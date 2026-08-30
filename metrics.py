#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SOC-метрики платформы (для главы «эксперименты» диплома).

Считает по event-store + детектору:
  • Detection rate (эпизодный): доля аномальных эпизодов, где сработал детектор.
  • ATT&CK coverage: доля исполненных техник, покрытых правилами.
  • MTTD (Mean Time To Detect): среднее sim-время от первого события эпизода до
    первого алерта по нему (по актору/окну).
  • FP-rate: доля алертов, попавших на нормальные (benign) события.
  • Alerts/day: интенсивность алертов по sim-времени.

ВАЖНО про честность: detection rate и MTTD сопоставляют АЛЕРТЫ (blue, без меток) с
РАЗМЕТКОЙ (для оценки). Сам детектор меток не видит — это разбор постфактум.

Запуск:  python metrics.py [--json]
"""
import sys
import json
import argparse
import collections

import stats
import config
import eventstore
import run_defense


def _parse(ts):
    """Единый разбор метки времени — тот же, что у детектора и коррелятора.

    Своя копия на одном strptime возвращала None на метках с микросекундами,
    с суффиксом Z и со смещением часового пояса. Здесь по времени считается
    MTTD и окна эпизодов, поэтому расхождение между разбором в метрике и
    разбором в бою давало бы неверные, но правдоподобные числа.
    """
    import detector
    return detector.parse_ts(ts)


#: Сколько событий журнала берётся в расчёт метрик.
#:
#: metrics.py запускается ПОДПРОЦЕССОМ из консоли каждые пять минут и грузил
#: журнал целиком (`limit=10_000_000`). На стенде это десятки тысяч событий и
#: сотня мегабайт; на длинном прогоне цифра не ограничена ничем, а прогон
#: детектора по всему журналу ещё и линеен по его длине. Ограничение с ЯВНЫМ
#: сообщением честнее, чем незаметная деградация: в выводе видно, по скольким
#: событиям посчитано.
MAX_ROWS = 200_000


def compute():
    eventstore.init()
    rows = eventstore.read_since(0, limit=MAX_ROWS) if eventstore.enabled() else []
    if not rows:
        return None
    truncated = len(rows) >= MAX_ROWS

    # ПРОГОН ДЕТЕКТОРА — РОВНО ОДИН РАЗ ПО ПОТОКУ.
    #
    # Детектор — потоковый и с состоянием: Enricher копит оконную историю
    # актора, UEBA — профили и резервуар для квантиля порога. Раньше compute()
    # проходил по rows ДВАЖДЫ (второй раз — ради PR-AUC), причём тем же самым
    # синглтоном run_defense._ENGINE. На втором проходе профили уже были
    # «прогреты» всей выборкой, порог UEBA стоял на другом значении, а история
    # каждого актора удваивалась. В итоге PR-AUC считался по риску, который
    # НИКОГДА не выставлялся в бою, и в отчёте соседствовали две
    # взаимно несогласованные цифры по одному и тому же прогону.
    #
    # Теперь риск каждого события запоминается на единственном проходе.
    risks = []                 # риск события в порядке потока
    alerts = []                # (row, det)
    for r in rows:
        det = run_defense.process(r)
        risks.append(det.get("risk", 0.0))
        if det.get("alert"):
            alerts.append((r, det))

    # --- эпизоды (по разметке — для оценки) ---
    episodes = collections.defaultdict(lambda: {"events": [], "techs": set(), "first": None})
    for r in rows:
        eid = r.get("episode_id")
        if not eid:
            continue
        ep = episodes[eid]
        ep["events"].append(r)
        if r.get("technique_id"):
            ep["techs"].add(r["technique_id"])
        t = _parse(r.get("ts_sim"))
        if t and (ep["first"] is None or t < ep["first"]):
            ep["first"] = t

    # детект эпизода = есть алерт по актору эпизода в окне эпизода
    alerts_by_actor = collections.defaultdict(list)
    for r, det in alerts:
        alerts_by_actor[r.get("actor")].append((_parse(r.get("ts_sim")), det["risk"]))

    # СТРОГИЙ детект: алерт пришёл НА СОБЫТИЕ ЭТОГО ЖЕ ЭПИЗОДА.
    # Раньше засчитывалось любое срабатывание того же актора в окне эпизода —
    # включая алерт на его СОСЕДНЕЕ ДОБРОКАЧЕСТВЕННОЕ действие. Атакующий в
    # рабочее время делает и обычную работу, поэтому такое совпадение случайно
    # и завышает detection rate. Считаем обе величины: строгую (в отчёт) и
    # мягкую (для сравнения — насколько велика была накрутка).
    alerted_eids = {}
    for r, det in alerts:
        eid = r.get("episode_id")
        t = _parse(r.get("ts_sim"))
        if eid and t and (eid not in alerted_eids or t < alerted_eids[eid]):
            alerted_eids[eid] = t

    detected = 0; detected_loose = 0; mttd_vals = []
    for eid, ep in episodes.items():
        actor = ep["events"][0].get("actor")
        first = ep["first"]
        last = max((_parse(e.get("ts_sim")) for e in ep["events"] if _parse(e.get("ts_sim"))),
                   default=first)
        if any(t and first and first <= t <= (last or first)
               for (t, _risk) in alerts_by_actor.get(actor, [])):
            detected_loose += 1
        hit = alerted_eids.get(eid)
        if hit is not None:
            detected += 1
            if first:
                mttd_vals.append((hit - first).total_seconds() / 60.0)

    n_ep = len(episodes)
    det_rate = detected / n_ep if n_ep else 0.0
    # MTTD усредняется ТОЛЬКО по пойманным эпизодам — у непойманных времени
    # обнаружения не существует. Это цензурированная выборка, и число надо
    # читать как «медиана/среднее среди пойманных», а не «среднее по атакам».
    # Ниже отдаём и долю, по которой оно посчитано.
    mttd = sum(mttd_vals) / len(mttd_vals) if mttd_vals else 0.0
    mttd_median = (sorted(mttd_vals)[len(mttd_vals) // 2] if mttd_vals else 0.0)

    # --- ATT&CK coverage: покрытые правилами техники / ВСЯ матрица.
    #     Тот же честный знаменатель, что на странице «Покрытие» в консоли
    #     (раньше здесь было деление на «атакованные техники» — метрика
    #     всегда показывала ~100%, потому что мерила сама себя). ---
    from attack_matrix import all_techniques
    matrix = all_techniques()
    executed = set()
    for ep in episodes.values():
        executed |= ep["techs"]
    covered_rules = set(run_defense._ENGINE.techniques_covered())
    covered_in_matrix = covered_rules & matrix
    cov = len(covered_in_matrix) / len(matrix) if matrix else 0.0

    # --- ДОЛЯ ЛОЖНЫХ ПО ТРЁМ ЗНАМЕНАТЕЛЯМ -------------------------------
    #
    # Одна цифра «FP-rate» здесь невозможна честно, потому что «ложная тревога»
    # значит разное на разных уровнях конвейера:
    #
    #   по СОБЫТИЯМ      — сколько сырых детектов пришлось на нормальные
    #                      события. Самая пессимистичная и наименее полезная
    #                      величина: детект — не единица работы, аналитик их
    #                      поштучно не разбирает.
    #   по ИНЦИДЕНТАМ    — сколько склеенных инцидентов не пересеклись ни с
    #                      одним эпизодом атаки. Ближе к делу, но включает
    #                      низкорисковый поведенческий шум, который до очереди
    #                      не доходит.
    #   по ДЕЙСТВЕННЫМ   — то же среди инцидентов выше порога действия. Ровно
    #                      то, что реально попадёт к человеку.
    #
    # Раньше печаталась ТОЛЬКО третья, и это выглядело как выбор удобного
    # знаменателя: порог 0.6 ничем не обоснован, а от него цифра меняется в
    # разы. Теперь печатаются все три, и видно, что именно чем оплачено.
    # Рецензенту нужен не самый красивый показатель, а понятная шкала.
    import correlator
    cor = correlator.Correlator()
    for r, det in alerts:
        cor.add(r, det)
    incidents = list(cor.incidents.values())

    # Порог берётся от СЛИТОГО риска инцидента, а не от максимума по
    # событиям: свидетельства разных слоёв в многошаговой кампании приходят
    # на РАЗНЫХ шагах, и максимум их не складывает
    # (см. correlator.Correlator._incident_risk).
    #
    # Само правило «дошёл до очереди» живёт в correlator.actionable — там же,
    # откуда его берёт research/workload_curve.py. Две копии этого условия
    # успели разойтись: кривая порога считала по одному правилу, метрика по
    # другому, и рекомендация кривой не совпадала с поведением продукта.
    ACTION_THRESHOLD = config.ACTION_THRESHOLD
    _actionable = correlator.actionable

    ep_windows = collections.defaultdict(list)
    for ep in episodes.values():
        a = ep["events"][0].get("actor")
        f = ep["first"]
        lst = [_parse(e.get("ts_sim")) for e in ep["events"]]
        l = max([t for t in lst if t], default=f)
        if f:
            ep_windows[a].append((f, l or f))

    def _inc_is_fp(inc):
        a = inc.get("actor")
        s = _parse(inc.get("start_ts")); e = _parse(inc.get("last_ts")) or s
        return not any(s and wf and s <= wl and (e or s) >= wf
                       for (wf, wl) in ep_windows.get(a, []))

    actionable = [inc for inc in incidents if _actionable(inc)]
    inc_fp = sum(1 for inc in actionable if _inc_is_fp(inc))
    all_inc_fp = sum(1 for inc in incidents if _inc_is_fp(inc))
    fp = sum(1 for r, _ in alerts if not r.get("is_anomaly"))

    fp_rate = inc_fp / len(actionable) if actionable else 0.0
    fp_rate_incidents = all_inc_fp / len(incidents) if incidents else 0.0
    fp_rate_events = fp / len(alerts) if alerts else 0.0

    # Кривая «доля ложных от порога действия» — чтобы выбор 0.6 не выглядел
    # подогнанным: видно, как цифра ведёт себя на всём диапазоне.
    fp_by_threshold = []
    for thr in (0.2, 0.4, 0.6, 0.8, 0.9):
        sel = [inc for inc in incidents
               if inc.get("risk", inc.get("max_risk", 0)) >= thr]
        nfp = sum(1 for inc in sel if _inc_is_fp(inc))
        fp_by_threshold.append({
            "threshold": thr, "incidents": len(sel),
            "fp": nfp, "fp_rate": round(nfp / len(sel), 3) if sel else 0.0})

    # --- alerts/day (sim) ---
    # Знаменатель — длительность ВСЕГО ПОТОКА, а не отрезка между первым и
    # последним алертом. Раньше делили на разброс времён самих алертов: если
    # все алерты пришлись на один час двухнедельного прогона, метрика выдавала
    # «240 алертов в день» вместо честных 0.7. Чем ТИШЕ детектор, тем сильнее
    # завышался показатель его шумности — знак ошибки был обратный смыслу.
    ev_times = [t for t in (_parse(r.get("ts_sim")) for r in rows) if t]
    span_days = ((max(ev_times) - min(ev_times)).total_seconds() / 86400.0
                 if len(ev_times) > 1 else 0.0)
    span_days = max(span_days, 1.0 / 24)          # не меньше часа, иначе делим на шум
    per_day = len(alerts) / span_days

    # --- статистика: интервалы вместо точечных оценок ---
    # Detection rate 74.5% на 55 эпизодах — это на самом деле «где-то между 61 и
    # 85%». Без интервала такая цифра создаёт ложную точность, и это первое,
    # к чему придирается рецензент.
    dr_lo, dr_hi = stats.wilson(detected, n_ep) if n_ep else (0.0, 0.0)
    fp_lo, fp_hi = (stats.wilson(inc_fp, len(actionable)) if actionable else (0.0, 0.0))
    prec_tp = sum(1 for r, _ in alerts if r.get("is_anomaly"))
    prec_lo, prec_hi = stats.wilson(prec_tp, len(alerts)) if alerts else (0.0, 0.0)
    mttd_lo, mttd_hi = stats.bootstrap_ci(mttd_vals) if len(mttd_vals) > 2 else (mttd, mttd)

    # --- PR-AUC по риску алертов: интегральное качество без привязки к порогу.
    #     Именно PR, а не ROC: доля атакующих событий здесь порядка процента, и
    #     при таком дисбалансе ROC-AUC выглядит отлично даже у слабого
    #     детектора (знаменатель FPR — огромное число нормальных событий). ---
    risk_pos, risk_neg = [], []
    for r, s in zip(rows, risks):          # риски с ЕДИНСТВЕННОГО прогона выше
        (risk_pos if r.get("is_anomaly") else risk_neg).append(s)
    pr = stats.pr_auc(risk_pos, risk_neg)
    roc = stats.roc_auc(risk_pos, risk_neg)
    pr_base = stats.baseline_pr(len(risk_pos), len(risk_neg))

    return {
        "events": len(rows), "anomaly_episodes": n_ep, "alerts": len(alerts),
        # Признак «журнал прочитан не целиком»: без него длинный прогон
        # давал бы метрики по хвосту и выглядел как метрики по всему.
        "events_truncated": truncated, "events_limit": MAX_ROWS,
        "detection_rate": round(det_rate, 3), "detected_episodes": detected,
        # мягкий критерий (любой алерт актора в окне) — для сравнения, НЕ в отчёт
        "detection_rate_loose": round(detected_loose / n_ep, 3) if n_ep else 0.0,
        "attack_coverage": round(cov, 3),
        "mttd_sim_min": round(mttd, 1),
        "mttd_median_sim_min": round(mttd_median, 1),
        "mttd_measured_on": len(mttd_vals),      # цензурирование: сколько эпизодов
        "mttd_ci": [round(mttd_lo, 1), round(mttd_hi, 1)],
        "fp_rate": round(fp_rate, 3), "fp_incidents": inc_fp,
        "fp_rate_ci": [round(fp_lo, 3), round(fp_hi, 3)],
        # ТРИ ЗНАМЕНАТЕЛЯ — см. комментарий в compute()
        "fp_rate_events": round(fp_rate_events, 3),
        "fp_rate_incidents": round(fp_rate_incidents, 3),
        "fp_incidents_all": all_inc_fp,
        "fp_by_threshold": fp_by_threshold,
        "action_threshold": ACTION_THRESHOLD,
        "incidents": len(incidents), "actionable_incidents": len(actionable),
        "fp_alerts": fp,
        "precision": round(prec_tp / len(alerts), 3) if alerts else 0.0,
        "precision_ci": [round(prec_lo, 3), round(prec_hi, 3)],
        "detection_rate_ci": [round(dr_lo, 3), round(dr_hi, 3)],
        "pr_auc": round(pr, 3), "pr_baseline": round(pr_base, 4),
        "roc_auc": round(roc, 3),
        "alerts_per_sim_day": round(per_day, 1),
        "techniques_executed": len(executed),
        "techniques_in_matrix": len(matrix),
        "techniques_covered": len(covered_in_matrix),
    }


def main():
    ap = argparse.ArgumentParser(description="SOC metrics")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    m = compute()
    if not m:
        print("[!] Нет событий в event-store (запусти мир)."); sys.exit(1)
    if args.json:
        print(json.dumps(m, ensure_ascii=False, indent=2)); return
    def ci(key):
        lo, hi = m[key]
        return f"[{lo*100:.0f}–{hi*100:.0f}%]"

    print("=" * 68)
    print("SOC METRICS (эпизодная оценка по event-store)")
    print("=" * 68)
    print(f"  событий:                 {m['events']}")
    print(f"  аномальных эпизодов:     {m['anomaly_episodes']}")
    print(f"  алертов всего:           {m['alerts']}")
    print("-" * 68)
    print(f"  Detection rate:          {m['detection_rate']*100:.1f}% {ci('detection_rate_ci')}  "
          f"({m['detected_episodes']}/{m['anomaly_episodes']})")
    print("    строгий критерий: алерт НА СОБЫТИИ эпизода. Мягкий (любой алерт")
    print(f"    того же актора в окне) дал бы {m['detection_rate_loose']*100:.1f}% — разница и есть")
    print("    величина случайных совпадений.")
    print(f"  Precision (события):     {m['precision']*100:.1f}% {ci('precision_ci')}")
    print(f"  ATT&CK coverage:         {m['attack_coverage']*100:.1f}%  "
          f"({m['techniques_covered']}/{m['techniques_in_matrix']} техник матрицы)")
    print(f"  MTTD (sim-минуты):       среднее {m['mttd_sim_min']} "
          f"[{m['mttd_ci'][0]}–{m['mttd_ci'][1]}], медиана {m['mttd_median_sim_min']}")
    print(f"    цензурировано: посчитано по {m['mttd_measured_on']} пойманным эпизодам из "
          f"{m['anomaly_episodes']}; у непойманных времени обнаружения не существует.")
    print("  Доля ложных — ТРИ знаменателя (одной честной цифры не бывает):")
    print(f"    по событиям:           {m['fp_rate_events']*100:5.1f}%  "
          f"({m['fp_alerts']}/{m['alerts']} сырых детектов на норме)")
    print(f"    по инцидентам:         {m['fp_rate_incidents']*100:5.1f}%  "
          f"({m['fp_incidents_all']}/{m['incidents']} после корреляции)")
    print(f"    по ДЕЙСТВЕННЫМ:        {m['fp_rate']*100:5.1f}% {ci('fp_rate_ci')}  "
          f"({m['fp_incidents']}/{m['actionable_incidents']} дошли бы до аналитика)")
    print(f"    зависимость от порога действия (сейчас {m['action_threshold']}):")
    for _t in m["fp_by_threshold"]:
        print(f"      risk >= {_t['threshold']:.1f}:  {_t['fp']:>4}/{_t['incidents']:<5} = "
              f"{_t['fp_rate']*100:5.1f}%")
    print("    Цифра сильно зависит от порога, поэтому приводить одну без")
    print("    остальных некорректно — это и есть выбор удобного знаменателя.")
    # ЧТО ЭТА ЦИФРА ЗНАЧИТ ПРИ ТАКОМ ДИСБАЛАНСЕ.
    #
    # «60% ложных» звучит провально ровно до того момента, пока не сравнить с
    # базовой частотой. Если атаки составляют 0.4% потока, то случайно взятый
    # инцидент верен в 0.4% случаев; 40% верных — это в сто раз лучше случайного.
    # Для SOC решающим является не ДОЛЯ, а ЧИСЛО тревог в день: разобрать три
    # инцидента, из которых один настоящий, — рабочая нагрузка; разобрать
    # триста при той же доле — невозможная.
    _base = m["pr_baseline"] or 0.0
    _prec_inc = 1.0 - m["fp_rate"]
    if _base > 0:
        print(f"    Точность действенных инцидентов {_prec_inc*100:.0f}% при базовой "
              f"частоте атак {_base*100:.2f}%")
        print(f"    — выигрыш над случайным в {_prec_inc/_base:.0f} раз. При "
              f"{m['alerts_per_sim_day']} алертах в сим-день это посильная нагрузка;")
        print("    решает не доля, а абсолютное число тревог "
              "(см. research/workload_curve.py).")
    print(f"  Alerts / sim-день:       {m['alerts_per_sim_day']}")
    print("-" * 68)
    print(f"  PR-AUC:                  {m['pr_auc']:.3f}  "
          f"(база при этом дисбалансе: {m['pr_baseline']:.4f})")
    print(f"  ROC-AUC:                 {m['roc_auc']:.3f}  "
          "— смотреть на PR, а не сюда: при доле атак "
          f"{m['pr_baseline']*100:.1f}% ROC льстит детектору")
    print("=" * 68)
    print("  Интервалы — Уилсон 95% (для MTTD — bootstrap). Точечная оценка без")
    print("  интервала создаёт ложную точность: 74.5% на 55 эпизодах это 61–85%.")


if __name__ == "__main__":
    main()
