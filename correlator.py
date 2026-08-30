"""
Корреляционный движок (EPIC 3) — склеивает blue-алерты в ИНЦИДЕНТЫ.

Логика: алерты одного актора в пределах временно́го окна (по sim-времени) =
один инцидент. Инцидент копит ATT&CK-цепочку (тактики/техники по порядку),
максимальный risk, затронутые репозитории. Если в цепочке ≥2 РАЗНЫХ тактик —
это многошаговая атака (kill-chain), помечаем как campaign-like.

ВАЖНО: корреляция работает на blue-АЛЕРТАХ детектора (наблюдаемое), а НЕ на
campaign_id из мира — то есть защита сама восстанавливает цепочку, честно.
"""
import bisect
import logging
import itertools
import time as _time

import config

log = logging.getLogger("correlator")

_ids = itertools.count(1)


def actionable(inc, threshold=None):
    """Дойдёт ли инцидент до очереди аналитика.

    Одно определение на всех: его спрашивают и metrics.py при подсчёте
    полноты, и research/workload_curve.py при построении кривой порога.
    Раньше правило было записано в этих двух местах ПО-РАЗНОМУ — метрика
    пропускала инцидент, если по нему сработало правило, а кривая смотрела
    только на риск. Кривая обещала одно, продукт делал другое.

    Инцидент со сработавшим правилом раньше попадал в очередь ВСЕГДА, мимо
    порога. Рассуждение было такое: правило детерминированное и написано
    человеком под конкретную технику, «приватный ключ в коммите» стоит
    посмотреть при любом риске. Звучит убедительно, поэтому это и не
    проверяли.

    Проверили (research/workload_curve.py, три сида, оба профиля скрытности,
    342 эпизода атак, 46 сим-дней, порог 0.70):

        политика                        очередь/день   полнота   настоящих
        только риск >= порога                    6.3   258/342       29.7%
        то же, но правило мимо порога           10.5   258/342       17.8%

    Обход стоил +4.2 инцидента в день — на две трети длиннее очередь — и не
    принёс НИ ОДНОГО эпизода. Так и должно быть: одного сработавшего правила
    хватает, чтобы слитый риск сам перевалил за порог. Мимо порога проходили
    только СЛАБЫЕ срабатывания правил — те, что не подтверждаются ни
    поведением, ни моделью. Именно они и составляли треть очереди.

    Обход оставлен выключателем, а не удалён: рассуждение в его пользу
    разумное, и на другом наборе правил замер может дать другой ответ.
    """
    thr = config.ACTION_THRESHOLD if threshold is None else threshold
    if inc.get("risk", inc.get("max_risk", 0)) >= thr:
        return True
    if not getattr(config, "RULE_BYPASSES_THRESHOLD", False):
        return False
    if "has_rule" in inc:
        return bool(inc["has_rule"])
    return any(a.get("layer") == "rules" for a in inc.get("alerts", []))


def severity_bounds():
    """Границы уровней. Выводятся ИЗ ПОРОГА ДЕЙСТВИЯ, а не назначены отдельно.

    Раньше уровни стояли константами (critical ≥ 0.85, high ≥ 0.6, medium ≥ 0.4),
    а попадание в очередь решал config.ACTION_THRESHOLD = 0.70. Инцидент с
    риском 0.65 показывался как HIGH и при этом в очередь НЕ ПОПАДАЛ, а
    сортировка очереди ставила его выше действительно действенных medium.
    Значок уровня — главная подсказка аналитика при триаже, и он не должен
    противоречить собственному определению системы «на что смотреть».

    После правки «high и выше» означает ровно «дошло до очереди».
    """
    thr = float(getattr(config, "ACTION_THRESHOLD", 0.7))
    thr = min(max(thr, 0.05), 0.95)
    return {"high": thr,
            "critical": min(0.99, thr + (1.0 - thr) * 0.5),
            "medium": thr * 0.6}


def severity_for(risk, n_events=None, n_tactics=None):
    """Уровень инцидента по риску, ОГРАНИЧЕННЫЙ шириной свидетельства.

    ── Почему одного риска недостаточно ─────────────────────────────────
    Слияние в лог-шансах при приоре 0.01 насыщается на двух-трёх сигналах:
    измерено — fuse(0.3, 0.3) = 0.736, fuse(0.72, 0.3) = 0.944. Это
    математически верно (каждый сигнал в тридцать раз выше базовой частоты),
    но severity, выведенная из такого апостериора, перестаёт различать
    случаи: при работе аналитиком 44 инцидента из 46 оказались CRITICAL, и
    уровень перестал что-либо подсказывать при разборе.

    Хуже того, в критические попадало ОДНО событие, увиденное двумя слоями:
    «ручной прогон в production вне рабочего времени» (правило 0.64) плюс эхо
    того же события моделью (0.55) давали 0.95. Один запуск пайплайна ночью
    критическим инцидентом не является.

    Поэтому уровень ограничивается шириной свидетельства — тем, что платформа
    и так считает: сколько РАЗНЫХ событий и сколько тактик ATT&CK. Это не
    новая модель скоринга: риск и его расчёт не меняются, меняется только
    отображение уровня, чтобы он снова различал случаи.

      * одно событие                         -> не выше high;
      * менее двух тактик ATT&CK             -> не выше high;
      * иначе                                -> как раньше, по риску.
    """
    b = severity_bounds()
    r = float(risk or 0.0)
    if n_events is not None and n_tactics is not None:
        thin = (n_events <= 1) or (n_tactics < 2)
        if thin and r >= b["critical"]:
            return "high"
    if r >= b["critical"]:
        return "critical"
    if r >= b["high"]:
        return "high"
    if r >= b["medium"]:
        return "medium"
    return "low"


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
    """Единый разбор метки времени — тот же, что у детектора.

    Здесь была своя копия на одном strptime: она возвращала None на форме с
    микросекундами, на 'Z'-суффиксе RFC 3339 и на смещении часового пояса, а на
    НЕ-строке (например int) вовсе бросала TypeError, потому что ловился только
    ValueError. Две расходящиеся реализации разбора времени в системе, где
    корреляция строится на времени, — источник расхождений между тем, что видит
    детектор, и тем, что видит коррелятор.
    """
    import detector
    return detector.parse_ts(ts)


#: Верхние границы против «затопления тревогами».
#:
#: incidents рос неограниченно, alerts внутри инцидента — тоже, а chain
#: сортировался НА КАЖДОМ добавлении: инцидент из n сработок стоил
#: O(n² log n). Затопление тревогами — не гипотеза, а прямое действие
#: атакующего: шумим под одним актором, конвейер уходит в сортировку, карточка
#: инцидента разрастается сверх того, что интерфейс способен показать, а
#: настоящий шаг тонет среди тысяч строк.
MAX_INCIDENTS = 2000
MAX_ALERTS_PER_INCIDENT = 400
MAX_CHAIN = 200

#: Сколько сильнейших событий инцидента участвует в слиянии риска.
#: Затухание γ делает вклад дальних членов пренебрежимым, а обрезание
#: защищает от того, чтобы шумовой хвост тащил риск вверх числом.
MAX_FUSED_EVENTS = 8


#: Служебные значения поля technique у слоёв, не имеющих техники ATT&CK.
#: Держим одним списком: тот же набор фильтруется в интерфейсе (attackTech в
#: dashboard.html) и в выгрузке покрытия, и расхождение между ними означало бы
#: «ML» в матрице ATT&CK.
_LAYER_SENTINELS = ("ML", "UEBA")


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
        # ЕДИНИЦА СВИДЕТЕЛЬСТВА — СОБЫТИЕ, А НЕ СЛОЙ.
        #
        # Слияние по максимумам слоёв применяло формулу ВТОРОЙ РАЗ к тому же
        # самому событию: detector.process уже слил правила и свидетельство ML
        # в риск события, а здесь его составляющие сливались снова. Для
        # инцидента из ОДНОГО события это давало риск заметно выше, чем
        # вердикт детектора по этому событию.
        #
        # Замерено при работе аналитиком: инцидент из одного `pipeline_run`
        # (правило 0.64 «ручной прогон в production вне рабочего времени» плюс
        # эхо того же события моделью 0.55) получал риск 0.95 и уровень
        # CRITICAL. Один запуск пайплайна ночью — это не критический инцидент,
        # и два детектора, увидевшие ОДНО событие, не являются двумя
        # независимыми свидетельствами.
        #
        # Теперь складываются риски РАЗНЫХ событий, каждое со своим уже
        # слитым значением. Инцидент из одного события получает ровно риск
        # этого события; несколько событий по-прежнему усиливают друг друга
        # с тем же затуханием.
        ev_risks = sorted((float(r) for r in (inc.get("event_risks") or [])), reverse=True)
        if ev_risks:
            try:
                import detector
                return detector.fuse([{"risk": r} for r in ev_risks[:MAX_FUSED_EVENTS]])
            except Exception:
                log.error("не удалось слить риск инцидента — беру максимум",
                          exc_info=True, extra={"ctx": {"incident_id": inc.get("id")}})
                return ev_risks[0]
        best = {}
        for a in inc.get("alerts", []):
            layer = a.get("layer") or "unknown"
            best[layer] = max(best.get(layer, 0.0), float(a.get("risk", 0.0)))
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
        # ПРЕДЕЛ НА ПОЛНУЮ ДЛИТЕЛЬНОСТЬ, А НЕ ТОЛЬКО НА РАЗРЫВ.
        #
        # Окно закрывалось ИСКЛЮЧИТЕЛЬНО по паузе между соседними тревогами,
        # поэтому непрерывная активность держала инцидент открытым сколько
        # угодно. Замерено при работе аналитиком: инциденты на 9 ч 31 мин,
        # 9 ч 46 мин и 10 ч 26 мин — 51 тревога, 43 шага, 4 тактики под одним
        # актором. Это не случай, а «всё, что человек сделал за день»: и
        # разобрать такое нельзя, и цепочка атаки в нём не читается.
        # Интерфейс при этом обещает «алерты одного актора за три часа».
        if inc is not None and t is not None:
            start = _parse(inc["start_ts"])
            if start and abs((t - start).total_seconds()) > self.window_min * 60:
                log.debug("окно инцидента закрыто по предельной длительности",
                          extra={"ctx": {"incident_id": inc["id"], "actor": actor,
                                         "span_min": round((t - start).total_seconds() / 60, 1),
                                         "window_min": self.window_min}})
                inc = None
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
            self._evict()

        # ГРАНИЦЫ ОКНА ОБНОВЛЯЮТСЯ ТОЛЬКО РАЗБИРАЕМЫМ ВРЕМЕНЕМ.
        #
        # Раньше ветка `else` присваивала last_ts безусловно, поэтому событие с
        # ts_sim = None записывало None в поле, от которого зависит проверка
        # разрыва, — и окно этого актора НЕ ЗАКРЫВАЛОСЬ БОЛЬШЕ НИКОГДА.
        # Воспроизводилось так (окно 1 минута):
        #
        #   add(bob, 2026-01-01T10:00)  -> инцидент 5590340
        #   add(bob, ts=None)           -> инцидент 5590340
        #   add(bob, 2030-01-01T10:00)  -> инцидент 5590340   (через четыре года)
        #
        # Одно битое событие сливало всю дальнейшую жизнь актора в один
        # инцидент: цепочка ATT&CK теряет смысл, is_campaign становится истиной
        # на несвязанной активности, а окно инцидента пересекается почти с
        # любым эпизодом при подсчёте ложных срабатываний.
        #
        # Событие без пригодного времени по-прежнему попадает в текущий
        # инцидент (оно наблюдалось), но границ окна не двигает.
        t_ev = _parse(ts)
        if t_ev is not None:
            t_last = _parse(inc["last_ts"])
            t_start = _parse(inc["start_ts"])
            if t_last is None or t_ev > t_last:
                inc["last_ts"] = ts
            if t_start is None or t_ev < t_start:
                inc["start_ts"] = ts
        else:
            inc["undated_events"] = inc.get("undated_events", 0) + 1
        inc["max_risk"] = max(inc["max_risk"], det.get("risk", 0))
        # Риск ЭТОГО события (уже слитый детектором) — единица свидетельства
        # для incident_risk(). Держим только самые сильные: слабый хвост на
        # слияние с затуханием всё равно почти не влияет, а память инцидента
        # ограничена.
        _er = inc.setdefault("event_risks", [])
        _er.append(float(det.get("risk", 0.0)))
        if len(_er) > MAX_FUSED_EVENTS * 4:
            _er.sort(reverse=True); del _er[MAX_FUSED_EVENTS * 4:]
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
            # ВЕРХНЯЯ ГРАНИЦА НА ЧИСЛО СРАБОТОК В ИНЦИДЕНТЕ.
            #
            # Список рос неограниченно, а инцидент живёт в памяти процесса.
            # Затопление тревогами под одним актором раздувало карточку сверх
            # того, что интерфейс способен показать, и настоящий шаг тонул.
            # Держим самые рисковые и самые свежие, остальное считаем.
            if len(inc["alerts"]) >= MAX_ALERTS_PER_INCIDENT:
                inc["alerts_dropped"] = inc.get("alerts_dropped", 0) + 1
                weakest = min(range(len(inc["alerts"])),
                              key=lambda k: inc["alerts"][k].get("risk", 0))
                if inc["alerts"][weakest].get("risk", 0) >= a.get("risk", 0):
                    # ничего слабее нового нет — новую сработку не храним,
                    # но её техника/тактика ниже всё равно учитывается
                    tac0 = a.get("tactic"); tech0 = a.get("technique")
                    if tac0 and tac0 not in inc["tactics"]:
                        inc["tactics"].append(tac0)
                    if tech0 and tech0 not in inc["techniques"]:
                        inc["techniques"].append(tech0)
                    continue
                inc["alerts"].pop(weakest)
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
            # ЦЕПОЧКА — ЭТО ШАГИ АТАКИ, А НЕ СЛОИ, КОТОРЫЕ ИХ ЗАМЕТИЛИ.
            #
            # Поведенческий слой и модель кладут в technique служебные значения
            # UEBA и ML: техники ATT&CK у них нет по определению. Пока они
            # попадали в цепочку наравне с настоящими шагами, каждый шаг
            # задваивался — на живом инциденте кампании supply_chain_full
            # цепочка из ЧЕТЫРЁХ шагов печаталась семью строками:
            #
            #   11:29 Reconnaissance       T1593.003
            #   12:03 Initial Access       T1195.001
            #   12:03 Behavioral           ML          <- тот же момент
            #   12:34 Command and Control  T1102
            #   12:34 Behavioral           ML          <- тот же момент
            #
            # Аналитик читает kill-chain, чтобы понять ХОД атаки, и дубликаты с
            # тем же временем этому прямо мешают; в печатный IR-отчёт они
            # уходили как отдельные этапы расследования. Подтверждение модели
            # никуда не девается — оно остаётся в списке алертов и в
            # доказательствах, то есть там, где отвечает на вопрос «почему
            # сработало», а не «что происходило».
            if tech and tech not in _LAYER_SENTINELS and len(inc["chain"]) < MAX_CHAIN:
                # ВСТАВКА В ОТСОРТИРОВАННУЮ ПОЗИЦИЮ вместо пересортировки всего
                # массива на каждом добавлении: раньше инцидент из n сработок
                # стоил O(n² log n), и это была прямая цена «затопления
                # тревогами» под одним актором. Ключи держим рядом, чтобы
                # bisect не строил их заново.
                step = {"ts": ts, "tactic": tac, "technique": tech,
                        "action": ev.get("action"), "risk": a["risk"]}
                key = str(ts or "")
                keys = inc.setdefault("_chain_keys", [])
                pos = bisect.bisect_right(keys, key)
                keys.insert(pos, key)
                inc["chain"].insert(pos, step)
            elif tech and tech not in _LAYER_SENTINELS:
                inc["chain_dropped"] = inc.get("chain_dropped", 0) + 1
        # ЦЕПОЧКА ХРАНИТСЯ В ХРОНОЛОГИИ, А НЕ В ПОРЯДКЕ ПРИХОДА.
        #
        # Симулированное время внутри окна не строго возрастает: события
        # разных акторов и слоёв приходят вперемешку. Экран инцидента
        # сортировал цепочку перед отрисовкой сам, а вот печатный IR-отчёт
        # и вкладка MITRE брали массив как есть — и печатали шаги атаки
        # задом наперёд на тех участках, где порядок нарушен (на живом
        # стенде нашлось два таких разрыва в цепочке из 32 шагов).
        # Порядок теперь поддерживается вставкой (см. выше), поэтому
        # пересортировка на каждом добавлении не нужна.
        inc["touched_real"] = _time.time()
        inc["is_campaign"] = len([x for x in inc["tactics"] if x != "Behavioral"]) >= 2
        inc["risk"] = self._incident_risk(inc)
        _n_ev = len({(a.get("ts_sim"), a.get("action"), a.get("path"))
                     for a in inc.get("alerts", [])})
        _n_tac = len([x for x in inc["tactics"] if x != "Behavioral"])
        inc["n_events"] = _n_ev
        inc["severity"] = severity_for(inc["risk"], _n_ev, _n_tac)
        # ПОЧЕМУ УРОВЕНЬ НИЖЕ РИСКА. Без этой строки аналитик видит две
        # карточки с одинаковым риском 0.99 и разными уровнями и не может
        # понять, чем они отличаются.
        if severity_for(inc["risk"]) != inc["severity"]:
            inc["severity_note"] = (
                "уровень ограничен: "
                + ("наблюдение одно" if _n_ev <= 1 else f"событий {_n_ev}")
                + ", "
                + ("тактика одна" if _n_tac < 2 else f"тактик {_n_tac}")
                + " — для критического нужны разные события минимум в двух тактиках")
        else:
            inc.pop("severity_note", None)
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

    def _evict(self, keep_ids=()):
        """Не держать больше MAX_INCIDENTS инцидентов.

        Словарь не чистился вообще: консоль — процесс, который предполагается
        оставлять запущенным, и память росла монотонно. Вытесняем самые давно
        не тронутые, НО никогда — те, по которым аналитик уже вынес вердикт:
        их id хранится в SQLite, и потеря объекта означала бы потерю связи
        между вердиктом и инцидентом.
        """
        if len(self.incidents) <= MAX_INCIDENTS:
            return 0
        protected = set(keep_ids)
        try:
            import eventstore
            protected |= {int(k) for k in (eventstore.all_incident_status() or {})}
        except Exception:
            log.debug("не удалось прочитать вердикты перед вытеснением инцидентов",
                      exc_info=True)
        victims = sorted((i for i in self.incidents.values()
                          if i["id"] not in protected),
                         key=lambda i: i.get("touched_real") or 0)
        n = 0
        for i in victims:
            if len(self.incidents) <= MAX_INCIDENTS:
                break
            self.incidents.pop(i["id"], None)
            if self._open_by_actor.get(i["actor"]) == i["id"]:
                self._open_by_actor.pop(i["actor"], None)
            n += 1
        if n:
            log.info("вытеснены старые инциденты",
                     extra={"ctx": {"вытеснено": n, "осталось": len(self.incidents),
                                    "предел": MAX_INCIDENTS}})
        return n

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
