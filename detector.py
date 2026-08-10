"""
Blue Detection Stack — потоковый детектор для контура «защита».

Слои:
  E   Enricher   — оконные агрегаты по актору (всплески удалений, интенсивность
      API-чтений, число разных репозиториев). Без него «массовость» и «разведку»
      нельзя отличить от единичного нормального действия, потому что в
      нормализованном словаре (taxonomy.py) у них ОДНО И ТО ЖЕ имя действия.
  L0  Rules Engine — правила из detections/*.json (Detection-as-Code): условие по
      НАБЛЮДАЕМЫМ полям события → alert + привязка к MITRE ATT&CK.
  L1  UEBA — вероятностная модель поведения актора. Скор = суммарная
      НЕОЖИДАННОСТЬ события в битах (surprisal), порог берётся из данных под
      заданный бюджет тревог, а не назначается константой.
  L2  ML — обученный классификатор по наблюдаемым признакам события
      (ml_features.FEATURES). Ловит то, подо что правило ещё не написано,
      и обобщается на форматы секретов, которых не видел.
  Fusion — объединяет сработки в один скоринг события с учётом зависимости слоёв.

АНТИ-ЛИК: на вход подаются только наблюдаемые поля (см. run_defense.observed),
метки мира (is_anomaly/anomaly_type/family/...) детектор не видит и не использует.
Дополнительно tests/test_leakage.py проверяет, что ни одно наблюдаемое поле не
несёт слишком много информации о метке (в частности, имя действия).

Зависимостей нет (json/stdlib). Правила — JSON, чтобы работало без pyyaml.
"""
import os
import json
import glob
import math
import logging
import collections
from datetime import datetime

log = logging.getLogger("detector")

RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "detections")
MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "models", "runtime_model.json")


# ----------------------------------------------------------------------
def _match_cond(value, cond):
    """Одно условие поля: прямое значение или {op: arg}."""
    if isinstance(cond, dict):
        for op, arg in cond.items():
            if op == ">=":
                if not (isinstance(value, (int, float)) and not isinstance(value, bool)
                        and value >= arg): return False
            elif op == ">":
                if not (isinstance(value, (int, float)) and not isinstance(value, bool)
                        and value > arg): return False
            elif op == "<=":
                if not (isinstance(value, (int, float)) and not isinstance(value, bool)
                        and value <= arg): return False
            elif op == "<":
                if not (isinstance(value, (int, float)) and not isinstance(value, bool)
                        and value < arg): return False
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
            elif op == "contains_any":
                if value is None: return False
                hay = value if isinstance(value, (list, tuple, set)) else str(value)
                if not any((a in hay) for a in arg): return False
            elif op == "is_null":
                if bool(value is None) != bool(arg): return False
            else:
                return False
        return True
    # ОТСУТСТВУЮЩИЙ булев атрибут считается ЛОЖЬЮ.
    #
    # Условие вида {"security_content": false} читается как «файл не является
    # рабочим продуктом SOC-команды». Если признака в событии нет вовсе — а так
    # выглядят все события, записанные до появления признака, — то естественный
    # ответ «нет», а не «условие не выполнено».
    #
    # Без этого добавление нового признака молча ломает детектирование на всей
    # накопленной истории: правила с новым условием перестают срабатывать при
    # переигрывании журнала, и выглядит это как исчезнувшая техника.
    if isinstance(cond, bool) and value is None:
        return cond is False
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
    if isinstance(ts, datetime):
        return ts
    try:
        return datetime.strptime(ts or "", "%Y-%m-%dT%H:%M:%S")
    except Exception:
        return None


# ======================================================================
#  E — ОБОГАЩЕНИЕ ОКОННЫМИ АГРЕГАТАМИ
# ======================================================================
class Enricher:
    """Считает по потоку скользящие агрегаты на актора.

    Зачем. После нормализации словаря действий массовое удаление выглядит как
    N обычных `file_delete`, а разведка — как серия обычных `api_read`. Ровно
    так это выглядит и в настоящем аудит-логе GitLab. Поэтому «массовость» и
    «интенсивность» должны ВЫЧИСЛЯТЬСЯ, а не читаться из имени действия.

    Добавляемые поля (доступны правилам и ML как обычные признаки):
        burst_file_delete_10m    — удалений файлов этим актором за 10 минут
        burst_branch_delete_30m  — удалений веток за 30 минут
        burst_api_read_15m       — чтений API за 15 минут
        api_items_sum_15m        — суммарный объём выдачи API за 15 минут
        distinct_api_paths_15m   — сколько РАЗНЫХ путей API опрошено
        burst_any_30m            — событий любого типа за 30 минут
        distinct_projects_1h     — сколько разных репозиториев затронуто за час
    """

    WINDOWS = {
        "file_delete":   ("burst_file_delete_10m", 10),
        "branch_delete": ("burst_branch_delete_30m", 30),
        "api_read":      ("burst_api_read_15m", 15),
    }

    #: Насколько далеко назад по sim-времени может «прыгнуть» поток, прежде чем
    #: это будет считаться НОВЫМ прогоном, а не запоздавшим событием.
    #: Журнал накапливается между запусками, а каждый запуск начинает
    #: симулированное время заново — на границе прогонов метка времени
    #: откатывается на недели назад.
    NEW_RUN_GAP_H = 6

    def __init__(self):
        self.hist = collections.defaultdict(lambda: collections.deque(maxlen=512))

    @staticmethod
    def _path_features(ev):
        """Признаки, выводимые ИЗ ПУТИ, детектор считает сам.

        Почему не полагаться на источник. Признаки бывают двух родов:

          • по СОДЕРЖИМОМУ — энтропия, secret-сигнатуры, конструкции обфускации.
            Их может посчитать только тот, у кого есть сам файл, поэтому они
            приходят в событии;
          • по ПУТИ — «это правило детектирования», «это lock-файл», «это
            манифест зависимостей». Путь есть в КАЖДОМ событии, и вывести их
            можно на месте.

        Пока признаки второго рода приходили из источника, добавление нового
        молча ломало детектирование на всей накопленной истории: у старых
        событий поля просто нет, условие `security_content: false` не
        выполняется, и правило перестаёт срабатывать при переигрывании журнала.
        Выглядит это как внезапно исчезнувшая техника.

        Считая их здесь, детектор получает одинаковую картину и на свежем
        потоке, и на архиве.
        """
        path = ev.get("path")
        if not path:
            return ev
        try:
            import content_features as cf
        except Exception:
            return ev
        for key, rx in (("security_content", cf._SECURITY_CONTENT_RE),
                        ("generated_signal", cf._GENERATED_RE),
                        ("deps_manifest", cf._DEPS_RE)):
            if ev.get(key) is None:
                ev[key] = bool(rx.search(str(path)))
        return ev

    def enrich(self, ev):
        """Возвращает КОПИЮ события с добавленными агрегатами.

        Агрегаты считаются ВКЛЮЧАЯ текущее событие (оно уже произошло, и
        аналитику оно видно), история пополняется ровно один раз — двойного
        учёта нет.

        Окно ДВУСТОРОННЕЕ: lo <= ts <= t.

        Почему это важно. Поток событий НЕ упорядочен по симулированному
        времени: красная команда датирует шаги кампании задним числом («атака
        развернулась к текущему моменту»), а журнал копится между запусками, и
        каждый запуск начинает sim-время заново — на границе прогонов метка
        откатывается на недели назад. В живом журнале так идёт больше половины
        событий.

        Пока окно ограничивалось только снизу (`ts >= lo`), для события со
        «старой» меткой в него попадала ВСЯ последующая история актора, и
        всплеск раздувался с реальных 25 событий до 512 (предел очереди).
        Признак `burst_any` — самый весомый у ML-слоя, поэтому модель кричала
        почти на каждое событие: 93% инцидентов были ложными, и все они
        приходили от одного слоя.
        """
        out = dict(ev)
        for field, _ in self.WINDOWS.values():
            out.setdefault(field, 0)
        out.setdefault("burst_any_30m", 0)
        out.setdefault("distinct_projects_1h", 0)
        self._path_features(out)

        actor = ev.get("actor")
        t = _parse_ts(ev.get("ts_sim"))
        if not actor or t is None:
            return out

        h = self.hist[actor]
        # Смена прогона: время ушло далеко назад — прежняя история к этому
        # потоку отношения не имеет, считать по ней всплески нельзя.
        if h and (h[-1][0] - t).total_seconds() > self.NEW_RUN_GAP_H * 3600:
            log.debug("сброс истории актора: поток начал новый прогон",
                      extra={"ctx": {"actor": actor, "было": h[-1][0].isoformat(),
                                     "стало": t.isoformat(), "событий": len(h)}})
            h.clear()

        h.append((t, ev.get("action"), ev.get("project"),
                  ev.get("api_path"), ev.get("items_returned") or 0))

        def window(minutes):
            hi = t.timestamp()
            lo = hi - minutes * 60
            return [x for x in h if lo <= x[0].timestamp() <= hi]

        out["burst_any_30m"] = len(window(30))
        out["distinct_projects_1h"] = len({x[2] for x in window(60) if x[2]})

        act = ev.get("action")
        if act in self.WINDOWS:
            field, mins = self.WINDOWS[act]
            w = [x for x in window(mins) if x[1] == act]
            out[field] = len(w)
            if act == "api_read":
                out["api_items_sum_15m"] = sum(x[4] or 0 for x in w)
                out["distinct_api_paths_15m"] = len({x[3] for x in w if x[3]})
        return out


# ======================================================================
#  L1 — ВЕРОЯТНОСТНЫЙ UEBA
# ======================================================================
def _surprisal(p):
    """-log2(p) с защитой от нуля. Единица измерения — биты информации."""
    return -math.log2(max(p, 1e-12))


class _VonMisesHours:
    """Непараметрическая оценка плотности часа активности НА ОКРУЖНОСТИ.

    Час — циклическая величина: 23:00 и 01:00 соседи, а обычная гистограмма
    этого не знает и считает переход через полночь разрывом. Здесь 24-бинная
    гистограмма сглаживается ядром фон Мизеса

        K(d) ∝ exp(κ · cos(2π·d / 24)),

    что эквивалентно круговому KDE, но считается за O(24) на событие.
    κ задаёт ширину ядра: больше κ — уже ядро (κ = 4 ≈ σ порядка 1.5–2 часов).
    """

    def __init__(self, kappa=4.0):
        self.kappa = kappa
        self.counts = [0] * 24
        self.n = 0
        w = [math.exp(kappa * math.cos(2 * math.pi * d / 24.0)) for d in range(24)]
        s = sum(w)
        self.kernel = [x / s for x in w]

    def update(self, hour):
        if hour is None:
            return
        self.counts[int(hour) % 24] += 1
        self.n += 1

    def prob(self, hour, alpha=1.0):
        """Сглаженная вероятность часа: круговой KDE + равномерный приор Дирихле."""
        if hour is None:
            return 1.0 / 24
        h = int(hour) % 24
        acc = 0.0
        for k in range(24):
            if self.counts[k]:
                acc += self.counts[k] * self.kernel[(h - k) % 24]
        return (acc + alpha) / (self.n + alpha * 24)


class _Categorical:
    """Мультиномиальное распределение со сглаживанием Дирихле.

    P(x) = (c_x + α) / (n + α·K), где K — размер словаря значений.
    Ни разу не виденное значение получает ненулевую вероятность — и тем большую
    неожиданность, чем длиннее история актора. Это заменяет прежний бинарный
    флаг «раньше такого не было», который одинаково реагировал на новичка с 12
    событиями и на ветерана с 4000.
    """

    def __init__(self, alpha=0.7):
        self.alpha = alpha
        self.c = collections.Counter()
        self.n = 0

    def update(self, x):
        if x is None:
            return
        self.c[x] += 1
        self.n += 1

    def prob(self, x, global_vocab):
        k = max(len(global_vocab), len(self.c), 2)
        return (self.c.get(x, 0) + self.alpha) / (self.n + self.alpha * k)


def _poisson_sf(c, lam):
    """P(X >= c) для X ~ Poisson(λ) — хвостовая вероятность всплеска."""
    if c <= 0:
        return 1.0
    lam = max(lam, 1e-6)
    term = math.exp(-lam)
    acc = term
    for k in range(1, int(c)):
        term *= lam / k
        acc += term
        if acc >= 1.0:
            return 1e-12
    return max(1e-12, 1.0 - acc)


class UEBA:
    """Поведенческие профили акторов: сколько БИТ неожиданности в событии.

    Было: risk += 0.3 за новый репозиторий, += 0.2 за ночь, += 0.2 за новое
    действие, порог 0.45. Веса и порог взяты из головы, шкала ничего не значит.

    Стало: событие оценивается суммарной неожиданностью

        S(e) = Σ_k  −log₂ P(x_k | actor)

    по компонентам k из COMPONENTS. Каждое слагаемое — биты информации,
    величины сопоставимы и складываются как логарифм совместной вероятности при
    условной независимости.

    ── КОГДА НЕОЖИДАННОСТЬ ЯВЛЯЕТСЯ МЕРОЙ РИСКА ─────────────────────────────
    Это ключевое место, и раньше оно было пропущено.

    Правильная мера улики — отношение правдоподобий:

        LLR(x) = log P(x | атака) − log P(x | норма).

    UEBA моделирует ТОЛЬКО знаменатель. Использовать −log P(x | норма) вместо
    LLR законно ровно тогда, когда P(x | атака) РАВНОМЕРНО по носителю: тогда
    числитель — константа, и порядок событий по LLR совпадает с порядком по
    неожиданности. «Редкое» становится синонимом «подозрительного».

    Если же атака систематически предпочитает ЧАСТЫЕ значения, знак вклада
    переворачивается: редкость начинает свидетельствовать в пользу НОРМЫ, а
    сумма тянет скор в неправильную сторону.

    ── ЧТО ПОКАЗАЛ ЗАМЕР (tools/ueba_components.py) ─────────────────────────
    На нагрузке 20 320 событий, ROC-AUC каждой компоненты по отдельности:

        hour    0.577   ← единственная информативная
        action  0.494   ← не различает
        repo    0.492   ← не различает
        burst   0.400   ← РАБОТАЕТ ПРОТИВ
        сумма всех четырёх: 0.451 — ХУЖЕ СЛУЧАЙНОГО

    Причины не статистические, а конструктивные — их видно из постановки:

      • `action`: taxonomy.py СПЕЦИАЛЬНО сделан так, чтобы атака и обычная
        работа описывались ОДНИМИ И ТЕМИ ЖЕ действиями (иначе имя действия
        стало бы меткой). Значит P(action | атака) ≈ P(action | норма) по
        построению, и допущение о равномерной альтернативе неверно. ROC 0.494
        — это не дефект, а ПОДТВЕРЖДЕНИЕ того, что нормализация словаря
        сработала.

      • `burst`: профили уклонения stealthy/adaptive явно РАСТЯГИВАЮТ шаги
        кампании во времени. Атакующий по построению тише обычной работы,
        поэтому P(высокий c | атака) МЕНЬШЕ, чем под нормой. Плюс поток
        пачечный: Var/E ≈ 4.2 (сессии), а пуассоновский хвост при
        сверхдисперсии оценивает обычную пачку из 20 событий в 20.7 бит при
        эмпирических 5.8 — то есть добавляет норме несколько бит шума.

      • `repo`: атака целится в конкретные репозитории (секреты, инфраструктура),
        а не равномерно; вклад близок к нулю, но знак не переворачивает.

    ── РЕШЕНИЕ ──────────────────────────────────────────────────────────────
    В сумму входят только компоненты, для которых допущение о равномерной
    альтернативе защитимо (COMPONENTS, по умолчанию repo + hour). Компоненты
    интенсивности НЕ выбрасываются: они остаются признаками слоя L2
    (burst_any, burst_delete, burst_api, distinct_projects), где ЗНАК
    ВЫУЧИВАЕТСЯ ПО ДАННЫМ. Модель это и сделала — вес burst_any вышел
    отрицательным (−1.15), то есть она самостоятельно выучила то, что здесь
    выведено из постановки задачи.

    Все компоненты по-прежнему СЧИТАЮТСЯ и отдаются в `parts` для объяснения
    алерта и для диагностики — просто не все входят в сумму.

    Порог не константа, а квантиль эмпирического распределения S под заданный
    БЮДЖЕТ ТРЕВОГ (UEBA_ALERT_BUDGET): «не более X% событий доходит до очереди» —
    величина, осмысленная для SOC и напрямую управляющая нагрузкой аналитика.
    """

    def __init__(self):
        self.MIN_EVENTS = _cfg("UEBA_MIN_EVENTS", 30)
        self.BUDGET = _cfg("UEBA_ALERT_BUDGET", 0.004)      # доля событий
        self.MIN_CALIB = _cfg("UEBA_MIN_CALIB", 400)        # событий до калибровки
        self.FALLBACK_BITS = _cfg("UEBA_FALLBACK_BITS", 18.0)
        self.SCALE_BITS = _cfg("UEBA_SCALE_BITS", 6.0)      # +6 бит над порогом -> risk 0.5
        self.VEL_WIN = _cfg("UEBA_VELOCITY_WINDOW_MIN", 30)
        # Нижняя граница λ пуассоновской модели интенсивности. При λ → 0 хвост
        # P(X ≥ c) улетает в машинный ноль, и одно-единственное действие
        # «нового» актора получало бы десятки бит неожиданности на пустом
        # месте. Поскольку c и λ теперь считаются ВКЛЮЧАЯ текущее событие,
        # осмысленный минимум — 1: «в окне бывает хотя бы это одно действие».
        self.MIN_RATE = _cfg("UEBA_MIN_RATE", 1.0)
        self.MIN_EXCESS = _cfg("UEBA_MIN_EXCESS_BITS", 1.0)
        #: Компоненты, ВХОДЯЩИЕ В СУММУ. Остальные считаются и показываются, но
        #: в скор не идут — см. разбор допущения о равномерной альтернативе в
        #: докстринге класса. Проверить решение: tools/ueba_components.py
        self.COMPONENTS = tuple(_cfg("UEBA_COMPONENTS", ("repo", "hour")))
        self._disabled = False

        self.actor = collections.defaultdict(lambda: {
            "n": 0,
            "hours": _VonMisesHours(),
            "repos": _Categorical(),
            "actions": _Categorical(),
            "recent": collections.deque(maxlen=256),
            "rate_ewma": None,
        })
        self.RECALIB_EVERY = _cfg("UEBA_RECALIB_EVERY", 200)
        self.vocab_repos = set()
        self.vocab_actions = set()
        self.scores = collections.deque(maxlen=8000)        # резервуар для квантиля
        self._thr_cache = None
        self._since_recalc = 10 ** 9

    # ---------------- порог из данных ----------------
    def threshold_bits(self):
        """Квантиль (1 − BUDGET) эмпирического распределения S.

        Пока распределение неизвестно, слой МОЛЧИТ (порог = ∞), а не работает
        по константе. Причина практическая: на первых сотнях событий профили
        пусты, неожиданность у всех высокая, и фиксированный порог давал
        лавину ложных тревог именно там, где данных меньше всего. Молчать до
        калибровки честнее, чем угадывать порог.
        """
        if self._disabled:
            return float("inf")
        if len(self.scores) < self.MIN_CALIB:
            return float("inf")
        # Пересчёт квантиля — O(n log n) по резервуару в 8000 значений. Раньше
        # флаг «грязно» ставился на КАЖДОМ событии прямо перед вызовом, поэтому
        # кэш не работал ни разу: сортировка 8000 чисел выполнялась на каждое
        # событие потока. Пересчитываем не чаще, чем раз в RECALIB_EVERY
        # наблюдений — на форму распределения это не влияет, а стоимость слоя
        # падает на два порядка.
        if self._thr_cache is None or self._since_recalc >= self.RECALIB_EVERY:
            s = sorted(self.scores)
            idx = min(len(s) - 1, max(0, int((1.0 - self.BUDGET) * len(s))))
            self._thr_cache = max(s[idx], 1.0)
            self._since_recalc = 0
        return self._thr_cache

    def disable(self):
        """Выключить слой (используется в ablation-экспериментах)."""
        self._disabled = True

    # ---------------- скоринг ----------------
    def components(self, ev):
        """Неожиданность КАЖДОЙ компоненты в битах, без суммирования.

        Отдельным методом, чтобы диагностика (tools/ueba_components.py) мерила
        РОВНО то же, что считает бой: решение «какие компоненты входят в сумму»
        должно проверяться на тех же числах, на которых принято.

        Возвращает (dict компонент -> биты, dict компонент -> текст объяснения).
        """
        a = ev.get("actor")
        p = self.actor[a]
        bits, why = {}, {}

        proj = ev.get("project")
        if proj:
            s = _surprisal(p["repos"].prob(proj, self.vocab_repos))
            bits["repo"] = s
            if s >= 4.0:
                why["repo"] = f"редкий для @{a} репозиторий {proj} ({s:.1f} бит)"

        act = ev.get("action")
        if act:
            s = _surprisal(p["actions"].prob(act, self.vocab_actions))
            bits["action"] = s
            if s >= 4.0:
                why["action"] = f"нетипичное действие {act} ({s:.1f} бит)"

        hr = ev.get("hour")
        if hr is not None:
            s = _surprisal(p["hours"].prob(hr))
            bits["hour"] = s
            if s >= 4.5:
                why["hour"] = f"нетипичный час {hr}:00 ({s:.1f} бит)"

        t = _parse_ts(ev.get("ts_sim"))
        if t is not None and p["rate_ewma"] is not None:
            # Окно ДВУСТОРОННЕЕ — по той же причине, что и в Enricher: поток не
            # упорядочен по симулированному времени (шаги кампании датируются
            # задним числом, журнал копится между запусками). При односторонней
            # границе событие со «старой» меткой видело всю последующую историю
            # актора, и интенсивность завышалась в разы: вместо 5 событий за
            # полчаса получалось 147.
            #
            # Условие именно `is not None`, а не «истинно»: rate_ewma == 0.0
            # ложно как булево, и всплеск у актора, который в этом окне обычно
            # НЕ ДЕЛАЕТ НИЧЕГО, полностью выпадал из оценки.
            hi = t.timestamp()
            lo = hi - self.VEL_WIN * 60
            c = sum(1 for x in p["recent"] if lo <= x.timestamp() <= hi) + 1
            lam = max(p["rate_ewma"], self.MIN_RATE)
            s = _surprisal(_poisson_sf(c, lam))
            bits["burst"] = s
            if s >= 6.0:
                why["burst"] = (f"всплеск {c} событий за {self.VEL_WIN}м "
                                f"при обычных {p['rate_ewma']:.1f} ({s:.1f} бит)")
        return bits, why

    def score(self, ev):
        """Неожиданность события ДО обновления профиля.

        Возвращает (risk 0..1, reasons, bits). risk — монотонное преобразование
        битов над порогом: risk = 1 − 2^(−(S−T)/SCALE); каждые SCALE бит сверх
        порога уполовинивают «остаток недоверия». Ниже порога risk = 0.

        В сумму входят только COMPONENTS — компоненты, для которых допущение о
        равномерной альтернативе защитимо (см. докстринг класса). Остальные
        считаются и попадают в объяснение, но скор не двигают.
        """
        a = ev.get("actor")
        if not a:
            return 0.0, [], 0.0
        p = self.actor[a]
        if p["n"] < self.MIN_EVENTS:
            return 0.0, [], 0.0

        comp, why = self.components(ev)
        bits = sum(v for k, v in comp.items() if k in self.COMPONENTS)
        parts = [why[k] for k in self.COMPONENTS if k in why]

        self.scores.append(bits)
        self._since_recalc += 1

        thr = self.threshold_bits()
        # ЗАПАС НАД ПОРОГОМ, а не просто «выше порога».
        #
        # Порог — эмпирический квантиль, и у него есть собственная погрешность:
        # он оценён по конечному резервуару, а само распределение S зависит от
        # того, сколько истории актора уже прочитано. Окно интенсивности
        # ДВУСТОРОННЕЕ (иначе не считаются кампании, датированные задним
        # числом), поэтому событие, вокруг которого поток уже прочитан целиком,
        # видит больше соседей, чем то же событие в момент калибровки. Разница
        # порядка доли бита — но её достаточно, чтобы совершенно рутинное
        # действие оказалось на волосок выше квантиля и породило алерт.
        #
        # Требование «превысить порог хотя бы на MIN_EXCESS бит» — это
        # требование, чтобы событие было как минимум вдвое менее вероятным, чем
        # граничное. Величина осмысленная: 1 бит = ровно двукратная разница в
        # правдоподобии, а не подобранный коэффициент.
        if thr == float("inf") or bits <= thr + self.MIN_EXCESS:
            return 0.0, parts, bits
        risk = 1.0 - math.pow(2.0, -(bits - thr) / max(self.SCALE_BITS, 0.5))
        return min(0.97, risk), parts, bits

    def update(self, ev):
        a = ev.get("actor")
        if not a:
            return
        p = self.actor[a]
        p["n"] += 1
        p["hours"].update(ev.get("hour"))
        if ev.get("project"):
            p["repos"].update(ev["project"]); self.vocab_repos.add(ev["project"])
        if ev.get("action"):
            p["actions"].update(ev["action"]); self.vocab_actions.add(ev["action"])
        t = _parse_ts(ev.get("ts_sim"))
        if t:
            # смена прогона: прежняя история к новому потоку не относится
            if p["recent"] and (p["recent"][-1] - t).total_seconds() > 6 * 3600:
                p["recent"].clear()
                p["rate_ewma"] = None
            hi = t.timestamp()
            lo = hi - self.VEL_WIN * 60
            # +1 — САМО ТЕКУЩЕЕ СОБЫТИЕ.
            #
            # score() считает наблюдаемое c ВКЛЮЧАЯ текущее событие, а базовая
            # интенсивность λ раньше копилась БЕЗ него. Основания разные, и для
            # актора с ритмом «одно действие в 37 минут» окно в 30 минут почти
            # всегда пустое: λ сходилась к 0, тогда как c не мог быть меньше 1.
            # Пуассоновский хвост P(X ≥ 1 | λ→0) → 0, то есть КАЖДОЕ действие
            # такого актора выглядело бесконечно неожиданным. Ошибка гасилась
            # лишь тем, что при λ = 0.0 слагаемое молча выбрасывалось (0.0
            # ложно как булево) — то есть один дефект прикрывал другой.
            #
            # Теперь c и λ измеряются на одном основании.
            c = sum(1 for x in p["recent"] if lo <= x.timestamp() <= hi) + 1
            # EWMA личной интенсивности (событий за окно VEL_WIN, включая себя)
            p["rate_ewma"] = float(c) if p["rate_ewma"] is None \
                else 0.97 * p["rate_ewma"] + 0.03 * c
            p["recent"].append(t)


# ======================================================================
#  L2 — ML
# ======================================================================
class MLScorer:
    """Инференс обученной модели по наблюдаемым признакам события.

    Модель линейная (логистическая регрессия со стандартизацией), веса лежат в
    models/runtime_model.json вместе со списком признаков, параметрами нормировки,
    порогом под FP-бюджет и коэффициентами калибровки Платта.

    Линейная модель выбрана не от бедности: она даёт вклад каждого признака в
    явном виде, поэтому алерт можно объяснить аналитику («сработало из-за высокой
    энтропии при отсутствии сигнатуры»), а для SOC объяснимость важнее лишней
    доли AUC.

    Если файла модели нет — слой молча выключается (available() == False), и
    система работает на правилах и UEBA. Так стенд запускается на чистой машине.
    """

    #: Версия формата модели. Поднимается, когда меняется СМЫСЛ полей, а не
    #: только их значения. v2: калибровка Платта считается от МАРЖИ z, а не от
    #: уже сжатой сигмоидой вероятности (см. proba()).
    FORMAT = 2

    def __init__(self, path=None):
        self.path = path or MODEL_PATH
        self.ok = False
        self.w = self.b = self.mu = self.sd = None
        self.threshold = 0.5
        self.platt = None
        self.platt_on = "margin"
        self.isotonic = None
        self.calibration = "platt"
        self.trained_on = None
        self.metrics = {}
        self._load()

    def _load(self):
        try:
            import ml_features
            with open(self.path, encoding="utf-8") as f:
                m = json.load(f)
            if m.get("features") != ml_features.FEATURES:
                log.warning(
                    "модель обучена на другом наборе признаков — слой L2 выключен. "
                    "Переобучи: python research/train_runtime_model.py",
                    extra={"ctx": {"path": self.path,
                                   "в модели": len(m.get("features") or []),
                                   "в коде": len(ml_features.FEATURES)}})
                return
            fmt = int(m.get("format", 1))
            if fmt < self.FORMAT:
                # Старый формат нельзя интерпретировать как новый: в v1 Платт
                # обучался поверх сигмоиды, из-за чего выход модели физически не
                # мог превысить ~0.035 и слой не влиял на решение. Молча
                # подхватывать такой файл опаснее, чем работать без слоя.
                log.warning(
                    "модель формата v%d, детектор ожидает v%d — слой L2 выключен. "
                    "Переобучи: python research/train_runtime_model.py",
                    fmt, self.FORMAT, extra={"ctx": {"path": self.path}})
                return
            self.w = m["w"]; self.b = m["b"]; self.mu = m["mu"]; self.sd = m["sd"]
            self.threshold = float(m.get("threshold", 0.5))
            self.platt = m.get("platt")
            self.platt_on = m.get("platt_on", "margin")
            self.isotonic = m.get("isotonic")
            self.calibration = m.get("calibration", "platt")
            if self.calibration == "isotonic" and not self.isotonic:
                log.warning("модель заявляет изотоническую калибровку, но узлов "
                            "нет — откатываюсь на Платта",
                            extra={"ctx": {"path": self.path}})
                self.calibration = "platt"
            self.trained_on = m.get("trained_on")
            self.metrics = m.get("metrics") or {}
            self.ok = True
            log.info("ML-слой загружен", extra={"ctx": {
                "features": len(self.w), "threshold": self.threshold,
                "format": fmt, "calibration": self.calibration,
                "platt_on": self.platt_on,
                "trained_on": self.trained_on, "metrics": self.metrics}})
        except FileNotFoundError:
            log.info("модели нет (%s) — слой L2 выключен, работаем на L0+L1", self.path)
        except Exception:
            log.error("не удалось загрузить модель — слой L2 выключен", exc_info=True)

    def available(self):
        return self.ok

    def _z(self, x):
        """Маржа линейной модели: z = b + Σ wⱼ·(xⱼ − μⱼ)/σⱼ. Не ограничена."""
        z = self.b
        for j, wj in enumerate(self.w):
            z += wj * ((x[j] - self.mu[j]) / (self.sd[j] or 1.0))
        return z

    def proba(self, ev):
        """Калиброванная P(атака | событие).

        Калибровка Платта применяется к МАРЖЕ z, а не к сигмоиде от неё:

            P = σ(A·z + B),     A, B подобраны на отложенной выборке.

        Почему это принципиально. Маржа z пробегает всю вещественную ось, и
        аффинное преобразование A·z + B тоже. Если же подать на вход Платта
        уже сжатую вероятность p = σ(z) ∈ (0,1), то A·p + B пробегает лишь
        отрезок длины |A|, и ВЕСЬ выход модели схлопывается в узкую полосу.
        На обученной модели этого стенда так и было: A = 3.85, B = −7.18, то
        есть выход лежал в [0.0008, 0.0347] — модель не могла выдать больше
        3.5% НИ ПРИ КАКОМ событии. Слой формально работал, фактически не
        влиял ни на риск, ни на приоритет: его вклад в fuse() был постоянным.
        """
        import ml_features
        z = self._z(ml_features.featurize(ev))
        # Изотоническая калибровка — непараметрическая: кусочно-линейная
        # монотонная функция маржи, выбирается на обучении, если даёт меньший
        # ECE, чем Платт (см. research/train_runtime_model.py).
        if self.calibration == "isotonic" and self.isotonic:
            import stats
            return stats.isotonic_apply(self.isotonic, z)
        if self.platt:
            if self.platt_on == "proba":      # формат v1 — сюда попадать не должны
                z = self.platt["a"] * (1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))) \
                    + self.platt["b"]
            else:
                z = self.platt["a"] * z + self.platt["b"]
        return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))

    def top_contributions(self, ev, k=3):
        """Признаки с наибольшим ПОЛОЖИТЕЛЬНЫМ вкладом в маржу — объяснение алерта.

        Вклад признака j равен wⱼ·zⱼ, где zⱼ — стандартизованное значение.
        Это точное аддитивное разложение маржи (для линейной модели совпадает
        с SHAP-значением относительно среднего), поэтому объяснение не
        «правдоподобное», а буквально то, из чего сложился скор.
        """
        import ml_features
        x = ml_features.featurize(ev)
        contrib = []
        for j, wj in enumerate(self.w):
            v = wj * ((x[j] - self.mu[j]) / (self.sd[j] or 1.0))
            if v > 0:
                contrib.append((v, ml_features.FEATURES[j]))
        contrib.sort(key=lambda t: -t[0])
        return [name for _, name in contrib[:k]]

    def explain(self, ev, k=6):
        """Полное разложение скора: [(признак, значение, вклад в маржу), ...].

        Отдаётся в API инцидента, чтобы аналитик видел ЧИСЛА, а не только
        названия признаков.
        """
        import ml_features
        x = ml_features.featurize(ev)
        z0 = self.b
        parts = []
        for j, wj in enumerate(self.w):
            v = wj * ((x[j] - self.mu[j]) / (self.sd[j] or 1.0))
            if abs(v) > 1e-9:
                parts.append({"feature": ml_features.FEATURES[j],
                              "value": round(x[j], 4),
                              "contribution": round(v, 4)})
        parts.sort(key=lambda d: -abs(d["contribution"]))
        return {"bias": round(z0, 4), "margin": round(self._z(x), 4),
                "proba": round(self.proba(ev), 6), "top": parts[:k]}


# ----------------------------------------------------------------------
def _logit(p):
    p = max(1e-6, min(1.0 - 1e-6, p))
    return math.log(p / (1.0 - p))


def _sigmoid(z):
    return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))


def fuse(alerts, mode=None, prior=None):
    """Слияние рисков нескольких слоёв в один скоринг события.

    Режимы:
      max        — максимум (консервативно, без допущений);
      noisy_or   — 1 − Π(1 − rᵢ);
      logodds    — сложение СВИДЕТЕЛЬСТВ (log-likelihood ratio) с затуханием
                   для зависимых источников (режим по умолчанию).

    ── Математика режима logodds ──────────────────────────────────────────
    Наивный Байес в лог-шансах:

        logit P(атака | e₁..eₙ) = logit π + Σᵢ log Λᵢ,
        где Λᵢ = P(eᵢ|атака)/P(eᵢ|норма) — отношение правдоподобий i-го слоя.

    Каждый слой отдаёт не Λ, а свою АПОСТЕРИОРНУЮ оценку pᵢ = P(атака|eᵢ).
    Свидетельство слоя восстанавливается вычитанием общего приора:

        log Λᵢ = logit pᵢ − logit π.

    Итого:

        logit P = logit π + Σᵢ γ^i · (logit pᵢ − logit π),

    где γ = FUSION_DECAY ∈ (0,1] штрафует зависимость слоёв: правило, UEBA и
    модель смотрят на одно и то же событие, условная независимость нарушена, и
    без затухания согласие завышало бы уверенность мультипликативно.

    ── Почему прежняя формула была неверна ────────────────────────────────
    Раньше складывались АПОСТЕРИОРНЫЕ лог-шансы без вычитания приора:

        logit P = Σᵢ γ^i · logit pᵢ.

    Приор при этом входил в сумму n раз вместо одного. Практическое следствие
    на этом стенде: приор низкий, поэтому у большинства слоёв pᵢ < 0.5 и
    logit pᵢ < 0 — КАЖДЫЙ дополнительный слой ТЯНУЛ РИСК ВНИЗ. Численно:
    правило с риском 0.70 + подтверждение модели с p = 0.033 давали на выходе
    0.30. Подтверждение второго слоя снижало риск события больше чем вдвое,
    два правила по 0.4 давали 0.35 — меньше каждого из них по отдельности.
    Свойство «согласие слоёв не может понижать риск» теперь выполняется по
    построению и закреплено тестом (tests/test_detector.py::fuse).

    prior — доля атакующих событий в потоке (config.FUSION_PRIOR). Это
    единственный параметр, который надо честно оценивать по данным, а не
    подбирать: он равен базовой частоте класса.
    """
    if not alerts:
        return 0.0
    mode = mode or _cfg("FUSION_MODE", "logodds")
    risks = sorted((float(a.get("risk", 0.0)) for a in alerts), reverse=True)
    risks = [max(1e-4, min(0.9999, r)) for r in risks]

    if mode == "max":
        return round(min(0.99, risks[0]), 4)

    if mode == "noisy_or":
        prod = 1.0
        for r in risks:
            prod *= (1.0 - r)
        return round(min(0.99, 1.0 - prod), 4)

    gamma = _cfg("FUSION_DECAY", 0.5)
    pi = prior if prior is not None else _cfg("FUSION_PRIOR", 0.01)
    l_pi = _logit(pi)
    z = l_pi
    for i, r in enumerate(risks):
        z += (gamma ** i) * (_logit(r) - l_pi)      # вклад = свидетельство слоя
    return round(min(0.99, _sigmoid(z)), 4)


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
    def __init__(self, rules_dir=None, use_ml=None):
        if rules_dir is None:
            d = _cfg("DETECTIONS_DIR", "detections")
            rules_dir = d if os.path.isabs(d) else os.path.join(
                os.path.dirname(os.path.abspath(__file__)), d)
        self.rules = self._load(rules_dir)
        self.enricher = Enricher()
        self.ueba = UEBA()
        want_ml = use_ml if use_ml is not None else _cfg("ML_ENABLED", True)
        self.ml = MLScorer() if want_ml else None
        self.ml_risk_cap = _cfg("ML_RISK_CAP", 0.8)
        # Ниже этого значения выход модели считается неинформативным и в
        # слияние не идёт: около приора вклад слоя в лог-шансы близок к нулю,
        # а численный шум калибровки — нет.
        self.ml_evidence_min = _cfg("ML_EVIDENCE_MIN",
                                    3.0 * _cfg("FUSION_PRIOR", 0.01))

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
        """Прогнать событие через E+L0+L1+L2. Возвращает dict со списком сработок.
        Профиль UEBA обновляется ПОСЛЕ скоринга."""
        ev = self.enricher.enrich(ev)
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

        # L1 — UEBA (вероятностный)
        u_risk, u_reasons, u_bits = self.ueba.score(ev)
        if u_risk > 0:
            alerts.append({
                "layer": "ueba", "rule_id": "ueba-behavior",
                "title": "Поведенческая аномалия (UEBA)",
                "technique": "UEBA", "tactic": "Behavioral",
                "severity": "medium" if u_risk < 0.6 else "high", "risk": round(u_risk, 3),
                "reason": "; ".join(u_reasons) or
                          f"отклонение от базлайна актора ({u_bits:.1f} бит)",
                "bits": round(u_bits, 2),
            })
        self.ueba.update(ev)

        # L2 — ML
        #
        # Модель играет ДВЕ роли, и их важно не смешивать:
        #
        #   1) СОБСТВЕННАЯ ТРЕВОГА — только когда p >= порога, подобранного под
        #      бюджет ложных срабатываний. Это то, что попадает в очередь
        #      аналитика, и цена ошибки здесь — его время.
        #   2) СВИДЕТЕЛЬСТВО для слияния — когда p заметно выше приора π, но
        #      ниже порога. Само по себе это не повод будить человека, но если
        #      сработало правило, согласие модели ОБЯЗАНО повышать риск: в
        #      логарифме шансов вклад слоя равен log(p/π · (1−π)/(1−p)) и при
        #      p > π положителен. Без этого канала модель влияла на решение
        #      только в 0.05% случаев (там, где она и так одна справлялась), а
        #      эшелонирование существовало лишь на бумаге.
        #
        # Свидетельство не порождает алерт: оно добавляется в fuse() отдельным
        # списком и в очередь не попадает.
        m_p = None
        evidence = []
        if self.ml is not None and self.ml.available():
            try:
                m_p = self.ml.proba(ev)
                if m_p >= self.ml.threshold:
                    why = self.ml.top_contributions(ev)
                    alerts.append({
                        "layer": "ml", "rule_id": "ml-content",
                        "title": "ML: событие похоже на вредоносное",
                        "technique": "ML", "tactic": "Behavioral",
                        "severity": "medium" if m_p < 0.8 else "high",
                        # cap: одна лишь модель не должна давать critical сама по себе
                        "risk": round(min(self.ml_risk_cap, m_p), 3),
                        "reason": ("модель: " + ", ".join(why)) if why else "модель: высокий скор",
                        "proba": round(m_p, 4),
                    })
                elif alerts and m_p >= self.ml_evidence_min:
                    evidence.append({"layer": "ml-evidence", "rule_id": "ml-evidence",
                                     "risk": round(min(self.ml_risk_cap, m_p), 4)})
            except Exception:
                log.error("ML-слой упал на событии — продолжаем без него", exc_info=True)

        _ctx = {"actor": ev.get("actor"), "action": ev.get("action"),
                "project": ev.get("project"), "ts_sim": ev.get("ts_sim"),
                "event_id": ev.get("_id")}
        if not alerts:
            log.debug("no-alert", extra={"ctx": {**_ctx,
                      "ueba_bits": round(u_bits, 2),
                      "ml_proba": m_p, "rules_checked": len(self.rules)}})
            return {"alert": False, "risk": 0.0, "alerts": [],
                    "ueba_bits": round(u_bits, 2), "ml_proba": m_p}
        risk = fuse(alerts + evidence)
        techs = sorted({a["technique"] for a in alerts if a.get("technique")})
        tactics = sorted({a["tactic"] for a in alerts if a.get("tactic")})
        log.info("alert", extra={"ctx": {**_ctx,
                 "rules_hit": [a["rule_id"] for a in alerts if a["layer"] == "rules"],
                 "layer_risks": {a["rule_id"]: a["risk"] for a in alerts},
                 "ueba_bits": round(u_bits, 2), "ueba_reasons": u_reasons,
                 "ml_proba": m_p,
                 "ml_evidence": [e["risk"] for e in evidence],
                 "fusion_prior": _cfg("FUSION_PRIOR", 0.01),
                 "fused_risk": round(risk, 3),
                 "techniques": techs, "tactics": tactics}})
        return {"alert": True, "risk": round(risk, 2), "alerts": alerts,
                "evidence": evidence,
                "techniques": techs, "tactics": tactics,
                "ueba_bits": round(u_bits, 2), "ml_proba": m_p}
