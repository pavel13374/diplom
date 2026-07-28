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

        S(e) = -log₂P(repo|actor) - log₂P(action|actor)
               - log₂P(hour|actor) - log₂P(всплеск не меньше наблюдаемого)

    Каждое слагаемое — биты информации; величины сопоставимы между собой и
    складываются корректно (это логарифм совместной вероятности при условной
    независимости компонент — допущение явное и проверяемое, в отличие от
    произвольных весов).

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
        self._disabled = False

        self.actor = collections.defaultdict(lambda: {
            "n": 0,
            "hours": _VonMisesHours(),
            "repos": _Categorical(),
            "actions": _Categorical(),
            "recent": collections.deque(maxlen=256),
            "rate_ewma": None,
        })
        self.vocab_repos = set()
        self.vocab_actions = set()
        self.scores = collections.deque(maxlen=8000)        # резервуар для квантиля
        self._thr_cache = None
        self._thr_dirty = True

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
        if self._thr_dirty or self._thr_cache is None:
            s = sorted(self.scores)
            idx = min(len(s) - 1, max(0, int((1.0 - self.BUDGET) * len(s))))
            self._thr_cache = max(s[idx], 1.0)
            self._thr_dirty = False
        return self._thr_cache

    def disable(self):
        """Выключить слой (используется в ablation-экспериментах)."""
        self._disabled = True

    # ---------------- скоринг ----------------
    def score(self, ev):
        """Неожиданность события ДО обновления профиля.

        Возвращает (risk 0..1, reasons, bits). risk — монотонное преобразование
        битов над порогом: risk = 1 − 2^(−(S−T)/SCALE); каждые SCALE бит сверх
        порога уполовинивают «остаток недоверия». Ниже порога risk = 0.
        """
        a = ev.get("actor")
        if not a:
            return 0.0, [], 0.0
        p = self.actor[a]
        if p["n"] < self.MIN_EVENTS:
            return 0.0, [], 0.0

        parts = []
        bits = 0.0

        proj = ev.get("project")
        if proj:
            s = _surprisal(p["repos"].prob(proj, self.vocab_repos))
            bits += s
            if s >= 4.0:
                parts.append(f"редкий для @{a} репозиторий {proj} ({s:.1f} бит)")

        act = ev.get("action")
        if act:
            s = _surprisal(p["actions"].prob(act, self.vocab_actions))
            bits += s
            if s >= 4.0:
                parts.append(f"нетипичное действие {act} ({s:.1f} бит)")

        hr = ev.get("hour")
        if hr is not None:
            s = _surprisal(p["hours"].prob(hr))
            bits += s
            if s >= 4.5:
                parts.append(f"нетипичный час {hr}:00 ({s:.1f} бит)")

        t = _parse_ts(ev.get("ts_sim"))
        if t is not None and p["rate_ewma"]:
            # Окно ДВУСТОРОННЕЕ — по той же причине, что и в Enricher: поток не
            # упорядочен по симулированному времени (шаги кампании датируются
            # задним числом, журнал копится между запусками). При односторонней
            # границе событие со «старой» меткой видело всю последующую историю
            # актора, и интенсивность завышалась в разы: вместо 5 событий за
            # полчаса получалось 147.
            hi = t.timestamp()
            lo = hi - self.VEL_WIN * 60
            c = sum(1 for x in p["recent"] if lo <= x.timestamp() <= hi) + 1
            s = _surprisal(_poisson_sf(c, p["rate_ewma"]))
            bits += s
            if s >= 6.0:
                parts.append(f"всплеск {c} событий за {self.VEL_WIN}м "
                             f"при обычных {p['rate_ewma']:.1f} ({s:.1f} бит)")

        self.scores.append(bits)
        self._thr_dirty = True

        thr = self.threshold_bits()
        if thr == float("inf") or bits <= thr:
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
            c = sum(1 for x in p["recent"] if lo <= x.timestamp() <= hi)
            # EWMA личной интенсивности (событий за окно VEL_WIN)
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

    def __init__(self, path=None):
        self.path = path or MODEL_PATH
        self.ok = False
        self.w = self.b = self.mu = self.sd = None
        self.threshold = 0.5
        self.platt = None
        self.trained_on = None
        self._load()

    def _load(self):
        try:
            import ml_features
            with open(self.path, encoding="utf-8") as f:
                m = json.load(f)
            if m.get("features") != ml_features.FEATURES:
                log.warning("модель обучена на другом наборе признаков — слой L2 выключен",
                            extra={"ctx": {"path": self.path}})
                return
            self.w = m["w"]; self.b = m["b"]; self.mu = m["mu"]; self.sd = m["sd"]
            self.threshold = float(m.get("threshold", 0.5))
            self.platt = m.get("platt")
            self.trained_on = m.get("trained_on")
            self.ok = True
            log.info("ML-слой загружен", extra={"ctx": {
                "features": len(self.w), "threshold": self.threshold,
                "trained_on": self.trained_on}})
        except FileNotFoundError:
            log.info("модели нет (%s) — слой L2 выключен, работаем на L0+L1", self.path)
        except Exception:
            log.error("не удалось загрузить модель — слой L2 выключен", exc_info=True)

    def available(self):
        return self.ok

    def _z(self, x):
        z = self.b
        for j, wj in enumerate(self.w):
            z += wj * ((x[j] - self.mu[j]) / (self.sd[j] or 1.0))
        return z

    def proba(self, ev):
        import ml_features
        x = ml_features.featurize(ev)
        p = 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, self._z(x)))))
        if self.platt:                        # калибровка Платта: p -> P(атака|p)
            za = self.platt["a"] * p + self.platt["b"]
            p = 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, za))))
        return p

    def top_contributions(self, ev, k=3):
        """Признаки с наибольшим положительным вкладом — для объяснения алерта."""
        import ml_features
        x = ml_features.featurize(ev)
        contrib = []
        for j, wj in enumerate(self.w):
            v = wj * ((x[j] - self.mu[j]) / (self.sd[j] or 1.0))
            if v > 0:
                contrib.append((v, ml_features.FEATURES[j]))
        contrib.sort(reverse=True)
        return [name for _, name in contrib[:k]]


# ----------------------------------------------------------------------
def fuse(alerts, mode=None):
    """Слияние рисков нескольких сработок в один скоринг события.

      max        — максимум (консервативно);
      noisy_or   — 1 − Π(1 − rᵢ);
      logodds    — сумма лог-шансов с затуханием для ЗАВИСИМЫХ источников
                   (режим по умолчанию).

    Почему не чистый noisy-OR. Он корректен только при УСЛОВНОЙ НЕЗАВИСИМОСТИ
    сигналов, а здесь правило, UEBA и ML смотрят на одно и то же событие и часто
    срабатывают по коррелирующим причинам. Независимость нарушена, и noisy-OR
    систематически завышает риск: два сигнала по 0.6 давали 0.84.

    Режим logodds складывает лог-шансы, но каждый следующий источник входит с
    затухающим весом γ^i (γ = FUSION_DECAY, по умолчанию 0.5). Это явная поправка
    на зависимость: согласие слоёв по-прежнему повышает уверенность, но уже не
    мультипликативно.
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
    z = 0.0
    for i, r in enumerate(risks):
        z += (gamma ** i) * math.log(r / (1.0 - r))
    p = 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))
    return round(min(0.99, p), 4)


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
        m_p = None
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
        risk = fuse(alerts)
        techs = sorted({a["technique"] for a in alerts if a.get("technique")})
        tactics = sorted({a["tactic"] for a in alerts if a.get("tactic")})
        log.info("alert", extra={"ctx": {**_ctx,
                 "rules_hit": [a["rule_id"] for a in alerts if a["layer"] == "rules"],
                 "layer_risks": {a["rule_id"]: a["risk"] for a in alerts},
                 "ueba_bits": round(u_bits, 2), "ueba_reasons": u_reasons,
                 "ml_proba": m_p,
                 "fused_risk": round(risk, 3),
                 "techniques": techs, "tactics": tactics}})
        return {"alert": True, "risk": round(risk, 2), "alerts": alerts,
                "techniques": techs, "tactics": tactics,
                "ueba_bits": round(u_bits, 2), "ml_proba": m_p}
