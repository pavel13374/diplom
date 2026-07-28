"""
Виртуальные («симулированные») часы — основа таймлапса.

Идея: отвязать «время в отделе» от реального времени. Один реальный
час может вмещать целые сутки/неделю работы. Ночи и выходные
проматываются почти мгновенно, поэтому реальное время тратится в
основном на «рабочие часы».

Все паузы в коде выражаются в СИМУЛИРОВАННЫХ секундах и переводятся в
реальный сон делением на scale (sim-секунд за 1 реальную секунду).

Модуль держит глобальный «активный» clock, чтобы и агенты, и контент
обращались к одному источнику времени через simclock.now()/today()/sleep().
"""
import time as _time
import logging
from datetime import datetime, timedelta, date

logger = logging.getLogger(__name__)

_ACTIVE = None


class SimClock:
    def __init__(self, start_sim, scale, work_start, work_end, work_days,
                 fast_forward_offhours=True, api_min_pause=0.4, max_real_sleep=8.0):
        self.start_sim   = start_sim
        self.scale       = max(0.0001, float(scale))
        self.work_start  = work_start
        self.work_end    = work_end
        self.work_days   = list(work_days)
        self.fast_forward_offhours = fast_forward_offhours
        self.api_min_pause = api_min_pause
        self.max_real_sleep = max_real_sleep
        self._start_real = _time.monotonic()
        self._offset     = timedelta(0)

    def now(self):
        elapsed_real = _time.monotonic() - self._start_real
        return self.start_sim + timedelta(seconds=elapsed_real * self.scale) + self._offset

    def today(self):
        return self.now().date()

    def sleep(self, sim_seconds):
        if sim_seconds <= 0:
            real = self.api_min_pause
        else:
            real = sim_seconds / self.scale
        real = max(self.api_min_pause, min(real, self.max_real_sleep))
        _time.sleep(real)

    def is_work_time(self, now=None):
        now = now or self.now()
        if now.weekday() not in self.work_days:
            return False
        return self.work_start <= now.hour < self.work_end

    def next_work_start(self, now=None):
        now = now or self.now()
        if now.weekday() in self.work_days and now.hour < self.work_start:
            return now.replace(hour=self.work_start, minute=0, second=0, microsecond=0)
        for add in range(1, 9):
            d = (now + timedelta(days=add)).replace(
                hour=self.work_start, minute=0, second=0, microsecond=0)
            if d.weekday() in self.work_days:
                return d
        return now + timedelta(hours=1)

    def fast_forward_to(self, target_sim):
        delta = target_sim - self.now()
        if delta.total_seconds() > 0:
            self._offset += delta

    def fast_forward(self, sim_seconds):
        if sim_seconds > 0:
            self._offset += timedelta(seconds=sim_seconds)

    def set_scale(self, new_scale):
        cur = self.now()
        self.start_sim   = cur
        self._start_real = _time.monotonic()
        self._offset     = timedelta(0)
        self.scale       = max(0.0001, float(new_scale))


# ----------------------------------------------------------------------
def init(clock):
    global _ACTIVE
    _ACTIVE = clock
    return clock

def get():
    return _ACTIVE

def now():
    return _ACTIVE.now() if _ACTIVE else datetime.now()

def today():
    return _ACTIVE.today() if _ACTIVE else date.today()

def today_iso():
    return today().isoformat()

def sleep(sim_seconds):
    if _ACTIVE:
        _ACTIVE.sleep(sim_seconds)
    else:
        _time.sleep(min(sim_seconds, 2.0))

def is_work_time():
    return _ACTIVE.is_work_time() if _ACTIVE else True

def stamp():
    return now().strftime("%a %Y-%m-%d %H:%M")


def content_date_iso():
    """Дата для записи в GitLab (rule date/modified и т.п.).
    Зависит от config.GITLAB_DATES: 'real' (по умолч.) — реальное время сервера,
    'sim' — симулированное."""
    try:
        import config
        if getattr(config, "GITLAB_DATES", "real") == "sim":
            return today_iso()
    except Exception:
        pass
    return datetime.now().date().isoformat()
