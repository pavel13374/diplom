"""
Red Team Engine — связывает точечные anomaly-примитивы в МНОГОШАГОВЫЕ
ATT&CK-кампании (EPIC 1). Каждый шаг = техника ATT&CK → конкретное GitLab-действие
(переиспользуем `activities/anomaly.py`). Все шаги одной кампании склеены общим
campaign_id и идут от ОДНОГО актора-«злоумышленника» (как реальная цепочка).

Разметка шага (через events.tag в AnomalyActivity.run):
    campaign_id, campaign_name, step_idx, technique_id, tactic, evasion_profile
плюс уже существующие episode_id / family / is_decisive.

Профили уклонения (1.3 — задел): noisy (быстро, подряд) vs stealthy (паузы между
шагами длиннее, «low-and-slow»). Для EPIC 1.1 достаточно влиять на тайминг.

ВАЖНО: «мир» не знает о «защите» — здесь только генерация активности противника,
никакой связи с детекторами.
"""
import uuid
import logging

import config
import events
import simclock

logger = logging.getLogger("red_team")

# Каталог кампаний. Шаг = (anom_method, technique_id, tactic).
# anom_method должен совпадать с _a_<...> в activities/anomaly.py.
#: Профили уклонения. Перечислены ЯВНО, потому что значение приходит из
#: очереди команд (кнопка на консоли защиты) и записывается в разметку
#: событий как evasion_profile.
EVASIONS = ("noisy", "stealthy", "adaptive")

CAMPAIGNS = {
    "ci_token_to_exfil": {
        "title": "CI-токен → отключение защиты → эксфильтрация",
        "steps": [
            ("disable_pipeline_security", "T1562.001", "Defense Evasion"),
            ("pipeline_token_leak",       "T1552.004", "Credential Access"),
            ("secret_exfil_vault",        "T1213",     "Collection"),
            ("data_exfiltration",         "T1567",     "Exfiltration"),
        ],
    },
    "insider_secret_theft": {
        "title": "Инсайдер: лишний токен → секрет в коммите → вынос",
        "steps": [
            ("rogue_token",              "T1098.001", "Persistence"),
            ("secret_in_commit",         "T1552.001", "Credential Access"),
            ("commit_to_secrets_repo",   "T1213",     "Collection"),
            ("artifact_secret_exposure", "T1567",     "Exfiltration"),
        ],
    },
    "supply_chain_recon": {
        "title": "Разведка → лишний токен → отравленный CI → вынос",
        "steps": [
            ("recon_enumeration", "T1087",     "Reconnaissance"),
            ("rogue_token",       "T1098.001", "Persistence"),
            ("secret_in_ci",      "T1059",     "Execution"),
            ("data_exfiltration", "T1567",     "Exfiltration"),
        ],
    },
    "review_bypass_sabotage": {
        "title": "Обход ревью → отравленный CI → разрушение",
        "steps": [
            ("weaken_protection",        "T1562",     "Defense Evasion"),
            ("self_approval_merge",      "T1562",     "Defense Evasion"),
            ("secret_in_ci",             "T1059",     "Execution"),
            ("mass_deletion",            "T1485",     "Impact"),
        ],
    },
    # --- новые сценарии: больше тактик и техник ATT&CK ---
    "cloud_takeover": {
        "title": "Захват облака → ключи реестра → вынос",
        "steps": [
            ("recon_enumeration", "T1087",     "Reconnaissance"),
            ("rogue_token",       "T1098.001", "Persistence"),
            ("container_creds",   "T1552.007", "Credential Access"),
            ("data_exfiltration", "T1567",     "Exfiltration"),
        ],
    },
    "ci_persistence": {
        "title": "Обход защиты → плановое CI-задание → вынос",
        "steps": [
            ("weaken_protection", "T1562.001", "Defense Evasion"),
            ("scheduled_ci_job",  "T1053",     "Execution"),
            ("secret_in_ci",      "T1552.004", "Credential Access"),
            ("data_exfiltration", "T1567",     "Exfiltration"),
        ],
    },
    "lateral_move": {
        "title": "SSH deploy-ключ → секрет → сбор из vault",
        "steps": [
            ("add_deploy_key",    "T1021.004", "Lateral Movement"),
            ("secret_in_commit",  "T1552.001", "Credential Access"),
            ("secret_exfil_vault","T1213",     "Collection"),
        ],
    },
    "destructive_insider": {
        "title": "Инсайдер: разведка → массовое удаление → срыв восстановления",
        "steps": [
            ("recon_enumeration", "T1087",     "Reconnaissance"),
            ("mass_deletion",     "T1485",     "Impact"),
            ("inhibit_recovery",  "T1490",     "Impact"),
        ],
    },
    "supply_chain_full": {
        "title": "Supply-chain: поиск → подмена зависимости → C2 → вынос",
        "steps": [
            ("code_search",     "T1593.003", "Reconnaissance"),
            ("dep_poison",      "T1195.001", "Initial Access"),
            ("webhook_c2",      "T1102",     "Command and Control"),
            ("exfil_altproto",  "T1048",     "Exfiltration"),
        ],
    },
    "priv_esc_cloud": {
        "title": "Повышение прав → облачный аккаунт → сбор → вынос",
        "steps": [
            ("elevate_privs",       "T1548",     "Privilege Escalation"),
            ("cloud_account_create","T1136.003", "Persistence"),
            ("automated_collection","T1119",     "Collection"),
            ("data_exfiltration",   "T1567",     "Exfiltration"),
        ],
    },
    "stealth_token_theft": {
        "title": "Разведка прав → кража OAuth → обфускация → зачистка следов",
        "steps": [
            ("perm_discovery",     "T1069",     "Discovery"),
            ("steal_oauth",        "T1528",     "Credential Access"),
            ("obfuscated_payload", "T1027",     "Defense Evasion"),
            ("history_rewrite",    "T1070.004", "Defense Evasion"),
        ],
    },
    # --- сценарии, добавленные по результатам трассируемости ---
    # tests/test_rule_coverage.py показал, что четыре правила не срабатывали ни
    # разу: техника описана, а шага атаки, который бы её исполнял, в кампаниях
    # не было. Правило без исполняемого шага создаёт видимость покрытия ATT&CK.
    "insider_collection": {
        "title": "Инсайдер: доступ к секретам → секрет в комментарии → пересылка почты",
        "steps": [
            ("grant_secret_access",  "T1098",     "Persistence"),
            ("secret_in_mr_comment", "T1552.001", "Credential Access"),
            ("mailbox_forward",      "T1114.003", "Collection"),
            ("data_exfiltration",    "T1567",     "Exfiltration"),
        ],
    },
    "supply_chain_creds": {
        "title": "Разведка → креды приватного индекса в манифесте → зашитый токен",
        "steps": [
            ("code_search",           "T1593.003", "Reconnaissance"),
            ("supply_chain_secret",   "T1195.002", "Initial Access"),
            ("hardcoded_token",       "T1552.001", "Credential Access"),
            ("artifact_secret_exposure", "T1567",  "Exfiltration"),
        ],
    },
    "review_bypass_push": {
        "title": "Ослабление защиты → merge без ревью → прямой push в main",
        "steps": [
            ("weaken_protection",      "T1562",     "Defense Evasion"),
            ("merge_without_review",   "T1562",     "Defense Evasion"),
            ("direct_push_protected",  "T1078",     "Initial Access"),
            ("secret_in_commit",       "T1552.001", "Credential Access"),
        ],
    },
    "deploy_abuse": {
        "title": "Злоупотребление деплоем → сбор → вынос по scp",
        "steps": [
            ("deploy_tool_abuse",   "T1072",     "Execution"),
            ("automated_collection","T1119",     "Collection"),
            ("exfil_altproto",      "T1048",     "Exfiltration"),
        ],
    },
}


class RedTeamEngine:
    def __init__(self, agents, state=None):
        self.agents = agents
        self.state = state

    def _attacker(self):
        from activities.anomaly import AnomalyActivity
        return AnomalyActivity(self.agents, self.state)._actor()

    def list_campaigns(self):
        return [{"key": k, "title": v["title"], "steps": len(v["steps"])}
                for k, v in CAMPAIGNS.items()]

    # Темп РЕАЛЬНОГО времени между шагами кампании (сек). Влияет только на то,
    # как быстро аналитик видит поступление детектов, а не на sim-метки событий.
    TEMPO_REAL_GAP = {"fast": 0, "realistic": 14, "slow": 40}

    def run_campaign(self, key=None, evasion="noisy", actor=None, avoid_techniques=None,
                     dwell_days=0, persona=None, motive=None, tempo="fast"):
        # ВТОРАЯ проверка, помимо маршрута: evasion попадает в поле разметки
        # evasion_profile КАЖДОГО порождённого события, а по нему стратифицируют
        # результаты metrics.py и research/. Произвольная строка тихо создаёт
        # фантомную страту, поэтому валидируем и здесь — источник команды может
        # быть не только HTTP-маршрутом.
        if evasion not in EVASIONS:
            logger.warning("неизвестный профиль уклонения — беру noisy",
                        extra={"ctx": {"передан": str(evasion)[:40],
                                       "допустимо": sorted(EVASIONS)}})
            evasion = "noisy"
        """Исполнить кампанию по шагам одним актором. Возвращает summary.
        avoid_techniques — для adaptive: техники, которые blue уже ловил, противник
        пропускает (co-evolution: атакующий адаптируется под защиту).
        tempo — темп РЕАЛЬНОГО времени: fast (мгновенно), realistic, slow —
        добавляет реальную паузу между шагами, чтобы атаку было видно поэтапно."""
        import random
        import time as _rt
        from activities.anomaly import AnomalyActivity
        _real_gap = self.TEMPO_REAL_GAP.get(tempo, 0)

        if key is None:
            key = random.choice(list(CAMPAIGNS))
        camp = CAMPAIGNS.get(key)
        if not camp:
            logger.warning(f"unknown campaign: {key}"); return None
        avoid = set(avoid_techniques or [])

        cid = "camp-" + uuid.uuid4().hex[:12]
        attacker = actor or self._attacker()
        engine = AnomalyActivity(self.agents, self.state)

        logger.warning(f"[RED] КАМПАНИЯ '{key}' ({camp['title']}) актор=@{attacker.username} "
                       f"профиль={evasion} шагов={len(camp['steps'])} id={cid}")
        # служебный маркер старта (meta — в датасет не идёт)
        try:
            events.emit("campaign_start", actor=attacker.username, role=attacker.role,
                        extra={"meta": True, "campaign_id": cid, "campaign_name": key,
                               "evasion_profile": evasion, "steps": len(camp["steps"]),
                               "persona": persona, "motive": motive, "dwell_days": dwell_days})
        except Exception:
            pass

        ok_steps = 0; skipped = 0
        import datetime as _dt
        # Реалистичный тайминг: КАЖДОЕ событие строго позже предыдущего (атака не
        # происходит «вся за минуту»), а между шагами — заметный интервал.
        _orig_now = simclock.now
        _nsteps = len(camp["steps"])
        _pos = {"sec": 0}
        # межшаговый интервал: дни (dwell) или десятки минут (обычная атака)
        if dwell_days and _nsteps > 1:
            _step_gap = int(dwell_days * 86400 / (_nsteps - 1))
        else:
            _step_gap = random.randint(25, 70) * 60
        # Атака РАЗВЕРНУЛАСЬ К ТЕКУЩЕМУ МОМЕНТУ: раскладываем шаги в ПРОШЛОЕ,
        # последний шаг попадает примерно на «сейчас». Иначе события получали
        # метку времени из будущего (в UI: «сделано в 17:53», а на часах 16:05).
        _span = _step_gap * max(0, _nsteps - 1) + 110 * _nsteps
        _base = simclock.now() - _dt.timedelta(seconds=_span)
        # Разрыв берётся из ОТДЕЛЬНОГО потока случайности, а не из общего.
        #
        # Здесь была невоспроизводимость всех офлайн-экспериментов. Пока
        # кампания идёт, simclock.now подменён на _adv_now, и КАЖДОЕ чтение
        # часов дёргало общий random. Чтение часов — не событие: его делают
        # и логгер, и запись в стор, и проверка рабочего времени, причём
        # разное число раз в зависимости от того, куда пошло исполнение.
        # В итоге один и тот же сид давал разные тексты коммитов, разные
        # метки времени и разный датасет (замерено: 887–896 событий, полнота
        # гуляла на 5 п.п.). Свой поток убирает связь: сколько бы раз ни
        # посмотрели на часы, всё остальное в прогоне не сдвинется.
        _rnd_t = random.Random(f"{key}|{evasion}|{getattr(config, 'SEED', 42)}")
        def _adv_now(_b=_base, _p=_pos, _r=_rnd_t):
            _p["sec"] += _r.randint(25, 110)   # внутри шага события идут с разрывом
            return _b + _dt.timedelta(seconds=_p["sec"])
        simclock.now = _adv_now
        for idx, (method, tech, tactic) in enumerate(camp["steps"]):
            if evasion == "adaptive" and tech in avoid:
                skipped += 1
                logger.warning(f"[RED]   шаг {idx+1}/{len(camp['steps'])} {tactic}/{tech} "
                               f"({method}) -> ПРОПУЩЕН (адаптация: техника палится)")
                continue
            if idx > 0:
                _pos["sec"] += _step_gap            # межшаговый интервал
            ctx = {"campaign_id": cid, "campaign_name": key, "step_idx": idx,
                   "technique_id": tech, "tactic": tactic, "evasion_profile": evasion,
                   "persona": persona, "motive": motive}
            try:
                ok = engine.run(anom_type=method, actor=attacker, campaign=ctx)
            except Exception as e:
                logger.exception(f"[RED] шаг {idx} ({method}) упал: {e}"); ok = False
            ok_steps += 1 if ok else 0
            logger.warning(f"[RED]   шаг {idx+1}/{len(camp['steps'])} {tactic}/{tech} "
                           f"({method}) -> {'ok' if ok else 'fail'}")
            self._between_steps(evasion)
            # Реальная пауза между шагами (кроме последнего): атака «разворачивается»
            # во времени, аналитик видит детекты поэтапно, а не все сразу.
            if _real_gap and idx < len(camp["steps"]) - 1:
                _rt.sleep(_real_gap)

        simclock.now = _orig_now  # вернуть нормальные часы после dwell-спреда
        logger.warning(f"[RED] КАМПАНИЯ '{key}' завершена: {ok_steps}/{len(camp['steps'])} шагов"
                       + (f" (dwell {dwell_days}д)" if dwell_days else ""))
        return {"campaign_id": cid, "key": key, "steps": len(camp["steps"]),
                "ok_steps": ok_steps, "skipped": skipped, "dwell_days": dwell_days,
                "persona": persona, "actor": attacker.username, "evasion": evasion}

    def _between_steps(self, evasion):
        """Пауза между шагами. stealthy = дольше (low-and-slow)."""
        base = config.scenario_pause_seconds()
        mult = {"noisy": 1.0, "stealthy": 3.0, "adaptive": 2.0}.get(evasion, 1.0)
        simclock.sleep(base * mult)
