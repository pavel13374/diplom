"""
Планировщик активностей SOC-команды.

Управляет:
  * виртуальным временем (таймлапс) и рабочими часами;
  * ритмом отдела: стендапы, on-call, отпуска, спринты, change-freeze;
  * выбором активностей по СОСТОЯНИЮ правил (жизненный цикл);
  * новыми сценариями: issues, кампании, релизы.

Всё время — симулированное (см. simclock). Реальный сон = sim / TIME_SCALE.
"""
import random
import logging

import config
import simclock
import events
from config import (
    DELAYS, PROJECTS, OFF_HOURS_ALLOWED_ACTIVITIES, LUNCH_BREAK, FEATURES,
)

logger = logging.getLogger(__name__)


def weighted_choice(weights: dict) -> str:
    keys   = list(weights.keys())
    values = list(weights.values())
    return random.choices(keys, weights=values, k=1)[0]


class Scheduler:
    def __init__(self, agents: dict, gl_client, state=None):
        self.agents = agents
        self.gl     = gl_client
        self.state  = state
        self.iteration = 0
        self.stats  = {k: 0 for k in config.ACTIVITY_WEIGHTS}
        for extra in ("standup", "release"):
            self.stats[extra] = 0
        self.stats["total_runs"] = 0
        self.stats["total_ok"]   = 0
        self.stats["total_fail"] = 0
        self.stats["skipped_offhours"] = 0
        self.last_ff = None
        self._last_day        = None
        self._standup_day     = None
        self._lunch_day       = None
        self._oncall_week     = None
        self._sprint_number   = (state.data["sprint_number"] if state else 1)
        self.last_activity    = None
        self.last_actor       = None
        self.last_activity_ts = None
        self._recent_acts = []

        from activities import flow
        flow.set_agents(agents)

    # ------------------------------------------------------------------
    def _role(self, *roles):
        return [a for u, a in self.agents.items()
                if config.USERS.get(u, {}).get("role") in roles]

    def _engineers(self):
        pool = self._role("detection_engineer", "threat_hunter", "soc_analyst", "devops")
        if not pool:
            pool = [a for u, a in self.agents.items()
                    if config.USERS.get(u, {}).get("role") not in ("lead", "bot")]
        return pool or list(self.agents.values())

    def _random_engineer(self):
        return random.choice(self._engineers())

    def _lead(self):
        leads = self._role("lead")
        return leads[0] if leads else (self.agents.get("alex.petrov") or next(iter(self.agents.values())))

    def _anna(self):
        mls = self._role("ml_engineer")
        return random.choice(mls) if mls else self._random_engineer()

    def _pick_role(self, *roles):
        pool = self._role(*roles)
        return random.choice(pool) if pool else None

    def _agent_or_lead(self, username):
        return self.agents.get(username) or self._lead()

    def _get_open_mr_count(self) -> int:
        total = 0
        for pid in set(config.WORK_REPOS.values()):
            total += len(self.gl.get_open_mrs(pid))
        return total

    # ------------------------------------------------------------------
    def _daily_and_rhythm_hooks(self):
        if not self.state:
            return
        now = simclock.now()
        today = now.date()

        if self._last_day != today:
            self._last_day = today
            if FEATURES.get("pto") and random.random() < config.PTO_PROBABILITY_PER_DAY:
                who = random.choice(["maria.ivanova", "dmitry.kozlov", "anna.smirnova"])
                self.state.set_pto(who)
                logger.info(f"[rhythm] {who} сегодня в PTO (отпуск/болезнь)")
            num, _ = self.state.ensure_sprint()
            if num != self._sprint_number:
                self._sprint_number = num
                logger.info(f"[rhythm] начался Sprint {num} — готовим релиз прошлого")
                self._run_release()

        iso_week = now.isocalendar()[1]
        if self._oncall_week is None:
            self._oncall_week = iso_week
        elif iso_week != self._oncall_week:
            self._oncall_week = iso_week
            self.state.advance_oncall()
            logger.info(f"[rhythm] смена on-call: дежурный @{self.state.current_oncall()}")

        if (FEATURES.get("standup") and simclock.is_work_time()
                and self._standup_day != today):
            self._standup_day = today
            self._run_standup()

    def _run_standup(self):
        try:
            from activities.standup import StandupActivity
            self.stats["standup"] += 1
            StandupActivity(self.agents, self._lead(), self.state).run()
        except Exception as e:
            logger.exception(f"standup failed: {e}")

    def _run_release(self):
        try:
            from activities.release import ReleaseActivity
            self.stats["release"] += 1
            ReleaseActivity(self._lead(), self.state).run()
        except Exception as e:
            logger.exception(f"release failed: {e}")

    def _maybe_lunch(self):
        if not LUNCH_BREAK.get("enabled"):
            return
        now = simclock.now()
        if self._lunch_day == now.date():
            return
        if now.hour == LUNCH_BREAK["hour"]:
            self._lunch_day = now.date()
            logger.info(f"[rhythm] обед (~{LUNCH_BREAK['duration_min']} мин sim)")
            simclock.sleep(LUNCH_BREAK["duration_min"] * 60)

    def _change_freeze_now(self) -> bool:
        if not FEATURES.get("change_freeze_friday"):
            return False
        now = simclock.now()
        return now.weekday() == 4 and now.hour >= 14

    # ------------------------------------------------------------------
    def _handle_offhours(self) -> bool:
        clock = simclock.get()
        timelapse = config.TIMELAPSE_ENABLED and config.FAST_FORWARD_OFFHOURS and clock

        if config.OFF_HOURS_MODE == "idle":
            if timelapse:
                target = clock.next_work_start()
                clock.fast_forward_to(target)
                self.last_ff = f"⏩ промотка нерабочего времени → {target:%a %H:%M}"
                logger.info(f"[Scheduler] {self.last_ff} (сейчас {simclock.stamp()})")
                simclock.sleep(0)
                return False
            else:
                if clock:
                    target = clock.next_work_start()
                    import time as _t
                    while simclock.now() < target:
                        _t.sleep(min(config.OFF_HOURS_POLL_SECONDS, 30))
                return False

        # честный ночной шум: легитимная активность (релизный кранч / дежурный чинит баг),
        # чтобы off-hours перестал быть тривиальным признаком атаки (FP становятся честными)
        if random.random() < getattr(config, "NIGHT_NOISE_PROB", 0.12):
            return self._offhours_benign_burst()

        if random.random() < config.OFF_HOURS_ACTIVITY_PROBABILITY:
            if getattr(config, "ATTACK_AUTO", False) and random.random() < config.ANOMALY_RATE_OFFHOURS:
                return self._run_anomaly(offhours=True)
            activity = random.choice(OFF_HOURS_ALLOWED_ACTIVITIES)
            oncall = self.state.current_oncall() if self.state else "dmitry.kozlov"
            logger.info(f"[Scheduler] [on-call @{oncall}] {simclock.stamp()}: {activity}")
            self.stats[activity] = self.stats.get(activity, 0) + 1
            ok = self._dispatch(activity, forced_actor=oncall)
            self.stats["total_ok" if ok else "total_fail"] += 1
            simclock.sleep(config.scenario_pause_seconds())
            return ok

        self.stats["skipped_offhours"] += 1
        if timelapse:
            clock.fast_forward(random.uniform(30, 120) * 60)
            self.last_ff = f"⏩ промотка нерабочего времени (сейчас {simclock.stamp()})"
            logger.info(f"[Scheduler] {self.last_ff}")
            simclock.sleep(0)
        else:
            simclock.sleep(config.OFF_HOURS_POLL_SECONDS)
        return False

    def _offhours_benign_burst(self) -> bool:
        """Легитимная ночная/выходная активность (НЕ атака): релизный кранч,
        дежурный чинит горящий баг, плановое обслуживание. Эмитит нормальные
        события ночью, чтобы off-hours не был тривиальным маркером атаки."""
        import events as _ev
        import random as _r
        oncall = self.state.current_oncall() if self.state else "dmitry.kozlov"
        scenario = _r.choice(["release_crunch", "oncall_hotfix", "weekend_maintenance"])
        repos = ["detection-rules", "normalization-rules", "playbooks", "soc-infra"]
        paths = ["rules/win/fix.yml", "src/util.py", "docs/runbook.md", "ci/deploy.yml",
                 "config/.env.example", "normalizers/parse.py"]
        n = _r.randint(1, 3)
        for _ in range(n):
            path = _r.choice(paths)
            ph = path.endswith(".env.example")
            _ev.emit("push", actor=oncall, role="detection_engineer",
                     project=_r.choice(repos), path=path,
                     extra={"shannon_entropy": 3.2 if ph else round(_r.uniform(2.0, 3.6), 2),
                            "regex_hits": [], "n_regex_hits": 0,
                            "filename_signal": ph, "placeholder_signal": ph,
                            "bytes": _r.randint(120, 900), "ext": path.split(".")[-1]})
        self.stats["offhours_benign"] = self.stats.get("offhours_benign", 0) + n
        logger.info(f"[Scheduler] [night benign @{oncall}] {simclock.stamp()}: {scenario} x{n}")
        return True

    # ------------------------------------------------------------------
    def _choose_activity_and_target(self):
        kwargs = {}

        if self.state and FEATURES.get("lifecycle_state"):
            due = self.state.due_reverts()
            if due:
                p = due[0]
                return "revert_bad_rule", {"target_slug": p["slug"], "reason": p["reason"]}

        open_mrs = self._get_open_mr_count()
        if open_mrs >= config.MAX_OPEN_MRS:
            return "__drain__", {}

        activity = weighted_choice(config.ACTIVITY_WEIGHTS)
        tries = 0
        while activity in self._recent_acts[-2:] and tries < 5:
            activity = weighted_choice(config.ACTIVITY_WEIGHTS); tries += 1

        if self._change_freeze_now() and activity in (
                "bulk_maintenance", "new_detection_rule", "recreate_fixed_rule",
                "deprecate_rule"):
            logger.info("[Scheduler] [change-freeze] пятница — выбираю безопасную задачу")
            activity = random.choice(
                ["triage_false_positive", "open_issue", "update_dashboard", "tune_threshold"])

        if self.state and FEATURES.get("lifecycle_state"):
            if activity in ("tune_threshold", "fix_existing_rule"):
                noisy = self.state.pick_noisy()
                if noisy:
                    kwargs["target"] = noisy["path"]
            elif activity == "deprecate_rule":
                dead = self.state.pick_deprecatable()
                if dead:
                    kwargs["target"] = dead["path"]

        self._recent_acts.append(activity)
        self._recent_acts = self._recent_acts[-6:]
        return activity, kwargs

    # ------------------------------------------------------------------
    def run_once(self) -> bool:
        self.iteration += 1
        self.stats["total_runs"] += 1

        # команды из Purple-консоли (например, запуск red-кампании по кнопке)
        if self._poll_commands():
            return True

        self._daily_and_rhythm_hooks()

        if not simclock.is_work_time():
            return self._handle_offhours()

        self._maybe_lunch()

        # редкая инъекция размеченной аномалии
        if getattr(config, "ATTACK_AUTO", False) and random.random() < config.ANOMALY_RATE:
            return self._run_anomaly()

        activity, kwargs = self._choose_activity_and_target()
        if activity == "__drain__":
            return self._drain_mrs()
        logger.info(f"[Scheduler] {simclock.stamp()} · итерация {self.iteration}: {activity}")
        self.stats[activity] = self.stats.get(activity, 0) + 1

        ok = self._dispatch(activity, **kwargs)
        self.stats["total_ok" if ok else "total_fail"] += 1
        if ok:
            logger.info(f"[Scheduler] OK {activity}")
        else:
            logger.warning(f"[Scheduler] FAIL {activity}")

        simclock.sleep(config.scenario_pause_seconds())
        return ok

    # ------------------------------------------------------------------
    def _drain_mrs(self) -> bool:
        """Разгрузка бэклога с ГАРАНТИЕЙ прогресса: снимаем Draft и мёржим; то,
        что смержить нельзя (конфликты/удалённая ветка/устойчивый 405), — закрываем,
        иначе планировщик навсегда застрянет в режиме разгрузки и не делает работу."""
        lead = self._lead()
        merged = closed = processed = 0
        LIMIT = 12
        for pid in set(config.WORK_REPOS.values()):
            for mr in self.gl.get_open_mrs(pid)[:8]:
                iid = mr.get("iid")
                if not iid:
                    continue
                processed += 1
                title = str(mr.get("title", "") or "").lower()
                if mr.get("draft") or mr.get("work_in_progress") or title.startswith(("draft:", "wip:")):
                    try:
                        self.gl.mark_mr_ready(pid, iid)
                    except Exception:
                        pass
                if lead.merge_mr(pid, iid):
                    merged += 1
                else:
                    try:
                        if self.gl.close_mr(pid, iid):
                            closed += 1
                    except Exception:
                        pass
                if merged + closed >= LIMIT:
                    break
            if merged + closed >= LIMIT:
                break
        logger.info(f"[Scheduler] разгрузка очереди: смержено {merged}, закрыто {closed} (просмотрено {processed})")
        simclock.sleep(config.scenario_pause_seconds())
        return (merged + closed) > 0

    def _run_anomaly(self, offhours=False) -> bool:
        # КТО и ЗАЧЕМ: назначаем персону-нарушителя (мотив, время, dwell, уклонение)
        import personas
        p = personas.assign(self.agents, offhours=offhours)
        # полноценная многошаговая кампания — с вероятностью CAMPAIGN_RATE (если у персоны она есть)
        if p.get("campaign") and random.random() < getattr(config, "CAMPAIGN_RATE", 0.0):
            return self._run_campaign(offhours=offhours, persona=p)
        # иначе одиночная аномалия (в т.ч. careless_dev — случайная утечка, НЕ атака по мотиву)
        from activities.anomaly import AnomalyActivity
        self.stats["anomaly"] = self.stats.get("anomaly", 0) + 1
        self.last_activity = "anomaly:" + p.get("kind", "?")
        self.last_activity_ts = simclock.stamp()
        actor = self.agents.get(p.get("actor")) if p.get("actor") else None
        ctx = {"evasion_profile": p.get("evasion", "noisy"),
               "persona": p.get("kind"), "motive": p.get("motive")}
        ok = AnomalyActivity(self.agents, self.state).run(
            anom_type=p.get("single_anomaly"), actor=actor, campaign=ctx)
        self.stats["total_ok" if ok else "total_fail"] += 1
        simclock.sleep(config.scenario_pause_seconds())
        return ok

    def _run_campaign(self, offhours=False, persona=None) -> bool:
        from red_team import RedTeamEngine
        self.stats["campaign"] = self.stats.get("campaign", 0) + 1
        self.last_activity = "red_campaign" + (":" + persona["kind"] if persona else "")
        self.last_activity_ts = simclock.stamp()
        eng = RedTeamEngine(self.agents, self.state)
        if persona:
            # персона задаёт актора, кампанию, уклонение и dwell time (low-and-slow)
            actor = self.agents.get(persona.get("actor")) if persona.get("actor") else None
            res = eng.run_campaign(key=persona.get("campaign"),
                                   evasion=persona.get("evasion", "noisy"),
                                   actor=actor, dwell_days=persona.get("dwell_days", 0),
                                   persona=persona.get("kind"), motive=persona.get("motive"))
        else:
            evasion = "stealthy" if offhours and random.random() < 0.5 else "noisy"
            res = eng.run_campaign(evasion=evasion)
        ok = bool(res and res.get("ok_steps"))
        self.stats["total_ok" if ok else "total_fail"] += 1
        simclock.sleep(config.scenario_pause_seconds())
        return ok

    def _poll_commands(self) -> bool:
        """Опрос очереди команд из event-store (управление из Purple-консоли)."""
        try:
            import eventstore
            if not eventstore.enabled():
                return False
            cmd = eventstore.claim_command()
        except Exception:
            return False
        if not cmd:
            return False
        ctype = cmd.get("type"); payload = cmd.get("payload") or {}
        try:
            if ctype == "campaign":
                from red_team import RedTeamEngine
                key = payload.get("key")
                evasion = payload.get("evasion", "noisy")
                tempo = payload.get("tempo", "fast")
                self.stats["campaign"] = self.stats.get("campaign", 0) + 1
                self.last_activity = "red_campaign(cmd)"
                res = RedTeamEngine(self.agents, self.state).run_campaign(
                    key=key, evasion=evasion, tempo=tempo)
                eventstore.set_command_result(cmd["id"],
                    f"{res.get('key')}: {res.get('ok_steps')}/{res.get('steps')} steps" if res else "failed")
                self.stats["total_ok"] += 1
                return True
            elif ctype == "anomaly":
                self._run_anomaly()
                eventstore.set_command_result(cmd["id"], "anomaly injected")
                return True
            elif ctype == "response":
                issue_iid = self._respond_incident(payload)
                if issue_iid:
                    ns = getattr(config, "PROJECT_NAMESPACE", "soc-team")
                    repo = getattr(self, "_last_ir_repo", None) or "playbooks"
                    url = f"{config.GITLAB_URL.rstrip('/')}/{ns}/{repo}/-/issues/{issue_iid}"
                    eventstore.set_command_result(cmd["id"], url)
                else:
                    from agents.base import GITLAB_STATUS
                    eventstore.set_command_result(cmd["id"],
                        "failed: " + (GITLAB_STATUS.get("last_error") or "issue не создан (проверь права/доступ lead)"))
                return True
        except Exception as e:
            logger.exception(f"command {ctype} failed: {e}")
        return False

    def _respond_incident(self, payload) -> bool:
        """Ответное действие защиты (sandbox): завести IR-issue по инциденту."""
        try:
            lead = self._lead()
            pid = config.playbook_repo_id()
            # путь репозитория, в котором реально заводим issue (для корректной ссылки)
            repo_path = None
            for _nm, _id in getattr(config, "WORK_REPOS", {}).items():
                if _id == pid:
                    repo_path = _nm
                    break
            if not repo_path:
                for _nm, _id in getattr(config, "PROJECTS", {}).items():
                    if _id == pid:
                        repo_path = _nm
                        break
            self._last_ir_repo = repo_path or "playbooks"
            actor = payload.get("actor", "?"); sev = payload.get("severity", "high")
            tactics = ", ".join(payload.get("tactics", []) or [])
            repos = ", ".join(payload.get("repos", []) or [])
            title = f"[IR] Инцидент по @{actor} ({sev})"
            body = ("## Автоматический инцидент (Purple Team)\n\n"
                    f"**Подозреваемый:** @{actor}\n**Severity:** {sev}\n"
                    f"**ATT&CK-цепочка:** {tactics}\n**Затронутые репозитории:** {repos}\n\n"
                    "### Рекомендованные действия\n"
                    "- [ ] Отозвать токены/секреты подозреваемого\n"
                    "- [ ] Заморозить ветки/доступ до разбора\n"
                    "- [ ] Проверить kill-chain, собрать таймлайн\n\n"
                    "_Заведено автоматически детектором по кнопке «Реагировать»._")
            iid = lead.create_issue(pid, title, body, labels=["type::incident", "auto::ir"])
            if iid:
                logger.warning(f"[RESPONSE] заведён IR-issue #{iid} в репо id={pid} по @{actor} (sev={sev})")
            else:
                from agents.base import GITLAB_STATUS
                logger.warning(f"[RESPONSE] НЕ удалось завести IR-issue (репо id={pid}): "
                               f"{GITLAB_STATUS.get('last_error') or 'нет ответа GitLab'}")
            return iid or 0
        except Exception as e:
            logger.exception(f"respond failed: {e}")
            return False

    # ------------------------------------------------------------------
    def _dispatch(self, activity: str, target=None, target_slug=None,
                  reason=None, forced_actor=None) -> bool:
        from activities.new_rule         import NewRuleActivity
        from activities.fix_rule         import FixRuleActivity
        from activities.revert_rule      import RevertRuleActivity
        from activities.update_parser    import UpdateParserActivity
        from activities.update_playbook  import UpdatePlaybookActivity
        from activities.tune_rule        import TuneThresholdActivity
        from activities.deprecate_rule   import DeprecateRuleActivity
        from activities.recreate_rule    import RecreateRuleActivity
        from activities.threat_intel     import ThreatIntelActivity
        from activities.dashboard        import DashboardActivity
        from activities.triage           import TriageFalsePositiveActivity
        from activities.incident         import IncidentActivity
        from activities.bulk_maintenance import BulkMaintenanceActivity
        from activities.issue_ops        import IssueActivity
        from activities.campaign         import CampaignActivity
        from activities.extra_ops        import CiVariableUpdate, DependencyBump, DocsWiki
        from activities.quirks           import BenignQuirk
        from activities.repo_scenarios   import (HuntQueryActivity, CloudDetectionActivity,
            SiemContentActivity, EdrRuleActivity, AutomationActivity, IrRunbookActivity)
        from activities.dev_workflows    import (IterativeReviewActivity,
            DependencyAuditActivity, SprintRetroActivity)
        from activities.ops_admin        import BENIGN_ADMIN

        lead   = self._lead()
        author = (self._agent_or_lead(forced_actor) if forced_actor
                  else self._pick_available_engineer())
        st = self.state

        self.last_activity    = activity
        self.last_actor       = getattr(author, "username", None)
        self.last_activity_ts = simclock.stamp()
        try:
            events.emit("activity", actor=getattr(author, 'username', None),
                        role=getattr(author, 'role', None), extra={"activity": activity, "meta": True})
        except Exception:
            logger.error("не удалось записать событие активности %s", activity, exc_info=True)

        try:
            if activity == "new_detection_rule":
                return NewRuleActivity(author, lead, state=st).run()
            elif activity == "fix_existing_rule":
                eng = self._anna() if random.random() < 0.15 else author
                return FixRuleActivity(eng, lead, state=st, target=target).run()
            elif activity == "revert_bad_rule":
                return RevertRuleActivity(author, lead, state=st,
                                          target_slug=target_slug, reason=reason).run()
            elif activity == "update_parser":
                eng = self._anna() if random.random() < 0.40 else author
                return UpdateParserActivity(eng, lead).run()
            elif activity == "update_playbook":
                eng = lead if random.random() < 0.30 else author
                return UpdatePlaybookActivity(eng, lead).run()
            elif activity == "refactor_rule":
                return FixRuleActivity(author, lead, state=st, target=target).run()
            elif activity == "add_test_sample":
                return self._add_test_sample(author, lead)
            elif activity == "tune_threshold":
                return TuneThresholdActivity(author, lead, state=st, target=target).run()
            elif activity == "deprecate_rule":
                eng = lead if random.random() < 0.4 else author
                return DeprecateRuleActivity(eng, lead, state=st, target=target).run()
            elif activity == "recreate_fixed_rule":
                return RecreateRuleActivity(author, lead, state=st).run()
            elif activity == "threat_intel_update":
                eng = self._anna() if random.random() < 0.5 else author
                return ThreatIntelActivity(eng, lead).run()
            elif activity == "update_dashboard":
                eng = lead if random.random() < 0.5 else author
                return DashboardActivity(eng, lead).run()
            elif activity == "triage_false_positive":
                return TriageFalsePositiveActivity(author, lead).run()
            elif activity == "handle_incident":
                actor = (self._agent_or_lead(self.state.current_oncall())
                         if self.state else author)
                return IncidentActivity(actor, lead).run()
            elif activity == "bulk_maintenance":
                eng = self._anna() if random.random() < 0.5 else lead
                return BulkMaintenanceActivity(eng, lead).run()
            elif activity == "open_issue":
                return IssueActivity(author, lead, state=st).run()
            elif activity == "campaign":
                return CampaignActivity(self.agents, lead, state=st).run()
            elif activity == "ci_variable_update":
                return CiVariableUpdate(author, lead).run()
            elif activity == "dependency_bump":
                eng = self._anna() if random.random() < 0.4 else author
                return DependencyBump(eng, lead).run()
            elif activity == "docs_wiki":
                eng = lead if random.random() < 0.25 else author
                return DocsWiki(eng, lead).run()
            elif activity == "iterative_review":
                return IterativeReviewActivity(author, lead).run()
            elif activity == "dependency_audit":
                eng = self._pick_role("devops", "detection_engineer") or author
                return DependencyAuditActivity(eng, lead).run()
            elif activity == "sprint_retro":
                return SprintRetroActivity(self.agents, lead, state=st).run()
            elif activity == "hunt_query":
                eng = self._pick_role("threat_hunter") or author
                return HuntQueryActivity(eng, lead).run()
            elif activity == "cloud_detection":
                return CloudDetectionActivity(author, lead).run()
            elif activity == "siem_content":
                eng = self._pick_role("detection_engineer", "soc_analyst") or author
                return SiemContentActivity(eng, lead).run()
            elif activity == "edr_rule":
                eng = self._pick_role("detection_engineer", "devops") or author
                return EdrRuleActivity(eng, lead).run()
            elif activity == "automation_script":
                eng = self._pick_role("devops") or author
                return AutomationActivity(eng, lead).run()
            elif activity == "ir_runbook":
                eng = self._pick_role("soc_analyst") or (lead if random.random()<0.4 else author)
                return IrRunbookActivity(eng, lead).run()
            elif activity == "benign_quirk":
                return BenignQuirk(author, lead, state=st).run()
            elif activity in BENIGN_ADMIN:
                # Штатная админ-работа (токены, ключи, вебхуки, расписания,
                # права, force-push). Нужна, чтобы эти действия не были
                # эксклюзивом атакующего — иначе имя действия = метка.
                return BENIGN_ADMIN[activity](author, lead, state=st).run()
            else:
                logger.warning(f"Unknown activity: {activity}")
                return False
        except Exception as e:
            logger.exception(f"Activity {activity} raised: {e}")
            return False

    def _pick_available_engineer(self):
        out = self.state.who_is_out_today() if self.state else None
        engs = [a for a in self._engineers() if a.username != out]
        return random.choice(engs or self._engineers())

    # ------------------------------------------------------------------
    def _add_test_sample(self, author, lead) -> bool:
        from content import rules as rc
        import json
        pid   = config.rule_repo_id()
        files = author.gl.list_files(pid, "rules")
        ymls  = [f for f in files if f.endswith(".yml")]
        if not ymls:
            return False
        target = random.choice(ymls)
        slug   = target.split("/")[-1].replace(".yml", "")
        branch = author.unique_branch(f"test/{slug[:20]}")
        if not author.create_branch(pid, branch):
            return False
        author.think()
        negative_sample = json.dumps({
            "EventID": "4688", "Computer": "WORKSTATION-BENIGN",
            "SubjectUserName": "SYSTEM$",
            "NewProcessName": "C:\\Windows\\System32\\svchost.exe",
            "CommandLine": "svchost.exe -k netsvcs",
            "ParentProcessName": "C:\\Windows\\System32\\services.exe",
            "expected_match": False, "rule": slug,
            "note": "Negative test: system process, should NOT trigger",
        }, indent=2)
        sample_path = f"tests/samples/{slug}_negative.json"
        if not author.push_file(pid, sample_path, negative_sample,
                                f"test({slug}): add negative sample", branch):
            return False
        author.commit_pause()
        mr_iid = author.create_mr(
            pid, branch, f"test({slug}): add negative test sample",
            f"Негативный семпл для `{slug}`.", lead.user_id)
        if not mr_iid:
            return False
        from activities import flow
        return flow.approve_and_merge(lead, author, pid, mr_iid, branch=branch,
                                      approve_comment="Негативные тесты важны. Approve.")

    # ------------------------------------------------------------------
    def print_stats(self):
        logger.info("=" * 50)
        logger.info("СТАТИСТИКА СИМУЛЯТОРА")
        logger.info(f"  Sim-время финала:   {simclock.stamp()}")
        logger.info(f"  Итераций всего:     {self.stats['total_runs']}")
        logger.info(f"  Успешных:           {self.stats['total_ok']}")
        logger.info(f"  С ошибками:         {self.stats['total_fail']}")
        logger.info(f"  Пропущено off-hours:{self.stats['skipped_offhours']}")
        if self.state:
            logger.info(f"  Правил в стейте:    {self.state.rule_count()}")
            logger.info(f"  Спринт:             #{self.state.data['sprint_number']}")
        logger.info("  По активностям:")
        for k, v in sorted(self.stats.items(), key=lambda kv: -kv[1]):
            if k in ("total_runs", "total_ok", "total_fail", "skipped_offhours"):
                continue
            if v:
                logger.info(f"    {k:24} {v}")
        logger.info("=" * 50)
