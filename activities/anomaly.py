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
        if name:
            return name, (config.WORK_REPOS.get(name) or PROJECTS.get(name))
        pool = [n for n in config.WORK_REPOS if n != "soc-secrets"] or NORMAL_REPOS
        n = random.choice(pool)
        return n, config.WORK_REPOS.get(n, PROJECTS.get(n))

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
        """Перебор репозиториев и листинг секрет-путей (Reconnaissance)."""
        targets = random.sample(
            ["detection-rules", "soc-secrets", "soc-infra", "playbooks", "normalization-rules"],
            k=min(3, 5))
        with events.tag(is_decisive=True, detail="enumerated repos and secret paths"):
            events.emit("repo_enum", actor=actor.username, role=actor.role,
                        project="soc-infra", target=",".join(targets),
                        message="listed repositories and secret-bearing paths")
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
            lead = self.agents["alex.petrov"]
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
        path = _p
        with events.tag(is_decisive=True, repo=name, target="main"):
            ok = actor.push_file(pid, _p, _c, _m, "main")
        if not ok:
            # ветка main защищена — фиксируем сам факт попытки
            events.emit("anomaly_attempt", actor=actor.username, role=actor.role,
                        project=name, target="main",
                        message="attempted direct push to protected main (blocked)")
        return ok

    def _a_weaken_protection(self, actor):
        pid = PROJECTS["soc-infra"]
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
        pid = PROJECTS["soc-infra"]
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
        target = random.choice(["maria.ivanova", "dmitry.kozlov", "anna.smirnova"])
        ok = actor.gl.create_named_token(USERS[target]["id"],
                                         name="ci-temp-" + datetime.now().strftime("%H%M%S"),
                                         scopes=["api"])
        events.emit("token_create", actor=actor.username, role=actor.role,
                    target=target, message="created additional API token",
                    extra={"token_scope": "api", "for_user": target, "is_decisive": True})
        return ok

    # === РАЗРУШИТЕЛЬНЫЕ ================================================
    def _a_mass_deletion(self, actor):
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
        events.emit("mass_delete", actor=actor.username, role=actor.role, project=name,
                    branch=branch, message=f"deleted {len(victims)} files",
                    extra={"deleted_count": len(victims), "is_decisive": True})
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
        pid = PROJECTS["soc-secrets"]
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

    # === НОВЫЕ ПРИМИТИВЫ: расширяют покрытие ATT&CK ====================
    # Каждый эмитит СВОЁ действие, под которое есть отдельное правило.
    # Действия синтетические (как repo_enum) — это шаг атаки в журнале,
    # а не изменение в GitLab; детектор ловит их по наблюдаемому действию.

    def _a_scheduled_ci_job(self, actor):
        """Плановое задание CI, запускающее полезную нагрузку атакующего.
        MITRE T1053 Scheduled Task/Job (Execution)."""
        name, _ = self._repo()
        with events.tag(is_decisive=True, repo=name,
                        detail="attacker-controlled scheduled pipeline added"):
            events.emit("ci_schedule", actor=actor.username, role=actor.role,
                        project=name, path=".gitlab-ci.yml", branch="main",
                        message="ci: add nightly scheduled pipeline",
                        target="schedule:0 3 * * *")
        return True

    def _a_container_creds(self, actor):
        """Секрет доступа к контейнерному реестру/кластеру в манифесте.
        MITRE T1552.007 Container API Credentials (Credential Access)."""
        name, _ = self._repo()
        with events.tag(is_decisive=True, repo=name, secret_type="container_creds",
                        detail="registry/cluster credentials in a k8s manifest"):
            events.emit("container_creds", actor=actor.username, role=actor.role,
                        project=name, path="deploy/k8s/registry-secret.yaml", branch="main",
                        message="deploy: add imagePullSecret for prod registry")
        return True

    def _a_inhibit_recovery(self, actor):
        """Удаление резервных веток/тегов и истории — мешает восстановлению.
        MITRE T1490 Inhibit System Recovery (Impact)."""
        name, _ = self._repo()
        with events.tag(is_decisive=True, repo=name,
                        detail="backup branches and tags deleted"):
            events.emit("inhibit_recovery", actor=actor.username, role=actor.role,
                        project=name, path="refs/backup/*", branch="backup",
                        message="chore: prune old backup refs",
                        target="deleted backup/* and release tags")
        return True

    def _a_add_deploy_key(self, actor):
        """Добавлен внешний SSH deploy-ключ для доступа к репозиториям.
        MITRE T1021.004 Remote Services: SSH (Lateral Movement)."""
        name, _ = self._repo()
        with events.tag(is_decisive=True, repo=name, secret_type="ssh_key",
                        detail="external SSH deploy key added to repo"):
            events.emit("deploy_key_add", actor=actor.username, role=actor.role,
                        project=name, path="settings/deploy_keys", branch="main",
                        message="ci: add deploy key for build runner",
                        target="ssh-ed25519 AAAAC3Nz... build@ext")
        return True

    def _a_code_search(self, actor):
        """Поиск по коду в поисках секретов. MITRE T1593.003 (Reconnaissance)."""
        name, _ = self._repo()
        with events.tag(is_decisive=True, repo=name, detail="searched code for secret patterns"):
            events.emit("code_search", actor=actor.username, role=actor.role,
                        project=name, path="search", branch="main",
                        message="grep across repos for tokens/keys", target="secret patterns")
        return True
    def _a_dep_poison(self, actor):
        """Подмена зависимости (supply-chain). MITRE T1195.001 (Initial Access)."""
        name, _ = self._repo()
        with events.tag(is_decisive=True, repo=name, detail="malicious dependency pinned"):
            events.emit("dep_poison", actor=actor.username, role=actor.role,
                        project=name, path="requirements.txt", branch="main",
                        message="chore: bump internal-utils to 9.9.9", target="internal-utils==9.9.9 (typo-squat)")
        return True
    def _a_deploy_tool_abuse(self, actor):
        """Злоупотребление средством развёртывания. MITRE T1072 (Execution)."""
        name, _ = self._repo()
        with events.tag(is_decisive=True, repo=name, detail="deployment tool used to run attacker task"):
            events.emit("deploy_tool_abuse", actor=actor.username, role=actor.role,
                        project=name, path="deploy/ansible/site.yml", branch="main",
                        message="deploy: run one-off provisioning play", target="runs attacker task on all hosts")
        return True
    def _a_cloud_account_create(self, actor):
        """Создан облачный служебный аккаунт. MITRE T1136.003 (Persistence)."""
        name, _ = self._repo()
        with events.tag(is_decisive=True, repo=name, detail="extra cloud service account provisioned"):
            events.emit("cloud_account_create", actor=actor.username, role=actor.role,
                        project=name, path="iam/service-accounts.tf", branch="main",
                        message="iam: add ci-runner service account", target="svc-attacker with broad scopes")
        return True
    def _a_elevate_privs(self, actor):
        """Повышение прав через обход контроля. MITRE T1548 (Privilege Escalation)."""
        name, _ = self._repo()
        with events.tag(is_decisive=True, repo=name, detail="elevation control bypassed"):
            events.emit("elevate_privs", actor=actor.username, role=actor.role,
                        project=name, path="ci/sudoers.d/runner", branch="main",
                        message="ci: allow runner NOPASSWD sudo", target="runner ALL=(ALL) NOPASSWD:ALL")
        return True
    def _a_history_rewrite(self, actor):
        """Переписывание истории и удаление следов. MITRE T1070.004 (Defense Evasion)."""
        name, _ = self._repo()
        with events.tag(is_decisive=True, repo=name, detail="history rewritten to remove indicators"):
            events.emit("history_rewrite", actor=actor.username, role=actor.role,
                        project=name, path="main", branch="main",
                        message="force-push rewriting history", target="git push --force after filter-branch")
        return True
    def _a_obfuscated_payload(self, actor):
        """Обфусцированный код в коммите. MITRE T1027 (Defense Evasion)."""
        name, _ = self._repo()
        with events.tag(is_decisive=True, repo=name, detail="obfuscated payload committed"):
            events.emit("obfuscated_payload", actor=actor.username, role=actor.role,
                        project=name, path="scripts/util.min.js", branch="main",
                        message="chore: minify helper", target="base64/eval-packed payload")
        return True
    def _a_steal_oauth(self, actor):
        """Кража OAuth/приложенческого токена. MITRE T1528 (Credential Access)."""
        name, _ = self._repo()
        with events.tag(is_decisive=True, repo=name, detail="application OAuth token captured"):
            events.emit("steal_oauth", actor=actor.username, role=actor.role,
                        project=name, path="ci/oauth_dump.log", branch="main",
                        message="ci: capture pipeline OAuth token", target="PIPELINE OAuth token exfiltrated")
        return True
    def _a_perm_discovery(self, actor):
        """Перечисление прав и групп доступа. MITRE T1069 (Discovery)."""
        name, _ = self._repo()
        with events.tag(is_decisive=True, repo=name, detail="permission groups enumerated"):
            events.emit("perm_discovery", actor=actor.username, role=actor.role,
                        project=name, path="audit/members.txt", branch="main",
                        message="list project members and roles", target="who has Maintainer/Owner")
        return True
    def _a_automated_collection(self, actor):
        """Автоматический сбор данных из репозиториев. MITRE T1119 (Collection)."""
        name, _ = self._repo()
        with events.tag(is_decisive=True, repo=name, detail="automated harvester over repositories"):
            events.emit("automated_collection", actor=actor.username, role=actor.role,
                        project=name, path="collect/harvest.sh", branch="main",
                        message="chore: nightly repo harvester", target="clones all repos and greps secrets")
        return True
    def _a_webhook_c2(self, actor):
        """Управление через внешний веб-сервис. MITRE T1102 (Command and Control)."""
        name, _ = self._repo()
        with events.tag(is_decisive=True, repo=name, detail="outbound webhook to external service"):
            events.emit("webhook_c2", actor=actor.username, role=actor.role,
                        project=name, path="settings/webhooks", branch="main",
                        message="add webhook to external host", target="POST to https://attacker.example/hook")
        return True
    def _a_exfil_altproto(self, actor):
        """Вынос по альтернативному протоколу. MITRE T1048 (Exfiltration)."""
        name, _ = self._repo()
        with events.tag(is_decisive=True, repo=name, detail="data pushed over scp/dns to external host"):
            events.emit("exfil_altproto", actor=actor.username, role=actor.role,
                        project=name, path="ci/upload.sh", branch="main",
                        message="ci: sync artifacts to remote", target="scp artifacts to attacker host")
        return True
