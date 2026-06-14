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
    def run(self, anom_type=None):
        anom_type = anom_type or self._pick()
        if not anom_type:
            return False
        fn = getattr(self, "_a_" + anom_type, None)
        if not fn:
            return False
        actor = self._actor()
        ok = False
        with events.tag(anomaly_type=anom_type, severity=SEVERITY.get(anom_type, "medium")):
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

    # === СЕКРЕТЫ =======================================================
    def _a_secret_in_commit(self, actor):
        name, pid = self._repo(random.choice(["detection-rules", "normalization-rules", "soc-infra"]))
        stype, content = sb.secret_env_file()
        branch = actor.unique_branch("chore/config")
        if not actor.create_branch(pid, branch):
            return False
        actor.think(2)
        path = random.choice(["config/prod.env", "deploy/.env", "config/settings_prod.py",
                              "infra/secrets.env"])
        with events.tag(secret_type=stype, repo=name):
            ok = actor.push_file(pid, path, content,
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
        with events.tag(secret_type=secret["type"], repo=name):
            return actor.push_file(pid, ".gitlab-ci.yml", ci,
                                   "ci: add prod deploy job", branch)

    def _a_secret_in_mr_comment(self, actor):
        name, pid = self._repo()
        branch = actor.unique_branch("fix/typo")
        if not actor.create_branch(pid, branch):
            return False
        actor.push_file(pid, f"docs/note_{branch[-5:]}.md", "minor doc fix\n",
                        "docs: fix typo", branch)
        iid = actor.create_mr(pid, branch, "docs: fix typo", "Мелкая правка.",
                              USERS["alex.petrov"]["id"])
        if not iid:
            return False
        secret = sb.random_secret()
        body = ("Чтобы проверить деплой, вот креды от прод-стейджа, не теряй:\n\n```\n"
                + "\n".join(secret["lines"]) + "\n```")
        with events.tag(secret_type=secret["type"], repo=name):
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
        with events.tag(secret_type="vault_export", repo=name):
            return actor.push_file(pid, "backup/prod_secrets_backup.env", content,
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
        with events.tag(secret_type=secret["type"], repo=name):
            return actor.push_file(pid, "scripts/push_metrics.py", code,
                                   "feat: metrics push helper", branch)

    # === ПРАВА / ОБХОД РЕВЬЮ ===========================================
    def _a_self_approval_merge(self, actor):
        name, pid = self._repo()
        branch = actor.unique_branch("feat/self")
        if not actor.create_branch(pid, branch):
            return False
        actor.push_file(pid, f"docs/change_{branch[-5:]}.md", "self-approved change\n",
                        "feat: small change", branch)
        iid = actor.create_mr(pid, branch, "feat: small change", "Без ревью, сам аппрувлю.",
                              actor.user_id)
        if not iid:
            return False
        actor.approve_mr(pid, iid)
        return actor.merge_mr(pid, iid)

    def _a_merge_without_review(self, actor):
        name, pid = self._repo()
        branch = actor.unique_branch("feat/fast")
        if not actor.create_branch(pid, branch):
            return False
        actor.push_file(pid, f"docs/fast_{branch[-5:]}.md", "merged without review\n",
                        "feat: quick change", branch)
        iid = actor.create_mr(pid, branch, "feat: quick change", "Мержу без ревью, срочно.",
                              USERS["alex.petrov"]["id"])
        if not iid:
            return False
        return actor.merge_mr(pid, iid)

    def _a_direct_push_protected(self, actor):
        name, pid = self._repo()
        path = f"hotpatch/{datetime.now().strftime('%H%M%S')}.txt"
        with events.tag(repo=name, target="main"):
            ok = actor.push_file(pid, path, "direct hotpatch to main, bypassing MR\n",
                                 "hotfix: direct patch to main", "main")
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
        with events.tag(target="main", repo="soc-infra"):
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
        with events.tag(repo="soc-infra", grantee=grantee, target="soc-secrets"):
            return actor.push_file(pid, "policy/soc-secrets-members.yml", members,
                                   "chore: update soc-secrets access list", branch)

    def _a_rogue_token(self, actor):
        target = random.choice(["maria.ivanova", "dmitry.kozlov", "anna.smirnova"])
        ok = actor.gl.create_named_token(USERS[target]["id"],
                                         name="ci-temp-" + datetime.now().strftime("%H%M%S"),
                                         scopes=["api"])
        events.emit("token_create", actor=actor.username, role=actor.role,
                    target=target, message="created additional API token",
                    extra={"token_scope": "api", "for_user": target})
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
                    extra={"deleted_count": len(victims)})
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
        with events.tag(secret_type="ci_token", repo=name,
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
        with events.tag(repo=name, detail="disabled SAST/secret-detection in CI"):
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
        with events.tag(secret_type=secret["type"], repo=name,
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
            with events.tag(secret_type=stype, repo="soc-secrets", target="main",
                            detail="direct write of new secret to vault repo"):
                return actor.push_file(pid, f"vault/{branch[-5:]}.env", content,
                                       "add: new service credentials", "main")
        actor.think(2)
        with events.tag(secret_type=stype, repo="soc-secrets",
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
        with events.tag(repo=name, secret_type="data_blob",
                        detail="large encoded archive committed (possible exfiltration)"):
            return actor.push_file(pid, "export/dump_b64.txt", content,
                                   "chore: nightly data export", branch)
