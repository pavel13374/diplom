"""
Общий слой «потока работы» поверх MR: имитация CI-пайплайнов, настоящие
approvals, эмодзи-реакции, Draft→Ready, брошенные MR. Переиспользуется
всеми активностями, чтобы код-ревью выглядел как живой процесс.
"""
import random
import logging
import config
import simclock

logger = logging.getLogger(__name__)

# Глобальный реестр агентов (ставится из main/scheduler), чтобы получить soc-bot.
_AGENTS = {}


def set_agents(agents: dict):
    global _AGENTS
    _AGENTS = agents


def _bot():
    return _AGENTS.get("soc-bot")


# -----------------------------------------------------------------------
CI_FAIL_REASONS = [
    "sigma-lint: invalid YAML indentation",
    "rule-tests: negative sample triggered the rule",
    "sigma check: duplicate rule id detected",
    "rule-tests: 1 of 3 samples failed to match",
    "ecs-validate: unknown field in detection block",
    "pipeline timeout on large rule set",
]

AUTHOR_CI_FIX = [
    "Поправил отступы в YAML, перезапустил пайплайн.",
    "Перегенерил UUID — был конфликт. CI перезапущен.",
    "Исправил негативный семпл, теперь не триггерит. Жду зелёный.",
    "Привёл поле к ECS, пуш фикса сделал.",
    "Увеличил таймаут джобы, ретрай пайплайна.",
]


def run_ci(pid: int, mr_iid: int, branch: str, author) -> bool:
    """Имитирует пайплайн. С вероятностью PROBS['ci_fail'] — красный билд,
    автор пушит fixup, затем зелёный. Возвращает True если в итоге green."""
    bot = _bot()
    if not config.FEATURES.get("ci_pipeline") or not bot:
        return True

    pipeline_id = random.randint(1000, 9999)
    if random.random() < config.PROBS.get("ci_fail", 0.0):
        reason = random.choice(CI_FAIL_REASONS)
        bot.comment_mr(pid, mr_iid,
                       f"🔴 **Pipeline #{pipeline_id} failed**\n\n`{reason}`\n\n"
                       f"Джоба `validate` упала. Требуется фикс.")
        author.think(config.DELAYS["agent_think"])
        # автор пушит fixup-коммит в ветку
        author.push_file(
            pid, ".ci/pipeline-status.txt",
            f"fixup for pipeline #{pipeline_id}\n{simclock.now().isoformat()}\n",
            "ci: fixup after failed pipeline", branch,
        )
        author.comment_mr(pid, mr_iid, random.choice(AUTHOR_CI_FIX))
        author.commit_pause()
        new_pipeline = random.randint(1000, 9999)
        bot.comment_mr(pid, mr_iid,
                       f"✅ **Pipeline #{new_pipeline} passed** — все джобы зелёные.")
        return True
    else:
        bot.comment_mr(pid, mr_iid,
                       f"✅ **Pipeline #{pipeline_id} passed** "
                       f"(sigma-lint, rule-tests, ecs-validate).")
        return True


def maybe_draft_first(author, pid: int, mr_iid: int, title: str):
    """С вероятностью делает MR черновиком, потом помечает Ready."""
    if not config.FEATURES.get("draft_mrs"):
        return
    if random.random() < config.PROBS.get("mr_draft_first", 0.0):
        author.set_mr_title(pid, mr_iid, f"Draft: {title}")
        author.think(config.DELAYS["agent_think"])
        author.set_mr_title(pid, mr_iid, title)
        logger.info(f"[{author.username}] MR !{mr_iid}: Draft → Ready")


def maybe_abandon(author, lead, pid: int, mr_iid: int) -> bool:
    """С вероятностью MR закрывают без мёржа (передумали/дубль/неактуально)."""
    if random.random() < config.PROBS.get("mr_abandoned", 0.0):
        reason = random.choice([
            "Закрываю — дубль уже существующего правила, нашёл при поиске.",
            "Откладываю: нужно собрать больше данных с prod прежде чем катить.",
            "Закрываю, договорились реализовать иначе в рамках спринта.",
            "Не актуально — техника уже покрыта другим набором правил.",
        ])
        author.comment_mr(pid, mr_iid, reason)
        author.close_mr(pid, mr_iid)
        return True
    return False


def approve_and_merge(lead, author, pid: int, mr_iid: int, branch: str = "",
                      approve_comment: str = "LGTM. Merge.",
                      emoji: str = "thumbsup") -> bool:
    """Финализация MR: CI → эмодзи → настоящий approve → merge."""
    if branch:
        run_ci(pid, mr_iid, branch, author)

    lead.react(pid, mr_iid, emoji)
    if config.FEATURES.get("approvals"):
        lead.approve_mr(pid, mr_iid)
    lead.comment_mr(pid, mr_iid, approve_comment)
    lead.think(config.DELAYS["merge_wait"])
    return lead.merge_mr(pid, mr_iid)
