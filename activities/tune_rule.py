"""
Активность: тюнинг существующего правила.
Инженер калибрует пороги/таймфреймы по результатам наблюдений за FP-рейтом.
"""
import re
import random
import logging
import config
from config import PROJECTS, USERS, DELAYS
from content import commit_messages as cm, comments
from activities import flow

logger = logging.getLogger(__name__)


class TuneThresholdActivity:
    """Подкрутка порогов/окон агрегации в правиле для снижения шума."""

    def __init__(self, author_agent, lead_agent, state=None, target=None):
        self.author = author_agent
        self.lead   = lead_agent
        self.state  = state
        self.target = target     # путь к правилу из стейта (приоритетно)
        self.pid    = config.populated_rule_repo(author_agent.gl)

    def run(self) -> bool:
        all_files  = self.author.gl.list_files(self.pid, "rules")
        rule_files = [f for f in all_files if f.endswith(".yml")]
        if not rule_files:
            self.author.log("No rules to tune, skipping")
            return False

        # Приоритет — «шумное» правило из стейта, если оно реально есть в репо
        if self.target and self.target in rule_files:
            target = self.target
        else:
            target = random.choice(rule_files)
        slug    = target.split("/")[-1].replace(".yml", "")
        content = self.author.gl.get_file(self.pid, target)
        if not content:
            return False

        branch = self.author.unique_branch(f"tune/{slug[:20]}")
        self.author.log(f"Tuning rule: {slug}")

        if not self.author.create_branch(self.pid, branch):
            return False
        self.author.think()

        new_content, what = self._retune(content)
        msg = cm.tune_message(slug, what)
        if not self.author.push_file(self.pid, target, new_content, msg, branch):
            return False
        self.author.commit_pause()

        lead_id = USERS["alex.petrov"]["id"]
        mr_iid  = self.author.create_mr(
            self.pid, branch,
            f"tune({slug}): recalibrate after FP review",
            self._mr_desc(slug, what),
            lead_id,
        )
        if not mr_iid:
            return False

        self.author.think(3)
        self.author.comment_mr(self.pid, mr_iid, comments.tuning_comment())
        self.lead.think(DELAYS["review_wait"])
        ok = flow.approve_and_merge(
            self.lead, self.author, self.pid, mr_iid, branch=branch,
            approve_comment=comments.tuning_review(), emoji="thumbsup",
        )
        if ok and self.state and self.state.get_rule(slug):
            r = self.state.get_rule(slug)
            self.state.update_rule(
                slug, noisy=False,
                fp_rate=max(0, r.get("fp_rate", 10) - random.randint(8, 20)),
                tunes=r.get("tunes", 0) + 1,
            )
        return ok

    def _retune(self, content: str):
        """Меняет числовые пороги/таймфреймы; возвращает (контент, что_сделано)."""
        what = random.choice([
            "threshold raised", "timeframe widened", "baseline allowlist",
        ])
        lines = content.split("\n")
        out   = []
        changed = False
        for line in lines:
            # count() > N  -> увеличиваем
            m = re.search(r"count\(\)\s*>\s*(\d+)", line)
            if m and not changed:
                old = int(m.group(1))
                new = old + random.choice([5, 10, 15, 20])
                line = line.replace(f"count() > {old}", f"count() > {new}")
                changed = True
            # |gt: N
            m2 = re.search(r"\|gt:\s*(\d+)", line)
            if m2 and not changed:
                old = int(m2.group(1))
                new = old + random.choice([10, 20, 50])
                line = re.sub(r"(\|gt:\s*)\d+", rf"\g<1>{new}", line)
                changed = True
            # timeframe: Xm
            m3 = re.search(r"timeframe:\s*(\d+)m", line)
            if m3 and not changed:
                old = int(m3.group(1))
                new = old + random.choice([2, 5, 10])
                line = re.sub(r"(timeframe:\s*)\d+m", rf"\g<1>{new}m", line)
                changed = True
            out.append(line)

        from datetime import date
        # Обновляем/добавляем modified и комментарий тюнинга
        result = []
        added_mod = "modified:" in content
        for line in out:
            if line.startswith("modified:"):
                result.append(f"modified: {date.today().isoformat()}")
                continue
            if line.startswith("date:") and not added_mod:
                result.append(line)
                result.append(f"modified: {date.today().isoformat()}")
                added_mod = True
                continue
            result.append(line)
        result.append(f"# tuned {date.today().isoformat()}: {what} after FP review")
        return "\n".join(result), what

    def _mr_desc(self, slug: str, what: str) -> str:
        return f"""## Тюнинг правила `{slug}`

**Что изменено:** {what}

### Обоснование
По наблюдениям за последнюю неделю правило давало повышенный FP-рейт.
Калибровка снижает шум, сохраняя истинные срабатывания.

### Метрики (до → после, ожидаемо)
- FP/день: высокий → приемлемый
- TP: без изменений

- [ ] Проверено на исторических данных
- [ ] Обновлён дашборд тюнинга
"""
