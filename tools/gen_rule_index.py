# -*- coding: utf-8 -*-
"""Генерация detections/_index.md — читаемого каталога правил."""
import sys
import json
import glob
import collections

sys.path.insert(0, ".")
from attack_matrix import ATTACK, all_techniques

rules = [json.load(open(f, encoding="utf-8")) for f in sorted(glob.glob("detections/*.json"))]
by_tech = collections.defaultdict(list)
for r in rules:
    by_tech[r.get("technique")].append(r)
matrix = all_techniques()

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEV_RU = {"critical": "критич.", "high": "высок.", "medium": "средн.", "low": "низк."}

out = []
w = out.append
w("# Каталог правил детектирования\n")
w("> Файл создаётся скриптом `tools/gen_rule_index.py` — правьте правила в")
w("> `detections/*.json`, а не здесь.\n")
w(f"Правил: **{len(rules)}**. Покрыто техник модели угроз: "
  f"**{len({r.get('technique') for r in rules} & matrix)}/{len(matrix)}**.\n")
w("Правило описывается декларативно и подхватывается без перезапуска логики.")
w("Условия опираются только на **наблюдаемые атрибуты** события — то, что видно")
w("в аудит-логе GitLab. Правил вида «действие == название атаки» в каталоге нет")
w("и быть не может: это проверяет `tools/lint_rules.py`.\n")
w("---\n")

for tactic, techs in ATTACK:
    tech_ids = [t for t, _ in techs]
    present = [t for t in tech_ids if by_tech.get(t)]
    blind = [t for t in tech_ids if not by_tech.get(t)]
    if not present and not blind:
        continue
    w(f"## {tactic}\n")
    for tid, tname in techs:
        rs = by_tech.get(tid, [])
        if not rs:
            w(f"### ⬜ {tid} — {tname}\n")
            w("Слепая зона: правила пока нет. Это очередь работ detection")
            w("engineering, а не пробел в модели угроз.\n")
            continue
        for r in sorted(rs, key=lambda x: SEV_ORDER.get(x.get("severity"), 9)):
            w(f"### ✅ {tid} — {tname}\n")
            w(f"**{r['title']}**  ")
            w(f"`{r['id']}` · риск {r['risk']} · {SEV_RU.get(r.get('severity'), r.get('severity'))}\n")
            if r.get("rationale"):
                w(r["rationale"] + "\n")
            w("Условие срабатывания:\n")
            w("```json")
            w(json.dumps(r["when"], ensure_ascii=False, indent=2))
            w("```\n")
    w("")

w("---\n")
w("## Слепые зоны\n")
covered = {r.get("technique") for r in rules} & matrix
blind = sorted(matrix - covered)
w(f"Техник в модели угроз без правила: **{len(blind)}**.\n")
w("| Техника | Почему пока не покрыта |")
w("|---|---|")
WHY = {
 "T1030": "лимиты размера передачи не видны в событиях git/CI",
 "T1071.001": "прикладной сетевой уровень вне контура GitLab-аудита",
 "T1074": "промежуточное складирование данных наблюдаемо только на хосте",
 "T1078.004": "облачные учётные записи живут вне GitLab",
 "T1080": "заражение общего содержимого требует данных файловой системы",
 "T1199": "доверенные отношения видны на уровне интеграций, не в аудите репо",
 "T1505": "серверные компоненты — уровень хоста",
 "T1518": "инвентаризация ПО не отражается в событиях репозитория",
 "T1526": "перечисление облачных сервисов идёт мимо GitLab API",
 "T1550.001": "использование украденного токена неотличимо от легитимного вызова",
 "T1555": "хранилища паролей вне периметра",
 "T1565.001": "манипуляция данными в покое — уровень БД, не репозитория",
 "T1613": "инвентаризация контейнеров — уровень оркестратора",
}
for t in blind:
    name = next((n for _, lst in ATTACK for tt, n in lst if tt == t), "")
    w(f"| `{t}` {name} | {WHY.get(t, 'не покрыта')} |")
w("")
w("Эти техники намеренно оставлены в матрице: если бы в знаменатель попали")
w("только те, под которые уже написаны правила, покрытие всегда равнялось бы")
w("100%, и метрика измеряла бы сама себя.\n")

open("detections/_index.md", "w", encoding="utf-8").write("\n".join(out))
print("строк:", len(out), "| правил:", len(rules), "| слепых зон:", len(blind))
