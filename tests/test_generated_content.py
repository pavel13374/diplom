#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ТЕСТ СОДЕРЖИМОГО, КОТОРОЕ УХОДИТ В GITLAB.

Зачем этот файл появился
------------------------
Вся остальная батарея тестов была ЗЕЛЁНОЙ в тот момент, когда в репозитории
GitLab заливались файлы такого вида:

    # Playbook: {pb['title']}
    **Severity:** {severity}
    **Author:** {self.author.name}

Причина — потерянный префикс `f` у 14 шаблонов в activities/*, agents/lead.py и
content/rules.py: строки перестали быть f-строками и уходили в коммит как есть.
Одновременно исчезли присваивания (`severity = random.choice(...)` превратилось
в голый вызов), поэтому даже возврат префикса без восстановления переменных дал
бы NameError. Похоже на след автоматической «чистки неиспользуемого кода».

Ни один тест этого не увидел, потому что все они проверяли ДВИЖОК (детектор,
метрики, маршруты) и ни один — ПРОДУКТ (то, что команда «пишет» в репозитории).
А продукт здесь и есть предмет работы: без него стенд генерирует мусор.

Что проверяется
---------------
  1. Ни один генератор содержимого не отдаёт незакрытых `{...}`.
  2. Генератор Sigma-правил отдаёт разбираемый YAML с обязательными полями.
  3. Все шаблоны вызываются без исключений (нет забытых импортов date/datetime).
  4. Статически: в кодовой базе не осталось не-f-строк с плейсхолдерами и
     вычислений, результат которых выброшен, — то есть тот же класс дефекта не
     вернётся незамеченным.

Запуск:  python tests/test_generated_content.py
"""
import os as _os, sys as _sys
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)
_os.chdir(_ROOT)

import ast
import re
import random
import logging

logging.disable(logging.CRITICAL)
try:
    _sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

FAILED = []


def check(name, ok, detail=""):
    print(f"  {'✅' if ok else '❌'} {name}" + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        FAILED.append(name)


#: `{...}` с чем-то похожим на имя/выражение внутри. Одиночные `{` в тексте
#: (например в JSON-примерах) не ловим — только настоящие подстановки.
PLACEHOLDER = re.compile(r"\{[A-Za-z_][A-Za-z0-9_\.\[\]'\"()]*\}")

SKIP_DIRS = {".git", "__pycache__", "attic", ".venv", "venv", "node_modules"}


# ======================================================================
#  1. Статика: не-f-строки с плейсхолдерами
# ======================================================================
def _py_files():
    """Пути ВСЕГДА в posix-виде: './activities/x.py', а не '.\\activities\\x.py'.

    Иначе проверки вида `p.startswith("./tests/")` молча не срабатывают на
    Windows, где os.walk отдаёт разделитель `\\`. Именно так этот тест на
    машине автора посчитал сам себя второй реализацией словаря действий и
    насчитал лишние двадцать молчаливых except из каталога tests/ — то есть
    сам оказался платформозависимым, проверяя платформонезависимость.
    """
    for root, dirs, files in _os.walk("."):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fn in sorted(files):
            if fn.endswith(".py"):
                yield _os.path.join(root, fn).replace(_os.sep, "/")


def test_paths_platform_independent():
    """Сам обход файлов не должен зависеть от разделителя пути.

    Этот тест — про тест. На Windows `os.walk` отдаёт `.\\activities\\x.py`, и
    все проверки вида `p.startswith("./tests/")` молча перестают срабатывать.
    Последствия были ровно такие: на машине автора этот файл посчитал
    `ml_features.ACTIONS` «второй копией словаря действий» (потому что не смог
    исключить сам ml_features.py) и насчитал лишние 20 молчаливых `except` из
    каталога tests/. То есть проверка платформонезависимости сама оказалась
    платформозависимой.

    Симптом коварен: на Linux всё зелено, на Windows — два ложных провала, и
    непонятно, сломан продукт или тест.
    """
    print("\n-- платформонезависимость обхода файлов --")
    paths = list(_py_files())
    check(f"файлов найдено ({len(paths)})", len(paths) > 50)
    check("ни в одном пути нет обратного слэша",
          not any("\\" in p for p in paths),
          str([p for p in paths if "\\" in p][:3]))
    check("все пути начинаются с './'",
          all(p.startswith("./") for p in paths),
          str([p for p in paths if not p.startswith("./")][:3]))
    check("исключение по каталогу работает",
          any(p.startswith("./tests/") for p in paths)
          and any(p.startswith("./activities/") for p in paths))
    check("ml_features.py находится по ожидаемому пути",
          "./ml_features.py" in paths)


def test_no_unformatted_templates():
    """Обычная строка с `{placeholder}`, которую возвращают или присваивают.

    Такая строка почти наверняка задумывалась f-строкой: `.format()` к
    возвращаемому значению уже не применить.
    """
    print("\n-- статический анализ шаблонов --")
    bad = []
    for p in _py_files():
        try:
            tree = ast.parse(open(p, encoding="utf-8").read())
        except SyntaxError as e:
            bad.append(f"{p}: синтаксическая ошибка {e}")
            continue
        for node in ast.walk(tree):
            val = node.value if isinstance(node, (ast.Return, ast.Assign)) else None
            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                hits = sorted(set(PLACEHOLDER.findall(val.value)))
                if hits:
                    bad.append(f"{p}:{val.lineno} не-f-строка с {hits[:4]}")
    check(f"нет не-f-строк с плейсхолдерами ({len(bad)} найдено)", not bad)
    for b in bad[:12]:
        print(f"       {b}")


def test_no_discarded_computations():
    """`random.choice([...])` отдельной строкой — результат выброшен.

    Ровно так выглядел след автоочистки: присваивание убрали, вызов оставили,
    а шаблон ниже продолжал ссылаться на исчезнувшую переменную.
    """
    print("\n-- вычисления, результат которых выброшен --")
    PURE = {"choice", "sample", "randint", "uniform", "gauss", "seed",
            "replace", "strip", "lower", "upper", "split", "isoformat",
            "today", "now", "strftime"}
    bad = []
    for p in _py_files():
        try:
            tree = ast.parse(open(p, encoding="utf-8").read())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)):
                continue
            fn = node.value.func
            name = fn.attr if isinstance(fn, ast.Attribute) else \
                (fn.id if isinstance(fn, ast.Name) else "")
            mod = fn.value.id if (isinstance(fn, ast.Attribute)
                                  and isinstance(fn.value, ast.Name)) else ""
            if name in PURE or name.startswith("generate_") or mod == "random":
                # seed/shuffle меняют состояние ГСЧ или список на месте —
                # это осмысленный вызов, а не потерянное присваивание
                if name in ("shuffle", "seed"):
                    continue
                # os.replace / shutil.replace — АТОМАРНОЕ ПЕРЕИМЕНОВАНИЕ ФАЙЛА,
                # а не str.replace: результат выбрасывать нечего, весь смысл в
                # побочном действии. Эвристика ловила по имени метода и
                # помечала атомарную запись состояния как потерянное
                # присваивание.
                if name == "replace" and mod in ("os", "_os", "shutil", "pathlib"):
                    continue
                bad.append(f"{p}:{node.lineno} {ast.unparse(node.value)[:70]}")
    check(f"нет выброшенных вычислений ({len(bad)} найдено)", not bad)
    for b in bad[:12]:
        print(f"       {b}")


# ======================================================================
#  2. Динамика: реально вызываем генераторы
# ======================================================================
class _FakeGL:
    def get_file(self, *a, **k):
        return "# существующий файл\n"

    def list_files(self, *a, **k):
        return ["rules/execution/a.yml"]


class _FakeAgent:
    """Минимальный агент: у шаблонов от него нужны только name/username/gl."""
    name = "Maria Ivanova"
    username = "maria.ivanova"
    role = "detection_engineer"
    user_id = 37
    gl = _FakeGL()

    def log(self, *a, **k):
        pass

    def think(self, *a, **k):
        pass


def _call_templates():
    """(имя, текст) для всех генераторов содержимого."""
    from activities.bulk_maintenance import BulkMaintenanceActivity
    from activities.dashboard import DashboardActivity
    from activities.deprecate_rule import DeprecateRuleActivity
    from activities.fix_rule import FixRuleActivity
    from activities.incident import IncidentActivity
    from activities.recreate_rule import RecreateRuleActivity
    from activities.revert_rule import RevertRuleActivity
    from activities.triage import TriageFalsePositiveActivity
    from activities.tune_rule import TuneThresholdActivity
    from activities.update_parser import UpdateParserActivity
    from activities.update_playbook import UpdatePlaybookActivity, NEW_PLAYBOOKS
    from agents.lead import LeadAgent
    from collections import Counter

    a, lead = _FakeAgent(), _FakeAgent()

    def mk(cls):
        o = cls.__new__(cls)
        o.author, o.lead, o.pid, o.state = a, lead, 1, None
        o.target_slug = None
        return o

    tech = {"id": "T1003.001", "title": "LSASS Dump", "tactic": "credential_access",
            "description": "тест", "level": "high"}
    out = [
        ("bulk_maintenance._migration_doc",
         mk(BulkMaintenanceActivity)._migration_doc("нормализация полей")),
        ("dashboard._coverage_doc",
         mk(DashboardActivity)._coverage_doc(Counter({"execution": 4}), 12)),
        ("dashboard._fp_report",
         mk(DashboardActivity)._fp_report(["rules/a.yml", "rules/b.yml"])),
        ("deprecate_rule._archive_note",
         mk(DeprecateRuleActivity)._archive_note("slug", "rules/x.yml", "шумит")),
        ("fix_rule._mr_desc",
         mk(FixRuleActivity)._mr_desc("slug", "filter_added", "сервисные аккаунты", True)),
        ("incident._incident_report",
         mk(IncidentActivity)._incident_report("INC-1", "Подозрительный вход", "High")),
        ("recreate_rule._mr_desc", mk(RecreateRuleActivity)._mr_desc(tech, "slug")),
        ("revert_rule._revert_note",
         mk(RevertRuleActivity)._revert_note("Плохое правило", "a" * 40, "FP", "переписать")),
        ("triage._triage_note", mk(TriageFalsePositiveActivity)._triage_note("slug", "false_positive")),
        ("tune_rule._mr_desc", mk(TuneThresholdActivity)._mr_desc("slug", "сужено условие")),
        ("update_parser._changelog_entry",
         mk(UpdateParserActivity)._changelog_entry("sysmon", "поддержка EventID 25")),
        ("update_parser._mr_desc",
         mk(UpdateParserActivity)._mr_desc("sysmon", "поддержка EventID 25")),
        ("update_playbook._generate_playbook",
         mk(UpdatePlaybookActivity)._generate_playbook(NEW_PLAYBOOKS[0])),
        ("update_playbook._forensics_appendix",
         mk(UpdatePlaybookActivity)._forensics_appendix()),
    ]
    ld = LeadAgent.__new__(LeadAgent)
    ld.name = "Alex Petrov"
    out.append(("lead._runner_config", ld._runner_config()))
    out.append(("lead._onboarding_doc", ld._onboarding_doc()))
    return out


def test_templates_render():
    print("\n-- генераторы содержимого для GitLab --")
    random.seed(3)
    try:
        rendered = _call_templates()
    except Exception as e:
        check("все шаблоны вызываются без исключения", False, repr(e))
        import traceback
        traceback.print_exc()
        return
    check(f"все шаблоны вызываются без исключения ({len(rendered)} шт.)", True)
    for name, text in rendered:
        hits = sorted(set(PLACEHOLDER.findall(text)))
        check(f"{name}: нет незакрытых плейсхолдеров", not hits, str(hits[:4]))
        check(f"{name}: не пустой", len(text.strip()) > 40)


def test_sigma_rule():
    print("\n-- генератор Sigma-правил (content/rules.py) --")
    from content import rules as rc
    random.seed(5)
    ok_all = True
    for tech in random.sample(rc.TECHNIQUES, k=min(25, len(rc.TECHNIQUES))):
        for status in ("experimental", "production"):
            text = rc.generate_sigma_rule(tech, author="maria.ivanova", status=status,
                                          extra_filters=["User|endswith: '$'"])
            if PLACEHOLDER.findall(text):
                check(f"Sigma {tech['id']}: незакрытые плейсхолдеры", False,
                      str(sorted(set(PLACEHOLDER.findall(text)))[:4]))
                ok_all = False
                continue
            for field in ("title:", "id:", "status:", "author:", "date:",
                          "logsource:", "detection:", "condition:", "level:"):
                if field not in text:
                    check(f"Sigma {tech['id']}: нет поля {field}", False)
                    ok_all = False
            if "{" in text.split("detection:")[0]:
                check(f"Sigma {tech['id']}: скобка в шапке", False)
                ok_all = False
    check("все сгенерированные Sigma-правила корректны", ok_all)

    # id должен быть уникальным на каждый вызов — иначе весь репозиторий
    # правил получит один и тот же UUID
    ids = set()
    for _ in range(40):
        t = rc.generate_sigma_rule(rc.TECHNIQUES[0], author="a")
        ids.add(re.search(r"^id: (\S+)", t, re.M).group(1))
    check(f"id правила уникален на каждый вызов ({len(ids)}/40)", len(ids) == 40)


def test_ir_report_html():
    print("\n-- HTML-отчёт по инциденту (console.py) --")
    try:
        import console
        assert console.__doc__, "у console нет докстринга"
    except Exception as e:
        check("console импортируется", False, repr(e))
        return
    inc = {"id": 42, "actor": "sergey.volkov", "start_ts": "2026-07-20T02:10:00",
           "last_ts": "2026-07-20T03:40:00", "max_risk": 0.87, "severity": "high",
           "repos": ["detection-rules", "soc-secrets"],
           "tactics": ["Discovery", "Exfiltration"], "techniques": ["T1087", "T1567"],
           "alerts": [{"ts_sim": "2026-07-20T02:10:00", "action": "api_read",
                       "project": "detection-rules", "path": None, "branch": None,
                       "mr_iid": None, "risk": 0.5, "technique": "T1087",
                       "tactic": "Discovery", "reason": "серия запросов",
                       "layer": "rules", "rule_id": "code-search"}],
           "chain": [{"ts": "2026-07-20T02:10:00", "tactic": "Discovery",
                      "technique": "T1087", "action": "api_read", "risk": 0.5}]}
    try:
        # Сборка отчёта переехала в console_app.incidents вместе с
        # остальным разделом инцидентов (console.py стал точкой входа).
        from console_app import incidents as _inc
        html = _inc._incident_report_html(42, inc)
    except Exception as e:
        check("IR-отчёт генерируется", False, repr(e))
        import traceback
        traceback.print_exc()
        return
    hits = sorted(set(PLACEHOLDER.findall(html)))
    check("IR-отчёт: нет незакрытых плейсхолдеров", not hits, str(hits[:6]))
    check("IR-отчёт: нет двойных фигурных скобок в CSS", "{{" not in html)
    check("IR-отчёт: номер инцидента подставлен", "#42" in html)
    check("IR-отчёт: актор подставлен", "sergey.volkov" in html)
    check("IR-отчёт: закрыт тег html", html.rstrip().endswith("</html>"))


def test_feature_taxonomy_sync():
    print("\n-- синхронность словаря действий и вектора признаков --")
    import ml_features
    missing, extra = ml_features.check_taxonomy()
    check("ACTIONS покрывает taxonomy.OBSERVABLE", not missing, str(missing))
    check("в ACTIONS нет действий вне словаря", not extra, str(extra))
    check("длина вектора совпадает с FEATURES",
          len(ml_features.featurize({})) == len(ml_features.FEATURES))
    check("неизвестное действие помечается act_unknown",
          ml_features.featurize({"action": "нет_такого"})[
              ml_features.FEATURES.index("act_unknown")] == 1.0)


def test_single_feature_implementation():
    """В кодовой базе должна быть РОВНО ОДНА функция, строящая вектор признаков.

    Зачем проверка. Докстринг `ml_features.py` обещает, что `featurize()` един
    для research и для боевого детектора, и что расхождение train/serve
    «исключено конструктивно». Обещание держалось только на дисциплине: в
    `research/train_model.py` жила ВТОРАЯ реализация на 22 признака со своим
    списком действий (`repo_enum`, `comment`, `approve` — таких в taxonomy нет).
    Числа, полученные тем скриптом, были несопоставимы с боевой моделью, но
    выглядели как метрики того же детектора.

    Критерии — СЕМАНТИЧЕСКИЕ, а не по имени. Проверка по имени константы дала
    бы ложные срабатывания: `config.FEATURES` — это флаги реализма мира,
    `dev_workflows.ACTIONS` — пункты ретроспективы, а
    `research/content_ml_features.FEATURES` — ДРУГОЕ признаковое пространство
    (только по содержимому файла, без привязки к событию) для отдельного
    вопроса «отличим ли секрет по статистике текста без регулярок». Это не
    дубликаты, и запрещать их нельзя.

    Поэтому ловим:
      (а) функцию вне ml_features, возвращающую вектор длиной >= 8 из
          вычисляемых элементов — то есть строящую признаки события;
      (б) список строк, который заметно пересекается с taxonomy.OBSERVABLE
          или с ml_features.FEATURES, — то есть ВТОРУЮ копию того же словаря.
    """
    print("\n-- единственность реализации признаков --")
    import ml_features
    import taxonomy
    ALLOWED = {"./ml_features.py"}
    known_actions = set(taxonomy.OBSERVABLE)
    known_feats = set(ml_features.FEATURES)
    dup_vec, dup_const = [], []

    for p in _py_files():
        if p in ALLOWED or p.startswith("./tests/"):
            continue
        try:
            tree = ast.parse(open(p, encoding="utf-8").read())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            # (а) функция, возвращающая длинный вычисляемый вектор
            if isinstance(node, ast.FunctionDef):
                for sub in ast.walk(node):
                    if not (isinstance(sub, ast.Return)
                            and isinstance(sub.value, (ast.List, ast.BinOp))):
                        continue
                    lst = sub.value if isinstance(sub.value, ast.List) else sub.value.left
                    if not (isinstance(lst, ast.List) and len(lst.elts) >= 8):
                        continue
                    computed = sum(1 for e in lst.elts
                                   if isinstance(e, (ast.IfExp, ast.BinOp, ast.Call)))
                    if computed >= 8:
                        dup_vec.append(f"{p}:{node.lineno} {node.name}() "
                                       f"-> вектор из {len(lst.elts)} вычисляемых элементов")
            # (б) список строк, пересекающийся с известными словарями
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.List):
                vals = {e.value for e in node.value.elts
                        if isinstance(e, ast.Constant) and isinstance(e.value, str)}
                if len(vals) < 5:
                    continue
                ov_a = len(vals & known_actions)
                ov_f = len(vals & known_feats)
                name = next((t.id for t in node.targets if isinstance(t, ast.Name)), "?")
                if ov_a >= 5:
                    dup_const.append(f"{p}:{node.lineno} {name} — {ov_a} общих "
                                     f"действий с taxonomy.OBSERVABLE")
                elif ov_f >= 5:
                    dup_const.append(f"{p}:{node.lineno} {name} — {ov_f} общих "
                                     f"признаков с ml_features.FEATURES")

    check(f"нет второй реализации вектора признаков ({len(dup_vec)})", not dup_vec)
    for d in dup_vec[:6]:
        print(f"       {d}")
    check(f"нет второй копии словаря действий/признаков ({len(dup_const)})", not dup_const)
    for d in dup_const[:6]:
        print(f"       {d}")

    # и позитивная проверка: боевой детектор и обучение зовут ОДНУ функцию
    src_det = open("detector.py", encoding="utf-8").read()
    src_trn = open("research/train_runtime_model.py", encoding="utf-8").read()
    check("детектор использует ml_features.featurize",
          "ml_features.featurize(" in src_det)
    check("обучение использует ml_features.featurize",
          "ml_features.featurize(" in src_trn)
    check("удалённый train_model.py не вернулся",
          not _os.path.exists("research/train_model.py"))


def test_no_hardcoded_project_ids():
    """Ни одна активность не берёт id репозитория из статической карты PROJECTS.

    `PROJECTS` — это id того GitLab-инстанса, где проект запускался первый раз.
    После пересоздания репозиториев автодискавери находит НАСТОЯЩИЕ id и кладёт
    их в `WORK_REPOS`, а `PROJECTS` остаётся со старыми. Активность, читающая
    `PROJECTS[...]` напрямую, продолжает ходить по устаревшему id и молча
    падает — событие в журнал пишется, в GitLab не появляется ничего.

    На накопленном журнале это дало 571 отказ за прогон ровно у тех активностей,
    которые читали PROJECTS, и ноль у тех, что ходили через config.*_repo_id():

        DashboardActivity  docs/*   100 из 109
        IncidentActivity   ir/*     197 из 197
        BulkMaintenance    chore/*   28 из  69

    Разрешена одна точка разрешения имени в id — config.repo_id().
    """
    print("\n-- разрешение id репозиториев --")
    bad = []
    for p in _py_files():
        if not (p.startswith("./activities/") or p.startswith("./agents/")):
            continue
        try:
            tree = ast.parse(open(p, encoding="utf-8").read())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            # PROJECTS["имя"] в любом виде
            if isinstance(node, ast.Subscript):
                v = node.value
                name = (v.id if isinstance(v, ast.Name) else
                        v.attr if isinstance(v, ast.Attribute) else "")
                if name == "PROJECTS":
                    bad.append(f"{p}:{node.lineno} PROJECTS[...] — нужен config.repo_id()")
            # PROJECTS.get("имя")
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "get"):
                v = node.func.value
                name = (v.id if isinstance(v, ast.Name) else
                        v.attr if isinstance(v, ast.Attribute) else "")
                if name == "PROJECTS":
                    bad.append(f"{p}:{node.lineno} PROJECTS.get(...) — нужен config.repo_id()")
    check(f"нет захардкоженных id репозиториев ({len(bad)})", not bad)
    for b in bad[:10]:
        print(f"       {b}")

    import config
    check("config.repo_id существует", hasattr(config, "repo_id"))
    check("config.repo_id разрешает известное имя",
          config.repo_id("detection-rules") is not None)
    check("config.repo_id не падает на неизвестном имени",
          isinstance(config.repo_id("нет-такого-репозитория"), int))


#: ПОТОЛОК молчаливых обработчиков исключений.
#:
#: `except: pass` без записи в лог превращает отказ в невидимку. Именно так
#: пропали 571 отказ GitLab за прогон: события писались с gitlab_ok=false, а в
#: логах не было ни строки, и счётчик ошибок в интерфейсе показывал ноль.
#:
#: Полностью запретить нельзя — часть случаев законна (опциональный импорт,
#: разбор необязательного поля). Поэтому зафиксирован ПОТОЛОК: число не должно
#: расти. Снижать его — нормально, поднимать — только осознанно и с
#: объяснением, почему молчание здесь допустимо.
SILENT_EXCEPT_LIMIT = 70   # храповик затянут: было 82 при более мягком
                           # правиле подсчёта, стало 66 при более строгом


def test_silent_except_budget():
    """Сколько отказов в коде остаются невидимыми.

    Из подсчёта исключены категории, где молчание не является долгом:

      • `sys.stdout.reconfigure(encoding="utf-8")` — идиома совместимости
        (метода нет до Python 3.7 и на перенаправленном потоке). Логировать
        её нечем: логгер в этот момент ещё не настроен, а сам факт «консоль
        не умеет UTF-8» ни на что не влияет. Таких мест 23, и считать их
        техдолгом — значит размывать оставшиеся 80, где молчание реально
        прячет отказ.
      • каталог `tests/` — там `except SyntaxError: continue` является частью
        самой проверки;
      • смена прав файла (`os.chmod`) с явным перехватом
        `(OSError, NotImplementedError)`: на Windows и FAT прав как таковых
        нет, и отсутствие поддержки — не отказ, а свойство платформы. Важно,
        что перехват здесь УЗКИЙ: `except Exception` в этот список не попадает;
      • откат транзакции (`rollback`) внутри обработчика уже логируемой
        ошибки: настоящая причина пишется рядом, а неудача самого отката
        добавить к ней нечего;
      • удаление временного файла в ветке очистки (`os.remove(tmp)`): файл и
        так не нужен, а отказ удаления не меняет исхода операции.
    """
    print("\n-- бюджет молчаливых except --")
    total = 0
    idiom = 0
    per_file = {}
    for p in _py_files():
        if p.startswith("./tests/"):
            continue
        try:
            src = open(p, encoding="utf-8").read()
            tree = ast.parse(src)
        except SyntaxError:
            continue
        n = 0
        for node in ast.walk(tree):
            if not isinstance(node, ast.Try):
                continue
            body_src = " ".join(ast.unparse(x) for x in node.body)
            legit = "reconfigure" in body_src and "encoding" in body_src
            for h in node.handlers:
                b = h.body
                if not (len(b) == 1 and isinstance(b[0], (ast.Pass, ast.Continue,
                                                          ast.Return, ast.Break))):
                    continue
                # ЧТО СЧИТАЕТСЯ ДОЛГОМ, А ЧТО НЕТ.
                #
                # Смысл бюджета — «сколько ОТКАЗОВ остаются невидимыми». Это
                # про широкий перехват: `except Exception: pass` скрывает
                # ЛЮБУЮ причину, включая ту, о которой никто не думал.
                #
                # Узкий перехват вокруг попытки РАЗБОРА — другое дело. Цепочка
                #
                #     try:    datetime.fromisoformat(s)
                #     except ValueError: pass          # пробуем следующий формат
                #     try:    datetime.strptime(s, fmt)
                #
                # ничего не прячет: названа ровно ожидаемая неудача, а результат
                # обрабатывается ниже. Считать её долгом — значит поощрять
                # написание `except Exception` там, где автор точно знает, чего
                # ждёт, то есть подталкивать ровно к тому дефекту, который
                # бюджет и должен предотвращать.
                #
                # Поэтому узкий перехват НЕ считается долгом, если в теле нет
                # операции, отказ которой означает потерю данных.
                exc = ast.unparse(h.type) if h.type is not None else ""
                narrow = bool(exc) and "Exception" not in exc and "BaseException" not in exc
                LOSSY = ("write", "commit", "save", "append", "execute", "flush",
                         "dump", "send", "post(", "put(", "insert", "makedirs")
                lossy = any(k in body_src for k in LOSSY)
                if legit or (narrow and not lossy):
                    idiom += 1
                else:
                    n += 1
        if n:
            per_file[p] = n
            total += n
    print(f"       (не считаются: {idiom} мест с sys.stdout.reconfigure — "
          f"идиома совместимости)")
    ok = total <= SILENT_EXCEPT_LIMIT
    check(f"молчаливых except: {total} (потолок {SILENT_EXCEPT_LIMIT})", ok)
    if not ok:
        print("       выросло — добавь logging или подними потолок осознанно:")
        for f, n in sorted(per_file.items(), key=lambda t: -t[1])[:8]:
            print(f"       {n:4}  {f}")

    # Ключевые модули обязаны логировать отказы GitLab и открытие хранилища
    for mod, needle, why in (
        ("agents/base.py", "logger.warning", "отказы GitLab"),
        ("gitlab_client.py", "logger.warning", "ошибки API"),
        ("eventstore.py", "_log.error", "недоступное хранилище"),
        ("main.py", "soclog", "структурные логи в процессе мира"),
    ):
        src = open(mod, encoding="utf-8").read()
        check(f"{mod}: логирует {why}", needle in src)

    import eventstore
    check("eventstore.last_error() существует", hasattr(eventstore, "last_error"))
    # /api/health живёт в разделе system консоли защиты.
    src = open("console_app/system.py", encoding="utf-8").read()
    check("/api/health отдаёт store_error", '"store_error"' in src)
    tpl = open("templates/console/dashboard.html", encoding="utf-8").read()
    check("интерфейс показывает отказ хранилища", "storeWarn" in tpl)


def test_bat_files_are_cmd_safe():
    """Батники должны быть в ASCII и с CRLF — иначе cmd.exe их не разберёт.

    Найдено на живой машине. START_PANEL.bat был записан в UTF-8 с
    кириллицей в комментариях и с переводами строк в стиле Unix. cmd.exe
    читает .bat в кодировке OEM (cp866 на русской Windows) ПОБАЙТНО, и
    многобайтные последовательности UTF-8 распадаются: часть байтов
    попадает на служебные символы `&`, `|`, `(`, `)`, строка рвётся, и
    cmd пытается выполнить обломки как команды:

        'ся' is not recognized as an internal or external command
        'from' is not recognized as an internal or external command

    `chcp 65001` внутри файла не спасает: комментарии выше него уже
    прочитаны в старой кодировке. Отсюда правило: в .bat только ASCII,
    весь текст для человека — в Python, который печатает его под UTF-8.

    Одиночные LF ломают многострочные блоки `if errorlevel 1 ( ... )`,
    поэтому переводы строк обязаны быть CRLF.
    """
    print("\n-- батники разбираются cmd.exe --")
    import glob
    bats = sorted(glob.glob("*.bat"))
    check(f"батники найдены ({len(bats)})", len(bats) > 0)
    non_ascii, lf_only = [], []
    for fn in bats:
        raw = open(fn, "rb").read()
        try:
            raw.decode("ascii")
        except UnicodeDecodeError:
            non_ascii.append(fn)
        if raw.count(b"\n") - raw.count(b"\r\n"):
            lf_only.append(fn)
    # Пока в ASCII приведён только START_PANEL.bat — он единственный, который
    # запускает панель и по которому проблема воспроизвелась. Остальные
    # остаются как есть, но CRLF обязателен для всех.
    check("START_PANEL.bat в чистом ASCII", "START_PANEL.bat" not in non_ascii,
          ", ".join(non_ascii))
    check("во всех .bat переводы строк CRLF", not lf_only, ", ".join(lf_only))


def main():
    print("=" * 72)
    print("  ТЕСТ СОДЕРЖИМОГО, КОТОРОЕ УХОДИТ В GITLAB")
    print("=" * 72)
    test_paths_platform_independent()
    test_no_unformatted_templates()
    test_no_discarded_computations()
    test_templates_render()
    test_sigma_rule()
    test_ir_report_html()
    test_feature_taxonomy_sync()
    test_single_feature_implementation()
    test_no_hardcoded_project_ids()
    test_silent_except_budget()
    test_bat_files_are_cmd_safe()
    print("-" * 72)
    if FAILED:
        print(f"  ❌ ПРОВАЛЕНО: {len(FAILED)} -> {FAILED[:8]}")
        return 1
    print("  ✅ Всё, что уходит в GitLab, отрендерено полностью.")
    return 0


if __name__ == "__main__":
    _sys.exit(main())
