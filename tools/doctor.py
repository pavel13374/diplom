#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DOCTOR — проверка окружения перед запуском платформы.

Печатает чек-лист: версия Python, нужные пакеты, свободны ли порты 8787/8788,
доступность GitLab (из config), наличие Ollama (для LLM-разбора).

Запуск:  python doctor.py
"""

# --- скрипт живёт в подпапке; движок проекта — в корне ---
import os as _os, sys as _sys
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
for _p in (_ROOT, _os.path.join(_ROOT, "tools"), _os.path.join(_ROOT, "research")):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
_os.chdir(_ROOT)
del _os, _sys
import os
import sys
import socket

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


def line(ok, name, detail=""):
    mark = "OK " if ok else "-- "
    print(f"  [{mark}] {name}" + (f": {detail}" if detail else ""))


def port_free(p):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.3)
    try:
        free = s.connect_ex(("127.0.0.1", p)) != 0
    finally:
        s.close()
    return free


def main():
    print("=" * 56)
    print("  DOCTOR — проверка окружения")
    print("=" * 56)

    v = sys.version_info
    line(v >= (3, 8), "Python >= 3.8", f"{v.major}.{v.minor}.{v.micro}")

    print("\n  Пакеты:")
    for mod, need in [("flask", True), ("requests", True), ("sklearn", False),
                      ("numpy", False), ("pandas", False)]:
        try:
            __import__(mod)
            try:
                import importlib.metadata as _md
                ver = _md.version(mod if mod != "sklearn" else "scikit-learn")
            except Exception:
                ver = "ok"
            line(True, mod, ver)
        except Exception:
            line(False, mod, "не установлен" + ("  (нужен для сайтов)" if need else "  (нужен для ML)"))

    print("\n  Порты (должны быть свободны):")
    line(port_free(8787), "8787 (Environment Console)")
    line(port_free(8788), "8788 (Purple Team Console)")

    print("\n  GitLab (из config):")
    try:
        import config
        url = config.GITLAB_URL
        tok = bool(config.ADMIN_TOKEN and config.ADMIN_TOKEN.startswith("glpat-"))
        line(bool(url), "GITLAB_URL", url)
        line(tok, "ADMIN_TOKEN задан", "glpat-..." if tok else "проверь токен")
        try:
            import urllib.request, ssl
            ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url.rstrip("/") + "/api/v4/version",
                                         headers={"PRIVATE-TOKEN": config.ADMIN_TOKEN})
            with urllib.request.urlopen(req, timeout=4, context=ctx) as r:
                import json
                ver = json.loads(r.read()).get("version", "?")
            line(True, "GitLab отвечает", f"v{ver}")
        except Exception as e:
            line(False, "GitLab недоступен", str(e)[:60])
    except Exception as e:
        line(False, "config", str(e)[:60])

    print("\n  LLM (Ollama, опционально):")
    try:
        import llm_client
        ok, why, models = llm_client.status(force=True)
        # Печатаем ПРИЧИНУ целиком, без обрезки: раньше здесь было
        # «не запущена», и на машине с работающей Ollama это сообщение
        # уводило в сторону — сервис был жив, мешал системный прокси.
        line(ok, "Ollama", (", ".join(models) or "нет моделей") if ok else "недоступна")
        if not ok:
            print(f"      причина: {why}")
        # Показываем окружение, влияющее на транспорт: это две самые частые
        # причины отказа при живом сервисе.
        import os as _o
        px = {k: v for k, v in _o.environ.items()
              if k.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")}
        if px:
            print("      прокси в окружении: "
                  + ", ".join(f"{k}={v}" for k, v in sorted(px.items())))
        try:
            import urllib.request as _ur
            sysprx = _ur.getproxies()
            if sysprx:
                print(f"      системный прокси: {sysprx} "
                      "(для локального адреса он больше не применяется)")
        except Exception:
            pass
        print(f"      адрес из конфигурации: {llm_client._host()} · "
              f"модель: {llm_client._model()}")
    except Exception as e:
        line(False, "llm_client", str(e)[:50])

    print("\n  Слои детектирования:")
    try:
        import detector
        import taxonomy
        from attack_matrix import all_techniques
        e = detector.DetectionEngine()
        matrix = all_techniques()
        covered = set(e.techniques_covered()) & matrix
        line(e.rule_count() > 0, "L0 правила загружены",
             f"{e.rule_count()} шт, покрыто {len(covered)}/{len(matrix)} техник "
             f"({len(covered)/len(matrix)*100:.0f}%)")

        # L0: правил-тавтологий быть не должно (см. taxonomy.py)
        import json as _json, glob as _glob
        taut = []
        for fp in _glob.glob(os.path.join(BASE, "detections", "*.json")):
            w = (_json.load(open(fp, encoding="utf-8")).get("when") or {})
            if len(w) == 1 and "action" in w:
                taut.append(os.path.basename(fp))
        line(not taut, "правила не читают метку",
             "все опираются на атрибуты" if not taut
             else f"тавтологии: {', '.join(taut[:3])}")

        line(True, "L1 UEBA",
             f"порог из данных, бюджет тревог {e.ueba.BUDGET*100:.2f}% "
             f"событий, калибровка после {e.ueba.MIN_CALIB}")

        if e.ml is not None and e.ml.available():
            m = e.ml
            line(True, "L2 ML загружен",
                 f"порог {m.threshold:.4f}, обучена {m.trained_on}, "
                 f"калибровка Платта: {'да' if m.platt else 'нет'}")
        else:
            line(None, "L2 ML не загружен",
                 "работаем на L0+L1 — обучить: python research/train_runtime_model.py")

        line(True, "слияние рисков", f"режим {detector._cfg('FUSION_MODE', 'logodds')} "
             f"(поправка на зависимость слоёв)")
        line(len(taxonomy.OBSERVABLE) > 0, "словарь наблюдаемых действий",
             f"{len(taxonomy.OBSERVABLE)} действий, {len(taxonomy.ATTRIBUTES)} атрибутов")
    except Exception as ex:
        line(False, "detector", str(ex)[:70])

    print("\n  Event-store и данные:")
    try:
        import eventstore
        eventstore.init()
        ok = eventstore.enabled()
        st = eventstore.stats() if ok else {}
        line(ok, "events.db открыт",
             f"{st.get('events', 0)} событий" if ok
             else "не открылся — проверь data/ и config.EVENT_STORE")
        if ok:
            for cur in ("defense", "console"):
                try:
                    pos = eventstore.get_cursor(cur)
                    lag = max(0, (st.get("events") or 0) - (pos or 0))
                    line(lag < 5000, f"курсор «{cur}»",
                         f"позиция {pos}, отставание {lag}"
                         + ("" if lag < 5000 else " — читатель давно не работал"))
                except Exception as ex2:
                    line(False, f"курсор «{cur}»", str(ex2)[:50])
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        dd = os.path.join(base, "data")
        line(os.access(dd, os.W_OK) if os.path.isdir(dd) else False,
             "data/ доступна на запись",
             dd if os.path.isdir(dd) else "папки нет — создастся при старте")
    except Exception as ex:
        line(False, "eventstore", str(ex)[:60])

    print("\n  Конвейер (смоук офлайн):")
    try:
        import run_defense
        # Эталон строится ИЗ РЕАЛЬНОГО СОДЕРЖИМОГО через тот же
        # content_features, что и в бою: так смоук проверяет весь путь
        # «текст -> признаки -> правило», а не подставленные вручную поля.
        import content_features
        _content = ("# deploy config\n"
                    "GITLAB_TOKEN=glpat-" + "A1b2C3d4E5f6G7h8I9j0" + "\n")
        _probe = {"action": "push", "actor": "_doctor", "project": "soc-infra",
                  "path": "config/prod.env", "branch": "main",
                  "ts_sim": "2026-01-01T03:00:00", "hour": 3, "is_night": True,
                  "bytes": len(_content),
                  "is_anomaly": True, "campaign_id": "_doctor"}
        _probe.update(content_features.analyze(_content, _probe["path"]))
        res = run_defense.process(_probe)
        hits = [a["rule_id"] for a in res.get("alerts", [])]
        line(bool(res.get("alert")), "детектор ловит эталонное событие",
             f"risk={res.get('risk')}, сработало: {', '.join(hits)}"
             if res.get("alert") else "эталон не пойман — правила изменялись?")
        line("secret-signature-commit" in hits,
             "сигнатура секрета распознана по содержимому",
             "правило secret-signature-commit сработало" if "secret-signature-commit" in hits
             else "правило молчит — проверь content_features и detections/")
        leak_ok = "campaign_id" not in run_defense.observed(_probe)
        line(leak_ok, "анти-лик: observed() срезает разметку",
             "ок" if leak_ok else "!!! разметка мира видна детектору")
    except Exception as ex:
        line(False, "конвейер", str(ex)[:60])

    print("\n  Обращения к GitLab:")
    try:
        import json as _json
        import collections as _c
        _jsonl = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "data", "events.jsonl")
        # РАЗБИРАЕМ ТОЛЬКО ПОСЛЕДНИЙ ПРОГОН.
        #
        # Журнал копится между запусками, и отказы прошлых прогонов остаются в
        # нём навсегда. Если считать по всему файлу, уже исправленная проблема
        # продолжает гореть красным, и диагностика перестаёт что-либо значить.
        # Смотрим последний run_id, а по всей истории даём только справку.
        runs = []
        rows = []
        if os.path.exists(_jsonl):
            with open(_jsonl, encoding="utf-8") as _f:
                for _ln in _f:
                    _ln = _ln.strip()
                    if not _ln:
                        continue
                    try:
                        _r = _json.loads(_ln)
                    except Exception:
                        continue
                    if _r.get("gitlab_ok") is None:
                        continue
                    rows.append(_r)
                    rid = _r.get("run_id")
                    if rid and (not runs or runs[-1] != rid):
                        runs.append(rid)
        last_run = runs[-1] if runs else None

        hist_bad = sum(1 for _r in rows if _r.get("gitlab_ok") is False)
        cur = [_r for _r in rows if _r.get("run_id") == last_run] if last_run else rows

        ok_op, bad_op = _c.Counter(), _c.Counter()
        by_repo = _c.Counter(); tot_repo = _c.Counter()
        for _r in cur:
            _a = _r.get("action") or "?"
            _p = str(_r.get("project"))
            tot_repo[_p] += 1
            if _r.get("gitlab_ok"):
                ok_op[_a] += 1
            else:
                bad_op[_a] += 1
                by_repo[_p] += 1

        total_bad = sum(bad_op.values())
        total_ok = sum(ok_op.values())
        if last_run:
            print(f"    последний прогон: {last_run}   "
                  f"(в журнале всего прогонов: {len(runs)})")
            if hist_bad > total_bad:
                print(f"    за всю историю журнала отказов: {hist_bad} — "
                      f"это прошлые прогоны, ниже только последний")
        if total_ok + total_bad == 0:
            line(True, "журнал обращений", "пуст — мир ещё не запускался")
        else:
            rate = total_bad / max(1, total_ok + total_bad)
            line(rate < 0.05, "общая доля отказов",
                 f"{total_bad} из {total_ok + total_bad} = {rate * 100:.1f}%"
                 + ("" if rate < 0.05 else "  <- разбери по операциям ниже"))
            # СИСТЕМАТИЧЕСКИЙ отказ одной операции важнее общего счётчика:
            # «312 ошибок» ничего не говорит, «create_branch 357 из 3855»
            # указывает на конкретную причину (обычно устаревший id репозитория,
            # см. config.repo_id).
            for _a, _n in bad_op.most_common(4):
                _t = _n + ok_op[_a]
                _r2 = _n / max(1, _t)
                line(_r2 < 0.05, f"операция {_a}",
                     f"{_n} отказов из {_t} = {_r2 * 100:.1f}%"
                     + ("" if _r2 < 0.05 else "  <- систематический сбой"))
            for _p, _n in by_repo.most_common(3):
                _t = tot_repo[_p]
                _r2 = _n / max(1, _t)
                if _r2 >= 0.05:
                    line(False, f"репозиторий {_p}",
                         f"{_n} отказов из {_t} = {_r2 * 100:.1f}%"
                         "  <- проверь, что id актуален (автодискавери)")
    except Exception as ex:
        line(False, "разбор отказов GitLab", str(ex)[:60])

    print("\n  Логи:")
    try:
        import soclog
        paths = soclog.install()
        line(True, "структурный лог", paths.get("jsonl", ""))
        errs = soclog.tail_errors(5)
        line(not errs, "errors.log",
             "пустой — ошибок не было" if not errs
             else f"{len(errs)} последних строк — пришли файл на разбор")
    except Exception as ex:
        line(False, "soclog", str(ex)[:50])

    print("=" * 56)
    print("  Готово. Если что-то [--], см. подсказки выше.")
    print("  Для разбора проблем присылай: logs/errors.log и logs/debug.jsonl")


if __name__ == "__main__":
    main()
