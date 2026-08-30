#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
СИНХРОННОСТЬ СЛОВАРЯ ПЕРЕВОДА С ПРАВИЛАМИ И ИНТЕРФЕЙСОМ.

Зачем нужен отдельный тест. Названия правил живут в detections/*.json, а их
английские варианты — в static/i18n.js. Это два разных файла, которые никто не
связывает: при переписывании правил словарь молча остался со старыми строками,
и 36 из 38 названий в английской версии интерфейса остались по-русски. Заметить
это можно было только глазами, переключив язык и пролистав каталог правил.

Что проверяется:
  1. у КАЖДОГО правила есть перевод названия;
  2. в словаре нет «мёртвых» переводов правил, которых больше не существует;
  3. словарь синтаксически корректен и не содержит дублей ключей
     (дубль в JS молча затирает первое значение);
  4. переводы не пустые и отличаются от оригинала;
  5. в словарь не попали данные — имена людей, названия репозиториев,
     идентификаторы техник: их переводить нельзя, это содержимое журнала.

Запуск: python tests/test_i18n_rules.py
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
import re
import sys
import json
import glob
import collections

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

OK = "✅"; BAD = "❌"
fails = []


def check(name, cond, detail=""):
    print(f"  {OK if cond else BAD} {name}")
    if not cond:
        fails.append(name)
        if detail:
            print(f"      {detail}")


def parse_dict(js_text):
    """Достать пары «ключ: значение» из объекта DICT в i18n.js.

    Полноценный парсер JS не нужен: словарь плоский и записан строковыми
    литералами в одинарных кавычках, по одной паре на строку.
    """
    body_start = js_text.index("var DICT = {")
    depth = 0
    i = js_text.index("{", body_start)
    start = i
    while i < len(js_text):
        if js_text[i] == "{":
            depth += 1
        elif js_text[i] == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    body = js_text[start:i]

    pairs = []
    rx = re.compile(r"^\s*'((?:[^'\\]|\\.)*)'\s*:\s*'((?:[^'\\]|\\.)*)'\s*,?\s*$", re.M)
    for m in rx.finditer(body):
        pairs.append((m.group(1).replace("\\'", "'"),
                      m.group(2).replace("\\'", "'")))
    return pairs



def test_no_near_miss_keys():
    """Ключ, ПОХОЖИЙ на строку разметки, но не совпадающий точно.

    Словарь сопоставляет текст ЦЕЛИКОМ, поэтому расхождение в один символ —
    это перевод, который выглядит существующим и не применяется никогда.
    Так и накопилось:

        разметка: «Инциденты с принятым решением: вердикт, статус, …»
        словарь : «Инциденты с принятым решением: verdict, статус, …»

    Промах возник оттого, что ключи снимались с ЭКРАНА, а на экране i18n уже
    успел перевести отдельный сегмент («вердикт» → «verdict»): у него есть
    запасной проход по кускам между разделителями. Плюс обрезка длинной
    строки сканером и несовпадение регистра.

    Проверка ловит ровно этот класс: строка разметки, для которой точного
    ключа нет, но есть очень похожий.
    """
    import difflib
    print("\n-- ключи, почти совпадающие с разметкой --")
    js = open(os.path.join(_ROOT, "static", "i18n.js"), encoding="utf-8").read()
    keys = [k for k, _ in parse_dict(js)]
    markup = "".join(open(p, encoding="utf-8").read()
                     for p in glob.glob(os.path.join(_ROOT, "templates", "**", "*.html"),
                                        recursive=True))
    # Сравнивать надо с тем, что окажется в DOM: браузер декодирует сущности
    # (&amp; -> &), а i18n нормализует типографские кавычки. Без этого проверка
    # ругалась бы на «ATT&amp;CK» против «ATT&CK» — перевод при этом рабочий.
    import html as _html
    markup = _html.unescape(markup).replace("\u2019", "'").replace("\u2018", "'")

    cands = set()
    for m in re.finditer(r"class=page-sub>([^<]{20,140})<", markup):
        cands.add(m.group(1).strip())
    for m in re.finditer(r'title="([^"]{20,140})"', markup):
        cands.add(m.group(1).strip())

    bad = []
    for c in cands:
        if not re.search(r"[А-Яа-яЁё]", c) or c in keys:
            continue
        close = difflib.get_close_matches(c, keys, n=1, cutoff=0.86)
        if close:
            bad.append(f"разметка «{c[:52]}…» vs словарь «{close[0][:52]}…»")
    check("нет ключей, почти совпадающих с разметкой", not bad, "; ".join(bad[:3]))


def main():
    print("=" * 68)
    print("  СЛОВАРЬ ПЕРЕВОДА ↔ ПРАВИЛА ДЕТЕКТИРОВАНИЯ")
    print("=" * 68)

    rules = [json.load(open(f, encoding="utf-8"))
             for f in sorted(glob.glob("detections/*.json"))]
    titles = {r["title"] for r in rules}

    js = open(os.path.join("static", "i18n.js"), encoding="utf-8").read()
    pairs = parse_dict(js)
    dic = dict(pairs)
    print(f"  правил: {len(rules)} | записей в словаре: {len(pairs)}")
    test_no_near_miss_keys()

    print("-" * 68)

    # 1. каждое правило переведено
    missing = sorted(titles - set(dic))
    check("у каждого правила есть перевод названия", not missing,
          "нет перевода: " + "; ".join(missing[:5]) if missing else "")

    # 2. нет мёртвых переводов правил
    # (эвристика: русская строка, которой нет ни в правилах, ни в разметке)
    # Строки интерфейса живут не только в разметке: часть собирается на
    # сервере (console.py / webapp.py) и часть — в браузере (static/ui.js).
    # Ищем во всех этих источниках, иначе живые переводы попадут в «мёртвые».
    tpl = ""
    for pat in (os.path.join("templates", "*", "*.html"),
                os.path.join("static", "*.js"),
                "console.py", "webapp.py"):
        for f in glob.glob(pat):
            tpl += open(f, encoding="utf-8").read()
    # Сравниваем по СХЛОПНУТЫМ пробелам: в разметке длинная фраза перенесена
    # на несколько строк, и дословный поиск подстроки её не находит. Ровно так
    # же сопоставляет и сам i18n.js — «по очищенному от пробелов тексту».
    tpl = re.sub(r"\s+", " ", tpl)
    cyr = re.compile("[А-Яа-яЁё]")
    dead = [ru for ru in dic
            if cyr.search(ru) and ru not in titles
            and re.sub(r"\s+", " ", ru) not in tpl
            and len(ru) > 25]
    check("нет мёртвых переводов длинных строк", not dead,
          "не встречаются ни в правилах, ни в разметке: "
          + "; ".join(dead[:5]) if dead else "")

    # 3. дубли ключей
    cnt = collections.Counter(k for k, _ in pairs)
    dups = [k for k, c in cnt.items() if c > 1]
    check("нет дублирующихся ключей", not dups,
          "дубли (в JS второй молча затирает первый): " + "; ".join(dups[:5])
          if dups else "")

    # 4. переводы осмысленные
    empty = [k for k, v in dic.items() if not v.strip()]
    same = [k for k, v in dic.items() if k == v and cyr.search(k)]
    check("нет пустых переводов", not empty, "; ".join(empty[:5]) if empty else "")
    check("русские строки не переведены сами в себя", not same,
          "; ".join(same[:5]) if same else "")

    # 5. данные не переводятся
    forbidden = []
    for k in dic:
        if re.fullmatch(r"T\d{4}(\.\d{3})?", k):
            forbidden.append(k)                       # ID техники ATT&CK
        if re.fullmatch(r"[a-z][a-z.\-]+\.[a-z]+", k) and "." in k:
            forbidden.append(k)                       # логин или имя репозитория
    check("в словарь не попали данные (техники, логины, репозитории)",
          not forbidden, "; ".join(forbidden[:5]) if forbidden else "")

    print("-" * 68)
    if fails:
        print(f"  {BAD} ПРОВАЛЕНО: {len(fails)}")
        print()
        print("  Как чинить: добавь строку в static/i18n.js в блок")
        print("  «названия правил детектирования» рядом с остальными.")
        return 1
    print(f"  {OK} Словарь синхронен с правилами: {len(titles)} названий переведены.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
