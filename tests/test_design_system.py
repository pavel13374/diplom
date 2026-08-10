"""
Проверка, что дизайн-система остаётся системой.

Каждое правило здесь появилось после конкретной поломки, а не из вкуса.
Раньше интерфейс выглядел сгенерированным ровно потому, что ограничений
не было: любой элемент мог получить любой размер, цвет и скругление.

Что проверяем:
  1. В шаблонах нет блоков <style> — иначе они молча проигрывают
     design-system.css, который подключается ниже, и половина правил
     становится мёртвым кодом (было 105 из 166 селекторов).
  2. В шаблонах нет хардкод-цветов — их набралось 112 уникальных.
  3. Нет градиентов — было 15 штук «из цвета в тот же цвет»: следы
     механической замены хекса на токены.
  4. Нет эмодзи — они рендерятся системным цветным шрифтом, не слушаются
     currentColor и ломают строку.
  5. Нет @keyframes и transform на ховере — подъёмы карточек и затухание
     при переключении вкладки читались как подтормаживание.
  6. Шкала размеров и радиусов в CSS ограничена.
  7. Объявленные шрифты действительно лежат в static/fonts.
  8. Моноширинный шрифт применён ограниченно.
"""
import io
import os
import re
import sys
import glob

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSS = os.path.join(ROOT, "static", "design-system.css")
TEMPLATES = sorted(glob.glob(os.path.join(ROOT, "templates", "**", "*.html"),
                             recursive=True))

# Разрешённые размеры шрифта в CSS: шкала плюс служебные величины,
# которые не являются текстом интерфейса (иконки, засечки графиков).
# Шкала v11 «OPERATOR»: плотный инженерный интерфейс.
ALLOWED_FONT_SIZES = {"10px", "11px", "12px", "13px", "16px", "20px", "26px",
                      "9px", ".94em", "inherit"}
# Радиусов два: --r = 6px у панели и --r-ctl = 4px у контрола. Плюс круг,
# пилюля и 3px у совсем мелких образцов цвета в легенде — там 4px на
# квадрате 14×14 читается как овал.
#
# Три пикселя, стоявшие здесь раньше, были попыткой «не скруглять
# вообще». На плотной сетке из полусотни прямоугольников это давало
# решётку, в которой глазу не за что зацепиться: границы соседних
# блоков сливались. Шести пикселей достаточно, чтобы блок опознавался
# отдельным объектом, и мало, чтобы экран стал набором пилюль.
ALLOWED_RADII = {"6px", "4px", "3px", "2px", "999px", "50%", "0"}
ALLOWED_WEIGHTS = {"400", "500", "600", "inherit", "normal", "bold"}

EMOJI = re.compile("[\U0001F300-\U0001FAFF\u2600-\u27BF\u2B00-\u2BFF]")


def read(p):
    return io.open(p, encoding="utf-8").read()


def strip_comments(css):
    return re.sub(r"/\*.*?\*/", "", css, flags=re.S)


def head_of(html):
    i = html.lower().find("</head>")
    return html[:i] if i > 0 else html


def main():
    fails = []
    notes = []
    css = read(CSS)
    css_nc = strip_comments(css)

    print("=" * 70)
    print("  ДИЗАЙН-СИСТЕМА: ограничения")
    print("=" * 70)

    def check(ok, title, detail=""):
        print("  %-5s %s" % ("OK" if ok else "ПЛОХО", title))
        if not ok:
            fails.append(title)
            if detail:
                print("        " + detail)

    # 1. блоки <style> в head шаблонов
    bad = []
    for t in TEMPLATES:
        if re.search(r"<style[^>]*>", head_of(read(t))):
            bad.append(os.path.relpath(t, ROOT))
    check(not bad, "в шаблонах нет блоков <style>", ", ".join(bad))

    # 2. хардкод-цвета в шаблонах. Исключение одно: RPT_CSS — стили
    #    печатного отчёта, он открывается отдельным документом, где
    #    переменных дизайн-системы просто нет.
    bad = []
    for t in TEMPLATES:
        html = read(t)
        html = re.sub(r"const RPT_CSS=.*?;\n", "", html, flags=re.S)
        found = re.findall(r"(?<!&)#[0-9a-fA-F]{3,8}\b", html)
        found = [c for c in found if not re.fullmatch(r"#\d{4}", c)]
        if found:
            bad.append("%s: %s" % (os.path.relpath(t, ROOT), ", ".join(sorted(set(found))[:6])))
    check(not bad, "в шаблонах нет хардкод-цветов (кроме печатного отчёта)", "; ".join(bad))

    # 3. градиенты
    bad = [os.path.relpath(t, ROOT) for t in TEMPLATES if "gradient(" in read(t)]
    check(not bad, "в шаблонах нет градиентов", ", ".join(bad))

    # Градиент как ЦВЕТ запрещён. Как маска (затухание у края прокрутки)
    # это не заливка, а подсказка о том, что область скроллится.
    grads = re.findall(r"background(?:-image)?\s*:[^;}]*(?:linear|radial)-gradient\(", css_nc)
    check(len(grads) <= 1,
          "в CSS не больше одного цветового градиента (индикатор уровня high)",
          "найдено: %d" % len(grads))

    # 4. эмодзи
    bad = []
    for t in TEMPLATES + [os.path.join(ROOT, "static", "i18n.js"),
                          os.path.join(ROOT, "static", "ui.js")]:
        if not os.path.exists(t):
            continue
        src = read(t)
        found = set(EMOJI.findall(src))
        # Стрелка внутри фразы — нормальная типографика («токен → вынос»).
        # Ловим только стрелку НА ГРАНИЦЕ ТЕГА, то есть в роли иконки.
        found |= set(re.findall(r">\s*([←→⬇▶↗⇅↑▲▾])|([←→⬇▶↗⇅↑▲▾])\s*<", src)[0]
                     if False else [])
        icons = re.findall(r">\s*[←→⬇▶↗⇅↑▲▾]|[←→⬇▶↗⇅↑▲▾]\s*<", src)
        if found or icons:
            bad.append("%s: %s" % (os.path.relpath(t, ROOT),
                                   " ".join(sorted(found)[:8]) + (" (иконкой: %d)" % len(icons) if icons else "")))
    check(not bad, "нет эмодзи; стрелки не используются вместо иконок", "; ".join(bad))

    # 5. движение
    kf = re.findall(r"@keyframes\s+([\w-]+)", css_nc)
    check(not kf, "в CSS нет @keyframes", ", ".join(kf))

    # transform:none — защитный сброс, он как раз и убирает подъёмы.
    hovers = [m.group(0) for m in re.finditer(r":hover[^{}]*\{[^}]*?transform\s*:\s*([^;}]+)", css_nc)
              if m.group(1).strip() != "none"]
    check(not hovers, "нет подъёмов и масштабирования на ховере",
          "найдено: %d" % len(hovers))

    # 6. шкала
    sizes = set(re.findall(r"font-size\s*:\s*([^;}\s]+)", css_nc))
    sizes = {s for s in sizes if not s.startswith("var(")}
    extra = sizes - ALLOWED_FONT_SIZES
    check(not extra, "размеры шрифта в CSS не выходят за шкалу",
          "лишние: " + ", ".join(sorted(extra)))

    radii = set(re.findall(r"border-radius\s*:\s*([^;}]+)", css_nc))
    # Значения, собранные из токена (var(--r), calc(var(--r) - 1px) для
    # внутреннего угла вложенной шапки), системе не противоречат —
    # проверяем только литералы.
    radii = {r.strip() for r in radii
             if not r.strip().startswith("var(") and "var(--r" not in r}
    extra = {r for r in radii if r not in ALLOWED_RADII}
    check(not extra, "радиусы в CSS не выходят за набор",
          "лишние: " + ", ".join(sorted(extra)))

    # @font-face объявляет диапазон вариативного шрифта (100 900) —
    # это не начертание текста, блоки исключаем.
    css_nofaces = re.sub(r"@font-face\s*\{[^}]*\}", "", css_nc, flags=re.S)
    weights = set(re.findall(r"font-weight\s*:\s*([^;}\s]+)", css_nofaces))
    weights = {w for w in weights if not w.startswith("var(")}
    extra = weights - ALLOWED_WEIGHTS
    check(not extra, "начертания только 400 / 500 / 600",
          "лишние: " + ", ".join(sorted(extra)))

    # 7. шрифты лежат на диске
    srcs = re.findall(r"url\('(/static/fonts/[^']+)'\)", css)
    missing = [u for u in srcs
               if not os.path.exists(os.path.join(ROOT, u.lstrip("/")))]
    check(srcs and not missing,
          "объявленные @font-face лежат в static/fonts (%d шт.)" % len(srcs),
          "нет файлов: " + ", ".join(missing))

    # 8. Моноширинный ограничен техническими значениями.
    #    Критерий: символы, которые сравнивают глазами или выравнивают
    #    в колонку — ID техники, хэш, путь, IP, timestamp, тело лога,
    #    значение риска. Русские слова, статусы и подписи — нет.
    #    Потолок держит общий объём, а список ниже ловит настоящий
    #    регресс: моноширинный на контейнере обычного текста.
    # Потолок держит долю моноширинного: когда им набрано 45% интерфейса,
    # продукт читается как терминал. Сорок мест — это ровно технические
    # поля: идентификаторы, хэши, пути, время в логе, ID техник ATT&CK.
    mono = len(re.findall(r"var\(--font-mono\)", css_nc))
    check(mono <= 40, "моноширинный шрифт применён ограниченно",
          "использований: %d (потолок 40)" % mono)

    PROSE = ["body", ".sub", ".page-sub", ".help", ".hint", ".explain",
             ".card>h2", ".lead", ".assum", ".note", ".t-body", ".ds-tl-title",
             ".m-name", ".g-tt", ".kpi .l", "label"]
    bad = []
    for m in re.finditer(r"([^{}]+)\{([^}]*)\}", css_nc):
        if "var(--font-mono)" not in m.group(2):
            continue
        sels = [x.strip() for x in m.group(1).split(",")]
        for p in PROSE:
            if p in sels:
                bad.append(p)
    check(not bad, "моноширинный не назначен контейнерам обычного текста",
          ", ".join(sorted(set(bad))))

    # 9. у каждого тега не больше одного атрибута class
    bad = []
    for t in TEMPLATES:
        if re.search(r"<[a-zA-Z][^<>]*\sclass=[^<>]*\sclass=", read(t)):
            bad.append(os.path.relpath(t, ROOT))
    check(not bad, "нет тегов с двумя атрибутами class", ", ".join(bad))

    # 10. пояснительные простыни поверх контента
    bad = []
    for t in TEMPLATES:
        html = read(t)
        for m in re.finditer(r"<b>(Что это|Откуда|Что делать|Как читать)\.</b>", html):
            bad.append(os.path.relpath(t, ROOT))
            break
    check(not bad, "нет баннеров «Что это. Откуда. Что делать.»", ", ".join(bad))

    # 11. classList.add с тернарником, способным вернуть пустую строку.
    #     Пустой токен бросает DOMException и обрывает весь цикл
    #     обновления: половина экрана навсегда остаётся прочерками.
    #     Ровно так и было в панели «Запись в GitLab».
    bad = []
    for t in TEMPLATES:
        for m in re.finditer(r"classList\.add\(([^)]*)\)", read(t)):
            arg = m.group(1)
            if "?" in arg and ("''" in arg or '""' in arg):
                bad.append("%s: %s" % (os.path.relpath(t, ROOT), arg[:60]))
    check(not bad, "classList.add не может получить пустой класс", "; ".join(bad))

    # 12. Молчаливый catch. Если опрос падает без единого следа, поломку
    #     замечают уже на защите, а не в консоли браузера.
    #     Соглашение: `catch(e)` обязан сообщить об ошибке, `catch(x)` —
    #     осознанно проглоченная (внутри самого репортёра, чтобы он не
    #     падал сам). Поэтому ищем именно `catch(e){}`.
    bad = []
    for t in TEMPLATES:
        src = re.sub(r"/\*.*?\*/", "", read(t), flags=re.S)
        n = len(re.findall(r"catch\s*\(\s*e\s*\)\s*\{\s*\}", src))
        if n:
            bad.append("%s: %d" % (os.path.relpath(t, ROOT), n))
    check(not bad, "нет молчаливых catch(e): ошибка обязана попадать в консоль",
          "; ".join(bad))

    # 13. Сырые идентификаторы в подписях. snake_case в тексте кнопки или
    #     заголовка — это утечка внутреннего ключа наружу.
    bad = []
    for t in TEMPLATES:
        for m in re.finditer(r">\s*([a-z]+_[a-z_]+)\s*<", read(t)):
            bad.append("%s: %s" % (os.path.relpath(t, ROOT), m.group(1)))
    check(not bad, "в подписях нет сырых snake_case-идентификаторов",
          "; ".join(sorted(set(bad))[:8]))

    print("-" * 70)
    for n in notes:
        print("  " + n)
    if fails:
        print("  ПРОВАЛЕНО: %d" % len(fails))
        for f in fails:
            print("     - " + f)
        return 1
    print("  Дизайн-система в границах.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
