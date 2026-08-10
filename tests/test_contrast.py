"""
Проверка контраста интерфейса по WCAG 2.1 AA.

Читает токены из static/design-system.css и считает контраст для всех
сочетаний «текст на фоне», которые реально встречаются в консолях, —
отдельно для тёмной и светлой темы.

Пороги WCAG 2.1 AA:
  4.5 : обычный текст (меньше 18pt / 14pt жирного)
  3.0 : крупный текст и графические элементы (иконки, полосы, точки)

Тест нужен потому, что палитру легко «улучшить» на глаз и незаметно
уронить читаемость: жёлтый и зелёный на белом фоне проваливают порог
почти всегда, а приглушённый серый — на тёмном.

Токены могут ссылаться друг на друга через var(--x) — псевдонимы
раскрываются рекурсивно, иначе тест видит строку вместо цвета и
молча пропускает пару.
"""
import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSS = os.path.join(ROOT, "static", "design-system.css")

THEMES = {
    ":root": "тёмная",
    '[data-theme="light"]': "светлая",
}

# Фоны, на которых вообще может оказаться текст.
BACKGROUNDS = ["--bg", "--surface-1", "--surface-2", "--surface-3", "--surface-4"]

# Токены текста: проверяются на КАЖДОМ фоне из списка выше.
TEXT_TOKENS = [
    ("--text-1", "основной текст"),
    ("--text-2", "вторичный текст"),
    ("--text-3", "приглушённый текст"),
    ("--accent-text", "акцент как текст"),
    ("--sev-critical", "уровень critical текстом"),
    ("--sev-high", "уровень high текстом"),
    ("--sev-medium", "уровень medium текстом"),
    ("--sev-low", "уровень low текстом"),
    ("--success", "успех текстом"),
]

# Графика: заливка кнопки, полоса, точка. Порог 3:1.
GRAPHIC_PAIRS = [
    ("--accent", "--bg", "акцент как заливка на полотне"),
    ("--accent", "--surface-2", "акцент как заливка на карточке"),
]


def _raw_tokens():
    css = io.open(CSS, encoding="utf-8").read()
    out = {}
    for sel in THEMES:
        i = css.index(sel + "{")
        j = css.index("\n}", i)
        block = css[i:j]
        # комментарии внутри блока не должны попадать в значения
        block = re.sub(r"/\*.*?\*/", "", block, flags=re.S)
        out[sel] = dict(re.findall(r"(--[\w-]+)\s*:\s*([^;]+);", block))
    return out


def _resolve(name, theme, root, depth=0):
    """Раскрывает var(--x) до конкретного цвета."""
    if depth > 8:
        return None
    val = theme.get(name, root.get(name))
    if val is None:
        return None
    val = val.strip()
    m = re.match(r"^var\(\s*(--[\w-]+)\s*\)$", val)
    if m:
        return _resolve(m.group(1), theme, root, depth + 1)
    return val


def _rgb(v):
    v = (v or "").strip()
    m = re.match(r"^#([0-9a-fA-F]{6})$", v)
    if m:
        h = m.group(1)
        return tuple(int(h[k:k + 2], 16) for k in (0, 2, 4))
    m = re.match(r"^#([0-9a-fA-F]{3})$", v)
    if m:
        h = m.group(1)
        return tuple(int(h[k] * 2, 16) for k in (0, 1, 2))
    m = re.match(r"^rgba?\(([^)]+)\)$", v)
    if m:
        parts = [x.strip() for x in m.group(1).split(",")]
        return tuple(int(float(x)) for x in parts[:3])
    return None


def _lum(c):
    def ch(x):
        x /= 255.0
        return x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4
    r, g, b = map(ch, c)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a, b):
    la, lb = _lum(a), _lum(b)
    if la < lb:
        la, lb = lb, la
    return (la + 0.05) / (lb + 0.05)


def main():
    T = _raw_tokens()
    root = T[":root"]
    fails = []
    unresolved = []
    print("=" * 62)
    print("  КОНТРАСТ ИНТЕРФЕЙСА — WCAG 2.1 AA")
    print("=" * 62)

    for sel, label in THEMES.items():
        theme = T[sel]
        print("\n  тема: %s" % label)
        worst = (99.0, "")
        checked = 0

        for fg, what in TEXT_TOKENS:
            a = _rgb(_resolve(fg, theme, root))
            if not a:
                unresolved.append((label, fg))
                continue
            for bgname in BACKGROUNDS:
                b = _rgb(_resolve(bgname, theme, root))
                if not b:
                    unresolved.append((label, bgname))
                    continue
                r = contrast(a, b)
                checked += 1
                if r < worst[0]:
                    worst = (r, "%s на %s" % (what, bgname))
                if r < 4.5:
                    fails.append((label, "%s на %s" % (what, bgname), r, 4.5))

        for fg, bgname, what in GRAPHIC_PAIRS:
            a = _rgb(_resolve(fg, theme, root))
            b = _rgb(_resolve(bgname, theme, root))
            if not a or not b:
                unresolved.append((label, fg + "/" + bgname))
                continue
            r = contrast(a, b)
            checked += 1
            if r < 3.0:
                fails.append((label, what, r, 3.0))
            print("    %-5s %5.2f (нужно 3.0)  %s"
                  % ("OK" if r >= 3.0 else "НИЗКО", r, what))

        print("    проверено пар текста: %d, худшая: %.2f — %s"
              % (checked - len(GRAPHIC_PAIRS), worst[0], worst[1]))

    print("\n" + "=" * 62)
    if unresolved:
        print("  токены не разобраны: %d" % len(unresolved))
        for label, name in unresolved[:10]:
            print("     %s — %s" % (label, name))
        return 1
    if fails:
        print("  НИЖЕ ПОРОГА AA: %d" % len(fails))
        for label, what, r, need in fails:
            print("     %s — %s: %.2f < %.1f" % (label, what, r, need))
        return 1
    print("  ВСЕ СОЧЕТАНИЯ ПРОХОДЯТ WCAG 2.1 AA")
    return 0


if __name__ == "__main__":
    sys.exit(main())
