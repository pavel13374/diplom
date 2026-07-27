"""
Проверка контраста интерфейса по WCAG 2.1 AA.

Читает токены из static/design-system.css и считает контраст для всех
сочетаний «текст на фоне», которые реально встречаются в консолях, —
отдельно для тёмной, светлой и яркой темы.

Пороги WCAG 2.1 AA:
  4.5 : обычный текст (меньше 18pt / 14pt жирного)
  3.0 : крупный текст и графические элементы (иконки, полосы, точки)

Тест нужен потому, что палитру легко «улучшить» на глаз и незаметно
уронить читаемость: жёлтый и зелёный на белом фоне проваливают порог
почти всегда, а приглушённый серый — на тёмном.
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
    '[data-theme="bright"]': "яркая",
}

# (токен текста, токен фона, порог, описание)
PAIRS = [
    ("--text-1", "--bg", 4.5, "основной текст на полотне"),
    ("--text-1", "--surface-2", 4.5, "основной текст на карточке"),
    ("--text-1", "--surface-3", 4.5, "основной текст на вложенном блоке"),
    ("--text-2", "--surface-2", 4.5, "вторичный текст на карточке"),
    ("--text-2", "--surface-3", 4.5, "вторичный текст на вложенном блоке"),
    ("--text-3", "--surface-2", 4.5, "приглушённый текст на карточке"),
    ("--text-3", "--surface-1", 4.5, "приглушённый текст в сайдбаре"),
    ("--text-4", "--surface-2", 4.5, "метаданные на карточке"),
    ("--critical", "--surface-2", 4.5, "критичный уровень текстом"),
    ("--high", "--surface-2", 4.5, "высокий уровень текстом"),
    ("--warning", "--surface-2", 4.5, "средний уровень текстом"),
    ("--success", "--surface-2", 4.5, "успех текстом"),
    ("--info", "--surface-2", 4.5, "информация текстом"),
    ("--accent-brand", "--surface-2", 3.0, "акцент как графика"),
    ("--sev-critical", "--surface-2", 3.0, "метка critical"),
    ("--sev-high", "--surface-2", 3.0, "метка high"),
    ("--sev-medium", "--surface-2", 3.0, "метка medium"),
    ("--sev-low", "--surface-2", 3.0, "метка low"),
    ("--layer-ueba", "--surface-2", 3.0, "слой UEBA"),
    ("--layer-rule", "--surface-2", 3.0, "слой правил"),
    ("--layer-signature", "--surface-2", 3.0, "слой сигнатур"),
    ("--layer-ml", "--surface-2", 3.0, "слой ML"),
]


def _tokens():
    css = io.open(CSS, encoding="utf-8").read()
    out = {}
    for sel in THEMES:
        i = css.index(sel + "{")
        j = css.index("}", i)
        out[sel] = dict(re.findall(r"(--[\w-]+):\s*([^;]+);", css[i:j]))
    return out


def _rgb(v):
    v = (v or "").strip()
    m = re.match(r"^#([0-9a-fA-F]{6})$", v)
    if m:
        h = m.group(1)
        return tuple(int(h[k:k + 2], 16) for k in (0, 2, 4))
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
    T = _tokens()
    root = T[":root"]
    fails = []
    print("=" * 62)
    print("  КОНТРАСТ ИНТЕРФЕЙСА — WCAG 2.1 AA")
    print("=" * 62)
    for sel, label in THEMES.items():
        print("\n  тема: %s" % label)
        for fg, bg, need, what in PAIRS:
            a = _rgb(T[sel].get(fg) or root.get(fg))
            b = _rgb(T[sel].get(bg) or root.get(bg))
            if not a or not b:
                print("    ??    токен не разобран: %s / %s" % (fg, bg))
                fails.append((label, what, 0.0, need))
                continue
            r = contrast(a, b)
            ok = r >= need
            if not ok:
                fails.append((label, what, r, need))
            print("    %s %5.2f (нужно %.1f)  %s"
                  % ("OK   " if ok else "НИЗКО", r, need, what))
    print("\n" + "=" * 62)
    if fails:
        print("  ❌ ниже порога AA: %d" % len(fails))
        for label, what, r, need in fails:
            print("     %s — %s: %.2f < %.1f" % (label, what, r, need))
        return 1
    print("  ✅ все сочетания проходят WCAG 2.1 AA")
    return 0


if __name__ == "__main__":
    sys.exit(main())
