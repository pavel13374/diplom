#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PDF-отчёты по инцидентам и полный отчёт прогона (для приложения к диплому).
Кириллица через DejaVu (в комплекте reportlab). Без внешних сервисов.
"""
import io
import datetime as _dt

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
                                HRFlowable)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

_ACCENT = colors.HexColor("#7c3aed")
_INK = colors.HexColor("#1f2733")
_SOFT = colors.HexColor("#6b7480")
_LINE = colors.HexColor("#e4e8f0")

_FONTS_READY = False


def _fonts():
    global _FONTS_READY
    if _FONTS_READY:
        return "DejaVu", "DejaVu-Bold", "DejaVu-Mono"
    cands = ["/usr/share/fonts/truetype/dejavu/",
             "C:/Windows/Fonts/", "/Library/Fonts/", "/usr/share/fonts/"]
    def find(name):
        import os
        for d in cands:
            p = os.path.join(d, name)
            if os.path.exists(p):
                return p
        return None
    try:
        reg = find("DejaVuSans.ttf"); bold = find("DejaVuSans-Bold.ttf"); mono = find("DejaVuSansMono.ttf")
        if reg:
            pdfmetrics.registerFont(TTFont("DejaVu", reg))
            pdfmetrics.registerFont(TTFont("DejaVu-Bold", bold or reg))
            pdfmetrics.registerFont(TTFont("DejaVu-Mono", mono or reg))
            _FONTS_READY = True
            return "DejaVu", "DejaVu-Bold", "DejaVu-Mono"
    except Exception:
        pass
    return "Helvetica", "Helvetica-Bold", "Courier"


def _styles():
    reg, bold, mono = _fonts()
    getSampleStyleSheet()
    st = {
        "h1": ParagraphStyle("h1", fontName=bold, fontSize=19, textColor=_INK, leading=23, spaceAfter=4),
        "h2": ParagraphStyle("h2", fontName=bold, fontSize=13, textColor=_ACCENT, leading=17, spaceBefore=12, spaceAfter=5),
        "p": ParagraphStyle("p", fontName=reg, fontSize=10, textColor=_INK, leading=15),
        "soft": ParagraphStyle("soft", fontName=reg, fontSize=9, textColor=_SOFT, leading=13),
        "mono": ParagraphStyle("mono", fontName=mono, fontSize=8.5, textColor=_INK, leading=12),
        "cell": ParagraphStyle("cell", fontName=reg, fontSize=9, textColor=_INK, leading=12),
        "cellb": ParagraphStyle("cellb", fontName=bold, fontSize=9, textColor=_INK, leading=12),
    }
    return st, (reg, bold, mono)


def _header_footer(canvas, doc):
    canvas.saveState()
    reg, bold, mono = _fonts()
    canvas.setFillColor(_ACCENT)
    canvas.rect(0, A4[1] - 8, A4[0], 8, fill=1, stroke=0)
    canvas.setFont(reg, 8)
    canvas.setFillColor(_SOFT)
    canvas.drawString(18 * mm, 12 * mm, "SOC Purple-Team Platform · отчёт сгенерирован платформой")
    canvas.drawRightString(A4[0] - 18 * mm, 12 * mm, "стр. %d" % doc.page)
    canvas.restoreState()


def _sev_color(sev):
    return {"critical": colors.HexColor("#b91c1c"), "high": colors.HexColor("#b45309"),
            "medium": colors.HexColor("#1d4ed8"), "low": colors.HexColor("#6b7480")}.get(sev, _SOFT)


def _doc(buf, title):
    return SimpleDocTemplate(buf, pagesize=A4, title=title,
                             leftMargin=18 * mm, rightMargin=18 * mm,
                             topMargin=20 * mm, bottomMargin=20 * mm)


def incident_pdf(iid, inc, ctx):
    st, _ = _styles()
    buf = io.BytesIO()
    doc = _doc(buf, f"Инцидент #{iid}")
    E = []
    E.append(Paragraph(f"Инцидент #{iid}", st["h1"]))
    E.append(Paragraph(f"Актор: <b>{inc.get('actor','?')}</b> · "
                       f"дата: {_dt.datetime.now().strftime('%Y-%m-%d %H:%M')}", st["soft"]))
    E.append(Spacer(1, 4))
    E.append(HRFlowable(width="100%", color=_LINE, thickness=1))

    tr = inc.get("triage") or {}
    sev = inc.get("severity", "—")
    rows = [
        [Paragraph("Severity", st["cellb"]), Paragraph(str(sev), st["cell"])],
        [Paragraph("Max risk", st["cellb"]), Paragraph(str(round(inc.get("max_risk", 0), 2)), st["cell"])],
        [Paragraph("Алертов", st["cellb"]), Paragraph(str(len(inc.get("alerts", []))), st["cell"])],
        [Paragraph("Многошаговая", st["cellb"]), Paragraph("да" if inc.get("is_campaign") else "нет", st["cell"])],
        [Paragraph("Репозитории", st["cellb"]), Paragraph(", ".join(inc.get("repos", [])) or "—", st["cell"])],
        [Paragraph("Тактики ATT&CK", st["cellb"]), Paragraph(", ".join(inc.get("tactics", [])) or "—", st["cell"])],
    ]
    t = Table(rows, colWidths=[38 * mm, 130 * mm])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, _LINE),
                           ("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f6f8fc")),
                           ("ROWBACKGROUNDS", (1, 0), (1, -1), [colors.white])]))
    E.append(Spacer(1, 8)); E.append(t)

    E.append(Paragraph("Вердикт (LLM-триаж)", st["h2"]))
    if tr:
        E.append(Paragraph(f"<b>{tr.get('title','—')}</b> · источник: {tr.get('_source','?')} · "
                           f"TP: {'да' if tr.get('is_true_positive') else 'нет'} · "
                           f"confidence {tr.get('confidence','—')}", st["p"]))
        E.append(Spacer(1, 3))
        E.append(Paragraph(tr.get("narrative", "—"), st["p"]))
        acts = tr.get("recommended_actions") or []
        if acts:
            E.append(Spacer(1, 4))
            E.append(Paragraph("Рекомендованные действия:", st["cellb"]))
            for a in acts:
                E.append(Paragraph("• " + str(a), st["p"]))
    else:
        E.append(Paragraph("Триаж ещё не запускался.", st["soft"]))

    E.append(Paragraph("ATT&CK kill-chain", st["h2"]))
    ch = inc.get("chain", [])
    if ch:
        data = [[Paragraph("№", st["cellb"]), Paragraph("Время", st["cellb"]),
                 Paragraph("Тактика", st["cellb"]), Paragraph("Техника", st["cellb"]),
                 Paragraph("Действие", st["cellb"]), Paragraph("Risk", st["cellb"])]]
        for n, c in enumerate(ch, 1):
            data.append([Paragraph(str(n), st["cell"]),
                         Paragraph((c.get("ts", "") or "").replace("T", " ")[5:16], st["cell"]),
                         Paragraph(c.get("tactic", "") or "", st["cell"]),
                         Paragraph(c.get("technique", "") or "", st["mono"]),
                         Paragraph(c.get("action", "") or "", st["cell"]),
                         Paragraph(str(c.get("risk", "")), st["cell"])])
        t2 = Table(data, colWidths=[8 * mm, 24 * mm, 34 * mm, 26 * mm, 54 * mm, 14 * mm], repeatRows=1)
        t2.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, _LINE),
                                ("BACKGROUND", (0, 0), (-1, 0), _ACCENT),
                                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                                ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        E.append(t2)
    else:
        E.append(Paragraph("Цепочка пуста.", st["soft"]))

    E.append(Paragraph("Как получен вердикт (прозрачность)", st["h2"]))
    E.append(Paragraph("Контекст для LLM собран только из наблюдаемых blue-полей; метки симулятора "
                       "(campaign_id, is_anomaly, episode_id) не используются — гарантия test_antileak.py. "
                       f"Сигналы контента: энтропия Шеннона {ctx.get('shannon_entropy','—')}, "
                       f"regex-совпадений {ctx.get('n_regex_hits',0)}, "
                       f"плейсхолдер: {'да' if ctx.get('placeholder_signal') else 'нет'}.", st["soft"]))

    doc.build(E, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return buf.getvalue()


def full_pdf(incidents, metrics=None):
    st, _ = _styles()
    buf = io.BytesIO()
    doc = _doc(buf, "SOC — сводный отчёт")
    E = []
    E.append(Paragraph("SOC Purple-Team Platform", st["h1"]))
    E.append(Paragraph("Сводный отчёт прогона · приложение к дипломной работе", st["soft"]))
    E.append(Paragraph(_dt.datetime.now().strftime("%Y-%m-%d %H:%M"), st["soft"]))
    E.append(Spacer(1, 6)); E.append(HRFlowable(width="100%", color=_LINE, thickness=1))

    E.append(Paragraph("Сводные метрики", st["h2"]))
    if metrics:
        def pct(v): return f"{round((v or 0) * 100)}%"
        mrows = [
            [Paragraph("Обнаружение атак", st["cellb"]), Paragraph(pct(metrics.get("detection_rate")), st["cell"])],
            [Paragraph("MTTD (сим-мин)", st["cellb"]), Paragraph(str(metrics.get("mttd_sim_min", "—")), st["cell"])],
            [Paragraph("FP-rate", st["cellb"]), Paragraph(pct(metrics.get("fp_rate")), st["cell"])],
            [Paragraph("Покрытие ATT&CK", st["cellb"]), Paragraph(pct(metrics.get("attack_coverage")), st["cell"])],
            [Paragraph("Событий / алертов", st["cellb"]),
             Paragraph(f"{metrics.get('events','—')} / {metrics.get('alerts','—')}", st["cell"])],
        ]
        mt = Table(mrows, colWidths=[50 * mm, 40 * mm])
        mt.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, _LINE),
                                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f6f8fc"))]))
        E.append(mt)
    else:
        E.append(Paragraph("Метрики не рассчитаны (открой «Для комиссии» на :8788 или запусти python metrics.py).", st["soft"]))

    E.append(Paragraph(f"Инциденты ({len(incidents)})", st["h2"]))
    data = [[Paragraph("#", st["cellb"]), Paragraph("Актор", st["cellb"]),
             Paragraph("Severity", st["cellb"]), Paragraph("Risk", st["cellb"]),
             Paragraph("Алертов", st["cellb"]), Paragraph("Тактики", st["cellb"])]]
    for i in sorted(incidents, key=lambda x: -x.get("max_risk", 0))[:60]:
        data.append([Paragraph(str(i["id"]), st["cell"]),
                     Paragraph(i.get("actor", "") or "", st["cell"]),
                     Paragraph(i.get("severity", "") or "", st["cell"]),
                     Paragraph(str(round(i.get("max_risk", 0), 2)), st["cell"]),
                     Paragraph(str(len(i.get("alerts", []))), st["cell"]),
                     Paragraph(", ".join(i.get("tactics", [])[:4]) or "—", st["cell"])])
    t = Table(data, colWidths=[10 * mm, 34 * mm, 22 * mm, 14 * mm, 18 * mm, 72 * mm], repeatRows=1)
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, _LINE),
                           ("BACKGROUND", (0, 0), (-1, 0), _ACCENT),
                           ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                           ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    E.append(t)
    E.append(Spacer(1, 10))
    E.append(Paragraph("Оценка честная: детектор не видит разметку симулятора; метрики считаются "
                       "постфактум сопоставлением алертов с разметкой (анти-лик, test_antileak.py).", st["soft"]))
    doc.build(E, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return buf.getvalue()
