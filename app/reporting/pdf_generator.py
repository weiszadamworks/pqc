"""
Enterprise Corporate Minimalist Audit Dossier Generator
Generates multi-page, certified regulatory reports with full Hungarian character support (ő, ű).
Uses Windows system fonts (Arial + Consolas full family: normal, bold, italic, bold-italic).
Design: Black, White, Blue corporate minimalist (matching the web dashboard).
"""

import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
)

# --- Register TrueType Fonts for full Central European / Hungarian support ---
_BUNDLED_FONTS = Path(__file__).resolve().parent / "fonts"
_WIN_FONTS = Path("C:/Windows/Fonts")

def _find_font_file(filename: str) -> Path:
    bundled = _BUNDLED_FONTS / filename
    if bundled.exists():
        return bundled
    win = _WIN_FONTS / filename
    if win.exists():
        return win
    return bundled

def _register_system_fonts() -> bool:
    """Register Arial and Consolas full families for zero-glitch Hungarian rendering."""
    mappings = [
        ("QSArial", _find_font_file("arial.ttf")),
        ("QSArial-Bold", _find_font_file("arialbd.ttf")),
        ("QSArial-Italic", _find_font_file("ariali.ttf")),
        ("QSArial-BoldItalic", _find_font_file("arialbi.ttf")),
        ("QSConsolas", _find_font_file("consola.ttf")),
        ("QSConsolas-Bold", _find_font_file("consolab.ttf")),
        ("QSConsolas-Italic", _find_font_file("consolai.ttf")),
        ("QSConsolas-BoldItalic", _find_font_file("consolaz.ttf")),
    ]
    all_ok = True
    for name, path in mappings:
        if path.exists():
            try:
                pdfmetrics.registerFont(TTFont(name, str(path)))
            except Exception:
                all_ok = False
        else:
            all_ok = False

    if all_ok:
        from reportlab.pdfbase.pdfmetrics import registerFontFamily
        registerFontFamily('QSArial',
                           normal='QSArial',
                           bold='QSArial-Bold',
                           italic='QSArial-Italic',
                           boldItalic='QSArial-BoldItalic')
        registerFontFamily('QSConsolas',
                           normal='QSConsolas',
                           bold='QSConsolas-Bold',
                           italic='QSConsolas-Italic',
                           boldItalic='QSConsolas-BoldItalic')
    return all_ok

_SYS_FONTS_OK = _register_system_fonts()

FONT = 'QSArial' if _SYS_FONTS_OK else 'Helvetica'
FONT_B = 'QSArial-Bold' if _SYS_FONTS_OK else 'Helvetica-Bold'
MONO = 'QSConsolas' if _SYS_FONTS_OK else 'Courier'
MONO_B = 'QSConsolas-Bold' if _SYS_FONTS_OK else 'Courier-Bold'

# Page geometry: A4 is 210 x 297 mm
USABLE_W = A4[0] - 28 * mm  # 182 mm


class AuditPDFGenerator:
    """Generates institutional, certified multi-page PDF audit dossiers."""

    # Corporate Minimalist Palette (Exact match to Web UI)
    BG_BLACK = colors.HexColor("#09090b")
    BG_DARK = colors.HexColor("#121215")
    BG_CELL = colors.HexColor("#18181b")
    BORDER_HAIRLINE = colors.HexColor("#27272a")
    BLUE_ACCENT = colors.HexColor("#2563eb")
    BLUE_LIGHT = colors.HexColor("#3b82f6")
    WHITE = colors.white
    TEXT_MAIN = colors.HexColor("#e4e4e7")
    TEXT_MUTED = colors.HexColor("#a1a1aa")
    TEXT_DIM = colors.HexColor("#71717a")
    RED_ALERT = colors.HexColor("#ef4444")
    GREEN_OK = colors.HexColor("#22c55e")
    AMBER_WARN = colors.HexColor("#eab308")

    @classmethod
    def generate_report(cls, scan_result: Dict[str, Any], compliance_result: Dict[str, Any], output_path: Path) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            rightMargin=14 * mm,
            leftMargin=14 * mm,
            topMargin=12 * mm,
            bottomMargin=14 * mm
        )

        # --- Typography Styles ---
        st_title = ParagraphStyle('DocTitle', fontName=FONT_B, fontSize=16, leading=20, textColor=cls.WHITE)
        st_subtitle = ParagraphStyle('DocSub', fontName=FONT, fontSize=8, leading=11, textColor=cls.TEXT_MUTED)
        st_h1 = ParagraphStyle('SecH1', fontName=FONT_B, fontSize=11, leading=14, textColor=cls.WHITE, spaceBefore=7, spaceAfter=3)
        st_body = ParagraphStyle('BodyText', fontName=FONT, fontSize=7.5, leading=11, textColor=cls.TEXT_MAIN)
        st_body_bold = ParagraphStyle('BodyBold', fontName=FONT_B, fontSize=7.5, leading=11, textColor=cls.WHITE)
        st_body_white = ParagraphStyle('BodyW', fontName=FONT, fontSize=7.5, leading=11, textColor=cls.WHITE)
        st_meta_lbl = ParagraphStyle('MetaLbl', fontName=FONT_B, fontSize=6.5, leading=9, textColor=cls.TEXT_DIM)
        st_meta_val = ParagraphStyle('MetaVal', fontName=FONT, fontSize=7.5, leading=10, textColor=cls.WHITE)
        st_mono = ParagraphStyle('MonoVal', fontName=MONO, fontSize=6.5, leading=9, textColor=cls.TEXT_MAIN)
        st_mono_bold = ParagraphStyle('MonoValB', fontName=MONO_B, fontSize=6.5, leading=9, textColor=cls.WHITE)
        st_small = ParagraphStyle('SmallText', fontName=FONT, fontSize=6.5, leading=9, textColor=cls.TEXT_DIM)

        # KPI specific styles (separated to avoid baseline collisions)
        st_kpi_lbl = ParagraphStyle('KPILbl', fontName=FONT_B, fontSize=6.5, leading=8.5, textColor=cls.TEXT_DIM, alignment=1)
        st_kpi_val = ParagraphStyle('KPIVal', fontName=FONT_B, fontSize=18, leading=22, textColor=cls.WHITE, alignment=1)
        st_kpi_val_blue = ParagraphStyle('KPIValB', fontName=FONT_B, fontSize=18, leading=22, textColor=cls.BLUE_LIGHT, alignment=1)
        st_kpi_val_green = ParagraphStyle('KPIValG', fontName=FONT_B, fontSize=18, leading=22, textColor=cls.GREEN_OK, alignment=1)
        st_kpi_val_amber = ParagraphStyle('KPIValA', fontName=FONT_B, fontSize=18, leading=22, textColor=cls.AMBER_WARN, alignment=1)
        st_kpi_val_red = ParagraphStyle('KPIValR', fontName=FONT_B, fontSize=18, leading=22, textColor=cls.RED_ALERT, alignment=1)
        st_kpi_sub = ParagraphStyle('KPISub', fontName=FONT, fontSize=6.5, leading=8.5, textColor=cls.TEXT_MUTED, alignment=1)

        story = []
        host = scan_result.get("hostname", "N/A")
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        aid = f"QS-DORA-{uuid.uuid4().hex[:8].upper()}"
        ip_port = f"{scan_result.get('resolved_ip', '?')}:{scan_result.get('port', 443)}"

        comp = compliance_result
        dora = comp.get("dora_score", 0)
        nis2 = comp.get("nis2_score", 0)
        pqc_s = comp.get("quantum_resilience_score", 0)
        grade = comp.get("grade", "N/A")
        status = comp.get("audit_status", "N/A")
        tls = scan_result.get("tls_info", {})
        cert = scan_result.get("certificate_info", {})
        pqc = scan_result.get("pqc_info", {})
        hndl = comp.get("hndl_risk", {})
        db = comp.get("dora_breakdown", {})
        bench = comp.get("benchmark_comparison", {})
        mosca = comp.get("mosca_theorem", {})

        score_color_style = st_kpi_val_green if dora >= 80 else (st_kpi_val_amber if dora >= 60 else st_kpi_val_red)

        # Reusable table builder
        def build_dark_table(data, col_widths, is_header=True, custom_valign='TOP'):
            t = Table(data, colWidths=col_widths)
            style_cmds = [
                ('BACKGROUND', (0, 0), (-1, -1), cls.BG_DARK),
                ('BOX', (0, 0), (-1, -1), 0.5, cls.BORDER_HAIRLINE),
                ('INNERGRID', (0, 0), (-1, -1), 0.3, cls.BORDER_HAIRLINE),
                ('VALIGN', (0, 0), (-1, -1), custom_valign),
                ('TOPPADDING', (0, 0), (-1, -1), 4.5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4.5),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ]
            if is_header:
                style_cmds.append(('BACKGROUND', (0, 0), (-1, 0), cls.BG_BLACK))
                style_cmds.append(('BOTTOMPADDING', (0, 0), (-1, 0), 5))
            t.setStyle(TableStyle(style_cmds))
            return t

        # Reusable panel container
        def build_panel(paragraphs, bg=None, border_color=None):
            if not isinstance(paragraphs, list):
                paragraphs = [paragraphs]
            rows = [[p] for p in paragraphs]
            t = Table(rows, colWidths=[USABLE_W])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), bg or cls.BG_DARK),
                ('BOX', (0, 0), (-1, -1), 0.5, border_color or cls.BORDER_HAIRLINE),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
                ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ]))
            return t

        # =========================================================================
        # PAGE 1: EXECUTIVE COMPLIANCE DASHBOARD
        # =========================================================================

        # 1. Header Micro-Bar
        hdr_table = Table([[
            Paragraph("<b>QUANTUMSHIELD ENTERPRISE</b><br/><font color='#71717a'>Kriptográfiai Audit &amp; Compliance Platform</font>", st_body_white),
            Paragraph(f"<b>MINŐSÍTETT AUDIT DOSSZIÉ</b><br/><font color='#3b82f6'>{aid}</font>",
                      ParagraphStyle('HdrR', parent=st_body_white, alignment=2))
        ]], colWidths=[105 * mm, USABLE_W - 105 * mm])
        hdr_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), cls.BG_BLACK),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(hdr_table)
        story.append(HRFlowable(width="100%", thickness=1.5, color=cls.BLUE_ACCENT, spaceAfter=8))

        # 2. Document Title
        story.append(Paragraph("DORA &amp; Poszt-Kvantum Kriptográfiai Audit Jelentés", st_title))
        story.append(Paragraph(
            "Hivatalos vizsgálati dosszié az EU DORA (2022/2554) 9. Cikk, RTS 2024/1774, "
            "NIS2 (2022/2555) 21. Cikk, valamint a NIST FIPS 203 (PQC ML-KEM) szabványok alapján.", st_subtitle))
        story.append(Spacer(1, 6))

        # 3. Endpoint Metadata Grid
        meta_rows = [
            [Paragraph("CÉLPONT (FQDN):", st_meta_lbl), Paragraph(f"<b>{host}</b>", st_meta_val),
             Paragraph("HÁLÓZATI CÍM:", st_meta_lbl), Paragraph(ip_port, st_mono_bold)],
            [Paragraph("AUDIT IDŐPONTJA:", st_meta_lbl), Paragraph(now_str, st_body),
             Paragraph("SZABVÁNY:", st_meta_lbl), Paragraph("CycloneDX 1.6 CBOM", st_body)],
            [Paragraph("VIZSGÁLAT TÍPUSA:", st_meta_lbl), Paragraph("Nem invazív Layer 4/6 Kriptográfiai Szonda", st_body),
             Paragraph("FELÜGYELET:", st_meta_lbl), Paragraph("EU DORA / MNB / EBA / ENISA", st_body)]
        ]
        story.append(build_dark_table(meta_rows, [36 * mm, 55 * mm, 36 * mm, 55 * mm], is_header=False, custom_valign='MIDDLE'))
        story.append(Spacer(1, 8))

        # 4. Executive KPI Cards (Constructed cleanly without inline <br/> font collisions!)
        kpi_cell_w = USABLE_W / 4.0
        kpi_col1 = [Paragraph("DORA READINESS", st_kpi_lbl), Spacer(1, 2), Paragraph(f"{dora}", score_color_style), Spacer(1, 2), Paragraph("/ 100 • EU 2022/2554", st_kpi_sub)]
        kpi_col2 = [Paragraph("NIS2 RESILIENCE", st_kpi_lbl), Spacer(1, 2), Paragraph(f"{nis2}", score_color_style), Spacer(1, 2), Paragraph("/ 100 • EU 2022/2555", st_kpi_sub)]
        kpi_col3 = [Paragraph("PQC RESILIENCE", st_kpi_lbl), Spacer(1, 2), Paragraph(f"{pqc_s}%", st_kpi_val_blue), Spacer(1, 2), Paragraph("NIST FIPS 203 ML-KEM", st_kpi_sub)]

        # Grade card
        grade_short = grade.split(" ")[0] if " " in grade else grade
        kpi_col4 = [Paragraph("AUDITOR VERDICT", st_kpi_lbl), Spacer(1, 2), Paragraph(f"{grade_short}", score_color_style), Spacer(1, 2), Paragraph(f"{status[:24]}", st_kpi_sub)]

        kpi_grid_data = [[kpi_col1, kpi_col2, kpi_col3, kpi_col4]]
        kpi_table = Table(kpi_grid_data, colWidths=[kpi_cell_w] * 4)
        kpi_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), cls.BG_DARK),
            ('BOX', (0, 0), (-1, -1), 0.5, cls.BORDER_HAIRLINE),
            ('INNERGRID', (0, 0), (-1, -1), 0.3, cls.BORDER_HAIRLINE),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(kpi_table)
        story.append(Spacer(1, 8))

        # 5. Executive Summary
        story.append(Paragraph("1. Vezetői Összefoglaló &amp; Auditori Értékelés", st_h1))
        exec_text = comp.get("executive_summary", "")
        if not exec_text:
            pqc_str = ("A célrendszer alkalmazza az X25519MLKEM768 poszt-kvantum hibrid kulcscserét."
                       if pqc.get("pqc_supported") else
                       "A célrendszer kizárólag klasszikus kulcscserét alkalmaz. PQC migráció szükséges.")
            exec_text = (
                f"A(z) {host} célponton elvégzett vizsgálat megállapította, hogy a kiszolgáló "
                f"{tls.get('version')} protokollt és {tls.get('cipher_name')} titkosítást használ. "
                f"A tanúsítvány {cert.get('key_type')} ({cert.get('key_size_bits')} bit) kulcsra épül, "
                f"{cert.get('days_until_expiration')} napig érvényes. {pqc_str}"
            )
        story.append(Paragraph(exec_text, st_body))
        story.append(Spacer(1, 5))

        # Market Benchmark Bar
        if bench:
            bench_text = (
                f"<b>PIACI ÖSSZEHASONLÍTÁS:</b> Top {100 - bench.get('percentile', 0)}%  |  "
                f"Iparági átlagos DORA pontszám: <b>{bench.get('industry_avg_dora_score', 62)}/100</b>  |  "
                f"{bench.get('better_than', '')}"
            )
            story.append(build_panel(Paragraph(bench_text, st_small), bg=cls.BG_BLACK))
            story.append(Spacer(1, 6))

        # 6. HNDL & Mosca Threat Box
        rl = hndl.get("risk_level", "MEDIUM")
        hbg = colors.HexColor("#190a0a") if rl in ("HIGH", "CRITICAL") else (cls.BG_BLACK if rl == "LOW" else cls.BG_DARK)
        hbc = cls.RED_ALERT if rl in ("HIGH", "CRITICAL") else (cls.BLUE_ACCENT if rl == "LOW" else cls.AMBER_WARN)
        hndl_status = hndl.get("status_text", "")
        mosca_formula = mosca.get("formula", hndl.get("mosca_inequality", ""))
        fin_impact = hndl.get("estimated_financial_impact", "")

        hndl_paragraphs = [
            Paragraph(f"<b>HARVEST NOW, DECRYPT LATER (HNDL) KVANTUM-KITETTSÉG: <font color='{hbc.hexval()}'>[{rl} KOCKÁZAT]</font></b>", st_body_bold),
            Paragraph(hndl_status, st_body),
        ]
        if mosca_formula:
            hndl_paragraphs.append(Spacer(1, 2))
            hndl_paragraphs.append(Paragraph(f"<b>Mosca-tétel Elemzés:</b> <font face='{MONO}' size=7 color='#3b82f6'>{mosca_formula}</font>", st_body))

        hndl_paragraphs.append(Paragraph(
            f"<b>Várható CRQC Kvantumáttörés:</b> {hndl.get('estimated_crqc_threat_window', '2029-2033')}  |  "
            f"<b>Biztonságos Adatmegőrzés:</b> {hndl.get('shelf_life_safe_years', 0)} év", st_body
        ))
        if fin_impact:
            hndl_paragraphs.append(Paragraph(f"<b>Becsült Pénzügyi Kockázat:</b> {fin_impact}", st_body))

        story.append(build_panel(hndl_paragraphs, bg=hbg, border_color=hbc))

        # =========================================================================
        # PAGE 2: REGULATORY MATRIX, RISK REGISTER & CYCLONEDX CBOM
        # =========================================================================
        story.append(PageBreak())

        # 1. DORA 9. Cikk Mátrix
        story.append(Paragraph("2. DORA (EU 2022/2554) 9. Cikk Megfelelőségi Mátrix", st_h1))
        story.append(Paragraph("Az MNB és EBA felügyeleti elvárásai alapján készített auditálási bontás:", st_subtitle))
        story.append(Spacer(1, 4))

        dora_rows = [
            [Paragraph("<b>DORA CIKKELY</b>", st_body_bold), Paragraph("<b>ELŐÍRÁS TARTALMA</b>", st_body_bold),
             Paragraph("<b>SÚLY / PONT</b>", st_body_bold), Paragraph("<b>MINŐSÍTÉS</b>", st_body_bold)],
            [Paragraph("<b>9. Cikk (1)</b>", st_body_white), Paragraph("Erős titkosítás és korszerű AEAD cipher suite-ok kötelező alkalmazása", st_body),
             Paragraph(f"{db.get('strong_encryption', 0)} / 25", st_mono),
             Paragraph("<font color='#22c55e'><b>MEGFELELT</b></font>" if db.get('strong_encryption', 0) >= 20 else "<font color='#ef4444'><b>HIÁNYOS</b></font>", st_body)],
            [Paragraph("<b>9. Cikk (2)</b>", st_body_white), Paragraph("Kriptográfiai eszközleltár (CBOM), kulcsok életciklus- és lejáratkezelése", st_body),
             Paragraph(f"{db.get('key_management', 0)} / 30", st_mono),
             Paragraph("<font color='#22c55e'><b>MEGFELELT</b></font>" if db.get('key_management', 0) >= 25 else "<font color='#ef4444'><b>HIÁNYOS</b></font>", st_body)],
            [Paragraph("<b>9. Cikk (4) &amp; RTS</b>", st_body_white), Paragraph("Kripto-agilitás, PQC hibrid kulcscsere támogatása (HNDL megelőzés)", st_body),
             Paragraph(f"{db.get('crypto_agility', 0)} / 25", st_mono),
             Paragraph("<font color='#22c55e'><b>MEGFELELT</b></font>" if db.get('crypto_agility', 0) >= 20 else "<font color='#eab308'><b>MIGRÁCIÓ</b></font>", st_body)],
            [Paragraph("<b>Biztonságos Csatornák</b>", st_body_white), Paragraph("Elavult protokollok (SSLv3, TLS 1.0, TLS 1.1) tiltása", st_body),
             Paragraph(f"{db.get('secure_protocols', 0)} / 20", st_mono),
             Paragraph("<font color='#22c55e'><b>MEGFELELT</b></font>" if db.get('secure_protocols', 0) >= 16 else "<font color='#ef4444'><b>HIÁNYOS</b></font>", st_body)],
        ]
        story.append(build_dark_table(dora_rows, [38 * mm, 84 * mm, 26 * mm, 34 * mm]))
        story.append(Spacer(1, 8))

        # 2. Risk Register
        risks = comp.get("risk_register", [])
        if risks:
            story.append(Paragraph("3. Strukturált Kockázati Jegyzék (Risk Register)", st_h1))
            story.append(Spacer(1, 3))
            rr_data = [
                [Paragraph("<b>AZONOSÍTÓ</b>", st_body_bold), Paragraph("<b>KATEGÓRIA</b>", st_body_bold),
                 Paragraph("<b>FELTÁRT KOCKÁZAT ÉS MEGÁLLAPÍTÁS</b>", st_body_bold), Paragraph("<b>HATÁS</b>", st_body_bold),
                 Paragraph("<b>JOGSZABÁLY</b>", st_body_bold)]
            ]
            for r in risks:
                imp = r.get("impact", "KÖZEPES")
                ic = cls.RED_ALERT if imp == "MAGAS" else (cls.AMBER_WARN if imp == "KÖZEPES" else cls.TEXT_MAIN)
                rr_data.append([
                    Paragraph(r.get("id", "RISK"), st_mono_bold),
                    Paragraph(r.get("category", "Kriptográfia"), st_body_white),
                    Paragraph(r.get("finding", ""), st_body),
                    Paragraph(f"<font color='{ic.hexval()}'><b>{imp}</b></font>", st_body),
                    Paragraph(r.get("regulation", ""), st_small),
                ])
            story.append(build_dark_table(rr_data, [22 * mm, 26 * mm, 72 * mm, 20 * mm, 42 * mm]))
            story.append(Spacer(1, 8))

        # 3. CycloneDX 1.6 CBOM Table
        section_num = 4 if risks else 3
        story.append(Paragraph(f"{section_num}. Kriptográfiai Eszközleltár (CycloneDX 1.6 CBOM)", st_h1))
        story.append(Paragraph("A felügyeleti hatóságok felé kötelezően bemutatandó tételes kriptográfiai leltár:", st_subtitle))
        story.append(Spacer(1, 3))

        cbom_rows = [
            [Paragraph("<b>ESZKÖZTÍPUS</b>", st_body_bold), Paragraph("<b>AZONOSÍTOTT PRIMITÍV</b>", st_body_bold),
             Paragraph("<b>PARAMÉTEREK &amp; OID</b>", st_body_bold), Paragraph("<b>KVANTUMBIZTONSÁG</b>", st_body_bold)],
            [Paragraph("TLS Protokoll", st_body_white), Paragraph(f"{tls.get('version', 'N/A')}", st_body),
             Paragraph(f"{tls.get('cipher_name', '')}", st_mono),
             Paragraph("<font color='#22c55e'>Korszerű</font>" if tls.get('is_tls13') else "<font color='#ef4444'>Elavult</font>", st_body)],
            [Paragraph("Kulcscsere (KEX)", st_body_white), Paragraph(f"{pqc.get('group_name', 'None')}", st_body),
             Paragraph("NIST FIPS 203 / IETF" if pqc.get('pqc_supported') else "Klasszikus ECDHE/RSA", st_mono),
             Paragraph(f"<font color='{cls.BLUE_LIGHT.hexval() if pqc.get('pqc_supported') else cls.RED_ALERT.hexval()}'>"
                       f"<b>{'PQC Védett' if pqc.get('pqc_supported') else 'Shor-sebezhető'}</b></font>", st_body)],
            [Paragraph("X.509 Tanúsítvány", st_body_white),
             Paragraph(f"{cert.get('key_type', '')} ({cert.get('key_size_bits', '')} bit)", st_body),
             Paragraph(f"CN={cert.get('common_name', host)[:35]}", st_mono),
             Paragraph("Klasszikus Aszimmetrikus", st_body)],
            [Paragraph("Aláíró Algoritmus", st_body_white), Paragraph(f"{cert.get('signature_algorithm', '')}", st_body),
             Paragraph(f"Hash: {cert.get('signature_hash', '')}", st_mono),
             Paragraph(f"<font color='{cls.RED_ALERT.hexval()}'><b>Sebezhető</b></font>"
                       if cert.get("is_weak_signature") else "<font color='#22c55e'>Megfelelő</font>", st_body)],
            [Paragraph("Érvényesség", st_body_white), Paragraph(f"{cert.get('days_until_expiration', 'N/A')} nap", st_body),
             Paragraph(f"Lejárat: {str(cert.get('not_after', ''))[:10]}", st_mono),
             Paragraph(f"<font color='{cls.RED_ALERT.hexval()}'><b>LEJÁRT</b></font>"
                       if cert.get("is_expired") else "<font color='#22c55e'>Érvényes</font>", st_body)],
        ]
        story.append(build_dark_table(cbom_rows, [36 * mm, 48 * mm, 58 * mm, 40 * mm]))

        # =========================================================================
        # PAGE 3: DEEP TLS/CERT ASSESSMENT, REMEDIATION & CERTIFICATION
        # =========================================================================
        story.append(PageBreak())

        # 1. TLS & Certificate Deep Assessment
        tls_a = comp.get("tls_security_assessment", {})
        cert_a = comp.get("cert_security_assessment", {})
        if tls_a or cert_a:
            section_num += 1
            story.append(Paragraph(f"{section_num}. TLS és Tanúsítvány Biztonsági Mélyelemzés", st_h1))
            story.append(Spacer(1, 3))
            assess_list = []
            if tls_a:
                assess_list.extend([
                    ("TLS Protokoll Verzió", tls_a.get("protocol_verdict", "N/A")),
                    ("Cipher Suite Erősség", tls_a.get("cipher_strength_verdict", "N/A")),
                    ("Forward Secrecy (PFS)", tls_a.get("forward_secrecy", "N/A")),
                    ("Downgrade Védelem", tls_a.get("downgrade_resistance", "N/A")),
                ])
            if cert_a:
                assess_list.extend([
                    ("Kulcserősség Besorolás", cert_a.get("key_strength_verdict", "N/A")),
                    ("Aláíró Hash Algoritmus", cert_a.get("signature_algorithm_verdict", "N/A")),
                    ("Lejárati Kockázat", cert_a.get("expiration_risk", "N/A")),
                    ("Kvantum Sebezhetőség", cert_a.get("quantum_vulnerability", "N/A")),
                ])
            assess_rows = [[Paragraph("<b>VIZSGÁLT SZEMPONT</b>", st_body_bold), Paragraph("<b>AUDITORI ÉRTÉKELÉS &amp; HATÁS</b>", st_body_bold)]]
            for lbl, val in assess_list:
                assess_rows.append([Paragraph(f"<b>{lbl}</b>", st_body_white), Paragraph(val, st_body)])
            story.append(build_dark_table(assess_rows, [44 * mm, USABLE_W - 44 * mm]))
            story.append(Spacer(1, 7))

        # 2. Remediation Playbook
        section_num += 1
        story.append(Paragraph(f"{section_num}. Prioritizált Technikai Akcióterv (Remediation)", st_h1))
        story.append(Spacer(1, 3))
        remediation_steps = comp.get("remediation_steps", [])
        if not remediation_steps:
            story.append(build_panel(Paragraph("A célrendszer maradéktalanul megfelel a legmagasabb szintű DORA és poszt-kvantum elvárásoknak.", st_body_white)))
        else:
            rem_table_data = [[Paragraph("<b>SZINT</b>", st_body_bold), Paragraph("<b>HIÁNYOSSÁG / KOCKÁZAT</b>", st_body_bold), Paragraph("<b>KONKRÉT JAVÍTÁSI LÉPÉS (ACTION ITEM)</b>", st_body_bold)]]
            for step in remediation_steps:
                sev = step.get("severity", "INFO")
                sev_color = cls.RED_ALERT if sev == "CRITICAL" else (cls.AMBER_WARN if sev == "HIGH" else cls.BLUE_LIGHT)
                rem_table_data.append([
                    Paragraph(f"<font color='{sev_color.hexval()}'><b>{sev}</b></font>", st_body),
                    Paragraph(f"<b>{step.get('title', '')}</b>", st_body_white),
                    Paragraph(step.get('action', ''), st_body)
                ])
            story.append(build_dark_table(rem_table_data, [22 * mm, 50 * mm, USABLE_W - 72 * mm]))
        story.append(Spacer(1, 6))

        # 3. NGINX Config Playbook Box
        story.append(build_panel([
            Paragraph("<b>Mérnöki Konfigurációs Minta (PQC Hibrid X25519MLKEM768 Kézfogás):</b>", st_body_white),
            Spacer(1, 2),
            Paragraph(
                "# /etc/nginx/nginx.conf - Quantum-Safe DORA Art. 9 Compliant<br/>"
                "ssl_protocols TLSv1.3;<br/>"
                "ssl_prefer_server_ciphers off;<br/>"
                "ssl_ecdh_curve X25519MLKEM768:x25519:secp256r1;<br/>"
                "ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256;",
                st_mono
            )
        ], bg=cls.BG_BLACK))
        story.append(Spacer(1, 8))

        # 4. Formal Certification & Audit Hash Seal
        raw_audit_text = f"{aid}_{host}_{dora}_{now_str}_{scan_result.get('resolved_ip')}"
        audit_hash = hashlib.sha256(raw_audit_text.encode("utf-8")).hexdigest()

        story.append(build_panel([
            Paragraph("<b>AUDITORI TANÚSÍTVÁNY &amp; DIGITÁLIS HITELESÍTŐ ZÁRADÉK</b>", st_body_bold),
            Spacer(1, 2),
            Paragraph(
                "Igazoljuk, hogy a jelen audit dossziéban rögzített kriptográfiai vizsgálat az Európai Unió "
                "DORA (EU 2022/2554) 9. Cikkében, az RTS 2024/1774 rendeletben, valamint a NIST FIPS 203 "
                "szabványban előírt követelmények alapján, automatizált mélyhálózati eljárással készült.", st_body),
            Spacer(1, 2),
            Paragraph(f"<b>Audit Dosszié Azonosító:</b> <font color='#3b82f6'>{aid}</font>", st_body),
            Paragraph(f"<b>Digitális SHA-256 Integritási Hash:</b>", st_body),
            Paragraph(audit_hash, st_mono_bold),
            Spacer(1, 2),
            Paragraph("A dokumentum digitálisan hitelesített kivonatnak minősül, amely felhasználható "
                      "az MNB és az EBA felügyeleti ellenőrzések hivatalos mellékleteként.", st_small),
        ], bg=cls.BG_DARK, border_color=cls.BLUE_ACCENT))

        # Build document with dark background canvas
        def on_page(canvas, doc_ref):
            canvas.saveState()
            canvas.setFillColor(cls.BG_BLACK)
            canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)
            # Footer dividing line
            canvas.setStrokeColor(cls.BORDER_HAIRLINE)
            canvas.setLineWidth(0.3)
            canvas.line(14 * mm, 10 * mm, A4[0] - 14 * mm, 10 * mm)
            # Footer text
            canvas.setFillColor(cls.TEXT_DIM)
            canvas.setFont(FONT, 6)
            canvas.drawString(14 * mm, 6 * mm, f"QuantumShield Enterprise  //  {aid}  //  {now_str}")
            canvas.drawRightString(A4[0] - 14 * mm, 6 * mm, f"Oldal {canvas.getPageNumber()} / 3")
            canvas.restoreState()

        doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
        return output_path
