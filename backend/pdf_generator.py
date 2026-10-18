from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor, white, black
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import io
import re

def generate_pdf(scan, violations, findings, compliance, narrative: str | None = None) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
        topMargin=15*mm, bottomMargin=15*mm,
        leftMargin=20*mm, rightMargin=20*mm)

    styles = getSampleStyleSheet()
    NAVY  = HexColor('#1a1a2e')
    RED   = HexColor('#dc3545')
    ORANGE= HexColor('#fd7e14')
    GREEN = HexColor('#28a745')
    score_color = HexColor(compliance.get('color', '#333333'))

    title_style = ParagraphStyle('title', fontSize=20, textColor=white,
        fontName='Helvetica-Bold', alignment=TA_CENTER, spaceAfter=4)
    sub_style   = ParagraphStyle('sub',   fontSize=10, textColor=HexColor('#aaaaaa'),
        fontName='Helvetica', alignment=TA_CENTER)
    h2_style    = ParagraphStyle('h2',    fontSize=13, textColor=NAVY,
        fontName='Helvetica-Bold', spaceBefore=14, spaceAfter=6)
    body_style  = ParagraphStyle('body',  fontSize=9,  textColor=black,
        fontName='Helvetica', spaceAfter=4, leading=13)
    small_style = ParagraphStyle('small', fontSize=8,  textColor=HexColor('#555555'),
        fontName='Helvetica', spaceAfter=3, leading=11)
    fix_style   = ParagraphStyle('fix',   fontSize=8,  textColor=HexColor('#2d6a4f'),
        fontName='Helvetica', spaceAfter=3, leading=11)

    story = []
    W = 170*mm  # content width

    # ── Header ───────────────────────────────────────────────────────────────
    header_data = [[
        Paragraph('PrivacyPilot', title_style),
    ]]
    sub_data = [[
        Paragraph(f"DPDP Act Compliance Report · Generated {scan.created_at.strftime('%d %b %Y %H:%M')} UTC", sub_style),
    ]]
    header_table = Table([[Paragraph('PrivacyPilot', title_style)]], colWidths=[W])
    header_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), NAVY),
        ('TOPPADDING',    (0,0), (-1,-1), 12),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING',   (0,0), (-1,-1), 10),
    ]))
    story.append(header_table)

    sub_table = Table([[Paragraph(
        f"DPDP Act Compliance Report · {scan.created_at.strftime('%d %b %Y')}", sub_style
    )]], colWidths=[W])
    sub_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), NAVY),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(sub_table)
    story.append(Spacer(1, 8*mm))

    # ── Score ─────────────────────────────────────────────────────────────────
    score     = compliance.get('score', 0)
    rating    = compliance.get('rating', 'Unknown')
    critical  = compliance.get('critical_count', 0)
    high      = compliance.get('high_count', 0)

    score_style  = ParagraphStyle('sc', fontSize=40, textColor=score_color,
        fontName='Helvetica-Bold', alignment=TA_CENTER)
    rating_style = ParagraphStyle('rt', fontSize=14, textColor=score_color,
        fontName='Helvetica-Bold', alignment=TA_CENTER, spaceAfter=2)
    detail_style = ParagraphStyle('dt', fontSize=9,  textColor=HexColor('#666666'),
        fontName='Helvetica', alignment=TA_CENTER)

    score_table = Table([
        [Paragraph(f'{score}<font size="18" color="#aaaaaa">/100</font>', score_style)],
        [Paragraph(f'{rating} Compliance', rating_style)],
        [Paragraph(f'{critical} critical · {high} high severity violations', detail_style)],
    ], colWidths=[W])
    score_table.setStyle(TableStyle([
        ('BOX', (0,0), (-1,-1), 1.5, score_color),
        ('ROUNDEDCORNERS', (0,0), (-1,-1), 5),
        ('TOPPADDING',    (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('BACKGROUND', (0,0), (-1,-1), HexColor('#fafafa')),
    ]))
    story.append(score_table)
    story.append(Spacer(1, 6*mm))

    # ── AI Executive Summary (narrative) ────────────────────────────────────
    if narrative:
        story.append(Paragraph('AI-Generated Executive Summary', h2_style))
        story.append(HRFlowable(width=W, thickness=1, color=NAVY))
        story.append(Spacer(1, 2*mm))

        narrative_style = ParagraphStyle(
            'narr', fontSize=9, textColor=black,
            fontName='Helvetica', spaceAfter=6, leading=14,
            leftIndent=4, borderPad=8,
        )
        narrative_bg_style = ParagraphStyle(
            'narrh', fontSize=10, textColor=NAVY,
            fontName='Helvetica-Bold', spaceAfter=4,
        )

        # Convert **bold** markdown to <b> tags (ReportLab supports <b>)
        def _md_to_pdf(text):
            return re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)

        # Wrap in a light-blue background table
        paras = [p.strip() for p in narrative.split('\n\n') if p.strip()]
        narr_content = '<br/><br/>'.join(_md_to_pdf(p) for p in paras)
        narr_table = Table(
            [[Paragraph(narr_content, narrative_style)]],
            colWidths=[W]
        )
        narr_table.setStyle(TableStyle([
            ('BACKGROUND',    (0,0), (-1,-1), HexColor('#f0f4ff')),
            ('LEFTPADDING',   (0,0), (-1,-1), 10),
            ('RIGHTPADDING',  (0,0), (-1,-1), 10),
            ('TOPPADDING',    (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ('BOX',           (0,0), (-1,-1), 1.5, NAVY),
        ]))
        story.append(narr_table)
        story.append(Spacer(1, 6*mm))

        # ── Scan Summary ──────────────────────────────────────────────────────────
    story.append(Paragraph('Scan Summary', h2_style))
    story.append(HRFlowable(width=W, thickness=1, color=NAVY))
    summary_data = [
        ['Repository', scan.repo_url.replace('https://github.com/', ''),
         'Scan Date', scan.created_at.strftime('%d %b %Y %H:%M')],
        ['PII Findings', str(scan.findings_count),
         'DPDP Violations', str(scan.violations_count)],
    ]
    summary_table = Table(summary_data, colWidths=[30*mm, 55*mm, 30*mm, 55*mm])
    summary_table.setStyle(TableStyle([
        ('FONTNAME',  (0,0), (-1,-1), 'Helvetica'),
        ('FONTSIZE',  (0,0), (-1,-1), 9),
        ('FONTNAME',  (0,0), (0,-1), 'Helvetica-Bold'),
        ('FONTNAME',  (2,0), (2,-1), 'Helvetica-Bold'),
        ('TEXTCOLOR', (1,1), (1,1), NAVY),
        ('TEXTCOLOR', (3,1), (3,1), RED),
        ('BACKGROUND',(0,0), (-1,-1), HexColor('#f5f5f5')),
        ('GRID',      (0,0), (-1,-1), 0.5, HexColor('#dddddd')),
        ('TOPPADDING',(0,0), (-1,-1), 6),
        ('BOTTOMPADDING',(0,0),(-1,-1), 6),
        ('LEFTPADDING',  (0,0),(-1,-1), 8),
    ]))
    story.append(Spacer(1, 3*mm))
    story.append(summary_table)
    story.append(Spacer(1, 6*mm))

    # ── Consent Gaps ─────────────────────────────────────────────────────────
    story.append(Paragraph(f'Consent Gaps Detected ({scan.gaps_count})', h2_style))
    story.append(HRFlowable(width=W, thickness=1, color=NAVY))
    story.append(Spacer(1, 2*mm))
    gaps = list({f.pii_category for f in findings if f.is_gap})
    if gaps:
        gap_text = '  ·  '.join(gaps)
        story.append(Paragraph(
            f'These PII types are in the code but NOT in the privacy policy: <b>{gap_text}</b>',
            body_style
        ))
    else:
        story.append(Paragraph('No consent gaps detected.', body_style))
    story.append(Spacer(1, 6*mm))

    # ── Violations ───────────────────────────────────────────────────────────
    story.append(Paragraph('DPDP Act Violations', h2_style))
    story.append(HRFlowable(width=W, thickness=1, color=NAVY))
    story.append(Spacer(1, 2*mm))

    for v in violations:
        sev_color = RED if v.severity == 'critical' else ORANGE
        sev_label = v.severity.upper()

        v_header = Table([[
            Paragraph(f'{v.dpdp_section} — {v.section_title}',
                ParagraphStyle('vh', fontSize=10, fontName='Helvetica-Bold', textColor=black)),
            Paragraph(sev_label,
                ParagraphStyle('vb', fontSize=8, fontName='Helvetica-Bold',
                    textColor=white, alignment=TA_CENTER)),
        ]], colWidths=[140*mm, 30*mm])
        v_header.setStyle(TableStyle([
            ('BACKGROUND', (1,0), (1,0), sev_color),
            ('BACKGROUND', (0,0), (0,0), HexColor('#f8f8f8')),
            ('TOPPADDING',    (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING',   (0,0), (0,0),  8),
            ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(v_header)

        v_body = Table([[
            Paragraph(
                f'<b>PII Type:</b> {v.pii_category}<br/>'
                f'<b>Evidence:</b> {v.evidence}<br/>'
                f'<font color="#2d6a4f"><b>Fix:</b> {v.recommendation}</font>',
                small_style
            )
        ]], colWidths=[W])
        v_body.setStyle(TableStyle([
            ('BOX',           (0,0), (-1,-1), 0.5, HexColor('#dddddd')),
            ('TOPPADDING',    (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING',   (0,0), (-1,-1), 8),
        ]))
        story.append(v_body)
        story.append(Spacer(1, 3*mm))

    # ── Sample Findings ───────────────────────────────────────────────────────
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph('Sample Code Findings (first 10)', h2_style))
    story.append(HRFlowable(width=W, thickness=1, color=NAVY))
    story.append(Spacer(1, 2*mm))

    findings_data = [['PII Type', 'Sensitivity', 'File', 'Line', 'Detected By']]
    for f in findings[:10]:
        findings_data.append([
            f.pii_category or '',
            f.sensitivity  or '',
            (f.file_path   or '')[-40:],
            str(f.line_number or ''),
            f.source or '',
        ])

    findings_table = Table(findings_data,
        colWidths=[25*mm, 22*mm, 70*mm, 14*mm, 39*mm])
    findings_table.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,0),  NAVY),
        ('TEXTCOLOR',     (0,0), (-1,0),  white),
        ('FONTNAME',      (0,0), (-1,0),  'Helvetica-Bold'),
        ('FONTSIZE',      (0,0), (-1,-1), 8),
        ('FONTNAME',      (0,1), (-1,-1), 'Helvetica'),
        ('ROWBACKGROUNDS',(0,1), (-1,-1), [white, HexColor('#f9f9f9')]),
        ('GRID',          (0,0), (-1,-1), 0.5, HexColor('#dddddd')),
        ('TOPPADDING',    (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING',   (0,0), (-1,-1), 6),
    ]))
    story.append(findings_table)

    # ── Disclaimer ────────────────────────────────────────────────────────────
    story.append(Spacer(1, 8*mm))
    story.append(Paragraph(
        '<b>Disclaimer:</b> This report is for research and demonstration purposes only. '
        'It does not constitute legal advice. PrivacyPilot — Capstone Project 2024–25.',
        ParagraphStyle('disc', fontSize=7, textColor=HexColor('#888888'),
            fontName='Helvetica', leading=10)
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer.read()