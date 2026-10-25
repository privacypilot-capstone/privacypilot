from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor, white, black
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import io
import re
from xml.sax.saxutils import escape as _xml_escape

from database import scan_gap_categories, violation_locations, location_label


def _x(value) -> str:
    """Escape text for a ReportLab Paragraph, which parses its input as
    markup: evidence such as "<b>unclosed" or "<img …>" (quoted from the
    scanned policy) otherwise raises ValueError and the PDF fails."""
    return _xml_escape("" if value is None else str(value))

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
    AMBER = HexColor('#ffc107')
    # Same four-colour scale as the HTML report (medium/low were drawn in
    # the same orange as high before).
    SEVERITY_COLORS = {'critical': RED, 'high': ORANGE, 'medium': AMBER, 'low': GREEN}
    score_color = HexColor(compliance.get('color', '#333333'))

    # leading > fontSize: with ReportLab's default leading (12) large text
    # overlapped the line below it.
    title_style = ParagraphStyle('title', fontSize=20, leading=24, textColor=white,
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
    score     = compliance.get('score_display', compliance.get('score', 0))
    rating    = compliance.get('rating', 'Unknown')
    critical  = compliance.get('critical_count', 0)
    high      = compliance.get('high_count', 0)

    score_style  = ParagraphStyle('sc', fontSize=40, leading=46, textColor=score_color,
        fontName='Helvetica-Bold', alignment=TA_CENTER)
    rating_style = ParagraphStyle('rt', fontSize=14, leading=18, textColor=score_color,
        fontName='Helvetica-Bold', alignment=TA_CENTER, spaceAfter=2)
    detail_style = ParagraphStyle('dt', fontSize=9,  textColor=HexColor('#666666'),
        fontName='Helvetica', alignment=TA_CENTER)

    score_table = Table([
        [Paragraph(f'{score}<font size="18" color="#aaaaaa">/100</font>', score_style)],
        [Paragraph(f'{_x(rating)} Compliance', rating_style)],
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

        # Escape first, then convert **bold** markdown to <b> tags
        def _md_to_pdf(text):
            return re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', _x(text))

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
    gaps = scan_gap_categories(scan, findings)
    if gaps:
        gap_text = _x('  ·  '.join(gaps))
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

    # Text that may contain long unbroken tokens (paths, minified code) wraps
    # anywhere (CJK word wrap), so it never runs out of its column.
    loc_style  = ParagraphStyle('loc', fontSize=7, fontName='Courier', leading=9,
        textColor=HexColor('#333333'), leftIndent=4*mm, wordWrap='CJK')
    cell_style = ParagraphStyle('cell', fontSize=6.5, fontName='Helvetica', leading=8,
        wordWrap='CJK')
    code_style = ParagraphStyle('cellcode', fontSize=6.5, fontName='Courier', leading=8,
        wordWrap='CJK')
    vbody_style = ParagraphStyle('vbody', parent=small_style, leftIndent=2*mm)
    vfix_style  = ParagraphStyle('vfix', parent=fix_style, leftIndent=2*mm)

    for v in violations:
        sev_color = SEVERITY_COLORS.get(v.severity, ORANGE)
        sev_label = _x((v.severity or '').upper())

        v_header = Table([[
            Paragraph(f'{_x(v.dpdp_section)} — {_x(v.section_title)}',
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
        story.append(Spacer(1, 1.5*mm))

        # Plain paragraphs (not one table cell), so a violation with a long
        # evidence text or hundreds of locations flows across pages instead
        # of failing with "flowable too large".
        recipient = getattr(v, 'recipient', None)
        story.append(Paragraph(f'<b>PII Type:</b> {_x(v.pii_category)}'
                               + (f'  ·  <b>Recipient:</b> {_x(recipient)}' if recipient else ''),
                               vbody_style))
        story.append(Paragraph(f'<b>Evidence:</b> {_x(v.evidence)}', vbody_style))
        locs = violation_locations(v)
        if locs:
            story.append(Paragraph(f'<b>Locations ({len(locs)}):</b>', vbody_style))
            for i, l in enumerate(locs, 1):
                story.append(Paragraph(f'{i}. {_x(location_label(l))}', loc_style))
        story.append(Paragraph(f'<b>Fix:</b> {_x(v.recommendation)}', vfix_style))
        story.append(HRFlowable(width=W, thickness=0.5, color=HexColor('#dddddd'),
                                spaceBefore=2*mm, spaceAfter=3*mm))

    # ── All Findings ──────────────────────────────────────────────────────────
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph(f'All Code Findings ({len(findings)})', h2_style))
    story.append(HRFlowable(width=W, thickness=1, color=NAVY))
    story.append(Spacer(1, 2*mm))

    origin_label = {'first_party': 'Your code', 'third_party': 'Third-party',
                    'generated': 'Generated'}
    header = ['#', 'PII Type', 'File : line', 'Origin', 'Sent to', 'Code', 'Detected by']
    col_w = [9*mm, 15*mm, 48*mm, 15*mm, 18*mm, 43*mm, 22*mm]
    tstyle = TableStyle([
        ('BACKGROUND',    (0,0), (-1,0),  NAVY),
        ('TEXTCOLOR',     (0,0), (-1,0),  white),
        ('FONTNAME',      (0,0), (-1,0),  'Helvetica-Bold'),
        ('FONTSIZE',      (0,0), (-1,-1), 6.5),
        ('FONTNAME',      (0,1), (-1,-1), 'Helvetica'),
        ('ROWBACKGROUNDS',(0,1), (-1,-1), [white, HexColor('#f9f9f9')]),
        ('GRID',          (0,0), (-1,-1), 0.4, HexColor('#dddddd')),
        ('VALIGN',        (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING',    (0,0), (-1,-1), 2),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2),
        ('LEFTPADDING',   (0,0), (-1,-1), 3),
        ('RIGHTPADDING',  (0,0), (-1,-1), 3),
    ])
    rows = []
    for i, f in enumerate(findings, 1):
        rows.append([
            str(i),
            f.pii_category or '',
            Paragraph(f'{_x(f.file_path or "N/A")} : {_x(f.line_number or "")}', cell_style),
            origin_label.get(f.origin or 'first_party', f.origin or ''),
            Paragraph(_x(f.third_party_sdk or '—'), cell_style),
            Paragraph(_x(f.raw_text or ''), code_style),
            Paragraph(_x(f.source or ''), cell_style),
        ])
    if not rows:
        story.append(Paragraph('No findings.', body_style))
    # Several moderate tables rather than one huge one: ReportLab splits a
    # table across pages by re-laying it out, which gets slow for very long
    # tables. Every table repeats the header row on each page.
    CHUNK = 200
    for k in range(0, len(rows), CHUNK):
        t = Table([header] + rows[k:k + CHUNK], colWidths=col_w, repeatRows=1)
        t.setStyle(tstyle)
        story.append(t)

    # ── Disclaimer ────────────────────────────────────────────────────────────
    story.append(Spacer(1, 8*mm))
    story.append(Paragraph(
        '<b>Disclaimer:</b> This report is for research and demonstration purposes only. '
        'It does not constitute legal advice. PrivacyPilot — B.Tech Capstone Project.',
        ParagraphStyle('disc', fontSize=7, textColor=HexColor('#888888'),
            fontName='Helvetica', leading=10)
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer.read()