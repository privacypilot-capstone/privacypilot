from datetime import datetime


def generate_report_html(scan, violations, findings, compliance, narrative: str | None = None) -> str:
    """
    Generate a full HTML compliance report for a scan.
    Returns HTML string ready for PDF conversion.
    """

    severity_color = {
        "critical": "#dc3545",
        "high":     "#fd7e14",
        "medium":   "#ffc107",
        "low":      "#28a745",
    }

    # Build violations HTML
    violations_html = ""
    for v in violations:
        color = severity_color.get(v.severity, "#666")
        violations_html += f"""
        <div class="violation">
            <div class="violation-header">
                <span class="section">{v.dpdp_section} — {v.section_title}</span>
                <span class="badge" style="background:{color}">{v.severity.upper()}</span>
            </div>
            <div class="violation-body">
                <p><strong>PII Type:</strong> {v.pii_category}</p>
                <p><strong>Evidence:</strong> {v.evidence}</p>
                <p class="fix"><strong>Recommended Fix:</strong> {v.recommendation}</p>
            </div>
        </div>
        """

    # Build findings HTML (first 10)
    findings_html = ""
    for f in findings[:10]:
        findings_html += f"""
        <tr>
            <td>{f.pii_category}</td>
            <td>{f.sensitivity}</td>
            <td>{f.file_path or 'N/A'}</td>
            <td>{f.line_number or 'N/A'}</td>
            <td>{f.source}</td>
        </tr>
        """

    score_color = compliance.get("color", "#333")
    score       = compliance.get("score", 0)
    rating      = compliance.get("rating", "Unknown")
    critical    = compliance.get("critical_count", 0)
    high        = compliance.get("high_count", 0)

    # Deduplicated gap chips — computed before the f-string to avoid lambda-in-fstring issues
    _gap_cats = sorted(dict.fromkeys(f.pii_category for f in findings if f.is_gap))
    gaps_html = (
        "".join(f'<span class="gap-tag">{c}</span>' for c in _gap_cats)
        if _gap_cats else '<p style="color:#888">No gaps detected.</p>'
    )

    # ── Narrative (LLM executive summary) ──────────────────────────────────
    if narrative:
        # Convert **bold** markdown to <strong> and split paragraphs
        def _md_to_html(text):
            text = __import__('re').sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
            paras = [p.strip() for p in text.split('\n\n') if p.strip()]
            return '\n'.join(f'<p>{p}</p>' for p in paras)
        narrative_html = f'''
        <div class="narrative">
          <h3>&#x1F4CA; AI-Generated Executive Summary</h3>
          {_md_to_html(narrative)}
        </div>'''
    else:
        narrative_html = ''

    html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
  body {{
    font-family: 'Helvetica Neue', Arial, sans-serif;
    margin: 0; padding: 0; color: #222; font-size: 13px;
  }}
  .header {{
    background: #1a1a2e; color: #fff;
    padding: 28px 36px; margin-bottom: 0;
  }}
  .header h1 {{ margin: 0; font-size: 26px; letter-spacing: 1px; }}
  .header p  {{ margin: 4px 0 0; color: #aaa; font-size: 13px; }}
  .content   {{ padding: 28px 36px; }}
  .score-box {{
    text-align: center; padding: 24px;
    border: 3px solid {score_color};
    border-radius: 12px; margin-bottom: 24px;
    background: #fafafa;
  }}
  .score-num  {{ font-size: 56px; font-weight: bold; color: {score_color}; }}
  .score-label{{ font-size: 18px; font-weight: bold; color: {score_color}; }}
  .score-sub  {{ font-size: 12px; color: #888; margin-top: 4px; }}
  .section-title {{
    font-size: 16px; font-weight: bold;
    border-bottom: 2px solid #1a1a2e;
    padding-bottom: 6px; margin: 24px 0 12px;
    color: #1a1a2e;
  }}
  .meta-grid {{
    display: grid; grid-template-columns: 1fr 1fr;
    gap: 12px; margin-bottom: 20px;
  }}
  .meta-item {{
    background: #f5f5f5; border-radius: 8px;
    padding: 12px 16px;
  }}
  .meta-item label {{ font-size: 11px; color: #888; display: block; }}
  .meta-item span  {{ font-size: 15px; font-weight: bold; color: #222; }}
  .violation {{
    border: 1px solid #ddd; border-radius: 8px;
    margin-bottom: 14px; overflow: hidden;
  }}
  .violation-header {{
    display: flex; justify-content: space-between;
    align-items: center; padding: 10px 14px;
    background: #f8f8f8; border-bottom: 1px solid #eee;
  }}
  .section {{ font-weight: bold; font-size: 13px; }}
  .badge {{
    color: #fff; padding: 3px 10px;
    border-radius: 99px; font-size: 11px; font-weight: bold;
  }}
  .violation-body {{ padding: 12px 14px; }}
  .violation-body p {{ margin: 4px 0; font-size: 12px; }}
  .fix {{ color: #2d6a4f !important; }}
  .narrative {{
    background: #f0f4ff; border-left: 4px solid #1a1a2e;
    border-radius: 6px; padding: 16px 20px;
    margin-bottom: 24px; font-size: 12px; line-height: 1.7;
    color: #222;
  }}
  .narrative h3 {{
    margin: 0 0 10px; font-size: 14px; color: #1a1a2e;
    letter-spacing: 0.3px;
  }}
  .narrative p {{ margin: 8px 0; }}
  .narrative strong {{ color: #1a1a2e; }}
  .gap-tag {{
    display: inline-block; background: #fff3cd;
    border: 1px solid #ffc107; border-radius: 4px;
    padding: 4px 10px; margin: 3px; font-size: 12px;
    font-family: monospace;
  }}
  table {{
    width: 100%; border-collapse: collapse;
    font-size: 11px; margin-top: 8px;
  }}
  th {{
    background: #1a1a2e; color: #fff;
    padding: 8px 10px; text-align: left;
  }}
  td {{ padding: 7px 10px; border-bottom: 1px solid #eee; }}
  tr:nth-child(even) td {{ background: #f9f9f9; }}
  .footer {{
    margin-top: 32px; padding: 16px 36px;
    background: #f5f5f5; font-size: 11px; color: #888;
    border-top: 1px solid #ddd;
  }}
</style>
</head>
<body>

<div class="header">
  <h1>PrivacyPilot</h1>
  <p>DPDP Act Compliance Report — Generated {datetime.utcnow().strftime('%d %B %Y, %H:%M UTC')}</p>
</div>

<div class="content">

  <!-- Score -->
  <div class="score-box">
    <div class="score-num">{score}<span style="font-size:24px;color:#aaa">/100</span></div>
    <div class="score-label">{rating} Compliance</div>
    <div class="score-sub">{critical} critical · {high} high severity violations</div>
  </div>

  {narrative_html}

  <!-- Scan Info -->
  <div class="section-title">Scan Summary</div>
  <div class="meta-grid">
    <div class="meta-item">
      <label>Repository</label>
      <span>{scan.repo_url.replace('https://github.com/', '')}</span>
    </div>
    <div class="meta-item">
      <label>Scan Date</label>
      <span>{scan.created_at.strftime('%d %b %Y %H:%M')}</span>
    </div>
    <div class="meta-item">
      <label>PII Findings in Code</label>
      <span>{scan.findings_count}</span>
    </div>
    <div class="meta-item">
      <label>DPDP Violations</label>
      <span style="color:#dc3545">{scan.violations_count}</span>
    </div>
  </div>

  <!-- Consent Gaps -->
  <div class="section-title">Consent Gaps Detected ({scan.gaps_count})</div>
  <p style="font-size:12px;color:#555;margin-bottom:10px">
    These PII types are processed in the source code but are NOT disclosed in the privacy policy:
  </p>
  {gaps_html}

  <!-- Violations -->
  <div class="section-title">DPDP Act Violations</div>
  {violations_html or '<p style="color:#28a745">No violations detected.</p>'}

  <!-- Sample Findings -->
  <div class="section-title">Sample Code Findings (first 10)</div>
  <table>
    <tr>
      <th>PII Type</th>
      <th>Sensitivity</th>
      <th>File</th>
      <th>Line</th>
      <th>Detected By</th>
    </tr>
    {findings_html}
  </table>

  <!-- Disclaimer -->
  <div style="margin-top:24px;padding:12px 16px;background:#fff3cd;
              border-radius:8px;font-size:11px;color:#666;border:1px solid #ffc107">
    <strong>Disclaimer:</strong> This report is generated for research and demonstration
    purposes only. It does not constitute legal advice and is not a substitute for a
    professional legal audit. PrivacyPilot — Capstone Project 2024–25.
  </div>

</div>

<div class="footer">
  PrivacyPilot · DPDP Act Compliance Engine · Automated Code-Aware Privacy Auditing ·
  Scan ID: {scan.id}
</div>

</body>
</html>
"""
    return html