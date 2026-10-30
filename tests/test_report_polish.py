

# ── Report polish: violation IDs, clean AI summary text ──────────────────────

def test_violations_get_stable_ids_in_recorded_order():
    from types import SimpleNamespace as NS
    from database import number_violations
    vs = number_violations([NS(id=9), NS(id=3), NS(id=5)])
    assert [(v.id, v.ref) for v in vs] == [(3, "V-01"), (5, "V-02"), (9, "V-03")]


def test_summary_text_is_cleaned_for_reports():
    from textfmt import clean_summary, to_html, inline_pdf
    s = clean_summary("Hello, I am Vidhi.\n\nScore **14.7511/100**.\n\n*Disclaimer: see a lawyer.*")
    assert s == "Score **14.7/100**."
    html = to_html("Use `a*b` and **x** *y* stray * mark\n\n- one\n- two")
    assert "<code>a*b</code>" in html and "<strong>x</strong>" in html and "<em>y</em>" in html
    assert "stray  mark" in html and "<ul><li>one</li><li>two</li></ul>" in html
    assert "*" not in html.replace("a*b", "")
    assert inline_pdf("<b>x `y`") == '&lt;b&gt;x <font face="Courier">y</font>'
