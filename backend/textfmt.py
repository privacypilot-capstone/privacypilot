"""Light Markdown handling for LLM text (executive summary) shown in the
web app, the HTML report and the PDF report.

The models write a little Markdown (**bold**, *italic*, `code`, "- " lists)
and sometimes open with a greeting. Everything is escaped first, so text
echoed from a scanned privacy policy can never inject markup."""
import re
from html import escape as _html_escape

_GREETING = re.compile(r"^\s*(hello|hi|hey|namaste)\b[^\n]*", re.I)


def clean_summary(text: str | None) -> str | None:
    """Drop a greeting/self-introduction paragraph and stray heading marks."""
    if not text:
        return text
    paras = [p for p in re.split(r"\n\s*\n", text.strip()) if p.strip()]
    if paras and _GREETING.match(paras[0]) and len(paras) > 1:
        paras = paras[1:]
    # The reports carry their own disclaimer: drop the model's.
    if paras and re.match(r"^[\s*_]*disclaimer\b", paras[-1], re.I) and len(paras) > 1:
        paras = paras[:-1]
    out = "\n\n".join(paras)
    # Scores quoted with raw precision ("14.7511/100") → one decimal.
    out = re.sub(r"\b(\d{1,3}\.\d)\d+(\s*/\s*100)", r"\1\2", out)
    out = re.sub(r"^\s*#{1,6}\s+", "", out, flags=re.M)
    return out.strip()


DETECTOR_LABELS = {
    "code_scanner": "Pattern match",
    "presidio_scanner": "Language analysis",
    "taint_analysis": "Data-flow tracking",
    "scope_inference": "Inferred (document/image service)",
    "policy_parser": "Privacy policy",
    "policy_parser_bullets": "Privacy policy",
}


def detector_label(source: str | None) -> str:
    return DETECTOR_LABELS.get(source or "", source or "")


def blocks(text: str) -> list[tuple[str, list[str]]]:
    """Split into ('p', [lines]) / ('ul', [items]) / ('ol', [items]) blocks."""
    out: list[tuple[str, list[str]]] = []
    cur: tuple[str, list[str]] | None = None
    for raw in (text or "").replace("\r", "").split("\n"):
        line = raw.rstrip()
        b = re.match(r"^\s*[-*•]\s+(.*)$", line)
        n = re.match(r"^\s*\d+[.)]\s+(.*)$", line)
        if b or n:
            kind = "ul" if b else "ol"
            if not cur or cur[0] != kind:
                cur = (kind, []); out.append(cur)
            cur[1].append((b or n).group(1))
        elif not line.strip():
            cur = None
        else:
            if not cur or cur[0] != "p":
                cur = ("p", []); out.append(cur)
            cur[1].append(line.strip())
    return out


def _inline(text: str, esc, code_open: str, code_close: str) -> str:
    s = esc(text)
    s = re.sub(r"`([^`]+)`", lambda m: f"{code_open}{m.group(1)}{code_close}", s)
    s = re.sub(r"\*\*(.+?)\*\*|__(.+?)__", lambda m: f"<b>{m.group(1) or m.group(2)}</b>", s)
    s = re.sub(r"(?<![\w*])\*(?!\s)([^*\n]+?)\*(?![\w*])", r"<i>\1</i>", s)
    # Leftover Markdown marks outside code spans are dropped (a literal *
    # only belongs in code, which the model writes in backticks).
    parts = re.split(f"({re.escape(code_open)}.*?{re.escape(code_close)})", s)
    return "".join(p if p.startswith(code_open) else p.replace("*", "").replace("`", "")
                   for p in parts)


def inline_html(text: str) -> str:
    # The input is escaped before any tag is added, so every <b>/<i> here
    # came from Markdown; use the semantic HTML tags.
    s = _inline(text, _html_escape, "<code>", "</code>")
    return (s.replace("<b>", "<strong>").replace("</b>", "</strong>")
             .replace("<i>", "<em>").replace("</i>", "</em>"))


def inline_pdf(text: str) -> str:
    """ReportLab Paragraph markup (same escaping rules as XML)."""
    from xml.sax.saxutils import escape
    return _inline(text, escape, '<font face="Courier">', "</font>")


def to_html(text: str) -> str:
    parts = []
    for kind, items in blocks(clean_summary(text) or ""):
        if kind == "p":
            parts.append("<p>" + "<br>".join(inline_html(l) for l in items) + "</p>")
        else:
            parts.append(f"<{kind}>" + "".join(f"<li>{inline_html(i)}</li>" for i in items) + f"</{kind}>")
    return "\n".join(parts)
