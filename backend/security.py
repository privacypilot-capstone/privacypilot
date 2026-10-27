"""
Secret handling for PrivacyPilot's own data (threat model, Table 22 of the report).

 * seal()/unseal()    the GitHub token is encrypted (Fernet: AES-128-CBC + HMAC)
                      before it is put in a Celery task message, so a reader of
                      Redis, of the Celery result backend or of a task log sees
                      only ciphertext, and the ciphertext expires.
 * redact_secrets()   masks tokens and API keys in any text bound for a log, an
                      error message stored with a scan, or a response.
 * redact_for_llm()   masks secrets and personal data (e-mail, phone, Aadhaar,
                      PAN, card numbers) in text sent to an external LLM.
 * install_log_redaction()  puts redact_secrets() on every log record.

The key comes from PRIVACYPILOT_TOKEN_KEY (a Fernet key). If it is not set, a
random key is created once in backend/.token_key (mode 0600, git-ignored); the
API and the workers both mount ./backend, so they share it with no setup.
"""
from __future__ import annotations

import logging
import os
import re
import stat
from pathlib import Path

_PREFIX = "pp1:"
_KEY_FILE = Path(os.getenv("PRIVACYPILOT_TOKEN_KEY_FILE",
                           str(Path(__file__).resolve().parent / ".token_key")))
# A sealed token older than this is refused (seconds). A scan that waits for a
# GitHub rate limit can run for hours, so the default is generous but finite.
TOKEN_TTL_S = int(os.getenv("PRIVACYPILOT_TOKEN_TTL_S", str(12 * 3600)))

_fernet = None


def _load_key() -> bytes:
    env = os.getenv("PRIVACYPILOT_TOKEN_KEY")
    if env:
        return env.encode()
    from cryptography.fernet import Fernet
    try:
        return _KEY_FILE.read_bytes().strip()
    except FileNotFoundError:
        pass
    key = Fernet.generate_key()
    try:  # O_EXCL: if the API and a worker race, exactly one creates the file
        fd = os.open(_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
        return key
    except FileExistsError:
        return _KEY_FILE.read_bytes().strip()


def _f():
    global _fernet
    if _fernet is None:
        from cryptography.fernet import Fernet
        _fernet = Fernet(_load_key())
    return _fernet


def seal(token: str | None) -> str | None:
    """Encrypt a token for transport in a task message. Empty stays empty."""
    if not token or token.startswith(_PREFIX):
        return token
    return _PREFIX + _f().encrypt(token.encode()).decode()


def unseal(value: str | None) -> str | None:
    """Inverse of seal(). A value that was never sealed (a plain token, as in
    unit tests or a task queued by an older version) is returned unchanged."""
    if not value or not value.startswith(_PREFIX):
        return value
    from cryptography.fernet import InvalidToken
    try:
        return _f().decrypt(value[len(_PREFIX):].encode(), ttl=TOKEN_TTL_S).decode()
    except InvalidToken:
        raise ValueError("The stored GitHub token has expired or cannot be decrypted; "
                         "start the scan again.") from None


# ── redaction ────────────────────────────────────────────────────────────────

_SECRET_RES = [  # (pattern, replacement)
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "***REDACTED***"),        # GitHub classic / OAuth / app tokens
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "***REDACTED***"),       # GitHub fine-grained token
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b"), "***REDACTED***"),            # Google API key
    (re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_\-]{20,}\b"), "***REDACTED***"),    # OpenAI / Anthropic key
    (re.compile(r"\bpp1:[A-Za-z0-9_\-=]{20,}"), "***REDACTED***"),             # our own sealed token
    (re.compile(r"(?i)\b(Bearer|token)\s+[A-Za-z0-9._\-]{16,}"), r"\1 ***REDACTED***"),
    (re.compile(r"(?i)([?&](?:key|token|access_token|api_key)=)[^&\s\"']+"), r"\1***REDACTED***"),
]


def redact_secrets(text) -> str:
    s = str(text)
    for rx, repl in _SECRET_RES:
        s = rx.sub(repl, s)
    return s


_PII_RES = [
    (re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"), "[email]"),
    (re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"), "[PAN]"),
    (re.compile(r"\b(?:\d[ -]?){13,16}\b"), "[card]"),
    (re.compile(r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b"), "[aadhaar]"),
    (re.compile(r"(?<!\w)(?:\+?91[ -]?)?[6-9]\d{9}\b"), "[phone]"),
]


def redact_for_llm(text) -> str:
    """Mask secrets and personal-data values before text leaves for an LLM.
    Category names ("email", "phone") are kept: the model needs them, not values."""
    s = redact_secrets(text)
    for rx, repl in _PII_RES:
        s = rx.sub(repl, s)
    return s


class _RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = redact_secrets(record.getMessage())
            record.args = ()
        except Exception:
            pass
        return True


def install_log_redaction() -> None:
    """Idempotent: put the filter on the root logger's handlers and on the
    loggers that Celery, uvicorn and requests use."""
    for name in ("", "celery", "celery.app.trace", "celery.worker", "uvicorn", "uvicorn.error",
                 "uvicorn.access", "urllib3", "requests"):
        lg = logging.getLogger(name)
        if not any(isinstance(f, _RedactingFilter) for f in lg.filters):
            lg.addFilter(_RedactingFilter())
        for h in lg.handlers:
            if not any(isinstance(f, _RedactingFilter) for f in h.filters):
                h.addFilter(_RedactingFilter())
