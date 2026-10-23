"""
Sink classification — single source of truth
============================================
Both the code scanner (which *labels* a finding's sink) and the rule engine
(which *routes* a finding to Rule 2a or Rule 2b) import from here, so the two
can never disagree about what a sink is called.

`canonical_sink(text)` takes a piece of code — a whole line, or the callee of
a call expression followed by "(" (e.g. "self.logger.warning(") — and returns
a short canonical label such as "mixpanel", "requests.post", "axios.post",
"fetch", "kafka", "celery", "logger", "print", or None if no sink is present.

`sink_kind(label)` maps a canonical label to one of
"sdk" | "http" | "queue" | "logger" | None.

`recipient_for_url(url)` names the RECIPIENT of an HTTP call from its URL:
a known SDK host gives that SDK's label (a POST to *.firebaseio.com is
Firebase, to api.segment.io is Segment), any other host gives the host name
(e.g. "maps.googleapis.com"). The scanner uses it so that one recipient is
reported once, whether the code calls it through its SDK or over plain HTTP
(previously "firebase" and "requests.post" were two separate recipients).

Matching uses identifier boundaries instead of raw substrings, so
"fingerprint(" / "Blueprint(" are not mistaken for print(), "user_segment"
is not the Segment SDK, and "catalog" is not a logger.
"""

import re

# Identifier boundary: the needle must not be glued to a preceding
# letter / digit / underscore (so "fingerprint(" does not contain a print call).
_L = r'(?<![A-Za-z0-9_])'

# ── Third-party SDKs (Rule 2a: Section 8(2)) ─────────────────────────────────
# Right side is left open on purpose so "mixpanel_client" / "firebaseApp"
# still count as the SDK.
SDK_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(_L + r'firestore', re.I),   'firebase'),
    (re.compile(_L + r'firebase', re.I),    'firebase'),
    (re.compile(_L + r'crashlytics', re.I), 'crashlytics'),
    (re.compile(_L + r'mixpanel', re.I),    'mixpanel'),
    (re.compile(_L + r'amplitude', re.I),   'amplitude'),
    (re.compile(_L + r'segment[._]', re.I), 'segment'),
    (re.compile(_L + r'clevertap', re.I),   'clevertap'),
    (re.compile(_L + r'analytics\s*[.(]', re.I), 'analytics'),
    (re.compile(_L + r'twilio', re.I),      'twilio'),
    (re.compile(_L + r'sendgrid', re.I),    'sendgrid'),
]

# ── Outbound HTTP (Rule 2a) ──────────────────────────────────────────────────
HTTP_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(_L + r'requests\s*\.\s*post\s*\(', re.I),  'requests.post'),
    # GET requests send data too (query parameters, path segments): a
    # geocoding call with the user's coordinates is a transmission.
    (re.compile(_L + r'requests\s*\.\s*get\s*\(', re.I),   'requests.get'),
    (re.compile(_L + r'httpx\s*\.\s*get\s*\(', re.I),      'httpx.get'),
    (re.compile(_L + r'axios\s*\.\s*get\s*\(', re.I),      'axios.get'),
    (re.compile(_L + r'requests\s*\.\s*put\s*\(', re.I),   'requests.put'),
    (re.compile(_L + r'requests\s*\.\s*patch\s*\(', re.I), 'requests.patch'),
    (re.compile(_L + r'httpx\s*\.\s*post\s*\(', re.I),     'httpx.post'),
    (re.compile(_L + r'httpx\s*\.\s*put\s*\(', re.I),      'httpx.put'),
    (re.compile(_L + r'axios\s*\.\s*post\s*\(', re.I),     'axios.post'),
    (re.compile(_L + r'axios\s*\.\s*put\s*\(', re.I),      'axios.put'),
    (re.compile(_L + r'axios\s*\.\s*patch\s*\(', re.I),    'axios.patch'),
    (re.compile(_L + r'fetch\s*\(', re.I),                 'fetch'),
    (re.compile(_L + r'urlopen\s*\(', re.I),               'urllib'),
]

# ── Queues / message brokers (Rule 2a) ───────────────────────────────────────
QUEUE_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(_L + r'kafka', re.I),                       'kafka'),
    (re.compile(_L + r'producer\s*\.\s*send\s*\(', re.I),   'kafka'),
    (re.compile(_L + r'rabbitmq', re.I),                    'rabbitmq'),
    (re.compile(r'\.\s*basic_publish\s*\(', re.I),          'rabbitmq'),
    (re.compile(_L + r'celery', re.I),                      'celery'),
    (re.compile(r'\.\s*delay\s*\(', re.I),                  'celery'),
    (re.compile(r'\.\s*apply_async\s*\(', re.I),            'celery'),
    (re.compile(_L + r'redis\w*\s*\.\s*publish\s*\(', re.I), 'redis.publish'),
    (re.compile(_L + r'pubsub', re.I),                      'pubsub'),
]

# ── Loggers / monitoring (Rule 2b: Section 8(5)) ─────────────────────────────
LOGGER_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(_L + r'sentry(?:_sdk)?\s*\.\s*capture', re.I), 'sentry'),
    (re.compile(_L + r'datadog', re.I),                        'datadog'),
    (re.compile(_L + r'cloudwatch', re.I),                     'cloudwatch'),
    (re.compile(r'console\s*\.\s*(?:log|error|warn|info|debug)\s*\(', re.I), 'console.log'),
    (re.compile(_L + r'logging\s*\.\s*(?:debug|info|warning|warn|error|exception|critical|log)\s*\(', re.I), 'logging'),
    # matches logger.info(…) and self.logger.info(…) / app.logger.info(…)
    (re.compile(r'(?:^|[^A-Za-z0-9_])logger\s*\.\s*(?:debug|info|warning|warn|error|exception|critical|log)\s*\(', re.I), 'logger'),
    (re.compile(r'(?:^|[^A-Za-z0-9_.])log\s*\.\s*(?:debug|info|warning|warn|error)\s*\(', re.I), 'log'),
    (re.compile(_L + r'print\s*\(', re.I),                     'print'),
]

SDK_LABELS    = {lbl for _, lbl in SDK_RULES}
HTTP_LABELS   = {lbl for _, lbl in HTTP_RULES}
QUEUE_LABELS  = {lbl for _, lbl in QUEUE_RULES}
LOGGER_LABELS = {lbl for _, lbl in LOGGER_RULES}
# Loggers that SEND the data to an outside logging / monitoring service (a
# third party processing it) rather than writing the application's own logs.
EXTERNAL_LOGGER_LABELS = {'sentry', 'datadog', 'cloudwatch'}

# Priority when several sinks share a line: a named third-party SDK first,
# then HTTP, then queues, then loggers.
_ORDERED = SDK_RULES + HTTP_RULES + QUEUE_RULES + LOGGER_RULES


def canonical_sink(text: str | None) -> str | None:
    """Return the canonical sink label found in `text`, or None."""
    if not text:
        return None
    for pattern, label in _ORDERED:
        if pattern.search(text):
            return label
    return None


# ── Recipients of HTTP calls, by host ────────────────────────────────────────
# Host (or parent domain) → SDK label. Matched on the host name only.
HOST_SDK: dict[str, str] = {
    'firebaseio.com':            'firebase',
    'firebasedatabase.app':      'firebase',
    'firebase.googleapis.com':   'firebase',
    'firestore.googleapis.com':  'firebase',
    'firebaselogging.googleapis.com': 'firebase',
    'crashlytics.com':           'crashlytics',
    'segment.io':                'segment',
    'segment.com':               'segment',
    'mixpanel.com':              'mixpanel',
    'amplitude.com':             'amplitude',
    'clevertap.com':             'clevertap',
    'clevertap-prod.com':        'clevertap',
    'google-analytics.com':      'analytics',
    'twilio.com':                'twilio',
    'sendgrid.com':              'sendgrid',
    'sendgrid.net':              'sendgrid',
}
_HOST_LABEL_RE = re.compile(r'^(?=.{1,253}$)[a-z0-9-]+(?:\.[a-z0-9-]+)+$')


def url_host(url: str | None) -> str | None:
    """Host name of an absolute http(s) URL, lower-cased; None otherwise."""
    if not url:
        return None
    from urllib.parse import urlparse
    try:
        p = urlparse(url.strip())
    except ValueError:
        return None
    if p.scheme not in ('http', 'https') or not p.hostname:
        return None
    return p.hostname.lower()


def recipient_for_url(url: str | None) -> str | None:
    """SDK label for a known SDK host, else the host name, else None."""
    host = url_host(url)
    if not host:
        return None
    for domain, label in HOST_SDK.items():
        if host == domain or host.endswith('.' + domain):
            return label
    return host


def sink_kind(label: str | None) -> str | None:
    """Map a canonical label to 'sdk' | 'http' | 'queue' | 'logger' | None.
    A host name produced by recipient_for_url() is an HTTP recipient."""
    if not label:
        return None
    lbl = label.lower()
    if lbl in LOGGER_LABELS:
        return 'logger'
    if lbl in SDK_LABELS:
        return 'sdk'
    if lbl in HTTP_LABELS:
        return 'http'
    if lbl in QUEUE_LABELS:
        return 'queue'
    # Non-canonical label (e.g. stored by an older scanner version):
    # classify it by running the matcher over it.
    again = canonical_sink(label if '(' in label else label + '(')
    if again and again.lower() != lbl:
        return sink_kind(again)
    # A host name from recipient_for_url() (e.g. "maps.googleapis.com").
    return 'http' if _HOST_LABEL_RE.match(lbl) else None


# ── Naming an SDK in privacy-policy prose (policy_parser Pass 3) ─────────────
# Policies are plain English, so the code patterns above don't apply. Each
# SDK label gets a whole-word pattern for how a policy would name it. Two
# labels are also everyday words and need a qualifier:
#   "analytics" — only a named product ("Google Analytics", "Firebase
#                 Analytics"), never the generic word ("we use analytics");
#   "segment"   — only the company ("Segment.com", "Twilio Segment",
#                 "Segment CDP"), never "we segment customers".
SDK_DISCLOSURE_PATTERNS: dict[str, re.Pattern] = {
    'firebase':    re.compile(r'\b(?:firebase|firestore)\b'),
    'crashlytics': re.compile(r'\bcrashlytics\b'),
    'mixpanel':    re.compile(r'\bmixpanel\b'),
    'amplitude':   re.compile(r'\bamplitude\b'),
    'segment':     re.compile(r'\bsegment\s*\.\s*(?:com|io)\b|\btwilio\s+segment\b|\bsegment\s+(?:cdp|inc)\b'),
    'clevertap':   re.compile(r'\bclevertap\b'),
    'analytics':   re.compile(r'\b(?:google|firebase|adobe)\s+analytics\b'),
    'twilio':      re.compile(r'\btwilio\b'),
    'sendgrid':    re.compile(r'\bsendgrid\b'),
    # external logging / monitoring services (EXTERNAL_LOGGER_LABELS)
    'sentry':      re.compile(r'\bsentry\b'),
    'datadog':     re.compile(r'\bdatadog\b'),
    'cloudwatch':  re.compile(r'\bcloudwatch\b'),
}


def sdks_named_in(text_lower: str) -> set[str]:
    """Canonical SDK labels that a (lower-cased) policy sentence names."""
    return {label for label, rx in SDK_DISCLOSURE_PATTERNS.items() if rx.search(text_lower)}
