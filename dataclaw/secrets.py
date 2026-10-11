"""Detect and redact secrets in conversation data."""

import base64
import binascii
import json
import math
import re
from typing import Any

import ahocorasick

from .anonymizer import Anonymizer

REDACTED = "[REDACTED]"

_GENERIC_SECRET_SUFFIXES = (
    "auth",
    "key",
    "secret",
    "token",
    "password",
    "passwd",
)
_GENERIC_SECRET_SUFFIX_RE = "|".join(re.escape(name) for name in _GENERIC_SECRET_SUFFIXES)
_GENERIC_SECRET_NAME_PATTERN = (
    rf"(?:(?:[A-Za-z0-9]+[_-])*(?:{_GENERIC_SECRET_SUFFIX_RE})"
    rf"|(?:api|access|refresh|client|service|signing|private|session|bot|secret)(?:{_GENERIC_SECRET_SUFFIX_RE})"
    r"|(?-i:[a-z][A-Za-z0-9]*(?:Auth|Key|Secret|Token|Password)))"
    r"(?:[_-][A-Za-z0-9]+)*"
)
_GENERIC_SECRET_NAME_RE = re.compile(rf"{_GENERIC_SECRET_NAME_PATTERN}\Z", re.IGNORECASE)
# A suffix can be followed by another name component, tabs, or newlines.
# Fast paths must never be narrower than their corresponding detector.
_GENERIC_SECRET_MARKERS = _GENERIC_SECRET_SUFFIXES
_OPAQUE_SECRET_CHARS = r"A-Za-z0-9_/+=.:%@!~$*?\-"
_FAST_PATH_CASE_MARKERS = (
    "eyJ",
    "sk-ant-",
    "sk-",
    "sb_secret_",
    "AIzaSy",
    "gsk_",
    "fm1_",
    "fm2_",
    "0x",
    "hf_",
    "ghp_",
    "gho_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "pypi-",
    "npm_",
    "AKIA",
    "xox",
    "discord",
    "PRIVATE KEY",
    "Bearer",
    "密码",
)
_FAST_PATH_LOWER_MARKERS = tuple(
    dict.fromkeys(
        ("postgres", "secret_key", "aws_secret_access_key", "password", "passwd", "bearer", "bot")
        + _GENERIC_SECRET_MARKERS
    )
)
_NON_ANON_STRING_KEYS = frozenset(
    {
        # Keep this list limited to keys in DataClaw's normalized export schema.
        # Providers that preserve source-specific raw payload fields can expose
        # NON_ANON_STRING_KEYS in their parser module; export passes those here.
        "session_id",
        "model",
        "git_branch",
        "start_time",
        "end_time",
        "role",
        "timestamp",
        "tool",
        "status",
        "type",
        "media_type",
        "source",
        "project",
    }
)

# Ordered from most specific to least specific
SECRET_PATTERNS = [
    # JWT tokens - full 3-segment form
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}")),
    # JWT tokens - partial (header only or header+partial payload, e.g. truncated)
    ("jwt_partial", re.compile(r"eyJ[A-Za-z0-9_-]{15,}")),
    # PostgreSQL/database connection strings with passwords
    ("db_url", re.compile(r"postgres(?:ql)?://[^:]+:[^@\s]+@[^\s\"'`]+")),
    # Anthropic API keys
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    # OpenAI project/service-account keys and compatible provider prefixes.
    # Keep the prefix list explicit to avoid treating ordinary sk-* identifiers as keys.
    (
        "openai_key",
        re.compile(
            r"(?<![A-Za-z0-9_-])sk-(?:(?:proj|svcacct|or-v1|cp|api)-[A-Za-z0-9_-]{20,}"
            r"|[0-9a-fA-F]{32}|[A-Za-z0-9]{40,})(?![A-Za-z0-9_-])"
        ),
    ),
    ("supabase_secret", re.compile(r"\bsb_secret_[A-Za-z0-9_-]{20,}")),
    # FAL key-id:secret pairs and Zhipu id.secret pairs; a UUID/hash alone is not a key.
    (
        "fal_key",
        re.compile(
            r"(?<![A-Za-z0-9_-])[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}"
            r":[A-Za-z0-9_-]{32,}(?![A-Za-z0-9_-])"
        ),
    ),
    (
        "zhipu_key",
        re.compile(r"(?<![A-Za-z0-9_.-])[0-9a-fA-F]{32}\.[A-Za-z0-9]{16}(?![A-Za-z0-9_-])"),
    ),
    # Google API keys (Gemini, Maps, etc.)
    ("google_api_key", re.compile(r"AIzaSy[A-Za-z0-9_-]{33}")),
    # Groq API keys
    ("groq_key", re.compile(r"gsk_[A-Za-z0-9]{20,}")),
    # Telegram bot tokens
    ("telegram_token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")),
    # Fly.io machine/access tokens
    ("flyio_token", re.compile(r"fm[12]_[A-Za-z0-9/+=]{20,}")),
    # Ethereum / EVM private keys (0x + 64 hex chars)
    ("eth_private_key", re.compile(r"0x[0-9a-fA-F]{56,64}\b")),
    # Hugging Face tokens
    ("hf_token", re.compile(r"hf_[A-Za-z0-9]{20,}")),
    # GitHub tokens
    ("github_token", re.compile(r"(?:ghp|gho|ghs|ghr)_[A-Za-z0-9]{30,}")),
    ("github_pat_token", re.compile(r"github_pat_[A-Za-z0-9]{22,}_[A-Za-z0-9]{59,}")),
    # PyPI tokens
    ("pypi_token", re.compile(r"pypi-[A-Za-z0-9_-]{50,}")),
    # NPM tokens
    ("npm_token", re.compile(r"npm_[A-Za-z0-9]{30,}")),
    # AWS access key IDs (but not in regex pattern context)
    ("aws_key", re.compile(r"(?<![A-Za-z0-9\[])AKIA[0-9A-Z]{16}(?![0-9A-Z\]{}])")),
    # AWS secret keys (40 chars, mixed case + special) - allow suffixed names like _GUTENBERG
    (
        "aws_secret",
        re.compile(
            r"(?:aws_secret_access_key\w*|secret_key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
            re.IGNORECASE,
        ),
    ),
    # Slack tokens
    ("slack_token", re.compile(r"xox[bpsa]-[A-Za-z0-9-]{20,}")),
    # Discord webhook URLs (contain a secret token in the path)
    ("discord_webhook", re.compile(r"https?://(?:discord\.com|discordapp\.com)/api/webhooks/\d+/[A-Za-z0-9_-]{20,}")),
    # Validate the first segment as an encoded numeric account ID in scan_text.
    (
        "discord_token",
        re.compile(
            r"(?<![A-Za-z0-9_.-])[A-Za-z0-9_-]{20,32}\.[A-Za-z0-9_-]{6,8}"
            r"\.[A-Za-z0-9_-]{27,110}(?![A-Za-z0-9_-])"
        ),
    ),
    ("discord_mfa_token", re.compile(r"\bmfa\.[A-Za-z0-9_-]{80,}(?![A-Za-z0-9_-])")),
    # Private keys
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
            r"[\s\S]*?"
            r"-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
        ),
    ),
    # Generic secret references across CLI flags, URL params, JSON, and assignments
    (
        "generic_secret",
        re.compile(
            rf"""
            (?<![A-Za-z0-9])
            {_GENERIC_SECRET_NAME_PATTERN}
            (?![A-Za-z0-9_-])
            ['"]?
            (?:\s*[=:]\s*|\s+)
            (?:"(?P<double_quoted>[^"\r\n]{{16,}})"
              |'(?P<single_quoted>[^'\r\n]{{16,}})'
              |(?P<unquoted>[{_OPAQUE_SECRET_CHARS}]{{16,}}))
            """,
            re.IGNORECASE | re.VERBOSE,
        ),
    ),
    # Bearer tokens in headers (JWT and non-JWT)
    ("bearer", re.compile(rf"(?:Bearer|Bot)\s+([{_OPAQUE_SECRET_CHARS}]{{20,}})", re.IGNORECASE)),
    # IP addresses (public, non-loopback, non-private-by-default)
    (
        "ip_address",
        re.compile(
            r"\b(?!127\.0\.0\.)(?!0\.0\.0\.0)(?!255\.255\.)"
            r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
        ),
    ),
    # Passwords pasted after a keyword (English/Chinese), on same or next line
    (
        "password_value",
        re.compile(
            rf"(?<![A-Za-z0-9])(?:password|passwd|密码)(?:[_-][A-Za-z0-9]+)*(?![A-Za-z0-9_-])\s*[=:]?\s*\n?\s*"
            rf'''(?:"(?P<double_quoted>[^"\r\n]{{8,}})"'''
            rf"|'(?P<single_quoted>[^'\r\n]{{8,}})'"
            rf"|(?P<unquoted>[{_OPAQUE_SECRET_CHARS}]{{8,}}))",
            re.IGNORECASE,
        ),
    ),
    # Email addresses (for PII removal) - require at least 2-char local part
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]{2,}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    # Long base64-like strings in quotes (checked for entropy - see scan_text)
    ("high_entropy", re.compile(r"""['"][A-Za-z0-9_/+=.-]{40,}['"]""")),
]

ALLOWLIST = [
    re.compile(r"noreply@"),
    re.compile(r"@example\.com"),
    re.compile(r"@localhost"),
    re.compile(r"@anthropic\.com"),
    re.compile(r"@github\.com"),
    re.compile(r"@users\.noreply\.github\.com"),
    re.compile(r"AKIA\["),  # regex patterns about AWS keys
    re.compile(r"sk-ant-\.\*"),  # regex patterns about API keys
    re.compile(r"postgres://user:pass@"),  # example/documentation URLs  # nosec B105
    re.compile(r"postgres://username:password@"),  # nosec B105
    re.compile(r"@pytest"),  # Python decorator false positives
    re.compile(r"@tasks\."),
    re.compile(r"@mcp\."),
    re.compile(r"@server\."),
    re.compile(r"@app\."),
    re.compile(r"@router\."),
    re.compile(r"192\.168\."),  # private IPs (low risk)
    re.compile(r"10\.\d+\.\d+\.\d+"),
    re.compile(r"172\.(?:1[6-9]|2\d|3[01])\."),
    re.compile(r"8\.8\.8\.8"),  # Google DNS
    re.compile(r"8\.8\.4\.4"),
    re.compile(r"1\.1\.1\.1"),  # Cloudflare DNS
]

_BASE64_BLOB_RE = re.compile(r"(?:[A-Za-z0-9+/]{4}){1024,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_WHITESPACE_RE = re.compile(r"\s+")
_DIGIT_RE = re.compile(r"\d")
_TELEGRAM_PREFIX_RE = re.compile(r"\b\d{8,10}:")
_IPV4_CANDIDATE_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def should_skip_large_binary_string(text: str) -> bool:
    """Return True for large base64/binary-like payloads we should not rewrite."""
    if not text or len(text) < 4096:
        return False

    if text.startswith("data:") and "base64," in text[:128]:
        return True

    # ANSI color/control sequences are common in long terminal output and should
    # still be treated as text, not binary blobs.
    # Examine the whole value: a binary-looking prefix or a single NUL must not
    # hide plaintext credentials later in a terminal output string.
    sample_without_ansi = text if "\x1b" not in text else _ANSI_ESCAPE_RE.sub("", text)
    compact = (
        sample_without_ansi
        if _WHITESPACE_RE.search(sample_without_ansi) is None
        else _WHITESPACE_RE.sub("", sample_without_ansi)
    )
    if len(compact) < 4096:
        return False
    return _BASE64_BLOB_RE.fullmatch(compact) is not None


def should_skip_structured_string_transform(
    key: str | None,
    value: str,
    parent_dict: dict[str, Any] | None,
) -> bool:
    """Return True for schema-marked binary/document payload strings we should not rewrite."""
    if key == "data" and isinstance(parent_dict, dict) and parent_dict.get("type") == "base64":
        return True
    return bool(key == "url" and value.startswith("data:"))


def contains_large_binary_value(value: Any) -> bool:
    if isinstance(value, str):
        return should_skip_large_binary_string(value)
    if isinstance(value, dict):
        return any(contains_large_binary_value(child_value) for child_value in value.values())
    if isinstance(value, list):
        return any(contains_large_binary_value(item) for item in value)
    return False


def summarize_large_binary_value(value: Any) -> Any:
    if isinstance(value, str) and should_skip_large_binary_string(value):
        return {"type": "large_blob", "length": len(value)}
    if isinstance(value, dict):
        return {key: summarize_large_binary_value(child_value) for key, child_value in value.items()}
    if isinstance(value, list):
        return [summarize_large_binary_value(item) for item in value]
    return value


def shannon_entropy(s: str) -> float:
    """Higher values indicate more random-looking strings."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def has_mixed_char_types(s: str) -> bool:
    """Check if string has a mix of uppercase, lowercase, and digits."""
    has_upper = any(c.isupper() for c in s)
    has_lower = any(c.islower() for c in s)
    has_digit = any(c.isdigit() for c in s)
    return has_upper and has_lower and has_digit


def _build_marker_automaton(markers: tuple[str, ...]):
    automaton = ahocorasick.Automaton()
    for marker in markers:
        automaton.add_word(marker, marker)
    automaton.make_automaton()
    return automaton


_FAST_PATH_CASE_AUTOMATON = _build_marker_automaton(_FAST_PATH_CASE_MARKERS)
_FAST_PATH_LOWER_AUTOMATON = _build_marker_automaton(_FAST_PATH_LOWER_MARKERS)


class _FastPathState:
    __slots__ = ("_case_markers", "_has_digit", "_has_ipv4_candidate", "_has_telegram_prefix", "_lower_markers", "text")

    def __init__(self, text: str):
        self.text = text
        self._case_markers: set[str] | None = None
        self._lower_markers: set[str] | None = None
        self._has_digit: bool | None = None
        self._has_telegram_prefix: bool | None = None
        self._has_ipv4_candidate: bool | None = None

    def case_markers(self) -> set[str]:
        if self._case_markers is None:
            self._case_markers = {marker for _, marker in _FAST_PATH_CASE_AUTOMATON.iter(self.text)}
        return self._case_markers

    def lower_markers(self) -> set[str]:
        if self._lower_markers is None:
            self._lower_markers = {marker for _, marker in _FAST_PATH_LOWER_AUTOMATON.iter(self.text.lower())}
        return self._lower_markers

    def has_digit(self) -> bool:
        if self._has_digit is None:
            self._has_digit = _DIGIT_RE.search(self.text) is not None
        return self._has_digit

    def has_telegram_prefix(self) -> bool:
        if self._has_telegram_prefix is None:
            self._has_telegram_prefix = _TELEGRAM_PREFIX_RE.search(self.text) is not None
        return self._has_telegram_prefix

    def has_ipv4_candidate(self) -> bool:
        if self._has_ipv4_candidate is None:
            self._has_ipv4_candidate = _IPV4_CANDIDATE_RE.search(self.text) is not None
        return self._has_ipv4_candidate


def _has_any_marker(found_markers: set[str], needles: tuple[str, ...]) -> bool:
    return any(needle in found_markers for needle in needles)


def _pattern_may_match(name: str, state: _FastPathState) -> bool:
    text = state.text
    if name in ("jwt", "jwt_partial"):
        return "eyJ" in state.case_markers()
    if name == "db_url":
        return "postgres" in state.lower_markers()
    if name == "anthropic_key":
        return "sk-ant-" in state.case_markers()
    if name == "openai_key":
        return "sk-" in state.case_markers()
    if name == "supabase_secret":
        return "sb_secret_" in state.case_markers()
    if name == "fal_key":
        return len(text) >= 69 and ":" in text and "-" in text
    if name == "zhipu_key":
        return len(text) >= 49 and "." in text
    if name == "discord_token":
        return len(text) >= 55 and text.count(".") >= 2
    if name == "discord_mfa_token":
        return "mfa." in text
    if name == "google_api_key":
        return "AIzaSy" in state.case_markers()
    if name == "groq_key":
        return "gsk_" in state.case_markers()
    if name == "telegram_token":
        return len(text) >= 44 and ":" in text and state.has_telegram_prefix()
    if name == "flyio_token":
        case_markers = state.case_markers()
        return "fm1_" in case_markers or "fm2_" in case_markers
    if name == "eth_private_key":
        return "0x" in state.case_markers()
    if name == "hf_token":
        return "hf_" in state.case_markers()
    if name == "github_token":
        return _has_any_marker(state.case_markers(), ("ghp_", "gho_", "ghs_", "ghr_"))
    if name == "github_pat_token":
        return "github_pat_" in state.case_markers()
    if name == "pypi_token":
        return "pypi-" in state.case_markers()
    if name == "npm_token":
        return "npm_" in state.case_markers()
    if name == "aws_key":
        return "AKIA" in state.case_markers()
    if name == "aws_secret":
        if "=" not in text and ":" not in text:
            return False
        return _has_any_marker(state.lower_markers(), ("secret_key", "aws_secret_access_key"))
    if name == "slack_token":
        return "xox" in state.case_markers()
    if name == "discord_webhook":
        return "discord" in state.case_markers() and "/api/webhooks/" in text
    if name == "private_key":
        return "PRIVATE KEY" in state.case_markers() and "-----BEGIN" in text and "-----END" in text
    if name == "generic_secret":
        if (
            "-" not in text
            and "=" not in text
            and ":" not in text
            and "?" not in text
            and "&" not in text
            and " " not in text
        ):
            return False
        return _has_any_marker(state.lower_markers(), _GENERIC_SECRET_MARKERS)
    if name == "bearer":
        return _has_any_marker(state.lower_markers(), ("bearer", "bot")) and len(text) >= 24
    if name == "ip_address":
        return "." in text and state.has_ipv4_candidate()
    if name == "password_value":
        case_markers = state.case_markers()
        lower_markers = state.lower_markers()
        return "password" in lower_markers or "passwd" in lower_markers or "密码" in case_markers
    if name == "email":
        return "@" in text and "." in text
    if name == "high_entropy":
        return ('"' in text or "'" in text) and state.has_digit()
    return True


def _is_secret_reference(value: str) -> bool:
    """Recognize complete placeholder/lookup expressions, never substrings of keys."""
    if value in {REDACTED, "your_api_key_here", "your_secret_key_here", "your_token_here", "changeme", "replace_me"}:
        return True
    if re.fullmatch(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*|<[A-Z_]+>", value):
        return True
    name = r"[A-Za-z_][A-Za-z0-9_]*"
    return bool(
        re.fullmatch(rf"(?:process\.env|import\.meta\.env)\.{name}", value)
        or re.fullmatch(rf"(?:os\.environ|process\.env|import\.meta\.env)\[(?:'{name}'|\"{name}\")\]", value)
        or re.fullmatch(rf"(?:os\.getenv|os\.environ\.get)\((?:'{name}'|\"{name}\")\)", value)
    )


def _allowlisted_match(name: str, value: str) -> bool:
    # PII exceptions are not credential exceptions. A secret containing a private
    # IP or an example email must still be removed in its entirety.
    if name in {"email", "ip_address", "aws_key", "anthropic_key"}:
        return any(pattern.search(value) for pattern in ALLOWLIST)
    if name == "db_url":
        return bool(
            re.fullmatch(
                r"postgres(?:ql)?://(?:user:pass|username:password)@"
                r"(?:localhost|(?:[A-Za-z0-9-]+\.)?example\.com)(?::\d+)?(?:/[^\s?#]*)?",
                value,
            )
        )
    return False


def scan_text(text: str) -> list[dict]:
    if not text:
        return []

    findings = []
    fast_path_state = _FastPathState(text)
    for name, pattern in SECRET_PATTERNS:
        if not _pattern_may_match(name, fast_path_state):
            continue
        for match in pattern.finditer(text):
            matched_text = match.group(0)

            if _allowlisted_match(name, matched_text):
                continue

            if name == "discord_token":
                first = matched_text.split(".", 1)[0]
                try:
                    account = base64.b64decode(first + "=" * (-len(first) % 4), altchars=b"-_", validate=True)
                except (ValueError, binascii.Error):
                    continue
                if re.fullmatch(rb"[1-9][0-9]{14,21}", account) is None:
                    continue
            if name in {"generic_secret", "password_value"}:
                secret = next(value for value in match.groupdict().values() if value is not None)
                if _is_secret_reference(secret):
                    continue

            # For high_entropy, verify string actually looks like a secret
            if name == "high_entropy":
                inner = matched_text[1:-1]  # strip quotes
                if _is_secret_reference(inner):
                    continue
                if not has_mixed_char_types(inner):
                    continue
                if shannon_entropy(inner) < 3.5:
                    continue
                if inner.count(".") > 2:
                    continue

            findings.append(
                {
                    "type": name,
                    "start": match.start(),
                    "end": match.end(),
                    "match": matched_text,
                }
            )

    return findings


def redact_text(text: str) -> tuple[str, int]:
    if not text:
        return text, 0
    if should_skip_large_binary_string(text):
        return text, 0

    findings = scan_text(text)
    if not findings:
        return text, 0

    # Redact the UNION of overlaps. Keeping just an inner match can leave the
    # rest of a credential (for example a JWT signature or FAL suffix) behind.
    spans: list[tuple[int, int]] = []
    for finding in sorted(findings, key=lambda item: (item["start"], item["end"])):
        start, end = finding["start"], finding["end"]
        if spans and start < spans[-1][1]:
            spans[-1] = (spans[-1][0], max(spans[-1][1], end))
        else:
            spans.append((start, end))

    result = text
    for start, end in reversed(spans):
        result = result[:start] + REDACTED + result[end:]

    return result, len(spans)


def redact_custom_strings(text: str, strings: list[str]) -> tuple[str, int]:
    if not text or not strings:
        return text, 0

    original_text = text
    count = 0
    for target in strings:
        if not target or len(target) < 3:
            continue
        escaped = re.escape(target)
        pattern = rf"\b{escaped}\b" if len(target) >= 4 else escaped
        text, replacements = re.subn(pattern, REDACTED, text)
        count += replacements

    if count == 0:
        return original_text, 0
    return text, count


def _transform_value(
    value: Any,
    anonymizer: Anonymizer | None = None,
    custom_strings: list[str] | None = None,
    key: str | None = None,
    parent_dict: dict[str, Any] | None = None,
    non_anon_string_keys: frozenset[str] = _NON_ANON_STRING_KEYS,
    embedded_depth: int = 0,
) -> tuple[Any, int, bool]:
    """Recursively anonymize and/or redact a string, list, or dict value."""
    if isinstance(value, str):
        if should_skip_structured_string_transform(key, value, parent_dict):
            return value, 0, False
        # A structured key supplies the context that scanning its value alone
        # loses. Never mistake schema IDs or lookup expressions for credentials.
        if (
            isinstance(key, str)
            and _GENERIC_SECRET_NAME_RE.fullmatch(key)
            and len(value) >= (8 if re.search(r"password|passwd", key, re.IGNORECASE) else 16)
            and (
                re.fullmatch(rf"[{_OPAQUE_SECRET_CHARS}]+", value)
                or (re.search(r"password|passwd", key, re.IGNORECASE) and "\n" not in value and "\r" not in value)
            )
            and not _is_secret_reference(value)
        ):
            return REDACTED, 1, True

        if should_skip_large_binary_string(value):
            return value, 0, False

        # Some providers preserve a whole message/tool result as a JSON string.
        # Decode only complete JSON containers, so key-based protection also
        # applies inside these wrappers. Leave unchanged strings byte-for-byte.
        if embedded_depth < 8 and value.lstrip().startswith(("{", "[")):
            try:
                embedded = json.loads(value)
            except (ValueError, RecursionError):
                pass
            else:
                if isinstance(embedded, (dict, list)):
                    transformed, n, changed = _transform_value(
                        embedded,
                        anonymizer,
                        custom_strings,
                        non_anon_string_keys=non_anon_string_keys,
                        embedded_depth=embedded_depth + 1,
                    )
                    if changed:
                        return json.dumps(transformed, ensure_ascii=False), n, True
                    return value, 0, False

        result = value
        count = 0
        changed = False

        if anonymizer is not None and key not in non_anon_string_keys:
            anonymized = anonymizer.text(result)
            if anonymized != result:
                result = anonymized
                changed = True

        result, count = redact_text(result)
        if count > 0:
            changed = True
        if custom_strings:
            result, n = redact_custom_strings(result, custom_strings)
            count += n
            if n > 0:
                changed = True
        return result, count, changed

    if isinstance(value, dict):
        total = 0
        out: dict[Any, Any] | None = None
        for k, v in value.items():
            transformed, n, changed = _transform_value(
                v, anonymizer, custom_strings, k, value, non_anon_string_keys, embedded_depth
            )
            total += n
            transformed_key = k
            if isinstance(k, str):
                transformed_key, n = redact_text(k)
                total += n
                if custom_strings:
                    transformed_key, n = redact_custom_strings(transformed_key, custom_strings)
                    total += n
            key_changed = transformed_key != k
            if out is None:
                if not changed and not key_changed:
                    continue
                out = dict(value)
            if key_changed:
                del out[k]
                # Two secret-bearing keys must not overwrite one another, or a
                # pre-existing literal [REDACTED] field, after sanitization.
                base_key = transformed_key
                suffix = 2
                while transformed_key in out:
                    transformed_key = f"{base_key}#{suffix}"
                    suffix += 1
            out[transformed_key] = transformed
        if out is None:
            return value, 0, False
        return out, total, True

    if isinstance(value, list):
        total = 0
        out_list: list[Any] | None = None
        for idx, item in enumerate(value):
            transformed, n, changed = _transform_value(
                item,
                anonymizer,
                custom_strings,
                key,
                parent_dict,
                non_anon_string_keys,
                embedded_depth,
            )
            total += n
            if out_list is None:
                if not changed:
                    continue
                out_list = list(value[:idx])
            out_list.append(transformed)
        if out_list is None:
            return value, 0, False
        return out_list, total, True
    return value, 0, False


def transform_session(
    session: dict,
    anonymizer: Anonymizer,
    custom_strings: list[str] | None = None,
    non_anon_string_keys: frozenset[str] | set[str] | None = None,
) -> tuple[dict, int]:
    """Anonymize and redact all exported session content in one pass."""
    effective_non_anon_string_keys = _NON_ANON_STRING_KEYS | frozenset(non_anon_string_keys or ())

    # Project labels are intentionally kept in non_anon_string_keys so they're stable identifiers,
    # but the label is constructed from cwd basenames that can contain the user's username
    # (e.g. `/Users/alice` -> "claude:alice"). Run the label through the anonymizer's text rewrite
    # so usernames embedded in the label get hashed; non-username basenames pass through unchanged.
    project_label = session.get("project")
    if isinstance(project_label, str) and project_label:
        anonymized_label = anonymizer.text(project_label)
        if anonymized_label != project_label:
            session["project"] = anonymized_label

    transformed, total, changed = _transform_value(
        session, anonymizer, custom_strings, non_anon_string_keys=effective_non_anon_string_keys
    )
    if changed:
        session.clear()
        session.update(transformed)
    return session, total


def redact_session(session: dict, custom_strings: list[str] | None = None) -> tuple[dict, int]:
    """Redact all secrets in a session dict. Returns (redacted_session, total_redactions)."""
    transformed, total, changed = _transform_value(session, custom_strings=custom_strings)
    if changed:
        session.clear()
        session.update(transformed)
    return session, total
