"""Make a message safe to display: one line, no control characters, bounded."""

import unicodedata

__all__ = ["MAX_MESSAGE_LENGTH", "render_value", "sanitize"]

MAX_MESSAGE_LENGTH = 1024
_ELLIPSIS = "\u2026"
# Bidirectional marks and overrides can make a message read differently from
# what it contains ("Trojan Source"): they are dropped.
_BIDI = frozenset("\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


def render_value(raw):
    """Text of a record value for field=: multivalue joined with ', '."""
    if raw is None:
        return ""
    if isinstance(raw, (list, tuple)):
        return ", ".join(str(v) for v in raw if v not in (None, ""))
    return str(raw)


def sanitize(text):
    """Collapse whitespace, drop control and bidirectional-override characters."""
    out = []
    for char in text:
        category = unicodedata.category(char)
        if char in "\t\r\n\v\f" or category in ("Zl", "Zp"):
            out.append(" ")
        elif category in ("Cc", "Cs", "Co", "Cn") or char in _BIDI:
            continue
        else:
            out.append(char)
    cleaned = " ".join("".join(out).split())
    if len(cleaned) > MAX_MESSAGE_LENGTH:
        cleaned = cleaned[: MAX_MESSAGE_LENGTH - 1].rstrip() + _ELLIPSIS
    return cleaned
