"""Parse the arguments of ``| warn``.

Splunk hands the command two parallel lists: ``args`` (already unquoted and
unescaped by Splunk) and ``raw_args`` (as typed, quotes included). The raw form
tells a quoted text apart from an option, so ``"count=0 before 01/10"`` stays a
message while ``level=error`` is an option. Values always come from ``args``:
quoting rules are Splunk's, not reimplemented here.
"""

import re

from .expr import ExprError, compile_condition

__all__ = ["ArgumentError", "Settings", "parse_arguments", "LEVELS"]

LEVELS = ("warn", "error", "info")
_OPTIONS = ("if", "level", "message", "field")
_OPTION_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=")


class ArgumentError(ValueError):
    pass


class Settings:
    __slots__ = ("message", "field", "condition", "condition_text", "level")

    def __init__(self, message, field, condition, condition_text, level):
        self.message = message
        self.field = field
        self.condition = condition
        self.condition_text = condition_text
        self.level = level


def parse_arguments(args, raw_args):
    """Return Settings, or raise ArgumentError with a user-facing message."""
    args = list(args or [])
    raw_args = list(raw_args or [])
    if len(args) != len(raw_args):
        raise ArgumentError("cannot read the arguments (args and raw_args differ in length)")

    options = {}
    words = []
    for value, raw in zip(args, raw_args):
        match = None if raw.startswith('"') else _OPTION_RE.match(raw)
        if match is None:
            words.append(value)
            continue
        name = match.group(1)
        if name not in _OPTIONS:
            raise ArgumentError(
                f"unknown option '{name}'. Options are: {', '.join(_OPTIONS)}. "
                "Text containing '=' must be quoted."
            )
        if name in options:
            raise ArgumentError(f"option '{name}' is given more than once")
        options[name] = value.split("=", 1)[1]

    if words and "message" in options:
        raise ArgumentError('give the text either as message="..." or as free text, not both')
    if words and "field" in options:
        raise ArgumentError(
            "give either a text or field=<name>, not both (a field is only read through field=)"
        )
    if "message" in options and "field" in options:
        raise ArgumentError("message and field are mutually exclusive")

    message = options.get("message")
    if message is None and words:
        message = " ".join(words)
    field = options.get("field")
    if field is not None:
        field = field.strip()
        if not field:
            raise ArgumentError("field= needs a field name")
    elif message is None or not message.strip():
        raise ArgumentError('a message is required: | warn "text" or | warn field=<name>')

    level = options.get("level", "warn").strip().lower()
    if level not in LEVELS:
        raise ArgumentError(f"level must be one of: {', '.join(LEVELS)}")

    condition = None
    condition_text = options.get("if")
    if condition_text is not None:
        try:
            condition = compile_condition(condition_text)
        except ExprError as error:
            raise ArgumentError(f"invalid if= condition: {error}") from None

    return Settings(message, field, condition, condition_text, level)
