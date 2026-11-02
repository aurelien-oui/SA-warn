"""``| warn``: show a message under the search bar, optionally on a condition.

    | warn "This dataset is incomplete before 2026-10-01"
    | warn if="count > 1000" level=error "Too many results"
    | eval msg="Only " . count . " hosts" | warn field=msg

No network access, no file written: the command only reads the records that
pass through it and returns them unchanged. level=error stops the search.
"""

import os
import sys

_BIN = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_BIN, "lib"))
sys.path.insert(0, _BIN)

from sa_warn.arguments import ArgumentError, parse_arguments  # noqa: E402
from sa_warn.expr import ExprError  # noqa: E402
from sa_warn.message import render_value, sanitize  # noqa: E402
from splunklib.searchcommands import Configuration, StreamingCommand, dispatch  # noqa: E402
from splunklib.searchcommands.internals import CsvDialect  # noqa: E402


def _quote(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    value = str(value)
    if value == "":
        return ""
    return '"' + value.replace('"', '""') + '"'


@Configuration(distributed=False)
class WarnCommand(StreamingCommand):
    """Pass records through unchanged; emit one message if the condition holds."""

    def __init__(self):
        super().__init__()
        self._settings = None
        self._done = False

    def _protocol_v2_option_parser(self, arg):
        # Arguments are parsed in prepare() from args and raw_args, so that a
        # quoted text containing '=' is not mistaken for an option.
        return [arg]

    def _quote_output_values(self):
        # splunklib writes CSV with QUOTE_MINIMAL, and splunkd strips the
        # surrounding whitespace of unquoted values: " x " came back as "x"
        # (measured on Splunk 9.3). Quote every non-empty value; leave empty
        # ones unquoted so that null stays null.
        writer = self._record_writer
        buffer = writer._buffer

        def writerow(row):
            buffer.write(",".join(_quote(value) for value in row))
            buffer.write(CsvDialect.lineterminator)

        writer._writerow = writerow

    def prepare(self):
        self._quote_output_values()
        info = self.metadata.searchinfo
        try:
            self._settings = parse_arguments(
                getattr(info, "args", None), getattr(info, "raw_args", None)
            )
        except ArgumentError as error:
            self.write_error("{}", f"warn: {error}")
            raise SystemExit(1) from None

    def _emit(self, text):
        # splunklib formats the message with str.format: pass it as an argument
        # so that braces in user text are not interpreted.
        level = self._settings.level
        if level == "error":
            self._stop(text)
        writer = self.write_warning if level == "warn" else self.write_info
        writer("{}", sanitize(text))

    def _stop(self, text):
        # Splunk 10 turns any ERROR message of a custom command into a failed
        # search; 9.x only showed a red banner (measured). level=error is
        # therefore a deliberate stop on every version: splunklib sends the
        # message in a last chunk and the process exits non-zero.
        self.write_error("{}", sanitize(text))
        raise SystemExit(1)

    def _fire(self, record):
        self._done = True
        settings = self._settings
        if settings.field is None:
            self._emit(settings.message)
            return
        value = render_value(record.get(settings.field)) if record is not None else ""
        if value.strip():
            self._emit(value)
        else:
            self._emit(f'warn: field "{settings.field}" is empty or missing')

    def stream(self, records):
        settings = self._settings
        if not self._done and settings.condition is None and settings.field is None:
            self._fire(None)
        for record in records:
            if not self._done:
                if settings.condition is None:
                    self._fire(record)
                else:
                    try:
                        matched = settings.condition(record)
                    except ExprError as error:
                        self._stop(f"warn: if= condition failed: {error}")
                    if matched:
                        self._fire(record)
            yield record


if __name__ == "__main__":
    dispatch(WarnCommand, sys.argv, sys.stdin, sys.stdout, __name__)
