"""Evaluator for a subset of the SPL ``where`` / ``eval`` expression language.

Pure Python, no ``eval()``, no I/O. The expression is parsed once, statically
checked (functions, arity, boolean result), then evaluated against each record.

Semantics follow what was measured on Splunk 9.3 (see docs/conception.md):

* ``=`` and ``LIKE`` are case-sensitive; keywords (AND, OR, NOT, XOR, LIKE, IN)
  are not.
* A field value that looks like a number compares as a number, except against a
  quoted string literal, where both sides compare as strings.
* A comparison involving null yields null; in a boolean context null is false
  (so ``NOT zz=1`` is true when ``zz`` is absent).
* On a multivalue field, ``=`` and the ordering operators are true if any value
  matches; ``!=`` is the negation of ``=``.
* An empty field value is null: the search protocol does not distinguish an
  absent field from an empty one.
"""

import decimal
import ipaddress
import math
import re
import time

__all__ = ["ExprError", "compile_condition", "MAX_EXPRESSION_LENGTH"]

MAX_EXPRESSION_LENGTH = 4096
MAX_DEPTH = 64


class ExprError(ValueError):
    """Invalid expression (raised at compile time) or evaluation failure."""


# --------------------------------------------------------------------------
# Values
# --------------------------------------------------------------------------

_NUMBER_RE = re.compile(r"\s*[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?\s*\Z")


class FieldStr(str):
    """A string that comes from a record: numeric if it looks like a number."""

    __slots__ = ()


class MV(tuple):
    """A multivalue field (tuple of FieldStr, at least two values)."""

    __slots__ = ()


def _as_number(value):
    """Number for a number or a numeric-looking field string, else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, FieldStr) and _NUMBER_RE.match(value):
        number = float(value)
        if number.is_integer() and re.match(r"\s*[+-]?\d+\s*\Z", value):
            return int(value)
        return number
    return None


def _format_number(number):
    if isinstance(number, float):
        if number.is_integer() and abs(number) < 1e16:
            return str(int(number))
        return repr(number)
    return str(number)


def _as_string(value):
    """String form of a scalar, None for null and for a multivalue."""
    if value is None or isinstance(value, MV):
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _format_number(value)
    return str(value)


def _scalar(value):
    """Scalar functions and arithmetic return null on a multivalue (measured)."""
    return None if isinstance(value, MV) else value


def _truth(value):
    return value is True


def field_value(raw):
    """Convert a record value (str, list or None) to an evaluator value."""
    if raw is None:
        return None
    if isinstance(raw, (list, tuple)):
        values = [FieldStr(v) for v in raw if v is not None and v != ""]
        if not values:
            return None
        if len(values) == 1:
            return values[0]
        return MV(values)
    raw = str(raw)
    if raw == "":
        return None
    return FieldStr(raw)


# --------------------------------------------------------------------------
# Tokenizer
# --------------------------------------------------------------------------

_KEYWORDS = {"AND", "OR", "NOT", "XOR", "LIKE", "IN"}

_TOKEN_RE = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<number>(?:\d+(?:\.\d+)?|\.\d+)(?:[eE][+-]?\d+)?)
  | (?P<string>"(?:[^"\\]|\\.)*")
  | (?P<field>'(?:[^'\\]|\\.)*')
  | (?P<name>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<op>==|!=|<=|>=|=|<|>|\+|-|\*|/|%|\.|\(|\)|,)
    """,
    re.VERBOSE,
)

_UNESCAPE_RE = re.compile(r"\\(.)", re.DOTALL)


def _unescape(text):
    return _UNESCAPE_RE.sub(lambda m: m.group(1), text)


def _tokenize(text):
    tokens = []
    position = 0
    while position < len(text):
        match = _TOKEN_RE.match(text, position)
        if match is None:
            raise ExprError(f"unexpected character {text[position]!r} at position {position + 1}")
        kind = match.lastgroup
        value = match.group(kind)
        position = match.end()
        if kind == "ws":
            continue
        if kind == "string":
            tokens.append(("str", _unescape(value[1:-1])))
        elif kind == "field":
            name = _unescape(value[1:-1])
            if not name:
                raise ExprError("empty field name ''")
            tokens.append(("field", name))
        elif kind == "number":
            number = float(value)
            if re.fullmatch(r"\d+", value):
                number = int(value)
            tokens.append(("num", number))
        elif kind == "name":
            if value.upper() in _KEYWORDS:
                tokens.append(("kw", value.upper()))
            else:
                tokens.append(("name", value))
        else:
            tokens.append(("op", value))
    tokens.append(("end", None))
    return tokens


# --------------------------------------------------------------------------
# AST: each node is (static_type, evaluate(record) -> value)
# static_type in {"bool", "num", "str", "any"}
# --------------------------------------------------------------------------


def _compare(op, left, right, left_literal_str, right_literal_str):
    """Comparison with Splunk typing rules. Returns True, False or None."""
    if left is None or right is None:
        return None
    if isinstance(left, MV) or isinstance(right, MV):
        # Measured: '=' is true if any value matches, '!=' is its negation,
        # ordering operators never hold on a multivalue.
        if op not in ("=", "!="):
            return None
        if isinstance(left, MV):
            many, one, many_lit, one_lit = left, right, left_literal_str, right_literal_str
        else:
            many, one, many_lit, one_lit = right, left, right_literal_str, left_literal_str
        others = one if isinstance(one, MV) else (one,)
        found = any(_compare("=", a, b, many_lit, one_lit) is True for a in many for b in others)
        return found if op == "=" else not found
    if isinstance(left, bool) or isinstance(right, bool):
        if op in ("=", "!=") and isinstance(left, bool) and isinstance(right, bool):
            return (left == right) if op == "=" else (left != right)
        return False
    if left_literal_str or right_literal_str:
        a, b = _as_string(left), _as_string(right)
    else:
        a, b = _as_number(left), _as_number(right)
        if a is None or b is None:
            if isinstance(left, (int, float)) or isinstance(right, (int, float)):
                return False
            a, b = _as_string(left), _as_string(right)
    if op == "=":
        return a == b
    if op == "!=":
        return a != b
    if op == "<":
        return a < b
    if op == ">":
        return a > b
    if op == "<=":
        return a <= b
    return a >= b


def _like_regex(pattern):
    out = []
    for char in pattern:
        if char == "%":
            out.append(".*")
        elif char == "_":
            out.append(".")
        else:
            out.append(re.escape(char))
    return re.compile("".join(out) + r"\Z", re.DOTALL)


def _compile_regex(pattern):
    try:
        return re.compile(pattern)
    except re.error as error:
        raise ExprError(f"invalid regular expression {pattern!r}: {error}") from None


class _Parser:
    def __init__(self, text):
        self.tokens = _tokenize(text)
        self.index = 0
        self.depth = 0

    # -- token helpers -----------------------------------------------------

    def peek(self):
        return self.tokens[self.index]

    def advance(self):
        token = self.tokens[self.index]
        self.index += 1
        return token

    def accept(self, kind, value=None):
        token = self.peek()
        if token[0] == kind and (value is None or token[1] == value):
            self.index += 1
            return True
        return False

    def expect(self, kind, value):
        if not self.accept(kind, value):
            raise ExprError(f"expected {value!r}, found {self._describe(self.peek())}")

    @staticmethod
    def _describe(token):
        if token[0] == "end":
            return "end of expression"
        if token[0] == "str":
            return f'"{token[1]}"'
        return repr(str(token[1]))

    def _enter(self):
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise ExprError("expression is nested too deeply")

    def _leave(self):
        self.depth -= 1

    # -- grammar -----------------------------------------------------------

    def parse(self):
        node = self.parse_or()
        if self.peek()[0] != "end":
            raise ExprError(f"unexpected {self._describe(self.peek())}")
        return node

    def parse_or(self):
        left = self.parse_xor()
        while self.accept("kw", "OR"):
            right = self.parse_xor()
            _require_bool(left, "OR")
            _require_bool(right, "OR")
            left = _or(left, right)
        return left

    def parse_xor(self):
        left = self.parse_and()
        while self.accept("kw", "XOR"):
            right = self.parse_and()
            _require_bool(left, "XOR")
            _require_bool(right, "XOR")
            left = _xor(left, right)
        return left

    def parse_and(self):
        left = self.parse_not()
        while self.accept("kw", "AND"):
            right = self.parse_not()
            _require_bool(left, "AND")
            _require_bool(right, "AND")
            left = _and(left, right)
        return left

    def parse_not(self):
        if self.accept("kw", "NOT"):
            self._enter()
            operand = self.parse_not()
            self._leave()
            _require_bool(operand, "NOT")
            return _not(operand)
        return self.parse_comparison()

    def parse_comparison(self):
        left = self.parse_additive()
        token = self.peek()
        if token[0] == "op" and token[1] in ("=", "==", "!=", "<", ">", "<=", ">="):
            self.advance()
            op = "=" if token[1] == "==" else token[1]
            right = self.parse_additive()
            return _comparison(op, left, right)
        if token[0] == "kw" and token[1] == "LIKE":
            self.advance()
            right = self.parse_additive()
            return _call("like", [left, right])
        if token[0] == "kw" and token[1] == "IN":
            self.advance()
            self.expect("op", "(")
            values = [self.parse_or()]
            while self.accept("op", ","):
                values.append(self.parse_or())
            self.expect("op", ")")
            return _call("in", [left] + values)
        return left

    def parse_additive(self):
        left = self.parse_multiplicative()
        while True:
            token = self.peek()
            if token[0] == "op" and token[1] in ("+", "-", "."):
                self.advance()
                right = self.parse_multiplicative()
                left = _arith(token[1], left, right)
            else:
                return left

    def parse_multiplicative(self):
        left = self.parse_unary()
        while True:
            token = self.peek()
            if token[0] == "op" and token[1] in ("*", "/", "%"):
                self.advance()
                right = self.parse_unary()
                left = _arith(token[1], left, right)
            else:
                return left

    def parse_unary(self):
        if self.accept("op", "-"):
            self._enter()
            operand = self.parse_unary()
            self._leave()
            return _arith("*", _const("num", -1), operand)
        if self.accept("op", "+"):
            return self.parse_unary()
        return self.parse_primary()

    def parse_primary(self):
        token = self.advance()
        kind, value = token
        if kind == "num":
            return _const("num", value)
        if kind == "str":
            return _const("str", value)
        if kind == "field":
            return _field(value)
        if kind == "kw" and value in ("LIKE", "IN") and self.peek() == ("op", "("):
            # like() and in() are also functions
            kind, value = "name", value.lower()
        if kind == "name":
            if self.accept("op", "("):
                args = []
                if not self.accept("op", ")"):
                    self._enter()
                    args.append(self.parse_or())
                    while self.accept("op", ","):
                        args.append(self.parse_or())
                    self._leave()
                    self.expect("op", ")")
                return _call(value, args)
            return _field(value)
        if kind == "op" and value == "(":
            self._enter()
            node = self.parse_or()
            self._leave()
            self.expect("op", ")")
            return node
        raise ExprError(f"unexpected {self._describe(token)}")


# -- node builders ---------------------------------------------------------


class _Node:
    __slots__ = ("type", "evaluate", "literal_str")

    def __init__(self, type_, evaluate, literal_str=False):
        self.type = type_
        self.evaluate = evaluate
        self.literal_str = literal_str


def _require_bool(node, where):
    if node.type != "bool":
        raise ExprError(f"{where} only takes boolean arguments")


def _const(type_, value):
    return _Node(type_, lambda record: value, literal_str=(type_ == "str"))


def _field(name):
    def evaluate(record):
        return field_value(record.get(name))

    return _Node("any", evaluate)


def _or(left, right):
    return _Node("bool", lambda r: _truth(left.evaluate(r)) or _truth(right.evaluate(r)))


def _and(left, right):
    return _Node("bool", lambda r: _truth(left.evaluate(r)) and _truth(right.evaluate(r)))


def _xor(left, right):
    return _Node("bool", lambda r: _truth(left.evaluate(r)) != _truth(right.evaluate(r)))


def _not(operand):
    return _Node("bool", lambda r: not _truth(operand.evaluate(r)))


def _comparison(op, left, right):
    if (left.type == "str" and right.type == "num") or (left.type == "num" and right.type == "str"):
        raise ExprError(f"the '{op}' operator received different types")
    left_lit = left.literal_str
    right_lit = right.literal_str

    def evaluate(record):
        return _compare(op, left.evaluate(record), right.evaluate(record), left_lit, right_lit)

    return _Node("bool", evaluate)


def _arith(op, left, right):
    if op == ".":

        def concat(record):
            a = _as_string(left.evaluate(record))
            b = _as_string(right.evaluate(record))
            if a is None or b is None:
                return None
            return a + b

        return _Node("str", concat)

    if op == "+" and {left.type, right.type} == {"str", "num"}:
        raise ExprError("'+' only takes two strings or two numbers")
    if op != "+" and "str" in (left.type, right.type):
        raise ExprError(f"'{op}' only takes numbers")

    def evaluate(record):
        a_raw = _scalar(left.evaluate(record))
        b_raw = _scalar(right.evaluate(record))
        if a_raw is None or b_raw is None:
            return None
        a, b = _as_number(a_raw), _as_number(b_raw)
        if a is None or b is None:
            if op == "+" and a is None and b is None:
                return _as_string(a_raw) + _as_string(b_raw)
            return None
        try:
            if op == "+":
                return a + b
            if op == "-":
                return a - b
            if op == "*":
                return a * b
            if op == "/":
                if b == 0:
                    return None
                result = a / b
                return (
                    int(result)
                    if isinstance(a, int) and isinstance(b, int) and result.is_integer()
                    else result
                )
            if b == 0:
                return None
            return (
                math.fmod(a, b)
                if isinstance(a, float) or isinstance(b, float)
                else int(math.fmod(a, b))
            )
        except (OverflowError, ValueError):
            return None

    type_ = "num" if left.type != "str" and right.type != "str" else "any"
    return _Node(type_, evaluate)


# -- functions ---------------------------------------------------------------


def _fn_if(args):
    cond, then, other = args
    _require_bool(cond, "if()")
    type_ = then.type if then.type == other.type else "any"
    return _Node(
        type_, lambda r: then.evaluate(r) if _truth(cond.evaluate(r)) else other.evaluate(r)
    )


def _fn_case(args):
    if len(args) % 2:
        raise ExprError("case() takes condition/value pairs")
    pairs = list(zip(args[0::2], args[1::2]))
    for cond, _ in pairs:
        _require_bool(cond, "case()")
    types = {value.type for _, value in pairs}
    type_ = types.pop() if len(types) == 1 else "any"

    def evaluate(record):
        for cond, value in pairs:
            if _truth(cond.evaluate(record)):
                return value.evaluate(record)
        return None

    return _Node(type_, evaluate)


def _fn_coalesce(args):
    types = {a.type for a in args}
    type_ = types.pop() if len(types) == 1 else "any"

    def evaluate(record):
        for arg in args:
            value = arg.evaluate(record)
            if value is not None:
                return value
        return None

    return _Node(type_, evaluate)


def _fn_in(args):
    if len(args) < 2:
        raise ExprError("in() takes a value and at least one candidate")
    subject, candidates = args[0], args[1:]

    def evaluate(record):
        value = subject.evaluate(record)
        if value is None:
            return None
        for candidate in candidates:
            if _compare(
                "=", value, candidate.evaluate(record), subject.literal_str, candidate.literal_str
            ):
                return True
        return False

    return _Node("bool", evaluate)


def _fn_like(args):
    subject, pattern = args
    static = pattern.evaluate({}) if pattern.literal_str else None
    compiled = _like_regex(static) if static is not None else None

    def evaluate(record):
        value = subject.evaluate(record)
        if value is None:
            return None
        regex = compiled
        if regex is None:
            pat = _as_string(pattern.evaluate(record))
            if pat is None:
                return None
            regex = _like_regex(pat)
        values = value if isinstance(value, MV) else (value,)
        return any(regex.match(_as_string(v)) for v in values)

    return _Node("bool", evaluate)


def _fn_match(args):
    subject, pattern = args
    static = pattern.evaluate({}) if pattern.literal_str else None
    compiled = _compile_regex(static) if static is not None else None

    def evaluate(record):
        value = subject.evaluate(record)
        if value is None:
            return None
        regex = compiled
        if regex is None:
            pat = _as_string(pattern.evaluate(record))
            if pat is None:
                return None
            regex = _compile_regex(pat)
        values = value if isinstance(value, MV) else (value,)
        return any(regex.search(_as_string(v)) for v in values)

    return _Node("bool", evaluate)


def _fn_cidrmatch(args):
    cidr_node, ip_node = args

    def evaluate(record):
        cidr = _as_string(cidr_node.evaluate(record))
        ip = ip_node.evaluate(record)
        if cidr is None or ip is None:
            return None
        try:
            network = ipaddress.ip_network(cidr.strip(), strict=False)
        except ValueError:
            return False
        address = _as_string(ip)
        if address is None:
            return None
        try:
            return ipaddress.ip_address(address.strip()) in network
        except ValueError:
            return False

    return _Node("bool", evaluate)


def _unary(type_, func):
    """Function of one scalar argument; null in, null out."""

    def build(args):
        (arg,) = args

        def evaluate(record):
            value = _scalar(arg.evaluate(record))
            if value is None:
                return None
            return func(value)

        return _Node(type_, evaluate)

    return build


def _numeric_unary(func):
    def wrapped(value):
        number = _as_number(value)
        if number is None:
            return None
        try:
            return func(number)
        except (OverflowError, ValueError):
            return None

    return _unary("num", wrapped)


def _string_map(func):
    """String function applied to each value of a multivalue (measured: lower, upper)."""

    def build(args):
        (arg,) = args

        def evaluate(record):
            value = arg.evaluate(record)
            if value is None:
                return None
            if isinstance(value, MV):
                return MV(FieldStr(func(str(v))) for v in value)
            return func(_as_string(value))

        return _Node("str", evaluate)

    return build


def _round_half_up(number, digits=0):
    """Splunk rounds half toward +infinity on the decimal text: round(-2.5)=-2,
    round(2.675, 2)=2.68 (measured)."""
    quantum = decimal.Decimal(1).scaleb(-digits)
    value = decimal.Decimal(repr(number)) / quantum + decimal.Decimal("0.5")
    rounded = value.to_integral_value(rounding=decimal.ROUND_FLOOR) * quantum
    return int(rounded) if digits <= 0 else float(rounded)


def _fn_round(args):
    if len(args) not in (1, 2):
        raise ExprError("round() takes 1 or 2 arguments")

    def evaluate(record):
        number = _as_number(_scalar(args[0].evaluate(record)))
        if number is None:
            return None
        digits = 0
        if len(args) == 2:
            digits = _as_number(_scalar(args[1].evaluate(record)))
            if digits is None:
                return None
            digits = int(digits)
        return _round_half_up(number, digits)

    return _Node("num", evaluate)


def _fn_tonumber(args):
    if len(args) not in (1, 2):
        raise ExprError("tonumber() takes 1 or 2 arguments")

    def evaluate(record):
        value = _scalar(args[0].evaluate(record))
        if value is None:
            return None
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return value
        text = _as_string(value).strip()
        if len(args) == 2:
            base = _as_number(_scalar(args[1].evaluate(record)))
            if base is None or not 2 <= int(base) <= 36:
                return None
            try:
                return int(text, int(base))
            except ValueError:
                return None
        return _as_number(FieldStr(text))

    return _Node("num", evaluate)


def _fn_substr(args):
    if len(args) not in (2, 3):
        raise ExprError("substr() takes 2 or 3 arguments")

    def evaluate(record):
        text = _as_string(args[0].evaluate(record))
        start = _as_number(_scalar(args[1].evaluate(record)))
        if text is None or start is None:
            return None
        start = int(start)
        begin = start - 1 if start > 0 else (len(text) + start if start < 0 else 0)
        begin = max(begin, 0)
        if len(args) == 3:
            length = _as_number(_scalar(args[2].evaluate(record)))
            if length is None:
                return None
            return text[begin : begin + max(int(length), 0)]
        return text[begin:]

    return _Node("str", evaluate)


def _fn_replace(args):
    subject, pattern, replacement = args
    static = pattern.evaluate({}) if pattern.literal_str else None
    compiled = _compile_regex(static) if static is not None else None

    def evaluate(record):
        text = _as_string(subject.evaluate(record))
        repl = _as_string(replacement.evaluate(record))
        if text is None or repl is None:
            return None
        regex = compiled
        if regex is None:
            pat = _as_string(pattern.evaluate(record))
            if pat is None:
                return None
            regex = _compile_regex(pat)
        try:
            return regex.sub(repl, text)
        except (re.error, IndexError) as error:
            raise ExprError(f"replace(): {error}") from None

    return _Node("str", evaluate)


def _trim_builder(method):
    def build(args):
        if len(args) not in (1, 2):
            raise ExprError("trim functions take 1 or 2 arguments")

        def evaluate(record):
            value = args[0].evaluate(record)
            if value is None:
                return None
            chars = None
            if len(args) == 2:
                chars = _as_string(args[1].evaluate(record))
            if isinstance(value, MV):  # measured: trim(mv) trims each value
                return MV(FieldStr(getattr(str(v), method)(chars)) for v in value)
            return getattr(_as_string(value), method)(chars)

        return _Node("str", evaluate)

    return build


def _minmax(pick):
    def build(args):
        if not args:
            raise ExprError("min()/max() take at least one argument")

        def evaluate(record):
            values = []
            for arg in args:
                value = arg.evaluate(record)
                if isinstance(value, MV):
                    values.extend(value)
                elif value is not None:
                    values.append(value)
            if not values:
                return None
            numbers = [_as_number(v) for v in values]
            if all(n is not None for n in numbers):
                return pick(numbers)
            return pick(_as_string(v) for v in values)

        return _Node("any", evaluate)

    return build


def _fn_pow(args):
    base, exponent = args

    def evaluate(record):
        a = _as_number(_scalar(base.evaluate(record)))
        b = _as_number(_scalar(exponent.evaluate(record)))
        if a is None or b is None:
            return None
        try:
            result = math.pow(a, b)
        except (OverflowError, ValueError):
            return None
        return int(result) if isinstance(a, int) and isinstance(b, int) and b >= 0 else result

    return _Node("num", evaluate)


def _fn_isnull(args):
    (arg,) = args
    return _Node("bool", lambda r: arg.evaluate(r) is None)


def _fn_isnotnull(args):
    (arg,) = args
    return _Node("bool", lambda r: arg.evaluate(r) is not None)


def _fn_isnum(args):
    (arg,) = args
    return _Node("bool", lambda r: _as_number(_scalar(arg.evaluate(r))) is not None)


def _fn_isint(args):
    (arg,) = args

    def evaluate(record):
        number = _as_number(_scalar(arg.evaluate(record)))
        return isinstance(number, int)

    return _Node("bool", evaluate)


def _fn_isstr(args):
    (arg,) = args

    def evaluate(record):
        # Measured: true for any scalar, numeric-looking or not; false on a multivalue.
        value = _scalar(arg.evaluate(record))
        return value is not None and not isinstance(value, bool)

    return _Node("bool", evaluate)


def _fn_mvcount(args):
    (arg,) = args

    def evaluate(record):
        value = arg.evaluate(record)
        if value is None:
            return None
        return len(value) if isinstance(value, MV) else 1

    return _Node("num", evaluate)


def _fn_tostring(args):
    (arg,) = args

    def evaluate(record):
        value = arg.evaluate(record)
        if isinstance(value, MV):
            return " ".join(value)  # measured: tostring(mv) joins with a space
        return _as_string(value)

    return _Node("str", evaluate)


def _fn_ceiling(args):
    return _numeric_unary(lambda n: int(math.ceil(n)))(args)


# name -> (min_args, max_args or None, builder)
_FUNCTIONS = {
    "if": (3, 3, _fn_if),
    "case": (2, None, _fn_case),
    "coalesce": (1, None, _fn_coalesce),
    "in": (2, None, _fn_in),
    "like": (2, 2, _fn_like),
    "match": (2, 2, _fn_match),
    "cidrmatch": (2, 2, _fn_cidrmatch),
    "isnull": (1, 1, _fn_isnull),
    "isnotnull": (1, 1, _fn_isnotnull),
    "isnum": (1, 1, _fn_isnum),
    "isint": (1, 1, _fn_isint),
    "isstr": (1, 1, _fn_isstr),
    "null": (0, 0, lambda args: _Node("any", lambda r: None)),
    "true": (0, 0, lambda args: _Node("bool", lambda r: True)),
    "false": (0, 0, lambda args: _Node("bool", lambda r: False)),
    "len": (1, 1, _unary("num", lambda v: len(_as_string(v)))),
    "lower": (1, 1, _string_map(str.lower)),
    "upper": (1, 1, _string_map(str.upper)),
    "trim": (1, 2, _trim_builder("strip")),
    "ltrim": (1, 2, _trim_builder("lstrip")),
    "rtrim": (1, 2, _trim_builder("rstrip")),
    "substr": (2, 3, _fn_substr),
    "replace": (3, 3, _fn_replace),
    "tostring": (1, 1, _fn_tostring),
    "tonumber": (1, 2, _fn_tonumber),
    "abs": (1, 1, _numeric_unary(abs)),
    "round": (1, 2, _fn_round),
    "floor": (1, 1, _numeric_unary(lambda n: int(math.floor(n)))),
    "ceiling": (1, 1, _fn_ceiling),
    "ceil": (1, 1, _fn_ceiling),
    "sqrt": (1, 1, _numeric_unary(math.sqrt)),
    "pow": (2, 2, _fn_pow),
    "min": (1, None, _minmax(min)),
    "max": (1, None, _minmax(max)),
    "mvcount": (1, 1, _fn_mvcount),
    "now": (0, 0, None),
}

SUPPORTED_FUNCTIONS = tuple(sorted(_FUNCTIONS))


def _call(name, args):
    key = name.lower()
    if key not in _FUNCTIONS:
        raise ExprError(
            f"unsupported function {name}(). Compute it with eval before warn, "
            f'e.g. | eval w=<expression> | warn if="w=1" ...'
        )
    low, high, builder = _FUNCTIONS[key]
    if len(args) < low or (high is not None and len(args) > high):
        expected = str(low) if low == high else f"{low}+" if high is None else f"{low}-{high}"
        raise ExprError(f"{key}() takes {expected} argument(s), got {len(args)}")
    if key == "now":
        started = int(time.time())
        return _Node("num", lambda r: started)
    return builder(args)


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def compile_condition(text):
    """Compile a condition; return a predicate ``record -> bool``.

    Raises ExprError if the expression is invalid or not boolean.
    """
    if text is None or not text.strip():
        raise ExprError("empty condition")
    if len(text) > MAX_EXPRESSION_LENGTH:
        raise ExprError(f"condition longer than {MAX_EXPRESSION_LENGTH} characters")
    node = _Parser(text).parse()
    if node.type != "bool":
        raise ExprError("the result of the condition must be boolean")

    def predicate(record):
        return _truth(node.evaluate(record))

    return predicate
