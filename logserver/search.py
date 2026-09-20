from __future__ import annotations

import json
import re
from dataclasses import dataclass


class SearchSyntaxError(ValueError):
    pass


_TOKEN_RE = re.compile(
    r'''\s*(?:(?P<quoted>"(?:\\.|[^"\\])*")|(?P<op>>=|<=|!=|=|:|>|<)|(?P<lparen>\()|(?P<rparen>\))|(?P<minus>-)|(?P<word>[^\s():=<>!]+))'''
)

_FIELDS = {
    "id": "id",
    "time": "event_at",
    "event_at": "event_at",
    "received": "received_at",
    "received_at": "received_at",
    "source": "source",
    "facility": "facility",
    "severity": "severity",
    "level": "severity",
    "topic": "topics",
    "topics": "topics",
    "message": "message",
    "transport": "transport",
}
_TEXT_FIELDS = ("message", "topics", "source", "severity", "facility")


@dataclass(frozen=True, slots=True)
class Token:
    kind: str
    value: str


def _tokenize(text: str) -> list[Token]:
    tokens: list[Token] = []
    position = 0
    while position < len(text):
        match = _TOKEN_RE.match(text, position)
        if not match:
            if text[position:].strip() == "":
                break
            raise SearchSyntaxError(f"Unexpected character at position {position + 1}")
        position = match.end()
        kind = match.lastgroup
        assert kind is not None
        value = match.group(kind)
        if kind == "quoted":
            try:
                value = json.loads(value)
            except json.JSONDecodeError as exc:
                raise SearchSyntaxError("Invalid escape in quoted value") from exc
        elif kind == "word" and value.upper() in {"AND", "OR", "NOT"}:
            kind = value.lower()
        tokens.append(Token(kind, value))
    return tokens


@dataclass(frozen=True, slots=True)
class SqlFilter:
    clause: str
    params: tuple[object, ...]


class _Parser:
    def __init__(self, tokens: list[Token]):
        self.tokens = tokens
        self.pos = 0

    def parse(self) -> SqlFilter:
        if not self.tokens:
            return SqlFilter("1", ())
        result = self._or()
        if self._peek() is not None:
            raise SearchSyntaxError(f"Unexpected token '{self._peek().value}'")
        return result

    def _or(self) -> SqlFilter:
        left = self._and()
        while self._accept("or"):
            left = self._combine(left, "OR", self._and())
        return left

    def _and(self) -> SqlFilter:
        left = self._unary()
        while True:
            if self._accept("and"):
                left = self._combine(left, "AND", self._unary())
            elif self._starts_expression(self._peek()):
                left = self._combine(left, "AND", self._unary())
            else:
                return left

    def _unary(self) -> SqlFilter:
        if self._accept("not") or self._accept("minus"):
            value = self._unary()
            return SqlFilter(f"NOT ({value.clause})", value.params)
        if self._accept("lparen"):
            value = self._or()
            if not self._accept("rparen"):
                raise SearchSyntaxError("Missing closing parenthesis")
            return SqlFilter(f"({value.clause})", value.params)
        return self._term()

    def _term(self) -> SqlFilter:
        first = self._take("word", "quoted")
        if first is None:
            token = self._peek()
            raise SearchSyntaxError(f"Expected search term near '{token.value if token else 'end'}'")

        operator = self._take("op")
        if operator is None:
            return self._free_text(first.value)

        if first.kind != "word" or first.value.lower() not in _FIELDS:
            raise SearchSyntaxError(f"Unknown field '{first.value}'")
        value = self._take("word", "quoted")
        if value is None:
            raise SearchSyntaxError(f"Missing value after '{first.value}{operator.value}'")
        return self._comparison(_FIELDS[first.value.lower()], operator.value, value.value)

    @staticmethod
    def _free_text(value: str) -> SqlFilter:
        pattern = f"%{_escape_like(value.lower())}%"
        clause = " OR ".join(f"LOWER(COALESCE({field}, '')) LIKE ? ESCAPE '\\'" for field in _TEXT_FIELDS)
        return SqlFilter(f"({clause})", tuple(pattern for _ in _TEXT_FIELDS))

    @staticmethod
    def _comparison(field: str, operator: str, value: str) -> SqlFilter:
        if field == "id":
            try:
                number = int(value)
            except ValueError as exc:
                raise SearchSyntaxError("id must be an integer") from exc
            actual_operator = "=" if operator == ":" else operator
            return SqlFilter(f"id {actual_operator} ?", (number,))

        if field == "topics" and operator in {"=", "!="}:
            exists = "EXISTS (SELECT 1 FROM json_each(logs.topics) WHERE LOWER(json_each.value) = ?)"
            clause = exists if operator == "=" else f"NOT ({exists})"
            return SqlFilter(clause, (value.lower(),))

        if operator == ":":
            pattern = f"%{_escape_like(value.lower())}%"
            return SqlFilter(f"LOWER(COALESCE({field}, '')) LIKE ? ESCAPE '\\'", (pattern,))
        if operator not in {"=", "!=", ">", ">=", "<", "<="}:
            raise SearchSyntaxError(f"Unsupported operator '{operator}'")
        if operator in {"=", "!="}:
            return SqlFilter(f"LOWER(COALESCE({field}, '')) {operator} ?", (value.lower(),))
        return SqlFilter(f"COALESCE({field}, '') {operator} ?", (value,))

    def _peek(self) -> Token | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _accept(self, kind: str) -> Token | None:
        token = self._peek()
        if token is not None and token.kind == kind:
            self.pos += 1
            return token
        return None

    def _take(self, *kinds: str) -> Token | None:
        token = self._peek()
        if token is not None and token.kind in kinds:
            self.pos += 1
            return token
        return None

    @staticmethod
    def _starts_expression(token: Token | None) -> bool:
        return token is not None and token.kind in {"word", "quoted", "not", "minus", "lparen"}

    @staticmethod
    def _combine(left: SqlFilter, operator: str, right: SqlFilter) -> SqlFilter:
        return SqlFilter(f"({left.clause}) {operator} ({right.clause})", left.params + right.params)


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def compile_search(query: str | None) -> SqlFilter:
    return _Parser(_tokenize((query or "").strip())).parse()
