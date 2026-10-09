from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any


class ConditionalTemplateError(ValueError):
    pass


_DIRECTIVE = re.compile(r"\[\[(if(?:\s+(?:(?!\]\]).)+)?|else|/if)\]\]")
_FIELD = r"[A-Za-z_][A-Za-z0-9_]*"
_COMPARISON = re.compile(
    rf"^({_FIELD})\s*(==|!=|>=|<=|>|<|contains|matches)\s*(.+)$"
)
_MISSING_VALUES = {"", "unknown", "unavailable", "none", "null", "n/a"}


@dataclass(frozen=True, slots=True)
class _Condition:
    field: str
    operator: str
    operand: str | None = None
    pattern: re.Pattern[str] | None = None

    def evaluate(self, context: dict[str, Any]) -> bool:
        value = context.get(self.field)
        if self.operator == "available":
            return _available(value)
        if self.operator == "missing":
            return not _available(value)

        left = "" if value is None else str(value)
        right = self.operand or ""
        if self.operator == "==":
            return left == right
        if self.operator == "!=":
            return left != right
        if self.operator == "contains":
            return right in left
        if self.operator == "matches":
            assert self.pattern is not None
            return self.pattern.search(left) is not None
        try:
            left_number = float(left)
            right_number = float(right)
        except ValueError:
            return False
        if self.operator == ">":
            return left_number > right_number
        if self.operator == ">=":
            return left_number >= right_number
        if self.operator == "<":
            return left_number < right_number
        return left_number <= right_number


@dataclass(frozen=True, slots=True)
class _Text:
    value: str


@dataclass(frozen=True, slots=True)
class _Conditional:
    condition: _Condition
    when_true: tuple[_Node, ...]
    when_false: tuple[_Node, ...]


_Node = _Text | _Conditional


@dataclass(frozen=True, slots=True)
class ConditionalTemplate:
    nodes: tuple[_Node, ...]
    fields: frozenset[str]

    def render(self, context: dict[str, Any]) -> str:
        return _render_nodes(self.nodes, context)


@lru_cache(maxsize=256)
def compile_conditional_template(template: str) -> ConditionalTemplate:
    tokens: list[tuple[str, str]] = []
    offset = 0
    for match in _DIRECTIVE.finditer(template):
        if match.start() > offset:
            tokens.append(("text", template[offset:match.start()]))
        tokens.append(("directive", match.group(1)))
        offset = match.end()
    if offset < len(template):
        tokens.append(("text", template[offset:]))

    position = 0
    fields: set[str] = set()

    def parse_nodes(*, nested: bool) -> tuple[tuple[_Node, ...], str | None]:
        nonlocal position
        nodes: list[_Node] = []
        while position < len(tokens):
            kind, value = tokens[position]
            position += 1
            if kind == "text":
                if re.search(r"\[\[(?:if\b|else\b|/if\b)", value):
                    raise ConditionalTemplateError("malformed conditional directive")
                nodes.append(_Text(value))
                continue
            if value in {"else", "/if"}:
                if not nested:
                    raise ConditionalTemplateError(f"unexpected [[{value}]]")
                return tuple(nodes), value
            expression = value[2:].strip()
            condition = _parse_condition(expression)
            fields.add(condition.field)
            when_true, terminator = parse_nodes(nested=True)
            if terminator is None:
                raise ConditionalTemplateError("[[if ...]] is missing [[/if]]")
            when_false: tuple[_Node, ...] = ()
            if terminator == "else":
                when_false, terminator = parse_nodes(nested=True)
                if terminator != "/if":
                    raise ConditionalTemplateError("[[else]] is missing [[/if]]")
            nodes.append(_Conditional(condition, when_true, when_false))
        return tuple(nodes), None

    nodes, terminator = parse_nodes(nested=False)
    if terminator is not None:
        raise ConditionalTemplateError(f"unexpected [[{terminator}]]")
    return ConditionalTemplate(nodes, frozenset(fields))


def strip_conditional_directives(template: str) -> str:
    return _DIRECTIVE.sub("", template)


def _parse_condition(expression: str) -> _Condition:
    if not expression:
        raise ConditionalTemplateError("conditional field is required")
    missing = re.fullmatch(rf"not\s+({_FIELD})", expression)
    if missing:
        return _Condition(missing.group(1), "missing")
    if re.fullmatch(_FIELD, expression):
        return _Condition(expression, "available")
    comparison = _COMPARISON.fullmatch(expression)
    if not comparison:
        raise ConditionalTemplateError(f"invalid condition '{expression}'")
    field, operator, operand = comparison.groups()
    operand = _unquote(operand.strip())
    if not operand:
        raise ConditionalTemplateError("conditional comparison value is required")
    pattern = None
    if operator == "matches":
        try:
            pattern = re.compile(operand)
        except re.error as exc:
            raise ConditionalTemplateError(f"invalid conditional regex: {exc}") from exc
    if operator in {">", ">=", "<", "<="}:
        try:
            float(operand)
        except ValueError as exc:
            raise ConditionalTemplateError("numeric comparisons require a number") from exc
    return _Condition(field, operator, operand, pattern)


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _available(value: Any) -> bool:
    if value is None:
        return False
    return str(value).strip().lower() not in _MISSING_VALUES


def _render_nodes(nodes: tuple[_Node, ...], context: dict[str, Any]) -> str:
    rendered: list[str] = []
    for node in nodes:
        if isinstance(node, _Text):
            rendered.append(node.value)
        else:
            branch = node.when_true if node.condition.evaluate(context) else node.when_false
            rendered.append(_render_nodes(branch, context))
    return "".join(rendered)
