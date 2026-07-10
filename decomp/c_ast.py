"""Lossless, bounded C tokenization and conservative expression discovery.

This is deliberately not a C compiler.  It recognizes only enough unambiguous C
structure to anchor source transformations; callers must reject unknown nodes.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Iterator, Sequence


class CParseError(ValueError):
    """Raised for malformed or unsupported C source."""


@dataclass(frozen=True, slots=True)
class Token:
    kind: str
    text: str
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class Node:
    id: str
    kind: str
    start: int
    end: int
    operator: str | None = None
    children: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Function:
    id: str
    name: str
    start: int
    end: int
    body_id: str
    body_start: int
    body_end: int


@dataclass(frozen=True, slots=True)
class TranslationUnit:
    source: str
    tokens: tuple[Token, ...]
    functions: tuple[Function, ...]
    nodes: tuple[Node, ...]

    def node(self, node_id: str) -> Node:
        for node in self.nodes:
            if node.id == node_id:
                return node
        raise KeyError(node_id)

    def source_for(self, node_id: str) -> str:
        node = self.node(node_id)
        return self.source[node.start:node.end]


_MULTI = (">>=", "<<=", "...", "->", "++", "--", "<<", ">>", "<=", ">=", "==", "!=", "&&", "||", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "##")
_PUNCT = set("{}[]();,:?~.+-*/%&|^!=<>")
_TRIVIA = {"whitespace", "comment", "directive"}


def _node_id(kind: str, start: int, end: int, operator: str = "") -> str:
    # Positions make IDs stable when text outside a node is unchanged, and avoid
    # accidental identity claims across a different source file.
    return "c-v1:" + sha256(f"{kind}:{start}:{end}:{operator}".encode("ascii")).hexdigest()[:20]


def lex_c(source: str) -> tuple[Token, ...]:
    """Return every source byte as a token; lexical errors are explicit."""
    if not isinstance(source, str):
        raise TypeError("source must be str")
    out: list[Token] = []; i = 0; n = len(source); line_start = True
    while i < n:
        s = i; c = source[i]
        if c in " \t\r\n\v\f":
            i += 1
            while i < n and source[i] in " \t\r\n\v\f": i += 1
            trivia = source[s:i]
            out.append(Token("whitespace", trivia, s, i))
            # A directive may be indented after LF or CRLF.  Only horizontal
            # whitespace following the final line terminator preserves
            # beginning-of-line state.
            tail = trivia.rsplit("\n", 1)[-1]
            line_start = (("\n" in trivia and not tail.strip(" \t\r\v\f")) or
                          (line_start and "\n" not in trivia))
            continue
        if line_start and c == "#":
            i += 1
            while i < n:
                if source[i] == "\\" and i + 1 < n and source[i + 1] == "\n": i += 2; continue
                if source[i] == "\n": break
                i += 1
            out.append(Token("directive", source[s:i], s, i)); line_start = False; continue
        if source.startswith("//", i):
            i = source.find("\n", i)
            if i < 0: i = n
            out.append(Token("comment", source[s:i], s, i)); line_start = False; continue
        if source.startswith("/*", i):
            e = source.find("*/", i + 2)
            if e < 0: raise CParseError(f"unterminated comment at offset {s}")
            i = e + 2; out.append(Token("comment", source[s:i], s, i)); line_start = source[s:i].endswith("\n"); continue
        if c in "\"'":
            quote = c; i += 1
            while i < n:
                if source[i] == "\\":
                    i += 2
                elif source[i] == quote:
                    i += 1; break
                elif source[i] in "\r\n": raise CParseError(f"newline in literal at offset {s}")
                else: i += 1
            else: raise CParseError(f"unterminated literal at offset {s}")
            out.append(Token("string" if quote == '"' else "char", source[s:i], s, i)); line_start = False; continue
        if c.isalpha() or c == "_":
            i += 1
            while i < n and (source[i].isalnum() or source[i] == "_"): i += 1
            out.append(Token("identifier", source[s:i], s, i)); line_start = False; continue
        if c.isdigit() or (c == "." and i + 1 < n and source[i + 1].isdigit()):
            i += 1
            while i < n and (source[i].isalnum() or source[i] in "._"): i += 1
            out.append(Token("number", source[s:i], s, i)); line_start = False; continue
        match = next((p for p in _MULTI if source.startswith(p, i)), None)
        if match:
            i += len(match); out.append(Token("punctuator", match, s, i)); line_start = False; continue
        if c in _PUNCT:
            i += 1; out.append(Token("punctuator", c, s, i)); line_start = False; continue
        raise CParseError(f"unsupported character U+{ord(c):04X} at offset {s}")
    return tuple(out)


def _significant(tokens: Sequence[Token]) -> list[Token]: return [t for t in tokens if t.kind not in _TRIVIA]


def _balanced(tokens: Sequence[Token]) -> dict[int, int]:
    pairs = {"(": ")", "[": "]", "{": "}"}; stack: list[tuple[str, int]] = []; result: dict[int, int] = {}
    for i, token in enumerate(tokens):
        if token.text in pairs: stack.append((token.text, i))
        elif token.text in ")]}":
            if not stack or pairs[stack[-1][0]] != token.text: raise CParseError(f"unbalanced {token.text!r} at offset {token.start}")
            _, opening = stack.pop(); result[opening] = i; result[i] = opening
    if stack: raise CParseError(f"unclosed {stack[-1][0]!r} at offset {tokens[stack[-1][1]].start}")
    return result


def _top_level_split(tokens: list[Token], lo: int, hi: int, operators: set[str], pairs: dict[int, int]) -> tuple[int, str] | None:
    # Scan right-to-left, jumping from a closing delimiter to its opener.  An
    # operator nested in parentheses/subscripts/braces is never top-level.
    i = hi - 1
    while i >= lo:
        partner = pairs.get(i)
        if partner is not None and partner < i:
            i = partner - 1
            continue
        if tokens[i].text in operators:
            return i, tokens[i].text
        i -= 1
    return None


def _expression_nodes(tokens: list[Token], pairs: dict[int, int]) -> Iterator[Node]:
    precedence = (({"="}, "assignment"), ({"||"}, "logical_or"), ({"&&"}, "logical_and"), ({"|"}, "bitwise_or"), ({"^"}, "bitwise_xor"), ({"&"}, "bitwise_and"), ({"==", "!="}, "equality"), ({"<", ">", "<=", ">="}, "relational"), ({"<<", ">>"}, "shift"), ({"+", "-"}, "additive"), ({"*", "/", "%"}, "multiplicative"))
    def visit(lo: int, hi: int) -> Node | None:
        if lo >= hi: return None
        # Statement introducers are not expression operands.  This supports the
        # ordinary ``return expression;`` case without pretending to parse every
        # C statement form.
        if tokens[lo].text == "return":
            lo += 1
        if lo >= hi: return None
        while lo + 1 < hi and tokens[lo].text == "(" and pairs.get(lo) == hi - 1: lo += 1; hi -= 1
        if lo >= hi: return None
        for ops, kind in precedence:
            found = _top_level_split(tokens, lo, hi, ops, pairs)
            if found:
                index, op = found; left = visit(lo, index); right = visit(index + 1, hi)
                if left is None or right is None: return None
                node = Node(_node_id(kind, left.start, right.end, op), kind, left.start, right.end, op, (left.id, right.id)); yield_node.append(node); return node
        # subscript's opening bracket is known from matching pair map.
        for open_i in range(lo, hi):
            if tokens[open_i].text == "[" and pairs.get(open_i) == hi - 1 and open_i > lo:
                left = visit(lo, open_i); right = visit(open_i + 1, hi - 1)
                if left and right:
                    node = Node(_node_id("subscript", left.start, tokens[hi-1].end, "[]"), "subscript", left.start, tokens[hi-1].end, "[]", (left.id, right.id)); yield_node.append(node); return node
        if hi - lo == 1 and tokens[lo].kind in {"identifier", "number", "string", "char"}:
            node = Node(_node_id("atom", tokens[lo].start, tokens[lo].end), "atom", tokens[lo].start, tokens[lo].end); yield_node.append(node); return node
        return None
    # statements/conditions give bounded expression candidates; never parse comma-separated declarations whole.
    # Statements/conditions give bounded expression candidates; never parse a
    # whole declaration list as an expression.
    yield_node: list[Node] = []
    starts = [0]
    for i, token in enumerate(tokens):
        if token.text in ";{}":
            starts.append(i + 1)
    for start, end in zip(starts, starts[1:] + [len(tokens)]):
        if end > start and tokens[end - 1].text in ";{}":
            end -= 1
        if start < end:
            visit(start, end)
    seen: set[str] = set()
    for node in yield_node:
        if node.id not in seen: seen.add(node.id); yield node


def parse_c(source: str) -> TranslationUnit:
    """Parse lossless lexical structure and unambiguous file-scope definitions."""
    raw = lex_c(source); tokens = _significant(raw); pairs = _balanced(tokens)
    functions: list[Function] = []; nodes: list[Node] = []
    depth = 0
    for i, token in enumerate(tokens):
        if token.text == "{":
            if depth == 0:
                prior = i - 1
                if prior >= 0 and tokens[prior].text == ")" and prior in pairs:
                    open_paren = pairs[prior]; name_i = open_paren - 1
                    if name_i >= 0 and tokens[name_i].kind == "identifier":
                        close = pairs[i]
                        body = Node(_node_id("function_body", token.start, tokens[close].end), "function_body", token.start, tokens[close].end)
                        nodes.append(body)
                        functions.append(Function(_node_id("function", tokens[name_i].start, tokens[close].end), tokens[name_i].text, tokens[name_i].start, tokens[close].end, body.id, token.start, tokens[close].end))
            depth += 1
        elif token.text == "}":
            depth -= 1
    if depth != 0:
        raise CParseError("unbalanced braces")
    # Only a braced ``if (...) { ... } else { ... }`` is structurally sufficient
    # for a branch-swap transformation. Other statement forms remain unknown.
    for i, token in enumerate(tokens):
        if token.text != "if" or i + 2 >= len(tokens) or tokens[i + 1].text != "(":
            continue
        close_condition = pairs.get(i + 1)
        if close_condition is None or close_condition + 1 >= len(tokens) or tokens[close_condition + 1].text != "{":
            continue
        then_close = pairs[close_condition + 1]
        if then_close + 2 >= len(tokens) or tokens[then_close + 1].text != "else" or tokens[then_close + 2].text != "{":
            continue
        else_close = pairs[then_close + 2]
        condition = Node(_node_id("condition", tokens[i + 1].end, tokens[close_condition].start), "condition", tokens[i + 1].end, tokens[close_condition].start)
        nodes.append(condition)
        nodes.append(Node(_node_id("if_else", token.start, tokens[else_close].end), "if_else", token.start, tokens[else_close].end, None, (condition.id,)))
    nodes.extend(_expression_nodes(tokens, pairs))
    nodes.sort(key=lambda n: (n.start, n.end, n.kind, n.id))
    return TranslationUnit(source, raw, tuple(functions), tuple(nodes))

# Friendly aliases used by source-oriented callers.
parse_translation_unit = parse_c
