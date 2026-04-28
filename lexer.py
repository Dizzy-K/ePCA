from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class TokenType(str, Enum):
    COVENANT = "COVENANT"
    PERMIT = "PERMIT"
    FORBID = "FORBID"
    REQUIRE = "REQUIRE"
    IDENTIFIER = "IDENTIFIER"
    NUMBER = "NUMBER"
    STRING = "STRING"
    BOOLEAN = "BOOLEAN"
    GT = "GT"
    LT = "LT"
    GE = "GE"
    LE = "LE"
    EQ = "EQ"
    NE = "NE"
    AND = "AND"
    OR = "OR"
    LBRACE = "LBRACE"
    RBRACE = "RBRACE"
    LPAREN = "LPAREN"
    RPAREN = "RPAREN"
    SEMICOLON = "SEMICOLON"
    DOT = "DOT"
    EOF = "EOF"


KEYWORDS = {
    "covenant": TokenType.COVENANT,
    "permit": TokenType.PERMIT,
    "forbid": TokenType.FORBID,
    "require": TokenType.REQUIRE,
    "true": TokenType.BOOLEAN,
    "false": TokenType.BOOLEAN,
}


@dataclass(frozen=True)
class Token:
    type: TokenType
    value: str
    line: int
    column: int


class LexerError(ValueError):
    def __init__(self, message: str, line: int, column: int) -> None:
        super().__init__(f"{message} at line {line}, column {column}")
        self.line = line
        self.column = column


class Lexer:
    def __init__(self, source: str) -> None:
        self.source = source
        self.pos = 0
        self.line = 1
        self.column = 1

    def peek(self, offset: int = 0) -> str:
        idx = self.pos + offset
        if idx >= len(self.source):
            return "\0"
        return self.source[idx]

    def advance(self) -> str:
        ch = self.peek()
        self.pos += 1
        if ch == "\n":
            self.line += 1
            self.column = 1
        else:
            self.column += 1
        return ch

    def emit(self, token_type: TokenType, value: str, line: int, column: int) -> Token:
        return Token(token_type, value, line, column)

    def tokenize(self) -> list[Token]:
        tokens: list[Token] = []
        while self.pos < len(self.source):
            ch = self.peek()

            if ch in " \t\r\n":
                self.advance()
                continue

            if ch == "/" and self.peek(1) == "/":
                while self.peek() not in {"\n", "\0"}:
                    self.advance()
                continue

            line, column = self.line, self.column

            two_char = ch + self.peek(1)
            if two_char == "&&":
                self.advance(); self.advance()
                tokens.append(self.emit(TokenType.AND, "&&", line, column))
                continue
            if two_char == "||":
                self.advance(); self.advance()
                tokens.append(self.emit(TokenType.OR, "||", line, column))
                continue
            if two_char == ">=":
                self.advance(); self.advance()
                tokens.append(self.emit(TokenType.GE, ">=", line, column))
                continue
            if two_char == "<=":
                self.advance(); self.advance()
                tokens.append(self.emit(TokenType.LE, "<=", line, column))
                continue
            if two_char == "==":
                self.advance(); self.advance()
                tokens.append(self.emit(TokenType.EQ, "==", line, column))
                continue
            if two_char == "!=":
                self.advance(); self.advance()
                tokens.append(self.emit(TokenType.NE, "!=", line, column))
                continue

            if ch == "{":
                self.advance(); tokens.append(self.emit(TokenType.LBRACE, ch, line, column)); continue
            if ch == "}":
                self.advance(); tokens.append(self.emit(TokenType.RBRACE, ch, line, column)); continue
            if ch == "(":
                self.advance(); tokens.append(self.emit(TokenType.LPAREN, ch, line, column)); continue
            if ch == ")":
                self.advance(); tokens.append(self.emit(TokenType.RPAREN, ch, line, column)); continue
            if ch == ";":
                self.advance(); tokens.append(self.emit(TokenType.SEMICOLON, ch, line, column)); continue
            if ch == ".":
                self.advance(); tokens.append(self.emit(TokenType.DOT, ch, line, column)); continue
            if ch == ">":
                self.advance(); tokens.append(self.emit(TokenType.GT, ch, line, column)); continue
            if ch == "<":
                self.advance(); tokens.append(self.emit(TokenType.LT, ch, line, column)); continue

            if ch.isdigit():
                tokens.append(self._read_number())
                continue

            if ch in {"'", '"'}:
                tokens.append(self._read_string())
                continue

            if ch.isalpha() or ch == "_":
                tokens.append(self._read_identifier())
                continue

            raise LexerError(f"Unexpected character {ch!r}", line, column)

        tokens.append(Token(TokenType.EOF, "", self.line, self.column))
        return tokens

    def _read_number(self) -> Token:
        line, column = self.line, self.column
        raw = []
        seen_dot = False
        while True:
            ch = self.peek()
            if ch.isdigit():
                raw.append(self.advance())
            elif ch == "." and not seen_dot and self.peek(1).isdigit():
                seen_dot = True
                raw.append(self.advance())
            else:
                break
        return Token(TokenType.NUMBER, "".join(raw), line, column)

    def _read_string(self) -> Token:
        line, column = self.line, self.column
        quote = self.advance()
        chars: list[str] = []
        while True:
            ch = self.peek()
            if ch == "\0":
                raise LexerError("Unterminated string", line, column)
            if ch == "\n":
                raise LexerError("Unterminated string", line, column)
            if ch == quote:
                self.advance()
                break
            if ch == "\\":
                self.advance()
                esc = self.peek()
                mapping = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "'": "'"}
                if esc not in mapping:
                    raise LexerError(f"Unsupported escape \\{esc}", self.line, self.column)
                self.advance()
                chars.append(mapping[esc])
                continue
            chars.append(self.advance())
        return Token(TokenType.STRING, "".join(chars), line, column)

    def _read_identifier(self) -> Token:
        line, column = self.line, self.column
        chars: list[str] = []
        while True:
            ch = self.peek()
            if ch.isalnum() or ch == "_":
                chars.append(self.advance())
            else:
                break
        value = "".join(chars)
        token_type = KEYWORDS.get(value.lower(), TokenType.IDENTIFIER)
        return Token(token_type, value, line, column)


def tokenize(source: str) -> list[Token]:
    return Lexer(source).tokenize()
