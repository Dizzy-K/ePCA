from __future__ import annotations

from dataclasses import dataclass

from ast_nodes import (
    BooleanExpr,
    ComparisonExpr,
    ComparisonOperator,
    CovenantEffect,
    CovenantRequirement,
    CovenantSpec,
    CovenantStatement,
    LiteralValue,
    LogicalAndExpr,
    LogicalOrExpr,
)
from lexer import Token, TokenType, tokenize


class ParseError(ValueError):
    def __init__(self, message: str, token: Token) -> None:
        super().__init__(
            f"{message} at line {token.line}, column {token.column} "
            f"(got {token.value!r} [{token.type.value}])"
        )
        self.line = token.line
        self.column = token.column


@dataclass
class Parser:
    tokens: list[Token]
    pos: int = 0

    def current(self) -> Token:
        return self.tokens[self.pos]

    def expect(self, token_type: TokenType) -> Token:
        tok = self.current()
        if tok.type != token_type:
            raise ParseError(f"Expected {token_type.value}", tok)
        self.pos += 1
        return tok

    def match(self, token_type: TokenType) -> bool:
        if self.current().type == token_type:
            self.pos += 1
            return True
        return False

    def parse(self) -> CovenantSpec:
        spec = self.parse_covenant_decl()
        self.expect(TokenType.EOF)
        return spec

    def parse_covenant_decl(self) -> CovenantSpec:
        self.expect(TokenType.COVENANT)
        name = self.expect(TokenType.IDENTIFIER).value
        self.expect(TokenType.LBRACE)
        statements: list[CovenantStatement] = []
        requirements: list[CovenantRequirement] = []

        while self.current().type not in {TokenType.RBRACE, TokenType.EOF}:
            tok = self.current()
            if tok.type == TokenType.PERMIT:
                self.pos += 1
                statements.append(self.parse_statement(CovenantEffect.PERMIT))
            elif tok.type == TokenType.FORBID:
                self.pos += 1
                statements.append(self.parse_statement(CovenantEffect.FORBID))
            elif tok.type == TokenType.REQUIRE:
                self.pos += 1
                requirements.append(self.parse_requirement())
            else:
                raise ParseError("Expected permit, forbid, or require", tok)

        self.expect(TokenType.RBRACE)
        return CovenantSpec(name=name, statements=tuple(statements), requirements=tuple(requirements))

    def parse_statement(self, effect: CovenantEffect) -> CovenantStatement:
        action = self.parse_dotted_name()
        conditions: list[BooleanExpr] = []
        if self.current().type == TokenType.LPAREN:
            conditions.append(self.parse_parenthesized_expr())
        self.expect(TokenType.SEMICOLON)
        return CovenantStatement(effect=effect, action=action, conditions=tuple(conditions))

    def parse_requirement(self) -> CovenantRequirement:
        field = self.parse_dotted_name()
        operator = self.parse_operator()
        value = self.parse_value()
        self.expect(TokenType.SEMICOLON)
        return CovenantRequirement(field=field, operator=operator, value=value)

    def parse_dotted_name(self) -> str:
        name = self.expect(TokenType.IDENTIFIER).value
        while self.match(TokenType.DOT):
            name += "." + self.expect(TokenType.IDENTIFIER).value
        return name

    def parse_operator(self) -> ComparisonOperator:
        tok = self.current()
        mapping = {
            TokenType.GT: ComparisonOperator.GT,
            TokenType.LT: ComparisonOperator.LT,
            TokenType.GE: ComparisonOperator.GE,
            TokenType.LE: ComparisonOperator.LE,
            TokenType.EQ: ComparisonOperator.EQ,
            TokenType.NE: ComparisonOperator.NE,
        }
        if tok.type not in mapping:
            raise ParseError("Expected comparison operator", tok)
        self.pos += 1
        return mapping[tok.type]

    def parse_value(self) -> LiteralValue:
        tok = self.current()
        if tok.type == TokenType.NUMBER:
            self.pos += 1
            return float(tok.value) if "." in tok.value else int(tok.value)
        if tok.type == TokenType.STRING:
            self.pos += 1
            return tok.value
        if tok.type == TokenType.BOOLEAN:
            self.pos += 1
            return tok.value.lower() == "true"
        if tok.type == TokenType.IDENTIFIER:
            self.pos += 1
            return tok.value
        raise ParseError("Expected value", tok)

    def parse_parenthesized_expr(self) -> BooleanExpr:
        self.expect(TokenType.LPAREN)
        expr = self.parse_or_expr()
        self.expect(TokenType.RPAREN)
        return expr

    def parse_or_expr(self) -> BooleanExpr:
        expr = self.parse_and_expr()
        operands: list[BooleanExpr] = [expr]
        while self.match(TokenType.OR):
            operands.append(self.parse_and_expr())
        if len(operands) == 1:
            return expr
        return LogicalOrExpr(tuple(operands))

    def parse_and_expr(self) -> BooleanExpr:
        expr = self.parse_factor()
        operands: list[BooleanExpr] = [expr]
        while self.match(TokenType.AND):
            operands.append(self.parse_factor())
        if len(operands) == 1:
            return expr
        return LogicalAndExpr(tuple(operands))

    def parse_factor(self) -> BooleanExpr:
        if self.current().type == TokenType.LPAREN:
            return self.parse_parenthesized_expr()
        return self.parse_comparison()

    def parse_comparison(self) -> ComparisonExpr:
        field = self.parse_dotted_name()
        operator = self.parse_operator()
        value = self.parse_value()
        return ComparisonExpr(field=field, operator=operator, value=value)


def parse_tokens(tokens: list[Token]) -> CovenantSpec:
    return Parser(tokens).parse()


def parse_source(source: str) -> CovenantSpec:
    return parse_tokens(tokenize(source))
