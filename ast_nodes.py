from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TypeAlias


class CovenantEffect(str, Enum):
    PERMIT = "permit"
    FORBID = "forbid"


class ComparisonOperator(str, Enum):
    GT = ">"
    LT = "<"
    GE = ">="
    LE = "<="
    EQ = "=="
    NE = "!="


LiteralValue: TypeAlias = str | int | float | bool


@dataclass(frozen=True)
class ComparisonExpr:
    field: str
    operator: ComparisonOperator
    value: LiteralValue


@dataclass(frozen=True)
class LogicalAndExpr:
    operands: tuple["BooleanExpr", ...]


@dataclass(frozen=True)
class LogicalOrExpr:
    operands: tuple["BooleanExpr", ...]


BooleanExpr: TypeAlias = ComparisonExpr | LogicalAndExpr | LogicalOrExpr


@dataclass(frozen=True)
class CovenantRequirement:
    field: str
    operator: ComparisonOperator
    value: LiteralValue


@dataclass(frozen=True)
class CovenantStatement:
    effect: CovenantEffect
    action: str
    conditions: tuple[BooleanExpr, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class CovenantSpec:
    name: str
    statements: tuple[CovenantStatement, ...]
    requirements: tuple[CovenantRequirement, ...]
