from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

import z3

from ast_nodes import (
    BooleanExpr,
    ComparisonExpr,
    ComparisonOperator,
    CovenantEffect,
    CovenantRequirement,
    CovenantSpec,
    CovenantStatement,
    LogicalAndExpr,
    LogicalOrExpr,
)


class StrictSemanticError(TypeError):
    """Raised when the policy is semantically ill-typed for SMT compilation."""


class PolicyViolationError(RuntimeError):
    """Raised when verification is UNSAT and the unsat core identifies blocking rules."""

    def __init__(self, core_names: list[str], core_details: list[str]) -> None:
        self.core_names = core_names
        self.core_details = core_details
        message = "Policy verification failed (UNSAT). Unsat core: " + ", ".join(core_names)
        if core_details:
            message += "\nDetails:\n- " + "\n- ".join(core_details)
        super().__init__(message)


Primitive = str | int | float | bool


class SortKind(str, Enum):
    STRING = "string"
    INT = "int"
    REAL = "real"
    BOOL = "bool"


@dataclass(frozen=True)
class TrackedConstraint:
    name: str
    formula: z3.BoolRef
    description: str


@dataclass(frozen=True)
class CompiledPolicy:
    spec_name: str
    action_var: z3.SeqRef
    field_sorts: dict[str, SortKind]
    tracked_constraints: tuple[TrackedConstraint, ...]
    required_fields: tuple[str, ...]


@dataclass
class SymbolTable:
    action_var: z3.SeqRef
    fields: dict[str, z3.ExprRef]

    def get_field(self, field: str) -> z3.ExprRef:
        return self.fields[field]


@dataclass
class VerificationResult:
    sat_result: z3.CheckSatResult
    core_names: list[str]
    core_details: list[str]


class Z3Compiler:
    """Pure symbolic compiler for CovenantSpec.

    Compile phase:
      - receives only AST
      - produces symbolic variables + tracked BoolRef axioms

    Verify phase:
      - receives runtime assignments
      - injects equalities into a fresh solver with unsat_core enabled
      - raises PolicyViolationError on UNSAT
    """

    def __init__(self, spec: CovenantSpec) -> None:
        self.spec = spec
        self.compiled_policy = self.compile(spec)

    @classmethod
    def compile(cls, spec: CovenantSpec) -> CompiledPolicy:
        field_sorts = cls._infer_field_sorts(spec)
        symbols = cls._build_symbol_table(field_sorts)

        tracked: list[TrackedConstraint] = []

        # 1. require clauses become axioms
        for index, req in enumerate(spec.requirements):
            formula = cls._compile_requirement(req, symbols, field_sorts)
            name = f"require_{index}"
            desc = f"require axiom violated: {req.field} {req.operator.value} {req.value!r}"
            tracked.append(TrackedConstraint(name=name, formula=formula, description=desc))

        # 2. forbid clauses become negated safety predicates
        forbids = [s for s in spec.statements if s.effect == CovenantEffect.FORBID]
        for index, stmt in enumerate(forbids):
            predicate = cls._compile_statement_predicate(stmt, symbols, field_sorts)
            name = f"forbid_{index}"
            desc = f"forbid rule triggered: {cls._statement_to_text(stmt)}"
            tracked.append(TrackedConstraint(name=name, formula=z3.Not(predicate), description=desc))

        # 3. permit set becomes existence condition (default deny if none match)
        permits = [s for s in spec.statements if s.effect == CovenantEffect.PERMIT]
        if permits:
            permit_predicates = [
                cls._compile_statement_predicate(stmt, symbols, field_sorts) for stmt in permits
            ]
            tracked.append(
                TrackedConstraint(
                    name="permit_match_required",
                    formula=z3.Or(*permit_predicates),
                    description="default deny: at least one permit rule must match",
                )
            )
        else:
            tracked.append(
                TrackedConstraint(
                    name="permit_match_required",
                    formula=z3.BoolVal(False),
                    description="default deny: policy contains no permit rules",
                )
            )

        return CompiledPolicy(
            spec_name=spec.name,
            action_var=symbols.action_var,
            field_sorts=field_sorts,
            tracked_constraints=tuple(tracked),
            required_fields=tuple(sorted(field_sorts.keys())),
        )

    @staticmethod
    def verify_action(
        agent_state: dict[str, Any],
        params: dict[str, Any],
        compiled_policy: CompiledPolicy,
    ) -> z3.CheckSatResult:
        result = Z3Compiler.explain_action(agent_state, params, compiled_policy)
        if result.sat_result == z3.unsat:
            raise PolicyViolationError(result.core_names, result.core_details)
        return result.sat_result

    @staticmethod
    def explain_action(
        agent_state: dict[str, Any],
        params: dict[str, Any],
        compiled_policy: CompiledPolicy,
    ) -> VerificationResult:
        solver = z3.Solver()
        solver.set(unsat_core=True)

        label_descriptions: dict[str, str] = {}

        # 1. add compiled policy axioms
        for item in compiled_policy.tracked_constraints:
            label = z3.Bool(item.name)
            solver.assert_and_track(item.formula, label)
            label_descriptions[item.name] = item.description

        # 2. add runtime equalities for action + fields
        runtime_action, runtime_fields = Z3Compiler._normalize_runtime_inputs(agent_state, params)

        action_label = "runtime_action"
        solver.assert_and_track(
            compiled_policy.action_var == z3.StringVal(runtime_action),
            z3.Bool(action_label),
        )
        label_descriptions[action_label] = f"runtime binding: action == {runtime_action!r}"

        for field_name, sort_kind in compiled_policy.field_sorts.items():
            label_name = f"bind_{field_name.replace('.', '__')}"
            if field_name not in runtime_fields:
                solver.assert_and_track(z3.BoolVal(False), z3.Bool(label_name))
                label_descriptions[label_name] = f"missing runtime field required by policy: {field_name}"
                continue

            runtime_value = runtime_fields[field_name]
            actual_kind = Z3Compiler._runtime_sort_kind(runtime_value)
            if actual_kind != sort_kind:
                solver.assert_and_track(z3.BoolVal(False), z3.Bool(label_name))
                label_descriptions[label_name] = (
                    f"type mismatch for field {field_name}: expected {sort_kind.value}, got {actual_kind.value}"
                )
                continue

            symbol = Z3Compiler._make_symbol(field_name, sort_kind)
            literal = Z3Compiler._literal_to_z3(runtime_value, sort_kind)
            solver.assert_and_track(symbol == literal, z3.Bool(label_name))
            label_descriptions[label_name] = f"runtime binding: {field_name} == {runtime_value!r}"

        sat_result = solver.check()
        if sat_result == z3.unsat:
            core = solver.unsat_core()
            core_names = [str(item) for item in core]
            core_details = [label_descriptions.get(name, name) for name in core_names]
            return VerificationResult(sat_result=sat_result, core_names=core_names, core_details=core_details)

        return VerificationResult(sat_result=sat_result, core_names=[], core_details=[])

    @staticmethod
    def _normalize_runtime_inputs(
        agent_state: dict[str, Any],
        params: dict[str, Any],
    ) -> tuple[str, dict[str, Primitive]]:
        if "action" in params:
            action = params["action"]
            raw_params = params.get("params", {})
            if not isinstance(raw_params, dict):
                raise TypeError("params['params'] must be a dict when 'action' is present")
        else:
            action = params.get("__action__")
            raw_params = {k: v for k, v in params.items() if k != "__action__"}
        if not isinstance(action, str):
            raise TypeError("Runtime params must include an action string")

        runtime_fields = Z3Compiler._flatten_dict(agent_state)
        runtime_fields.update(Z3Compiler._flatten_dict(raw_params))
        return action, runtime_fields

    @staticmethod
    def _flatten_dict(data: dict[str, Any], prefix: str = "") -> dict[str, Primitive]:
        out: dict[str, Primitive] = {}
        for key, value in data.items():
            path = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                out.update(Z3Compiler._flatten_dict(value, path))
            elif isinstance(value, (str, int, float, bool)):
                out[path] = value
        return out

    @staticmethod
    def _infer_field_sorts(spec: CovenantSpec) -> dict[str, SortKind]:
        field_kinds: dict[str, set[SortKind]] = {}

        def record(field: str, value: Primitive) -> None:
            field_kinds.setdefault(field, set()).add(Z3Compiler._literal_sort_kind(value))

        for req in spec.requirements:
            record(req.field, req.value)

        def walk(expr: BooleanExpr) -> None:
            if isinstance(expr, ComparisonExpr):
                record(expr.field, expr.value)
            elif isinstance(expr, LogicalAndExpr) or isinstance(expr, LogicalOrExpr):
                for operand in expr.operands:
                    walk(operand)
            else:
                raise StrictSemanticError(f"Unsupported expression node: {type(expr)!r}")

        for stmt in spec.statements:
            for cond in stmt.conditions:
                walk(cond)

        resolved: dict[str, SortKind] = {}
        for field, kinds in field_kinds.items():
            if kinds == {SortKind.INT, SortKind.REAL}:
                resolved[field] = SortKind.REAL
            elif len(kinds) == 1:
                resolved[field] = next(iter(kinds))
            else:
                raise StrictSemanticError(
                    f"Incompatible literal types declared for field {field!r}: {sorted(k.value for k in kinds)}"
                )
        return resolved

    @staticmethod
    def _build_symbol_table(field_sorts: dict[str, SortKind]) -> SymbolTable:
        action_var = z3.String("action")
        fields = {name: Z3Compiler._make_symbol(name, sort_kind) for name, sort_kind in field_sorts.items()}
        return SymbolTable(action_var=action_var, fields=fields)

    @staticmethod
    def _make_symbol(field_name: str, sort_kind: SortKind) -> z3.ExprRef:
        symbol_name = field_name.replace('.', '__')
        if sort_kind == SortKind.STRING:
            return z3.String(symbol_name)
        if sort_kind == SortKind.INT:
            return z3.Int(symbol_name)
        if sort_kind == SortKind.REAL:
            return z3.Real(symbol_name)
        if sort_kind == SortKind.BOOL:
            return z3.Bool(symbol_name)
        raise StrictSemanticError(f"Unsupported sort kind: {sort_kind}")

    @staticmethod
    def _compile_requirement(
        req: CovenantRequirement,
        symbols: SymbolTable,
        field_sorts: dict[str, SortKind],
    ) -> z3.BoolRef:
        expr = ComparisonExpr(field=req.field, operator=req.operator, value=req.value)
        return Z3Compiler._compile_comparison(expr, symbols, field_sorts)

    @staticmethod
    def _compile_statement_predicate(
        stmt: CovenantStatement,
        symbols: SymbolTable,
        field_sorts: dict[str, SortKind],
    ) -> z3.BoolRef:
        action_match = symbols.action_var == z3.StringVal(stmt.action)
        if not stmt.conditions:
            condition_formula = z3.BoolVal(True)
        else:
            compiled_conditions = [
                Z3Compiler._compile_boolean_expr(expr, symbols, field_sorts) for expr in stmt.conditions
            ]
            condition_formula = z3.And(*compiled_conditions)
        return z3.And(action_match, condition_formula)

    @staticmethod
    def _compile_boolean_expr(
        expr: BooleanExpr,
        symbols: SymbolTable,
        field_sorts: dict[str, SortKind],
    ) -> z3.BoolRef:
        if isinstance(expr, ComparisonExpr):
            return Z3Compiler._compile_comparison(expr, symbols, field_sorts)
        if isinstance(expr, LogicalAndExpr):
            return z3.And(*[Z3Compiler._compile_boolean_expr(op, symbols, field_sorts) for op in expr.operands])
        if isinstance(expr, LogicalOrExpr):
            return z3.Or(*[Z3Compiler._compile_boolean_expr(op, symbols, field_sorts) for op in expr.operands])
        raise StrictSemanticError(f"Unsupported boolean expression node: {type(expr)!r}")

    @staticmethod
    def _compile_comparison(
        expr: ComparisonExpr,
        symbols: SymbolTable,
        field_sorts: dict[str, SortKind],
    ) -> z3.BoolRef:
        if expr.field not in field_sorts:
            raise StrictSemanticError(f"Field {expr.field!r} was not declared in field sort table")

        sort_kind = field_sorts[expr.field]
        literal_kind = Z3Compiler._literal_sort_kind(expr.value)

        # int literal can flow into real field by promotion
        if sort_kind == SortKind.REAL and literal_kind == SortKind.INT:
            literal_kind = SortKind.REAL
        if literal_kind != sort_kind:
            raise StrictSemanticError(
                f"Type mismatch in policy for field {expr.field!r}: field sort {sort_kind.value}, literal sort {literal_kind.value}"
            )

        field_var = symbols.get_field(expr.field)
        literal = Z3Compiler._literal_to_z3(expr.value, sort_kind)

        if sort_kind in {SortKind.STRING, SortKind.BOOL} and expr.operator not in {
            ComparisonOperator.EQ,
            ComparisonOperator.NE,
        }:
            raise StrictSemanticError(
                f"Operator {expr.operator.value!r} is not supported for sort {sort_kind.value} on field {expr.field!r}"
            )

        if expr.operator == ComparisonOperator.GT:
            return field_var > literal
        if expr.operator == ComparisonOperator.LT:
            return field_var < literal
        if expr.operator == ComparisonOperator.GE:
            return field_var >= literal
        if expr.operator == ComparisonOperator.LE:
            return field_var <= literal
        if expr.operator == ComparisonOperator.EQ:
            return field_var == literal
        if expr.operator == ComparisonOperator.NE:
            return field_var != literal
        raise StrictSemanticError(f"Unsupported comparison operator: {expr.operator!r}")

    @staticmethod
    def _literal_sort_kind(value: Primitive) -> SortKind:
        if type(value) is bool:
            return SortKind.BOOL
        if type(value) is int:
            return SortKind.INT
        if type(value) is float:
            return SortKind.REAL
        if type(value) is str:
            return SortKind.STRING
        raise StrictSemanticError(f"Unsupported literal type: {type(value)!r}")

    @staticmethod
    def _runtime_sort_kind(value: Primitive) -> SortKind:
        return Z3Compiler._literal_sort_kind(value)

    @staticmethod
    def _literal_to_z3(value: Primitive, sort_kind: SortKind) -> z3.ExprRef:
        if sort_kind == SortKind.BOOL:
            return z3.BoolVal(bool(value))
        if sort_kind == SortKind.INT:
            return z3.IntVal(int(value))
        if sort_kind == SortKind.REAL:
            return z3.RealVal(str(float(value) if isinstance(value, int) else value))
        if sort_kind == SortKind.STRING:
            return z3.StringVal(str(value))
        raise StrictSemanticError(f"Unsupported sort kind for literal conversion: {sort_kind}")

    @staticmethod
    def _statement_to_text(stmt: CovenantStatement) -> str:
        pieces = [stmt.effect.value, stmt.action]
        if stmt.conditions:
            pieces.append("(" + ", ".join(Z3Compiler._expr_to_text(expr) for expr in stmt.conditions) + ")")
        return " ".join(pieces)

    @staticmethod
    def _expr_to_text(expr: BooleanExpr) -> str:
        if isinstance(expr, ComparisonExpr):
            value_repr = repr(expr.value) if isinstance(expr.value, str) else str(expr.value)
            return f"{expr.field} {expr.operator.value} {value_repr}"
        if isinstance(expr, LogicalAndExpr):
            return " && ".join(Z3Compiler._expr_to_text(op) for op in expr.operands)
        if isinstance(expr, LogicalOrExpr):
            return " || ".join(Z3Compiler._expr_to_text(op) for op in expr.operands)
        raise StrictSemanticError(f"Unsupported expression for text conversion: {type(expr)!r}")
