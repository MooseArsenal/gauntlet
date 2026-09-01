"""Safe evaluation of branch guard conditions over session state.

Conditions are small boolean expressions written against scenario variables,
e.g. ``host_isolated == true``, ``domain_compromised == false and backups_intact``.
They are parsed with ``ast`` and walked over an allow-list — no ``eval``, no
attribute/call access — so an imported scenario can never execute code.
"""
from __future__ import annotations

import ast

_ALLOWED = (
    ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.UnaryOp, ast.Not,
    ast.Compare, ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
    ast.Name, ast.Load, ast.Constant,
)

# YAML lower-case booleans map to Python; also accept bare names as truthiness.
_LITERALS = {"true": True, "false": False, "none": None, "null": None}


def _eval(node: ast.AST, state: dict):
    if isinstance(node, ast.Expression):
        return _eval(node.body, state)
    if isinstance(node, ast.BoolOp):
        vals = [_eval(v, state) for v in node.values]
        return all(vals) if isinstance(node.op, ast.And) else any(vals)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not _eval(node.operand, state)
    if isinstance(node, ast.Compare):
        left = _eval(node.left, state)
        for op, comp in zip(node.ops, node.comparators):
            right = _eval(comp, state)
            if not _apply(op, left, right):
                return False
            left = right
        return True
    if isinstance(node, ast.Name):
        low = node.id.lower()
        if low in _LITERALS:
            return _LITERALS[low]
        return state.get(node.id, False)
    if isinstance(node, ast.Constant):
        return node.value
    raise ValueError(f"disallowed expression element: {type(node).__name__}")


def _apply(op, left, right) -> bool:
    if isinstance(op, ast.Eq):
        return left == right
    if isinstance(op, ast.NotEq):
        return left != right
    if isinstance(op, ast.Lt):
        return left < right
    if isinstance(op, ast.LtE):
        return left <= right
    if isinstance(op, ast.Gt):
        return left > right
    if isinstance(op, ast.GtE):
        return left >= right
    raise ValueError("disallowed comparison")


def safe_eval(expr: str, state: dict) -> bool:
    """Evaluate a guard expression to a bool. Empty/None guard is always true."""
    if not expr or not str(expr).strip():
        return True
    tree = ast.parse(str(expr), mode="eval")
    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED):
            raise ValueError(f"disallowed expression element: {type(node).__name__}")
    return bool(_eval(tree, state))


def referenced_names(expr: str) -> set[str]:
    """Variable names a guard references (for validation)."""
    if not expr or not str(expr).strip():
        return set()
    tree = ast.parse(str(expr), mode="eval")
    return {
        n.id for n in ast.walk(tree)
        if isinstance(n, ast.Name) and n.id.lower() not in _LITERALS
    }
