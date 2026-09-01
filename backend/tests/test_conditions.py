"""Safe branch-guard evaluator (M7)."""
import pytest

from app.engine.conditions import referenced_names, safe_eval


def test_basic_truthiness_and_comparisons():
    assert safe_eval("contained == true", {"contained": True}) is True
    assert safe_eval("contained == false", {"contained": True}) is False
    assert safe_eval("a and b", {"a": True, "b": False}) is False
    assert safe_eval("a or b", {"a": False, "b": True}) is True
    assert safe_eval("not done", {"done": False}) is True


def test_empty_guard_is_true_and_unknown_vars_are_false():
    assert safe_eval("", {}) is True
    assert safe_eval("   ", {}) is True
    assert safe_eval("missing == true", {}) is False  # unknown -> False


def test_referenced_names():
    assert referenced_names("a and b == true") == {"a", "b"}
    assert referenced_names("") == set()


@pytest.mark.parametrize("expr", [
    "__import__('os')",          # call
    "obj.attr",                  # attribute access
    "a + b",                     # arithmetic operator
    "[x for x in y]",            # comprehension
])
def test_disallowed_expressions_are_rejected(expr):
    with pytest.raises(ValueError):
        safe_eval(expr, {"a": 1, "b": 2, "y": []})
