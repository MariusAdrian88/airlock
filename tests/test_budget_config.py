from types import SimpleNamespace

from airlock.server.tools.common import budget_for


def ctx(**defaults):
    return SimpleNamespace(config=SimpleNamespace(defaults=defaults))


def test_defaults_per_tool():
    c = ctx(token_budget=2000, function_budget=10000, max_budget=32000)
    assert budget_for(c) == 2000
    assert budget_for(c, 0, "function_budget") == 10000


def test_fallbacks_when_config_is_silent():
    assert budget_for(ctx()) == 2000
    assert budget_for(ctx(), 0, "function_budget") == 10000


def test_override_is_capped():
    c = ctx(token_budget=2000, function_budget=10000, max_budget=32000)
    assert budget_for(c, 50000, "function_budget") == 32000
    assert budget_for(c, 500) == 500
    assert budget_for(c, 10) == 100


def test_cap_never_below_tool_default():
    # an older user config with max_budget 8000 still lets function use 10000
    c = ctx(token_budget=2000, function_budget=10000, max_budget=8000)
    assert budget_for(c, 0, "function_budget") == 10000
    assert budget_for(c, 20000, "function_budget") == 10000
    assert budget_for(c, 20000) == 8000
