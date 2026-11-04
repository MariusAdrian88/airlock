"""Shared pytest setup.

`--binary <exe>` enables the `ghidra` integration tests, which drive the real
worker (JVM + Ghidra, minutes for the first analysis). Without it they are skipped.
"""

from __future__ import annotations

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption("--binary", action="store", default=None,
                     help="path to a PE file for the Ghidra integration tests (-m ghidra)")


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "ghidra: needs a Ghidra install and --binary <exe>")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption("--binary"):
        return
    skip = pytest.mark.skip(reason="needs --binary <exe> (Ghidra integration test)")
    for item in items:
        if "ghidra" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(scope="session")
def binary_path(request: pytest.FixtureRequest) -> str:
    path = request.config.getoption("--binary")
    if not path:
        pytest.skip("needs --binary <exe>")
    return path
