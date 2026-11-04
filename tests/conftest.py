"""Shared pytest setup.

`--binary=<exe>` (or `--xbin=<folder>`) enables the `ghidra` integration tests, which drive
the real worker (JVM + Ghidra, minutes for the first analysis). Without either they are skipped.

Write it as `--binary=<exe>` (with the equals sign). With `--binary <exe>` pytest does not
yet know the option takes a value, so it treats <exe> as a test path, derives the rootdir
and ini file from the exe's folder, and never loads pyproject.toml or this conftest:
hence "unrecognized arguments: --binary".
"""

from __future__ import annotations

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption("--binary", action="store", default=None,
                     help="path to a PE file for the Ghidra integration tests (-m ghidra)")


    parser.addoption("--xbin", action="store", default=None,
                     help="folder with an exe and a DLL it imports (cross-binary Ghidra test); "
                          "pass with = like --binary")


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "ghidra: needs a Ghidra install and --binary <exe>")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption("--binary") or config.getoption("--xbin"):
        return  # tests lacking their own option skip through their fixture
    skip = pytest.mark.skip(reason="needs --binary <exe> or --xbin <folder> (Ghidra integration test)")
    for item in items:
        if "ghidra" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(scope="session")
def binary_path(request: pytest.FixtureRequest) -> str:
    path = request.config.getoption("--binary")
    if not path:
        pytest.skip("needs --binary <exe>")
    return path


@pytest.fixture(scope="session")
def xbin_dir(request: pytest.FixtureRequest) -> str:
    path = request.config.getoption("--xbin")
    if not path:
        pytest.skip("needs --xbin=<folder with an exe and a DLL it imports>")
    return path
