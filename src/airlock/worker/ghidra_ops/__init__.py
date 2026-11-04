"""Ghidra operations of the worker. Importing this package registers the ops.

No module here imports Ghidra or JPype at import time (the JVM is not running
yet); Java classes are imported inside functions after `start_ghidra`.
"""

from airlock.worker.ghidra_ops import decompile, extract, project  # noqa: F401
