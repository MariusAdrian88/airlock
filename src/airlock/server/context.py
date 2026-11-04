"""Shared state handed to every tool implementation."""

from __future__ import annotations

from dataclasses import dataclass, field

from airlock.config import Config
from airlock.worker.client import WorkerClient


@dataclass
class ServerContext:
    config: Config
    worker: WorkerClient
    not_implemented: list[str] = field(default_factory=list)
