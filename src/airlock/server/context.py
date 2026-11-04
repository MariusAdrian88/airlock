"""Shared state handed to every tool implementation."""

from __future__ import annotations

from dataclasses import dataclass, field

from airlock.config import Config
from airlock.server.indexer import Indexer
from airlock.worker.client import WorkerClient


@dataclass
class ServerContext:
    config: Config
    worker: WorkerClient
    not_implemented: list[str] = field(default_factory=list)
    indexer: Indexer = field(init=False)

    def __post_init__(self) -> None:
        self.indexer = Indexer(self.config, self.worker)
