"""Scanner adapters: build argv, run processes, write raw output for importers."""

from attestra.runner.scanners.registry import get_adapter

__all__ = ["get_adapter"]
