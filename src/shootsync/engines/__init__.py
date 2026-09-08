"""Reconciliation engines. Each takes (Lesson, segments) and returns an AsTaughtRecord."""
from .local import LocalReconciler

__all__ = ["LocalReconciler", "get_engine"]


def get_engine(name: str, **kwargs):
    if name == "local":
        return LocalReconciler(**kwargs)
    if name == "claude":
        from .claude import ClaudeReconciler
        return ClaudeReconciler(**kwargs)
    raise ValueError(f"unknown engine: {name!r} (expected 'local' or 'claude')")
