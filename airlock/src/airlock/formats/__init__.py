"""Per-format static analysers.

Every analyser takes a ``SafeFile`` (plus already-computed context) and returns a
list of ``Finding``. None of them writes to disk, spawns a process, or resolves a
network name. A parser that cannot make sense of its input raises, and the
scanner converts that into a fail-closed error rather than an ALLOW.
"""
