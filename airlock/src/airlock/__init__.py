"""Airlock — a pre-execution gate for files arriving on a machine.

Airlock inspects a file *statically*: it never executes, interprets, extracts to
disk, or otherwise gives the sample a chance to run. Every module in this package
treats its input as hostile.
"""

__version__ = "1.0.0"
