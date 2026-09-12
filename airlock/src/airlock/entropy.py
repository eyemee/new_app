"""Entropy and printability measures.

Used to tell "this region is compressed or encrypted" from "this region is code
or text". Packers, crypters and appended payloads all push a region's Shannon
entropy toward 8.0 bits/byte; hand-written code sits around 4.5-6.5.
"""

from __future__ import annotations

import math
from collections import Counter

#: Above this, a byte range is statistically indistinguishable from compressed
#: or encrypted data. 7.0 is the conventional line; 7.2 keeps the false positive
#: rate down on legitimately compressed resources.
PACKED_THRESHOLD = 7.2
HIGH_THRESHOLD = 7.0


def shannon(data: bytes) -> float:
    """Shannon entropy in bits per byte, 0.0 for empty input."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    value = -sum((c / total) * math.log2(c / total) for c in counts.values())
    return value + 0.0  # normalise -0.0


def printable_ratio(data: bytes) -> float:
    """Fraction of bytes that are printable ASCII, tab, CR or LF."""
    if not data:
        return 0.0
    printable = sum(1 for b in data if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D))
    return printable / len(data)


def looks_textual(data: bytes) -> bool:
    """A conservative "this is text" test: no NULs and mostly printable."""
    if not data:
        return True
    if b"\x00" in data[:4096]:
        return False
    return printable_ratio(data[:8192]) >= 0.90


def is_packed(entropy_value: float, size: int, min_size: int = 4096) -> bool:
    """Entropy alone is meaningless on small inputs -- a 40-byte section can hit
    5.3 bits/byte by accident -- so require a floor on the sample size."""
    return size >= min_size and entropy_value >= PACKED_THRESHOLD
