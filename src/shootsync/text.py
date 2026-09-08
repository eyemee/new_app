"""Small, dependency-free text utilities shared by the local aligner."""
from __future__ import annotations

import math
import re
from collections import Counter

STOPWORDS = {
    "a","an","and","are","as","at","be","because","been","but","by","can","could","did",
    "do","does","for","from","get","got","had","has","have","he","her","here","him","his",
    "how","i","if","in","into","is","it","its","just","like","me","more","most","my","no",
    "not","of","on","one","or","our","out","she","so","some","than","that","the","their",
    "them","then","there","these","they","this","to","up","us","very","was","we","were",
    "what","when","which","who","will","with","would","you","your","okay","right","going",
    "want","really","actually","thing","things","lot","kind","sort","yeah","uh","um","said",
    "say","says","let","now","about","all","also","any","been","being","were","own","them",
}

NUMBER_WORDS = {
    "zero":0,"one":1,"two":2,"three":3,"four":4,"five":5,"six":6,"seven":7,"eight":8,
    "nine":9,"ten":10,"eleven":11,"twelve":12,
}

_WORD_RE = re.compile(r"[a-z][a-z'-]*|\d+(?:[.,]\d+)?%?")


def stem(word: str) -> str:
    """Crude suffix stripper. Good enough to make 'anchoring'/'anchors'/'anchored' match."""
    for suf in ("ingly", "edly", "ing", "ers", "er", "ed", "es", "s", "ly"):
        if word.endswith(suf) and len(word) - len(suf) >= 4:
            return word[: -len(suf)]
    return word


def tokenize(text: str) -> list[str]:
    out = []
    for w in _WORD_RE.findall(text.lower()):
        if w in STOPWORDS or len(w) < 2:
            continue
        out.append(stem(w))
    return out


def numerals(text: str) -> set[str]:
    """Numeric claims in a passage: digits, percentages, and small number-words."""
    found: set[str] = set()
    for m in re.finditer(r"\d+(?:[.,]\d+)?%?", text.lower()):
        found.add(m.group(0).rstrip("."))
    for w, n in NUMBER_WORDS.items():
        if re.search(rf"\b{w}\b", text.lower()):
            found.add(str(n))
    return found


class Tfidf:
    """Minimal TF-IDF vectoriser with cosine similarity."""

    def __init__(self, documents: list[list[str]]):
        n = max(len(documents), 1)
        df = Counter()
        for doc in documents:
            df.update(set(doc))
        self.idf = {t: math.log((n + 1) / (c + 1)) + 1.0 for t, c in df.items()}
        self.default_idf = math.log(n + 1) + 1.0

    def vector(self, tokens: list[str]) -> dict[str, float]:
        if not tokens:
            return {}
        tf = Counter(tokens)
        vec = {t: (1.0 + math.log(c)) * self.idf.get(t, self.default_idf) for t, c in tf.items()}
        norm = math.sqrt(sum(v * v for v in vec.values())) or 1.0
        return {t: v / norm for t, v in vec.items()}

    @staticmethod
    def cosine(a: dict[str, float], b: dict[str, float]) -> float:
        if len(a) > len(b):
            a, b = b, a
        return sum(v * b.get(t, 0.0) for t, v in a.items())
