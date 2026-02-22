"""Shared utilities used across the AATMF toolkit."""

import math
import re
from collections.abc import Sequence

# ── Tactic -> Probe Type ─────────────────────────────────────

TACTIC_PROBE_TYPE_MAP: dict[str, str] = {
    "T1": "injection",
    "T2": "encoding",
    "T3": "single_turn",
    "T4": "multi_turn",
    "T5": "api_exploit",
    "T6": "training_poison",
    "T7": "output_exploit",
    "T8": "deception",
    "T9": "multimodal",
    "T10": "supply_chain",
    "T11": "agentic",
    "T12": "rag_injection",
    "T13": "model_theft",
    "T14": "infra",
    "T15": "human_workflow",
    "T16": "mcp_exploit",
    "T17": "a2a_attack",
    "T18": "evasion",
    "T19": "persistence",
    "T20": "orchestration",
}

# ── Tactic -> LLM Playbook Layer ─────────────────────────────

TACTIC_TO_PLAYBOOK_LAYER: dict[str, int] = {
    "T1": 1,
    "T2": 1,
    "T3": 2,
    "T4": 2,
    "T5": 5,
    "T6": 0,
    "T7": 4,
    "T8": 3,
    "T9": 1,
    "T10": 0,
    "T11": 5,
    "T12": 1,
    "T13": 0,
    "T14": 0,
    "T15": 3,
    "T16": 5,
    "T17": 5,
    "T18": 1,
    "T19": 2,
    "T20": 5,
}

# ── Executable vs Simulation-Only Types ──────────────────────

EXECUTABLE_TYPES: set[str] = {
    "injection",
    "encoding",
    "single_turn",
    "multi_turn",
    "output_exploit",
    "deception",
    "mcp_exploit",
    "evasion",
}

SIMULATION_TYPES: set[str] = {
    "api_exploit",
    "training_poison",
    "multimodal",
    "supply_chain",
    "agentic",
    "rag_injection",
    "model_theft",
    "infra",
    "human_workflow",
    "a2a_attack",
    "persistence",
    "orchestration",
}

# ── Tactic Name Lookup ───────────────────────────────────────

TACTIC_NAMES: dict[str, str] = {
    "T1": "Prompt Subversion",
    "T2": "Semantic Evasion",
    "T3": "Reasoning Exploitation",
    "T4": "Multi-Turn Memory Manipulation",
    "T5": "API & Tool Exploitation",
    "T6": "Training Data Poisoning",
    "T7": "Output Manipulation",
    "T8": "Identity Deception",
    "T9": "Multimodal Attacks",
    "T10": "Supply Chain Attacks",
    "T11": "Agentic Exploitation",
    "T12": "RAG Injection",
    "T13": "Model Theft/Extraction",
    "T14": "Infrastructure Attacks",
    "T15": "Human Workflow Exploitation",
    "T16": "MCP Exploitation",
    "T17": "A2A Attacks",
    "T18": "Evasion Techniques",
    "T19": "Persistence",
    "T20": "Orchestration Attacks",
}


# ── ID Normalization ─────────────────────────────────────────


def normalize_tactic_id(raw_id: str) -> str:
    """Normalize TC-01 -> T1, TC-15 -> T15, T1 -> T1. Accepts both formats."""
    raw = raw_id.strip().upper()
    if raw.startswith("TC-"):
        num = int(raw.replace("TC-", ""))
        return f"T{num}"
    if raw.startswith("T") and raw[1:].isdigit():
        return f"T{int(raw[1:])}"
    return raw


# ── Cosine Similarity ────────────────────────────────────────


def cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
    """Compute cosine similarity between two vectors."""
    if len(a) != len(b) or len(a) == 0:
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


# ── Code Pattern Detection ───────────────────────────────────

CODE_PATTERNS: list[re.Pattern] = [
    re.compile(r"\bimport\s+\w+", re.I),
    re.compile(r"\bdef\s+\w+\s*\(", re.I),
    re.compile(r"\bclass\s+\w+[\s:(]", re.I),
    re.compile(r"(?:subprocess|os\.system|eval|exec)\s*\(", re.I),
    re.compile(r"(?:socket|requests?|urllib|http)\.\w+", re.I),
    re.compile(r"(?:SELECT|INSERT|UPDATE|DELETE)\s+", re.I),
    re.compile(r"<script[\s>]", re.I),
    re.compile(r"(?:shell_exec|system|passthru|popen)\s*\(", re.I),
    re.compile(r"(?:sudo|chmod|chown|curl|wget)\s+", re.I),
    re.compile(r"(?:BEGIN\s+PGP|-----BEGIN\s+)", re.I),
    re.compile(r"(?:password|passwd|secret|token)\s*[=:]", re.I),
    re.compile(r"0x[0-9a-f]{8,}", re.I),
    re.compile(r"\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){3,}", re.I),
]


# ── Text Encoding Functions ──────────────────────────────────

LEET_MAP = {
    "a": "4",
    "e": "3",
    "i": "1",
    "o": "0",
    "s": "5",
    "t": "7",
    "l": "1",
    "g": "9",
    "b": "8",
}


def to_leetspeak(text: str) -> str:
    return "".join(LEET_MAP.get(c.lower(), c) for c in text)


def to_pig_latin(text: str) -> str:
    vowels = set("aeiouAEIOU")
    words = text.split()
    result = []
    for word in words:
        if not word or not word[0].isalpha():
            result.append(word)
            continue
        if word[0] in vowels:
            result.append(word + "way")
        else:
            i = 0
            while i < len(word) and word[i] not in vowels:
                i += 1
            result.append(word[i:] + word[:i] + "ay")
    return " ".join(result)


def to_fullwidth(text: str) -> str:
    result = []
    for c in text:
        cp = ord(c)
        if 0x21 <= cp <= 0x7E:
            result.append(chr(cp + 0xFEE0))
        elif c == " ":
            result.append("\u3000")
        else:
            result.append(c)
    return "".join(result)


NATO_ALPHABET = {
    "a": "Alpha",
    "b": "Bravo",
    "c": "Charlie",
    "d": "Delta",
    "e": "Echo",
    "f": "Foxtrot",
    "g": "Golf",
    "h": "Hotel",
    "i": "India",
    "j": "Juliet",
    "k": "Kilo",
    "l": "Lima",
    "m": "Mike",
    "n": "November",
    "o": "Oscar",
    "p": "Papa",
    "q": "Quebec",
    "r": "Romeo",
    "s": "Sierra",
    "t": "Tango",
    "u": "Uniform",
    "v": "Victor",
    "w": "Whiskey",
    "x": "X-ray",
    "y": "Yankee",
    "z": "Zulu",
}


def to_nato(text: str) -> str:
    result = []
    for c in text:
        if c.lower() in NATO_ALPHABET:
            result.append(NATO_ALPHABET[c.lower()])
        elif c == " ":
            result.append("[space]")
        else:
            result.append(c)
    return " ".join(result)


MORSE_CODE = {
    "a": ".-",
    "b": "-...",
    "c": "-.-.",
    "d": "-..",
    "e": ".",
    "f": "..-.",
    "g": "--.",
    "h": "....",
    "i": "..",
    "j": ".---",
    "k": "-.-",
    "l": ".-..",
    "m": "--",
    "n": "-.",
    "o": "---",
    "p": ".--.",
    "q": "--.-",
    "r": ".-.",
    "s": "...",
    "t": "-",
    "u": "..-",
    "v": "...-",
    "w": ".--",
    "x": "-..-",
    "y": "-.--",
    "z": "--..",
    "0": "-----",
    "1": ".----",
    "2": "..---",
    "3": "...--",
    "4": "....-",
    "5": ".....",
    "6": "-....",
    "7": "--...",
    "8": "---..",
    "9": "----.",
}


def to_morse(text: str) -> str:
    result = []
    for c in text:
        if c.lower() in MORSE_CODE:
            result.append(MORSE_CODE[c.lower()])
        elif c == " ":
            result.append("/")
        else:
            result.append(c)
    return " ".join(result)


# ── Quarter Splitter ─────────────────────────────────────────


def split_quarters(text: str) -> list[str]:
    """Split text into exactly 4 quarters. Last quarter gets remainder."""
    if len(text) < 4:
        return [text, "", "", ""]
    q = len(text) // 4
    return [text[:q], text[q : 2 * q], text[2 * q : 3 * q], text[3 * q :]]
