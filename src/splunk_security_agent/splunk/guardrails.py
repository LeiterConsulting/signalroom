from __future__ import annotations

import re

READ_ONLY_DENY = re.compile(
    r"(?i)\|\s*(delete|collect|outputlookup|sendemail|script|map)\b|"
    r"\b(rest|inputlookup)\s+.*\b(post|delete)\b"
)


def validate_read_only_spl(query: str) -> str:
    normalized = query.strip()
    if not normalized:
        raise ValueError("Validation SPL cannot be empty")
    if len(normalized) > 20000:
        raise ValueError("Validation SPL exceeds the 20,000-character safety limit")
    if READ_ONLY_DENY.search(normalized):
        raise ValueError("Validation SPL contains a modifying or high-risk command")
    if ";" in normalized:
        raise ValueError("Validation SPL cannot contain command separators")
    return normalized
