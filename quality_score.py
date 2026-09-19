"""Candidate purity scoring used for pool ordering and cleanup."""

from typing import Optional


def extract_purity_score(row: dict) -> Optional[int]:
    """Return the provider's raw risk coefficient (lower is cleaner)."""
    purity = row.get("purity") or {}
    value = purity.get("risk_score") if isinstance(purity, dict) else None
    if value is None and isinstance(purity, dict):
        value = purity.get("purity_score")
    if value is None:
        value = row.get("risk_score")
    if value is None:
        value = row.get("purity_score")
    try:
        return max(0, min(100, int(round(float(value)))))
    except (TypeError, ValueError):
        return None


def calculate_quality_score(row: dict) -> int:
    """Keep legacy higher-is-better ordering based only on provider purity."""
    coefficient = extract_purity_score(row)
    return 100 - coefficient if coefficient is not None else 0


def apply_quality_score(row: dict) -> dict:
    row["quality_score"] = calculate_quality_score(row)
    return row


def cleanup_sort_key(row: dict) -> tuple:
    return (
        int(row.get("quality_score") or 0),
        int(row.get("success_count") or 0),
        int(len(row.get("sources") or [])),
    )
