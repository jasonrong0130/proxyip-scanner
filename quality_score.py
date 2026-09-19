"""Local candidate quality scoring.

No paid API dependency. This score is used internally for pool ordering and cleanup.
"""

from typing import Any


def calculate_quality_score(row: dict) -> int:
    """Return 0-100 quality score from existing scanner metadata.

    Higher means a better candidate. Missing fields do not fail scoring.
    """
    score = 50

    if row.get("final_available") is True:
        score += 25
    elif row.get("available") is True:
        score += 10
    elif row.get("last_checked_at"):
        score -= 15

    failures = row.get("consecutive_failures") or row.get("failure_count") or row.get("failures") or 0
    try:
        score -= min(25, max(0, int(failures)) * 4)
    except Exception:
        pass

    purity = row.get("purity") or {}
    if not purity and any(key in row for key in ("purity_score", "risk_score", "is_residential", "is_idc")):
        purity = {key: row.get(key) for key in ("purity_score", "risk_score", "is_residential", "is_idc")}
    if isinstance(purity, dict):
        purity_score = purity.get("purity_score")
        risk = purity.get("risk_score")
        if isinstance(purity_score, (int, float)):
            score += (float(purity_score) - 50) * 0.35
        if isinstance(risk, (int, float)):
            score -= float(risk) * 0.2
        if purity.get("is_residential") is True:
            score += 15
        if purity.get("is_idc") is True:
            score -= 8

    latency = row.get("tcp_ms")
    if isinstance(latency, (int, float)):
        if latency < 80:
            score += 10
        elif latency < 160:
            score += 5
        elif latency > 500:
            score -= 12
        elif latency > 300:
            score -= 7

    speed = row.get("speed") or {}
    if not speed and row.get("avg_mbps") is not None:
        speed = {"avg_mbps": row.get("avg_mbps")}
    if isinstance(speed, dict):
        mbps = speed.get("avg_mbps")
        if isinstance(mbps, (int, float)):
            if mbps >= 100:
                score += 10
            elif mbps >= 30:
                score += 5
            elif mbps < 5:
                score -= 8

    sources = row.get("sources") or []
    if isinstance(sources, list) and len(sources) > 1:
        score += min(8, len(sources) * 2)

    return max(0, min(100, int(round(score))))


def apply_quality_score(row: dict) -> dict:
    row["quality_score"] = calculate_quality_score(row)
    return row


def cleanup_sort_key(row: dict) -> tuple:
    return (
        int(row.get("quality_score") or 0),
        int(len(row.get("sources") or [])),
    )
