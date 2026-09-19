"""Local candidate quality scoring.

No paid API dependency. This score is used internally for pool ordering and cleanup.
"""

import time
from typing import Any


def calculate_quality_score(row: dict) -> int:
    """Return 0-100 quality score from existing scanner metadata.

    Higher means a better candidate. Missing fields do not fail scoring.
    """
    score = 40

    if row.get("final_available") is True:
        score += 15
    elif row.get("available") is True:
        score += 8
    elif row.get("last_checked_at"):
        score -= 15

    failures = row.get("consecutive_failures") or row.get("failure_count") or row.get("failures") or 0
    try:
        score -= min(25, max(0, int(failures)) * 4)
    except Exception:
        pass

    # Reward nodes with enough verification history. A single successful probe
    # should not outweigh a long record of unstable behavior.
    checks = row.get("check_count")
    successes = row.get("success_count")
    if isinstance(checks, (int, float)) and isinstance(successes, (int, float)) and checks > 0:
        success_rate = max(0.0, min(1.0, float(successes) / float(checks)))
        score += (success_rate - 0.5) * 20
        if checks >= 20:
            score += 3

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
        if latency < 50:
            score += 10
        elif latency < 100:
            score += 8
        elif latency < 200:
            score += 5
        elif latency > 500:
            score -= 10
        elif latency > 300:
            score -= 7

    speed = row.get("speed") or {}
    if not speed and row.get("avg_mbps") is not None:
        speed = {"avg_mbps": row.get("avg_mbps")}
    if isinstance(speed, dict):
        mbps = speed.get("avg_mbps")
        if isinstance(mbps, (int, float)):
            if mbps >= 200:
                score += 15
            elif mbps >= 100:
                score += 10
            elif mbps >= 30:
                score += 5
            elif mbps < 5:
                score -= 8

    sources = row.get("sources") or []
    if isinstance(sources, list) and len(sources) > 1:
        score += min(8, len(sources) * 2)

    # Long-lived verified nodes should keep a small advantage, but stale
    # candidates should naturally fall down the pool without immediately being
    # deleted. This lets incremental scans focus resources on promising nodes.
    success_age = row.get("last_success_at")
    if isinstance(success_age, (int, float)):
        age_days = max(0, (time.time() - float(success_age)) / 86400)
        if age_days <= 1:
            score += 5
        elif age_days > 14:
            score -= min(10, int(age_days // 7))

    return max(0, min(100, int(round(score))))


def apply_quality_score(row: dict) -> dict:
    row["quality_score"] = calculate_quality_score(row)
    return row


def cleanup_sort_key(row: dict) -> tuple:
    return (
        int(row.get("quality_score") or 0),
        int(row.get("success_count") or 0),
        int(len(row.get("sources") or [])),
    )
