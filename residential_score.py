"""Residential proxy candidate scoring.

The score is an additional decision layer. IP intelligence providers remain
responsible for raw network classification.
"""

from __future__ import annotations

from typing import Any


IDC_WORDS = {
    "amazon", "aws", "google", "azure", "microsoft", "oracle",
    "digitalocean", "vultr", "hetzner", "linode", "ovh",
}

ISP_WORDS = {
    "ntt", "kddi", "softbank", "comcast", "at&t", "verizon",
    "spectrum", "telecom", "broadband", "isp",
}


def calculate_residential_score(purity: dict[str, Any], stable_days: int = 0) -> dict[str, Any]:
    score = 0
    reasons: list[str] = []

    if purity.get("is_residential") is True:
        score += 45
        reasons.append("IPPure residential")

    if purity.get("is_idc") is True:
        score -= 60
        reasons.append("IDC network")

    org = str(purity.get("org") or "").lower()

    if any(word in org for word in IDC_WORDS):
        score -= 50
        reasons.append("hosting ASN")

    if any(word in org for word in ISP_WORDS):
        score += 25
        reasons.append("ISP network")

    risk = purity.get("risk_score")
    if isinstance(risk, (int, float)):
        if risk < 20:
            score += 10
            reasons.append("low risk")
        elif risk > 70:
            score -= 20

    if stable_days >= 30:
        score += 20
        reasons.append("30 days stable")
    elif stable_days >= 7:
        score += 10

    score = max(0, min(100, score))

    if score >= 80:
        level = "A"
    elif score >= 60:
        level = "B"
    else:
        level = "C"

    return {
        "residential_score": score,
        "residential_level": level,
        "classification": "residential_candidate" if score >= 60 else "unknown",
        "reasons": reasons,
    }
