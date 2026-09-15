"""Residential ProxyIP pipeline helpers.

This module keeps residential classification separate from existing CF scanning.
The existing scanner remains the source of truth for TCP/TLS/EDT validation.
"""

from typing import Any, Dict


def build_residential_record(candidate: Dict[str, Any], purity: Dict[str, Any], score: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "proxyip": candidate.get("proxyip") or candidate.get("target"),
        "source": candidate.get("source", "unknown"),
        "exit_ip": purity.get("checked_ip"),
        "country": purity.get("country"),
        "asn": purity.get("asn"),
        "org": purity.get("org"),
        "is_residential": purity.get("is_residential"),
        "network_type": purity.get("network_type"),
        "purity_score": purity.get("purity_score"),
        "residential_score": score.get("residential_score"),
        "classification": score.get("classification"),
    }


def should_enter_residential_pool(record: Dict[str, Any]) -> bool:
    return bool(
        record.get("residential_score", 0) >= 70
        and record.get("proxyip")
        and record.get("exit_ip")
    )
