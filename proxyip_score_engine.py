"""
ProxyIP Scanner V2 quality scoring engine.

This module is intentionally independent from the scanner workflow so existing
scan behaviour remains unchanged. It provides a backend score calculation layer
for future candidate-pool promotion, aging and cleanup decisions.

Score range: 0-100

Weights:
- connectivity stability: 25
- latency: 15
- throughput: 15
- Cloudflare/edge quality: 15
- ASN/network reputation signals: 15
- freshness/history: 10
- failure penalty: 5
"""

from __future__ import annotations

from dataclasses import dataclass
from math import exp
from typing import Optional


@dataclass(slots=True)
class ProxyMetrics:
    latency_ms: Optional[float] = None
    speed_mbps: Optional[float] = None
    success_rate: float = 0.0
    cf_detected: bool = False
    colo_match: bool = False
    asn_quality: float = 0.5
    age_days: float = 0.0
    failures: int = 0


class ProxyScoreEngine:
    def score(self, metrics: ProxyMetrics) -> float:
        score = 0.0
        score += self._clamp(metrics.success_rate) * 25
        score += self._latency(metrics.latency_ms) * 15
        score += self._speed(metrics.speed_mbps) * 15
        score += (0.65 if metrics.cf_detected else 0.25) * 15
        if metrics.colo_match:
            score += 0.25 * 15
        score += self._clamp(metrics.asn_quality) * 15
        score += self._freshness(metrics.age_days) * 10
        score -= min(metrics.failures * 0.8, 5)
        return round(max(0, min(100, score)), 2)

    @staticmethod
    def _clamp(value: float) -> float:
        return max(0.0, min(1.0, value))

    @staticmethod
    def _latency(value: Optional[float]) -> float:
        if value is None:
            return 0.3
        return max(0.0, min(1.0, exp(-value / 300)))

    @staticmethod
    def _speed(value: Optional[float]) -> float:
        if value is None:
            return 0.2
        return max(0.0, min(1.0, value / 200))

    @staticmethod
    def _freshness(days: float) -> float:
        return max(0.0, min(1.0, exp(-max(days, 0) / 30)))


def calculate_proxy_score(**kwargs) -> float:
    return ProxyScoreEngine().score(ProxyMetrics(**kwargs))
