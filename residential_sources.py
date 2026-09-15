"""Residential proxy candidate sources.

This module only collects candidates. Existing scanner validation remains the
source of truth before a candidate can enter any production pool.
"""

from __future__ import annotations

import re
import urllib.request
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class ProxyCandidate:
    host: str
    port: int = 443
    source: str = "unknown"

    def value(self) -> str:
        return f"{self.host}:{self.port}"


IP_PORT_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?")


def _parse_text(text: str, source: str) -> list[ProxyCandidate]:
    seen: set[str] = set()
    result: list[ProxyCandidate] = []
    for match in IP_PORT_RE.finditer(text or ""):
        host = match.group(1)
        port = int(match.group(2) or 443)
        key = f"{host}:{port}"
        if key in seen:
            continue
        seen.add(key)
        result.append(ProxyCandidate(host=host, port=port, source=source))
    return result


def fetch_text(url: str, timeout: int = 15) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "ProxyIP-Scanner/1.1"})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read(3 * 1024 * 1024).decode("utf-8", errors="replace")


def collect_freesub(url: str) -> list[ProxyCandidate]:
    return _parse_text(fetch_text(url), "freesub")


def collect_vpngate(url: str) -> list[ProxyCandidate]:
    return _parse_text(fetch_text(url), "vpngate")


def collect_public_proxy(urls: Iterable[str]) -> list[ProxyCandidate]:
    output: list[ProxyCandidate] = []
    for url in urls:
        try:
            output.extend(_parse_text(fetch_text(url), "public_proxy"))
        except Exception:
            continue
    return output
