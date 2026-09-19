import asyncio
import csv
import gc
import io
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request

from edt_runtime import check_edt_runtime
from geoip import enrich_result
from quality_score import apply_quality_score

router = APIRouter()

_DATA_DIR: Optional[Path] = None
_REQUIRE_WEB_SESSION = None
_REQUIRE_CSRF = None
_PROBE_CALLBACK: Optional[Callable[..., Awaitable[dict]]] = None
_EDT_CONFIG = None
_DEFAULT_SNI = ""
_DEFAULT_PATH = "/cdn-cgi/trace"
_BACKGROUND_TASK: Optional[asyncio.Task] = None
_STATE_LOCK = asyncio.Lock()
_CONFIGURED = False

REFRESH_INTERVAL = max(3600, int(os.environ.get("CANDIDATE_REFRESH_INTERVAL", str(6 * 3600))))
RECHECK_INTERVAL = max(6 * 3600, int(os.environ.get("CANDIDATE_RECHECK_INTERVAL", str(24 * 3600))))
AVAILABLE_RECHECK_INTERVAL = max(RECHECK_INTERVAL, int(os.environ.get("CANDIDATE_AVAILABLE_RECHECK_INTERVAL", str(7 * 24 * 3600))))
MAX_PER_REGION = int(os.environ.get("CANDIDATE_MAX_PER_REGION", "0"))
AUTO_RECHECK_LIMIT = max(100, min(5000, int(os.environ.get("CANDIDATE_AUTO_RECHECK_LIMIT", "500"))))
POOL_MAX_PER_REGION = max(1000, min(200000, int(os.environ.get("CANDIDATE_POOL_MAX_PER_REGION", "30000"))))
VERIFIED_MAX_PER_REGION = max(100, min(50000, int(os.environ.get("CANDIDATE_VERIFIED_MAX_PER_REGION", "5000"))))
FAILED_RETRY_BASE = max(6 * 3600, int(os.environ.get("CANDIDATE_FAILED_RETRY_BASE", str(24 * 3600))))
STALE_RETENTION = max(24 * 3600, int(os.environ.get("CANDIDATE_STALE_RETENTION", str(14 * 24 * 3600))))
# Quality lifecycle cleanup. Failed low-value candidates should not consume the
# long-running pool capacity forever, while verified candidates are protected.
MIN_KEEP_SCORE = max(0, min(100, int(os.environ.get("CANDIDATE_MIN_KEEP_SCORE", "20"))))
MIN_KEEP_CHECKS = max(1, int(os.environ.get("CANDIDATE_MIN_KEEP_CHECKS", "3")))
MAX_CONSECUTIVE_FAILURES = max(1, int(os.environ.get("CANDIDATE_MAX_CONSECUTIVE_FAILURES", "8")))
SCAN_BATCH_LIMIT = max(100, min(100000, int(os.environ.get("CANDIDATE_SCAN_BATCH_LIMIT", "30000"))))
ASN_DISCOVERY_ENABLED = str(os.environ.get("CANDIDATE_ASN_DISCOVERY", "1")).strip().lower() in {"1", "true", "yes", "on"}
ASN_DISCOVERY_MAX_ASNS = max(1, min(32, int(os.environ.get("CANDIDATE_ASN_MAX", "8"))))
ASN_DISCOVERY_PREFIXES_PER_ASN = max(1, min(128, int(os.environ.get("CANDIDATE_ASN_PREFIXES", "24"))))
ASN_DISCOVERY_MAX_CANDIDATES = max(100, min(10000, int(os.environ.get("CANDIDATE_ASN_MAX_CANDIDATES", "1500"))))
ASN_DISCOVERY_PORTS = tuple(
    int(value.strip()) for value in os.environ.get("CANDIDATE_ASN_PORTS", "443,2053,8443").split(",")
    if value.strip().isdigit() and 1 <= int(value.strip()) <= 65535
) or (443,)
REGIONS = ("HK", "JP", "SG", "KR", "IN", "US", "DE")
NIREVIL_MASTER_CSV = "https://raw.githubusercontent.com/NiREvil/vless/main/sub/country_proxies/02_proxies.csv"
XIAOBEI_RAW_COUNTRY = "https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/download/countries/{region}.txt"
XIAOBEI_VALID_COUNTRY = "https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/valid/countries/{region}/all.txt"
XIAOBEI_FAST_COUNTRY = "https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/valid/countries/{region}/ltd.txt"
VPNGATE_SOURCE = "https://www.vpngate.net/api/iphone/"
FREESUB_SOURCES = (
    "https://raw.githubusercontent.com/hezhanleiok/freesub/main/output/v2ray.txt",
    "https://raw.githubusercontent.com/hezhanleiok/freesub/main/output/clash.yaml",
    "https://raw.githubusercontent.com/hezhanleiok/freesub/main/output/singbox.json",
)
PUBLIC_PROXY_SOURCES = (
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
)
REGION_CATALOG_TTL = REFRESH_INTERVAL
ENABLE_XIAOBEI = str(os.environ.get("CANDIDATE_ENABLE_XIAOBEI", "1")).strip().lower() in {"1", "true", "yes", "on"}
ENABLE_LEILAOMI = str(os.environ.get("CANDIDATE_ENABLE_LEILAOMI", "0")).strip().lower() in {"1", "true", "yes", "on"}
DNS_SOURCE_ROUNDS = max(1, min(8, int(os.environ.get("CANDIDATE_DNS_SOURCE_ROUNDS", "3"))))
DNS_SOURCE_HISTORY_MISSES = max(1, min(100, int(os.environ.get("CANDIDATE_DNS_HISTORY_MISSES", "12"))))
DNS_SOURCE_HISTORY_LIMIT = max(20, min(10000, int(os.environ.get("CANDIDATE_DNS_HISTORY_LIMIT", "2000"))))
DNS_SOURCE_RESOLVERS = tuple(
    item.strip()
    for item in os.environ.get("CANDIDATE_DNS_RESOLVERS", "1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4,9.9.9.9,149.112.112.112,208.67.222.222,208.67.220.220,94.140.14.14,94.140.15.15,223.5.5.5,223.6.6.6,119.29.29.29").split(",")
    if item.strip()
)

CMLIU = {
    "HK": "ProxyIP.HK.CMLiussss.net",
    "JP": "ProxyIP.JP.CMLiussss.net",
    "SG": "ProxyIP.SG.CMLiussss.net",
    "KR": "ProxyIP.KR.CMLiussss.net",
    "IN": "ProxyIP.IN.CMLiussss.net",
    "US": "ProxyIP.US.CMLiussss.net",
    "DE": "ProxyIP.DE.CMLiussss.net",
    "ALL": "proxyip.cmliussss.net",
}

DYNAMIC_DOMAINS = [
    "proxyip.cmliussss.net",
    "pyip.ygkkk.dpdns.org",
    "proxy.farel.is-a.dev",
    "proxyip.leilaomi.cc.cd",
    "proxyip.oracle.fxxk.dedyn.io",
    "proxyip.digitalocean.hw.090227.xyz",
    "proxyip.vultr.fxxk.dedyn.io",
    "proxyip.aliyun.hw.090227.xyz",
    "edtproxyip.lzj.pp.ua",
    "cdn.xn--b6gac.eu.org",
    "cdn-all.xn--b6gac.eu.org",
    "di.nscl.ir",
    "tr.diam4.ggff.net",
    "bpb.yousef.isegaro.com",
]

REGION_WORDS = {
    "HK": ["hong kong", "hkg"],
    "JP": ["japan", "tokyo", "osaka", "chiba", "saitama", "kanagawa", "aichi", "fukuoka"],
    "SG": ["singapore", "sin"],
    "KR": ["south korea", "korea", "seoul", "incheon"],
    "IN": ["india", "mumbai", "delhi", "chennai", "bangalore", "bengaluru", "hyderabad"],
    "US": ["united states", "usa", "california", "virginia", "oregon", "ohio", "iowa", "new york", "texas", "washington", "illinois"],
    "DE": ["germany", "frankfurt", "berlin", "bavaria", "hesse"],
}

IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?")


def _now() -> float:
    return time.time()


def _path(name: str) -> Path:
    if _DATA_DIR is None:
        raise RuntimeError("candidate pool not configured")
    return _DATA_DIR / name


def _load_json(name: str, default: Any) -> Any:
    path = _path(name)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _save_json(name: str, value: Any) -> None:
    path = _path(name)
    tmp = path.with_suffix(path.suffix + ".tmp")
    # Stream JSON directly to disk. Building one giant json.dumps() string for
    # an unlimited candidate pool temporarily duplicates tens of MiB in memory.
    with tmp.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, separators=(",", ":"))
        handle.flush()
        os.fsync(handle.fileno())
    tmp.replace(path)


def _release_memory() -> None:
    """Collect dead Python objects and return free glibc arenas when possible."""
    gc.collect()
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6")
        malloc_trim = getattr(libc, "malloc_trim", None)
        if malloc_trim is not None:
            malloc_trim(0)
    except Exception:
        pass


def _valid_public_ipv4(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return ip.version == 4 and ip.is_global
    except ValueError:
        return False


def _normalize(ip: str, port: Any = 443) -> Optional[str]:
    if not _valid_public_ipv4(ip):
        return None
    try:
        p = int(port or 443)
    except Exception:
        return None
    if p < 1 or p > 65535:
        return None
    return f"{ip}:{p}"


def _dedupe(values: List[str]) -> List[str]:
    seen = set()
    out = []
    for value in values:
        key = str(value).strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(str(value).strip())
    return out


def _parse_loose(text: str) -> List[str]:
    out: List[str] = []
    for match in IP_RE.finditer(str(text or "")):
        value = _normalize(match.group(1), match.group(2) or 443)
        if value:
            out.append(value)
    return _dedupe(out)


def _parse_xiaobei_access_type(text: str, wanted: tuple[str, ...] = ("RES", "MOB")) -> List[str]:
    tokens = tuple(f"-{str(item).upper()}" for item in wanted)
    lines = []
    for line in str(text or "").splitlines():
        upper = line.upper()
        if any(token in upper for token in tokens):
            lines.append(line)
    return _parse_loose("\n".join(lines))


def _parse_daily(text: str, region: str) -> List[str]:
    out: List[str] = []
    words = REGION_WORDS.get(region, [])
    for line in str(text or "").splitlines():
        lower = line.lower()
        match = re.search(r"<pre><code>(\d{1,3}(?:\.\d{1,3}){3})</code></pre>", line, re.I)
        if not match:
            continue
        if words and not any(word in lower for word in words):
            continue
        value = _normalize(match.group(1), 443)
        if value:
            out.append(value)
    return _dedupe(out)


def _host_is_public(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_global
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except Exception:
        return False
    ips = {info[4][0] for info in infos if info and info[4]}
    if not ips:
        return False
    for value in ips:
        try:
            if not ipaddress.ip_address(value).is_global:
                return False
        except ValueError:
            return False
    return True


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("重定向目标无效")
        if not _host_is_public(parsed.hostname):
            raise ValueError("重定向到非公网地址已阻止")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _fetch_text_sync(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("只支持公网 HTTP/HTTPS URL")
    if not _host_is_public(parsed.hostname):
        raise ValueError("URL 目标不是公网地址")
    request = urllib.request.Request(url, headers={"User-Agent": "ProxyIP-Scanner/1.1"})
    context = ssl.create_default_context()
    opener = urllib.request.build_opener(_SafeRedirectHandler(), urllib.request.HTTPSHandler(context=context))
    with opener.open(request, timeout=12) as response:
        final = urllib.parse.urlsplit(response.geturl())
        if not final.hostname or not _host_is_public(final.hostname):
            raise ValueError("最终 URL 不是公网地址")
        raw = response.read(3 * 1024 * 1024 + 1)
        if len(raw) > 3 * 1024 * 1024:
            raise ValueError("候选源响应超过 3 MiB")
        return raw.decode("utf-8", errors="replace")


async def _fetch_text(url: str) -> str:
    return await asyncio.to_thread(_fetch_text_sync, url)


def _clean_dns_host(host: str) -> str:
    host = str(host or "").strip().rstrip(".").lower()
    if not host or len(host) > 253 or "/" in host or ":" in host:
        raise ValueError("DNS 源必须填写纯域名")
    labels = host.split(".")
    if len(labels) < 2 or any(not label or len(label) > 63 for label in labels):
        raise ValueError("DNS 域名格式无效")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
        raise ValueError("DNS 域名格式无效")
    return host


def _resolve_dns_sync(host: str) -> List[str]:
    host = _clean_dns_host(host)
    try:
        infos = socket.getaddrinfo(host, 443, family=socket.AF_INET, type=socket.SOCK_STREAM)
    except Exception:
        return []
    values = []
    for info in infos:
        ip = info[4][0]
        value = _normalize(ip, 443)
        if value:
            values.append(value)
    return _dedupe(values)


def _dns_encode_name(host: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in host.split(".")) + b"\x00"


def _dns_skip_name(data: bytes, offset: int) -> int:
    seen = 0
    while offset < len(data):
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("DNS 响应截断")
            return offset + 2
        offset += 1
        if length == 0:
            return offset
        if length > 63 or offset + length > len(data):
            raise ValueError("DNS 响应名称无效")
        offset += length
        seen += 1
        if seen > 128:
            raise ValueError("DNS 响应名称过长")
    raise ValueError("DNS 响应截断")


def _query_dns_records_sync(host: str, resolver: str, qtype: int) -> List[str]:
    host = _clean_dns_host(host)
    if not _valid_public_ipv4(resolver) or qtype not in {1, 16}:
        return []
    txid = int.from_bytes(os.urandom(2), "big")
    packet = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + _dns_encode_name(host) + struct.pack("!HH", qtype, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(2.2)
        sock.sendto(packet, (resolver, 53))
        data, _ = sock.recvfrom(8192)
    finally:
        sock.close()
    if len(data) < 12:
        return []
    rid, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
    if rid != txid or (flags & 0x000F) != 0:
        return []
    offset = 12
    for _ in range(qdcount):
        offset = _dns_skip_name(data, offset)
        if offset + 4 > len(data):
            return []
        offset += 4
    values: List[str] = []
    txt_chunks: List[str] = []
    for _ in range(ancount):
        try:
            offset = _dns_skip_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, rclass, _, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
            offset += 10
            if offset + rdlength > len(data):
                break
            rdata = data[offset:offset + rdlength]
            offset += rdlength
            if rclass != 1:
                continue
            if qtype == 1 and rtype == 1 and rdlength == 4:
                value = _normalize(socket.inet_ntoa(rdata), 443)
                if value:
                    values.append(value)
            elif qtype == 16 and rtype == 16 and rdlength > 0:
                pos = 0
                pieces: List[bytes] = []
                while pos < len(rdata):
                    size = rdata[pos]
                    pos += 1
                    if pos + size > len(rdata):
                        pieces = []
                        break
                    pieces.append(rdata[pos:pos + size])
                    pos += size
                if pieces:
                    txt_chunks.append(b"".join(pieces).decode("utf-8", errors="replace"))
        except Exception:
            break
    if qtype == 16:
        return _parse_loose("\n".join(txt_chunks))
    return _dedupe(values)


def _query_dns_resolver_sync(host: str, resolver: str) -> List[str]:
    return _query_dns_records_sync(host, resolver, 1)


def _query_dns_txt_resolver_sync(host: str, resolver: str) -> List[str]:
    return _query_dns_records_sync(host, resolver, 16)


async def _resolve_dns(host: str) -> List[str]:
    return await asyncio.to_thread(_resolve_dns_sync, host)


async def _resolve_dns_multi(host: str) -> List[str]:
    host = _clean_dns_host(host)
    found: List[str] = []
    for round_index in range(DNS_SOURCE_ROUNDS):
        jobs = [asyncio.to_thread(_resolve_dns_sync, host)]
        jobs.extend(asyncio.to_thread(_query_dns_resolver_sync, host, resolver) for resolver in DNS_SOURCE_RESOLVERS)
        jobs.extend(asyncio.to_thread(_query_dns_txt_resolver_sync, host, resolver) for resolver in DNS_SOURCE_RESOLVERS)
        rows = await asyncio.gather(*jobs, return_exceptions=True)
        for row in rows:
            if isinstance(row, list):
                found.extend(row)
        if round_index + 1 < DNS_SOURCE_ROUNDS:
            await asyncio.sleep(0.2)
    items = _dedupe(found)
    if not items:
        raise ValueError("DNS A/TXT 记录解析失败")
    return items


async def _resolve_domains(domains: List[str]) -> List[str]:
    rows = await asyncio.gather(*(_resolve_dns(host) for host in domains), return_exceptions=True)
    out: List[str] = []
    for row in rows:
        if isinstance(row, list):
            out.extend(row)
    return _dedupe(out)



async def _refresh_region_catalog() -> dict:
    text = await _fetch_text(NIREVIL_MASTER_CSV)
    grouped: Dict[str, List[str]] = {}
    reader = csv.DictReader(io.StringIO(text))
    for raw in reader:
        row = {str(k or "").strip(): str(v or "").strip() for k, v in raw.items()}
        code = row.get("Data Center", "").upper()
        if not re.fullmatch(r"[A-Z]{2}", code):
            continue
        target = _normalize(row.get("IP Address", ""), row.get("Port", "443"))
        if not target:
            continue
        grouped.setdefault(code, []).append(target)
    regions = {}
    for code, values in grouped.items():
        items = _dedupe(values)
        if items:
            regions[code] = {"count": len(items), "candidates": items}
    data = {"updated_at": _now(), "regions": regions}
    _save_json("candidate_region_catalog.json", data)
    return data


async def _region_catalog(force: bool = False) -> dict:
    cached = _load_json("candidate_region_catalog.json", {"updated_at": None, "regions": {}})
    if not isinstance(cached, dict):
        cached = {"updated_at": None, "regions": {}}
    cached.setdefault("regions", {})
    age = _now() - float(cached.get("updated_at") or 0)
    if not force and cached["regions"] and age < REGION_CATALOG_TTL:
        return cached
    try:
        return await _refresh_region_catalog()
    except Exception:
        if cached["regions"]:
            return cached
        raise


def _catalog_pool(region: str, catalog: dict) -> dict:
    row = (catalog.get("regions") or {}).get(region) or {"count": 0, "candidates": []}
    candidates = [
        {"target": target, "sources": [f"NiREvil {region}"], "region_hints": [region]}
        for target in row.get("candidates", [])
    ]
    return {
        "count": len(candidates),
        "candidates": candidates,
        "source_stats": [{"name": f"NiREvil {region}", "count": len(candidates), "contributed": len(candidates), "ms": 0, "status": "ok"}],
        "updated_at": catalog.get("updated_at"),
    }

def _custom_sources() -> List[dict]:
    rows = _load_json("candidate_sources.json", [])
    return rows if isinstance(rows, list) else []


def _save_custom_sources(rows: List[dict]) -> None:
    _save_json("candidate_sources.json", rows)


def _merge_dns_history(row: dict, current_items: List[str]) -> List[str]:
    now = _now()
    raw_history = row.get("dns_history")
    history = raw_history if isinstance(raw_history, dict) else {}
    current = _dedupe(current_items)
    current_set = {item.lower() for item in current}
    kept: Dict[str, dict] = {}
    for target, meta in history.items():
        target = str(target or "").strip()
        if not target or target.lower() in current_set:
            continue
        meta = meta if isinstance(meta, dict) else {}
        misses = int(meta.get("misses") or 0) + 1
        if misses >= DNS_SOURCE_HISTORY_MISSES:
            continue
        kept[target] = {
            "last_seen_at": float(meta.get("last_seen_at") or 0),
            "misses": misses,
        }
    for target in current:
        kept[target] = {"last_seen_at": now, "misses": 0}
    historical = [target for target in kept if target.lower() not in current_set]
    historical.sort(key=lambda target: float(kept[target].get("last_seen_at") or 0), reverse=True)
    ordered = (current + historical)[:DNS_SOURCE_HISTORY_LIMIT]
    row["dns_history"] = {target: kept[target] for target in ordered}
    row["last_current_count"] = len(current)
    row["history_count"] = len(ordered)
    return ordered


def _public_source(row: dict) -> dict:
    public = {key: value for key, value in row.items() if key != "dns_history"}
    if str(row.get("type") or "") == "dns":
        history = row.get("dns_history")
        public["history_count"] = len(history) if isinstance(history, dict) else int(row.get("history_count") or 0)
    return public


def _pool_data() -> dict:
    """Legacy monolithic pool loader, retained only for one-time migration."""
    data = _load_json("candidate_pool.json", {"regions": {}, "updated_at": None})
    if not isinstance(data, dict):
        data = {"regions": {}, "updated_at": None}
    data.setdefault("regions", {})
    return data


def _region_pool_name(region: str) -> str:
    return f"candidate_pool_{str(region).upper()}.json"


def _pool_meta() -> dict:
    value = _load_json("candidate_pool_meta.json", {})
    return value if isinstance(value, dict) else {}


def _record_region_meta(region: str, data: dict) -> None:
    meta = _pool_meta()
    rows = meta.get("region_counts")
    if not isinstance(rows, dict):
        rows = {}
    rows[str(region).upper()] = {
        "count": int(data.get("count") or 0),
        "updated_at": data.get("updated_at"),
    }
    meta["region_counts"] = rows
    timestamps = [
        float(row.get("updated_at") or 0)
        for row in rows.values()
        if isinstance(row, dict) and row.get("updated_at")
    ]
    meta["pool_updated_at"] = max(timestamps) if timestamps else meta.get("pool_updated_at")
    meta["split_pool_v1"] = True
    _save_json("candidate_pool_meta.json", meta)


def _load_region_pool(region: str, catalog: Optional[dict] = None) -> dict:
    region = str(region or "").upper()
    value = _load_json(_region_pool_name(region), None)
    if isinstance(value, dict):
        value.setdefault("candidates", [])
        value.setdefault("source_stats", [])
        value.setdefault("count", len(value.get("candidates") or []))
        return value

    # During the first run after upgrading, lazily fall back to the old file.
    # Startup migration normally creates all split files before requests arrive.
    meta = _pool_meta()
    if not meta.get("split_pool_v1") and _path("candidate_pool.json").exists():
        legacy = _pool_data()
        row = (legacy.get("regions") or {}).get(region)
        if isinstance(row, dict):
            _save_json(_region_pool_name(region), row)
            _record_region_meta(region, row)
            del legacy
            _release_memory()
            return row
        del legacy
        _release_memory()

    if catalog is not None:
        return _catalog_pool(region, catalog)
    return {"updated_at": None, "count": 0, "candidates": [], "source_stats": []}


def _migrate_legacy_pool() -> None:
    """Split the old all-regions JSON once so normal reads stay region-bounded."""
    meta = _pool_meta()
    if meta.get("split_pool_v1"):
        return
    legacy_path = _path("candidate_pool.json")
    if not legacy_path.exists():
        meta["split_pool_v1"] = True
        _save_json("candidate_pool_meta.json", meta)
        return
    legacy = _pool_data()
    regions = legacy.get("regions") or {}
    for region, row in regions.items():
        if not isinstance(row, dict):
            continue
        _save_json(_region_pool_name(str(region).upper()), row)
        counts = meta.get("region_counts")
        if not isinstance(counts, dict):
            counts = {}
        counts[str(region).upper()] = {
            "count": int(row.get("count") or len(row.get("candidates") or [])),
            "updated_at": row.get("updated_at"),
        }
        meta["region_counts"] = counts
    meta["pool_updated_at"] = legacy.get("updated_at")
    meta["split_pool_v1"] = True
    _save_json("candidate_pool_meta.json", meta)
    del legacy
    _release_memory()


def _verified_data() -> dict:
    data = _load_json("candidate_verified.json", {"regions": {}, "updated_at": None})
    if not isinstance(data, dict):
        data = {"regions": {}, "updated_at": None}
    data.setdefault("regions", {})
    if not data.get("regions"):
        data = _migrate_legacy_verified_pool(data)
    return data


def _migrate_legacy_verified_pool(data: dict) -> dict:
    """Migrate legacy final_available rows into the v1.2 verified lifecycle store once."""
    migrated = False
    regions = data.setdefault("regions", {})
    meta = _pool_meta()
    for region in list((meta.get("region_counts") or {}).keys()):
        pool = _load_region_pool(str(region).upper())
        if not isinstance(pool, dict):
            continue
        rows = []
        for row in list(pool.get("candidates") or []):
            if not isinstance(row, dict) or row.get("final_available") is not True:
                continue
            item = dict(row)
            item.setdefault("quality_score", row.get("quality_score", 0))
            rows.append(item)
        if rows:
            code = str(region).upper()
            regions[code] = {
                "final_available": len(rows),
                "updated_at": _now(),
                "results": rows,
            }
            migrated = True
        del pool
    if migrated:
        data["updated_at"] = _now()
        _save_json("candidate_verified.json", data)
    return data


def _source_quality_data() -> dict:
    data = _load_json("source_quality.json", {"updated_at": None, "sources": {}})
    if not isinstance(data, dict):
        data = {"updated_at": None, "sources": {}}
    data.setdefault("sources", {})
    return data


def _asn_quality_data() -> dict:
    data = _load_json("asn_quality.json", {"updated_at": None, "asns": {}})
    if not isinstance(data, dict):
        data = {"updated_at": None, "asns": {}}
    data.setdefault("asns", {})
    return data


def _row_asn(row: dict) -> str:
    value = row.get("entry_asn") or row.get("asn")
    if not value and isinstance(row.get("entry_geo"), dict):
        value = row["entry_geo"].get("asn")
    digits = re.sub(r"\D", "", str(value or ""))
    return digits if digits and 1 <= int(digits) <= 4294967295 else ""


def _source_quality_sort_key(row: dict, quality: Optional[dict] = None) -> tuple:
    item = (quality or {}).get(str(row.get("name") or ""), {})
    return (
        float(item.get("success_rate") or 0),
        float(item.get("avg_score") or 0),
        int(item.get("verified") or 0),
        int(item.get("contributed") or 0),
    )


def _asn_quality_sort_key(asn: str, quality: Optional[dict] = None) -> tuple:
    item = (quality or {}).get(str(asn), {})
    return (
        float(item.get("success_rate") or 0),
        float(item.get("avg_score") or 0),
        int(item.get("sample_count") or 0),
    )


def _record_source_feedback(source_quality: dict, name: str, final_ok: bool, score: int) -> None:
    item = source_quality.setdefault("sources", {}).setdefault(name, {
        "name": name, "contributed": 0, "verified": 0, "success_rate": 0.0, "avg_score": 0.0,
    })
    previous = int(item.get("contributed") or 0)
    item["contributed"] = previous + 1
    item["verified"] = int(item.get("verified") or 0) + int(final_ok)
    item["avg_score"] = round(((float(item.get("avg_score") or 0) * previous) + score) / item["contributed"], 2)
    item["success_rate"] = round(item["verified"] / item["contributed"], 4)


def _record_asn_feedback(asn_quality: dict, asn: str, final_ok: bool, score: int) -> None:
    item = asn_quality.setdefault("asns", {}).setdefault(asn, {
        "asn": asn, "prefix_count": 0, "sample_count": 0, "success_rate": 0.0, "avg_score": 0.0,
    })
    previous = int(item.get("sample_count") or 0)
    item["sample_count"] = previous + 1
    item["avg_score"] = round(((float(item.get("avg_score") or 0) * previous) + score) / item["sample_count"], 2)
    item["success_rate"] = round((float(item.get("success_rate") or 0) * previous + int(final_ok)) / item["sample_count"], 4)


def _candidate_due(row: dict, ts: Optional[float] = None) -> bool:
    ts = float(ts or _now())
    checked_at = float(row.get("last_checked_at") or 0)
    if checked_at <= 0:
        return True
    if row.get("final_available") is True:
        return ts - checked_at >= AVAILABLE_RECHECK_INTERVAL
    failures = max(0, int(row.get("consecutive_failures") or 0))
    retry_after = min(7 * 24 * 3600, FAILED_RETRY_BASE * (2 ** min(max(failures - 1, 0), 4)))
    return ts - checked_at >= retry_after


def _candidate_keep_key(row: dict) -> tuple:
    return (
        1 if row.get("final_available") is True else 0,
        int(row.get("quality_score") or 0),
        int(row.get("source_weight") or 0),
        int(row.get("success_count") or 0),
        float(row.get("last_success_at") or 0),
        float(row.get("last_seen_at") or 0),
        len(row.get("sources") or []),
    )


def _prune_pool_rows(rows: List[dict]) -> List[dict]:
    now_ts = _now()
    retained: List[dict] = []
    for row in rows:
        if not isinstance(row, dict) or not row.get("target"):
            continue

        apply_quality_score(row)
        score = int(row.get("quality_score") or 0)
        failures = int(row.get("consecutive_failures") or 0)
        checks = int(row.get("check_count") or 0)

        # Keep known-good endpoints even if their upstream source temporarily disappears.
        if row.get("final_available") is not True and now_ts - float(row.get("last_seen_at") or now_ts) > STALE_RETENTION:
            continue

        # Remove candidates that have enough evidence to be classified as bad.
        # New candidates are allowed to receive initial probes before cleanup.
        if row.get("final_available") is not True:
            if checks >= MIN_KEEP_CHECKS and score < MIN_KEEP_SCORE:
                continue
            if failures >= MAX_CONSECUTIVE_FAILURES:
                continue

        retained.append(row)

    retained.sort(key=_candidate_keep_key, reverse=True)
    return retained[:POOL_MAX_PER_REGION]


def _public_candidate(row: dict, include_quality: bool = False) -> dict:
    # Candidate preview hides lifecycle internals. Verified pool exposes quality fields
    # because it is the maintained production output pool.
    hidden = {
        "quality_score", "first_seen_at", "last_seen_at", "last_checked_at", "last_success_at",
        "last_failure_at", "check_count", "success_count", "failure_count", "consecutive_failures",
        "avg_mbps", "purity_score", "risk_score", "is_residential", "is_idc",
    }
    if include_quality:
        hidden -= {"quality_score", "avg_mbps", "purity_score", "risk_score"}
    return {key: value for key, value in row.items() if key not in hidden}


def _verified_pool_payload(data: Optional[dict] = None) -> dict:
    data = data or _verified_data()
    results = []
    for region, item in sorted((data.get("regions") or {}).items()):
        if not isinstance(item, dict):
            continue
        for row in item.get("results") or []:
            if not isinstance(row, dict):
                continue
            purity = row.get("purity")
            if isinstance(purity, dict):
                network_type = str(purity.get("network_type") or "")
                if purity.get("is_idc") is True or network_type in {"IDC", "机房IP"}:
                    purity = "IDC"
                elif purity.get("is_residential") is True or network_type in {"Residential", "家宽IP", "家宽/运营商IP"}:
                    purity = "Residential"
                else:
                    purity = network_type or "-"
            elif not purity:
                purity = "IDC" if row.get("is_idc") is True else ("Residential" if row.get("is_residential") is True else "-")
            results.append({
                "target": row.get("target") or row.get("candidate") or "",
                "region": region,
                "quality_score": int(row.get("quality_score") or 0),
                "avg_mbps": row.get("avg_mbps"),
                "tcp_ms": row.get("tcp_ms"),
                "tls_ms": row.get("tls_ms"),
                "purity": purity,
                "success_count": int(row.get("success_count") or 0),
                "failure_count": int(row.get("failure_count") or 0),
                "check_count": int(row.get("check_count") or 0),
                "last_verified_at": row.get("last_verified_at") or item.get("updated_at") or data.get("updated_at"),
            })
    return {"updated_at": data.get("updated_at"), "total": len(results), "results": results}


async def _run_source(name: str, region_hint: Optional[str], loader: Callable[[], Awaitable[List[str]]]) -> dict:
    started = _now()
    try:
        items = _dedupe(await loader())
        # Internal source trust weight. It only affects backend ordering and
        # never changes public API output.
        source_weight = 50
        lowered = str(name).lower()
        if "高速" in name or "已验证" in name or "residential" in lowered:
            source_weight += 25
        if "asn" in lowered:
            source_weight += 10
        if "公共" in name or "freesub" in lowered or "vpngate" in lowered:
            source_weight -= 10
        return {"name": name, "region_hint": region_hint, "items": items, "count": len(items), "source_weight": source_weight, "status": "ok", "ms": round((_now() - started) * 1000, 1)}
    except Exception as exc:
        return {"name": name, "region_hint": region_hint, "items": [], "count": 0, "source_weight": 0, "status": str(exc)[:180], "ms": round((_now() - started) * 1000, 1)}


async def _load_custom_source(row: dict) -> List[str]:
    source_type = str(row.get("type") or "url")
    value = str(row.get("value") or "").strip()
    if source_type == "dns":
        current = await _resolve_dns_multi(value)
        return _merge_dns_history(row, current)
    return _parse_loose(await _fetch_text(value))


async def _region_sources(region: str) -> List[dict]:
    work = []
    if ENABLE_XIAOBEI:
        # Keep the higher-value subsets first so the per-region cap favors
        # fast and residential/mobile candidates before the wider raw pool.
        work.extend([
            _run_source(f"Xiaobei 高速优选 {region}", region, lambda region=region: _fetch_xiaobei_fast(region)),
            _run_source(f"Xiaobei 家宽/移动 {region}", region, lambda region=region: _fetch_xiaobei_residential(region)),
            _run_source(f"Xiaobei 已验证 {region}", region, lambda region=region: _fetch_xiaobei_valid(region)),
            _run_source(f"Xiaobei 原始候选 {region}", region, lambda region=region: _fetch_xiaobei_raw(region)),
        ])
    work.append(_run_source(f"NiREvil {region}", region, lambda region=region: _fetch_country(region)))
    work.append(_run_source("VPNGate", None, _fetch_vpngate))
    work.append(_run_source("freesub", None, _fetch_freesub))
    work.append(_run_source("公共 SOCKS5/HTTP proxy", None, _fetch_public_proxies))
    if region in REGIONS:
        if region in REGION_WORDS:
            work.append(_run_source(f"NiREvil Daily {region}", region, lambda region=region: _fetch_daily(region)))
        if region in CMLIU and region != "ALL":
            work.append(_run_source(f"CMliu {region}", region, lambda region=region: _resolve_dns(CMLIU[region])))
        work.append(_run_source("EDT 动态域名组（全球补充）", None, lambda: _resolve_domains(DYNAMIC_DOMAINS)))
    if region == "US" and ENABLE_LEILAOMI:
        work.append(_run_source("LeilaoMi all/best", "US", _fetch_leilaomi))
    if ASN_DISCOVERY_ENABLED:
        work.append(_run_source("ASN 后台发现", region, lambda region=region: _discover_asn_candidates(region)))

    custom_rows = _custom_sources()
    custom_indexes = []
    for index, row in enumerate(custom_rows):
        if row.get("enabled") is False:
            continue
        source_region = str(row.get("region") or "ALL").upper()
        if source_region not in {"ALL", region}:
            continue
        custom_indexes.append(index)
        work.append(_run_source(f"我的源 · {row.get('name') or '未命名'}", None if source_region == "ALL" else source_region, lambda row=row: _load_custom_source(row)))

    results = await asyncio.gather(*work)

    # Update health information for custom sources in the same order they were appended.
    custom_start = len(results) - len(custom_indexes)
    changed = False
    for offset, index in enumerate(custom_indexes):
        result = results[custom_start + offset]
        row = custom_rows[index]
        row["last_checked_at"] = _now()
        row["last_count"] = result.get("count", 0)
        if result.get("status") == "ok":
            row["last_status"] = "ok"
            row["failures"] = 0
        else:
            row["last_status"] = result.get("status")
            row["failures"] = int(row.get("failures") or 0) + 1
            if row["failures"] >= 3:
                row["enabled"] = False
        changed = True
    if changed:
        _save_custom_sources(custom_rows)
    quality = _source_quality_data().get("sources") or {}
    results.sort(key=lambda row: _source_quality_sort_key(row, quality), reverse=True)
    return results


async def _fetch_xiaobei_raw(region: str) -> List[str]:
    text = await _fetch_text(XIAOBEI_RAW_COUNTRY.format(region=region))
    return _parse_loose(text)


async def _fetch_xiaobei_valid(region: str) -> List[str]:
    text = await _fetch_text(XIAOBEI_VALID_COUNTRY.format(region=region))
    return _parse_loose(text)


async def _fetch_xiaobei_fast(region: str) -> List[str]:
    text = await _fetch_text(XIAOBEI_FAST_COUNTRY.format(region=region))
    return _parse_loose(text)


async def _fetch_xiaobei_residential(region: str) -> List[str]:
    text = await _fetch_text(XIAOBEI_VALID_COUNTRY.format(region=region))
    return _parse_xiaobei_access_type(text, ("RES", "MOB"))


async def _fetch_country(region: str) -> List[str]:
    text = await _fetch_text(f"https://raw.githubusercontent.com/NiREvil/vless/main/sub/country_proxies/{region}.txt")
    return _parse_loose(text)


async def _fetch_daily(region: str) -> List[str]:
    text = await _fetch_text("https://raw.githubusercontent.com/NiREvil/vless/main/sub/ProxyIP-Daily.md")
    return _parse_daily(text, region)


async def _fetch_vpngate() -> List[str]:
    text = await _fetch_text(VPNGATE_SOURCE)
    return _parse_loose(text)


async def _fetch_freesub() -> List[str]:
    rows = await asyncio.gather(*(_fetch_text(url) for url in FREESUB_SOURCES), return_exceptions=True)
    values = []
    for row in rows:
        if not isinstance(row, Exception):
            values.extend(_parse_loose(row))
    if not values:
        raise RuntimeError("freesub 无有效代理地址")
    return _dedupe(values)


async def _fetch_public_proxies() -> List[str]:
    rows = await asyncio.gather(*(_fetch_text(url) for url in PUBLIC_PROXY_SOURCES), return_exceptions=True)
    values = []
    for row in rows:
        if not isinstance(row, Exception):
            values.extend(_parse_loose(row))
    return _dedupe(values)


async def _fetch_leilaomi() -> List[str]:
    sources = [
        ("all", "https://list.leilaomi.cc.cd/all.txt"),
        ("best", "https://list.leilaomi.cc.cd/best.txt"),
    ]
    rows = await asyncio.gather(*(_fetch_text(url) for _, url in sources), return_exceptions=True)
    texts: List[str] = []
    errors: List[str] = []
    for (name, _), row in zip(sources, rows):
        if isinstance(row, Exception):
            errors.append(f"{name}: {row}")
        else:
            texts.append(row)
    if not texts:
        detail = "; ".join(errors) or "unknown error"
        raise RuntimeError(f"LeilaoMi 来源不可用：{detail}"[:180])
    return _parse_loose("\n".join(texts))


async def _fetch_ripe_asn_prefixes(asn: Any) -> List[str]:
    digits = re.sub(r"\D", "", str(asn or ""))
    if not digits or not (1 <= int(digits) <= 4294967295):
        return []
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{digits}&sourceapp=proxyip-scanner"
    data = json.loads(await _fetch_text(url))
    prefixes: List[str] = []
    for item in ((data.get("data") or {}).get("prefixes") or []):
        value = str((item or {}).get("prefix") or "").strip()
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if network.version == 4 and network.is_global:
            prefixes.append(str(network))
    return _dedupe(prefixes)[:ASN_DISCOVERY_PREFIXES_PER_ASN]


def _sample_prefix_targets(prefixes: List[str], budget: int) -> List[str]:
    out: List[str] = []
    for prefix in prefixes:
        if len(out) >= budget:
            break
        try:
            network = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            continue
        if network.version != 4 or not network.is_global or network.num_addresses <= 2:
            continue
        usable = network.num_addresses - 2
        # Bounded deterministic sampling keeps ASN discovery useful without attempting a full ASN sweep.
        samples = min(16, usable)
        for index in range(samples):
            offset = 1 + ((index + 1) * usable // (samples + 1))
            ip = str(network.network_address + offset)
            for port in ASN_DISCOVERY_PORTS:
                value = _normalize(ip, port)
                if value:
                    out.append(value)
                    if len(out) >= budget:
                        return _dedupe(out)
    return _dedupe(out)


async def _discover_asn_candidates(region: str) -> List[str]:
    if not ASN_DISCOVERY_ENABLED:
        return []
    verified = _verified_data().get("regions", {}).get(region) or {}
    results = list(verified.get("results") or [])
    results.sort(key=lambda row: int(row.get("quality_score") or 0), reverse=True)
    asns: List[str] = []
    for row in results:
        asn = row.get("entry_asn") or ((row.get("entry_geo") or {}).get("asn") if isinstance(row.get("entry_geo"), dict) else None)
        digits = re.sub(r"\D", "", str(asn or ""))
        if digits and digits not in asns:
            asns.append(digits)
        if len(asns) >= ASN_DISCOVERY_MAX_ASNS:
            break
    if not asns:
        return []
    asn_quality = _asn_quality_data().get("asns") or {}
    asns.sort(key=lambda value: _asn_quality_sort_key(value, asn_quality), reverse=True)
    prefix_rows = await asyncio.gather(*(_fetch_ripe_asn_prefixes(asn) for asn in asns), return_exceptions=True)
    prefixes: List[str] = []
    quality_data = _asn_quality_data()
    for asn, row in zip(asns, prefix_rows):
        if not isinstance(row, Exception):
            prefixes.extend(row)
            quality_data.setdefault("asns", {}).setdefault(asn, {
                "asn": asn, "prefix_count": 0, "sample_count": 0, "success_rate": 0.0, "avg_score": 0.0,
            })["prefix_count"] = len(row)
    quality_data["updated_at"] = _now()
    _save_json("asn_quality.json", quality_data)
    return _sample_prefix_targets(_dedupe(prefixes), ASN_DISCOVERY_MAX_CANDIDATES)


async def get_pool_targets(region: str = "HK") -> List[str]:
    """Return the current candidate pool as endpoint strings without sending it through the browser."""
    region = str(region or "HK").upper()
    catalog = await _region_catalog()
    targets: List[str] = []
    if region == "ALL":
        for region_row in (catalog.get("regions") or {}).values():
            targets.extend(str(value).strip() for value in region_row.get("candidates", []) if str(value).strip())
        for code in (catalog.get("regions") or {}):
            region_data = _load_region_pool(code, catalog)
            targets.extend(
                str(row.get("target") or "").strip()
                for row in region_data.get("candidates", [])
                if str(row.get("target") or "").strip()
            )
            del region_data
        result = _dedupe(targets)
        del targets
        _release_memory()
        return result
    if not re.fullmatch(r"[A-Z]{2}", region) or region not in (catalog.get("regions") or {}):
        raise ValueError("unsupported region")
    data = _load_region_pool(region, catalog)
    result = _dedupe([
        str(row.get("target") or "").strip()
        for row in data.get("candidates", [])
        if str(row.get("target") or "").strip()
    ])
    del data
    _release_memory()
    return result


async def get_scan_targets(region: str = "HK", limit: Optional[int] = None, force: bool = False) -> List[str]:
    """Return only new/due candidates, prioritising never-scanned endpoints."""
    region = str(region or "HK").upper()
    cap = None if force else max(1, min(int(limit or SCAN_BATCH_LIMIT), SCAN_BATCH_LIMIT))
    ts = _now()
    selected: List[tuple] = []

    def collect(rows: List[dict]) -> None:
        for row in rows:
            target = str(row.get("target") or "").strip()
            if not target or not (force or _candidate_due(row, ts)):
                continue
            selected.append((
                0 if not row.get("last_checked_at") else 1,
                -int(row.get("quality_score") or 0),
                -int(row.get("source_weight") or 0),
                float(row.get("last_checked_at") or 0),
                -len(row.get("sources") or []),
                target,
            ))
        if cap is not None and len(selected) > cap * 2:
            selected.sort()
            del selected[cap:]

    if region == "ALL":
        meta = _pool_meta()
        codes = list((meta.get("region_counts") or {}).keys()) or list(REGIONS)
        for code in codes:
            if not _path(_region_pool_name(code)).exists():
                continue
            data = _load_region_pool(code)
            collect(list(data.get("candidates") or []))
            del data
            _release_memory()
    else:
        if not re.fullmatch(r"[A-Z]{2}", region):
            raise ValueError("unsupported region")
        if _path(_region_pool_name(region)).exists():
            data = _load_region_pool(region)
        else:
            data = await refresh_region(region)
        collect(list(data.get("candidates") or []))
        del data
        _release_memory()

    selected.sort()
    result = _dedupe([item[5] for item in selected])
    return result if cap is None else result[:cap]


async def _build_region_data(region: str, catalog: dict) -> dict:
    source_rows = await _region_sources(region)
    merged: Dict[str, dict] = {}
    seen = set()
    stats = []
    for source in source_rows:
        contributed = 0
        for target in source.get("items", []):
            key = target.lower()
            if key not in merged:
                merged[key] = {"target": target, "source": source.get("name"), "sources": [], "region_hints": []}
            meta = merged[key]
            if source["name"] not in meta["sources"]:
                meta["sources"].append(source["name"])
            if not meta.get("source"):
                meta["source"] = source.get("name")
            hint = source.get("region_hint")
            if hint and hint not in meta["region_hints"]:
                meta["region_hints"].append(hint)
            if key not in seen:
                seen.add(key)
                contributed += 1
        stats.append({k: source.get(k) for k in ("name", "count", "status", "ms", "source_weight")} | {"contributed": contributed})
        source["items"] = []

    ts = _now()
    previous_data = _load_region_pool(region)
    previous_rows = list(previous_data.get("candidates") or [])
    previous = {str(row.get("target") or "").lower(): row for row in previous_rows if row.get("target")}
    state_fields = (
        "first_seen_at", "last_checked_at", "last_success_at", "last_failure_at",
        "check_count", "success_count", "failure_count", "consecutive_failures",
        "available", "final_available", "tcp_ms", "tls_ms", "quality_score",
        "avg_mbps", "purity_score", "risk_score", "is_residential", "is_idc",
    )
    candidates: List[dict] = []
    for key, row in merged.items():
        old = previous.get(key)
        if old:
            for field in state_fields:
                if field in old:
                    row[field] = old[field]
            row["first_seen_at"] = float(old.get("first_seen_at") or ts)
        else:
            row["first_seen_at"] = ts
        row["last_seen_at"] = ts
        candidates.append(row)

    for key, old in previous.items():
        if key in merged:
            continue
        if old.get("final_available") is True or ts - float(old.get("last_seen_at") or ts) <= STALE_RETENTION:
            candidates.append(old)

    candidates = _prune_pool_rows(candidates)
    if MAX_PER_REGION > 0:
        candidates = candidates[:MAX_PER_REGION]
    data = {"updated_at": ts, "count": len(candidates), "candidates": candidates, "source_stats": stats}
    del source_rows, merged, seen, previous_data, previous_rows, previous
    _release_memory()
    return data


async def refresh_region(region: str) -> dict:
    region = str(region or "HK").upper()
    if not re.fullmatch(r"[A-Z]{2}", region):
        raise ValueError("unsupported region")
    catalog = await _region_catalog()
    if region not in (catalog.get("regions") or {}):
        raise ValueError("该地区当前没有候选 IP")
    async with _STATE_LOCK:
        data = await _build_region_data(region, catalog)
        _save_json(_region_pool_name(region), data)
        _record_region_meta(region, data)
        return data


async def refresh_all() -> dict:
    catalog = await _region_catalog(force=True)
    summary = {"catalog_regions": len(catalog.get("regions") or {})}
    for region in REGIONS:
        try:
            if region not in (catalog.get("regions") or {}):
                raise ValueError("该地区当前没有候选 IP")
            async with _STATE_LOCK:
                data = await _build_region_data(region, catalog)
                _save_json(_region_pool_name(region), data)
                _record_region_meta(region, data)
            summary[region] = {"count": data.get("count", 0), "updated_at": data.get("updated_at")}
            del data
            _release_memory()
        except Exception as exc:
            summary[region] = {"count": 0, "error": str(exc)}
            _release_memory()
    meta = _pool_meta()
    meta["last_refresh_at"] = _now()
    meta["split_pool_v1"] = True
    _save_json("candidate_pool_meta.json", meta)
    _release_memory()
    return summary


async def record_scan_results(region: str, results: List[dict], count_check: bool = True) -> dict:
    """Merge scan outcomes into split lifecycle storage and the verified pool."""
    region = str(region or "").upper()
    if region != "ALL" and not re.fullmatch(r"[A-Z]{2}", region):
        raise ValueError("unsupported region")
    result_map = {
        str(row.get("candidate") or row.get("input") or "").strip().lower(): row
        for row in (results or [])
        if isinstance(row, dict) and str(row.get("candidate") or row.get("input") or "").strip()
    }
    if not result_map:
        return {"tested": 0, "verified": 0}

    ts = _now()
    total_touched = 0
    async with _STATE_LOCK:
        verified = _verified_data()
        meta = _pool_meta()
        source_quality = _source_quality_data() if count_check else None
        asn_quality = _asn_quality_data() if count_check else None
        if region == "ALL":
            region_codes = list((meta.get("region_counts") or {}).keys()) or list(REGIONS)
        else:
            region_codes = [region]

        for code in region_codes:
            pool_path = _path(_region_pool_name(code))
            if not pool_path.exists():
                continue
            region_data = _load_region_pool(code)
            candidates = list(region_data.get("candidates") or [])
            existing_verified = ((verified.get("regions") or {}).get(code) or {}).get("results") or []
            verified_map = {
                str(row.get("candidate") or row.get("input") or "").strip().lower(): row
                for row in existing_verified
                if isinstance(row, dict) and str(row.get("candidate") or row.get("input") or "").strip()
            }

            touched = 0
            base_available = 0
            for candidate in candidates:
                key = str(candidate.get("target") or "").strip().lower()
                result = result_map.get(key)
                if result is None:
                    continue
                touched += 1
                total_touched += 1
                final_ok = result.get("final_available") is True if "final_available" in result else result.get("available") is True
                candidate["available"] = result.get("available") is True
                candidate["final_available"] = final_ok

                if count_check:
                    candidate["last_checked_at"] = ts
                    candidate["check_count"] = int(candidate.get("check_count") or 0) + 1
                    if final_ok:
                        candidate["success_count"] = int(candidate.get("success_count") or 0) + 1
                        candidate["consecutive_failures"] = 0
                        candidate["last_success_at"] = ts
                    else:
                        candidate["failure_count"] = int(candidate.get("failure_count") or 0) + 1
                        candidate["consecutive_failures"] = int(candidate.get("consecutive_failures") or 0) + 1
                        candidate["last_failure_at"] = ts

                for field in ("tcp_ms", "tls_ms"):
                    if result.get(field) is not None:
                        candidate[field] = result.get(field)
                speed = result.get("speed") or {}
                if isinstance(speed, dict) and speed.get("avg_mbps") is not None:
                    candidate["avg_mbps"] = speed.get("avg_mbps")
                purity = result.get("purity") or {}
                if isinstance(purity, dict):
                    for source_field in ("purity_score", "risk_score", "is_residential", "is_idc"):
                        if purity.get(source_field) is not None:
                            candidate[source_field] = purity.get(source_field)

                if result.get("available") is True:
                    base_available += 1
                apply_quality_score(candidate)
                if count_check:
                    source_names = list(candidate.get("sources") or [])
                    if not source_names and candidate.get("source"):
                        source_names = [str(candidate.get("source"))]
                    score = int(candidate.get("quality_score") or 0)
                    for source_name in source_names:
                        _record_source_feedback(source_quality, str(source_name), final_ok, score)
                    asn = _row_asn(result) or _row_asn(candidate)
                    if asn:
                        _record_asn_feedback(asn_quality, asn, final_ok, score)
                if final_ok:
                    item = dict(candidate)
                    for result_key, result_value in result.items():
                        if result_value is not None:
                            item[result_key] = result_value
                    for preserve_key in (
                        "sources", "success_count", "failure_count", "avg_mbps",
                        "purity", "tcp_ms", "tls_ms", "quality_score",
                    ):
                        if candidate.get(preserve_key) is not None:
                            item[preserve_key] = candidate.get(preserve_key)
                    item["quality_score"] = int(candidate.get("quality_score") or item.get("quality_score") or 0)
                    item["last_verified_at"] = ts
                    verified_map[key] = item
                else:
                    verified_map.pop(key, None)

            if not touched:
                del region_data, candidates, verified_map
                _release_memory()
                continue

            candidates = _prune_pool_rows(candidates)
            region_data["candidates"] = candidates
            region_data["count"] = len(candidates)
            region_data["updated_at"] = ts
            _save_json(_region_pool_name(code), region_data)
            _record_region_meta(code, region_data)

            verified_rows = list(verified_map.values())
            verified_rows.sort(
                key=lambda row: (
                    int(row.get("quality_score") or 0),
                    int(row.get("success_count") or 0),
                    len(row.get("sources") or []),
                    -float(row.get("tcp_ms") if isinstance(row.get("tcp_ms"), (int, float)) else 1e9),
                    float(row.get("last_verified_at") or 0),
                ),
                reverse=True,
            )
            verified_rows = verified_rows[:VERIFIED_MAX_PER_REGION]
            previous = (verified.get("regions") or {}).get(code) or {}
            verified["regions"][code] = {
                "updated_at": ts,
                "tested": touched if count_check else int(previous.get("tested") or 0),
                "tested_total": int(previous.get("tested_total") or 0) + (touched if count_check else 0),
                "base_available": base_available,
                "final_available": len(verified_rows),
                "results": verified_rows,
            }
            del region_data, candidates, verified_map, verified_rows
            _release_memory()

        verified["updated_at"] = ts
        _save_json("candidate_verified.json", verified)
        if count_check:
            source_quality["updated_at"] = ts
            asn_quality["updated_at"] = ts
            _save_json("source_quality.json", source_quality)
            _save_json("asn_quality.json", asn_quality)
        verified_total = sum(
            int((row or {}).get("final_available") or 0)
            for row in (verified.get("regions") or {}).values()
        )
    _release_memory()
    return {"tested": total_touched, "verified": verified_total}


async def recheck_region(region: str, limit: Optional[int] = None, force: bool = False) -> dict:
    if _PROBE_CALLBACK is None:
        raise RuntimeError("EDT 自动复检探针未配置")
    if _EDT_CONFIG is None or not getattr(_EDT_CONFIG, "configured", False):
        raise RuntimeError("EDT 真连接验证未配置")
    if not _DEFAULT_SNI:
        raise RuntimeError("EDT 自动复检缺少检测 SNI")
    region = region.upper()
    cap = max(1, min(int(limit or AUTO_RECHECK_LIMIT), AUTO_RECHECK_LIMIT))
    candidates = await get_scan_targets(region, cap, force=force)
    if not candidates:
        existing = _verified_data().get("regions", {}).get(region) or {}
        return {
            "updated_at": existing.get("updated_at"), "tested": 0, "base_available": 0,
            "final_available": int(existing.get("final_available") or 0), "results": list(existing.get("results") or []),
        }
    sem = asyncio.Semaphore(50)

    async def base_one(target: str) -> dict:
        async with sem:
            try:
                return await _PROBE_CALLBACK(target, _DEFAULT_SNI, _DEFAULT_PATH, True, "", 7.0)
            except Exception as exc:
                return {"candidate": target, "available": False, "final_available": False, "error": str(exc)[:180]}

    base_rows = await asyncio.gather(*(base_one(target) for target in candidates))
    base_ok = [row for row in base_rows if row.get("available") is True]
    for row in base_rows:
        if row.get("available") is not True:
            row["final_available"] = False
    runtime_sem = asyncio.Semaphore(10)

    async def runtime_one(row: dict) -> dict:
        async with runtime_sem:
            try:
                runtime = await check_edt_runtime(row.get("candidate"), _EDT_CONFIG)
                row["edt_runtime"] = runtime
                row["edt_available"] = runtime.get("ok") is True
                row["final_available"] = row["edt_available"]
                if row["final_available"]:
                    await enrich_result(row, _DATA_DIR)
            except Exception as exc:
                row["edt_available"] = False
                row["final_available"] = False
                row["error"] = str(exc)[:180]
            return row

    checked = await asyncio.gather(*(runtime_one(row) for row in base_ok))
    checked_map = {str(row.get("candidate") or "").lower(): row for row in checked}
    outcomes = [checked_map.get(str(row.get("candidate") or "").lower(), row) for row in base_rows]
    await record_scan_results(region, outcomes)
    verified_row = _verified_data().get("regions", {}).get(region) or {}
    meta = _load_json("candidate_pool_meta.json", {})
    meta["last_recheck_at"] = _now()
    meta.setdefault("last_recheck_by_region", {})[region] = _now()
    _save_json("candidate_pool_meta.json", meta)
    return {
        "updated_at": verified_row.get("updated_at"),
        "tested": len(candidates),
        "base_available": len(base_ok),
        "final_available": int(verified_row.get("final_available") or 0),
        "results": list(verified_row.get("results") or []),
    }


async def _background_loop() -> None:
    await asyncio.sleep(3)
    while True:
        try:
            meta = _load_json("candidate_pool_meta.json", {})
            ts = _now()
            if ts - float(meta.get("last_refresh_at") or 0) >= REFRESH_INTERVAL:
                await refresh_all()
                meta = _load_json("candidate_pool_meta.json", {})
            # Drain one bounded region batch per cycle. New candidates are first,
            # then due rechecks; this prevents every refresh from rescanning the full pool.
            if _EDT_CONFIG is not None and getattr(_EDT_CONFIG, "configured", False) and _DEFAULT_SNI:
                cursor = int(meta.get("recheck_cursor") or 0) % len(REGIONS)
                for offset in range(len(REGIONS)):
                    idx = (cursor + offset) % len(REGIONS)
                    data = await recheck_region(REGIONS[idx], AUTO_RECHECK_LIMIT, force=False)
                    if int(data.get("tested") or 0) > 0:
                        meta = _load_json("candidate_pool_meta.json", {})
                        meta["recheck_cursor"] = (idx + 1) % len(REGIONS)
                        meta["last_background_recheck_at"] = _now()
                        _save_json("candidate_pool_meta.json", meta)
                        break
            await asyncio.sleep(1800)
        except asyncio.CancelledError:
            return
        except Exception:
            await asyncio.sleep(600)


def _auth(request: Request, csrf: bool = False) -> dict:
    if _REQUIRE_WEB_SESSION is None:
        raise HTTPException(status_code=503, detail="candidate pool not configured")
    payload = _REQUIRE_WEB_SESSION(request)
    if csrf:
        _REQUIRE_CSRF(request, payload)
    return payload


@router.get("/api/candidate-regions")
async def api_candidate_regions(request: Request) -> dict:
    _auth(request)
    try:
        catalog = await _region_catalog()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"地区目录读取失败：{exc}")
    meta = _pool_meta()
    region_counts = meta.get("region_counts") if isinstance(meta.get("region_counts"), dict) else {}
    rows = []
    for code, data in (catalog.get("regions") or {}).items():
        catalog_count = int(data.get("count") or 0)
        pool_row = region_counts.get(code) if isinstance(region_counts.get(code), dict) else {}
        pool_count = int(pool_row.get("count") or 0)
        count = pool_count if pool_count > 0 else catalog_count
        if count <= 0:
            continue
        rows.append({
            "code": code,
            "count": count,
            "pool_count": pool_count,
            "catalog_count": catalog_count,
            "pool_updated_at": pool_row.get("updated_at"),
        })
    rows.sort(key=lambda item: (-item["count"], item["code"]))
    return {
        "regions": rows,
        "updated_at": catalog.get("updated_at"),
        "pool_updated_at": meta.get("pool_updated_at"),
    }


@router.get("/api/candidate-pool")
async def api_pool(request: Request, region: str = "HK", preview_limit: int = 300) -> dict:
    _auth(request)
    region = region.upper()
    preview_limit = max(0, min(int(preview_limit or 0), 1000))
    verified = _verified_data()
    catalog = await _region_catalog()

    if region == "ALL":
        seen: set[str] = set()
        preview: List[dict] = []
        preview_by_key: Dict[str, dict] = {}
        stats: Dict[str, dict] = {}
        updated_values: List[float] = []
        master_count = 0

        def add_preview(target: str, sources: List[str], hints: List[str], source: Optional[str] = None) -> bool:
            key = str(target or "").strip().lower()
            if not key:
                return False
            is_new = key not in seen
            if is_new:
                seen.add(key)
            item = preview_by_key.get(key)
            if item is None and is_new and len(preview) < preview_limit:
                item = {"target": target, "sources": [], "region_hints": []}
                if source:
                    item["source"] = source
                preview.append(item)
                preview_by_key[key] = item
            if item is not None:
                for value in sources:
                    if value not in item["sources"]:
                        item["sources"].append(value)
                for value in hints:
                    if value not in item["region_hints"]:
                        item["region_hints"].append(value)
            return is_new

        for code, region_row in (catalog.get("regions") or {}).items():
            for target in region_row.get("candidates", []):
                if add_preview(str(target), ["NiREvil 全地区"], [code], "NiREvil 全地区"):
                    master_count += 1
        if catalog.get("updated_at"):
            updated_values.append(float(catalog["updated_at"]))
        stats["NiREvil 全地区"] = {
            "name": "NiREvil 全地区", "count": master_count,
            "contributed": master_count, "ms": 0, "status": "ok",
        }

        for code in (catalog.get("regions") or {}):
            region_data = _load_region_pool(code, catalog)
            if region_data.get("updated_at"):
                updated_values.append(float(region_data["updated_at"]))
            for row in region_data.get("candidates", []):
                target = str(row.get("target") or "").strip()
                add_preview(
                    target,
                    list(row.get("sources") or []),
                    list(row.get("region_hints") or []),
                    row.get("source"),
                )
            for row in region_data.get("source_stats", []):
                name = str(row.get("name") or "未命名来源")
                if name not in stats:
                    stats[name] = {"name": name, "count": 0, "contributed": 0, "ms": 0, "status": "ok"}
                item = stats[name]
                item["count"] += int(row.get("count") or 0)
                item["contributed"] += int(row.get("contributed") or 0)
                item["ms"] = round(float(item.get("ms") or 0) + float(row.get("ms") or 0), 1)
                if row.get("status") != "ok":
                    item["status"] = row.get("status") or "失败"
            del region_data
            _release_memory()

        pool_view = {
            "count": len(seen),
            "candidates": preview,
            "source_stats": list(stats.values()),
            "updated_at": max(updated_values) if updated_values else None,
        }
        del seen, preview_by_key, stats
        _release_memory()
    else:
        if not re.fullmatch(r"[A-Z]{2}", region) or region not in (catalog.get("regions") or {}):
            raise HTTPException(status_code=400, detail="unsupported region")
        data = _load_region_pool(region, catalog)
        pool_view = dict(data)
        pool_view["candidates"] = [
            _public_candidate(row)
            for row in list(data.get("candidates") or [])[:preview_limit]
        ]
        del data
        _release_memory()

    return {
        "region": region,
        "pool": pool_view,
        "meta": _pool_meta(),
        "refresh_interval": REFRESH_INTERVAL,
        "recheck_interval": RECHECK_INTERVAL,
    }


@router.get("/api/candidate-pool/verified")
async def api_verified_pool(request: Request) -> dict:
    _auth(request)
    return _verified_pool_payload()


@router.get("/api/candidate-pool/quality")
async def api_pool_quality(request: Request) -> dict:
    _auth(request)
    return {"source_quality": _source_quality_data(), "asn_quality": _asn_quality_data()}


@router.post("/api/candidate-pool/refresh")
async def api_refresh(request: Request) -> dict:
    _auth(request, csrf=True)
    body = await request.json()
    region = str(body.get("region") or "HK").upper()
    if region == "ALL":
        return {"ok": True, "regions": await refresh_all()}
    try:
        data = await refresh_region(region)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    meta = _load_json("candidate_pool_meta.json", {})
    meta["last_refresh_at"] = _now()
    _save_json("candidate_pool_meta.json", meta)
    return {"ok": True, "region": region, "count": data.get("count", 0), "updated_at": data.get("updated_at")}


@router.post("/api/candidate-pool/recheck")
async def api_recheck(request: Request) -> dict:
    _auth(request, csrf=True)
    body = await request.json()
    region = str(body.get("region") or "HK").upper()
    try:
        data = await recheck_region(region, body.get("limit"), force=True)
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"ok": True, "region": region, **{k: data.get(k) for k in ("tested", "base_available", "final_available", "updated_at")}}


@router.get("/api/candidate-sources")
async def api_sources(request: Request) -> dict:
    _auth(request)
    return {"sources": [_public_source(row) for row in _custom_sources()]}


@router.post("/api/candidate-sources")
async def api_save_source(request: Request) -> dict:
    _auth(request, csrf=True)
    body = await request.json()
    name = str(body.get("name") or "").strip()
    value = str(body.get("value") or "").strip()
    source_type = str(body.get("type") or "").strip().lower()
    region = str(body.get("region") or "ALL").upper()
    if not name or not value:
        raise HTTPException(status_code=400, detail="名称和地址不能为空")
    if source_type not in {"url", "dns"}:
        source_type = "url" if value.lower().startswith(("http://", "https://")) else "dns"
    if region != "ALL":
        catalog = await _region_catalog()
        if region not in (catalog.get("regions") or {}):
            raise HTTPException(status_code=400, detail="不支持的地区")
    rows = _custom_sources()
    source_id = str(body.get("id") or "").strip()
    existing = next((row for row in rows if row.get("id") == source_id), None) if source_id else None
    if existing is None:
        existing = {"id": uuid.uuid4().hex[:10], "failures": 0, "last_status": "-", "last_count": None, "enabled": True, "created_at": _now()}
        rows.append(existing)
    previous_type = str(existing.get("type") or "")
    previous_value = str(existing.get("value") or "").strip()
    existing.update({"name": name, "value": value, "type": source_type, "region": region, "enabled": bool(body.get("enabled", existing.get("enabled", True))), "updated_at": _now()})
    if source_type != "dns" or previous_type != source_type or previous_value != value:
        existing.pop("dns_history", None)
        existing.pop("last_current_count", None)
        existing.pop("history_count", None)
    _save_custom_sources(rows)
    return {"ok": True, "source": existing}


@router.post("/api/candidate-sources/{source_id}/test")
async def api_test_source(source_id: str, request: Request) -> dict:
    _auth(request, csrf=True)
    rows = _custom_sources()
    row = next((item for item in rows if item.get("id") == source_id), None)
    if not row:
        raise HTTPException(status_code=404, detail="source not found")
    started = _now()
    try:
        items = await _load_custom_source(row)
        row["last_status"] = "ok"
        row["last_count"] = len(items)
        row["last_checked_at"] = _now()
        row["failures"] = 0
        _save_custom_sources(rows)
        return {"ok": True, "count": len(items), "current_count": row.get("last_current_count") if row.get("type") == "dns" else len(items), "history_count": row.get("history_count") if row.get("type") == "dns" else len(items), "preview": items[:20], "ms": round((_now() - started) * 1000, 1)}
    except Exception as exc:
        row["last_status"] = str(exc)[:180]
        row["last_checked_at"] = _now()
        row["failures"] = int(row.get("failures") or 0) + 1
        if row["failures"] >= 3:
            row["enabled"] = False
        _save_custom_sources(rows)
        raise HTTPException(status_code=400, detail=row["last_status"])


@router.delete("/api/candidate-sources/{source_id}")
async def api_delete_source(source_id: str, request: Request) -> dict:
    _auth(request, csrf=True)
    rows = _custom_sources()
    new_rows = [row for row in rows if row.get("id") != source_id]
    if len(new_rows) == len(rows):
        raise HTTPException(status_code=404, detail="source not found")
    _save_custom_sources(new_rows)
    return {"ok": True}


def configure(
    app,
    require_web_session,
    require_csrf,
    data_dir: Path,
    probe_callback,
    edt_config,
    default_probe_sni: str,
    default_probe_path: str,
) -> None:
    global _DATA_DIR, _REQUIRE_WEB_SESSION, _REQUIRE_CSRF, _PROBE_CALLBACK, _EDT_CONFIG, _DEFAULT_SNI, _DEFAULT_PATH, _CONFIGURED
    if _CONFIGURED:
        return
    _DATA_DIR = Path(data_dir)
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    _REQUIRE_WEB_SESSION = require_web_session
    _REQUIRE_CSRF = require_csrf
    _PROBE_CALLBACK = probe_callback
    _EDT_CONFIG = edt_config
    _DEFAULT_SNI = str(default_probe_sni or "").strip()
    if not _DEFAULT_SNI and _EDT_CONFIG is not None:
        try:
            _DEFAULT_SNI = urllib.parse.urlsplit(str(getattr(_EDT_CONFIG, "worker_url", "") or "")).hostname or ""
        except Exception:
            _DEFAULT_SNI = ""
    _DEFAULT_PATH = str(default_probe_path or "/cdn-cgi/trace")
    app.include_router(router)

    async def startup() -> None:
        global _BACKGROUND_TASK
        # v1.1.0 originally stored every region in one large JSON file. Split it
        # once at startup so normal reads and refreshes never hydrate all regions.
        await asyncio.to_thread(_migrate_legacy_pool)
        if _BACKGROUND_TASK is None or _BACKGROUND_TASK.done():
            _BACKGROUND_TASK = asyncio.create_task(_background_loop())

    async def shutdown() -> None:
        global _BACKGROUND_TASK
        if _BACKGROUND_TASK and not _BACKGROUND_TASK.done():
            _BACKGROUND_TASK.cancel()
            try:
                await _BACKGROUND_TASK
            except asyncio.CancelledError:
                pass
        _BACKGROUND_TASK = None

    # FastAPI/Starlette newer releases removed FastAPI.add_event_handler.
    # Wrap the router lifespan instead so V4 works on both current CI and production.
    from contextlib import asynccontextmanager
    previous_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def combined_lifespan(app_instance):
        await startup()
        try:
            async with previous_lifespan(app_instance) as state:
                yield state
        finally:
            await shutdown()

    app.router.lifespan_context = combined_lifespan
    _CONFIGURED = True
