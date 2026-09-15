import asyncio
import csv
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

router = APIRouter()

_DATA_DIR: Optional[Path] = None
_REQUIRE_WEB_SESSION = None
_REQUIRE_CSRF = None
_PROBE_CALLBACK: Optional[Callable[..., Awaitable[dict]]] = None
_EDT_CONFIG = None
_DEFAULT_SNI = ""
_DEFAULT_PATH = "/cdn-cgi/trace"
_BACKGROUND_TASK: Optional[asyncio.Task] = None
_CONFIGURED = False

REFRESH_INTERVAL = max(3600, int(os.environ.get("CANDIDATE_REFRESH_INTERVAL", str(6 * 3600))))
RECHECK_INTERVAL = max(6 * 3600, int(os.environ.get("CANDIDATE_RECHECK_INTERVAL", str(24 * 3600))))
MAX_PER_REGION = max(100, min(10000, int(os.environ.get("CANDIDATE_MAX_PER_REGION", "5000"))))
AUTO_RECHECK_LIMIT = max(100, min(5000, int(os.environ.get("CANDIDATE_AUTO_RECHECK_LIMIT", "500"))))
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
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


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
    data = _load_json("candidate_pool.json", {"regions": {}, "updated_at": None})
    if not isinstance(data, dict):
        data = {"regions": {}, "updated_at": None}
    data.setdefault("regions", {})
    return data


def _verified_data() -> dict:
    data = _load_json("candidate_verified.json", {"regions": {}, "updated_at": None})
    if not isinstance(data, dict):
        data = {"regions": {}, "updated_at": None}
    data.setdefault("regions", {})
    return data


async def _run_source(name: str, region_hint: Optional[str], loader: Callable[[], Awaitable[List[str]]]) -> dict:
    started = _now()
    try:
        items = _dedupe(await loader())
        return {"name": name, "region_hint": region_hint, "items": items, "count": len(items), "status": "ok", "ms": round((_now() - started) * 1000, 1)}
    except Exception as exc:
        return {"name": name, "region_hint": region_hint, "items": [], "count": 0, "status": str(exc)[:180], "ms": round((_now() - started) * 1000, 1)}


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


async def get_pool_targets(region: str = "HK") -> List[str]:
    """Return the current candidate pool as endpoint strings without sending it through the browser."""
    region = str(region or "HK").upper()
    catalog = await _region_catalog()
    pool = _pool_data()
    targets: List[str] = []
    if region == "ALL":
        for code, region_row in (catalog.get("regions") or {}).items():
            targets.extend(str(value).strip() for value in region_row.get("candidates", []) if str(value).strip())
        for region_data in (pool.get("regions") or {}).values():
            targets.extend(
                str(row.get("target") or "").strip()
                for row in region_data.get("candidates", [])
                if str(row.get("target") or "").strip()
            )
        return _dedupe(targets)
    if not re.fullmatch(r"[A-Z]{2}", region) or region not in (catalog.get("regions") or {}):
        raise ValueError("unsupported region")
    data = pool.get("regions", {}).get(region) or _catalog_pool(region, catalog)
    return _dedupe([
        str(row.get("target") or "").strip()
        for row in data.get("candidates", [])
        if str(row.get("target") or "").strip()
    ])


async def refresh_region(region: str) -> dict:
    region = str(region or "HK").upper()
    if not re.fullmatch(r"[A-Z]{2}", region):
        raise ValueError("unsupported region")
    catalog = await _region_catalog()
    if region not in (catalog.get("regions") or {}):
        raise ValueError("该地区当前没有候选 IP")
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
        stats.append({k: source.get(k) for k in ("name", "count", "status", "ms")} | {"contributed": contributed})
    candidates = list(merged.values())[:MAX_PER_REGION]
    pool = _pool_data()
    pool["regions"][region] = {"updated_at": _now(), "count": len(candidates), "candidates": candidates, "source_stats": stats}
    pool["updated_at"] = _now()
    _save_json("candidate_pool.json", pool)
    return pool["regions"][region]


async def refresh_all() -> dict:
    catalog = await _region_catalog(force=True)
    summary = {"catalog_regions": len(catalog.get("regions") or {})}
    for region in REGIONS:
        try:
            data = await refresh_region(region)
            summary[region] = {"count": data.get("count", 0), "updated_at": data.get("updated_at")}
        except Exception as exc:
            summary[region] = {"count": 0, "error": str(exc)}
    meta = _load_json("candidate_pool_meta.json", {})
    meta["last_refresh_at"] = _now()
    _save_json("candidate_pool_meta.json", meta)
    return summary


async def recheck_region(region: str, limit: Optional[int] = None) -> dict:
    if _PROBE_CALLBACK is None:
        raise RuntimeError("EDT 自动复检探针未配置")
    if _EDT_CONFIG is None or not getattr(_EDT_CONFIG, "configured", False):
        raise RuntimeError("EDT 真连接验证未配置")
    if not _DEFAULT_SNI:
        raise RuntimeError("EDT 自动复检缺少检测 SNI")
    region = region.upper()
    pool = _pool_data().get("regions", {}).get(region) or {}
    candidates = [row.get("target") for row in pool.get("candidates", []) if row.get("target")]
    candidates = candidates[: max(1, min(int(limit or AUTO_RECHECK_LIMIT), AUTO_RECHECK_LIMIT))]
    sem = asyncio.Semaphore(50)

    async def base_one(target: str) -> dict:
        async with sem:
            return await _PROBE_CALLBACK(target, _DEFAULT_SNI, _DEFAULT_PATH, True, "", 7.0)

    base_rows = await asyncio.gather(*(base_one(target) for target in candidates))
    base_ok = [row for row in base_rows if row.get("available") is True]
    runtime_sem = asyncio.Semaphore(10)

    async def runtime_one(row: dict) -> dict:
        async with runtime_sem:
            runtime = await check_edt_runtime(row.get("candidate"), _EDT_CONFIG)
            row["edt_runtime"] = runtime
            row["edt_available"] = runtime.get("ok") is True
            row["final_available"] = row["edt_available"]
            if row["final_available"]:
                await enrich_result(row, _DATA_DIR)
            return row

    checked = await asyncio.gather(*(runtime_one(row) for row in base_ok))
    good = [row for row in checked if row.get("final_available") is True]
    verified = _verified_data()
    verified["regions"][region] = {
        "updated_at": _now(),
        "tested": len(candidates),
        "base_available": len(base_ok),
        "final_available": len(good),
        "results": good,
    }
    verified["updated_at"] = _now()
    _save_json("candidate_verified.json", verified)
    meta = _load_json("candidate_pool_meta.json", {})
    meta["last_recheck_at"] = _now()
    _save_json("candidate_pool_meta.json", meta)
    return verified["regions"][region]


async def _background_loop() -> None:
    await asyncio.sleep(3)
    while True:
        try:
            meta = _load_json("candidate_pool_meta.json", {})
            ts = _now()
            if ts - float(meta.get("last_refresh_at") or 0) >= REFRESH_INTERVAL:
                await refresh_all()
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
    pool = _pool_data()
    pool_regions = pool.get("regions") or {}
    rows = []
    for code, data in (catalog.get("regions") or {}).items():
        catalog_count = int(data.get("count") or 0)
        pool_row = pool_regions.get(code) or {}
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
        "pool_updated_at": pool.get("updated_at"),
    }


@router.get("/api/candidate-pool")
async def api_pool(request: Request, region: str = "HK", preview_limit: int = 300) -> dict:
    _auth(request)
    region = region.upper()
    pool = _pool_data()
    verified = _verified_data()
    catalog = await _region_catalog()
    if region == "ALL":
        merged: Dict[str, dict] = {}
        stats: Dict[str, dict] = {}
        updated_values: List[float] = []
        master_count = 0
        for code, region_row in (catalog.get("regions") or {}).items():
            for target in region_row.get("candidates", []):
                key = str(target).lower()
                if key not in merged:
                    merged[key] = {"target": target, "sources": ["NiREvil 全地区"], "region_hints": [code]}
                    master_count += 1
        if catalog.get("updated_at"):
            updated_values.append(float(catalog["updated_at"]))
        stats["NiREvil 全地区"] = {"name": "NiREvil 全地区", "count": master_count, "contributed": master_count, "ms": 0, "status": "ok"}
        for code, region_data in (pool.get("regions") or {}).items():
            if region_data.get("updated_at"):
                updated_values.append(float(region_data["updated_at"]))
            for row in region_data.get("candidates", []):
                target = str(row.get("target") or "").strip()
                if not target:
                    continue
                key = target.lower()
                if key not in merged:
                    merged[key] = {"target": target, "sources": [], "region_hints": []}
                item = merged[key]
                for source in row.get("sources", []):
                    if source not in item["sources"]:
                        item["sources"].append(source)
                for hint in row.get("region_hints", []):
                    if hint not in item["region_hints"]:
                        item["region_hints"].append(hint)
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
        data = {
            "count": len(merged),
            "candidates": list(merged.values()),
            "source_stats": list(stats.values()),
            "updated_at": max(updated_values) if updated_values else None,
        }
    else:
        if not re.fullmatch(r"[A-Z]{2}", region) or region not in (catalog.get("regions") or {}):
            raise HTTPException(status_code=400, detail="unsupported region")
        data = pool.get("regions", {}).get(region) or _catalog_pool(region, catalog)
    # The browser only needs a short preview. Keep the complete pool server-side
    # so large regions do not transfer/render thousands of endpoints on every page load.
    preview_limit = max(0, min(int(preview_limit or 0), 1000))
    pool_view = dict(data)
    pool_view["candidates"] = list(data.get("candidates") or [])[:preview_limit]
    verified_row = verified.get("regions", {}).get(region) or {"final_available": 0, "results": [], "updated_at": None}
    verified_view = dict(verified_row)
    verified_view["results"] = list(verified_row.get("results") or [])[: min(preview_limit, 100)]
    return {
        "region": region,
        "pool": pool_view,
        "verified": verified_view,
        "meta": _load_json("candidate_pool_meta.json", {}),
        "refresh_interval": REFRESH_INTERVAL,
        "recheck_interval": RECHECK_INTERVAL,
    }


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
        data = await recheck_region(region, body.get("limit"))
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
