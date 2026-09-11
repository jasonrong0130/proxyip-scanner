import asyncio
import json
import ssl
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

IPPURE_HOST = "my.ippure.com"
IPPURE_PATH = "/v1/info"


def _clamp_score(value: Any) -> Optional[int]:
    try:
        return max(0, min(100, int(round(float(value)))))
    except Exception:
        return None


def _decode_chunked(body: bytes) -> bytes:
    out = bytearray()
    pos = 0
    try:
        while pos < len(body):
            end = body.find(b"\r\n", pos)
            if end < 0:
                break
            size = int(body[pos:end].split(b";", 1)[0].strip(), 16)
            pos = end + 2
            if size == 0:
                break
            out.extend(body[pos:pos + size])
            pos += size + 2
        return bytes(out) if out else body
    except Exception:
        return body


def _normalize_ippure(data: dict) -> dict:
    risk = _clamp_score(data.get("fraudScore"))
    residential = data.get("isResidential") if isinstance(data.get("isResidential"), bool) else None
    network_type = "家宽IP" if residential is True else ("非家宽IP" if residential is False else "未识别")
    return {
        "ok": True,
        "provider": "IPPure",
        "checked_ip": data.get("ip"),
        "purity_score": (100 - risk) if risk is not None else None,
        "risk_score": risk,
        "network_type": network_type,
        "is_residential": residential,
        "is_idc": None,
        "is_native": None,
        "asn": data.get("asn"),
        "org": data.get("asOrganization"),
        "country": data.get("country"),
        "country_code": data.get("countryCode"),
        "region": data.get("region"),
        "city": data.get("city"),
        "error": None,
    }


def _normalize_ping0(data: dict) -> dict:
    risk = _clamp_score(data.get("iprisk"))
    is_idc = data.get("isidc") if isinstance(data.get("isidc"), bool) else None
    asn_type = str(data.get("asntype") or "").lower()
    org_type = str(data.get("orgtype") or "").lower()
    if is_idc is True:
        network_type = "机房IP"
    elif is_idc is False and (asn_type == "isp" or org_type == "isp"):
        network_type = "家宽/运营商IP"
    elif is_idc is False:
        network_type = "非机房IP"
    else:
        network_type = "未识别"
    return {
        "ok": True,
        "provider": "Ping0",
        "checked_ip": data.get("ip"),
        "purity_score": (100 - risk) if risk is not None else None,
        "risk_score": risk,
        "network_type": network_type,
        "is_residential": None,
        "is_idc": is_idc,
        "is_native": data.get("isnative") if isinstance(data.get("isnative"), bool) else None,
        "asn": data.get("asn"),
        "org": data.get("org") or data.get("asnname"),
        "country": data.get("country"),
        "country_code": None,
        "region": data.get("province"),
        "city": data.get("city"),
        "error": None,
    }


async def query_ippure_via_candidate(candidate_host: str, candidate_port: int, timeout: float = 12.0) -> dict:
    writer = None
    try:
        ctx = ssl.create_default_context()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(candidate_host, candidate_port, ssl=ctx, server_hostname=IPPURE_HOST),
            timeout=timeout,
        )
        req = (
            f"GET {IPPURE_PATH} HTTP/1.1\r\n"
            f"Host: {IPPURE_HOST}\r\n"
            "User-Agent: ProxyIP-Scanner/1.0\r\n"
            "Accept: application/json\r\n"
            "Accept-Encoding: identity\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        writer.write(req)
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        raw = bytearray()
        while len(raw) < 256 * 1024:
            chunk = await asyncio.wait_for(reader.read(min(64 * 1024, 256 * 1024 - len(raw))), timeout=timeout)
            if not chunk:
                break
            raw.extend(chunk)
        split = bytes(raw).find(b"\r\n\r\n")
        if split < 0:
            return {"ok": False, "provider": "IPPure", "error": "无效 HTTP 响应"}
        head = bytes(raw[:split]).decode("iso-8859-1", errors="replace")
        first = head.split("\r\n", 1)[0].split()
        status = int(first[1]) if len(first) >= 2 and first[1].isdigit() else 0
        headers: Dict[str, str] = {}
        for line in head.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        body = bytes(raw[split + 4:])
        if headers.get("transfer-encoding", "").lower() == "chunked":
            body = _decode_chunked(body)
        if status != 200:
            return {"ok": False, "provider": "IPPure", "error": f"HTTP {status or '异常'}"}
        data = json.loads(body.decode("utf-8", errors="replace"))
        return _normalize_ippure(data)
    except Exception as exc:
        return {"ok": False, "provider": "IPPure", "error": str(exc)[:180]}
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


def _ping0_sync(ip: str, api_key: str, timeout: float) -> dict:
    key = urllib.parse.quote(api_key, safe="")
    encoded_ip = urllib.parse.quote(ip, safe=":.")
    url = f"https://ping0.cc/apiloc/apikey({key})/ip({encoded_ip})"
    req = urllib.request.Request(url, headers={"User-Agent": "ProxyIP-Scanner/1.0", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read(256 * 1024).decode("utf-8", errors="replace"))
    return _normalize_ping0(data)


async def query_ping0(ip: str, api_key: str, timeout: float = 12.0) -> dict:
    try:
        return await asyncio.to_thread(_ping0_sync, ip, api_key, timeout)
    except Exception as exc:
        return {"ok": False, "provider": "Ping0", "error": str(exc)[:180]}


async def check_purity(
    candidate_host: str,
    candidate_port: int,
    exit_ip: Optional[str],
    ping0_api_key: str = "",
    timeout: float = 12.0,
) -> dict:
    # Ping0 supports arbitrary-IP lookup when an API key is configured. Without a
    # key, IPPure is queried through the candidate itself so IPPure sees that path's
    # actual egress IP rather than the scanner VPS IP.
    if ping0_api_key and exit_ip:
        result = await query_ping0(str(exit_ip), ping0_api_key, timeout)
        if result.get("ok"):
            return result
    return await query_ippure_via_candidate(candidate_host, candidate_port, timeout)
