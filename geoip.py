import asyncio
import ipaddress
import json
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

CACHE_TTL = 7 * 24 * 3600
_LOCK = asyncio.Lock()

COUNTRY_ZH = {
    "HK": "香港", "MO": "澳门", "TW": "台湾", "CN": "中国大陆",
    "JP": "日本", "KR": "韩国", "SG": "新加坡", "US": "美国",
    "DE": "德国", "IE": "爱尔兰", "GB": "英国", "FR": "法国",
    "NL": "荷兰", "CA": "加拿大", "AU": "澳大利亚", "CL": "智利",
    "BR": "巴西", "IN": "印度", "ID": "印度尼西亚", "MY": "马来西亚",
    "TH": "泰国", "VN": "越南", "PH": "菲律宾", "RU": "俄罗斯",
    "SE": "瑞典", "FI": "芬兰", "NO": "挪威", "DK": "丹麦",
    "CH": "瑞士", "AT": "奥地利", "IT": "意大利", "ES": "西班牙",
    "PL": "波兰", "CZ": "捷克", "RO": "罗马尼亚", "TR": "土耳其",
    "AE": "阿联酋", "ZA": "南非", "MX": "墨西哥", "AR": "阿根廷",
}

CITY_ZH = {
    "Hong Kong": "香港", "Tokyo": "东京", "Osaka": "大阪", "Seoul": "首尔",
    "Singapore": "新加坡", "Frankfurt am Main": "法兰克福", "Frankfurt": "法兰克福",
    "Dublin": "都柏林", "London": "伦敦", "Amsterdam": "阿姆斯特丹",
    "Paris": "巴黎", "Madrid": "马德里", "Milan": "米兰", "Warsaw": "华沙",
    "Santiago": "圣地亚哥", "Los Angeles": "洛杉矶", "San Jose": "圣何塞",
    "Seattle": "西雅图", "Chicago": "芝加哥", "Dallas": "达拉斯",
    "Ashburn": "阿什本", "Reston": "雷斯顿", "Washington": "华盛顿",
    "New York": "纽约", "Miami": "迈阿密", "Toronto": "多伦多",
    "Sydney": "悉尼", "Melbourne": "墨尔本", "Taipei": "台北",
}

COLO_ZH = {
    "HKG": ("香港", "香港"), "NRT": ("日本", "东京"), "KIX": ("日本", "大阪"),
    "ICN": ("韩国", "首尔"), "SIN": ("新加坡", "新加坡"), "TPE": ("台湾", "台北"),
    "FRA": ("德国", "法兰克福"), "DUB": ("爱尔兰", "都柏林"), "LHR": ("英国", "伦敦"),
    "AMS": ("荷兰", "阿姆斯特丹"), "CDG": ("法国", "巴黎"), "MAD": ("西班牙", "马德里"),
    "MXP": ("意大利", "米兰"), "WAW": ("波兰", "华沙"), "SCL": ("智利", "圣地亚哥"),
    "SJC": ("美国", "圣何塞"), "LAX": ("美国", "洛杉矶"), "SEA": ("美国", "西雅图"),
    "ORD": ("美国", "芝加哥"), "DFW": ("美国", "达拉斯"), "IAD": ("美国", "北弗吉尼亚"),
    "EWR": ("美国", "纽约"), "MIA": ("美国", "迈阿密"), "YYZ": ("加拿大", "多伦多"),
    "SYD": ("澳大利亚", "悉尼"), "MEL": ("澳大利亚", "墨尔本"),
}

VPS_KEYWORDS = (
    "amazon", "aws", "google", "microsoft", "azure", "oracle", "digitalocean", "vultr",
    "linode", "akamai", "hetzner", "ovh", "leaseweb", "choopa", "contabo", "hosthatch",
    "racknerd", "akamai connected cloud", "tencent", "alibaba", "aliyun", "huawei",
    "cloud", "hosting", "host", "server", "datacenter", "data center", "colo", "vps",
)


def _cache_path(data_dir: Path) -> Path:
    return Path(data_dir) / "geo_cache.json"


def _load_cache(data_dir: Path) -> dict:
    try:
        value = json.loads(_cache_path(data_dir).read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def _save_cache(data_dir: Path, cache: dict) -> None:
    path = _cache_path(data_dir)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _lookup_sync(ip: str) -> dict:
    url = "https://ipwho.is/" + urllib.parse.quote(ip, safe="")
    req = urllib.request.Request(url, headers={"User-Agent": "ProxyIP-Scanner/1.1"})
    with urllib.request.urlopen(req, timeout=8) as response:
        data = json.loads(response.read(256 * 1024).decode("utf-8", errors="replace"))
    if not data.get("success", True):
        raise RuntimeError(data.get("message") or "GeoIP 查询失败")
    connection = data.get("connection") or {}
    country_code = str(data.get("country_code") or "").upper()
    country = COUNTRY_ZH.get(country_code) or str(data.get("country") or country_code or "未识别")
    city_raw = str(data.get("city") or data.get("region") or "").strip()
    city = CITY_ZH.get(city_raw, city_raw)
    asn = connection.get("asn")
    org = str(connection.get("org") or connection.get("isp") or "").strip()
    isp = str(connection.get("isp") or "").strip()
    domain = str(connection.get("domain") or "").strip()
    org_l = (org + " " + isp + " " + domain).lower()
    is_cf = str(asn) == "13335" or "cloudflare" in org_l
    is_vps = (not is_cf) and any(word in org_l for word in VPS_KEYWORDS)
    network_type = "Cloudflare" if is_cf else ("VPS/IDC" if is_vps else "普通网络/其他")
    label = country + (" · " + city if city and city != country else "")
    return {
        "ip": ip,
        "country_code": country_code,
        "country": country,
        "city": city or "未识别",
        "label": label,
        "asn": asn,
        "org": org or isp or "未识别",
        "isp": isp,
        "domain": domain,
        "is_cloudflare": is_cf,
        "is_vps_idc": is_vps,
        "network_type": network_type,
        "lookup_at": time.time(),
    }


async def lookup_ip(ip: Optional[str], data_dir: Path) -> Optional[dict]:
    if not ip or not _is_public_ip(ip):
        return None
    async with _LOCK:
        cache = _load_cache(data_dir)
        row = cache.get(ip)
        if isinstance(row, dict) and time.time() - float(row.get("lookup_at") or 0) < CACHE_TTL:
            return row
    try:
        row = await asyncio.to_thread(_lookup_sync, ip)
    except Exception:
        return None
    async with _LOCK:
        cache = _load_cache(data_dir)
        cache[ip] = row
        if len(cache) > 10000:
            ordered = sorted(cache.items(), key=lambda item: float(item[1].get("lookup_at") or 0), reverse=True)[:8000]
            cache = dict(ordered)
        _save_cache(data_dir, cache)
    return row


def colo_label(code: Optional[str]) -> str:
    code = str(code or "").upper()
    if not code:
        return "未识别"
    item = COLO_ZH.get(code)
    if not item:
        return code
    country, city = item
    if city == country:
        return f"{country}（{code}）"
    return f"{country} · {city}（{code}）"


async def enrich_result(row: dict, data_dir: Path) -> dict:
    host = str(row.get("host") or "").strip()
    exit_ip = str(row.get("exit_ip") or "").strip()
    entry_geo, exit_geo = await asyncio.gather(lookup_ip(host, data_dir), lookup_ip(exit_ip, data_dir))

    if entry_geo:
        row["entry_geo"] = entry_geo
        row["entry_country"] = entry_geo.get("country")
        row["entry_country_code"] = entry_geo.get("country_code")
        row["entry_city"] = entry_geo.get("city")
        row["entry_location"] = entry_geo.get("label")
        row["entry_asn"] = entry_geo.get("asn")
        row["entry_org"] = entry_geo.get("org")
        row["entry_network_type"] = entry_geo.get("network_type")
        row["entry_is_cloudflare"] = entry_geo.get("is_cloudflare")
        row["entry_is_vps_idc"] = entry_geo.get("is_vps_idc")
    else:
        row.setdefault("entry_location", "未识别")

    if exit_geo:
        row["exit_geo"] = exit_geo
        row["exit_country"] = exit_geo.get("country")
        row["exit_country_code"] = exit_geo.get("country_code")
        row["exit_city"] = exit_geo.get("city")
        row["exit_location"] = exit_geo.get("label")
        row["exit_asn"] = exit_geo.get("asn")
        row["exit_org"] = exit_geo.get("org")
    else:
        code = str(row.get("country") or "").upper()
        country = COUNTRY_ZH.get(code, code or "未识别")
        row.setdefault("exit_country", country)
        row.setdefault("exit_country_code", code)
        row.setdefault("exit_location", country)

    row["colo_label"] = colo_label(row.get("colo"))
    return row
