import asyncio
import base64
import csv
import gc
import hashlib
import hmac
import io
import ipaddress
import json
import os
import re
import secrets
import ssl
import time
import uuid
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from edt_runtime import check_edt_runtime, load_edt_runtime_config
from edt_verify import EDT_VERIFY_MODE, check_edt_runtime_selected, edt_remote_configured, edt_verification_configured
import candidate_pool
from geoip import enrich_result
from purity import check_purity

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("PROXY_SCANNER_DATA_DIR", str(APP_DIR / "data"))).resolve()
STATIC_DIR = APP_DIR / "static"
DATA_DIR.mkdir(parents=True, exist_ok=True)

APP_NAME = "ProxyIP Scanner"
APP_VERSION = "1.1.0"
CHECK_CONCURRENCY_OPTIONS = (20, 50, 100, 200)
CLOUDFLARE_HTTPS_PORTS = (443, 2053, 2083, 2087, 2096, 8443)
DEFAULT_SCAN_PORTS = (443,)
DEFAULT_CHECK_CONCURRENCY = int(os.environ.get("CHECK_CONCURRENCY", "50"))
if DEFAULT_CHECK_CONCURRENCY not in CHECK_CONCURRENCY_OPTIONS:
    DEFAULT_CHECK_CONCURRENCY = 50
DEFAULT_SPEED_CONCURRENCY = int(os.environ.get("SPEED_CONCURRENCY", "3"))
DEFAULT_TIMEOUT = float(os.environ.get("PROBE_TIMEOUT", "7"))
DEFAULT_SPEED_BYTES = int(os.environ.get("SPEED_BYTES", str(5 * 1024 * 1024)))
DEFAULT_SPEED_REPEATS = int(os.environ.get("SPEED_REPEATS", "3"))
DEFAULT_PROBE_SNI = os.environ.get("DEFAULT_PROBE_SNI", "").strip()
DEFAULT_PROBE_PATH = os.environ.get("DEFAULT_PROBE_PATH", "/cdn-cgi/trace").strip() or "/cdn-cgi/trace"
DEFAULT_SPEED_SNI = os.environ.get("DEFAULT_SPEED_SNI", "speed.cloudflare.com").strip()
DEFAULT_SPEED_PATH = os.environ.get("DEFAULT_SPEED_PATH", "/__down?bytes={bytes}").strip()
ADMIN_USER = os.environ.get("ADMIN_USER", "admin").strip() or "admin"
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH", "").strip()
SESSION_SECRET = os.environ.get("SESSION_SECRET", "").strip()
EDT_API_TOKEN = os.environ.get("EDT_API_TOKEN", "").strip()
EDT_RUNTIME_CONFIG = load_edt_runtime_config()
DEFAULT_EDT_RUNTIME_CONCURRENCY = max(1, min(50, int(os.environ.get("EDT_RUNTIME_CONCURRENCY", "10"))))
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "1").strip() not in {"0", "false", "False"}
SESSION_TTL = int(os.environ.get("SESSION_TTL", str(12 * 3600)))
LOGIN_WINDOW = int(os.environ.get("LOGIN_WINDOW", "900"))
LOGIN_MAX_FAILURES = int(os.environ.get("LOGIN_MAX_FAILURES", "5"))
PING0_API_KEY = os.environ.get("PING0_API_KEY", "").strip()
DEFAULT_PURITY_CONCURRENCY = max(1, min(10, int(os.environ.get("PURITY_CONCURRENCY", "4"))))
CHECKPOINT_BATCH_SIZE = max(20, min(1000, int(os.environ.get("SCAN_CHECKPOINT_BATCH", "100"))))
LARGE_JOB_THRESHOLD = max(1000, int(os.environ.get("LARGE_JOB_THRESHOLD", "20000")))
MAX_RESUME_ITEMS = max(1000, int(os.environ.get("MAX_RESUME_ITEMS", "500000")))
JOB_RETENTION_DAYS = max(1, min(365, int(os.environ.get("JOB_RETENTION_DAYS", "7"))))
JOB_RETENTION_SECONDS = JOB_RETENTION_DAYS * 86400
JOB_META_FIELDS = (
    "id", "state", "interrupted_stage", "resume_available", "created_at", "started_at", "finished_at", "candidate_region",
    "total", "completed", "available", "final_available", "generic_available", "same_exit",
    "runtime_total", "runtime_completed", "runtime_available",
    "speed_total", "speed_completed", "purity_total", "purity_completed",
)
JOB_ACTIVE_STATES = {"queued", "checking", "runtime_checking", "speeding", "purity_checking", "speed_paused", "purity_paused"}

TARGET_RE = re.compile(r"^[A-Za-z0-9._-]+$")
JOBS: Dict[str, dict] = {}
POST_SPEED_TASKS: Dict[str, asyncio.Task] = {}
PURITY_TASKS: Dict[str, asyncio.Task] = {}
LOGIN_FAILURES: Dict[str, Deque[float]] = defaultdict(deque)

app = FastAPI(title=APP_NAME, version=APP_VERSION, docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def now() -> float:
    return time.time()


def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64u_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def sign_session(payload: dict) -> str:
    if not SESSION_SECRET:
        raise RuntimeError("SESSION_SECRET is not configured")
    body = b64u_encode(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    sig = hmac.new(SESSION_SECRET.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest()
    return body + "." + b64u_encode(sig)


def verify_session(token: str) -> Optional[dict]:
    if not token or "." not in token or not SESSION_SECRET:
        return None
    try:
        body, sig = token.split(".", 1)
        expected = hmac.new(SESSION_SECRET.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, b64u_decode(sig)):
            return None
        payload = json.loads(b64u_decode(body).decode("utf-8"))
        if int(payload.get("exp", 0)) < int(now()):
            return None
        return payload
    except Exception:
        return None


def verify_password(password: str, encoded: str) -> bool:
    try:
        kind, salt_b64, digest_b64 = encoded.split("$", 2)
        if kind != "scrypt":
            return False
        salt = b64u_decode(salt_b64)
        expected = b64u_decode(digest_b64)
        actual = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2 ** 14, r=8, p=1, dklen=len(expected))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def client_ip(request: Request) -> str:
    # Only trust CF-Connecting-IP when the request arrived through a local/reverse-proxy hop.
    peer = request.client.host if request.client else "unknown"
    cf_ip = request.headers.get("cf-connecting-ip", "").strip()
    if cf_ip and peer in {"127.0.0.1", "::1"}:
        return cf_ip
    return peer


def login_is_blocked(ip: str) -> bool:
    q = LOGIN_FAILURES[ip]
    cutoff = now() - LOGIN_WINDOW
    while q and q[0] < cutoff:
        q.popleft()
    return len(q) >= LOGIN_MAX_FAILURES


def mark_login_failure(ip: str) -> None:
    LOGIN_FAILURES[ip].append(now())


def clear_login_failures(ip: str) -> None:
    LOGIN_FAILURES.pop(ip, None)


def require_web_session(request: Request) -> dict:
    payload = verify_session(request.cookies.get("proxyip_session", ""))
    if not payload or payload.get("sub") != ADMIN_USER:
        raise HTTPException(status_code=401, detail="authentication required")
    return payload


def require_edt_token(authorization: Optional[str], x_edt_token: Optional[str]) -> None:
    if not EDT_API_TOKEN:
        raise HTTPException(status_code=503, detail="EDT_API_TOKEN is not configured")
    supplied = ""
    if authorization and authorization.lower().startswith("bearer "):
        supplied = authorization[7:].strip()
    elif x_edt_token:
        supplied = x_edt_token.strip()
    if not supplied or not secrets.compare_digest(supplied, EDT_API_TOKEN):
        raise HTTPException(status_code=401, detail="invalid EDT token")


def public_ip_ok(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return True
    return ip.is_global


def parse_target(raw: str) -> Tuple[str, int, str]:
    value = str(raw or "").strip()
    value = re.sub(r"^proxyip://", "", value, flags=re.I)
    if not value:
        raise ValueError("empty target")
    if any(ch.isspace() for ch in value) or "/" in value or "#" in value or "$" in value:
        raise ValueError("invalid characters")
    host = value
    port = 443
    if value.startswith("["):
        m = re.match(r"^\[([0-9A-Fa-f:]+)\](?::(\d+))?$", value)
        if not m:
            raise ValueError("invalid IPv6 target")
        host = m.group(1)
        if m.group(2):
            port = int(m.group(2))
    else:
        m = re.match(r"^([^:]+):(\d+)$", value)
        if m:
            host = m.group(1)
            port = int(m.group(2))
        elif value.count(":") > 1:
            host = value
    if not 1 <= port <= 65535:
        raise ValueError("port out of range")
    if not public_ip_ok(host):
        raise ValueError("private/reserved IPs are blocked")
    if ":" not in host and not TARGET_RE.match(host):
        raise ValueError("invalid hostname")
    normalized = "[{}]:{}".format(host, port) if ":" in host else "{}:{}".format(host, port)
    return host, port, normalized


async def hostname_is_public(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return public_ip_ok(host)
    except ValueError:
        pass
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None)
    ips = {info[4][0] for info in infos if info[4]}
    return bool(ips) and all(public_ip_ok(ip) for ip in ips)


def validate_sni(value: str) -> str:
    sni = str(value or "").strip().lower().rstrip(".")
    if not sni:
        raise ValueError("SNI is required")
    if ":" in sni or "/" in sni or not TARGET_RE.match(sni):
        raise ValueError("invalid SNI")
    return sni


def validate_path(value: str) -> str:
    path = str(value or "/").strip() or "/"
    if not path.startswith("/") or "\r" in path or "\n" in path:
        raise ValueError("invalid path")
    return path[:2048]


async def close_writer(writer: Any) -> None:
    if not writer:
        return
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass


async def tcp_probe(host: str, port: int, timeout: float) -> dict:
    started = time.perf_counter()
    writer = None
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        return {"ok": True, "ms": round((time.perf_counter() - started) * 1000, 1), "error": None}
    except Exception as exc:
        return {"ok": False, "ms": None, "error": str(exc)}
    finally:
        await close_writer(writer)


def parse_headers(header_bytes: bytes) -> Tuple[int, Dict[str, str]]:
    text = header_bytes.decode("iso-8859-1", errors="replace")
    lines = text.split("\r\n")
    status = 0
    if lines:
        m = re.match(r"^HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0])
        if m:
            status = int(m.group(1))
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return status, headers


def decode_chunked(body: bytes) -> bytes:
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


async def https_probe(proxy_host: str, proxy_port: int, sni_host: str, path: str, timeout: float, body_limit: int = 256 * 1024) -> dict:
    context = ssl.create_default_context()
    writer = None
    started = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy_host, proxy_port, ssl=context, server_hostname=sni_host),
            timeout=timeout,
        )
        tls_ms = round((time.perf_counter() - started) * 1000, 1)
        request = (
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: ProxyIP-Scanner/{}\r\n"
            "Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
        ).format(path, sni_host, APP_VERSION).encode("ascii")
        writer.write(request)
        await asyncio.wait_for(writer.drain(), timeout=timeout)

        raw = bytearray()
        cap = body_limit + 64 * 1024
        while len(raw) < cap:
            chunk = await asyncio.wait_for(reader.read(min(64 * 1024, cap - len(raw))), timeout=timeout)
            if not chunk:
                break
            raw.extend(chunk)

        split = bytes(raw).find(b"\r\n\r\n")
        if split < 0:
            return {"ok": False, "tls_ms": tls_ms, "status": None, "headers": {}, "body": b"", "error": "invalid HTTP response"}
        status, headers = parse_headers(bytes(raw[:split]))
        body = bytes(raw[split + 4:])
        if headers.get("transfer-encoding", "").lower() == "chunked":
            body = decode_chunked(body)
        return {
            "ok": bool(status),
            "tls_ms": tls_ms,
            "status": status or None,
            "headers": headers,
            "body": body[:body_limit],
            "error": None if status else "missing HTTP status",
        }
    except Exception as exc:
        return {"ok": False, "tls_ms": None, "status": None, "headers": {}, "body": b"", "error": str(exc)}
    finally:
        await close_writer(writer)


def parse_trace(body: bytes) -> dict:
    data = {}
    for line in body.decode("utf-8", errors="replace").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            data[k.strip()] = v.strip()
    return data


def cloudflare_reached(headers: Dict[str, str]) -> bool:
    server = headers.get("server", "").lower()
    return server == "cloudflare" or "cf-ray" in headers


def classify_exit(candidate_host: str, exit_ip: Optional[str]) -> str:
    if not exit_ip:
        return "unknown"
    try:
        return "same" if str(ipaddress.ip_address(candidate_host)) == str(ipaddress.ip_address(exit_ip)) else "different"
    except ValueError:
        return "unknown"


async def speed_test(proxy_host: str, proxy_port: int, sni_host: str, path_template: str, size_bytes: int, timeout: float) -> dict:
    if not sni_host:
        return {"ok": False, "mbps": None, "error": "speed SNI is not configured"}
    path = path_template.replace("{bytes}", str(size_bytes))
    context = ssl.create_default_context()
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy_host, proxy_port, ssl=context, server_hostname=sni_host),
            timeout=timeout,
        )
        request = (
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: ProxyIP-Scanner/{}\r\n"
            "Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
        ).format(path, sni_host, APP_VERSION).encode("ascii")
        writer.write(request)
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        header_bytes = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=timeout)
        status, _ = parse_headers(header_bytes[:-4])
        if status < 200 or status >= 400:
            return {"ok": False, "status": status, "mbps": None, "bytes": 0, "seconds": None, "error": "HTTP {}".format(status)}
        received = 0
        body_started = time.perf_counter()
        while received < size_bytes:
            chunk = await asyncio.wait_for(reader.read(min(64 * 1024, size_bytes - received)), timeout=timeout)
            if not chunk:
                break
            received += len(chunk)
        elapsed = max(time.perf_counter() - body_started, 0.001)
        ok = received >= min(size_bytes, 128 * 1024)
        return {
            "ok": ok,
            "status": status,
            "mbps": round(received * 8 / elapsed / 1_000_000, 2) if ok else None,
            "bytes": received,
            "seconds": round(elapsed, 3),
            "error": None if ok else "short download",
        }
    except Exception as exc:
        return {"ok": False, "status": None, "mbps": None, "bytes": 0, "seconds": None, "error": str(exc)}
    finally:
        await close_writer(writer)


async def test_one(raw: str, probe_sni: str, probe_path: str, expect_cloudflare: bool, generic_sni: str, timeout: float) -> dict:
    tested_at = now()
    try:
        host, port, normalized = parse_target(raw)
        if not await hostname_is_public(host):
            raise ValueError("hostname resolves to private/reserved address")
        sni = validate_sni(probe_sni)
        path = validate_path(probe_path)
    except Exception as exc:
        return {"input": raw, "candidate": raw, "available": False, "state": "checked", "error_stage": "input", "error": str(exc), "tested_at": tested_at}

    tcp = await tcp_probe(host, port, timeout)
    if not tcp["ok"]:
        return {
            "input": raw, "candidate": normalized, "host": host, "port": port, "sni": sni,
            "available": False, "cloudflare_reached": False, "generic_ok": None,
            "tcp_ms": None, "tls_ms": None, "http_status": None,
            "exit_ip": None, "country": None, "colo": None, "exit_match": "unknown",
            "error_stage": "tcp", "error": tcp["error"], "tested_at": tested_at, "state": "checked",
        }

    probe = await https_probe(host, port, sni, path, timeout)
    reached_cf = cloudflare_reached(probe.get("headers", {})) if probe.get("ok") else False
    available = bool(probe.get("ok") and (reached_cf if expect_cloudflare else True))
    trace_data = parse_trace(probe.get("body", b"")) if probe.get("ok") else {}
    exit_ip = trace_data.get("ip")

    generic_ok = None
    generic_status = None
    generic_error = None
    if generic_sni:
        try:
            gsni = validate_sni(generic_sni)
            generic = await https_probe(host, port, gsni, "/", timeout, 64 * 1024)
            generic_status = generic.get("status")
            generic_ok = bool(generic.get("ok"))
            generic_error = generic.get("error")
        except Exception as exc:
            generic_ok = False
            generic_error = str(exc)

    error = None
    error_stage = None
    if not available:
        error_stage = "tls_http"
        if not probe.get("ok"):
            error = probe.get("error") or "TLS/HTTP probe failed"
        elif expect_cloudflare and not reached_cf:
            error = "HTTP reached but Cloudflare was not confirmed"

    return {
        "input": raw, "candidate": normalized, "host": host, "port": port, "sni": sni,
        "available": available, "cloudflare_reached": reached_cf,
        "generic_ok": generic_ok, "generic_status": generic_status, "generic_error": generic_error,
        "tcp_ms": tcp.get("ms"), "tls_ms": probe.get("tls_ms"), "http_status": probe.get("status"),
        "exit_ip": exit_ip, "country": trace_data.get("loc"), "colo": trace_data.get("colo"),
        "exit_match": classify_exit(host, exit_ip), "error_stage": error_stage, "error": error,
        "tested_at": tested_at, "state": "checked",
    }


def job_path(job_id: str) -> Path:
    return DATA_DIR / (job_id + ".json")


def job_meta_path(job_id: str) -> Path:
    return DATA_DIR / (job_id + ".meta.json")


def checkpoint_path(job_id: str) -> Path:
    return DATA_DIR / (job_id + ".checkpoint.jsonl")


def is_large_job(job: dict) -> bool:
    try:
        return int(job.get("total") or 0) >= LARGE_JOB_THRESHOLD
    except Exception:
        return False


def compact_failed_row(row: dict) -> dict:
    """Keep enough failed-row detail for UI/history while dropping dozens of empty fields."""
    if not isinstance(row, dict) or row.get("available") is not False:
        return row
    candidate = row.get("candidate") or row.get("input") or ""
    keep = (
        "host", "port", "available", "cloudflare_reached", "tcp_ms", "tls_ms", "http_status",
        "error_stage", "error", "tested_at", "state", "final_available", "edt_available",
    )
    out = {"candidate": candidate}
    for key in keep:
        if key in row and row.get(key) is not None:
            out[key] = row.get(key)
    if out.get("error"):
        out["error"] = str(out["error"])[:180]
    out.setdefault("available", False)
    out.setdefault("state", "checked")
    return out


def compact_large_job_rows(job: dict) -> None:
    if not is_large_job(job):
        return
    rows = job.get("results") or []
    for idx, row in enumerate(rows):
        if isinstance(row, dict) and row.get("available") is False:
            rows[idx] = compact_failed_row(row)


def _atomic_json_write(path: Path, payload: dict) -> None:
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        # Stream directly to disk. json.dumps() built a second giant in-memory copy
        # of 100k+ result jobs and was the main stage-transition OOM spike.
        json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
        handle.flush()
        os.fsync(handle.fileno())
    tmp.replace(path)


def persist_job_meta(job: dict) -> None:
    if not job.get("id"):
        return
    meta = {key: job.get(key) for key in JOB_META_FIELDS}
    _atomic_json_write(job_meta_path(str(job["id"])), meta)


def persist_job(job: dict) -> None:
    safe = {k: v for k, v in job.items() if not str(k).startswith("_")}
    _atomic_json_write(job_path(str(job["id"])), safe)
    persist_job_meta(job)


def flush_result_checkpoints(job: dict) -> None:
    buffer = job.get("_checkpoint_buffer") or []
    if not buffer:
        return
    path = checkpoint_path(job["id"])
    with path.open("a", encoding="utf-8") as handle:
        for item in buffer:
            handle.write(json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    job["_checkpoint_buffer"] = []


def checkpoint_result(job: dict, index: int) -> None:
    if index < 0 or index >= len(job.get("results", [])):
        return
    buffer = job.setdefault("_checkpoint_buffer", [])
    buffer.append({"i": int(index), "row": job["results"][index]})
    if len(buffer) >= CHECKPOINT_BATCH_SIZE:
        flush_result_checkpoints(job)


def replay_result_checkpoints(job: dict) -> int:
    path = checkpoint_path(str(job.get("id") or ""))
    if not path.exists():
        return 0
    applied = 0
    large = is_large_job(job)
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                    idx = int(item.get("i"))
                    row = item.get("row")
                except Exception:
                    continue
                if not isinstance(row, dict) or idx < 0 or idx >= len(job.get("results", [])):
                    continue
                job["results"][idx] = compact_failed_row(row) if large and row.get("available") is False else row
                applied += 1
    except Exception:
        return applied
    return applied


def rebuild_job_counters(job: dict) -> None:
    rows = [row for row in (job.get("results") or []) if isinstance(row, dict)]
    job["completed"] = sum(1 for row in rows if row.get("state") == "checked")
    job["available"] = sum(1 for row in rows if row.get("available") is True)
    job["generic_available"] = sum(1 for row in rows if row.get("generic_ok") is True)
    job["same_exit"] = sum(1 for row in rows if row.get("exit_match") == "same")
    job["runtime_completed"] = sum(1 for row in rows if row.get("available") is True and row.get("edt_available") is not None)
    job["runtime_available"] = sum(1 for row in rows if row.get("edt_available") is True)
    job["final_available"] = sum(1 for row in rows if row.get("final_available") is True)
    job["speed_completed"] = sum(1 for row in rows if isinstance(row.get("speed"), dict) and row.get("speed", {}).get("attempts") is not None)
    job["purity_completed"] = sum(1 for row in rows if isinstance(row.get("purity"), dict) and bool(row.get("purity")))


def compact_job_checkpoint(job: dict) -> None:
    flush_result_checkpoints(job)
    if is_large_job(job):
        # Large jobs keep the append-only journal as the durable full-detail source.
        # The JSON snapshot stores compact failed rows, avoiding a huge resident set.
        compact_large_job_rows(job)
    persist_job(job)
    if not is_large_job(job):
        try:
            checkpoint_path(job["id"]).unlink(missing_ok=True)
        except Exception:
            pass


def _extract_stub_scalar(prefix: str, key: str) -> Any:
    pattern = r'"{}"\s*:\s*(null|true|false|-?\d+(?:\.\d+)?|"(?:\\.|[^"\\])*")'.format(re.escape(key))
    match = re.search(pattern, prefix)
    if not match:
        return None
    try:
        return json.loads(match.group(1))
    except Exception:
        return None


def _scan_job_scalars(path: Path, keys: tuple[str, ...]) -> dict:
    """Stream-scan scalar fields without loading the huge results array."""
    wanted = set(keys)
    found: dict = {}
    overlap = ""
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            while wanted:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                text = overlap + chunk
                for key in list(wanted):
                    value = _extract_stub_scalar(text, key)
                    if value is not None:
                        found[key] = value
                        wanted.discard(key)
                overlap = text[-4096:]
    except Exception:
        pass
    return found


def _checkpoint_summary(job_id: str, total: int) -> dict:
    """Rebuild latest per-row counters from the append-only checkpoint using bounded memory."""
    path = checkpoint_path(job_id)
    if not path.exists() or total <= 0:
        return {}
    flags = bytearray(total)
    extra = bytearray(total)
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                try:
                    item = json.loads(line)
                    idx = int(item.get("i"))
                    row = item.get("row") or {}
                except Exception:
                    continue
                if idx < 0 or idx >= total or not isinstance(row, dict):
                    continue
                bits = 0
                if row.get("state") == "checked": bits |= 1
                if row.get("available") is True: bits |= 2
                if row.get("generic_ok") is True: bits |= 4
                if row.get("exit_match") == "same": bits |= 8
                if row.get("edt_available") is not None: bits |= 16
                if row.get("edt_available") is True: bits |= 32
                if row.get("final_available") is True: bits |= 64
                flags[idx] = bits
                xbits = 0
                speed = row.get("speed") or {}
                if isinstance(speed, dict) and speed.get("attempts") is not None: xbits |= 1
                purity = row.get("purity") or {}
                if isinstance(purity, dict) and bool(purity): xbits |= 2
                extra[idx] = xbits
    except Exception:
        return {}
    return {
        "completed": sum(1 for value in flags if value & 1),
        "available": sum(1 for value in flags if value & 2),
        "generic_available": sum(1 for value in flags if value & 4),
        "same_exit": sum(1 for value in flags if value & 8),
        "runtime_completed": sum(1 for value in flags if value & 16),
        "runtime_available": sum(1 for value in flags if value & 32),
        "final_available": sum(1 for value in flags if value & 64),
        "speed_completed": sum(1 for value in extra if value & 1),
        "purity_completed": sum(1 for value in extra if value & 2),
    }


def read_job_stub(path: Path) -> Optional[dict]:
    job_id = path.stem
    meta_path = job_meta_path(job_id)
    stub: dict = {}
    had_meta = False
    meta_changed = False
    try:
        if meta_path.exists():
            raw = json.loads(meta_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                stub = {key: raw.get(key) for key in JOB_META_FIELDS}
                had_meta = True
        # Old large jobs put targets/results before some summary scalars. Repair
        # missing metadata by streaming only scalar fields from the snapshot.
        if not stub or int(stub.get("total") or 0) <= 0:
            scanned = _scan_job_scalars(path, JOB_META_FIELDS)
            for key, value in scanned.items():
                if stub.get(key) is None or key in {"total", "created_at", "started_at", "candidate_region"}:
                    if stub.get(key) != value:
                        stub[key] = value
                        meta_changed = True
    except Exception:
        return None
    if str(stub.get("id") or job_id) != job_id:
        return None
    stub["id"] = job_id
    total = int(stub.get("total") or 0)
    old_state = str(stub.get("state") or "")
    interrupted_stage = str(stub.get("interrupted_stage") or "")
    resume_blocked = total > MAX_RESUME_ITEMS
    if resume_blocked:
        stub["resume_available"] = False

    # Stable completed/cancelled history already has authoritative metadata.
    # Replaying a large append-only checkpoint for every historical job at
    # process startup can delay Uvicorn from binding its socket for many seconds.
    # Only crash/interruption recovery needs the expensive checkpoint summary.
    needs_checkpoint_recovery = (
        not had_meta
        or (not resume_blocked and old_state in {"queued", "checking", "runtime_checking", "speeding", "purity_checking"})
        or (not resume_blocked and old_state == "interrupted" and interrupted_stage in {"queued", "checking"})
    )
    if needs_checkpoint_recovery and total > 0 and not resume_blocked:
        checkpoint = _checkpoint_summary(job_id, total)
        if checkpoint:
            for key, value in checkpoint.items():
                if stub.get(key) != value:
                    stub[key] = value
                    meta_changed = True

    if old_state in {"queued", "checking", "runtime_checking", "speeding", "purity_checking"}:
        stub["interrupted_stage"] = old_state
        stub["state"] = "interrupted"
        # If base scanning reached total but the process died during the stage
        # transition, resume still needs to run so run_job can enter EDT.
        stub["resume_available"] = (not resume_blocked) and old_state in {"checking", "queued"} and total > 0
        stub["finished_at"] = stub.get("finished_at") or now()
        if resume_blocked:
            stub["resume_available"] = False
        meta_changed = True
    elif old_state == "interrupted" and interrupted_stage in {"checking", "queued"} and total > 0:
        # Large interrupted jobs are metadata-only and must never rebuild targets/results.
        if resume_blocked:
            stub["resume_available"] = False
            meta_changed = True
        elif stub.get("resume_available") is not True:
            stub["resume_available"] = True
            meta_changed = True

    stub["_lazy"] = True
    stub["_lazy_path"] = str(path)
    # Avoid an fsync-heavy rewrite of every healthy history meta file at startup.
    if meta_changed or not had_meta:
        try:
            persist_job_meta(stub)
        except Exception:
            pass
    return stub


def _delete_job_files(job_id: str) -> int:
    deleted = 0
    for path in (job_path(job_id), job_meta_path(job_id), checkpoint_path(job_id)):
        try:
            if path.exists():
                path.unlink()
                deleted += 1
        except Exception:
            pass
    return deleted


def _job_runtime_is_active(job_id: str, job: Optional[dict] = None) -> bool:
    job = job if job is not None else JOBS.get(job_id)
    if job is not None and str(job.get("state") or "") in JOB_ACTIVE_STATES:
        return True
    tasks = [
        job.get("_task") if isinstance(job, dict) else None,
        POST_SPEED_TASKS.get(job_id),
        PURITY_TASKS.get(job_id),
    ]
    return any(task is not None and not task.done() for task in tasks)


def purge_job(job_id: str, *, collect: bool = True) -> dict:
    job_id = str(job_id or "").strip()
    job = JOBS.get(job_id)
    if _job_runtime_is_active(job_id, job):
        return {"deleted": False, "reason": "active", "deleted_files": 0}

    job = JOBS.pop(job_id, None)
    POST_SPEED_TASKS.pop(job_id, None)
    PURITY_TASKS.pop(job_id, None)
    deleted_files = _delete_job_files(job_id)

    if isinstance(job, dict):
        job.clear()

    if collect:
        gc.collect()

    return {
        "deleted": job is not None or deleted_files > 0,
        "reason": None,
        "deleted_files": deleted_files,
    }


def _job_ids_on_disk() -> set[str]:
    job_ids: set[str] = set()
    patterns = (
        re.compile(r"^([0-9a-f]{12})\.json$"),
        re.compile(r"^([0-9a-f]{12})\.meta\.json$"),
        re.compile(r"^([0-9a-f]{12})\.checkpoint\.jsonl$"),
    )
    try:
        for path in DATA_DIR.iterdir():
            for pattern in patterns:
                match = pattern.fullmatch(path.name)
                if match:
                    job_ids.add(match.group(1))
                    break
    except Exception:
        pass
    return job_ids


def purge_history_jobs() -> dict:
    deleted = 0
    deleted_files = 0
    skipped_active = 0
    job_ids = set(JOBS) | _job_ids_on_disk()

    for job_id in sorted(job_ids):
        result = purge_job(job_id, collect=False)
        if result.get("reason") == "active":
            skipped_active += 1
            continue
        if result.get("deleted"):
            deleted += 1
            deleted_files += int(result.get("deleted_files") or 0)

    gc.collect()
    return {
        "deleted": deleted,
        "deleted_files": deleted_files,
        "skipped_active": skipped_active,
    }


def _job_meta_is_expired(job_id: str, ts: Optional[float] = None) -> bool:
    meta_path = job_meta_path(job_id)
    if not meta_path.exists():
        return False
    try:
        raw = json.loads(meta_path.read_text(encoding="utf-8"))
        state = str(raw.get("state") or "")
        if state in JOB_ACTIVE_STATES:
            return False
        finished_at = float(raw.get("finished_at") or 0)
    except Exception:
        return False
    return finished_at > 0 and finished_at < (ts or now()) - JOB_RETENTION_SECONDS


def cleanup_expired_jobs() -> int:
    cutoff = now() - JOB_RETENTION_SECONDS
    removed = 0
    for job_id, job in list(JOBS.items()):
        state = str(job.get("state") or "")
        if state in JOB_ACTIVE_STATES:
            continue
        try:
            finished_at = float(job.get("finished_at") or 0)
        except Exception:
            finished_at = 0
        if finished_at <= 0 or finished_at >= cutoff:
            continue
        result = purge_job(job_id, collect=False)
        if result.get("deleted"):
            removed += 1
    if removed:
        gc.collect()
    return removed


def load_job_index() -> None:
    JOBS.clear()
    ts = now()
    for path in DATA_DIR.glob("*.json"):
        if not re.fullmatch(r"[0-9a-f]{12}\.json", path.name):
            continue
        job_id = path.stem
        if _job_meta_is_expired(job_id, ts):
            _delete_job_files(job_id)
            continue
        stub = read_job_stub(path)
        if stub:
            JOBS[stub["id"]] = stub
    cleanup_expired_jobs()


def hydrate_job(job_id: str) -> Optional[dict]:
    cleanup_expired_jobs()
    current = JOBS.get(job_id)
    if not current:
        return None
    if not current.get("_lazy"):
        return current
    if int(current.get("total") or 0) > MAX_RESUME_ITEMS:
        return None
    path = Path(str(current.get("_lazy_path") or job_path(job_id)))
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except Exception:
        return None
    if not isinstance(data, dict) or str(data.get("id") or "") != job_id:
        return None
    replay_result_checkpoints(data)
    compact_large_job_rows(data)
    rebuild_job_counters(data)
    # The lightweight startup index may have converted an in-flight state to interrupted.
    for key in ("state", "interrupted_stage", "resume_available", "finished_at"):
        if key in current and current.get(key) is not None:
            data[key] = current.get(key)
    data["_lazy_path"] = str(path)
    JOBS[job_id] = data
    return data


def release_job_memory(job: dict) -> None:
    state = str(job.get("state") or "")
    if state in JOB_ACTIVE_STATES:
        return
    try:
        flush_result_checkpoints(job)
        persist_job_meta(job)
    except Exception:
        pass
    job.pop("_task", None)
    job.pop("_checkpoint_buffer", None)
    if int(job.get("total") or 0) > MAX_RESUME_ITEMS and state == "interrupted":
        job.pop("targets", None)
        job.pop("results", None)
        job.pop("settings", None)
        job.pop("speed_session", None)
    stub = {key: job.get(key) for key in JOB_META_FIELDS}
    stub["_lazy"] = True
    stub["_lazy_path"] = str(job_path(str(job.get("id") or "")))
    JOBS[str(job.get("id") or "")] = stub
    gc.collect()


load_job_index()


async def _run_job_impl(job: dict) -> None:
    settings = job["settings"]
    targets = job["targets"]
    concurrency = settings["check_concurrency"]
    rebuild_job_counters(job)
    job["state"] = "checking"
    job["interrupted_stage"] = None
    job["resume_available"] = False
    job["started_at"] = job.get("started_at") or now()
    persist_job(job)

    pending_indices = [
        i for i, row in enumerate(job.get("results", []))
        if row.get("state") != "checked"
    ]
    next_index = 0
    index_lock = asyncio.Lock()

    async def worker_loop() -> None:
        nonlocal next_index
        while not job.get("cancel_requested"):
            async with index_lock:
                if next_index >= len(pending_indices):
                    return
                idx = pending_indices[next_index]
                next_index += 1
            raw = targets[idx]
            job["results"][idx]["state"] = "checking"
            result = await test_one(
                raw,
                settings["probe_sni"],
                settings["probe_path"],
                settings["expect_cloudflare"],
                settings["generic_sni"],
                settings["timeout"],
            )
            job["results"][idx] = result
            job["completed"] += 1
            if result.get("available"):
                job["available"] += 1
            if result.get("generic_ok") is True:
                job["generic_available"] += 1
            if result.get("exit_match") == "same":
                job["same_exit"] += 1
            checkpoint_result(job, idx)
            if is_large_job(job) and result.get("available") is False:
                job["results"][idx] = compact_failed_row(result)

    workers = [asyncio.create_task(worker_loop()) for _ in range(min(concurrency, len(targets)))]
    if workers:
        await asyncio.gather(*workers, return_exceptions=True)

    if job.get("cancel_requested"):
        for row in job["results"]:
            if row.get("state") in {"pending", "checking"}:
                row["state"] = "cancelled"
        job["state"] = "cancelled"
        job["finished_at"] = now()
        compact_job_checkpoint(job)
        release_job_memory(job)
        return

    runtime_cfg = settings.get("edt_runtime") or {}
    if runtime_cfg.get("enabled"):
        runtime_candidates = [i for i, r in enumerate(job["results"]) if isinstance(r, dict) and r.get("available") is True]
        for row in job["results"]:
            if row.get("available") is not True:
                row["final_available"] = False
                row["edt_available"] = None
        job["runtime_total"] = len(runtime_candidates)
        job["state"] = "runtime_checking"
        compact_job_checkpoint(job)
        runtime_index = 0
        runtime_lock = asyncio.Lock()

        async def runtime_worker_loop() -> None:
            nonlocal runtime_index
            while not job.get("cancel_requested"):
                async with runtime_lock:
                    if runtime_index >= len(runtime_candidates):
                        return
                    row_idx = runtime_candidates[runtime_index]
                    row = job["results"][row_idx]
                    runtime_index += 1
                row["state"] = "runtime_checking"
                runtime_result = await check_edt_runtime_selected(
                    row["candidate"], EDT_RUNTIME_CONFIG,
                    sni=settings.get("probe_sni", ""),
                    path=settings.get("probe_path", ""),
                    expect_cloudflare=settings.get("expect_cloudflare", True),
                    timeout=settings.get("timeout", DEFAULT_TIMEOUT),
                )
                row["edt_runtime"] = runtime_result
                row["edt_available"] = runtime_result.get("ok") is True
                row["final_available"] = row["edt_available"]
                row["state"] = "checked"
                if not row["edt_available"]:
                    row["error_stage"] = runtime_result.get("error_stage") or "edt_runtime"
                    row["error"] = runtime_result.get("error") or "EDT 真连接失败"
                job["runtime_completed"] += 1
                if row["edt_available"]:
                    job["runtime_available"] += 1
                    job["final_available"] += 1
                checkpoint_result(job, row_idx)

        runtime_workers = [
            asyncio.create_task(runtime_worker_loop())
            for _ in range(min(runtime_cfg.get("concurrency") or DEFAULT_EDT_RUNTIME_CONCURRENCY, len(runtime_candidates)))
        ]
        if runtime_workers:
            await asyncio.gather(*runtime_workers, return_exceptions=True)
    else:
        for row in job["results"]:
            row["edt_available"] = None
            row["final_available"] = row.get("available") is True
        job["final_available"] = job["available"]

    if job.get("cancel_requested"):
        for row in job["results"]:
            if row.get("state") == "runtime_checking":
                row["state"] = "cancelled"
        job["state"] = "cancelled"
        job["finished_at"] = now()
        persist_job(job)
        return

    # Enrich every base-available row so the "可进入EDT" category also shows
    # country / ASN / operator information even when EDT final verification fails.
    # Failed TCP/TLS rows remain excluded to avoid unnecessary lookups.
    geo_rows = [i for i, row in enumerate(job["results"]) if isinstance(row, dict) and row.get("available") is True]
    if geo_rows:
        geo_index = 0
        geo_lock = asyncio.Lock()

        async def geo_worker_loop() -> None:
            nonlocal geo_index
            while True:
                async with geo_lock:
                    if geo_index >= len(geo_rows):
                        return
                    row_idx = geo_rows[geo_index]
                    geo_index += 1
                row = job["results"][row_idx]
                try:
                    await enrich_result(row, DATA_DIR)
                except Exception:
                    pass
                checkpoint_result(job, row_idx)

        geo_workers = [asyncio.create_task(geo_worker_loop()) for _ in range(min(6, len(geo_rows)))]
        if geo_workers:
            await asyncio.gather(*geo_workers, return_exceptions=True)

    speed_cfg = settings["speed"]
    if speed_cfg["enabled"]:
        candidates = [i for i, r in enumerate(job["results"]) if isinstance(r, dict) and r.get("final_available") is True]
        job["speed_total"] = len(candidates)
        job["state"] = "speeding"
        persist_job(job)

        speed_index = 0
        speed_lock = asyncio.Lock()

        async def speed_worker_loop() -> None:
            nonlocal speed_index
            while not job.get("cancel_requested"):
                async with speed_lock:
                    if speed_index >= len(candidates):
                        return
                    row_idx = candidates[speed_index]
                    row = job["results"][row_idx]
                    speed_index += 1
                values: List[float] = []
                attempts: List[dict] = []
                for _ in range(speed_cfg["repeats"]):
                    if job.get("cancel_requested"):
                        break
                    one = await speed_test(
                        row["host"], row["port"], speed_cfg["sni"], speed_cfg["path"],
                        speed_cfg["bytes"], max(settings["timeout"], 20.0),
                    )
                    attempts.append(one)
                    if one.get("ok") and one.get("mbps") is not None:
                        values.append(float(one["mbps"]))
                row["speed"] = {
                    "mode": speed_cfg.get("mode", "quick"),
                    "bytes_per_attempt": speed_cfg["bytes"],
                    "attempts": attempts,
                    "avg_mbps": round(sum(values) / len(values), 2) if values else None,
                    "min_mbps": round(min(values), 2) if values else None,
                    "max_mbps": round(max(values), 2) if values else None,
                    "stability": round(min(values) / max(values), 3) if len(values) >= 2 and max(values) > 0 else None,
                }
                job["speed_completed"] += 1
                checkpoint_result(job, row_idx)

        speed_workers = [
            asyncio.create_task(speed_worker_loop())
            for _ in range(min(speed_cfg["concurrency"], len(candidates)))
        ]
        if speed_workers:
            await asyncio.gather(*speed_workers, return_exceptions=True)

    job["state"] = "cancelled" if job.get("cancel_requested") else "completed"
    job["finished_at"] = now()
    compact_job_checkpoint(job)
    release_job_memory(job)


async def run_job(job: dict) -> None:
    try:
        await _run_job_impl(job)
    except asyncio.CancelledError:
        job["cancel_requested"] = True
        job["state"] = "cancelled"
        job["finished_at"] = job.get("finished_at") or now()
        try:
            compact_job_checkpoint(job)
        except Exception:
            try:
                persist_job(job)
            except Exception:
                pass
        raise
    except Exception:
        previous_state = str(job.get("state") or "")
        if previous_state in {"queued", "checking", "runtime_checking", "speeding", "purity_checking"}:
            job["interrupted_stage"] = previous_state
        job["state"] = "interrupted"
        job["resume_available"] = previous_state in {"queued", "checking"} and int(job.get("total") or 0) > 0
        job["finished_at"] = now()
        try:
            compact_job_checkpoint(job)
        except Exception:
            try:
                persist_job(job)
            except Exception:
                pass
        raise
    finally:
        job.pop("_task", None)
        if str(job.get("state") or "") not in JOB_ACTIVE_STATES:
            release_job_memory(job)


def clean_import_target(raw: Any) -> str:
    """Remove common labels/comments while keeping the endpoint expression."""
    value = str(raw or "").strip().strip("\"'")
    if not value:
        return ""
    value = re.sub(r"^proxyip://", "", value, flags=re.I).strip()
    value = re.split(r"[#＃|｜]", value, maxsplit=1)[0].strip()
    return value


CIDR_IMPORT_RE = re.compile(
    r"(?<![0-9.])(?P<cidr>(?:\d{1,3}\.){3}\d{1,3}/\d{1,2})(?::(?P<ports>\d{1,5}(?:\s*,\s*\d{1,5})*))?"
)
MULTIPORT_IMPORT_RE = re.compile(
    r"^\s*(?P<ip>(?:\d{1,3}\.){3}\d{1,3}):(?P<ports>\d{1,5}(?:\s*,\s*\d{1,5})+)\s*$"
)
CSV_IP_PORT_RE = re.compile(
    r"^\s*(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s*[,，;；]\s*(?P<port>\d{1,5})(?:\s*[,，;；]|$)"
)
ENDPOINT_IMPORT_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])(?P<host>(?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+)(?::(?P<port>\d{1,5}))?"
)


def normalize_scan_ports(values: Any) -> List[int]:
    if values is None or values == "":
        return list(DEFAULT_SCAN_PORTS)
    if isinstance(values, str):
        parts = re.split(r"[\s,，;；]+", values.strip())
    elif isinstance(values, (list, tuple, set)):
        parts = list(values)
    else:
        raise ValueError("scan_ports must be a list or delimited string")
    ports: List[int] = []
    seen = set()
    for raw in parts:
        value = str(raw).strip()
        if not value:
            continue
        if not value.isdigit():
            raise ValueError("invalid scan port: {}".format(value))
        port = int(value)
        if not 1 <= port <= 65535:
            raise ValueError("port out of range: {}".format(port))
        if port not in seen:
            seen.add(port)
            ports.append(port)
    if not ports:
        raise ValueError("at least one scan port is required")
    return ports


def parse_import_ports(raw: Optional[str], default_ports: Optional[List[int]] = None) -> List[int]:
    if not raw:
        return normalize_scan_ports(default_ports if default_ports is not None else DEFAULT_SCAN_PORTS)
    return normalize_scan_ports(raw)


def expand_cidr_import(cidr: str, ports_raw: Optional[str], default_ports: Optional[List[int]] = None) -> List[str]:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError("invalid CIDR: {}".format(cidr)) from exc
    if network.version != 4:
        raise ValueError("CIDR batch import currently supports IPv4 only")
    ports = parse_import_ports(ports_raw, default_ports)
    expanded: List[str] = []
    for ip in network:
        if not public_ip_ok(str(ip)):
            raise ValueError("private/reserved IPs are blocked")
        for port in ports:
            expanded.append("{}:{}".format(ip, port))
    return expanded


def extract_import_targets(raw: Any, default_ports: Optional[List[int]] = None) -> List[str]:
    value = clean_import_target(raw)
    if not value:
        return []
    ports_for_bare = normalize_scan_ports(default_ports if default_ports is not None else DEFAULT_SCAN_PORTS)

    cidr_match = CIDR_IMPORT_RE.search(value)
    if cidr_match:
        return expand_cidr_import(cidr_match.group('cidr'), cidr_match.group('ports'), ports_for_bare)

    multiport_match = MULTIPORT_IMPORT_RE.match(value)
    if multiport_match:
        ip = multiport_match.group('ip')
        try:
            parsed_ip = ipaddress.ip_address(ip)
        except ValueError as exc:
            raise ValueError("invalid IPv4 target") from exc
        if parsed_ip.version != 4 or not public_ip_ok(ip):
            raise ValueError("private/reserved IPs are blocked")
        return ["{}:{}".format(ip, port) for port in parse_import_ports(multiport_match.group('ports'))]

    csv_match = CSV_IP_PORT_RE.search(value)
    if csv_match:
        return ["{}:{}".format(csv_match.group('ip'), csv_match.group('port'))]

    found: List[str] = []
    for match in ENDPOINT_IMPORT_RE.finditer(value):
        host = match.group('host')
        explicit_port = match.group('port')
        if explicit_port:
            found.append("{}:{}".format(host, explicit_port))
        else:
            for port in ports_for_bare:
                found.append("{}:{}".format(host, port))
    if found:
        return found

    # Preserve bracketed IPv6 and other legacy one-target input forms. IPv6 keeps
    # the legacy single-port parser because its colons cannot safely mean a port group.
    compact = re.split(r"\s+", value, maxsplit=1)[0].strip()
    return [compact] if compact else []


def normalized_targets(values: Any, default_ports: Optional[List[int]] = None) -> List[str]:
    ports_for_bare = normalize_scan_ports(default_ports if default_ports is not None else DEFAULT_SCAN_PORTS)
    if isinstance(values, str):
        raw_items = re.split(r"[\r\n;；]+", values)
    elif isinstance(values, list):
        raw_items = [str(v) for v in values]
    else:
        raise ValueError("targets must be a string or list")

    out: List[str] = []
    seen = set()
    for item in raw_items:
        for value in extract_import_targets(item, ports_for_bare):
            if not value:
                continue
            try:
                _, _, normalized = parse_target(value)
            except ValueError:
                normalized = value
            key = normalized.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(normalized)
    if not out:
        raise ValueError("no targets")
    return out


def import_preview(values: Any, default_ports: Optional[List[int]] = None) -> Tuple[int, List[str]]:
    ports_for_bare = normalize_scan_ports(default_ports if default_ports is not None else DEFAULT_SCAN_PORTS)
    if isinstance(values, str):
        raw_items = re.split(r"[\r\n;；]+", values)
    elif isinstance(values, list):
        raw_items = [str(v) for v in values]
    else:
        raise ValueError("targets must be a string or list")

    count = 0
    preview: List[str] = []
    seen = set()
    for item in raw_items:
        try:
            extracted = extract_import_targets(item, ports_for_bare)
        except ValueError:
            continue
        for value in extracted:
            try:
                _, _, normalized = parse_target(value)
            except ValueError:
                continue
            key = normalized.lower()
            if key in seen:
                continue
            seen.add(key)
            count += 1
            if len(preview) < 200:
                preview.append(normalized)
    return count, preview

def normalize_check_concurrency(value: Any) -> int:
    try:
        concurrency = int(value)
    except Exception:
        return DEFAULT_CHECK_CONCURRENCY
    return concurrency if concurrency in CHECK_CONCURRENCY_OPTIONS else DEFAULT_CHECK_CONCURRENCY


def clamp_int(value: Any, default: int, low: int, high: int) -> int:
    try:
        return max(low, min(high, int(value)))
    except Exception:
        return default


def clamp_float(value: Any, default: float, low: float, high: float) -> float:
    try:
        return max(low, min(high, float(value)))
    except Exception:
        return default


@app.get("/", response_class=HTMLResponse)
async def root() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
async def health() -> dict:
    return {"ok": True, "name": APP_NAME, "version": APP_VERSION, "jobs": len(JOBS)}


@app.post("/api/auth/login")
async def login(request: Request) -> JSONResponse:
    if not ADMIN_PASSWORD_HASH or not SESSION_SECRET:
        raise HTTPException(status_code=503, detail="admin authentication is not configured")
    ip = client_ip(request)
    if login_is_blocked(ip):
        raise HTTPException(status_code=429, detail="too many login failures; try again later")
    body = await request.json()
    username = str(body.get("username", ""))
    password = str(body.get("password", ""))
    if username != ADMIN_USER or not verify_password(password, ADMIN_PASSWORD_HASH):
        mark_login_failure(ip)
        raise HTTPException(status_code=401, detail="invalid username or password")
    clear_login_failures(ip)
    csrf = secrets.token_urlsafe(24)
    token = sign_session({"sub": ADMIN_USER, "exp": int(now()) + SESSION_TTL, "csrf": csrf})
    response = JSONResponse({"ok": True, "username": ADMIN_USER, "csrf": csrf})
    response.set_cookie(
        "proxyip_session", token, max_age=SESSION_TTL, httponly=True, secure=COOKIE_SECURE,
        samesite="strict", path="/",
    )
    return response


@app.post("/api/auth/logout")
async def logout() -> JSONResponse:
    response = JSONResponse({"ok": True})
    response.delete_cookie("proxyip_session", path="/")
    return response


@app.get("/api/auth/me")
async def me(request: Request) -> dict:
    payload = require_web_session(request)
    return {"authenticated": True, "username": payload["sub"], "csrf": payload.get("csrf", "")}


def require_csrf(request: Request, payload: dict) -> None:
    supplied = request.headers.get("x-csrf-token", "")
    expected = str(payload.get("csrf", ""))
    if not supplied or not expected or not secrets.compare_digest(supplied, expected):
        raise HTTPException(status_code=403, detail="invalid CSRF token")


@app.get("/api/config")
async def config(request: Request) -> dict:
    require_web_session(request)
    return {
        "default_probe_sni": DEFAULT_PROBE_SNI,
        "default_probe_path": DEFAULT_PROBE_PATH,
        "default_speed_sni": DEFAULT_SPEED_SNI,
        "default_speed_path": DEFAULT_SPEED_PATH,
        "default_check_concurrency": DEFAULT_CHECK_CONCURRENCY,
        "default_speed_concurrency": DEFAULT_SPEED_CONCURRENCY,
        "default_speed_bytes": DEFAULT_SPEED_BYTES,
        "default_speed_repeats": DEFAULT_SPEED_REPEATS,
        "check_concurrency_options": list(CHECK_CONCURRENCY_OPTIONS),
        "default_scan_ports": list(DEFAULT_SCAN_PORTS),
        "cloudflare_https_ports": list(CLOUDFLARE_HTTPS_PORTS),
        "purity_provider": "Ping0" if PING0_API_KEY else "IPPure",
        "purity_concurrency": DEFAULT_PURITY_CONCURRENCY,
        "edt_runtime_configured": edt_verification_configured(EDT_RUNTIME_CONFIG),
        "edt_verify_mode": EDT_VERIFY_MODE,
        "edt_remote_configured": edt_remote_configured(),
        "edt_runtime_target": f"{EDT_RUNTIME_CONFIG.target_host}:{EDT_RUNTIME_CONFIG.target_port}",
        "edt_runtime_path_template": EDT_RUNTIME_CONFIG.path_template,
        "edt_runtime_concurrency": DEFAULT_EDT_RUNTIME_CONCURRENCY,
    }


@app.post("/api/import/preview")
async def preview_import(request: Request) -> dict:
    payload = require_web_session(request)
    require_csrf(request, payload)
    body = await request.json()
    try:
        scan_ports = normalize_scan_ports(body.get("scan_ports"))
        valid, preview = import_preview(body.get("targets"), scan_ports)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"valid": valid, "preview": preview, "scan_ports": scan_ports}


@app.get("/api/jobs")
async def list_jobs(request: Request) -> dict:
    require_web_session(request)
    cleanup_expired_jobs()
    rows = []
    # History is metadata-only. Never hydrate full targets/results for listing.
    for job_id in list(JOBS):
        job = JOBS.get(job_id) or {}
        path = Path(str(job.get("_lazy_path") or job_path(job_id)))
        stub = read_job_stub(path) if path.exists() else job
        if stub:
            JOBS[job_id] = stub
        rows.append({k: stub.get(k) for k in ["id", "state", "interrupted_stage", "resume_available", "created_at", "started_at", "finished_at", "total", "completed", "available", "final_available", "runtime_total", "runtime_completed", "runtime_available", "speed_total", "speed_completed", "purity_total", "purity_completed"]})
    rows.sort(key=lambda x: x.get("created_at", 0) or 0, reverse=True)
    return {"jobs": rows[:100]}


@app.post("/api/jobs")
async def create_job(request: Request) -> dict:
    payload = require_web_session(request)
    require_csrf(request, payload)
    cleanup_expired_jobs()
    body = await request.json()
    try:
        scan_ports = normalize_scan_ports(body.get("scan_ports"))
        candidate_region = str(body.get("candidate_region") or "").strip().upper()
        if candidate_region:
            targets = await candidate_pool.get_pool_targets(candidate_region)
            if not targets:
                raise ValueError("candidate pool is empty")
        else:
            targets = normalized_targets(body.get("targets"), scan_ports)
        probe_sni = validate_sni(body.get("probe_sni") or DEFAULT_PROBE_SNI)
        probe_path = validate_path(body.get("probe_path") or DEFAULT_PROBE_PATH)
        generic_sni = str(body.get("generic_sni", "")).strip()
        if generic_sni:
            generic_sni = validate_sni(generic_sni)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    runtime_body = body.get("edt_runtime") or {}
    runtime_enabled = bool(runtime_body.get("enabled", False))
    if runtime_enabled and not edt_verification_configured(EDT_RUNTIME_CONFIG):
        raise HTTPException(status_code=503, detail="EDT 真连接验证尚未在服务器配置")
    runtime_concurrency = clamp_int(runtime_body.get("concurrency"), DEFAULT_EDT_RUNTIME_CONCURRENCY, 1, 50)

    speed_body = body.get("speed") or {}
    speed_enabled = bool(speed_body.get("enabled", False))
    speed_sni = str(speed_body.get("sni") or DEFAULT_SPEED_SNI).strip()
    if speed_enabled:
        try:
            speed_sni = validate_sni(speed_sni)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    speed_mode = "precise" if str(speed_body.get("mode") or "").lower() == "precise" else "quick"
    speed_profile = {"bytes": 20 * 1024 * 1024, "repeats": 3, "concurrency": 2} if speed_mode == "precise" else {"bytes": 5 * 1024 * 1024, "repeats": 3, "concurrency": 3}
    speed_bytes = speed_profile["bytes"]
    speed_repeats = speed_profile["repeats"]

    job_id = uuid.uuid4().hex[:12]
    job = {
        "id": job_id,
        "candidate_region": candidate_region or None,
        "created_at": now(), "started_at": None, "finished_at": None,
        "state": "queued", "cancel_requested": False, "interrupted_stage": None, "resume_available": False,
        "targets": targets, "total": len(targets), "completed": 0, "available": 0, "final_available": 0,
        "generic_available": 0, "same_exit": 0, "runtime_total": 0, "runtime_completed": 0, "runtime_available": 0,
        "speed_total": 0, "speed_completed": 0, "purity_total": 0, "purity_completed": 0,
        "settings": {
            "probe_sni": probe_sni, "probe_path": probe_path,
            "expect_cloudflare": bool(body.get("expect_cloudflare", True)),
            "generic_sni": generic_sni,
            "timeout": clamp_float(body.get("timeout"), DEFAULT_TIMEOUT, 2.0, 30.0),
            "check_concurrency": normalize_check_concurrency(body.get("check_concurrency")),
            "scan_ports": scan_ports,
            "edt_runtime": {"enabled": runtime_enabled, "concurrency": runtime_concurrency},
            "speed": {
                "enabled": speed_enabled,
                "mode": speed_mode,
                "sni": speed_sni,
                "path": validate_path(speed_body.get("path") or DEFAULT_SPEED_PATH),
                "bytes": speed_bytes,
                "repeats": speed_repeats,
                "concurrency": speed_profile["concurrency"],
            },
        },
        "results": [{"candidate": raw, "state": "pending"} for raw in targets],
    }
    JOBS[job_id] = job
    persist_job(job)
    job["_task"] = asyncio.create_task(run_job(job))
    return {"id": job_id, "state": job["state"], "total": len(targets), "scan_ports": scan_ports}




def _post_key(row: dict) -> str:
    return str(row.get("candidate") or row.get("input") or "").strip()


def _session_completed(session: dict) -> set[str]:
    values = session.get("completed") if isinstance(session, dict) else []
    return {str(value).strip() for value in (values or []) if str(value).strip()}


async def run_post_speed(job: dict, candidate_keys: set[str], mode: str) -> None:
    try:
        settings = job.get("settings") or {}
        old_speed = settings.get("speed") or {}
        mode = "precise" if str(mode or "").lower() == "precise" else "quick"
        profile = {"bytes": 20 * 1024 * 1024, "repeats": 3, "concurrency": 2} if mode == "precise" else {"bytes": 5 * 1024 * 1024, "repeats": 3, "concurrency": 3}
        speed_cfg = {
            "mode": mode,
            "sni": str(old_speed.get("sni") or DEFAULT_SPEED_SNI).strip(),
            "path": validate_path(old_speed.get("path") or DEFAULT_SPEED_PATH),
            "bytes": profile["bytes"],
            "repeats": profile["repeats"],
            "concurrency": profile["concurrency"],
        }
        if not speed_cfg["sni"]:
            raise RuntimeError("测速 SNI 未配置")

        session = job.get("speed_session") or {}
        completed = _session_completed(session)
        all_candidates = [
            row for row in job.get("results", [])
            if row.get("available") is True and _post_key(row) in candidate_keys
        ]
        all_keys = {_post_key(row) for row in all_candidates}
        completed.intersection_update(all_keys)
        candidates = [row for row in all_candidates if _post_key(row) not in completed]

        session.update({
            "targets": sorted(candidate_keys),
            "mode": mode,
            "completed": sorted(completed),
            "status": "running",
            "updated_at": now(),
        })
        session.setdefault("created_at", now())
        job["speed_session"] = session
        job["speed_total"] = len(all_candidates)
        job["speed_completed"] = len(completed)
        job["state"] = "speeding"
        job["finished_at"] = None
        persist_job(job)

        sem = asyncio.Semaphore(speed_cfg["concurrency"])
        progress_lock = asyncio.Lock()

        async def one_row(row: dict) -> None:
            key = _post_key(row)
            async with sem:
                if job.get("speed_pause_requested") or job.get("cancel_requested"):
                    return
                values: List[float] = []
                attempts: List[dict] = []
                for _ in range(speed_cfg["repeats"]):
                    if job.get("speed_pause_requested") or job.get("cancel_requested"):
                        break
                    one = await speed_test(
                        row["host"], row["port"], speed_cfg["sni"], speed_cfg["path"],
                        speed_cfg["bytes"], max(float(settings.get("timeout") or DEFAULT_TIMEOUT), 20.0),
                    )
                    attempts.append(one)
                    if one.get("ok") and one.get("mbps") is not None:
                        values.append(float(one["mbps"]))

                complete = len(attempts) >= speed_cfg["repeats"]
                if attempts:
                    row["speed"] = {
                        "mode": speed_cfg.get("mode", "quick"),
                        "bytes_per_attempt": speed_cfg["bytes"],
                        "attempts": attempts,
                        "avg_mbps": round(sum(values) / len(values), 2) if values else None,
                        "min_mbps": round(min(values), 2) if values else None,
                        "max_mbps": round(max(values), 2) if values else None,
                        "stability": round(min(values) / max(values), 3) if len(values) >= 2 and max(values) > 0 else None,
                        "complete": complete,
                    }
                if not complete:
                    persist_job(job)
                    return

                async with progress_lock:
                    completed.add(key)
                    session["completed"] = sorted(completed)
                    session["updated_at"] = now()
                    job["speed_completed"] = len(completed)
                    persist_job(job)

        await asyncio.gather(*(one_row(row) for row in candidates), return_exceptions=True)

        if len(completed) >= len(all_candidates):
            job["state"] = "completed"
            job["speed_pause_requested"] = False
            session["status"] = "completed"
            session["updated_at"] = now()
            job["finished_at"] = now()
        elif job.get("speed_pause_requested"):
            job["state"] = "speed_paused"
            session["status"] = "paused"
            session["updated_at"] = now()
            job["finished_at"] = None
        elif job.get("cancel_requested"):
            session["status"] = "stopping"
        else:
            job["state"] = "completed"
            session["status"] = "completed"
            session["updated_at"] = now()
            job["finished_at"] = now()
    except Exception as exc:
        job["state"] = "interrupted"
        job["speed_error"] = str(exc)[:200]
        job["finished_at"] = now()
    finally:
        persist_job(job)
        POST_SPEED_TASKS.pop(job.get("id", ""), None)
        release_job_memory(job)


@app.post("/api/jobs/{job_id}/resume-scan")
async def resume_interrupted_scan(job_id: str, request: Request) -> dict:
    payload = require_web_session(request)
    require_csrf(request, payload)
    job = hydrate_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    if job.get("state") != "interrupted" or job.get("interrupted_stage") not in {"checking", "queued"}:
        raise HTTPException(status_code=409, detail="当前任务不是可续扫的一级扫描")
    if int(job.get("total") or 0) > MAX_RESUME_ITEMS:
        job["resume_available"] = False
        persist_job_meta(job)
        raise HTTPException(status_code=409, detail="超大任务不支持自动恢复，请重新创建任务")
    pending = sum(1 for row in job.get("results", []) if row.get("state") != "checked")
    total = int(job.get("total") or 0)
    completed = int(job.get("completed") or 0)
    if pending <= 0 and not (total > 0 and completed >= total):
        raise HTTPException(status_code=409, detail="没有可恢复的扫描进度")
    job["cancel_requested"] = False
    job["finished_at"] = None
    job["resume_available"] = False
    persist_job(job)
    job["_task"] = asyncio.create_task(run_job(job))
    return {"ok": True, "id": job_id, "remaining": pending, "completed": job.get("completed", 0)}


@app.post("/api/jobs/{job_id}/speed")
async def speed_existing_results(job_id: str, request: Request) -> dict:
    payload = require_web_session(request)
    require_csrf(request, payload)
    job = hydrate_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    if job.get("state") in {"queued", "checking", "runtime_checking", "speeding", "purity_checking", "speed_paused", "purity_paused"}:
        raise HTTPException(status_code=409, detail="当前任务仍在运行或已暂停；请先继续或停止当前后处理任务")
    body = await request.json()
    requested = body.get("targets")
    if isinstance(requested, list) and requested:
        candidate_keys = {str(value).strip() for value in requested if str(value).strip()}
    else:
        candidate_keys = {
            _post_key(row) for row in job.get("results", []) if row.get("available") is True
        }
    matched = [
        row for row in job.get("results", [])
        if row.get("available") is True and _post_key(row) in candidate_keys
    ]
    if not matched:
        raise HTTPException(status_code=400, detail="当前范围没有可测速的基础可用/EDT候选节点")
    mode = "precise" if str(body.get("mode") or "").lower() == "precise" else "quick"
    matched_keys = {_post_key(row) for row in matched}
    job["cancel_requested"] = False
    job["speed_stopped"] = False
    job["speed_pause_requested"] = False
    job["speed_session"] = {
        "targets": sorted(matched_keys), "mode": mode, "completed": [],
        "status": "running", "created_at": now(), "updated_at": now(),
    }
    job["state"] = "speeding"
    job["speed_total"] = len(matched)
    job["speed_completed"] = 0
    job["finished_at"] = None
    persist_job(job)
    task = asyncio.create_task(run_post_speed(job, matched_keys, mode))
    POST_SPEED_TASKS[job_id] = task
    return {"ok": True, "id": job_id, "speed_total": len(matched), "state": "speeding"}


@app.post("/api/jobs/{job_id}/speed/pause")
async def pause_speed(job_id: str, request: Request) -> dict:
    payload = require_web_session(request)
    require_csrf(request, payload)
    job = hydrate_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    if job.get("state") != "speeding":
        raise HTTPException(status_code=409, detail="当前不在测速中")
    job["speed_pause_requested"] = True
    persist_job(job)
    task = POST_SPEED_TASKS.get(job_id)
    if task is not None and not task.done():
        await task
    return {
        "ok": True, "id": job_id, "state": job.get("state"),
        "speed_total": job.get("speed_total", 0), "speed_completed": job.get("speed_completed", 0),
    }


@app.post("/api/jobs/{job_id}/speed/resume")
async def resume_speed(job_id: str, request: Request) -> dict:
    payload = require_web_session(request)
    require_csrf(request, payload)
    job = hydrate_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    if job.get("state") != "speed_paused":
        raise HTTPException(status_code=409, detail="当前测速并未暂停")
    session = job.get("speed_session") or {}
    targets = {str(value).strip() for value in (session.get("targets") or []) if str(value).strip()}
    if not targets:
        raise HTTPException(status_code=409, detail="没有可恢复的测速会话")
    mode = "precise" if str(session.get("mode") or "").lower() == "precise" else "quick"
    job["cancel_requested"] = False
    job["speed_pause_requested"] = False
    job["speed_stopped"] = False
    job["state"] = "speeding"
    job["finished_at"] = None
    session["status"] = "running"
    session["updated_at"] = now()
    persist_job(job)
    task = asyncio.create_task(run_post_speed(job, targets, mode))
    POST_SPEED_TASKS[job_id] = task
    return {
        "ok": True, "id": job_id, "state": "speeding",
        "speed_total": job.get("speed_total", 0), "speed_completed": job.get("speed_completed", 0),
    }


async def run_post_purity(job: dict, candidate_keys: set[str], concurrency: int) -> None:
    try:
        settings = job.get("settings") or {}
        session = job.get("purity_session") or {}
        completed = _session_completed(session)
        all_candidates = [
            row for row in job.get("results", [])
            if row.get("host") and _post_key(row) in candidate_keys
        ]
        all_keys = {_post_key(row) for row in all_candidates}
        completed.intersection_update(all_keys)
        candidates = [row for row in all_candidates if _post_key(row) not in completed]
        concurrency = clamp_int(concurrency, DEFAULT_PURITY_CONCURRENCY, 1, 10)

        session.update({
            "targets": sorted(candidate_keys),
            "concurrency": concurrency,
            "completed": sorted(completed),
            "status": "running",
            "updated_at": now(),
        })
        session.setdefault("created_at", now())
        job["purity_session"] = session
        job["purity_total"] = len(all_candidates)
        job["purity_completed"] = len(completed)
        job["state"] = "purity_checking"
        job["finished_at"] = None
        persist_job(job)

        sem = asyncio.Semaphore(concurrency)
        progress_lock = asyncio.Lock()

        async def one_row(row: dict) -> None:
            key = _post_key(row)
            async with sem:
                if job.get("purity_pause_requested") or job.get("cancel_requested"):
                    return
                timeout = max(float(settings.get("timeout") or DEFAULT_TIMEOUT), 12.0)
                result = await check_purity(
                    str(row.get("host") or ""),
                    int(row.get("port") or 443),
                    row.get("exit_ip"),
                    PING0_API_KEY,
                    timeout,
                )
                row["purity"] = result
                async with progress_lock:
                    completed.add(key)
                    session["completed"] = sorted(completed)
                    session["updated_at"] = now()
                    job["purity_completed"] = len(completed)
                    persist_job(job)

        await asyncio.gather(*(one_row(row) for row in candidates), return_exceptions=True)

        if len(completed) >= len(all_candidates):
            job["state"] = "completed"
            job["purity_pause_requested"] = False
            session["status"] = "completed"
            session["updated_at"] = now()
            job["finished_at"] = now()
        elif job.get("purity_pause_requested"):
            job["state"] = "purity_paused"
            session["status"] = "paused"
            session["updated_at"] = now()
            job["finished_at"] = None
        elif job.get("cancel_requested"):
            session["status"] = "stopping"
        else:
            job["state"] = "completed"
            session["status"] = "completed"
            session["updated_at"] = now()
            job["finished_at"] = now()
    except Exception as exc:
        job["state"] = "interrupted"
        job["purity_error"] = str(exc)[:200]
        job["finished_at"] = now()
    finally:
        persist_job(job)
        PURITY_TASKS.pop(job.get("id", ""), None)
        release_job_memory(job)


@app.post("/api/jobs/{job_id}/purity")
async def purity_existing_results(job_id: str, request: Request) -> dict:
    payload = require_web_session(request)
    require_csrf(request, payload)
    job = hydrate_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    if job.get("state") in {"queued", "checking", "runtime_checking", "speeding", "purity_checking", "speed_paused", "purity_paused"}:
        raise HTTPException(status_code=409, detail="当前任务仍在运行或已暂停；请先继续或停止当前后处理任务")
    body = await request.json()
    requested = body.get("targets")
    if isinstance(requested, list) and requested:
        candidate_keys = {str(value).strip() for value in requested if str(value).strip()}
    else:
        candidate_keys = {
            _post_key(row) for row in job.get("results", []) if row.get("host")
        }
    matched = [
        row for row in job.get("results", [])
        if row.get("host") and _post_key(row) in candidate_keys
    ]
    if not matched:
        raise HTTPException(status_code=400, detail="当前范围没有可检测纯净度的 IP")
    concurrency = clamp_int(body.get("concurrency"), DEFAULT_PURITY_CONCURRENCY, 1, 10)
    matched_keys = {_post_key(row) for row in matched}
    job["cancel_requested"] = False
    job["purity_stopped"] = False
    job["purity_pause_requested"] = False
    job["purity_session"] = {
        "targets": sorted(matched_keys), "concurrency": concurrency, "completed": [],
        "status": "running", "created_at": now(), "updated_at": now(),
    }
    job["state"] = "purity_checking"
    job["purity_total"] = len(matched)
    job["purity_completed"] = 0
    job["finished_at"] = None
    persist_job(job)
    task = asyncio.create_task(run_post_purity(job, matched_keys, concurrency))
    PURITY_TASKS[job_id] = task
    return {"ok": True, "id": job_id, "purity_total": len(matched), "state": "purity_checking"}


@app.post("/api/jobs/{job_id}/purity/pause")
async def pause_purity(job_id: str, request: Request) -> dict:
    payload = require_web_session(request)
    require_csrf(request, payload)
    job = hydrate_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    if job.get("state") != "purity_checking":
        raise HTTPException(status_code=409, detail="当前不在纯净度检测中")
    job["purity_pause_requested"] = True
    persist_job(job)
    task = PURITY_TASKS.get(job_id)
    if task is not None and not task.done():
        await task
    return {
        "ok": True, "id": job_id, "state": job.get("state"),
        "purity_total": job.get("purity_total", 0), "purity_completed": job.get("purity_completed", 0),
    }


@app.post("/api/jobs/{job_id}/purity/resume")
async def resume_purity(job_id: str, request: Request) -> dict:
    payload = require_web_session(request)
    require_csrf(request, payload)
    job = hydrate_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    if job.get("state") != "purity_paused":
        raise HTTPException(status_code=409, detail="当前纯净度检测并未暂停")
    session = job.get("purity_session") or {}
    targets = {str(value).strip() for value in (session.get("targets") or []) if str(value).strip()}
    if not targets:
        raise HTTPException(status_code=409, detail="没有可恢复的纯净度检测会话")
    concurrency = clamp_int(session.get("concurrency"), DEFAULT_PURITY_CONCURRENCY, 1, 10)
    job["cancel_requested"] = False
    job["purity_pause_requested"] = False
    job["purity_stopped"] = False
    job["state"] = "purity_checking"
    job["finished_at"] = None
    session["status"] = "running"
    session["updated_at"] = now()
    persist_job(job)
    task = asyncio.create_task(run_post_purity(job, targets, concurrency))
    PURITY_TASKS[job_id] = task
    return {
        "ok": True, "id": job_id, "state": "purity_checking",
        "purity_total": job.get("purity_total", 0), "purity_completed": job.get("purity_completed", 0),
    }


JOB_SUMMARY_FIELDS = JOB_META_FIELDS


def job_summary(job: dict) -> dict:
    return {key: job.get(key) for key in JOB_SUMMARY_FIELDS}


def _result_key(row: dict) -> str:
    return str(row.get("candidate") or row.get("input") or "").strip()


def _result_region(row: dict, prefix: str) -> str:
    code = str(row.get(f"{prefix}_country_code") or "").strip().upper()
    if prefix == "exit" and not code:
        fallback = str(row.get("country") or "").strip()
        if len(fallback) == 2 and fallback.isalpha():
            code = fallback.upper()
    if len(code) == 2 and code.isalpha():
        return code
    raw = str(row.get(f"{prefix}_country") or "").strip()
    if prefix == "exit" and not raw:
        raw = str(row.get("country") or "").strip()
    if len(raw) == 2 and raw.isalpha():
        return raw.upper()
    return raw or "未识别"


def _purity_bucket_server(row: dict) -> str:
    purity = row.get("purity") or {}
    if not purity.get("ok"):
        return "unchecked"
    network_type = str(purity.get("network_type") or "")
    if network_type in {"家宽IP", "家宽/运营商IP"}:
        return "residential"
    if any(word in network_type for word in ("机房", "非家宽", "非住宅")):
        return "idc"
    return "other"


def _entry_type_match(row: dict, value: str) -> bool:
    if value == "all":
        return True
    if value == "cloudflare":
        return row.get("entry_is_cloudflare") is True
    if value == "vps":
        return row.get("entry_is_vps_idc") is True
    if value == "non_cf":
        return row.get("entry_is_cloudflare") is not True
    return True


def _facet_values(indexed_rows: list[tuple[int, dict]], prefix: str) -> list[dict]:
    counts: Dict[str, int] = {}
    for _, row in indexed_rows:
        value = _result_region(row, prefix)
        if not value or value == "未识别":
            continue
        counts[value] = counts.get(value, 0) + 1
    return [{"value": key, "count": counts[key]} for key in sorted(counts)]


def query_job_results(job: dict, body: dict) -> dict:
    status = str(body.get("status") or "all")
    entry = str(body.get("entry") or "all")
    exit_region = str(body.get("exit") or "all")
    entry_type = str(body.get("entry_type") or "all")
    purity_filter = str(body.get("purity") or "all")
    sort_mode = str(body.get("sort") or "default")
    selected = {str(value).strip() for value in (body.get("selected") or []) if str(value).strip()}
    scope_selected = {str(value).strip() for value in (body.get("scope_selected") or []) if str(value).strip()}

    base: list[tuple[int, dict]] = []
    for idx, row in enumerate(job.get("results", [])):
        # Pending rows never need to be transferred to the browser. Checked base rows
        # are visible immediately, even before EDT has finished.
        if row.get("available") is None and row.get("final_available") is None:
            continue
        if status == "edt_candidate" and row.get("available") is not True:
            continue
        if status == "available" and row.get("final_available") is not True:
            continue
        if status == "failed" and not (row.get("final_available") is False or row.get("available") is False):
            continue
        if status == "selected" and _result_key(row) not in selected:
            continue
        if not _entry_type_match(row, entry_type):
            continue
        if purity_filter != "all" and _purity_bucket_server(row) != purity_filter:
            continue
        if scope_selected and _result_key(row) not in scope_selected:
            continue
        base.append((idx, row))

    entry_base = base if exit_region == "all" else [item for item in base if _result_region(item[1], "exit") == exit_region]
    exit_base = base if entry == "all" else [item for item in base if _result_region(item[1], "entry") == entry]
    entry_facets = _facet_values(entry_base, "entry")
    exit_facets = _facet_values(exit_base, "exit")

    rows = base
    if entry != "all":
        rows = [item for item in rows if _result_region(item[1], "entry") == entry]
    if exit_region != "all":
        rows = [item for item in rows if _result_region(item[1], "exit") == exit_region]
    if body.get("final_only"):
        rows = [item for item in rows if item[1].get("final_available") is True]

    if sort_mode == "tcp":
        rows.sort(key=lambda item: item[1].get("tcp_ms") if item[1].get("tcp_ms") is not None else float("inf"))
    elif sort_mode == "tls":
        rows.sort(key=lambda item: item[1].get("tls_ms") if item[1].get("tls_ms") is not None else float("inf"))
    elif sort_mode == "speed":
        rows.sort(key=lambda item: -float((item[1].get("speed") or {}).get("avg_mbps") or -1))
    elif sort_mode == "purity":
        rows.sort(key=lambda item: float((item[1].get("purity") or {}).get("risk_score") if (item[1].get("purity") or {}).get("risk_score") is not None else 1e9))
    elif sort_mode == "entry_region":
        rows.sort(key=lambda item: _result_region(item[1], "entry"))
    elif sort_mode == "exit_region":
        rows.sort(key=lambda item: _result_region(item[1], "exit"))

    total = len(rows)
    if body.get("keys_only"):
        return {
            "keys": [_result_key(row) for _, row in rows if _result_key(row)],
            "total": total,
            "entry_facets": entry_facets,
            "exit_facets": exit_facets,
            "final_available_count": sum(1 for _, row in rows if row.get("final_available") is True),
        }

    page_size = clamp_int(body.get("page_size"), 50, 20, 200)
    if body.get("all_rows"):
        page = 1
        page_size = max(1, min(50000, total or 1))
    else:
        page = max(1, int(body.get("page") or 1))
    pages = max(1, (total + page_size - 1) // page_size)
    page = min(page, pages)
    start = (page - 1) * page_size
    view = rows[start:start + page_size]
    out_rows = []
    for idx, row in view:
        item = dict(row)
        item["_i"] = idx
        out_rows.append(item)
    return {
        "rows": out_rows,
        "total": total,
        "page": page,
        "pages": pages,
        "page_size": page_size,
        "entry_facets": entry_facets,
        "exit_facets": exit_facets,
        "final_available_count": sum(1 for _, row in rows if row.get("final_available") is True),
    }


@app.get("/api/jobs/{job_id}/summary")
async def get_job_summary(job_id: str, request: Request) -> dict:
    require_web_session(request)
    cleanup_expired_jobs()
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    if not job.get("_lazy"):
        flush_result_checkpoints(job)
    return job_summary(job)


@app.post("/api/jobs/{job_id}/results/query")
async def get_job_results_page(job_id: str, request: Request) -> dict:
    payload = require_web_session(request)
    require_csrf(request, payload)
    ref = JOBS.get(job_id)
    was_lazy = bool(ref and ref.get("_lazy"))
    job = hydrate_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    flush_result_checkpoints(job)
    body = await request.json()
    result = query_job_results(job, body if isinstance(body, dict) else {})
    if was_lazy:
        release_job_memory(job)
    return result


@app.get("/api/jobs/{job_id}")
async def get_job(job_id: str, request: Request) -> dict:
    require_web_session(request)
    ref = JOBS.get(job_id)
    was_lazy = bool(ref and ref.get("_lazy"))
    job = hydrate_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    safe = {k: v for k, v in job.items() if not str(k).startswith("_")}
    if was_lazy:
        release_job_memory(job)
    return safe


@app.post("/api/jobs/{job_id}/cancel")
async def cancel_job(job_id: str, request: Request) -> dict:
    payload = require_web_session(request)
    require_csrf(request, payload)
    job = hydrate_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")

    state = str(job.get("state") or "")

    # Speed/purity are post-processing stages on an already completed scan.
    # Stop them without turning the whole scan into a permanently cancelled job,
    # and wait for the old asyncio task to finish before allowing a restart.
    if state in {"speeding", "purity_checking", "speed_paused", "purity_paused"}:
        is_speed = state in {"speeding", "speed_paused"}
        job["cancel_requested"] = True
        task_map = POST_SPEED_TASKS if is_speed else PURITY_TASKS
        task = task_map.get(job_id)
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception:
                pass
        task_map.pop(job_id, None)
        session_name = "speed_session" if is_speed else "purity_session"
        session = job.get(session_name) or {}
        if session:
            session["status"] = "stopped"
            session["stopped_at"] = now()
        job["cancel_requested"] = False
        if is_speed:
            job["speed_pause_requested"] = False
            job["speed_stopped"] = True
        else:
            job["purity_pause_requested"] = False
            job["purity_stopped"] = True
        job["state"] = "completed"
        job["finished_at"] = now()
        persist_job(job)
        return {
            "ok": True,
            "id": job_id,
            "state": job.get("state"),
            "restartable": True,
        }

    # Cancelling the primary scan remains a real job cancellation.
    if state in {"queued", "checking", "runtime_checking"}:
        job["cancel_requested"] = True
        job["state"] = "cancelled"
        job["finished_at"] = now()
        persist_job(job)
        task = job.get("_task")
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception:
                pass
        else:
            compact_job_checkpoint(job)
            release_job_memory(job)
        return {"ok": True, "id": job_id, "state": "cancelled", "restartable": False}

    return {"ok": True, "id": job_id, "state": job.get("state"), "restartable": True}


@app.delete("/api/jobs")
async def delete_job_history(request: Request) -> dict:
    payload = require_web_session(request)
    require_csrf(request, payload)
    result = purge_history_jobs()
    return {"ok": True, **result}


@app.delete("/api/jobs/{job_id}")
async def delete_job(job_id: str, request: Request) -> dict:
    payload = require_web_session(request)
    require_csrf(request, payload)
    if job_id not in JOBS and not any(path.exists() for path in (job_path(job_id), job_meta_path(job_id), checkpoint_path(job_id))):
        raise HTTPException(status_code=404, detail="job not found")
    result = purge_job(job_id)
    if result.get("reason") == "active":
        raise HTTPException(status_code=409, detail="stop the job before deleting it")
    return {"ok": True, "id": job_id, **result}


@app.get("/api/jobs/{job_id}/export.csv")
async def export_csv(job_id: str, request: Request) -> Response:
    require_web_session(request)
    job = hydrate_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    output = io.StringIO()
    fields = [
        "IP", "端口", "可用", "Cloudflare可达", "连接延迟(ms)", "TLS延迟(ms)", "HTTP状态",
        "出口IP", "出口国家/地区", "Cloudflare机房", "通用SNI可用", "平均速度(Mbps)",
        "最低速度(Mbps)", "最高速度(Mbps)", "错误信息",
    ]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for row in job.get("results", []):
        speed = row.get("speed") or {}
        writer.writerow({
            "IP": row.get("host") or row.get("candidate"),
            "端口": row.get("port"),
            "可用": "是" if row.get("available") is True else ("否" if row.get("available") is False else ""),
            "Cloudflare可达": "是" if row.get("cloudflare_reached") is True else ("否" if row.get("cloudflare_reached") is False else ""),
            "连接延迟(ms)": row.get("tcp_ms"),
            "TLS延迟(ms)": row.get("tls_ms"),
            "HTTP状态": row.get("http_status"),
            "出口IP": row.get("exit_ip"),
            "出口国家/地区": row.get("country"),
            "Cloudflare机房": row.get("colo"),
            "通用SNI可用": "是" if row.get("generic_ok") is True else ("否" if row.get("generic_ok") is False else ""),
            "平均速度(Mbps)": speed.get("avg_mbps"),
            "最低速度(Mbps)": speed.get("min_mbps"),
            "最高速度(Mbps)": speed.get("max_mbps"),
            "错误信息": row.get("error"),
        })
    return Response(
        "\ufeff" + output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="proxyip-{}.csv"'.format(job_id)},
    )


@app.post("/api/integrations/edt/check")
async def edt_check(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    x_edt_token: Optional[str] = Header(default=None),
) -> dict:
    require_edt_token(authorization, x_edt_token)
    body = await request.json()
    proxyip = str(body.get("proxyip", "")).strip()
    sni = str(body.get("sni") or DEFAULT_PROBE_SNI).strip()
    path = str(body.get("path") or DEFAULT_PROBE_PATH).strip()
    if not proxyip:
        raise HTTPException(status_code=400, detail="proxyip is required")
    if not sni:
        raise HTTPException(status_code=400, detail="sni is required")
    result = await test_one(
        proxyip, sni, path, bool(body.get("expect_cloudflare", True)),
        str(body.get("generic_sni", "")).strip(),
        clamp_float(body.get("timeout"), DEFAULT_TIMEOUT, 2.0, 30.0),
    )
    base_available = bool(result.get("available"))
    runtime_result = None
    if base_available and EDT_RUNTIME_CONFIG.configured:
        runtime_result = await check_edt_runtime(result.get("candidate") or proxyip, EDT_RUNTIME_CONFIG)
    final_available = base_available and (runtime_result.get("ok") is True if runtime_result is not None else True)
    error_stage = result.get("error_stage")
    error = result.get("error")
    if base_available and runtime_result is not None and not final_available:
        error_stage = runtime_result.get("error_stage") or "edt_runtime"
        error = runtime_result.get("error") or "EDT 真连接失败"
    return {
        "success": final_available,
        "available": final_available,
        "base_available": base_available,
        "edt_runtime_ok": runtime_result.get("ok") if runtime_result is not None else None,
        "edt_runtime_ms": runtime_result.get("ms") if runtime_result is not None else None,
        "edt_runtime_target": runtime_result.get("target") if runtime_result is not None else None,
        "validation_mode": "external_vps_sni_tls_http+edt_runtime" if runtime_result is not None else "external_vps_sni_tls_http",
        "proxyip": result.get("candidate"),
        "sni": result.get("sni") or sni,
        "tcp_ms": result.get("tcp_ms"),
        "tls_ms": result.get("tls_ms"),
        "http_status": result.get("http_status"),
        "cloudflare_reached": bool(result.get("cloudflare_reached")),
        "exit_ip": result.get("exit_ip"),
        "country": result.get("country"),
        "colo": result.get("colo"),
        "exit_match": result.get("exit_match"),
        "generic_ok": result.get("generic_ok"),
        "error_stage": error_stage,
        "error": error,
    }


@app.post("/api/integrations/edt/check-batch")
async def edt_check_batch(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    x_edt_token: Optional[str] = Header(default=None),
) -> dict:
    require_edt_token(authorization, x_edt_token)
    body = await request.json()
    try:
        targets = normalized_targets(body.get("proxyips") or body.get("targets"))
        sni = validate_sni(body.get("sni") or DEFAULT_PROBE_SNI)
        path = validate_path(body.get("path") or DEFAULT_PROBE_PATH)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    concurrency = normalize_check_concurrency(body.get("concurrency"))
    timeout = clamp_float(body.get("timeout"), DEFAULT_TIMEOUT, 2.0, 30.0)
    results: List[Optional[dict]] = [None] * len(targets)
    batch_index = 0
    batch_lock = asyncio.Lock()

    async def batch_worker_loop() -> None:
        nonlocal batch_index
        while True:
            async with batch_lock:
                if batch_index >= len(targets):
                    return
                idx = batch_index
                raw = targets[idx]
                batch_index += 1
            results[idx] = await test_one(
                raw, sni, path, bool(body.get("expect_cloudflare", True)), "", timeout
            )

    batch_workers = [
        asyncio.create_task(batch_worker_loop())
        for _ in range(min(concurrency, len(targets)))
    ]
    if batch_workers:
        await asyncio.gather(*batch_workers)
    return {
        "validation_mode": "external_vps_sni_tls_http",
        "total": len(results), "available": sum(1 for r in results if r.get("available")),
        "results": results,
    }

# Candidate pool is configured after all auth/probe helpers and routes exist.
candidate_pool.configure(
    app,
    require_web_session,
    require_csrf,
    DATA_DIR,
    test_one,
    EDT_RUNTIME_CONFIG,
    DEFAULT_PROBE_SNI,
    DEFAULT_PROBE_PATH,
)

