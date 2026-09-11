import asyncio
import ipaddress
import os
import ssl
import time
import uuid
from dataclasses import dataclass
from urllib.parse import quote, urlsplit, urlunsplit

from websockets.asyncio.client import connect as ws_connect


@dataclass(frozen=True)
class EdtRuntimeConfig:
    worker_url: str
    user_id: str
    path_template: str
    target_host: str
    target_port: int
    target_sni: str
    target_path: str
    expected_status: int
    timeout: float

    @property
    def configured(self) -> bool:
        if not self.worker_url or not self.user_id or "{proxyip}" not in self.path_template:
            return False
        try:
            uuid.UUID(self.user_id)
            parsed = urlsplit(self.worker_url)
            return parsed.scheme in {"https", "wss"} and bool(parsed.netloc)
        except Exception:
            return False


def load_edt_runtime_config() -> EdtRuntimeConfig:
    # Use a non-Cloudflare target so a Cloudflare-facing endpoint cannot pass by
    # merely returning its own TLS ServerHello. The probe must complete a valid
    # TLS session to Google and receive the known generate_204 response.
    target_host = os.environ.get("EDT_RUNTIME_TARGET_HOST", "www.google.com").strip() or "www.google.com"
    try:
        target_port = int(os.environ.get("EDT_RUNTIME_TARGET_PORT", "443"))
    except Exception:
        target_port = 443
    target_path = os.environ.get("EDT_RUNTIME_TARGET_PATH", "/generate_204").strip() or "/generate_204"
    if not target_path.startswith("/"):
        target_path = "/" + target_path
    try:
        expected_status = int(os.environ.get("EDT_RUNTIME_EXPECT_STATUS", "204"))
    except Exception:
        expected_status = 204
    try:
        timeout = float(os.environ.get("EDT_RUNTIME_TIMEOUT", "10"))
    except Exception:
        timeout = 10.0
    return EdtRuntimeConfig(
        worker_url=os.environ.get("EDT_RUNTIME_WORKER_URL", "").strip().rstrip("/"),
        user_id=(os.environ.get("EDT_PROBE_UUID", "").strip() or os.environ.get("EDT_RUNTIME_UUID", "").strip()),
        path_template=os.environ.get("EDT_RUNTIME_PATH_TEMPLATE", "/forceproxyip={proxyip}").strip() or "/forceproxyip={proxyip}",
        target_host=target_host,
        target_port=max(1, min(65535, target_port)),
        target_sni=os.environ.get("EDT_RUNTIME_TARGET_SNI", target_host).strip() or target_host,
        target_path=target_path,
        expected_status=max(100, min(599, expected_status)),
        timeout=max(2.0, min(30.0, timeout)),
    )


def _vless_address(host: str) -> bytes:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        raw = host.encode("idna")
        if not raw or len(raw) > 255:
            raise ValueError("EDT runtime target hostname is invalid")
        return bytes([2, len(raw)]) + raw
    if ip.version == 4:
        return bytes([1]) + ip.packed
    return bytes([3]) + ip.packed


def _vless_request(user_id: str, host: str, port: int, payload: bytes) -> bytes:
    uid = uuid.UUID(user_id).bytes
    return b"\x00" + uid + b"\x00\x01" + int(port).to_bytes(2, "big") + _vless_address(host) + payload


def _runtime_ws_url(cfg: EdtRuntimeConfig, proxyip: str) -> str:
    parsed = urlsplit(cfg.worker_url)
    scheme = "wss" if parsed.scheme in {"https", "wss"} else "ws"
    encoded_proxy = quote(proxyip, safe="[]:.-_")
    path = cfg.path_template.replace("{proxyip}", encoded_proxy)
    if not path.startswith("/"):
        path = "/" + path
    return urlunsplit((scheme, parsed.netloc, path, "", ""))


class _VlessTunnelReader:
    def __init__(self, websocket, deadline: float):
        self.websocket = websocket
        self.deadline = deadline
        self.header_done = False
        self.buffer = bytearray()

    async def recv_payload(self) -> bytes:
        while True:
            remaining = self.deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise asyncio.TimeoutError
            message = await asyncio.wait_for(self.websocket.recv(), timeout=max(0.1, remaining))
            if isinstance(message, str):
                message = message.encode("utf-8", errors="replace")
            if not message:
                continue
            if self.header_done:
                return bytes(message)

            self.buffer.extend(message)
            if len(self.buffer) < 2:
                continue
            if self.buffer[0] != 0:
                raise RuntimeError("unexpected VLESS response version")
            offset = 2 + self.buffer[1]
            if len(self.buffer) < offset:
                continue
            payload = bytes(self.buffer[offset:])
            self.buffer.clear()
            self.header_done = True
            if payload:
                return payload


async def check_edt_runtime(proxyip: str, cfg: EdtRuntimeConfig) -> dict:
    started = time.perf_counter()
    base_result = {
        "configured": cfg.configured,
        "target": f"{cfg.target_host}:{cfg.target_port}",
        "target_sni": cfg.target_sni,
        "target_path": cfg.target_path,
        "expected_status": cfg.expected_status,
    }
    if not cfg.configured:
        return {
            **base_result,
            "ok": False,
            "error_stage": "config",
            "error": "EDT runtime verification is not configured",
            "ms": None,
        }

    ws_url = _runtime_ws_url(cfg, proxyip)
    try:
        context = ssl.create_default_context()
        incoming = ssl.MemoryBIO()
        outgoing = ssl.MemoryBIO()
        tls = context.wrap_bio(incoming, outgoing, server_side=False, server_hostname=cfg.target_sni)
        sent_vless_header = False
        deadline = asyncio.get_running_loop().time() + cfg.timeout

        async with ws_connect(
            ws_url,
            open_timeout=cfg.timeout,
            close_timeout=1,
            ping_interval=None,
            max_size=1024 * 1024,
        ) as websocket:
            tunnel_reader = _VlessTunnelReader(websocket, deadline)

            async def send_tls_bytes() -> None:
                nonlocal sent_vless_header
                while True:
                    data = outgoing.read()
                    if not data:
                        return
                    remaining = deadline - asyncio.get_running_loop().time()
                    if remaining <= 0:
                        raise asyncio.TimeoutError
                    if not sent_vless_header:
                        data = _vless_request(cfg.user_id, cfg.target_host, cfg.target_port, data)
                        sent_vless_header = True
                    await asyncio.wait_for(websocket.send(data), timeout=max(0.1, remaining))

            # Complete a real TLS handshake over the VLESS/WS tunnel. Certificate
            # validation is enabled by create_default_context(), so receiving any
            # arbitrary TLS record is no longer enough to pass.
            while True:
                try:
                    tls.do_handshake()
                    await send_tls_bytes()
                    break
                except ssl.SSLWantWriteError:
                    await send_tls_bytes()
                except ssl.SSLWantReadError:
                    await send_tls_bytes()
                    encrypted = await tunnel_reader.recv_payload()
                    incoming.write(encrypted)

            cert = tls.getpeercert() or {}
            cipher = tls.cipher()

            request = (
                f"GET {cfg.target_path} HTTP/1.1\r\n"
                f"Host: {cfg.target_host}\r\n"
                "User-Agent: ProxyIP-Scanner-EDT/2\r\n"
                "Accept: */*\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")

            offset = 0
            while offset < len(request):
                try:
                    offset += tls.write(request[offset:])
                    await send_tls_bytes()
                except ssl.SSLWantWriteError:
                    await send_tls_bytes()
                except ssl.SSLWantReadError:
                    await send_tls_bytes()
                    incoming.write(await tunnel_reader.recv_payload())

            plaintext = bytearray()
            http_status = None
            while asyncio.get_running_loop().time() < deadline:
                try:
                    chunk = tls.read(64 * 1024)
                    if chunk:
                        plaintext.extend(chunk)
                        if b"\r\n" in plaintext and http_status is None:
                            first_line = bytes(plaintext).split(b"\r\n", 1)[0].decode("ascii", errors="replace")
                            parts = first_line.split()
                            if len(parts) >= 2 and parts[0].startswith("HTTP/") and parts[1].isdigit():
                                http_status = int(parts[1])
                        if b"\r\n\r\n" in plaintext and http_status is not None:
                            ok = http_status == cfg.expected_status
                            return {
                                **base_result,
                                "ok": ok,
                                "error_stage": None if ok else "edt_runtime_http",
                                "error": None if ok else f"unexpected target HTTP status: {http_status}",
                                "ms": round((time.perf_counter() - started) * 1000, 1),
                                "http_status": http_status,
                                "response_bytes": len(plaintext),
                                "tls_version": tls.version(),
                                "tls_cipher": cipher[0] if cipher else None,
                                "peer_cert_subject": cert.get("subject"),
                            }
                    else:
                        incoming.write(await tunnel_reader.recv_payload())
                except ssl.SSLWantReadError:
                    await send_tls_bytes()
                    incoming.write(await tunnel_reader.recv_payload())
                except ssl.SSLWantWriteError:
                    await send_tls_bytes()
                except ssl.SSLEOFError:
                    break

            return {
                **base_result,
                "ok": False,
                "error_stage": "edt_runtime_http",
                "error": "TLS handshake succeeded but expected HTTP response was not received",
                "ms": round((time.perf_counter() - started) * 1000, 1),
                "http_status": http_status,
                "response_bytes": len(plaintext),
                "tls_version": tls.version(),
                "tls_cipher": cipher[0] if cipher else None,
                "peer_cert_subject": cert.get("subject"),
            }
    except asyncio.TimeoutError:
        return {
            **base_result,
            "ok": False,
            "error_stage": "edt_runtime_timeout",
            "error": "EDT real connection timed out",
            "ms": round((time.perf_counter() - started) * 1000, 1),
        }
    except ssl.SSLCertVerificationError as exc:
        return {
            **base_result,
            "ok": False,
            "error_stage": "edt_runtime_tls_verify",
            "error": f"target TLS certificate verification failed: {exc}",
            "ms": round((time.perf_counter() - started) * 1000, 1),
        }
    except ssl.SSLError as exc:
        return {
            **base_result,
            "ok": False,
            "error_stage": "edt_runtime_tls",
            "error": f"target TLS handshake failed: {exc}",
            "ms": round((time.perf_counter() - started) * 1000, 1),
        }
    except Exception as exc:
        return {
            **base_result,
            "ok": False,
            "error_stage": "edt_runtime",
            "error": str(exc),
            "ms": round((time.perf_counter() - started) * 1000, 1),
        }
