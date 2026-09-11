import asyncio
import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict

from edt_runtime import check_edt_runtime

EDT_VERIFY_MODE = (os.environ.get("EDT_VERIFY_MODE", "local").strip().lower() or "local")
if EDT_VERIFY_MODE not in {"local", "remote"}:
    EDT_VERIFY_MODE = "local"
EDT_REMOTE_URL = os.environ.get("EDT_REMOTE_URL", "").strip().rstrip("/")
EDT_REMOTE_TOKEN = os.environ.get("EDT_REMOTE_TOKEN", "").strip()
try:
    EDT_REMOTE_TIMEOUT = max(3.0, min(60.0, float(os.environ.get("EDT_REMOTE_TIMEOUT", "15"))))
except Exception:
    EDT_REMOTE_TIMEOUT = 15.0


def edt_remote_configured() -> bool:
    return bool(EDT_REMOTE_URL and EDT_REMOTE_TOKEN)


def edt_verification_configured(local_cfg: Any) -> bool:
    if EDT_VERIFY_MODE == "remote":
        return edt_remote_configured()
    return bool(getattr(local_cfg, "configured", False))


def _remote_endpoint() -> str:
    if EDT_REMOTE_URL.endswith("/api/integrations/edt/check"):
        return EDT_REMOTE_URL
    return EDT_REMOTE_URL + "/api/integrations/edt/check"


def normalize_remote_response(data: Dict[str, Any]) -> Dict[str, Any]:
    edt_ok = data.get("edt_runtime_ok")
    base_ok = data.get("base_available") is True
    if edt_ok is None:
        detail = str(data.get("error") or "").strip()
        return {
            "configured": True,
            "ok": False,
            "error_stage": data.get("error_stage") or "edt_remote_config",
            "error": ("远程验证器未执行 EDT 真连接" + (": " + detail if detail else "")),
            "ms": data.get("edt_runtime_ms"),
            "target": data.get("edt_runtime_target"),
            "verifier_mode": "remote",
            "remote_base_available": base_ok,
            "remote_validation_mode": data.get("validation_mode"),
        }
    ok = edt_ok is True
    return {
        "configured": True,
        "ok": ok,
        "error_stage": None if ok else (data.get("error_stage") or "edt_runtime"),
        "error": None if ok else (data.get("error") or "EDT 真连接失败"),
        "ms": data.get("edt_runtime_ms"),
        "target": data.get("edt_runtime_target"),
        "verifier_mode": "remote",
        "remote_base_available": base_ok,
        "remote_validation_mode": data.get("validation_mode"),
    }


def _remote_check_sync(
    proxyip: str,
    sni: str,
    path: str,
    expect_cloudflare: bool,
    timeout: float,
) -> Dict[str, Any]:
    if not edt_remote_configured():
        return {
            "configured": False,
            "ok": False,
            "error_stage": "edt_remote_config",
            "error": "远程 EDT 验证未配置",
            "ms": None,
            "target": None,
            "verifier_mode": "remote",
        }
    payload: Dict[str, Any] = {
        "proxyip": proxyip,
        "expect_cloudflare": bool(expect_cloudflare),
        "timeout": max(2.0, min(30.0, float(timeout or 7.0))),
    }
    if sni:
        payload["sni"] = sni
    if path:
        payload["path"] = path
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        _remote_endpoint(),
        data=body,
        method="POST",
        headers={
            "Authorization": "Bearer " + EDT_REMOTE_TOKEN,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "ProxyIP-Scanner-EDT-Remote/1",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=EDT_REMOTE_TIMEOUT) as resp:
            raw = resp.read(1024 * 1024)
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("invalid JSON response")
        return normalize_remote_response(data)
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            raw = exc.read(64 * 1024)
            parsed = json.loads(raw.decode("utf-8"))
            if isinstance(parsed, dict):
                detail = str(parsed.get("detail") or parsed.get("error") or "")
        except Exception:
            pass
        return {
            "configured": True,
            "ok": False,
            "error_stage": "edt_remote_http",
            "error": "远程 EDT 验证 HTTP {}{}".format(exc.code, ": " + detail if detail else ""),
            "ms": None,
            "target": None,
            "verifier_mode": "remote",
        }
    except Exception as exc:
        return {
            "configured": True,
            "ok": False,
            "error_stage": "edt_remote",
            "error": "远程 EDT 验证失败: {}".format(exc),
            "ms": None,
            "target": None,
            "verifier_mode": "remote",
        }


async def check_edt_runtime_selected(
    proxyip: str,
    local_cfg: Any,
    *,
    sni: str = "",
    path: str = "",
    expect_cloudflare: bool = True,
    timeout: float = 7.0,
) -> Dict[str, Any]:
    if EDT_VERIFY_MODE != "remote":
        result = await check_edt_runtime(proxyip, local_cfg)
        if isinstance(result, dict):
            result.setdefault("verifier_mode", "local")
        return result
    return await asyncio.to_thread(
        _remote_check_sync,
        proxyip,
        str(sni or "").strip(),
        str(path or "").strip(),
        bool(expect_cloudflare),
        float(timeout or 7.0),
    )
