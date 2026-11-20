#!/usr/bin/env python3
"""xAI-side oracle: is the writeback actually attached?

# Sanitized research copy. Ops/account/card/egress specifics removed.

POST.md 0x05 uses exactly this: never trust the Play UI, read xAI.
Runs on-device under the app uid (okhttp UA) so Cloudflare sees the app,
not your desktop. When the answer is HTML instead of JSON, treat it as a
miss and retry - the full engine also had a device-uid gRPC variant
(GetSubscriptions, empty body) for exactly that case.
"""
from __future__ import annotations

import json
import os
import subprocess
from typing import Any

PKG = "ai.x.grok"
SERIAL = os.environ.get("MUMU_SERIAL", "")


def _adb(*args: str, timeout: float = 35.0) -> str:
    r = subprocess.run(
        ["adb", *("-s", SERIAL), *args],
        capture_output=True, text=True, timeout=timeout, check=False,
    )
    return (r.stdout or "") + (r.stderr or "")


def _shell(cmd: str, timeout: float = 35.0) -> str:
    return _adb("shell", cmd, timeout=timeout)


def parse_subs_json(raw: str) -> dict[str, Any]:
    try:
        data = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return {"ok": False, "error": "bad_json", "raw": (raw or "")[:400]}
    if isinstance(data, dict) and data.get("code") in (16, "16"):
        return {"ok": False, "error": "unauthenticated", "raw": (raw or "")[:400], "rows": []}
    rows = data if isinstance(data, list) else data.get("subscriptions") or data.get("items") or []
    if not isinstance(rows, list):
        rows = []
    ultra_active = None
    for row in rows:
        if not isinstance(row, dict):
            continue
        sku = str(
            row.get("product") or row.get("productId") or row.get("sku")
            or (row.get("google") or {}).get("productId") or row.get("tier") or ""
        )
        status = str(row.get("status") or "").upper()
        is_active = status.endswith("STATUS_ACTIVE") or status == "ACTIVE"
        if is_active and ("ultra" in sku.lower() or "HEAVY" in sku):
            ultra_active = row
    cap = None
    if ultra_active:
        cap = ultra_active.get("cancelAtPeriodEnd", ultra_active.get("cancel_at_period_end"))
    return {
        "ok": True,
        "rows": rows,
        "ultra_active": ultra_active,
        "cancelAtPeriodEnd": cap,
        "has_ultra_active": ultra_active is not None,
    }


def leftover_ingest_ready(got: dict[str, Any] | None) -> bool:
    """grok.ultra STATUS_ACTIVE **and** cancelAtPeriodEnd. Both, or nothing."""
    box = got or {}
    return bool(box.get("has_ultra_active") and box.get("cancelAtPeriodEnd"))


def get_subs(jwt: str) -> dict[str, Any]:
    if not SERIAL:
        return {"ok": False, "error": "MUMU_SERIAL not set"}
    uid = _shell(f"stat -c %u /data/data/{PKG} 2>/dev/null").strip()
    if not uid.isdigit():
        return {"ok": False, "error": "no_app_uid"}
    resolve = ""
    pin = os.environ.get("GROK_CF_IP", "")  # optional --resolve pin
    if pin:
        resolve = f"--resolve grok.com:443:{pin} "
    script = (
        "#!/system/bin/sh\n"
        "curl -sS --max-time 20 "
        f"{resolve}"
        "-A okhttp/4.12.0 "
        f'-H "Cookie: sso={jwt}; sso-rw={jwt}" '
        '-H "Origin: https://grok.com" '
        '-H "Accept: application/json" '
        '"https://grok.com/rest/subscriptions?includeInactive=true"\n'
    )
    # write via shell heredoc-free path: echo base64 to avoid quoting pain
    import base64
    b64 = base64.b64encode(script.encode()).decode()
    _shell(
        f"echo {b64} | base64 -d > /data/data/{PKG}/cache/_oracle.sh "
        f"&& chmod 755 /data/data/{PKG}/cache/_oracle.sh "
        f"&& chown {uid}:{uid} /data/data/{PKG}/cache/_oracle.sh"
    )
    raw = _shell(f"su {uid} -c /data/data/{PKG}/cache/_oracle.sh")
    _shell(f"rm -f /data/data/{PKG}/cache/_oracle.sh")
    stripped = (raw or "").lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        box = parse_subs_json(raw)
        box["via"] = "device_uid"
        return box
    return {"ok": False, "error": "device_get_failed", "via": "device_uid", "raw": (raw or "")[:400]}
