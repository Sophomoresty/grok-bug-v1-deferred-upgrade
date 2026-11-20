#!/usr/bin/env python3
# Sanitized research copy. Ops/account/card/egress specifics removed.
"""Attach a compiled wall hook to the Grok process and fire one rpc export.

Device serial comes from the MUMU_SERIAL env var (rule: no baked-in serials).
Compiled hooks live under ./work/hooks/ (frida-compile output, see README).

Usage:
    MUMU_SERIAL=127.0.0.1:16384 HOOK_JS=work/hooks/heavy_wall.compiled.js \
        python3 fire_heavy.py inspect|p1m|p3m|fromlite|g4 [arg]
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import frida

# Sanitized: ANDROID_SERIAL fallback kept for plain adb tooling; MUMU_SERIAL wins.
SERIAL = os.environ.get("MUMU_SERIAL") or os.environ.get("ANDROID_SERIAL", "127.0.0.1:5555")
CACHE = Path(os.environ.get("GROK_WORK", "./work")).resolve() / "hooks"
JS = os.environ.get("HOOK_JS", str(CACHE / "heavy_wall.compiled.js"))
if not os.path.isabs(JS):
    JS = str(CACHE / JS)
CMD = sys.argv[1] if len(sys.argv) > 1 else "inspect"
ARG = sys.argv[2] if len(sys.argv) > 2 else ""


def main() -> None:
    js = open(JS, encoding="utf-8").read()
    dm = frida.get_device_manager()
    dev = None
    for d in dm.enumerate_devices():
        if d.id == SERIAL or SERIAL in d.id:
            dev = d
            break
    if dev is None:
        try:
            dev = frida.get_device(SERIAL, timeout=8)
        except Exception:
            dev = frida.get_usb_device(timeout=8)
    pid = None
    for p in dev.enumerate_processes():
        if p.name in ("Grok", "ai.x.grok"):
            pid = p.pid
            break
    if pid is None:
        print(json.dumps({"ok": False, "err": "grok_not_running"}))
        sys.exit(2)
    session = dev.attach(pid)
    script = session.create_script(js)
    script.on("message", lambda m, d: print("MSG", m.get("payload") or m, flush=True))
    script.load()
    fn = getattr(script.exports_sync, CMD)
    needs_arg = (
        "destg4",
        "destg4p1m",
        "firstg4extras",
        "hopprofile",
        "hopxtid",
        "hopxtidonly",
        "hopoldidonly",
        "hopoldidtok",
        "hopprofilealign",
        "destfromlite",
        "ultranogid",
        "destp1m",
    )
    box = fn(ARG) if CMD in needs_arg and ARG else fn()
    print(json.dumps(box, ensure_ascii=False, default=str))
    time.sleep(1.2)
    session.detach()


if __name__ == "__main__":
    main()
