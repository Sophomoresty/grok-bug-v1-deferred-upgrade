#!/usr/bin/env python3
# Sanitized research copy. Ops/account/card/egress specifics removed.
"""Attended gate CLI for the deferred-replacement chain (from gate.py).

Human-in-the-loop only: every lite/fromlite/g4 wall is fired with
GROK_HOLD_SUBSCRIBE=1, screenshotted, and only subscribed after a human
reviews the shot (`sub`). Unattended batch entry points do not exist in this
copy.

Kept: shot / lite-wall / fromlite-wall / sub (screenshot -> HOLD ->
Subscribe tap -> password verify -> inspect oracle).
Removed (ops): login / bind / yearlite / classify card routing; password now
comes from the GOOGLE_PW env var (never a pool module); last4 from
CARD_LAST4 or --last4.

Usage:
    MUMU_SERIAL=127.0.0.1:16384 GOOGLE_PW=... CARD_LAST4=... \
    python3 gate_attended.py shot|lite-wall|fromlite-wall|sub [--hook H] [--last4 XXXX]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import billing_core as billing  # noqa: E402
from billing_core import device  # noqa: E402


def _print(box: dict[str, Any]) -> int:
    print(json.dumps(box, ensure_ascii=False), flush=True)
    return 0 if box.get("ok") else 1


def _dump_blob() -> tuple[str, str]:
    """Retry uiautomator; FLAG_SECURE first dump often times out empty."""
    blob = ""
    xml = ""
    for i in range(6):
        xml = device.dump_ui(force=True) or ""
        blob = device.ui_blob(xml) if xml else (device.ui_blob() or "")
        if blob.strip() or (xml and "<node" in xml):
            break
        time.sleep(0.8)
    dest = device.serial_dir() / "gate-shot.xml"
    dest.parent.mkdir(parents=True, exist_ok=True)
    if xml:
        dest.write_text(xml, encoding="utf-8")
    return blob, str(dest)


def cmd_shot(_: argparse.Namespace) -> int:
    """Screencap + dump + classify the current wall. Never taps anything."""
    png = device.screenshot("gate-shot.png")
    blob, xml_path = _dump_blob()
    foc = device.current_focus() or ""
    return _print(
        {
            "ok": True,
            "stage": "shot",
            "serial": device.serial(),
            "focus": foc[:180],
            "blob": blob[:500],
            "png": str(png),
            "xml": xml_path,
            # ops removed: card-bind form classifiers (bind_dump_is_native_us / allows_save)
            "gate_lite": billing.gate_lite(blob),
            "gate_heavy": billing.gate_heavy(blob),
        }
    )


def _after_sub_text() -> str:
    """OCR first. One dump. Empty dump is not wall-left.

    After a Subscribe tap on a 28KB Lite wall, six 0B dumps once killed the
    desk with lite_still_wall tapped=false. Do not retry empty dumps. OCR
    Processing / Payment successful / backup / Play Fest already left the
    wall; skip the dump storm entirely.
    """
    ocr = device.screen_text("gate-sub-after.png") or ""
    if billing.sub_after_ocr_settled(ocr):
        return ocr
    xml = device.dump_ui(force=True) or ""
    after = device.ui_blob(xml) if xml else ""
    if not after.strip():
        return ocr
    return f"{after}\n{ocr}"


def _save_wall(name: str) -> dict[str, str]:
    png = device.screenshot(f"{name}.png")
    blob, xml_path = _dump_blob()
    xml_named = device.serial_dir() / f"{name}.xml"
    if Path(xml_path).is_file():
        xml_named.write_text(Path(xml_path).read_text(encoding="utf-8"), encoding="utf-8")
    return {"png": str(png), "xml": str(xml_named), "blob": blob}


def cmd_lite_wall(args: argparse.Namespace) -> int:
    os.environ["GROK_HOLD_SUBSCRIBE"] = "1"
    hook = (args.hook or "").strip()
    if not hook:
        return _print({"ok": False, "stage": "lite_wall_hold", "error": "need_lite_hook"})
    last4 = (args.last4 or os.environ.get("CARD_LAST4") or "").strip()
    box = billing.buy_lite(hook, args.password or "", last4=last4)
    saved = _save_wall("lite-wall")
    box.update({k: saved[k] for k in ("png", "xml")})
    ui = saved.get("blob") or box.get("ui") or ""
    box["ui"] = ui[:500]
    box["gate"] = box.get("gate") or billing.gate_lite(ui)
    return _print(box)


def cmd_fromlite_wall(args: argparse.Namespace) -> int:
    os.environ["GROK_HOLD_SUBSCRIBE"] = "1"
    hook = (args.hook or "").strip()
    if not hook:
        return _print({"ok": False, "stage": "fromlite_wall_hold", "error": "need_heavy_hook"})
    last4 = (args.last4 or os.environ.get("CARD_LAST4") or "").strip()
    box = billing.buy_fromlite(hook, args.password or "", last4=last4, skip_pick=False)
    saved = _save_wall("fromlite-wall")
    box.update({k: saved[k] for k in ("png", "xml")})
    ui = saved.get("blob") or box.get("ui") or ""
    box["ui"] = ui[:500]
    if box.get("stage") in (
        "lite_not_paid",
        "fromlite_not_home",
        "fromlite_card",
        "fromlite_fire",
        "fromlite_frozen",
        "fromlite_cooldown",
        "fromlite_acquire",
        "fromlite_gid_mismatch",
        "fromlite_gate",
    ):
        return _print(box)
    fired = box.get("fire") or {}
    offer_gate = billing.fromlite_offer_ok(fired)
    box["offer_gate"] = offer_gate
    if not offer_gate.get("ok"):
        device.back(0.5)
        box["ok"] = False
        box["stage"] = "fromlite_gate"
        box["gate"] = {"ok": False, "kind": "fromlite_bad_offer", **offer_gate}
        return _print(box)
    gid_gate = billing.fromlite_account_ok(fired, hook, expected_gid=billing.load_lite_gid16())
    box["gid_gate"] = gid_gate
    if not gid_gate.get("ok"):
        device.back(0.5)
        box["ok"] = False
        box["stage"] = "fromlite_gid_mismatch"
        return _print(box)
    heavy = billing.gate_heavy(ui)
    box["gate"] = heavy
    if not heavy.get("ok"):
        device.back(0.5)
        box["ok"] = False
        if billing.fromlite_landed_play_hub(ui):
            billing.mark_fromlite_unavailable(last4, kind="fromlite_play_hub")
            box["stage"] = "fromlite_acquire"
            box["kind"] = "fromlite_play_hub"
            box["gate"] = {"ok": False, "kind": "fromlite_play_hub", "text": ui[:240]}
        else:
            box["stage"] = "fromlite_gate"
    return _print(box)


def _gate_password() -> str:
    """Play password for the Google on this device. Never printed.

    ops removed: pool credential store. Research copy reads GOOGLE_PW only.
    """
    return os.environ.get("GOOGLE_PW", "")


def cmd_sub(args: argparse.Namespace) -> int:
    """Tap Subscribe on a wall a human already reviewed via `shot`.

    Classification order: password sheet -> lite -> heavy. The tap is only
    issued when a gate passes; an empty dump keeps still_wall (empty dump is
    NOT wall-left).
    """
    ocr = device.screen_text("gate-sub.png") or ""
    blob = ocr
    gated = (
        billing.gate_lite(ocr).get("ok")
        or billing.gate_heavy(ocr).get("ok")
        or billing.flag_secure_password_sheet(ocr)
    )
    if not gated:
        raw = device.ui_blob() or ""
        blob = f"{raw}\n{ocr}"
    if billing.flag_secure_password_sheet(blob):
        pw = str(getattr(args, "password", "") or "").strip() or _gate_password()
        ver = billing.verify_google_password(pw) if pw else {"ok": False, "error": "need_password"}
        return _print(
            {
                "ok": bool(ver.get("ok")),
                "stage": "password_verify" if ver.get("ok") else "password_failed",
                "verify": {k: ver.get(k) for k in ("ok", "kind", "error")},
            }
        )
    lite = billing.gate_lite(blob)
    heavy = billing.gate_heavy(blob)
    if lite.get("ok"):
        tapped = billing.tap_subscribe()
        time.sleep(0.8)
        after = _after_sub_text()
        if billing.item_unavailable_text(after):
            return _print(
                {
                    "ok": False,
                    "stage": "item_unavailable",
                    "tapped": tapped,
                    "gate": lite,
                }
            )
        low_after = after.lower()
        if "payment successful" in low_after:
            return _print(
                {
                    "ok": True,
                    "stage": "lite_subscribe",
                    "tapped": tapped,
                    "gate": lite,
                    "verify": {"ok": True, "kind": "payment_successful"},
                }
            )
        if billing.sub_after_ocr_settled(after) or billing.flag_secure_password_sheet(after):
            row = billing.find_sku(billing.inspect(), "grok.lite") or {}
            if row.get("autoRenewing") is True:
                return _print(
                    {
                        "ok": True,
                        "stage": "lite_subscribe",
                        "tapped": tapped,
                        "gate": lite,
                        "verify": {"ok": True, "kind": "lite_ar"},
                    }
                )
        if billing.flag_secure_password_sheet(after):
            pw = str(getattr(args, "password", "") or "").strip() or _gate_password()
            ver = billing.verify_google_password(pw) if pw else {"ok": False, "error": "need_password"}
            if not ver.get("ok"):
                lite_ar = (billing.find_sku(billing.inspect(), "grok.lite") or {}).get("autoRenewing") is True
                if billing.lite_timeout_paid(str(ver.get("kind") or ""), lite_ar):
                    return _print(
                        {
                            "ok": True,
                            "stage": "lite_subscribe",
                            "tapped": tapped,
                            "gate": lite,
                            "verify": {"ok": True, "kind": "lite_ar"},
                        }
                    )
            return _print(
                {
                    "ok": bool(ver.get("ok")),
                    "stage": "lite_verify" if ver.get("ok") else "lite_password",
                    "tapped": tapped,
                    "gate": lite,
                    "verify": {k: ver.get(k) for k in ("ok", "kind", "error")},
                }
            )
        still = (
            billing.gate_lite(after).get("ok")
            or not after.strip()
        )
        # FLAG_SECURE: tap_subscribe returns False after the 1836 fallback
        # even when the wall left (a g4 once reported tapped=false, then the
        # Manage page showed Canceled + a new GPA AR=true). Empty dump is NOT
        # wall-left either: OCR after tap; an empty after-text keeps still=True.
        ok = not still
        return _print(
            {
                "ok": ok,
                "stage": "lite_subscribe" if ok else ("lite_still_wall" if still else "lite_subscribe_miss"),
                "tapped": tapped,
                "gate": lite,
            }
        )
    if heavy.get("ok"):
        tapped = billing.tap_subscribe()
        time.sleep(0.8)
        after = _after_sub_text()
        if billing.item_unavailable_text(after):
            return _print(
                {
                    "ok": False,
                    "stage": "item_unavailable",
                    "tapped": tapped,
                    "gate": heavy,
                }
            )
        if billing.flag_secure_password_sheet(after):
            pw = str(getattr(args, "password", "") or "").strip() or _gate_password()
            ver = billing.verify_google_password(pw) if pw else {"ok": False, "error": "need_password"}
            return _print(
                {
                    "ok": bool(ver.get("ok")),
                    "stage": "heavy_verify" if ver.get("ok") else "heavy_password",
                    "tapped": tapped,
                    "gate": heavy,
                    "verify": {k: ver.get(k) for k in ("ok", "kind", "error")},
                }
            )
        still = (
            billing.gate_heavy(after).get("ok")
            or not after.strip()
        )
        ok = not still
        return _print(
            {
                "ok": ok,
                "stage": "fromlite_subscribe" if ok else ("fromlite_still_wall" if still else "fromlite_subscribe_miss"),
                "tapped": tapped,
                "gate": heavy,
            }
        )
    return _print({"ok": False, "stage": "sub_blocked", "lite": lite, "heavy": heavy, "blob": blob[:300]})


def main() -> int:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("shot")
    lw = sub.add_parser("lite-wall")
    lw.add_argument("--hook", default="")
    lw.add_argument("--password", default="")
    lw.add_argument("--last4", default="")
    fw = sub.add_parser("fromlite-wall")
    fw.add_argument("--hook", default="")
    fw.add_argument("--password", default="")
    fw.add_argument("--last4", default="")
    sb = sub.add_parser("sub")
    sb.add_argument("--password", default="")
    args = p.parse_args()
    fn = {
        "shot": cmd_shot,
        "lite-wall": cmd_lite_wall,
        "fromlite-wall": cmd_fromlite_wall,
        "sub": cmd_sub,
    }[args.cmd]
    return fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
