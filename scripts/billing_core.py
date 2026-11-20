#!/usr/bin/env python3
# Sanitized research copy. Ops/account/card/egress specifics removed.
"""Frida fire_heavy + Play wall gates + Cancel + 902 ack (mechanism core).

Trimmed from the original billing.py (~2800 lines). Kept here, complete and
readable: the frida fire pipeline, hook compile + GID/lite-token injection,
frida bundle size bump, GID dump paths (vending sqlite + in-app frida), wall
classification gates (lite / heavy / spinner / password sheet / play hub),
wait_wall, buy_lite / buy_fromlite (deferred lite->ultra replacement) /
buy_g4 writeback, cancel_grok, ack_token (IAB transact 902), and the
subscribe/verify helpers under them.

Removed (ops): inventory ingestion, card-platform freeze/topup
bookkeeping, per-Google park ledgers & cooldowns, cross-desk frida serial
locks, egress/DNS pinning, xAI GET subscription checks, and the account /
card / pool modules. Their call sites below are explicit no-op stubs
marked "# ops removed".

Device access is a trimmed adb shim (class DeviceShim below): serial from
MUMU_SERIAL, uiautomator dump parse, exec-out screencap + tesseract OCR,
input tap / su tap. OCR needs `tesseract` on PATH.
"""
from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

SCRIPTS = Path(__file__).resolve().parent
HOOK_SRC = SCRIPTS.parent / "hooks"
WORK = Path(os.environ.get("GROK_WORK", "./work")).resolve()
HOOKS = WORK / "hooks"  # frida-compile rejects entrypoints outside its project root
FIRE = SCRIPTS / "fire_heavy.py"
DUMP_GID = HOOK_SRC / "dump_gid.js"
DUMP_GID_COMPILED = HOOKS / "dump_gid.compiled.js"
LITE_JS = HOOK_SRC / "lite_wall.js"
HEAVY_JS = HOOK_SRC / "heavy_wall.js"
ACK_TMPL = HOOK_SRC / "ack_27008.js"
FRIDA_COMPILE = os.environ.get("FRIDA_COMPILE", "frida-compile")
TODAY_RE = re.compile(r"starting today|today\s*\$|今天\s*\$", re.I)
FIRST_RE = re.compile(r"first charge will occur|将于.{0,40}收取", re.I)
GID_RE = re.compile(r"[0-9a-f]{64}")


# ---------------------------------------------------------------- device shim
class DeviceShim:
    """Trimmed adb-backed device helper (from device.py, ops paths removed)."""

    PKG = "ai.x.grok"

    def serial(self) -> str:
        # Sanitized: no baked-in desk serials; MUMU_SERIAL (or ANDROID_SERIAL) only.
        return os.environ.get("MUMU_SERIAL") or os.environ.get("ANDROID_SERIAL") or ""

    def serial_slug(self) -> str:
        s = self.serial() or "default"
        return re.sub(r"[^0-9A-Za-z_.-]+", "_", s)

    def serial_dir(self) -> Path:
        d = WORK / self.serial_slug()
        d.mkdir(parents=True, exist_ok=True)
        return d

    def adb(self, *args: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["adb", "-s", self.serial(), *args],
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )

    def shell(self, cmd: str, timeout: int = 30, input_text: str | None = None) -> str:
        r = self.adb("shell", cmd, timeout=timeout)
        return (r.stdout or "") + (r.stderr or "")

    def grok_pid(self) -> str:
        return (self.shell("pidof ai.x.grok", timeout=8) or "").strip()

    # ---- ui dump ----
    def dump_ui(self, force: bool = False) -> str:
        remote = f"/data/local/tmp/_ui_{int(time.time() * 1000)}.xml"
        try:
            self.adb("shell", f"uiautomator dump {remote}", timeout=12)
            raw = self.adb("shell", f"cat {remote}", timeout=6).stdout or ""
            self.adb("shell", f"rm -f {remote}", timeout=4)
        except subprocess.TimeoutExpired:
            return ""
        return raw if (raw.startswith("<?xml") or "<hierarchy" in raw[:200]) else ""

    def nodes(self, xml: str | None = None) -> list[dict[str, Any]]:
        raw = self.dump_ui() if xml is None else xml
        out: list[dict[str, Any]] = []
        for m in re.finditer(r"<node\b[^>]*?/?>", raw):
            n = m.group(0)
            t = re.search(r'text="([^"]*)"', n)
            d = re.search(r'content-desc="([^"]*)"', n)
            b = re.search(r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', n)
            if not b:
                continue
            x1, y1, x2, y2 = map(int, b.groups())
            c = re.search(r'class="([^"]*)"', n)
            out.append(
                {
                    "text": t.group(1) if t else "",
                    "desc": d.group(1) if d else "",
                    "class": c.group(1) if c else "",
                    "clk": 'clickable="true"' in n,
                    "cx": (x1 + x2) // 2,
                    "cy": (y1 + y2) // 2,
                    "blob": f"{t.group(1) if t else ''}|{d.group(1) if d else ''}",
                }
            )
        return out

    def ui_blob(self, xml: str | None = None) -> str:
        return " | ".join(
            (n["text"] or n["desc"]).strip() for n in self.nodes(xml) if (n["text"] or n["desc"]).strip()
        )

    def find_text(self, *needles: str, xml: str | None = None) -> dict[str, Any] | None:
        for n in self.nodes(xml):
            blob = n["blob"].lower()
            if any(want.lower() in blob for want in needles):
                return n
        return None

    def find_exact_text(self, *labels: str, xml: str | None = None, min_y: int = 0) -> dict[str, Any] | None:
        """Exact node text/desc match; substring find_text hits TOS titles containing Accept."""
        want = {str(x).replace("&amp;", "&").strip().lower() for x in labels if x}
        hits = []
        for n in self.nodes(xml):
            if int(n.get("cy") or 0) < min_y:
                continue
            text = str(n.get("text") or "").replace("&amp;", "&").strip().lower()
            desc = str(n.get("desc") or "").replace("&amp;", "&").strip().lower()
            if text in want or desc in want:
                hits.append(n)
        if not hits:
            return None
        return max(hits, key=lambda x: int(x.get("cy") or 0))

    def find_all(self, *needles: str, xml: str | None = None) -> list[dict[str, Any]]:
        hits: list[dict[str, Any]] = []
        for n in self.nodes(xml):
            blob = n["blob"].lower()
            if any(want.lower() in blob for want in needles):
                hits.append(n)
        return hits

    # ---- input ----
    def tap(self, x: int, y: int, wait: float = 0.35) -> None:
        self.shell(f"input tap {x} {y}")
        if wait:
            time.sleep(wait)

    def su_tap(self, x: int, y: int, wait: float = 1.0) -> None:
        """NAF overlay sits above Play Subscribe; su input tap, then plain input tap fallback.

        adb-shell-root desks: `su -c` exits 1 and does nothing; plain input tap
        lands. Magisk desks: `su -c` returns 0 and still does nothing. Always
        follow with input tap.
        """
        rc = 124
        try:
            r = self.adb("shell", f"su -c 'input tap {int(x)} {int(y)}'", timeout=8)
            rc = r.returncode
        except subprocess.TimeoutExpired:
            rc = 124
        if rc != 0:
            try:
                self.adb("shell", f"input tap {int(x)} {int(y)}", timeout=8)
            except subprocess.TimeoutExpired:
                pass
        if wait:
            time.sleep(wait)

    def tap_text(self, *needles: str, wait: float = 1.2) -> bool:
        n = self.find_text(*needles)
        if not n:
            return False
        self.tap(n["cx"], n["cy"], wait)
        return True

    def tap_lowest(self, *needles: str, min_y: int = 1400, wait: float = 1.0) -> bool:
        hits = [n for n in self.find_all(*needles) if int(n.get("cy") or 0) >= min_y]
        if not hits:
            hits = self.find_all(*needles)
        if not hits:
            return False
        n = max(hits, key=lambda x: int(x.get("cy") or 0))
        self.tap(n["cx"], n["cy"], wait)
        return True

    def back(self, wait: float = 0.8) -> None:
        try:
            self.shell("input keyevent 4", timeout=8)
        except subprocess.TimeoutExpired:
            pass
        time.sleep(wait)

    def keyevent(self, code: int, wait: float = 0.4) -> None:
        self.shell(f"input keyevent {code}")
        time.sleep(wait)

    # ---- capture / OCR ----
    def screenshot(self, name: str = "now.png") -> Path:
        """FLAG_SECURE Play sheets black out `screencap /sdcard`; exec-out keeps pixels."""
        dest = self.serial_dir() / name
        data = b""
        try:
            r = subprocess.run(
                ["adb", "-s", self.serial(), "exec-out", "screencap", "-p"],
                capture_output=True,
                timeout=8,
                check=False,
            )
            data = r.stdout or b""
        except subprocess.TimeoutExpired:
            data = b""
        if data.startswith(b"\x89PNG"):
            dest.write_bytes(data)
            return dest
        return dest.with_name(dest.name + ".missing")

    def screen_text(self, name: str = "ocr.png") -> str:
        shot = self.screenshot(name)
        if not shot.exists() or shot.stat().st_size < 32:
            return ""
        try:
            r = subprocess.run(
                ["tesseract", str(shot), "stdout", "--psm", "6"],
                text=True,
                capture_output=True,
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return ""
        return ((r.stdout or "") + "\n" + (r.stderr or "")).strip()

    def ocr_find(self, needle: str, name: str = "ocr-find.png") -> dict[str, Any] | None:
        """tesseract tsv -> bounding box center for a text needle."""
        shot = self.screenshot(name)
        if not shot.exists() or shot.stat().st_size < 32:
            return None
        try:
            r = subprocess.run(
                ["tesseract", str(shot), "stdout", "tsv", "--psm", "6"],
                text=True,
                capture_output=True,
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        boxes: list[dict[str, Any]] = []
        for line in (r.stdout or "").splitlines()[1:]:
            parts = line.split("\t")
            if len(parts) < 12 or not (parts[11] or "").strip():
                continue
            try:
                conf = float(parts[10])
                left, top, w, h = int(parts[6]), int(parts[7]), int(parts[8]), int(parts[9])
            except ValueError:
                continue
            if conf < 30:
                continue
            boxes.append({"text": parts[11].strip(), "cx": left + w // 2, "cy": top + h // 2})
        hits = [b for b in boxes if needle.lower() in str(b["text"]).lower()]
        if hits:
            hits.sort(key=lambda b: int(b["cy"]))
            return hits[-1]
        return None

    # ---- ime ----
    def ensure_adb_ime(self) -> None:
        self.shell("settings put secure default_input_method com.android.adbkeyboard/.AdbIME")

    def hide_ime(self) -> None:
        self.keyevent(111, 0.3)  # ACTION_ESCAPE closes the soft keyboard

    def clear_field(self) -> None:
        self.shell("am broadcast -a ADB_CLEAR_TEXT")
        time.sleep(0.2)

    def type_text(self, text: str, wait: float = 0.5) -> None:
        safe = str(text).replace("'", "'\\''")
        self.shell(f"am broadcast -a ADB_INPUT_TEXT --es msg '{safe}'")
        time.sleep(wait)

    # ---- focus / play sheets ----
    def current_focus(self) -> str:
        raw = self.shell("dumpsys window displays")
        m = re.search(r"mCurrentFocus=Window\{[^ ]+ u0 ([^}]+)\}", raw)
        return m.group(1).strip() if m else ""

    def play_billing_focus(self, focus: str | None = None) -> bool:
        foc = (focus or self.current_focus()).lower()
        return any(k in foc for k in ("finsky.billing", "locktoportrait", "sheetuibuilder", "acquire"))

    def play_sheet_is_no_internet(self, text: str) -> bool:
        return "no internet" in (text or "").lower()

    def prepare_play_iap(self) -> dict[str, Any]:
        """Acquire needs VPN sockets. VPN lockdown makes GMS billing look like No internet."""
        self.shell("settings put global always_on_vpn_lockdown 0")
        self.shell("su -c 'ip rule del pref 9000; ip rule del pref 9001'")
        return {"ok": True, "lockdown": "0"}

    def recover_play_no_internet(self) -> bool:
        """Play IAP No internet is retryable. BACK aborts the acquire sheet."""
        if not self.play_sheet_is_no_internet(self.ui_blob() or ""):
            return False
        self.prepare_play_iap()
        n = self.find_text("Try again", "Try Again", "OK")
        if not n:
            self.su_tap(540, 1836, 0.8)
            return True
        self.su_tap(int(n.get("cx") or 540), int(n.get("cy") or 1836), 0.8)
        return True

    def play_egress(self) -> dict[str, Any]:
        # ops removed: egress country/IP probe (US_EGRESS is assumed pre-configured)
        return {}


device = DeviceShim()


# ------------------------------------------------- wall text classifiers
# (inlined from hop_oracle.py: pure text classification, mechanism not ops)
def skipg4_has_first_charge(text: str) -> bool:
    """Play dump 'Your first charge will occur on …' / 将于…收取."""
    low = str(text or "").lower()
    return "first charge will occur" in low or "收取" in low


def skipg4_wall_kind(text: str) -> str:
    """skipg4 subscribe wall classifier.

    Today $299 / Starting today $299 is CHARGE_FULL. $299 listed with no
    Today $0, no intro $99.99, and no first-charge copy is CHARGE_FULL.
    Starting Oct $299.99 plus first-charge copy is deferred restore, not
    CHARGE_FULL. leftover fromlite intro is $99.99 Starting Oct plus later $299.99.
    """
    low = str(text or "").lower()
    zero = "today $0" in low or "today $0.00" in low or "today  $0" in low
    today_full = (
        ("today $299" in low or "today $299.99" in low or "starting today" in low)
        and ("299.99" in low or "$299" in low)
        and not zero
    )
    if today_full:
        return "CHARGE_FULL"
    has_299 = "299.99" in low or "$299" in low
    intro_99 = "$99.99" in low or "99.99" in low.replace("299.99", "")
    if has_299 and not zero and not intro_99 and not skipg4_has_first_charge(text):
        return "CHARGE_FULL"
    return ""


def destg4_benefits_continue(blob: str) -> bool:
    """"You'll get these benefits if you subscribe" sheet. Tap Continue, then Subscribe."""
    low = (blob or "").lower()
    return "you'll get these benefits if you subscribe" in low or "you will get these benefits if you subscribe" in low


def playfest_prize_sheet(low: str) -> bool:
    return "play fest" in (low or "")


def cancel_authentication_required(blob: str) -> bool:
    """Play Manage subscription: Authentication is required. Sign in to your Google Account."""
    low = (blob or "").lower()
    if "no internet" in low:
        return False
    if "authentication is required" not in low:
        return False
    return "google account" in low or "sign in" in low


def cancel_server_error_dialog(blob: str) -> bool:
    """Play Error sheet: Server error. OCR often misses the OK label."""
    low = (blob or "").lower()
    if "server error" not in low:
        return False
    if "no internet" in low or "resubscribe" in low:
        return False
    return "error" in low


def cancel_no_internet_dialog(blob: str) -> bool:
    """Play Error sheet on Manage subscription: No internet connection + OK/Try again."""
    low = (blob or "").lower()
    if "no internet" not in low:
        return False
    return "ok" in low or "try again" in low


def cancel_stale_page_action(low: str, saw: list[str] | None = None) -> str:
    """done, wait, or continue for an already-canceled manage page.

    The washed GPA manage page (Canceled, will end, Resubscribe) is done only
    after this loop has itself tapped cancel_right or confirm; before that,
    keep waiting (the new GPA row sits under it).
    """
    text = (low or "").lower()
    finished = ("resubscribe" in text) or ("canceled" in text and "will end" in text)
    if not finished:
        return "continue"
    seen = list(saw or [])
    if "cancel_right" in seen or "confirm" in seen:
        return "done"
    if sum(1 for item in seen if item == "stale_canceled") >= 8:
        return "done"
    return "wait"


# ------------------------------------------------- ops-removed stubs
def hop_live_last4_on_list(shown: list[str] | None, want: str, avoid: str = "") -> str:
    # ops removed: remap-to-pool-card table; research copy never remaps off `want`.
    return ""


def hop_live_remap_wall_dump(want: str) -> bool:
    # ops removed: remap-to-pool-card table.
    return False


def remap_want_on_open_list(want: str, shown: list[str] | None, avoid: str = "") -> str:
    # ops removed: remap-to-pool-card table; keep the explicit want.
    return want


def mark_lite_paid(last4: str = "", order: str = "") -> dict[str, Any]:
    # ops removed: card-platform freeze bookkeeping after the Lite charge.
    return {"last4": str(last4 or ""), "order": str(order or ""), "frozen": False}


def lite_card_frozen(last4: str = "") -> bool:
    # ops removed: card-platform freeze lookup.
    return False


def fromlite_cooldown(last4: str = "") -> dict[str, Any]:
    # ops removed: per-Google item-cooldown ledger.
    return {"skip": False}


def mark_fromlite_unavailable(last4: str = "", order: str = "", kind: str = "item_unavailable") -> dict[str, Any]:
    # ops removed: per-Google park ledger (fromlite_unavailable.json).
    return {"parked": kind}


def ensure_play_dns() -> None:
    # ops removed: US egress/DNS pinning. US_EGRESS is assumed pre-configured.
    return None


def keep_leftover_ny() -> bool:
    # ops removed: pinned-egress desk routing. Always "keep" (no DNS rewrite).
    return True


def ensure_frida_server() -> None:
    """Start the on-device frida-server if pidof is empty (trimmed from hop.py)."""
    if (device.shell("pidof frida-server", timeout=8) or "").strip():
        return
    device.shell("setsid /data/local/tmp/frida-server >/dev/null 2>&1 &")
    time.sleep(1.0)


def accept_native_tos() -> dict[str, Any]:
    """Grok native TOS overlay: tap the exact Accept & Continue button, never Sign out.

    Trimmed from sso.py: TOS sits at cy~1681 with Sign out at cy~1819; a
    substring find_text("Accept") hits the title, so match button text exactly.
    """
    n = device.find_exact_text("Accept & Continue", "Accept and Continue")
    if not n:
        return {"ok": False, "err": "no_tos"}
    device.tap(int(n["cx"]), int(n["cy"]), 1.1)
    return {"ok": True, "tap": (int(n["cx"]), int(n["cy"]))}


# ------------------------------------------------- fire pipeline
def last_json(text: str) -> dict[str, Any]:
    for line in reversed((text or "").splitlines()):
        line = line.strip()
        if line.startswith("{") or line.startswith("["):
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                return parsed
    return {"ok": False, "error": "no_json", "raw": (text or "")[-500:]}


def _uv_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = os.environ.copy()
    env["ANDROID_SERIAL"] = device.serial()
    if extra:
        env.update(extra)
    return env


def _run_fire(
    argv: list[str], extra: dict[str, str], timeout: int
) -> subprocess.CompletedProcess[str]:
    """Run fire_heavy.py in its own process group.

    A subprocess.run TimeoutExpired otherwise leaves fire_heavy.py alive 2+ min
    (attach hung, screen still Ask). Kill the group, return fire_timeout.
    """
    p = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=str(HOOKS),
        env=_uv_env(extra),
        start_new_session=True,
    )
    try:
        stdout, stderr = p.communicate(timeout=timeout)
        return subprocess.CompletedProcess(argv, p.returncode, stdout, stderr)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            p.kill()
        except OSError:
            pass
        try:
            stdout, stderr = p.communicate(timeout=3)
        except Exception:
            stdout, stderr = "", ""
        err = ((stderr or "") + "\n" + (stdout or "") + "\nfire_timeout")[-800:]
        return subprocess.CompletedProcess(argv, -9, stdout or "", err)


def fire(cmd: str, hook: str | None = None, timeout: int = 70, arg: str | None = None) -> dict[str, Any]:
    # ops removed: cross-desk frida serial lock (line_lock.frida_serial) around g4.
    return _fire_run(cmd, hook=hook, timeout=timeout, arg=arg)


def _fire_run(cmd: str, hook: str | None = None, timeout: int = 70, arg: str | None = None) -> dict[str, Any]:
    # An empty pidof frida-server made fire p1m return in 0.33s with no JSON
    # while the screen stayed on Ask; every fire must ensure the server first.
    ensure_frida_server()
    if not device.grok_pid():
        device.shell("am start -n ai.x.grok/.main.GrokActivity")
        time.sleep(2.0)
        if not device.grok_pid():
            return {"ok": False, "err": "grok_not_running"}
    extra = {}
    if hook:
        extra["HOOK_JS"] = hook
    argv = ["uv", "run", "--with", "frida-tools", "python3", str(FIRE), cmd]
    if arg:
        argv.append(arg)
    r = _run_fire(argv, extra, timeout)
    err = (r.stderr or "") + "\n" + (r.stdout or "")
    if r.returncode != 0 and ("timeout was reached" in err or "TransportError" in err):
        device.shell("am force-stop ai.x.grok")
        time.sleep(1.2)
        device.shell("am start -n ai.x.grok/.main.GrokActivity")
        time.sleep(3.0)
        r = _run_fire(argv, extra, timeout)
        err = (r.stderr or "") + "\n" + (r.stdout or "")
    box = last_json(err)
    box["_rc"] = r.returncode
    if r.returncode == -9 or "fire_timeout" in err:
        box.setdefault("ok", False)
        box.setdefault("err", "fire_timeout")
        box["cmd"] = cmd
        return box
    if r.returncode != 0 and box.get("ok") is not False:
        box.setdefault("ok", False)
        box.setdefault("error", err[-240:])
    return box


# ------------------------------------------------- hook compile + patch
def compile_js(src: Path, dest: Path) -> dict[str, Any]:
    dest.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(
        [FRIDA_COMPILE, str(src), "-o", str(dest)],
        capture_output=True,
        text=True,
        timeout=40,
        cwd=str(HOOKS),
        check=False,
    )
    ok = dest.exists() and dest.stat().st_size > 100 and r.returncode == 0
    return {"ok": ok, "src": str(src), "dest": str(dest), "stderr": (r.stderr or "")[-200:]}


_ULTRA_TOKEN_RE = re.compile(r"""var FALLBACK_ULTRA_TOKEN = (['"])[^'"]*\1""")


def _bump_frida_bundle_size(original: str, patched: str) -> str:
    """frida-compile bundles declare each module's byte size.

    Patching FALLBACK_ULTRA_TOKEN inside heavy_wall.live.compiled.js grows the
    module but leaves the `494882 /serial/ultra-base/heavy_wall.live.js` header;
    create_script then raises InvalidArgumentError malformed package and fire
    returns in ~1s with no JSON while the screen is still Ask / Imagine.
    """
    if not original.startswith("\U0001F4E6\n") or not patched.startswith("\U0001F4E6\n"):
        return patched
    delta = len(patched.encode("utf-8")) - len(original.encode("utf-8"))
    if delta == 0:
        return patched
    lines = patched.split("\n")
    for i in range(1, len(lines)):
        line = lines[i]
        if " " not in line or not line.split(" ", 1)[0].isdigit():
            break
        size_s, path = line.split(" ", 1)
        if path.endswith("/heavy_wall.live.js"):
            lines[i] = f"{int(size_s) + delta} {path}"
            return "\n".join(lines)
    return patched


def patch_ultra_token_js(text: str, token: str) -> str | None:
    """Put a library purchase token into a compiled hook. Empty e2 still needs it."""
    tok = re.sub(r"[^A-Za-z0-9._\-]", "", token or "")
    if len(tok) < 20 or not _ULTRA_TOKEN_RE.search(text or ""):
        return None
    patched = _ULTRA_TOKEN_RE.sub(f'var FALLBACK_ULTRA_TOKEN = "{tok}"', text, count=1)
    if tok not in patched:
        return None
    return _bump_frida_bundle_size(text, patched)


def hook_with_ultra_token(token: str, work: Path) -> Path | None:
    """Compile the ultra fallback once, then write a per-run hook. Token stays in work."""
    tok = re.sub(r"[^A-Za-z0-9._\-]", "", token or "")
    if len(tok) < 20:
        return None
    work.mkdir(parents=True, exist_ok=True)
    compiled = HOOKS / "heavy_wall.live.compiled.js"
    base = ""
    if compiled.exists():
        base = compiled.read_text(encoding="utf-8")
    if "FALLBACK_ULTRA_TOKEN" not in base:
        # frida-compile rejects an entrypoint outside the hooks project.
        boxed = HOOKS / "serial" / "ultra-base"
        boxed.mkdir(parents=True, exist_ok=True)
        src = boxed / "heavy_wall.live.js"
        raw = HEAVY_JS.read_text(encoding="utf-8")
        if "FALLBACK_ULTRA_TOKEN" not in raw:
            return None
        src.write_text(raw, encoding="utf-8")
        out = boxed / "heavy_wall.live.compiled.js"
        box = compile_js(src, out)
        if not box.get("ok"):
            (work / "compile-err.txt").write_text(str(box.get("stderr") or "")[-400:], encoding="utf-8")
            return None
        base = out.read_text(encoding="utf-8")
        compiled.write_text(base, encoding="utf-8")
    patched = patch_ultra_token_js(base, tok)
    if not patched:
        return None
    dest = work / "heavy_wall.ultra.compiled.js"
    dest.write_text(patched, encoding="utf-8")
    return dest


def patch_gid(src: Path, dest: Path, gid: str, lite_token: str = "") -> None:
    text = src.read_text(encoding="utf-8")
    text = re.sub(r"var GID = '[0-9a-f]{64}'", f"var GID = '{gid}'", text)
    text = re.sub(r"var gid = '[0-9a-f]{64}'", f"var gid = '{gid}'", text)
    if "FALLBACK_LITE_TOKEN" in text:
        tok = re.sub(r"[^A-Za-z0-9._\-]", "", str(lite_token or ""))
        text = re.sub(r"var FALLBACK_LITE_TOKEN = '[^']*'", f"var FALLBACK_LITE_TOKEN = '{tok}'", text)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, encoding="utf-8")


# ------------------------------------------------- GID dump
def _gid_from_box(box: dict[str, Any]) -> str:
    gid = str(box.get("gid") or "")
    if GID_RE.fullmatch(gid):
        return gid
    blob = json.dumps(box, default=str)
    m = re.search(r"obfuscated(?:Account)?Id[=:]([0-9a-f]{64})", blob, re.I)
    if m:
        return m.group(1)
    m = GID_RE.search(blob)
    return m.group(0) if m else ""


def dump_gid_from_vending() -> dict[str, Any]:
    # adb shell is already root. Wrapping sqlite3 returns an empty string.
    raw = device.shell(
        "sqlite3 /data/data/com.android.vending/databases/library.db "
        "\"SELECT inapp_purchase_data FROM ownership WHERE doc_id LIKE '%grok%' "
        "ORDER BY purchase_time DESC;\"",
        timeout=8,
    )
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line:
            continue
        gid = ""
        sku = ""
        order = ""
        try:
            jo = json.loads(line)
            gid = str(jo.get("obfuscatedAccountId") or "")
            sku = str(jo.get("productId") or "")
            order = str(jo.get("orderId") or "")
        except json.JSONDecodeError:
            m = re.search(r'"obfuscatedAccountId"\s*:\s*"([0-9a-f]{64})"', line)
            gid = m.group(1) if m else ""
            sm = re.search(r'"productId"\s*:\s*"([^"]+)"', line)
            sku = sm.group(1) if sm else ""
        if GID_RE.fullmatch(gid):
            return {"ok": True, "gid": gid, "from": "vending", "sku": sku, "order": order}
    return {"ok": False, "err": "no_vending_gid"}


def dump_gid(*, allow_vending: bool = False) -> dict[str, Any]:
    # ops removed: cross-desk frida dump lock (line_lock.frida_dump).
    if allow_vending:
        vend = dump_gid_from_vending()
        if vend.get("ok"):
            return vend
    return _dump_gid_frida()


def _dump_gid_frida() -> dict[str, Any]:
    # frida-compile rejects an entrypoint outside the hooks project root.
    staged = HOOKS / "dump_gid.js"
    src = DUMP_GID.read_text(encoding="utf-8")
    stale = (not staged.exists()) or staged.read_text(encoding="utf-8") != src
    if stale or not DUMP_GID_COMPILED.exists():
        staged.write_text(src, encoding="utf-8")
        compiled = compile_js(staged, DUMP_GID_COMPILED)
        if not compiled.get("ok"):
            return {"ok": False, "err": "dump_gid_compile", "stderr": compiled.get("stderr")}
    if not device.grok_pid():
        device.shell("am start -n ai.x.grok/.main.GrokActivity")
        time.sleep(2.8)
    else:
        time.sleep(0.6)
    box: dict[str, Any] = {"ok": False}
    try:
        r = subprocess.run(
            [
                "uv",
                "run",
                "--with",
                "frida-tools",
                "python3",
                "-c",
                (
                    "import frida,os,json,sys;"
                    "s=os.environ['ANDROID_SERIAL'];"
                    "js=open(os.environ['JS']).read();"
                    "dm=frida.get_device_manager();"
                    "dev=next((d for d in dm.enumerate_devices() if s in d.id), None) or frida.get_device(s, timeout=8);"
                    "pid=next((p.pid for p in dev.enumerate_processes() if p.name in ('Grok','ai.x.grok')), None);"
                    "print(json.dumps({'ok':False,'err':'grok_not_running'})) if pid is None else None;"
                    "sys.exit(2) if pid is None else None;"
                    "sess=dev.attach(pid); sc=sess.create_script(js); sc.load();"
                    "box=sc.exports_sync.inspect(); print(json.dumps(box, default=str)); sess.detach()"
                ),
            ],
            capture_output=True,
            text=True,
            timeout=22,
            env=_uv_env({"JS": str(DUMP_GID_COMPILED)}),
            check=False,
        )
        box = last_json((r.stdout or "") + "\n" + (r.stderr or ""))
    except subprocess.TimeoutExpired:
        box = {"ok": False, "err": "dump_gid_timeout"}
    gid = _gid_from_box(box)
    if not GID_RE.fullmatch(gid):
        compiled = HOOKS / "heavy_wall.compiled.js"
        hook = str(compiled) if compiled.exists() else None
        insp = fire("inspect", hook=hook, timeout=35)
        gid = _gid_from_box(insp)
        if not GID_RE.fullmatch(gid):
            for p in purchases(insp):
                obf = str(p.get("obfuscatedAccountId") or "")
                if GID_RE.fullmatch(obf):
                    gid = obf
                    break
        box = {"ok": bool(GID_RE.fullmatch(gid)), "from": "inspect", "inspect": {"ok": insp.get("ok")}, "err": box.get("err")}
    box["gid"] = gid
    box["ok"] = bool(GID_RE.fullmatch(gid))
    return box


def prepare_hooks(gid: str, work: Path, lite_token: str = "") -> dict[str, Any]:
    """Compile GID into serial-scoped files (two concurrent workers race a shared live.js)."""
    work.mkdir(parents=True, exist_ok=True)
    slug = device.serial_slug()
    boxed = HOOKS / "serial" / slug
    boxed.mkdir(parents=True, exist_ok=True)
    lite_src = boxed / "lite_wall.live.js"
    heavy_src = boxed / "heavy_wall.live.js"
    lite_out = boxed / "lite_wall.live.compiled.js"
    heavy_out = boxed / "heavy_wall.live.compiled.js"
    patch_gid(LITE_JS, lite_src, gid)
    patch_gid(HEAVY_JS, heavy_src, gid, lite_token=lite_token)
    (work / "gid.txt").write_text(gid)
    (boxed / "gid.txt").write_text(gid)
    if lite_token:
        (work / "lite-token-head.txt").write_text(str(lite_token)[:24])
    a = compile_js(lite_src, lite_out)
    b = compile_js(heavy_src, heavy_out)
    ok = bool(a.get("ok") and b.get("ok"))
    return {
        "ok": ok,
        "gid": gid,
        "lite": str(lite_out),
        "heavy": str(heavy_out),
        "serial": slug,
        "compile": [a, b],
    }


# ------------------------------------------------- wall text / gates
def wall_text(name: str = "wall.png") -> str:
    dump = device.ui_blob() or ""
    ocr = device.screen_text(name) or ""
    return f"{dump}\n{ocr}"


def sub_after_ocr_settled(ocr: str) -> bool:
    """Subscribe left the wall. Extra uiautomator dumps do not change the gate.

    OCR Processing, then 8-14 more dumps, was a common pattern before the
    password sheet settled; the dumps add nothing.
    """
    low = (ocr or "").lower()
    return any(
        k in low
        for k in (
            "processing",
            "payment successful",
            "turn on backup",
            "play fest",
            "not now",
        )
    )


def lite_timeout_paid(verify_kind: str, lite_ar: bool | None) -> bool:
    """lite_password timeout_continue with grok.lite AR=true is paid."""
    return str(verify_kind or "") == "timeout_continue" and lite_ar is True


def gate_lite(text: str) -> dict[str, Any]:
    low = text.lower()
    if any(k in low for k in ("99.99", "299.99", "$99", "$299")):
        return {"ok": False, "kind": "CHARGE_FULL", "text": text[:240]}
    lite = "lite" in low or "supergrok lite" in low
    today = bool(TODAY_RE.search(text)) and ("9.99" in low or "9,99" in low)
    if lite and today:
        return {"ok": True, "kind": "lite_today", "text": text[:240]}
    if "start by adding a payment method" in low or "add a payment method" in low:
        return {"ok": False, "kind": "need_bind", "text": text[:240]}
    return {"ok": False, "kind": "unknown", "text": text[:240]}


_OCT25_2026 = re.compile(r"oct\s*25,?\s*2026", re.I)
_INTRO_99 = re.compile(r"(?<![\d.])\$99\.99")


def item_unavailable_text(text: str) -> bool:
    """Acquire dialog after Subscribe. Wall-left is not a paid upgrade."""
    return "the item you requested is not available" in (text or "").lower()


def oct25_item_wall(text: str) -> bool:
    """fromlite intro that Subscribe turns into item.

    Starting Oct 25, 2026 $99.99, first charge Oct 25, no Today $. Every such
    wall returned item. A $299.99-only g4 wall is not this.
    """
    raw = text or ""
    if not _OCT25_2026.search(raw):
        return False
    if _INTRO_99.search(raw):
        return True
    low = raw.lower()
    return "3-month" in low and "$299.99" in raw


def gate_heavy(text: str) -> dict[str, Any]:
    low = text.lower()
    kind = skipg4_wall_kind(text)
    # g4: $299.99 Starting Oct + first charge later is deferred $0 today.
    # Full-price restore has no first-charge copy.
    if kind == "CHARGE_FULL" and not FIRST_RE.search(text):
        return {"ok": False, "kind": "CHARGE_FULL", "text": text[:240]}
    if oct25_item_wall(text):
        return {"ok": False, "kind": "oct25_item_wall", "text": text[:240]}
    if "unable to change your subscription plan" in low:
        return {"ok": False, "kind": "unable_change", "text": text[:240]}
    if TODAY_RE.search(text):
        if "today $0" in low or "today $0.00" in low:
            return {"ok": True, "kind": "deferred", "text": text[:240]}
        if "9.99" in low and "lite" in low:
            return {"ok": False, "kind": "wrong_sku_lite", "text": text[:240]}
        if any(k in low for k in ("99.99", "299.99", "$99", "$299", "today $")):
            return {"ok": False, "kind": "CHARGE_FULL", "text": text[:240]}
    if FIRST_RE.search(text) and not TODAY_RE.search(text):
        return {"ok": True, "kind": "deferred", "text": text[:240]}
    if FIRST_RE.search(text) and "today" not in low:
        return {"ok": True, "kind": "deferred", "text": text[:240]}
    return {"ok": False, "kind": "unknown", "text": text[:240]}


def wall_dump_is_spinner(raw: str, ocr: str = "") -> bool:
    """Play billing sheet is the ProgressBar spinner, not a Subscribe wall.

    A 6659-byte dump with android:id/progress and OCR garbage is still
    loading. Keep waiting; do not treat OCR garbage as the wall (force-stop
    then moves LockToPortrait onto Play For you and it never lists).
    """
    blob = f"{raw or ''}\n{ocr or ''}".lower()
    if any(
        k in blob
        for k in (
            "subscribe",
            "supergrok",
            "add a payment",
            "starting today",
            "mastercard-",
            "visa-",
        )
    ):
        return False
    return "android:id/progress" in (raw or "") or "progressbar" in blob


def wall_is_ready(text: str) -> bool:
    """Subscribe wall is up. FLAG_SECURE dump may omit Subscribe; Starting Oct is deferred Heavy.

    Starting Oct $299 without first-charge / Today $ is not ready: the wall
    below showed "Your first charge will occur on Oct 18" while the wait_wall
    OCR truncated before that line and the caller classified CHARGE_FULL.
    """
    low = (text or "").lower()
    if not ("supergrok" in low or "grok ai" in low or "grok al" in low):
        return False
    if "starting oct" in low and ("299.99" in low or "$299" in low):
        if skipg4_has_first_charge(text) or "today $0" in low or "today $299" in low or "starting today" in low:
            return True
        return False
    return bool(
        "subscribe" in low
        or TODAY_RE.search(text or "")
        or FIRST_RE.search(text or "")
    )


def wait_wall(timeout: float = 40.0) -> str:
    end = time.time() + timeout
    text = ""
    empty_n = 0
    while time.time() < end:
        foc = device.play_billing_focus()
        raw = device.ui_blob() or ""
        if not raw.strip():
            empty_n += 1
            # 0B dumps after a card was already listed killed runs before;
            # OCR instead of looping the dump.
            if empty_n >= 2:
                return device.screen_text("wall-empty.png") or ""
            time.sleep(0.8)
            continue
        empty_n = 0
        blob = raw.lower()
        if "no internet" in blob:
            device.recover_play_no_internet()
            time.sleep(0.8)
            continue
        if "something went wrong on our end" in blob:
            return blob
        if wall_dump_is_spinner(raw):
            # Extra dumps starve the sheet. Sleep, do not return OCR garbage.
            time.sleep(1.5)
            continue
        if foc or "subscribe" in blob or "supergrok" in blob or "want to pay with cash" in blob:
            text = wall_text("wall.png")
            low = text.lower()
            if "something went wrong on our end" in low:
                return text
            if "no internet" in low:
                device.recover_play_no_internet()
                time.sleep(0.8)
                continue
            if "want to pay with cash" in low:
                # cash overlay sat on Add card until OK. Dismiss, keep wall.
                device.tap_text("OK")
                time.sleep(0.4)
                continue
            if "loading" in low and "subscribe" not in low and not TODAY_RE.search(text) and not FIRST_RE.search(text):
                time.sleep(0.8)
                continue
            if "unable to change your subscription plan" in low:
                return text
            if "start by adding a payment method" in low or "add a payment method" in low:
                return text
            if "turn on backup payment methods" in low:
                return text
            if wall_is_ready(text):
                return text
        time.sleep(0.6)
    return wall_text("wall-late.png")


# ------------------------------------------------- card pick (wall side)
_LAST4_RE = re.compile(r"(?:Visa|Mastercard)[- ]?(\d{4})", re.I)


def visible_last4s(blob: str) -> list[str]:
    return _LAST4_RE.findall(blob or "")


def picked_after_list_tap(after: str, want: str, list_ui: str) -> bool:
    """True only when the post-tap screen is the wanted Subscribe wall.

    The next sheet can be "You'll get these benefits if you subscribe"
    (SuperGrok + subscribe, no last4). A benefits sheet is not a picked card.
    A different visible last4 is not the wanted card either.
    """
    text = after or ""
    low = text.lower()
    if "benefits" in low:
        return False
    shown = visible_last4s(text)
    if shown and want not in shown:
        return False
    if "subscribe" not in low or "supergrok" not in low:
        return False
    return want in (list_ui or "") or want in text


def pick_plan(blob: str, want: str, avoid: str = "") -> dict[str, Any]:
    """Fail-closed last4 decision from dump/OCR text. No device I/O."""
    shown = visible_last4s(blob)
    low = (blob or "").lower()
    on_list = "add paypal" in low or ("payment methods" in low and "subscribe" not in low)
    on_wall = "supergrok" in low and "subscribe" in low
    avoids = [a.strip() for a in (avoid or "").split(",") if a.strip()]
    if not want:
        return {"ok": True, "kind": "no_want", "shown": shown, "on_list": on_list, "on_wall": on_wall}
    want_shown = want in shown
    avoid_shown = [a for a in avoids if a in shown]
    if want_shown and not avoid_shown:
        kind = "want_on_list" if on_list else "already_on_wall"
        return {"ok": True, "kind": kind, "shown": shown, "on_list": on_list, "on_wall": on_wall}
    if shown and not want_shown:
        return {
            "ok": False,
            "kind": "wrong_card",
            "shown": shown,
            "must_switch": True,
            "on_list": on_list,
            "on_wall": on_wall,
        }
    if "start by adding a payment method" in low or (
        "add a payment method" in low and not shown and not on_wall
    ):
        return {"ok": False, "kind": "need_bind", "shown": shown, "on_list": False, "on_wall": False}
    if on_list:
        return {"ok": False, "kind": "want_not_on_list", "shown": shown, "on_list": True, "on_wall": False}
    if on_wall:
        # FLAG_SECURE dump/OCR often omits last4 while Mastercard-XXXX is visible.
        # A chevron tap would drop a valid deferred Heavy wall. last4==want: no chevron.
        return {
            "ok": True,
            "kind": "wall_last4_hidden",
            "shown": shown,
            "must_switch": False,
            "on_list": False,
            "on_wall": True,
        }
    return {"ok": False, "kind": "unknown", "shown": shown, "on_list": on_list, "on_wall": on_wall}


def pick_wall_card(want: str, avoid: str = "", blob: str | None = None) -> dict[str, Any]:
    """Select last4 on the Subscribe wall or Payment methods. Fail closed if want is missing.

    A captured wall that already shows the wanted last4 is enough: extra dumps
    after it went 0 bytes and killed runs before the pill was tapped.
    """
    if not want:
        return {"ok": True, "kind": "no_want"}
    if blob:
        held = pick_plan(blob, want, avoid)
        shown = held.get("shown") or []
        if held.get("ok") and want in shown and held.get("on_wall"):
            return {
                "ok": True,
                "kind": held.get("kind") or "already_on_wall",
                "last4": want,
                "shown": shown,
                "via": "captured",
            }
    avoids = [a.strip() for a in (avoid or "").split(",") if a.strip()]
    ocr = device.screen_text("wall-pay.png") or ""
    blob = (device.ui_blob() or "") + "\n" + ocr
    plan = pick_plan(blob, want, avoid)
    live = hop_live_last4_on_list(plan.get("shown") or visible_last4s(blob), want, avoid)
    # Do not remap an explicit want off the wall dump. Open the list, then pick.
    if live and live != want and hop_live_remap_wall_dump(want):
        want = live
        plan = pick_plan(blob, want, avoid)
    if plan.get("ok") and plan.get("kind") in ("already_on_wall", "wall_last4_hidden"):
        # FLAG_SECURE dump/OCR often omits Mastercard-XXXX while the wanted
        # last4 is on the wall. Chevron drops a valid deferred Heavy wall.
        return {"ok": True, "kind": plan.get("kind"), "last4": want, "shown": plan.get("shown")}
    if plan.get("kind") == "need_bind":
        n = device.find_text("Add a payment method", "Add card", "Add payment method") or device.ocr_find(
            "Add a payment method"
        )
        if n:
            device.tap(int(n["cx"]), int(n["cy"]), 0.8)
            time.sleep(1.2)
        return {"ok": False, "kind": "need_bind", "last4": want, "shown": plan.get("shown"), "ui": blob[:240]}
    low = blob.lower()
    ocr_l = ocr.lower()
    ocr_wall = "supergrok" in ocr_l and ("subscribe" in ocr_l or "starting today" in ocr_l or "starting oct" in ocr_l)
    shown0 = plan.get("shown") or []
    if ocr_wall and not shown0:
        return {"ok": True, "kind": "wall_last4_hidden", "last4": want, "shown": shown0}
    if plan.get("must_switch") and want not in shown0:
        row = device.find_text("Visa", "Mastercard") or device.ocr_find("Visa") or device.ocr_find("Mastercard")
        cy = int(row["cy"]) if row else 1414
        device.tap(990, cy, 0.9)
        time.sleep(1.5)
        blob = (device.ui_blob() or "") + "\n" + (device.screen_text("wall-list.png") or "")
        low = blob.lower()
        ocr_wall = False
        plan = pick_plan(blob, want, avoid)
    on_list = bool(plan.get("on_list")) or (
        (not ocr_wall) and ("add paypal" in low or ("payment methods" in low and "subscribe" not in low) or want in blob)
    )
    shown_now = plan.get("shown") or visible_last4s(blob)
    # FLAG_SECURE dump of the Subscribe wall often only shows one last4.
    # want_not_on_list only if the payment-method *list* is open and want is
    # still missing. Stay on the wall and fall through to the avoid chevron.
    if shown_now and want not in shown_now and on_list:
        remapped = remap_want_on_open_list(want, shown_now, avoid)
        if remapped and remapped != want:
            want = remapped
            plan = pick_plan(blob, want, avoid)
        else:
            return {"ok": False, "kind": "want_not_on_list", "last4": want, "shown": shown_now, "ui": blob[:240]}

    def _tap_want() -> bool:
        n = device.find_text(f"Mastercard-{want}", f"Visa-{want}", want)
        if not n:
            n = device.ocr_find(f"Mastercard-{want}")
        if not n:
            n = device.ocr_find(f"Visa-{want}")
        if not n:
            n = device.ocr_find(want)
        if not n:
            return False
        device.tap(int(n["cx"]), int(n["cy"]), 1.1)
        time.sleep(1.2)
        return True

    if on_list:
        last_ui = blob
        tapped = False
        for _try in range(4):
            last_ui = (device.ui_blob() or "") + "\n" + (device.screen_text("wall-list.png") or "")
            if _tap_want():
                tapped = True
                break
            time.sleep(2.2)
        if not tapped:
            return {"ok": False, "kind": "want_not_on_list", "last4": want, "ui": last_ui[:240]}
        if want not in last_ui:
            return {"ok": False, "kind": "want_not_on_list", "last4": want, "ui": last_ui[:240]}
        deadline = time.time() + 8.0
        while time.time() < deadline:
            after = ((device.ui_blob() or "") + "\n" + (device.screen_text("wall-picked.png") or "")).lower()
            after_plan = pick_plan(after, want, avoid)
            if after_plan.get("ok") and after_plan.get("kind") == "already_on_wall":
                return {"ok": True, "kind": "picked_list", "last4": want, "shown": after_plan.get("shown")}
            if picked_after_list_tap(after, want, last_ui):
                # FLAG_SECURE may hide last4 after a real list tap. The benefits
                # interstitial is not that wall.
                return {"ok": True, "kind": "picked_list", "last4": want}
            time.sleep(0.6)
        foc = device.current_focus()
        # SheetUi payment list after error: do not BACK, BACK kills the PI.
        if "SheetUiBuilderHostActivity" in foc:
            return {"ok": False, "kind": "picked_on_sheet_no_wall", "last4": want, "ui": (device.ui_blob() or "")[:240]}
        return {"ok": False, "kind": "picked_but_left_wall", "last4": want, "ui": (device.ui_blob() or "")[:240]}
    avoid_hit = any(a in blob for a in avoids)
    want_hit = want in blob
    shown = visible_last4s(blob)
    if shown and want not in shown:
        avoid_hit = True
    if want_hit and not avoid_hit:
        return {"ok": True, "kind": "already_on_wall", "last4": want}
    if avoid_hit:
        n = device.find_text("Change payment method", "Change payment")
        if not n:
            for nd in device.nodes():
                blobn = ((nd.get("text") or "") + (nd.get("desc") or "")).lower()
                if "change payment" in blobn and nd.get("clk"):
                    n = nd
                    break
        if not n:
            for nd in device.nodes():
                blobn = ((nd.get("text") or "") + (nd.get("desc") or "")).lower()
                if any(a.lower() in blobn for a in avoids) and nd.get("clk"):
                    n = nd
                    break
        if not n:
            for a in avoids:
                n = device.ocr_find(f"Visa-{a}") or device.ocr_find(f"Mastercard-{a}")
                if n:
                    break
        if not n:
            for s4 in shown:
                if s4 == want:
                    continue
                n = device.find_text(f"Visa-{s4}", f"Mastercard-{s4}", s4)
                if not n:
                    n = device.ocr_find(f"Visa-{s4}") or device.ocr_find(f"Mastercard-{s4}")
                if n:
                    break
        if not n:
            return {"ok": False, "kind": "avoid_on_wall_no_change", "last4": want, "shown": shown, "ui": blob[:240]}
        device.tap(int(n["cx"]), int(n["cy"]), 1.0)
        time.sleep(1.2)
        blob2 = (device.ui_blob() or "") + "\n" + (device.screen_text("wall-list.png") or "")
        if not _tap_want():
            return {"ok": False, "kind": "want_not_on_list", "last4": want, "ui": blob2[:240]}
        deadline = time.time() + 6.0
        while time.time() < deadline:
            after = (device.ui_blob() or "") + "\n" + (device.screen_text("wall-picked.png") or "")
            al = after.lower()
            if want in after and "subscribe" in al and "supergrok" in al:
                return {"ok": True, "kind": "switched", "last4": want}
            time.sleep(0.6)
        foc = device.current_focus()
        if "SheetUiBuilderHostActivity" in foc:
            return {"ok": False, "kind": "picked_on_sheet_no_wall", "last4": want, "ui": (device.ui_blob() or "")[:240]}
        stack = device.shell("dumpsys activity activities") or ""
        if "LockToPortraitUiBuilderHostActivity" in stack and "LockToPortrait" not in foc:
            device.back(0.9)
            time.sleep(0.8)
            after2 = (device.ui_blob() or "") + "\n" + (device.screen_text("wall-picked2.png") or "")
            if want in after2 and "subscribe" in after2.lower() and "supergrok" in after2.lower():
                return {"ok": True, "kind": "switched", "last4": want}
        return {"ok": False, "kind": "picked_but_left_wall", "last4": want, "ui": (device.ui_blob() or "")[:240]}
    if shown and want not in shown:
        return {"ok": False, "kind": "wrong_card", "last4": want, "shown": shown, "ui": blob[:240]}
    end_plan = pick_plan(blob, want, avoid)
    if end_plan.get("ok"):
        return {"ok": True, "kind": end_plan.get("kind"), "last4": want, "shown": end_plan.get("shown")}
    return {"ok": False, "kind": end_plan.get("kind") or "want_not_on_list", "last4": want, "shown": end_plan.get("shown"), "ui": blob[:240]}


# ------------------------------------------------- subscribe / verify sheets
def fill_play_password(password: str) -> None:
    """Type the Play password without a second uiautomator dump.

    The password sheet dump can be 14KB; edit_field() dumped again, 0 bytes,
    and adb went offline before type. The field on that sheet is 540,1358.
    """
    device.tap(540, 1358, 0.25)
    device.clear_field()
    device.type_text(password)


def tap_subscribe() -> bool:
    """Tap the FLAG_SECURE Subscribe button only.

    Clickable Subscribe bounds [63,1789][1017,1884] cx,cy 540,1836 then
    su_tap -> Processing/Subscribed. OCR 'by tapping Subscribe' at cy~1439 is
    legal text. play_billing_focus fallback without a clickable button is an
    overlay miss; caller must re-dump. The 1810 clamp misses the button.
    """
    ocr = device.screen_text("tap-sub.png") or ""
    low = ocr.lower()
    if "subscribe" in low and "supergrok" in low:
        device.su_tap(540, 1836, 1.1)
        return True
    hits = [
        x
        for x in device.find_all("Subscribe")
        if int(x.get("cy") or 0) >= 1780 and x.get("clk")
    ]
    n = max(hits, key=lambda x: int(x.get("cy") or 0)) if hits else None
    if n:
        y = int(n["cy"] or 0)
        # 1810 clamp misses FLAG_SECURE Subscribe (nav overlap). Live hit is 1836.
        if y > 1836:
            y = 1836
        device.su_tap(int(n["cx"]), y, 1.1)
        return True
    if device.play_billing_focus():
        device.su_tap(540, 1836, 1.1)
        return False
    return False


def backup_sheet_action(blob: str, *, lite_paid: bool = False) -> str:
    """Backup interstitial.

    Acquire still live: BACK aborts the unpaid Lite. No thanks, else Turn on.
    Lite already paid (inspect grok.lite AR=true / Payment successful): BACK.
    Never Turn on after Lite paid: Turn on then fromlite -> item_unavailable
    with GID==accountId (observed once).
    """
    low = (blob or "").lower()
    if "backup payment" not in low and "turn on backup" not in low:
        return "none"
    if lite_paid:
        return "back"
    if "no, thanks" in low or "no thanks" in low:
        return "no_thanks"
    if "turn on" in low:
        return "turn_on"
    return "stay"


def dismiss_pay_sheets(*, lite_paid: bool = False) -> None:
    blob = device.ui_blob() or device.screen_text("sheet.png") or ""
    low = blob.lower()
    act = backup_sheet_action(blob, lite_paid=lite_paid)
    if act == "no_thanks":
        device.tap_text("No, thanks", "No thanks")
    elif act == "back":
        device.back(0.4)
    elif act == "turn_on":
        hits = [x for x in device.find_all("Turn on") if int(x.get("cy") or 0) >= 1700]
        if hits:
            n = max(hits, key=lambda x: int(x.get("cy") or 0))
            y = int(n["cy"] or 0)
            if y > 1810:
                y = 1810
            device.su_tap(int(n["cx"]), y, 1.0)
        else:
            device.su_tap(786, 1810, 1.0)
    if "no, thanks" in low or "no thanks" in low:
        device.tap_text("No, thanks", "No thanks")
        device.tap_text("OK", "Ok")
    if "require authentication" in low:
        device.tap_text("No, thanks", "No thanks")


def lite_verify_ok(ver: dict[str, Any] | None) -> bool:
    box = ver or {}
    if not box.get("ok"):
        return False
    return str(box.get("kind") or "") not in (
        "play_error",
        "item_unavailable",
        "OR-PFGVEM",
        "OR-HDT-16",
        "fake_no_internet",
        "card_declined",
        "left_wall",
        "left_wall_subs",
    )


def pay_fail_stage(ver: dict[str, Any] | None) -> str | None:
    """Map verify.kind to a stop stage.

    PFGVEM / FGVEM / issuer declined / CCREU / LIFE_TIME -> swap_card first.
    Bare 购买不成功 (no those codes) / HDT / fake No internet -> did_rotate.
    """
    box = ver or {}
    kind = str(box.get("kind") or "")
    ui = str(box.get("ui") or "").lower()
    if kind == "OR-HDT-16" or "or-hdt" in ui or "or_hdt" in ui:
        return "did_rotate"
    if kind == "OR-FGEMF" or "or-fgemf" in ui or "or_fgemf" in ui:
        return "swap_account"
    if kind == "fake_no_internet":
        return "did_rotate"
    if kind in ("OR-PFGVEM", "card_declined") or "or-pfgvem" in ui or "or_pfgvem" in ui or "or_fgvem" in ui:
        return "swap_card"
    if "issuer declined" in ui or "your card was declined" in ui:
        return "swap_card"
    if "life_time_amount_exceeded" in ui or "lifetime amount exceeded" in ui:
        return "swap_card"
    if kind in ("OR_CCREU", "OR-CCREU") or "or_ccreu" in ui or "or-ccreu" in ui:
        return "swap_card"
    if "购买不成功" in ui or "payment unsuccessful" in ui:
        return "did_rotate"
    if kind == "account_dead":
        return "swap_account"
    return None


def verify_fail_kind(blob: str) -> str:
    """Classify Play verify/result sheets. HDT is not card decline. FGVEM is funds."""
    low = (blob or "").lower()
    if "or-hdt" in low or "or_hdt" in low:
        return "OR-HDT-16"
    if "or-fgemf" in low or "or_fgemf" in low:
        return "OR-FGEMF"
    if "insufficient funds" in low or "or_fgvem" in low or "or-pfgvem" in low or "or_pfgvem" in low:
        return "OR-PFGVEM"
    if "life_time_amount_exceeded" in low or "lifetime amount exceeded" in low:
        return "card_declined"
    if "maximum number of login attempts" in low:
        return "login_attempt_limit"
    if any(
        k in low
        for k in (
            "not available for purchase",
            "unable to change your subscription",
            "couldn't complete this action",
            "can't be completed",
            "cannot be completed",
            "无法购买",
            "无法完成交易",
        )
    ):
        return "item_unavailable"
    if any(
        k in low
        for k in (
            "payment unsuccessful",
            "card issuer declined",
            "your card was declined",
            "issuer declined your",
            "this payment method has been declined",
            "try another payment method",
            "could not be completed",
        )
    ):
        return "card_declined"
    return ""


def verify_left_wall_pm(blob: str) -> bool:
    """Lite paid landed on Payment methods, not the Subscribe wall.

    After Verify, a dump can sit on `Payment methods | Visa-XXXX | Add credit
    or debit card` until timeout_continue while inspect grok.lite AR=true.
    Firing fromlite from that sheet then Subscribe -> item_unavailable.
    """
    low = (blob or "").lower()
    if "payment methods" not in low:
        return False
    if "starting today" in low or "starting oct" in low:
        return False
    return "visa-" in low or "mastercard-" in low or "add credit or debit" in low


def play_sheet_blocks_fromlite(blob: str) -> bool:
    """Play billing sheets that poison fromlite Acquire if we fire from them."""
    low = (blob or "").lower()
    if "the item you requested is not available" in low:
        return True
    if "turn on backup" in low or "backup payment methods" in low:
        return True
    if "payments & subscriptions" in low or "payments &amp; subscriptions" in low:
        return True
    if "payment methods" in low and (
        "add credit or debit" in low or "visa-" in low or "mastercard-" in low
    ):
        return True
    return False


def fromlite_landed_play_hub(blob: str) -> bool:
    """fromlite BUY_INTENT opened the Play hub, not the Heavy overlay on Grok.

    Fire JSON can be regular-p1m + accountId==lite-gid16 + modeArg=4 and the
    wall still lands on Payments & subscriptions. First hub landing consumes
    the replace offer; a re-fire shows a ghost deferred SuperGrok Heavy wall
    whose Subscribe returns item_unavailable. Do not re-fire, do not Subscribe.
    """
    low = (blob or "").lower()
    if "the item you requested is not available" in low:
        return True
    if "supergrok" in low and "subscribe" in low and (
        "your first charge will occur" in low
        or "starting nov" in low
        or "starting oct" in low
        or "starting dec" in low
    ):
        return False
    if "payments & subscriptions" in low or "payments &amp; subscriptions" in low:
        return True
    if "payment methods" in low and "subscribe" not in low:
        return True
    return False


def grok_home_ready(blob: str) -> bool:
    low = (blob or "").lower()
    return "ask anything" in low or "start grok voice" in low or "start new chat" in low


def leave_play_for_fromlite(timeout: float = 12.0) -> dict[str, Any]:
    """Lite paid must leave Play billing before fromlite fire.

    Payment methods -> fromlite Subscribe = item. From Ask anything,
    fromlite paid. Do not Turn on backup. A Grok TOS (Accept & Continue +
    Sign out) on the way is accepted first.
    """
    end = time.time() + timeout
    saw: list[str] = []
    while time.time() < end:
        blob = (device.ui_blob() or "") + "\n" + (device.screen_text("fromlite-leave.png") or "")
        low = blob.lower()
        if "not available" in low and "got it" in low:
            device.tap_text("Got it", "OK")
            saw.append("item_got_it")
            return {"ok": False, "stage": "fromlite_acquire", "saw": saw}
        if grok_home_ready(blob) and not play_sheet_blocks_fromlite(blob):
            return {"ok": True, "saw": saw, "home": True}
        if play_sheet_blocks_fromlite(blob) or device.play_billing_focus():
            device.back(0.5)
            saw.append("back_sheet")
            continue
        if "accept & continue" in low and "sign out" in low:
            tos = accept_native_tos()
            saw.append("tos_accept")
            if tos.get("ok"):
                time.sleep(0.6)
                continue
            return {"ok": False, "stage": "fromlite_not_home", "saw": saw, "tos": tos}
        break
    device.shell("am start -n ai.x.grok/.main.GrokActivity")
    time.sleep(1.4)
    blob = (device.ui_blob() or "") + "\n" + (device.screen_text("fromlite-leave2.png") or "")
    low = blob.lower()
    if "accept & continue" in low and "sign out" in low:
        tos = accept_native_tos()
        saw.append("tos_accept_after_start")
        blob = device.ui_blob() or ""
    home = grok_home_ready(blob) and not play_sheet_blocks_fromlite(blob)
    return {"ok": home, "saw": saw, "home": grok_home_ready(blob), "ui": blob[:200]}


def verify_left_wall_subs(blob: str) -> bool:
    """True when Play already left the Acquire Subscribe wall.

    Manage subscription + SuperGrok Heavy + Canceled/Resubscribe/will end.
    Naive `"subscribe" not in low` never matches because "subscription" and
    "Resubscribe" contain that substring, so verify idled 90s.
    """
    low = (blob or "").lower()
    if "manage subscription" not in low:
        return False
    if "supergrok" not in low and "grok ai" not in low and "grok al" not in low:
        return False
    return "canceled" in low or "resubscribe" in low or "will end" in low


def verify_left_wall_play_listing(blob: str) -> bool:
    """True when Play already left Acquire onto the Grok store listing.

    Grok AI + Open + Uninstall + In-app purchases. Listing copy "start your
    subscription" contains "subscribe"; do not use `"subscribe" not in`.
    """
    low = (blob or "").lower()
    if "uninstall" not in low or "in-app purchase" not in low:
        return False
    if "grok ai" not in low and "grok al" not in low:
        return False
    if "starting today" in low or "your first charge" in low:
        return False
    return "open" in low


def flag_secure_password_sheet(text: str) -> bool:
    """Play password sheet after Subscribe. Not wall-left.

    Dump timeout + OCR only `ADB Keyboard {ON}`: still the password sheet,
    type+Verify 540,1435/540,1785. A dump with `Enter your password` /
    `Forgot password?` is the password sheet even when the Lite title is
    still in the dump.
    """
    low = (text or "").lower()
    if "enter your password" in low or "forgot password" in low:
        return True
    if "adb keyboard" not in low:
        return False
    if any(
        k in low
        for k in (
            "supergrok",
            "subscribe",
            "starting today",
            "starting oct",
            "payment successful",
        )
    ):
        return False
    return True


def verify_google_password(password: str, timeout: float = 90.0) -> dict[str, Any]:
    end = time.time() + timeout
    saw: list[str] = []
    empty_n = 0
    while time.time() < end:
        ocr = ""
        try:
            ocr = device.screen_text("verify.png") or ""
        except Exception:
            ocr = ""
        xml = ""
        ocr_l = ocr.lower()
        ocr_hit = any(
            k in ocr_l
            for k in (
                "subscribe",
                "password",
                "declined",
                "successful",
                "you're subscribed",
                "thanks for subscribing",
                "not available",
                "try another payment",
                "couldn't complete",
                "couldn’t complete",
                "or_ccreu",
                "or-ccreu",
                "or_mivem",
                "or_fgvem",
                "or-pfgvem",
                "or-hdt",
                "or_hdt",
                "insufficient funds",
                "something went wrong",
            )
        )
        # FLAG_SECURE Play sheets: dump is slow and often omits
        # last4/password/decline copy. Two empty dumps -> type+Verify
        # 540,1435/540,1785, do not loop ui_blob.
        if not ocr_hit:
            if empty_n >= 2:
                if not password:
                    return {"ok": False, "saw": saw, "kind": "need_google_pw", "ui": (ocr or "")[:240]}
                device.ensure_adb_ime()
                device.tap(540, 1435, 0.2)
                device.clear_field()
                device.type_text(password)
                device.hide_ime()
                device.tap(540, 1785, 1.0)
                saw.append("verify")
                empty_n = 0
                time.sleep(1.4)
                continue
            xml = device.ui_blob() or ""
            if not str(xml).strip():
                empty_n += 1
            else:
                empty_n = 0
        else:
            empty_n = 0
        blob = f"{xml}\n{ocr}"
        if not str(blob).strip():
            time.sleep(0.6)
            continue
        low = blob.lower()
        if playfest_prize_sheet(low):
            # Left pill is Not now. Do not tap Explore.
            if not device.tap_text("Not now"):
                device.tap(270, 1780, 0.8)
            saw.append("playfest_not_now")
            time.sleep(1.0)
            continue
        dismiss_pay_sheets()
        kind = verify_fail_kind(blob)
        if kind:
            device.tap_text("Got it", "OK", "Try again") or device.back(0.4)
            return {"ok": False, "saw": saw, "kind": kind, "ui": blob[:240]}
        if "server error" in low or ("error" in low and "got it" in low):
            device.tap_text("Got it", "OK") or device.back(0.4)
            return {"ok": False, "saw": saw, "kind": "play_error", "ui": blob[:240]}
        if any(k in low for k in ("payment successful", "you're subscribed", "thanks for subscribing")):
            device.tap_text("Got it", "OK") or device.back(0.4)
            return {"ok": True, "saw": saw, "kind": "success"}
        if "supergrok heavy" in low and "next payment" in low:
            return {"ok": True, "saw": saw, "kind": "play_heavy_row"}
        if verify_left_wall_subs(blob):
            # Manage subscription Canceled / Resubscribe / will end after the
            # g4 tap. Inspect is the paid oracle.
            return {"ok": True, "saw": saw, "kind": "left_wall_subs"}
        if saw and verify_left_wall_pm(blob):
            return {"ok": True, "saw": saw, "kind": "left_wall_pm"}
        if verify_left_wall_play_listing(blob):
            return {"ok": True, "saw": saw, "kind": "left_wall_play"}
        if grok_home_ready(blob) and not device.play_billing_focus():
            # Subscribe 后墙关到 Grok Ask anything: 立刻结束等 inspect.
            return {"ok": False, "saw": saw, "kind": "timeout_continue", "left": "grok_home"}
        if device.play_sheet_is_no_internet(blob):
            # ops removed: pinned-egress IP cross-check (fake No internet).
            device.recover_play_no_internet()
            time.sleep(0.8)
            continue
        if (
            "enter your password" in low
            or ("password" in low and "verify" in low)
            or flag_secure_password_sheet(ocr)
        ):
            # Empty password must not type a fallback: a wrong password ends
            # in "maximum number of login attempts".
            if not password:
                return {"ok": False, "saw": saw, "kind": "need_google_pw", "ui": blob[:240]}
            # Password field is FLAG_SECURE between Enter your password
            # y=1350 and Remember y=1519 -> tap 1435, Verify pill 1785.
            device.ensure_adb_ime()
            device.tap(540, 1435, 0.2)
            device.clear_field()
            device.type_text(password)
            device.hide_ime()
            device.tap(540, 1785, 1.0)
            saw.append("verify")
            time.sleep(1.4)
            continue
        if device.play_billing_focus() and "subscribe" in low:
            # 还停在 Subscribe 墙 = 没买成, 继续等 item_unavailable / 密码页.
            time.sleep(0.6)
            continue
        if not device.play_billing_focus() and saw:
            # FLAG_SECURE hid a decline code once; leaving the wall is not paid.
            return {"ok": False, "saw": saw, "kind": "left_wall"}
        time.sleep(0.6)
    still = device.play_billing_focus()
    return {"ok": False, "saw": saw, "kind": "timeout_continue", "still_billing": still}


# ------------------------------------------------- fire evidence helpers
FROMLITE_OFFER_ID = "regular-p1m"
_FIRE_PUBLIC = ("ok", "offerId", "accountId", "modeArg", "d2rc", "err", "sent", "hasPI")


def public_fire(fired: dict[str, Any] | None) -> dict[str, Any]:
    """HOLD/sub evidence. Never copy purchaseToken / PAN."""
    src = fired if isinstance(fired, dict) else {}
    out: dict[str, Any] = {}
    for k in _FIRE_PUBLIC:
        if k in src:
            out[k] = src.get(k)
    return out


def persist_fire(name: str, fired: dict[str, Any] | None) -> Path:
    dest = device.serial_dir() / f"{name}-fire.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(public_fire(fired), ensure_ascii=False) + "\n", encoding="utf-8")
    return dest


def hook_gid_head(heavy_hook: str) -> str:
    """GID compiled into the serial live.js. Do not use a stale sibling gid.txt."""
    p = Path(heavy_hook)
    for cand in (p.parent / "heavy_wall.live.js", p.with_name("heavy_wall.live.js")):
        if cand.exists():
            m = re.search(r"var GID = '([0-9a-f]+)'", cand.read_text(encoding="utf-8"))
            if m:
                return m.group(1)[:16]
    return ""


def lite_gid16_path() -> Path:
    return device.serial_dir() / "lite-gid16.txt"


def save_lite_gid16(acct: str) -> str:
    head = str(acct or "").strip()[:16]
    if head:
        dest = lite_gid16_path()
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(head, encoding="utf-8")
    return head


def load_lite_gid16() -> str:
    p = lite_gid16_path()
    if not p.exists():
        return ""
    try:
        return p.read_text(encoding="utf-8").strip()[:16]
    except OSError:
        return ""


def fromlite_offer_ok(fired: dict[str, Any] | None) -> dict[str, Any]:
    """Only regular-p1m upgraded in testing; p3m/may2026 Subscribe -> item."""
    src = fired if isinstance(fired, dict) else {}
    oid = str(src.get("offerId") or "")
    ok = oid == FROMLITE_OFFER_ID
    return {"ok": ok, "offerId": oid, "want": FROMLITE_OFFER_ID}


def fromlite_account_ok(
    fired: dict[str, Any],
    heavy_hook: str,
    expected_gid: str = "",
) -> dict[str, Any]:
    """Subscribe only if extras.accountId is the Lite d2 GID.

    Receipt obf can differ from the Lite GID (observed 5d90 vs 6b2e); using
    the receipt obf for fromlite replace -> item_unavailable.
    """
    acct = str(fired.get("accountId") or "")
    gid = hook_gid_head(heavy_hook)
    want = str(expected_gid or "").strip()[:16] or gid
    mode = fired.get("modeArg")
    ok = bool(acct and want and acct == want and mode != 3)
    if gid and acct != gid:
        ok = False
    if expected_gid and acct != str(expected_gid).strip()[:16]:
        ok = False
    return {
        "ok": ok,
        "accountId": acct,
        "gid": gid,
        "expected": want,
        "modeArg": mode,
    }


def refresh_fromlite_hook(heavy_hook: str, expected_gid16: str = "") -> dict[str, Any]:
    """Recompile from the live lite receipt before fromlite.

    A hook baked before Lite -> Subscribe item. After lite AR=true,
    prepare_hooks(receipt obf, lite_token) in the same session produced a
    working deferred ultra wall. If lite-gid16 is known and the receipt obf
    head differs, fail-closed.
    """
    insp = inspect(heavy_hook)
    lite = find_sku(insp, "grok.lite") or {}
    obf = str(lite.get("obfuscatedAccountId") or "")
    token = str(lite.get("purchaseToken") or "")
    if lite.get("autoRenewing") is not True or not GID_RE.fullmatch(obf) or not token:
        return {"ok": False, "error": "no_live_lite", "hook": heavy_hook}
    want = str(expected_gid16 or hook_gid_head(heavy_hook) or "").strip()[:16]
    if want and obf[:16] != want:
        return {
            "ok": False,
            "error": "receipt_gid_mismatch",
            "gid": obf[:16],
            "expected": want,
            "hook": heavy_hook,
        }
    built = prepare_hooks(obf, device.serial_dir(), lite_token=token)
    if not built.get("ok"):
        return {"ok": False, "error": "recompile", "hook": heavy_hook}
    return {"ok": True, "hook": str(built.get("heavy") or ""), "gid": obf}


# ------------------------------------------------- inspect / purchases
def inspect(heavy_hook: str | None = None) -> dict[str, Any]:
    """Attach Grok. Start frida-server if pidof is empty.

    After a 0B dump adb blip, fire_heavy attach raised ServerNotRunningError
    and inspect returned no_json; ensure_frida_server then inspect returned
    the canceled grok.ultra.
    """
    ensure_frida_server()
    return fire("inspect", hook=heavy_hook)


def purchases(box: dict[str, Any]) -> list[dict[str, Any]]:
    rows = box.get("purchases") if isinstance(box, dict) else None
    return list(rows) if isinstance(rows, list) else []


def find_sku(box: dict[str, Any], sku: str) -> dict[str, Any] | None:
    for p in purchases(box):
        if str(p.get("productId") or "") == sku:
            return p
    return None


# ------------------------------------------------- buy: lite -> fromlite -> g4
def buy_lite(lite_hook: str, google_password: str, *, last4: str = "", avoid_last4: str = "") -> dict[str, Any]:
    if not keep_leftover_ny():
        ensure_play_dns()
    fired = fire("p1m", hook=lite_hook)
    if not fired.get("ok") and fired.get("d2rc") not in (0, None):
        return {"ok": False, "stage": "lite_fire", "fire": fired}
    if fired.get("err") == "no_lite_sku_token" or fired.get("g2rc") in (3, 6):
        return {"ok": False, "stage": "lite_no_offer", "fire": fired}
    text = wait_wall(timeout=40.0)
    first = gate_lite(text)
    if first.get("kind") == "need_bind":
        # The sheet can say Start by adding a payment method; force-stop drops
        # it and the retry lands on Ask. Return so the caller binds from the wall.
        return {"ok": False, "stage": "lite_gate", "gate": first, "fire": public_fire(fired), "ui": text[:400]}
    if not first.get("ok"):
        # wait_wall OCR garbage while the LockToPortrait ProgressBar is still
        # up: keep the overlay; only force-stop when billing focus is gone.
        if device.play_billing_focus() or wall_dump_is_spinner(text):
            text = wait_wall(timeout=25.0)
        else:
            device.shell("am force-stop ai.x.grok")
            time.sleep(0.7)
            fired = fire("p1m", hook=lite_hook)
            text = wait_wall(timeout=18.0)
    gate = gate_lite(text)
    if not gate.get("ok"):
        # need_bind: BACK opened "Want to pay with cash?" once. Bind from the
        # Add card wall.
        if gate.get("kind") != "need_bind" and not (
            device.play_billing_focus() or wall_dump_is_spinner(text)
        ):
            device.back(0.6)
        return {"ok": False, "stage": "lite_gate", "gate": gate, "fire": fired}
    picked = pick_wall_card(last4, avoid_last4)
    if not picked.get("ok"):
        return {"ok": False, "stage": "lite_card", "pick": picked, "gate": gate, "fire": fired}
    if os.environ.get("GROK_HOLD_SUBSCRIBE", "").strip().lower() in {"1", "true", "yes"}:
        shot = device.screenshot("lite-wall.png")
        save_lite_gid16(str(fired.get("accountId") or ""))
        persist_fire("lite", fired)
        return {
            "ok": True,
            "stage": "lite_wall_hold",
            "gate": gate,
            "fire": public_fire(fired),
            "pick": picked,
            "shot": str(shot),
            "ui": text[:400],
            "lite_gid16": load_lite_gid16(),
        }
    device.prepare_play_iap()
    if not tap_subscribe():
        return {"ok": False, "stage": "lite_subscribe", "error": "no_subscribe", "gate": gate, "pick": picked}
    ver = verify_google_password(google_password, timeout=50.0)
    dismiss_pay_sheets()
    if not lite_verify_ok(ver):
        insp = inspect()
        lite_row = find_sku(insp, "grok.lite") or {}
        if lite_row.get("autoRenewing") is True:
            mark_lite_paid(last4, str(lite_row.get("orderId") or ""))
            return {
                "ok": True,
                "stage": "lite",
                "fire": fired,
                "gate": gate,
                "verify": ver,
                "pick": picked,
                "via": "inspect",
            }
        return {
            "ok": False,
            "stage": pay_fail_stage(ver) or "lite_verify",
            "gate": gate,
            "verify": ver,
            "fire": fired,
            "pick": picked,
        }
    mark_lite_paid(last4)
    return {"ok": True, "stage": "lite", "fire": fired, "gate": gate, "verify": ver, "pick": picked}


def buy_fromlite(
    heavy_hook: str,
    google_password: str,
    *,
    last4: str = "",
    avoid_last4: str = "",
    skip_pick: bool = False,
    cmd: str = "fromlite",
    card_active: bool | None = None,
) -> dict[str, Any]:
    """Replace lite->ultra (deferred). Must land the want last4; another last4 on the wall is fail-closed.

    cmd=fromlite is the p3m intro variant of the hook; the verified path is
    regular-p1m (fromlite_offer_ok). Leave Play to Ask anything, then
    recompile from the live lite receipt, before fire.
    """
    frozen = card_active is False or (card_active is None and lite_card_frozen(last4))
    if frozen:
        return {
            "ok": False,
            "stage": "fromlite_frozen",
            "err": "unfreeze_first",
            "last4": last4,
        }
    cool = fromlite_cooldown(last4)
    if cool.get("skip"):
        return {"ok": False, "stage": "fromlite_acquire", **cool}
    # timeout_continue / left_wall_pm are not ownership. Inspect grok.lite AR
    # first; both have opened a regular-p1m deferred wall whose Subscribe
    # returned item_unavailable.
    owned = find_sku(inspect(), "grok.lite") or {}
    if owned.get("autoRenewing") is not True:
        return {
            "ok": False,
            "stage": "lite_not_paid",
            "error": "lite_ar_required",
            "order": str(owned.get("orderId") or ""),
        }
    left = leave_play_for_fromlite()
    if left.get("stage") == "fromlite_acquire":
        return {"ok": False, "stage": "fromlite_acquire", "leave": left}
    if not left.get("ok"):
        return {"ok": False, "stage": "fromlite_not_home", "leave": left}
    expected = load_lite_gid16()
    refreshed = refresh_fromlite_hook(heavy_hook, expected_gid16=expected)
    if not refreshed.get("ok"):
        stage = "fromlite_gid_mismatch" if refreshed.get("error") == "receipt_gid_mismatch" else "fromlite_fire"
        return {"ok": False, "stage": stage, "refresh": refreshed}
    heavy_hook = str(refreshed.get("hook") or heavy_hook)
    if not keep_leftover_ny():
        ensure_play_dns()
    last: dict[str, Any] = {"ok": False, "stage": "fromlite_fire"}
    cmds = (cmd,) if cmd in ("fromlite", "fromlitep1m") else ("fromlite",)
    for cmd in cmds:
        fired = fire(cmd, hook=heavy_hook)
        persist_fire("fromlite", fired)
        if fired.get("err") == "no_lite_token_for_fromlite":
            return {"ok": False, "stage": "fromlite_fire", "cmd": cmd, "fire": public_fire(fired)}
        gid_gate = fromlite_account_ok(fired, heavy_hook, expected_gid=expected)
        if not gid_gate.get("ok"):
            device.back(0.6)
            return {
                "ok": False,
                "stage": "fromlite_gid_mismatch",
                "cmd": cmd,
                "fire": public_fire(fired),
                **gid_gate,
            }
        offer_gate = fromlite_offer_ok(fired)
        if not offer_gate.get("ok"):
            device.back(0.6)
            return {
                "ok": False,
                "stage": "fromlite_gate",
                "cmd": cmd,
                "gate": {"ok": False, "kind": "fromlite_bad_offer", **offer_gate},
                "fire": public_fire(fired),
                "gid_gate": gid_gate,
            }
        text = wait_wall()
        if destg4_benefits_continue(text):
            # "You'll get these benefits if you subscribe". Continue, don't BACK.
            if not device.tap_text("Continue", "CONTINUE"):
                device.su_tap(540, 1700, 0.8)
            time.sleep(1.0)
            text = wait_wall()
        if fromlite_landed_play_hub(text):
            # Hub landing consumes the replace offer. Re-fire shows a ghost
            # deferred Heavy wall; Subscribe is item.
            mark_fromlite_unavailable(last4, kind="fromlite_play_hub")
            device.back(0.6)
            return {
                "ok": False,
                "stage": "fromlite_acquire",
                "kind": "fromlite_play_hub",
                "cmd": cmd,
                "gate": {"ok": False, "kind": "fromlite_play_hub", "text": text[:240]},
                "fire": public_fire(fired),
                "gid_gate": gid_gate,
                "ui": text[:400],
            }
        gate = gate_heavy(text)
        if not gate.get("ok"):
            device.back(0.6)
            return {"ok": False, "stage": "fromlite_gate", "cmd": cmd, "gate": gate, "fire": fired}
        if skip_pick:
            picked = {"ok": True, "kind": "skip_pick_replace", "last4": last4}
        else:
            picked = pick_wall_card(last4, avoid_last4)
            if not picked.get("ok"):
                return {"ok": False, "stage": "fromlite_card", "cmd": cmd, "pick": picked, "gate": gate, "fire": fired}
        if os.environ.get("GROK_HOLD_SUBSCRIBE", "").strip().lower() in {"1", "true", "yes"}:
            shot = device.screenshot("fromlite-wall.png")
            persist_fire("fromlite", fired)
            return {
                "ok": True,
                "stage": "fromlite_wall_hold",
                "cmd": cmd,
                "fire": public_fire(fired),
                "gate": gate,
                "pick": picked,
                "gid_gate": gid_gate,
                "offer_gate": offer_gate,
                "shot": str(shot),
                "ui": text[:400],
                "lite_gid16": expected,
            }
        if not tap_subscribe():
            return {"ok": False, "stage": "fromlite_subscribe", "cmd": cmd, "error": "no_subscribe", "gate": gate, "pick": picked}
        ver = verify_google_password(google_password, timeout=40.0)
        dismiss_pay_sheets()
        if ver.get("ok") and ver.get("kind") not in ("play_error", "item_unavailable"):
            return {"ok": True, "stage": "fromlite", "cmd": cmd, "fire": fired, "gate": gate, "verify": ver}
        insp = inspect()
        ultra_row = find_sku(insp, "grok.ultra") or {}
        if ultra_row.get("autoRenewing") is True:
            return {
                "ok": True,
                "stage": "fromlite",
                "cmd": cmd,
                "fire": fired,
                "gate": gate,
                "verify": ver,
                "pick": picked,
                "via": "inspect",
            }
        last = {
            "ok": False,
            "stage": "fromlite_verify",
            "cmd": cmd,
            "gate": gate,
            "verify": ver,
            "fire": fired,
            "pick": picked,
        }
        staged = pay_fail_stage(ver)
        if staged:
            last["stage"] = staged
            return last
        if ver.get("kind") != "item_unavailable":
            return last
        # item_unavailable is Play Acquire, not card decline. Do not chain p1m
        # on the same GPA in this call; rapid Subscribe poisons acquire cache.
        mark_fromlite_unavailable(last4)
        device.back(0.6)
        dismiss_pay_sheets()
        return last
    return last


def buy_g4(heavy_hook: str, google_password: str, *, last4: str = "", avoid_last4: str = "") -> dict[str, Any]:
    """Fire g4 only after the canceled ultra is acked.

    g4 from Ask with regular-p1m and mode 4 still showed "unable to change
    your subscription plan" until ack_token on the AR=false ultra. The next
    fire was a deferred wall and a new GPA. AR=true must not fire.
    """
    owned = find_sku(inspect(heavy_hook), "grok.ultra") or {}
    if owned.get("autoRenewing") is True:
        return {
            "ok": False,
            "stage": "g4_still_renewing",
            "order": str(owned.get("orderId") or ""),
        }
    token = str(owned.get("purchaseToken") or "")
    if token:
        acked = ack_token(token, device.serial_dir())
        if not acked.get("ok"):
            return {
                "ok": False,
                "stage": "g4_ack",
                "ack": {k: acked.get(k) for k in ("ok", "acked", "error")},
            }
    fired = fire("g4", hook=heavy_hook)
    if fired.get("err"):
        return {"ok": False, "stage": "g4_fire", "fire": fired}
    text = wait_wall()
    gate = gate_heavy(text)
    if not gate.get("ok"):
        device.back(0.6)
        return {"ok": False, "stage": "g4_gate", "gate": gate, "fire": fired}
    picked = pick_wall_card(last4, avoid_last4)
    if not picked.get("ok"):
        return {"ok": False, "stage": "g4_card", "pick": picked, "gate": gate, "fire": fired}
    if os.environ.get("GROK_HOLD_SUBSCRIBE", "").strip().lower() in {"1", "true", "yes"}:
        shot = device.screenshot("g4-wall.png")
        return {
            "ok": True,
            "stage": "g4_wall_hold",
            "gate": gate,
            "fire": fired,
            "pick": picked,
            "shot": str(shot),
            "ui": text[:400],
        }
    if not tap_subscribe():
        return {"ok": False, "stage": "g4_subscribe", "error": "no_subscribe", "gate": gate, "pick": picked}
    ver = verify_google_password(google_password)
    dismiss_pay_sheets()
    fail_kinds = (
        "play_error",
        "item_unavailable",
        "OR-HDT-16",
        "fake_no_internet",
        "OR-PFGVEM",
        "card_declined",
        "left_wall",
    )
    if not ver.get("ok") or ver.get("kind") in fail_kinds:
        insp = inspect()
        ultra_row = find_sku(insp, "grok.ultra") or {}
        if ultra_row.get("autoRenewing") is True:
            return {
                "ok": True,
                "stage": "g4",
                "fire": fired,
                "gate": gate,
                "verify": ver,
                "via": "inspect",
            }
        return {
            "ok": False,
            "stage": pay_fail_stage(ver) or "g4_verify",
            "gate": gate,
            "verify": ver,
            "fire": fired,
        }
    return {"ok": True, "stage": "g4", "fire": fired, "gate": gate, "verify": ver}


# ------------------------------------------------- cancel + ack
def cancel_tos_tap(low: str) -> tuple[int, int] | None:
    """Grok native TOS sits on top of Play cancel. Tap Accept, never Sign out.

    The destg4 cancel dump had Accept & Continue at cy~1681 and Sign out at
    cy~1819 until a tap at (540, 1681). The page title contains Accept, so
    match the button text.
    """
    text = (low or "").lower()
    if "accept & continue" not in text and "accept and continue" not in text:
        return None
    if "sign out" not in text:
        return None
    return (540, 1681)


def cancel_right_xy(hit: dict | None) -> tuple[int, int]:
    """Right-hand Cancel subscription pill.

    Pause payments is the left pill, Cancel subscription the right one. OCR
    joins both labels into "pause payments cancel subscription" and returns
    the gap between them. The right pill is 786, 1857.
    """
    if hit and int(hit.get("cx") or 0) > 700:
        return int(hit["cx"]), int(hit["cy"])
    return 786, 1857


def cancel_page_text(name: str = "cancel.png") -> str:
    """Screencap + OCR the cancel sheet. Do not uiautomator-dump it.

    The first dump was the Grok home; the next dumps were 0 bytes and the
    run stopped before Cancel was tapped.
    """
    return device.screen_text(name) or ""


def cancel_grok(timeout: float = 70.0) -> dict[str, Any]:
    device.shell("am force-stop ai.x.grok")
    time.sleep(0.3)
    device.keyevent(3, 0.3)
    # sku URL opens Manage subscription. Tapping SuperGrok on the list
    # deep-links into Grok and never shows Cancel.
    device.shell(
        "am start -a android.intent.action.VIEW "
        "-c android.intent.category.BROWSABLE "
        "-d 'https://play.google.com/store/account/subscriptions?sku=grok.ultra&package=ai.x.grok' "
        "com.android.vending"
    )
    time.sleep(2.2)
    end = time.time() + timeout
    saw: list[str] = []
    while time.time() < end:
        blob = cancel_page_text()
        if not blob.strip():
            ping = device.shell("echo ok", timeout=6) or ""
            if "ok" not in ping:
                return {
                    "ok": False,
                    "stage": "cancel",
                    "saw": saw,
                    "kind": "adb_dead",
                    "ui": "",
                }
        low = blob.lower()
        foc = device.current_focus().lower()
        if "com.android.browser" in foc or "subscribe to services or content" in low:
            # Play Help covered the cancel sheet. force-stop the browser; the
            # sku manage page is still underneath.
            device.shell("am force-stop com.android.browser")
            saw.append("close_play_help")
            time.sleep(0.5)
            continue
        tos_xy = cancel_tos_tap(low)
        if tos_xy:
            device.tap(tos_xy[0], tos_xy[1], 1.1)
            saw.append("tos_accept")
            time.sleep(1.2)
            continue
        if cancel_authentication_required(low):
            # Authentication is required + Try again loops the same sheet.
            # Stop; re-auth Play (REMOVE+ADD), then cancel again.
            return {
                "ok": False,
                "stage": "cancel",
                "saw": saw,
                "kind": "play_auth_required",
                "ui": blob[:240],
            }
        if cancel_server_error_dialog(low):
            # OCR was "Error Server error" and the blue OK label was missing.
            # Same OK row as the no-internet sheet, cy=1836.
            hit = device.find_exact_text("OK")
            if hit:
                device.tap(int(hit["cx"]), int(hit["cy"]), 1.1)
            else:
                device.tap(540, 1836, 1.1)
            saw.append("server_error_ok")
            time.sleep(1.2)
            continue
        if cancel_no_internet_dialog(low):
            # The body node "then try again." sits at cy=1590; tap_text("OK",
            # "Try again") hits that sentence and the sheet stays. Exact "OK"
            # is the blue button at cy=1836; the no-internet sheet's blue
            # button is exact "Try again" (no OK).
            hit = device.find_exact_text("OK") or device.find_exact_text("Try again")
            if hit:
                device.tap(int(hit["cx"]), int(hit["cy"]), 1.1)
                label = str(hit.get("text") or "").strip().lower()
                saw.append("no_internet_try_again" if "try again" in label else "no_internet_ok")
                if "try again" in label:
                    device.prepare_play_iap()
                time.sleep(1.2)
                continue
        if "pause payments" in low or "pause your subscription" in low:
            # never tap left Pause; only right Cancel
            pass
        if "play points" in low and "not now" in low:
            # sku cancel stuck 70s on Introducing Google Play Points. Not now
            # cx=539 cy=1509 then Manage subscription appears.
            if device.tap_text("Not now"):
                saw.append("play_points_not_now")
                time.sleep(1.2)
                continue
        # OCR empty with saw=[]: one dump for Not now (540,1510), then stop
        # dumping. Looping 0B dumps kills the run.
        if (
            "cancel subscription" not in low
            and "resubscribe" not in low
            and "play_points_not_now_dump" not in saw
        ):
            hit = device.find_exact_text("Not now")
            if hit:
                device.tap(int(hit["cx"]), int(hit["cy"]), 1.1)
                saw.append("play_points_not_now_dump")
                time.sleep(1.2)
                continue
        # The washed GPA is already Canceled. Returning here skipped the new
        # GPA's Cancel subscription pill.
        stale = cancel_stale_page_action(low, saw)
        if stale == "done":
            return {"ok": True, "stage": "cancel", "saw": saw, "kind": "canceled"}
        if stale == "wait":
            saw.append("stale_canceled")
            time.sleep(2.0)
            continue
        if "select a reason" in low or "keep subscription" in low:
            if device.tap_lowest("Cancel subscription", min_y=1400, wait=1.2):
                saw.append("confirm")
                time.sleep(1.6)
                continue
        if "cancel subscription" in low:
            hit = device.ocr_find("Cancel subscription", "cancel-btn.png")
            x, y = cancel_right_xy(hit)
            device.tap(x, y, 1.1)
            saw.append("cancel_right")
            time.sleep(1.4)
            continue
        if "vending" in device.current_focus().lower() and any(
            k in low for k in ("supergrok", "grok heavy", "grok lite")
        ):
            if device.tap_text("SuperGrok", "Grok"):
                saw.append("open_row")
                time.sleep(1.5)
                continue
        time.sleep(0.8)
    blob = cancel_page_text("cancel-end.png")
    ok = "resubscribe" in blob.lower() or "canceled" in blob.lower()
    return {"ok": ok, "stage": "cancel", "saw": saw, "ui": blob[:240]}


def ack_token(token: str, work: Path) -> dict[str, Any]:
    if not token:
        return {"ok": False, "error": "empty_token"}
    # Unique per serial under HOOKS; a shared ack.live.js races concurrent ack.
    # frida-compile cwd is HOOKS; dest must stay in that tree.
    slug = device.serial_slug()
    src = HOOKS / f"ack.{slug}.js"
    compiled = HOOKS / f"ack.{slug}.compiled.js"
    text = ACK_TMPL.read_text(encoding="utf-8")
    text = re.sub(r"var TOKEN = '[^']+'", f"var TOKEN = '{token}'", text)
    src.write_text(text, encoding="utf-8")
    work.mkdir(parents=True, exist_ok=True)
    (work / "ack.token").write_text(token)
    comp = compile_js(src, compiled)
    if not comp.get("ok"):
        return {"ok": False, "error": "ack_compile", "compile": comp}
    box = fire("fire", hook=str(compiled))
    after = box.get("after") if isinstance(box, dict) else None
    acked = False
    blob = json.dumps(box, default=str)
    if "acknowledged" in blob.lower() and "true" in blob.lower():
        acked = True
    if box.get("rc") in (0, "0") or box.get("ok") is True:
        acked = True
    if isinstance(after, list) and after:
        acked = True
    box["acked"] = acked
    box["ok"] = bool(acked)
    return box
