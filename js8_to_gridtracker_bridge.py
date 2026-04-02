#!/usr/bin/env python3
import json
import os
import re
import time
import socket
import struct
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple, Dict, List

import requests
import xml.etree.ElementTree as ET

# ============================================================
# Config
# ============================================================
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 2237          # JS8Call Improved WSJT-X UDP output

GT_HOST = "127.0.0.1"
GT_PORT = 2240              # Point GridTracker here

# Your own callsign
MYCALL = "KE8SWO"

# Modes:
#   "network"  -> denser awareness, includes reporter/target relations
#   "clean"    -> more conservative, mostly direct-ish station presence
#   "shadow"   -> parse/classify/log only, do not emit synthetic packets
MODE = "network"

# Credentials file location
CRED_FILE = Path.home() / ".config" / "js8_gt_bridge" / "hamqth.json"

# HamQTH grid cache lifetime
CACHE_TTL_SECONDS = 7 * 24 * 3600   # 7 days

# Emit suppression windows by packet type
SUPPRESS_SECONDS = {
    "GRID": 600,   # station grid spots can be longer-lived
    "ACT": 45,     # activity should feel live
    "REL": 45,     # relationship traffic should feel live
    "CQ": 45,      # cq/group traffic should feel live
    "GRP": 45,     # group markers
}

LOOKUP_TIMEOUT = 6

# WSJT-X UDP constants
MAGIC = 0xadbccbda
SCHEMA = 2

TYPE_HEARTBEAT = 0
TYPE_STATUS = 1
TYPE_DECODE = 2

# 4- or 6-character Maidenhead
GRID_RE = re.compile(r"\b([A-R]{2}\d{2}(?:[A-X]{2})?)\b", re.I)

# Generic token finder
TOKEN_RE = re.compile(r"[A-Z0-9/@?+\-]+(?:/[A-Z0-9]+)?", re.I)

NONCALL_WORDS = {
    "CQ", "QRZ", "DE", "HB", "HEARTBEAT", "SNR", "ACK", "ACK?", "INFO", "INFO?",
    "GRID", "GRID?", "STATUS", "MSG", "MSGS", "MSGS?", "QUERY", "QUERY?",
    "NO", "YES", "HEARING", "HEARING?", "ALLCALL", "APRSIS", "NOCC",
    "TOPSTK", "FLASH", "MAGNET", "GHOSTNET", "TO", "FROM", "CALL", "CALL?",
    "QSO", "73", "RR", "RRR", "FB", "GE", "GM", "GA", "GN", "TU", "PSE",
    "AGN", "SRI", "TEST", "DX", "QRP", "OM", "YL", "X", "F", "ANY", "LUC",
    "QUERYING", "RELAY", "Q", "SNR?", "GRID", "INFO", "STATUS", "MSGS",
    "QUERY", "HEARING", "NIL", "NULL"
}

# Group tokens are treated as CQ-like broadcast traffic
GROUP_TOKEN_RE = re.compile(r"@([A-Z0-9_]+)", re.I)

# Confidence levels
CONF_NONE = 0
CONF_LOW = 1
CONF_MED = 2
CONF_HIGH = 3


# ============================================================
# Logging helpers
# ============================================================
def utc_now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def log(msg: str) -> None:
    print(f"[{utc_now_str()}] {msg}", flush=True)


# ============================================================
# Credential helpers
# ============================================================
def load_credentials() -> Tuple[str, str]:
    env_user = os.environ.get("HAMQTH_USER", "").strip()
    env_pass = os.environ.get("HAMQTH_PASS", "").strip()
    if env_user and env_pass:
        return env_user, env_pass

    if CRED_FILE.exists():
        try:
            data = json.loads(CRED_FILE.read_text())
            user = str(data.get("user", "")).strip()
            password = str(data.get("password", "")).strip()
            if user and password:
                return user, password
        except Exception as e:
            log(f"[bridge] WARNING: could not read credentials file {CRED_FILE}: {e}")

    return "", ""


# ============================================================
# Minimal WSJT-X packet helpers
# ============================================================
def pack_u32(x: int) -> bytes:
    return struct.pack(">I", x)


def pack_i32(x: int) -> bytes:
    return struct.pack(">i", x)


def pack_bool(b: bool) -> bytes:
    return struct.pack(">B", 1 if b else 0)


def pack_double(x: float) -> bytes:
    return struct.pack(">d", float(x))


def pack_utf8_as_qbytearray(s: str) -> bytes:
    b = s.encode("utf-8", errors="replace")
    return pack_u32(len(b)) + b


def pack_qtime_ms_since_midnight(ms: int) -> bytes:
    return pack_u32(ms & 0xFFFFFFFF)


def unpack_u32(buf: bytes, off: int) -> Tuple[int, int]:
    return struct.unpack_from(">I", buf, off)[0], off + 4


def unpack_i32(buf: bytes, off: int) -> Tuple[int, int]:
    return struct.unpack_from(">i", buf, off)[0], off + 4


def unpack_bool(buf: bytes, off: int) -> Tuple[bool, int]:
    return (struct.unpack_from(">B", buf, off)[0] != 0), off + 1


def unpack_double(buf: bytes, off: int) -> Tuple[float, int]:
    return struct.unpack_from(">d", buf, off)[0], off + 8


def unpack_qbytearray_utf8(buf: bytes, off: int) -> Tuple[str, int]:
    n, off = unpack_u32(buf, off)
    if n == 0xFFFFFFFF:
        return "", off
    s = buf[off:off + n].decode("utf-8", errors="replace")
    return s, off + n


def unpack_qtime(buf: bytes, off: int) -> Tuple[int, int]:
    ms, off = unpack_u32(buf, off)
    return ms, off


@dataclass
class DecodeMsg:
    schema: int
    msg_type: int
    wsjtx_id: str
    new: bool
    time_ms: int
    snr: int
    dt: float
    df: int
    mode: str
    text: str
    low_conf: bool
    off_air: bool


def parse_wsjtx_packet(pkt: bytes) -> Optional[DecodeMsg]:
    if len(pkt) < 12:
        return None

    magic, off = unpack_u32(pkt, 0)
    if magic != MAGIC:
        return None

    schema, off = unpack_u32(pkt, off)
    msg_type, off = unpack_u32(pkt, off)
    wsjtx_id, off = unpack_qbytearray_utf8(pkt, off)

    if msg_type != TYPE_DECODE:
        return None

    new, off = unpack_bool(pkt, off)
    time_ms, off = unpack_qtime(pkt, off)
    snr, off = unpack_i32(pkt, off)
    dt, off = unpack_double(pkt, off)
    df, off = unpack_u32(pkt, off)
    mode, off = unpack_qbytearray_utf8(pkt, off)
    text, off = unpack_qbytearray_utf8(pkt, off)
    low_conf, off = unpack_bool(pkt, off)
    off_air, off = unpack_bool(pkt, off)

    return DecodeMsg(
        schema=schema,
        msg_type=msg_type,
        wsjtx_id=wsjtx_id,
        new=new,
        time_ms=time_ms,
        snr=snr,
        dt=dt,
        df=df,
        mode=mode,
        text=text,
        low_conf=low_conf,
        off_air=off_air,
    )


def build_decode_packet(m: DecodeMsg, new_text: str) -> bytes:
    out = bytearray()
    out += pack_u32(MAGIC)
    out += pack_u32(SCHEMA)
    out += pack_u32(TYPE_DECODE)
    out += pack_utf8_as_qbytearray(m.wsjtx_id)

    out += pack_bool(m.new)
    out += pack_qtime_ms_since_midnight(m.time_ms)
    out += pack_i32(m.snr)
    out += pack_double(m.dt)
    out += pack_u32(m.df)
    out += pack_utf8_as_qbytearray(m.mode)
    out += pack_utf8_as_qbytearray(new_text)
    out += pack_bool(m.low_conf)
    out += pack_bool(m.off_air)
    return bytes(out)


# ============================================================
# HamQTH lookup
# ============================================================
class HamQTHClient:
    def __init__(self, user: str, password: str):
        self.user = user
        self.password = password
        self.session_id: Optional[str] = None
        self.session_expires_at = 0.0
        self.http = requests.Session()

    def _ensure_session(self) -> None:
        if not self.user or not self.password:
            raise RuntimeError("HamQTH credentials not configured")

        now = time.time()
        if self.session_id and now < self.session_expires_at - 30:
            return

        url = "https://www.hamqth.com/xml.php"
        r = self.http.get(
            url,
            params={"u": self.user, "p": self.password},
            timeout=LOOKUP_TIMEOUT,
        )
        r.raise_for_status()
        root = ET.fromstring(r.text)

        sid = None
        err = None
        for el in root.iter():
            tag = el.tag.lower()
            if tag.endswith("session_id"):
                sid = (el.text or "").strip()
            if tag.endswith("error"):
                err = (el.text or "").strip()

        if err:
            raise RuntimeError(f"HamQTH login error: {err}")
        if not sid:
            raise RuntimeError("HamQTH login failed: no session_id returned")

        self.session_id = sid
        self.session_expires_at = now + 3600

    def lookup_grid(self, callsign: str) -> Optional[str]:
        self._ensure_session()
        url = "https://www.hamqth.com/xml.php"
        r = self.http.get(
            url,
            params={"id": self.session_id, "callsign": callsign},
            timeout=LOOKUP_TIMEOUT,
        )
        r.raise_for_status()
        root = ET.fromstring(r.text)

        grid = None
        err = None
        for el in root.iter():
            tag = el.tag.lower()
            if tag.endswith("grid"):
                grid = (el.text or "").strip()
            if tag.endswith("error"):
                err = (el.text or "").strip()

        if err:
            return None

        if grid and GRID_RE.match(grid):
            return grid.upper()
        return None


# ============================================================
# Caches
# ============================================================
class TimedGridCache:
    def __init__(self):
        self._d: Dict[str, Tuple[str, float]] = {}
        self._lock = threading.Lock()

    def get(self, call: str) -> Optional[str]:
        now = time.time()
        call = call.upper()
        with self._lock:
            if call in self._d:
                grid, ts = self._d[call]
                if now - ts < CACHE_TTL_SECONDS:
                    return grid
                del self._d[call]
        return None

    def put(self, call: str, grid: str) -> None:
        with self._lock:
            self._d[call.upper()] = (grid.upper(), time.time())


class EmitSuppressCache:
    def __init__(self):
        self._d: Dict[Tuple[str, str, str], float] = {}
        self._lock = threading.Lock()

    def should_emit(self, kind: str, a: str, b: str = "") -> bool:
        now = time.time()
        key = (kind.upper(), a.upper(), b.upper())
        ttl = SUPPRESS_SECONDS.get(kind.upper(), 60)
        with self._lock:
            old_keys = [k for k, ts in self._d.items() if now - ts > max(SUPPRESS_SECONDS.values())]
            for k in old_keys:
                del self._d[k]

            last = self._d.get(key)
            if last is not None and now - last < ttl:
                return False

            self._d[key] = now
            return True


# ============================================================
# Parsing + classification
# ============================================================
def normalize_call_for_lookup(call: str) -> str:
    return call.split("/")[0].upper()


def normalize_call_for_display(call: str) -> str:
    return call.split("/")[0].upper()


def looks_like_callsign(token: str) -> bool:
    t = token.strip().upper().strip(",:;")
    if not t:
        return False
    if t.startswith("@"):
        return False
    if t in NONCALL_WORDS:
        return False
    if GRID_RE.fullmatch(t):
        return False
    if not re.search(r"[A-Z]", t):
        return False
    if not re.search(r"\d", t):
        return False
    if len(t) < 3 or len(t) > 15:
        return False
    return True


def parse_snr(text: str) -> Optional[int]:
    m = re.search(r"\bSNR\s*([+\-]?\d+)\b", text.upper())
    if not m:
        return None
    try:
        return int(m.group(1))
    except Exception:
        return None


def extract_group(text: str) -> Optional[str]:
    m = GROUP_TOKEN_RE.search((text or "").upper())
    if not m:
        return None
    return m.group(1).upper()


@dataclass
class ParsedTraffic:
    raw: str
    msg_class: str
    reporter_raw: Optional[str] = None
    target_raw: Optional[str] = None
    reporter: Optional[str] = None
    target: Optional[str] = None
    group: Optional[str] = None
    snr: Optional[int] = None
    confidence: int = CONF_NONE
    original_has_grid: bool = False
    drop_reason: Optional[str] = None


def _tokenize_side(s: str) -> List[str]:
    return [tok.strip(",:;") for tok in s.split() if tok.strip(",:;")]


def _first_call(tokens: List[str]) -> Optional[str]:
    for tok in tokens:
        if looks_like_callsign(tok):
            return tok
    return None


def classify_text(text: str) -> ParsedTraffic:
    t = (text or "").strip().upper()
    p = ParsedTraffic(
        raw=t,
        msg_class="unknown",
        group=extract_group(t),
        snr=parse_snr(t),
        original_has_grid=bool(GRID_RE.search(t)),
    )

    if not t:
        p.drop_reason = "empty line"
        return p

    if re.fullmatch(r"[A-Z0-9/]+\s*:\s*", t):
        p.drop_reason = "empty-colon line"
        return p

    # reporter: target ...
    if ":" in t:
        left, right = t.split(":", 1)
        left_tokens = _tokenize_side(left)
        right_tokens = _tokenize_side(right)

        p.reporter_raw = _first_call(left_tokens)
        p.target_raw = _first_call(right_tokens)

        p.reporter = normalize_call_for_display(p.reporter_raw) if p.reporter_raw else None
        p.target = normalize_call_for_display(p.target_raw) if p.target_raw else None

        if p.group:
            p.msg_class = "group"
            p.confidence = CONF_HIGH if p.reporter and p.group else CONF_MED
            return p

        if "HEARTBEAT" in t:
            p.msg_class = "heartbeat_report"
            p.confidence = CONF_HIGH if p.reporter and p.target else CONF_MED
            return p

        if re.search(r"\bSNR\b", t):
            p.msg_class = "snr_report"
            p.confidence = CONF_HIGH if p.reporter and p.target and p.snr is not None else CONF_MED
            return p

        for marker in ("ACK", "MSG", "QUERY", "INFO?", "GRID?", "STATUS", "HEARING", "NO", "YES"):
            if marker in t:
                p.msg_class = "directed_control"
                p.confidence = CONF_MED if p.reporter and p.target else CONF_LOW
                return p

        p.msg_class = "directed_text"
        p.confidence = CONF_MED if p.reporter and p.target else CONF_LOW
        return p

    # non-colon forms
    toks = _tokenize_side(t)
    p.target_raw = _first_call(toks)
    p.target = normalize_call_for_display(p.target_raw) if p.target_raw else None

    if p.group:
        p.msg_class = "group"
        p.confidence = CONF_MED if p.target else CONF_LOW
        return p

    if re.search(r"\bCQ\b", t):
        p.msg_class = "cq"
        p.confidence = CONF_MED if p.target else CONF_LOW
        return p

    if "HEARTBEAT" in t:
        p.msg_class = "heartbeat_direct"
        p.confidence = CONF_HIGH if p.target else CONF_LOW
        return p

    if p.target and p.snr is not None:
        p.msg_class = "activity_direct"
        p.confidence = CONF_MED
        return p

    if p.target:
        p.msg_class = "activity_ambiguous"
        p.confidence = CONF_LOW
        return p

    p.drop_reason = "no plausible callsign"
    return p


def should_process(parsed: ParsedTraffic) -> bool:
    if parsed.drop_reason:
        log(f"[bridge] drop {parsed.drop_reason}: {parsed.raw}")
        return False
    if parsed.confidence == CONF_NONE:
        log(f"[bridge] drop unclassified: {parsed.raw}")
        return False
    return True


# ============================================================
# Lookup + emission helpers
# ============================================================
def get_lookup_grid(call: str, ham: Optional[HamQTHClient], grid_cache: TimedGridCache) -> Optional[str]:
    if not call:
        return None

    call_lookup = normalize_call_for_lookup(call)

    cached = grid_cache.get(call_lookup)
    if cached:
        return cached

    if not ham:
        return None

    try:
        grid = ham.lookup_grid(call_lookup)
        if grid:
            grid_cache.put(call_lookup, grid)
            return grid
    except Exception as e:
        log(f"[bridge] lookup error for {call_lookup}: {e}")

    return None


def emit_packet(tx: socket.socket, dm: DecodeMsg, text: str) -> None:
    if MODE == "shadow":
        return
    out_pkt = build_decode_packet(dm, text)
    tx.sendto(out_pkt, (GT_HOST, GT_PORT))


def emit_grid_packet(tx: socket.socket, dm: DecodeMsg, emit_cache: EmitSuppressCache,
                     call: str, grid: str, source_text: str) -> None:
    if not call or not grid:
        return
    if not emit_cache.should_emit("GRID", call, grid):
        return

    new_text = f"{call} {grid}"
    emit_packet(tx, dm, new_text)
    log(f"[bridge] +grid {call} -> {grid} | {source_text}    ==>  {new_text}")


def emit_activity_packet(tx: socket.socket, dm: DecodeMsg, emit_cache: EmitSuppressCache,
                         call: str, snr: Optional[int], source_text: str) -> None:
    if not call:
        return
    snr_text = "" if snr is None else f" {snr:+d}"
    if not emit_cache.should_emit("ACT", call, snr_text):
        return

    new_text = f"{call}{snr_text}".strip()
    emit_packet(tx, dm, new_text)
    log(f"[bridge] +act  {call}{snr_text} | {source_text}    ==>  {new_text}")


def emit_relation_packet(tx: socket.socket, dm: DecodeMsg, emit_cache: EmitSuppressCache,
                         a: str, b: str, snr: Optional[int], source_text: str) -> None:
    if not a or not b or a == b:
        return
    snr_text = "" if snr is None else f" {snr:+d}"
    if not emit_cache.should_emit("REL", a, b + snr_text):
        return

    new_text = f"{a} {b}{snr_text}"
    emit_packet(tx, dm, new_text)
    log(f"[bridge] +rel  {a} -> {b}{snr_text} | {source_text}    ==>  {new_text}")


def emit_cq_packet(tx: socket.socket, dm: DecodeMsg, emit_cache: EmitSuppressCache,
                   call: str, grid: Optional[str], source_text: str, group: Optional[str] = None) -> None:
    if not call:
        return

    suffix = f" {grid}" if grid else ""
    label = group if group else "CQ"
    cache_key = f"{label}{suffix}"
    if not emit_cache.should_emit("CQ", call, cache_key):
        return

    new_text = f"CQ {call}{suffix}"
    emit_packet(tx, dm, new_text)
    log(f"[bridge] +cq   {call} [{label}] | {source_text}    ==>  {new_text}")

    if group and emit_cache.should_emit("GRP", call, group):
        rel_text = f"{call} {group}"
        emit_packet(tx, dm, rel_text)
        log(f"[bridge] +grp  {call} -> {group} | {source_text}    ==>  {rel_text}")


def log_classification(parsed: ParsedTraffic) -> None:
    log(
        "[bridge] classify "
        f"class={parsed.msg_class} conf={parsed.confidence} "
        f"reporter={parsed.reporter or '-'} target={parsed.target or '-'} "
        f"group={parsed.group or '-'} snr={parsed.snr if parsed.snr is not None else '-'} "
        f"text={parsed.raw}"
    )


# ============================================================
# Main
# ============================================================
def main():
    hamqth_user, hamqth_pass = load_credentials()

    log(f"[bridge] mode: {MODE}")
    log(f"[bridge] listening on {LISTEN_HOST}:{LISTEN_PORT} (from JS8Call)")
    log(f"[bridge] sending to  {GT_HOST}:{GT_PORT} (to GridTracker2)")
    log(f"[bridge] credential file: {CRED_FILE}")

    if hamqth_user and hamqth_pass:
        source = "environment variables" if os.environ.get("HAMQTH_USER") and os.environ.get("HAMQTH_PASS") else "credential file"
        log(f"[bridge] HamQTH credentials loaded from {source}")
    else:
        log("[bridge] WARNING: HamQTH credentials not configured. Lookups will be skipped.")

    ham = HamQTHClient(hamqth_user, hamqth_pass) if (hamqth_user and hamqth_pass) else None
    grid_cache = TimedGridCache()
    emit_cache = EmitSuppressCache()

    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        rx.bind((LISTEN_HOST, LISTEN_PORT))
    except OSError as e:
        log(f"[bridge] ERROR: could not bind to {LISTEN_HOST}:{LISTEN_PORT}: {e}")
        log("[bridge] Another process is probably already using that UDP port.")
        log(f"[bridge] Try: sudo ss -ulpn | grep {LISTEN_PORT}")
        log("[bridge] Or kill old bridge instances with: pkill -f js8_to_gridtracker_bridge.py")
        raise

    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    while True:
        pkt, _addr = rx.recvfrom(8192)

        dm = parse_wsjtx_packet(pkt)
        if dm is None:
            if MODE != "shadow":
                tx.sendto(pkt, (GT_HOST, GT_PORT))
            continue

        # Always forward the original decode unless shadow mode
        if MODE != "shadow":
            tx.sendto(pkt, (GT_HOST, GT_PORT))

        parsed = classify_text(dm.text or "")
        if not should_process(parsed):
            continue

        # Normalize away self clutter
        if parsed.reporter == MYCALL:
            parsed.reporter = None
        if parsed.target == MYCALL:
            parsed.target = None

        # Re-evaluate if both sides disappeared
        if not parsed.reporter and not parsed.target:
            log(f"[bridge] drop no usable non-self station: {parsed.raw}")
            continue

        log_classification(parsed)

        reporter_grid = get_lookup_grid(parsed.reporter, ham, grid_cache) if parsed.reporter else None
        target_grid = get_lookup_grid(parsed.target, ham, grid_cache) if parsed.target else None

        # ----------------------------------------------------
        # Emission strategy by mode and confidence
        # ----------------------------------------------------

        # GRID packets: more conservative
        if not parsed.original_has_grid:
            if parsed.confidence >= CONF_MED:
                if parsed.target and target_grid:
                    emit_grid_packet(tx, dm, emit_cache, parsed.target, target_grid, parsed.raw)
                if MODE == "network" and parsed.reporter and reporter_grid:
                    emit_grid_packet(tx, dm, emit_cache, parsed.reporter, reporter_grid, parsed.raw)

        # Activity packets
        if parsed.msg_class in {"heartbeat_direct", "activity_direct", "cq", "group"}:
            if parsed.target:
                emit_activity_packet(tx, dm, emit_cache, parsed.target, parsed.snr, parsed.raw)

        elif parsed.msg_class in {"heartbeat_report", "snr_report", "directed_control", "directed_text"}:
            if MODE == "network":
                if parsed.target:
                    emit_activity_packet(tx, dm, emit_cache, parsed.target, parsed.snr, parsed.raw)
                if parsed.reporter and parsed.confidence >= CONF_HIGH:
                    emit_activity_packet(tx, dm, emit_cache, parsed.reporter, parsed.snr, parsed.raw)
            elif MODE == "clean":
                if parsed.target and parsed.confidence >= CONF_HIGH:
                    emit_activity_packet(tx, dm, emit_cache, parsed.target, parsed.snr, parsed.raw)

        elif parsed.msg_class == "activity_ambiguous":
            if MODE == "network" and parsed.target:
                emit_activity_packet(tx, dm, emit_cache, parsed.target, parsed.snr, parsed.raw)

        # Relation packets only in network mode, and only medium/high confidence
        if MODE == "network" and parsed.confidence >= CONF_MED:
            if parsed.reporter and parsed.target:
                emit_relation_packet(tx, dm, emit_cache, parsed.reporter, parsed.target, parsed.snr, parsed.raw)

        # CQ/group packets
        if parsed.msg_class in {"cq", "group"}:
            cq_sender = parsed.target or parsed.reporter
            cq_grid = target_grid or reporter_grid
            if cq_sender:
                emit_cq_packet(tx, dm, emit_cache, cq_sender, cq_grid, parsed.raw, group=parsed.group)

        # High-confidence heartbeat direct can also look a little CQ-like for awareness
        if MODE == "network" and parsed.msg_class == "heartbeat_direct" and parsed.target:
            emit_cq_packet(tx, dm, emit_cache, parsed.target, target_grid, parsed.raw, group=None)


if __name__ == "__main__":
    main()