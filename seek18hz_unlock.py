# SPDX-License-Identifier: MIT
# Copyright (c) 2026 hedger <hedger@nanode.su>
"""
seek18hz_unlock.py
==================

Standalone Seek Thermal Compact PRO (USB 0x289D:0x0011) 18 Hz frame-rate
unlock for current firmware. Self-contained; depends only on `pyusb`.

Safety:
    * Dry-run by default. Pass --commit to actually write to flash.
    * Detects already-patched devices and exits gracefully (idempotent).
    * Validates plaintext header magic, length, vector table, and the
      bootloader's checksum invariant (sum-of-u32 == 0xFFFF) BEFORE
      uploading.
    * Re-reads the slot after upload (decrypting with the device-side
      KeyB) to confirm the patched bytes are present.

Tested on macOS (libusb via Homebrew). Should work on Linux (libusb-1.0
package) and Windows (libusb DLL + WinUSB driver via Zadig).

Usage:
    python seek18hz_unlock.py            # dry-run / status check
    python seek18hz_unlock.py --commit   # actually flash

Exit codes:
    0  patch was applied successfully OR device already patched
    1  device not found
    2  device firmware does not match expected layout / refused patch
    3  flash write failed / readback verification failed
    4  user did not pass --commit (dry-run reported what would happen)
"""

from __future__ import annotations

import argparse
import os
import re
import struct
import sys
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path

# PyInstaller + Windows: add the bundle temp dir to the DLL search path so
# the bundled libusb-1.0.dll is found by ctypes when usb.core initialises.
if sys.platform == "win32" and getattr(sys, "frozen", False):
    os.add_dll_directory(sys._MEIPASS)  # type: ignore[attr-defined]

try:
    import usb.core
    import usb.util
except ImportError:
    sys.stderr.write(
        "ERROR: pyusb is not installed.\n"
        "  Install with: pip install -r requirements.txt\n"
        "  System libusb is also required:\n"
        "    macOS:   brew install libusb\n"
        "    Linux:   apt install libusb-1.0-0  (or distro equivalent)\n"
        "    Windows: install WinUSB driver via Zadig (https://zadig.akeo.ie)\n"
    )
    raise SystemExit(2)


# ============================================================================
# Device / USB constants
# ============================================================================
VID = 0x289D
PID = 0x0011

BMREQ_OUT = 0x41   # vendor | interface | OUT
BMREQ_IN  = 0xC1   # vendor | interface | IN

OP_GET_ERROR_CODE             = 0x35
OP_SET_OPERATION_MODE         = 0x3C
OP_GET_OPERATION_MODE         = 0x3D
OP_GET_FIRMWARE_INFO          = 0x4E  # IN  — firmware version + build date
OP_GET_FEATURED_FIRMWARE_DATA = 0x4F  # IN  — read upgrade window
OP_SET_FEATURED_FIRMWARE_DATA = 0x50  # OUT — write upgrade chunk
OP_COMPLETE_MEMORY_UPGRADE    = 0x51  # OUT — verify+commit (u16 checksum)
OP_BEGIN_FIRMWARE_UPGRADE     = 0x52  # OUT — select bank (u16 subcmd)
OP_RESET_DEVICE               = 0x59
OP_SET_RAM_DATA_FEATURES      = 0x5A  # OUT — arm upgrade-window (case 0 = device-id block)

# SetRamDataFeatures case IDs
RAM_DATA_CASE_DEVICE_ID = 0  # window → g_device_id_block_a (248 B); serial at +16
# arg1 is the window size in u16 words (window_bytes = arg1 * 2).
# Case 0 validates arg1 <= 0x7C (124), so 124 * 2 = 248 bytes max.
RAM_DATA_CASE0_ARG1 = 124   # 0x7C — requests the full 248-byte device-id block

# ============================================================================
# Subcmd dumping — exploratory probe of all accessible flash windows
#
# Instead of assuming a fixed mapping, we probe a range of BeginFirmwareUpgrade
# subcmds and save whatever raw data the device returns. Subcmds that error out
# or return only 0xFF padding are skipped. The patch logic still uses specific
# subcmds (0 = write target, 8 = active bank readback) which were identified
# through prior RE; those constants remain for the unlock path only.
# ============================================================================

# Subcmds probed during exploratory dump.
# The firmware has 68 entries (0..67) in its BeginFirmwareUpgrade dispatch table;
# subcmds 46-67 all return 0xFF (unmapped) on our unit but may differ on others.
SUBCMD_DUMP_RANGE = range(0, 68)  # probe all 68 known subcmd slots

# Patch-relevant subcmds (identified via prior RE, not assumed from mapping)
SUBCMD_MAIN_FW   = 0     # write target (Bank A for reads, Bank B for writes)
SUBCMD_ACTIVE_FW = 8     # Bank B readback (reflects last write after power-cycle)

READ_CAP       = 0xFF00   # FSM reliably caps reads at 65,280 B
READ_CHUNK     = 256
SUBCMD_PROBE_SIZE = 256   # initial probe read for each subcmd (small/fast)
SUBCMD_FULL_SIZE  = 0x10000  # full read for subcmds that return non-FF data

# ============================================================================
# Firmware layout
# ============================================================================
HEADER_OFFS  = 512
HEADER_MAGIC = 0xA1B2C3D4      # regular firmware (not recovery)
RAM_LO, RAM_HI = 0x10000000, 0x10020000

# 18 Hz patch site — located via masked signature for forward-compat across
# firmware revisions. In current firmware (54,840 B plaintext) the unique hit
# is at file offset 0x19B0; rec[20] starts there. Patch byte at +3, checksum
# compensator at +0x0F (zero padding inside the same record).
#
# The signature masks byte 3 (the enable byte we patch) so the same matcher
# works on both factory and patched firmware. Layout of rec[20] header:
#   +0: 0x02 (type=framerate)  +1: 0x14  +2: 0x14  +3: enable (00/01)
#   +4: 0xFF                   +5: 0xFF  +6: 0x00 +7: 0x20
REC20_SIG_HEAD   = bytes.fromhex("021414")     # bytes 0..2
REC20_SIG_TAIL   = bytes.fromhex("ffff0020")   # bytes 4..7
REC20_ENABLE_OFF = 3       # 0x00 = 18 Hz disabled, 0x01 = enabled
REC20_COMP_OFF   = 0x0F    # padding byte we flip to 0xFF to cancel checksum delta
PATCH_ENABLE_NEW = 0x01
PATCH_COMP_NEW   = 0xFF

# ============================================================================
# Bootloader-extracted keys (xorshift128, shifts 11/8/19; key XORed with
# 0x13579BDF then assigned with one-slot left-rotation).
#   KeyA — primary key, used to decrypt factory-encrypted firmware blobs and
#          for the upload path (host -> device).
#   KeyB — fallback used by the bootloader when the device-unique key region
#          @ flash 0x14000218..0x14000228 is all 0x00 or all 0xFF. On any
#          unit where that region is unfused, the device re-encrypts uploads
#          with KeyB before storing to flash. Readback therefore needs KeyB.
# ============================================================================
KEY_A = bytes.fromhex("9091a79257d81aa75f7c77bab0aafa02")
KEY_B = bytes.fromhex("95be600d80dc442d7aa00a8a9644bc54")
INIT_XOR = 0x13579BDF
HEADER_PRESERVE_RANGE = (128, 144)  # dwords [128..143] = file [512..575]

MASK32 = 0xFFFFFFFF


# ============================================================================
# xorshift128 cipher (self-inverse — encrypt == decrypt)
# ============================================================================
def _key_schedule(key: bytes) -> list[int]:
    k = list(struct.unpack("<4I", key))
    # state[3] = key[0] ^ INIT_XOR ; left-rotate-by-one assignment
    return [
        (k[1] ^ INIT_XOR) & MASK32,
        (k[2] ^ INIT_XOR) & MASK32,
        (k[3] ^ INIT_XOR) & MASK32,
        (k[0] ^ INIT_XOR) & MASK32,
    ]


def _next_word(s: list[int]) -> int:
    t = (s[0] ^ (s[0] << 11)) & MASK32
    s[0], s[1], s[2] = s[1], s[2], s[3]
    s[3] = (s[3] ^ (s[3] >> 19) ^ t ^ (t >> 8)) & MASK32
    return s[3]


def crypt(buf: bytes, key: bytes) -> bytes:
    """XOR `buf` with the xorshift128 keystream derived from `key`.
    Dwords [128..143] (file offset 512..575 = plaintext header) are
    passed through verbatim; keystream still advances."""
    state = _key_schedule(key)
    out = bytearray(len(buf))
    nwords = len(buf) // 4
    lo, hi = HEADER_PRESERVE_RANGE
    for i in range(nwords):
        ks = _next_word(state)
        word = struct.unpack_from("<I", buf, i * 4)[0]
        if lo <= i < hi:
            out_word = word                  # bypass for header
        else:
            out_word = (word ^ ks) & MASK32  # XOR with keystream
        struct.pack_into("<I", out, i * 4, out_word)
    # Tail bytes (if len not multiple of 4): copy verbatim. The bootloader
    # never decrypts these because they're beyond the declared `length`.
    rem = len(buf) - nwords * 4
    if rem:
        out[nwords * 4:] = buf[nwords * 4:]
    return bytes(out)


def checksum(buf: bytes) -> int:
    """Sum of u32 little-endian words over the first len(buf) bytes,
    mod 2^32. The bootloader requires this == 0xFFFF for the first
    `header.length` bytes of plaintext."""
    n = len(buf) // 4
    total = 0
    for i in range(n):
        total = (total + struct.unpack_from("<I", buf, i * 4)[0]) & MASK32
    return total


# ============================================================================
# USB wire helpers
# ============================================================================
class Wire:
    def __init__(self, dev):
        self.dev = dev

    def out(self, op: int, payload: bytes, timeout: int = 5000) -> None:
        n = self.dev.ctrl_transfer(BMREQ_OUT, op, 0, 0, payload, timeout)
        if n != len(payload):
            raise IOError(f"opcode 0x{op:02X}: short write {n}/{len(payload)}")

    def inn(self, op: int, length: int, timeout: int = 5000) -> bytes:
        return bytes(self.dev.ctrl_transfer(BMREQ_IN, op, 0, 0, length, timeout))

    def get_firmware_info(self) -> "FirmwareInfo":
        try:
            return FirmwareInfo.from_bytes(self.inn(OP_GET_FIRMWARE_INFO, 64))
        except Exception:
            return FirmwareInfo()

    def get_err(self) -> int:
        return int.from_bytes(self.inn(OP_GET_ERROR_CODE, 4), "little")

    def get_op(self) -> int:
        return int.from_bytes(self.inn(OP_GET_OPERATION_MODE, 2), "little")

    def set_op(self, mode: int) -> None:
        self.out(OP_SET_OPERATION_MODE, mode.to_bytes(2, "little"))

    def begin_upgrade(self, subcmd: int) -> None:
        self.out(OP_BEGIN_FIRMWARE_UPGRADE, subcmd.to_bytes(2, "little"))

    def write_chunk(self, chunk: bytes) -> None:
        self.out(OP_SET_FEATURED_FIRMWARE_DATA, chunk)

    def read_chunk(self, length: int) -> bytes:
        return self.inn(OP_GET_FEATURED_FIRMWARE_DATA, length)

    def complete_upgrade(self, csum16: int) -> None:
        self.out(OP_COMPLETE_MEMORY_UPGRADE, csum16.to_bytes(2, "little"))

    def set_ram_data_features(self, case: int, arg1: int = 0, arg2: int = 0) -> None:
        self.out(OP_SET_RAM_DATA_FEATURES,
                 struct.pack("<HHH", case, arg1, arg2))

    def get_serial(self) -> str:
        """Read the 12-char ASCII serial from g_device_id_block_a offset +16.

        Uses the SetRamDataFeatures(case=0, arg1=124) → GetFeaturedFirmwareData path
        (non-destructive RAM read; auto-disarms after the window is consumed).
        arg1=124 (0x7C) → window_size = 124*2 = 248 bytes (firmware validated max).
        Returns an empty string on any failure.
        """
        try:
            self.set_ram_data_features(RAM_DATA_CASE_DEVICE_ID, arg1=RAM_DATA_CASE0_ARG1)
            block = self.read_chunk(248)
            # serial is 12 ASCII bytes at offset 16 (0x10)
            raw = block[16:28]
            return raw.rstrip(b"\x00").decode("ascii", errors="replace")
        except Exception:
            return ""

    def reset(self) -> None:
        try:
            self.out(OP_RESET_DEVICE, b"", timeout=2000)
        except Exception:
            pass  # device drops mid-transaction during reset


# ============================================================================
# Domain data structures
# ============================================================================
@dataclass
class FirmwareInfo:
    """Parsed GetFirmwareInfo (0x4E) response from the camera.

    On-wire layout (36 B, confirmed on live device and decrypted binary):
      +0x00  u8[4]   version  major.minor.patch.build  (e.g. 4.9.1.15)
      +0x04  char[]  __DATE__ null-terminated (e.g. "Mar 14 2019")
      +0x10  char[]  __TIME__ null-terminated (e.g. "09:18:41")
    """
    version: tuple[int, int, int, int] = (0, 0, 0, 0)
    build_date: str = ""
    build_time: str = ""

    @classmethod
    def from_bytes(cls, raw: bytes) -> "FirmwareInfo":
        """Parse the 0x4E response bytes. Returns a default instance on failure."""
        version: tuple[int, int, int, int] = (0, 0, 0, 0)
        build_date = build_time = ""
        if len(raw) >= 4:
            v = raw[0:4]
            if any(b not in (0x00, 0xFF) for b in v):
                version = (v[0], v[1], v[2], v[3])
        if len(raw) > 4:
            rest = raw[4:]
            end1 = rest.find(b'\x00')
            date_bytes = rest[:end1] if end1 >= 0 else rest
            build_date = date_bytes.decode('ascii', errors='replace').strip()
            if build_date and end1 >= 0:
                after = rest[end1 + 1:]
                start2 = next((i for i, b in enumerate(after) if b != 0), len(after))
                end2 = after.find(b'\x00', start2)
                time_bytes = after[start2:end2] if end2 >= 0 else after[start2:]
                build_time = time_bytes.decode('ascii', errors='replace').strip()
        return cls(version=version, build_date=build_date, build_time=build_time)

    @property
    def version_str(self) -> str:
        return ".".join(str(v) for v in self.version)

    @property
    def slug(self) -> str:
        """Filename-safe version string, e.g. 'v4.9.1.15'."""
        if any(v not in (0, 0xFF) for v in self.version):
            return f"v{self.version_str}"
        return "vunknown"

    @property
    def build(self) -> str:
        return f"{self.build_date} {self.build_time}".strip()

    def __str__(self) -> str:
        parts = []
        if any(v not in (0, 0xFF) for v in self.version):
            parts.append(f"ver={self.version_str}")
        if self.build:
            parts.append(f"build={self.build}")
        return "  ".join(parts) if parts else "(unavailable)"


# ============================================================================
# Artifact saving helpers
# ============================================================================
def _sanitize_slug(s: str, maxlen: int = 20) -> str:
    """Return a filename-safe version of s, truncated to maxlen characters."""
    return re.sub(r'[^A-Za-z0-9._-]', '_', s)[:maxlen]


def _unique_path(p: Path) -> Path:
    """Return p if it does not exist, else append a _NNN counter until free."""
    if not p.exists():
        return p
    parent, stem, suffix = p.parent, p.stem, p.suffix
    n = 1
    while True:
        candidate = parent / f"{stem}_{n:03d}{suffix}"
        if not candidate.exists():
            return candidate
        n += 1


def save_derived(slug: str, subcmd: int, data: bytes, suffix: str) -> Path:
    """Save a derived file (plain, patched, etc.) as
    seek_<slug>_subcmd_<NN>_<suffix>.bin. Never clobbers."""
    p = _unique_path(Path(f"seek_{slug}_subcmd_{subcmd:02d}_{suffix}.bin"))
    p.write_bytes(data)
    return p


def open_device() -> "usb.core.Device":
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        sys.stderr.write(
            f"ERROR: Seek Compact PRO not found (VID=0x{VID:04X} PID=0x{PID:04X}).\n"
            "  - Check the USB cable.\n"
            "  - On Linux, you may need udev rules or to run as root.\n"
            "  - On Windows, install the WinUSB driver via Zadig.\n"
        )
        raise SystemExit(1)
    try:
        if dev.get_active_configuration() is None:
            dev.set_configuration()
    except usb.core.USBError:
        try:
            dev.set_configuration()
        except usb.core.USBError as e:
            sys.stderr.write(f"WARN: set_configuration: {e}\n")
    try:
        usb.util.claim_interface(dev, 0)
    except usb.core.USBError as e:
        sys.stderr.write(f"WARN: claim_interface: {e}\n")
    return dev


# ============================================================================
# Flash I/O
# ============================================================================
def _is_all_ff(data: bytes) -> bool:
    """True if data is all 0xFF (erased/unmapped flash)."""
    return all(b == 0xFF for b in data)


def explore_subcmds(w: "Wire", slug: str, zf: zipfile.ZipFile,
                    subcmds: range = SUBCMD_DUMP_RANGE,
                    probe_size: int = SUBCMD_PROBE_SIZE,
                    full_size: int = SUBCMD_FULL_SIZE,
                    ) -> dict[int, bytes]:
    """Probe each subcmd in *subcmds*, write non-empty dumps directly into *zf*.

    Returns a dict of {subcmd: raw_data} for all subcmds that returned
    non-0xFF data. No loose .bin files are created for dump data —
    everything goes into the ZIP.
    """
    results: dict[int, bytes] = {}
    name = lambda sc: f"seek_{slug}_subcmd_{sc:02d}.bin"
    for sc in subcmds:
        try:
            probe = dump_slot(w, subcmd=sc, bytes_to_read=probe_size)
        except IOError as e:
            print(f"      subcmd {sc:02d}: SKIP ({e})")
            continue
        if not probe or _is_all_ff(probe):
            continue
        try:
            data = dump_slot(w, subcmd=sc, bytes_to_read=full_size)
        except IOError:
            data = probe
        results[sc] = data
        zf.writestr(name(sc), data)
        print(f"      subcmd {sc:02d}: {len(data):>5} B  head={data[:8].hex()}  → {name(sc)}")
    return results
def dump_slot(w: Wire, *, bytes_to_read: int = READ_CAP,
              chunk: int = READ_CHUNK,
              subcmd: int = SUBCMD_MAIN_FW) -> bytes:
    """Read `bytes_to_read` from the given subcmd flash window.

    Read-only — never calls SetFeaturedFirmwareData or CompleteMemoryUpgrade.

    Subcmd mapping (see FINDINGS.md):
      0,5,7,9 → Bank A (factory, KeyA-encrypted)
      8       → Bank B (active upgrade, KeyB-encrypted after first flash)
      2       → Bootloader (64 KiB, plain XIP — no encryption)
      1,4     → Config / calibration block
      3       → Bank-selector table
    """
    if w.get_op() != 0:
        w.set_op(0)
        time.sleep(0.02)
    w.begin_upgrade(subcmd)
    time.sleep(0.02)
    err = w.get_err()
    if err:
        raise IOError(f"BeginFirmwareUpgrade({subcmd}) returned err 0x{err:08X}")
    buf = bytearray()
    while len(buf) < bytes_to_read:
        want = min(chunk, bytes_to_read - len(buf))
        try:
            blk = w.read_chunk(want)
        except Exception as e:
            sys.stderr.write(
                f"WARN: read stopped at {len(buf)}/{bytes_to_read} B: {e}\n"
            )
            break
        if not blk:
            break
        buf.extend(blk)
    return bytes(buf)


# Compatibility alias for existing callers
dump_main_slot = dump_slot


def upload_image(w: Wire, image: bytes, *, chunk: int = 64) -> int:
    """Stream `image` to the main slot. Returns the device-side
    sum-16 of the uploaded bytes (the value passed to Complete)."""
    if w.get_op() != 0:
        w.set_op(0)
        time.sleep(0.02)
    # NOTE: SetRamDataFeatures(case=11) "arm" step is INTENTIONALLY skipped.
    # On current firmware it returns err 0x20000 and is not required —
    # BeginFirmwareUpgrade(0) sets up the upgrade FSM on its own.
    w.begin_upgrade(SUBCMD_MAIN_FW)
    err = w.get_err()
    if err:
        raise IOError(f"BeginFirmwareUpgrade(0) returned err 0x{err:08X}")
    total = len(image)
    nchunks = (total + chunk - 1) // chunk
    t0 = time.time()
    for i in range(nchunks):
        off = i * chunk
        end = min(off + chunk, total)
        w.write_chunk(image[off:end])
        if (i % 128) == 0 or i == nchunks - 1:
            pct = 100.0 * end / total
            dt = time.time() - t0
            rate = end / dt / 1024 if dt > 0 else 0
            sys.stdout.write(
                f"\r    upload: {end}/{total} B ({pct:5.1f}%, {rate:.1f} KB/s)   "
            )
            sys.stdout.flush()
    sys.stdout.write("\n")
    err = w.get_err()
    if err:
        raise IOError(
            f"streaming failed with err 0x{err:08X}; "
            f"aborting BEFORE Complete (image NOT committed)."
        )
    csum16 = sum(image) & 0xFFFF
    w.complete_upgrade(csum16)
    time.sleep(0.05)
    err = w.get_err()
    if err == 0x70000:
        raise IOError("device rejected checksum (err 0x70000) — image NOT committed.")
    if err:
        raise IOError(f"CompleteMemoryUpgrade failed with err 0x{err:08X}")
    return csum16


def wait_for_reenum(timeout_s: float = 20.0) -> "usb.core.Device":
    t0 = time.time()
    while time.time() - t0 < timeout_s:
        time.sleep(0.5)
        dev = usb.core.find(idVendor=VID, idProduct=PID)
        if dev is not None:
            return dev
    raise IOError(f"device did not re-enumerate within {timeout_s}s")


# ============================================================================
# Patch logic
# ============================================================================
def _find_rec20(plain: bytes) -> int:
    """Locate rec[20] by masked signature (byte 3 = enable, wildcarded).
    Works on both factory and patched firmware."""
    hits = []
    i = 0
    tail_off = len(REC20_SIG_HEAD) + 1     # skip enable byte at offset 3
    while True:
        j = plain.find(REC20_SIG_HEAD, i)
        if j < 0:
            break
        i = j + 1
        if plain[j + tail_off:j + tail_off + len(REC20_SIG_TAIL)] == REC20_SIG_TAIL:
            hits.append(j)
    if not hits:
        raise ValueError(
            f"rec[20] signature {REC20_SIG_HEAD.hex()}??{REC20_SIG_TAIL.hex()} "
            "NOT FOUND — firmware layout differs from expected."
        )
    if len(hits) > 1:
        raise ValueError(
            f"rec[20] signature ambiguous (found at {[hex(h) for h in hits]})."
        )
    return hits[0]


@dataclass
class FirmwareImage:
    """A validated, decrypted firmware image with its structural metadata.

    Construct with FirmwareImage.from_encrypted() from a raw flash slot.
    Call .patch() to produce an 18 Hz-unlocked copy, .encrypt() to re-encrypt.
    """
    data: bytes             # full plaintext bytes
    key_name: str           # "KeyA" or "KeyB" — key that decrypted this image
    magic: int              # header magic word
    length: int             # declared plaintext length (used for checksum)
    sp: int                 # initial stack pointer (vector table[0])
    reset: int              # reset handler address (vector table[1])
    csum: int               # sum-of-u32 over data[:length]
    rec20_off: int          # byte offset of rec[20] in data
    enable_byte: int        # current 18 Hz enable flag (0x00 or 0x01)
    comp_byte: int          # current checksum-compensator byte value

    # ------------------------------------------------------------------ #
    # Deserialization                                                      #
    # ------------------------------------------------------------------ #
    @classmethod
    def from_encrypted(cls, enc: bytes) -> "FirmwareImage":
        """Decrypt *enc* with KeyA then KeyB, validate structure, return an instance.
        Prefers the key whose decryption passes the checksum invariant.
        Raises ValueError if no valid image can be decoded."""
        candidates = []
        for key_name, key in (("KeyA", KEY_A), ("KeyB", KEY_B)):
            plain = crypt(enc, key)
            magic = struct.unpack_from("<I", plain, HEADER_OFFS)[0]
            if magic != HEADER_MAGIC:
                continue
            length = struct.unpack_from("<I", plain, HEADER_OFFS + 4)[0]
            if not (0 < length <= len(plain)):
                continue
            csum = checksum(plain[:length])
            candidates.append((csum == 0xFFFF, key_name, plain, magic, length, csum))
        candidates.sort(key=lambda c: not c[0])  # checksum-valid first
        if not candidates:
            raise ValueError(
                f"neither KeyA nor KeyB decrypts to magic 0x{HEADER_MAGIC:08X}."
            )
        csum_ok, key_name, plain, magic, length, csum = candidates[0]
        sp, reset = struct.unpack_from("<2I", plain, 0)
        if sp != 0x10020000:
            raise ValueError(f"vector SP=0x{sp:08X}, expected 0x10020000")
        if not (RAM_LO <= reset <= RAM_HI):
            raise ValueError(f"vector Reset=0x{reset:08X} not in RAM")
        if not csum_ok:
            raise ValueError(f"checksum 0x{csum:08X} != 0x0000FFFF")
        rec20_off = _find_rec20(plain)
        return cls(
            data=plain,
            key_name=key_name,
            magic=magic,
            length=length,
            sp=sp,
            reset=reset,
            csum=csum,
            rec20_off=rec20_off,
            enable_byte=plain[rec20_off + REC20_ENABLE_OFF],
            comp_byte=plain[rec20_off + REC20_COMP_OFF],
        )

    # ------------------------------------------------------------------ #
    # Serialization                                                        #
    # ------------------------------------------------------------------ #
    def encrypt(self, key: bytes = KEY_A) -> bytes:
        """Re-encrypt this image with *key* and return the encrypted slot bytes."""
        return crypt(self.data, key)

    # ------------------------------------------------------------------ #
    # State properties                                                     #
    # ------------------------------------------------------------------ #
    @property
    def enable_off(self) -> int:
        """Absolute byte offset of the 18 Hz enable flag in data."""
        return self.rec20_off + REC20_ENABLE_OFF

    @property
    def comp_off(self) -> int:
        """Absolute byte offset of the checksum-compensator byte in data."""
        return self.rec20_off + REC20_COMP_OFF

    @property
    def status(self) -> str:
        """'patched', 'unpatched', or 'unknown'."""
        if self.enable_byte == 0x00 and self.comp_byte == 0x00:
            return "unpatched"
        if self.enable_byte == PATCH_ENABLE_NEW and self.comp_byte == PATCH_COMP_NEW:
            return "patched"
        return "unknown"

    # ------------------------------------------------------------------ #
    # Mutation                                                             #
    # ------------------------------------------------------------------ #
    def patch(self) -> "FirmwareImage":
        """Return a new FirmwareImage with the 18 Hz unlock applied.
        Raises ValueError if not in the expected factory (unpatched) state."""
        if self.enable_byte != 0x00:
            raise ValueError(
                f"enable byte at 0x{self.enable_off:04X} = 0x{self.enable_byte:02X}; "
                "expected 0x00 (18 Hz disabled). Already patched or layout changed."
            )
        if self.comp_byte != 0x00:
            raise ValueError(
                f"compensator at 0x{self.comp_off:04X} = 0x{self.comp_byte:02X}; "
                "expected 0x00. Refusing to overwrite."
            )
        buf = bytearray(self.data)
        buf[self.enable_off] = PATCH_ENABLE_NEW
        buf[self.comp_off]   = PATCH_COMP_NEW
        new_data = bytes(buf)
        return FirmwareImage(
            data=new_data,
            key_name=self.key_name,
            magic=self.magic,
            length=self.length,
            sp=self.sp,
            reset=self.reset,
            csum=checksum(new_data[:self.length]),
            rec20_off=self.rec20_off,
            enable_byte=PATCH_ENABLE_NEW,
            comp_byte=PATCH_COMP_NEW,
        )


def run(args: argparse.Namespace) -> int:
    print("=" * 60)
    print("Seek Thermal Compact PRO FPS Unlock - by hedger, https://github.com/hedger")
    print("=" * 60)

    # 1. Open device
    print("\n[1/6] Opening device ...")
    dev = open_device()
    w = Wire(dev)
    print(f"      op_mode={w.get_op()}  last_err=0x{w.get_err():08X}")
    serial = _sanitize_slug(w.get_serial()) or "noserial"
    print(f"      serial={serial}")

    fw_info = w.get_firmware_info()
    slug = f"{serial}_{fw_info.slug}"
    zip_path = _unique_path(Path(f"seek_{slug}_dump.zip"))

    # 2. Exploratory dump — probe all subcmds, write directly into ZIP
    print(f"\n[2/6] Probing subcmds {SUBCMD_DUMP_RANGE.start}..{SUBCMD_DUMP_RANGE.stop - 1} ...")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        dump_data = explore_subcmds(w, slug, zf)
    if not dump_data:
        sys.stderr.write("ERROR: no subcmds returned data — device may be in wrong mode.\n")
        return 2
    print(f"      {len(dump_data)} subcmd(s) returned non-empty data → {zip_path.name}")

    # Extract firmware banks for patch logic (subcmd 0 = Bank A, subcmd 8 = Bank B)
    enc_a = dump_data.get(SUBCMD_MAIN_FW)
    enc_b = dump_data.get(SUBCMD_ACTIVE_FW)
    if not enc_a or not enc_b:
        sys.stderr.write(
            f"ERROR: missing firmware banks in dump "
            f"(sub{SUBCMD_MAIN_FW:02d}={enc_a is not None}, "
            f"sub{SUBCMD_ACTIVE_FW:02d}={enc_b is not None}).\n"
        )
        return 2

    # 3. Check Bank B first — that's where the device actually boots from
    #    after a successful upgrade. Bank A is the factory rescue.
    print("\n[3/6] Decrypting and checking patch status ...")
    print(f"      Firmware info:  {fw_info}")
    img_a: FirmwareImage | None = None
    img_b: FirmwareImage | None = None
    try:
        img_b = FirmwareImage.from_encrypted(enc_b)
        print(f"      Bank B: {img_b.status.upper()}  (key={img_b.key_name})"
              f"  enable=0x{img_b.enable_byte:02X}  comp=0x{img_b.comp_byte:02X}")
    except ValueError as e:
        print(f"      Bank B: UNKNOWN  ({e})")
    try:
        img_a = FirmwareImage.from_encrypted(enc_a)
        print(f"      Bank A: {img_a.status.upper()}  (key={img_a.key_name})"
              f"  enable=0x{img_a.enable_byte:02X}  comp=0x{img_a.comp_byte:02X}")
        art = save_derived(slug, SUBCMD_MAIN_FW, img_a.data, "plain")
        print(f"      Saved: {art}")
    except ValueError as e:
        print(f"      Bank A: UNKNOWN  ({e})")

    # The authoritative state is Bank B (the live boot bank after first upgrade).
    status_b = img_b.status if img_b else "unknown"
    if status_b == "patched":
        print("\nBank B is PATCHED — device is already unlocked. No action required.")
        return 0
    status_a = img_a.status if img_a else "unknown"
    if status_b == "unknown" and status_a == "unknown":
        sys.stderr.write(
            "\nERROR: neither bank matches expected layout — refusing to patch.\n"
        )
        return 2
    if status_a != "unpatched":
        sys.stderr.write(
            f"\nERROR: Bank A is not in factory state (status={status_a}); refusing to patch.\n"
        )
        return 2

    # 4. Patch in memory (from Bank A factory plaintext)
    print("\n[4/6] Patching plaintext + repairing checksum ...")
    assert img_a is not None
    patched = img_a.patch()
    assert patched.csum == 0xFFFF, f"post-patch checksum = 0x{patched.csum:08X}"
    print(f"      patched offsets: enable=0x{patched.enable_off:04X}  "
          f"comp=0x{patched.comp_off:04X}")
    print(f"      post-patch checksum (must be 0x0000FFFF): "
          f"0x{patched.csum:08X}")
    # Re-encrypt with KeyA (upload-side key; device may re-encrypt to KeyB internally).
    patched_enc = patched.encrypt(KEY_A)
    # Sanity: crypt is self-inverse — crypt(crypt(x)) == x.
    if crypt(patched_enc, KEY_A) != patched.data:
        sys.stderr.write("ERROR: cipher round-trip failed; aborting.\n")
        return 2
    art = save_derived(slug, SUBCMD_MAIN_FW, patched.data, "patched")
    print(f"      Saved: {art}")
    art = save_derived(slug, SUBCMD_MAIN_FW, patched_enc, "patched_enc")
    print(f"      Saved: {art}")

    # 5. Either dry-run or commit
    print("\n[5/6] " + ("DRY RUN — not writing." if not args.commit else "Uploading to device ..."))
    if not args.commit:
        print("      (pass --commit to actually flash)")
        print("      Image that would be flashed:")
        print(f"        size               = {len(patched_enc)} B")
        print(f"        device-side sum-16 = 0x{(sum(patched_enc) & 0xFFFF):04X}")
        return 4

    csum16 = upload_image(w, patched_enc, chunk=args.chunk_size)
    print(f"      committed with sum-16 = 0x{csum16:04X}")
    print("      resetting device ...")
    w.reset()

    # 6. Re-enumerate and verify (read Bank B — that's where the patch lives)
    print("\n[6/6] Waiting for re-enumeration and verifying readback ...")
    dev2 = wait_for_reenum(timeout_s=args.reenum_timeout)
    w2 = Wire(dev2)
    print(f"      device back  op_mode={w2.get_op()}  last_err=0x{w2.get_err():08X}")
    enc_b_after = dump_main_slot(w2, subcmd=SUBCMD_ACTIVE_FW)
    try:
        img_b_after = FirmwareImage.from_encrypted(enc_b_after)
        status2 = img_b_after.status
        print(f"      Bank B post-flash: {status2.upper()}  (key={img_b_after.key_name})")
    except ValueError as e:
        status2 = "unknown"
        print(f"      Bank B post-flash: UNKNOWN  ({e})")
    if status2 != "patched":
        sys.stderr.write(
            "\nERROR: post-flash Bank B does NOT confirm patched state.\n"
            f"   status={status2}\n"
            "   Power-cycle the camera and re-run with no flags to recheck.\n"
        )
        return 3

    print("\nSUCCESS — Bank B holds the patched firmware; device should boot in 18 Hz mode.")
    return 0


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        description="Seek Compact PRO 18 Hz unlock (cross-platform).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Default mode is dry-run (status check only). "
               "Use --commit to actually flash.",
    )
    p.add_argument("--commit", action="store_true",
                   help="Actually write the patch to flash. Default is dry-run.")
    p.add_argument("--chunk-size", type=int, default=64,
                   help="USB chunk size for the upload (default 64).")
    p.add_argument("--reenum-timeout", type=float, default=20.0,
                   help="Seconds to wait for the device to reappear after reset (default 20).")
    args = p.parse_args(argv)

    if not (1 <= args.chunk_size <= 4096):
        sys.stderr.write("ERROR: --chunk-size must be in [1, 4096]\n")
        return 2

    try:
        return run(args)
    except KeyboardInterrupt:
        sys.stderr.write("\nInterrupted.\n")
        return 130
    except (IOError, usb.core.USBError) as e:
        sys.stderr.write(f"\nERROR: {e}\n")
        return 3


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
