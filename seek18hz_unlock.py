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
import struct
import sys
import time
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
OP_GET_FEATURED_FIRMWARE_DATA = 0x4F  # IN  — read upgrade window
OP_SET_FEATURED_FIRMWARE_DATA = 0x50  # OUT — write upgrade chunk
OP_COMPLETE_MEMORY_UPGRADE    = 0x51  # OUT — verify+commit (u16 checksum)
OP_BEGIN_FIRMWARE_UPGRADE     = 0x52  # OUT — select bank (u16 subcmd)
OP_RESET_DEVICE               = 0x59

SUBCMD_MAIN_FW   = 0       # write target / factory-bank read alias
SUBCMD_ACTIVE_FW = 8       # second bank (Bank B) — reflects last write (see FINDINGS.md)
SUBCMD_BANK_TABLE = 3      # bootloader bank-selector table (active index + 3 bank addrs)
SLOT_SIZE      = 0x10000 # 64 KiB physical slot
READ_CAP       = 0xFF00  # FSM reliably caps reads at 65,280 B
READ_CHUNK     = 256

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

    def reset(self) -> None:
        try:
            self.out(OP_RESET_DEVICE, b"", timeout=2000)
        except Exception:
            pass  # device drops mid-transaction during reset


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
def dump_main_slot(w: Wire, *, bytes_to_read: int = READ_CAP,
                   chunk: int = READ_CHUNK,
                   subcmd: int = SUBCMD_MAIN_FW) -> bytes:
    """Read `bytes_to_read` from the given firmware-related subcmd.
    Read-only — never calls SetFeaturedFirmwareData or CompleteMemoryUpgrade.

    On this firmware, subcmd 0 maps to the factory/rescue bank (Bank A)
    and subcmd 8 maps to the active upgrade bank (Bank B). See FINDINGS.md.
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
def detect_key(enc: bytes) -> tuple[str, bytes, bytes]:
    """Try KeyA and KeyB. Prefer the key that yields a VALID checksum
    (sum-of-u32 == 0xFFFF over the declared length). The header magic
    alone is not a reliable discriminator because the cipher leaves
    bytes [512..575] verbatim, so any encryption (even with the wrong
    key) appears to "match" the magic. Fall back to whichever key
    produces a valid header length if neither validates."""
    candidates = []
    for name, k in (("KeyA", KEY_A), ("KeyB", KEY_B)):
        dec = crypt(enc, k)
        magic = struct.unpack_from("<I", dec, HEADER_OFFS)[0]
        if magic != HEADER_MAGIC:
            continue
        length = struct.unpack_from("<I", dec, HEADER_OFFS + 4)[0]
        if not (0 < length <= len(dec)):
            continue
        csum_ok = (checksum(dec[:length]) == 0xFFFF)
        candidates.append((csum_ok, name, k, dec))
    # Prefer validated; else any candidate; else fail.
    candidates.sort(key=lambda c: not c[0])  # True first
    if not candidates:
        raise ValueError(
            f"neither KeyA nor KeyB decrypts to magic 0x{HEADER_MAGIC:08X} "
            "with a valid header length."
        )
    _, name, k, dec = candidates[0]
    return name, k, dec


def find_rec20(plain: bytes) -> int:
    """Locate rec[20] by masked signature (byte 3 = enable, wildcarded).
    Works on both factory and patched firmware."""
    hits = []
    i = 0
    head_len = len(REC20_SIG_HEAD)         # 3
    tail_off = head_len + 1                # skip enable byte (offset 3)
    while True:
        j = plain.find(REC20_SIG_HEAD, i)
        if j < 0:
            break
        i = j + 1
        # require tail to match at the wildcarded position
        if plain[j + tail_off:j + tail_off + len(REC20_SIG_TAIL)] == REC20_SIG_TAIL:
            hits.append(j)
    if not hits:
        raise ValueError(
            f"rec[20] signature {REC20_SIG_HEAD.hex()}??{REC20_SIG_TAIL.hex()} "
            "NOT FOUND. Firmware layout differs from what this script knows about — "
            "refuse to patch."
        )
    if len(hits) > 1:
        raise ValueError(
            f"rec[20] signature is ambiguous (found at {[hex(h) for h in hits]}); "
            "refusing to guess which one to patch."
        )
    return hits[0]


def patch_plain(plain: bytes) -> tuple[bytes, dict]:
    """Apply 18 Hz unlock + checksum compensation to plaintext image.
    Returns (patched, info)."""
    buf = bytearray(plain)
    rec20 = find_rec20(bytes(buf))
    enable_off = rec20 + REC20_ENABLE_OFF
    comp_off   = rec20 + REC20_COMP_OFF
    if buf[enable_off] != 0x00:
        raise ValueError(
            f"rec[20] enable byte at 0x{enable_off:04X} is "
            f"0x{buf[enable_off]:02X}, expected 0x00 (= 18 Hz disabled). "
            "Either already patched, or layout unexpected."
        )
    if buf[comp_off] != 0x00:
        raise ValueError(
            f"checksum compensator byte at 0x{comp_off:04X} is "
            f"0x{buf[comp_off]:02X}, expected 0x00. Refusing to overwrite."
        )
    buf[enable_off] = PATCH_ENABLE_NEW
    buf[comp_off]   = PATCH_COMP_NEW
    return bytes(buf), {
        "rec20_off": rec20,
        "enable_off": enable_off,
        "comp_off": comp_off,
    }


def validate_plain(plain: bytes, *, expect_patched: bool) -> dict:
    """Validate a plaintext firmware image. Returns metadata dict.
    Raises ValueError on any invariant violation."""
    if len(plain) < HEADER_OFFS + 8:
        raise ValueError(f"image too small: {len(plain)} B")
    magic, length = struct.unpack_from("<2I", plain, HEADER_OFFS)
    if magic != HEADER_MAGIC:
        raise ValueError(f"bad magic 0x{magic:08X} (expected 0x{HEADER_MAGIC:08X})")
    if not (0 < length <= len(plain)):
        raise ValueError(f"bad header length {length} (image is {len(plain)} B)")
    sp, reset = struct.unpack_from("<2I", plain, 0)
    if sp != 0x10020000:
        raise ValueError(f"vector SP=0x{sp:08X}, expected 0x10020000")
    if not (RAM_LO <= reset <= RAM_HI):
        raise ValueError(f"vector Reset=0x{reset:08X} not in RAM")
    csum = checksum(plain[:length])
    if csum != 0xFFFF:
        raise ValueError(f"checksum sum-of-u32 = 0x{csum:08X}, expected 0x0000FFFF")
    rec20 = find_rec20(plain)
    enable = plain[rec20 + REC20_ENABLE_OFF]
    comp   = plain[rec20 + REC20_COMP_OFF]
    if expect_patched:
        if enable != PATCH_ENABLE_NEW:
            raise ValueError(
                f"expected patched: byte at 0x{rec20+REC20_ENABLE_OFF:04X} = "
                f"0x{enable:02X}, expected 0x{PATCH_ENABLE_NEW:02X}"
            )
        if comp != PATCH_COMP_NEW:
            raise ValueError(
                f"expected patched: compensator at 0x{rec20+REC20_COMP_OFF:04X} "
                f"= 0x{comp:02X}, expected 0x{PATCH_COMP_NEW:02X}"
            )
    return {
        "magic": magic,
        "length": length,
        "sp": sp,
        "reset": reset,
        "csum": csum,
        "rec20_off": rec20,
        "enable_byte": enable,
        "comp_byte": comp,
    }


# ============================================================================
# Status / patch flow
# ============================================================================
def status_string(enc_slot: bytes) -> tuple[str, dict]:
    """Return (status_str, meta). status_str ∈ {'unpatched','patched','unknown'}.
    Discriminates on the actual rec[20] enable byte and the checksum
    compensator value, not just structural validity."""
    try:
        kname, _key, plain = detect_key(enc_slot)
    except ValueError as e:
        return "unknown", {"error": str(e)}
    try:
        meta = validate_plain(plain, expect_patched=False)
    except ValueError as e:
        return "unknown", {"key": kname, "error": str(e)}
    enable = meta["enable_byte"]
    comp = meta["comp_byte"]
    if enable == 0x00 and comp == 0x00:
        return "unpatched", {"key": kname, **meta}
    if enable == PATCH_ENABLE_NEW and comp == PATCH_COMP_NEW:
        return "patched", {"key": kname, **meta}
    return "unknown", {
        "key": kname,
        "error": f"unexpected enable=0x{enable:02X} comp=0x{comp:02X}",
        **meta,
    }


def run(args: argparse.Namespace) -> int:
    print("Seek Compact PRO 18 Hz unlock")
    print("=" * 60)

    # 1. Open device
    print("\n[1/6] Opening device ...")
    dev = open_device()
    w = Wire(dev)
    print(f"      op_mode={w.get_op()}  last_err=0x{w.get_err():08X}")

    # 2. Read both firmware-related subcmds:
    #      sub00 -> Bank A (factory/rescue, KeyA)
    #      sub08 -> Bank B (active upgrade target, KeyB after device write)
    print(f"\n[2/6] Reading firmware banks ({READ_CAP} B each) ...")
    enc_a = dump_main_slot(w, subcmd=SUBCMD_MAIN_FW)
    enc_b = dump_main_slot(w, subcmd=SUBCMD_ACTIVE_FW)
    print(f"      Bank A (sub00) head = {enc_a[:8].hex()}  ({len(enc_a)} B)")
    print(f"      Bank B (sub08) head = {enc_b[:8].hex()}  ({len(enc_b)} B)")

    # 3. Check Bank B first — that's where the device actually boots from
    #    after a successful upgrade. Bank A is the factory rescue.
    print("\n[3/6] Decrypting and checking patch status ...")
    status_b, meta_b = status_string(enc_b)
    status_a, meta_a = status_string(enc_a)
    print(f"      Bank B status: {status_b.upper()}  (key={meta_b.get('key','?')})")
    if status_b != "unknown":
        print(f"        enable={meta_b.get('enable_byte')}  comp={meta_b.get('comp_byte')}")
    print(f"      Bank A status: {status_a.upper()}  (key={meta_a.get('key','?')})")
    if status_a != "unknown":
        print(f"        enable={meta_a.get('enable_byte')}  comp={meta_a.get('comp_byte')}")

    # The authoritative state is Bank B (the live boot bank after first upgrade).
    status = status_b
    if status == "patched":
        print("\nBank B is PATCHED — device is already unlocked. No action required.")
        return 0
    if status == "unknown" and status_a == "unknown":
        sys.stderr.write(
            "\nERROR: neither bank matches expected layout — refusing to patch.\n"
        )
        return 2
    # Bank B is unpatched (or unknown); fall through to flashing using Bank A as plaintext source.
    if status_a != "unpatched":
        sys.stderr.write(
            f"\nERROR: Bank A is not in factory state (status={status_a}); refusing to patch.\n"
        )
        return 2

    # 4. Patch in memory (from Bank A factory plaintext)
    print("\n[4/6] Patching plaintext + repairing checksum ...")
    kname, key, plain = detect_key(enc_a)
    patched_plain, info = patch_plain(plain)
    pmeta = validate_plain(patched_plain, expect_patched=True)
    print(f"      patched offsets: enable=0x{info['enable_off']:04X}  "
          f"comp=0x{info['comp_off']:04X}")
    print(f"      post-patch checksum (must be 0x0000FFFF): "
          f"0x{pmeta['csum']:08X}")
    assert pmeta["csum"] == 0xFFFF
    # Re-encrypt with the SAME key we read with (upload-side key is always
    # KeyA on factory devices; device may re-encrypt to KeyB internally).
    patched_enc = crypt(patched_plain, KEY_A)
    # Sanity: round-trip
    rt = crypt(patched_enc, KEY_A)
    if rt != patched_plain:
        sys.stderr.write("ERROR: cipher round-trip failed; aborting.\n")
        return 2

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
    status2, meta2 = status_string(enc_b_after)
    print(f"      Bank B post-flash status: {status2.upper()}  "
          f"(decrypted with {meta2.get('key', '?')})")
    if status2 != "patched":
        sys.stderr.write(
            "\nERROR: post-flash Bank B does NOT confirm patched state.\n"
            f"   status={status2}  meta={meta2}\n"
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
