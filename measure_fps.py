"""Measure actual frame rate from the Seek Compact PRO thermal camera.

Protocol (from libseek-thermal SeekCam.cpp / SeekThermalPro.cpp):
  Init:
    TARGET_PLATFORM(0x54) = {0x01}
    SET_OPERATION_MODE(0x3C) = {0x00, 0x00}       -- idle
    SET_IMAGE_PROCESSING_MODE(0x3E) = {0x08, 0x00}
    SET_OPERATION_MODE(0x3C) = {0x01, 0x00}       -- stream
  Per-frame loop:
    START_GET_IMAGE_TRANSFER(0x53) = struct.pack('<I', RAW_WORDS)  -- request one frame
    bulk read 13 × 13680 bytes from EP 0x81 = one full frame (177,840 B)
    frame_id = struct.unpack_from('<H', frame, 4)[0]
      1 = calibration/FFC (shutter closes)
      3 = normal thermal frame
      4 = dead-pixel/init frame
  Teardown:
    SET_OPERATION_MODE(0x3C) = {0x00, 0x00}

RAW geometry (from SeekThermalPro.h):
  THERMAL_PRO_RAW_WIDTH  = 342
  THERMAL_PRO_RAW_HEIGHT = 260
  THERMAL_PRO_REQUEST_SIZE = 13680  (bytes per bulk chunk)
  Frame = 342 * 260 * 2 = 177,840 bytes = 13 chunks
"""

from __future__ import annotations

import struct
import sys
import time
from pathlib import Path
from typing import Optional

try:
    import usb.core
    import usb.util
except ImportError:
    sys.exit("ERROR: pyusb not installed. pip install pyusb")

# ── optional visualisation ────────────────────────────────────────────────────
try:
    import numpy as np
    from PIL import Image
    HAVE_PIL = True
except ImportError:
    HAVE_PIL = False
    print("NOTE: numpy/Pillow not installed — will skip PNG save. "
          "pip install numpy Pillow")

VID, PID = 0x289D, 0x0011
TYPE_OUT, TYPE_IN = 0x41, 0xC1   # vendor|interface|OUT / IN

OP_GETERR    = 0x35
OP_SETOPMODE = 0x3C
OP_GETOPMODE = 0x3D
OP_SETIPMODE = 0x3E             # SET_IMAGE_PROCESSING_MODE
OP_IMGXFER   = 0x53             # START_GET_IMAGE_TRANSFER — send before EVERY frame
OP_PLATFORM  = 0x54             # TARGET_PLATFORM

# Raw geometry (SeekThermalPro.h)
RAW_W    = 342
RAW_H    = 260
RAW_WORDS = RAW_W * RAW_H       # 88,920 u16 words  (= 0x15B58)
CHUNK    = 13680                 # bytes per bulk read chunk
N_CHUNKS = (RAW_WORDS * 2) // CHUNK  # 13 chunks per frame
FRAME_BYTES = RAW_WORDS * 2     # 177,840 bytes / frame

# Visible thermal image ROI (from SeekThermalPro): x=1,y=4, 320×240
ROI_X, ROI_Y, ROI_W, ROI_H = 1, 4, 320, 240

BULK_EP      = 0x81
CAPTURE_SECS = 10.0

OUT_PNG = Path("/tmp/seek_stream_fps_test.png")


# ── USB helpers ───────────────────────────────────────────────────────────────
def ctrl_out(dev, op: int, payload: bytes = b"", timeout: int = 3000):
    try:
        return dev.ctrl_transfer(TYPE_OUT, op, 0, 0, payload, timeout)
    except usb.core.USBError as e:
        return f"ERR:{e}"

def ctrl_in(dev, op: int, length: int, timeout: int = 3000) -> Optional[bytes]:
    try:
        return bytes(dev.ctrl_transfer(TYPE_IN, op, 0, 0, length, timeout))
    except usb.core.USBError:
        return None

def get_err(dev) -> int:
    b = ctrl_in(dev, OP_GETERR, 4)
    return int.from_bytes(b, "little") if b else 0xFFFFFFFF

def get_opmode(dev) -> int:
    b = ctrl_in(dev, OP_GETOPMODE, 2)
    return int.from_bytes(b, "little") if b else -1

def teardown(dev):
    ctrl_out(dev, OP_SETOPMODE, b"\x00\x00")
    ctrl_out(dev, OP_SETOPMODE, b"\x00\x00")
    ctrl_out(dev, OP_SETOPMODE, b"\x00\x00")


def request_frame(dev) -> Optional[bytes]:
    """Send START_GET_IMAGE_TRANSFER then read exactly one 177,840-byte frame
    as 13 × 13,680-byte bulk chunks.  Returns raw bytes or None on error."""
    payload = struct.pack('<I', RAW_WORDS)
    r = dev.ctrl_transfer(TYPE_OUT, OP_IMGXFER, 0, 0, payload, 3000)
    if r != len(payload):
        return None

    buf = bytearray(FRAME_BYTES)
    pos = 0
    for _ in range(N_CHUNKS):
        try:
            chunk = bytes(dev.read(BULK_EP, CHUNK, timeout=2000))
        except usb.core.USBTimeoutError:
            return None  # frame incomplete
        except usb.core.USBError:
            return None
        buf[pos:pos + len(chunk)] = chunk
        pos += len(chunk)
    return bytes(buf)


OUT_PNG = Path("/tmp/seek_stream_fps_test.png")


# ── frame visualisation ───────────────────────────────────────────────────────
def save_frame_png(raw: bytes, path: Path):
    if not HAVE_PIL:
        return
    arr = np.frombuffer(raw, dtype=np.uint16).reshape(RAW_H, RAW_W)
    # Extract the thermal ROI (skip metadata rows/cols as per libseek-thermal)
    roi = arr[ROI_Y:ROI_Y + ROI_H, ROI_X:ROI_X + ROI_W].astype(np.float32)
    lo, hi = roi.min(), roi.max()
    grey = ((roi - lo) / max(1, hi - lo) * 255).astype(np.uint8)
    Image.fromarray(grey, "L").save(str(path))
    print(f"      saved frame PNG ({ROI_W}×{ROI_H} thermal ROI) → {path}")


# ── main ──────────────────────────────────────────────────────────────────────
def main() -> int:
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        sys.stderr.write(
            f"ERROR: Seek Compact PRO not found (VID=0x{VID:04X} PID=0x{PID:04X}).\n"
        )
        return 1

    try:
        dev.set_configuration()
    except usb.core.USBError:
        pass

    print("Seek Compact PRO — frame-rate measurement")
    print("=" * 60)
    print(f"  RAW={RAW_W}×{RAW_H}  frame={FRAME_BYTES}B  chunks={N_CHUNKS}×{CHUNK}B")
    print(f"  initial opmode = {get_opmode(dev)}  err = 0x{get_err(dev):08X}")

    all_timestamps: list[float] = []
    thermal_timestamps: list[float] = []
    last_frame: Optional[bytes] = None
    ffc_count = 0

    try:
        # Init sequence (SeekThermalPro::init_cam)
        print("\n[1] Init sequence ...")
        ctrl_out(dev, OP_PLATFORM, b"\x01")                  # TARGET_PLATFORM = 1
        ctrl_out(dev, OP_SETOPMODE, b"\x00\x00")             # idle
        ctrl_out(dev, OP_SETIPMODE, b"\x08\x00")             # SET_IMAGE_PROCESSING_MODE = 8
        r = ctrl_out(dev, OP_SETOPMODE, b"\x01\x00")         # stream
        print(f"    SET_OPERATION_MODE(1) = {r}  opmode={get_opmode(dev)}  err=0x{get_err(dev):08X}")

        # Per-frame loop — send START_GET_IMAGE_TRANSFER before every frame
        print(f"\n[2] Capturing frames for {CAPTURE_SECS:.0f}s "
              f"(per-frame request+read, {N_CHUNKS}×{CHUNK}B) ...")
        t_start = time.perf_counter()
        t_end = t_start + CAPTURE_SECS
        frame_idx = 0

        while time.perf_counter() < t_end:
            raw = request_frame(dev)
            if raw is None:
                print(f"    [frame {frame_idx}] request_frame returned None — stopping")
                break

            ts = time.perf_counter()
            all_timestamps.append(ts)
            last_frame = raw

            # Decode frame metadata (u16 words at head of raw frame)
            # word[0] = frame_counter, word[1] = ?, word[2] = frame_id
            words = struct.unpack_from('<5H', raw, 0)
            frame_id = words[2]

            if frame_id == 1:
                ffc_count += 1
                label = "FFC/cal"   # shutter click
            elif frame_id == 3:
                thermal_timestamps.append(ts)
                label = "thermal"
            elif frame_id == 4:
                label = "init"
            else:
                label = f"id={frame_id}"

            if frame_idx < 8 or frame_idx % 20 == 0 or frame_id == 1:
                elapsed = ts - t_start
                n_th = len(thermal_timestamps)
                fps_so_far = (n_th - 1) / (thermal_timestamps[-1] - thermal_timestamps[0]) \
                             if n_th >= 2 else 0.0
                print(f"    frame {frame_idx:4d}  t={elapsed:6.2f}s  "
                      f"fps={fps_so_far:5.2f}  [{label}]  head={raw[:8].hex()}")
            frame_idx += 1

        # Stats
        n_all = len(all_timestamps)
        n_th  = len(thermal_timestamps)
        print(f"\n{'='*60}")
        print(f"Captured {n_all} frames total ({n_th} thermal, {ffc_count} FFC/cal) "
              f"in {CAPTURE_SECS:.0f}s window")

        if n_th >= 2:
            total_t = thermal_timestamps[-1] - thermal_timestamps[0]
            avg_fps = (n_th - 1) / total_t if total_t > 0 else 0
            intervals = [thermal_timestamps[i+1] - thermal_timestamps[i]
                         for i in range(n_th - 1)]
            min_ms = min(intervals) * 1000
            max_ms = max(intervals) * 1000
            avg_ms = total_t / (n_th - 1) * 1000
            med_ms = sorted(intervals)[len(intervals)//2] * 1000
            print(f"  Thermal FPS:   {avg_fps:.2f} Hz")
            print(f"  Interval min:  {min_ms:.1f} ms")
            print(f"  Interval max:  {max_ms:.1f} ms")
            print(f"  Interval avg:  {avg_ms:.1f} ms")
            print(f"  Interval med:  {med_ms:.1f} ms")
            print()
            if avg_fps >= 16.0:
                print("  RESULT: ✓ 18 Hz unlock confirmed (>= 16 FPS measured)")
            elif avg_fps >= 8.0:
                print("  RESULT: ~ Intermediate rate — may be throttled or warming up")
            else:
                print("  RESULT: ✗ Low rate — firmware may still be in 9 Hz mode")
        elif n_th == 1:
            print("  Only 1 thermal frame received — cannot compute FPS.")
        else:
            print("  No thermal frames received. Check streaming sequence.")

        # Save a thermal frame
        if last_frame:
            save_frame_png(last_frame, OUT_PNG)

    finally:
        print("\n[3] Teardown: SetOperationMode(0)")
        teardown(dev)
        print(f"    opmode={get_opmode(dev)}  err=0x{get_err(dev):08X}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
