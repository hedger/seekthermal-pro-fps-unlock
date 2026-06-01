# seek-thermal-pro-unlock

Reverse-engineered tools for the **Seek Thermal Compact PRO** thermal
camera (USB `0x289D:0x0011`, NXP LPC43S30 Cortex-M4F) that unlock the
hidden 18 Hz frame-rate mode and verify it over USB.

The official firmware ships with high-frame-rate mode disabled by a
single byte in a hardware-profile table; this repository provides a
tool to flip that byte in-place and a second tool to measure the
resulting streaming rate.

> ⚠️ Reverse-engineering project. **Use at your own risk.** May void
> warranty. Tested on **one** Compact PRO unit (firmware revision
> `magic=0xA1B2C3D4 length=54840`). Run the dry-run first — it will
> confirm whether your firmware matches before touching anything.

---

## Contents

| File | Purpose |
|---|---|
| [`seek18hz_unlock.py`](seek18hz_unlock.py) | Flash-level 18 Hz unlock. Safe dry-run by default. |
| [`measure_fps.py`](measure_fps.py) | Measure actual streaming frame rate via USB bulk endpoint. |
| [`requirements.txt`](requirements.txt) | Minimal deps for the unlock tool (`pyusb` only). |
| [`requirements-capture.txt`](requirements-capture.txt) | Extended deps for unlock + capture/validation (`pyusb`, `numpy`, `Pillow`). |
| [`FINDINGS.md`](FINDINGS.md) | Full RE writeup: flash layout, cipher, USB protocol, patch derivation. |

---

## Quick start

```sh
# Install system libusb (see Platform notes below), then create a venv:
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 1. Unlock tool only:
pip install -r requirements.txt

# — OR — unlock + capture/validation:
pip install -r requirements-capture.txt

# Plug in the Seek Compact PRO. No other Seek software should be running.

# 2. Check status / dry-run (no writes):
python seek18hz_unlock.py

# 3. If the device shows UNPATCHED, apply the patch:
python seek18hz_unlock.py --commit

# 4. Verify — measure the streaming frame rate over USB:
python measure_fps.py
```

Expected `measure_fps.py` output after a successful unlock (10 s window):

```
Captured ~148 frames total (~124 thermal, ~5 FFC/cal)
  Thermal FPS:   ~14 Hz average  (peaks at 17-18 Hz)
  Interval min:  ~55 ms  (≈ 18 Hz)
```

The average is pulled below 18 Hz by automatic flat-field calibration
(FFC) events where the shutter closes momentarily — identical to the
behaviour visible in the Seek Android/iOS app. The peak inter-frame
rate of ~55 ms (≈ 18 Hz) is the unlocked hardware rate.

---

## `seek18hz_unlock.py`

### Exit codes

| code | meaning |
|---:|---|
| 0 | Patch applied (or already patched) |
| 1 | Device not found |
| 2 | Firmware layout mismatch — refused to patch |
| 3 | Flash write or readback verification failed |
| 4 | Dry-run completed (use `--commit` to flash) |

### Safeguards

- **Dry-run by default** — no bytes leave the host without `--commit`.
- **Idempotent** — detects an already-patched Bank B and exits 0
  without writing. (Bank A always looks factory — see *Readback caveat*.)
- **Multi-key detection** — tries KeyA (factory) then KeyB (post-upgrade
  device-side re-encryption key). Works on both fresh and previously
  upgraded units.
- **Signature-driven patch location** — finds the hardware-profile table
  row via an 8-byte masked signature, not a hardcoded offset, so minor
  firmware-revision drift is tolerated.
- **Checksum invariant** — sum-of-u32 over the first `length` bytes must
  equal `0xFFFF mod 2³²`. The patch flips one byte then compensates by
  flipping a padding byte in the same row, keeping the invariant exact.
- **Pre-flight validation** — vector table, header magic, header length,
  and checksum are all checked *before* any USB write begins.
- **Post-flash readback** — after `--commit`, re-reads and re-decrypts
  Bank B, confirms the patched bytes are present.

### Readback caveat (two-bank flash layout)

The camera has a two-bank firmware layout:

- **Bank A** (`subcmd 0`): factory rescue copy. *Never overwritten* by
  the upgrade FSM. After a power-cycle this slot always reads back as
  the original factory image, even on a patched device. Do not conclude
  the device is unpatched from Bank A alone.
- **Bank B** (`subcmd 8`): active upgrade target. After a successful
  first upgrade this is re-encrypted with the device-internal KeyB and
  is what the bootloader actually executes. This is the authoritative
  patched/unpatched indicator.

The script reads both banks and treats Bank B as ground truth.

### How it works (short version)

1. Read the encrypted firmware from Bank A (`subcmd 0`) and Bank B
   (`subcmd 8`) via vendor opcode `0x4F` in 512-byte chunks.
2. Detect which key applies (KeyA = factory, KeyB = post-upgrade) by
   decrypting with both and choosing whichever yields a valid checksum.
3. Locate the 27-row hardware-profile table; row 20 controls 18 Hz
   (`enabled` byte at row offset +3).
4. Flip the enable byte `0x00 → 0x01`. Compensate the checksum by
   flipping a padding byte in the same row `0x00 → 0xFF`.
5. Re-encrypt with KeyA, upload via opcodes `0x52` + `0x50` + `0x51`,
   reset via `0x59`.
6. Re-read Bank B, decrypt with KeyB, confirm the patched bytes.

Full cipher specification and slot format in [FINDINGS.md](FINDINGS.md).

---

## `measure_fps.py`

Measures the USB-level thermal streaming frame rate using the correct
per-frame request protocol (derived from
[libseek-thermal](https://github.com/OpenThermal/libseek-thermal)).

### Protocol

Each frame requires sending `START_GET_IMAGE_TRANSFER` (opcode `0x53`)
with the raw pixel count as a 4-byte little-endian payload, then reading
the response in bulk chunks:

```
Init:
  TARGET_PLATFORM (0x54)            = {0x01}
  SET_OPERATION_MODE (0x3C)         = {0x00, 0x00}   -- idle
  SET_IMAGE_PROCESSING_MODE (0x3E)  = {0x08, 0x00}
  SET_OPERATION_MODE (0x3C)         = {0x01, 0x00}   -- stream

Per-frame (repeat until done):
  ctrl OUT 0x53  payload=struct.pack('<I', 342*260)  -- request one frame
  bulk IN  0x81  read 13 × 13,680 bytes              -- 177,840 B / frame

Teardown:
  SET_OPERATION_MODE (0x3C) = {0x00, 0x00}  (× 3)
```

Raw geometry (Compact PRO): **342 × 260** pixels (u16 LE), 177,840 bytes
per frame, 13 bulk chunks of 13,680 bytes each. The thermal image ROI is
320 × 240 pixels at `x=1, y=4` within the raw frame.

Frame type is identified by `u16` word at byte offset 4 in each frame:

| frame_id | meaning |
|---:|---|
| 1 | FFC / autocalibration (shutter closes) |
| 3 | Normal thermal frame |
| 4 | Dead-pixel / init frame |

`measure_fps.py` counts only `frame_id == 3` frames for the FPS
calculation. If numpy and Pillow are installed it also saves a grayscale
PNG of the last thermal ROI to `/tmp/seek_stream_fps_test.png`.

---

## Platform notes

`pyusb` requires a `libusb` backend at the OS level:

- **macOS**: `brew install libusb`
- **Linux**: `apt install libusb-1.0-0`

  Non-root USB access requires a udev rule:
  ```
  # /etc/udev/rules.d/99-seek.rules
  SUBSYSTEM=="usb", ATTRS{idVendor}=="289d", ATTRS{idProduct}=="0011", MODE="0666"
  ```
  Then: `sudo udevadm control --reload-rules && sudo udevadm trigger`

- **Windows**: install **WinUSB** for the device via
  [Zadig](https://zadig.akeo.ie) (replaces the Seek vendor driver).
  Seek's official software will not work while WinUSB is active.

  > The pre-built Windows `.exe` bundles `libusb-1.0.dll` — no separate
  > libusb installation is needed. WinUSB/Zadig is still required to give
  > libusb access to the camera itself.

### Requirement sets

| File | Installs | Use when |
|---|---|---|
| `requirements.txt` | `pyusb` | You only need to unlock the device. |
| `requirements-capture.txt` | `pyusb`, `numpy`, `Pillow` | You also want to run `measure_fps.py` and save PNG frames. |

---

## Background

Detailed technical findings — bootloader cipher, flash slot layout,
USB opcode table, and full patch derivation with checksum math — are in
[FINDINGS.md](FINDINGS.md).
