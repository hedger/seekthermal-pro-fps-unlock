# Seek Compact PRO — RE findings (flash structure, crypto, unlock)

Reverse-engineered from a single Compact PRO unit (USB `0x289D:0x0011`,
NXP LPC43S30 Cortex-M4F). Confirmed by:

- Static IDA analysis of the bootloader (copied from flash `0x140003B8`
  to RAM `0x1001C000`, 6,220 B), reset vector `0x1001C124` (Thumb).
- Static analysis of the decrypted runtime firmware (54,840 B,
  Cortex-M Thumb, base `0x10000000`).
- Live USB probing across all 68 `BeginFirmwareUpgrade` subcmds.
- Round-trip decrypt → patch → re-encrypt → flash → readback → re-decrypt.

## 1. Hardware

| | |
|---|---|
| USB descriptor | `iManufacturer="Seek Thermal, Inc."`, `iProduct="PIR324 Thermal Camera"` |
| MCU | NXP LPC43S30 (Cortex-M4F) |
| SRAM | `0x10000000..0x10020000` (128 KiB) |
| SPIFI XIP flash | `0x14000000..0x14800000` (8 MiB), 64 KiB sectors |
| USB endpoints | Bulk OUT `0x01` (512 B), Bulk IN `0x81` (512 B). Control over EP0. |

The vendor command protocol uses **EP0 control transfers** only:

- `bmRequestType = 0x41` (vendor | interface | OUT) or `0xC1` (IN).
- `bRequest` = command opcode (see below).
- `wValue = 0`, `wIndex = 0`.

## 2. Flash layout (physical)

From bootloader RE (`sub_1001C060`, the slot selector):

| Address | Size | Contents |
|---|---|---|
| `0x14000000..0x14010000` | 64 KiB | **Bootloader** (vectors @ 0x00; first 0x3B8 B = boot vectors + CRT0 stub; from `0x140003B8` onward = body that CRT0 copies to RAM `0x1001C000`) |
| `0x14010000..0x14020000` | 64 KiB | **Config / calibration block** (active slot index + per-unit cal data) |
| `0x14030000..0x14040000` | 64 KiB | **Firmware Bank A** — factory rescue copy (KeyA, never written by upgrade FSM) |
| `0x14050000..0x14060000` | 64 KiB | **Firmware Bank B** — active upgrade target (KeyB-encrypted after first upgrade) |
| `0x14070000..0x14080000` | 64 KiB | Firmware Bank C (defined in bank table; empty on our unit) |
| `0x14080000..` | varies | Sensor calibration sectors (pixel correction tables, etc.) |

### Bank-selector table (subcmd 3)

The bootloader's 3-bank table is exposed on subcmd 3. On a never-upgraded
device it reads as all `0xFF` (uninitialized). After the first successful
`CompleteMemoryUpgrade`, the device writes:

```
offset 0x00:  u32 active_index = 1               # 0=A, 1=B, 2=C
offset 0x04:  u32 bank_addr[0]  = 0x14030000      # Bank A (factory)
offset 0x08:  u32 bank_addr[1]  = 0x14050000      # Bank B (upgrade)
offset 0x0C:  u32 bank_addr[2]  = 0x14070000      # Bank C
offset 0x10:  zeros padding ...
```

This is what makes the post-flash boot prefer Bank B's contents.

### Subcmd → bank mapping (verified by live diff before/after a flash)

The upgrade-FSM subcmd dispatch is NOT a flat 1:1 map. Empirically:

| subcmd(s) | Maps to | Notes |
|---|---|---|
| 0, 5, 7, 9 | Bank A read alias | Decrypts with KeyA. **Read-only** — never reflects an upgrade write. |
| 8 | Bank B read alias | After upgrade, decrypts with KeyB and reflects the freshly-written contents. Before any upgrade, falls back to Bank A's contents. |
| 6, 11–25, 46–67 | Unmapped / erased | All `0xFF`. Physical destination unknown; do not write. |
| 1, 4 | Config / cal block (0x14010000) | NOT a firmware slot. |
| 2 | Bootloader sector (0x14000000) | Flashing this = instant brick. |
| 3 | Bank-selector table | See above. |
| 26–29, 31–45 | Per-sensor cal data | DO NOT WRITE. |
| 10, 30 | Sparse sensor metadata | Informational. |

**Write target**: `BeginFirmwareUpgrade(0)` followed by `SetFeaturedFirmwareData`
chunks + `CompleteMemoryUpgrade` writes to **Bank B** (0x14050000) and
updates the bank table to make Bank B active. Bank A is never overwritten
by the upgrade FSM — so a botched flash can be recovered by clearing the
bank table (which currently appears to require JTAG/SWD; the FSM offers
no opcode to do so).

**Read-after-write asymmetry**:
- Immediately after `Complete` (same USB session), subcmd 0 returns the
  just-written data (the staging path "echoes" what was uploaded).
- After power-cycle, subcmd 0 reverts to Bank A's factory contents.
  Subcmd 8 then reflects the live boot bank (B).
- This is the source of all the earlier "readback caveats".

## 3. Slot file format

Each 64 KiB firmware bank holds an encrypted blob with a **plaintext
header at offset 512 (0x200)**:

| Offset | Type | Field |
|---|---|---|
| `0x200` | u32 LE | `magic` — `0xA1B2C3D4` regular FW, `0xA1C4FC14` recovery image |
| `0x204` | u32 LE | `length` — plaintext byte count covered by checksum |
| `0x208..0x240` | bytes | reserved / build metadata |

Bytes `0x000..0x1FF` of the slot are **encrypted** (start of code/vector
table); bytes `0x200..0x23F` (16 dwords = 64 B) are **plaintext**
(header, bypassed by the cipher); bytes `0x240..` are **encrypted** code
and data.

After decryption the slot starts with a normal Cortex-M vector table:
SP at offset 0 (= `0x10020000`, top of RAM), reset handler at offset 4
(`0x10000409` on current firmware — Thumb, RAM-resident).

## 4. Cipher

**xorshift128 keystream XOR**, with a 16-dword preserved-header window.

### Key schedule (`sub_1001C2E0` in bootloader)
```python
# k = the 4-dword key, each XORed with INIT_XOR = 0x13579BDF
state[3] = k[0] ^ INIT_XOR
state[0] = k[1] ^ INIT_XOR  
state[1] = k[2] ^ INIT_XOR
state[2] = k[3] ^ INIT_XOR
```
(One-slot left rotation: key dword *i* is loaded into state slot *i-1 mod 4*,
shifted so dword 0 ends up in slot 3.)

### PRGA — Marsaglia xorshift128 with shifts (11, 8, 19) (`sub_1001C350`)
```python
t = (s[0] ^ (s[0] << 11)) & 0xFFFFFFFF
s[0], s[1], s[2] = s[1], s[2], s[3]
s[3] = (s[3] ^ (s[3] >> 19) ^ t ^ (t >> 8)) & 0xFFFFFFFF
return s[3]
```

### Decryption (`sub_1001C374`)
```python
for i in range(slot_size // 4):
    ks = next_word(state)
    if 128 <= i < 144:                # dwords [128..143] = file bytes [512..575]
        plain[i] = enc[i]             #   = plaintext header window
    else:
        plain[i] = enc[i] ^ ks
```
The cipher is **self-inverse** (XOR), so `encrypt = decrypt`.

### Keys (from bootloader image)
| | Bytes | Source |
|---|---|---|
| **KeyA** | `9091 a792 57d8 1aa7 5f7c 77ba b0aa fa02` | Flash @ `0x14001C2C`. Decrypts factory-encrypted firmware. Used for host-side encrypt-on-upload. |
| **KeyB** | `95be 600d 80dc 442d 7aa0 0a8a 9644 bc54` | Flash @ `0x14001C3C`. Fallback used by `sub_1001C30C` when the device-unique key region @ flash `0x14000218..0x14000228` is all `0x00` or all `0xFF`. On unfused units (our unit, and probably all retail units) this is the effective device-side key. |

### Validation (`sub_1001C40C`)
After decryption the bootloader computes `sum(u32 for u32 in plain[:length]) mod 2^32`
and **requires the result to equal `0xFFFF`** (exactly — 32-bit value).
Any non-zero alteration of the plaintext that doesn't preserve this
invariant is rejected at boot.

### Device-side re-encryption on upload (live-observed)

When the host uploads a KeyA-encrypted blob:
1. Device decrypts received bytes with KeyA, validates magic & checksum.
2. Device **re-encrypts with KeyB** (or the device-fused key, if any)
   before writing to flash.
3. Bootloader at next boot decrypts with KeyB → boots.

Practical consequence: a readback dump on a freshly-flashed device
decrypts with **KeyB**, not KeyA. The unlock script handles this by
trying both keys in sequence.

## 5. Vendor USB opcodes (subset relevant to upgrade)

| opcode | dir | name | payload |
|---:|---|---|---|
| `0x35` | IN | GetErrorCode | reads 4 B; non-zero = latched error from last failed op |
| `0x3C` | OUT | SetOperationMode | u16 mode (0 = idle) |
| `0x3D` | IN | GetOperationMode | reads 2 B |
| `0x4F` | IN | GetFeaturedFirmwareData | reads N bytes from upgrade window |
| `0x50` | OUT | SetFeaturedFirmwareData | writes chunk to upgrade window |
| `0x51` | OUT | CompleteMemoryUpgrade | u16 checksum (= `sum(uploaded_bytes) & 0xFFFF`); verifies + commits to flash |
| `0x52` | OUT | BeginFirmwareUpgrade | u16 subcmd (selects bank — see §2 table) |
| `0x59` | OUT | ResetDevice | empty; reboots (USB drops mid-transaction) |
| `0x5A` | OUT | SetRamDataFeatures | u16 case + u16 arg1 + u16 arg2. Case 11 was documented as "arm upgrade FSM" on FW v4.9.2; on the current revision it returns err `0x20000` and **is not needed**. |

### Upgrade sequence (verified working on current FW)

```
SetOperationMode(0)           # 0x3C
BeginFirmwareUpgrade(0)       # 0x52 — selects main FW bank
for chunk in image:
    SetFeaturedFirmwareData(chunk)   # 0x50 — 64-byte chunks
CompleteMemoryUpgrade(sum16)  # 0x51 — verifies & commits
ResetDevice()                 # 0x59 — reboots
```

The `SetRamDataFeatures(case=11)` "arm" step from older flasher scripts
**must be skipped** on this firmware revision (returns `0x20000`).

## 6. 18 Hz unlock derivation

In the decrypted firmware there is a **27-row hardware-profile table**
defining which sensor / framerate combinations the firmware is willing
to enter. Each row is **38 bytes (stride 0x26)** in the current firmware
(was 0x36 = 54 bytes in older v4.9.2 reference). Row format starts:

```
+0   u8   type        (0x02 = framerate descriptor)
+1   u8   hw_id_lo    (0x14)
+2   u8   hw_id_hi    (0x14)
+3   u8   ENABLED     (0x00 = disabled, 0x01 = enabled)   ← PATCH TARGET
+4..  ...payload (timing constants, gain values, etc.) ...
+0x0F u8  (padding — verified zero in shipped firmware)   ← COMPENSATOR
```

**Row 20** is the 18 Hz Compact PRO descriptor. In the shipped firmware
its `ENABLED` byte is `0x00`; the firmware refuses to enter 18 Hz mode
because of this. The table is located dynamically by 8-byte signature:

```
REC20_SIG_PREFIX = 02 14 14 00 FF FF 00 20
```

In current firmware this yields exactly one match at plaintext file
offset `0x19B0`. Patching:

```
[0x19B3]  0x00 → 0x01   # enable 18 Hz
[0x19BF]  0x00 → 0xFF   # checksum compensator (padding inside same row)
```

### Why the compensator is exact

`0x19B3` is byte 3 (highest in LE u32) of the dword at file `0x19B0`.
Flipping it from `0x00` to `0x01` adds `+0x01000000` to that dword.
`0x19BF` is byte 3 of the dword at file `0x19BC`. Flipping it from
`0x00` to `0xFF` adds `+0xFF000000 ≡ -0x01000000 (mod 2³²)` to that
dword.

Net sum-of-u32 delta = `+0x01000000 + (-0x01000000) = 0`. The
bootloader's `sum == 0xFFFF` invariant is preserved exactly.

### Why the compensator is "safe"

Byte `0x19BF` is verified zero on the shipped firmware and lies in the
padding tail of the same row. It is read by no code path (it's not
inside any meaningful field of any row descriptor). Setting it to
`0xFF` has no observable runtime effect.

## 7. Recovery / brick-out paths

The upgrade FSM writes only to Bank B and never touches Bank A. So in
principle, if a botched upgrade is in Bank B and the bank-selector table
in sub03 has been flipped to active_index=1, the device boots broken —
but Bank A still holds the factory firmware untouched. Unfortunately
the runtime FSM offers no opcode to clear or rewrite the bank table:
you cannot ask the device to fall back to Bank A in software.

Before any risky modification, **always** keep a verified-good copy of
the device's Bank A encrypted dump on disk (the script's dry-run mode
reads sub00 / Bank A without modifying anything).