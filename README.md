# smt878u-ionstack-poc

Pure-C, host-assisted re-root proof of concept for **Samsung Galaxy Tab S7
(SM-T878U / gts7l)** against **CVE-2026-43499** (IonStack / GhostLock).

The runtime chain uses native C/ELF components only. It does not require
Python, Java, DEX, `app_process`, or a JVM on the Android target. ADB is used
for deployment and verification.

## Supported profile

This POC intentionally fails closed unless all profile checks match:

```text
device:      gts7l
Android:     13 / SDK 33
fingerprint: samsung/gts7lsqwnc/gts7l:13/TP1A.220624.014/T878USQS8DXE1:user/release-keys
kernel:      4.19.113
build:       T878USQS8DXE1
```

Unsupported or failed runs can panic or reboot the device. Keep a recovery
path available.

This repository is narrowly scoped to the firmware profile above. It is not a
general-purpose rooting tool, and offsets or assumptions must not be reused on
other devices without independent validation.

## Security research only

- Use only on hardware you own or are explicitly authorized to test.
- Successful exploitation can panic, reboot, or brick devices.
- Root produced by this POC is ephemeral and does not modify AVB, boot images,
  or system partitions; reboot removes it.

## Quick start

1. Build on a macOS or Linux host (see [Build](#build)).
2. Install the official Android SDK Platform Tools and connect the supported
   device with USB debugging enabled.
3. Confirm ADB sees the device:

```sh
adb devices -l
```

Then:

```sh
./build/smt878u-ionstack-reroot -s SERIAL --preflight-only
./build/smt878u-ionstack-reroot -s SERIAL --validate-only
./build/smt878u-ionstack-reroot -s SERIAL
```

After the host reports success, verify root and open a shell:

```sh
adb -s SERIAL shell /data/local/tmp/su -c id
adb -s SERIAL shell /data/local/tmp/su
```

`-s SERIAL` is optional when exactly one ADB device is connected.

## Build

Requirements:

- macOS or Linux host with `clang`, `make`, and `adb`
- Android NDK (API 35 is the default build API)
- an arm64/compat32 target matching the profile above

```sh
make -j4
```

Override discovery when needed:

```sh
make NDK_ROOT=/path/to/android-ndk API=35 -j4
```

All artifacts are emitted under `build/`.

### Host platforms

The host controller supports macOS arm64, Linux x86_64, and Windows x86_64.
The Android device artifacts are identical across host platforms.

```sh
# native host controller only
make host

# Windows x86_64 controller with LLVM-MinGW
make host-windows \
  WINDOWS_CC=/path/to/llvm-mingw/bin/x86_64-w64-mingw32-clang
```

## Run

Start with the non-exploit profile check, then validation, then the full chain:

```sh
./build/smt878u-ionstack-reroot -s SERIAL --preflight-only
./build/smt878u-ionstack-reroot -s SERIAL --validate-only
./build/smt878u-ionstack-reroot -s SERIAL
```

Logs are written below `results/YYYY-MM-DD/` by default.

### Collect reboot / crash artifacts

```sh
./tools/collect_reboot_artifacts.sh SERIAL
```

## Using `su` after a successful run

The supported user-facing client is installed at `/data/local/tmp/su`. It
connects to the temporary root daemon through
`/data/local/tmp/temp_su.sock`. Do not move it into `/system/bin`, and do not
rely on it surviving reboot.

## Layout

| Path | What |
|---|---|
| `src/host/` | Host-side ADB orchestrator |
| `src/device/` | On-device reroot / perf helpers |
| `src/exploit/` | IonStack-derived exploit chain (SM-T878U offsets) |
| `src/trigger/` | Chainwalk / diagnostic probe |
| `tools/su_daemon.c` | Temporary `su` daemon client/server bits |
| `tools/collect_reboot_artifacts.sh` | Post-reboot artifact collector |
| `build/` | Build outputs (gitignored) |
| `results/` | Run logs (gitignored) |

## Provenance

This tree started from the public `xpad2-ionstack-poc` packaging layout and an
IonStack CVE-2026-43499 source snapshot, then was re-ported to SM-T878U
(`gts7l` / `T878USQS8DXE1`).

- Combined project: `GPL-3.0-or-later` (`LICENSE`)
- IonStack-derived files under `src/exploit/` and `tools/su_daemon.c`: Apache-2.0
  provenance retained (`NOTICE`, `licenses/Apache-2.0.txt`)

## Security reports

Please do not include device identifiers, private firmware images, crash dumps,
or other sensitive data in a public issue. See `SECURITY.md`.

## Disclaimer

Provided **as-is**, without warranty of any kind. Authors and contributors are
not responsible for misuse, damage, or legal consequences arising from use of
this material.
