# Handoff: Quest 2 IonStack/CVE-2026-43499 exploit port

Read this first. Full technical detail, methodology, and all extracted
offsets are in `PORTING_NOTES.md` -- this file is just the
"what's done, what's live, what's next" pointer. Where a claim below
needs evidence, `PORTING_NOTES.md` has it (search for the bolded section
titles referenced here).

## Current blocker: the corruption write doesn't land, even under ideal
## conditions, even with the reference exploit's exact unmodified design

The KASLR-leak/slide step is solid (see "Solid, working pieces" below).
One level deeper -- the actual memory-corruption write, used by both the
original boot_id-leak mechanism and this project's own isolated
`uts-write-test` stage -- does not land. Confirmed via extensive live GDB
debugging (QEMU and real device) in the session that found this. Key
facts (`PORTING_NOTES.md`: "Major reframing: EDEADLK..." onward, near
the end):

- **`EDEADLK` from `FUTEX_CMP_REQUEUE_PI` is the intended, successful
  trigger outcome, not a failure** -- misdiagnosed throughout this
  project's entire prior history. `remove_waiter()`'s CVE bug fires
  exactly on this path, confirmed live, every time.
- The `ptrace(PTRACE_SETREGSET)` spray (replaced the confirmed-dead
  pselect route) lands its forged waiter byte-for-byte correctly,
  confirmed live via GDB.
- Two field-level hypotheses (`RTMUTEX_OWNER_OFF`, the forged waiter's
  `task` field) were tried, live-tested, and **reverted** -- direct
  comparison against the reference exploit
  (github.com/Wtrwx/smt878u-ionstack-poc) showed both were unverified
  deviations from its proven design, and they made things crash more,
  not work.
- With source reverted to match the reference exactly (mechanism-wise --
  addressing still correctly uses `writable_image_addr()`/`text_addr()`,
  not the reference's physmap macros, which are broken on this device by
  `memstart_addr` randomization): **a clean QEMU test of the reference's
  completely unmodified boot_id-leak mechanism still produces no write.**
  This is the biggest open question -- something more fundamental differs
  between this target (Quest 2/kona, `4.19.325-cip128-st12-...`) and
  whatever the reference's original target runs, or the mechanism needs
  re-deriving from this kernel's own disassembly. See PORTING_NOTES.md's
  "What's still unexplained" (end of file) for concrete next steps.
- Built reusable QEMU live-debugging infrastructure to make the above
  possible without the real device for every iteration -- including a
  `KernelSnitch` bypass (doesn't work under QEMU TCG) using a real,
  `/proc/self/pagemap`-resolved userspace page. Full recipe + gdbstub/tmux
  gotchas in `PORTING_NOTES.md`.
- Found (not yet fixed in the real exploit path) an unrelated bug: the
  `IONSTACK_UTS_TEST_ATTEMPTS` retry loop reuses one prepared page across
  attempts, but a single successful trigger mutates that page, so later
  attempts in the same run can crash for reasons unrelated to whatever's
  being tested. Worked around during testing via `...ATTEMPTS=1`.

**Immediate next step**: re-test the real device with the current
(reverted) source, cleanly (single attempt, fresh reboot) -- not done yet
(last real-device test used the since-reverted owner fix). Confirms
whether the QEMU findings generalize to real hardware.

---

## Solid, working pieces (do not re-litigate these)

- **KASLR slide recovery**: tracefs-based, exploit-free, reads real
  already-slid `.text` pointers from `sched_blocked_reason`'s tracepoint.
  Reliable, live-tested repeatedly, cross-validated. Default route
  (`slide_leak_kernel_base()` in `slide.c`); old UAF route renamed
  `slide_uaf_leak_kernel_base()`, reachable via `IONSTACK_SLIDE_SOURCE=uaf`.
- **`memstart_addr` KASLR randomization** (broke every physmap-alias
  read/write in the exploit, independent of the slide itself): fixed via
  `writable_image_addr()` (prefers KASLR-based addressing over the broken
  physmap alias whenever `kaslr_done`), applied across
  `fops.c`/`util.c`/`root.c`/`pipe.c`.
- **Dead pselect fake-waiter route**: confirmed dead three times over
  (static analysis, QEMU live GDB, real-device live self-check) --
  replaced entirely by the `ptrace(PTRACE_SETREGSET)` spray, which lands
  correctly. Do not revisit pselect.
- **`offset.h`**: rewritten to the real device's own kernel image
  (`q2_52150470034600150_kernel`, recovered via `vmlinux-to-elf`), not
  the local QEMU rebuild (confirmed to differ by non-uniform amounts per
  symbol). The `rt_mutex`/`rt_mutex_waiter`/
  `task_struct.{pi_lock,prio,real_cred}` cluster is disassembly-confirmed
  exact against the real device binary; everything else in that category
  (seccomp, `configfs_buffer`, `file_operations`, `struct page`, other
  `cred`/`task_struct` fields) is carried over, unverified.

Still unresolved, low priority unless something downstream needs them:
`SLIDE_RANDOM_BOOT_ID_DATA_OFF`/`COPY_SPLICE_READ_OFF` placeholder
history is settled (see PORTING_NOTES.md if picking at this) but
`P0_KERNEL_PHYS_LOAD`/`MM_STRUCT_SZ` are still unresolved (need root or
an engineering-build device, unavailable so far).

## Real device: connected, adb-authorized, production build

Quest 2, serial `1WMHH810EV0413`, fingerprint
`oculus/hollywood/hollywood:14/UP1A.231005.007.A1/52150470034600150:.../release-keys`.
`adb root` fails (production build, expected), shell is uid=2000, SELinux
Enforcing -- the correct starting state, not an obstacle. Re-plug/
re-authorize if `adb devices -l` doesn't show it.

**Treat it as a real device, not a disposable QEMU VM.** Read-only recon
and static/offline analysis: always fine. Any new code path that reaches
further than a previously-run attempt: new territory, discuss with the
user first even if guardrails look solid. A full live trigger attempt
(`IONSTACK_STAGE=full`) has been run multiple times this project
(deterministic dead end at the pselect route historically; more recent
attempts against the corruption-write blocker above have caused real
crashes/reboots -- see PORTING_NOTES.md's crash-dump sections before
re-running anything beyond `dry`).

## What exists on disk

- `q2_build/` -- kernel/QEMU/Buildroot build kit (local rebuild -- **not**
  the real device's exact kernel commit).
  - `q2_build/build/oculus-quest2-device-kernel/{Image,vmlinux,System.map,dtbs}`
  - `q2_build/build/qemu-kernel/{Image,vmlinux,System.map}` -- QEMU-bootable
    variant, confirmed same `_text` link base as the device kernel but
    different internal symbol offsets (different linked-in drivers) --
    use `offset_qemu.h`, not `offset.h`, against this build.
  - `q2_build/buildroot/output/images/rootfs.ext4` -- QEMU rootfs.
- `./` -- working copy of the PoC
  (github.com/Wtrwx/smt878u-ionstack-poc, originally for Samsung SM-T878U).
  - `src/exploit/offset.h` -- real-device offsets (see above).
  - `src/exploit/offset_qemu.h` -- QEMU-kernel-build offsets (new; only
    the handful of `*_OFF` constants needed for QEMU corruption-mechanism
    testing are actually correct here, everything else is a harmless
    copy from `offset.h`). Selected via `-DIONSTACK_TARGET_QEMU=1`.
  - `real_device/` -- `device_vmlinux.elf`/`device.nm`/`device.config`,
    recovered from the real device's raw kernel image, regenerable via
    `vmlinux-to-elf` if needed.
  - `PORTING_NOTES.md` -- the real writeup, read this for anything beyond
    the summary above.
  - `tools/ionstack_test_harness.c` -- builds the exploit sources as a
    plain static executable via the system's own `aarch64-linux-gnu-gcc`
    (glibc, not Android NDK) -- confirmed this is what past scratch
    binaries were actually built with too. No Android NDK required.
- `q2_52150470034600150_kernel` -- the real device's actual kernel image
  (confirmed via fingerprint/`vmlinux-to-elf` cross-check). Source for
  `offset.h` and `real_device/`.
