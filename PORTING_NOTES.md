# Porting smt878u-ionstack-poc to Meta Oculus Quest 2

Source PoC: https://github.com/Wtrwx/smt878u-ionstack-poc (Samsung Galaxy Tab
S7 SM-T878U / gts7l / Android 13 / kernel 4.19.113, CVE-2026-43499).
Target: Meta Oculus Quest 2 (Snapdragon XR2 "kona"/"hollywood",
`oculus-linux-kernel` @ `oculus-quest2-kernel-master`, kernel 4.19.325).

Working copy lives in `q2_port/`. All porting work happens inside
`q2_exploit2/`, per session scope.

## Status

- [x] Kernel + QEMU + Buildroot build reproduced from `q2_build/`
      (`build.sh` patched to also emit `vmlinux`/`System.map`, needed for
      offset extraction).
- [x] QEMU boot verified end-to-end on `4.19.325-cip128-st12-g6e428607392d-dirty`.
- [x] `oculus-linux-kernel` has every structural prerequisite:
      `CONFIG_ASHMEM=y`, `CONFIG_CONFIGFS_FS=y`, `CONFIG_FUTEX_PI=y`,
      `CONFIG_RT_MUTEXES=y`, `CONFIG_SECURITY_SELINUX=y`,
      `CONFIG_DEBUG_INFO=y`/DWARF4 (unstripped vmlinux, full symbols, no
      disassembly needed for most offsets).
- [x] `offset.h` re-derived via `nm`/`pahole` against the rebuilt vmlinux,
      then again against the real device's own kernel image (see
      "Real-device pass").
- [x] Real device connected: Quest 2, serial `1WMHH810EV0413`, fingerprint
      `oculus/hollywood/hollywood:14/UP1A.231005.007.A1/52150470034600150:.../release-keys`,
      production build (`adbd` non-root, SELinux Enforcing, shell uid=2000).
- [x] Dead `pselect`-based fake-waiter route replaced with a
      `ptrace(PTRACE_SETREGSET)`-based spray (see "Workaround found"),
      confirmed byte-correct live via GDB.
- [ ] **Current blocker**: the memory-corruption write itself doesn't land
      even under ideal conditions -- see the final sections of this file
      ("CORRECTION: EDEADLK..." onward). Read `NEXT_SESSION.md` first for
      the current-state summary; this file has the full derivation trail.

## Methodology (offset derivation)

1. Built the kernel via `q2_build/build.sh` (patched to keep `vmlinux`+
   `System.map`) for both the real-device `.config` and the QEMU-bootable
   variant.
2. Diffed the two `.config`s: differences limited to virtio/serial/
   devtmpfs/hw_random/rtc (QEMU support) and a few early-SMC/RPM-only
   options (`QCOM_EARLY_RANDOM`, `MSM_PM`, `QCOM_QHEE_ENABLE_MEM_PROTECTION`,
   `QTI_SYSTEM_PM`) -- none touch any struct this exploit cares about.
3. Cross-checked `task_struct`/`cred`/`rt_mutex` layout identical between
   the QEMU-variant and real-device vmlinux, both linking `_text` at
   `0xffffff8008080000` -- offsets from the QEMU-variant vmlinux should
   carry over, provided the physical device runs a kernel from this exact
   source+config+toolchain (later found not exactly true -- see
   "Real-device pass").
4. For every `offset.h` `#define`: resolved via `nm`/`grep` on
   `System.map` (unstripped, includes local `static` symbols -- e.g.
   `ashmem_fops`, `loggers`, `nfulnl_logger`, `sysctl_bootid`, zero
   disassembly needed) and `pahole -C <struct>` for every struct-member
   offset (`task_struct`, `cred`, `seccomp`, `rt_mutex`,
   `rt_mutex_waiter`, `mm_struct`, `struct page`, `pipe_buffer`,
   `configfs_buffer`, `file_operations`, `miscdevice`, `selinux_state`,
   `task_security_struct`, `task_group`, `sched_dl_entity`).
5. Where the original repo's value matched the freshly computed one, kept
   it; where not, used the computed value. **Do not assume any offset
   transfers without checking individually** -- see next section for how
   much the two builds actually diverged, field by field.

## Concrete divergences from the original SM-T878U `offset.h`

Real, pahole/nm-verified, not hypothetical:

- **`struct rt_mutex`**: `waiters` at **8** (assumed 0x10), `owner` at
  **24** (assumed 0x20). Both builds have
  `CONFIG_DEBUG_SPINLOCK=n`/`CONFIG_DEBUG_RT_MUTEXES=n`, so it's not a
  debug-config difference -- the vendor trees just laid it out
  differently.
- **`task_struct`**: nearly every field differs (`pid` 1592 vs assumed
  1600, `real_cred` 2016 vs 2032, `pi_lock` 2228 vs 2248, etc.) -- many
  small `CONFIG_*` differences (WALT scheduler, cgroup fields), not one
  clean shift. `stack` (offset 96) matched by coincidence.
- **`struct seccomp`**: plain upstream 2-field layout (`mode`, `filter`,
  16 bytes) -- no `filter_count`. `HAVE_SECCOMP_FILTER_COUNT=0`.
- **`struct selinux_state`**: consolidated `struct selinux_state` (real
  global struct), no standalone `int selinux_enforcing`, no
  `selinux_blob_sizes` symbol. `cred->security` still a plain
  `task_security_struct*` with `sid`@4 (matches original,
  `SELINUX_HAS_BLOB_SIZES=0` holds) -- only the enforcing-flag target
  changed shape.
- **`struct configfs_buffer`**: fields shifted 24-40 bytes throughout
  (`needs_read_fill` 64 vs 96, `bin_buffer` 72 vs 104) -- likely a
  `struct mutex` size/alignment difference upstream.
- **`struct file_operations`**: matches except `splice_read` (0xc0 here
  vs assumed 0xb8) -- this tree has `splice_write` immediately before it,
  shifting everything by 8 bytes (`show_fdinfo` still lands at 0xd8 by
  coincidence).
- **`struct page.slab_cache`**: 24 (0x18), not assumed 0x08
  (`STRUCT_PAGE_TYPE_OFF`=0x30 and struct size 0x40 did match).
- **`mm_struct.owner`**: 808 (0x328), not assumed 888.

## `rt_mutex` owner-field aliasing (traced, not a live bug)

`RTMUTEX_WAITERS_ROOT_OFF=8` numerically equals the original
`RTMUTEX_WAIT_LOCK_OWNER_TASK_OFF` (also 8, a leftover debug-spinlock
field absent on this non-`CONFIG_DEBUG_SPINLOCK` build). Traced every
call site (`util.c`): two **read** sites only feed a diagnostic log
comparison (now-meaningless output, not unsafe); the one **write** site
zeroes wait_lock owner_cpu/task first but is *unconditionally* followed,
in every branch, by a real write to `RTMUTEX_WAITERS_ROOT_OFF` covering
the same 8 bytes -- the zero-write is harmlessly clobbered immediately
after. Left as-is; correct by construction. `RTMUTEX_WAIT_LOCK_OWNER_CPU_OFF`/`_TASK_OFF` left defined (inert) purely so the file compiles without touching call sites.

## Configfs symbol choice

`CONFIGFS_WRITE_OFF`/`CONFIGFS_BIN_WRITE_ITER_OFF` both alias
`CONFIGFS_WRITE_FILE_OFF` (plain, non-`_bin_` variant), same pattern as
the original, repointed at this build's `configfs_write_file`
(`0x2dc4e4` relative to `_text`). Also resolved
`configfs_write_bin_file`/`configfs_read_bin_file`
(`0x2dc880`/`0x2dc700`) in case `fops-check` shows the plain variant
doesn't work. `IONSTACK_ENABLE_UNSAFE_CONFIGFS_READ=0` in `fops.c`
(matches upstream design) -- `CONFIGFS_READ_*` resolved but likely dead
code.

## The `PSELECT_WAITER_WORD_SHIFT` dead end (superseded by the `ptrace`
## spray, kept for the record -- do not re-attempt this route)

The original exploit's fake-`rt_mutex_waiter` install
(`do_pselect_fake_lock_route()`/`prepare_pselect_fdsets()` in `fops.c`,
parallel copy in `slide.c`) writes forged waiter words into `pselect6`'s
`fd_set` arguments and blocks inside `pselect()` to hold them on the
stack, at a byte offset (`PSELECT_WAITER_WORD_SHIFT`) meant to overlap
`futex_wait_requeue_pi`'s `rt_waiter` local. Confirmed dead on this
kernel build, multiple independent ways:

- **Live GDB measurement** (QEMU, `nokaslr`, `-s`/`-smp 1`, tiny
  `tools/stacktest.c` probe calling `pselect6(nfds=320)` then
  `futex(FUTEX_WAIT_REQUEUE_PI)`): breakpointed `core_sys_select`
  (fs/select.c:606) and `futex_wait_requeue_pi` (kernel/futex.c:3319).
  `&stack_fds = 0xffffff800a4abc70`, `&rt_waiter = 0xffffff800a4abbc8`
  -- both measured off the identical `pt_regs` anchor
  (`0xffffff800a4abec0`), so directly comparable. **`rt_waiter` sits 168
  bytes *below* `stack_fds[0]`** -- entirely outside the 256-byte array
  in either direction. No positive word-shift can ever reach it.
- **The code's own reachability check already fails**:
  `pselect_fake_waiter_user_reachable()` requires
  `shift + 10 - 1 < user_words`. With `NFDS=320` -> `words_per_set=5` ->
  `user_words=15` (words 0-14 are the real `in`/`out`/`ex` sets; 15-29
  are kernel-computed *result* sets, not user-writable).
  `PSELECT_WAITER_WORD_SHIFT=16` (carried from SM-T878U) lands entirely
  in the result region. The exploit's own code detects this and disables
  the consumer thread rather than proceed. `nfds=640` (suggested by the
  code's own comment) doesn't rescue it either -- it would move the shift
  into user-writable range, but flips `pselect_uses_stack_bitmap()` false
  (kernel then kmallocs the fd bitmaps off-stack entirely).
- **Root cause**: fixed property of how Clang laid out these two
  functions' stack frames on this build -- not a mis-tuned constant.
  Confirmed identically **on the real device's own kernel binary** later
  (see "Live trigger attempt"): `slide pselect reach ... shift=16
  global=16..25 user_words=0..14 ... user_reachable=0`, and the exploit's
  own safety interlock correctly refused to proceed
  (`IONSTACK_SLIDE_FORCE_UNREACHABLE=1` would reproduce a known panic).

**Do not re-attempt re-deriving `PSELECT_WAITER_WORD_SHIFT`/
`PSELECT_ROUTE_NFDS`/`SLIDE_PSELECT_WORD_SHIFT`** -- confirmed three
times (QEMU static, QEMU live GDB, real-device live self-check) this is
not a constant-tuning problem. The `try_cfi_stage()`/
`try_cfi_writeonly_modprobe_stage()` write path in `fops.c` depends on
this same fake-waiter install (it only *verifies* `ashmem_misc_fops` was
already corrupted as a side effect of the rt_mutex PI chain-walk
processing the planted waiter -- confirmed load-bearing, not optional
scaffolding, no simpler KASLR-free bypass via `fops-write-root`). Kernel
Clang CFI was checked and ruled out as an explanation for the "CFI" stage
naming (`CONFIG_LTO_CLANG is not set` on both local and real-device
configs -- purely this exploit's own internal codename).

This was superseded by the `ptrace(PTRACE_SETREGSET)` spray (see
"Workaround found" below), which lands correctly. Do not revisit
`pselect`.

## `KernelSnitch` (mm_struct-leak timing side channel) does not work
## under QEMU TCG, but does work on real hardware

`slide_leak_kernel_base()`'s first step is `KernelSnitch`
(`src/exploit/kernelsnitch/`), a timing/collision side channel that
sprays ~4096 futex-hash probes and correlates timing thresholds
(`threshold≈1250`) to find a reclaimed `mm_struct` slab slot. Under QEMU:
`correlate_match_count=0` on every attempt, consistently. QEMU here is
**TCG software emulation** (x86_64 host, aarch64 guest -- KVM can't
cross architectures), which doesn't model real cache/memory timing, so a
timing side channel has no reason to work regardless of whether the
offsets are correct. **This means QEMU can validate deterministic things
(offsets, stack-address arithmetic) but not this timing-dependent leak**
-- a QEMU failure here should not be read as "broken on Quest 2." Later
confirmed on the real device: `KernelSnitch` **does work** there (4-16
`correlate_match_count` per attempt, noisy but functional, leaked a real
`mm_struct`) -- the QEMU failure really was a TCG artifact, not a broken
technique.

## Building without the Android NDK

The `Makefile` only builds `ionstack_preload.so` via the Android NDK's
bionic clang, not installed here. `common.h`'s includes are all plain
POSIX (`<pthread.h>`, `<sys/syscall.h>`, etc.) -- not Android-specific
except `preload.c`'s su-install paths, which fail harmlessly off-Android.
Built a standalone glibc binary instead:

```
aarch64-linux-gnu-gcc -O2 -g0 -fPIE -pie -Wall -Wextra -Wno-unused-parameter \
  -Wno-sign-compare -Wno-unused-function -DIONSTACK_ENABLE_UNSAFE_CONFIGFS_READ=0 \
  -static main.c util.c slide.c fops.c pipe.c root.c harness.c -pthread -o ionstack_test
```

`harness.c` stands in for `preload.c` (avoids needing
`build/su_daemon_aarch64_pie`, NDK-built, `.incbin`'d by `su_blob.S`):

```c
int run_exploit(int argc, char **argv);
int main(int argc, char **argv) { return run_exploit(argc, argv); }
int prepare_modprobe_su_files(void) { return 0; }
int trigger_modprobe_su(void) { return 0; }
```

Also in-tree: `tools/ionstack_test_harness.c` (same idea, already
committed). One real, portable, toolchain-agnostic fix: `util.c` uses
`INT_MAX` without `<limits.h>` (bionic pulls it in transitively, glibc
doesn't) -- added `#include <limits.h>` to `common.h`.

Transfer to a running QEMU guest: `python3 -m http.server` on the host
(bound to a scratch dir), guest reaches it at the SLIRP gateway
`10.0.2.2` (no bridge/tap needed). Confirmed this is also what past
`ionstack_v*` scratch binaries were built with, matching the `.comment`
section ("GCC: (Ubuntu 15.2.0-16ubuntu1)"). Statically-linked non-bionic
binaries run fine via `adb shell` too (same syscall ABI) -- one build
serves both QEMU and real device, outside the QEMU-only diagnostic
pieces (see near the end of this file).

`IONSTACK_STAGE=dry` (pure static self-check) runs clean on both QEMU and
the real device, dumping every resolved address consistent with
`offset.h`/`nm`/`pahole` ground truth.

## Workaround found: `ptrace(PTRACE_SETREGSET)` replaces the dead
## `pselect` route

Found via a parallel research project targeting the same CVE on a Quest 1
/ kernel 4.4.205 (`~/ai_test/test/q1_build/ghostlock_research/`, "GhostLock"
naming) -- different device/kernel/compiler, but the same underlying bug
and the same class of "which syscall's on-stack buffer reaches the
dangling waiter" problem. Their own docs describe a near-identical dead
end for `core_sys_select`, and they also tried
`readv`/`writev`/`sendmsg`/`setsockopt(MCAST_JOIN_GROUP)` -- all too
shallow. **What worked**: `ptrace(PTRACE_SETREGSET, child, NT_PRSTATUS,
&iov)` on a stopped tracee of the calling thread runs
`arch/arm64/kernel/ptrace.c`'s `gpr_set()`, whose local `struct
user_pt_regs newregs` (272 bytes) is filled by an unconditional
`copy_from_user()` **before** `valid_user_regs()` can reject it -- same
copy-before-validate shape as every dead-end candidate, just deeper in
the stack. Confirmed present in our kernel with the identical shape
(`arch/arm64/kernel/ptrace.c:612-628`).

**Verified live on our own kernel**, same GDB technique: breakpointed
`gpr_set`, measured `&newregs = 0xffffff800b73bb38` with `pt_regs` anchor
`0xffffff800b73bec0`. Different process/stack allocation than the
`stack_fds`/`rt_waiter` measurement, but both anchors land at the
identical remainder mod `0x4000` (`0x3ec0`) -- kernel stacks are
16KB-aligned at their base and `pt_regs` sits at a fixed offset from the
true base regardless of thread (a property of the compiled `el0_svc`
entry assembly). This makes every anchor-relative measurement in this
project comparable across runs via `anchor - 0x3ec0 = stack base`:

```
newregs   offset-from-stack-base = 15160, spans [15160, 15432)
rt_waiter offset-from-stack-base = 15304
stack_fds offset-from-stack-base = 15472, spans [15472, 15728)  (confirms non-overlap independently)
```

**`rt_waiter` (15304) falls inside `newregs`'s span, 144 bytes in**
(15160+144=15304), with 48 bytes headroom after the 80-byte
(`FAKE_WAITER_SIZE=0x50`... actually 10 words × 8 bytes = 80B) forged
waiter. `PTRACE_SPRAY_OFF = 0x90` (144). This offset was re-verified
later this project (after the EDEADLK correction below, see "Re-verified"
section) and also confirmed byte-for-byte via live GDB (see the QEMU
infrastructure section) -- correctly derived from the start.

**Mechanism**: fork a `PTRACE_TRACEME`+`SIGSTOP` child once
(`spray_setup`), then repeatedly call `ptrace(PTRACE_SETREGSET, child,
NT_PRSTATUS, &iov)` with a 272-byte buffer holding the 80-byte forged
waiter at offset `0x90` -- each call is a fast, non-blocking stack write.
Must run in a tight loop **from the victim thread itself**, with no other
syscalls from that thread between spraying and the trigger
(`sched_setattr`, called from a different thread) -- any intervening
syscall reuses/stomps the same stack region (see "post-spray grace
period" near the end of this file for a case where this still bit us).
`PTRACE_SETREGSET` returns `EINVAL` every call (confirmed both locally
and against the real device) because the forged registers fail
`valid_user_regs()` -- expected/harmless, the write already landed first.

Implemented: `ptrace_spray_setup()`/`ptrace_stamp_spray()`/
`ptrace_spray_teardown()` (fops.c, shared via common.h),
`do_ptrace_fake_lock_route()` (fops.c) / `slide_ptrace_stack_copy()`
(slide.c), modeled on the Quest 1 project's equivalents. Reused the exact
forged-waiter word values already computed for the pselect route (only
the delivery mechanism changed). `IONSTACK_SPRAY_ROUTE` env var selects
route (default ptrace; `=pselect` falls back to the dead route for
comparison).

**QEMU cannot test the real trigger at all**: `prepare_good_kernel_page()`
depends on the same `KernelSnitch` side channel confirmed broken under
QEMU/TCG, regardless of KASLR or spray route -- the real device is the
only environment that can exercise this code. Confirmed with the user
before running anything live.

### First three live-device tests: crash, root-cause, fix, repeat

Each test rebooted for a clean baseline and used continuous
`/proc/uptime` polling for crash detection (more reliable than
before/after `uptime -p` comparison).

**Test 1** (only `fops.c` on ptrace, `slide.c` still on dead pselect):
`slide.c`'s KASLR leak hit the dead pselect wall before reaching
`fops.c`'s new code -- nothing new actually exercised. Ported the same
ptrace fix into `slide.c` before retrying.

**Test 2** (both routes on ptrace): Attempt 1 got a validated leak,
reached `slide_ptrace_stack_copy()`, sprayed successfully
(`spray_calls=44389`), and the trigger fired cleanly (`sched_ok=1`,
`last_sched_ret=0`) -- first live confirmation the ptrace spray lands the
forged waiter where the bug reads it. Attempt 2 got another validated
leak, entered the same path -- **and the device rebooted** (confirmed via
`adb get-state`/`uptime`, not a disconnect). Root-caused via kernel
source: `rt_mutex_adjust_prio_chain()`, when the corrupted-chain "renumber"
changes the top waiter and the lock has no owner, calls
`wake_up_process(rt_mutex_top_waiter(lock)->task)` -- our forged waiter's
`task` field (word[6]). GhostLock's own PoC sets this to `NULL`
(confirmed in their `poc_stage3.c`), producing a clean, contained
NULL-deref oops. **This port's `build_ptrace_waiter_words()`/
`build_slide_ptrace_waiter_words()` instead set word[6] to
`text_addr(INIT_TASK)`/`SLIDE_INIT_TASK`** (inherited unchanged from the
dead pselect route, where it never mattered) -- under the now-working
ptrace route this reaches a real `wake_up_process(init_task)` call, which
the scheduler doesn't expect and can plausibly corrupt runqueue state or
hang, matching "watchdog reboot" instead of a contained oops. **Fix**:
changed word[6] to `fake_task` (a forged task object already built in
`util.c`'s `prepare_skb_payload()` for exactly this purpose in the
FOPS payload mode -- its own comment already flagged the same concern).
Not yet live-verified at this point.

**Test 3** (`fake_task` fix in place): identical pattern -- attempt 1
clean (`sched_ok=1`), attempt 2 rebooted (confirmed via continuous
`/proc/uptime`, seconds dropped 833->6). **`fake_task` alone did not fix
it.** Traced why attempt 1's clean success still gets retried at all:
`slide_read_stext()` requires the leaked `/proc/sys/kernel/random/boot_id`
bytes to look like a canonical kernel VA (`>>48 == 0xffff`) -- if that
check fails the attempt is discarded and retried, meaning "attempt 1 was
retried" = the trigger fired but the boot_id storage was never actually
overwritten. **Found the reason**: `slide.c`'s word[5]/`pi_left` used
`SLIDE_RANDOM_BOOT_ID_DATA`, whose offset had been an unresolved `0x0`
placeholder since session 1 -- evaluating to `KIMAGE_TEXT_BASE + 0` (the
kernel's own **text segment start**), not boot_id storage at all.
Checked `drivers/char/random.c`: `static u8 sysctl_bootid[UUID_SIZE]`
(~line 1441) is the real target, and this is the *same* symbol
`SLIDE_SYSCTL_BOOTID_OFF` already correctly resolved (confirmed via `nm`
on both builds) -- `SLIDE_RANDOM_BOOT_ID_DATA` was never a different
object, just never connected to the already-resolved value. Plausibly
explains both the failed leak (boot_id storage never touched) and part
of the crash risk (writing a corrupted value into live kernel `.text` is
far less predictable than a small static array). **Fix**: pointed
`slide.c`'s word[5] at `SLIDE_SYSCTL_BOOTID` instead. (This specific
`SLIDE_RANDOM_BOOT_ID_DATA`/`SLIDE_SYSCTL_BOOTID` assignment was later
found to be backwards -- see "Correction" below; don't trust this
paragraph's naming, only the root-cause finding that `_OFF=0` was wrong.)

**Test 4** (both fixes in place): same pattern again -- attempt 1 clean,
attempt 2 apparently failed leak validation, attempt 3 got a validated
leak and **the device rebooted** (confirmed via `/proc/uptime`,
1664->15). This crash landed at a *different* point: log's last lines
were mid-`KernelSnitch` heap-groom retry, not the ptrace-spray/trigger
step (ruled out stdio buffering as the explanation -- `set_unbuffer()`
genuinely calls `setvbuf(..., _IONBF, 0)`). Prompted a full audit of
`offset.h` for remaining placeholders:
- `SELINUX_BLOB_SIZES_OFF=0x0`: confirmed dead code, gated behind
  `#if HAVE_SELINUX_BLOB_SIZES` which is 0 here. Not a risk.
- `P0_KERNEL_PHYS_LOAD`: still an unconfirmed SM-T878U placeholder, but
  implicitly exercised successfully by every `KernelSnitch`/`data_addr()`
  call so far -- not treated as an equally urgent landmine.
- **`COPY_SPLICE_READ_OFF=0x0` -- a real, serious, previously-missed
  bug**, worse than the boot_id one: feeds `FOPS_SPLICE_READ_OFF` in the
  forged `file_operations` table installed as the real, **system-wide**
  `ashmem_misc_fops`. With `_OFF=0`, `.splice_read` pointed at `_text+0`
  -- literal header bytes, not code. ashmem is used system-wide (not
  just by this exploit), so *any* process calling `splice()`/`sendfile()`
  on *any* ashmem fd while the fake table is installed would jump into
  garbage -- a plausible, timing-independent, system-wide crash source
  that would explain the inconsistent crash locations across tests 2-4.
  **Fix**: set to `generic_file_splice_read`'s real address (`0x26fbf0`,
  confirmed via `nm` on both builds) -- the standard kernel idiom for
  this field.

After tests 2-4 (three crashes, three fixes: `fake_task`,
`SLIDE_SYSCTL_BOOTID`, `COPY_SPLICE_READ_OFF`), none yet confirmed live.

## Correction: `SLIDE_RANDOM_BOOT_ID_DATA`/`SLIDE_SYSCTL_BOOTID` are two
## different objects, and their assignment was swapped twice

The Test 3 fix above (pointing `slide.c`'s word[5] at `SLIDE_SYSCTL_BOOTID`)
assumed the two constants were the same object with one just never
derived. **Wrong** -- the original SM-T878U `offset.h` has them as two
different non-zero values (`SLIDE_RANDOM_BOOT_ID_DATA_OFF=0x02ef61f8`,
`SLIDE_SYSCTL_BOOTID_OFF=0x03249f98`). Per user description:
`SLIDE_RANDOM_BOOT_ID_DATA` is the **`.procname` pointer field** within
`boot_id`'s entry in `random_table[]` (`drivers/char/random.c`), derived
as: `random_table` symbol address + `4 * sizeof(struct ctl_table)` (64
bytes, `pahole`-confirmed, `procname` at member offset 0) +0, since
`boot_id` is `random_table[4]` (poolsize=0, entropy_avail=1,
write_wakeup_threshold=2, urandom_min_reseed_secs=3, boot_id=4). Real
device: `random_table@0xffffff8009c5a5a0` -> `0xffffff8009c5a6a0` ->
`SLIDE_RANDOM_BOOT_ID_DATA_OFF = 0x1bda6a0`. Reverted `slide.c`'s two
call sites to `SLIDE_RANDOM_BOOT_ID_DATA` with this value.

**Then corrected again**, mid-live-test, per explicit user instruction
(exact values given, applied verbatim without substituting independent
reasoning): the assignment above was backwards. Final, correct values on
the real device:
- `SLIDE_SYSCTL_BOOTID_OFF = 0x1bda6a0` -- the `.procname` pointer (what
  the paragraph above had assigned to the other constant).
- `SLIDE_RANDOM_BOOT_ID_DATA_OFF = 0x1d4b849` -- `&sysctl_bootid`, the
  raw boot_id data buffer.

No code changes needed for this final swap (call sites reference the
constants by name). **Lesson**: when a `0x0` placeholder looks redundant
with another already-resolved constant, verify against the actual
original source before treating them as interchangeable -- "looks like
the same thing" isn't confirmation. **Do not swap these two values a
third time without explicit new evidence.**

## Other resolved/still-open placeholders

- `SLIDE_RANDOM_BOOT_ID_DATA_OFF`/`SLIDE_SYSCTL_BOOTID_OFF`: resolved,
  see above.
- `COPY_SPLICE_READ_OFF`: resolved (`generic_file_splice_read`), see
  above.
- `MM_STRUCT_SZ`: kept at `0x400` (1024) assuming `mm_struct`'s 896-byte
  size rounds to the same SLUB size-class as the source device. Not
  independently confirmed (`/sys/kernel/slab/mm_struct/object_size` is
  permission-denied to the unprivileged real-device shell).
- `P0_KERNEL_PHYS_LOAD`: still the SM-T878U placeholder value; a real
  physical address dependent on the actual bootloader, not derivable
  from vmlinux. `/proc/iomem` permission-denied on the real device.
- Real-device `BUILD_FINGERPRINT`/`EXPECTED_*` gating in
  `src/device/ionstack_reroot_device.c`: `BUILD_FINGERPRINT` now known
  and in `offset.h`; that orchestrator also calls
  `__system_property_get`, which doesn't exist on the QEMU/Buildroot
  rootfs at all -- QEMU testing exercises the kernel-facing primitives
  directly instead of the full on-device orchestrator.

## Real-device pass: adb access, real kernel image, `offset.h` re-derived

### Recon (read-only, unprivileged `adb shell`, uid=2000)

```
serial:      1WMHH810EV0413 (product:hollywood model:Quest_2 device:hollywood)
fingerprint: oculus/hollywood/hollywood:14/UP1A.231005.007.A1/52150470034600150:user/abl_signing_keys:release,amss_signing_keys:release,release-keys
uname -a:    Linux localhost 4.19.325-cip128-st12-g48f31e2db128 #1 SMP PREEMPT Tue Apr 21 21:26:38 PDT 2026 aarch64 Toybox
adb root:    fails ("adbd cannot run as root in production builds") -- expected
getenforce:  Enforcing
```

Fingerprint's serial field (`52150470034600150`) matches the supplied
kernel filename (`q2_52150470034600150_kernel`) exactly -- confirms it's
the right image for this exact device.

`/proc/config.gz` pulled and compared to the local build config:
`CONFIG_LTO_NONE=y` (no kernel CFI, confirmed on real hardware too);
**`CONFIG_RANDOMIZE_BASE=y`** (KASLR is genuinely on, unlike the
`nokaslr` QEMU test setup -- the slide stage is a real requirement, not
a QEMU artifact); `CONFIG_KALLSYMS_ALL=y` but `/proc/kallsyms` itself is
permission-denied to the unprivileged shell (as are
`kernel/kptr_restrict`, `/proc/iomem`,
`/sys/kernel/slab/mm_struct/object_size`, `dmesg` -- all expected
hardening). `/dev/ashmem` present, world-read-write.

### Chased the exact source commit, then stopped (per explicit user
### direction -- do not re-attempt)

Real device's `g48f31e2db128` local-version hash is not the same commit
as this project's `q2_build/oculus-linux-kernel` checkout
(`g6e428607392d`, current tip of `oculus-quest2-kernel-master`).
Unshallowed the local clone (90 commits) and grepped full history -- not
present. Closest by date is `e3e096cb8` (6 days later). Concluded (and
told directly) not to keep chasing this -- Meta evidently squash-publishes
from a broader internal monorepo. Pivoted to extracting ground truth
directly from the real kernel image.

### Recovering ground truth from `q2_52150470034600150_kernel`

Valid ARM64 boot Image (30365712 bytes), stripped/no DWARF, but
`CONFIG_KALLSYMS_ALL=y` bakes the full symbol table into the image
itself. Used `vmlinux-to-elf` (already installed, v1.3.6):

```
vmlinux-to-elf q2_52150470034600150_kernel device_vmlinux.elf
```

Recovered 107616 symbols; its independently-guessed kernel base matched
the already-known `0xffffff8008080000` `_text` link address -- an
independent confirmation via a different tool/method. Saved
`device_vmlinux.elf`, `device.nm`, `device.config` under
`q2_port/real_device/` (regenerable from the kernel file, kept since slow
to re-derive).

### `offset.h`: real values differ from the local rebuild by design

Every symbol-address `*_OFF` recomputed from `device_vmlinux.elf`.
Confirmed the old (local-rebuild) numbers would have been wrong by
varying, non-uniform amounts: `INIT_TASK_OFF`/`MODPROBE_PATH_OFF` shifted
`-0x20000`, `SELINUX_STATE_OFF` by `-0x22000`, `ASHMEM_FOPS_OFF` by
`-0x11508`, `CONFIGFS_WRITE_FILE_OFF` by only `+0x28` -- never zero.
One naming gotcha: `ASHMEM_COMPAT_IOCTL_OFF`'s real symbol is
`compat_ashmem_ioctl` (reversed from the macro name). `ASHMEM_MISC_FOPS_OFF`
needed one extra step: device kallsyms only names the `ashmem_misc`
`struct miscdevice` itself, not a separate fops symbol -- applied the
already-known `+0x10` (`.fops` member offset, `pahole`-confirmed) to the
device's own `ashmem_misc` address.

### Struct-member offsets: carried over, then spot-verified by
### disassembly

No DWARF in the recovered ELF, so struct *member* offsets (unlike symbol
*addresses*) can't be mechanically re-derived -- carried over from the
local rebuild on the reasoning that layout depends on
config+version+compiler ABI (identical between the two), not the
unrelated commit differences that shifted symbol addresses. Spot-checked
this by disassembling real functions in `device_vmlinux.elf` against
their unambiguous upstream semantics:

- `__rt_mutex_init`: confirms `wait_lock@0`, `waiters root/leftmost@{8,0x10}`,
  `owner@0x18`.
- `rt_mutex_init_waiter`: confirms `tree_entry@0`, `pi_tree_entry@0x18`,
  `task@0x30`.
- `task_blocks_on_rt_mutex`: confirms `owner@0x18` (2nd check),
  `task->pi_lock@0x8b4`, `waiter->task@0x30`/`waiter->lock@0x38` (one
  `stp`), `task->prio@0xc4` -> `waiter->prio@0x40`,
  `task->sched_dl_entity.deadline` -> `waiter->deadline@0x48`.
- `get_task_cred`: confirms `task->real_cred@0x7e0`.

**Every field checked matched exactly** -- the entire
`rt_mutex`/`rt_mutex_waiter`/critical-`task_struct`-fields cluster (the
actual corruption primitive, the single most safety-critical part of the
exploit). Everything else (seccomp, `configfs_buffer`,
`file_operations`, `struct page`, other `cred` fields) remains
carried-over/unverified by this method, not contradicted.

### Live-tested on the real device (`dry` only, no kernel bug touched)

Rebuilt `tools/ionstack_test_harness.c` with the updated `offset.h`,
pushed via `adb push`, ran `IONSTACK_STAGE=dry` -- clean, all addresses
consistent. One line looked like a bug but wasn't:
`/dev/ashmem710f6a9e-...` -- `init_ashmem_path()` deliberately probes a
`/dev/ashmem<boot_id>` randomized device node before falling back to
plain `/dev/ashmem`, and this **is** the real, openable node on this
hardware. Did not go further than `dry` this pass (real device isn't
freely resettable, and the pselect-shift problem was still unresolved at
this point).

## Live trigger attempt against the real device (`IONSTACK_STAGE=full`,
## on explicit instruction)

Ran the full default chain as a backgrounded, logged `adb shell`
process, polled continuously. Full log:
`q2_port/real_device/live_trigger_attempt_1.log`.

**`KernelSnitch` works on real hardware** -- confirms the QEMU failure
was a TCG artifact. Found `correlate_match_count` 4-16 per attempt,
leaked a real `mm_struct`, proceeded through the full reclaim/spray into
the live futex requeue-PI race: `FUTEX_CMP_REQUEUE_PI` returned
`errno=35` (`EDEADLK` -- at this point still believed to mean "trigger
missed," later corrected, see below). Immediately after, the exploit's
own self-check reproduced the QEMU static finding **on the real kernel
binary**: `slide pselect reach nfds=320 words_per_set=5 shift=16
global=16..25 user_words=0..14 total_words=0..29 user_reachable=0` for
all 10 fake-waiter fields, and correctly refused to proceed (`slide
consumer refusing sched_setattr: ... set
IONSTACK_SLIDE_FORCE_UNREACHABLE=1 to reproduce old panic`). Attempt 1
failed cleanly; killed after attempt 2 began repeating the identical
pattern (deterministic, not flaky -- no need to burn all 20 attempts on
real hardware).

**Device health fully normal throughout and after** (`adb get-state`
stayed `device`, `uptime` showed no reboot, fingerprint responded
normally). This closed out "does the pselect dead-end generalize to the
real device" -- yes, confirmed live, not just inferred from the
local-rebuild-derived binary.

## Tracefs-based KASLR slide recovery -- confirmed working, real device,
## first try

While debugging why the rt_mutex-UAF slide route never produced a valid
leak, found (via `arch/arm64/mm/init.c`) that `CONFIG_RANDOMIZE_BASE=y`
**also randomizes `memstart_addr`** (runtime `PHYS_OFFSET`) by up to
~128GB in 1GB steps, from the *same* KASLR seed as the virtual slide --
meaning `P0_PHYS_OFFSET`/`P0_KERNEL_PHYS_LOAD` (assumed fixed) are very
likely wrong on any given real boot, silently breaking every
physmap-alias read/write (`P0_DATA_ALIAS_CONST`) in the whole exploit,
independent of anything else being debugged. Confirmed the *natural*
`P0_PHYS_OFFSET=0x80000000` via the device's own DTS
(`hyp_region@80000000`) and `/proc/meminfo` (`MemTotal≈5.97GB` matches
spec), but had no way to determine the actual per-boot shift (no root;
`/proc/iomem`/`kallsyms`/`cmdline` all denied). Tried back-solving via
`KernelSnitch`'s own leaked addresses -- failed (best agreement 4/21,
noise-level), likely because those addresses weren't from a *validated*
(`ok=1`) run.

Pivoted to a completely different, exploit-free technique from
github.com/BuSung-dev/CVE-2026-43499-S25U's `slide.c`: reads
`sched_blocked_reason`'s tracefs `caller` field, which is `get_wchan(tsk)`
-- a genuine, already-slid `.text` return address -- straight out of
`/sys/kernel/tracing/per_cpu/cpuN/trace_pipe_raw`. No UAF, no
`KernelSnitch`, no physical addressing at all, so entirely unaffected by
the `memstart_addr` problem. Verified live: shell's groups already
include `readtracefs`; `sched_blocked_reason/format` readable; enabling
`tracing_on`+the event succeeded unprivileged; `trace_pipe_raw` is
world-readable. Captured live data, found repeating canonical-kernel-VA
values.

The S25U repo's own constants don't transfer: their `sched_blocked_reason`
event ID is 109, ours (read from
`.../sched_blocked_reason/format`'s `ID:` line) is **75**. Their slide
validation bound (`<=0x1f0000`) reflects a different KASLR scheme; ours
(4.19 `kaslr_early_init()`, "middle half of VMALLOC") places the slide
anywhere in `[64GB, 192GB)`, 2MB-aligned, `VA_BITS=39`.

Re-derived independently: since the slide is always 2MB-aligned, a real
leaked pointer's low 21 bits equal its source function's low 21 bits.
Took the two most frequent captured values, computed `value & 0x1fffff`,
searched `device_vmlinux.elf`'s `nm` output for symbols whose address
range contains that residue -- found `worker_thread+152` and
`rcu_gp_kthread+1448` (both plausible, near-always-blocked functions).
Both independently implied the **exact same slide**, `0x2e48c00000`
(~185GB, 2MB-aligned, inside `[64GB,192GB)`) -- two independent symbol
IDs agreeing exactly is essentially conclusive.

Added to `offset.h`: `SLIDE_TRACEFS_EVENT_ID=75`,
`SLIDE_TRACEFS_WORKER_THREAD_OFF=0x63a84`,
`SLIDE_TRACEFS_RCU_GP_KTHREAD_OFF=0xe4248`,
`SLIDE_TRACEFS_MIN_SLIDE`/`MAX_SLIDE` (theoretical `[64GB,192GB)` bound).
Implemented in `slide.c`: `slide_tracefs_parse_page()` (ring-buffer
parser, ported from S25U but collects every matching event per page, not
just the first, for cross-validation), `slide_tracefs_slide_from_caller()`
(validates 2MB-alignment + range), `slide_tracefs_leak_kernel_base()`
(captures 1s from every CPU, accepts first `worker_thread`-consistent
sample, separately checks `rcu_gp_kthread` agreement as `rcu_confirm`).
Old UAF route renamed `slide_uaf_leak_kernel_base()`
(`IONSTACK_SLIDE_SOURCE=uaf`). `slide_leak_kernel_base()` is now a
dispatcher: tracefs by default, UAF fallback only if tracefs fails.

**Live-tested via `IONSTACK_STAGE=slide` -- worked first try**:
```
slide tracefs collected samples=587
slide-kaslr-ok source=tracefs pid=6932 base=ffffffae50c80000 slide=0000002e48c00000 rcu_confirm=1 samples=587
```
`rcu_confirm=1` (both reference functions agreed exactly, matching the
hand-computed value). Device stayed fully stable. Removes the
`memstart_addr` uncertainty from the slide step entirely and gives a
trustworthy KASLR base for later stages.

## `memstart_addr` also broke the later stages -- fixed via
## `writable_image_addr()`

Full-chain run (`ionstack_v9`, tracefs slide + unchanged fops/root
stages) on a fresh reboot: tracefs slide succeeded again immediately
(different slide value than before, confirming repeatability across
boots), progressed into the fops CFI-hijack stage, then crashed/rebooted
(caught via `adb devices` no longer listing the serial -- a reliable
crash signal; confirmed via `/proc/uptime` reset).

Root cause: `text_addr()` (-> `kaslr_image_addr()`, uses only the
now-reliable *virtual* KASLR slide, no `memstart_addr` dependency) was
already correct for function pointers. `data_addr()` (-> `p0_data_alias()`,
the physmap-alias formula) was still fully dependent on the unresolved
`memstart_addr` randomization, and is what every static kernel *data*
symbol used: `ASHMEM_MISC_FOPS` (the fops-hijack write target -- all of
the rt_mutex corruption math), `root.c`'s
`INIT_TASK_TASKS`/`SELINUX_ENFORCING`/`SELINUX_BLOB_SIZES`/
`SECURITY_CAPABLE_HEAD`, `pipe.c`'s
`KMALLOC_CACHES`/`KMALLOC_CGROUP_PIPE_SLOT`, `MODPROBE_PATH`. Already
present but essentially unused: `writable_image_addr(addr)` = `kaslr_done
? kaslr_image_addr(addr) : data_addr(addr)` -- since `kaslr_done` is now
reliably 1 (tracefs sets it early), this already does the right thing:
prefer the validated virtual-KASLR addressing. Same physical page, just
a different, non-broken valid virtual alias -- a drop-in fix, not a
workaround.

Applied via targeted `sed` (exact constant names, not a blanket
`data_addr(`->`writable_image_addr(` replace -- avoids touching
`data_addr()`'s own definition or `writable_image_addr()`'s internal
fallback call) across `fops.c`/`util.c`/`root.c`/`pipe.c` for:
`ASHMEM_MISC_FOPS`, `INIT_TASK_TASKS`, `SELINUX_ENFORCING`,
`SELINUX_BLOB_SIZES`, `SECURITY_CAPABLE_HEAD`, `KMALLOC_CACHES`,
`KMALLOC_CGROUP_PIPE_SLOT`, `MODPROBE_PATH`. Left `main.c`'s
diagnostic-only `log_dry_offsets()` `data_addr()` calls unchanged.
Rebuilt as `ionstack_v10`.

Live-tested across two reboots: one crashed during the fops CFI-hijack
stage's first attempt; the other reached a normal single-attempt miss
and was still cleanly retrying (no crash) when stopped to pivot to the
isolated write-test below -- so this fix's effect on crash-worthiness
was inconclusive at the time (the fops-hijack stage still wasn't
reliably succeeding either way).

## Standalone single-write UAF verification test (`uts-write-test` stage)

Since the fops-hijack stage is a complex multi-step primitive (rt_mutex
corruption -> fake_fops table -> CFI dispatch -> pipe-physrw) where a
failure could stem from many places, built a minimal, isolated test of
just the *write* primitive: a single UAF-corrupted write to
`&init_uts_ns.name.release`, verifiable unambiguously via `uname -a`
(unlike the boot_id leak's "top 16 bits == 0xffff" heuristic).

`INIT_UTS_NS_RELEASE_OFF` derivation: `nm` on the recovered device ELF
(`init_uts_ns@0xffffff8009bcb328`) + `pahole -C uts_namespace`/`new_utsname`
on the local rebuild: `kref`(4B, offset 0) + `name`(offset 4) ->
`release` at `new_utsname` offset 130 (`sysname[65]+nodename[65]`) ->
absolute offset `4+130=134` (`0x86`) -> `INIT_UTS_NS_RELEASE_OFF = 0x1b4b3ae`.

Reuses the exact "write one 8-byte value to a chosen target, `owner=0`
fast-path clean exit" payload already used for the boot_id leak
(`PAGE_PAYLOAD_SLIDE` mode) rather than a new payload mode: two new
globals, `uts_write_test_target`/`uts_write_test_value` (`util.c`,
default 0), which `prepare_skb_payload()` and
`build_slide_ptrace_waiter_words()` (word[3]/`pi_parent_color`=value,
word[5]/`pi_left`=target) use if set, falling back to the normal
boot_id-leak behavior otherwise. `slide_uts_write_test()` (`slide.c`):
requires `kaslr_done` (needs the real slide, not `memstart_addr` --
target computed via `writable_image_addr()`), reads `uname()` before,
sets the overrides to `writable_image_addr(INIT_UTS_NS_RELEASE)` and
marker `0x2144454e57503251` (`"Q2PWNED!"`, little-endian), prepares the
page, forks a child running the same waiter/owner/consumer trigger
threads the boot_id leak uses, reads `uname()` again, reports whether
`release` changed. New isolated stage `IONSTACK_STAGE=uts-write-test`.

**First live test (`ionstack_v11`, one-shot, no retry)**: tracefs slide
and page-prep both succeeded, but `FUTEX_CMP_REQUEUE_PI` returned
`errno=35` (`EDEADLK`) -- at the time interpreted as "the trigger didn't
fire" (later corrected, see next section -- this is actually the
intended outcome). `release` unsurprisingly unchanged; inconclusive on
its own since this test had no retry loop (the real slide/fops routes
retry 20/24 times specifically because of perceived race misses).
**Added a retry loop** (`UTS_WRITE_TEST_TRIGGER_ATTEMPTS=20`, overridable
via `IONSTACK_UTS_TEST_ATTEMPTS`), page prepared once and reused across
attempts. Rebuilt as `ionstack_v12`.

---

# Major reframing: `EDEADLK` is the intended trigger outcome, and the
# corruption write still doesn't land even matching the reference exactly

Everything below happened in one extended debugging session and
significantly revises earlier conclusions in this file.

## `EDEADLK` from `FUTEX_CMP_REQUEUE_PI` is success, not failure

Every historical log in this project showing `errno=35` was
misdiagnosed as "the trigger didn't fire." **Wrong.** Per external
research (nebusec.ai/research/ionstack-part-2/, kernel 6.12.80/x86_64 --
different version, same CVE bug) and confirmed against our own kernel
source: the three-thread cycle (waiter blocks via
`FUTEX_WAIT_REQUEUE_PI`; owner holds `FUTEX_LOCK_PI(f_pi_chain)`; main
thread calls `FUTEX_CMP_REQUEUE_PI`) is *designed* so the kernel's PI
chain-walk detects the cycle and returns `-EDEADLK` -- and it's exactly
this deadlock-detection rollback that invokes the buggy `remove_waiter()`
(`kernel/locking/rtmutex.c` ~line 1079: clears `current->pi_blocked_on`
instead of `waiter->task->pi_blocked_on`, since `current` during this
rollback is the *main* thread, not the waiter thread whose
`rt_mutex_waiter` it actually is), leaving `waiter_task->pi_blocked_on`
dangling into the waiter thread's own soon-to-be-reused kernel stack.
Per the research, once triggered "there is no time pressure at all" for
the spray/corruption step (though this project's own findings below
complicate that for this kernel/arch -- see "post-spray grace period").

Confirmed live via GDB (local kernel rebuild): breakpointing
`remove_waiter()` during a real EDEADLK-triggering attempt shows
`waiter->task->pi_blocked_on` correctly pointing at the live `rt_waiter`
before the call, and still pointing at that exact dangling address
after -- fires exactly as described, every time `EDEADLK` is returned.

**Going forward**: `errno=35` in any trigger log means "fired correctly."
A genuine race-miss looks like `cmp_requeue ret=0`/`ret=1` (an actual
non-deadlocked requeue) instead. The retry loop is harmless to keep as a
hedge against real misses, but it wasn't solving the problem it was
built to solve.

## Ruled out: `prctl(PR_SET_MM, PR_SET_MM_MAP, ...)` spray can't port here

The nebusec.ai research's own spray primitive (different from ours)
forges a waiter via `prctl_set_mm_map()`'s `user_auxv` stack buffer,
extended via a racing `fallocate(PUNCH_HOLE)`. Checked directly
(`kernel/sys.c:2109-2131`): the unprivileged path for `PR_SET_MM_MAP`
only exists `#ifdef CONFIG_CHECKPOINT_RESTORE`. Real device's
`/proc/config.gz`: `# CONFIG_CHECKPOINT_RESTORE is not set` -- falls
through to `if (!capable(CAP_SYS_RESOURCE)) return -EPERM`. Not portable
here; this project's own `ptrace(PTRACE_SETREGSET)` primitive remains
correct (re-verified next).

## Re-verified: `PTRACE_SPRAY_OFF` was correctly derived all along

Briefly suspected (prompted by the EDEADLK correction) that
`PTRACE_SPRAY_OFF` might have been measured against the wrong
function/thread (a stale TODO comment referencing
`rt_mutex_adjust_prio_chain`, which runs on the consumer thread, not the
waiter). Re-checked: the actual original measurement (see "Workaround
found" above) correctly breakpointed `futex_wait_requeue_pi` and
measured `&rt_waiter` directly on the *waiter* thread's own stack --
correct. The stale comment was leftover pre-verification scratch, not
the real methodology. Also independently confirmed via
`kernel/futex.c` ~line 3341's own comment ("The waiter is allocated on
our stack..."). No re-measurement needed. Separately reconfirmed live
via GDB this session that the spray lands its full 10-word forged waiter
exactly at `PTRACE_SPRAY_OFF` within `gpr_set()`'s `newregs` buffer,
byte-for-byte, every time checked (see QEMU section below).

## `uts-write-test` results, and two mistaken "fixes" chased and reverted

Live-tested extensively (real device and QEMU) after the EDEADLK
correction. Every attempt across dozens of runs and many rebuilds shows
the same result: trigger fires correctly (`EDEADLK`), spray lands
correctly (byte-for-byte, GDB-confirmed), but `init_uts_ns.name.release`
never actually changes. Two field-level hypotheses were tried, live
tested, and **reverted** after direct comparison against the reference
exploit showed they were unverified deviations from its proven design:

1. **`RTMUTEX_OWNER_OFF` for `PAGE_PAYLOAD_SLIDE`**: with the forged
   `lock`'s `owner` left `0`, `rt_mutex_adjust_prio_chain()` returns
   early (`if (!rt_mutex_owner(lock)) {...; return 0;}`) before ever
   reaching the `pi_tree_entry`-based `rt_mutex_enqueue_pi()`/`dequeue_pi()`
   calls that use `write_pc`/`write_left` (the forged waiter's
   `pi_parent_color`/`pi_left`, where the leak/write value+target live).
   Changed to `text_addr(INIT_TASK) | 1`. Live-tested both QEMU and real
   device: execution genuinely goes deeper (crash dumps land later and
   later inside `rt_mutex_adjust_prio_chain`), but never produces a
   working write -- instead new, deeper crashes, including one real-device
   reboot (a spinlock-held deadlock, see QEMU section). **Reverted**:
   the reference's own `util.c` also sets `RTMUTEX_OWNER_OFF=0`
   unconditionally for this exact payload mode, and its boot_id leak is
   proven to work on real hardware with that value -- the write
   mechanism doesn't require a non-NULL owner. Wrong lever.
2. **`word[6]` (forged waiter's `task` field)**: an earlier (pre-this-
   session) pass had changed this from the reference's `SLIDE_INIT_TASK`
   to `fake_task`, based on reasoning borrowed from a *different* payload
   mode and explicitly self-flagged as "post-crash fix, not yet
   live-verified." Matters directly for `owner=0`: `wake_up_process(
   rt_mutex_top_waiter(lock)->task)` runs on this field, and `fake_task`
   (`util.c`) only has `usage`/`prio`/`pi_lock`/`pi_waiters`/
   `task_group`/`pi_top_task` populated -- no `sched_class`/`state`/`cpu`,
   a real risk for `wake_up_process()`'s scheduler bookkeeping.
   **Reverted** to the reference's intent (real `init_task`), but via
   `text_addr(INIT_TASK)` rather than the reference's own physmap-based
   `SLIDE_INIT_TASK` (confirmed broken here by `memstart_addr`
   randomization -- `text_addr()` is the required, Quest2-specific
   correction, not a behavioral deviation).

**With both reverted** (now matching the reference exactly, modulo the
required addressing correction): a clean QEMU test (fresh page, single
attempt, confirmed `EDEADLK`, zero crashes -- see
`IONSTACK_ORIGINAL_BOOTID_MECHANISM` below) of the reference's
**completely unmodified** boot_id-leak mechanism still produces no
write. `boot_id` read back byte-identical before/after. **This is the
most important finding of this session**: the reference's exact,
proven-on-real-hardware mechanism doesn't reproduce on this target
(Quest 2/kona, `4.19.325-cip128`) even under ideal, crash-free
conditions -- ruling out every specific-field hypothesis chased this
session (and possibly earlier ones) as *the* remaining blocker. See
"What's still unexplained" at the end of this file.

## QEMU: real, backed-page live-debugging infrastructure (new, reusable)

`KernelSnitch` still doesn't work under QEMU TCG (confirmed again,
`found=0` consistently). Built a way around this without fixing
`KernelSnitch` itself:

**GDB kernel-debug recipe** (previous attempts got stuck on gdbstub
protocol errors -- this recipe reliably works):
- Boot with `-s -S` (gdbstub, paused at reset), `nokaslr` on cmdline (no
  need to fight real KASLR for this kind of testing).
- `gdb-multiarch -q vmlinux` (matching `q2_build/build/qemu-kernel/`'s
  own vmlinux, **not** the real device's) in a second tmux window,
  `target remote localhost:1234`, `continue` immediately -- a stale/
  interrupted connection attempt reliably desyncs the protocol ("Ignoring
  packet error"/`info threads` empty); kill and restart QEMU fresh rather
  than retry the same connection.
- Breakpoints on functions that also fire during normal boot
  (`remove_waiter`, `rt_mutex_adjust_pi`) hit immediately/repeatedly for
  unrelated legitimate activity -- `disable` them, `continue` through
  boot to a shell, `enable` right before the actual test. **Forgetting to
  `continue` after an interrupt/inspect cycle silently freezes the whole
  guest** with no obvious symptom -- always check `info threads` shows
  CPUs actually running, not all in `cpu_do_idle`.
- **A crash while holding a spinlock permanently deadlocks the guest**
  (confirmed via `info threads` showing a CPU stuck in
  `__cmpwait_case_4` on the lock's address, matching a crash-dump
  register) -- the fault handler kills the process/thread group but
  doesn't release C-level spinlocks it held. Kill and boot fresh; no
  further info available. This is also the direct explanation for real
  device reboots on crash: not a panic, a deadlock that eventually trips
  the watchdog.
- `q2_build/build/qemu-kernel/` is a **different build** from the real
  device kernel (different linked drivers -- QCOM vs virtio, confirmed
  via `.config` diff to be purely driver/platform, nothing in
  scheduler/locking/futex) and from `oculus-quest2-device-kernel/` too,
  differing in exact symbol *addresses* (same `_text` link base
  `0xffffff8008080000` across all three, but internal offsets shift).
  **Do not reuse `offset.h`'s numbers against `qemu-kernel`.** Created
  `offset_qemu.h` (mirrors `offset.h`, only `INIT_TASK_OFF`,
  `ROOT_TASK_GROUP_OFF`, `INIT_UTS_NS_RELEASE_OFF` re-derived from
  `qemu-kernel/System.map` -- the rest is copy-pasted and invalid for
  `qemu-kernel`, harmless since unused by this test path). Selected via
  `-DIONSTACK_TARGET_QEMU=1`, wired into `common.h`'s `offset.h`/
  `offset_qemu.h` include.
- Build with `aarch64-linux-gnu-gcc-15` (Ubuntu 15.2.0), not the Android
  NDK (confirmed this is what past `ionstack_v*` binaries actually used
  too, via `.comment`). Statically-linked non-bionic binaries run fine
  on both the real device and the QEMU rootfs unmodified. No
  `preload.c`/`su_blob.S` needed for isolated-stage testing -- use
  `tools/ionstack_test_harness.c` or a minimal ad-hoc `main()` + dummy
  `embedded_su_start`/`embedded_su_end` symbols.
- File-serve: `python3 -m http.server` on host, guest reaches it at
  `10.0.2.2` (QEMU usermode networking gateway).

**`IONSTACK_QEMU_REAL_PAGE`** (`slide_uts_write_test()`): the actual
`KernelSnitch` bypass. `mmap()`s a large (16x needed), `MAP_LOCKED`
region, reads `/proc/self/pagemap` per page (works unprivileged as root,
which the QEMU guest runs as by default -- diagnostic only, never on a
real device), scans for a physically-contiguous `ORDER3_SIZE` (32KB) run
(plain mmap pages aren't guaranteed contiguous, but usually are on a
fresh guest within a modest scan). Resolves the kernel linear-map
address via `P0_PAGE_OFFSET | (phys - QEMU_PHYS_OFFSET)` -- **
`QEMU_PHYS_OFFSET = 0x40000000`, not the real device's `P0_PHYS_OFFSET`
(`0x80000000`)**: confirmed via `/proc/iomem`'s `System RAM` entry that
`-M virt`'s simulated RAM starts elsewhere. Formula independently
verified (not assumed): wrote a marker into a real mmap'd page, computed
the candidate kernel address, read it back via GDB -- byte-for-byte
match. Requires `nokaslr` (doesn't account for `memstart_addr`
randomization, unlike `writable_image_addr()`).

**`prepare_skb_payload_into_region()`** (`util.c`, new): lets the bypass
reuse the actual, unmodified `prepare_skb_payload()` content logic
(every live-tested fix applies here automatically), delivering it via a
plain `memcpy()` instead of the real reclaim/skb-send mechanism. **Found
and fixed a real alignment bug in this bypass** (not the real exploit):
`prepare_skb_payload()` writes into `skb_buf` at *absolute* offsets
(e.g. `LOCK_OFF`) and computes `fake_lock = base + SKB_DATA_DELTA +
LOCK_OFF` (`SKB_DATA_DELTA = -0xe80`) -- i.e. `skb_buf[X]` is meant to
land at kernel address `base + SKB_DATA_DELTA + X`, not `base + X`. The
first version of this bypass naively did `memcpy(region, skb_buf, len)`
-- off by `SKB_DATA_DELTA`. Confirmed via GDB disassembly: this made
`RTMUTEX_WAITERS_LEFTMOST_OFF` (written as literal `0`) read back
non-zero, and `rt_mutex_top_waiter()`'s `BUG_ON(w->lock != lock)` check
dereferenced the garbage as a waiter pointer, crashing in
`rt_mutex_adjust_prio_chain()` -- explains a whole cluster of this
session's earlier "why does it crash reading `waiter->lock`" confusion;
it was this bypass's own bug, not the real corruption mechanism. **Fixed**:
pass `base = region_kernel_addr - SKB_DATA_DELTA` (i.e.
`region_kernel_addr + 0xe80`) so `payload_base` (computed internally as
`base + SKB_DATA_DELTA`) lands back on `region[0]`.

**`IONSTACK_ORIGINAL_BOOTID_MECHANISM`** (`slide_uts_write_test()`):
skips setting `uts_write_test_target`/`value`, leaving
`build_slide_ptrace_waiter_words()`'s word[3]/word[5] at their normal
`SLIDE_LOGGERS_0_1`/`SLIDE_RANDOM_BOOT_ID_DATA` defaults -- tests the
reference's own unmodified mechanism through this same harness. Reads
back `/proc/sys/kernel/random/boot_id` after and logs it alongside the
expected leak value/target. This is what produced the clean negative
result above.

**Found and fixed: a page-reuse-corruption bug.** `IONSTACK_UTS_TEST_ATTEMPTS`'s
retry loop reused the *same* prepared page (`page_base`/`fake_lock`)
across attempts, but a single successful `EDEADLK`-triggered pass through
`rt_mutex_adjust_prio_chain()` **permanently mutates** `lock`'s memory:
`rt_mutex_dequeue()`/`enqueue()` (the `tree_entry` calls, which run
unconditionally regardless of `owner`) update `lock->waiters.rb_leftmost`
to point at *that attempt's* dangling waiter. Never reset before the next
attempt, whose very first `rt_mutex_top_waiter(lock)` call dereferenced
the now-stale pointer (pointing into a long-dead thread's stack) and
crashed. Explained why attempt 1 (fresh page) never crashed but later
attempts often did, independent of whichever hypothesis was being tested.

`fops.c`'s `do_ptrace_fake_lock_route()` already had the right pattern for
this (re-preps the page on every attempt after the first) -- mirrored it:
extracted the page-prep branch (`IONSTACK_QEMU_REAL_PAGE`/
`IONSTACK_SKIP_PAGE_PREP`/real `prepare_good_kernel_page()`) into
`slide_uts_prepare_page()`, called once before the loop and again at the
top of every subsequent iteration. For `IONSTACK_QEMU_REAL_PAGE`, the
expensive part (mmap+`/proc/self/pagemap` scan for a physically-
contiguous region) is cached in static locals across calls -- re-priming
just re-runs `prepare_skb_payload_into_region()` on the already-found
region, which is the part that actually needs to be fresh (the
*content*, not the address, is what a trigger mutates). The real
`prepare_good_kernel_page()` path has no such shortcut (KernelSnitch's
groomed page isn't otherwise directly user-writable) and re-grooms fully
on every call -- same cost `fops.c`'s route already accepts.

Live-tested in QEMU post-fix: 4 consecutive attempts (mix of `EDEADLK`
and race-miss outcomes), zero crashes -- previously attempt 2+ almost
always crashed with this exact bug. Confirms the fix. (Did not change the
separate, still-open "why doesn't the write land" question -- this bug
was masking/corrupting later attempts' results, not causing the missing
write itself, which attempt 1 already showed independent of this bug.)

**Post-spray "grace period" fix** (`slide_ptrace_stack_copy()`, applied
permanently to the real code path): once the spray loop detects
`sched_ok`, the waiter thread used to immediately call
`ptrace_spray_teardown()` (more syscalls) then `sleep(1)` forever -- all
reusing the same stack region the forged waiter still occupies, while
`rt_mutex_adjust_prio_chain()` may still be mid-flight reading it on
another CPU (not one atomic read -- separate `task->pi_lock`/
`lock->wait_lock` steps). Confirmed live: a page that read back
byte-correct at one moment later faulted with `pte=0` (not present) on a
second read from the same call. **Fixed**: spin in pure userspace
(`clock_gettime(CLOCK_MONOTONIC)` is vDSO, no kernel entry) for
`IONSTACK_POST_SPRAY_GRACE_MS` (default 500ms) before any further
syscalls; converted the final idle-wait to a pure `yield` spin too.
Measurably reduced crashes at the trylock/`waiter->lock`-read stage, but
alone did not produce a working write -- and per the alignment-bug
finding, some of what looked like this race was actually that separate
bug. Worth keeping (still a real, applicable race), but its isolated
necessity for the *real* mechanism isn't cleanly separated from the
other fixes made in the same window.

## Current source/binary state

- Tracked source: `RTMUTEX_OWNER_OFF` and `word[6]` both reverted to
  match the reference (modulo the required `text_addr()` addressing
  correction). Grace-period fix and idle-spin are permanent, real fixes.
  The `IONSTACK_UTS_TEST_ATTEMPTS` page-reuse bug is documented but not
  fixed.
- New QEMU-only pieces, all inert unless their env vars are set (never
  set against the real device): `offset_qemu.h`, `IONSTACK_TARGET_QEMU`
  (common.h), `IONSTACK_QEMU_REAL_PAGE`/`IONSTACK_ORIGINAL_BOOTID_MECHANISM`/
  `IONSTACK_POST_SPRAY_GRACE_MS` (slide.c),
  `prepare_skb_payload_into_region()` (util.c).
- Scratch binaries (job tmp/scratchpad, regenerable, not tracked):
  `ionstack_v13`/`v14` (real-device, offset.h), `ionstack_qemu2`
  through `ionstack_qemu11` (QEMU, offset_qemu.h, progressively adding
  the fixes above -- `qemu11` is latest/most complete). `pagemap_probe`/
  `pagemap_probe2` (standalone physmap-formula verification, not part of
  the exploit).
- Real device: last live-tested with `ionstack_v14` (owner fix applied,
  since reverted -- needs a rebuild to re-test current state). That test
  crashed/deadlocked (watchdog reboot) on the 3rd of 15 attempts,
  consistent with the retry-loop page-reuse bug (attempt 1 clean, later
  attempts on a mutated page) rather than the owner fix specifically
  (same crash signature reproduced in QEMU with owner already reverted).

## What's still unexplained (most important open question)

With every field-level hypothesis reverted to match the reference
exactly, **the reference's own unmodified mechanism still produces no
write against this target**, under clean/crash-free QEMU conditions.
Leading candidates, none confirmed:

1. **A genuine kernel-version/build difference** between this target
   (Quest 2/kona, `4.19.325-cip128-st12-...`, Meta/Facebook CIP fork) and
   whatever the reference's SM-T878U target actually runs (undocumented
   in the reference repo). If `rt_mutex_adjust_prio_chain()`/
   `rt_mutex_enqueue()`/`_pi()`/`wake_up_process()` differ version-
   specifically, the *mechanism* -- not just byte offsets -- may need
   re-deriving from this kernel's own disassembly rather than the
   reference's source-level reasoning. Worth directly re-tracing what
   `rt_mutex_dequeue()`/`rt_mutex_enqueue()` (tree_entry, word0-2, run
   unconditionally regardless of `owner`) and `wake_up_process()`
   actually *do* to a real, cleanly-forged waiter+lock (no crash,
   `owner=0`, fresh page), step by step, rather than continuing to guess
   which field should matter.
2. The corruption mechanism might not be a simple "one write" primitive
   read off `write_pc`/`write_left`-named fields at all -- that framing
   is this project's own code/variable naming, not independently
   re-derived from the reference's actual disassembled behavior. Worth a
   broad, unconditional GDB watchpoint (not a source-derived guess)
   across the `boot_id` buffer's physmap *and* text-image aliases, for
   the reference's own mechanism, single-stepping from
   `rt_mutex_adjust_pi()`'s entry to see exactly which instruction (if
   any) first touches that memory.
3. **QEMU-specific**: even with the `SKB_DATA_DELTA` alignment bug fixed,
   there could be a second, undiscovered bug in the diagnostic bypass
   itself (new, unaudited code) rather than the real mechanism. The
   real-device `ionstack_v14` test crashing with the same signature as
   QEMU is reassuring (suggests the harness is at least directionally
   representative), but that test used the since-reverted owner fix, not
   the current reference-matching state. **Re-testing the current
   (reverted) source against the real device, cleanly (single attempt,
   fresh reboot), is the most direct way to rule this out and hasn't
   been done yet.**
