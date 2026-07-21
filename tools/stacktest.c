/* Standalone stack-layout probe: calls the two syscalls whose kernel-stack
 * frame layout we need to compare (core_sys_select's on-stack fd_set
 * buffer vs futex_wait_requeue_pi's on-stack rt_mutex_waiter), so we can
 * breakpoint both in gdb and diff the addresses on the same thread's
 * kernel stack. Not part of the exploit itself -- a one-off dynamic
 * reconnaissance tool for PORTING_NOTES.md's "biggest open risk". */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

int main(void) {
  fd_set rfds, wfds, efds;
  FD_ZERO(&rfds);
  FD_ZERO(&wfds);
  FD_ZERO(&efds);
  struct timespec ts = {0, 1};

  printf("[stacktest] pid=%d about to call pselect6(nfds=320)\n", getpid());
  fflush(stdout);
  long r1 = syscall(SYS_pselect6, 320, &rfds, &wfds, &efds, &ts, NULL);
  printf("[stacktest] pselect6 returned %ld errno=%d\n", r1, errno);
  fflush(stdout);

  unsigned futex1 = 0, futex2 = 0;
  struct timespec abst = {1, 0}; /* already-past deadline: returns fast */
  printf("[stacktest] about to call futex(FUTEX_WAIT_REQUEUE_PI)\n");
  fflush(stdout);
  long r2 = syscall(SYS_futex, &futex1, FUTEX_WAIT_REQUEUE_PI, 0, &abst,
                     &futex2, 0);
  printf("[stacktest] futex returned %ld errno=%d\n", r2, errno);
  fflush(stdout);

  printf("[stacktest] done\n");
  fflush(stdout);
  return 0;
}
