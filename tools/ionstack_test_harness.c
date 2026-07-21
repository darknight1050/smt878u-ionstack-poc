#include <stdio.h>

int run_exploit(int argc, char **argv);

int main(int argc, char **argv) {
  return run_exploit(argc, argv);
}

int prepare_modprobe_su_files(void) {
  fprintf(stderr, "[harness] prepare_modprobe_su_files stub, no-op\n");
  return 0;
}

int trigger_modprobe_su(void) {
  fprintf(stderr, "[harness] trigger_modprobe_su stub, no-op\n");
  return 0;
}
