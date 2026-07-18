#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  cat <<'EOF'
usage: collect_reboot_artifacts.sh [serial] [output_dir]

Environment:
  ANDROID_SERIAL   optional adb serial override

Examples:
  ./tools/collect_reboot_artifacts.sh
  ./tools/collect_reboot_artifacts.sh <serial>
  ANDROID_SERIAL=<serial> ./tools/collect_reboot_artifacts.sh "" /tmp/out
EOF
  exit 0
fi

serial="${ANDROID_SERIAL:-${1:-}}"
timestamp="$(date +%Y%m%d-%H%M%S)"
out_root="${2:-$(pwd)/results/reboot-artifacts}"
out_dir="${out_root}/${timestamp}"

adb_cmd=(adb)
if [[ -n "${serial}" ]]; then
  adb_cmd+=( -s "${serial}" )
fi

mkdir -p "${out_dir}"

run_host() {
  echo "+ $*" | tee -a "${out_dir}/host.log"
  "$@" >>"${out_dir}/host.log" 2>&1 || true
}

capture_shell() {
  local name="$1"
  shift
  {
    echo "+ ${adb_cmd[*]} shell $*"
    "${adb_cmd[@]}" shell "$@"
  } >"${out_dir}/${name}" 2>&1 || true
}

capture_pull_dir() {
  local remote="$1"
  local local_name="$2"
  mkdir -p "${out_dir}/${local_name}"
  {
    echo "+ ${adb_cmd[*]} pull ${remote} ${out_dir}/${local_name}"
    "${adb_cmd[@]}" pull "${remote}" "${out_dir}/${local_name}"
  } >"${out_dir}/${local_name}.log" 2>&1 || true
}

run_host "${adb_cmd[@]}" wait-for-device
run_host "${adb_cmd[@]}" get-state
run_host "${adb_cmd[@]}" devices -l

capture_shell getprop.txt getprop
capture_shell uname.txt uname -a
capture_shell boot_id.txt cat /proc/sys/kernel/random/boot_id
capture_shell cmdline.txt cat /proc/cmdline
capture_shell dmesg.txt dmesg
capture_shell logcat_all.txt logcat -d -b all
capture_shell logcat_kernel.txt logcat -d -b kernel
capture_shell logcat_crash.txt logcat -d -b crash
capture_shell mounts.txt cat /proc/mounts
capture_shell last_kmsg.txt sh -c 'cat /proc/last_kmsg 2>/dev/null || true'
capture_shell tombstones_ls.txt sh -c 'ls -la /data/tombstones 2>/dev/null || true'
capture_shell dropbox_ls.txt sh -c 'ls -la /data/system/dropbox 2>/dev/null || true'
capture_shell pstore_ls.txt sh -c 'ls -la /sys/fs/pstore 2>/dev/null || true'
capture_shell ramoops_ls.txt sh -c 'ls -la /mnt/vendor/persist/ramoops 2>/dev/null || true'

capture_pull_dir /sys/fs/pstore pstore
capture_pull_dir /data/tombstones tombstones
capture_pull_dir /data/system/dropbox dropbox
capture_pull_dir /mnt/vendor/persist/ramoops ramoops

cat >"${out_dir}/README.txt" <<EOF
Collected reboot/crash artifacts

Timestamp: ${timestamp}
Serial: ${serial:-default}

Key files:
- getprop.txt
- uname.txt
- boot_id.txt
- dmesg.txt
- logcat_kernel.txt
- logcat_crash.txt
- pstore/
- tombstones/
- dropbox/
- ramoops/
EOF

echo "saved: ${out_dir}"
