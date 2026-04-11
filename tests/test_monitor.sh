#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

echo "test_monitor.sh"
echo "----------------"

NC_PID=""

cleanup() {
    if [ -n "$NC_PID" ]; then
        kill "$NC_PID" 2>/dev/null || true
        wait "$NC_PID" 2>/dev/null || true
    fi
    "$STRAIT_BIN" clean -y >/dev/null 2>&1 || true
}
trap cleanup EXIT

nc -l -p 9999 >/dev/null 2>&1 &
NC_PID=$!
sleep 0.5

"$STRAIT_BIN" limit set "$NC_PID" 1000 2000 >/dev/null 2>&1

SAVED_PID="$NC_PID"
kill "$NC_PID" 2>/dev/null || true
wait "$NC_PID" 2>/dev/null || true
NC_PID=""

sleep 1

test_start "monitor auto-cleans when watched process dies"
if assert_cgroup_not_exists "$SAVED_PID" && assert_bpf_not_attached; then
    test_pass
fi

print_summary
