#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

echo "test_clean.sh"
echo "------------"

cleanup() {
    stop_nc_listener
    "$PIDNL_BIN" clean -y >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --- clean removes cgroup and BPF after limit set ---

start_nc_listener 9999

set +e
"$PIDNL_BIN" limit set "$_NC_PID" 1000 2000 >/dev/null 2>&1
set -e

test_start "cgroup exists after limit set"
if assert_cgroup_exists "$_NC_PID"; then
    test_pass
fi

test_start "BPF programs attached after limit set"
if assert_bpf_attached; then
    test_pass
fi

test_start "'clean -y' removes cgroup"
"$PIDNL_BIN" clean -y >/dev/null 2>&1
if assert_cgroup_not_exists "$_NC_PID"; then
    test_pass
fi

test_start "'clean -y' detaches BPF programs"
if assert_bpf_not_attached; then
    test_pass
fi

test_start "'clean -y' exits 0"
# Set limit again so clean has something to clean
set +e
"$PIDNL_BIN" limit set "$_NC_PID" 1000 1000 >/dev/null 2>&1
set -e
if assert_exit_code 0 "$PIDNL_BIN" clean -y; then
    test_pass
fi

test_start "'clean -y' prints confirmation"
set +e
"$PIDNL_BIN" limit set "$_NC_PID" 1000 1000 >/dev/null 2>&1
set -e
output=$("$PIDNL_BIN" clean -y 2>/dev/null) || true
if [[ "$output" == *"Cleanup complete"* ]]; then
    test_pass
else
    test_fail "expected 'Cleanup complete' in output"
    echo "       got: $output"
fi

stop_nc_listener

# --- clean with no prior limits ---

test_start "'clean -y' with no limits exits 0"
if assert_exit_code 0 "$PIDNL_BIN" clean -y; then
    test_pass
fi

# --- clean without --yes prompts ---

test_start "'clean --help' exits 0"
if assert_exit_code 0 "$PIDNL_BIN" clean --help; then
    test_pass
fi

print_summary