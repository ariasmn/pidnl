#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

echo "test_limit.sh"
echo "------------"

cleanup() {
    stop_nc_listener
    "$STRAIT_BIN" clean -y >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --- limit set ---

start_nc_listener 9999

test_start "'limit set' creates cgroup for PID"
set +e
"$STRAIT_BIN" limit set "$_NC_PID" 1000 2000 >/dev/null 2>&1
set -e
if assert_cgroup_exists "$_NC_PID"; then
    test_pass
fi

test_start "'limit set' attaches BPF programs"
if assert_bpf_attached; then
    test_pass
fi

test_start "'limit set' exits 0"
if assert_exit_code 0 "$STRAIT_BIN" limit set "$_NC_PID" 1000 2000; then
    test_pass
fi

test_start "'limit set' prints confirmation"
output=$("$STRAIT_BIN" limit set "$_NC_PID" 500 500 2>/dev/null) || true
if [[ "$output" == *"Limiting PID"*"$_NC_PID"* ]]; then
    test_pass
else
    test_fail "expected 'Limiting PID ... $_NC_PID' in output"
    echo "       got: $output"
fi

# --- limit set with -1 (unlimited direction) ---

test_start "'limit set' with unlimited upload exits 0"
if assert_exit_code 0 "$STRAIT_BIN" limit set "$_NC_PID" -1 500; then
    test_pass
fi

test_start "'limit set' with unlimited download exits 0"
if assert_exit_code 0 "$STRAIT_BIN" limit set "$_NC_PID" 500 -1; then
    test_pass
fi

test_start "'limit set' with both unlimited fails"
if assert_exit_code 1 "$STRAIT_BIN" limit set "$_NC_PID" -1 -1; then
    test_pass
fi

# --- limit set with invalid inputs ---

test_start "'limit set' with invalid PID fails"
if assert_stderr_contains "invalid PID" "$STRAIT_BIN" limit set 0 1000 2000; then
    test_pass
fi

test_start "'limit set' with nonexistent PID fails"
if assert_stderr_contains "not found" "$STRAIT_BIN" limit set 999999 1000 2000; then
    test_pass
fi

# --- limit unset ---

test_start "'limit unset' removes cgroup"
set +e
"$STRAIT_BIN" limit set "$_NC_PID" 1000 1000 >/dev/null 2>&1
"$STRAIT_BIN" limit unset "$_NC_PID" >/dev/null 2>&1
set -e
if assert_cgroup_not_exists "$_NC_PID"; then
    test_pass
fi

test_start "'limit unset' detaches BPF programs"
if assert_bpf_not_attached; then
    test_pass
fi

test_start "'limit unset' exits 0"
set +e
"$STRAIT_BIN" limit set "$_NC_PID" 1000 1000 >/dev/null 2>&1
set -e
if assert_exit_code 0 "$STRAIT_BIN" limit unset "$_NC_PID"; then
    test_pass
fi

test_start "'limit unset' prints confirmation"
set +e
"$STRAIT_BIN" limit set "$_NC_PID" 1000 1000 >/dev/null 2>&1
set -e
output=$("$STRAIT_BIN" limit unset "$_NC_PID" 2>/dev/null) || true
if [[ "$output" == *"Removed rate limit"*"$_NC_PID"* ]]; then
    test_pass
else
    test_fail "expected 'Removed rate limit ... $_NC_PID' in output"
    echo "       got: $output"
fi

stop_nc_listener

# --- limit set/unset with no args ---

test_start "'limit set' with no args prints usage"
if assert_stdout_contains "Usage" "$STRAIT_BIN" limit set; then
    test_pass
fi

test_start "'limit unset' with no args prints usage"
if assert_stdout_contains "Usage" "$STRAIT_BIN" limit unset; then
    test_pass
fi

test_start "'limit' with no subcommand prints error"
if assert_stderr_contains "missing subcommand" "$STRAIT_BIN" limit; then
    test_pass
fi

test_start "'limit' with unknown subcommand prints error"
if assert_stderr_contains "unknown subcommand" "$STRAIT_BIN" limit bogus; then
    test_pass
fi

print_summary