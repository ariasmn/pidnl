#!/usr/bin/env bash
set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

# Counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
CURRENT_TEST=""

# The binary under test - default to local build
PIDNL_BIN="${PIDNL_BIN:-./cli/pidnl}"

# Test tracking
FAILED_TESTS=()

test_start() {
    CURRENT_TEST="$1"
    TESTS_RUN=$((TESTS_RUN + 1))
    printf "  %-50s " "$CURRENT_TEST"
}

test_pass() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo -e "${GREEN}PASS${NC}"
}

test_fail() {
    TESTS_FAILED=$((TESTS_FAILED + 1))
    FAILED_TESTS+=("$CURRENT_TEST")
    echo -e "${RED}FAIL${NC}"
    if [ -n "${1:-}" ]; then
        echo "       $1"
    fi
}

# Assert that a command exits with expected code
assert_exit_code() {
    local expected="$1"
    shift
    local actual
    set +e
    "$@" > /dev/null 2>&1
    actual=$?
    set -e
    if [ "$actual" -ne "$expected" ]; then
        test_fail "expected exit code $expected, got $actual (command: $*)"
        return 1
    fi
    return 0
}

# Assert that stdout of a command contains a string
assert_stdout_contains() {
    local expected_substring="$1"
    shift
    local output
    output=$("$@" 2>/dev/null)
    if [[ "$output" != *"$expected_substring"* ]]; then
        test_fail "stdout missing: '$expected_substring'"
        echo "       got: $(echo "$output" | head -3)"
        return 1
    fi
    return 0
}

# Assert that stderr of a command contains a string
assert_stderr_contains() {
    local expected_substring="$1"
    shift
    local output
    output=$("$@" 2>&1 >/dev/null)
    if [[ "$output" != *"$expected_substring"* ]]; then
        test_fail "stderr missing: '$expected_substring'"
        echo "       got: $(echo "$output" | head -3)"
        return 1
    fi
    return 0
}

# Assert that stdout of a command does NOT contain a string
assert_stdout_not_contains() {
    local unexpected_substring="$1"
    shift
    local output
    output=$("$@" 2>/dev/null)
    if [[ "$output" == *"$unexpected_substring"* ]]; then
        test_fail "stdout should not contain: '$unexpected_substring'"
        return 1
    fi
    return 0
}

# Print summary at the end
print_summary() {
    echo ""
    echo "========================================="
    echo "  Tests run:    $TESTS_RUN"
    echo -e "  Passed:       ${GREEN}$TESTS_PASSED${NC}"
    if [ "$TESTS_FAILED" -gt 0 ]; then
        echo -e "  Failed:       ${RED}$TESTS_FAILED${NC}"
        echo ""
        echo "  Failed tests:"
        for t in "${FAILED_TESTS[@]}"; do
            echo "    - $t"
        done
    else
        echo -e "  Failed:       ${GREEN}0${NC}"
    fi
    echo "========================================="
    echo ""

    return "$TESTS_FAILED"
}

# --- BPF and cgroup helpers ---

# Check that a cgroup directory exists for a PID under /sys/fs/cgroup/pidnl/
assert_cgroup_exists() {
    local pid="$1"
    if [ ! -d "/sys/fs/cgroup/pidnl/${pid}" ]; then
        test_fail "cgroup /sys/fs/cgroup/pidnl/${pid} does not exist"
        return 1
    fi
    return 0
}

# Check that a cgroup directory does NOT exist
assert_cgroup_not_exists() {
    local pid="$1"
    if [ -d "/sys/fs/cgroup/pidnl/${pid}" ]; then
        test_fail "cgroup /sys/fs/cgroup/pidnl/${pid} still exists"
        return 1
    fi
    return 0
}

# Check that BPF links are attached via bpftool
assert_bpf_attached() {
    local output
    output=$(bpftool link show 2>/dev/null || true)
    if echo "$output" | grep -q "egress_rl\|ingress_rl"; then
        return 0
    fi
    test_fail "no BPF links (egress_rl/ingress_rl) found"
    return 1
}

# Check that BPF links are NOT attached (after unset/clean)
assert_bpf_not_attached() {
    local output
    output=$(bpftool link show 2>/dev/null || true)
    if echo "$output" | grep -q "egress_rl\|ingress_rl"; then
        test_fail "BPF links still present after cleanup"
        return 1
    fi
    return 0
}

# Start a background process with a TCP listener
_NC_PID=""
start_nc_listener() {
    local port="${1:-9999}"
    nc -l -p "$port" >/dev/null 2>&1 &
    _NC_PID=$!
    sleep 0.5
}

stop_nc_listener() {
    if [ -n "$_NC_PID" ]; then
        kill "$_NC_PID" 2>/dev/null || true
        wait "$_NC_PID" 2>/dev/null || true
        _NC_PID=""
    fi
}
