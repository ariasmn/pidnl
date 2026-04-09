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
STRAIT_BIN="${STRAIT_BIN:-./cli/strait}"

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
