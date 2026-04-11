#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export STRAIT_BIN="${STRAIT_BIN:-./cli/strait}"

TOTAL_RUN=0
TOTAL_PASSED=0
TOTAL_FAILED=0
FAILED_SUITES=()

echo "========================================="
echo "  strait functional tests"
echo "  binary: $STRAIT_BIN"
echo "========================================="
echo ""

if [ ! -x "$STRAIT_BIN" ]; then
    echo "ERROR: binary not found or not executable: $STRAIT_BIN"
    echo "Run 'make dev' first."
    exit 1
fi

# Run each test suite, capture its output and exit code
for test_file in "$SCRIPT_DIR"/test_*.sh; do
    [ -f "$test_file" ] || continue

    suite_name="$(basename "$test_file" .sh)"

    # Capture output; don't let set -e kill us on test failures
    set +e
    output=$("$test_file" 2>&1)
    suite_exit=$?
    set -e

    echo "$output"

    # Parse the summary line from the suite to get counts
    # Strip ANSI color codes before parsing
    clean_output=$(echo "$output" | sed 's/\x1b\[[0-9;]*m//g')
    suite_run=$(echo "$clean_output" | grep "Tests run:" | awk '{print $3}')
    suite_passed=$(echo "$clean_output" | grep "Passed:" | awk '{print $2}')
    suite_failed=$(echo "$clean_output" | grep "Failed:" | awk '{print $2}')

    TOTAL_RUN=$((TOTAL_RUN + ${suite_run:-0}))
    TOTAL_PASSED=$((TOTAL_PASSED + ${suite_passed:-0}))
    TOTAL_FAILED=$((TOTAL_FAILED + ${suite_failed:-0}))

    if [ "$suite_exit" -ne 0 ]; then
        FAILED_SUITES+=("$suite_name")
    fi
done

echo "========================================="
echo "  TOTAL"
echo "========================================="
echo "  Tests run:    $TOTAL_RUN"
if [ "$TOTAL_FAILED" -gt 0 ]; then
    echo -e "  \033[0;31mFailed:       $TOTAL_FAILED\033[0m"
    echo ""
    echo "  Failed suites:"
    for s in "${FAILED_SUITES[@]}"; do
        echo "    - $s"
    done
    echo ""
    exit 1
else
    echo -e "  \033[0;32mAll tests passed\033[0m"
    echo ""
    exit 0
fi
