#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

echo "test_list.sh"
echo "------------"

NC_PID=""

cleanup() {
    if [ -n "$NC_PID" ]; then
        kill "$NC_PID" 2>/dev/null || true
        wait "$NC_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# --- list shows a process with a TCP socket ---

nc -l -p 9999 >/dev/null 2>&1 &
NC_PID=$!
sleep 0.5

test_start "'list' shows process with TCP socket"
output=$("$PIDNL_BIN" list 2>/dev/null) || true
if [[ "$output" == *"$NC_PID"* ]] || [[ "$output" == *"nc"* ]]; then
    test_pass
else
    test_fail "expected PID $NC_PID or 'nc' in output"
    echo "       got: $(echo "$output" | head -5)"
fi

test_start "'list' shows TCP column with 'Yes'"
output=$("$PIDNL_BIN" list 2>/dev/null) || true
if [[ "$output" == *"Yes"* ]]; then
    test_pass
else
    test_fail "expected 'Yes' in TCP column"
    echo "       got: $(echo "$output" | head -5)"
fi

test_start "'list' exits 0"
if assert_exit_code 0 "$PIDNL_BIN" list; then
    test_pass
fi

# --- list shows header row ---

test_start "'list' shows header row"
output=$("$PIDNL_BIN" list 2>/dev/null) || true
if [[ "$output" == *"PID"* ]] && [[ "$output" == *"NAME"* ]] && [[ "$output" == *"EXECUTABLE"* ]]; then
    test_pass
else
    test_fail "expected header row with PID, NAME, EXECUTABLE"
    echo "       got: $(echo "$output" | head -2)"
fi

# --- cleanup happens in trap ---

print_summary