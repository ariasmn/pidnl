#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

echo "test_help.sh"
echo "------------"

test_start "'--help' prints usage"
if assert_stdout_contains "Usage: pidnl" "$PIDNL_BIN" --help; then
    test_pass
fi

test_start "'--help' mentions all commands"
if assert_stdout_contains "list" "$PIDNL_BIN" --help && \
   assert_stdout_contains "limit" "$PIDNL_BIN" --help && \
   assert_stdout_contains "clean" "$PIDNL_BIN" --help; then
    test_pass
fi

test_start "'--help' mentions -h option"
output=$("$PIDNL_BIN" --help 2>/dev/null)
if [[ "$output" == *"-h, --help"* ]]; then
    test_pass
else
    test_fail "stdout missing: '-h, --help'"
    echo "       got: $(echo "$output" | head -3)"
fi

test_start "'--help' does not list 'help' as a command"
output=$("$PIDNL_BIN" --help 2>/dev/null)
if [[ "$output" != *"  help                "* ]]; then
    test_pass
else
    test_fail "stdout should not contain 'help' command line"
fi

test_start "'--help' exits 0"
if assert_exit_code 0 "$PIDNL_BIN" --help; then
    test_pass
fi

# --- pidnl -h ---

test_start "'-h' prints usage"
if assert_stdout_contains "Usage: pidnl" "$PIDNL_BIN" -h; then
    test_pass
fi

test_start "'-h' exits 0"
if assert_exit_code 0 "$PIDNL_BIN" -h; then
    test_pass
fi

# --- pidnl limit --help ---

test_start "'limit --help' prints limit usage"
if assert_stdout_contains "limit set" "$PIDNL_BIN" limit --help; then
    test_pass
fi

test_start "'limit --help' exits 0"
if assert_exit_code 0 "$PIDNL_BIN" limit --help; then
    test_pass
fi

# --- pidnl clean --help ---

test_start "'clean --help' prints clean usage"
if assert_stdout_contains "clean" "$PIDNL_BIN" clean --help; then
    test_pass
fi

test_start "'clean --help' exits 0"
if assert_exit_code 0 "$PIDNL_BIN" clean --help; then
    test_pass
fi

# --- no arguments ---

test_start "no args prints error to stderr"
if assert_stderr_contains "missing command" "$PIDNL_BIN"; then
    test_pass
fi

test_start "no args exits non-zero"
if assert_exit_code 1 "$PIDNL_BIN"; then
    test_pass
fi

# --- unknown command ---

test_start "unknown command prints error"
if assert_stderr_contains "unknown command" "$PIDNL_BIN" boguscommand; then
    test_pass
fi

test_start "unknown command exits non-zero"
if assert_exit_code 1 "$PIDNL_BIN" boguscommand; then
    test_pass
fi

# --- 'help' is not a valid command ---

test_start "'help' is rejected as unknown command"
if assert_stderr_contains "unknown command" "$PIDNL_BIN" help; then
    test_pass
fi

test_start "'help' exits non-zero"
if assert_exit_code 1 "$PIDNL_BIN" help; then
    test_pass
fi

print_summary
