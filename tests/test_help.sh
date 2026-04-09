#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

echo "test_help.sh"
echo "------------"

# --- strait help ---

test_start "'help' prints usage"
if assert_stdout_contains "Usage: strait" "$STRAIT_BIN" help; then
    test_pass
fi

test_start "'help' prints all commands"
if assert_stdout_contains "list" "$STRAIT_BIN" help && \
   assert_stdout_contains "limit" "$STRAIT_BIN" help && \
   assert_stdout_contains "clean" "$STRAIT_BIN" help && \
   assert_stdout_contains "help" "$STRAIT_BIN" help; then
    test_pass
fi

test_start "'help' exits 0"
if assert_exit_code 0 "$STRAIT_BIN" help; then
    test_pass
fi

# --- strait --help ---

test_start "'--help' prints usage"
if assert_stdout_contains "Usage: strait" "$STRAIT_BIN" --help; then
    test_pass
fi

test_start "'--help' exits 0"
if assert_exit_code 0 "$STRAIT_BIN" --help; then
    test_pass
fi

# --- strait -h ---

test_start "'-h' prints usage"
if assert_stdout_contains "Usage: strait" "$STRAIT_BIN" -h; then
    test_pass
fi

test_start "'-h' exits 0"
if assert_exit_code 0 "$STRAIT_BIN" -h; then
    test_pass
fi

# --- no arguments ---

test_start "no args prints error to stderr"
if assert_stderr_contains "missing command" "$STRAIT_BIN"; then
    test_pass
fi

test_start "no args exits non-zero"
if assert_exit_code 1 "$STRAIT_BIN"; then
    test_pass
fi

# --- unknown command ---

test_start "unknown command prints error"
if assert_stderr_contains "unknown command" "$STRAIT_BIN" boguscommand; then
    test_pass
fi

test_start "unknown command exits non-zero"
if assert_exit_code 1 "$STRAIT_BIN" boguscommand; then
    test_pass
fi

# --- help output content ---

test_start "'help' mentions --help option"
if assert_stdout_contains "--help" "$STRAIT_BIN" help; then
    test_pass
fi

test_start "'help' mentions -h option"
if assert_stdout_contains "-h" "$STRAIT_BIN" help; then
    test_pass
fi

print_summary
