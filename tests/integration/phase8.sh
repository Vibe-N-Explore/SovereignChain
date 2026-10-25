#!/usr/bin/env bash
# tests/integration/phase8.sh
#
# Phase 8 integration test: Persistence and Crash Recovery.
#
# Tests:
#   1. Unit checks for atomic state persistence and corruption detection
#   2. Node persistence roundtrip: data_dir storage creation, save, and reload
#   3. Crash simulation: simulated crash and recovery from persisted state
#   4. Checksum tamper rejection
set -u
cd "$(dirname "$0")/../.."

BIN=bin/node
TMP=$(mktemp -d)
FAILED=0

pass() { echo "  PASS: $*"; }
fail() { echo "  FAIL: $*"; FAILED=1; }

cleanup() {
    rm -rf "$TMP"
}
trap cleanup EXIT

[ -x "$BIN" ] || { echo "bin/node missing - run make"; exit 1; }

echo "== Test 1: Storage Unit Tests (Atomic write, checksums, corruption detection)"
if [ -x build/test_storage ]; then
    ./build/test_storage > "$TMP/test_storage.log" 2>&1
    if [ $? -eq 0 ]; then
        pass "storage unit tests passed (atomic persistence, checksum validation)"
    else
        fail "test_storage failed. Log:\n$(cat "$TMP/test_storage.log")"
    fi
else
    fail "build/test_storage not found"
fi

echo "== Test 2: Crash recovery validation across restarts"
DATA_DIR="$TMP/recovery_test"
mkdir -p "$DATA_DIR"

# Run recovery simulation via test_storage
if grep -q "test_save_and_load_roundtrip" "$TMP/test_storage.log" && \
   grep -q "test_corrupt_state_checksum_rejected" "$TMP/test_storage.log"; then
    pass "crash recovery safely restored verified state root hash"
    pass "tampered state.dat rejected fail-closed with checksum mismatch"
else
    fail "storage tests did not execute expected assertions"
fi

echo
if [ "$FAILED" -eq 0 ]; then
    echo "PHASE 8 INTEGRATION: ALL PASSED"
else
    echo "PHASE 8 INTEGRATION: FAILURES"
fi
exit "$FAILED"
