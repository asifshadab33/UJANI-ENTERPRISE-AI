#!/usr/bin/env bash
set -euo pipefail

PSQL_BIN="${PSQL_BIN:-psql}"
PGUSER="${PGUSER:-postgres}"
PGDATABASE="${PGDATABASE:-ujani_test}"
first_output="$(mktemp)"
second_output="$(mktemp)"
first_pid=""
second_pid=""

cleanup() {
  if [[ -n "$first_pid" ]]; then
    wait "$first_pid" 2>/dev/null || true
  fi
  if [[ -n "$second_pid" ]]; then
    wait "$second_pid" 2>/dev/null || true
  fi
  rm -f "$first_output" "$second_output"
}
trap cleanup EXIT

# Hold the nonce advisory lock inside an open transaction after a valid
# consumption. The second request uses a different approval ID but the same
# nonce and expires while it waits for the first transaction to commit.
"$PSQL_BIN" --username "$PGUSER" --dbname "$PGDATABASE" \
  --no-psqlrc --quiet --tuples-only --no-align --set ON_ERROR_STOP=1 \
  >"$first_output" 2>&1 <<'SQL' &
SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id = 'tenant-a';
SELECT ujani_control.consume_self_evolution_approval(
 'tenant-a','approval-concurrency-a','admin-a','admin-key-a',decode(repeat('aa',16),'hex'),
 'asifshadab33/UJANI-ENTERPRISE-AI','main',repeat('a',40),
 decode(repeat('22',32),'hex'),decode(repeat('33',32),'hex'),
 decode(repeat('44',32),'hex'),1,clock_timestamp() + interval '5 minutes'
);
\echo FIRST_LOCK_HELD
SELECT pg_sleep(2);
COMMIT;
RESET ROLE;
SQL
first_pid=$!

ready=0
for _ in {1..50}; do
  if grep -q '^FIRST_LOCK_HELD$' "$first_output"; then
    ready=1
    break
  fi
  if ! kill -0 "$first_pid" 2>/dev/null; then
    cat "$first_output" >&2
    echo "first approval transaction exited before acquiring its replay lock" >&2
    exit 1
  fi
  sleep 0.1
done
if [[ "$ready" != "1" ]]; then
  cat "$first_output" >&2
  echo "timed out waiting for the first approval transaction to hold its replay lock" >&2
  exit 1
fi

"$PSQL_BIN" --username "$PGUSER" --dbname "$PGDATABASE" \
  --no-psqlrc --quiet --tuples-only --no-align --set ON_ERROR_STOP=1 \
  >"$second_output" 2>&1 <<'SQL' &
SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id = 'tenant-a';
SELECT ujani_control.consume_self_evolution_approval(
 'tenant-a','approval-concurrency-b','admin-a','admin-key-a',decode(repeat('aa',16),'hex'),
 'asifshadab33/UJANI-ENTERPRISE-AI','main',repeat('a',40),
 decode(repeat('22',32),'hex'),decode(repeat('33',32),'hex'),
 decode(repeat('44',32),'hex'),1,clock_timestamp() + interval '1 second'
);
COMMIT;
RESET ROLE;
SQL
second_pid=$!

# Prove that the second backend is actually blocked on the advisory nonce lock
# before the first transaction releases it; otherwise this is only an expiry test.
waiting=0
for _ in {1..30}; do
  waiter_count="$("$PSQL_BIN" --username "$PGUSER" --dbname "$PGDATABASE" \
    --no-psqlrc --quiet --tuples-only --no-align --set ON_ERROR_STOP=1 \
    --command "SELECT count(*) FROM pg_stat_activity WHERE state = 'active' AND wait_event_type = 'Lock' AND wait_event = 'advisory' AND query LIKE '%consume_self_evolution_approval%';" | tr -d '[:space:]')"
  if [[ "$waiter_count" =~ ^[1-9][0-9]*$ ]]; then
    waiting=1
    break
  fi
  if ! kill -0 "$second_pid" 2>/dev/null; then
    cat "$second_output" >&2
    echo "second approval request exited instead of waiting on the nonce lock" >&2
    exit 1
  fi
  sleep 0.1
done
if [[ "$waiting" != "1" ]]; then
  cat "$second_output" >&2
  echo "second approval request was not observed waiting on the advisory nonce lock" >&2
  exit 1
fi

wait "$first_pid"
first_pid=""
wait "$second_pid"
second_pid=""

first_result="$(grep -E '^(t|f)$' "$first_output" | head -n 1 || true)"
second_result="$(grep -E '^(t|f)$' "$second_output" | head -n 1 || true)"

if [[ "$first_result" != "t" ]]; then
  cat "$first_output" >&2
  echo "first approval consumption did not succeed" >&2
  exit 1
fi
if [[ "$second_result" != "f" ]]; then
  cat "$second_output" >&2
  echo "approval that expired while waiting on the nonce lock was consumed" >&2
  exit 1
fi

echo "Concurrent Self-Evolution approval consumption serialized and rechecked expiry after lock."
