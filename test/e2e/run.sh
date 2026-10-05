#!/usr/bin/env bash
# Merlin adversarial end-to-end test. run.sh builds and starts a merlinServer, then runs the
# negative driver, which creates an HTTP listener over the operator gRPC API, stands up two
# rogue agents with the real merlin-agent client, and launches the peer-to-peer link-graph
# cycle attack from GHSA-j4v3-8vg5-7p7g. A fixed server survives; a vulnerable one crashes.
#
# Exit 0 = the server survived the attack and stayed responsive.
#
# Layout assumption (same as test/smoke): the merlin-agent repo is a sibling of this repo.
# Override with env vars: MERLIN, ADDR, PASSWORD, LPORT, PSK.
set -uo pipefail

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MERLIN="${MERLIN:-$(cd "$E2E_DIR/../.." && pwd)}"
ADDR="${ADDR:-127.0.0.1:50071}"
PASSWORD="${PASSWORD:-e2etest}"
LPORT="${LPORT:-28080}"
PSK="${PSK:-merlin}"
WORK="$(mktemp -d)"
SRV_LOG="$WORK/server.log"
SERVER_PID=""

cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
  pkill -f "$WORK/merlinServer" 2>/dev/null
  rm -rf "$WORK" 2>/dev/null
}
trap cleanup EXIT

say() { printf '\n=== %s ===\n' "$*"; }

if pgrep -x merlinServer >/dev/null 2>&1; then
  echo "a merlinServer process is already running; kill it first (pkill -x merlinServer)"; exit 1
fi

say "Building merlinServer"
( cd "$MERLIN" && go build -o "$WORK/merlinServer" . ) || { echo "server build failed"; exit 1; }

say "Building negative driver"
( cd "$E2E_DIR" && go build -o "$WORK/e2e-driver" . ) || { echo "driver build failed"; exit 1; }

say "Starting merlinServer ($ADDR)"
# exec so SERVER_PID is the server itself (not a wrapping subshell), making teardown reliable.
( cd "$MERLIN" && exec "$WORK/merlinServer" -addr "$ADDR" -password "$PASSWORD" >"$SRV_LOG" 2>&1 ) &
SERVER_PID=$!

# Wait for the gRPC port to accept connections.
for _ in $(seq 1 60); do
  if (exec 3<>"/dev/tcp/${ADDR%%:*}/${ADDR##*:}") 2>/dev/null; then exec 3>&- 3<&-; break; fi
  sleep 0.5
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then echo "server exited early:"; cat "$SRV_LOG"; exit 1; fi
done

say "Running the link-graph cycle attack"
"$WORK/e2e-driver" -addr "$ADDR" -password "$PASSWORD" -port "$LPORT" -psk "$PSK"
RC=$?

say "Server status after attack"
if kill -0 "$SERVER_PID" 2>/dev/null; then
  echo "server process $SERVER_PID still alive"
else
  echo "server process DIED during the attack"
  RC=1
fi

# Note on what "pass" proves: the fixed server rejects the self-link at insertion, so no
# cycle forms and the walk-guard's log line is NOT expected here. The assertion is simply
# that the server survived the attack. To confirm this test actually catches the bug, run
# it against the pre-fix commit (the server crashes and this fails).

if [ "$RC" -eq 0 ]; then
  echo; echo "NEGATIVE E2E PASSED ✔"
else
  echo; echo "NEGATIVE E2E FAILED ✗"
  echo "--- server log tail ---"; tail -40 "$SRV_LOG"
fi
exit "$RC"
