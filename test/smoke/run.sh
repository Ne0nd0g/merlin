#!/usr/bin/env bash
# Merlin end-to-end smoke test.
# Builds the server + agent from the local workspace, starts the server headless, then runs the
# gRPC driver which exercises each transport (create listener -> run agent -> issue commands).
# Exit 0 = every case passed.
#
# Layout assumption: the merlin-agent repo is a sibling of this repo (../merlin-agent).
# Override with env vars: MERLIN, AGENT, ADDR, PASSWORD, TIMEOUT.
set -uo pipefail

SMOKE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MERLIN="${MERLIN:-$(cd "$SMOKE_DIR/../.." && pwd)}"
AGENT="${AGENT:-$(cd "$MERLIN/.." && pwd)/merlin-agent}"
ADDR="${ADDR:-127.0.0.1:50051}"
PASSWORD="${PASSWORD:-smoketest}"
WORK="$(mktemp -d)"
SRV_LOG="$WORK/server.log"
SERVER_PID=""

cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
  pkill -f "$WORK/merlinServer" 2>/dev/null
  pkill -f 'merlin-agent-smoke' 2>/dev/null
  rm -rf "$WORK" 2>/dev/null
}
trap cleanup EXIT

say() { printf '\n=== %s ===\n' "$*"; }

# Refuse to run if a stale server is already holding the gRPC port (exact name, not -f which
# would match shell wrappers that merely mention the binary).
if pgrep -x merlinServer >/dev/null 2>&1; then
  echo "a merlinServer process is already running; kill it first (pkill -x merlinServer)"; exit 1
fi

[ -d "$AGENT" ] || { echo "agent repo not found at $AGENT (set AGENT=...)"; exit 1; }

say "Building server ($MERLIN)"
( cd "$MERLIN" && go build -o "$WORK/merlinServer" . ) || { echo "server build failed"; exit 1; }

say "Building agent ($AGENT)"
( cd "$AGENT" && go build -o "$WORK/merlin-agent-smoke" . ) || { echo "agent build failed"; exit 1; }

say "Starting server (addr=$ADDR, log=$SRV_LOG)"
# exec so SERVER_PID is the server itself (not a wrapping subshell), making teardown reliable.
( cd "$MERLIN" && exec "$WORK/merlinServer" -addr "$ADDR" -password "$PASSWORD" >"$SRV_LOG" 2>&1 ) &
SERVER_PID=$!

# Wait for the gRPC port to accept connections.
for _ in $(seq 1 30); do
  if (exec 3<>"/dev/tcp/${ADDR%%:*}/${ADDR##*:}") 2>/dev/null; then exec 3>&- 3<&-; break; fi
  sleep 0.5
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then echo "server exited early:"; cat "$SRV_LOG"; exit 1; fi
done

say "Running driver"
( cd "$MERLIN" && go run ./test/smoke/driver \
    -addr "$ADDR" -password "$PASSWORD" \
    -agent "$WORK/merlin-agent-smoke" \
    -workdir "$WORK" -timeout "${TIMEOUT:-60s}" )
RC=$?

if [ $RC -ne 0 ]; then
  say "Server log (tail)"; tail -n 25 "$SRV_LOG"
  for al in "$WORK"/agent-*.log; do
    [ -f "$al" ] || continue
    say "Agent log: $(basename "$al") (tail)"; tail -n 20 "$al"
  done
fi
exit $RC
