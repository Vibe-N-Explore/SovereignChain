#!/usr/bin/env bash
# Launch all six SovereignChain nodes on localhost (development harness).
# Logs go to logs/node_<id>.log. Press Ctrl-C to stop every node.
set -euo pipefail
cd "$(dirname "$0")/.."

BIN=bin/node
NET=config/network.conf
[ -x "$BIN" ] || { echo "bin/node not found - run 'make' first" >&2; exit 1; }

mkdir -p logs
pids=()

stop_all() {
    for p in "${pids[@]}"; do kill -TERM "$p" 2>/dev/null || true; done
    wait 2>/dev/null || true
}
trap stop_all INT TERM

for i in 0 1 2 3 4 5; do
    "$BIN" --network "$NET" --config "config/node_$i.conf" \
        >"logs/node_$i.log" 2>&1 &
    pids+=("$!")
done

# If any node died immediately (bad config, port in use), say so and stop.
sleep 1
for idx in "${!pids[@]}"; do
    if ! kill -0 "${pids[$idx]}" 2>/dev/null; then
        echo "node $idx exited early - see logs/node_$idx.log:" >&2
        tail -n 3 "logs/node_$idx.log" >&2 || true
        stop_all
        exit 1
    fi
done

echo "6 nodes running (pids: ${pids[*]}). Logs: logs/node_<id>.log. Ctrl-C to stop."
wait || true
