#!/usr/bin/env bash
# Smoke test for the connector's read-only HTTP API. Starts a real daemon on a
# temp data dir whose store was filled by tests/http_fixture.c. Chains/peers are
# deliberately unreachable, so this also checks the disconnected-state output.
set -euo pipefail
cd "$(dirname "$0")/.."
T=$(mktemp -d); trap 'kill $PID 2>/dev/null || true; rm -rf "$T"' EXIT
PORT=${PORT:-18088}; BASE=http://127.0.0.1:$PORT
OPENSSL_CFLAGS=$(pkg-config --cflags openssl 2>/dev/null || true)
cc -std=c17 -Wall -Wextra -Werror -I../src -Isrc $OPENSSL_CFLAGS -o "$T/fixture" tests/http_fixture.c \
   src/cn_store.c src/cn_activity.c src/cn_transfer.c src/cn_config.c src/cn_rate.c ../src/config.c ../src/log.c ../src/crypto.c ../src/tx.c -lssl -lcrypto
XFR=$("$T/fixture" "$T/data" "$T/conn.key")
sed -e "s#^key_path .*#key_path = $T/conn.key#" -e "s#^data_dir .*#data_dir = $T/data#" \
    -e "s#^listen_port .*#listen_port = 18000#" config/connector0.conf > "$T/c.conf"
${CONNECTOR_BIN:-./bin/connector} --config "$T/c.conf" --http-port "$PORT" --http-origin null >"$T/log" 2>&1 & PID=$!
for i in $(seq 1 50); do curl -s -o /dev/null "$BASE/api/status" && break; sleep 0.1; done
fail=0; ok(){ echo "PASS $1"; }; bad(){ echo "FAIL $1"; fail=1; }
j(){ python3 -c "import sys,json;d=json.load(sys.stdin);print($1)"; }
chk(){ [ "$2" = "$3" ] && ok "$1" || { bad "$1 (got '$2', want '$3')"; }; }

chk "status service"        "$(curl -s $BASE/api/status | j 'd["service"]')" sovereignchain-connector
chk "status chains offline" "$(curl -s $BASE/api/status | j '[c["connected"] for c in d["chains"]]')" "[False, False]"
chk "status activity count" "$(curl -s $BASE/api/status | j 'd["store"]["activity_count"]')" 5
chk "status transfer total" "$(curl -s $BASE/api/status | j 'd["store"]["transfers"]["total"]')" 1
chk "topology links not live" "$(curl -s $BASE/api/topology | j 'any(l["live"] for l in d["links"])')" False
chk "activity all"          "$(curl -s $BASE/api/activity | j 'len(d["records"])')" 5
chk "activity chain=a"      "$(curl -s "$BASE/api/activity?chain=a" | j 'len(d["records"])')" 3
chk "activity chain=B"      "$(curl -s "$BASE/api/activity?chain=B" | j 'len(d["records"])')" 2
chk "activity status final" "$(curl -s "$BASE/api/activity?status=finalized" | j 'len(d["records"])')" 1
chk "activity paging 1"     "$(curl -s "$BASE/api/activity?limit=2" | j '(len(d["records"]),d["has_more"],d["next_since"])')" "(2, True, '2')"
chk "activity paging 2"     "$(curl -s "$BASE/api/activity?limit=2&since=2" | j '[r["seq"] for r in d["records"]]')" "['3', '4']"
chk "activity sig valid"    "$(curl -s $BASE/api/activity | j 'all(r["reporter_signature_valid"] for r in d["records"])')" True
chk "activity amount string" "$(curl -s $BASE/api/activity | j 'type(d["records"][0]["amount"]).__name__')" str
chk "activity vertex null"  "$(curl -s $BASE/api/activity | j 'd["records"][0]["source_vertex_hash"]')" None
RID=$(curl -s $BASE/api/activity | j 'd["records"][2]["record_id"]')
chk "activity by id"        "$(curl -s $BASE/api/activity/$RID | j '(d["seq"],d["source_chain"])')" "('3', 'A')"
chk "activity bad id 400"   "$(curl -s -o /dev/null -w %{http_code} $BASE/api/activity/zz)" 400
chk "activity unknown 404"  "$(curl -s -o /dev/null -w %{http_code} $BASE/api/activity/$(printf '0%.0s' $(seq 64)))" 404
chk "bad limit 400"         "$(curl -s -o /dev/null -w %{http_code} "$BASE/api/activity?limit=9999")" 400
chk "bad param 400"         "$(curl -s -o /dev/null -w %{http_code} "$BASE/api/activity?x=1")" 400
chk "transfers list"        "$(curl -s $BASE/api/transfers | j '(len(d["transfers"]),d["total_matching"])')" "(1, '1')"
chk "transfer by id"        "$(curl -s $BASE/api/transfers/$XFR | j '(d["state"],d["dest_amount"],d["rate"]["num"],d["dest_tx_hash"])')" "('SOURCE_VERIFIED', '1500', '3', None)"
chk "transfer detail esc"   "$(curl -s $BASE/api/transfers/$XFR | j 'd["error_detail"]')" 'fixture "quoted" detail'
chk "transfers state filter" "$(curl -s "$BASE/api/transfers?state=COMPLETED" | j 'len(d["transfers"])')" 0
chk "rates"                 "$(curl -s $BASE/api/rates | j '[(r["direction"],r["num"],r["den"]) for r in d["rates"]]')" "[('A_to_B', '1', '1'), ('B_to_A', '1', '1')]"
chk "POST rejected 405"     "$(curl -s -o /dev/null -w %{http_code} -X POST $BASE/api/rates)" 405
chk "unknown path 404"      "$(curl -s -o /dev/null -w %{http_code} $BASE/nope)" 404
chk "bad Host 403"          "$(curl -s -o /dev/null -w %{http_code} -H 'Host: evil.example' $BASE/api/status)" 403
chk "CORS allowed origin"   "$(curl -si -H 'Origin: null' $BASE/api/status | tr -d '\r' | grep -ci '^access-control-allow-origin: null')" 1
chk "CORS other origin none" "$(curl -si -H 'Origin: http://evil.example' $BASE/api/status | grep -ci '^access-control-allow-origin')" 0
chk "preflight 204"         "$(curl -s -o /dev/null -w %{http_code} -X OPTIONS -H 'Origin: null' -H 'Access-Control-Request-Method: GET' $BASE/api/status)" 204
chk "preflight denied 403"  "$(curl -s -o /dev/null -w %{http_code} -X OPTIONS -H 'Origin: http://evil.example' $BASE/api/status)" 403
chk "oversized header 431"  "$(curl -s -o /dev/null -w %{http_code} -H "X-Pad: $(head -c 9000 /dev/zero | tr '\0' a)" $BASE/api/status)" 431
chk "daemon survived"       "$(kill -0 $PID && echo yes)" yes
[ $fail = 0 ] && echo "ALL HTTP SMOKE TESTS PASSED" || { echo "SOME TESTS FAILED"; exit 1; }
