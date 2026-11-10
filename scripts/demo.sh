#!/usr/bin/env bash
# End-to-end demo: provision devices, run the server, send honest results,
# try three attacks, then tamper with the audit log and catch it.
#
#   ./scripts/demo.sh            # runs everything, leaves the server up at the end
#   KEEP_RUNNING=0 ./scripts/demo.sh   # stop the server when done (used in CI)
set -euo pipefail

cd "$(dirname "$0")/.."
PORT="${PORT:-8000}"
export ERI_SERVER="http://127.0.0.1:${PORT}"
export ERI_DB="demo-data/eri.db"
export ERI_REGISTRY="demo-data/devices.json"
export ERI_KEYS="demo-data/keys"
export ERI_ELECTION="config/election.json"

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

rm -rf demo-data && mkdir -p demo-data

step "1. Provision five scanners (key pair + station assignment)"
for i in 1 2 3 4 5; do
  eri-scanner provision --device "SCN-00$i" --station "ST-00$i"
done

step "2. Start the central server"
uvicorn --factory eri.server:create_app --port "$PORT" --log-level warning > demo-data/server.log 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do
  curl -fs "$ERI_SERVER/healthz" > /dev/null 2>&1 && break
  sleep 0.2
done
echo "server running at $ERI_SERVER (pid $SERVER_PID)"

step "3. Four stations report honestly"
for i in 1 2 3 4; do
  eri-scanner submit --device "SCN-00$i" --station "ST-00$i" --seed "$i"
done

step "4. Attack: change votes after signing (expect 401)"
eri-scanner submit --device SCN-005 --station ST-005 --tamper || true

step "5. Attack: a device reports for a station it was not assigned to (expect 403)"
eri-scanner submit --device SCN-001 --station ST-005 || true

step "6. Fault: signed numbers that do not add up (expect 202, flagged for review, not counted)"
eri-scanner submit --device SCN-005 --station ST-005 --inconsistent || true

step "7. Recount is correct, but an attacker replays it (expect 201, then 409)"
eri-scanner submit --device SCN-005 --station ST-005 --seed 5 --replay || true

step "8. Public totals"
curl -s "$ERI_SERVER/api/totals" | python3 -m json.tool

step "9. Audit log is intact"
HEAD=$(curl -s "$ERI_SERVER/api/totals" | python3 -c 'import json,sys; print(json.load(sys.stdin)["audit"]["head_hash"])')
eri-audit verify --db "$ERI_DB" --expect-head "$HEAD"

step "10. An insider edits one audit entry directly in the database..."
python3 - "$ERI_DB" <<'PY'
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
conn.execute("UPDATE audit_log SET event = 'result_accepted' WHERE event = 'rejected_bad_signature'")
conn.commit()
PY
echo "...and verification catches it:"
eri-audit verify --db "$ERI_DB" --expect-head "$HEAD" || true

step "Done"
echo "Dashboard: $ERI_SERVER/    API docs: $ERI_SERVER/docs    Metrics: $ERI_SERVER/metrics"
if [ "${KEEP_RUNNING:-1}" = "1" ]; then
  echo "Server keeps running; press Ctrl+C to stop."
  wait $SERVER_PID
fi
