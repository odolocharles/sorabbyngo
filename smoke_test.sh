#!/bin/bash
# Sorabbyngo — Live API Smoke Test
# Requires the server to be running: python -m sorabbyngo
# Usage: bash smoke_test.sh

BASE="http://localhost:8000"
PASS=0
FAIL=0

check() {
  local label="$1"
  local expected="$2"
  local actual="$3"
  if echo "$actual" | grep -q "$expected"; then
    echo "  ✅  $label"
    ((PASS++))
  else
    echo "  ❌  $label"
    echo "      Expected to find: $expected"
    echo "      Got: $actual"
    ((FAIL++))
  fi
}

echo ""
echo "========================================="
echo "  Sorabbyngo — API Smoke Test"
echo "========================================="

# ── Health ────────────────────────────────────
echo ""
echo "── Health ──"
R=$(curl -s "$BASE/health")
check "GET /health → status ok"       '"status": "ok"'    "$R"
check "GET /health → platform field"  '"platform"'        "$R"

# ── Ingest event ─────────────────────────────
echo ""
echo "── Events ──"
# Use timestamp-unique host to avoid dedup across runs
UNIQUE_HOST="prod-server-$(date +%s)"
R=$(curl -s -X POST "$BASE/api/v1/events" \
  -H "Content-Type: application/json" \
  -d "{
    \"source\": \"falco\",
    \"payload\": {
      \"severity\": \"CRITICAL\",
      \"category\": \"INTRUSION\",
      \"title\": \"SSH brute-force detected\",
      \"description\": \"Multiple failed SSH logins from external IP\",
      \"host\": \"$UNIQUE_HOST\",
      \"process\": \"sshd\",
      \"user\": \"root\"
    }
  }")
check "POST /api/v1/events → 201 with id"  '"id"'           "$R"
EVENT_ID=$(echo "$R" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null || true)
if [ -z "$EVENT_ID" ]; then
  echo "  ❌  Could not extract event_id — aborting smoke test"
  exit 1
fi
echo "      event_id=$EVENT_ID"

# Duplicate
R=$(curl -s -X POST "$BASE/api/v1/events" \
  -H "Content-Type: application/json" \
  -d "{
    \"source\": \"falco\",
    \"payload\": {
      \"severity\": \"CRITICAL\",
      \"category\": \"INTRUSION\",
      \"title\": \"SSH brute-force detected\",
      \"description\": \"Multiple failed SSH logins from external IP\",
      \"host\": \"$UNIQUE_HOST\",
      \"process\": \"sshd\",
      \"user\": \"root\"
    }
  }")
check "POST duplicate event → deduplicated"  '"duplicate"'  "$R"

# List events
R=$(curl -s "$BASE/api/v1/events")
check "GET /api/v1/events → array"  '"id"'  "$R"

# Get single event
R=$(curl -s "$BASE/api/v1/events/$EVENT_ID")
check "GET /api/v1/events/:id → correct event"  "$EVENT_ID"  "$R"

# Filter by severity
R=$(curl -s "$BASE/api/v1/events?severity=CRITICAL")
check "GET /api/v1/events?severity=CRITICAL"  '"CRITICAL"'  "$R"

# Bad severity
R=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/api/v1/events?severity=BOGUS")
check "GET /api/v1/events?severity=BOGUS → 400"  "400"  "$R"

# ── Triage ───────────────────────────────────
echo ""
echo "── Triage ──"
R=$(curl -s -X POST "$BASE/api/v1/events/$EVENT_ID/triage")
check "POST /api/v1/events/:id/triage → score"    '"score"'              "$R"
check "POST /api/v1/events/:id/triage → verdict"  '"IMMEDIATE_RESPONSE"' "$R"

# ── Investigate ──────────────────────────────
echo ""
echo "── Investigation ──"
R=$(curl -s -X POST "$BASE/api/v1/events/$EVENT_ID/investigate")
check "POST /api/v1/events/:id/investigate → report"  '"id"'               "$R"
check "POST investigate → has response_actions"        '"response_actions"' "$R"
REPORT_ID=$(echo "$R" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null || true)
if [ -z "$REPORT_ID" ]; then
  echo "  ❌  Could not extract report_id — aborting smoke test"
  exit 1
fi
echo "      report_id=$REPORT_ID"

# List reports
R=$(curl -s "$BASE/api/v1/reports")
check "GET /api/v1/reports → array"  '"id"'  "$R"

# Get single report
R=$(curl -s "$BASE/api/v1/reports/$REPORT_ID")
check "GET /api/v1/reports/:id → correct report"  "$REPORT_ID"  "$R"

# ── Execute ───────────────────────────────────
echo ""
echo "── Execution ──"
R=$(curl -s -X POST "$BASE/api/v1/reports/$REPORT_ID/execute")
check "POST /api/v1/reports/:id/execute → records"  '"action_type"'  "$R"
RECORD_ID=$(echo "$R" | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")
echo "      first record_id=$RECORD_ID"

# List records
R=$(curl -s "$BASE/api/v1/records")
check "GET /api/v1/records → array"  '"id"'  "$R"

# Filter by report
R=$(curl -s "$BASE/api/v1/records?report_id=$REPORT_ID")
check "GET /api/v1/records?report_id=... → filtered"  "$REPORT_ID"  "$R"

# Get single record
R=$(curl -s "$BASE/api/v1/records/$RECORD_ID")
check "GET /api/v1/records/:id → correct record"  "$RECORD_ID"  "$R"

# Approve pending (find a PENDING record if any)
PENDING_ID=$(curl -s "$BASE/api/v1/records" | python3 -c "
import sys,json
records = json.load(sys.stdin)
pending = [r for r in records if r['status'] == 'PENDING']
print(pending[0]['id'] if pending else '')
")
if [ -n "$PENDING_ID" ]; then
  R=$(curl -s -X POST "$BASE/api/v1/records/$PENDING_ID/approve")
  check "POST /api/v1/records/:id/approve"  '"id"'  "$R"
else
  echo "  ⏭   No PENDING records to approve (all non-destructive)"
fi

# ── Error cases ───────────────────────────────
echo ""
echo "── Error handling ──"
R=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/api/v1/events/no-such-id")
check "GET missing event → 404"  "404"  "$R"

R=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/api/v1/reports/no-such-id")
check "GET missing report → 404"  "404"  "$R"

R=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/api/v1/does-not-exist")
check "GET unknown route → 404"  "404"  "$R"

R=$(curl -s -X POST "$BASE/api/v1/events" -H "Content-Type: application/json" -d '{"source":"x"}')
check "POST event missing payload → 400"  "error"  "$R"

# ── Summary ───────────────────────────────────
echo ""
echo "========================================="
echo "  Results: $PASS passed, $FAIL failed"
echo "========================================="
echo ""
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
