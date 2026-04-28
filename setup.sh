#!/bin/bash
# Sorabbyngo — Setup, Test & Run
# Usage: bash setup.sh
#
# What this does:
#   1. Installs pip dependencies
#   2. Runs the pytest unit test suite (99 tests, no server needed)
#   3. Starts the Flask API server in the background
#   4. Runs the live smoke test against the running server
#   5. Keeps the server running — Ctrl+C to stop

set -e
cd "$(dirname "$0")"

echo ""
echo "========================================="
echo "  Sorabbyngo — Enterprise AI Security"
echo "========================================="

# ── 1. Install dependencies ──────────────────
echo ""
echo "[1/4] Installing dependencies..."
pip install flask flask-cors pydantic pytest --quiet
echo "      Done."

# ── 2. Unit tests (no server needed) ─────────
echo ""
echo "[2/4] Running unit tests..."
python -m pytest tests/ -v
echo ""

# ── 3. Start server in background ────────────
echo "[3/4] Starting API server on http://localhost:8000 ..."
python -m sorabbyngo &
SERVER_PID=$!

# Wait until the server is accepting connections
for i in $(seq 1 15); do
  if curl -s http://localhost:8000/health > /dev/null 2>&1; then
    echo "      Server is up (PID $SERVER_PID)."
    break
  fi
  sleep 0.5
done

# ── 4. Live smoke test ────────────────────────
echo ""
echo "[4/4] Running live smoke test..."
bash smoke_test.sh
SMOKE_EXIT=$?

# ── Keep server running ───────────────────────
if [ $SMOKE_EXIT -eq 0 ]; then
  echo ""
  echo "✅  All checks passed."
else
  echo ""
  echo "⚠️   Some smoke tests failed — check output above."
fi

echo ""
echo "Server is still running at http://localhost:8000"
echo "Press Ctrl+C to stop."
echo ""

# Keep script alive so server stays up
wait $SERVER_PID
