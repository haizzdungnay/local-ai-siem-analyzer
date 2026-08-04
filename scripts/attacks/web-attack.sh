#!/usr/bin/env bash
# Bounded DVWA traffic for the isolated lab. Never point this script outside Victim .20.
set -euo pipefail

TARGET="${1:-192.168.100.20}"
SCENARIO="${2:-all}"
BURST_COUNT="${3:-6}"
CONFIRMATION="${4:-}"
BASE_URL="http://${TARGET}/DVWA"

if [[ "$TARGET" != "192.168.100.20" ]]; then
  echo "Refusing target outside the canonical Victim: $TARGET" >&2
  exit 2
fi

if ! [[ "$BURST_COUNT" =~ ^[0-9]+$ ]] || (( BURST_COUNT < 3 || BURST_COUNT > 10 )); then
  echo "BURST_COUNT must be an integer in 3..10" >&2
  exit 2
fi

http_probe() {
  local label="$1"
  shift
  printf '%-24s' "$label"
  curl --max-time 10 -sS -o /dev/null -w 'HTTP %{http_code}\n' "$@" || true
}

baseline() {
  echo "=== baseline: normal unauthenticated navigation ==="
  http_probe "DVWA root" "${BASE_URL}/"
  http_probe "login page" "${BASE_URL}/login.php"
  http_probe "setup redirect/page" "${BASE_URL}/setup.php"
}

error_burst() {
  echo "=== error-burst: bounded missing paths ==="
  local index
  for ((index = 1; index <= BURST_COUNT; index++)); do
    http_probe "missing path ${index}/${BURST_COUNT}" \
      "${BASE_URL}/bounded-missing-${index}?source=ai-siem-live-test"
    sleep 0.25
  done
}

signatures() {
  echo "=== signatures: SQLi, XSS and traversal-shaped requests ==="
  http_probe "SQLi-shaped query" --get \
    --data-urlencode "id=1' OR 1=1--" \
    --data-urlencode "Submit=Submit" \
    "${BASE_URL}/vulnerabilities/sqli/"
  http_probe "XSS-shaped query" --get \
    --data-urlencode "name=<script>alert('bounded')</script>" \
    "${BASE_URL}/vulnerabilities/xss_r/"
  http_probe "traversal-shaped path" --path-as-is \
    "${BASE_URL}/../../../../etc/passwd"
}

nikto_scan() {
  echo "=== nikto: bounded 45-second scan ==="
  if [[ "$CONFIRMATION" != "I_UNDERSTAND_NIKTO_ALERT_VOLUME" ]]; then
    echo "Nikto can create thousands of alerts; explicit confirmation is required." >&2
    echo "Re-run with: nikto 6 I_UNDERSTAND_NIKTO_ALERT_VOLUME" >&2
    return 2
  fi
  if command -v nikto >/dev/null && command -v timeout >/dev/null; then
    local status=0
    timeout --signal=TERM --kill-after=5s 50s \
      nikto -h "${BASE_URL}/" -maxtime 45s -nointeractive || status=$?
    if (( status == 124 || status == 137 )); then
      echo "NIKTO=hard-timeout after bounded wall-clock limit"
    elif (( status != 0 )); then
      echo "NIKTO=completed with exit ${status}"
    fi
  else
    echo "NIKTO_OR_TIMEOUT=missing; scenario skipped"
  fi
}

START_UTC="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "SCENARIO=${SCENARIO} TARGET=${TARGET} START_UTC=${START_UTC}"

case "$SCENARIO" in
  baseline) baseline ;;
  error-burst) error_burst ;;
  signatures) signatures ;;
  nikto) nikto_scan ;;
  all)
    baseline
    error_burst
    signatures
    echo "NIKTO=excluded from all; run the explicit nikto mode only after reviewing alert-volume risk"
    ;;
  *)
    echo "Unknown scenario: $SCENARIO" >&2
    echo "Use: baseline | error-burst | signatures | nikto | all" >&2
    exit 2
    ;;
esac

END_UTC="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "SCENARIO=${SCENARIO} END_UTC=${END_UTC}"
echo "Wait up to 120 seconds for Indexer ingest before analysis."
