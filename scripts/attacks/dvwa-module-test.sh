#!/usr/bin/env bash
# Fixed, bounded DVWA-shaped requests for the isolated Wazuh lab only.
# The dashboard sends this script to the fixed Kali runner with a fixed target.
set -euo pipefail

TARGET="${1:-192.168.100.20}"
SCENARIO="${2:-}"
BASE_URL="http://${TARGET}/DVWA"
REQUEST_FAILURES=0
REQUEST_TIMEOUT_SECONDS=2
CONNECT_TIMEOUT_SECONDS=1
BRUTE_FORCE_ATTEMPTS=300
BRUTE_FORCE_CONCURRENCY=25
BRUTE_FORCE_REQUEST_TIMEOUT_SECONDS=1
BRUTE_FORCE_BATCH_PAUSE_SECONDS=0.2
BRUTE_FORCE_LAUNCHED=0
BRUTE_FORCE_SUCCEEDED=0
SCRIPT_DEADLINE_SECONDS=18
SCRIPT_STARTED_SECONDS=$SECONDS

[[ "${TARGET}" == "192.168.100.20" ]] || {
  echo "Refusing target outside the canonical Victim" >&2
  exit 2
}

request() {
  local label="$1"
  local curl_exit=0
  shift
  if (( SECONDS - SCRIPT_STARTED_SECONDS + BRUTE_FORCE_REQUEST_TIMEOUT_SECONDS >= SCRIPT_DEADLINE_SECONDS )); then
    echo "SCRIPT_DEADLINE_EXCEEDED=${SCRIPT_DEADLINE_SECONDS}" >&2
    exit 124
  fi
  printf '%-28s' "${label}"
  curl --max-time "${REQUEST_TIMEOUT_SECONDS}" --connect-timeout "${CONNECT_TIMEOUT_SECONDS}" -sS -o /dev/null -w 'HTTP %{http_code}\n' "$@" || curl_exit=$?
  if (( curl_exit != 0 )); then
    printf 'CURL_EXIT=%s\n' "${curl_exit}" >&2
    REQUEST_FAILURES=$((REQUEST_FAILURES + 1))
  fi
}

brute_force_batch() {
  local first_attempt="$1"
  local last_attempt="$2"
  local attempt pid failures=0
  local -a pids=()

  if (( SECONDS - SCRIPT_STARTED_SECONDS >= SCRIPT_DEADLINE_SECONDS )); then
    echo "SCRIPT_DEADLINE_EXCEEDED=${SCRIPT_DEADLINE_SECONDS}" >&2
    exit 124
  fi
  printf 'DVWA login attempts %s-%s/%s\n' "${first_attempt}" "${last_attempt}" "${BRUTE_FORCE_ATTEMPTS}"
  for (( attempt = first_attempt; attempt <= last_attempt; attempt++ )); do
    (
      curl --max-time "${BRUTE_FORCE_REQUEST_TIMEOUT_SECONDS}" --connect-timeout "${CONNECT_TIMEOUT_SECONDS}" \
        -sS -o /dev/null --data 'username=lab-invalid-user&password=lab-invalid-password&Login=Login' \
        "${BASE_URL}/login.php"
    ) &
    pids+=("$!")
    BRUTE_FORCE_LAUNCHED=$((BRUTE_FORCE_LAUNCHED + 1))
  done
  for pid in "${pids[@]}"; do
    if wait "${pid}"; then
      BRUTE_FORCE_SUCCEEDED=$((BRUTE_FORCE_SUCCEEDED + 1))
    else
      failures=$((failures + 1))
    fi
  done
  if (( failures > 0 )); then
    printf 'BATCH_REQUEST_FAILURES=%s\n' "${failures}" >&2
    REQUEST_FAILURES=$((REQUEST_FAILURES + failures))
  fi
}

case "${SCENARIO}" in
  brute-force)
    for (( batch_start = 1; batch_start <= BRUTE_FORCE_ATTEMPTS; batch_start += BRUTE_FORCE_CONCURRENCY )); do
      batch_end=$((batch_start + BRUTE_FORCE_CONCURRENCY - 1))
      if (( batch_end > BRUTE_FORCE_ATTEMPTS )); then
        batch_end="${BRUTE_FORCE_ATTEMPTS}"
      fi
      brute_force_batch "${batch_start}" "${batch_end}"
      if (( batch_end < BRUTE_FORCE_ATTEMPTS )); then
        sleep "${BRUTE_FORCE_BATCH_PAUSE_SECONDS}"
      fi
    done
    if (( SECONDS - SCRIPT_STARTED_SECONDS >= SCRIPT_DEADLINE_SECONDS )); then
      echo "SCRIPT_DEADLINE_EXCEEDED=${SCRIPT_DEADLINE_SECONDS}" >&2
      exit 124
    fi
    if (( REQUEST_FAILURES != 0 || BRUTE_FORCE_LAUNCHED != BRUTE_FORCE_ATTEMPTS || BRUTE_FORCE_SUCCEEDED != BRUTE_FORCE_ATTEMPTS )); then
      printf 'BRUTE_FORCE_INCOMPLETE launched=%s succeeded=%s failed=%s\n' \
        "${BRUTE_FORCE_LAUNCHED}" "${BRUTE_FORCE_SUCCEEDED}" "${REQUEST_FAILURES}" >&2
      exit 1
    fi
    echo "BRUTE_FORCE_REQUESTS=${BRUTE_FORCE_ATTEMPTS}"
    ;;
  command-injection)
    request "Command-shaped input" --get --data-urlencode 'ip=127.0.0.1;echo+bounded-marker' "${BASE_URL}/vulnerabilities/exec/"
    ;;
  csrf)
    request "CSRF-shaped request" --data 'password_new=lab-value&password_conf=lab-value&Change=Change' "${BASE_URL}/vulnerabilities/csrf/"
    ;;
  file-inclusion)
    request "LFI-shaped path" --path-as-is "${BASE_URL}/../../../../wazuh-fim-lab-fixture"
    ;;
  file-upload)
    marker_file="$(mktemp)"
    trap 'rm -f "${marker_file}"' EXIT
    printf 'bounded upload marker\n' > "${marker_file}"
    request "Upload marker" -F "uploaded=@${marker_file};type=text/plain" -F 'Upload=Upload' "${BASE_URL}/vulnerabilities/upload/"
    ;;
  insecure-captcha)
    request "CAPTCHA validation" --get --data-urlencode 'step=lab-invalid-captcha' "${BASE_URL}/vulnerabilities/captcha/"
    ;;
  sql-injection)
    request "SQLi-shaped query" --get --data-urlencode "id=1' OR 1=1--" --data-urlencode 'Submit=Submit' "${BASE_URL}/vulnerabilities/sqli/"
    ;;
  sql-injection-blind)
    request "Blind SQLi-shaped query" --get --data-urlencode "id=1' AND '1'='2" --data-urlencode 'Submit=Submit' "${BASE_URL}/vulnerabilities/sqli_blind/"
    ;;
  weak-session-ids)
    request "Session test" --get --data-urlencode 'session=00000001' "${BASE_URL}/vulnerabilities/weak_id/"
    ;;
  xss-dom)
    request "DOM XSS-shaped query" --get --data-urlencode 'default=<img src=x onerror=bounded()>' "${BASE_URL}/vulnerabilities/xss_d/"
    ;;
  xss-reflected)
    request "Reflected XSS query" --get --data-urlencode 'name=<script>bounded()</script>' "${BASE_URL}/vulnerabilities/xss_r/"
    ;;
  xss-stored)
    request "Stored XSS marker" --data-urlencode 'txtName=lab-marker' --data-urlencode 'mtxMessage=<b>bounded-marker</b>' --data-urlencode 'btnSign=Sign Guestbook' "${BASE_URL}/vulnerabilities/xss_s/"
    ;;
  csp-bypass)
    request "CSP test query" --get --data-urlencode 'name=<script src=/lab-marker.js></script>' "${BASE_URL}/vulnerabilities/xss_r/"
    ;;
  javascript-attacks)
    request "Client logic test" --get --data-urlencode 'amount=0' --data-urlencode 'client_override=true' "${BASE_URL}/vulnerabilities/javascript/"
    ;;
  authorisation-bypass)
    request "Access-control test" --get --data-urlencode 'id=999999' "${BASE_URL}/vulnerabilities/authbypass/"
    ;;
  open-http-redirect)
    request "Redirect test" --get --data-urlencode 'next=http://192.168.100.30/lab-redirect-sink' "${BASE_URL}/vulnerabilities/open_redirect/"
    ;;
  cryptography)
    request "Crypto test" --get --data-urlencode 'algorithm=md5' "${BASE_URL}/vulnerabilities/cryptography/"
    ;;
  api)
    request "API test" -H 'Accept: application/json' -H 'X-Lab-Test: bounded' "${BASE_URL}/api/lab-object/999999"
    ;;
  *)
    echo "Unknown fixed DVWA scenario" >&2
    exit 2
    ;;
esac

echo "SCENARIO=${SCENARIO} TARGET=${TARGET} END_UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
if (( REQUEST_FAILURES > 0 )); then
  echo "REQUEST_FAILURES=${REQUEST_FAILURES}" >&2
  exit 1
fi
