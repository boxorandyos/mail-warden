#!/usr/bin/env bash
set -euo pipefail

SMTP_HOST="${SMTP_HOST:-127.0.0.1}"
SMTP_PORT="${SMTP_PORT:-25}"
COUNT="${COUNT:-500}"
PARALLEL="${PARALLEL:-20}"
SENDER="${SENDER:-loadtest@example.net}"
RECIPIENT="${RECIPIENT:-user@company.com}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required"
  exit 1
fi

echo "Sending ${COUNT} test messages to ${SMTP_HOST}:${SMTP_PORT} (${PARALLEL} parallel workers)..."
python3 - "$SMTP_HOST" "$SMTP_PORT" "$COUNT" "$PARALLEL" "$SENDER" "$RECIPIENT" <<'PY'
import smtplib, sys, concurrent.futures, time
host, port, count, parallel, sender, rcpt = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5], sys.argv[6]
msg = f"From: {sender}\r\nTo: {rcpt}\r\nSubject: queue stress\r\n\r\nmailwarden load test\r\n"

def send_one(i: int):
    with smtplib.SMTP(host, port, timeout=15) as s:
        s.sendmail(sender, [rcpt], msg + f"id={i}\r\n")
    return i

start = time.time()
ok = 0
with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as ex:
    futures = [ex.submit(send_one, i) for i in range(count)]
    for f in concurrent.futures.as_completed(futures):
        try:
            f.result()
            ok += 1
        except Exception as e:
            print(f"send failure: {e}", file=sys.stderr)
elapsed = time.time() - start
print(f"sent_ok={ok} total={count} elapsed_sec={elapsed:.2f} rate={ok/elapsed if elapsed else 0:.2f}/s")
if ok != count:
    sys.exit(1)
PY

echo "Queue stress completed. Validate queue depth/drain with: postqueue -p"
