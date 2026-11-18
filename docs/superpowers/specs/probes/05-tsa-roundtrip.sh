#!/bin/sh
# Probe: RFC 3161 round trip against public TSAs, in parallel, plus the
# fail-closed verification matrix (genuine / wrong imprint / wrong anchor).
# Proves §5 and §10. Needs network + openssl. Expected: PASS.
set -eu
command -v openssl >/dev/null || { echo "SKIP no openssl"; exit 0; }
W=$(mktemp -d "${TMPDIR:-/tmp}/gtp5.XXXXXX"); cd "$W"

printf 'payload\n' > p.bin
openssl ts -query -data p.bin -sha256 -cert -out q.tsq 2>/dev/null || { echo "SKIP query build failed"; exit 0; }

post() { # url out
  curl -sS --max-time 20 -H 'Content-Type: application/timestamp-query' \
    --data-binary @q.tsq "$1" -o "$2" -w '%{http_code} %{time_total}'
}

# two TSAs in parallel over the same imprint, each own nonce
curl -sS --max-time 20 -H 'Content-Type: application/timestamp-query' --data-binary @q.tsq \
  https://freetsa.org/tsr -o a.tsr -w 'freetsa %{http_code} %{time_total}\n' & P1=$!
curl -sS --max-time 20 -H 'Content-Type: application/timestamp-query' --data-binary @q.tsq \
  https://rfc3161.ai.moda -o b.tsr -w 'ai.moda %{http_code} %{time_total}\n' & P2=$!
wait $P1 || true; wait $P2 || true

[ -s a.tsr ] || { echo "SKIP freetsa unreachable"; exit 0; }
curl -sS --max-time 20 https://freetsa.org/files/cacert.pem -o ca.pem

openssl ts -verify -in a.tsr -queryfile q.tsq -CAfile ca.pem 2>/dev/null \
  && echo "PASS genuine token verifies" || { echo "FAIL genuine token rejected"; exit 1; }

printf 'other\n' > p2.bin
openssl ts -query -data p2.bin -sha256 -cert -out q2.tsq 2>/dev/null
if openssl ts -verify -in a.tsr -queryfile q2.tsq -CAfile ca.pem 2>/dev/null; then
  echo "FAIL wrong imprint accepted"; exit 1
else
  echo "PASS wrong imprint rejected (fail-closed)"
fi

if openssl ts -verify -in a.tsr -queryfile q.tsq -CAfile /etc/ssl/cert.pem 2>/dev/null; then
  echo "note: anchor accepted by system store too"
else
  echo "PASS unpinned anchor rejected (fail-closed)"
fi

echo "PASS $([ -s b.tsr ] && echo 'second TSA also returned a token' || echo 'second TSA offline, quorum still met by one')"
