#!/usr/bin/env bash
#
# diag_dual_verify.sh -- no-rebuild diagnostic for the dual cert-verify failure.
#
# The measure client fails at statem_clnt.c:2218 = the CLASSICAL (ECDSA) chain
# verify (peer_chain leaf -> ca_class_<alg>). That step is provider/RTT-
# independent and deterministic, so a per-host failure means one INPUT differs
# on the failing pair: the classical leaf bytes the server sends, the client's
# trust anchor, or the verify-time clock. This script checks all three without
# pushing/rebuilding.  (dual's classical component is a per-algorithm ECDSA
# chain, curve category-paired to the PQC leaf; mldsa65 -> P-384.)
#
# Usage: ./diag_dual_verify.sh [pair]   (default: tokyo)
set -euo pipefail
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
require_instances

PAIR="${1:-tokyo}"
SHARD="${2:-0}"
SMOKE="$REMOTE_HYBRID/smoke"
CIP="$(inst_field "$PAIR" "$SHARD" client public_ip)"
SIP="$(inst_field "$PAIR" "$SHARD" server public_ip)"
[ -n "$CIP" ] && [ -n "$SIP" ] || die "could not resolve client/server IP for pair '$PAIR' shard '$SHARD'"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
log "pair=$PAIR  client=$CIP  server=$SIP"

# --- 1. fixture md5 on both hosts (ECDSA = dual classical; MLDSA = dual PQC) --
FILES="ca_class_mldsa65.pem server_class_mldsa65_cert.pem server_class_mldsa65_key.pem ca_mldsa65.pem server_mldsa65_cert.pem"
echo "===== [1] fixture md5 (client vs server) ====="
printf '%-26s %-34s %-34s %s\n' FILE CLIENT SERVER MATCH
for f in $FILES; do
    cm="$(ssh_to "$CIP" "md5sum $SMOKE/$f 2>/dev/null | cut -d' ' -f1" || true)"
    sm="$(ssh_to "$SIP" "md5sum $SMOKE/$f 2>/dev/null | cut -d' ' -f1" || true)"
    [ -z "$cm" ] && cm="(missing)"; [ -z "$sm" ] && sm="(missing)"
    if [ "$cm" = "$sm" ]; then m=OK; else m="*** MISMATCH ***"; fi
    printf '%-26s %-34s %-34s %s\n' "$f" "$cm" "$sm" "$m"
done

# --- 2. cross-verify: does the SERVER's classical leaf chain to CLIENT's CA? -
# This is exactly what statem_clnt.c:2218 does. Pull both, verify with the
# default provider only (ECDSA needs no oqsprovider).
echo
echo "===== [2] cross cert-chain verify (server leaf vs client CA) ====="
scp_from "$CIP" "$SMOKE/ca_class_mldsa65.pem"          "$TMP/client_ca_class.pem"
scp_from "$SIP" "$SMOKE/server_class_mldsa65_cert.pem" "$TMP/server_class_cert.pem"
OSSL="${OPENSSL:-openssl}"
echo "-- server leaf identity (as served) --"
$OSSL x509 -in "$TMP/server_class_cert.pem" -noout -subject -issuer -dates \
    -fingerprint -sha256 || true
echo "-- openssl verify -CAfile <client ca_class> <server leaf> --"
if $OSSL verify -CAfile "$TMP/client_ca_class.pem" "$TMP/server_class_cert.pem"; then
    echo "VERDICT[2]: server classical leaf DOES chain to client ca_class -> H1 (leaf skew) refuted"
else
    echo "VERDICT[2]: server classical leaf does NOT verify against client ca_class -> H1 CONFIRMED (fixture/CA skew)"
fi

# --- 3. clock skew (verify uses the client's wall clock) ---------------------
echo
echo "===== [3] clock (verify-time) ====="
echo "client: $(ssh_to "$CIP" "date -u +%Y-%m-%dT%H:%M:%SZ")"
echo "server: $(ssh_to "$SIP" "date -u +%Y-%m-%dT%H:%M:%SZ")"
echo "local : $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- 4. the actual failing handshake, stderr captured (real error text) ------
echo
echo "===== [4] bare measure client -> server (1 run, stderr) ====="
ssh_to "$CIP" "cd $REMOTE_REPO && \
  LD_LIBRARY_PATH=$REMOTE_REPO:/usr/local/lib OPENSSL_MODULES=$REMOTE_MODULES \
  ./test/hybrid_measure --role client --host $SIP --port ${PORT:-4433} \
  --format dual --alg mldsa65 --certs $REMOTE_HYBRID/smoke --runs 1 2>&1 || true" \
  | sed 's/^/  client: /'
echo
echo "NOTE: a server must be listening on $SIP:${PORT:-4433} for [4]; start it with"
echo "  ssh server 'cd $REMOTE_HYBRID && ... ./measure_orchestrate.sh server' (or run.sh)."
echo "Sections [1]-[3] are independent of [4] and decisive on their own."
