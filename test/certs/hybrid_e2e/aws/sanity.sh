#!/usr/bin/env bash
#
# sanity.sh -- pre-full-measurement gate (run BEFORE run.sh).
#
# For every region pair it runs ONE tiny real client<->server pass
# (dual x mldsa65, 5 handshakes, unshaped) over the public path and checks:
#   * verify_ok == 1 for every row             (PoP actually verified)
#   * pq_verify_ms  > 0 and within a sane bound (crypto instrumentation live)
#
# pq_verify_ms == 0 is the ABI-skew signature: the measurement binary was NOT a
# clean HYBRID_MEASURE build.  The gate then names the offending pair so you can
# re-run `./setup.sh <pair>` (which rebuilds clean) before retrying.
#
# All three pairs must pass before run.sh should proceed.
#
# Usage: ./sanity.sh
set -euo pipefail
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
preflight_local
require_instances

SFMT="dual"; SALG="mldsa65"; SRUNS="${SRUNS:-5}"
LOGDIR="$AWS_DIR/sanity_logs"; mkdir -p "$LOGDIR"

# common env passed to the orchestrator on both sides for a 1-combo, unshaped run
ORCH_ENV="RUNS=$SRUNS PORT=$PORT FORMATS=$SFMT ALGS=$SALG LOSSES=0 BWS=0 RESUME=0"

# Every (pair x shard) is a separately-built instance pair, so each must clear
# the ABI/PoP gate independently.  dual x mldsa65 is self-contained (ORCH_ENV
# overrides the shard subset), so it runs on any shard's instances.
GATE=0
for pair in $PAIRS; do
  for shard in $(shard_ids); do
    sreg=$(server_region_for_pair "$pair")
    sip=$(inst_field "$pair" "$shard" server public_ip)
    cip=$(inst_field "$pair" "$shard" client public_ip)
    label="sanity-$pair-s$shard"
    csv_remote="$REMOTE_HYBRID/${label}.csv"
    log "=== sanity $pair/s$shard : client($cip) -> server($sip in $sreg) ==="
    ssh_to "$cip" "rm -f $csv_remote"

    # server: serve the single combo, then exits on its own (count is bounded)
    ssh_to "$sip" "cd $REMOTE_HYBRID && $ORCH_ENV ./measure_orchestrate.sh server" \
        >"$LOGDIR/server_${pair}_s${shard}.log" 2>&1 &
    spid=$!
    sleep 4   # let the listener come up; the binary also retries connect ~5s

    # client: connect to the server PUBLIC ip, write a dedicated sanity CSV
    if ssh_to "$cip" "cd $REMOTE_HYBRID && sudo -E $ORCH_ENV CSV=$csv_remote \
            ./measure_orchestrate.sh client $sip $label" \
            >"$LOGDIR/client_${pair}_s${shard}.log" 2>&1; then
        :
    else
        log "FAIL $pair/s$shard: client orchestrator exited non-zero (see sanity_logs/client_${pair}_s${shard}.log)"
        GATE=1
        # Client died before consuming the server's bounded handshake count, so
        # the server would block on accept(). Stop it (mirrors run.sh) so the
        # wait below returns instead of hanging the whole gate.
        kill "$spid" 2>/dev/null || true
        ssh_to "$sip" "pkill -f measure_orchestrate.sh; pkill -f hybrid_measure" \
            >/dev/null 2>&1 || true
    fi
    wait "$spid" 2>/dev/null || true

    # pull + validate
    scp_from "$cip" "$csv_remote" "$LOGDIR/${label}.csv" 2>/dev/null \
        || { log "FAIL $pair/s$shard: no CSV produced"; GATE=1; continue; }

    # columns: 10=pq_verify_ms 14=verify_ok ; skip header
    verdict=$(awk -F, 'NR>1{
        n++;
        if ($14+0 != 1) bad++;
        if ($10+0 == 0) zero++;
        if ($10+0 > 0 && $10+0 <= 0.2) ok++;
    } END {
        printf "%d %d %d %d", n, (bad?bad:0), (zero?zero:0), (ok?ok:0)
    }' "$LOGDIR/${label}.csv")
    read -r n bad zero ok <<<"$verdict"

    if [ "${n:-0}" -eq 0 ]; then
        log "FAIL $pair/s$shard: CSV has no data rows"; GATE=1
    elif [ "${zero:-0}" -gt 0 ]; then
        log "FAIL $pair/s$shard: pq_verify_ms==0 on $zero/$n rows => ABI SKEW (not a clean build)."
        log "      fix: ./setup.sh $pair   (forces make clean + HYBRID_MEASURE rebuild)"
        GATE=1
    elif [ "${bad:-0}" -gt 0 ]; then
        log "FAIL $pair/s$shard: verify_ok!=1 on $bad/$n rows (PoP not verified)"; GATE=1
    else
        log "PASS $pair/s$shard: $n rows, verify_ok=1 all, pq_verify_ms live ($ok in (0,0.2]ms)"
    fi
  done
done

if [ "$GATE" = 0 ]; then
    log "ALL PAIRS PASSED sanity gate. Safe to run ./run.sh"
    exit 0
fi
die "sanity gate FAILED -- do NOT run full measurement until every pair passes"
