#!/usr/bin/env bash
#
# run.sh -- full measurement, all 3 region pairs fully in parallel.
#
# Each pair is an independent background job:
#   * server instance: measure_orchestrate.sh server   (serves the matrix)
#   * client instance: measure_orchestrate.sh client <server_public_ip> <label>
#     under `sudo -E` so tc shaping works on the client NIC.
# The pair stays in lockstep by design: the server serves a fixed count per
# (format,alg) and the client consumes exactly that many across its conditions.
#
# Logs stream to run_logs/pair_<pair>.log.  Output CSV lives on each client as
# measure_<label>.csv (collected by collect.sh).
#
# RESUME defaults to 0 (full run) -- a 2-instance resume needs a SHARED combo
# marker on both hosts, which we do not synchronise here; partial resume would
# desync the lockstep count.  Re-run a failed pair from scratch instead.
#
# Usage: ./run.sh            # all pairs
#        ./run.sh <pair>     # one pair only
set -euo pipefail
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
preflight_local
require_instances

RUNS="${RUNS:-100}"
IFACE="${IFACE:-ens5}"
RESUME="${RESUME:-0}"
LOGDIR="$AWS_DIR/run_logs"; mkdir -p "$LOGDIR"

# A 2-instance resume needs a SHARED per-combo marker on both hosts; we do not
# synchronise that, and a partial resume desyncs the server's fixed per-combo
# count from the client's connection count. Refuse it -- re-run the pair clean.
[ "$RESUME" = 0 ] || die "RESUME=$RESUME unsupported in the 2-instance wrapper \
(would desync server/client lockstep). Re-run the pair from scratch with RESUME=0."

# env common to every shard (matrix defaults come from the orchestrator; the
# per-shard ALGS/COMPOSITE_ALGS/ECDSA_TAGS are appended inside run_shard).
ORCH_BASE="RUNS=$RUNS PORT=$PORT RESUME=$RESUME"
[ -n "${FORMATS:-}" ] && ORCH_BASE="$ORCH_BASE FORMATS='$FORMATS'"
[ -n "${LOSSES:-}" ]  && ORCH_BASE="$ORCH_BASE LOSSES='$LOSSES'"
[ -n "${BWS:-}" ]     && ORCH_BASE="$ORCH_BASE BWS='$BWS'"

# --- best-effort tc cleanup on every client if we are interrupted ----------
cleanup_tc() {
    log "interrupt: clearing tc on all clients ..."
    while IFS=$'\t' read -r pair shard role region id pub priv; do
        [ "$role" = client ] || continue
        ssh_to "$pub" "sudo tc qdisc del dev $IFACE root 2>/dev/null || true" \
            >/dev/null 2>&1 || true
    done < <(inst_rows)
}
trap 'cleanup_tc; exit 130' INT TERM

run_shard() { # $1=pair $2=shard  (one background job per pair x shard)
    local pair="$1" shard="$2"
    local sreg sip cip label lf orch
    sreg=$(server_region_for_pair "$pair")
    sip=$(inst_field "$pair" "$shard" server public_ip)
    cip=$(inst_field "$pair" "$shard" client public_ip)
    label=$(region_label_for_pair "$pair")   # PURE region (no shard) in the CSV
    lf="$LOGDIR/pair_${pair}_s${shard}.log"

    # Per-shard algorithm subset (load-balanced by signing cost).  The CSV
    # filename carries _s<shard>; the region COLUMN stays pure via $label.
    orch="$ORCH_BASE SHARD=$shard ALGS='$(shard_algs "$shard")' \
COMPOSITE_ALGS='$(shard_composite "$shard")' ECDSA_TAGS='$(shard_ecdsa "$shard")'"

    {
        echo "=== pair $pair shard $shard : client($cip) -> server($sip in $sreg), RUNS=$RUNS ==="
        echo "    ALGS=[$(shard_algs "$shard")] COMPOSITE=[$(shard_composite "$shard")] ECDSA=[$(shard_ecdsa "$shard")]"
        # server runs in the background of THIS ssh; the connection stays up
        ssh_to "$sip" "cd $REMOTE_HYBRID && $orch ./measure_orchestrate.sh server" &
        local spid=$!
        sleep 5
        # client: sudo -E for tc; connects to the server PUBLIC ip.
        # Capture rc WITHOUT tripping set -e so we always reach the reap path.
        local crc=0
        ssh_to "$cip" "cd $REMOTE_HYBRID && sudo -E $orch IFACE=$IFACE \
            ./measure_orchestrate.sh client $sip $label" || crc=$?
        if [ "$crc" != 0 ]; then
            # Client died: stop the local server ssh AND the remote orchestrator,
            # otherwise the server hangs on accept() for the unconsumed handshakes.
            echo "client rc=$crc -- killing server ssh($spid) + remote orchestrator"
            kill "$spid" 2>/dev/null || true
            ssh_to "$sip" "pkill -f measure_orchestrate.sh; pkill -f hybrid_measure" \
                >/dev/null 2>&1 || true
        fi
        # Reap the server job and surface its failure (no blanket || true mask).
        local src=0
        wait "$spid" 2>/dev/null || src=$?
        echo "=== pair $pair shard $shard finished (client rc=$crc, server rc=$src) ==="
        [ "$crc" = 0 ] && [ "$src" = 0 ] || exit 1
    } >"$lf" 2>&1
}

# --- fan out: every (pair x shard) instance pair runs fully in parallel -----
SEL="${1:-$PAIRS}"
PIDS=(); NAMES=()
for pair in $SEL; do
    for shard in $(shard_ids); do
        log "launching pair $pair shard $shard (log: run_logs/pair_${pair}_s${shard}.log)"
        run_shard "$pair" "$shard" &
        PIDS+=("$!"); NAMES+=("$pair/s$shard")
    done
done

log "all pair x shard jobs running in parallel; tail -f run_logs/pair_*.log to follow"
RC=0
for i in "${!PIDS[@]}"; do
    if wait "${PIDS[$i]}"; then log "pair ${NAMES[$i]} done"; else log "pair ${NAMES[$i]} ERROR"; RC=1; fi
done

trap - INT TERM
[ "$RC" = 0 ] && log "measurement complete. Next: ./collect.sh" \
              || log "one or more pairs errored; check run_logs/ then ./collect.sh (partial)"
exit "$RC"
