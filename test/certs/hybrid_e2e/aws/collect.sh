#!/usr/bin/env bash
#
# collect.sh -- pull the per-pair CSVs off the 3 clients, validate them, and
# merge into results/combined.csv.
#
# Validation (per pair):
#   * verify_ok != 1 row count                      (invalid handshakes)
#   * all crypto columns zero across the file        => ABI skew (re-measure)
#   * per-(format,alg,loss,bw) group size != $RUNS    => incomplete / desynced
#
# Usage: ./collect.sh            # all pairs
#        ./collect.sh <pair>     # one pair only
set -euo pipefail
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
preflight_local
require_instances

RUNS="${RUNS:-100}"
mkdir -p "$RESULTS_DIR"
SEL="${1:-$PAIRS}"

COMBINED="$RESULTS_DIR/combined.csv"
: > "$COMBINED"
HEADER_DONE=0
WARN=0

for pair in $SEL; do
    cip=$(inst_field "$pair" client public_ip)
    label=$(region_label_for_pair "$pair")
    remote="$REMOTE_HYBRID/measure_${label}.csv"
    local_csv="$RESULTS_DIR/measure_${pair}.csv"

    log "=== collect $pair from client $cip ==="
    if ! scp_from "$cip" "$remote" "$local_csv" 2>/dev/null; then
        log "WARN $pair: could not fetch $remote (no measurement CSV?)"; WARN=1; continue
    fi

    # --- per-pair validation (awk over the 14-col schema) ------------------
    # cols: 2=format 3=alg 5=loss 6=bw 9=pq_sign 10=pq_verify
    #       11=cl_sign 12=cl_verify 14=verify_ok
    report=$(awk -F, -v runs="$RUNS" 'NR>1{
        n++;
        if ($14+0 != 1) bad++;
        if (($9+0)>0 || ($10+0)>0 || ($11+0)>0 || ($12+0)>0) anycrypto=1;
        key=$2 SUBSEP $3 SUBSEP $5 SUBSEP $6; g[key]++;
    } END {
        bmin=runs; for (k in g){ grp++; if (g[k]!=runs) wronggrp++; }
        printf "%d %d %d %d %d", n, (bad?bad:0), (anycrypto?1:0), grp, (wronggrp?wronggrp:0)
    }' "$local_csv")
    read -r n bad anycrypto grp wronggrp <<<"$report"

    log "$pair: rows=$n combos(grouped by fmt,alg,loss,bw)=$grp"
    if [ "${n:-0}" -eq 0 ]; then
        log "WARN $pair: empty CSV"; WARN=1
    fi
    if [ "${anycrypto:-0}" -ne 1 ]; then
        log "WARN $pair: ALL crypto columns are 0 => ABI skew; this pair must be re-measured after ./setup.sh $pair"; WARN=1
    fi
    if [ "${bad:-0}" -gt 0 ]; then
        log "WARN $pair: $bad/$n rows have verify_ok!=1 (excluded from stats downstream)"; WARN=1
    fi
    if [ "${wronggrp:-0}" -gt 0 ]; then
        log "WARN $pair: $wronggrp/$grp condition-groups have row-count != RUNS($RUNS) (incomplete/desynced)"; WARN=1
    fi

    # --- merge -------------------------------------------------------------
    if [ "$HEADER_DONE" = 0 ]; then
        head -1 "$local_csv" >> "$COMBINED"; HEADER_DONE=1
    fi
    tail -n +2 "$local_csv" >> "$COMBINED"
done

total=$(($(wc -l < "$COMBINED") - 1))
log "combined -> $COMBINED ($total data rows)"
if [ "$WARN" = 0 ]; then
    log "collection clean: no validation warnings."
else
    log "collection finished WITH WARNINGS (see above) -- review before using for stats."
fi
