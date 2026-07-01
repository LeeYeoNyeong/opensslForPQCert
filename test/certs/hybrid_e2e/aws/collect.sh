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
  label=$(region_label_for_pair "$pair")   # PURE region (CSV region column)
  for shard in $(shard_ids); do
    cip=$(inst_field "$pair" "$shard" client public_ip)
    remote="$REMOTE_HYBRID/measure_${label}_s${shard}.csv"
    local_csv="$RESULTS_DIR/measure_${pair}_s${shard}.csv"

    log "=== collect $pair/s$shard from client $cip ==="
    if ! scp_from "$cip" "$remote" "$local_csv" 2>/dev/null; then
        log "WARN $pair/s$shard: could not fetch $remote (no measurement CSV?)"; WARN=1; continue
    fi

    # --- per-shard validation (awk over the 14-col schema) -----------------
    # cols: 2=format 3=alg 5=loss 6=bw 9=pq_sign 10=pq_verify
    #       11=cl_sign 12=cl_verify 14=verify_ok
    report=$(awk -F, -v runs="$RUNS" 'NR>1{
        n++;
        if ($14+0 != 1) bad++;
        if (($9+0)>0 || ($10+0)>0 || ($11+0)>0 || ($12+0)>0) anycrypto=1;
        key=$2 SUBSEP $3 SUBSEP $5 SUBSEP $6; g[key]++;
    } END {
        for (k in g){ grp++; if (g[k]!=runs) wronggrp++; }
        printf "%d %d %d %d %d", n, (bad?bad:0), (anycrypto?1:0), grp, (wronggrp?wronggrp:0)
    }' "$local_csv")
    read -r n bad anycrypto grp wronggrp <<<"$report"

    log "$pair/s$shard: rows=$n combos(grouped by fmt,alg,loss,bw)=$grp"
    if [ "${n:-0}" -eq 0 ]; then
        log "WARN $pair/s$shard: empty CSV"; WARN=1
    fi
    if [ "${anycrypto:-0}" -ne 1 ]; then
        log "WARN $pair/s$shard: ALL crypto columns are 0 => ABI skew; re-measure after ./setup.sh $pair"; WARN=1
    fi
    if [ "${bad:-0}" -gt 0 ]; then
        log "WARN $pair/s$shard: $bad/$n rows have verify_ok!=1 (excluded from stats downstream)"; WARN=1
    fi
    if [ "${wronggrp:-0}" -gt 0 ]; then
        log "WARN $pair/s$shard: $wronggrp/$grp condition-groups have row-count != RUNS($RUNS) (incomplete/desynced)"; WARN=1
    fi

    # --- merge (region column already pure; shard only named the file) -----
    if [ "$HEADER_DONE" = 0 ]; then
        head -1 "$local_csv" >> "$COMBINED"; HEADER_DONE=1
    fi
    tail -n +2 "$local_csv" >> "$COMBINED"
  done
done

total=$(($(wc -l < "$COMBINED") - 1))
log "combined -> $COMBINED ($total data rows)"

# --- per-region grid reconstruction check ----------------------------------
# The shards of a region must reassemble the FULL format-specific grid, with no
# gap and no duplicate.  Expected combos/region (format-specific, NOT 7x25):
#   (dual,catalyst,chameleon,related,pure) x |ALL_ALGS|  +  composite x |ALL_COMPOSITE|
#   + traditional x |ALL_ECDSA|
# times the number of network conditions = baseline(1) + nonzero LOSSES + nonzero BWS.
n_algs=$(echo $ALL_ALGS | wc -w); n_comp=$(echo $ALL_COMPOSITE | wc -w)
n_ecdsa=$(echo $ALL_ECDSA | wc -w)
LOSSES="${LOSSES:-0 5 10}"; BWS="${BWS:-0 1 5 10}"
n_cond=1
for l in $LOSSES; do [ "$l" = 0 ] || n_cond=$((n_cond+1)); done
for b in $BWS;    do [ "$b" = 0 ] || n_cond=$((n_cond+1)); done
exp_combos=$(( 5*n_algs + n_comp + n_ecdsa ))          # 69 by default
exp_groups=$(( exp_combos * n_cond ))                  # 414 by default
log "expected per region: $exp_combos combos x $n_cond conditions = $exp_groups (fmt,alg,loss,bw) groups"

# awk over combined: per region count distinct (fmt,alg) combos, distinct
# (fmt,alg,loss,bw) groups, and any duplicated group (row-count > RUNS).
gridrep=$(awk -F, -v runs="$RUNS" 'NR>1{
    reg=$1; combo=reg SUBSEP $2 SUBSEP $3; grp=combo SUBSEP $5 SUBSEP $6;
    if(!(combo in C)){C[combo]=1; ncombo[reg]++}
    if(!(grp in G)){G[grp]=1; ngrp[reg]++}
    gc[grp]++;
} END {
    for(g in gc){ split(g,a,SUBSEP); if(gc[g]>runs) dup[a[1]]++ }
    for(r in ncombo) printf "%s %d %d %d\n", r, ncombo[r], ngrp[r], (dup[r]?dup[r]:0)
}' "$COMBINED")
while read -r reg nc ng nd; do
    [ -z "$reg" ] && continue
    if [ "$nc" != "$exp_combos" ] || [ "$ng" != "$exp_groups" ]; then
        log "WARN $reg: combos=$nc (exp $exp_combos) groups=$ng (exp $exp_groups) -- shard merge incomplete/overlapping"; WARN=1
    elif [ "$nd" -gt 0 ]; then
        log "WARN $reg: $nd groups exceed RUNS rows -- shard overlap (duplicate combos across shards)"; WARN=1
    else
        log "OK   $reg: $nc combos / $ng groups reconstructed from shards (complete, no overlap)"
    fi
done <<EOF
$gridrep
EOF

if [ "$WARN" = 0 ]; then
    log "collection clean: no validation warnings."
else
    log "collection finished WITH WARNINGS (see above) -- review before using for stats."
fi
