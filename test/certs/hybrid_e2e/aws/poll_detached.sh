#!/usr/bin/env bash
#
# poll_detached.sh -- watch the detached per-shard measurement to completion.
# Prints one progress line per cycle; exits 0 when every shard's client CSV has
# reached its expected row count (combos x conditions x RUNS), or non-zero if a
# shard's orchestrator has died with an incomplete CSV and made no progress for
# two consecutive cycles (a genuine stall, not just slow).
set -uo pipefail
cd "$(dirname "$0")"; . ./lib.sh
RUNS="${RUNS:-100}"; INTERVAL="${INTERVAL:-120}"; MAXCYC="${MAXCYC:-60}"

# Conditions per combo, mirroring measure_orchestrate.sh conditions(): the
# unshaped baseline plus each nonzero loss and each nonzero bandwidth value.
# Derived from the same LOSSES/BWS env the run was launched with, so an
# override like LOSSES=0 BWS="1 5 10" is counted correctly without having to
# pass a matching NCOND by hand; an explicit NCOND still wins.
if [ -z "${NCOND:-}" ]; then
    # No explicit env: fall back to the conditions run_detached.sh recorded at
    # launch, so a bare ./poll_detached.sh matches a reduced-condition run.
    [ -z "${LOSSES:-}${BWS:-}" ] && [ -f .last_run.env ] && . ./.last_run.env
    NCOND=1
    for _l in ${LOSSES:-0 5 10};   do [ "$_l" = 0 ] || NCOND=$((NCOND+1)); done
    for _b in ${BWS:-0 1 5 10};    do [ "$_b" = 0 ] || NCOND=$((NCOND+1)); done
fi

# expected CSV data-rows for a shard = combos x NCOND conditions x RUNS
expected_for() { # $1=shard
    local na nc ne
    na=$(echo $(shard_algs "$1") | wc -w)
    nc=$(echo $(shard_composite "$1") | wc -w)
    ne=$(echo $(shard_ecdsa "$1") | wc -w)
    echo $(( (5*na + nc + ne) * NCOND * RUNS ))
}

declare -a PREV
cyc=0
while :; do
  cyc=$((cyc+1))
  done_all=1; stalled=""; tot_have=0; tot_exp=0; i=0
  line=""
  for pair in $PAIRS; do
    label=$(region_label_for_pair "$pair")
    for shard in $(shard_ids); do
      cip=$(inst_field "$pair" "$shard" client public_ip)
      exp=$(expected_for "$shard")
      have=$(ssh_to "$cip" "n=\$(wc -l < $REMOTE_HYBRID/measure_${label}_s${shard}.csv 2>/dev/null || echo 1); echo \$((n-1))" </dev/null 2>/dev/null)
      have=${have:-0}; [ "$have" -lt 0 ] 2>/dev/null && have=0
      tot_have=$((tot_have+have)); tot_exp=$((tot_exp+exp))
      if [ "$have" -lt "$exp" ]; then
        done_all=0
        # stall check: orchestrator dead AND no progress since last cycle
        prev0=${PREV[$i]:-0}
        if [ "$have" = "$prev0" ]; then
          alive=$(ssh_to "$cip" "pgrep -fc measure_orchestrate" </dev/null 2>/dev/null)
          [ "${alive:-0}" = 0 ] && stalled="$stalled $pair/s$shard($have/$exp)"
        fi
      fi
      PREV[$i]=$have; i=$((i+1))
    done
  done
  pct=$(( tot_exp>0 ? tot_have*100/tot_exp : 0 ))
  echo "[poll $cyc $(date -u +%H:%M:%SZ)] $tot_have/$tot_exp rows (${pct}%)${stalled:+  STALLED:$stalled}"
  [ "$done_all" = 1 ] && { echo "ALL_COMPLETE $tot_have rows"; exit 0; }
  [ -n "$stalled" ] && { echo "STALLED_DETECTED$stalled"; exit 2; }
  [ "$cyc" -ge "$MAXCYC" ] && { echo "POLL_MAXCYC reached ($cyc); still $tot_have/$tot_exp"; exit 3; }
  sleep "$INTERVAL"
done
