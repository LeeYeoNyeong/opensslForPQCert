#!/usr/bin/env bash
#
# poll_exit.sh -- wait until every shard's client orchestrator has EXITED
# (completed its full matrix), which is the real completion signal when CSVs may
# contain pre-existing rows (row COUNT is then meaningless).  A shard is done
# when its client has 0 measure_orchestrate procs AND its CSV holds >= expected
# distinct (fmt,alg,loss,bw,run) groups (guards against an orchestrator that
# died early rather than finishing).  On completion the fresh run's rows are the
# LAST occurrence of every combo, so collect's dedup-keep-last yields clean data.
set -uo pipefail
cd "$(dirname "$0")"; . ./lib.sh
RUNS="${RUNS:-100}"; INTERVAL="${INTERVAL:-150}"; MAXCYC="${MAXCYC:-40}"
expc(){ na=$(echo $(shard_algs $1)|wc -w); nc=$(echo $(shard_composite $1)|wc -w); ne=$(echo $(shard_ecdsa $1)|wc -w); echo $(((5*na+nc+ne)*6*RUNS)); }

cyc=0
while :; do
  cyc=$((cyc+1)); done_n=0; notdone=""
  for pair in $PAIRS; do label=$(region_label_for_pair "$pair")
    for shard in $(shard_ids); do
      cip=$(inst_field "$pair" "$shard" client public_ip); exp=$(expc "$shard")
      out=""; for t in 1 2 3; do
        out=$(ssh_to "$cip" "p=\$(pgrep -fc measure_orchestrate.sh); u=\$(tail -n +2 $REMOTE_HYBRID/measure_${label}_s${shard}.csv 2>/dev/null|awk -F, '{print \$2,\$3,\$5,\$6,\$7}'|sort -u|wc -l|tr -d ' '); echo \$p \$u" </dev/null 2>/dev/null)
        [ -n "$out" ] && break; sleep 1
      done
      set -- ${out:-9 0}; p=${1:-9}; u=${2:-0}
      if [ "${p:-9}" = 0 ] && [ "${u:-0}" -ge "$exp" ] 2>/dev/null; then
        done_n=$((done_n+1))
      else
        notdone="$notdone ${pair:0:3}/s$shard(p=$p,u=$u/$exp)"
      fi
    done
  done
  echo "[exit-poll $cyc $(date -u +%H:%M:%SZ)] done $done_n/27${notdone:+  pending:$notdone}"
  [ "$done_n" -ge 27 ] && { echo "ALL_EXITED all 27 shards completed their matrix"; exit 0; }
  [ "$cyc" -ge "$MAXCYC" ] && { echo "EXITPOLL_MAXCYC ($cyc); done $done_n/27"; exit 3; }
  sleep "$INTERVAL"
done
