#!/usr/bin/env bash
#
# run_detached.sh -- launch the per-shard server+client measurement orchestrators
# as REMOTE nohup-detached jobs, then return immediately.  Unlike run.sh (which
# holds the ssh sessions open for the whole matrix and dies -- taking the remote
# clients with it -- if the local process is killed), this decouples the long
# remote measurement from the fragile local launcher: each orchestrator runs
# under nohup on its own instance and survives ssh disconnect.  Poll the client
# CSVs (poll_detached.sh) for completion, then collect.sh.
#
# Lockstep is unchanged: the server serves a fixed count per combo and the client
# consumes exactly that many; free_port (measure_orchestrate) evicts any stale
# server on the port before binding.
set -uo pipefail
cd "$(dirname "$0")"; . ./lib.sh
RUNS="${RUNS:-100}"; IFACE="${IFACE:-ens5}"

for pair in $PAIRS; do
  label=$(region_label_for_pair "$pair")
  for shard in $(shard_ids); do
    sip=$(inst_field "$pair" "$shard" server public_ip)
    cip=$(inst_field "$pair" "$shard" client public_ip)
    algs=$(shard_algs "$shard"); comp=$(shard_composite "$shard"); ecd=$(shard_ecdsa "$shard")

    # --- SERVER: write a remote runner with the shard env baked in, nohup it ---
    ssh_to "$sip" "bash -s" </dev/null <<REMOTE
cat > /tmp/orch_srv.sh <<'INNER'
#!/bin/bash
cd $REMOTE_HYBRID
export RUNS=$RUNS PORT=$PORT RESUME=0 SHARD=$shard
export ALGS='$algs' COMPOSITE_ALGS='$comp' ECDSA_TAGS='$ecd'
exec ./measure_orchestrate.sh server
INNER
chmod +x /tmp/orch_srv.sh
nohup /tmp/orch_srv.sh >/tmp/orch_srv.log 2>&1 </dev/null &
echo "server launched pid \$!"
REMOTE
    sleep 1

    # --- CLIENT: same, under sudo for tc; connects to the server public IP ----
    ssh_to "$cip" "bash -s" </dev/null <<REMOTE
cat > /tmp/orch_cli.sh <<'INNER'
#!/bin/bash
cd $REMOTE_HYBRID
export RUNS=$RUNS PORT=$PORT RESUME=0 SHARD=$shard IFACE=$IFACE
export ALGS='$algs' COMPOSITE_ALGS='$comp' ECDSA_TAGS='$ecd'
exec ./measure_orchestrate.sh client $sip $label
INNER
chmod +x /tmp/orch_cli.sh
sudo nohup /tmp/orch_cli.sh >/tmp/orch_cli.log 2>&1 </dev/null &
echo "client launched pid \$!"
REMOTE
    echo "launched $pair/s$shard (algs=[$algs] comp=[$comp] ecdsa=[$ecd])"
  done
done
echo "ALL_LAUNCHED $(date -u +%H:%M:%SZ) -- poll with ./poll_detached.sh"
