#!/usr/bin/env bash
#
# AWS measurement orchestrator for the hybrid PQC certificate matrix.
#
# Drives test/hybrid_measure across the full matrix:
#   formats   : dual catalyst chameleon related  (+ pure, traditional baselines)
#   algorithms: 11 PQC variants (ML-DSA / Falcon / SLH-DSA-SHA2) per format
#   network   : loss {0,5,10}% and bandwidth {1,5,10}Mbit, applied SEPARATELY
#               (loss figure and bandwidth figure are distinct experiments --
#               they are never combined in one run).
#
# Runs as a matched pair: one SERVER instance and one CLIENT instance that walk
# the SAME (format,algorithm) matrix order in lockstep.  tc shaping is applied
# on the CLIENT egress NIC only; the server is never shaped.  The server serves
# a flat count of handshakes per combo; the client splits that count across the
# network conditions.
#
#   # on the server instance:
#   ./measure_orchestrate.sh server
#   # on the client instance:
#   ./measure_orchestrate.sh client <server_ip> <region_label>
#
# Environment overrides:
#   RUNS        handshakes per (combo,condition)   (default 100)
#   IFACE       client NIC for tc shaping          (default eth0)
#   PORT        TCP port                           (default 4433)
#   CERTS       fixture dir   (default: ./smoke next to this script)
#   OPENSSL_ROOT  repo root   (default: three levels up)
#   FORMATS     space list    (default: dual catalyst chameleon related pure traditional)
#   ALGS        space list of PQC variants
#   LOSSES      loss %% list   (default: 0 5 10)
#   BWS         bandwidth list (default: 0 1 5 10 ; 0 = unshaped)
#   CSV         output path    (default: ./measure_<region>.csv on the client)
#
# Resume: the client skips any (format,alg,loss,bw) tuple already present in the
# CSV, so an interrupted run can be re-launched and picks up where it stopped.
#
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=${OPENSSL_ROOT:-$(cd "$HERE/../../.." && pwd)}
BIN="$ROOT/test/hybrid_measure"
CERTS=${CERTS:-"$HERE/smoke"}
PORT=${PORT:-4433}
RUNS=${RUNS:-100}
IFACE=${IFACE:-eth0}

export DYLD_LIBRARY_PATH="$ROOT${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
export LD_LIBRARY_PATH="$ROOT${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export OPENSSL_MODULES=${OPENSSL_MODULES:-/usr/local/lib/ossl-modules}

FORMATS=${FORMATS:-"dual catalyst chameleon related pure traditional"}
ALGS=${ALGS:-"mldsa44 mldsa65 mldsa87 falcon512 falcon1024 \
sphincssha2128ssimple sphincssha2128fsimple sphincssha2192ssimple sphincssha2192fsimple \
sphincssha2256ssimple sphincssha2256fsimple"}
LOSSES=${LOSSES:-"0 5 10"}
BWS=${BWS:-"0 1 5 10"}

# Security-level label (matches the measure-prep pairing) and ECDSA tag per PQC.
cat_level() {
    case "$1" in
        mldsa44)              echo "Cat2" ;;      # FIPS-204 Cat2, paired to P-256
        falcon512|sphincssha2128ssimple|sphincssha2128fsimple) echo "Cat1" ;;
        mldsa65|sphincssha2192ssimple|sphincssha2192fsimple)   echo "Cat3" ;;
        mldsa87|falcon1024|sphincssha2256ssimple|sphincssha2256fsimple) echo "Cat5" ;;
        p256) echo "Cat1" ;; p384) echo "Cat3" ;; p521) echo "Cat5" ;;
        *) echo "-" ;;
    esac
}

# For the traditional baseline iterate the three ECDSA curve tags instead of the
# PQC list.
algs_for_format() {
    if [ "$1" = "traditional" ]; then echo "p256 p384 p521"; else echo "$ALGS"; fi
}

# Conditions for a combo: each loss value (bw unshaped) AND each bw value (loss
# 0).  loss=0,bw=0 is the unshaped baseline, emitted once.
conditions() {
    echo "0 0"                       # unshaped baseline
    for l in $LOSSES; do [ "$l" = 0 ] || echo "$l 0"; done
    for b in $BWS;    do [ "$b" = 0 ] || echo "0 $b"; done
}

# Total handshakes the server must serve for one combo = sum over conditions.
runs_per_combo() {
    n=0
    while read -r _ _; do n=$((n + RUNS)); done <<EOF
$(conditions)
EOF
    echo "$n"
}

# ---- tc shaping (client only) ---------------------------------------------
tc_clear() { tc qdisc del dev "$IFACE" root 2>/dev/null || true; }

tc_apply() { # $1=loss%  $2=bwMbit (0 = none)
    loss=$1; bw=$2
    tc_clear
    if [ "$bw" != 0 ]; then
        # tbf for bandwidth limiting; burst/latency sized for the link.
        tc qdisc add dev "$IFACE" root handle 1: tbf \
            rate "${bw}mbit" burst 32kbit latency 400ms
    elif [ "$loss" != 0 ]; then
        tc qdisc add dev "$IFACE" root netem loss "${loss}%"
    fi
}

# Always clear shaping on exit, even on Ctrl-C / error.
trap 'tc_clear' EXIT INT TERM

# Readiness is handled inside the measurement binary: its client retries the
# initial connect for ~5 s.  A shell-side TCP probe is deliberately avoided --
# it would be accept()ed by the server and consumed as a handshake, desyncing
# the fixed per-combo count.

# ---- resume (COMBO granularity, lockstep-safe) ----------------------------
# Resume must skip the SAME unit on both sides or the fixed per-combo server
# count desyncs from the client's connection count (server hangs on accept).
# So resume is per (format,alg) COMBO -- never per condition -- and is gated by
# a marker file that BOTH server and client must consult identically.  Default
# RESUME=0 => nothing is skipped => the pair can never fall out of lockstep.
# For a two-instance run, enabling resume requires the SAME marker on both
# hosts (shared storage or copy it across); otherwise re-run both from scratch.
RESUME=${RESUME:-0}
MARKER=${MARKER:-"$HERE/.measure_done"}

combo_done() { # $1=fmt $2=alg
    [ "$RESUME" = 1 ] || return 1
    [ -f "$MARKER" ] && grep -qx "$1:$2" "$MARKER" 2>/dev/null
}
mark_combo() { # $1=fmt $2=alg
    [ "$RESUME" = 1 ] || return 0
    echo "$1:$2" >> "$MARKER"
}

# ---- server role ----------------------------------------------------------
run_server() {
    total=$(runs_per_combo)
    echo "[server] matrix; $total handshakes/combo on port $PORT (resume=$RESUME)" >&2
    for fmt in $FORMATS; do
        for alg in $(algs_for_format "$fmt"); do
            if combo_done "$fmt" "$alg"; then
                echo "[server] skip $fmt x $alg (marked done)" >&2
                continue
            fi
            echo "[server] $fmt x $alg ($total handshakes)" >&2
            "$BIN" --role server --format "$fmt" --alg "$alg" \
                --certs "$CERTS" --port "$PORT" --runs "$total" \
                || echo "[server] WARN $fmt x $alg returned $?" >&2
            mark_combo "$fmt" "$alg"
            sleep 1   # brief gap so the client can detect the next listener
        done
    done
    echo "[server] done" >&2
}

# ---- client role ----------------------------------------------------------
run_client() {
    host=$1; region=$2
    csv=${CSV:-"$HERE/measure_${region}.csv"}
    [ -f "$csv" ] || "$BIN" --csv-header > "$csv"

    for fmt in $FORMATS; do
        for alg in $(algs_for_format "$fmt"); do
            lvl=$(cat_level "$alg")
            if combo_done "$fmt" "$alg"; then
                echo "[client] skip $fmt x $alg (marked done)" >&2
                continue
            fi
            echo "[client] $fmt x $alg (binary retries initial connect) ..." >&2
            # Every non-skipped combo runs its FULL condition set so the
            # client's connection count matches the server's fixed total.
            while read -r loss bw; do
                tc_apply "$loss" "$bw"
                echo "[client] $fmt $alg loss=$loss bw=$bw x$RUNS" >&2
                "$BIN" --role client --format "$fmt" --alg "$alg" \
                    --certs "$CERTS" --host "$host" --port "$PORT" \
                    --runs "$RUNS" --csv "$csv" \
                    --region "$region" --loss "$loss" --bw "$bw" --cat-level "$lvl"
                tc_clear
            done <<EOF
$(conditions)
EOF
            mark_combo "$fmt" "$alg"
        done
    done
    echo "[client] done -> $csv" >&2
}

# ---- entry ----------------------------------------------------------------
[ -x "$BIN" ] || { echo "missing $BIN (build test/hybrid_measure)" >&2; exit 1; }

case "${1:-}" in
    server) run_server ;;
    client) run_client "${2:?usage: client <server_ip> <region>}" "${3:?region label}" ;;
    *) echo "usage: $0 {server | client <server_ip> <region_label>}" >&2; exit 1 ;;
esac
