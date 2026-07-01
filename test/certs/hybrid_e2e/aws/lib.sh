#!/usr/bin/env bash
#
# Shared configuration + helpers for the NETWORK-26-00272 AWS measurement wrapper.
#
# This file is *sourced* by provision/setup/sanity/run/collect/teardown.sh.  It
# holds the single source of truth for region layout, instance shape, tags and
# the SSH / jq accessors used everywhere else, so the six scripts can never
# disagree about the topology.
#
# Nothing here spends money or touches AWS on its own -- it only defines
# constants and functions.
#
# macOS portability note: the system bash is 3.2 (no `declare -A`).  Region maps
# are therefore expressed as case statements, not associative arrays.

set -euo pipefail

# ---- topology (CONFIRMED layout) ------------------------------------------
# 3 region pairs, fully parallel.  Every client lives in Seoul; each server
# lives in its pair's region.  Cross-region traffic goes over the public
# internet (different VPCs), so the client connects to the server PUBLIC IP and
# the server security group opens the measurement port to that client's PUBLIC
# IP only.
PROJECT="NETWORK-26-00272"
PAIRS="tokyo singapore virginia"
CLIENT_REGION="ap-northeast-2"          # Seoul -- all three clients

# pair -> server region
server_region_for_pair() {
    case "$1" in
        tokyo)     echo "ap-northeast-1" ;;   # Tokyo
        singapore) echo "ap-southeast-1" ;;   # Singapore
        virginia)  echo "us-east-1"      ;;   # N. Virginia
        *) echo "lib.sh: unknown pair '$1'" >&2; return 1 ;;
    esac
}

# pair -> region label baked into the CSV (passed to measure_orchestrate client).
# The CSV "region" column stays the PURE region (no shard) so collect.sh can
# merge every shard of a region into one logical region without rewriting rows.
region_label_for_pair() { echo "seoul-$1"; }

# Every region we touch (client region first).
all_regions() { echo "$CLIENT_REGION ap-northeast-1 ap-southeast-1 us-east-1"; }

# ---- intra-region load-balancing shards -----------------------------------
# Each region runs $SHARDS independent client+server instance pairs so the
# algorithm matrix is split across them by SIGNING COST, cutting wall-clock
# without co-locating measurements (co-located crypto would contend for CPU and
# pollute timings -- parallelism is ALWAYS across instance pairs, never inside
# one).  Each shard measures its own algorithm subset x ALL formats x ALL
# network conditions; the union of shards reproduces the full per-region grid.
SHARDS="${SHARDS:-3}"
shard_ids() { local k=0; while [ "$k" -lt "$SHARDS" ]; do echo "$k"; k=$((k+1)); done; }

# Canonical full label lists (single source of truth; must match the
# measure_orchestrate.sh defaults exactly).  25 labels = 11 PQC + 11 composite +
# 3 ECDSA.  shard_* below partition these with no overlap and no gap.
ALL_ALGS="mldsa44 mldsa65 mldsa87 falcon512 falcon1024 \
slhdsasha2128s slhdsasha2128f slhdsasha2192s slhdsasha2192f \
slhdsasha2256s slhdsasha2256f"
ALL_COMPOSITE="p256_mldsa44 p384_mldsa65 p521_mldsa87 \
p256_falcon512 p521_falcon1024 \
p256_slhdsasha2128s p256_slhdsasha2128f \
p384_slhdsasha2192s p384_slhdsasha2192f \
p521_slhdsasha2256s p521_slhdsasha2256f"
ALL_ECDSA="p256 p384 p521"

# Round-robin fallback for shard counts other than the paper's N=3.
shard_rr() { # $1=shard_id $2=list
    local k="$1" i=0 w
    for w in $2; do [ "$((i % SHARDS))" -eq "$k" ] && printf '%s ' "$w"; i=$((i+1)); done
}

# N=3 concrete layout: isolate the two heaviest SLH-DSA "small" variants (sign
# ~300 ms) on shard 0, the remaining SLH-DSA on shard 1, and the light majority
# (ML-DSA, Falcon, ALL composite, ALL ECDSA) on shard 2.
# N=9 layout: each of the 6 SLH-DSA variants gets its OWN shard (s0-s5) since a
# bare SLH-DSA runs on 5 PQC formats (the true critical path); the light bare
# algs (ML-DSA/Falcon) share s6-s8, which also carry the composite labels (1
# format each) and ECDSA. Heaviest bare-SLH-DSA-small on the lowest shards.
shard_algs() { # $1=shard_id -> PQC labels for the 5 PQC-using formats
    case "$SHARDS:$1" in
        3:0) echo "slhdsasha2192s slhdsasha2256s" ;;
        3:1) echo "slhdsasha2128s slhdsasha2128f slhdsasha2192f slhdsasha2256f" ;;
        3:2) echo "mldsa44 mldsa65 mldsa87 falcon512 falcon1024" ;;
        9:0) echo "slhdsasha2256s" ;;
        9:1) echo "slhdsasha2192s" ;;
        9:2) echo "slhdsasha2128s" ;;
        9:3) echo "slhdsasha2256f" ;;
        9:4) echo "slhdsasha2192f" ;;
        9:5) echo "slhdsasha2128f" ;;
        9:6) echo "mldsa87 falcon1024" ;;
        9:7) echo "mldsa44 mldsa65" ;;
        9:8) echo "falcon512" ;;
        *)   shard_rr "$1" "$ALL_ALGS" ;;
    esac
}
shard_composite() { # $1=shard_id -> composite labels for the composite format
    case "$SHARDS:$1" in
        3:0|3:1) echo "" ;;
        3:2)     echo "$ALL_COMPOSITE" ;;
        9:0|9:1|9:2) echo "" ;;                       # keep bare-heavy shards lean
        9:3) echo "p521_slhdsasha2256f" ;;
        9:4) echo "p384_slhdsasha2192f" ;;
        9:5) echo "p256_slhdsasha2128f" ;;
        9:6) echo "p521_slhdsasha2256s p521_mldsa87" ;;
        9:7) echo "p384_slhdsasha2192s p384_mldsa65" ;;
        9:8) echo "p256_slhdsasha2128s p256_mldsa44 p256_falcon512 p521_falcon1024" ;;
        *)       shard_rr "$1" "$ALL_COMPOSITE" ;;
    esac
}
shard_ecdsa() { # $1=shard_id -> ECDSA tags for the traditional format
    case "$SHARDS:$1" in
        3:0|3:1) echo "" ;;
        3:2)     echo "$ALL_ECDSA" ;;
        9:6) echo "p256" ;; 9:7) echo "p384" ;; 9:8) echo "p521" ;;
        9:0|9:1|9:2|9:3|9:4|9:5) echo "" ;;
        *)       shard_rr "$1" "$ALL_ECDSA" ;;
    esac
}

# ---- instance shape -------------------------------------------------------
INSTANCE_TYPE="${INSTANCE_TYPE:-c5.xlarge}"   # fixed perf, 4 vCPU; t-class forbidden
ROOT_VOLUME_GB="${ROOT_VOLUME_GB:-30}"
ROOT_VOLUME_TYPE="gp3"
PORT="${PORT:-4433}"

# ---- naming ---------------------------------------------------------------
KEY_NAME="${KEY_NAME:-measure-key}"
SG_NAME="${SG_NAME:-measure-sg-$PROJECT}"
SG_DESC="NETWORK-26-00272 hybrid PQC TLS measurement"

# ---- local paths ----------------------------------------------------------
AWS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEY_PEM="${KEY_PEM:-$AWS_DIR/$KEY_NAME.pem}"
INSTANCES_JSON="${INSTANCES_JSON:-$AWS_DIR/instances.json}"
RESULTS_DIR="${RESULTS_DIR:-$AWS_DIR/results}"

# ---- remote paths (on each Ubuntu instance) -------------------------------
SSH_USER="ubuntu"
REMOTE_REPO="/home/ubuntu/opensslForPQCert"
REMOTE_HYBRID="$REMOTE_REPO/test/certs/hybrid_e2e"
REMOTE_MODULES="/usr/local/lib/ossl-modules"

# ---- build / source knobs (overridable for reproducibility) ---------------
REPO_URL="${REPO_URL:-https://github.com/LeeYeoNyeong/opensslForPQCert.git}"
REPO_BRANCH="${REPO_BRANCH:-hybrid-cert}"
LIBOQS_REF="${LIBOQS_REF:-0.15.0}"            # paper-pinned liboqs
OQSPROV_REF="${OQSPROV_REF:-0.11.0}"      # paper-pinned oqs-provider
BUILD_JOBS="${BUILD_JOBS:-4}"                 # c5.xlarge = 4 vCPU

# ---- ssh / scp ------------------------------------------------------------
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o ConnectTimeout=20 -o ServerAliveInterval=30 -o LogLevel=ERROR)

ssh_to()  { local ip="$1"; shift; ssh "${SSH_OPTS[@]}" -i "$KEY_PEM" "$SSH_USER@$ip" "$@"; }
scp_to()  { local ip="$1" src="$2" dst="$3"; scp "${SSH_OPTS[@]}" -i "$KEY_PEM" "$src" "$SSH_USER@$ip:$dst"; }
scp_from(){ local ip="$1" src="$2" dst="$3"; scp "${SSH_OPTS[@]}" -i "$KEY_PEM" "$SSH_USER@$ip:$src" "$dst"; }

# ---- instances.json accessors (require jq) --------------------------------
require_instances() {
    [ -f "$INSTANCES_JSON" ] || { echo "missing $INSTANCES_JSON -- run provision.sh first" >&2; exit 1; }
}

# field for a (pair,shard,role): inst_field <pair> <shard> <role> <field>.
# shard defaults to 0 so single-shard callers/manifests keep working.
inst_field() {
    jq -r --arg p "$1" --argjson s "${2:-0}" --arg r "$3" --arg f "$4" \
        '.[] | select(.pair==$p and (.shard // 0)==$s and .role==$r) | .[$f]' "$INSTANCES_JSON"
}

# all rows as TSV: pair shard role region id public_ip private_ip
inst_rows() {
    jq -r '.[] | [.pair,(.shard // 0),.role,.region,.id,.public_ip,.private_ip] | @tsv' \
        "$INSTANCES_JSON"
}

# instance ids in a given region (for teardown / waits)
ids_in_region() {
    jq -r --arg reg "$1" '.[] | select(.region==$reg) | .id' "$INSTANCES_JSON"
}

# ---- misc -----------------------------------------------------------------
my_ip() { curl -fsS https://checkip.amazonaws.com 2>/dev/null || curl -fsS ifconfig.me; }

confirm() { # confirm "<prompt>"  -- honours FORCE=1 / --yes
    [ "${FORCE:-0}" = "1" ] && return 0
    local reply
    printf '%s [y/N] ' "$1" >&2
    read -r reply
    case "$reply" in y|Y|yes|YES) return 0 ;; *) echo "aborted." >&2; return 1 ;; esac
}

log()  { echo "[$(basename "${0:-lib}")] $*" >&2; }
die()  { echo "ERROR: $*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "required tool not found: $1"; }
preflight_local() { need aws; need jq; need ssh; need scp; need curl; }
