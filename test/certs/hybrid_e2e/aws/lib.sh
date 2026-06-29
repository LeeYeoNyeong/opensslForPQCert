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

# pair -> region label baked into the CSV (passed to measure_orchestrate client)
region_label_for_pair() { echo "seoul-$1"; }

# Every region we touch (client region first).
all_regions() { echo "$CLIENT_REGION ap-northeast-1 ap-southeast-1 us-east-1"; }

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

# field for a (pair,role): inst_field <pair> <role> <field>
inst_field() {
    jq -r --arg p "$1" --arg r "$2" --arg f "$3" \
        '.[] | select(.pair==$p and .role==$r) | .[$f]' "$INSTANCES_JSON"
}

# all rows as TSV: pair role region id public_ip private_ip
inst_rows() {
    jq -r '.[] | [.pair,.role,.region,.id,.public_ip,.private_ip] | @tsv' "$INSTANCES_JSON"
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
