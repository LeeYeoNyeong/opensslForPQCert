#!/usr/bin/env bash
#
# provision.sh -- create the 6-instance NETWORK-26-00272 measurement fleet.
#
#   3 clients  in Seoul        (ap-northeast-2), one per region pair
#   3 servers  in Tokyo / Singapore / Virginia, one per region pair
#
# All instances: c5.xlarge, Ubuntu 24.04 LTS, on-demand, 30 GB gp3 root.
#
# Ordering matters for the firewall: clients are launched first so their PUBLIC
# IPs are known, then each server security group opens the measurement port to
# exactly its pair's client /32.  SSH (22) is opened only to the operator's
# current public IP.
#
# Output: instances.json (consumed by every other script).
# Cost:   ~$1.20/hour for the 6 instances -- TEARDOWN WHEN DONE.
#
# Usage:  ./provision.sh [--yes]
set -euo pipefail
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
[ "${1:-}" = "--yes" ] && FORCE=1
preflight_local

# Never clobber a manifest that may describe a still-running fleet -- doing so
# orphans those instances from teardown.sh and leaks cost.  teardown renames
# instances.json to .terminated, so the normal lifecycle passes this guard.
[ -f "$INSTANCES_JSON" ] && die "$INSTANCES_JSON already exists -- a fleet may still be \
live. Run ./teardown.sh first (or remove the file manually if you are certain no \
tagged instances are running)."

# --- cost warning + confirmation -------------------------------------------
cat >&2 <<EOF

  ============================================================
   NETWORK-26-00272 provisioning -- 6 x $INSTANCE_TYPE on-demand
  ============================================================
   client x3  Seoul ($CLIENT_REGION)
   server x1  Tokyo (ap-northeast-1)
   server x1  Singapore (ap-southeast-1)
   server x1  Virginia (us-east-1)

   Estimated cost: ~\$0.17-0.21 / instance-hour  ==>  ~\$1.20 / hour total
                   (+ EBS ${ROOT_VOLUME_GB}GB gp3 each; verify current pricing)

   *** These run until you call teardown.sh.  Forgetting = ongoing charges. ***
  ============================================================
EOF
confirm "Launch 6 on-demand instances now?" || exit 1

OPERATOR_IP="$(my_ip)/32"
log "operator IP (SSH allowed from): $OPERATOR_IP"

# --- per-region prerequisites: key pair + security group + AMI -------------
ensure_key() { # $1=region
    local region="$1"
    if aws ec2 describe-key-pairs --region "$region" --key-names "$KEY_NAME" >/dev/null 2>&1; then
        log "[$region] key '$KEY_NAME' already imported"
        return
    fi
    if [ ! -f "$KEY_PEM" ]; then
        log "generating local key pair $KEY_PEM"
        ssh-keygen -t rsa -b 4096 -N '' -f "$KEY_PEM" -C "$KEY_NAME" >/dev/null
        chmod 600 "$KEY_PEM"
    fi
    log "[$region] importing key '$KEY_NAME'"
    aws ec2 import-key-pair --region "$region" --key-name "$KEY_NAME" \
        --public-key-material "fileb://$KEY_PEM.pub" \
        --tag-specifications "ResourceType=key-pair,Tags=[{Key=Project,Value=$PROJECT}]" \
        >/dev/null
}

ensure_sg() { # $1=region  -> prints GroupId
    local region="$1" vpc gid
    gid=$(aws ec2 describe-security-groups --region "$region" \
            --filters "Name=group-name,Values=$SG_NAME" \
            --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || echo "None")
    if [ "$gid" = "None" ] || [ -z "$gid" ]; then
        vpc=$(aws ec2 describe-vpcs --region "$region" \
                --filters "Name=isDefault,Values=true" \
                --query 'Vpcs[0].VpcId' --output text)
        [ "$vpc" != "None" ] || die "[$region] no default VPC; create one or set a VPC manually"
        gid=$(aws ec2 create-security-group --region "$region" \
                --group-name "$SG_NAME" --description "$SG_DESC" --vpc-id "$vpc" \
                --tag-specifications "ResourceType=security-group,Tags=[{Key=Project,Value=$PROJECT}]" \
                --query 'GroupId' --output text)
        log "[$region] created SG $gid in $vpc"
    fi
    # SSH from operator only (idempotent: ignore duplicate-rule error)
    aws ec2 authorize-security-group-ingress --region "$region" --group-id "$gid" \
        --protocol tcp --port 22 --cidr "$OPERATOR_IP" >/dev/null 2>&1 || true
    echo "$gid"
}

latest_ami() { # $1=region -> Ubuntu 24.04 amd64 server (Canonical)
    aws ec2 describe-images --region "$1" --owners 099720109477 \
        --filters "Name=name,Values=ubuntu/images/*/ubuntu-noble-24.04-amd64-server-*" \
                  "Name=state,Values=available" \
                  "Name=architecture,Values=x86_64" \
        --query 'sort_by(Images,&CreationDate)[-1].ImageId' --output text
}

open_port_from() { # $1=region $2=sg $3=clientPublicIp
    local region="$1" sg="$2" ip="$3" existing err
    [ -n "$ip" ] && [ "$ip" != None ] \
        || die "[$region] client public IP is empty/None -- cannot open tcp/$PORT"

    # Revoke any stale tcp/$PORT rules (old client /32s from a prior provision)
    # so the SG matches "exactly this pair's client /32".  SSH (22) is untouched.
    existing=$(aws ec2 describe-security-groups --region "$region" --group-id "$sg" \
        --query "SecurityGroups[0].IpPermissions[?ToPort==\`$PORT\` && FromPort==\`$PORT\`]" \
        --output json 2>/dev/null || echo "[]")
    if [ -n "$existing" ] && [ "$existing" != "[]" ] && [ "$existing" != "null" ]; then
        aws ec2 revoke-security-group-ingress --region "$region" --group-id "$sg" \
            --ip-permissions "$existing" >/dev/null 2>&1 || true
        log "[$region] revoked stale tcp/$PORT ingress rule(s)"
    fi

    err=$(mktemp)
    if aws ec2 authorize-security-group-ingress --region "$region" --group-id "$sg" \
            --protocol tcp --port "$PORT" --cidr "$ip/32" >/dev/null 2>"$err"; then
        log "[$region] opened tcp/$PORT from $ip/32"
    elif grep -qi duplicate "$err"; then
        log "[$region] tcp/$PORT from $ip/32 already authorized"
    else
        cat "$err" >&2; rm -f "$err"
        die "[$region] failed to authorize tcp/$PORT from $ip/32"
    fi
    rm -f "$err"
}

launch() { # $1=region $2=sg $3=ami $4=role $5=pair -> prints instance-id
    local region="$1" sg="$2" ami="$3" role="$4" pair="$5"
    aws ec2 run-instances --region "$region" --image-id "$ami" \
        --instance-type "$INSTANCE_TYPE" --key-name "$KEY_NAME" \
        --security-group-ids "$sg" --count 1 \
        --block-device-mappings "DeviceName=/dev/sda1,Ebs={VolumeSize=$ROOT_VOLUME_GB,VolumeType=$ROOT_VOLUME_TYPE}" \
        --tag-specifications \
          "ResourceType=instance,Tags=[{Key=Project,Value=$PROJECT},{Key=Role,Value=$role},{Key=Pair,Value=$pair},{Key=Name,Value=measure-$role-$pair}]" \
        --query 'Instances[0].InstanceId' --output text
}

wait_running_ip() { # $1=region $2=id -> "public private"
    aws ec2 wait instance-running --region "$1" --instance-ids "$2"
    aws ec2 describe-instances --region "$1" --instance-ids "$2" \
        --query 'Reservations[0].Instances[0].[PublicIpAddress,PrivateIpAddress]' \
        --output text
}

# --- 1. keys + SGs + AMIs in every region ----------------------------------
log "ensuring key pairs in all regions ..."
for r in $(all_regions); do ensure_key "$r"; done

CLIENT_SG=$(ensure_sg "$CLIENT_REGION")
CLIENT_AMI=$(latest_ami "$CLIENT_REGION")
log "client region $CLIENT_REGION  SG=$CLIENT_SG  AMI=$CLIENT_AMI"

# items accumulated as one-line JSON objects.  The manifest is rewritten after
# EVERY instance so a crash mid-provision still leaves teardown.sh a usable file.
ITEMS=()
emit() { # role pair region id public private
    ITEMS+=("$(jq -nc --arg role "$1" --arg pair "$2" --arg region "$3" \
        --arg id "$4" --arg pub "$5" --arg priv "$6" \
        '{id:$id,role:$role,pair:$pair,region:$region,public_ip:$pub,private_ip:$priv}')")
    printf '%s\n' "${ITEMS[@]}" | jq -s '.' > "$INSTANCES_JSON"
}

# If provisioning aborts after launching instances, point the operator at a
# tag-based emergency cleanup (the manifest may be partial).
emergency() {
    echo >&2
    echo "!! provision interrupted -- instances may be running. Check $INSTANCES_JSON," >&2
    echo "!! run ./teardown.sh, and/or sweep by tag in each region:" >&2
    for r in $(all_regions); do
        echo "   aws ec2 describe-instances --region $r \\" >&2
        echo "     --filters Name=tag:Project,Values=$PROJECT Name=instance-state-name,Values=running,pending \\" >&2
        echo "     --query 'Reservations[].Instances[].InstanceId' --output text" >&2
    done
}
trap emergency ERR INT TERM

# --- 2. launch the 3 clients (Seoul) and capture their public IPs ----------
declare CLIENT_TOKYO_IP="" CLIENT_SINGAPORE_IP="" CLIENT_VIRGINIA_IP=""
for pair in $PAIRS; do
    cid=$(launch "$CLIENT_REGION" "$CLIENT_SG" "$CLIENT_AMI" client "$pair")
    log "launched client/$pair = $cid (Seoul); waiting for running ..."
    read -r pub priv < <(wait_running_ip "$CLIENT_REGION" "$cid")
    log "client/$pair up: public=$pub private=$priv"
    emit client "$pair" "$CLIENT_REGION" "$cid" "$pub" "$priv"
    case "$pair" in
        tokyo)     CLIENT_TOKYO_IP="$pub" ;;
        singapore) CLIENT_SINGAPORE_IP="$pub" ;;
        virginia)  CLIENT_VIRGINIA_IP="$pub" ;;
    esac
done

client_ip_for_pair() {
    case "$1" in
        tokyo) echo "$CLIENT_TOKYO_IP" ;;
        singapore) echo "$CLIENT_SINGAPORE_IP" ;;
        virginia) echo "$CLIENT_VIRGINIA_IP" ;;
    esac
}

# --- 3. per server region: SG + open port from its client, then launch -----
for pair in $PAIRS; do
    sreg=$(server_region_for_pair "$pair")
    ssg=$(ensure_sg "$sreg")
    sami=$(latest_ami "$sreg")
    open_port_from "$sreg" "$ssg" "$(client_ip_for_pair "$pair")"
    log "[$sreg] SG=$ssg AMI=$sami ; launching server/$pair ..."
    sid=$(launch "$sreg" "$ssg" "$sami" server "$pair")
    read -r pub priv < <(wait_running_ip "$sreg" "$sid")
    log "server/$pair up: public=$pub private=$priv"
    emit server "$pair" "$sreg" "$sid" "$pub" "$priv"
done

# --- 4. assemble instances.json --------------------------------------------
printf '%s\n' "${ITEMS[@]}" | jq -s '.' > "$INSTANCES_JSON"
trap - ERR INT TERM          # full fleet up + recorded; disarm emergency notice
log "wrote $INSTANCES_JSON"
jq -r '.[] | "  \(.role)/\(.pair)\t\(.region)\t\(.id)\tpub=\(.public_ip)"' "$INSTANCES_JSON" >&2

cat >&2 <<EOF

  Next: ./setup.sh   (deps + clean HYBRID_MEASURE build + fixtures)
  Cost is now accruing -- remember ./teardown.sh when finished.
EOF
