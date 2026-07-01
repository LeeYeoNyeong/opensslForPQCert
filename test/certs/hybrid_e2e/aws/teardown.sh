#!/usr/bin/env bash
#
# teardown.sh -- terminate the fleet (STOP THE BILLING).
#
# Default: terminate the 6 instances in instances.json (across all 4 regions),
#          wait for termination, leave the key pair + security groups in place
#          (cheap, reusable on the next provision).
#
#   --full : also delete the security groups and key pairs in every region.
#
# Usage: ./teardown.sh [--full] [--yes]
set -euo pipefail
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
preflight_local

FULL=0
for a in "$@"; do
    case "$a" in
        --full) FULL=1 ;;
        --yes)  FORCE=1 ;;
        *) die "unknown arg: $a (usage: ./teardown.sh [--full] [--yes])" ;;
    esac
done
require_instances

log "instances slated for termination:"
# inst_rows cols: 1=pair 2=shard 3=role 4=region 5=id
inst_rows | awk -F'\t' '{printf "  %s/%s/s%s\t%s\t%s\n",$3,$1,$2,$4,$5}' >&2
[ "$FULL" = 1 ] && log "(--full) will ALSO delete security groups + key pairs in every region"
confirm "Terminate all of the above now?" || exit 1

# --- terminate per region --------------------------------------------------
for region in $(all_regions); do
    ids=$(ids_in_region "$region" | tr '\n' ' ')
    [ -n "${ids// }" ] || continue
    log "[$region] terminating: $ids"
    aws ec2 terminate-instances --region "$region" --instance-ids $ids >/dev/null
done

log "waiting for termination ..."
for region in $(all_regions); do
    ids=$(ids_in_region "$region" | tr '\n' ' ')
    [ -n "${ids// }" ] || continue
    aws ec2 wait instance-terminated --region "$region" --instance-ids $ids || true
    log "[$region] terminated"
done

# --- optional: SGs + key pairs --------------------------------------------
if [ "$FULL" = 1 ]; then
    for region in $(all_regions); do
        gid=$(aws ec2 describe-security-groups --region "$region" \
                --filters "Name=group-name,Values=$SG_NAME" \
                --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || echo None)
        if [ "$gid" != None ] && [ -n "$gid" ]; then
            # SG deletion can race instance ENI cleanup; retry briefly.  Track
            # success explicitly -- the loop's exit status is the trailing sleep
            # (always 0), so `done || ...` would never fire on total failure.
            deleted=0
            for _ in 1 2 3 4 5; do
                if aws ec2 delete-security-group --region "$region" --group-id "$gid" 2>/dev/null; then
                    log "[$region] deleted SG $gid"; deleted=1; break
                fi
                sleep 6
            done
            [ "$deleted" = 1 ] || log "[$region] WARN: could not delete SG $gid (still in use?)"
        fi
        if aws ec2 describe-key-pairs --region "$region" --key-names "$KEY_NAME" >/dev/null 2>&1; then
            aws ec2 delete-key-pair --region "$region" --key-name "$KEY_NAME" >/dev/null
            log "[$region] deleted key pair $KEY_NAME"
        fi
    done
    log "note: local $KEY_PEM / $KEY_PEM.pub kept (delete by hand if you want them gone)"
fi

# archive the manifest so a stale instances.json can't drive a later script
mv -f "$INSTANCES_JSON" "$INSTANCES_JSON.terminated" 2>/dev/null || true
log "teardown complete. instances.json -> instances.json.terminated"
cat >&2 <<EOF

  Verify nothing is left running / costing money:
    for r in $(all_regions); do
      echo "== \$r =="; aws ec2 describe-instances --region "\$r" \\
        --filters "Name=tag:Project,Values=$PROJECT" "Name=instance-state-name,Values=running,pending" \\
        --query 'Reservations[].Instances[].InstanceId' --output text
    done
EOF
