#!/usr/bin/env bash
#
# measure_all.sh -- step-gated driver: provision -> setup -> sanity -> run -> collect.
#
# Deliberately NOT fully unattended.  Each step prompts before proceeding, and
# the sanity gate is a hard stop before the (expensive) full run.  teardown is
# NOT included: you terminate by hand AFTER confirming the data is collected, so
# an accidental run can never destroy the fleet mid-measurement.
#
# Usage: ./measure_all.sh
#   honour FORCE=1 to skip the per-step prompts (sanity still hard-gates run).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

step() { # "<name>" <script...>
    local name="$1"; shift
    echo >&2
    confirm ">>> step: $name -- run now?" || { log "skipped $name"; return 1; }
    "$@"
}

step "1/5 provision (SPENDS MONEY)" "$HERE/provision.sh"          || exit 0
step "2/5 setup (deps + clean build + fixtures)" "$HERE/setup.sh" || exit 0

# sanity is a HARD gate: a failure here aborts before the full run regardless.
echo >&2; log ">>> step 3/5 sanity gate (mandatory before full run)"
if ! "$HERE/sanity.sh"; then
    die "sanity failed -- fix the flagged pair(s) with ./setup.sh <pair> then re-run measure_all.sh"
fi

step "4/5 run (FULL measurement, parallel, hours)" "$HERE/run.sh" || exit 0
step "5/5 collect (pull + validate + combine CSVs)" "$HERE/collect.sh" || exit 0

cat >&2 <<EOF

  Pipeline finished. Results in: $RESULTS_DIR/combined.csv
  When you have confirmed the data, stop billing with:
      ./teardown.sh          # terminate instances (keep SG/key)
      ./teardown.sh --full   # also delete SGs + key pairs
EOF
