#!/usr/bin/env bash
#
# setup.sh -- provision dependencies, build the measurement binary CLEAN, and
# distribute identical certificate fixtures to all 6 instances.
#
# Per instance (run in parallel over SSH):
#   * apt: build-essential git iproute2 cmake ninja-build perl pkg-config libssl-dev
#   * liboqs $LIBOQS_REF  -> /usr/local
#   * oqs-provider $OQSPROV_REF -> $REMOTE_MODULES/oqsprovider.so
#   * clone fork @ $REPO_BRANCH
#   * CLEAN measurement build: make clean && ./Configure -DHYBRID_MEASURE && make
#     (clean is MANDATORY -- HYBRID_MEASURE changes the SSL_CONNECTION layout;
#      an incremental build => ABI skew => zeroed crypto columns)
#   * verify oqsprovider exposes mldsa/falcon/sphincs(SLH-DSA) signature algs
#
# Fixtures are generated ONCE (on the tokyo client) and copied to every host so
# server and client present/trust byte-identical certificates.
#
# Usage: ./setup.sh            # all instances
#        ./setup.sh <pair>     # just one pair's 2 instances (debug)
set -euo pipefail
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
preflight_local
require_instances

LOGDIR="$AWS_DIR/setup_logs"; mkdir -p "$LOGDIR"

# --- remote build script (runs on each instance; args are positional) ------
# Quoted heredoc => no local expansion; the instance receives it verbatim.
remote_build_body() {
cat <<'REMOTE'
set -euo pipefail
LIBOQS_REF="$1"; OQSPROV_REF="$2"; REPO_URL="$3"; REPO_BRANCH="$4"; JOBS="$5"; MODULES="$6"
export DEBIAN_FRONTEND=noninteractive

echo "::: apt deps"
sudo apt-get update -y
sudo apt-get install -y build-essential git iproute2 cmake ninja-build perl pkg-config libssl-dev

# Rebuild deps unless an oqsprovider built from the SAME pinned refs is present.
# A stamp file records the (liboqs|oqs-provider) refs the module was built from,
# so changing a ref forces a rebuild instead of silently reusing stale bits.
STAMP="$HOME/.oqs_refs"
# The trailing marker is bumped whenever the build recipe changes in a way that
# the refs alone don't capture (here: the SLH-DSA 192s/256s/256f generate.yml
# patch). This invalidates stamps from instances built before the patch so they
# rebuild instead of silently reusing a module missing those three variants.
WANT="$LIBOQS_REF|$OQSPROV_REF|slhdsa6"
if [ -f "$MODULES/oqsprovider.so" ] && [ "$(cat "$STAMP" 2>/dev/null)" = "$WANT" ]; then
  echo "::: oqsprovider already built from $WANT, skipping liboqs/oqs-provider"
else
  echo "::: liboqs $LIBOQS_REF"
  rm -rf ~/liboqs
  git clone --depth 1 --branch "$LIBOQS_REF" https://github.com/open-quantum-safe/liboqs.git ~/liboqs
  cmake -S ~/liboqs -B ~/liboqs/build -GNinja -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local
  ninja -C ~/liboqs/build
  sudo ninja -C ~/liboqs/build install
  sudo ldconfig

  echo "::: oqs-provider $OQSPROV_REF"
  rm -rf ~/oqs-provider
  git clone https://github.com/open-quantum-safe/oqs-provider.git ~/oqs-provider
  git -C ~/oqs-provider checkout "$OQSPROV_REF"

  # 0.11.0 ships SLH-DSA 192s/256s/256f as enable:false (only enable_tls:true).
  # Flip them on and regenerate the provider sources so all six SLH-DSA variants
  # are registered. A fresh checkout reverts generate.yml, so this runs on every
  # (re)build, BEFORE cmake. Any failure is fatal -- never silently skip.
  echo "::: enable SLH-DSA 192s/256s/256f in generate.yml + regenerate sources"
  pip3 install --quiet --break-system-packages jinja2 pyyaml tabulate 2>/dev/null || \
    sudo apt-get install -y python3-jinja2 python3-yaml python3-tabulate
  ( cd ~/oqs-provider && python3 - <<'PYEOF'
import sys
f = 'oqs-template/generate.yml'
lines = open(f).read().split('\n')
targets = ['sphincssha2192ssimple', 'sphincssha2256ssimple', 'sphincssha2256fsimple']
def flip(target):
    in_block = False
    for i, ln in enumerate(lines):
        st = ln.strip()
        if st.startswith('- name:') or st.startswith('name:'):
            in_block = (("'%s'" % target) in ln)
            continue
        if in_block and st == 'enable: false':
            lines[i] = ln.replace('enable: false', 'enable: true')
            return True
        if in_block and st == 'enable: true':
            return True  # already enabled
    return False
for t in targets:
    if not flip(t):
        sys.stderr.write("FATAL: could not enable %s in generate.yml\n" % t)
        sys.exit(1)
open(f, 'w').write('\n'.join(lines))
print("generate.yml: SLH-DSA 192s/256s/256f set enable:true")
PYEOF
  ) || { echo "FATAL: generate.yml SLH-DSA patch failed" >&2; exit 4; }
  ( cd ~/oqs-provider && python3 oqs-template/generate.py ) \
    || { echo "FATAL: oqs-provider generate.py failed" >&2; exit 4; }

  cmake -S ~/oqs-provider -B ~/oqs-provider/build -GNinja \
        -Dliboqs_DIR=/usr/local/lib/cmake/liboqs -DOPENSSL_ROOT_DIR=/usr \
        -DCMAKE_INSTALL_PREFIX=/usr/local
  ninja -C ~/oqs-provider/build
  sudo mkdir -p "$MODULES"
  # module is emitted under build/lib/ as a regular file -- restrict to a real
  # file so we never cp the cmake 'oqsprovider.dir' build directory by mistake.
  sudo cp "$(find ~/oqs-provider/build -name 'oqsprovider.so' -type f | head -1)" "$MODULES/"
  echo "$WANT" > "$STAMP"   # record the refs this module was built from
fi

echo "::: clone fork @ $REPO_BRANCH"
if [ ! -d ~/opensslForPQCert/.git ]; then
  git clone --branch "$REPO_BRANCH" "$REPO_URL" ~/opensslForPQCert \
    || { git clone "$REPO_URL" ~/opensslForPQCert; git -C ~/opensslForPQCert checkout "$REPO_BRANCH"; }
else
  git -C ~/opensslForPQCert fetch --all -q
  git -C ~/opensslForPQCert checkout "$REPO_BRANCH"
  git -C ~/opensslForPQCert pull -q || true
fi

cd ~/opensslForPQCert
echo "::: CLEAN HYBRID_MEASURE build (mandatory)"
make clean >/dev/null 2>&1 || true
./Configure -DHYBRID_MEASURE
make -j"$JOBS"
make -j"$JOBS" test/hybrid_measure

echo "::: oqsprovider load check"
# Include /usr/local/lib (liboqs.so) so the provider resolves, and load it
# explicitly -- a bare `list` only loads the default provider and would report
# no PQC algorithms even when oqsprovider.so is installed.
export LD_LIBRARY_PATH="$HOME/opensslForPQCert:/usr/local/lib"
export OPENSSL_MODULES="$MODULES"
if ~/opensslForPQCert/apps/openssl list -signature-algorithms -provider oqsprovider 2>/dev/null \
     | grep -iqE 'mldsa|falcon|sphincs'; then
  echo "OQS_OK"
else
  echo "OQS_FAIL: mldsa/falcon/sphincs not exposed (oqsprovider not loaded)" >&2
  exit 3
fi
echo "SETUP_OK"
REMOTE
}

setup_one() { # $1=role $2=pair $3=ip   (runs foreground; caller backgrounds it)
    local role="$1" pair="$2" ip="$3" lf="$LOGDIR/${1}_${2}.log"
    {
        echo "=== setup $role/$pair ($ip) ==="
        remote_build_body | ssh_to "$ip" "bash -s -- \
            '$LIBOQS_REF' '$OQSPROV_REF' '$REPO_URL' '$REPO_BRANCH' '$BUILD_JOBS' '$REMOTE_MODULES'"
    } >"$lf" 2>&1
}

# --- fan out setup over the selected instances -----------------------------
# Background directly in this loop so the PIDs are direct children (waitable).
FILTER="${1:-}"
PIDS=(); NAMES=()
while IFS=$'\t' read -r pair role region id pub priv; do
    [ -n "$FILTER" ] && [ "$pair" != "$FILTER" ] && continue
    log "starting setup: $role/$pair @ $pub (log: setup_logs/${role}_${pair}.log)"
    setup_one "$role" "$pair" "$pub" &
    PIDS+=("$!")
    NAMES+=("$role/$pair")
done < <(inst_rows)

# --- wait + report ---------------------------------------------------------
FAIL=0
for i in "${!PIDS[@]}"; do
    if wait "${PIDS[$i]}"; then
        if tail -3 "$LOGDIR/$(echo "${NAMES[$i]}" | tr '/' '_').log" | grep -q SETUP_OK; then
            log "OK   ${NAMES[$i]}"
        else
            log "FAIL ${NAMES[$i]} (no SETUP_OK marker)"; FAIL=1
        fi
    else
        log "FAIL ${NAMES[$i]} (ssh/build exited non-zero; see log)"; FAIL=1
    fi
done
[ "$FAIL" = 0 ] || die "one or more instances failed setup; inspect setup_logs/ and re-run ./setup.sh <pair>"

# --- fixtures: generate ONCE, distribute to all (identical CA trust) -------
if [ -n "$FILTER" ]; then
    log "single-pair run -- skipping fixture (re)distribution; run full ./setup.sh to redistribute"
    exit 0
fi

GEN_IP="$(inst_field tokyo client public_ip)"
log "generating fixtures once on tokyo client ($GEN_IP)"
ssh_to "$GEN_IP" "set -e
  export LD_LIBRARY_PATH=$REMOTE_REPO OPENSSL_MODULES=$REMOTE_MODULES
  cd $REMOTE_HYBRID
  OPENSSL=$REMOTE_REPO/apps/openssl ./gen_smoke_certs.sh
  tar czf /tmp/smoke.tgz -C $REMOTE_HYBRID smoke"
scp_from "$GEN_IP" "/tmp/smoke.tgz" "$AWS_DIR/smoke.tgz"
log "fixtures pulled -> $AWS_DIR/smoke.tgz"

while IFS=$'\t' read -r pair role region id pub priv; do
    [ "$pub" = "$GEN_IP" ] && { log "skip fixture push to generator ($role/$pair)"; continue; }
    log "pushing fixtures -> $role/$pair ($pub)"
    scp_to "$pub" "$AWS_DIR/smoke.tgz" "/tmp/smoke.tgz"
    ssh_to "$pub" "tar xzf /tmp/smoke.tgz -C $REMOTE_HYBRID"
done < <(inst_rows)

log "setup complete on all 6 instances. Next: ./sanity.sh"
