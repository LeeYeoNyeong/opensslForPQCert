#!/bin/sh
# Generate per-algorithm hybrid PQC certificate fixtures for the cross-algorithm
# e2e smoke harness (test/hybrid_smoke_test.c).
#
# For every PQC algorithm in $ALGS this produces, under ./smoke/:
#   PQC chain (Dual / Chameleon-delta / Related leaf source):
#     ca_<alg>.pem        ca_<alg>_key.pem          - PQC CA
#     server_<alg>_cert.pem server_<alg>_key.pem    - PQC leaf (issued by PQC CA)
#     client_<alg>_cert.pem client_<alg>_key.pem    - PQC leaf for mutual TLS
#   Catalyst single-certificate (RSA leaf + PQC alt key, self alt-signed):
#     catalyst_<alg>_cert.pem      - RSA leaf (issuer ca_rsa) carrying the PQC alt
#                                    public key + self alternative signature
#     catalyst_<alg>_key.pem       - RSA main private key
#     catalyst_<alg>_alt_key.pem   - PQC alternative private key (PQCertificateVerify)
# Shared classical assets (issued once, reused by every algorithm):
#     ca_rsa.pem ca_rsa_key.pem  server_rsa_cert.pem server_rsa_key.pem
#     client_rsa_cert.pem client_rsa_key.pem
#
# The Catalyst alternative-signature OID is given by the oqsprovider algorithm
# NAME (OBJ_txt2obj resolves it); openssl x509 -req then drives ALT_SIGNATURE_sign
# with the supplied alt key, so alt_sig_validate_path verifies the leaf against
# its own embedded alt public key on the receiving side.
#
# Requires the repo-built openssl with oqsprovider loadable. Set OPENSSL,
# DYLD_LIBRARY_PATH and OPENSSL_MODULES before invoking (see the recipe wrapper).
set -e

DIR=$(cd "$(dirname "$0")" && pwd)
OUT="$DIR/smoke"
mkdir -p "$OUT"

# Repo root = three levels up from test/certs/hybrid_e2e. macOS /bin/sh strips
# DYLD_* across exec (SIP), so (re)export the dynamic library path HERE, inside
# the script, rather than relying on the caller's environment surviving.
ROOT=${OPENSSL_ROOT:-$(cd "$DIR/../../.." && pwd)}
export DYLD_LIBRARY_PATH="$ROOT${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
export OPENSSL_MODULES=${OPENSSL_MODULES:-/usr/local/lib/ossl-modules}
OSSL=${OPENSSL:-$ROOT/apps/openssl}

cd "$OUT"
PROV="-provider oqsprovider -provider default"
SUBJ_CA_C="/O=PQTest/CN=Test Classical CA"
SUBJ_CA_P="/O=PQTest/CN=Test PQC CA"
SUBJ_SRV="/O=PQTest/CN=server.example.com"
SUBJ_CLI="/O=PQTest/CN=client.example.com"

# ALGS are *labels* (FIPS-205 SLH-DSA naming for SLH-DSA; identical to the
# provider name for ML-DSA / Falcon).  Labels are the primary identifier: they
# name every fixture file (ca_slhdsasha2128f.pem, ...) so the measurement
# orchestrator and binary can find the assets by label.  Only genpkey and the
# OID resolution for the Catalyst alt signature need the provider key-type name
# that oqsprovider 0.11.0 actually exposes -- prov_name() maps label->provider.
ALGS=${ALGS:-"mldsa44 mldsa65 mldsa87 falcon512 falcon1024 slhdsasha2128s slhdsasha2128f slhdsasha2192s slhdsasha2192f slhdsasha2256s slhdsasha2256f"}

prov_name() { # label -> oqsprovider algorithm name (genpkey / OBJ_txt2obj)
    case "$1" in
        slhdsasha2128s) echo sphincssha2128ssimple ;;
        slhdsasha2128f) echo sphincssha2128fsimple ;;
        slhdsasha2192s) echo sphincssha2192ssimple ;;
        slhdsasha2192f) echo sphincssha2192fsimple ;;
        slhdsasha2256s) echo sphincssha2256ssimple ;;
        slhdsasha2256f) echo sphincssha2256fsimple ;;
        # Composite SLH-DSA labels: ECDSAcurve_slhdsa... -> ECDSAcurve_sphincs...simple
        # (only the SLH-DSA component differs; the ECDSA-curve prefix is kept).
        p256_slhdsasha2128s) echo p256_sphincssha2128ssimple ;;
        p256_slhdsasha2128f) echo p256_sphincssha2128fsimple ;;
        p384_slhdsasha2192s) echo p384_sphincssha2192ssimple ;;
        p384_slhdsasha2192f) echo p384_sphincssha2192fsimple ;;
        p521_slhdsasha2256s) echo p521_sphincssha2256ssimple ;;
        p521_slhdsasha2256f) echo p521_sphincssha2256fsimple ;;
        # ML-DSA / Falcon (bare or composite): label == provider name.
        *) echo "$1" ;;
    esac
}

# --- Shared classical assets -------------------------------------------------
$OSSL genpkey $PROV -algorithm RSA -out ca_rsa_key.pem
$OSSL req -new -x509 $PROV -key ca_rsa_key.pem -out ca_rsa.pem -days 3650 -subj "$SUBJ_CA_C"

$OSSL genpkey $PROV -algorithm RSA -out server_rsa_key.pem
$OSSL req -new $PROV -key server_rsa_key.pem -out server_rsa_req.pem -subj "$SUBJ_SRV"
$OSSL x509 -req $PROV -in server_rsa_req.pem -CA ca_rsa.pem -CAkey ca_rsa_key.pem \
    -CAcreateserial -out server_rsa_cert.pem -days 3650
rm -f server_rsa_req.pem

$OSSL genpkey $PROV -algorithm RSA -out client_rsa_key.pem
$OSSL req -new $PROV -key client_rsa_key.pem -out client_rsa_req.pem -subj "$SUBJ_CLI"
$OSSL x509 -req $PROV -in client_rsa_req.pem -CA ca_rsa.pem -CAkey ca_rsa_key.pem \
    -CAcreateserial -out client_rsa_cert.pem -days 3650
rm -f client_rsa_req.pem

# --- Per-algorithm assets ----------------------------------------------------
gen_leaf() { # $1=provider_alg $2=ca_prefix $3=leaf_prefix(label) $4=subj
    # NB: use distinct names -- /bin/sh has no function-local scope, and reusing
    # the caller's loop variable "alg" here would clobber it for the next call.
    palg=$1; capfx=$2; leaf=$3; subj=$4
    $OSSL genpkey $PROV -algorithm "$palg" -out "${leaf}_key.pem"
    $OSSL req -new $PROV -key "${leaf}_key.pem" -out "${leaf}_req.pem" -subj "$subj"
    $OSSL x509 -req $PROV -in "${leaf}_req.pem" -CA "${capfx}.pem" -CAkey "${capfx}_key.pem" \
        -CAcreateserial -out "${leaf}_cert.pem" -days 3650
    rm -f "${leaf}_req.pem"
}

for alg in $ALGS; do
    echo "=== $alg ==="
    prov=$(prov_name "$alg")   # provider key-type name (genpkey / OID)
    # PQC CA  (file name = label, genpkey algorithm = provider name)
    $OSSL genpkey $PROV -algorithm "$prov" -out "ca_${alg}_key.pem"
    $OSSL req -new -x509 $PROV -key "ca_${alg}_key.pem" -out "ca_${alg}.pem" \
        -days 3650 -subj "$SUBJ_CA_P"
    # PQC server + client leaves (issued by the PQC CA)
    gen_leaf "$prov" "ca_${alg}" "server_${alg}" "$SUBJ_SRV"
    gen_leaf "$prov" "ca_${alg}" "client_${alg}" "$SUBJ_CLI"

    # Catalyst: RSA leaf carrying the PQC alt key, self alternative-signed.
    $OSSL genpkey $PROV -algorithm "$prov" -out "catalyst_${alg}_alt_key.pem"
    $OSSL pkey $PROV -in "catalyst_${alg}_alt_key.pem" -pubout -out "catalyst_${alg}_alt_pub.pem"
    $OSSL genpkey $PROV -algorithm RSA -out "catalyst_${alg}_key.pem"
    $OSSL req -new $PROV -key "catalyst_${alg}_key.pem" -out "catalyst_${alg}_req.pem" -subj "$SUBJ_SRV"
    cat > "catalyst_${alg}.ext" <<EOF
subjectAltPublicKeyInfo = file:catalyst_${alg}_alt_pub.pem
altSignatureAlgorithm = ${prov}
altSignatureValue = file:catalyst_${alg}_alt_key.pem
EOF
    $OSSL x509 -req $PROV -in "catalyst_${alg}_req.pem" \
        -CA ca_rsa.pem -CAkey ca_rsa_key.pem -CAcreateserial \
        -out "catalyst_${alg}_cert.pem" -days 3650 -extfile "catalyst_${alg}.ext"
    rm -f "catalyst_${alg}_req.pem" "catalyst_${alg}.ext" "catalyst_${alg}_alt_pub.pem"
done

# --- Composite single-certificate control ------------------------------------
# draft-ounsworth-style composite: a SINGLE leaf whose key is an oqsprovider
# composite sigalg (ECDSA curve paired to the PQC security level).  No alt key,
# no separate PQC chain -- it is the pure-PQC single-cert wiring with a composite
# key, so only the ca/server/client leaves are issued (matching build_pure /
# build_composite in hybrid_fixtures.c).  Labels equal the provider name for
# ML-DSA / Falcon; for SLH-DSA the label keeps the FIPS-205 slhdsa naming
# (p256_slhdsasha2128f) while genpkey uses the provider name via prov_name().
COMPOSITE_ALGS=${COMPOSITE_ALGS:-"p256_mldsa44 p384_mldsa65 p521_mldsa87 \
p256_falcon512 p521_falcon1024 \
p256_slhdsasha2128s p256_slhdsasha2128f \
p384_slhdsasha2192s p384_slhdsasha2192f \
p521_slhdsasha2256s p521_slhdsasha2256f"}

for clabel in $COMPOSITE_ALGS; do
    echo "=== composite $clabel ==="
    cprov=$(prov_name "$clabel")   # provider sigalg name (genpkey)
    # Composite CA (file name = label, genpkey algorithm = provider name)
    $OSSL genpkey $PROV -algorithm "$cprov" -out "ca_${clabel}_key.pem"
    $OSSL req -new -x509 $PROV -key "ca_${clabel}_key.pem" -out "ca_${clabel}.pem" \
        -days 3650 -subj "$SUBJ_CA_P"
    # Composite server + client leaves (issued by the composite CA)
    gen_leaf "$cprov" "ca_${clabel}" "server_${clabel}" "$SUBJ_SRV"
    gen_leaf "$cprov" "ca_${clabel}" "client_${clabel}" "$SUBJ_CLI"
done

# --- Traditional ECDSA baseline (security-level paired control) --------------
# P-256 (Cat1), P-384 (Cat3), P-521 (Cat5).  Used by the measurement binary's
# "traditional" format as the classical-only baseline.
gen_ecdsa() { # $1=tag $2=curve
    tag=$1; curve=$2
    $OSSL genpkey $PROV -algorithm EC -pkeyopt "ec_paramgen_curve:$curve" \
        -out "ca_ecdsa_${tag}_key.pem"
    $OSSL req -new -x509 $PROV -key "ca_ecdsa_${tag}_key.pem" \
        -out "ca_ecdsa_${tag}.pem" -days 3650 -subj "$SUBJ_CA_C"
    $OSSL genpkey $PROV -algorithm EC -pkeyopt "ec_paramgen_curve:$curve" \
        -out "ecdsa_${tag}_key.pem"
    $OSSL req -new $PROV -key "ecdsa_${tag}_key.pem" \
        -out "ecdsa_${tag}_req.pem" -subj "$SUBJ_SRV"
    $OSSL x509 -req $PROV -in "ecdsa_${tag}_req.pem" \
        -CA "ca_ecdsa_${tag}.pem" -CAkey "ca_ecdsa_${tag}_key.pem" \
        -CAcreateserial -out "ecdsa_${tag}_cert.pem" -days 3650
    rm -f "ecdsa_${tag}_req.pem"
}

gen_ecdsa p256 P-256
gen_ecdsa p384 P-384
gen_ecdsa p521 P-521

echo "Generated smoke cert assets in $OUT for: $ALGS"
echo "  composite: $COMPOSITE_ALGS"
echo "  + ECDSA p256/p384/p521"
