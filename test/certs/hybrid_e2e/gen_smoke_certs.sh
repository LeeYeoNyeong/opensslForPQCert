#!/bin/sh
# Generate per-algorithm hybrid PQC certificate fixtures for the cross-algorithm
# e2e smoke harness (test/hybrid_smoke_test.c) and the AWS measurement binary
# (test/hybrid_measure).
#
# REALISTIC 3-TIER PKI (Root CA -> Intermediate CA -> Leaf), per the paper:
#   * Root CA : self-signed, CA:TRUE.               File: ca_<x>.pem (trust anchor)
#   * ICA     : issued by Root, CA:TRUE pathlen:0.   File: ica_<x>.pem
#   * Leaf    : issued by ICA, CA:FALSE + EKU.       Transmitted chain = leaf + ICA
#
# The transmitted server certificate file is therefore TWO certs (leaf then ICA);
# the client's trust anchor is the Root only.  For every chain type this yields:
#   ca_<x>.pem   ca_<x>_key.pem      - Root CA (trust anchor)
#   ica_<x>.pem  ica_<x>_key.pem     - Intermediate CA
#   server_<x>_cert.pem              - leaf + ICA  (2 certs; leaf issued by ICA)
#   server_<x>_key.pem               - leaf private key
#   client_<x>_cert.pem client_<x>_key.pem - client leaf (+ ICA) for mutual TLS
#
# Per-algorithm chains produced:
#   PQC chain (Dual PQC leaf / Chameleon-delta / Related PQC leaf source / Pure):
#     ca_<alg>, ica_<alg>, server_<alg>, client_<alg>
#   Catalyst FULL alternative-signature chain (single-certificate hybrid):
#     ca_catalyst_<alg>, ica_catalyst_<alg> : ECDSA CA certs each carrying a PQC
#         alternative key (subjectAltPublicKeyInfo) and an altSignatureValue
#         signed by the PARENT's alt key (root self-alt-signed).  This forms the
#         alt-signature chain that X509v3_alt_sig_validate_path() walks.
#     catalyst_<alg>_cert.pem : leaf (+ ICA) whose altSignatureValue is signed by
#         the ICA's alt key; subjectAltPublicKeyInfo is the leaf's own alt pubkey.
#     catalyst_<alg>_key.pem      - ECDSA main private key (curve paired to the
#         PQC alt key's NIST category via cat_curve())
#     catalyst_<alg>_alt_key.pem  - leaf PQC alt private key (PQCertificateVerify PoP)
# Per-algorithm classical ECDSA chain (the traditional component of the
# dual/related/chameleon hybrids; curve paired to the PQC leaf's NIST category
# per cat_curve(), matching the composite ECDSA pairing and the paper's stated
# "ECDSA P-384 with ML-DSA-65"-style pairing):
#   ca_class_<alg>, ica_class_<alg>, server_class_<alg>, client_class_<alg>
# Composite single-certificate control chain (per ECDSA-paired composite label):
#   ca_<clabel>, ica_<clabel>, server_<clabel>, client_<clabel>
# Traditional ECDSA baseline (per curve tag p256/p384/p521):
#   ca_ecdsa_<tag>, ica_ecdsa_<tag>, ecdsa_<tag>
#
# Requires the repo-built openssl with oqsprovider loadable. Set OPENSSL,
# DYLD_LIBRARY_PATH and OPENSSL_MODULES before invoking (see the recipe wrapper).
# OUT is overridable (default ./smoke) so a test run cannot clobber committed
# fixtures -- run against a throwaway dir when validating changes.
set -e

DIR=$(cd "$(dirname "$0")" && pwd)
OUT="${OUT:-$DIR/smoke}"
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
SUBJ_CA_C="/O=PQTest/CN=Test Classical Root CA"
SUBJ_ICA_C="/O=PQTest/CN=Test Classical ICA"
SUBJ_CA_P="/O=PQTest/CN=Test PQC Root CA"
SUBJ_ICA_P="/O=PQTest/CN=Test PQC ICA"
SUBJ_SRV="/O=PQTest/CN=server.example.com"
SUBJ_CLI="/O=PQTest/CN=client.example.com"

# Fail loudly if an expected output was not produced.  apps/openssl can return
# rc=0 even when a provider key type is unavailable (e.g. oqsprovider not yet
# rebuilt against the fork libcrypto, so SLH-DSA / composite genpkey writes no
# file), so `set -e` alone does NOT catch a silently-skipped cert.  Every
# generator below therefore (a) removes its target up front, so a stale file
# from a previous run cannot mask a failure, and (b) asserts its outputs exist
# and are non-empty via need().
die()  { echo "FATAL: gen_smoke_certs.sh: $*" >&2; exit 1; }
need() { for _f in "$@"; do [ -s "$_f" ] || die "missing/empty output: $OUT/$_f"; done; }

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

# cat_curve: map a bare PQC label to the ECDSA curve of its NIST security
# category, so the *classical* component of a hybrid is paired with an
# equivalent-strength ECDSA key (as the paper states: "ML-DSA-65 is NIST Cat3,
# paired with ECDSA P-384").  This is the SAME curve the composite control uses
# for the corresponding level, keeping catalyst/dual/related/chameleon
# consistent with composite/traditional.  Unknown labels are fatal so a typo
# cannot silently fall back to the wrong curve.
#   Cat1 -> P-256 : mldsa44, falcon512, slhdsa128 (s/f)
#   Cat3 -> P-384 : mldsa65, slhdsa192 (s/f)
#   Cat5 -> P-521 : mldsa87, falcon1024, slhdsa256 (s/f)
cat_curve() { # $1 = bare PQC label
    case "$1" in
        mldsa44|falcon512|slhdsasha2128s|slhdsasha2128f)   echo P-256 ;;
        mldsa65|slhdsasha2192s|slhdsasha2192f)             echo P-384 ;;
        mldsa87|falcon1024|slhdsasha2256s|slhdsasha2256f)  echo P-521 ;;
        *) die "cat_curve: no NIST-category ECDSA curve mapping for '$1'" ;;
    esac
}

# --- key generation (algspec: RSA | EC:CURVE | <provider-alg>) ----------------
keygen() { # $1=outfile $2=algspec
    rm -f "$1"
    case "$2" in
        EC:*) $OSSL genpkey $PROV -algorithm EC \
                  -pkeyopt "ec_paramgen_curve:${2#EC:}" -out "$1" ;;
        *)    $OSSL genpkey $PROV -algorithm "$2" -out "$1" ;;
    esac
    need "$1"
}

# --- Root + Intermediate CA (self-signed Root, ICA issued by Root) -----------
gen_root_ica() { # $1=pfx $2=algspec $3=subj_root $4=subj_ica
    _pfx=$1; _alg=$2; _sroot=$3; _sica=$4
    rm -f "ca_${_pfx}_key.pem" "ca_${_pfx}.pem" \
          "ica_${_pfx}_key.pem" "ica_${_pfx}.pem" "ica_${_pfx}_req.pem" "ica_${_pfx}.ext"
    keygen "ca_${_pfx}_key.pem" "$_alg"
    $OSSL req -new -x509 $PROV -key "ca_${_pfx}_key.pem" -out "ca_${_pfx}.pem" \
        -days 3650 -subj "$_sroot" -addext "basicConstraints=critical,CA:TRUE"
    need "ca_${_pfx}.pem"
    keygen "ica_${_pfx}_key.pem" "$_alg"
    $OSSL req -new $PROV -key "ica_${_pfx}_key.pem" -out "ica_${_pfx}_req.pem" -subj "$_sica"
    printf 'basicConstraints = critical,CA:TRUE,pathlen:0\n' > "ica_${_pfx}.ext"
    $OSSL x509 -req $PROV -in "ica_${_pfx}_req.pem" \
        -CA "ca_${_pfx}.pem" -CAkey "ca_${_pfx}_key.pem" -CAcreateserial \
        -out "ica_${_pfx}.pem" -days 3650 -extfile "ica_${_pfx}.ext"
    rm -f "ica_${_pfx}_req.pem" "ica_${_pfx}.ext"
    need "ica_${_pfx}.pem"
}

# --- leaf issued by an ICA; output cert file = leaf + ICA (transmitted chain) -
gen_leaf3() { # $1=algspec $2=ica_pfx $3=leaf_pfx $4=subj $5=eku
    _alg=$1; _ica=$2; _leaf=$3; _subj=$4; _eku=$5
    rm -f "${_leaf}_key.pem" "${_leaf}_cert.pem" "${_leaf}_req.pem" \
          "${_leaf}.ext" "${_leaf}_leaf.pem"
    keygen "${_leaf}_key.pem" "$_alg"
    $OSSL req -new $PROV -key "${_leaf}_key.pem" -out "${_leaf}_req.pem" -subj "$_subj"
    printf 'basicConstraints = critical,CA:FALSE\nextendedKeyUsage = %s\n' "$_eku" \
        > "${_leaf}.ext"
    $OSSL x509 -req $PROV -in "${_leaf}_req.pem" \
        -CA "ica_${_ica}.pem" -CAkey "ica_${_ica}_key.pem" -CAcreateserial \
        -out "${_leaf}_leaf.pem" -days 3650 -extfile "${_leaf}.ext"
    need "${_leaf}_leaf.pem"
    cat "${_leaf}_leaf.pem" "ica_${_ica}.pem" > "${_leaf}_cert.pem"
    rm -f "${_leaf}_req.pem" "${_leaf}.ext" "${_leaf}_leaf.pem"
    need "${_leaf}_cert.pem"
}

# --- Catalyst full alternative-signature 3-tier chain ------------------------
# Root/ICA/Leaf are all RSA certs carrying a PQC alternative key; each cert's
# altSignatureValue is signed by its PARENT's alt key (Root self-alt-signed), so
# X509v3_alt_sig_validate_path() verifies leaf->ICA->Root alt signatures.  Only
# the leaf's alt private key is used at handshake time (PQCertificateVerify PoP).
# The Catalyst chain is deliberately SEPARATE from the shared plain RSA chain:
# putting an alt key on the shared Root would make the alt-signature walk require
# alt keys on the plain dual/related/chameleon RSA leaves too, which they lack.
gen_catalyst() { # $1=label $2=provider_alg
    _clab=$1; _palg=$2
    _ccurve=$(cat_curve "$_clab")   # traditional (main) key: category-paired ECDSA
    for _who in "ca_catalyst_${_clab}" "ica_catalyst_${_clab}" "catalyst_${_clab}"; do
        keygen "${_who}_alt_key.pem" "$_palg"
        rm -f "${_who}_alt_pub.pem"
        $OSSL pkey $PROV -in "${_who}_alt_key.pem" -pubout -out "${_who}_alt_pub.pem"
        need "${_who}_alt_pub.pem"
        keygen "${_who}_key.pem" "EC:$_ccurve"
    done

    # ROOT: self-signed CA, alt-signed by its OWN alt key (top self-check).
    rm -f "ca_catalyst_${_clab}.pem" "ca_catalyst_${_clab}_req.pem" "ca_catalyst_${_clab}.ext"
    $OSSL req -new $PROV -key "ca_catalyst_${_clab}_key.pem" \
        -out "ca_catalyst_${_clab}_req.pem" -subj "$SUBJ_CA_P"
    cat > "ca_catalyst_${_clab}.ext" <<EOF
basicConstraints = critical,CA:TRUE
subjectAltPublicKeyInfo = file:ca_catalyst_${_clab}_alt_pub.pem
altSignatureAlgorithm = ${_palg}
altSignatureValue = file:ca_catalyst_${_clab}_alt_key.pem
EOF
    $OSSL x509 -req $PROV -in "ca_catalyst_${_clab}_req.pem" \
        -signkey "ca_catalyst_${_clab}_key.pem" -out "ca_catalyst_${_clab}.pem" \
        -days 3650 -extfile "ca_catalyst_${_clab}.ext"
    need "ca_catalyst_${_clab}.pem"

    # ICA: issued by Root, alt-signed by ROOT's alt key.
    rm -f "ica_catalyst_${_clab}.pem" "ica_catalyst_${_clab}_req.pem" "ica_catalyst_${_clab}.ext"
    $OSSL req -new $PROV -key "ica_catalyst_${_clab}_key.pem" \
        -out "ica_catalyst_${_clab}_req.pem" -subj "$SUBJ_ICA_P"
    cat > "ica_catalyst_${_clab}.ext" <<EOF
basicConstraints = critical,CA:TRUE,pathlen:0
subjectAltPublicKeyInfo = file:ica_catalyst_${_clab}_alt_pub.pem
altSignatureAlgorithm = ${_palg}
altSignatureValue = file:ca_catalyst_${_clab}_alt_key.pem
EOF
    $OSSL x509 -req $PROV -in "ica_catalyst_${_clab}_req.pem" \
        -CA "ca_catalyst_${_clab}.pem" -CAkey "ca_catalyst_${_clab}_key.pem" -CAcreateserial \
        -out "ica_catalyst_${_clab}.pem" -days 3650 -extfile "ica_catalyst_${_clab}.ext"
    need "ica_catalyst_${_clab}.pem"

    # LEAF: issued by ICA, alt-signed by ICA's alt key; subjectAltPub = leaf own.
    rm -f "catalyst_${_clab}_cert.pem" "catalyst_${_clab}_leaf.pem" \
          "catalyst_${_clab}_req.pem" "catalyst_${_clab}.ext"
    $OSSL req -new $PROV -key "catalyst_${_clab}_key.pem" \
        -out "catalyst_${_clab}_req.pem" -subj "$SUBJ_SRV"
    cat > "catalyst_${_clab}.ext" <<EOF
basicConstraints = critical,CA:FALSE
extendedKeyUsage = serverAuth,clientAuth
subjectAltPublicKeyInfo = file:catalyst_${_clab}_alt_pub.pem
altSignatureAlgorithm = ${_palg}
altSignatureValue = file:ica_catalyst_${_clab}_alt_key.pem
EOF
    $OSSL x509 -req $PROV -in "catalyst_${_clab}_req.pem" \
        -CA "ica_catalyst_${_clab}.pem" -CAkey "ica_catalyst_${_clab}_key.pem" -CAcreateserial \
        -out "catalyst_${_clab}_leaf.pem" -days 3650 -extfile "catalyst_${_clab}.ext"
    need "catalyst_${_clab}_leaf.pem"
    cat "catalyst_${_clab}_leaf.pem" "ica_catalyst_${_clab}.pem" > "catalyst_${_clab}_cert.pem"
    need "catalyst_${_clab}_cert.pem"

    # Runtime needs only: ca_catalyst (trust), catalyst_<clab>_cert (leaf+ICA),
    # catalyst_<clab>_key (leaf main), catalyst_<clab>_alt_key (leaf PoP).  Drop
    # the generation-only material (Root/ICA alt private keys, pubs, reqs, exts).
    rm -f "ca_catalyst_${_clab}_alt_key.pem" "ica_catalyst_${_clab}_alt_key.pem" \
          "ca_catalyst_${_clab}_alt_pub.pem" "ica_catalyst_${_clab}_alt_pub.pem" \
          "catalyst_${_clab}_alt_pub.pem" \
          "ca_catalyst_${_clab}_req.pem" "ica_catalyst_${_clab}_req.pem" "catalyst_${_clab}_req.pem" \
          "ca_catalyst_${_clab}.ext" "ica_catalyst_${_clab}.ext" "catalyst_${_clab}.ext" \
          "catalyst_${_clab}_leaf.pem"
}

# --- Per-algorithm PQC chain + classical ECDSA chain + Catalyst alt-chain -----
# The classical component of dual/related/chameleon is a dedicated per-algorithm
# ECDSA 3-tier chain whose curve is paired to the PQC leaf's NIST category
# (cat_curve()), NOT a single shared RSA chain.  Pairing an equal-strength ECDSA
# key with each PQC algorithm matches the paper's stated pairing and the
# composite control's ECDSA-curve selection, and removes the RSA size/perf skew.
for alg in $ALGS; do
    echo "=== $alg ==="
    prov=$(prov_name "$alg")   # provider key-type name (genpkey / OID)
    curve=$(cat_curve "$alg")  # category-paired ECDSA curve for the classical side
    gen_root_ica "$alg" "$prov" "$SUBJ_CA_P" "$SUBJ_ICA_P"
    gen_leaf3 "$prov" "$alg" "server_${alg}" "$SUBJ_SRV" serverAuth
    gen_leaf3 "$prov" "$alg" "client_${alg}" "$SUBJ_CLI" clientAuth
    # Classical ECDSA chain (traditional component of dual/related/chameleon).
    gen_root_ica "class_${alg}" "EC:$curve" "$SUBJ_CA_C" "$SUBJ_ICA_C"
    gen_leaf3 "EC:$curve" "class_${alg}" "server_class_${alg}" "$SUBJ_SRV" serverAuth
    gen_leaf3 "EC:$curve" "class_${alg}" "client_class_${alg}" "$SUBJ_CLI" clientAuth
    gen_catalyst "$alg" "$prov"
done

# --- Composite single-certificate control ------------------------------------
# draft-ounsworth-style composite: a SINGLE leaf whose key is an oqsprovider
# composite sigalg (ECDSA curve paired to the PQC security level).  No alt key,
# no separate PQC chain -- it is the pure-PQC single-cert wiring with a composite
# key, so only the ca/ica/server/client certs are issued (matching build_pure /
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
    gen_root_ica "$clabel" "$cprov" "$SUBJ_CA_P" "$SUBJ_ICA_P"
    gen_leaf3 "$cprov" "$clabel" "server_${clabel}" "$SUBJ_SRV" serverAuth
    gen_leaf3 "$cprov" "$clabel" "client_${clabel}" "$SUBJ_CLI" clientAuth
done

# --- Traditional ECDSA baseline (security-level paired control) --------------
# P-256 (Cat1), P-384 (Cat3), P-521 (Cat5).  Used by the measurement binary's
# "traditional" format as the classical-only baseline.
gen_ecdsa() { # $1=tag $2=curve
    gen_root_ica "ecdsa_$1" "EC:$2" "$SUBJ_CA_C" "$SUBJ_ICA_C"
    gen_leaf3 "EC:$2" "ecdsa_$1" "ecdsa_$1" "$SUBJ_SRV" serverAuth
}

gen_ecdsa p256 P-256
gen_ecdsa p384 P-384
gen_ecdsa p521 P-521

# --- Final self-check: every expected asset must exist & be non-empty --------
# This is the backstop against apps/openssl's rc=0-on-failure behaviour: even if
# a per-step need() were ever missed, no fixture set is declared good unless the
# complete expected manifest (every bare alg, every composite alg, ECDSA, RSA,
# and the 3-tier Root+ICA of each) is present.  Missing entries are collected
# and reported together, then fatal.
missing=
chk() { [ -s "$OUT/$1" ] || missing="$missing $1"; }
chk_chain() { # $1=pfx  -- Root + ICA + server/client leaf files
    chk "ca_$1.pem";          chk "ca_$1_key.pem"
    chk "ica_$1.pem";         chk "ica_$1_key.pem"
    chk "server_$1_cert.pem"; chk "server_$1_key.pem"
    chk "client_$1_cert.pem"; chk "client_$1_key.pem"
}
for alg in $ALGS; do
    chk_chain "$alg"
    # Classical ECDSA chain (traditional component of dual/related/chameleon).
    chk_chain "class_$alg"
    # Catalyst full alt-chain: Root + ICA (public) + leaf (leaf+ICA) + keys.
    chk "ca_catalyst_${alg}.pem";     chk "ca_catalyst_${alg}_key.pem"
    chk "ica_catalyst_${alg}.pem";    chk "ica_catalyst_${alg}_key.pem"
    chk "catalyst_${alg}_cert.pem";   chk "catalyst_${alg}_key.pem"
    chk "catalyst_${alg}_alt_key.pem"
done
for clabel in $COMPOSITE_ALGS; do
    chk_chain "$clabel"
done
for t in p256 p384 p521; do
    chk "ca_ecdsa_${t}.pem";   chk "ca_ecdsa_${t}_key.pem"
    chk "ica_ecdsa_${t}.pem";  chk "ica_ecdsa_${t}_key.pem"
    chk "ecdsa_${t}_cert.pem"; chk "ecdsa_${t}_key.pem"
done
[ -z "$missing" ] || die "self-check failed; missing/empty fixtures:$missing"

echo "Generated 3-tier smoke cert assets in $OUT for: $ALGS"
echo "  composite: $COMPOSITE_ALGS"
echo "  + ECDSA p256/p384/p521 baseline, per-alg classical ECDSA chain,"
echo "    per-alg Catalyst ECDSA-base alt-chain"
