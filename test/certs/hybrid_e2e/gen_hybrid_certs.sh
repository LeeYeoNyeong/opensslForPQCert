#!/bin/sh
# Generate hybrid PQC certificate test assets for the Phase 4 e2e harness.
#
# Produces, into this directory:
#   Dual (multi-certificate) format:
#     classical chain  : ca_rsa.pem        + server_rsa_{cert,key}.pem
#     PQC chain        : ca_mldsa65.pem    + server_mldsa65_{cert,key}.pem
#     client mTLS dual : client_rsa_{cert,key}.pem + client_mldsa65_{cert,key}.pem
#   Pair-matching control:
#     server PQC key is mldsa65; a mldsa44-only client must NOT pair-match.
#
# The single-certificate Catalyst format has no generation CLI; it is built
# programmatically by the C harness (hybrid_e2e_test.c) and is not produced here.
#
# Requires the repo-built openssl with oqsprovider loadable. Run via the
# wrapper that sets DYLD_LIBRARY_PATH + OPENSSL_MODULES (see run note below),
# or export them before invoking.
set -e

DIR=$(cd "$(dirname "$0")" && pwd)
cd "$DIR"

OSSL=${OPENSSL:-openssl}
PROV="-provider oqsprovider -provider default"
SUBJ_CA_C="/O=PQTest/CN=Test Classical CA"
SUBJ_CA_P="/O=PQTest/CN=Test PQC CA"
SUBJ_SRV="/O=PQTest/CN=server.example.com"
SUBJ_CLI="/O=PQTest/CN=client.example.com"

gen_chain() { # $1=keyalg $2=prefix $3=ca_subj $4=leaf_subj $5=leaf_name
    keyalg=$1; pfx=$2; ca_subj=$3; leaf_subj=$4; leaf=$5
    $OSSL genpkey $PROV -algorithm "$keyalg" -out "ca_${pfx}_key.pem"
    $OSSL req -new -x509 $PROV -key "ca_${pfx}_key.pem" -out "ca_${pfx}.pem" \
        -days 3650 -subj "$ca_subj"
    $OSSL genpkey $PROV -algorithm "$keyalg" -out "${leaf}_${pfx}_key.pem"
    $OSSL req -new $PROV -key "${leaf}_${pfx}_key.pem" -out "${leaf}_${pfx}_req.pem" \
        -subj "$leaf_subj"
    $OSSL x509 -req $PROV -in "${leaf}_${pfx}_req.pem" \
        -CA "ca_${pfx}.pem" -CAkey "ca_${pfx}_key.pem" -CAcreateserial \
        -out "${leaf}_${pfx}_cert.pem" -days 3650
    rm -f "${leaf}_${pfx}_req.pem"
}

# Server dual: RSA classical + mldsa65 PQC
gen_chain RSA      rsa     "$SUBJ_CA_C" "$SUBJ_SRV" server
gen_chain mldsa65  mldsa65 "$SUBJ_CA_P" "$SUBJ_SRV" server

# Client dual (for mutual TLS): RSA classical + mldsa65 PQC, signed by same CAs
$OSSL genpkey $PROV -algorithm RSA -out client_rsa_key.pem
$OSSL req -new $PROV -key client_rsa_key.pem -out client_rsa_req.pem -subj "$SUBJ_CLI"
$OSSL x509 -req $PROV -in client_rsa_req.pem -CA ca_rsa.pem -CAkey ca_rsa_key.pem \
    -CAcreateserial -out client_rsa_cert.pem -days 3650
rm -f client_rsa_req.pem

$OSSL genpkey $PROV -algorithm mldsa65 -out client_mldsa65_key.pem
$OSSL req -new $PROV -key client_mldsa65_key.pem -out client_mldsa65_req.pem -subj "$SUBJ_CLI"
$OSSL x509 -req $PROV -in client_mldsa65_req.pem -CA ca_mldsa65.pem -CAkey ca_mldsa65_key.pem \
    -CAcreateserial -out client_mldsa65_cert.pem -days 3650
rm -f client_mldsa65_req.pem

echo "Generated hybrid e2e cert assets in $DIR:"
ls -1 *.pem
