/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Cross-algorithm e2e smoke harness for hybrid PQC certificate negotiation.
 *
 * The committed test/hybrid_e2e_test.c proves all five hybrid formats end-to-end
 * with ML-DSA-65.  This harness re-runs the four negotiated formats (Dual,
 * Catalyst, Chameleon, Related) over the FULL measurement algorithm set
 * (ML-DSA 44/65/87, Falcon 512/1024, SLH-DSA-SHA2 128/192/256 s+f) to confirm
 * the integration is signature-algorithm agnostic before AWS measurement.
 * Composite is out of scope structurally (single standard signature_algorithms
 * signature, no PQCertificateVerify); it is not exercised here.
 *
 * Each case drives a real TLS 1.3 handshake over shared-memory BIOs and asserts
 * that hybrid auth was negotiated, that exactly one classical CertificateVerify
 * and one PQCertificateVerify were observed (the PoP was actually sent AND the
 * client verified it through the normal path -- there is no verify callback
 * override), and that the handshake completed.
 *
 * Fixtures live under test/certs/hybrid_e2e/smoke/ and are produced by
 * gen_smoke_certs.sh (per-algorithm PQC chains + Catalyst alt-key certs, shared
 * classical RSA chain).  PQC operations require oqsprovider; without it the
 * tests skip.
 */

#include <openssl/ssl.h>
#include <openssl/provider.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/obj_mac.h>
#include <openssl/v3_dcd.h>
#include <openssl/v3_certbind.h>
#include <openssl/err.h>

#include "helpers/ssltestlib.h"
#include "testutil.h"

/* Internal header: read the negotiated hybrid state directly (no public API). */
#include "../ssl/ssl_local.h"

extern int SSL_CTX_set1_pq_verify_store(SSL_CTX *ctx, X509_STORE *store);

static char *certsdir = NULL;
static OSSL_PROVIDER *defprov = NULL;
static OSSL_PROVIDER *oqsprov = NULL;
static int have_oqs = 0;

/*
 * The measurement algorithm set, by oqsprovider key-type name.  These are the
 * exact EVP_PKEY type-name strings (lower-case, no hyphens) that
 * tls1_select_pq_sigalg() and the cert-classification helpers match on.
 */
static const char *const ALGS[] = {
    "mldsa44", "mldsa65", "mldsa87",
    "falcon512", "falcon1024",
    "slhdsasha2128s", "slhdsasha2128f",
    "slhdsasha2192s", "slhdsasha2192f",
    "slhdsasha2256s", "slhdsasha2256f",
};
#define NALG ((int)OSSL_NELEM(ALGS))

/* Current algorithm for the running case; set by each test before building. */
static const char *PQ = NULL;

/* Format a per-algorithm fixture name into |buf| and return it. */
static const char *af(char *buf, size_t n, const char *fmt)
{
    BIO_snprintf(buf, n, fmt, PQ);
    return buf;
}

typedef struct {
    int pq_cert_verify;
    int classical_cv;
} handshake_obs;

static void msg_cb(int write_p, int version, int content_type, const void *buf,
                   size_t len, SSL *ssl, void *arg)
{
    handshake_obs *o = arg;

    if (content_type != SSL3_RT_HANDSHAKE || len < 1)
        return;
    switch (((const unsigned char *)buf)[0]) {
    case SSL3_MT_PQ_CERTIFICATE_VERIFY:
        o->pq_cert_verify++;
        break;
    case SSL3_MT_CERTIFICATE_VERIFY:
        o->classical_cv++;
        break;
    default:
        break;
    }
}

static int client_hybrid_negotiated(SSL *clientssl)
{
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL(clientssl);

    return sc != NULL && sc->s3.tmp.hybrid_cert != 0;
}

static char *cert_path(const char *name)
{
    return test_mk_file_path(certsdir, name);
}

static X509 *load_cert(const char *name)
{
    char *path = cert_path(name);
    BIO *b = NULL;
    X509 *x = NULL;

    if (path != NULL && (b = BIO_new_file(path, "r")) != NULL)
        x = PEM_read_bio_X509(b, NULL, NULL, NULL);
    BIO_free(b);
    OPENSSL_free(path);
    return x;
}

static EVP_PKEY *load_key(const char *name)
{
    char *path = cert_path(name);
    BIO *b = NULL;
    EVP_PKEY *k = NULL;

    if (path != NULL && (b = BIO_new_file(path, "r")) != NULL)
        k = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
    BIO_free(b);
    OPENSSL_free(path);
    return k;
}

static X509_STORE *trust_store(const char *name)
{
    X509_STORE *store = X509_STORE_new();
    X509 *ca = load_cert(name);

    if (store == NULL || ca == NULL || !X509_STORE_add_cert(store, ca)) {
        X509_STORE_free(store);
        X509_free(ca);
        return NULL;
    }
    X509_free(ca);
    return store;
}

static int add_basic_constraints(X509 *x)
{
    X509V3_CTX ctx;
    X509_EXTENSION *e;
    int ok;

    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, x, x, NULL, NULL, 0);
    e = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints,
                            "critical,CA:FALSE");
    if (e == NULL)
        return 0;
    ok = X509_add_ext(x, e, -1);
    X509_EXTENSION_free(e);
    return ok;
}

/* --- Shared handshake driver --------------------------------------------- */

static int run_handshake(SSL *serverssl, SSL *clientssl, int *creason)
{
    int sdone = 0, cdone = 0, i;

    if (creason != NULL)
        *creason = 0;

    for (i = 0; i < 200 && (!sdone || !cdone); i++) {
        if (!cdone) {
            int r = SSL_do_handshake(clientssl);

            if (r == 1) {
                cdone = 1;
            } else {
                int e = SSL_get_error(clientssl, r);

                if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) {
                    if (creason != NULL)
                        *creason = ERR_GET_REASON(ERR_peek_last_error());
                    return 0;
                }
            }
        }
        if (!sdone) {
            int r = SSL_do_handshake(serverssl);

            if (r == 1) {
                sdone = 1;
            } else {
                int e = SSL_get_error(serverssl, r);

                if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)
                    return 0;
            }
        }
    }
    return sdone && cdone;
}

static int connect_observed(SSL_CTX *sctx, SSL_CTX *cctx, handshake_obs *obs,
                            int *negotiated, int *creason)
{
    SSL *serverssl = NULL, *clientssl = NULL;
    int ret = 0;

    memset(obs, 0, sizeof(*obs));
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL)))
        goto end;

    SSL_set_accept_state(serverssl);
    SSL_set_connect_state(clientssl);

    SSL_set_msg_callback(clientssl, msg_cb);
    SSL_set_msg_callback_arg(clientssl, obs);

    ret = run_handshake(serverssl, clientssl, creason);
    if (negotiated != NULL)
        *negotiated = client_hybrid_negotiated(clientssl);

 end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    return ret;
}

/*
 * Assert the standard hybrid happy-path outcome: handshake completed, hybrid
 * was negotiated, and exactly one classical CertificateVerify plus one
 * PQCertificateVerify were observed by the client's message callback.
 */
static int expect_hybrid_ok(SSL_CTX *sctx, SSL_CTX *cctx)
{
    handshake_obs obs;
    int negotiated = 0;

    if (!TEST_true(connect_observed(sctx, cctx, &obs, &negotiated, NULL)))
        return 0;
    return TEST_int_eq(negotiated, 1)
        && TEST_int_eq(obs.classical_cv, 1)
        && TEST_int_eq(obs.pq_cert_verify, 1);
}

/* --- Format builders (parameterised by the global PQ algorithm) ----------- */

/* Dual: server presents a separate per-algorithm PQC certificate. */
static int build_dual_pair(SSL_CTX **sctx, SSL_CTX **cctx)
{
    char nb[160], kb[160], cab[160];
    char *scert = cert_path("server_rsa_cert.pem");
    char *skey = cert_path("server_rsa_key.pem");
    char *carsa = cert_path("ca_rsa.pem");
    X509 *pqcert = load_cert(af(nb, sizeof(nb), "server_%s_cert.pem"));
    EVP_PKEY *pqkey = load_key(af(kb, sizeof(kb), "server_%s_key.pem"));
    X509_STORE *pqstore = trust_store(af(cab, sizeof(cab), "ca_%s.pem"));
    int ok = 0;

    *sctx = NULL;
    *cctx = NULL;
    if (!TEST_ptr(scert) || !TEST_ptr(skey) || !TEST_ptr(carsa)
            || !TEST_ptr(pqcert) || !TEST_ptr(pqkey) || !TEST_ptr(pqstore))
        goto end;

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, TLS1_3_VERSION,
                                       sctx, cctx, scert, skey)))
        goto end;

    if (!TEST_true(SSL_CTX_load_verify_file(*cctx, carsa)))
        goto end;
    SSL_CTX_set_verify(*cctx, SSL_VERIFY_PEER, NULL);

    /* Server: enable hybrid, present the PQC certificate. */
    if (!TEST_true(SSL_CTX_enable_dual_certs(*sctx))
            || !TEST_true(SSL_CTX_set_pq_certificate(*sctx, pqcert, pqkey, NULL)))
        goto end;

    /* Client: enable hybrid, trust the PQC CA. */
    if (!TEST_true(SSL_CTX_enable_dual_certs(*cctx))
            || !TEST_true(SSL_CTX_set1_pq_verify_store(*cctx, pqstore)))
        goto end;

    ok = 1;
 end:
    OPENSSL_free(scert);
    OPENSSL_free(skey);
    OPENSSL_free(carsa);
    X509_free(pqcert);
    EVP_PKEY_free(pqkey);
    X509_STORE_free(pqstore);
    if (!ok) {
        SSL_CTX_free(*sctx);
        SSL_CTX_free(*cctx);
        *sctx = NULL;
        *cctx = NULL;
    }
    return ok;
}

/* Catalyst: single RSA leaf carrying the PQC alt key; alt key loaded via API. */
static int build_catalyst_pair(SSL_CTX **sctx, SSL_CTX **cctx)
{
    char cb[160], kb[160], ab[160];
    char *scert = cert_path(af(cb, sizeof(cb), "catalyst_%s_cert.pem"));
    char *skey = cert_path(af(kb, sizeof(kb), "catalyst_%s_key.pem"));
    X509 *catcert = load_cert(af(cb, sizeof(cb), "catalyst_%s_cert.pem"));
    EVP_PKEY *altkey = load_key(af(ab, sizeof(ab), "catalyst_%s_alt_key.pem"));
    char *carsa = cert_path("ca_rsa.pem");
    int ok = 0;

    *sctx = NULL;
    *cctx = NULL;
    if (!TEST_ptr(scert) || !TEST_ptr(skey) || !TEST_ptr(catcert)
            || !TEST_ptr(altkey) || !TEST_ptr(carsa))
        goto end;

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, TLS1_3_VERSION,
                                       sctx, cctx, scert, skey)))
        goto end;

    if (!TEST_true(SSL_CTX_load_verify_file(*cctx, carsa)))
        goto end;
    SSL_CTX_set_verify(*cctx, SSL_VERIFY_PEER, NULL);

    if (!TEST_true(SSL_CTX_enable_dual_certs(*sctx))
            || !TEST_true(SSL_CTX_set_catalyst_alt_key(*sctx, catcert, altkey)))
        goto end;
    if (!TEST_true(SSL_CTX_enable_dual_certs(*cctx)))
        goto end;

    ok = 1;
 end:
    OPENSSL_free(scert);
    OPENSSL_free(skey);
    OPENSSL_free(carsa);
    X509_free(catcert);
    EVP_PKEY_free(altkey);
    if (!ok) {
        SSL_CTX_free(*sctx);
        SSL_CTX_free(*cctx);
        *sctx = NULL;
        *cctx = NULL;
    }
    return ok;
}

/* Chameleon Base = RSA leaf carrying a deltaCertificateDescriptor for the PQC Delta. */
static X509 *make_chameleon_base(X509 *ca_rsa, EVP_PKEY *ca_rsa_key,
                                 X509 *ca_pq, EVP_PKEY *ca_pq_key,
                                 EVP_PKEY *base_main, EVP_PKEY *delta_pq)
{
    X509 *base = NULL, *delta = NULL, *base_dcd = NULL, *ret = NULL;
    ASN1_TIME *nb = ASN1_TIME_set(NULL, 1700000000);
    ASN1_TIME *na = ASN1_TIME_set(NULL, 1900000000);
    ASN1_OCTET_STRING *dcd_oct = NULL;
    X509_EXTENSION *de = NULL;
    X509_NAME *subj = X509_NAME_new();

    if (nb == NULL || na == NULL || subj == NULL
            || !X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC,
                   (const unsigned char *)"server.example.com", -1, -1, 0))
        goto end;

    base = X509_new();
    delta = X509_new();
    if (base == NULL || delta == NULL)
        goto end;

    if (!X509_set_version(base, X509_VERSION_3)
            || !ASN1_INTEGER_set(X509_get_serialNumber(base), 1001)
            || !X509_set1_notBefore(base, nb) || !X509_set1_notAfter(base, na)
            || !X509_set_subject_name(base, subj)
            || !X509_set_issuer_name(base, X509_get_subject_name(ca_rsa))
            || !X509_set_pubkey(base, base_main)
            || !add_basic_constraints(base)
            || X509_sign(base, ca_rsa_key, EVP_sha256()) == 0)
        goto end;

    /* Delta: PQC key, issued by the PQC CA, PQ signature (md = NULL). */
    if (!X509_set_version(delta, X509_VERSION_3)
            || !ASN1_INTEGER_set(X509_get_serialNumber(delta), 1002)
            || !X509_set1_notBefore(delta, nb) || !X509_set1_notAfter(delta, na)
            || !X509_set_subject_name(delta, subj)
            || !X509_set_issuer_name(delta, X509_get_subject_name(ca_pq))
            || !X509_set_pubkey(delta, delta_pq)
            || !add_basic_constraints(delta)
            || X509_sign(delta, ca_pq_key, NULL) == 0)
        goto end;

    dcd_oct = create_delta_certificate_descriptor(base, delta);
    if (dcd_oct == NULL)
        goto end;

    base_dcd = X509_dup(base);
    de = X509_EXTENSION_create_by_NID(NULL, NID_id_ce_deltaCertificateDescriptor,
                                      0, dcd_oct);
    if (base_dcd == NULL || de == NULL
            || !X509_add_ext(base_dcd, de, -1)
            || X509_sign(base_dcd, ca_rsa_key, EVP_sha256()) == 0)
        goto end;

    ret = base_dcd;
    base_dcd = NULL;
 end:
    X509_EXTENSION_free(de);
    ASN1_OCTET_STRING_free(dcd_oct);
    ASN1_TIME_free(nb);
    ASN1_TIME_free(na);
    X509_NAME_free(subj);
    X509_free(base);
    X509_free(delta);
    X509_free(base_dcd);
    return ret;
}

static int build_chameleon_pair(SSL_CTX **sctx, SSL_CTX **cctx)
{
    char cab[160], cakb[160], dkb[160];
    char *scert = cert_path("server_rsa_cert.pem");
    char *skey = cert_path("server_rsa_key.pem");
    char *carsa = cert_path("ca_rsa.pem");
    X509 *ca_rsa = load_cert("ca_rsa.pem");
    EVP_PKEY *ca_rsa_key = load_key("ca_rsa_key.pem");
    X509 *ca_pq = load_cert(af(cab, sizeof(cab), "ca_%s.pem"));
    EVP_PKEY *ca_pq_key = load_key(af(cakb, sizeof(cakb), "ca_%s_key.pem"));
    EVP_PKEY *base_main = load_key("server_rsa_key.pem");
    EVP_PKEY *delta_key = load_key(af(dkb, sizeof(dkb), "server_%s_key.pem"));
    X509 *base = NULL;
    X509_STORE *pqstore = NULL;
    char pqcab[160];
    int ok = 0;

    *sctx = NULL;
    *cctx = NULL;
    if (!TEST_ptr(scert) || !TEST_ptr(skey) || !TEST_ptr(carsa)
            || !TEST_ptr(ca_rsa) || !TEST_ptr(ca_rsa_key) || !TEST_ptr(ca_pq)
            || !TEST_ptr(ca_pq_key) || !TEST_ptr(base_main) || !TEST_ptr(delta_key))
        goto end;

    base = make_chameleon_base(ca_rsa, ca_rsa_key, ca_pq, ca_pq_key,
                               base_main, delta_key);
    if (!TEST_ptr(base))
        goto end;

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, TLS1_3_VERSION,
                                       sctx, cctx, scert, skey)))
        goto end;

    if (!TEST_true(SSL_CTX_use_certificate(*sctx, base))
            || !TEST_true(SSL_CTX_use_PrivateKey(*sctx, base_main)))
        goto end;

    if (!TEST_true(SSL_CTX_load_verify_file(*cctx, carsa)))
        goto end;
    SSL_CTX_set_verify(*cctx, SSL_VERIFY_PEER, NULL);

    pqstore = trust_store(af(pqcab, sizeof(pqcab), "ca_%s.pem"));
    if (!TEST_ptr(pqstore)
            || !TEST_true(SSL_CTX_set1_pq_verify_store(*cctx, pqstore)))
        goto end;

    if (!TEST_true(SSL_CTX_enable_dual_certs(*sctx))
            || !TEST_true(SSL_CTX_set_chameleon_delta_key(*sctx, base, delta_key)))
        goto end;
    if (!TEST_true(SSL_CTX_enable_dual_certs(*cctx)))
        goto end;

    ok = 1;
 end:
    OPENSSL_free(scert);
    OPENSSL_free(skey);
    OPENSSL_free(carsa);
    X509_free(ca_rsa);
    EVP_PKEY_free(ca_rsa_key);
    X509_free(ca_pq);
    EVP_PKEY_free(ca_pq_key);
    EVP_PKEY_free(base_main);
    EVP_PKEY_free(delta_key);
    X509_free(base);
    X509_STORE_free(pqstore);
    if (!ok) {
        SSL_CTX_free(*sctx);
        SSL_CTX_free(*cctx);
        *sctx = NULL;
        *cctx = NULL;
    }
    return ok;
}

/* Related: per-algorithm PQC leaf carrying an RFC 9763 RelatedCertificate ext. */
static X509 *make_related_pqc(EVP_PKEY *pqc_key, X509 *ca_pq,
                              EVP_PKEY *ca_pq_key, X509 *bind_to)
{
    X509 *pqc = X509_new();
    ASN1_TIME *nb = ASN1_TIME_set(NULL, 1700000000);
    ASN1_TIME *na = ASN1_TIME_set(NULL, 1900000000);
    X509_NAME *subj = X509_NAME_new();
    int ok = 0;

    if (pqc == NULL || nb == NULL || na == NULL || subj == NULL
            || !X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC,
                   (const unsigned char *)"server.example.com", -1, -1, 0))
        goto end;

    if (!X509_set_version(pqc, X509_VERSION_3)
            || !ASN1_INTEGER_set(X509_get_serialNumber(pqc), 2001)
            || !X509_set1_notBefore(pqc, nb) || !X509_set1_notAfter(pqc, na)
            || !X509_set_subject_name(pqc, subj)
            || !X509_set_issuer_name(pqc, X509_get_subject_name(ca_pq))
            || !X509_set_pubkey(pqc, pqc_key)
            || !add_basic_constraints(pqc))
        goto end;

    if (!add_related_certificate_extension(pqc, bind_to, EVP_sha256(),
                                           "https://example.com/related"))
        goto end;

    if (X509_sign(pqc, ca_pq_key, NULL) == 0)
        goto end;
    ok = 1;
 end:
    ASN1_TIME_free(nb);
    ASN1_TIME_free(na);
    X509_NAME_free(subj);
    if (!ok) {
        X509_free(pqc);
        pqc = NULL;
    }
    return pqc;
}

static int build_related_pair(SSL_CTX **sctx, SSL_CTX **cctx)
{
    char cab[160], cakb[160], pkb[160], pqcab[160];
    char *scert = cert_path("server_rsa_cert.pem");
    char *skey = cert_path("server_rsa_key.pem");
    char *carsa = cert_path("ca_rsa.pem");
    X509 *classical = load_cert("server_rsa_cert.pem");
    X509 *ca_pq = load_cert(af(cab, sizeof(cab), "ca_%s.pem"));
    EVP_PKEY *ca_pq_key = load_key(af(cakb, sizeof(cakb), "ca_%s_key.pem"));
    EVP_PKEY *pqc_key = load_key(af(pkb, sizeof(pkb), "server_%s_key.pem"));
    X509 *pqc = NULL;
    X509_STORE *pqstore = NULL;
    int ok = 0;

    *sctx = NULL;
    *cctx = NULL;
    if (!TEST_ptr(scert) || !TEST_ptr(skey) || !TEST_ptr(carsa)
            || !TEST_ptr(classical) || !TEST_ptr(ca_pq)
            || !TEST_ptr(ca_pq_key) || !TEST_ptr(pqc_key))
        goto end;

    /* Bind the PQC leaf to the classical leaf that is actually transmitted. */
    pqc = make_related_pqc(pqc_key, ca_pq, ca_pq_key, classical);
    if (!TEST_ptr(pqc))
        goto end;

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, TLS1_3_VERSION,
                                       sctx, cctx, scert, skey)))
        goto end;

    if (!TEST_true(SSL_CTX_enable_dual_certs(*sctx))
            || !TEST_true(SSL_CTX_set_pq_certificate(*sctx, pqc, pqc_key, NULL)))
        goto end;

    if (!TEST_true(SSL_CTX_load_verify_file(*cctx, carsa)))
        goto end;
    SSL_CTX_set_verify(*cctx, SSL_VERIFY_PEER, NULL);
    pqstore = trust_store(af(pqcab, sizeof(pqcab), "ca_%s.pem"));
    if (!TEST_ptr(pqstore)
            || !TEST_true(SSL_CTX_set1_pq_verify_store(*cctx, pqstore)))
        goto end;
    if (!TEST_true(SSL_CTX_enable_dual_certs(*cctx)))
        goto end;

    ok = 1;
 end:
    OPENSSL_free(scert);
    OPENSSL_free(skey);
    OPENSSL_free(carsa);
    X509_free(classical);
    X509_free(ca_pq);
    EVP_PKEY_free(ca_pq_key);
    EVP_PKEY_free(pqc_key);
    X509_free(pqc);
    X509_STORE_free(pqstore);
    if (!ok) {
        SSL_CTX_free(*sctx);
        SSL_CTX_free(*cctx);
        *sctx = NULL;
        *cctx = NULL;
    }
    return ok;
}

/* --- Parameterised tests: one per format, indexed over ALGS -------------- */

typedef int (*builder_fn)(SSL_CTX **, SSL_CTX **);

static int run_format(int idx, const char *label, builder_fn build)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    int ok = 0;

    if (!have_oqs)
        return TEST_skip("oqsprovider not available");

    PQ = ALGS[idx];
    TEST_info("%s x %s", label, PQ);

    if (!build(&sctx, &cctx))
        goto end;
    if (!expect_hybrid_ok(sctx, cctx))
        goto end;
    ok = 1;
 end:
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    PQ = NULL;
    return ok;
}

static int test_dual(int idx)      { return run_format(idx, "Dual",      build_dual_pair); }
static int test_catalyst(int idx)  { return run_format(idx, "Catalyst",  build_catalyst_pair); }
static int test_chameleon(int idx) { return run_format(idx, "Chameleon", build_chameleon_pair); }
static int test_related(int idx)   { return run_format(idx, "Related",   build_related_pair); }

int setup_tests(void)
{
    if ((certsdir = test_get_argument(0)) == NULL) {
        TEST_error("usage: hybrid_smoke_test certsdir");
        return 0;
    }

    defprov = OSSL_PROVIDER_load(NULL, "default");
    oqsprov = OSSL_PROVIDER_load(NULL, "oqsprovider");
    have_oqs = (oqsprov != NULL);
    if (!have_oqs)
        TEST_info("oqsprovider not loadable; cross-algorithm tests will skip");

    ADD_ALL_TESTS(test_dual, NALG);
    ADD_ALL_TESTS(test_catalyst, NALG);
    ADD_ALL_TESTS(test_chameleon, NALG);
    ADD_ALL_TESTS(test_related, NALG);
    return 1;
}

void cleanup_tests(void)
{
    OSSL_PROVIDER_unload(oqsprov);
    OSSL_PROVIDER_unload(defprov);
}
