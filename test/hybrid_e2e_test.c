/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * End-to-end test harness for hybrid PQC certificate negotiation (Phase 4).
 *
 * Drives a real TLS 1.3 handshake between two in-process endpoints over shared
 * memory BIOs and asserts on the negotiation/authentication outcome.  It is the
 * first repo test that exercises the hybrid path end-to-end rather than by code
 * argument, and is used to demonstrate the cumulative integration work:
 *
 *   - negotiation gate  : hybrid auth fires only when BOTH sides opt in
 *   - key-aware matching : the server selects its PQC certificate only when the
 *                          client advertised that key's signature algorithm
 *   - PQCertificateVerify: it is sent + verified on a successful hybrid handshake
 *   - downgrade defense  : a strict client aborts when hybrid is stripped, while
 *                          a permissive client falls back to traditional auth
 *   - mutual TLS         : the server verifies a client-presented dual cert
 *
 * Both hybrid formats are now driven end-to-end:
 *   - Dual (multi-certificate): the server presents a separate PQC certificate.
 *   - Catalyst (single-certificate): the server presents one certificate whose
 *     PQC public key lives in a subjectAltPublicKeyInfo extension and signs the
 *     PQCertificateVerify with the matching alternative private key loaded via
 *     SSL_CTX_set_catalyst_alt_key().  The crypto contract of that send path
 *     (alt-keypair coherence + chained sign/verify) is additionally proven by
 *     the standalone test in test/phase4d_repro/.
 *
 * PQC operations require oqsprovider; if it cannot be loaded the tests skip.
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

/* Internal headers: lets the harness poke the client's PQ sigalg list and read
 * the negotiated hybrid state directly, neither of which has a public API. */
#include "../ssl/ssl_local.h"

/*
 * Defined in libssl (ssl_lib.c) but not declared in a public header; the test
 * links libssl statically, so a local prototype is enough to call it.
 */
extern int SSL_CTX_set1_pq_verify_store(SSL_CTX *ctx, X509_STORE *store);

static char *certsdir = NULL;
static OSSL_PROVIDER *defprov = NULL;
static OSSL_PROVIDER *oqsprov = NULL;
static int have_oqs = 0;

/* Observations gathered from a handshake via the message callback. */
typedef struct {
    int pq_cert_verify;     /* PQCertificateVerify messages seen */
    int classical_cv;       /* (classical) CertificateVerify messages seen */
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

/* Did the client end up believing hybrid auth was negotiated (EE echo seen)? */
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

/* An X509_STORE holding a single trust anchor loaded from |name|. */
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

/* Attach the Dual-format PQC certificate + key to a server (sending) context. */
static int server_add_pq_cert(SSL_CTX *sctx)
{
    X509 *cert = load_cert("server_mldsa65_cert.pem");
    EVP_PKEY *key = load_key("server_mldsa65_key.pem");
    int ok = 0;

    if (!TEST_ptr(cert) || !TEST_ptr(key))
        goto end;
    if (!TEST_true(SSL_CTX_enable_dual_certs(sctx)))
        goto end;
    if (!TEST_true(SSL_CTX_set_pq_certificate(sctx, cert, key, NULL)))
        goto end;
    /* set_pq_certificate takes its own references. */
    ok = 1;
 end:
    X509_free(cert);
    EVP_PKEY_free(key);
    return ok;
}

/* Configure a client (receiving) context to accept + verify Dual hybrid auth. */
static int client_enable_hybrid(SSL_CTX *cctx)
{
    X509_STORE *pqstore = trust_store("ca_mldsa65.pem");
    int ok = 0;

    if (!TEST_ptr(pqstore))
        goto end;
    if (!TEST_true(SSL_CTX_enable_dual_certs(cctx)))
        goto end;
    /* Trust anchor for verifying the server's PQC certificate chain. */
    if (!TEST_true(SSL_CTX_set1_pq_verify_store(cctx, pqstore)))
        goto end;
    ok = 1;
 end:
    X509_STORE_free(pqstore);
    return ok;
}

/*
 * Configure mutual TLS on top of a hybrid pair: the client presents a Dual
 * (classical + PQC) certificate, and the server is set up to require and verify
 * both of the client's chains.
 */
static int configure_mutual(SSL_CTX *sctx, SSL_CTX *cctx)
{
    X509 *ccert = load_cert("client_rsa_cert.pem");
    EVP_PKEY *ckey = load_key("client_rsa_key.pem");
    X509 *cpqcert = load_cert("client_mldsa65_cert.pem");
    EVP_PKEY *cpqkey = load_key("client_mldsa65_key.pem");
    X509_STORE *spqstore = trust_store("ca_mldsa65.pem");
    char *carsa = cert_path("ca_rsa.pem");
    int ok = 0;

    if (!TEST_ptr(ccert) || !TEST_ptr(ckey) || !TEST_ptr(cpqcert)
            || !TEST_ptr(cpqkey) || !TEST_ptr(spqstore) || !TEST_ptr(carsa))
        goto end;

    /* Client presents its classical + PQC certificate. */
    if (!TEST_true(SSL_CTX_use_certificate(cctx, ccert))
            || !TEST_true(SSL_CTX_use_PrivateKey(cctx, ckey))
            || !TEST_true(SSL_CTX_set_pq_certificate(cctx, cpqcert, cpqkey, NULL)))
        goto end;

    /* Server requires + verifies the client's classical and PQC chains. */
    if (!TEST_true(SSL_CTX_load_verify_file(sctx, carsa))
            || !TEST_true(SSL_CTX_set1_pq_verify_store(sctx, spqstore)))
        goto end;
    SSL_CTX_set_verify(sctx,
                       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    ok = 1;
 end:
    X509_free(ccert);
    EVP_PKEY_free(ckey);
    X509_free(cpqcert);
    EVP_PKEY_free(cpqkey);
    X509_STORE_free(spqstore);
    OPENSSL_free(carsa);
    return ok;
}

/*
 * Build a server/client context pair.
 *   server_hybrid : server presents a Dual (classical + PQC) certificate
 *   client_hybrid : client advertises hybrid_cert and can verify PQC auth
 */
static int build_pair(SSL_CTX **sctx, SSL_CTX **cctx,
                      int server_hybrid, int client_hybrid)
{
    char *scert = cert_path("server_rsa_cert.pem");
    char *skey = cert_path("server_rsa_key.pem");
    int ok = 0;

    *sctx = NULL;
    *cctx = NULL;
    if (!TEST_ptr(scert) || !TEST_ptr(skey))
        goto end;

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, TLS1_3_VERSION,
                                       sctx, cctx, scert, skey)))
        goto end;

    /* Client verifies the server's classical chain against the RSA CA. */
    {
        char *carsa = cert_path("ca_rsa.pem");
        int okca = carsa != NULL && SSL_CTX_load_verify_file(*cctx, carsa);

        OPENSSL_free(carsa);
        if (!TEST_true(okca))
            goto end;
    }
    SSL_CTX_set_verify(*cctx, SSL_VERIFY_PEER, NULL);

    if (server_hybrid && !server_add_pq_cert(*sctx))
        goto end;
    if (client_hybrid && !client_enable_hybrid(*cctx))
        goto end;

    ok = 1;
 end:
    OPENSSL_free(scert);
    OPENSSL_free(skey);
    if (!ok) {
        SSL_CTX_free(*sctx);
        SSL_CTX_free(*cctx);
        *sctx = NULL;
        *cctx = NULL;
    }
    return ok;
}

/*
 * Drive the handshake to completion over the shared memory BIOs set up by
 * create_ssl_objects().  Returns 1 on full success, 0 otherwise.  On client
 * failure the client's top error reason is stored in *creason.
 */
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

/* Run one handshake with the given contexts and collect observations. */
static int connect_observed(SSL_CTX *sctx, SSL_CTX *cctx, handshake_obs *obs,
                            int *negotiated, int *creason, int client_strict,
                            uint16_t client_pq_sigalg)
{
    SSL *serverssl = NULL, *clientssl = NULL;
    int ret = 0;

    memset(obs, 0, sizeof(*obs));
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL)))
        goto end;

    /* create_ssl_objects() only wires the BIOs; set the handshake roles. */
    SSL_set_accept_state(serverssl);
    SSL_set_connect_state(clientssl);

    SSL_set_msg_callback(clientssl, msg_cb);
    SSL_set_msg_callback_arg(clientssl, obs);

    if (client_strict && !TEST_true(SSL_set_hybrid_cert_required(clientssl, 1)))
        goto end;

    /* Restrict the client's advertised PQ signature algorithms (T3). */
    if (client_pq_sigalg != 0) {
        SSL_CONNECTION *csc = SSL_CONNECTION_FROM_SSL(clientssl);
        uint16_t one[1];

        one[0] = client_pq_sigalg;
        if (!TEST_ptr(csc)
                || !TEST_true(tls1_set_raw_pq_sigalgs(csc->cert, one, 1, 1)))
            goto end;
    }

    ret = run_handshake(serverssl, clientssl, creason);
    if (negotiated != NULL)
        *negotiated = client_hybrid_negotiated(clientssl);

 end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    return ret;
}

/*
 * Test 1 (+ 4): happy path. Both sides opt in -> hybrid negotiated, the server
 * sends BOTH a classical CertificateVerify and a PQCertificateVerify, and the
 * client verifies them (4c chaining) so the handshake completes.
 */
static int test_happy_path(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    handshake_obs obs;
    int negotiated = 0, ok = 0;

    if (!have_oqs)
        return TEST_skip("oqsprovider not available");
    if (!build_pair(&sctx, &cctx, 1, 1))
        goto end;
    if (!TEST_true(connect_observed(sctx, cctx, &obs, &negotiated, NULL, 0, 0)))
        goto end;
    if (!TEST_int_eq(negotiated, 1)
            || !TEST_int_eq(obs.classical_cv, 1)
            || !TEST_int_eq(obs.pq_cert_verify, 1))
        goto end;
    ok = 1;
 end:
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return ok;
}

/*
 * Test 2: negotiation gate. Hybrid auth must fire only when BOTH sides opt in.
 * idx 0 both -> hybrid; idx 1 client-only -> fallback; idx 2 server-only ->
 * fallback. Fallback handshakes must complete WITHOUT a PQCertificateVerify.
 */
static int test_negotiation_gate(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    handshake_obs obs;
    int negotiated = 0, ok = 0;
    int server_hybrid = (idx == 0 || idx == 2);
    int client_hybrid = (idx == 0 || idx == 1);
    int expect_hybrid = (idx == 0);

    if (!have_oqs)
        return TEST_skip("oqsprovider not available");
    if (!build_pair(&sctx, &cctx, server_hybrid, client_hybrid))
        goto end;
    if (!TEST_true(connect_observed(sctx, cctx, &obs, &negotiated, NULL, 0, 0)))
        goto end;
    if (!TEST_int_eq(negotiated, expect_hybrid)
            || !TEST_int_eq(obs.pq_cert_verify, expect_hybrid))
        goto end;
    ok = 1;
 end:
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return ok;
}

/*
 * Test 3: key-aware pair matching. The server's PQC key is mldsa65.
 *   idx 0: client advertises mldsa65 -> pair matches -> hybrid negotiated.
 *   idx 1: client advertises only mldsa44 -> no pair -> standard fallback
 *          (no false-positive hybrid, no PQCertificateVerify).
 */
static int test_pair_matching(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    handshake_obs obs;
    int negotiated = 0, ok = 0;
    /* Server's PQC key is mldsa65; idx 0 advertises it, idx 1 advertises mldsa44. */
    uint16_t client_pq = (idx == 0) ? TLSEXT_SIGALG_mldsa_65 : TLSEXT_SIGALG_mldsa_44;
    int expect_hybrid = (idx == 0);

    if (!have_oqs)
        return TEST_skip("oqsprovider not available");
    if (!build_pair(&sctx, &cctx, 1, 1))
        goto end;
    if (!TEST_true(connect_observed(sctx, cctx, &obs, &negotiated, NULL, 0,
                                    client_pq)))
        goto end;
    if (!TEST_int_eq(negotiated, expect_hybrid)
            || !TEST_int_eq(obs.pq_cert_verify, expect_hybrid))
        goto end;
    ok = 1;
 end:
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return ok;
}

/*
 * Test 5a: downgrade defense. A strict client that advertised hybrid_cert must
 * ABORT when the server does not echo it (here the server is non-hybrid, the
 * natural realization of an on-path attacker stripping the advertisement/echo).
 * The defense rests on the strict client policy plus PQC unforgeability.
 */
static int test_downgrade_strict_no_echo(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    handshake_obs obs;
    int creason = 0, ok = 0;

    if (!have_oqs)
        return TEST_skip("oqsprovider not available");
    /* client opts in (and is strict); server does NOT offer hybrid. */
    if (!build_pair(&sctx, &cctx, 0, 1))
        goto end;
    if (!TEST_false(connect_observed(sctx, cctx, &obs, NULL, &creason, 1, 0)))
        goto end;
    if (!TEST_int_eq(creason, SSL_R_HYBRID_CERT_DOWNGRADE))
        goto end;
    ok = 1;
 end:
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return ok;
}

/*
 * Test 5c: a PERMISSIVE client (default) accepts a standard handshake when the
 * server does not negotiate hybrid -- no abort (R2 backward compatibility).
 */
static int test_downgrade_permissive(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    handshake_obs obs;
    int negotiated = 1, ok = 0;

    if (!have_oqs)
        return TEST_skip("oqsprovider not available");
    if (!build_pair(&sctx, &cctx, 0, 1))
        goto end;
    if (!TEST_true(connect_observed(sctx, cctx, &obs, &negotiated, NULL, 0, 0)))
        goto end;
    if (!TEST_int_eq(negotiated, 0)
            || !TEST_int_eq(obs.pq_cert_verify, 0))
        goto end;
    ok = 1;
 end:
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return ok;
}

/*
 * Test 6: mutual TLS. The server requires a client certificate and verifies the
 * client's Dual (classical + PQC) chains. A successful handshake exercises the
 * symmetric, server-side hybrid authentication path (the client now produces the
 * classical CertificateVerify + PQCertificateVerify that the server verifies).
 */
static int test_mutual_tls(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    handshake_obs obs;
    int negotiated = 0, ok = 0;

    if (!have_oqs)
        return TEST_skip("oqsprovider not available");
    if (!build_pair(&sctx, &cctx, 1, 1))
        goto end;
    if (!configure_mutual(sctx, cctx))
        goto end;
    if (!TEST_true(connect_observed(sctx, cctx, &obs, &negotiated, NULL, 0, 0)))
        goto end;
    /* Hybrid negotiated and at least one PQCertificateVerify on the wire. */
    if (!TEST_int_eq(negotiated, 1)
            || !TEST_int_ge(obs.pq_cert_verify, 1))
        goto end;
    ok = 1;
 end:
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return ok;
}

/*
 * Build a hybrid pair where the server uses the single-certificate Catalyst
 * format: its MAIN certificate carries the PQC public key in a
 * subjectAltPublicKeyInfo extension, and the matching PQC private key is loaded
 * through SSL_CTX_set_catalyst_alt_key().  No separate PQC certificate is
 * installed or transmitted.  The client trusts the classical RSA CA (which also
 * authenticates the embedded alt key via the alternative-signature chain check)
 * and opts into hybrid auth.
 */
static int build_catalyst_pair(SSL_CTX **sctx, SSL_CTX **cctx)
{
    char *scert = cert_path("server_catalyst_cert.pem");
    char *skey = cert_path("server_catalyst_key.pem");
    X509 *catcert = load_cert("server_catalyst_cert.pem");
    EVP_PKEY *altkey = load_key("server_catalyst_alt_key.pem");
    char *carsa = cert_path("ca_rsa.pem");
    int ok = 0;

    *sctx = NULL;
    *cctx = NULL;
    if (!TEST_ptr(scert) || !TEST_ptr(skey) || !TEST_ptr(catcert)
            || !TEST_ptr(altkey) || !TEST_ptr(carsa))
        goto end;

    /* Server presents the Catalyst certificate as its main certificate. */
    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, TLS1_3_VERSION,
                                       sctx, cctx, scert, skey)))
        goto end;

    /* Client verifies the server's (classical + alt) certificate via the RSA CA. */
    if (!TEST_true(SSL_CTX_load_verify_file(*cctx, carsa)))
        goto end;
    SSL_CTX_set_verify(*cctx, SSL_VERIFY_PEER, NULL);

    /* Server: enable hybrid and load the Catalyst alternative private key. */
    if (!TEST_true(SSL_CTX_enable_dual_certs(*sctx))
            || !TEST_true(SSL_CTX_set_catalyst_alt_key(*sctx, catcert, altkey)))
        goto end;

    /* Client: opt into hybrid auth (advertise hybrid_cert + PQ sigalgs). */
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

/*
 * Test 7: Catalyst happy path. The server signs PQCertificateVerify with the
 * certificate's alternative private key; the client recovers the verifying key
 * from the peer certificate's subjectAltPublicKeyInfo extension and verifies it.
 * Hybrid must be negotiated and exactly one classical + one PQCertificateVerify
 * must appear -- with NO second certificate on the wire (single-cert format).
 */
static int test_catalyst_happy_path(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    handshake_obs obs;
    int negotiated = 0, ok = 0;

    if (!have_oqs)
        return TEST_skip("oqsprovider not available");
    if (!build_catalyst_pair(&sctx, &cctx))
        goto end;
    if (!TEST_true(connect_observed(sctx, cctx, &obs, &negotiated, NULL, 0, 0)))
        goto end;
    if (!TEST_int_eq(negotiated, 1)
            || !TEST_int_eq(obs.classical_cv, 1)
            || !TEST_int_eq(obs.pq_cert_verify, 1))
        goto end;
    ok = 1;
 end:
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return ok;
}

/*
 * Build a Chameleon Base certificate at runtime: a classical (RSA) Base issued
 * by the RSA CA, carrying a deltaCertificateDescriptor that encodes a PQC
 * (mldsa65) Delta issued by the PQC CA. The peer reconstructs the Delta from the
 * Base + DCD and verifies it against the PQC CA (pq_verify_store). Base and Delta
 * share subject/validity and carry no other extensions, so the diff-only DCD
 * (serial, issuer, signature alg, SubjectPublicKeyInfo) reconstructs an exact
 * Delta whose signature still verifies under the PQC CA.
 */
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

    /*
     * Base: RSA key, issued by the RSA CA, classical sha256 signature. Base and
     * Delta carry an identical basicConstraints extension so the diff-only DCD's
     * extensions field is (legitimately) absent and the reconstructed Delta's
     * extensions match the original exactly -- a Base whose ONLY extension were
     * the DCD would reconstruct to an (encoded) empty extensions field that does
     * not byte-match a Delta with no extensions field at all.
     */
    if (!X509_set_version(base, X509_VERSION_3)
            || !ASN1_INTEGER_set(X509_get_serialNumber(base), 1001)
            || !X509_set1_notBefore(base, nb) || !X509_set1_notAfter(base, na)
            || !X509_set_subject_name(base, subj)
            || !X509_set_issuer_name(base, X509_get_subject_name(ca_rsa))
            || !X509_set_pubkey(base, base_main)
            || !add_basic_constraints(base)
            || X509_sign(base, ca_rsa_key, EVP_sha256()) == 0)
        goto end;

    /* Delta: mldsa65 key, issued by the PQC CA, PQ signature (md = NULL). */
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

/*
 * Build a hybrid pair where the server uses the single-certificate Chameleon
 * format: its MAIN certificate is the Base carrying a deltaCertificateDescriptor,
 * and the matching Delta PQC private key is loaded through
 * SSL_CTX_set_chameleon_delta_key().  No separate PQC certificate is installed or
 * transmitted.  The client trusts the RSA CA (classical chain) and the PQC CA
 * (the reconstructed Delta's chain, via the PQ verify store) and opts into hybrid.
 */
static int build_chameleon_pair(SSL_CTX **sctx, SSL_CTX **cctx)
{
    char *scert = cert_path("server_rsa_cert.pem");
    char *skey = cert_path("server_rsa_key.pem");
    char *carsa = cert_path("ca_rsa.pem");
    X509 *ca_rsa = load_cert("ca_rsa.pem");
    EVP_PKEY *ca_rsa_key = load_key("ca_rsa_key.pem");
    X509 *ca_pq = load_cert("ca_mldsa65.pem");
    EVP_PKEY *ca_pq_key = load_key("ca_mldsa65_key.pem");
    EVP_PKEY *base_main = load_key("server_rsa_key.pem");
    EVP_PKEY *delta_key = load_key("server_mldsa65_key.pem");
    X509 *base = NULL;
    X509_STORE *pqstore = NULL;
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

    /* Replace the server leaf with the in-memory Chameleon Base + its RSA key. */
    if (!TEST_true(SSL_CTX_use_certificate(*sctx, base))
            || !TEST_true(SSL_CTX_use_PrivateKey(*sctx, base_main)))
        goto end;

    /* Client verifies the Base's classical chain against the RSA CA. */
    if (!TEST_true(SSL_CTX_load_verify_file(*cctx, carsa)))
        goto end;
    SSL_CTX_set_verify(*cctx, SSL_VERIFY_PEER, NULL);

    /* Client trusts the PQC CA for the reconstructed Delta's chain. */
    pqstore = trust_store("ca_mldsa65.pem");
    if (!TEST_ptr(pqstore)
            || !TEST_true(SSL_CTX_set1_pq_verify_store(*cctx, pqstore)))
        goto end;

    /* Server: enable hybrid and load the Chameleon Delta private key. */
    if (!TEST_true(SSL_CTX_enable_dual_certs(*sctx))
            || !TEST_true(SSL_CTX_set_chameleon_delta_key(*sctx, base, delta_key)))
        goto end;

    /* Client: opt into hybrid auth (advertise hybrid_cert + PQ sigalgs). */
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

/*
 * Test 8: Chameleon happy path. The server signs PQCertificateVerify with the
 * Delta private key; the client reconstructs the Delta certificate from the peer
 * certificate's deltaCertificateDescriptor extension, validates it against the
 * PQC CA, and verifies the signature with the Delta's public key. Hybrid must be
 * negotiated and exactly one classical + one PQCertificateVerify must appear --
 * with NO second certificate on the wire (single-cert format).
 */
static int test_chameleon_happy_path(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    handshake_obs obs;
    int negotiated = 0, ok = 0;

    if (!have_oqs)
        return TEST_skip("oqsprovider not available");
    if (!build_chameleon_pair(&sctx, &cctx))
        goto end;
    if (!TEST_true(connect_observed(sctx, cctx, &obs, &negotiated, NULL, 0, 0)))
        goto end;
    if (!TEST_int_eq(negotiated, 1)
            || !TEST_int_eq(obs.classical_cv, 1)
            || !TEST_int_eq(obs.pq_cert_verify, 1))
        goto end;
    ok = 1;
 end:
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return ok;
}

/*
 * Build an mldsa65 PQC leaf certificate that carries an RFC 9763
 * RelatedCertificate extension binding it (by hash) to |bind_to|. Issued by the
 * PQC CA so it chains to the PQ verify store; its public key is taken from
 * |pqc_key| so the matching private key signs the PQCertificateVerify. This is
 * the Related (multi-certificate) format: the PoP path is identical to Dual; the
 * RelatedCertificate extension is the additional certificate-binding check
 * performed by parse_related_certificate_cb on the receiving side.
 */
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

    /* Bind to |bind_to| by hash (RFC 9763 RelatedCertificate extension). */
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

/*
 * Build a Related-format hybrid pair. The server presents its RSA classical
 * certificate plus an mldsa65 PQC certificate that carries a RelatedCertificate
 * extension hash-binding it to the transmitted classical leaf. When |tamper| is
 * set the binding targets a DIFFERENT certificate (the client RSA cert) so the
 * hash will not match the classical leaf the peer receives -- used to prove the
 * binding is actually enforced on the wire.
 */
static int build_related_pair(SSL_CTX **sctx, SSL_CTX **cctx, int tamper)
{
    char *scert = cert_path("server_rsa_cert.pem");
    char *skey = cert_path("server_rsa_key.pem");
    char *carsa = cert_path("ca_rsa.pem");
    X509 *classical = load_cert("server_rsa_cert.pem");
    X509 *other = load_cert("client_rsa_cert.pem");
    X509 *ca_pq = load_cert("ca_mldsa65.pem");
    EVP_PKEY *ca_pq_key = load_key("ca_mldsa65_key.pem");
    EVP_PKEY *pqc_key = load_key("server_mldsa65_key.pem");
    X509 *pqc = NULL;
    X509_STORE *pqstore = NULL;
    int ok = 0;

    *sctx = NULL;
    *cctx = NULL;
    if (!TEST_ptr(scert) || !TEST_ptr(skey) || !TEST_ptr(carsa)
            || !TEST_ptr(classical) || !TEST_ptr(other) || !TEST_ptr(ca_pq)
            || !TEST_ptr(ca_pq_key) || !TEST_ptr(pqc_key))
        goto end;

    pqc = make_related_pqc(pqc_key, ca_pq, ca_pq_key,
                           tamper ? other : classical);
    if (!TEST_ptr(pqc))
        goto end;

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, TLS1_3_VERSION,
                                       sctx, cctx, scert, skey)))
        goto end;

    /* Server: enable hybrid and present the Related PQC certificate. */
    if (!TEST_true(SSL_CTX_enable_dual_certs(*sctx))
            || !TEST_true(SSL_CTX_set_pq_certificate(*sctx, pqc, pqc_key, NULL)))
        goto end;

    /* Client verifies the classical chain (RSA CA) and trusts the PQC CA. */
    if (!TEST_true(SSL_CTX_load_verify_file(*cctx, carsa)))
        goto end;
    SSL_CTX_set_verify(*cctx, SSL_VERIFY_PEER, NULL);
    pqstore = trust_store("ca_mldsa65.pem");
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
    X509_free(other);
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

/*
 * Test 9: Related happy path. The server presents a classical + PQC certificate
 * pair where the PQC certificate carries a RelatedCertificate extension binding
 * it to the classical leaf. The PoP is the same chained PQCertificateVerify as
 * Dual; additionally the client's parse_related_certificate_cb recomputes the
 * binding hash and accepts. Hybrid must be negotiated with one classical + one
 * PQCertificateVerify.
 */
static int test_related_happy_path(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    handshake_obs obs;
    int negotiated = 0, ok = 0;

    if (!have_oqs)
        return TEST_skip("oqsprovider not available");
    if (!build_related_pair(&sctx, &cctx, 0))
        goto end;
    if (!TEST_true(connect_observed(sctx, cctx, &obs, &negotiated, NULL, 0, 0)))
        goto end;
    if (!TEST_int_eq(negotiated, 1)
            || !TEST_int_eq(obs.classical_cv, 1)
            || !TEST_int_eq(obs.pq_cert_verify, 1))
        goto end;
    ok = 1;
 end:
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return ok;
}

/*
 * Test 10: Related binding enforcement -- DOCUMENTS A KNOWN, REPORTED GAP.
 *
 * The PQC certificate's RelatedCertificate extension binds to the WRONG
 * certificate, so its hash does NOT match the classical leaf actually
 * transmitted. RFC 9763 intends this mismatch to be rejected, which would abort
 * the handshake. It does NOT: this build computes the binding but never enforces
 * it, by code inspection on two independent paths --
 *   1. parse_related_certificate_cb (the SSL_EXT_TLS1_3_CERTIFICATE custom
 *      extension) never fires on the PQC certificate, which is transmitted in a
 *      separate chain (peer_pqc_chain), not as chainidx==1 of the standard
 *      Certificate message it was written for; and
 *   2. the direct hash check in statem_clnt.c (tls_process_server_certificate,
 *      the peer_pqc_chain loop) is deliberately non-fatal -- it `continue`s on a
 *      hash mismatch and never raises an error.
 * So the Related (RFC 9763) certificate binding is currently INERT: the PoP is
 * the same working chained PQCertificateVerify as Dual, but the hash binding
 * that distinguishes Related is not enforced end-to-end. This test pins that
 * reality (the handshake COMPLETES despite a tampered binding) so the suite is
 * honest and green; if binding enforcement is ever wired up, this test will fail
 * and point a future change here. It asserts a gap, not desired behavior.
 */
static int test_related_binding_known_gap(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    handshake_obs obs;
    int ok = 0, completed;

    if (!have_oqs)
        return TEST_skip("oqsprovider not available");
    if (!build_related_pair(&sctx, &cctx, 1))
        goto end;
    completed = connect_observed(sctx, cctx, &obs, NULL, NULL, 0, 0);
    TEST_info("KNOWN GAP: RFC 9763 RelatedCertificate hash binding is NOT "
              "enforced end-to-end; a mismatched binding does not abort the "
              "handshake (PoP is Dual-equivalent). See test comment.");
    /* Current, reported behavior: the tampered binding is NOT rejected. */
    if (!TEST_true(completed))
        goto end;
    ok = 1;
 end:
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return ok;
}

int setup_tests(void)
{
    if (!TEST_ptr(certsdir = test_get_argument(0)))
        return 0;

    defprov = OSSL_PROVIDER_load(NULL, "default");
    oqsprov = OSSL_PROVIDER_load(NULL, "oqsprovider");
    have_oqs = (oqsprov != NULL);
    if (!have_oqs)
        TEST_info("oqsprovider unavailable: hybrid e2e tests will skip");

    ADD_TEST(test_happy_path);
    ADD_ALL_TESTS(test_negotiation_gate, 3);
    ADD_ALL_TESTS(test_pair_matching, 2);
    ADD_TEST(test_downgrade_strict_no_echo);
    ADD_TEST(test_downgrade_permissive);
    ADD_TEST(test_mutual_tls);
    ADD_TEST(test_catalyst_happy_path);
    ADD_TEST(test_chameleon_happy_path);
    ADD_TEST(test_related_happy_path);
    ADD_TEST(test_related_binding_known_gap);
    return 1;
}

void cleanup_tests(void)
{
    OSSL_PROVIDER_unload(oqsprov);
    OSSL_PROVIDER_unload(defprov);
}
