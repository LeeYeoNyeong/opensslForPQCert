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
 * Only the Dual (multi-certificate) format is driven end-to-end here; both the
 * send and receive sides of that format are fully wired.  The single-certificate
 * Catalyst send path is not wired (the server has no way to sign
 * PQCertificateVerify with a certificate's alternative private key), so Catalyst
 * is covered by the standalone chaining proof in test/phase4c_repro/ instead.
 *
 * PQC operations require oqsprovider; if it cannot be loaded the tests skip.
 */

#include <openssl/ssl.h>
#include <openssl/provider.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
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
    return 1;
}

void cleanup_tests(void)
{
    OSSL_PROVIDER_unload(oqsprov);
    OSSL_PROVIDER_unload(defprov);
}
