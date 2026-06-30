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
 *
 * Composite is also exercised, as a single-certificate control: its leaf carries
 * an oqsprovider composite sigalg key, which is_pqc_only_certificate() classifies
 * so the server sends ONE PQCertificateVerify and no classical CertificateVerify,
 * and hybrid is NOT negotiated.  Composite fixtures are regenerated on the
 * measurement host (not committed), so the composite cases skip gracefully when
 * their PEMs are absent (see fixtures_present()).
 *
 * Each hybrid case drives a real TLS 1.3 handshake over shared-memory BIOs and
 * asserts that hybrid auth was negotiated, that exactly one classical
 * CertificateVerify and one PQCertificateVerify were observed (the PoP was
 * actually sent AND the client verified it through the normal path -- there is
 * no verify callback override), and that the handshake completed.  The composite
 * case asserts the single-PQCertificateVerify / hybrid-not-negotiated outcome.
 *
 * The per-format SSL_CTX wiring lives in the shared hybrid_fixtures module
 * (also used by the real-socket measurement binary); this file only drives the
 * memory-BIO handshake and asserts the observable outcome.
 *
 * Fixtures live under test/certs/hybrid_e2e/smoke/ and are produced by
 * gen_smoke_certs.sh.  PQC operations require oqsprovider; without it the tests
 * skip.
 */

#include <openssl/ssl.h>
#include <openssl/provider.h>
#include <openssl/err.h>

#include "helpers/ssltestlib.h"
#include "testutil.h"
#include "hybrid_fixtures.h"

/* Internal header: read the negotiated hybrid state directly (no public API). */
#include "../ssl/ssl_local.h"

static char *certsdir = NULL;
static OSSL_PROVIDER *defprov = NULL;
static OSSL_PROVIDER *oqsprov = NULL;
static int have_oqs = 0;

/*
 * The measurement algorithm set, as fixture *labels*.  hf_build_pair() uses
 * these only to locate the per-algorithm PEM fixtures (server_<label>_cert.pem,
 * ...) produced by gen_smoke_certs.sh; they are not fed to genpkey or to the
 * negotiation match.  For ML-DSA / Falcon the label equals the oqsprovider
 * key-type name; for SLH-DSA we keep the FIPS-205 label (slhdsasha2*) while the
 * fixtures were generated under, and TLS negotiation matches on, the provider
 * name (sphincssha2*simple, resolved in ssl/t1_lib.c from the key itself).
 */
static const char *const ALGS[] = {
    "mldsa44", "mldsa65", "mldsa87",
    "falcon512", "falcon1024",
    "slhdsasha2128s", "slhdsasha2128f",
    "slhdsasha2192s", "slhdsasha2192f",
    "slhdsasha2256s", "slhdsasha2256f",
};
#define NALG ((int)OSSL_NELEM(ALGS))

/*
 * Composite fixture labels (ECDSA curve paired to the PQC level).  For SLH-DSA
 * the label keeps the FIPS-205 naming while the key was generated under the
 * provider name (e.g. p256_slhdsasha2128f -> p256_sphincssha2128fsimple), as in
 * gen_smoke_certs.sh.  These select server_<label>_cert.pem / ca_<label>.pem.
 */
static const char *const COMPOSITE_ALGS[] = {
    "p256_mldsa44", "p384_mldsa65", "p521_mldsa87",
    "p256_falcon512", "p521_falcon1024",
    "p256_slhdsasha2128s", "p256_slhdsasha2128f",
    "p384_slhdsasha2192s", "p384_slhdsasha2192f",
    "p521_slhdsasha2256s", "p521_slhdsasha2256f",
};
#define NCOMP ((int)OSSL_NELEM(COMPOSITE_ALGS))

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

/* --- Parameterised tests: one per format, indexed over ALGS -------------- */

static int run_format(int idx, HF_FORMAT fmt)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    int ok = 0;

    if (!have_oqs)
        return TEST_skip("oqsprovider not available");

    TEST_info("%s x %s", hf_format_name(fmt), ALGS[idx]);

    if (!TEST_true(hf_build_pair(fmt, ALGS[idx], certsdir, &sctx, &cctx)))
        goto end;
    if (!expect_hybrid_ok(sctx, cctx))
        goto end;
    ok = 1;
 end:
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return ok;
}

static int test_dual(int idx)      { return run_format(idx, HF_DUAL); }
static int test_catalyst(int idx)  { return run_format(idx, HF_CATALYST); }
static int test_chameleon(int idx) { return run_format(idx, HF_CHAMELEON); }
static int test_related(int idx)   { return run_format(idx, HF_RELATED); }

/* Composite fixtures are regenerated on the measurement host, not committed. */
static int fixtures_present(const char *label)
{
    char path[256];
    BIO *b;

    BIO_snprintf(path, sizeof(path), "%s/server_%s_cert.pem", certsdir, label);
    if ((b = BIO_new_file(path, "r")) == NULL)
        return 0;
    BIO_free(b);
    return 1;
}

/*
 * Composite control: a single leaf carrying a composite sigalg key.  Unlike the
 * four hybrid formats, hybrid is NOT negotiated and the server sends exactly one
 * PQCertificateVerify with no classical CertificateVerify.
 */
static int test_composite(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    handshake_obs obs;
    int negotiated = 0, ok = 0;

    if (!have_oqs)
        return TEST_skip("oqsprovider not available");
    if (!fixtures_present(COMPOSITE_ALGS[idx]))
        return TEST_skip("composite fixtures absent (regenerated on measure host)");

    TEST_info("composite x %s", COMPOSITE_ALGS[idx]);

    if (!TEST_true(hf_build_pair(HF_COMPOSITE, COMPOSITE_ALGS[idx], certsdir,
                                 &sctx, &cctx)))
        goto end;
    if (!TEST_true(connect_observed(sctx, cctx, &obs, &negotiated, NULL)))
        goto end;
    if (!TEST_int_eq(negotiated, 0)
            || !TEST_int_eq(obs.classical_cv, 0)
            || !TEST_int_eq(obs.pq_cert_verify, 1))
        goto end;
    ok = 1;
 end:
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return ok;
}

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
    ADD_ALL_TESTS(test_composite, NCOMP);
    return 1;
}

void cleanup_tests(void)
{
    OSSL_PROVIDER_unload(oqsprov);
    OSSL_PROVIDER_unload(defprov);
}
