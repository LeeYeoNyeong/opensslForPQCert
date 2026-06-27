/*
 * Phase 4d: Catalyst server-side PQCertificateVerify send path (negative proof).
 *
 * The send path added in this phase signs the PQCertificateVerify with the
 * Catalyst alternative PRIVATE key, while the 4c receive path verifies it with
 * the alternative PUBLIC key recovered from the peer certificate's
 * subjectAltPublicKeyInfo extension via X509_get_alt_pubkey(). For the round
 * trip to hold, two contracts must be true and are proven here against the REAL
 * library code (X509_get_alt_pubkey + EVP_PKEY_eq, the exact primitives the
 * loader ssl_cert_set_catalyst_alt_key and the read path use):
 *
 *   C1  keypair coherence: the alt private key the server loads must match the
 *       alt public key embedded in the certificate. ssl_cert_set_catalyst_alt_key
 *       enforces this with EVP_PKEY_eq(alt_pub, alt_priv); a mismatched key is
 *       refused at load time (so the server can never sign with a key the peer
 *       cannot verify against).
 *
 *   C2  chained sign->verify: the PQ CV TBS is built over the live handshake
 *       hash, which INCLUDES the just-written classical CertificateVerify
 *       (4c chaining). Signing that TBS with the alt private key and verifying
 *       with the cert's alt public key must agree, and tampering the classical
 *       CV must break it (the classical CV is cryptographically bound).
 *
 * Assertions:
 *   T1  X509_get_alt_pubkey recovers the embedded alt key                -> non-NULL
 *   T2  EVP_PKEY_eq(alt_pub, alt_priv) == 1  (loader coherence accepts)  -> PASS
 *   T3  EVP_PKEY_eq(alt_pub, wrong_priv) != 1 (loader coherence rejects) -> PASS
 *   T4  honest chained: sign(alt_priv, TBS_chained) verifies under
 *       alt_pub recovered from the cert                                  -> PASS
 *   T5  1-bit tamper of the classical CV -> recomputed chained TBS, verify
 *       server's original sig                                            -> FAIL
 *   T6  key mismatch: a signature by wrong_priv verified under the cert's
 *       alt_pub                                                          -> FAIL
 *
 * Run for two single-cert PQ algorithms (mldsa44, mldsa65) via oqsprovider.
 */
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* X509_get_alt_pubkey() is declared in x509v3.h (this fork). */

/* mirror of statem_lib.c get_cert_verify_tbs_data() TLS 1.3 layout */
#define TLS13_TBS_START_SIZE     64
#define TLS13_TBS_PREAMBLE_SIZE  (TLS13_TBS_START_SIZE + 33 + 1)
static const char servercontext[] = "TLS 1.3, server CertificateVerify";

static void transcript_hash(const unsigned char *msg, size_t n,
                            unsigned char *out, size_t *outlen) {
    SHA256(msg, n, out);
    *outlen = SHA256_DIGEST_LENGTH;
}

static size_t build_tbs(const unsigned char *hash, size_t hashlen,
                        unsigned char *tbs) {
    memset(tbs, 32, TLS13_TBS_START_SIZE);
    strcpy((char *)tbs + TLS13_TBS_START_SIZE, servercontext);
    memcpy(tbs + TLS13_TBS_PREAMBLE_SIZE, hash, hashlen);
    return TLS13_TBS_PREAMBLE_SIZE + hashlen;
}

static int pq_sign(EVP_PKEY *k, const unsigned char *tbs, size_t tl,
                   unsigned char **sig, size_t *sl) {
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    int ok = 0;
    if (EVP_DigestSignInit_ex(c, NULL, NULL, NULL, NULL, k, NULL) <= 0) goto e;
    if (EVP_DigestSign(c, NULL, sl, tbs, tl) <= 0) goto e;
    *sig = OPENSSL_malloc(*sl);
    if (*sig == NULL || EVP_DigestSign(c, *sig, sl, tbs, tl) <= 0) goto e;
    ok = 1;
e:  EVP_MD_CTX_free(c);
    return ok;
}

static int pq_verify(EVP_PKEY *k, const unsigned char *tbs, size_t tl,
                     const unsigned char *sig, size_t sl) {
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    int rv = -1;
    if (EVP_DigestVerifyInit_ex(c, NULL, NULL, NULL, NULL, k, NULL) <= 0) goto e;
    rv = EVP_DigestVerify(c, sig, sl, tbs, tl);
e:  EVP_MD_CTX_free(c);
    return rv; /* 1 = pass, <=0 = fail */
}

static EVP_PKEY *keygen(const char *alg) {
    EVP_PKEY *k = NULL;
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    if (g && EVP_PKEY_keygen_init(g) > 0)
        EVP_PKEY_keygen(g, &k);
    EVP_PKEY_CTX_free(g);
    return k;
}

/*
 * Build a minimal Catalyst-style certificate: a classical main key plus the alt
 * PQC public key embedded in a subjectAltPublicKeyInfo extension -- exactly what
 * X509_get_alt_pubkey() reads on the peer side. The certificate is NOT chain
 * validated here (that path needs altSignatureValue and is covered e2e), so a
 * self-signature with the main key is sufficient to materialise a real X509.
 */
static X509 *make_catalyst_cert(EVP_PKEY *main_key, EVP_PKEY *alt_pub) {
    X509 *x = X509_new();
    X509_PUBKEY *xpk = NULL;
    X509_NAME *nm = NULL;
    int ok = 0;

    if (x == NULL)
        goto end;
    if (!X509_set_version(x, X509_VERSION_3))
        goto end;
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    if (!X509_set_pubkey(x, main_key))
        goto end;
    nm = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
                               (const unsigned char *)"catalyst.example", -1, -1, 0);
    if (!X509_set_issuer_name(x, nm))
        goto end;

    /* Embed the alt public key in subjectAltPublicKeyInfo (the Catalyst ext). */
    if (!X509_PUBKEY_set(&xpk, alt_pub))
        goto end;
    if (X509_add1_ext_i2d(x, NID_subject_alt_public_key_info, xpk, 0, 0) != 1)
        goto end;

    if (X509_sign(x, main_key, EVP_sha256()) == 0)
        goto end;
    ok = 1;
 end:
    X509_PUBKEY_free(xpk);
    if (!ok) {
        X509_free(x);
        x = NULL;
    }
    return x;
}

static int run(const char *alg) {
    int fails = 0;
    EVP_PKEY *main_key = NULL, *alt_priv = NULL, *wrong_priv = NULL;
    EVP_PKEY *alt_pub = NULL;
    X509 *cert = NULL;
    unsigned char *sig = NULL, *wsig = NULL;
    size_t sl = 0, wsl = 0;

    printf("\n=== algorithm: %s ===\n", alg);

    main_key  = keygen("RSA");
    alt_priv  = keygen(alg);
    wrong_priv = keygen(alg);
    if (!main_key || !alt_priv || !wrong_priv) {
        fprintf(stderr, "keygen failed\n"); ERR_print_errors_fp(stderr);
        fails++; goto end;
    }

    cert = make_catalyst_cert(main_key, alt_priv); /* alt_priv carries its pub */
    if (!cert) {
        fprintf(stderr, "cert build failed\n"); ERR_print_errors_fp(stderr);
        fails++; goto end;
    }

    /* T1: recover the alt public key the way the read path / loader does. */
    alt_pub = X509_get_alt_pubkey(cert);
    printf("T1 X509_get_alt_pubkey recover  : %s (expect non-NULL)\n",
           alt_pub != NULL ? "PASS" : "FAIL");
    if (alt_pub == NULL) { fails++; goto end; }

    /* T2: loader coherence accepts the matching private key. */
    int t2 = EVP_PKEY_eq(alt_pub, alt_priv);
    printf("T2 EVP_PKEY_eq(pub, alt_priv)   : %s (expect PASS=1)\n",
           t2 == 1 ? "PASS" : "FAIL");
    if (t2 != 1) fails++;

    /* T3: loader coherence rejects an unrelated private key. */
    int t3 = EVP_PKEY_eq(alt_pub, wrong_priv);
    printf("T3 EVP_PKEY_eq(pub, wrong_priv) : %s (expect FAIL!=1)\n",
           t3 != 1 ? "PASS" : "FAIL");
    if (t3 == 1) fails++;

    /* Chained TBS: prefix transcript || classical CertificateVerify bytes. */
    unsigned char prefix[256];
    for (size_t i = 0; i < sizeof(prefix); i++) prefix[i] = (unsigned char)(i * 7 + 1);
    unsigned char classicalCV[80];
    for (size_t i = 0; i < sizeof(classicalCV); i++) classicalCV[i] = (unsigned char)(0xA0 ^ i);

    unsigned char buf[sizeof(prefix) + sizeof(classicalCV)];
    memcpy(buf, prefix, sizeof(prefix));
    memcpy(buf + sizeof(prefix), classicalCV, sizeof(classicalCV));
    unsigned char h[EVP_MAX_MD_SIZE]; size_t hl;
    transcript_hash(buf, sizeof(buf), h, &hl);
    unsigned char tbs[TLS13_TBS_PREAMBLE_SIZE + EVP_MAX_MD_SIZE];
    size_t tl = build_tbs(h, hl, tbs);

    /* Server signs with the alt PRIVATE key (this phase's send path). */
    if (!pq_sign(alt_priv, tbs, tl, &sig, &sl)) {
        fprintf(stderr, "alt sign failed\n"); ERR_print_errors_fp(stderr);
        fails++; goto end;
    }

    /* T4: honest receiver verifies with alt_pub recovered from the cert. */
    int t4 = pq_verify(alt_pub, tbs, tl, sig, sl);
    printf("T4 chained honest sign->verify  : %s (expect PASS)\n",
           t4 == 1 ? "PASS" : "FAIL");
    if (t4 != 1) fails++;

    /* T5: tamper 1 bit of the classical CV, recompute chained TBS, verify. */
    unsigned char buf2[sizeof(buf)];
    memcpy(buf2, buf, sizeof(buf));
    buf2[sizeof(prefix) + 10] ^= 0x01;
    unsigned char h2[EVP_MAX_MD_SIZE]; size_t hl2;
    transcript_hash(buf2, sizeof(buf2), h2, &hl2);
    unsigned char tbs2[TLS13_TBS_PREAMBLE_SIZE + EVP_MAX_MD_SIZE];
    size_t tl2 = build_tbs(h2, hl2, tbs2);
    int t5 = pq_verify(alt_pub, tbs2, tl2, sig, sl);
    printf("T5 1-bit classical CV tamper    : %s (expect FAIL = CV bound)\n",
           t5 == 1 ? "PASS" : "FAIL");
    if (t5 == 1) fails++;

    /* T6: a signature by the wrong key must not verify under the cert key. */
    if (!pq_sign(wrong_priv, tbs, tl, &wsig, &wsl)) {
        fprintf(stderr, "wrong sign failed\n"); ERR_print_errors_fp(stderr);
        fails++; goto end;
    }
    int t6 = pq_verify(alt_pub, tbs, tl, wsig, wsl);
    printf("T6 wrong-key sig under cert key : %s (expect FAIL = coherence)\n",
           t6 == 1 ? "PASS" : "FAIL");
    if (t6 == 1) fails++;

 end:
    OPENSSL_free(sig);
    OPENSSL_free(wsig);
    EVP_PKEY_free(alt_pub);
    EVP_PKEY_free(main_key);
    EVP_PKEY_free(alt_priv);
    EVP_PKEY_free(wrong_priv);
    X509_free(cert);
    printf("--> %s: %s\n", alg, fails == 0 ? "ALL OK" : "MISMATCH");
    return fails;
}

int main(void) {
    OSSL_PROVIDER *def = OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER *oqs = OSSL_PROVIDER_load(NULL, "oqsprovider");
    if (!oqs) { fprintf(stderr, "oqsprovider load failed\n"); ERR_print_errors_fp(stderr); return 2; }

    int fails = 0;
    fails += run("mldsa44");
    fails += run("mldsa65");

    printf("\n================ %s ================\n",
           fails == 0 ? "CATALYST SEND PROOF: ALL PASS" : "FAILURES PRESENT");
    OSSL_PROVIDER_unload(oqs);
    if (def) OSSL_PROVIDER_unload(def);
    return fails ? 1 : 0;
}
