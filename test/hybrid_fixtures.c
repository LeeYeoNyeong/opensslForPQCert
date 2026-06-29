/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/obj_mac.h>
#include <openssl/v3_dcd.h>
#include <openssl/v3_certbind.h>
#include <openssl/err.h>

#include "hybrid_fixtures.h"

extern int SSL_CTX_set1_pq_verify_store(SSL_CTX *ctx, X509_STORE *store);

/*
 * Local, testutil-free equivalents of test_mk_file_path() and
 * create_ssl_ctx_pair() so this fixture module can be linked into both the
 * testutil-based smoke harness and the plain-main() measurement binary.
 */
static char *hf_path(const char *dir, const char *name)
{
    size_t dlen = strlen(dir), nlen = strlen(name);
    char *p = OPENSSL_malloc(dlen + 1 + nlen + 1);

    if (p == NULL)
        return NULL;
    memcpy(p, dir, dlen);
    p[dlen] = '/';
    memcpy(p + dlen + 1, name, nlen);
    p[dlen + 1 + nlen] = '\0';
    return p;
}

static int hf_ctx_pair(SSL_CTX **sctx, SSL_CTX **cctx,
                       const char *certfile, const char *keyfile)
{
    SSL_CTX *s = SSL_CTX_new(TLS_server_method());
    SSL_CTX *c = SSL_CTX_new(TLS_client_method());

    if (s == NULL || c == NULL)
        goto err;
    if (!SSL_CTX_set_min_proto_version(s, TLS1_3_VERSION)
            || !SSL_CTX_set_max_proto_version(s, TLS1_3_VERSION)
            || !SSL_CTX_set_min_proto_version(c, TLS1_3_VERSION)
            || !SSL_CTX_set_max_proto_version(c, TLS1_3_VERSION))
        goto err;
    if (SSL_CTX_use_certificate_file(s, certfile, SSL_FILETYPE_PEM) != 1
            || SSL_CTX_use_PrivateKey_file(s, keyfile, SSL_FILETYPE_PEM) != 1
            || SSL_CTX_check_private_key(s) != 1)
        goto err;
    *sctx = s;
    *cctx = c;
    return 1;
 err:
    SSL_CTX_free(s);
    SSL_CTX_free(c);
    return 0;
}

/* --- name <-> format -------------------------------------------------------- */

static const char *const FMT_NAMES[HF_FORMAT_COUNT] = {
    "dual", "catalyst", "chameleon", "related", "pure", "traditional"
};

const char *hf_format_name(HF_FORMAT fmt)
{
    if ((int)fmt < 0 || (int)fmt >= HF_FORMAT_COUNT)
        return "?";
    return FMT_NAMES[fmt];
}

int hf_format_from_name(const char *name, HF_FORMAT *out)
{
    int i;

    if (name == NULL)
        return 0;
    for (i = 0; i < HF_FORMAT_COUNT; i++) {
        if (strcmp(name, FMT_NAMES[i]) == 0) {
            *out = (HF_FORMAT)i;
            return 1;
        }
    }
    return 0;
}

int hf_format_is_hybrid(HF_FORMAT fmt)
{
    return fmt == HF_DUAL || fmt == HF_CATALYST
        || fmt == HF_CHAMELEON || fmt == HF_RELATED;
}

/* --- fixture loading helpers ----------------------------------------------- */

/* Format a per-algorithm fixture name (printf-style with a single %s). */
static const char *af(char *buf, size_t n, const char *fmt, const char *alg)
{
    BIO_snprintf(buf, n, fmt, alg);
    return buf;
}

static char *cert_path(const char *certsdir, const char *name)
{
    return hf_path(certsdir, name);
}

static X509 *load_cert(const char *certsdir, const char *name)
{
    char *path = cert_path(certsdir, name);
    BIO *b = NULL;
    X509 *x = NULL;

    if (path != NULL && (b = BIO_new_file(path, "r")) != NULL)
        x = PEM_read_bio_X509(b, NULL, NULL, NULL);
    BIO_free(b);
    OPENSSL_free(path);
    return x;
}

static EVP_PKEY *load_key(const char *certsdir, const char *name)
{
    char *path = cert_path(certsdir, name);
    BIO *b = NULL;
    EVP_PKEY *k = NULL;

    if (path != NULL && (b = BIO_new_file(path, "r")) != NULL)
        k = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
    BIO_free(b);
    OPENSSL_free(path);
    return k;
}

static X509_STORE *trust_store(const char *certsdir, const char *name)
{
    X509_STORE *store = X509_STORE_new();
    X509 *ca = load_cert(certsdir, name);

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

/* --- per-format builders --------------------------------------------------- */

/* Dual: server presents a separate per-algorithm PQC certificate. */
static int build_dual(const char *pq, const char *cd,
                      SSL_CTX **sctx, SSL_CTX **cctx)
{
    char nb[160], kb[160], cab[160];
    char *scert = cert_path(cd, "server_rsa_cert.pem");
    char *skey = cert_path(cd, "server_rsa_key.pem");
    char *carsa = cert_path(cd, "ca_rsa.pem");
    X509 *pqcert = load_cert(cd, af(nb, sizeof(nb), "server_%s_cert.pem", pq));
    EVP_PKEY *pqkey = load_key(cd, af(kb, sizeof(kb), "server_%s_key.pem", pq));
    X509_STORE *pqstore = trust_store(cd, af(cab, sizeof(cab), "ca_%s.pem", pq));
    int ok = 0;

    if (scert == NULL || skey == NULL || carsa == NULL
            || pqcert == NULL || pqkey == NULL || pqstore == NULL)
        goto end;

    if (!hf_ctx_pair(sctx, cctx, scert, skey))
        goto end;

    if (!SSL_CTX_load_verify_file(*cctx, carsa))
        goto end;
    SSL_CTX_set_verify(*cctx, SSL_VERIFY_PEER, NULL);

    if (!SSL_CTX_enable_dual_certs(*sctx)
            || !SSL_CTX_set_pq_certificate(*sctx, pqcert, pqkey, NULL))
        goto end;
    if (!SSL_CTX_enable_dual_certs(*cctx)
            || !SSL_CTX_set1_pq_verify_store(*cctx, pqstore))
        goto end;

    ok = 1;
 end:
    OPENSSL_free(scert);
    OPENSSL_free(skey);
    OPENSSL_free(carsa);
    X509_free(pqcert);
    EVP_PKEY_free(pqkey);
    X509_STORE_free(pqstore);
    return ok;
}

/* Catalyst: single RSA leaf carrying the PQC alt key; alt key loaded via API. */
static int build_catalyst(const char *pq, const char *cd,
                          SSL_CTX **sctx, SSL_CTX **cctx)
{
    char cb[160], kb[160], ab[160];
    char *scert = cert_path(cd, af(cb, sizeof(cb), "catalyst_%s_cert.pem", pq));
    char *skey = cert_path(cd, af(kb, sizeof(kb), "catalyst_%s_key.pem", pq));
    X509 *catcert = load_cert(cd, af(cb, sizeof(cb), "catalyst_%s_cert.pem", pq));
    EVP_PKEY *altkey = load_key(cd, af(ab, sizeof(ab), "catalyst_%s_alt_key.pem", pq));
    char *carsa = cert_path(cd, "ca_rsa.pem");
    int ok = 0;

    if (scert == NULL || skey == NULL || catcert == NULL
            || altkey == NULL || carsa == NULL)
        goto end;

    if (!hf_ctx_pair(sctx, cctx, scert, skey))
        goto end;

    if (!SSL_CTX_load_verify_file(*cctx, carsa))
        goto end;
    SSL_CTX_set_verify(*cctx, SSL_VERIFY_PEER, NULL);

    if (!SSL_CTX_enable_dual_certs(*sctx)
            || !SSL_CTX_set_catalyst_alt_key(*sctx, catcert, altkey))
        goto end;
    if (!SSL_CTX_enable_dual_certs(*cctx))
        goto end;

    ok = 1;
 end:
    OPENSSL_free(scert);
    OPENSSL_free(skey);
    OPENSSL_free(carsa);
    X509_free(catcert);
    EVP_PKEY_free(altkey);
    return ok;
}

/* Chameleon Base = RSA leaf carrying a deltaCertificateDescriptor for the Delta. */
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

static int build_chameleon(const char *pq, const char *cd,
                           SSL_CTX **sctx, SSL_CTX **cctx)
{
    char cab[160], cakb[160], dkb[160], pqcab[160];
    char *scert = cert_path(cd, "server_rsa_cert.pem");
    char *skey = cert_path(cd, "server_rsa_key.pem");
    char *carsa = cert_path(cd, "ca_rsa.pem");
    X509 *ca_rsa = load_cert(cd, "ca_rsa.pem");
    EVP_PKEY *ca_rsa_key = load_key(cd, "ca_rsa_key.pem");
    X509 *ca_pq = load_cert(cd, af(cab, sizeof(cab), "ca_%s.pem", pq));
    EVP_PKEY *ca_pq_key = load_key(cd, af(cakb, sizeof(cakb), "ca_%s_key.pem", pq));
    EVP_PKEY *base_main = load_key(cd, "server_rsa_key.pem");
    EVP_PKEY *delta_key = load_key(cd, af(dkb, sizeof(dkb), "server_%s_key.pem", pq));
    X509 *base = NULL;
    X509_STORE *pqstore = NULL;
    int ok = 0;

    if (scert == NULL || skey == NULL || carsa == NULL
            || ca_rsa == NULL || ca_rsa_key == NULL || ca_pq == NULL
            || ca_pq_key == NULL || base_main == NULL || delta_key == NULL)
        goto end;

    base = make_chameleon_base(ca_rsa, ca_rsa_key, ca_pq, ca_pq_key,
                               base_main, delta_key);
    if (base == NULL)
        goto end;

    if (!hf_ctx_pair(sctx, cctx, scert, skey))
        goto end;

    if (!SSL_CTX_use_certificate(*sctx, base)
            || !SSL_CTX_use_PrivateKey(*sctx, base_main))
        goto end;

    if (!SSL_CTX_load_verify_file(*cctx, carsa))
        goto end;
    SSL_CTX_set_verify(*cctx, SSL_VERIFY_PEER, NULL);

    pqstore = trust_store(cd, af(pqcab, sizeof(pqcab), "ca_%s.pem", pq));
    if (pqstore == NULL || !SSL_CTX_set1_pq_verify_store(*cctx, pqstore))
        goto end;

    if (!SSL_CTX_enable_dual_certs(*sctx)
            || !SSL_CTX_set_chameleon_delta_key(*sctx, base, delta_key))
        goto end;
    if (!SSL_CTX_enable_dual_certs(*cctx))
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

static int build_related(const char *pq, const char *cd,
                         SSL_CTX **sctx, SSL_CTX **cctx)
{
    char cab[160], cakb[160], pkb[160], pqcab[160];
    char *scert = cert_path(cd, "server_rsa_cert.pem");
    char *skey = cert_path(cd, "server_rsa_key.pem");
    char *carsa = cert_path(cd, "ca_rsa.pem");
    X509 *classical = load_cert(cd, "server_rsa_cert.pem");
    X509 *ca_pq = load_cert(cd, af(cab, sizeof(cab), "ca_%s.pem", pq));
    EVP_PKEY *ca_pq_key = load_key(cd, af(cakb, sizeof(cakb), "ca_%s_key.pem", pq));
    EVP_PKEY *pqc_key = load_key(cd, af(pkb, sizeof(pkb), "server_%s_key.pem", pq));
    X509 *pqc = NULL;
    X509_STORE *pqstore = NULL;
    int ok = 0;

    if (scert == NULL || skey == NULL || carsa == NULL
            || classical == NULL || ca_pq == NULL
            || ca_pq_key == NULL || pqc_key == NULL)
        goto end;

    /* Bind the PQC leaf to the classical leaf that is actually transmitted. */
    pqc = make_related_pqc(pqc_key, ca_pq, ca_pq_key, classical);
    if (pqc == NULL)
        goto end;

    if (!hf_ctx_pair(sctx, cctx, scert, skey))
        goto end;

    if (!SSL_CTX_enable_dual_certs(*sctx)
            || !SSL_CTX_set_pq_certificate(*sctx, pqc, pqc_key, NULL))
        goto end;

    if (!SSL_CTX_load_verify_file(*cctx, carsa))
        goto end;
    SSL_CTX_set_verify(*cctx, SSL_VERIFY_PEER, NULL);
    pqstore = trust_store(cd, af(pqcab, sizeof(pqcab), "ca_%s.pem", pq));
    if (pqstore == NULL || !SSL_CTX_set1_pq_verify_store(*cctx, pqstore))
        goto end;
    if (!SSL_CTX_enable_dual_certs(*cctx))
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
    return ok;
}

/*
 * Pure PQC baseline: server presents a PQC leaf as its only certificate.  This
 * is the standard TLS 1.3 path -- the CertificateVerify itself carries the PQC
 * signature, there is no PQCertificateVerify and hybrid is not enabled.
 */
static int build_pure(const char *pq, const char *cd,
                      SSL_CTX **sctx, SSL_CTX **cctx)
{
    char cb[160], kb[160], cab[160];
    char *scert = cert_path(cd, af(cb, sizeof(cb), "server_%s_cert.pem", pq));
    char *skey = cert_path(cd, af(kb, sizeof(kb), "server_%s_key.pem", pq));
    char *capq = cert_path(cd, af(cab, sizeof(cab), "ca_%s.pem", pq));
    int ok = 0;

    if (scert == NULL || skey == NULL || capq == NULL)
        goto end;

    if (!hf_ctx_pair(sctx, cctx, scert, skey))
        goto end;

    if (!SSL_CTX_load_verify_file(*cctx, capq))
        goto end;
    SSL_CTX_set_verify(*cctx, SSL_VERIFY_PEER, NULL);

    ok = 1;
 end:
    OPENSSL_free(scert);
    OPENSSL_free(skey);
    OPENSSL_free(capq);
    return ok;
}

/*
 * Traditional baseline: classical ECDSA leaf.  |pq| names the curve fixture
 * tag ("p256"/"p384"/"p521"); fixtures are ecdsa_<tag>_{cert,key}.pem with CA
 * ca_ecdsa_<tag>.pem.
 */
static int build_traditional(const char *tag, const char *cd,
                             SSL_CTX **sctx, SSL_CTX **cctx)
{
    char cb[160], kb[160], cab[160];
    char *scert = cert_path(cd, af(cb, sizeof(cb), "ecdsa_%s_cert.pem", tag));
    char *skey = cert_path(cd, af(kb, sizeof(kb), "ecdsa_%s_key.pem", tag));
    char *caec = cert_path(cd, af(cab, sizeof(cab), "ca_ecdsa_%s.pem", tag));
    int ok = 0;

    if (scert == NULL || skey == NULL || caec == NULL)
        goto end;

    if (!hf_ctx_pair(sctx, cctx, scert, skey))
        goto end;

    if (!SSL_CTX_load_verify_file(*cctx, caec))
        goto end;
    SSL_CTX_set_verify(*cctx, SSL_VERIFY_PEER, NULL);

    ok = 1;
 end:
    OPENSSL_free(scert);
    OPENSSL_free(skey);
    OPENSSL_free(caec);
    return ok;
}

int hf_build_pair(HF_FORMAT fmt, const char *pq_alg, const char *certsdir,
                  SSL_CTX **sctx, SSL_CTX **cctx)
{
    int ok = 0;

    *sctx = NULL;
    *cctx = NULL;

    switch (fmt) {
    case HF_DUAL:        ok = build_dual(pq_alg, certsdir, sctx, cctx); break;
    case HF_CATALYST:    ok = build_catalyst(pq_alg, certsdir, sctx, cctx); break;
    case HF_CHAMELEON:   ok = build_chameleon(pq_alg, certsdir, sctx, cctx); break;
    case HF_RELATED:     ok = build_related(pq_alg, certsdir, sctx, cctx); break;
    case HF_PURE:        ok = build_pure(pq_alg, certsdir, sctx, cctx); break;
    case HF_TRADITIONAL: ok = build_traditional(pq_alg, certsdir, sctx, cctx); break;
    default:             ok = 0; break;
    }

    if (!ok) {
        SSL_CTX_free(*sctx);
        SSL_CTX_free(*cctx);
        *sctx = NULL;
        *cctx = NULL;
    }
    return ok;
}
