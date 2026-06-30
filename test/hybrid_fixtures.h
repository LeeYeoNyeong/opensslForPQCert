/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Shared hybrid-format SSL_CTX fixture builders.
 *
 * The cross-algorithm smoke harness (memory-BIO) and the AWS measurement
 * binary (real sockets) both need to stand up a server/client SSL_CTX pair
 * configured for a given hybrid certificate format and PQC algorithm.  The
 * builders are factored here so there is a single source of truth for the
 * per-format certificate wiring; the two front-ends differ only in transport.
 *
 * Fixtures live under <certsdir> and are produced by gen_smoke_certs.sh.  PQC
 * operations require oqsprovider to be loaded in the default library context
 * before these are called.
 */

#ifndef OSSL_TEST_HYBRID_FIXTURES_H
# define OSSL_TEST_HYBRID_FIXTURES_H

# include <openssl/ssl.h>

typedef enum {
    HF_DUAL = 0,    /* separate per-algorithm PQC certificate chain          */
    HF_CATALYST,    /* RSA leaf carrying PQC alt public key + alt signature  */
    HF_CHAMELEON,   /* RSA base leaf carrying a deltaCertificateDescriptor   */
    HF_RELATED,     /* PQC leaf carrying an RFC 9763 RelatedCertificate ext  */
    HF_PURE,        /* pure PQC leaf, standard signature_algorithms path     */
    HF_TRADITIONAL, /* classical ECDSA leaf, baseline (no PQC)               */
    HF_FORMAT_COUNT
} HF_FORMAT;

/*
 * Build a configured (server, client) SSL_CTX pair for |fmt|.  For the hybrid
 * and pure formats |pq_alg| is the per-algorithm fixture *label* (e.g.
 * "mldsa65", "slhdsasha2128f"); it selects the PEM fixtures by name only and is
 * never passed to a provider.  For SLH-DSA the label differs from the provider
 * key-type name the fixtures were generated under (sphincssha2*simple).  For
 * HF_TRADITIONAL |pq_alg| names the ECDSA curve fixture tag
 * ("p256"/"p384"/"p521").  Returns 1 on success; on failure
 * returns 0 with *sctx,*cctx freed and set to NULL.
 */
int hf_build_pair(HF_FORMAT fmt, const char *pq_alg, const char *certsdir,
                  SSL_CTX **sctx, SSL_CTX **cctx);

/* "dual"/"catalyst"/"chameleon"/"related"/"pure"/"traditional". */
const char *hf_format_name(HF_FORMAT fmt);
int hf_format_from_name(const char *name, HF_FORMAT *out);

/* 1 for the four negotiated hybrid formats (a PQCertificateVerify is expected). */
int hf_format_is_hybrid(HF_FORMAT fmt);

#endif /* OSSL_TEST_HYBRID_FIXTURES_H */
