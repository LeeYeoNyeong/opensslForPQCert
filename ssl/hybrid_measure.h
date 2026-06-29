/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Handshake-internal crypto timing instrumentation for the hybrid PQC
 * measurement harness.
 *
 * This entire facility is compiled out unless the whole tree is configured
 * with -DHYBRID_MEASURE (i.e. a dedicated measurement build).  The default
 * production build sees nothing: no struct fields, no timing calls, no
 * <time.h> dependency.  This keeps measurement instrumentation from leaking
 * into the production handshake path (cf. the debug-printf lesson).
 *
 * Timing is per-connection state (a field on SSL_CONNECTION), never a global,
 * so it is re-entrancy / thread safe.  Each measured EVP_DigestSign /
 * EVP_DigestVerify region accumulates elapsed CLOCK_MONOTONIC nanoseconds into
 * the matching counter; the measurement binary reads the counters off the
 * SSL_CONNECTION after the handshake completes and converts to milliseconds.
 */

#ifndef OSSL_SSL_HYBRID_MEASURE_H
# define OSSL_SSL_HYBRID_MEASURE_H

# ifdef HYBRID_MEASURE

#  include <time.h>
#  include <stdint.h>

/*
 * Per-connection accumulators (nanoseconds).  "sign" counters are populated on
 * the side that constructs a *CertificateVerify; "verify" counters on the side
 * that processes one.  In a one-way (server-auth) TLS 1.3 handshake the server
 * populates the *_sign_ns fields and the client populates the *_verify_ns
 * fields, so a single CSV row pairs a server's sign cost with a client's
 * verify cost only when both endpoints share the same build and the harness
 * collects from both -- otherwise unused counters stay 0.
 */
typedef struct hybrid_measure_st {
    uint64_t pq_sign_ns;
    uint64_t pq_verify_ns;
    uint64_t classical_sign_ns;
    uint64_t classical_verify_ns;
} OSSL_HYBRID_MEASURE;

/*
 * Bracket a measured region with two macros (no helper function, so this header
 * can be included tree-wide via ssl_local.h without emitting an unused-static
 * function into every translation unit):
 *
 *   HYBRID_MEASURE_START(_hm0);
 *   ... EVP_DigestSign/Verify ...
 *   HYBRID_MEASURE_ACCUM(s->hybrid_measure.pq_sign_ns, _hm0);
 *
 * START declares a `struct timespec`, so it must be the first statement of its
 * block (C89 declaration placement); the existing instrumentation sites open a
 * dedicated block for it.  The accumulator is only ever expanded inside
 * statem_lib.c, which already pulls in <time.h>.
 */
#  define HYBRID_MEASURE_START(var) \
    struct timespec var; clock_gettime(CLOCK_MONOTONIC, &(var))

#  define HYBRID_MEASURE_ACCUM(field, var)                                  \
    do {                                                                    \
        struct timespec _hm_end;                                            \
        clock_gettime(CLOCK_MONOTONIC, &_hm_end);                           \
        (field) += ((uint64_t)_hm_end.tv_sec * 1000000000ULL               \
                    + (uint64_t)_hm_end.tv_nsec)                            \
                 - ((uint64_t)(var).tv_sec * 1000000000ULL                  \
                    + (uint64_t)(var).tv_nsec);                             \
    } while (0)

# endif /* HYBRID_MEASURE */

#endif /* OSSL_SSL_HYBRID_MEASURE_H */
