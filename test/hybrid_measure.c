/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Real-socket TLS 1.3 handshake measurement driver for the hybrid PQC
 * certificate matrix.
 *
 * Unlike the memory-BIO smoke harness this opens real TCP sockets so it can be
 * driven across AWS instances under netem/tbf network shaping.  It measures
 * three things per handshake:
 *
 *   1. handshake_ms      -- wall time of SSL_connect on the client.
 *   2. crypto timings    -- sign/verify nanoseconds collected by the in-tree
 *                           #ifdef HYBRID_MEASURE instrumentation in
 *                           tls_construct/process_{,pq_}cert_verify.  The client
 *                           reads its own *_verify counters off the
 *                           SSL_CONNECTION; the server hands its *_sign counters
 *                           to the client as a one-line app-data message right
 *                           after the handshake, so a single CSV row carries
 *                           both endpoints' crypto costs.
 *   3. cert_bytes        -- total DER bytes of ALL certificates the server
 *                           transmitted: the main certificate_list (leaf + ICA;
 *                           Chameleon base + both ICAs) plus the separate PQC
 *                           certificate_list (pq_leaf + pq_ICA) for the
 *                           multi-certificate hybrids.  This is the full 3-tier
 *                           handshake transmission size, not just the leaf; the
 *                           Root (trust anchor) is never sent and is excluded.
 *
 * Correctness gating (no fake measurements):
 *   - oqsprovider load is verified at startup; for any PQC format a failure is
 *     fatal (it is never silently skipped / counted as success).
 *   - for the four hybrid formats the client confirms it actually observed and
 *     verified a PQCertificateVerify (msg-callback count == 1 and, in a
 *     measurement build, pq_verify_ns > 0) through the normal verification path
 *     -- there is no verify-callback override.  A handshake that does not meet
 *     this is recorded with verify_ok=0 and does NOT contribute a valid row.
 *
 * CSV columns (header written by --csv-header):
 *   region,format,algorithm,cat_level,loss,bw,run,handshake_ms,
 *   pq_sign_ms,pq_verify_ms,classical_sign_ms,classical_verify_ms,
 *   cert_bytes,verify_ok
 *
 * Composite format note (column semantics):
 *   The "composite" format presents a single leaf certificate whose key is an
 *   oqsprovider composite sigalg (e.g. p384_mldsa65).  Its combined classical+PQC
 *   signature is ONE inseparable operation, so it cannot be split across the
 *   classical_* and pq_* columns.  In this fork is_pqc_only_certificate()
 *   classifies the composite key, so the server emits a single
 *   PQCertificateVerify (no classical CertificateVerify) just like a pure PQC
 *   leaf; the whole composite sign/verify cost is therefore recorded in
 *   pq_sign_ms / pq_verify_ms and classical_sign_ms = classical_verify_ms = 0.
 *   composite is a single-certificate control: hybrid is NOT negotiated and no
 *   separate PQC certificate is sent, so verify_ok mirrors the pure baseline
 *   (a completed handshake with oqsprovider loaded is a valid sample).
 *
 * Build: compiled into the test tree.  For real crypto timings configure the
 * whole tree with -DHYBRID_MEASURE; without it handshake_ms and cert_bytes are
 * still valid and the crypto columns are reported as 0 (a warning is printed
 * once).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/ssl.h>
#include <openssl/provider.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#include "hybrid_fixtures.h"
#include "../ssl/ssl_local.h"

#ifdef _WIN32

/*
 * The measurement driver is POSIX-only (BSD sockets + fork()).  It is added to
 * the default test program list, so on Windows / other non-POSIX targets it
 * compiles to a harmless stub instead of breaking the build.
 */
int main(void)
{
    fprintf(stderr, "hybrid_measure: POSIX-only measurement tool; "
            "not supported on this platform\n");
    return 1;
}

#else  /* !_WIN32 */

#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

/* --- options --------------------------------------------------------------- */

typedef struct {
    const char *role;       /* server | client | loopback */
    const char *format;     /* dual|catalyst|chameleon|related|pure|traditional|composite */
    const char *alg;        /* PQC key-type name, or ECDSA tag for traditional */
    const char *certs;      /* fixture directory */
    const char *host;       /* client: server host */
    int port;
    int runs;
    const char *csv;        /* output CSV path (append); NULL => stdout */
    const char *region;     /* CSV passthrough label */
    const char *loss;       /* CSV passthrough label */
    const char *bw;         /* CSV passthrough label */
    const char *cat_level;  /* CSV passthrough label */
    int csv_header;         /* if set, just print the header and exit */
} opts;

/* Per-handshake collected sample. */
typedef struct {
    double handshake_ms;
    double pq_sign_ms;
    double pq_verify_ms;
    double classical_sign_ms;
    double classical_verify_ms;
    long cert_bytes;
    int verify_ok;
} sample;

static const char *CSV_HEADER =
    "region,format,algorithm,cat_level,loss,bw,run,handshake_ms,"
    "pq_sign_ms,pq_verify_ms,classical_sign_ms,classical_verify_ms,"
    "cert_bytes,verify_ok";

/* --- timing & error helpers ------------------------------------------------ */

static uint64_t now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void die(const char *msg)
{
    fprintf(stderr, "hybrid_measure: %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(2);
}

/* The client counts PoP messages it receives so a bypass cannot pass unnoticed. */
typedef struct {
    int pq_cert_verify;
    int classical_cv;
} obs_t;

static void msg_cb(int write_p, int version, int content_type, const void *buf,
                   size_t len, SSL *ssl, void *arg)
{
    obs_t *o = arg;

    if (content_type != SSL3_RT_HANDSHAKE || len < 1)
        return;
    switch (((const unsigned char *)buf)[0]) {
    case SSL3_MT_PQ_CERTIFICATE_VERIFY: o->pq_cert_verify++; break;
    case SSL3_MT_CERTIFICATE_VERIFY:    o->classical_cv++;   break;
    default: break;
    }
}

/*
 * Read the per-connection crypto counters that the #ifdef HYBRID_MEASURE
 * instrumentation accumulated on this SSL.  Returns 1 if real counters were
 * read, 0 if this is a non-measurement build (callers then report 0 ms).
 */
static int read_crypto_ns(SSL *ssl, uint64_t *pq_sign, uint64_t *pq_verify,
                          uint64_t *cl_sign, uint64_t *cl_verify)
{
#ifdef HYBRID_MEASURE
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL(ssl);

    if (sc == NULL)
        return 0;
    *pq_sign = sc->hybrid_measure.pq_sign_ns;
    *pq_verify = sc->hybrid_measure.pq_verify_ns;
    *cl_sign = sc->hybrid_measure.classical_sign_ns;
    *cl_verify = sc->hybrid_measure.classical_verify_ns;
    return 1;
#else
    *pq_sign = *pq_verify = *cl_sign = *cl_verify = 0;
    return 0;
#endif
}

static int client_hybrid_negotiated(SSL *ssl)
{
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL(ssl);

    return sc != NULL && sc->s3.tmp.hybrid_cert != 0;
}

/*
 * Total DER bytes of every certificate in |chain| (0 for NULL/empty).  Used to
 * size the full transmitted certificate material rather than just the leaf.
 */
static long sum_chain_der(STACK_OF(X509) *chain)
{
    long total = 0;
    int i, n = sk_X509_num(chain);

    for (i = 0; i < n; i++) {
        int len = i2d_X509(sk_X509_value(chain, i), NULL);

        if (len > 0)
            total += len;
    }
    return total;
}

/* --- provider loading ------------------------------------------------------ */

static OSSL_PROVIDER *g_def, *g_oqs;

static int load_providers(int need_pqc)
{
    g_def = OSSL_PROVIDER_load(NULL, "default");
    g_oqs = OSSL_PROVIDER_load(NULL, "oqsprovider");

    if (g_def == NULL) {
        fprintf(stderr, "hybrid_measure: default provider failed to load\n");
        return 0;
    }
    if (g_oqs == NULL) {
        /*
         * Never let a PQC measurement silently degrade to a non-PQC handshake:
         * abort loudly instead of recording fake rows.
         */
        if (need_pqc) {
            fprintf(stderr,
                "hybrid_measure: oqsprovider failed to load but format needs "
                "PQC -- aborting (set OPENSSL_MODULES to the oqsprovider dir)\n");
            return 0;
        }
        fprintf(stderr, "hybrid_measure: warning: oqsprovider not loaded "
                "(traditional baseline only)\n");
    }
    return 1;
}

/* --- TCP plumbing ---------------------------------------------------------- */

static int tcp_listen(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    int yes = 1;

    if (fd < 0)
        return -1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0
            || listen(fd, 16) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int tcp_connect(const char *host, int port)
{
    char portstr[16];
    struct addrinfo hints, *res = NULL, *rp;
    int fd = -1;

    BIO_snprintf(portstr, sizeof(portstr), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0)
        return -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0)
            continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd >= 0) {
        int yes = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
    }
    return fd;
}

/* --- server side ----------------------------------------------------------- */

/*
 * Accept |runs| handshakes.  After each, hand the server's sign timings to the
 * client as one line "<pq_sign_ns> <classical_sign_ns>\n" so the client's CSV
 * row carries both endpoints' crypto cost.  Returns 0 on success.
 */
static int run_server(SSL_CTX *sctx, int listen_fd, int runs)
{
    int i;

    for (i = 0; i < runs; i++) {
        int cfd = accept(listen_fd, NULL, NULL);
        { int _nd = 1; setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &_nd, sizeof(_nd)); }
        SSL *ssl;
        uint64_t ps = 0, pv = 0, cs = 0, cv = 0;
        char line[96];
        int n;

        if (cfd < 0)
            return 1;
        ssl = SSL_new(sctx);
        if (ssl == NULL) {
            close(cfd);
            return 1;
        }
        SSL_set_fd(ssl, cfd);
        if (SSL_accept(ssl) == 1) {
            read_crypto_ns(ssl, &ps, &pv, &cs, &cv);
            n = BIO_snprintf(line, sizeof(line), "%llu %llu\n",
                             (unsigned long long)ps, (unsigned long long)cs);
            if (n > 0)
                SSL_write(ssl, line, n);
            SSL_shutdown(ssl);
        } else {
            /* Report the failure but keep serving the remaining runs. */
            fprintf(stderr, "hybrid_measure: server handshake %d failed\n", i);
            ERR_print_errors_fp(stderr);
        }
        SSL_free(ssl);
        close(cfd);
    }
    return 0;
}

/* --- client side ----------------------------------------------------------- */

/* Read the server's "ps cs\n" timing line. Returns 1 on success. */
static int read_server_timings(SSL *ssl, uint64_t *ps, uint64_t *cs)
{
    char buf[128];
    int total = 0, n;

    *ps = *cs = 0;
    /* The line is short; loop until we see a newline or the peer closes. */
    while (total < (int)sizeof(buf) - 1) {
        n = SSL_read(ssl, buf + total, sizeof(buf) - 1 - total);
        if (n <= 0)
            break;
        total += n;
        buf[total] = '\0';
        if (strchr(buf, '\n') != NULL)
            break;
    }
    if (total <= 0)
        return 0;
    return sscanf(buf, "%llu %llu",
                  (unsigned long long *)ps, (unsigned long long *)cs) == 2;
}

/*
 * Connect, retrying for up to ~5 s so the very first connection of a combo can
 * wait for the matching server process to come up.  Crucially this does NOT use
 * a separate readiness probe: a bare TCP probe would be accept()ed by the
 * server and consumed as a (failed) handshake, throwing the fixed per-combo
 * count out of lockstep.  Every connection here is a real measured handshake.
 */
static int connect_retry(const char *host, int port)
{
    int fd, i;

    for (i = 0; i < 50; i++) {
        fd = tcp_connect(host, port);
        if (fd >= 0)
            return fd;
        usleep(100000);   /* 100 ms */
    }
    return -1;
}

static int run_client_once(SSL_CTX *cctx, const char *host, int port,
                           HF_FORMAT fmt, sample *out)
{
    int fd = connect_retry(host, port);
    SSL *ssl = NULL;
    obs_t obs;
    uint64_t t0, t1, cps = 0, ccs = 0;          /* server-reported sign ns */
    uint64_t ps = 0, pv = 0, cs = 0, cv = 0;    /* client-read counters */
    X509 *peer = NULL;
    int hybrid = hf_format_is_hybrid(fmt);
    int ok = 0;

    memset(out, 0, sizeof(*out));
    memset(&obs, 0, sizeof(obs));
    if (fd < 0) {
        fprintf(stderr, "hybrid_measure: connect failed\n");
        return 0;
    }

    ssl = SSL_new(cctx);
    if (ssl == NULL)
        goto end;
    SSL_set_fd(ssl, fd);
    SSL_set_msg_callback(ssl, msg_cb);
    SSL_set_msg_callback_arg(ssl, &obs);

    t0 = now_ns();
    if (SSL_connect(ssl) != 1) {
        fprintf(stderr, "hybrid_measure: client handshake failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }
    t1 = now_ns();
    out->handshake_ms = (double)(t1 - t0) / 1e6;

    /* Read the server's sign timings before tearing the connection down. */
    read_server_timings(ssl, &cps, &ccs);
    read_crypto_ns(ssl, &ps, &pv, &cs, &cv);

    /* Sign timings come from the server; verify timings from this client. */
    out->pq_sign_ms = (double)cps / 1e6;
    out->classical_sign_ms = (double)ccs / 1e6;
    out->pq_verify_ms = (double)pv / 1e6;
    out->classical_verify_ms = (double)cv / 1e6;

    /*
     * cert_bytes = total transmitted certificate bytes (3-tier handshake
     * transmission overhead), NOT just the leaf.  It sums the DER of every cert
     * the server sent: the main certificate_list (leaf + ICA; for Chameleon
     * base + classical ICA + PQC ICA) plus, for the multi-certificate hybrids
     * (Dual/Related), the separate PQC certificate_list (pq_leaf + pq_ICA).  On
     * the client SSL_get_peer_cert_chain() includes the leaf; the PQC chain is
     * kept on the connection as session->peer_pqc_chain.  The Root (trust
     * anchor) is never transmitted, so it is correctly excluded.
     */
    peer = SSL_get1_peer_certificate(ssl);
    {
        SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL(ssl);
        long cb = sum_chain_der(SSL_get_peer_cert_chain(ssl));

        if (sc != NULL && sc->session != NULL)
            cb += sum_chain_der(sc->session->peer_pqc_chain);
        if (cb == 0 && peer != NULL)     /* fallback: at least the leaf */
            cb = i2d_X509(peer, NULL);
        out->cert_bytes = cb;
    }

    /*
     * Validity gate: the handshake completed AND, for the hybrid formats, a
     * single PQCertificateVerify was actually received and verified via the
     * normal path.  In a measurement build we additionally require the PQ
     * verify counter to be non-zero.
     */
    if (hybrid) {
        int pq_seen = obs.pq_cert_verify == 1;
#ifdef HYBRID_MEASURE
        int pq_timed = pv > 0;
#else
        int pq_timed = 1;
#endif
        out->verify_ok = client_hybrid_negotiated(ssl) && pq_seen && pq_timed;
    } else {
        out->verify_ok = 1;
    }
    ok = out->verify_ok;

 end:
    X509_free(peer);
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (fd >= 0)
        close(fd);
    return ok;
}

static void csv_write_row(FILE *f, const opts *o, int run, const sample *s)
{
    fprintf(f, "%s,%s,%s,%s,%s,%s,%d,%.4f,%.4f,%.4f,%.4f,%.4f,%ld,%d\n",
            o->region, o->format, o->alg, o->cat_level, o->loss, o->bw,
            run, s->handshake_ms, s->pq_sign_ms, s->pq_verify_ms,
            s->classical_sign_ms, s->classical_verify_ms,
            s->cert_bytes, s->verify_ok);
    fflush(f);
}

static int run_client(SSL_CTX *cctx, const opts *o, HF_FORMAT fmt)
{
    FILE *f = stdout;
    int i, valid = 0;

    if (o->csv != NULL && (f = fopen(o->csv, "a")) == NULL)
        die("cannot open CSV output");

    for (i = 0; i < o->runs; i++) {
        sample s;

        run_client_once(cctx, o->host, o->port, fmt, &s);
        csv_write_row(f, o, i, &s);
        if (s.verify_ok)
            valid++;
    }

    if (f != stdout)
        fclose(f);
    fprintf(stderr, "hybrid_measure: %d/%d valid handshakes (%s x %s)\n",
            valid, o->runs, o->format, o->alg);
    return valid == o->runs ? 0 : 1;
}

/* --- loopback (local validation): fork server child, run client in parent -- */

static int run_loopback(const opts *o, HF_FORMAT fmt)
{
    int listen_fd = tcp_listen(o->port);
    int port = o->port;
    pid_t pid;
    int rc = 1;

    if (listen_fd < 0)
        die("loopback: listen failed");

    /* If port 0 was requested, discover the ephemeral port for the client. */
    if (port == 0) {
        struct sockaddr_in a;
        socklen_t al = sizeof(a);

        if (getsockname(listen_fd, (struct sockaddr *)&a, &al) == 0)
            port = ntohs(a.sin_port);
    }

    pid = fork();
    if (pid < 0)
        die("loopback: fork failed");

    if (pid == 0) {
        /* Child: server. Build its own CTX (post-fork) and serve. */
        SSL_CTX *sctx = NULL, *cctx = NULL;
        int src;

        if (!hf_build_pair(fmt, o->alg, o->certs, &sctx, &cctx))
            _exit(3);
        SSL_CTX_free(cctx);
        src = run_server(sctx, listen_fd, o->runs);
        SSL_CTX_free(sctx);
        close(listen_fd);
        _exit(src);
    } else {
        /* Parent: client. */
        SSL_CTX *sctx = NULL, *cctx = NULL;
        opts co = *o;
        int st = 0;

        close(listen_fd);
        co.host = "127.0.0.1";
        co.port = port;
        if (hf_build_pair(fmt, o->alg, o->certs, &sctx, &cctx)) {
            SSL_CTX_free(sctx);
            rc = run_client(cctx, &co, fmt);
            SSL_CTX_free(cctx);
        }
        waitpid(pid, &st, 0);
        if (WIFEXITED(st) && WEXITSTATUS(st) != 0)
            fprintf(stderr, "hybrid_measure: server child exited %d\n",
                    WEXITSTATUS(st));
    }
    return rc;
}

/* --- argument parsing ------------------------------------------------------ */

static const char *arg_val(int argc, char **argv, int *i)
{
    if (*i + 1 >= argc) {
        fprintf(stderr, "hybrid_measure: missing value for %s\n", argv[*i]);
        exit(2);
    }
    return argv[++(*i)];
}

static void usage(void)
{
    fprintf(stderr,
        "usage: hybrid_measure --role {server|client|loopback} "
        "--format FMT --alg ALG --certs DIR\n"
        "         [--host H] [--port P] [--runs N] [--csv FILE]\n"
        "         [--region R] [--loss L] [--bw B] [--cat-level C]\n"
        "       hybrid_measure --csv-header\n"
        "  FMT: dual|catalyst|chameleon|related|pure|traditional|composite\n");
}

int main(int argc, char **argv)
{
    opts o;
    HF_FORMAT fmt;
    SSL_CTX *sctx = NULL, *cctx = NULL;
    int i, rc = 1, need_pqc;

    memset(&o, 0, sizeof(o));
    o.role = "loopback";
    o.host = "127.0.0.1";
    o.port = 4433;
    o.runs = 100;
    o.region = o.loss = o.bw = o.cat_level = "-";

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--role") == 0)            o.role = arg_val(argc, argv, &i);
        else if (strcmp(argv[i], "--format") == 0)     o.format = arg_val(argc, argv, &i);
        else if (strcmp(argv[i], "--alg") == 0)        o.alg = arg_val(argc, argv, &i);
        else if (strcmp(argv[i], "--certs") == 0)      o.certs = arg_val(argc, argv, &i);
        else if (strcmp(argv[i], "--host") == 0)       o.host = arg_val(argc, argv, &i);
        else if (strcmp(argv[i], "--port") == 0)       o.port = atoi(arg_val(argc, argv, &i));
        else if (strcmp(argv[i], "--runs") == 0)       o.runs = atoi(arg_val(argc, argv, &i));
        else if (strcmp(argv[i], "--csv") == 0)        o.csv = arg_val(argc, argv, &i);
        else if (strcmp(argv[i], "--region") == 0)     o.region = arg_val(argc, argv, &i);
        else if (strcmp(argv[i], "--loss") == 0)       o.loss = arg_val(argc, argv, &i);
        else if (strcmp(argv[i], "--bw") == 0)         o.bw = arg_val(argc, argv, &i);
        else if (strcmp(argv[i], "--cat-level") == 0)  o.cat_level = arg_val(argc, argv, &i);
        else if (strcmp(argv[i], "--csv-header") == 0) o.csv_header = 1;
        else { usage(); return 2; }
    }

    if (o.csv_header) {
        printf("%s\n", CSV_HEADER);
        return 0;
    }

    if (o.format == NULL || o.alg == NULL || o.certs == NULL) {
        usage();
        return 2;
    }
    if (!hf_format_from_name(o.format, &fmt)) {
        fprintf(stderr, "hybrid_measure: unknown format '%s'\n", o.format);
        return 2;
    }
    if (o.runs < 1)
        o.runs = 1;

#ifndef HYBRID_MEASURE
    fprintf(stderr, "hybrid_measure: NOTE built without -DHYBRID_MEASURE; "
            "crypto timing columns will be 0 (handshake_ms still valid)\n");
#endif

    need_pqc = fmt != HF_TRADITIONAL;
    if (!load_providers(need_pqc))
        return 2;

    if (strcmp(o.role, "loopback") == 0) {
        rc = run_loopback(&o, fmt);
    } else if (strcmp(o.role, "server") == 0) {
        int listen_fd = tcp_listen(o.port);

        if (listen_fd < 0)
            die("server: listen failed");
        if (!hf_build_pair(fmt, o.alg, o.certs, &sctx, &cctx))
            die("server: fixture build failed (certs/oqsprovider?)");
        SSL_CTX_free(cctx);
        rc = run_server(sctx, listen_fd, o.runs);
        SSL_CTX_free(sctx);
        close(listen_fd);
    } else if (strcmp(o.role, "client") == 0) {
        if (!hf_build_pair(fmt, o.alg, o.certs, &sctx, &cctx))
            die("client: fixture build failed (certs/oqsprovider?)");
        SSL_CTX_free(sctx);
        rc = run_client(cctx, &o, fmt);
        SSL_CTX_free(cctx);
    } else {
        usage();
        rc = 2;
    }

    OSSL_PROVIDER_unload(g_oqs);
    OSSL_PROVIDER_unload(g_def);
    return rc;
}

#endif  /* _WIN32 */
