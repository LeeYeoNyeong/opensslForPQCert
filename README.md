# Hybrid PQC Certificates in TLS 1.3 — Reproduction Artifact

This repository is an OpenSSL fork that implements and benchmarks **hybrid
post-quantum certificate formats** in TLS 1.3. It is the public reproduction
artifact for the paper:

> **From Standards to Practice: Benchmarking Hybrid PQC Certificates in TLS 1.3**
> Submitted to *IEEE Network* (under revision — bibliographic details will be
> added if accepted).

During the migration to post-quantum cryptography, certificates must often carry
*both* a classical and a post-quantum signature so that the connection remains
verifiable by parties that trust only one of the two. Several competing
"hybrid certificate" formats have been proposed to encode this pairing. This
fork implements four of them behind a single TLS extension and provides an
end-to-end measurement harness that quantifies their handshake, cryptographic,
and certificate-size overheads over realistic wide-area network conditions.

The fork adds, in round numbers, **~8,000 lines of C** to OpenSSL's TLS 1.3
handshake layer and X.509 certificate handling (plus a separate ~3,200-line
measurement/test harness). The central handshake addition is a new
`PQCertificateVerify` message that carries the proof-of-possession for the
post-quantum key, chained onto the classical `CertificateVerify` transcript.

> **Scope note (measured configuration).** In the benchmarked configuration,
> *authentication* (signatures / certificates) is post-quantum, while the TLS
> *key exchange* is classical **X25519** — the KEM is held fixed as a controlled
> variable so the measurements isolate certificate/signature overhead. This is a
> deliberate scope choice, not a hybrid PQC KEM deployment.

---

## Supported hybrid certificate formats

Four hybrid formats are negotiated through the fork's `hybrid_cert` TLS
extension. A fifth format, **Composite**, is handled entirely through
oqs-provider composite signature OIDs on the standard `signature_algorithms`
path and does **not** go through `hybrid_cert` (it is included in the
measurements as a control, not as a negotiated hybrid type).

| Type code | Format | Family | Mechanism (spec) |
|:--:|---|---|---|
| 1 | **Chameleon** | single certificate | Delta Certificate Descriptor (`DeltaCertificateDescriptor`); the delta (PQC) certificate is reconstructed from the base certificate's DCD extension |
| 2 | **Catalyst** | single certificate | `subjectAltPublicKeyInfo` + `altSignatureAlgorithm` + `altSignatureValue` X.509 extensions on one object |
| 3 | **Related** | multi certificate | RFC 9763 `RelatedCertificate` extension binding a PQC leaf to a classical leaf by hash |
| 4 | **Dual** | multi certificate | two independent certificate chains (classical + PQC), draft-yusef-tls-pqt-dual-certs |
| — | *Composite* | single certificate | oqs-provider composite OID (e.g. `p256_mldsa65`); negotiated via `signature_algorithms`, not `hybrid_cert` |

### `hybrid_cert` type negotiation

`hybrid_cert` (`TLSEXT_TYPE_hybrid_cert = 0xff51`) is a **capability + type
selection** extension:

- **ClientHello** — the client advertises the set of hybrid certificate types it
  can verify, as a bitset over the type codes above
  (`TLSEXT_HYBRID_CERT_TYPE_CHAMELEON=1` … `_DUAL=4`, see
  `include/openssl/tls1.h`).
- **Server** — the server selects one hybrid certificate it holds whose signature
  algorithm matches the client's `signature_algorithms` preference, and **echoes
  the single chosen type** back in the EncryptedExtensions message.
- The algorithm itself (ML-DSA-44/65/87, Falcon-512/1024, SLH-DSA variants, …)
  is negotiated through the **standard `signature_algorithms` extension** — there
  is no separate algorithm-negotiation extension. (The earlier
  `dual_signature_algorithms` extension has been **removed**; negotiation is
  unified onto `signature_algorithms`.)

Relevant symbols: `SSL_CTX_set_hybrid_cert_types()` /
`SSL_set_hybrid_cert_types()` and `SSL_CTX_set_hybrid_cert_required()`
(`include/openssl/ssl.h`).

---

## Build instructions

### Toolchain (as used for the paper's measurements)

| Component | Version | Notes |
|---|---|---|
| OpenSSL (this fork) | **3.3.4-dev** | `VERSION.dat`; branch `hybrid-cert` |
| liboqs | **0.15.0** | paper-pinned (`test/certs/hybrid_e2e/aws/lib.sh`) |
| oqs-provider | **0.11.0** | regenerated against liboqs 0.15.0 so that all six SLH-DSA parameter sets are registered (the 192s/256s/256f variants ship disabled in stock 0.11.0) |

> oqs-provider is **not** the stock 0.11.0 binary: the 0.11.0 tag is checked out,
> `oqs-template/generate.yml` is patched to enable SLH-DSA 192s/256s/256f, and
> `generate.py` is re-run against the liboqs 0.15.0 sources. The provisioning
> script `test/certs/hybrid_e2e/aws/setup.sh` performs these steps automatically.

### 1. Build the fork's OpenSSL

Build order matters: **build this fork first**, so that oqs-provider links
against *this* `libcrypto` (a different `OSSL_LIB_CTX` from the system OpenSSL
would break PQC certificate decoding at runtime).

```bash
# functional build
./Configure
make -j"$(nproc)"

# measurement build — adds the in-handshake sign/verify timers
make clean
./Configure -DHYBRID_MEASURE
make -j"$(nproc)"
make -j"$(nproc)" test/hybrid_measure
```

The `-DHYBRID_MEASURE` flag brackets the `EVP_DigestSign*` / `EVP_DigestVerify*`
calls in the (PQ)CertificateVerify construct/process paths with
`clock_gettime(CLOCK_MONOTONIC)` timers. Use a plain `./Configure` (no flag) for
functional testing.

### 2. Build liboqs 0.15.0 and oqs-provider 0.11.0

The exact, verified sequence — including the SLH-DSA `generate.yml` patch and the
requirement that oqs-provider's cmake points at the fork via
`-DOPENSSL_ROOT_DIR=<fork>` — lives in
[`test/certs/hybrid_e2e/aws/setup.sh`](test/certs/hybrid_e2e/aws/setup.sh). On a
fresh Ubuntu 24.04 AWS instance, `setup.sh` builds the fork, liboqs, and
oqs-provider end to end and installs the provider module under
`/usr/local/lib/ossl-modules`. Reuse it (or follow it step by step) rather than
re-deriving the dependency build by hand.

### 3. Functional smoke test

```bash
OPENSSL_MODULES=/usr/local/lib/ossl-modules \
  ./test/hybrid_e2e_test test/certs/hybrid_e2e
```

This is also wired into the OpenSSL test harness as
`test/recipes/90-test_hybrid_e2e.t`.

---

## Reproducing the measurements

The measurement infrastructure lives under
[`test/certs/hybrid_e2e/`](test/certs/hybrid_e2e/). Two documents are the
authoritative procedure and should be read first:

- [`test/certs/hybrid_e2e/MEASURE_AWS_GUIDE.md`](test/certs/hybrid_e2e/MEASURE_AWS_GUIDE.md)
  — what is measured and how (metrics, matrix, harness internals).
- [`test/certs/hybrid_e2e/aws/README.md`](test/certs/hybrid_e2e/aws/README.md)
  — the AWS automation (provision → setup → sanity → run → collect → teardown).

### What is measured

| Metric | Where | How |
|---|---|---|
| Handshake time | client | `clock_gettime` around `SSL_connect` |
| PQ / classical sign time | server | `-DHYBRID_MEASURE` timers around `EVP_DigestSign*`, shipped to the client after the handshake |
| PQ / classical verify time | client | `-DHYBRID_MEASURE` timers around `EVP_DigestVerify*` |
| Certificate-chain verification time | client | `-DHYBRID_MEASURE` timer around the X.509 chain / hybrid-format validations in `tls_post_process_server_certificate` (main chain incl. Catalyst alt-signature, PQC chain, Chameleon Delta reconstruction, RFC 9763 Related binding); reported as the trailing `cert_verify_ms` CSV column |
| Certificate bytes | client | total DER bytes of **all** certificates the server transmitted: main `certificate_list` (leaf + intermediate) plus the separate PQC chain for the multi-certificate hybrids — the Root (trust anchor) is never sent and is excluded |

The sign/verify timers cover only the proof-of-possession signatures
(`CertificateVerify` / `PQCertificateVerify`); certificate-chain verification is
reported separately in `cert_verify_ms` rather than folded into them.

### Fixture / certificate generation

`test/certs/hybrid_e2e/gen_smoke_certs.sh` generates the CA and key material
(ECDSA / ML-DSA / Falcon / SLH-DSA) into a `smoke/` directory as **3-tier
chains** (Root → intermediate CA → leaf); the Root acts as the trust anchor and
is never transmitted. Note two properties of the pipeline:

- **Chameleon** and **Related** on-wire certificates are **not** static files —
  they are assembled at runtime by the measurement harness in
  `test/hybrid_fixtures.c` (`make_chameleon_base()` / `make_related_pqc()`),
  using the generated CA/key material as inputs.
- SLH-DSA fixtures use FIPS 205 labels (`slhdsa…`) in filenames/CSVs while the
  oqs-provider is called with its algorithm names (`sphincs…simple`); the
  generation script maps between them.

### Launching a benchmark run

The per-host driver is `test/certs/hybrid_e2e/measure_orchestrate.sh`. It sweeps,
for each `(format, algorithm)` combination:

- **Formats:** `dual`, `catalyst`, `chameleon`, `related`, plus `pure` (PQC-only)
  and `traditional` (ECDSA) baselines, and `composite` as a control.
- **PQC variants:** 11 (ML-DSA ×3, Falcon ×2, SLH-DSA ×6).
- **Network conditions (applied *separately*):** packet loss `{0, 5, 10}%` and
  bandwidth `{0, 1, 5, 10}` Mbit (`0` = unshaped), via `tc netem` (egress loss)
  and `tbf` on an IFB device (ingress-shaped download).
- **Repetitions:** `RUNS=100` per tuple (override via the `RUNS` env var).

For the wide-area matrix, the AWS wrapper in `test/certs/hybrid_e2e/aws/` pairs
Seoul clients with servers in **Tokyo**, **Singapore**, and **Virginia** (three
region pairs, `c5.xlarge`), and orchestrates the full
provision→setup→run→collect→teardown cycle. Each region pair is split into
load-balanced intra-region shards (`SHARDS` in `aws/lib.sh`; the paper campaign
used 9 shards per pair, i.e. 54 instances, isolating each slow SLH-DSA-*s*
variant on its own shard). Collected per-shard CSVs are merged into a single
`combined.csv` under `aws/results/` (untracked — see below).

---

## Dataset availability

Raw measurement data is **not tracked in this repository by design**
(`aws/results/`, run logs, and instance artifacts are gitignored — they carry
per-run infrastructure details). The paper's canonical dataset is a single
merged CSV of **124,200 handshakes** (`verify_ok` 100%; 100 runs per
region × format × algorithm × network-condition group) with the schema:

```
region,format,algorithm,cat_level,loss,bw,run,handshake_ms,
pq_sign_ms,pq_verify_ms,classical_sign_ms,classical_verify_ms,
cert_bytes,verify_ok
```

Runs made with the current tree additionally append a trailing
`cert_verify_ms` column (client certificate-chain verification, added after the
paper campaign; `hybrid_measure --csv-header` prints the current 15-column
header). The dataset is available from the authors on request, and any row of it
can be regenerated with the AWS automation above.

---

## Branch note

The released implementation lives on the **`hybrid-cert`** branch (this branch),
not on `master`. Check out `hybrid-cert` to reproduce the paper. The upstream
OpenSSL history is retained for reference; the original OpenSSL project README is
preserved under the upstream `master` branch.

---

## Citation

The paper is currently under revision at *IEEE Network*; the BibTeX entry below
will be completed (authors, year, DOI) once the paper is accepted and the final
publication details are assigned.

```bibtex
@article{hybridpqc-tls13,
  title   = {From Standards to Practice: Benchmarking Hybrid PQC Certificates in TLS 1.3},
  journal = {IEEE Network},
  note    = {Under revision}
}
```

---

## License

This project is a fork of OpenSSL and is distributed under the terms of the
OpenSSL license (Apache License 2.0). See [`LICENSE.txt`](LICENSE.txt). All added
hybrid-certificate and measurement code is released under the same terms.
