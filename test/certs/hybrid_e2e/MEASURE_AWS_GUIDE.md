# Hybrid PQC TLS 1.3 — AWS Measurement Guide

End-to-end procedure for the handshake / crypto / certificate-size matrix using
`test/hybrid_measure` and `measure_orchestrate.sh`.

## 0. What is measured

| Metric | Where | How |
|---|---|---|
| handshake time (ms) | client | `clock_gettime(CLOCK_MONOTONIC)` around `SSL_connect` |
| PQ / classical sign (ms) | server | `#ifdef HYBRID_MEASURE` brackets around `EVP_DigestSign*` in `tls_construct_{,pq_}cert_verify`; the server ships its counters to the client as one app-data line right after the handshake |
| PQ / classical verify (ms) | client | brackets around `EVP_DigestVerify*` in `tls_process_{,pq_}cert_verify`, read off the client `SSL_CONNECTION` |
| certificate bytes | client | DER length of the peer leaf certificate |

Matrix: **4 hybrid formats** (`dual`, `catalyst`, `chameleon`, `related`) ×
**11 PQC variants**, plus the `pure` PQC and `traditional` ECDSA baselines, ×
**network conditions** (loss `0/5/10 %` and bandwidth `1/5/10 Mbit`, applied
*separately*), × **3 region pairs**. `composite` is out of scope (no
PQCertificateVerify; standard `signature_algorithms` path).

## 1. Build the measurement binary (CLEAN build — mandatory)

The crypto instrumentation is gated by `-DHYBRID_MEASURE`, which **adds a field
to `struct ssl_connection_st`**. An incremental rebuild after toggling the flag
leaves part of `libssl` compiled with the old struct layout → ABI skew and
zeroed/garbage counters. Always start from a clean tree:

```sh
cd <repo>
make clean
./Configure -DHYBRID_MEASURE        # same target args you normally use
make -j"$(nproc)" build_libs
make -j"$(nproc)" test/hybrid_measure
```

Verify the flag took effect (crypto columns must be non-zero in §4):

```sh
./test/hybrid_measure --csv-header   # prints the column header
```

> Production builds are unaffected: without `-DHYBRID_MEASURE` the field, the
> timing code and `<time.h>` dependency are all compiled out. Rebuild the normal
> way (`make clean && ./Configure && make`) when you are done measuring.

## 2. oqsprovider

PQC keys require oqsprovider in the **system** modules dir (not the in-tree
`providers/`, which the test runner would otherwise shadow):

```sh
export OPENSSL_MODULES=/usr/local/lib/ossl-modules   # contains oqsprovider.{so,dylib}
export LD_LIBRARY_PATH=<repo>                         # Linux; DYLD_LIBRARY_PATH on macOS
<repo>/apps/openssl list -providers | grep -i oqs     # must list oqsprovider
```

`hybrid_measure` aborts (exit 2) if oqsprovider fails to load for any PQC
format — a missing provider is never silently counted as a passing run.

## 3. Generate fixtures once (before any measurement)

```sh
cd <repo>/test/certs/hybrid_e2e
OPENSSL=<repo>/apps/openssl ./gen_smoke_certs.sh     # writes ./smoke/
```

This produces the per-algorithm PQC chains, Catalyst alt-key certs, the shared
RSA chain and the ECDSA `p256/p384/p521` baseline. Generate on **one** host and
copy `smoke/` to both instances so server and client present/trust identical
material.

## 4. Local smoke before AWS

```sh
cd <repo>
export LD_LIBRARY_PATH=$PWD OPENSSL_MODULES=/usr/local/lib/ossl-modules
CERTS=$PWD/test/certs/hybrid_e2e/smoke
# loopback forks a server child and a client over 127.0.0.1
./test/hybrid_measure --role loopback --format dual --alg mldsa65 \
    --certs "$CERTS" --port 0 --runs 5
```

Sanity: `verify_ok=1`, `handshake_ms` non-zero, and the crypto columns non-zero
and algorithm-dependent (ML-DSA verify ≪ SLH-DSA-256; SLH-DSA `s` variants have
a very large *sign* cost).

## 5. AWS: two instances, one region pair

Pick a region pair (e.g. `us-east-1` ↔ `eu-west-1`), launch one instance in
each, security group open on the chosen TCP port (default 4433) between them.

Server instance:

```sh
cd <repo>/test/certs/hybrid_e2e
RUNS=100 PORT=4433 ./measure_orchestrate.sh server
```

Client instance (needs `tc` / `iproute2`; run as root for shaping):

```sh
cd <repo>/test/certs/hybrid_e2e
RUNS=100 IFACE=eth0 PORT=4433 \
  sudo -E ./measure_orchestrate.sh client <server_private_ip> useast1-euwest1
```

Both sides walk the **same matrix order** in lockstep; the server serves a flat
count per `(format,alg)` and the client splits it across the network conditions.
tc shaping is applied on the **client** NIC only and cleared after every
condition (and on Ctrl-C / error via a trap). Output: `measure_<region>.csv`.

Repeat for the other two region pairs (re-run with a different region label).

### Knobs (environment)

| var | default | meaning |
|---|---|---|
| `RUNS` | 100 | handshakes per (combo, condition) |
| `IFACE` | eth0 | client NIC shaped with tc |
| `PORT` | 4433 | TCP port |
| `FORMATS` | dual catalyst chameleon related pure traditional | format list |
| `ALGS` | 11 PQC variants | PQC list (traditional uses p256/p384/p521) |
| `LOSSES` | 0 5 10 | netem loss % (separate experiment) |
| `BWS` | 0 1 5 10 | tbf bandwidth Mbit (0 = unshaped; separate experiment) |
| `CSV` | measure_<region>.csv | output path |

### Resume

The client skips any `(format,alg,loss,bw)` tuple already present in the CSV, so
a crashed run can simply be relaunched with the same arguments.

## 6. Scale / time estimate

Per region pair, conditions per combo = 1 baseline + 2 extra losses + 3
bandwidths = **6**. Combos = 4 hybrid × 11 + pure × 11 + traditional × 3 = **58**.
Rows per region = 58 × 6 × RUNS. At RUNS=100 → ~34.8 k handshakes/region,
~104 k across 3 region pairs.

Wall-clock is dominated by SLH-DSA `s`-variant **signing** on the server
(hundreds of ms–seconds each) and by the shaped-bandwidth conditions. Budget a
few hours per region pair at RUNS=100; drop `RUNS` or trim `ALGS` for a quick
pass first.

## 7. CSV schema

```
region,format,algorithm,cat_level,loss,bw,run,handshake_ms,
pq_sign_ms,pq_verify_ms,classical_sign_ms,classical_verify_ms,cert_bytes,verify_ok
```

- `verify_ok=0` rows are invalid handshakes (connect failure, or for a hybrid
  format a missing/未-verified PQCertificateVerify) — exclude them from stats.
- For `pure`/`traditional` the single signature flows through the classical
  CertificateVerify path, so its cost lands in `classical_sign_ms` /
  `classical_verify_ms` and the `pq_*` columns are 0 by design.
- `cert_bytes` is the peer **leaf** DER size as seen by the client. The extra
  PQC certificate of the multi-cert formats (Dual/Related) travels in the
  PQCertificate message; record full chain sizes statically from `smoke/` if a
  total-bytes figure is needed.
```
