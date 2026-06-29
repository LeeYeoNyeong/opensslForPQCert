# AWS measurement automation — NETWORK-26-00272

Infrastructure wrapper that deploys, runs and tears down the hybrid PQC TLS 1.3
measurement matrix on AWS. The measurement logic itself
(`../measure_orchestrate.sh`, `../../../test/hybrid_measure`) is unchanged — these
scripts only **provision → setup → sanity → run → collect → teardown** six EC2
instances around it.

## Topology (fixed)

| role | count | region | pair |
|---|---|---|---|
| client | 3 | Seoul `ap-northeast-2` | one per pair |
| server | 1 | Tokyo `ap-northeast-1` | `tokyo` |
| server | 1 | Singapore `ap-southeast-1` | `singapore` |
| server | 1 | Virginia `us-east-1` | `virginia` |

All instances are **c5.xlarge** (fixed perf, 4 vCPU — t-class is forbidden so
crypto timings stay consistent), Ubuntu 24.04 LTS, on-demand, 30 GB gp3 root.

Each `(Seoul client ↔ remote server)` pair is fully independent and runs in
parallel: separate tc/CPU, no cross-interference. Cross-region traffic uses the
**public** path, so the client connects to the server's public IP and the
server security group opens the measurement port (`4433`) to that pair's client
`/32` only. SSH (`22`) is opened only to the operator's current public IP.

## Prerequisites

- `aws` CLI v2 configured (`aws configure` — a profile with EC2 rights in all
  four regions). Credentials are **never** hardcoded; the scripts use your
  ambient AWS profile.
- Local tools: `jq`, `ssh`, `scp`, `curl` (checked at startup).
- The fork must be reachable by `git clone` from the instances. Default
  `REPO_URL` is the public GitHub URL; if your repo is private, override
  `REPO_URL` with an authenticated URL (deploy token) before `setup.sh`.

## Run order

```sh
cd test/certs/hybrid_e2e/aws

./provision.sh        # creates key/SG/AMI + 6 instances -> instances.json  (COSTS MONEY)
./setup.sh            # parallel: deps + liboqs + oqs-provider + CLEAN build + fixtures
./sanity.sh           # GATE: 1 tiny pass/pair; must pass before the full run
./run.sh              # full matrix, 3 pairs in parallel (hours)
./collect.sh          # scp CSVs -> results/, validate, -> results/combined.csv
./teardown.sh         # terminate instances (STOP BILLING)  [--full also deletes SG/key]
```

Or step-gated end-to-end (teardown excluded on purpose):

```sh
./measure_all.sh
```

## The three guards against an invalid measurement

1. **Clean build is forced.** `-DHYBRID_MEASURE` changes the
   `struct ssl_connection_st` layout; an incremental rebuild leaves part of
   `libssl` on the old layout → **ABI skew** → zeroed crypto columns. `setup.sh`
   always does `make clean && ./Configure -DHYBRID_MEASURE && make`.
2. **oqsprovider load is verified.** `setup.sh` fails an instance if
   `list -signature-algorithms` does not expose mldsa/falcon/slhdsa.
3. **Sanity gate.** `sanity.sh` runs one real pass per pair and refuses to pass
   if any `pq_verify_ms == 0` (the ABI-skew signature) or any `verify_ok != 1`.
   `run.sh` should only follow a green sanity. `collect.sh` re-checks the same
   conditions on the full data after the fact.

## Knobs (environment)

| var | default | used by | meaning |
|---|---|---|---|
| `RUNS` | 100 | run/collect/sanity | handshakes per (combo, condition) |
| `INSTANCE_TYPE` | c5.xlarge | provision | instance shape |
| `ROOT_VOLUME_GB` | 30 | provision | gp3 root size |
| `PORT` | 4433 | all | measurement TCP port |
| `IFACE` | eth0 | run/sanity | client NIC shaped with tc |
| `REPO_URL` / `REPO_BRANCH` | origin / hybrid-cert | setup | fork source |
| `LIBOQS_REF` | 0.11.0 | setup | liboqs tag (paper-pinned) |
| `OQSPROV_REF` | 0.10.1-dev | setup | oqs-provider ref (paper-pinned; override if it does not resolve) |
| `BUILD_JOBS` | 4 | setup | `make -j` on the 4-vCPU instances |
| `FORMATS`/`ALGS`/`LOSSES`/`BWS` | orchestrator defaults | run | matrix trimming |
| `FORCE=1` | — | provision/teardown/master | skip confirmation prompts |

Per-script: `./setup.sh <pair>`, `./run.sh <pair>`, `./collect.sh <pair>` operate
on a single pair (debug / re-measure one region).

## Resume

`RESUME` defaults to **0** (full run). A 2-instance resume needs a *shared*
per-combo marker on both server and client; we do not synchronise that here, and
a partial resume would desync the server's fixed per-combo count from the
client's connection count (server hangs on `accept`). Re-measure a failed pair
from scratch with `./run.sh <pair>`.

## Cost

~$0.17–0.21 per instance-hour ⇒ **~$1.20/hour** for the six (plus EBS; verify
current pricing). The fleet runs until `teardown.sh`. `provision.sh` prints the
estimate and requires confirmation; `teardown.sh` prints a residual-resource
check command. **Forgetting teardown = ongoing charges.**

## What is committed

The scripts (`lib.sh`, `provision/setup/sanity/run/collect/teardown.sh`,
`measure_all.sh`) are committed for reproducibility (paper supplementary).
`instances.json`, `*.pem`, `results/` and the log dirs are git-ignored — resource
identifiers, private keys and measurement data are never committed.
