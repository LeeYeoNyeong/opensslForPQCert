**Dual Certificate Implementation for OpenSSL**


This project implements the "dual certificate" approach as defined in [IETF draft-yusef-tls-pqt-dual-certs](https://datatracker.ietf.org/doc/draft-yusef-tls-pqt-dual-certs/) for the OpenSSL cryptographic library. The implementation provides support for dual certificates with classic and post-quantum cryptography (PQC) chains in TLS handshakes.

**Table of Contents**


 - [Overview](#overview)
 - [Features](#features)
 - [ASN.1 Structures](#asn1-structures)
 - [Building and Testing](#building-and-testing)
 - [Test Script](#test-script)
 - [TLS Handshake Testing](#tls-handshake-testing)
 - [OID Registration](#oid-registration)


**Overview**


The IETF draft defines a mechanism to use dual certificates in TLS handshakes, allowing one certificate chain for classic cryptography and another for post-quantum cryptography. This is particularly useful for:

- Post-quantum cryptography migration
- Hybrid security approaches
- Backward compatibility with classic cryptography
- Future-proofing TLS connections

The implementation provides a complete solution for creating and using dual certificates according to the draft specification.

**Features**


**Self-Signed Certificate Support**

The implementation now fully supports self-signed certificates in dual certificate mode:

- **Automatic Detection**: The verification process automatically detects self-signed certificates
- **Signature Verification**: Self-signed certificates are verified using their own public key
- **TLS Handshake**: Self-signed certificates work seamlessly in TLS handshakes
- **Dual Mode**: Both classic and PQC self-signed certificates are supported simultaneously

This is particularly useful for:
- Development and testing environments
- Internal networks without CA infrastructure
- Prototyping and proof-of-concept implementations

**Implemented Components**


1. **Dual Certificate Structure** (`CERT`)
   - Added to SSL_CONNECTION structure
   - Contains classic and PQC certificate chains
   - Includes dual certificate enablement flag
   - Supports separate key management

2. **TLS Dual Signature Algorithms Extension** (`TLSEXT_TYPE_dual_signature_algorithms`)
   - Added to TLS handshake messages
   - Contains two signature algorithm lists (classic + PQC)
   - Supports all major PQC algorithms
   - Format compliant with draft specification


**Building and Testing**


**Prerequisites**


- OpenSSL 3.3.4 or later
- Make
- liboqs (for PQC algorithms)
- oqs provider

**Build Options**


```bash
git clone -b DUAL_Chain_approach https://github.com/wibs2401/opensslForPQCert.git
cd opensslForPQCert
./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl
make -j$(nproc)
sudo make install
```

**Test Program**


**Testing Process*

This section describes how to test the dual certificate implementation using OpenSSL 3.3.4 with OQS (Open Quantum Safe) support.

### Prerequisites

- OpenSSL 3.3.4 with OQS provider enabled
- Working directory for test certificates

### Test Setup

```bash
# Create a working directory
mkdir -p test_dual_certs
cd test_dual_certs
```

### Step 1: Generate CA Infrastructure

```bash
# Generate classic CA private key (RSA)
openssl genpkey -algorithm RSA -out ca_rsa_key.pem 

# Generate PQC CA private key ()
openssl genpkey -algorithm mldsa65 -out ca_mldsa65_key.pem

# Create classic CA certificate    
openssl-oqs req -new -x509 -key ca_rsa_key.pem \
-out ca_rsa.pem -days 365 \
-subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=TestClassicCA"

# Create PQC CA certificate
openssl-oqs req -new -x509 -key ca_mldsa65_key.pem \
-out ca_mldsa65_cert.pem -days 365 \
-subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=TestPQCA"
```

### Step 2: Generate Dual Certificates

```bash
# Generate classic certificate private key (RSA)
openssl genpkey -algorithm RSA -out server_rsa_key.pem

# Create classic certificate request
openssl req -new -key server_rsa_key.pem \
-out server_rsa_req.pem \
-subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=server.example.com"

# Sign classic certificate
openssl x509 -req -in server_rsa_req.pem \
-CA ca_rsa.pem -CAkey ca_rsa_key.pem -CAcreateserial \
-out server_rsa_cert.pem -days 365
    
# Generate PQC certificate private key (mldsa65)
openssl genpkey -algorithm mldsa65 -out server_mldsa65_key.pem

# Create PQC certificate request
openssl req -new -key server_mldsa65_key.pem \
-out server_mldsa65_req.pem \
-subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=server.example.com"

# Sign PQC certificate
openssl x509 -req -in server_mldsa65_req.pem \
-CA ca_mldsa65_cert.pem -CAkey ca_mldsa65_key.pem -CAcreateserial \
-out server_mldsa65_cert.pem -days 365

```

### Step 3: Generate Self-Signed Dual Certificates

For testing purposes or development environments, you can create self-signed dual certificates without a CA:

```bash
# Generate self-signed classic certificate (RSA)
openssl genpkey -algorithm RSA -out server_rsa_self_key.pem

# Create self-signed classic certificate
openssl req -new -x509 -key server_rsa_self_key.pem \
  -out server_rsa_self_cert.pem -days 365 \
  -subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=server.example.com"

# Generate self-signed PQC certificate (mldsa65)
openssl genpkey -algorithm mldsa65 -out server_mldsa65_self_key.pem

# Create self-signed PQC certificate
openssl req -new -x509 -key server_mldsa65_self_key.pem \
  -out server_mldsa65_self_cert.pem -days 365 \
  -subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=server.example.com"
```

**Note:** Self-signed certificates are now fully supported in the dual certificate implementation. The verification process will automatically detect and accept self-signed certificates when they are properly formatted.

### Step 4: Test Dual Certificate Usage

```bash
# Verify classic certificate
openssl x509 -in server_classic_cert.pem -text -noout

# Verify PQC certificate
openssl x509 -in server_pq_cert.pem -text -noout

# Verify self-signed classic certificate
openssl x509 -in server_rsa_self_cert.pem -text -noout

# Verify self-signed PQC certificate
openssl x509 -in server_mldsa65_self_cert.pem -text -noout
```

### Step 5: Verification of dual certificate with verify

#### 5.1 Verification with CA-signed certificates

```bash
# Verify dual certificates signed by CAs
openssl verify -dual \
  -CAfile ca_rsa.pem \
  -pqcafile ca_mldsa65_cert.pem \
  server_rsa_cert.pem \
  server_mldsa65_cert.pem
```

#### 5.2 Verification with self-signed certificates


```bash
# Verify self-signed dual certificates
openssl verify -dual \
  -CAfile server_rsa_self_cert.pem \
  -pqcafile server_mldsa65_self_cert.pem \
  server_rsa_self_cert.pem \
  server_mldsa65_self_cert.pem
```


### Step 6: TLS Handshake Testing

#### 6.1 Starting the OpenSSL Server with self-signed certificates


```bash
# Start the TLS server with self-signed dual certificates
openssl s_server \
  -cert server_rsa_self_cert.pem \
  -key server_rsa_self_key.pem \
  -pqcert server_mldsa65_self_cert.pem \
  -pqkey server_mldsa65_self_key.pem \
  -enable_dual_certs \
  -msg -debug
```

```bash
# Connect to server with self-signed dual certificates
openssl s_client -connect localhost:4433 \
  -CAfile server_rsa_self_cert.pem \
  -pqcafile server_mldsa65_self_cert.pem \
  -enable_dual_certs \
  -msg -debug
```

#### 6.3 Starting the OpenSSL Server with CA-signed certificates

```bash
# Start the TLS server with dual certificates
openssl s_server \
  -cert server_rsa_cert.pem \
  -key server_rsa_key.pem \
  -pqcert server_mldsa65_cert.pem \
  -pqkey server_mldsa65_key.pem \
  -CAfile ca_rsa.pem \
  -pqcafile ca_mldsa65_cert.pem \
  -enable_dual_certs \
  -msg -debug


#### Connecting the OpenSSL Client

```bash
# In another terminal, connect a TLS client
openssl s_client -connect localhost:4433 \
  -CAfile ca_rsa.pem \
  -pqcafile ca_mldsa65_cert.pem \
  -msg -debug

```







