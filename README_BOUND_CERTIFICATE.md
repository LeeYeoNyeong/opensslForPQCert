**Bound Certificate Implementation for OpenSSL**


This project implements the "bound certificate" approach as defined in [RFC 9763](https://datatracker.ietf.org/doc/html/rfc9763) for the OpenSSL cryptographic library. The implementation provides support for the `relatedCertRequest` attribute in Certificate Signing Requests (CSRs) and the `RelatedCertificate` extension in X.509 certificates.

**Table of Contents**


 - [Overview](#overview)
 - [Features](#features)
 - [ASN.1 Structures](#asn1-structures)
 - [Building and Testing](#building-and-testing)
 - [Test Script](#test-script)
 


**Overview**


RFC 9763 defines a mechanism to bind certificates together, allowing one certificate to reference another certificate through cryptographic means. This is particularly useful for:

- Certificate chaining and relationship verification
- Cross-certification scenarios
- Certificate binding in multi-certificate environments
- Post-quantum cryptography certificate binding

The implementation provides a complete solution for creating and verifying bound certificates according to the RFC 9763 specification.

**Features**


**Implemented Components**


1. **relatedCertRequest Attribute** (`id-aa-relatedCertRequest`)
   - Added to Certificate Signing Requests (CSRs)
   - Contains requester certificate information
   - Includes timestamp and location information
   - Digitally signed for integrity

2. **RelatedCertificate Extension** (`id-pe-relatedCert`)
   - Added to X.509 certificates
   - Contains hash of the related certificate
   - Supports multiple hash algorithms (SHA-256, SHA-512, etc.)


**Building and Testing**


**Prerequisites**


- OpenSSL 3.3.4 or later
- Make
- liboqs
- oqs provider

**Build Options**


```bash
git clone -b bound-openssl-3.3 https://github.com/wibs2401/opensslForPQCert.git
cd opensslForPQCert
./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl
make -j$(nproc)
sudo make install
```

**Testing Process**

This section describes how to test the RFC 9763 implementation using OpenSSL 3.3.4 with OQS (Open Quantum Safe) support.

### Prerequisites

- OpenSSL 3.3.4 with OQS provider enabled
- Working directory for test certificates

### Test Setup

```bash
# Create a working directory
mkdir -p test_bound_certs
cd test_bound_certs
```

### Step 1: Generate Self-Signed Certificate (P-256 ECDSA)

```bash
# Generate classic ECDSA private key (P-256)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out server_p256_key.pem

# Create self-signed P-256 certificate
openssl req -new -x509 -key server_p256_key.pem \
  -out server_p256_cert.pem -days 365 \
  -subj "/CN=server.example.com"
```

### Step 2: Generate Bound Certificate (MLDSA44) with relatedCertRequest

```bash
# Generate PQC private key (MLDSA44)
openssl genpkey -algorithm mldsa44 -out server_mldsa44_key.pem

# Create CSR with relatedCertRequest attribute pointing to the P-256 certificate
openssl req -new \
  -key server_mldsa44_key.pem \
  -out server_mldsa44_bound_req.pem \
  -subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=server.example.com" \
  -add_related_cert server_p256_cert.pem \
  -related_uri "$(pwd)/server_p256_cert.pem"

# Sign the CSR to create a self-signed certificate
# The RelatedCertificate extension will be automatically added
openssl x509 -req -in server_mldsa44_bound_req.pem \
  -key server_mldsa44_key.pem \
  -out server_mldsa44_bound_cert.pem -days 365
```

### Step 3: Alternative - Generate Bound Certificate (P-256) pointing to MLDSA44

```bash
# If you want to create a P-256 certificate bound to a MLDSA44 certificate
# (reverse direction: PQC → Classic)

# First, create a self-signed MLDSA44 certificate
openssl genpkey -algorithm mldsa44 -out server_pqc_key.pem
openssl req -new -x509 -key server_pqc_key.pem \
  -out server_pqc_cert.pem -days 365 \
  -subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=server.example.com"

# Then create P-256 CSR with relatedCertRequest pointing to MLDSA44 certificate
openssl req -new \
  -key server_p256_key.pem \
  -out server_p256_bound_req.pem \
  -subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=server.example.com" \
  -add_related_cert server_pqc_cert.pem \
  -related_uri "$(pwd)/server_pqc_cert.pem"

# Sign to create self-signed P-256 certificate with RelatedCertificate extension
openssl x509 -req -in server_p256_bound_req.pem \
  -key server_p256_key.pem \
  -out server_p256_bound_cert.pem -days 365
```

### Step 4: Verification

```bash
# Verify the CSR with relatedCertRequest attribute
openssl req -in server_mldsa44_bound_req.pem -text -noout

# Check the relatedCertRequest attribute specifically
openssl req -in server_mldsa44_bound_req.pem -text -noout | grep -A 20 "relatedCertRequest"

# Verify the signature of the relatedCertRequest attribute
openssl req -in server_mldsa44_bound_req.pem -verify -noout

# Verify self-signed certificates
openssl x509 -in server_p256_cert.pem -text -noout 

# Verify the bound certificate
openssl x509 -in server_mldsa44_bound_cert.pem -text -noout 

# Check the RelatedCertificate extension in the final certificate
openssl x509 -in server_mldsa44_bound_cert.pem -text -noout | grep -A 20 "Bound certificate extension"

# Verify that the RelatedCertificate extension was automatically added
# The extension should contain the hash of server_p256_cert.pem
```

### Step 5: TLS Handshake Testing

#### 5.1 Starting the OpenSSL Server

```bash
# Start the TLS server with self-signed certificates
# Note: For self-signed certificates, you can omit -CAfile and -pqcafile
# or use -verify_return_error to require client certificates
openssl s_server \
  -cert server_p256_cert.pem -key server_p256_key.pem \
  -pqcert server_mldsa44_bound_cert.pem -pqkey server_mldsa44_key.pem \
  -enable_dual_certs \
  -msg -debug

```

#### 5.2 Connecting the OpenSSL Client

```bash
# In another terminal, connect a TLS client
# For self-signed certificates, use -verify_return_error or -verify_depth 0
# to accept self-signed certificates
openssl s_client -connect localhost:4433 \
  -verify_return_error -verify_depth 0 \
  -msg
```







