#ifndef OPENSSL_V3_DCD_H
#define OPENSSL_V3_DCD_H

#include <openssl/x509.h>

typedef struct DeltaValidity_st {
    ASN1_TIME *notBefore;
    ASN1_TIME *notAfter;
} DeltaValidity;

typedef struct DeltaCertificateDescriptor_st {
    ASN1_INTEGER *serialNumber;
    X509_ALGOR *signature;
    X509_NAME *issuer;
    DeltaValidity *validity;
    X509_NAME *subject;
    X509_PUBKEY *SubjectPublicKeyInfo;
    STACK_OF(X509_EXTENSION) *extensions;
    ASN1_BIT_STRING *signatureValue;
} DeltaCertificateDescriptor;



int verify_dcd_signature(X509 *cert, X509_STORE *store, STACK_OF(X509) *untrusted);

/* Create and sign DCD */
ASN1_OCTET_STRING *create_delta_certificate_descriptor(X509 *base_cert,
                                                       X509 *delta_cert);

DECLARE_ASN1_FUNCTIONS(DeltaValidity)
DECLARE_ASN1_FUNCTIONS(DeltaCertificateDescriptor)

#endif