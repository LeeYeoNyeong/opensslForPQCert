/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 */

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <string.h>
#include <stdio.h>

#include <crypto/x509.h>
#include "x509_local.h"
#include <openssl/v3_dcd.h>

ASN1_SEQUENCE(DeltaValidity) = {
    ASN1_SIMPLE(DeltaValidity, notBefore, ASN1_TIME),
    ASN1_SIMPLE(DeltaValidity, notAfter, ASN1_TIME),
} ASN1_SEQUENCE_END(DeltaValidity);

IMPLEMENT_ASN1_FUNCTIONS(DeltaValidity);

ASN1_SEQUENCE(DeltaCertificateDescriptor) = {
    ASN1_SIMPLE(DeltaCertificateDescriptor, serialNumber, ASN1_INTEGER),
    ASN1_EXP_OPT(DeltaCertificateDescriptor, signature, X509_ALGOR, 0),
    ASN1_EXP_OPT(DeltaCertificateDescriptor, issuer, X509_NAME, 1),
    ASN1_EXP_OPT(DeltaCertificateDescriptor, validity, DeltaValidity, 2),
    ASN1_EXP_OPT(DeltaCertificateDescriptor, subject, X509_NAME, 3),
    ASN1_SIMPLE(DeltaCertificateDescriptor, SubjectPublicKeyInfo, X509_PUBKEY),
    ASN1_EXP_SEQUENCE_OF_OPT(DeltaCertificateDescriptor, extensions,
                             X509_EXTENSION, 4),
    ASN1_SIMPLE(DeltaCertificateDescriptor, signatureValue,
                ASN1_BIT_STRING)} ASN1_SEQUENCE_END(DeltaCertificateDescriptor);

IMPLEMENT_ASN1_FUNCTIONS(DeltaCertificateDescriptor);



static void *v2i_dcd_cert(const struct v3_ext_method *method,
                          struct v3_ext_ctx *ctx, STACK_OF(CONF_VALUE) * value);
static int i2r_dcd_cert(const struct v3_ext_method *method, void *ext, BIO *out,
                        int indent);

X509_ALGOR *copy_sigalg_from_cert(X509 *cert);
DeltaValidity *copy_validity_from_cert(X509 *cert);
STACK_OF(X509_EXTENSION) * copy_extensions_except_delta(X509 *cert);

const X509V3_EXT_METHOD ossl_v3_delta_cert_desc = {
    NID_id_ce_deltaCertificateDescriptor,
    0,
    ASN1_ITEM_ref(DeltaCertificateDescriptor),
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    v2i_dcd_cert,
    i2r_dcd_cert,
    NULL,
    NULL};

/* Helper functions for field comparison */
static int compare_serial_numbers(const ASN1_INTEGER *a,
                                  const ASN1_INTEGER *b) {
    return ASN1_INTEGER_cmp(a, b);
}

static int compare_signature_algorithms(const X509_ALGOR *a,
                                        const X509_ALGOR *b) {
    return X509_ALGOR_cmp(a, b);
}

static int compare_names(const X509_NAME *a, const X509_NAME *b) {
    return X509_NAME_cmp(a, b);
}

static int compare_validity(const X509 *delta, const X509 *base) {
    /*
     * Compare NotBefore and NotAfter.
     * Returns 0 if identical, non-zero otherwise.
     */
    const ASN1_TIME *d_nb = X509_get0_notBefore(delta);
    const ASN1_TIME *d_na = X509_get0_notAfter(delta);
    const ASN1_TIME *b_nb = X509_get0_notBefore(base);
    const ASN1_TIME *b_na = X509_get0_notAfter(base);

    if (ASN1_TIME_compare(d_nb, b_nb) != 0)
        return 1;
    if (ASN1_TIME_compare(d_na, b_na) != 0)
        return 1;

    return 0;
}

static int compare_public_keys(X509 *delta, X509 *base) {
    /* Returns 0 if keys are identical, non-zero otherwise */
    /* Note: X509_cmp_pubkey returns 1 if match, 0 if mismatch/error */
    /* So we invert the result */
    EVP_PKEY *d_pkey = X509_get0_pubkey(delta);
    EVP_PKEY *b_pkey = X509_get0_pubkey(base);

    if (d_pkey == NULL || b_pkey == NULL)
        return 1; // Cannot compare, assume different

    return X509_PUBKEY_eq(X509_get_X509_PUBKEY(delta),
                          X509_get_X509_PUBKEY(base))
               ? 0
               : 1;
}

/*
 * Copy extensions from delta cert that are NOT present or different in base
 * cert. Draft-07 4.1: "The extensions field MUST contain the extensions present
 * in the Delta Certificate that are not present in the Base Certificate." It
 * also implies extensions with different values should be included.
 */
static STACK_OF(X509_EXTENSION) *
    copy_different_extensions_from_stack(X509 *delta,
                                         const STACK_OF(X509_EXTENSION) *
                                             base_exts) {
    const STACK_OF(X509_EXTENSION) *d_exts = X509_get0_extensions(delta);
    STACK_OF(X509_EXTENSION) *ret = NULL;
    int i;

    if (!d_exts || sk_X509_EXTENSION_num(d_exts) == 0)
        return NULL;

    for (i = 0; i < sk_X509_EXTENSION_num(d_exts); i++) {
        X509_EXTENSION *d_ext = sk_X509_EXTENSION_value(d_exts, i);
        ASN1_OBJECT *obj = X509_EXTENSION_get_object(d_ext);
        int nid = OBJ_obj2nid(obj);

        /* Skip DCD extension itself to avoid recursion if it somehow exists */
        if (nid == NID_id_ce_deltaCertificateDescriptor)
            continue;

        int include = 0;

        if (base_exts == NULL) {
            include = 1;
        } else {
            /* Check if this extension exists in base stack */
            int base_idx = X509v3_get_ext_by_OBJ(base_exts, obj, -1);

            if (base_idx < 0) {
                /* Not in base, include it */
                include = 1;
            } else {
                /* Exists in base, compare values */
                X509_EXTENSION *b_ext = sk_X509_EXTENSION_value(base_exts, base_idx);
                /* Compare critical flag */
                if (X509_EXTENSION_get_critical(d_ext) !=
                    X509_EXTENSION_get_critical(b_ext))
                    include = 1;
                /* Compare value octet string */
                else if (ASN1_OCTET_STRING_cmp(X509_EXTENSION_get_data(d_ext),
                                               X509_EXTENSION_get_data(b_ext)) != 0)
                    include = 1;
            }
        }

        if (include) {
            if (ret == NULL) {
                if ((ret = sk_X509_EXTENSION_new_null()) == NULL)
                    return NULL;
            }

            X509_EXTENSION *dup_ext = X509_EXTENSION_dup(d_ext);
            if (dup_ext)
                sk_X509_EXTENSION_push(ret, dup_ext);
        }
    }

    return ret;
}

static STACK_OF(X509_EXTENSION) *
    copy_different_extensions(X509 *delta, X509 *base) {
    return copy_different_extensions_from_stack(delta,
                                                X509_get0_extensions(base));
}

static void *v2i_dcd_cert(const struct v3_ext_method *method,
                          struct v3_ext_ctx *ctx,
                          STACK_OF(CONF_VALUE) * value) {

    DeltaCertificateDescriptor *dcd = DeltaCertificateDescriptor_new();
    X509 *base_cert = NULL;

    if (!dcd) {
        fprintf(stderr, "Failed to allocate DeltaCertificateDescriptor\n");
        return NULL;
    }

    if (sk_CONF_VALUE_num(value) != 1) {
        fprintf(stderr,
                "deltaCertificateDescriptor must contain only one certificate\n");
        DeltaCertificateDescriptor_free(dcd);
        return NULL;
    }

    CONF_VALUE *val = sk_CONF_VALUE_value(value, 0);

    if (strncmp("file", val->name, 4)) {
        fprintf(stderr,
                "Value for deltaCertificateDescriptor must start with 'file:'\n");
        DeltaCertificateDescriptor_free(dcd);
        return NULL;
    }

    FILE *cert_file = fopen(val->value, "rb");
    if (!cert_file) {
        fprintf(stderr, "Failed to open certificate file: %s\n", val->value);
        DeltaCertificateDescriptor_free(dcd);
        return NULL;
    }

    X509 *delta_cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    fclose(cert_file);

    if (!delta_cert) {
        fprintf(stderr, "Failed to load delta certificate\n");
        DeltaCertificateDescriptor_free(dcd);
        return NULL;
    }

    /* Retrieve Base Certificate from context */
    /* For self-signed certs (e.g. openssl req -x509), ctx->subject_cert is the
     * cert being created */
    if (ctx && ctx->subject_cert) {
        base_cert = ctx->subject_cert;
    } else {
        /* If no base cert available (e.g. regular CSR req), we cannot perform
         * comparison */
        /* Draft-07 implies DCD is added by issuer, or self-issued. */
        /* For now, warn and proceed assuming we should copy everything or fail? */
        /* Let's fall back to copying everything if base cert is missing (safe
         * default) */
        // fprintf(stderr, "Warning: No Base Certificate available for comparison.
        // Including all fields.\n");
    }

    /*
     * Field Comparison Logic (Draft-07 Section 4.1)
     * Include field IFF it differs from Base Certificate
     */

    /* Serial Number */
    if (!base_cert ||
        compare_serial_numbers(X509_get_serialNumber(delta_cert),
                               X509_get_serialNumber(base_cert)) != 0) {
        dcd->serialNumber = ASN1_INTEGER_dup(X509_get_serialNumber(delta_cert));
    }

    /* Signature Algorithm */
    const X509_ALGOR *delta_sigalg = X509_get0_tbs_sigalg(delta_cert);
    const X509_ALGOR *base_sigalg =
        base_cert ? X509_get0_tbs_sigalg(base_cert) : NULL;

    if (!base_cert ||
        compare_signature_algorithms(delta_sigalg, base_sigalg) != 0) {
        dcd->signature = copy_sigalg_from_cert(delta_cert);
    }

    /* Issuer */
    if (!base_cert || compare_names(X509_get_issuer_name(delta_cert),
                                    X509_get_issuer_name(base_cert)) != 0) {
        dcd->issuer = X509_NAME_dup(X509_get_issuer_name(delta_cert));
    }

    /* Validity */
    if (!base_cert || compare_validity(delta_cert, base_cert) != 0) {
        dcd->validity = copy_validity_from_cert(delta_cert);
    }

    /* Subject */
    if (!base_cert || compare_names(X509_get_subject_name(delta_cert),
                                    X509_get_subject_name(base_cert)) != 0) {
        dcd->subject = X509_NAME_dup(X509_get_subject_name(delta_cert));
    }


    /* Subject Public Key Info */
    if (!base_cert || compare_public_keys(delta_cert, base_cert) != 0) {
        EVP_PKEY *pubkey = X509_get_pubkey(delta_cert);
        if (pubkey) {
            X509_PUBKEY_set(&dcd->SubjectPublicKeyInfo, pubkey);
            EVP_PKEY_free(pubkey);
        }
    }

    /* Extensions */
    if (base_cert) {
        dcd->extensions = copy_different_extensions(delta_cert, base_cert);
    } else {
        dcd->extensions = copy_extensions_except_delta(delta_cert);
    }

    /* Signature Value - Always included */
    const ASN1_BIT_STRING *sig = NULL;
    X509_get0_signature(&sig, NULL, delta_cert);
    if (sig != NULL) {
        dcd->signatureValue = ASN1_STRING_dup(sig);
    }

    X509_free(delta_cert);
    return dcd;
}

static int i2r_dcd_cert(const struct v3_ext_method *method, void *ext, BIO *out,
                        int indent) {
    DeltaCertificateDescriptor *dcd = ext;
    int ret = 0;

    if (dcd == NULL) {
        BIO_printf(out, "%*sNo DeltaCertificateDescriptor data\n", indent, "");
        return 1;
    }

    if (dcd->serialNumber) {
        BIO_printf(out, "%*sSerial Number: \n", indent, "");

        const BIGNUM *bn = ASN1_INTEGER_to_BN(dcd->serialNumber, NULL);
        if (bn != NULL) {
            unsigned char *buf = NULL;
            int len = BN_num_bytes(bn);

            buf = OPENSSL_malloc(len);
            if (buf != NULL) {
                BN_bn2bin(bn, buf);
                BIO_printf(out, "%*s", indent + 4, "");
                for (int i = 0; i < len; i++) {
                    BIO_printf(out, "%02x", buf[i]);
                    if (i < len - 1)
                        BIO_printf(out, ":");
                }
                BIO_printf(out, "\n");
                OPENSSL_free(buf);
            }
            BN_free((BIGNUM *)bn);
        } else {
            BIO_printf(out, "%*s<invalid serial number>\n", indent + 4, "");
        }
    }

    if (dcd->signature) {
        BIO_printf(out, "%*sSignature Algorithm: ", indent, "");
        if (i2a_ASN1_OBJECT(out, dcd->signature->algorithm) <= 0)
            goto err;
        BIO_printf(out, "\n");
    }

    if (dcd->issuer) {
        BIO_printf(out, "%*sIssuer: ", indent, "");
        if (X509_NAME_print_ex(out, dcd->issuer, 0, XN_FLAG_ONELINE) <= 0)
            goto err;
        BIO_printf(out, "\n");
    }

    if (dcd->validity) {
        BIO_printf(out, "%*sValidity:\n", indent, "");
        if (dcd->validity->notBefore) {
            BIO_printf(out, "%*sNot Before: ", indent + 4, "");
            ASN1_TIME_print(out, dcd->validity->notBefore);
            BIO_printf(out, "\n");
        }
        if (dcd->validity->notAfter) {
            BIO_printf(out, "%*sNot After: ", indent + 4, "");
            ASN1_TIME_print(out, dcd->validity->notAfter);
            BIO_printf(out, "\n");
        }
    }

    if (dcd->subject) {
        BIO_printf(out, "%*sSubject: ", indent, "");
        if (X509_NAME_print_ex(out, dcd->subject, 0, XN_FLAG_ONELINE) <= 0)
            goto err;
        BIO_printf(out, "\n");
    }

    if (dcd->SubjectPublicKeyInfo) {
        BIO_printf(out, "%*sSubject Public Key Info:\n", indent, "");
        {
            ASN1_OBJECT *xpoid = NULL;
            X509_PUBKEY_get0_param(&xpoid, NULL, NULL, NULL,
                                   dcd->SubjectPublicKeyInfo);
            BIO_printf(out, "%*sPublic Key Algorithm: ", indent + 4, "");
            if (i2a_ASN1_OBJECT(out, xpoid) <= 0)
                goto err;
            BIO_printf(out, "\n");

            EVP_PKEY *pkey = X509_PUBKEY_get0(dcd->SubjectPublicKeyInfo);
            if (pkey == NULL) {
                BIO_printf(out, "%*sUnable to load Public Key\n", indent + 4, "");
            } else {
                EVP_PKEY_print_public(out, pkey, indent + 8, NULL);
            }
        }
    }

    if (dcd->extensions && sk_X509_EXTENSION_num(dcd->extensions) > 0) {
        BIO_printf(out, "%*sX509v3 extensions:\n", indent, "");

        for (int i = 0; i < sk_X509_EXTENSION_num(dcd->extensions); i++) {
            X509_EXTENSION *ext = sk_X509_EXTENSION_value(dcd->extensions, i);
            ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);

            const X509V3_EXT_METHOD *method = X509V3_EXT_get(ext);
            void *ext_str = X509V3_EXT_d2i(ext);

            BIO_printf(out, "%*s", indent + 4, "");
            i2a_ASN1_OBJECT(out, obj);

            if (X509_EXTENSION_get_critical(ext))
                BIO_printf(out, ": critical\n");
            else
                BIO_printf(out, ":\n");

            if (method && ext_str) {
                if (method->i2r) {
                    BIO_printf(out, "%*s", indent + 8, "");
                    method->i2r(method, ext_str, out, indent + 8);
                } else {
                    BIO_printf(out, "%*s", indent + 8, "");
                    X509V3_EXT_print(out, ext, 0, 0);
                }
            } else {
                BIO_printf(out, "%*sUnable to decode or unrecognized extension\n",
                           indent + 8, "");
            }
            BIO_printf(out, "\n");
        }
    }

    if (dcd->signatureValue) {
        BIO_printf(out, "%*sSignature Value:\n", indent, "");
        for (int i = 0; i < dcd->signatureValue->length; i++) {
            if (i % 19 == 0)
                BIO_printf(out, "%*s", indent + 4, "");
            BIO_printf(out, "%02x", dcd->signatureValue->data[i]);
            if (i < dcd->signatureValue->length - 1)
                BIO_printf(out, ":");
            if ((i + 1) % 19 == 0)
                BIO_printf(out, "\n");
        }
    }

    ret = 1;
err:
    return ret;
}

X509_ALGOR *copy_sigalg_from_cert(X509 *cert) {
    const X509_ALGOR *alg = NULL;
    X509_ALGOR *copy = NULL;

    alg = X509_get0_tbs_sigalg(cert);

    if (!alg) {
        fprintf(stderr, "No signature algorithm found\n");
        return NULL;
    }

    copy = X509_ALGOR_dup(alg);
    if (!copy) {
        fprintf(stderr, "Failed to copy signature algorithm\n");
        return NULL;
    }

    return copy;
}

DeltaValidity *copy_validity_from_cert(X509 *cert) {
    const ASN1_TIME *nb = X509_get0_notBefore(cert);
    const ASN1_TIME *na = X509_get0_notAfter(cert);

    DeltaValidity *val = DeltaValidity_new();
    if (!val) {
        fprintf(stderr, "Failed to allocate memory for validity\n");
        return NULL;
    }

    val->notBefore = ASN1_TIME_dup(nb);
    val->notAfter = ASN1_TIME_dup(na);

    if (!val->notBefore || !val->notAfter) {
        ASN1_TIME_free(val->notBefore);
        ASN1_TIME_free(val->notAfter);
        DeltaValidity_free(val);
        return NULL;
    }

    return val;
}

STACK_OF(X509_EXTENSION) * copy_extensions_except_delta(X509 *cert) {
    int delta_ext_nid = NID_id_ce_deltaCertificateDescriptor;

    const STACK_OF(X509_EXTENSION) *orig_exts = X509_get0_extensions(cert);
    if (!orig_exts)
        return NULL;

    STACK_OF(X509_EXTENSION) *copy_exts = sk_X509_EXTENSION_new_null();
    if (!copy_exts)
        return NULL;

    for (int i = 0; i < sk_X509_EXTENSION_num(orig_exts); i++) {
        X509_EXTENSION *ext = sk_X509_EXTENSION_value(orig_exts, i);
        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);

        if (OBJ_obj2nid(obj) == delta_ext_nid)
            continue;

        X509_EXTENSION *ext_dup = X509_EXTENSION_dup(ext);

        if (!ext_dup) {
            for (int j = 0; j < sk_X509_EXTENSION_num(copy_exts); j++)
                X509_EXTENSION_free(sk_X509_EXTENSION_value(copy_exts, j));
            sk_X509_EXTENSION_free(copy_exts);
            return NULL;
        }

        sk_X509_EXTENSION_push(copy_exts, ext_dup);
    }

    return copy_exts;
}

STACK_OF(X509_EXTENSION) *
    copy_extensions_from_dcd(DeltaCertificateDescriptor *dcd) {
    const STACK_OF(X509_EXTENSION) *orig_exts = dcd->extensions;
    if (!orig_exts)
        return NULL;

    STACK_OF(X509_EXTENSION) *copy_exts = sk_X509_EXTENSION_new_null();
    if (!copy_exts)
        return NULL;

    for (int i = 0; i < sk_X509_EXTENSION_num(orig_exts); i++) {
        X509_EXTENSION *ext = sk_X509_EXTENSION_value(orig_exts, i);
        X509_EXTENSION *ext_dup = X509_EXTENSION_dup(ext);

        if (!ext_dup) {
            for (int j = 0; j < sk_X509_EXTENSION_num(copy_exts); j++)
                X509_EXTENSION_free(sk_X509_EXTENSION_value(copy_exts, j));
            sk_X509_EXTENSION_free(copy_exts);
            return NULL;
        }

        sk_X509_EXTENSION_push(copy_exts, ext_dup);
    }

    return copy_exts;
}

X509 *reconstruct_delta(X509 *base, DeltaCertificateDescriptor *dcd) {
    X509 *delta = X509_dup(base);
    int idx =
        X509_get_ext_by_NID(delta, NID_id_ce_deltaCertificateDescriptor, -1);

    if (idx >= 0)
        X509_delete_ext(delta, idx);

    if (dcd->serialNumber) {
        if (!X509_set_serialNumber(delta, dcd->serialNumber)) {
            fprintf(stderr, "Failed to copy serialNumber\n");
            return NULL;
        }
    }

    if (dcd->issuer) {
        if (!X509_set_issuer_name(delta, dcd->issuer)) {
            fprintf(stderr, "Failed to copy issuer name\n");
            return NULL;
        }
    }

    if (dcd->validity) {
        if (dcd->validity->notBefore &&
            !X509_set1_notBefore(delta, dcd->validity->notBefore)) {
            fprintf(stderr, "Failed to copy notBefore\n");
            return NULL;
        }
        if (dcd->validity->notAfter &&
            !X509_set1_notAfter(delta, dcd->validity->notAfter)) {
            fprintf(stderr, "Failed to copy notAfter\n");
            return NULL;
        }
    }

    if (dcd->subject) {
        if (!X509_set_subject_name(delta, dcd->subject)) {
            fprintf(stderr, "Failed to copy subject name\n");
            return NULL;
        }
    }

    if (dcd->SubjectPublicKeyInfo) {
        EVP_PKEY *pk = X509_PUBKEY_get0(dcd->SubjectPublicKeyInfo);
        if (!X509_set_pubkey(delta, pk)) {
            fprintf(stderr, "Failed to copy SubjectPublicKeyInfo\n");
            return NULL;
        }
    }

    while (X509_get_ext_count(delta) > 0) {
        X509_delete_ext(delta, 0);
    }

    if (dcd->extensions) {
        for (int i = 0; i < sk_X509_EXTENSION_num(dcd->extensions); ++i) {
            X509_EXTENSION *dup =
                X509_EXTENSION_dup(sk_X509_EXTENSION_value(dcd->extensions, i));
            if (!dup || !X509_add_ext(delta, dup, -1)) {
                X509_EXTENSION_free(dup);
                return NULL;
            }
            X509_EXTENSION_free(dup);
        }
    }

    if (dcd->signatureValue &&
        !ASN1_STRING_copy(&delta->signature, dcd->signatureValue)) {
        fprintf(stderr, "Failed to copy signatureValue\n");
    }

    delta->cert_info.enc.modified = 1;

    return delta;
}

int verify_dcd_signature(X509 *cert, X509_STORE *store, STACK_OF(X509) *untrusted) {
    printf("[DEBUG] verify_dcd_signature called\n");
    int ok = 0;
    int crit = -1;
    DeltaCertificateDescriptor *dcd =
        X509_get_ext_d2i(cert, NID_id_ce_deltaCertificateDescriptor, &crit, NULL);
    if (!dcd || !dcd->SubjectPublicKeyInfo) {
        fprintf(stderr, "No DeltaCertificateDescriptor or missing public key\n");
        return 0;
    }
    printf("[DEBUG] DCD extracted successfully\n");

    X509 *delta = reconstruct_delta(cert, dcd);
    if (!delta) {
      fprintf(stderr, "[DEBUG] Failed to reconstruct delta certificate\n");
      DeltaCertificateDescriptor_free(dcd);
        return 0;
    }
    printf("[DEBUG] Delta certificate reconstructed successfully\n");
    
    /* Restore full logic */
    printf("[DEBUG] Checking store: %p, untrusted: %p (count: %d)\n", 
           (void*)store, (void*)untrusted, untrusted ? sk_X509_num(untrusted) : 0);
    if (!store) {
        fprintf(stderr, "No store provided\n");
    } else {
        X509_STORE_CTX *ctx = X509_STORE_CTX_new();
        X509 *issuer = NULL;
        if (!ctx) goto end;

        if (!X509_STORE_CTX_init(ctx, store, delta, untrusted)) {
            X509_STORE_CTX_free(ctx);
            goto end;
        }

        if (X509_STORE_CTX_get1_issuer(&issuer, ctx, delta) != 1) {
            /* Fallback: Manual search in untrusted stack */
            if (untrusted) {
                for (int m = 0; m < sk_X509_num(untrusted); m++) {
                    X509 *candidate = sk_X509_value(untrusted, m);
                    if (X509_NAME_cmp(X509_get_issuer_name(delta), 
                                     X509_get_subject_name(candidate)) == 0) {
                        issuer = candidate;
                        X509_up_ref(issuer);
                        break;
                    }
                }
            }
        }

        if (issuer != NULL) {
            EVP_PKEY *issuer_key = X509_get_pubkey(issuer);
            if (issuer_key) {
                ok = X509_verify(delta, issuer_key);
                if (ok) {
                    /* Verification successful */
                    /* Now verify PQ ICA against PQ Root */
                    /* Delta cert has base signature, so we verify the issuer (PQ ICA) directly */
                    /* Find PQ Root in the trusted store */
                    X509_STORE_CTX *root_ctx = X509_STORE_CTX_new();
                    if (root_ctx) {
                        if (X509_STORE_CTX_init(root_ctx, store, issuer, NULL)) {
                            X509 *pq_root = NULL;
                            if (X509_STORE_CTX_get1_issuer(&pq_root, root_ctx, issuer) == 1) {
                                /* Found PQ Root, verify PQ ICA signature */
                                EVP_PKEY *root_key = X509_get_pubkey(pq_root);
                                if (root_key) {
                                    /* Clear any previous errors before verification */
                                    ERR_clear_error();
                                    
                                    int verify_ok = X509_verify(issuer, root_key);
                                    if (verify_ok > 0) {
                                        /* Verification successful - clear any intermediate errors */
                                        ERR_clear_error();
                                        ok = 1;
                                    } else {
                                        ok = 0;
                                    }
                                    EVP_PKEY_free(root_key);
                                } else {
                                    ok = 0;
                                }
                                X509_free(pq_root);
                            } else {
                                ok = 0;
                            }
                        } else {
                            ok = 0;
                        }
                        X509_STORE_CTX_free(root_ctx);
                    } else {
                        fprintf(stderr, "[Chameleon] Failed to create root verification context\n");
                        ok = 0;
                    }
                } else {
                     fprintf(stderr, "DCD Signature Verification Failed\n");
                }
                EVP_PKEY_free(issuer_key);
            }
            X509_free(issuer);
        } else {
            fprintf(stderr, "Delta CA (PQ ICA) not found in trusted store or untrusted chain\n");
            ok = 0;
        }
        X509_STORE_CTX_free(ctx);
    }

 end:
    if (dcd) {
        DeltaCertificateDescriptor_free(dcd);
    }
    if (delta) {
        X509_free(delta);
    }
    return ok;
}



/* TBS Structure for signing (excludes signatureValue) */
typedef DeltaCertificateDescriptor DeltaCertificateDescriptorTBS;

ASN1_SEQUENCE(DeltaCertificateDescriptorTBS) = {
    ASN1_SIMPLE(DeltaCertificateDescriptorTBS, serialNumber, ASN1_INTEGER),
    ASN1_EXP_OPT(DeltaCertificateDescriptorTBS, signature, X509_ALGOR, 0),
    ASN1_EXP_OPT(DeltaCertificateDescriptorTBS, issuer, X509_NAME, 1),
    ASN1_EXP_OPT(DeltaCertificateDescriptorTBS, validity, DeltaValidity, 2),
    ASN1_EXP_OPT(DeltaCertificateDescriptorTBS, subject, X509_NAME, 3),
    ASN1_SIMPLE(DeltaCertificateDescriptorTBS, SubjectPublicKeyInfo, X509_PUBKEY),
    ASN1_EXP_SEQUENCE_OF_OPT(DeltaCertificateDescriptorTBS, extensions,
                             X509_EXTENSION, 4)
} ASN1_SEQUENCE_END(DeltaCertificateDescriptorTBS);

/*
 * Create and sign a Delta Certificate Descriptor (DCD)
 * This function constructs a DCD from the Base Certificate and verified Delta Request,
 * signs it with the CA key, and returns the DER-encoded DCD as an ASN1_STRING
 * suitable for inclusion as an extension value.
 */
/*
 * Create a Delta Certificate Descriptor (DCD)
 * This function constructs a DCD from the Base Certificate and a pre-issued Delta Certificate.
 * It populates the DCD with fields that differ from the Base Certificate and copies the 
 * signature from the Delta Certificate.
 */
ASN1_OCTET_STRING *create_delta_certificate_descriptor(X509 *base_cert,
                                                       X509 *delta_cert)
{
    DeltaCertificateDescriptor *dcd = NULL;
    ASN1_OCTET_STRING *ext_val = NULL;
    unsigned char *der = NULL;
    int der_len = 0;
    const X509_ALGOR *sig_alg;
    const ASN1_BIT_STRING *sig_val;
    
    if (!base_cert || !delta_cert) {
        return NULL;
    }

    dcd = DeltaCertificateDescriptor_new();
    if (!dcd) {
        return NULL;
    }

    /* 1. Compare and Populate DCD fields */

    /* Serial Number: mandated to be present */
    ASN1_INTEGER_free(dcd->serialNumber);
    dcd->serialNumber = ASN1_INTEGER_dup(X509_get_serialNumber(delta_cert));
    if (!dcd->serialNumber) goto err;
    
    /* Issuer: include if different */
    if (X509_NAME_cmp(X509_get_issuer_name(base_cert), X509_get_issuer_name(delta_cert)) != 0) {
        dcd->issuer = X509_NAME_dup(X509_get_issuer_name(delta_cert));
        if (!dcd->issuer) goto err;
    }

    /* Validity: include if different */
    if (ASN1_TIME_compare(X509_get0_notBefore(base_cert), X509_get0_notBefore(delta_cert)) != 0 ||
        ASN1_TIME_compare(X509_get0_notAfter(base_cert), X509_get0_notAfter(delta_cert)) != 0) {
        DeltaValidity_free(dcd->validity);
        dcd->validity = DeltaValidity_new();
        if (!dcd->validity) goto err;
        ASN1_TIME_free(dcd->validity->notBefore);
        ASN1_TIME_free(dcd->validity->notAfter);
        dcd->validity->notBefore = ASN1_TIME_dup(X509_get0_notBefore(delta_cert));
        dcd->validity->notAfter = ASN1_TIME_dup(X509_get0_notAfter(delta_cert));
        if (!dcd->validity->notBefore || !dcd->validity->notAfter) goto err;
    }

    /* Subject: include if different */
    if (X509_NAME_cmp(X509_get_subject_name(base_cert), X509_get_subject_name(delta_cert)) != 0) {
        dcd->subject = X509_NAME_dup(X509_get_subject_name(delta_cert));
        if (!dcd->subject) goto err;
    }

    /* Subject Public Key Info: include if different (MUST be different per draft) */
    if (X509_PUBKEY_eq(X509_get_X509_PUBKEY(base_cert), X509_get_X509_PUBKEY(delta_cert)) != 1) {
        X509_PUBKEY_free(dcd->SubjectPublicKeyInfo);
        dcd->SubjectPublicKeyInfo = ASN1_item_dup(ASN1_ITEM_rptr(X509_PUBKEY), 
                                                  X509_get_X509_PUBKEY(delta_cert));
        if (!dcd->SubjectPublicKeyInfo) goto err;
    }
    
    /* Extensions: copy all from Delta (Draft implies DCD contains extensions that differ, 
       but for simplicity/correctness we should copy extensions present in Delta but not Base?
       Draft 4.2: "The CA MUST encode extensions in the Base Certificate in the same order used for the Delta Certificate"
       Draft 4.2: "...populates the DCD extension with the values of the fields which differ..."
       We will copy extensions from Delta Certificate to DCD. Simpler and safer for PQC extensions.
    */
    /* TODO: Only copy differing extensions. For now, copy all extensions from Delta Cert. */
     {
        const STACK_OF(X509_EXTENSION) *delta_exts = X509_get0_extensions(delta_cert);
        if (delta_exts && sk_X509_EXTENSION_num(delta_exts) > 0) {
            dcd->extensions = sk_X509_EXTENSION_deep_copy(delta_exts, 
                                                           X509_EXTENSION_dup, 
                                                           X509_EXTENSION_free);
             if (!dcd->extensions) goto err;
        }
     }

    /* 2. Copy Signature from Delta Certificate */
    /* Get signature algorithm and value from Delta Certificate */
    X509_get0_signature(&sig_val, &sig_alg, delta_cert);

    /* Copy AlgorithmIdentifier */
    dcd->signature = X509_ALGOR_dup(sig_alg);
    if (!dcd->signature) goto err;

    /* Copy Signature Value (BIT STRING) */
    /* Note: dcd->signatureValue is a BIT STRING */
    if (!ASN1_BIT_STRING_set(dcd->signatureValue, sig_val->data, sig_val->length))
        goto err;
    dcd->signatureValue->flags = sig_val->flags; // Important: copy unused bits flags

    /* 3. Encode the full DCD to OCTET STRING */
    der_len = i2d_DeltaCertificateDescriptor(dcd, &der);
    if (der_len < 0)
        goto err;
        
    ext_val = ASN1_OCTET_STRING_new();
    if (!ext_val) {
        OPENSSL_free(der);
        goto err;
    }
    ext_val->data = der;
    ext_val->length = der_len;
    ext_val->type = V_ASN1_OCTET_STRING;

    DeltaCertificateDescriptor_free(dcd);
    return ext_val;

err:
    if (dcd) DeltaCertificateDescriptor_free(dcd);
    if (ext_val) ASN1_OCTET_STRING_free(ext_val);
    if (der) OPENSSL_free(der);
    return NULL;
}
