#include <openssl/x509v3.h>
#include <openssl/asn1t.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <string.h>

#include <crypto/x509.h>
#include <stdbool.h>


ASN1_BIT_STRING* create_dummy_extension(EVP_PKEY* key);
static void *v2i_altAlg(const X509V3_EXT_METHOD *method, X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *values);
static int i2r_altAlg(const X509V3_EXT_METHOD *method, void *ext, BIO *out, int indent);

const X509V3_EXT_METHOD ossl_v3_alt_sig_alg = {
    NID_alt_signature_algorithm,        /* .ext_nid = */
    0,                      /* .ext_flags = */
    ASN1_ITEM_ref(X509_ALGOR), /* .it = */
    0, 0, 0, 0,
    0,                   /* .i2s = */
    0,                   /* .s2i = */
    NULL,                   /* .i2v = */
    v2i_altAlg,          /* .v2i = */
    i2r_altAlg,         /* .i2r = */
    NULL,                   /* .r2i = */
    NULL                    /* extension-specific data */
};


static void *v2i_altAlg(const X509V3_EXT_METHOD *method,
                        X509V3_CTX *ctx,
                        STACK_OF(CONF_VALUE) *values)
{
    if (sk_CONF_VALUE_num(values) != 1) {
        printf("[altSigAlg] error: only one algorithm OID must be specified.\n");
        return NULL;
    }

    CONF_VALUE *val = sk_CONF_VALUE_value(values, 0);


    ASN1_OBJECT *obj = OBJ_txt2obj(val->name, 0);
    if (!obj) {
        printf("[altSigAlg] error: invalid OID value: %s\n", val->value);
        return NULL;
    }

    X509_ALGOR *alg = X509_ALGOR_new();
    if (!alg) {
        printf("[altSigAlg] error: memory allocation failed for X509_ALGOR.\n");
        ASN1_OBJECT_free(obj);
        return NULL;
    }

    X509_ALGOR_set0(alg, obj, V_ASN1_UNDEF, NULL);  // no parameters

    return alg;
}

static int alt_signature_dump(BIO *bp, const ASN1_BIT_STRING *sig, int indent)
{
    const unsigned char *s;
    int i, n;

    if (!sig)
        return 0;

    n = sig->length;
    s = sig->data;
    for (i = 0; i < n; i++) {
        if ((i % 18) == 0) {
            if (i > 0 && BIO_write(bp, "\n", 1) <= 0)
                return 0;
            if (BIO_indent(bp, indent, indent) <= 0)
                return 0;
        }
        if (BIO_printf(bp, "%02x%s", s[i], ((i + 1) == n) ? "" : ":") <= 0)
            return 0;
    }
    return 1;
}

static int i2r_altAlg(const X509V3_EXT_METHOD *method,
                      void *ext,
                      BIO *out,
                      int indent)
{
    X509_ALGOR *alg = (X509_ALGOR *)ext;

    if (!alg || !alg->algorithm)
        return 0;

    if (BIO_printf(out, "%*s", indent, "") <= 0)
        return 0;
    if (i2a_ASN1_OBJECT(out, alg->algorithm) <= 0)
        return 0;

    return 1;
}

static void *v2i_altSig(const X509V3_EXT_METHOD *method, X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *values);
static int i2r_altSig(const X509V3_EXT_METHOD *method, void *ext_value, BIO *out, int indent);
static int ALT_SIGNATURE_verify(X509* x, EVP_PKEY* public_key);



const X509V3_EXT_METHOD ossl_v3_alt_sig_val = {
    NID_alt_signature_value,        /* .ext_nid = */
    0,                      /* .ext_flags = */
    ASN1_ITEM_ref(ASN1_BIT_STRING), /* .it = */
    0, 0, 0, 0,
    0,                   /* .i2s = */
    0,                   /* .s2i = */
    NULL,                   /* .i2v = */
    v2i_altSig,          /* .v2i = */
    i2r_altSig,         /* .i2r = */
    NULL,                   /* .r2i = */
    NULL                    /* extension-specific data */
};

static void *v2i_altSig(const X509V3_EXT_METHOD *method,
                        X509V3_CTX *ctx,
                        STACK_OF(CONF_VALUE) *values)
{
    ASN1_BIT_STRING* altsig = NULL;
    EVP_PKEY *pkey = NULL;
    BIO *keybio = NULL;

    if (sk_CONF_VALUE_num(values) != 1)
        return NULL;

    CONF_VALUE *val = sk_CONF_VALUE_value(values, 0);
    if (strncmp("file", val->name, 4)) {
        printf("Value for alt_sig_val must start with 'file:'\n");
        return NULL;
    }

    keybio = BIO_new_file(val->value, "rb");
    if (!keybio){ 
        printf("Failed to make alternative private key file\n");
        return NULL;
    }

    pkey = PEM_read_bio_PrivateKey(keybio, NULL, NULL, NULL);
    BIO_free(keybio);
    if (!pkey){ 
        printf("Failed to open alternative private key file\n");
        return NULL;
    }


    if((altsig = create_dummy_extension(pkey))==NULL) {
        printf("create_dummy_extension error\n");
        return NULL;
    }

    if (ctx->flags & CTX_TEST) {
        return altsig;
    }
 
   ctx->subject_cert->alt_sig_private_key = pkey;
   return altsig;


}

static int i2r_altSig(const X509V3_EXT_METHOD *method, void *ext_value,
                      BIO *out, int indent)
{
    ASN1_BIT_STRING *bs = (ASN1_BIT_STRING *)ext_value;

    if (!bs || !bs->data)
        return 0;

    return alt_signature_dump(out, bs, indent);
}

ASN1_BIT_STRING* create_dummy_extension(EVP_PKEY* key) {
    ASN1_BIT_STRING* hs;
    int signatureLength;

    hs = ASN1_BIT_STRING_new();

    signatureLength = EVP_PKEY_size(key);
    if ((hs->data = OPENSSL_zalloc(signatureLength)) == NULL) {
        printf("create_dummy_extension error\n");
        return NULL;
    }
    hs->length = signatureLength;
    hs->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
    hs->flags |= ASN1_STRING_FLAG_BITS_LEFT;

    return hs;

}


void ALT_SIGNATURE_sign(X509* x) {
    int i;
    X509_EXTENSION* ext;
    ASN1_OCTET_STRING *ext_oct = NULL;
    EVP_PKEY* private_key;
    ASN1_BIT_STRING* altsig;
    int ext_len;
    unsigned char *ext_der = NULL;
    if ((i = X509_get_ext_by_NID(x, NID_alt_signature_value, -1)) < 0) {
        // No extension to be signed
        return;
    }
    if ((ext = X509_get_ext(x, i)) == NULL) {
        return;
    }
    if ((private_key = x->alt_sig_private_key) == NULL) {
        return;
    }
    if ((altsig = create_dummy_extension(private_key)) == NULL) {
        // Error set by createDummyExtension, so we do not need to set any.
        return;
    }
    /* Manual signing to support keys without default digest (e.g. ML-DSA) */
    unsigned char *tbs = NULL;
    int tbslen;
    EVP_MD_CTX *md_ctx = NULL;
    size_t siglen = altsig->length;

    /* 1. Encode TBSCertificate (cert_info) */
    tbslen = ASN1_item_i2d((ASN1_VALUE *)&x->cert_info, &tbs, ASN1_ITEM_rptr(X509_CINF));
    if (tbslen <= 0) {
        ERR_print_errors_fp(stderr);
        return;
    }

    /* 2. Sign */
    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        OPENSSL_free(tbs);
        return;
    }

    if (EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, private_key) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(md_ctx);
        OPENSSL_free(tbs);
        return;
    }


    if (EVP_DigestSign(md_ctx, altsig->data, &siglen, tbs, tbslen) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(md_ctx);
        OPENSSL_free(tbs);
        return;
    }

    /* Update signature length in case it is smaller (unlikely for fixed size PQC but good practice) */
    altsig->length = (int)siglen;
    /* Clear unused bits - assuming byte aligned signature */
    altsig->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
    altsig->flags |= ASN1_STRING_FLAG_BITS_LEFT; 

    EVP_MD_CTX_free(md_ctx);
    OPENSSL_free(tbs);
    ext_der = NULL;
    ext_len = ASN1_item_i2d((void*)altsig, &ext_der, ASN1_ITEM_rptr(ASN1_BIT_STRING));
    if (ext_len < 0) {
        return;
    }
    if ((ext_oct = ASN1_OCTET_STRING_new()) == NULL) {
        return;
    }
    ext_oct->data = ext_der;
    ext_oct->length = ext_len;
    if (X509_EXTENSION_set_data(ext, ext_oct) != 1) {
    }
    x->cert_info.enc.modified = 1;
}

static int ALT_SIGNATURE_verify(X509* x, EVP_PKEY* public_key) {
    //trace_call("ALT_SIGNATURE_verify");
    int i;
    X509_EXTENSION* ext;
    X509_EXTENSION* ext_alg;
    ASN1_OCTET_STRING *extoct;
    ASN1_BIT_STRING* dummy = NULL;
    int ext_len;
    unsigned char *ext_der = NULL;
    ASN1_BIT_STRING *altsig = NULL;
    X509_ALGOR* altalg = NULL;
    ASN1_OCTET_STRING* ext_oct;
    ASN1_BIT_STRING* signature;

    // get the alternative signature value extension
    if ((i = X509_get_ext_by_NID(x, NID_alt_signature_value, -1)) < 0) {
        printf("[ALT_verify] no alt sig val extension\n");
        return 0;
    }
    if ((ext = X509_get_ext(x, i)) == NULL) {
        printf("[ALT_verify] no alt sig val extension\n");
        return 0;
    }
    extoct = ASN1_OCTET_STRING_dup(X509_EXTENSION_get_data(ext));
    if ((altsig = X509V3_EXT_d2i(ext)) == NULL) {
        printf("[ALT_verify] alt sig val parsing failure\n");
        return 0;
    }
    printf("[ALT_verify] extract altsig\n");
    signature = ASN1_STRING_dup(altsig);
 // get the alternative signature algorithm extension
    if ((i = X509_get_ext_by_NID(x, NID_alt_signature_algorithm, -1)) < 0) {
        printf("[ALT_verify] no alt sig alg extension\n");
        return 0;
    }
    if ((ext_alg = X509_get_ext(x, i)) == NULL) {
        printf("[ALT_verify] no alt sig alg extension\n");
        return 0;
    }
    if ((altalg = X509V3_EXT_d2i(ext_alg)) == NULL) {
    return 0;
    }


    //create a dummy extension for verification (contains all 0's as the signature string)
    if ((dummy = create_dummy_extension(public_key)) == NULL) {
        // Error set by createDummyExtension, so we do not need to set any.
        return 0;
    }

    printf("[ALT_verify] generte dummy extension\n");

    ext_len = ASN1_item_i2d((void*)dummy, &ext_der, ASN1_ITEM_rptr(ASN1_BIT_STRING));
    if (ext_len < 0) {
        printf("[ALT_verify] alt sig parsing failure\n");
        return 0;
    }
    if ((ext_oct = ASN1_OCTET_STRING_new()) == NULL) {
        printf("[ALT_verify] alt sig malloc failure\n");
        return 0;
    }
    ext_oct->data = ext_der;
    ext_oct->length = ext_len;
    //replace the extension data with the dummy extension data
    if (X509_EXTENSION_set_data(ext, ext_oct) != 1) {
        return 0;
    }
    x->cert_info.enc.modified = 1;

    /* Manual verification to support keys without default digest (e.g. ML-DSA) */
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    unsigned char *tbs = NULL;
    int tbslen;

    if (!md_ctx) {
        printf("[ALT_verify] context creation failed\n");
        X509_EXTENSION_set_data(ext, extoct);
        return 0;
    }

    tbslen = ASN1_item_i2d((ASN1_VALUE *)&x->cert_info, &tbs, ASN1_ITEM_rptr(X509_CINF));
    if (tbslen <= 0) {
        printf("[ALT_verify] TBS encoding failed\n");
        EVP_MD_CTX_free(md_ctx);
        X509_EXTENSION_set_data(ext, extoct);
        return 0;
    }



    if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, public_key) <= 0) {
        printf("[ALT_verify] DigestVerifyInit failed\n");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(md_ctx);
        OPENSSL_free(tbs);
        X509_EXTENSION_set_data(ext, extoct);
        return 0;
    }

    if (EVP_DigestVerify(md_ctx, signature->data, signature->length, tbs, tbslen) <= 0) {
        printf("[ALT_verify] alt sig verification failure\n");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(md_ctx);
        OPENSSL_free(tbs);
        X509_EXTENSION_set_data(ext, extoct);
        return 0;
    }

    EVP_MD_CTX_free(md_ctx);
    OPENSSL_free(tbs);

    //restore the extension to its original state for further verification
    X509_EXTENSION_set_data(ext, extoct);
    x->cert_info.enc.modified = 1;

    return 1;
}

static int alt_sig_validate_path_internal(X509_STORE_CTX *ctx,
                                             STACK_OF(X509) *chain) {
    EVP_PKEY* public_key = NULL;
    int i;
    X509 *x;
    bool need_pubkey = false; // if one certificate has a alternative key, all others upwards in the chain need one as well

    i = 0;
    x = sk_X509_value(chain, i);

    /*
     * Walk up the chain. Verify each alternative signature with the alternative key of the parent.
     */
    for (; i < sk_X509_num(chain) - 1; i++) {
        X509* parent = sk_X509_value(chain, i + 1);
        public_key = X509_get_alt_pubkey(parent);
        if (!public_key) {
            if (need_pubkey) {
                ctx->error = X509_V_ERR_ALT_SIG_VERIFY_FAIL;
                ctx->error_depth = i;
                ctx->current_cert = x;
                if (ctx->verify_cb(0, ctx) == 0)
                    return 0;
            }
            // we do not have a alternative key, but we do not need one. Continue checking the chain
            continue;
        }
        else {
            // this certificate has a alternative public key -> all parent certificates need to have one as well
            need_pubkey = true;
        }
        if (ALT_SIGNATURE_verify(x, public_key) == 0) {
            ctx->error = X509_V_ERR_ALT_SIG_VERIFY_FAIL;
            ctx->error_depth = i;
            ctx->current_cert = x;
            if (ctx->verify_cb(0, ctx) == 0)
                return 0;
        }
        x = parent;
    }

    // Check self signed alternative signature of the root certificate.
    public_key = X509_get_alt_pubkey(x);

    if (!public_key) {
        if (need_pubkey) {
            ctx->error = X509_V_ERR_ALT_SIG_VERIFY_FAIL;
            ctx->error_depth = i;
            ctx->current_cert = x;
            if (ctx->verify_cb(0, ctx) == 0)
                return 0;
        }
        return 1; // we do not need a alternative key -> all is good :)
    }
    return ALT_SIGNATURE_verify(x, public_key);
}

/*
 * Verify a the alternative signatures for a certificate chain.
 */
int X509v3_alt_sig_validate_path(X509_STORE_CTX *ctx) {
    if (ctx->chain == NULL
            || sk_X509_num(ctx->chain) == 0
            || ctx->verify_cb == NULL) {
        ctx->error = X509_V_ERR_UNSPECIFIED;
        return 0;
    }
    return alt_sig_validate_path_internal(ctx, ctx->chain);
}