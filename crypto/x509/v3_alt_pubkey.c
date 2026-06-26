#include <openssl/x509v3.h>
#include <openssl/asn1t.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <string.h>

#include <crypto/x509.h>

static void *v2i_altPubkey(const struct v3_ext_method *method, struct v3_ext_ctx *ctx, STACK_OF(CONF_VALUE) *values);
static int i2r_altPubkey(const X509V3_EXT_METHOD *method, void *ext, BIO *out, int indent);

const X509V3_EXT_METHOD ossl_v3_alt_pubkey = {
    NID_subject_alt_public_key_info,   		/* .ext_nid = */
    0,                      /* .ext_flags = */
    ASN1_ITEM_ref(X509_PUBKEY), /* .it = */
    0, 0, 0, 0,
    0,                   /* .i2s = */
    0,                   /* .s2i = */
    NULL,                   /* .i2v = */
	v2i_altPubkey,          /* .v2i = */
	i2r_altPubkey,			/* .i2r = */
    NULL,                   /* .r2i = */
    NULL                    /* extension-specific data */
};

static void *v2i_altPubkey(const struct v3_ext_method *method,
                              struct v3_ext_ctx *ctx,
                              STACK_OF(CONF_VALUE) *values)
{
	X509_PUBKEY* ext = NULL;
	BIO *pubkey = NULL;
	EVP_PKEY *pkey = NULL;

	//we need exactly one value, specifying the public key file
	if (sk_CONF_VALUE_num(values) != 1) {
    	fprintf(stderr, "alternative public key must contain only one public key\n");
		return NULL;
	}

	CONF_VALUE *val = sk_CONF_VALUE_value(values, 0);
	if (strncmp("file", val->name, 4)) {
    	fprintf(stderr, "Value for alt_pubkey must start with 'file:'\n");
		return NULL;
	}
	if (!(pubkey = BIO_new_file(val->value, "rb"))) {
    	fprintf(stderr, "Failed to open alternative public key file\n");
		return NULL;
	}
	if ((ext = X509_PUBKEY_new()) == NULL) {
    	fprintf(stderr, "Failed to malloc pub key\n");
		return NULL;
	}
	if ((pkey = PEM_read_bio_PUBKEY(pubkey, NULL, NULL, NULL)) == NULL) {
        fprintf(stderr, "Failed to load certificate\n");
		return NULL;
	}
	if(!X509_PUBKEY_set(&ext, pkey)) {
		return NULL;
	}
	return ext;

 err:
 	if (ext)
 		X509_PUBKEY_free(ext);
 	if (pubkey)
 		BIO_free(pubkey);
 	if (pkey)
 		EVP_PKEY_free(pkey);
	return NULL;
}


static int i2r_altPubkey(const X509V3_EXT_METHOD *method,
                            void *ext, BIO *out, int indent)
{
	X509_PUBKEY *xpkey = ext;
	ASN1_OBJECT *xpoid;
	X509_PUBKEY_get0_param(&xpoid, NULL, NULL, NULL, xpkey);
	if (BIO_printf(out, "%*sSubject Public Key Info:\n", indent, "") <= 0)
		return 0;
	if (BIO_printf(out, "%*sPublic Key Algorithm: ", indent + 4, "") <= 0)
		return 0;
	if (i2a_ASN1_OBJECT(out, xpoid) <= 0)
		return 0;
	if (BIO_puts(out, "\n") <= 0)
		return 0;

	EVP_PKEY* pkey = X509_PUBKEY_get0(xpkey);
	if (pkey == NULL) {
		BIO_printf(out, "%*sUnable to load Public Key\n", indent + 4, "");
		ERR_print_errors(out);
	} else {
		EVP_PKEY_print_public(out, pkey, indent + 8, NULL);
	}
	return 1;
}

EVP_PKEY* X509_get_alt_pubkey(X509* x) {
    int i;
	X509_EXTENSION* ext;
    X509_PUBKEY* ck;
    //X509_get_ext_by_NID(x, NID_subject_alt_public_key_info, -1):4 
    // get the Catalyst signature extension
    if ((i = X509_get_ext_by_NID(x, NID_subject_alt_public_key_info, -1)) < 0) {
    	return NULL;
    }
	if ((ext = X509_get_ext(x, i)) == NULL) {
		return NULL;
	}
    if ((ck = X509V3_EXT_d2i(ext)) == NULL) {
    	return NULL;
    }
    printf("no null 133\n");
    return X509_PUBKEY_get0(ck);
}