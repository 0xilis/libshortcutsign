#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/param_build.h>
#include <plist/plist.h>
#include <openssl/err.h>
#include <inttypes.h>
#include "extract.h"
#include "verify.h"
#include "res.h"

/*
 * NOTE: THIS CODE IS VERY INCOMPLETE AND BAD.
 * CURRENTLY USING A LOT OF DEPRECATED OPENSSL
 * FUNCTIONS BECAUSE I CANNOT FIND DOCS ON
 * THEIR REPLACEMENTS. VERY UNSTABLE, DO NOT USE!!!!
*/

/* Function to load a certificate chain from an array of certificate data */
__attribute__((visibility ("hidden"))) static STACK_OF(X509) *load_certificate_chain(uint8_t **cert_data_array, size_t cert_count, size_t *certSizesList) {
    STACK_OF(X509) *chain = sk_X509_new_null();
    if (!chain) {
        fprintf(stderr, "Error creating certificate chain\n");
        return NULL;
    }

    size_t i;
    for (i = 0; i < cert_count; i++) {
        const uint8_t *cert_data = cert_data_array[i];
        size_t cert_size = certSizesList[i];

        const unsigned char *p = cert_data;
        X509 *cert = d2i_X509(NULL, &p, cert_size);
        if (!cert) {
            fprintf(stderr, "Error parsing certificate %zu in chain\n", i);
            sk_X509_pop_free(chain, X509_free);
            return NULL;
        }

        sk_X509_push(chain, cert);
    }

    X509 *leafCert = d2i_X509(NULL, &AppleRootCA, 1215);

    if (!leafCert) {
        fprintf(stderr, "Error parsing leaf certificate\n");
        sk_X509_pop_free(chain, X509_free);
        return NULL;
    }

    /* Add the leaf certificate as the last certificate in the chain */
    sk_X509_push(chain, leafCert);

    return chain;
}

/* Function to verify a certificate chain */
__attribute__((visibility ("hidden"))) static int verify_certificate_chain(STACK_OF(X509) *chain) {
    if (!chain || sk_X509_num(chain) == 0) {
        fprintf(stderr, "Empty or invalid certificate chain\n");
        return -1;
    }

    /* Create a new X509 store */
    X509_STORE *store = X509_STORE_new();
    if (!store) {
        fprintf(stderr, "Error creating X509 store\n");
        return -1;
    }

    /* Disable certificate expiration checks */
    X509_STORE_set_flags(store, X509_V_FLAG_NO_CHECK_TIME);

    /* Add the root certificate (last in the chain) to the store */
    X509 *root_cert = sk_X509_value(chain, sk_X509_num(chain) - 1);
    if (!X509_STORE_add_cert(store, root_cert)) {
        fprintf(stderr, "Error adding root certificate to store\n");
        X509_STORE_free(store);
        return -1;
    }

    /* Create a verification context */
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error creating X509 store context\n");
        X509_STORE_free(store);
        return -1;
    }

    /* Initialize the context with the store and the certificate chain */
    X509 *leaf_cert = sk_X509_value(chain, 0);
    if (!X509_STORE_CTX_init(ctx, store, leaf_cert, chain)) {
        fprintf(stderr, "Error initializing X509 store context\n");
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
        return -1;
    }

    /* Verify the certificate chain */
    int ret = X509_verify_cert(ctx);
    if (ret != 1) {
        fprintf(stderr, "Certificate chain verification failed: %s\n",
                X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
    }

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);

    return ret; /* returns 1 if valid, 0 if invalid */
}

__attribute__((visibility ("hidden"))) static int verify_rsa_signature(const uint8_t *signed_data, size_t signed_data_len, const uint8_t *signature, size_t sig_len, EVP_PKEY *pkey) {
    /* Log the signed data and its hash for debugging */
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(signed_data, signed_data_len, hash);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_init(ctx);

    /* Use RSA-PSS padding */
    int ret = EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey);
    if (ret != 1) {
        fprintf(stderr, "Error initializing verification context (ret: %d)\n", ret);
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }

    /* Set RSA-PSS padding */
    if (EVP_PKEY_CTX_set_rsa_padding(EVP_MD_CTX_pkey_ctx(ctx), RSA_PKCS1_PSS_PADDING) != 1) {
        fprintf(stderr, "Error setting RSA-PSS padding\n");
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }

    ret = EVP_DigestVerifyUpdate(ctx, signed_data, signed_data_len);
    if (ret != 1) {
        fprintf(stderr, "Error updating verification context (ret: %d)\n", ret);
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }

    ret = EVP_DigestVerifyFinal(ctx, signature, sig_len);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return ret; /* returns 1 if valid, 0 if invalid, or -1 on error */
}

/* Function to extract the RSA public key from a certificate */
__attribute__((visibility ("hidden"))) static EVP_PKEY* get_public_key_from_cert(const uint8_t *cert_data, size_t cert_size) {
    const unsigned char *p = cert_data;

    X509 *cert = d2i_X509(NULL, &p, cert_size);
    if (!cert) {
        /* If it fails, print an error message */
        fprintf(stderr, "Error parsing certificate in DER format\n");

        /* Attempt to parse the cert as PEM format (Base64 encoded) */
        BIO *bio = BIO_new_mem_buf(cert_data, cert_size);
        if (!bio) {
            fprintf(stderr, "Error creating BIO for certificate\n");
            return NULL;
        }

        cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        BIO_free(bio);

        if (!cert) {
            fprintf(stderr, "Error parsing certificate in PEM format\n");
            return NULL;
        }
    }


    EVP_PKEY *evp_pkey = X509_get_pubkey(cert);
    if (!evp_pkey) {
        fprintf(stderr, "Error extracting public key from certificate\n");
        X509_free(cert);
        return NULL;
    }

    if (EVP_PKEY_id(evp_pkey) != EVP_PKEY_RSA) {
        fprintf(stderr, "Certificate does not contain an RSA public key\n");
        return NULL;
    }
    X509_free(cert);

    return evp_pkey;
}


/* Function to parse the plist file and extract the AppleIDCertificateChain */
__attribute__((visibility ("hidden"))) static int parse_plist_for_cert_chain(uint8_t *authData, size_t authDataSize, uint8_t ***cert_data_array, size_t *cert_count, size_t **certSizesList) {
    plist_t plist;
    if (plist_from_memory((const char *)authData, authDataSize, &plist, 0) != PLIST_ERR_SUCCESS) {
        fprintf(stderr, "Failed to read plist from file\n");
        return -1;
    }

    plist_t cert_chain = plist_dict_get_item(plist, "SigningCertificateChain");
    if (cert_chain) {
        fprintf(stderr, "auth data appears to be iCloud-Signed; libshortcutsign currently only supports contact signed\n");
        plist_free(plist);
        return -1;
    }

    cert_chain = plist_dict_get_item(plist, "AppleIDCertificateChain");
    if (!cert_chain || plist_get_node_type(cert_chain) != PLIST_ARRAY) {
        fprintf(stderr, "Invalid plist format or missing cert chain\n");
        plist_free(plist);
        return -1;
    }

    *cert_count = plist_array_get_size(cert_chain);
    *cert_data_array = malloc(sizeof(uint8_t*) * (*cert_count));
    *certSizesList = malloc(sizeof(size_t) * (*cert_count));

    size_t i;
    for (i = 0; i < *cert_count; i++) {
        plist_t cert_item = plist_array_get_item(cert_chain, i);
        if (plist_get_node_type(cert_item) != PLIST_DATA) {
            fprintf(stderr, "Invalid certificate data in cert chain\n");
            plist_free(plist);
            return -1;
        }

        uint8_t *cert_data;
        uint64_t cert_size;
        plist_get_data_val(cert_item, (char **)&cert_data, &cert_size);

        (*cert_data_array)[i] = malloc(cert_size);
        (*certSizesList)[i] = cert_size;
        memcpy((*cert_data_array)[i], cert_data, cert_size);
    }

    plist_free(plist);
    return 0;
}

/* Function to verify the authenticity of the dictionary (equivalent to verify_dict_auth_data) */
int verify_dict_auth_data(uint8_t *authData, size_t authDataSize) {
    uint8_t **cert_data_array;
    size_t cert_count;
    size_t *certSizesList;

    /* Parse the plist and extract the certificate chain */
    if (parse_plist_for_cert_chain(authData, authDataSize, &cert_data_array, &cert_count, &certSizesList) != 0) {
        return -1;
    }

    /* Load the certificate chain */
    STACK_OF(X509) *chain = load_certificate_chain(cert_data_array, cert_count, certSizesList);
    if (!chain) {
        fprintf(stderr, "Error loading certificate chain\n");
        return -1;
    }

    /* Verify the certificate chain */
    if (verify_certificate_chain(chain) != 1) {
        fprintf(stderr, "Certificate chain verification failed\n");
        sk_X509_pop_free(chain, X509_free);
        return -1;
    }

    /* Parse the plist to extract the SigningPublicKey and SigningPublicKeySignature */
    plist_t plist;
    if (plist_from_memory((const char *)authData, authDataSize, &plist, 0) != PLIST_ERR_SUCCESS) {
        fprintf(stderr, "Failed to read plist from file\n");
        return -1;
    }

    /* Extract SigningPublicKey */
    plist_t signing_public_key_item = plist_dict_get_item(plist, "SigningPublicKey");
    if (!signing_public_key_item || plist_get_node_type(signing_public_key_item) != PLIST_DATA) {
        fprintf(stderr, "Missing or invalid SigningPublicKey in plist\n");
        plist_free(plist);
        return -1;
    }
    uint8_t *signing_public_key;
    uint64_t signing_public_key_len;
    plist_get_data_val(signing_public_key_item, (char **)&signing_public_key, &signing_public_key_len);

    /* Extract SigningPublicKeySignature */
    plist_t signing_public_key_signature_item = plist_dict_get_item(plist, "SigningPublicKeySignature");
    if (!signing_public_key_signature_item || plist_get_node_type(signing_public_key_signature_item) != PLIST_DATA) {
        fprintf(stderr, "Missing or invalid SigningPublicKeySignature in plist\n");
        plist_free(plist);
        return -1;
    }
    uint8_t *signing_public_key_signature;
    uint64_t signing_public_key_signature_len;
    plist_get_data_val(signing_public_key_signature_item, (char **)&signing_public_key_signature, &signing_public_key_signature_len);

    /* Extract the root certificate (first in the chain) and get the EC public key */
    EVP_PKEY *root_cert_public_key = NULL;
    const uint8_t *root_cert_data = cert_data_array[0]; /* Assuming the first cert is the root cert */
    size_t root_cert_size = cert_count > 0 ? certSizesList[0] : 0;

    root_cert_public_key = get_public_key_from_cert(root_cert_data, root_cert_size);
    if (!root_cert_public_key) {
        fprintf(stderr, "Failed to extract public key from certificate\n");
        plist_free(plist);
        return -1;
    }

    /* Verify the signature using the root certificate's public key */
    if (verify_rsa_signature(signing_public_key, signing_public_key_len, signing_public_key_signature, signing_public_key_signature_len, root_cert_public_key) != 1) {
        fprintf(stderr, "Failed to verify signature\n");
        /* EC_KEY_free(root_cert_public_key); */
        EVP_PKEY_free(root_cert_public_key);
        plist_free(plist);
        return -1;
    }

    /* Free the allocated memory */
    size_t i;
    for (i = 0; i < cert_count; i++) {
        free(cert_data_array[i]);
    }
    free(cert_data_array);
    free(certSizesList);

    /* Free the plist structure */
    plist_free(plist);

    return 0; /* If everything is verified successfully */
}


/*
 * verify_contact_signed_auth_data
 *
 * Replicates WorkflowKit's signature check process
 * Currently only supports contact signed & no CMS (yet)
 *
 * If verified, this function returns 0.
 * If not verified, this function returns a negative error code.
*/
int verify_contact_signed_auth_data(uint8_t *authData, size_t authDataSize) {
    return verify_dict_auth_data(authData, authDataSize);
}

/*
 * verify_contact_signed_shortcut
 *
 * Replicates WorkflowKit's signature check process
 * Currently only supports contact signed & no CMS (yet)
 *
 * If verified, this function returns 0.
 * If not verified, this function returns a negative error code.
*/
int verify_contact_signed_shortcut(const char *signedShortcutPath) {
    size_t authDataSize;
    uint8_t *authData = auth_data_from_shortcut(signedShortcutPath, &authDataSize);
    if (!authData) {
        fprintf(stderr,"libshortcutsign: verification failed to extract authData\n");
        return -1;
    }
    return verify_contact_signed_auth_data(authData, authDataSize);
}

SSFormat get_shortcut_format(uint8_t *buffer, size_t bufferSize) {
    if (bufferSize < 6) {
        fprintf(stderr,"libshortcutsign: buffer too small\n");
        return SHORTCUT_UNKNOWN_FORMAT;
    }
    /* First see if it's bplist or plist */
    if (strcmp((char *)buffer, "bplist") == 0) {
        return SHORTCUT_UNSIGNED;
    }
    if (strcmp((char *)buffer, "<?xml") == 0) {
        return SHORTCUT_UNSIGNED;
    }
    /* check signed shortcut */
    size_t authDataSize;
    uint8_t *authData = auth_data_from_shortcut_buffer(buffer, bufferSize, &authDataSize);
    if (!authData || !authDataSize) {
        fprintf(stderr,"libshortcutsign: get_shortcut_format failed to extract authData\n");
        return SHORTCUT_UNKNOWN_FORMAT;
    }

    plist_t plist;
    if (plist_from_memory((const char *)authData, authDataSize, &plist, 0) != PLIST_ERR_SUCCESS) {
        fprintf(stderr, "Failed to read plist from file\n");
        return SHORTCUT_UNKNOWN_FORMAT;
    }

    plist_t cert_chain = plist_dict_get_item(plist, "SigningCertificateChain");
    if (cert_chain) {
        plist_free(plist);
        return SHORTCUT_SIGNED_ICLOUD;
    }

    cert_chain = plist_dict_get_item(plist, "AppleIDCertificateChain");
    if (!cert_chain || plist_get_node_type(cert_chain) != PLIST_ARRAY) {
        fprintf(stderr, "Invalid plist format or missing cert chain\n");
        plist_free(plist);
        return SHORTCUT_UNKNOWN_FORMAT;
    }

    return SHORTCUT_SIGNED_CONTACT;
}
