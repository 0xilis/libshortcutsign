#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/param_build.h>
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/encoder.h>
#include <openssl/x509.h>
#include <plist/plist.h>
#include <openssl/err.h>
#include <inttypes.h>
#include <stddef.h>
#include "extract.h"
#include "verify.h"
#include "res.h"
#include <libNeoAppleArchive.h>

/* Function to convert EVP_PKEY to X9.63 encoded ECDSA-P256 public key */
__attribute__((visibility ("hidden"))) int convert_evp_pkey_to_x963(EVP_PKEY *pkey, uint8_t *out, size_t *out_len) {
    BIGNUM *x = NULL, *y = NULL;
    int rc = -1;
    
    if (!pkey || !out || !out_len || *out_len < 65) {
        return -1;
    }

    /* Get X and Y coordinates */
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &x) != 1 ||
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &y) != 1) {
        goto cleanup;
    }

    /* Verify P-256 size */
    if (BN_num_bytes(x) != 32 || BN_num_bytes(y) != 32) {
        goto cleanup;
    }

    /* Format as uncompressed X9.63 */
    out[0] = 0x04;  // Uncompressed marker
    BN_bn2binpad(x, out + 1, 32);
    BN_bn2binpad(y, out + 33, 32);
    *out_len = 65;
    rc = 0;

cleanup:
    BN_free(x);
    BN_free(y);
    return rc;
}

void print_certificate_info(X509 *cert) {
    if (!cert) {
        fprintf(stderr, "Invalid certificate\n");
        return;
    }

    /* Print subject name */
    X509_NAME *subject = X509_get_subject_name(cert);
    if (subject) {
        char *subject_str = X509_NAME_oneline(subject, NULL, 0);
        if (subject_str) {
            printf("Subject: %s\n", subject_str);
            OPENSSL_free(subject_str);
        }
    }

    /* Print issuer name */
    X509_NAME *issuer = X509_get_issuer_name(cert);
    if (issuer) {
        char *issuer_str = X509_NAME_oneline(issuer, NULL, 0);
        if (issuer_str) {
            printf("Issuer: %s\n", issuer_str);
            OPENSSL_free(issuer_str);
        }
    }

    /* Print the validity period */
    const ASN1_TIME *notBefore = X509_get0_notBefore(cert);
    const ASN1_TIME *notAfter = X509_get0_notAfter(cert);
    if (notBefore && notAfter) {
        char notBeforeStr[128], notAfterStr[128];
        ASN1_TIME_to_tm(notBefore, NULL);
        ASN1_TIME_to_tm(notAfter, NULL);
        if (ASN1_TIME_to_tm(notBefore, (struct tm*)notBeforeStr) && ASN1_TIME_to_tm(notAfter, (struct tm*)notAfterStr)) {
            printf("Validity: %s - %s\n", notBeforeStr, notAfterStr);
        }
    }

    /* Print serial number */
    ASN1_INTEGER *serialNumber = X509_get_serialNumber(cert);
    if (serialNumber) {
        unsigned char *serialHex = NULL;
        int serialLength = i2d_ASN1_INTEGER(serialNumber, &serialHex);
        if (serialLength > 0) {
            printf("Serial Number: ");
            for (int i = 0; i < serialLength; i++) {
                printf("%02X", serialHex[i]);
            }
            printf("\n");
            OPENSSL_free(serialHex);
        }
    }

    /* Print the public key */
    EVP_PKEY *pubKey = X509_get_pubkey(cert);
    if (pubKey) {
        printf("Public Key Algorithm: %s\n", OBJ_nid2ln(EVP_PKEY_base_id(pubKey)));
        EVP_PKEY_free(pubKey);
    }
}

/* Function to load a certificate chain from an array of certificate data */
__attribute__((visibility ("hidden"))) static STACK_OF(X509) *load_certificate_chain(uint8_t **certDataArray, size_t certCount, size_t *certSizesList) {
    STACK_OF(X509) *chain = sk_X509_new_null();
    if (!chain) {
        fprintf(stderr, "Error creating certificate chain\n");
        return NULL;
    }

    size_t i;
    for (i = 0; i < certCount; i++) {
        const uint8_t *certData = certDataArray[i];
        size_t certSize = certSizesList[i];

        const unsigned char *p = certData;
        X509 *cert = d2i_X509(NULL, &p, certSize);
        if (!cert) {
            fprintf(stderr, "Error parsing certificate %zu in chain\n", i);
            sk_X509_pop_free(chain, X509_free);
            return NULL;
        }

        sk_X509_push(chain, cert);
    }

    if (certCount == 2) {
        const unsigned char *_AppleRootCA = AppleRootCA;
        X509 *leafCert = d2i_X509(NULL, &_AppleRootCA, 1215);

        if (!leafCert) {
            fprintf(stderr, "Error parsing leaf certificate\n");
            sk_X509_pop_free(chain, X509_free);
            return NULL;
        }

        /* Add the leaf certificate as the last certificate in the chain */
        sk_X509_push(chain, leafCert);
    }

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
__attribute__((visibility ("hidden"))) static EVP_PKEY* get_public_key_from_cert(const uint8_t *certData, size_t certSize) {
    const unsigned char *p = certData;

    X509 *cert = d2i_X509(NULL, &p, certSize);
    if (!cert) {
        /* If it fails, print an error message */
        fprintf(stderr, "Error parsing certificate in DER format\n");

        /* Attempt to parse the cert as PEM format (Base64 encoded) */
        BIO *bio = BIO_new_mem_buf(certData, certSize);
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

    X509_free(cert);

    return evp_pkey;
}


/* Function to parse the plist file and extract the AppleIDCertificateChain */
__attribute__((visibility ("hidden"))) static int parse_plist_for_cert_chain(uint8_t *authData, size_t authDataSize, uint8_t ***certDataArray, size_t *certCount, size_t **certSizesList, int *iCloudSigned, int iCloudAllowed) {
    plist_t plist;
    if (plist_from_memory((const char *)authData, authDataSize, &plist, 0) != PLIST_ERR_SUCCESS) {
        fprintf(stderr, "Failed to read plist from file\n");
        return -1;
    }

    *iCloudSigned = 0;
    plist_t cert_chain = plist_dict_get_item(plist, "AppleIDCertificateChain");
    if (!cert_chain) {
        *iCloudSigned = 1;
        cert_chain = plist_dict_get_item(plist, "SigningCertificateChain");
        if (!iCloudAllowed) {
            fprintf(stderr, "iCloud verification not yet supported\n");
            cert_chain = NULL;
            plist_free(plist);
            return -1;
        }
        if (!cert_chain || plist_get_node_type(cert_chain) != PLIST_ARRAY) {
            fprintf(stderr, "Invalid plist format or missing cert chain\n");
            plist_free(plist);
            return -1;
        }
    }

    *certCount = plist_array_get_size(cert_chain);
    *certDataArray = malloc(sizeof(uint8_t*) * (*certCount));
    *certSizesList = malloc(sizeof(size_t) * (*certCount));

    size_t i;
    for (i = 0; i < *certCount; i++) {
        plist_t certItem = plist_array_get_item(cert_chain, i);
        if (plist_get_node_type(certItem) != PLIST_DATA) {
            fprintf(stderr, "Invalid certificate data in cert chain\n");
            plist_free(plist);
            return -1;
        }

        uint8_t *certData;
        uint64_t certSize;
        plist_get_data_val(certItem, (char **)&certData, &certSize);

        (*certDataArray)[i] = malloc(certSize);
        (*certSizesList)[i] = certSize;
        memcpy((*certDataArray)[i], certData, certSize);
    }

    plist_free(plist);
    return 0;
}

/* Function to verify the authenticity of the dictionary (equivalent to verify_dict_auth_data) */
int verify_dict_auth_data(uint8_t *authData, size_t authDataSize) {
    uint8_t **certDataArray;
    size_t certCount;
    size_t *certSizesList;
    int iCloudSigned;

    /* Parse the plist and extract the certificate chain */
    if (parse_plist_for_cert_chain(authData, authDataSize, &certDataArray, &certCount, &certSizesList, &iCloudSigned, 1) != 0) {
        return -1;
    }

    /* Load the certificate chain */
    STACK_OF(X509) *chain = load_certificate_chain(certDataArray, certCount, certSizesList);
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

    plist_t plist;
    if (!iCloudSigned) {
        /* Parse the plist to extract the SigningPublicKey and SigningPublicKeySignature */
        if (plist_from_memory((const char *)authData, authDataSize, &plist, 0) != PLIST_ERR_SUCCESS) {
            fprintf(stderr, "Failed to read plist from file\n");
            return -1;
        }

        /* Extract SigningPublicKey */
        plist_t signingPublicKeyItem = plist_dict_get_item(plist, "SigningPublicKey");
        if (!signingPublicKeyItem || plist_get_node_type(signingPublicKeyItem) != PLIST_DATA) {
            fprintf(stderr, "Missing or invalid SigningPublicKey in plist\n");
            plist_free(plist);
            return -1;
        }
        uint8_t *signingPublicKey;
        uint64_t signingPublicKeyLen;
        plist_get_data_val(signingPublicKeyItem, (char **)&signingPublicKey, &signingPublicKeyLen);

        /* Extract SigningPublicKeySignature */
        plist_t signingPublicKeySignatureItem = plist_dict_get_item(plist, "SigningPublicKeySignature");
        if (!signingPublicKeySignatureItem || plist_get_node_type(signingPublicKeySignatureItem) != PLIST_DATA) {
            fprintf(stderr, "Missing or invalid SigningPublicKeySignature in plist\n");
            plist_free(plist);
            return -1;
        }
        uint8_t *signingPublicKeySignature;
        uint64_t signingPublicKeySignatureLen;
        plist_get_data_val(signingPublicKeySignatureItem, (char **)&signingPublicKeySignature, &signingPublicKeySignatureLen);

        /* Extract the root certificate (first in the chain) and get the EC public key */
        EVP_PKEY *rootCertPublicKey = NULL;
        const uint8_t *rootCertData = certDataArray[0]; /* Assuming the first cert is the root cert */
        size_t rootCertSize = certCount > 0 ? certSizesList[0] : 0;

        rootCertPublicKey = get_public_key_from_cert(rootCertData, rootCertSize);
        if (!rootCertPublicKey) {
            fprintf(stderr, "Failed to extract public key from certificate\n");
            plist_free(plist);
            return -1;
        }

        /* Verify the signature using the root certificate's public key */
        if (verify_rsa_signature(signingPublicKey, signingPublicKeyLen, signingPublicKeySignature, signingPublicKeySignatureLen, rootCertPublicKey) != 1) {
            fprintf(stderr, "Failed to verify signature\n");
            /* EC_KEY_free(rootCertPublicKey); */
            EVP_PKEY_free(rootCertPublicKey);
            plist_free(plist);
            return -1;
        }
    }

    /* Free the allocated memory */
    size_t i;
    for (i = 0; i < certCount; i++) {
        free(certDataArray[i]);
    }
    free(certDataArray);
    free(certSizesList);

    /* Free the plist structure */
    if (!iCloudSigned) {
        plist_free(plist);
    }

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
int __attribute__((deprecated)) verify_contact_signed_auth_data(uint8_t *authData, size_t authDataSize) {
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
int __attribute__((deprecated)) verify_contact_signed_shortcut(const char *signedShortcutPath) {
    return verify_signed_shortcut(signedShortcutPath);
}

int verify_signed_shortcut(const char *signedShortcutPath) {
    /* load AEA archive into memory */
    FILE *fp = fopen(signedShortcutPath,"rb");
    if (!fp) {
        fprintf(stderr,"libshortcutsign: verify_signed_shortcut failed to find path\n");
        return -1;
    }
    fseek(fp, 0, SEEK_END);
    size_t binarySize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    uint8_t *aeaShortcutArchive = malloc(binarySize);
    size_t n = fread(aeaShortcutArchive, 1, binarySize, fp);
    if (n != binarySize) {
        fprintf(stderr, "libshortcutsign: failed to read all of file\n");
        return -1;
    }
    fclose(fp);
    int result = verify_signed_shortcut_buffer(aeaShortcutArchive, binarySize);
    free(aeaShortcutArchive);
    return result;
}

int verify_signed_shortcut_buffer(uint8_t *buffer, size_t bufferSize) {
    size_t authDataSize;
    uint8_t *authData = auth_data_from_shortcut_buffer(buffer, bufferSize, &authDataSize);
    if (!authData) {
        fprintf(stderr,"libshortcutsign: verification failed to extract authData\n");
        return -1;
    }
    if (verify_dict_auth_data(authData, authDataSize)) {
        /* Invalid auth data */
        return -1;
    }
    /* I should probably move this to a separate verify shortcut prologue func... */
    uint8_t **certDataArray;
    size_t certCount;
    size_t *certSizesList;
    int iCloudSigned;

    /* Parse the plist and extract the certificate chain */
    if (parse_plist_for_cert_chain(authData, authDataSize, &certDataArray, &certCount, &certSizesList, &iCloudSigned, 1) != 0) {
        free(authData);
        return -1;
    }

    /* Load the certificate chain */
    STACK_OF(X509) *chain = load_certificate_chain(certDataArray, certCount, certSizesList);
    if (!chain) {
        fprintf(stderr, "Error loading certificate chain\n");
        return -1;
    }

    uint8_t *signingPublicKey = NULL;
    if (iCloudSigned) {
        /* Extract the root certificate (first in the chain) and get the EC public key */
        EVP_PKEY *rootCertPublicKey = NULL;
        const uint8_t *rootCertData = certDataArray[0]; /* Assuming the first cert is the root cert */
        size_t rootCertSize = certCount > 0 ? certSizesList[0] : 0;

        rootCertPublicKey = get_public_key_from_cert(rootCertData, rootCertSize);
        if (!rootCertPublicKey) {
            fprintf(stderr, "Failed to extract public key from certificate\n");
            return -1;
        }
        size_t signingPublicKeySize = 65;
        signingPublicKey = malloc(signingPublicKeySize * 2); /* allocate extra space just in case we grow in size */
        convert_evp_pkey_to_x963(rootCertPublicKey, signingPublicKey, &signingPublicKeySize);
        EVP_PKEY_free(rootCertPublicKey);
    } else {
        /* Parse the plist to extract the SigningPublicKey and SigningPublicKeySignature */
        plist_t plist;
        if (plist_from_memory((const char *)authData, authDataSize, &plist, 0) != PLIST_ERR_SUCCESS) {
            fprintf(stderr, "Failed to read plist from file\n");
            return -1;
        }

        /* Extract SigningPublicKey */
        plist_t signingPublicKeyItem = plist_dict_get_item(plist, "SigningPublicKey");
        if (!signingPublicKeyItem || plist_get_node_type(signingPublicKeyItem) != PLIST_DATA) {
            fprintf(stderr, "Missing or invalid SigningPublicKey in plist\n");
            plist_free(plist);
            return -1;
        }
        uint64_t signingPublicKeyLen;
        plist_get_data_val(signingPublicKeyItem, (char **)&signingPublicKey, &signingPublicKeyLen);
    }

    /* Ensure signingPublicKey is valid before using it */
    if (!signingPublicKey) {
        fprintf(stderr, "Failed to extract or allocate signingPublicKey\n");
        return -1;
    }

    NeoAEAArchive aea = neo_aea_archive_with_encoded_data_nocopy(buffer, bufferSize);
    if (!aea) {
        fprintf(stderr,"libshortcutsign: verification failed to form aea\n");
        return -1;
    }
    int isVerified = neo_aea_archive_verify(aea, signingPublicKey);

    /* Free the allocated memory */
    size_t i;
    for (i = 0; i < certCount; i++) {
        free(certDataArray[i]);
    }
    free(certDataArray);
    free(certSizesList);
    free(authData);

    neo_aea_archive_destroy(aea);
    return isVerified;
}

SSFormat get_shortcut_format(uint8_t *buffer, size_t bufferSize) {
    if (bufferSize < 6) {
        fprintf(stderr,"libshortcutsign: buffer too small\n");
        return SHORTCUT_UNKNOWN_FORMAT;
    }
    /* First see if it's bplist or plist */
    if (strncmp("bplist", (char *)buffer, 6) == 0) {
        return SHORTCUT_UNSIGNED;
    }
    if (strncmp("<?xml", (char *)buffer, 5) == 0) {
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

    free(authData);

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

void print_shortcut_cert_info(uint8_t *buffer, size_t bufferSize) {
    size_t authDataSize;
    uint8_t *authData = auth_data_from_shortcut_buffer(buffer, bufferSize, &authDataSize);
    if (!authData) {
        fprintf(stderr,"libshortcutsign: failed to extract authData\n");
        return;
    }

    uint8_t **certDataArray;
    size_t certCount;
    size_t *certSizesList;
    int iCloudSigned;

    /* Parse the plist and extract the certificate chain */
    if (parse_plist_for_cert_chain(authData, authDataSize, &certDataArray, &certCount, &certSizesList, &iCloudSigned, 1) != 0) {
        free(authData);
        return;
    }

    /* Load the certificate chain */
    STACK_OF(X509) *chain = load_certificate_chain(certDataArray, certCount, certSizesList);
    if (!chain) {
        fprintf(stderr, "Error loading certificate chain\n");
        free(certDataArray);
        free(certSizesList);
        free(authData);
        return;
    }

    int chain_size = sk_X509_num(chain);

    for (int i = 0; i < chain_size; i++) {
        X509 *cert = sk_X509_value(chain, i); 
        if (cert) {
            printf("Certificate %d:\n", i + 1);
            print_certificate_info(cert);
            printf("\n");
        } else {
            fprintf(stderr, "Error retrieving certificate at index %d\n", i);
        }
    }

    /* Free the allocated memory */
    size_t i;
    for (i = 0; i < certCount; i++) {
        free(certDataArray[i]);
    }
    free(certDataArray);
    free(certSizesList);
    free(authData);
}
