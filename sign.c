#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/kdf.h>
#include <openssl/param_build.h>
#include <lzfse.h>
#include <libNeoAppleArchive.h>
#include "res.h"

#define EMBEDDED_SIGNED_DATA_SIZE 10589
#define EMBEDDED_SIGNED_DATA_ADS 0x01

__attribute__((visibility ("hidden"))) static void *hmac_derive(void *hkdf_key, void *data1, size_t data1Len, void *data2, size_t data2Len) {
    unsigned char *hmac = malloc(SHA256_DIGEST_LENGTH);
    OSSL_PARAM params[4];

    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) {
        fprintf(stderr, "Failed to fetch EVP MAC\n");
        return NULL;
    }

    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP MAC context\n");
        return NULL;
    }
    
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, OSSL_DIGEST_NAME_SHA2_256, sizeof(OSSL_DIGEST_NAME_SHA2_256));
    params[1] = OSSL_PARAM_construct_end();

    /* Initialize HMAC with SHA-256 */
    if (!EVP_MAC_init(ctx, hkdf_key, 32, params)) {
        fprintf(stderr, "Failed to initialize EVP MAC\n");
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return NULL;
    }

    /* Update HMAC with data */
    if (data2 && data2Len > 0) {
        if (!EVP_MAC_update(ctx, data2, data2Len)) {
            fprintf(stderr, "Failed to update HMAC\n");
            EVP_MAC_CTX_free(ctx);
            EVP_MAC_free(mac);
            return NULL;
        }
    }
    if (data1 && data1Len > 0) {
        if (!EVP_MAC_update(ctx, data1, data1Len)) {
            fprintf(stderr, "Failed to update HMAC\n");
            EVP_MAC_CTX_free(ctx);
            EVP_MAC_free(mac);
            return NULL;
        }
    }
    if (!EVP_MAC_update(ctx, (const unsigned char *)&data2Len, 8)) {
        fprintf(stderr, "Failed to update HMAC\n");
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return NULL;
    }

    /* Finalize HMAC */
    size_t len = SHA256_DIGEST_LENGTH;
    if (!EVP_MAC_final(ctx, hmac, NULL, len)) {
        fprintf(stderr, "Failed to finalize HMAC\n");
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return NULL;
    }
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);

    return hmac;
}

__attribute__((visibility ("hidden"))) static void *do_hkdf(void *context, size_t contextLen, void *key) {
    void *derivedKey = malloc(512);
    if (!derivedKey) {
        return NULL;
    }
    EVP_KDF* kdf;
    if ((kdf = EVP_KDF_fetch(NULL, "hkdf", NULL)) == NULL) {
        return NULL;
    }
    EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (ctx == NULL) {
        return NULL;
    }
    OSSL_PARAM params[4] = {
        OSSL_PARAM_construct_utf8_string("digest", "sha256", sizeof("sha256")),
        OSSL_PARAM_construct_octet_string("key", key, 32),
        OSSL_PARAM_construct_octet_string("info", context, contextLen),
        OSSL_PARAM_construct_end()
    };
    if (EVP_KDF_CTX_set_params(ctx, params) <= 0) {
        return NULL;
    }
    if (EVP_KDF_derive(ctx, derivedKey, 32, NULL) <= 0) {
        return NULL;
    }
    EVP_KDF_CTX_free(ctx);
    return derivedKey;
}

/* Helper function to perform HKDF using OpenSSL */
__attribute__((visibility ("hidden"))) static int hkdf_extract_and_expand_helper(const uint8_t *salt, size_t salt_len,
                            const uint8_t *key, size_t key_len,
                            const uint8_t *info, size_t info_len,
                            uint8_t *out, size_t out_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to create HKDF context\n");
        return 0;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        fprintf(stderr, "Failed to initialize HKDF context\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0) {
        fprintf(stderr, "Failed to set HKDF hash function\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, salt_len) <= 0) {
        fprintf(stderr, "Failed to set HKDF salt\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, key, key_len) <= 0) {
        fprintf(stderr, "Failed to set HKDF key\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(ctx, info, info_len) <= 0) {
        fprintf(stderr, "Failed to set HKDF info\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_derive(ctx, out, &out_len) <= 0) {
        fprintf(stderr, "Failed to derive HKDF output\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    EVP_PKEY_CTX_free(ctx);
    return 1;
}

int resign_shortcut_prologue(uint8_t *signedShortcut, void *privateKey, size_t privateKeyLen) {

    /* privateKeyLen is unused but don't break API */
    (void)privateKeyLen;

    /* TODO: Don't just support X9.63 keys, also support PEM encoded */
    size_t authDataSize = 0;
    memcpy(&authDataSize, signedShortcut + 8, 4);

    /* zero out the sig for the hash */
    memset(signedShortcut + authDataSize + 0xc, 0, 128);  /* Zero out the signature field */

    /* parse the X9.63 ECDSA-P256 key */
    unsigned char *priv_key_ptr = (unsigned char *)privateKey;
    BIGNUM *pub_key_bn = BN_bin2bn(priv_key_ptr + 1, 64, NULL);
    if (!pub_key_bn) {
        fprintf(stderr, "shortcut-sign: failed to parse raw public key\n");
        return -1;
    }

    BIGNUM *priv_key_bn = BN_bin2bn(priv_key_ptr + 0x41, 32, NULL);
    if (!priv_key_bn) {
        fprintf(stderr, "shortcut-sign: failed to parse raw private key\n");
        return -1;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);;
	if (ctx == NULL) {
		fprintf(stderr, "shortcut-sign: failed to create EVP_PKEY_CTX object\n");
        BN_free(pub_key_bn);
        BN_free(priv_key_bn);
        return -1;
	}

    if (!EVP_PKEY_fromdata_init(ctx)) {
        fprintf(stderr, "shortcut-sign: failed to initialize context\n");
        BN_free(pub_key_bn);
        BN_free(priv_key_bn);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    OSSL_PARAM_BLD *paramb = OSSL_PARAM_BLD_new();
    if (!paramb) {
        fprintf(stderr, "shortcut-sign: failed to initialize parameter builder\n");
        BN_free(pub_key_bn);
        BN_free(priv_key_bn);
        return -1;
    }
    /* create an EC_PKEY object for the secp256r1 curve */
    if (!OSSL_PARAM_BLD_push_utf8_string(paramb, OSSL_PKEY_PARAM_GROUP_NAME, SN_X9_62_prime256v1, 0)) {
        fprintf(stderr, "shortcut-sign: failed to push group name\n");
        BN_free(pub_key_bn);
        BN_free(priv_key_bn);
        OSSL_PARAM_BLD_free(paramb);
        return -1;
    }
    /* set the private key in the EC_KEY object */
    if (!OSSL_PARAM_BLD_push_BN(paramb, OSSL_PKEY_PARAM_PRIV_KEY, priv_key_bn)) {
        fprintf(stderr, "shortcut-sign: failed to push private key\n");
        BN_free(pub_key_bn);
        BN_free(priv_key_bn);
        OSSL_PARAM_BLD_free(paramb);
        return -1;
    }
    /* set the public key in the EC_KEY object */
    if (!OSSL_PARAM_BLD_push_octet_string(paramb, OSSL_PKEY_PARAM_PUB_KEY, priv_key_ptr, 64 + 1)) {
        fprintf(stderr, "shortcut-sign: failed to push public key\n");
        BN_free(pub_key_bn);
        BN_free(priv_key_bn);
        OSSL_PARAM_BLD_free(paramb);
        return -1;
    }

    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(paramb);
    if (!params) {
        fprintf(stderr, "shortcut-sign: failed to create parameters\n");
        BN_free(pub_key_bn);
        BN_free(priv_key_bn);
        OSSL_PARAM_BLD_free(paramb);
        return -1;
    }
    OSSL_PARAM_BLD_free(paramb);

    EVP_PKEY *pkey = NULL;

    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
        fprintf(stderr, "shortcut-sign: failed to create EVP_PKEY object\n");
        BN_free(pub_key_bn);
        BN_free(priv_key_bn);
        EVP_PKEY_free(pkey);
        return -1;
    }
    OSSL_PARAM_free(params);
    
    /* sign the sha256 hash */
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        fprintf(stderr, "shortcut-sign: failed to create EVP_MD_CTX_new\n");
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (EVP_SignInit(md_ctx, EVP_sha256()) != 1) {
        fprintf(stderr, "shortcut-sign: EVP_SignInit failed\n");
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (EVP_SignUpdate(md_ctx, signedShortcut, authDataSize + 0x13c) != 1) {
        fprintf(stderr, "shortcut-sign: EVP_SignUpdate failed\n");
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }

    unsigned char *signature = malloc(EVP_PKEY_size(pkey));
    if (!signature) {
        fprintf(stderr, "shortcut-sign: not enough memory\n");
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }

    unsigned int sigLen;
    if (EVP_SignFinal(md_ctx, signature, &sigLen, pkey) != 1) {
        fprintf(stderr, "shortcut-sign: failed to sign the hash\n");
        free(signature);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }
    EVP_MD_CTX_free(md_ctx);

    /* there is no chance of this happening but im paranoid */
    if (sigLen > 128) {
        fprintf(stderr, "shortcut-sign: sigLen exceeds 128 bytes\n");
        free(signature);
        EVP_PKEY_free(pkey);
        return -1;
    }

    /* overwrite the signature field in the archive with the new signature */
    memcpy(signedShortcut + authDataSize + 0xc, signature, sigLen);

    /* clean up */
    free(signature);
    EVP_PKEY_free(pkey);
    return 0;
}

struct lss_aea_segment_header {
    uint32_t originalSize;
    uint32_t compressedSize;
    /* size: based on rootHeader.checksumAlgorithm
       0 for checksumAlgorithm 0
       8 for checksumAlgorithm 1 (Murmur64 Hash)
       32 for checksumAlgorithm 2 (SHA-256)
     */
    uint8_t* hash;
    uint8_t segmentHMAC[0x20];
};

int resign_shortcut_with_new_aa(uint8_t **signedShortcut, void *archivedDir, size_t archivedDirSize, size_t *newSize, void *privateKey) {
    /* TODO: This code is really hard to understand */
    /* In the future, neo_aea_sign implemented in libNeoAppleArchive, use that */

    uint8_t *_signedShortcut = *signedShortcut;

    /* Extract authDataSize from signedShortcut */
    size_t authDataSize;
    memcpy(&authDataSize, _signedShortcut + 8, 4);

    memcpy(_signedShortcut + authDataSize + 0xec, &archivedDirSize, 4);

    /* Set compressed LZFSE data */
    size_t signedShortcutMallocSize = authDataSize + 0x495c + archivedDirSize;
    _signedShortcut = realloc(_signedShortcut, signedShortcutMallocSize);
    if (!_signedShortcut) {
        fprintf(stderr,"libshortcutsign: could not realloc signedShortcut\n");
        return -1;
    }
    /* Adjust pointer for realloc */
    *signedShortcut = _signedShortcut;

    /* Prepare HKDF context */
    const uint8_t *salt = (uint8_t *)(_signedShortcut + authDataSize + 0xac);
    const uint8_t *keyDerivationKey = (uint8_t *)(_signedShortcut + authDataSize + 0x8c); // 32-byte key
    uint8_t context[0x4c] = {0};
    memcpy(context, "AEA_AMK", 7);
    memcpy(context + 11, privateKey, 0x41); // Copy public part of private key

    /* Derive key using OpenSSL HKDF */
    uint8_t derivedKey[32];
    if (!hkdf_extract_and_expand_helper(salt, 32, keyDerivationKey, 32, context, sizeof(context), derivedKey, 32)) {
        fprintf(stderr, "HKDF derivation failed\n");
        return -1;
    }

    /* 
     * Currently, signedShortcutMallocSize will be resignedSize
     * This is because we currently don't implement LZFSE compression
     * In the future, implement this...
     */
    size_t resignedShortcutSize = signedShortcutMallocSize;
    memcpy(_signedShortcut + authDataSize + 0xec + 8, &resignedShortcutSize, 4);

    /* Derive AEA_CK/AEA_SK keys using HKDF */
    uint8_t aea_ck_ctx[10];
    memcpy(aea_ck_ctx, "AEA_CK", 6);
    memset((char *)aea_ck_ctx + 6, 0, 4);
    uint8_t *aea_ck = do_hkdf(aea_ck_ctx, 10, derivedKey);
    uint8_t aea_sk_ctx[10];
    memcpy(aea_sk_ctx, "AEA_SK", 6);
    memset((char *)aea_sk_ctx + 6, 0, 4);
    uint8_t *aea_sk = do_hkdf(aea_sk_ctx, 10, aea_ck);

    uint8_t *hmac;

    int nSegment = 0;
    size_t sizeLeft = archivedDirSize;
    size_t maxSegmentSize = (size_t) *(uint32_t *)(_signedShortcut + authDataSize + 0xec + 16);
    uint8_t *segmentData = _signedShortcut + authDataSize + 0x495c;
    size_t mallocSizeLeft = archivedDirSize;
    uint8_t *originalFileSegment = archivedDir;
    struct lss_aea_segment_header *segmentHeader = (void *)(_signedShortcut + authDataSize + 0x13c);
    uint8_t *segmentHMAC = _signedShortcut + authDataSize + 0x295c;
    while (sizeLeft) {
        size_t segmentSize = maxSegmentSize;
        if (segmentSize > sizeLeft) {
            segmentSize = sizeLeft;
        }
        /*
         * TODO:
         *
         * Dealing with compression in multi-segment AEA is hard
         * For right now, I'm just going to have all segments uncompressed
         * When I do a full fledged neo_aea_sign, flesh it out later
         */
        if (mallocSizeLeft < sizeLeft) {
            fprintf(stderr,"libshortcutsign: mallocSizeLeft is under sizeLeft\n");
            return -1;
        }
        memcpy(segmentData, originalFileSegment, segmentSize);
        segmentHeader->originalSize = segmentSize;
        segmentHeader->compressedSize = segmentSize;
        
        /* HMAC derivation for AEA_CK, AEA_SK */
        hmac = hmac_derive(aea_sk, segmentData, segmentSize, 0, 0);

        /* Replace old hmac in binary data */
        memcpy(segmentHMAC, hmac, 32);
        free(hmac);

        nSegment++;
        sizeLeft -= segmentSize;
        segmentData += segmentSize;
        mallocSizeLeft -= segmentSize;
        originalFileSegment += segmentSize;
        segmentHeader += 40;
        segmentHMAC += 32;
    }
    free(archivedDir);
    free(aea_sk);

    /* Re-hmac for AEA_CHEK */
    uint8_t *aea_chek = do_hkdf("AEA_CHEK", 8, aea_ck);
    /* data1 is the segment headers in cluster 0 */
    hmac = hmac_derive(aea_chek, _signedShortcut + authDataSize + 0x13c, 0x2800, _signedShortcut + authDataSize + 0x293c, 32);
    memcpy(_signedShortcut + authDataSize + 0x11c, hmac, 32);
    free(hmac);

    /* Re-hmac for AEA_RHEK */
    uint8_t *aea_rhek = do_hkdf("AEA_RHEK", 8, derivedKey);
    uint8_t *chekPlusAuthData = malloc(authDataSize + 32);
    memcpy(chekPlusAuthData, _signedShortcut + authDataSize + 0x11c, 32);
    memcpy(chekPlusAuthData + 32, _signedShortcut + 0xc, authDataSize);
    hmac = hmac_derive(aea_rhek, _signedShortcut + authDataSize + 0xec, 0x30, chekPlusAuthData, authDataSize + 0x20);
    memcpy(_signedShortcut + authDataSize + 0xcc, hmac, 32);
    free(chekPlusAuthData);
    free(hmac);
    free(aea_rhek);

    /* Resign shortcut prologue */
    if (resign_shortcut_prologue(_signedShortcut, privateKey, 97)) {
        fprintf(stderr,"libshortcutsign: failed to resign prologue\n");
        return -1;
    }

    if (newSize) {
        *newSize = resignedShortcutSize;
    }

    return 0;
}

int resign_shortcut_with_new_plist(uint8_t **signedShortcut, void *plist, size_t plistSize, size_t *newSize, void *privateKey) {
    /* Form AAR from plist */
    NeoAAHeader header = neo_aa_header_create();
    if (!header) {
        fprintf(stderr,"libshortcutsign: failed to create aar header\n");
        return -1;
    }
    time_t currentDate = time(NULL);
    neo_aa_header_set_field_uint(header, NEO_AA_FIELD_C("TYP"), 1, 'D');
    neo_aa_header_set_field_string(header, NEO_AA_FIELD_C("PAT"), 0, 0);
    neo_aa_header_set_field_uint(header, NEO_AA_FIELD_C("MOD"), 2, 0x1ed);
    neo_aa_header_set_field_uint(header, NEO_AA_FIELD_C("FLG"), 1, 0);
    /* use currentTime for creation and modification time */
    neo_aa_header_set_field_timespec(header, NEO_AA_FIELD_C("CTM"), 12, currentDate);
    neo_aa_header_set_field_timespec(header, NEO_AA_FIELD_C("MTM"), 12, currentDate);
    NeoAAArchiveItem itemDir = neo_aa_archive_item_create_with_header(header);
    if (!itemDir) {
        fprintf(stderr,"libshortcutsign: failed to create aar header\n");
        neo_aa_header_destroy(header);
        return -1;
    }
    /* Create a new header for the Shortcut.wflow file */
    header = neo_aa_header_create();
    if (!header) {
        fprintf(stderr,"libshortcutsign: failed to create aar header\n");
        neo_aa_archive_item_destroy(itemDir);
        return -1;
    }
    neo_aa_header_set_field_uint(header, NEO_AA_FIELD_C("TYP"), 1, 'F');
    neo_aa_header_set_field_string(header, NEO_AA_FIELD_C("PAT"), strlen("Shortcut.wflow"), "Shortcut.wflow");
    neo_aa_header_set_field_uint(header, NEO_AA_FIELD_C("MOD"), 2, 0x1a4);
    neo_aa_header_set_field_uint(header, NEO_AA_FIELD_C("FLG"), 1, 0);
    neo_aa_header_set_field_timespec(header, NEO_AA_FIELD_C("CTM"), 12, currentDate);
    neo_aa_header_set_field_timespec(header, NEO_AA_FIELD_C("MTM"), 12, currentDate);

    neo_aa_header_set_field_blob(header, NEO_AA_FIELD_C("DAT"), 0, plistSize);

    /* TODO: ADD CTM & MTM fields once neoaa supports it */
    NeoAAArchiveItem itemPlist = neo_aa_archive_item_create_with_header(header);
    if (!itemPlist) {
        fprintf(stderr,"libshortcutsign: failed to create aar header\n");
        neo_aa_header_destroy(header);
        neo_aa_archive_item_destroy(itemDir);
        return -1;
    }
    /* Add plist blob data */
    neo_aa_archive_item_add_blob_data(itemPlist, plist, plistSize);
    
    NeoAAArchiveItem *items = malloc(sizeof(NeoAAArchiveItem) * 2);
    if (!items) {
        fprintf(stderr,"libshortcutsign: out of memory\n");
        neo_aa_archive_item_destroy(itemPlist);
        neo_aa_archive_item_destroy(itemDir);
        return -1;
    }
    items[0] = itemDir;
    items[1] = itemPlist;
    NeoAAArchivePlain archive = neo_aa_archive_plain_create_with_items_nocopy(items, 2);
    if (!archive) {
        fprintf(stderr,"libshortcutsign: failed to create aar header\n");
        return -1;
    }
    size_t aarSize = 0;
    uint8_t *encodedData = neo_aa_archive_plain_get_encoded_data(archive, &aarSize);
    neo_aa_archive_plain_destroy_nozero(archive);
    if (!encodedData || !aarSize) {
        fprintf(stderr,"libshortcutsign: failed to get encoded aar data\n");
        return -1;
    }
    return resign_shortcut_with_new_aa(signedShortcut, encodedData, aarSize, newSize, privateKey);
}

uint8_t *sign_shortcut_aar_with_private_key_and_auth_data(void *aar, size_t aarSize, void *privateKey, uint8_t *authData, size_t authDataSize, size_t *outSize) {
    /*
     * TODO:
     * neo_aea_sign_* is not done for libNeoAppleArchive
     * So, as a placebo until I finish and can implement it,
     * Allocate signed shortcut, piggyback off of one in resource
     * In the future, signedShortcutSize can be found by:
     * 0x495c + authDataSize + compressedSize;
     */
    int64_t _signedShortcutSize = EMBEDDED_SIGNED_DATA_SIZE + ((int64_t)authDataSize - (int64_t) EMBEDDED_SIGNED_DATA_ADS);
    if (_signedShortcutSize < 0) {
        fprintf(stderr,"libshortcutsign: _signeedShortcutSize underflow\n");
        return 0;
    }
    size_t signedShortcutSize = (size_t)_signedShortcutSize;
    uint8_t *signedShortcut = malloc(signedShortcutSize);
    /* Copy the root header from embedded aea */
    memcpy(signedShortcut, embeddedSignedData, 8);
    /* Copy the authDataSize to header */
    uint32_t _authDataSize = (uint32_t)authDataSize;
    memcpy(signedShortcut + 8, &_authDataSize, 4);
    /* Copy auth data */
    memcpy(signedShortcut + 12, authData, authDataSize);
    /* Copy the rest of the shortcut */
    memcpy(signedShortcut + 12 + authDataSize, embeddedSignedData + 12 + EMBEDDED_SIGNED_DATA_ADS, EMBEDDED_SIGNED_DATA_SIZE - EMBEDDED_SIGNED_DATA_ADS - 12);
    if (resign_shortcut_with_new_aa(&signedShortcut, aar, aarSize, outSize, privateKey)) {
        free(signedShortcut);
        fprintf(stderr,"libshortcutsign: could not sign aar\n");
        return 0;
    }
    return signedShortcut;
}

uint8_t *sign_shortcut_with_private_key_and_auth_data(void *plist, size_t plistSize, void *privateKey, uint8_t *authData, size_t authDataSize, size_t *outSize) {
    /* Form AAR from plist */
    NeoAAHeader header = neo_aa_header_create();
    if (!header) {
        fprintf(stderr,"libshortcutsign: failed to create aar header\n");
        return 0;
    }
    time_t currentDate = time(NULL);
    neo_aa_header_set_field_uint(header, NEO_AA_FIELD_C("TYP"), 1, 'D');
    neo_aa_header_set_field_string(header, NEO_AA_FIELD_C("PAT"), 0, 0);
    neo_aa_header_set_field_uint(header, NEO_AA_FIELD_C("MOD"), 2, 0x1ed);
    neo_aa_header_set_field_uint(header, NEO_AA_FIELD_C("FLG"), 1, 0);
    /* use currentTime for creation and modification time */
    neo_aa_header_set_field_timespec(header, NEO_AA_FIELD_C("CTM"), 12, currentDate);
    neo_aa_header_set_field_timespec(header, NEO_AA_FIELD_C("MTM"), 12, currentDate);
    NeoAAArchiveItem itemDir = neo_aa_archive_item_create_with_header(header);
    if (!itemDir) {
        fprintf(stderr,"libshortcutsign: failed to create aar header\n");
        neo_aa_header_destroy(header);
        return 0;
    }
    /* Create a new header for the Shortcut.wflow file */
    header = neo_aa_header_create();
    if (!header) {
        fprintf(stderr,"libshortcutsign: failed to create aar header\n");
        neo_aa_archive_item_destroy(itemDir);
        return 0;
    }
    neo_aa_header_set_field_uint(header, NEO_AA_FIELD_C("TYP"), 1, 'F');
    neo_aa_header_set_field_string(header, NEO_AA_FIELD_C("PAT"), strlen("Shortcut.wflow"), "Shortcut.wflow");
    neo_aa_header_set_field_uint(header, NEO_AA_FIELD_C("MOD"), 2, 0x1a4);
    neo_aa_header_set_field_uint(header, NEO_AA_FIELD_C("FLG"), 1, 0);
    neo_aa_header_set_field_timespec(header, NEO_AA_FIELD_C("CTM"), 12, currentDate);
    neo_aa_header_set_field_timespec(header, NEO_AA_FIELD_C("MTM"), 12, currentDate);

    neo_aa_header_set_field_blob(header, NEO_AA_FIELD_C("DAT"), 0, plistSize);

    /* TODO: ADD CTM & MTM fields once neoaa supports it */
    NeoAAArchiveItem itemPlist = neo_aa_archive_item_create_with_header(header);
    if (!itemPlist) {
        fprintf(stderr,"libshortcutsign: failed to create aar header\n");
        neo_aa_header_destroy(header);
        neo_aa_archive_item_destroy(itemDir);
        return 0;
    }
    /* Add plist blob data */
    neo_aa_archive_item_add_blob_data(itemPlist, plist, plistSize);
    
    NeoAAArchiveItem *items = malloc(sizeof(NeoAAArchiveItem) * 2);
    if (!items) {
        fprintf(stderr,"libshortcutsign: out of memory\n");
        neo_aa_archive_item_destroy(itemPlist);
        neo_aa_archive_item_destroy(itemDir);
        return 0;
    }
    items[0] = itemDir;
    items[1] = itemPlist;
    NeoAAArchivePlain archive = neo_aa_archive_plain_create_with_items_nocopy(items, 2);
    if (!archive) {
        fprintf(stderr,"libshortcutsign: failed to create aar header\n");
        return 0;
    }
    size_t aarSize = 0;
    uint8_t *aar = neo_aa_archive_plain_get_encoded_data(archive, &aarSize);
    neo_aa_archive_plain_destroy_nozero(archive);
    if (!aar || !aarSize) {
        fprintf(stderr,"libshortcutsign: failed to get encoded aar data\n");
        return 0;
    }
    return sign_shortcut_aar_with_private_key_and_auth_data(aar, aarSize, privateKey, authData, authDataSize, outSize);
}
