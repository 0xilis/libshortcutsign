#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/hmac.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/kdf.h>
#include <openssl/param_build.h>
#include "build/lzfse/include/lzfse.h"
#include "libs/libNeoAppleArchive/libNeoAppleArchive/libNeoAppleArchive.h"
#include "res.h"

/* Temporarily use private lnaa API until I finish public set_field_string */
void neo_aa_header_add_field_string(NeoAAHeader header, uint32_t key, size_t stringSize, char *s);

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

__attribute__((visibility ("hidden"))) static void *do_hkdf(const void *context, size_t contextLen, const void *key) {
    unsigned char *output = malloc(32);
    if (!output) {
        fprintf(stderr, "Failed to allocate memory for HKDF output\n");
        return NULL;
    }

    /* Create HKDF context */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to create HKDF context\n");
        free(output);
        return NULL;
    }

    /* Initialize HKDF */
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        fprintf(stderr, "Failed to initialize HKDF context\n");
        EVP_PKEY_CTX_free(ctx);
        free(output);
        return NULL;
    }

    /* Set HKDF hash function to SHA-256 */
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0) {
        fprintf(stderr, "Failed to set HKDF hash function\n");
        EVP_PKEY_CTX_free(ctx);
        free(output);
        return NULL;
    }

    /* Set HKDF key (input key material) */
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, key, 32) <= 0) {
        fprintf(stderr, "Failed to set HKDF key\n");
        EVP_PKEY_CTX_free(ctx);
        free(output);
        return NULL;
    }

    /* Set HKDF info (context) */
    if (EVP_PKEY_CTX_add1_hkdf_info(ctx, context, contextLen) <= 0) {
        fprintf(stderr, "Failed to set HKDF info\n");
        EVP_PKEY_CTX_free(ctx);
        free(output);
        return NULL;
    }

    /* Derive the output key */
    size_t out_len = 32;
    if (EVP_PKEY_derive(ctx, output, &out_len) <= 0) {
        fprintf(stderr, "Failed to derive HKDF output\n");
        EVP_PKEY_CTX_free(ctx);
        free(output);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return output;
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
    /* i cannot get this to work from uint32_t pointer so just do byte by byte */
    uint8_t *sptr = signedShortcut + 0xB;
    size_t authDataSize = 0;
    authDataSize |= *(sptr) << 24;
    authDataSize |= *(sptr - 1) << 16;
    authDataSize |= *(sptr - 2) << 8;
    authDataSize |= *(sptr - 3);

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
        ERR_print_errors_fp(stderr);
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

int resign_shortcut_with_new_aa(uint8_t *signedShortcut, void *archivedDir, size_t archivedDirSize, size_t *newSize, void *privateKey) {
    /* TODO: This code is really hard to understand */
    size_t compressedSize = archivedDirSize * 2;
    uint8_t *buffer = malloc(compressedSize);
    compressedSize = lzfse_encode_buffer(buffer, compressedSize, archivedDir, archivedDirSize, NULL);
    free(archivedDir);
    if (!buffer) {
        fprintf(stderr,"libshortcutsign: failed to compress LZFSE\n");
        return -1;
    }

    /* Extract authDataSize from signedShortcut */
    register const uint8_t *sptr = (const uint8_t *)(signedShortcut + 0xB);
    size_t authDataSize = *sptr << 24;
    authDataSize += *(sptr - 1) << 16;
    authDataSize += *(sptr - 2) << 8;
    authDataSize += *(sptr - 3);

    /* Fix authDataSize + offsets */
    memcpy(signedShortcut + authDataSize + 0xec, &archivedDirSize, 4);
    memcpy(signedShortcut + authDataSize + 0x13c, &archivedDirSize, 4);

    /* Set compressed LZFSE data */
    signedShortcut = realloc(signedShortcut, authDataSize + 0x495c + compressedSize);
    if (!signedShortcut) {
        fprintf(stderr,"libshortcutsign: could not realloc signedShortcut\n");
        return -1;
    }
    memcpy(signedShortcut + authDataSize + 0x495c, buffer, compressedSize);
    free(buffer);

    /* Prepare HKDF context */
    const uint8_t *salt = (uint8_t *)(signedShortcut + authDataSize + 0xac);
    const uint8_t *keyDerivationKey = (uint8_t *)(signedShortcut + authDataSize + 0x8c); // 32-byte key
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
     * before doing hmac, update the size in prolouge
     */
    memcpy(signedShortcut + authDataSize + 0x13c + 4, &compressedSize, 4);
    size_t resignedShortcutSize = authDataSize + 0x495c + compressedSize;
    memcpy(signedShortcut + authDataSize + 0xec + 8, &resignedShortcutSize, 4);

    /* Derive AEA_CK/AEA_SK keys using HKDF */
    void *aea_ck_ctx = malloc(10);
    memcpy(aea_ck_ctx, "AEA_CK", 6);
    memset((char *)aea_ck_ctx + 6, 0, 4);
    uint8_t *aea_ck = do_hkdf(aea_ck_ctx, 10, derivedKey);
    void *aea_sk_ctx = malloc(10);
    memcpy(aea_sk_ctx, "AEA_SK", 6);
    memset((char *)aea_sk_ctx + 6, 0, 4);
    uint8_t *aea_sk = do_hkdf(aea_sk_ctx, 10, aea_ck);
    free(aea_ck_ctx);
    free(aea_sk_ctx);

    /* HMAC derivation for AEA_CK, AEA_SK */
    uint8_t *hmac = hmac_derive(aea_sk, signedShortcut + authDataSize + 0x495c, compressedSize, 0, 0);

    /* Replace old hmac in binary data */
    memcpy(signedShortcut + authDataSize + 0x295c, hmac, 32);
    free(hmac);
    free(aea_sk);

    /* Re-hmac for AEA_CHEK */
    uint8_t *aea_chek = do_hkdf("AEA_CHEK", 8, aea_ck);
    /* TODO: This discloses memory into the resigned shortcut, but it still works?? */
    hmac = hmac_derive(aea_chek, signedShortcut + authDataSize + 0x13c, 0x2800, signedShortcut + authDataSize + 0x293c, 0x2020);
    memcpy(signedShortcut + authDataSize + 0x11c, hmac, 32);
    free(hmac);

    /* Re-hmac for AEA_RHEK */
    uint8_t *aea_rhek = do_hkdf("AEA_RHEK", 8, derivedKey);
    uint8_t *chekPlusAuthData = malloc(authDataSize + 32);
    memcpy(chekPlusAuthData, signedShortcut + authDataSize + 0x11c, 32);
    memcpy(chekPlusAuthData + 32, signedShortcut + 0xc, authDataSize);
    hmac = hmac_derive(aea_rhek, signedShortcut + authDataSize + 0xec, 0x30, chekPlusAuthData, authDataSize + 0x20);
    memcpy(signedShortcut + authDataSize + 0xcc, hmac, 32);
    free(chekPlusAuthData);
    free(hmac);
    free(aea_rhek);

    /* Resign shortcut prologue */
    if (resign_shortcut_prologue(signedShortcut, privateKey, 97)) {
        free(signedShortcut);
        fprintf(stderr,"libshortcutsign: failed to resign prologue\n");
        return -1;
    }

    if (newSize) {
        *newSize = (authDataSize + 0x495c + compressedSize);
    }

    return 0;
}

int resign_shortcut_with_new_plist(uint8_t *signedShortcut, void *plist, size_t plistSize, size_t *newSize, void *privateKey) {
    /* Form AAR from plist */
    NeoAAHeader header = neo_aa_header_create();
    if (!header) {
        fprintf(stderr,"libshortcutsign: failed to create aar header\n");
        return -1;
    }
    time_t currentDate = time(NULL);
    neo_aa_header_set_field_uint(header, NEO_AA_FIELD_C("TYP"), 1, 'D');
    neo_aa_header_add_field_string(header, NEO_AA_FIELD_C("PAT"), 0, 0);
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
    neo_aa_header_add_field_string(header, NEO_AA_FIELD_C("PAT"), strlen("Shortcut.wflow"), "Shortcut.wflow");
    neo_aa_header_set_field_uint(header, NEO_AA_FIELD_C("MOD"), 2, 0x1a4);
    neo_aa_header_set_field_uint(header, NEO_AA_FIELD_C("FLG"), 1, 0);
    neo_aa_header_set_field_timespec(header, NEO_AA_FIELD_C("CTM"), 12, currentDate);
    neo_aa_header_set_field_timespec(header, NEO_AA_FIELD_C("MTM"), 12, currentDate);

    /* If 16bit, do short, if 32bit do uint32_t, if more do 64bit */
    if (plistSize <= UINT16_MAX) {
        plistSize = (uint16_t)plistSize;
        neo_aa_header_set_field_blob(header, NEO_AA_FIELD_C("DAT"), sizeof(uint16_t), plistSize);
    } else if (plistSize <= UINT32_MAX) {
        plistSize = (uint32_t)plistSize;
        neo_aa_header_set_field_blob(header, NEO_AA_FIELD_C("DAT"), sizeof(uint32_t), plistSize);
    } else {
        neo_aa_header_set_field_blob(header, NEO_AA_FIELD_C("DAT"), sizeof(size_t), plistSize);
    }

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
    NeoAAArchivePlain archive = neo_aa_archive_plain_create_with_items(items, 2);
    neo_aa_archive_item_list_destroy(items, 2);
    if (!archive) {
        fprintf(stderr,"libshortcutsign: failed to create aar header\n");
        return -1;
    }
    size_t aarSize = 0;
    uint8_t *encodedData = neo_aa_archive_plain_get_encoded_data(archive, &aarSize);
    neo_aa_archive_plain_destroy(archive);
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
    int64_t _signedShortcutSize = 22485 + ((int64_t)authDataSize - (int64_t)0x89c);
    if (_signedShortcutSize < 0) {
        fprintf(stderr,"libshortcutsign: _signeedShortcutSize underflow\n");
        return 0;
    }
    size_t signedShortcutSize = (size_t)_signedShortcutSize;
    uint8_t *signedShortcut = malloc(signedShortcutSize);
    /* Copy the root header from embedded aea */
    memcpy(signedShortcut, &embeddedSignedData, 8);
    /* Copy the authDataSize to header */
    uint32_t _authDataSize = (uint32_t)authDataSize;
    memcpy(signedShortcut + 8, &_authDataSize, 4);
    /* Copy auth data */
    memcpy(signedShortcut + 12, authData, authDataSize);
    /* Copy the rest of the shortcut */
    memcpy(signedShortcut + 12 + authDataSize, &embeddedSignedData + 0x8a8, 22485 - 0x8a8);
    if (resign_shortcut_with_new_aa(signedShortcut, aar, aarSize, outSize, privateKey)) {
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
    neo_aa_header_add_field_string(header, NEO_AA_FIELD_C("PAT"), 0, 0);
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
    neo_aa_header_add_field_string(header, NEO_AA_FIELD_C("PAT"), strlen("Shortcut.wflow"), "Shortcut.wflow");
    neo_aa_header_set_field_uint(header, NEO_AA_FIELD_C("MOD"), 2, 0x1a4);
    neo_aa_header_set_field_uint(header, NEO_AA_FIELD_C("FLG"), 1, 0);
    neo_aa_header_set_field_timespec(header, NEO_AA_FIELD_C("CTM"), 12, currentDate);
    neo_aa_header_set_field_timespec(header, NEO_AA_FIELD_C("MTM"), 12, currentDate);

    /* If 16bit, do short, if 32bit do uint32_t, if more do 64bit */
    if (plistSize <= UINT16_MAX) {
        plistSize = (uint16_t)plistSize;
        neo_aa_header_set_field_blob(header, NEO_AA_FIELD_C("DAT"), sizeof(uint16_t), plistSize);
    } else if (plistSize <= UINT32_MAX) {
        plistSize = (uint32_t)plistSize;
        neo_aa_header_set_field_blob(header, NEO_AA_FIELD_C("DAT"), sizeof(uint32_t), plistSize);
    } else {
        neo_aa_header_set_field_blob(header, NEO_AA_FIELD_C("DAT"), sizeof(size_t), plistSize);
    }

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
    NeoAAArchivePlain archive = neo_aa_archive_plain_create_with_items(items, 2);
    neo_aa_archive_item_list_destroy(items, 2);
    if (!archive) {
        fprintf(stderr,"libshortcutsign: failed to create aar header\n");
        return 0;
    }
    size_t aarSize = 0;
    uint8_t *aar = neo_aa_archive_plain_get_encoded_data(archive, &aarSize);
    neo_aa_archive_plain_destroy(archive);
    if (!aar || !aarSize) {
        fprintf(stderr,"libshortcutsign: failed to get encoded aar data\n");
        return 0;
    }
    return sign_shortcut_aar_with_private_key_and_auth_data(aar, aarSize, privateKey, authData, authDataSize, outSize);
}
