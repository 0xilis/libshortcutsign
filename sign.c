#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/kdf.h>
#include "build/lzfse/include/lzfse.h"

void *hmac_derive(void *hkdf_key, void *data1, size_t data1Len, void *data2, size_t data2Len) {
    unsigned char *hmac = malloc(SHA256_DIGEST_LENGTH);
    HMAC_CTX *ctx = HMAC_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create HMAC context\n");
        return NULL;
    }

    /* Initialize HMAC with SHA-256 */
    if (!HMAC_Init_ex(ctx, hkdf_key, 32, EVP_sha256(), NULL)) {
        fprintf(stderr, "Failed to initialize HMAC\n");
        HMAC_CTX_free(ctx);
        return NULL;
    }

    /* Update HMAC with data */
    if (data2 && data2Len > 0) {
        HMAC_Update(ctx, data2, data2Len);
    }
    if (data1 && data1Len > 0) {
        HMAC_Update(ctx, data1, data1Len);
    }
    HMAC_Update(ctx, (const unsigned char *)&data2Len, 8);

    /* Finalize HMAC */
    unsigned int len = SHA256_DIGEST_LENGTH;
    HMAC_Final(ctx, hmac, &len);
    HMAC_CTX_free(ctx);

    return hmac;
}

void *do_hkdf(const void *context, size_t contextLen, const void *key) {
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
int hkdf_extract_and_expand_helper(const uint8_t *salt, size_t salt_len,
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

int resign_shortcut_prologue(uint8_t *aeaShortcutArchive, void *privateKey, size_t privateKeyLen) {
    /* TODO: Don't just support X9.63 keys, also support PEM encoded */
    /* i cannot get this to work from uint32_t pointer so just do byte by byte */
    uint8_t *sptr = aeaShortcutArchive + 0xB;
    size_t auth_data_size = 0;
    auth_data_size |= *(sptr) << 24;
    auth_data_size |= *(sptr - 1) << 16;
    auth_data_size |= *(sptr - 2) << 8;
    auth_data_size |= *(sptr - 3);

    /* zero out the sig for the hash */
    memset(aeaShortcutArchive + auth_data_size + 0xc, 0, 128);  /* Zero out the signature field */

    /* parse the X9.63 ECDSA-P256 key */
    const unsigned char *priv_key_ptr = (unsigned char *)privateKey;
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

    /* create an EC_KEY object for the secp256r1 curve */
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key) {
        fprintf(stderr, "shortcut-sign: failed to create EC_KEY object\n");
        BN_free(priv_key_bn);
        return -1;
    }

    /* set the public key in the EC_KEY object */
    if (!EC_KEY_set_private_key(ec_key, pub_key_bn)) {
        fprintf(stderr, "shortcut-sign: failed to set public key in EC_KEY\n");
        BN_free(priv_key_bn);
        EC_KEY_free(ec_key);
        return -1;
    }

    /* set the private key in the EC_KEY object */
    if (!EC_KEY_set_private_key(ec_key, priv_key_bn)) {
        fprintf(stderr, "shortcut-sign: failed to set private key in EC_KEY\n");
        BN_free(priv_key_bn);
        EC_KEY_free(ec_key);
        return -1;
    }

    /* assign the EC_KEY to an EVP_PKEY object */
    EVP_PKEY *private_key = EVP_PKEY_new();
    if (!private_key) {
        fprintf(stderr, "shortcut-sign: failed to create EVP_PKEY object\n");
        BN_free(priv_key_bn);
        EC_KEY_free(ec_key);
        return -1;
    }

    if (!EVP_PKEY_assign_EC_KEY(private_key, ec_key)) {
        fprintf(stderr, "shortcut-sign: failed to assign EC_KEY to EVP_PKEY\n");
        BN_free(priv_key_bn);
        EC_KEY_free(ec_key);
        EVP_PKEY_free(private_key);
        return -1;
    }

    /* sign the sha256 hash */
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        fprintf(stderr, "shortcut-sign: failed to create EVP_MD_CTX_new\n");
        EVP_PKEY_free(private_key);
        return -1;
    }

    if (EVP_SignInit(md_ctx, EVP_sha256()) != 1) {
        fprintf(stderr, "shortcut-sign: EVP_SignInit failed\n");
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(private_key);
        return -1;
    }

    if (EVP_SignUpdate(md_ctx, aeaShortcutArchive, auth_data_size + 0x13c) != 1) {
        fprintf(stderr, "shortcut-sign: EVP_SignUpdate failed\n");
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(private_key);
        return -1;
    }

    unsigned char *signature = malloc(EVP_PKEY_size(private_key));
    if (!signature) {
        fprintf(stderr, "shortcut-sign: not enough memory\n");
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(private_key);
        return -1;
    }

    unsigned int sig_len;
    if (EVP_SignFinal(md_ctx, signature, &sig_len, private_key) != 1) {
        fprintf(stderr, "shortcut-sign: failed to sign the hash\n");
        ERR_print_errors_fp(stderr);
        free(signature);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(private_key);
        return -1;
    }
    EVP_MD_CTX_free(md_ctx);

    /* there is no chance of this happening but im paranoid */
    if (sig_len > 128) {
        fprintf(stderr, "shortcut-sign: sig_len exceeds 128 bytes\n");
        free(signature);
        EVP_PKEY_free(private_key);
        return -1;
    }

    /* overwrite the signature field in the archive with the new signature */
    memcpy(aeaShortcutArchive + auth_data_size + 0xc, signature, sig_len);

    /* clean up */
    free(signature);
    EVP_PKEY_free(private_key);
    return 0;
}

int resign_shortcut_with_new_aa(uint8_t *aeaShortcutArchive, void *archivedDir, size_t aeaShortcutArchiveSize, const char *outputPath, void *privateKey) {
    /* TODO: This code is really hard to understand */
    size_t archivedDirSize = aeaShortcutArchiveSize;
    size_t compressed_size = archivedDirSize * 2;
    uint8_t *buffer = malloc(compressed_size);
    compressed_size = lzfse_encode_buffer(buffer, compressed_size, archivedDir, archivedDirSize, NULL);
    free(archivedDir);
    if (!buffer) {
        fprintf(stderr,"libshortcutsign: failed to compress LZFSE\n");
        return -1;
    }

    /* Extract auth_data_size from aeaShortcutArchive */
    register const uint8_t *sptr = (const uint8_t *)(aeaShortcutArchive + 0xB);
    size_t auth_data_size = *sptr << 24;
    auth_data_size += *(sptr - 1) << 16;
    auth_data_size += *(sptr - 2) << 8;
    auth_data_size += *(sptr - 3);

    /* Fix auth_data_size + offsets */
    memcpy(aeaShortcutArchive + auth_data_size + 0xec, &archivedDirSize, 4);
    memcpy(aeaShortcutArchive + auth_data_size + 0x13c, &archivedDirSize, 4);

    /* Set compressed LZFSE data */
    aeaShortcutArchive = realloc(aeaShortcutArchive, auth_data_size + 0x495c + compressed_size);
    memcpy(aeaShortcutArchive + auth_data_size + 0x495c, buffer, compressed_size);
    free(buffer);

    /* Prepare HKDF context */
    const uint8_t *salt = (uint8_t *)(aeaShortcutArchive + auth_data_size + 0xac);
    const uint8_t *keyDerivationKey = (uint8_t *)(aeaShortcutArchive + auth_data_size + 0x8c); // 32-byte key
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
    memcpy(aeaShortcutArchive + auth_data_size + 0x13c + 4, &compressed_size, 4);
    size_t resigned_shortcut_size = auth_data_size + 0x495c + compressed_size;
    memcpy(aeaShortcutArchive + auth_data_size + 0xec + 8, &resigned_shortcut_size, 4);

    /* Derive more keys using HKDF (AEA_CK, AEA_SK, etc.) */
    void *aea_ck_ctx = malloc(10);
    memcpy(aea_ck_ctx, "AEA_CK", 6);
    memset(aea_ck_ctx + 6, 0, 4);
    uint8_t *aea_ck = do_hkdf(aea_ck_ctx, 10, derivedKey);
    void *aea_sk_ctx = malloc(10);
    memcpy(aea_sk_ctx, "AEA_SK", 6);
    memset(aea_sk_ctx + 6, 0, 4);
    uint8_t *aea_sk = do_hkdf(aea_sk_ctx, 10, aea_ck);
    free(aea_ck_ctx);
    free(aea_sk_ctx);

    /* HMAC derivation for AEA_CK, AEA_SK, etc. */
    uint8_t *hmac = hmac_derive(aea_sk, aeaShortcutArchive + auth_data_size + 0x495c, compressed_size, 0, 0);

    /* Replace old hmac in binary data */
    memcpy(aeaShortcutArchive + auth_data_size + 0x295c, hmac, 32);
    free(hmac);
    free(aea_sk);

    /* Re-hmac for AEA_CHEK */
    uint8_t *aea_chek = do_hkdf("AEA_CHEK", 8, aea_ck);
    hmac = hmac_derive(aea_chek, aeaShortcutArchive + auth_data_size + 0x13c, 0x2800, aeaShortcutArchive + auth_data_size + 0x293c, 0x2020);
    memcpy(aeaShortcutArchive + auth_data_size + 0x11c, hmac, 32);
    free(hmac);

    /* Re-hmac for AEA_RHEK */
    uint8_t *aea_rhek = do_hkdf("AEA_RHEK", 8, derivedKey);
    uint8_t *chekPlusAuthData = malloc(auth_data_size + 32);
    memcpy(chekPlusAuthData, aeaShortcutArchive + auth_data_size + 0x11c, 32);
    memcpy(chekPlusAuthData + 32, aeaShortcutArchive + 0xc, auth_data_size);
    hmac = hmac_derive(aea_rhek, aeaShortcutArchive + auth_data_size + 0xec, 0x30, chekPlusAuthData, auth_data_size + 0x20);
    memcpy(aeaShortcutArchive + auth_data_size + 0xcc, hmac, 32);
    free(chekPlusAuthData);
    free(hmac);
    free(aea_rhek);
    if (resign_shortcut_prologue(aeaShortcutArchive, privateKey, 97)) {
        free(aeaShortcutArchive);
        fprintf(stderr,"libshortcutsign: failed to resign prologue\n");
        return -1;
    }

    /* Write the final resigned archive to output file */
    FILE *fp = fopen(outputPath, "w");
    if (!fp) {
        free(aeaShortcutArchive);
        fprintf(stderr,"libshortcutsign: failed to open destPath\n");
        return -1;
    }
    fwrite(aeaShortcutArchive, auth_data_size + 0x495c + compressed_size, 1, fp);
    fclose(fp);
    free(aeaShortcutArchive);
    return 0;
}