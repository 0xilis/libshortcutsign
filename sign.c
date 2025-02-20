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
#include "build/lzfse/include/lzfse.h"

void *hmac_derive(void *hkdf_key, void *data1, size_t data1Len, void *data2, size_t data2Len) {
    unsigned char *hmac = malloc(SHA256_DIGEST_LENGTH);  /* HMAC output size for SHA256 is 32 bytes. */
    size_t len = SHA256_DIGEST_LENGTH;

    /* Fetch the HMAC algorithm */
    EVP_MAC *hmac_type = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!hmac_type) {
        fprintf(stderr, "Failed to fetch HMAC\n");
        return NULL;
    }

    /* Create a MAC context with the HMAC algorithm */
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(hmac_type);
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP_MAC_CTX\n");
        EVP_MAC_free(hmac_type);
        return NULL;
    }

    /* Initialize the MAC context with the key */
    EVP_MAC_init(ctx, hkdf_key, 32, NULL);
    EVP_MAC_update(ctx, data2, data2Len);
    EVP_MAC_update(ctx, data1, data1Len);
    EVP_MAC_final(ctx, hmac, &len, SHA256_DIGEST_LENGTH);

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(hmac_type);

    return hmac;
}

void *hkdf_extract_and_expand(const void *salt, size_t salt_len, const void *key, size_t key_len, size_t output_len) {
    unsigned char *output = malloc(output_len);
    unsigned char prk[SHA256_DIGEST_LENGTH];
    size_t len = SHA256_DIGEST_LENGTH;

    /* Fetch the HMAC algorithm */
    EVP_MAC *hmac_type = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!hmac_type) {
        fprintf(stderr, "Failed to fetch HMAC\n");
        return NULL;
    }

    /* Create a MAC context with the HMAC algorithm */
    EVP_MAC_CTX *context = EVP_MAC_CTX_new(hmac_type);
    if (!context) {
        fprintf(stderr, "Failed to create EVP_MAC_CTX\n");
        EVP_MAC_free(hmac_type);
        return NULL;
    }

    /* Extract phase: HMAC(salt, key) */
    EVP_MAC_init(context, salt, salt_len, NULL);
    EVP_MAC_update(context, key, key_len);
    EVP_MAC_final(context, prk, &len, SHA256_DIGEST_LENGTH);

    EVP_MAC_CTX_free(context);
    EVP_MAC_free(hmac_type);

    /* Expand phase: HMAC(prk, info, 0x01, 0x02, ...) to get multiple keys */
    unsigned char counter = 1;
    size_t pos = 0;
    while (pos < output_len) {
        EVP_MAC_CTX *expand_context = EVP_MAC_CTX_new(hmac_type);
        if (!expand_context) {
            fprintf(stderr, "Failed to create EVP_MAC_CTX\n");
            return NULL;
        }

        EVP_MAC_init(expand_context, prk, SHA256_DIGEST_LENGTH, NULL);
        EVP_MAC_update(expand_context, &counter, 1);
        EVP_MAC_update(expand_context, (unsigned char*)&pos, sizeof(pos));
        EVP_MAC_final(expand_context, output + pos, &len, SHA256_DIGEST_LENGTH);

        EVP_MAC_CTX_free(expand_context);
        pos += len;
        counter++;
    }

    return output;
}

void resign_shortcut_prologue(uint8_t *aeaShortcutArchive, void *privateKey, size_t privateKeyLen) {
    /* Update signature field and delete certain portions of the archive */
    size_t auth_data_size = * (unsigned char *)(aeaShortcutArchive + 0xB); 
    memset(aeaShortcutArchive + auth_data_size + 0xc, 0, 128);  /* Zero out the signature */

    /* Remove all bytes from auth_data_size + 0x13c onwards */
    memset(aeaShortcutArchive + auth_data_size + 0x13c, 0, 1024);

    /* Perform SHA-256 on the modified archive */
    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *sha256_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(sha256_ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(sha256_ctx, aeaShortcutArchive, auth_data_size + 0x13c);
    EVP_DigestFinal_ex(sha256_ctx, sha256_hash, NULL);
    EVP_MD_CTX_free(sha256_ctx);

    /* Parse the raw ASN.1 private key */
    const unsigned char *priv_key_ptr = (unsigned char *)privateKey;
    BIGNUM *priv_key_bn = BN_bin2bn(priv_key_ptr, privateKeyLen, NULL);
    if (!priv_key_bn) {
        fprintf(stderr, "Failed to parse raw ASN.1 private key\n");
        return;
    }

    /* Create an EC_KEY object */
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); // P-256 curve
    if (!ec_key) {
        fprintf(stderr, "Failed to create EC_KEY object: %s\n", ERR_error_string(ERR_get_error(), NULL));
        BN_free(priv_key_bn);
        return;
    }

    /* Set the private key in the EC_KEY object */
    if (!EC_KEY_set_private_key(ec_key, priv_key_bn)) {
        fprintf(stderr, "Failed to set private key in EC_KEY: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EC_KEY_free(ec_key);
        BN_free(priv_key_bn);
        return;
    }

    /* Create a public key from the private key */
    if (!EC_KEY_generate_key(ec_key)) {
        fprintf(stderr, "Failed to generate public key from private key: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EC_KEY_free(ec_key);
        BN_free(priv_key_bn);
        return;
    }

    /* Assign the EC_KEY to an EVP_PKEY */
    EVP_PKEY *private_key = EVP_PKEY_new();
    if (!private_key) {
        fprintf(stderr, "Failed to create EVP_PKEY: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EC_KEY_free(ec_key);
        BN_free(priv_key_bn);
        return;
    }

    if (!EVP_PKEY_assign_EC_KEY(private_key, ec_key)) {
        fprintf(stderr, "Failed to assign EC_KEY to EVP_PKEY: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EC_KEY_free(ec_key);
        EVP_PKEY_free(private_key);
        BN_free(priv_key_bn);
        return;
    }

    /* Sign the hash with the private key using OpenSSL */
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_SignInit(md_ctx, EVP_sha256());
    EVP_SignUpdate(md_ctx, sha256_hash, SHA256_DIGEST_LENGTH);

    unsigned char *signature = malloc(EVP_PKEY_size(private_key));
    unsigned int sig_len;
    EVP_SignFinal(md_ctx, signature, &sig_len, private_key);
    EVP_MD_CTX_free(md_ctx);

    if (sig_len > 128) {
        fprintf(stderr, "sig_len is over 128 bytes, cannot be held in aea\n");
        return;
    }

    /* Overwrite the signature field in the buffer with the new signature */
    memcpy(aeaShortcutArchive + auth_data_size + 0xc, signature, sig_len);

    /* Clean up */
    free(signature);
    EVP_PKEY_free(private_key);
}

void resign_shortcut_with_new_aa(uint8_t *aeaShortcutArchive, void *archivedDir, size_t aeaShortcutArchiveSize, const char *outputPath, void *privateKey) {
    /* TODO: This code is really hard to understand */
    size_t archivedDirSize = aeaShortcutArchiveSize;
    size_t compressed_size = archivedDirSize * 2;
    uint8_t *buffer = malloc(compressed_size);
    compressed_size = lzfse_encode_buffer(buffer, compressed_size, archivedDir, archivedDirSize, NULL);
    free(archivedDir);
    if (!buffer) {
        fprintf(stderr,"libshortcutsign: failed to compress LZFSE\n");
        exit(1);
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
    uint8_t context[0x4c] = {0};
    memcpy(context, "AEA_AMK", 7);
    memcpy(context + 11, privateKey, 0x41); /* Copy public part of private key */

    /* Derive key using OpenSSL HKDF */
    uint8_t *derivedKey = malloc(0x100);
    uint8_t *hkdf_output = hkdf_extract_and_expand(salt, 32, context, sizeof(context), 32);
    if (hkdf_output) {
        memcpy(derivedKey, hkdf_output, 32);
        free(hkdf_output);
    } else {
        fprintf(stderr, "HKDF derivation failed\n");
        exit(1);
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
    uint8_t *aea_ck = hkdf_extract_and_expand(derivedKey, 32, aea_ck_ctx, 10, 32);
    void *aea_sk_ctx = malloc(10);
    memcpy(aea_sk_ctx, "AEA_SK", 6);
    memset(aea_sk_ctx + 6, 0, 4);
    uint8_t *aea_sk = hkdf_extract_and_expand(aea_ck, 32, aea_sk_ctx, 10, 32);
    free(aea_ck_ctx);
    free(aea_sk_ctx);

    /* HMAC derivation for AEA_CK, AEA_SK, etc. */
    uint8_t *hmac = hmac_derive(aea_sk, aeaShortcutArchive + auth_data_size + 0x495c, compressed_size, 0, 0);

    /* Replace old hmac in binary data */
    memcpy(aeaShortcutArchive + auth_data_size + 0x295c, hmac, 0x2000);
    free(hmac);
    free(aea_sk);

    /* Re-hmac for AEA_CHEK */
    uint8_t *aea_chek = hkdf_extract_and_expand(aea_ck, 32, "AEA_CHEK", 8, 32);
    hmac = hmac_derive(aea_chek, aeaShortcutArchive + auth_data_size + 0x13c, 0x2800, aeaShortcutArchive + auth_data_size + 0x293c, 0x2020);
    memcpy(aeaShortcutArchive + auth_data_size + 0x11c, hmac, 32);
    free(hmac);

    /* Re-hmac for AEA_RHEK */
    uint8_t *aea_rhek = hkdf_extract_and_expand(derivedKey, 32, "AEA_RHEK", 8, 32);
    uint8_t *chekPlusAuthData = malloc(auth_data_size + 32);
    memcpy(chekPlusAuthData, aeaShortcutArchive + auth_data_size + 0x11c, 32);
    memcpy(chekPlusAuthData + 32, aeaShortcutArchive + 0xc, auth_data_size);
    hmac = hmac_derive(aea_rhek, aeaShortcutArchive + auth_data_size + 0xec, 0x30, chekPlusAuthData, 0x59f);
    memcpy(aeaShortcutArchive + auth_data_size + 0xcc, hmac, 32);
    free(chekPlusAuthData);
    free(hmac);
    free(aea_rhek);
    resign_shortcut_prologue(aeaShortcutArchive, privateKey, 97);

    /* Write the final resigned archive to output file */
    FILE *fp = fopen(outputPath, "w");
    if (!fp) {
        free(aeaShortcutArchive);
        fprintf(stderr,"libshortcutsign: failed to open destPath\n");
        exit(1);
    }
    fwrite(aeaShortcutArchive, auth_data_size + 0x495c + compressed_size, 1, fp);
    fclose(fp);
    free(aeaShortcutArchive);
}