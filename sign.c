#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>

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

void resign_shortcut_prologue(char *aeaShortcutArchive, void *privateKey, size_t privateKeyLen) {
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

    /* Convert the raw private key to an EVP_PKEY */
    const unsigned char *priv_key_ptr = (unsigned char *)privateKey;
    EVP_PKEY *private_key = NULL;
    EC_KEY *ec_key = d2i_ECPrivateKey(NULL, &priv_key_ptr, privateKeyLen);
    if (!ec_key) {
        fprintf(stderr, "Failed to load EC private key from buffer\n");
        return;
    }

    private_key = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(private_key, ec_key);  /* Assign the EC key to the EVP_PKEY structure */

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