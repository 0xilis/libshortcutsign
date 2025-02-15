#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

void *hmac_derive(void *hkdf_key, void *data1, size_t data1Len, void *data2, size_t data2Len) {
    unsigned char *hmac = malloc(SHA256_DIGEST_LENGTH);  /* HMAC output size for SHA256 is 32 bytes. */
    unsigned int len = SHA256_DIGEST_LENGTH;

    /* Perform HMAC using SHA256 */
    HMAC_CTX *context = HMAC_CTX_new();
    HMAC_Init_ex(context, hkdf_key, 32, EVP_sha256(), NULL);
    HMAC_Update(context, (unsigned char*)data2, data2Len);
    HMAC_Update(context, (unsigned char*)data1, data1Len);
    HMAC_Update(context, (unsigned char*)&data2Len, sizeof(data2Len));
    HMAC_Final(context, hmac, &len);

    HMAC_CTX_free(context);

    return hmac;
}

void *hkdf_extract_and_expand(const void *salt, size_t salt_len, const void *key, size_t key_len, size_t output_len) {
    unsigned char *output = malloc(output_len);
    unsigned char prk[SHA256_DIGEST_LENGTH];
    unsigned int len = SHA256_DIGEST_LENGTH;

    /* Extract phase: HMAC(salt, key) */
    HMAC_CTX *context = HMAC_CTX_new();
    HMAC_Init_ex(context, salt, salt_len, EVP_sha256(), NULL);
    HMAC_Update(context, (unsigned char*)key, key_len);
    HMAC_Final(context, prk, &len);
    HMAC_CTX_free(context);

    /* Expand phase: HMAC(prk, info, 0x01, 0x02, ...) to get multiple keys */
    unsigned char counter = 1;
    size_t pos = 0;
    while (pos < output_len) {
        HMAC_CTX *expand_context = HMAC_CTX_new();
        HMAC_Init_ex(expand_context, prk, SHA256_DIGEST_LENGTH, EVP_sha256(), NULL);
        HMAC_Update(expand_context, &counter, 1);
        HMAC_Update(expand_context, (unsigned char*)&pos, sizeof(pos));
        HMAC_Final(expand_context, output + pos, &len);
        HMAC_CTX_free(expand_context);
        pos += len;
        counter++;
    }

    return output;
}

void resign_shortcut_prologue(char *aeaShortcutArchive, void *privateKey) {
    /* Update signature field and delete certain portions of the archive */
    size_t auth_data_size = * (unsigned char *)(aeaShortcutArchive + 0xB); 
    memset(aeaShortcutArchive + auth_data_size + 0xc, 0, 256);  /* Zero out the signature */

    // Remove all bytes from auth_data_size + 0x13c onwards
    memset(aeaShortcutArchive + auth_data_size + 0x13c, 0, 1024);

    /* Perform SHA-256 on the modified archive */
    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, aeaShortcutArchive, auth_data_size + 0x13c);
    SHA256_Final(sha256_hash, &sha256_ctx);

    /* Save the hash to a file (resigned_hash.bin) */
    FILE *hash_file = fopen("resigned_hash.bin", "wb");
    fwrite(sha256_hash, sizeof(sha256_hash), 1, hash_file);
    fclose(hash_file);

    /* Sign the hash with the private key using OpenSSL */
    FILE *private_key_file = fopen("ShortcutsSigningPrivateKey.pem", "r");
    EVP_PKEY *private_key = PEM_read_PrivateKey(private_key_file, NULL, NULL, NULL);
    fclose(private_key_file);

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_SignInit(md_ctx, EVP_sha256());
    EVP_SignUpdate(md_ctx, sha256_hash, SHA256_DIGEST_LENGTH);

    unsigned char *signature = malloc(EVP_PKEY_size(private_key));
    unsigned int sig_len;
    EVP_SignFinal(md_ctx, signature, &sig_len, private_key);
    EVP_MD_CTX_free(md_ctx);

    /* Write the signature to a file (resigned_sig.bin) */
    FILE *sig_file = fopen("resigned_sig.bin", "wb");
    fwrite(signature, sig_len, 1, sig_file);
    fclose(sig_file);

    /* Clean up */
    free(signature);
    EVP_PKEY_free(private_key);
}
