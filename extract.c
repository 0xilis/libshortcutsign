#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "libs/libNeoAppleArchive/libNeoAppleArchive/libNeoAppleArchive.h"

#include "build/lzfse/include/lzfse.h"

/* 
 * auth_data_from_shortcut
 *
 * Retrieves the auth data from a signed shortcut.
 *
 * This is xplat, meaning it works on macOS+Linux!
 *
 * If it fails to get auth data, it will return 0/nil.
*/
uint8_t *auth_data_from_shortcut(const char *path, size_t *authDataSize) {
    /* load shortcut into memory */
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr,"libshortcutsign: failed to open file\n");
        return 0;
    }
    fseek(fp, 0, SEEK_END);
    size_t size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *archive = malloc(size);
    /*
     * Explained better in comment below, but
     * a process may write to a file while
     * this is going on so size would be
     * bigger than the bytes we copy,
     * making it hit EOF before size
     * is hit. This means that potentially
     * other memory from the process may
     * be kept here. To prevent this,
     * we 0 out our buffer to make sure
     * it doesn't contain any leftover memory
     * left.
     */
    memset(archive, 0, size);
    /* copy bytes to binary */
    int c;
    size_t n = 0;
    while ((c = fgetc(fp)) != EOF) {
        if (n > size) {
            /*
             * If, at any point, a file is modified during / before copy,
             * ex it has a really small size, but another process
             * quickly modifies it after binary_size is saved but
             * before / during the bytes are copied to the buffer,
             * then it would go past the buffer, resulting
             * in a heap overflow from our race. Fixing this
             * problem by checking if n ever reaches past
             * the initial binary_size...
             */
            free(archive);
            fclose(fp);
            fprintf(stderr,"libshortcutsign: reached past binarySize\n");
            return 0;
        }
        archive[n++] = (char) c;
    }
    size_t archiveSize = n;
    fclose(fp);
    /* find the size of AEA_CONTEXT_FIELD_AUTH_DATA field blob */
    /* We assume it's located at 0x8-0xB */
    register const char *sptr = archive + 0xB;
    size_t authDataSizeLocal = *sptr << 24;
    authDataSizeLocal += *(sptr - 1) << 16;
    authDataSizeLocal += *(sptr - 2) << 8;
    authDataSizeLocal += *(sptr - 3);
    if (authDataSizeLocal > archiveSize-0x293c) {
        /* 
         * The encrypted data for for signed shortcuts, both contact signed
         * and icloud signed, should be at authDataSize+0x293c. If our authDataSize
         * reaches to or past the encrypted data, then it's too big.
        */
        fprintf(stderr,"libshortcutsign: authDataSizeLocal reaches past data start\n");
        return 0;
    }
    /* we got authDataSizeLocal, now fill buffer */
    uint8_t *authData = (uint8_t *)malloc(authDataSizeLocal);
    /*
     * the reason why we are doing a reverse
     * iteration is because doing it this way
     * will allow arm devices to take advantage
     * of the cbnz instruction, which should
     * mean about a 2 cycle save per iteration.
     *
     * also we're going to blindly trust that authDataSize
     * is not larger than the buffer, because unless
     * you malform a aea file it should never be.
    */
    unsigned int i = authDataSizeLocal;
    fill_buffer:
    i--;
    authData[i] = archive[i+0xc];
    if (i != 0) {goto fill_buffer;};
    free(archive);
    /* save bufferSize if it was specified */
    if (authDataSize) {
        *authDataSize = authDataSizeLocal;
    }
    return authData;
}
uint8_t *auth_data_from_shortcut_buffer(uint8_t *buffer, uint8_t bufferSize, size_t *authDataSize) {
    char *archive = (char *)buffer;
    size_t archiveSize = bufferSize;
    /* find the size of AEA_CONTEXT_FIELD_AUTH_DATA field blob */
    /* We assume it's located at 0x8-0xB */
    register const char *sptr = archive + 0xB;
    size_t _authDataSize = *sptr << 24;
    _authDataSize += *(sptr - 1) << 16;
    _authDataSize += *(sptr - 2) << 8;
    _authDataSize += *(sptr - 3);
    if (_authDataSize > archiveSize-0x293c) {
        /* 
         * The encrypted data for for signed shortcuts, both contact signed
         * and icloud signed, should be at authDataSize+0x293c. If our authDataSize
         * reaches to or past the encrypted data, then it's too big.
        */
        fprintf(stderr,"libshortcutsign: authDataSize reaches past data start\n");
        return 0;
    }
    /* we got authDataSize, now fill buffer */
    uint8_t *authData = (uint8_t *)malloc(_authDataSize);
    /*
     * the reason why we are doing a reverse
     * iteration is because doing it this way
     * will allow arm devices to take advantage
     * of the cbnz instruction, which should
     * mean about a 2 cycle save per iteration.
     *
     * also we're going to blindly trust that buf_size
     * is not larger than the buffer, because unless
     * you malform a aea file it should never be.
    */
    unsigned int i = _authDataSize;
    fill_buffer:
    i--;
    authData[i] = archive[i+0xc];
    if (i != 0) {goto fill_buffer;};
    free(archive);
    /* save bufferSize if it was specified */
    if (authDataSize) {
        *authDataSize = _authDataSize;
    }
    return authData;
}

__attribute__((visibility ("hidden"))) static int unwrap_file_out_of_neo_aa(uint8_t *inputBuffer, const char *outputPath, char *pathString, size_t bufferSize) {
    NeoAAArchivePlain archive = neo_aa_archive_plain_create_with_encoded_data(bufferSize, inputBuffer);
    if (!archive) {
        fprintf(stderr,"Not enough free memory to allocate archive\n");
        return -1;
    }
    unsigned int i = 0;
    for (i = 0; i < (unsigned int)archive->itemCount; i++) {
        /*
         * We loop through all items to find the PAT field key.
         * The PAT field key will be what path the item is in the
         * archive. This also includes symlinks.
         */
        NeoAAArchiveItem item = archive->items[i];
        NeoAAHeader header = item->header;
        int index = neo_aa_header_get_field_key_index(header, NEO_AA_FIELD_C("PAT"));
        if (index == -1) {
            continue;
        }
        /* If index is not -1, then header has PAT field key */
        char *patStr = neo_aa_header_get_field_key_string(header, index);
        if (!patStr) {
            printf("Could not get PAT entry in header\n");
            continue;
        }
        if (strncmp(pathString,patStr,strlen(pathString)) == 0) {
            free(patStr);
            /* Unwrap file */
            FILE *fp = fopen(outputPath, "w");
            if (!fp) {
                fprintf(stderr,"Failed to open outputPath.\n");
                return -1;
            }
            fwrite(item->encodedBlobData, item->encodedBlobDataSize, 1, fp);
            fclose(fp);
            neo_aa_archive_plain_destroy_nozero(archive);
            return 0;
        }
        free(patStr);
    }
    printf("Could not find file at the specified path in the project.\n");
    return -1;
}

__attribute__((visibility ("hidden"))) static uint8_t *unwrap_file_out_of_neo_aa_buffer(uint8_t *inputBuffer, char *pathString, size_t bufferSize, size_t *outBufferSize) {
    NeoAAArchivePlain archive = neo_aa_archive_plain_create_with_encoded_data(bufferSize, inputBuffer);
    if (!archive) {
        fprintf(stderr,"Not enough free memory to allocate archive\n");
        return 0;
    }
    unsigned int i = 0;
    for (i = 0; i < (unsigned int)archive->itemCount; i++) {
        /*
         * We loop through all items to find the PAT field key.
         * The PAT field key will be what path the item is in the
         * archive. This also includes symlinks.
         */
        NeoAAArchiveItem item = archive->items[i];
        NeoAAHeader header = item->header;
        int index = neo_aa_header_get_field_key_index(header, NEO_AA_FIELD_C("PAT"));
        if (index == -1) {
            continue;
        }
        /* If index is not -1, then header has PAT field key */
        char *patStr = neo_aa_header_get_field_key_string(header, index);
        if (!patStr) {
            printf("Could not get PAT entry in header\n");
            continue;
        }
        if (strncmp(pathString,patStr,strlen(pathString)) == 0) {
            free(patStr);
            /* Unwrap file */
            uint8_t *buffer = malloc(item->encodedBlobDataSize);
            memcpy(buffer, item->encodedBlobData, item->encodedBlobDataSize);
            if (outBufferSize) {
                *outBufferSize = item->encodedBlobDataSize;
            }
            neo_aa_archive_plain_destroy_nozero(archive);
            return buffer;
        }
        free(patStr);
    }
    printf("Could not find file at the specified path in the project.\n");
    return 0;
}

/*
 * extract_signed_shortcut
 *
 * Extracts the unsigned shortcut from the signed shortcut.
 * AEA-less! Use on non-Apple platforms :).
 */
int extract_signed_shortcut(const char *signedShortcutPath, const char *destPath) {
    /* load AEA archive into memory */
    FILE *fp = fopen(signedShortcutPath,"r");
    if (!fp) {
        fprintf(stderr,"libshortcutsign: extract_signed_shortcut failed to find path\n");
        return -1;
    }
    fseek(fp, 0, SEEK_END);
    size_t binarySize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    uint8_t *aeaShortcutArchive = malloc(binarySize);
    /*
     * Explained better in comment below, but
     * a process may write to a file while
     * this is going on so binary_size would be
     * bigger than the bytes we copy,
     * making it hit EOF before binary_size
     * is hit. This means that potentially
     * other memory from the process may
     * be kept here. To prevent this,
     * we 0 out our buffer to make sure
     * it doesn't contain any leftover memory
     * left.
     */
    memset(aeaShortcutArchive, 0, binarySize);
    /* copy bytes to binary, byte by byte... */
    int c;
    size_t n = 0;
    while ((c = fgetc(fp)) != EOF) {
        if (n > binarySize) {
            /*
             * If, at any point, a file is modified during / before copy,
             * ex it has a really small size, but another process
             * quickly modifies it after binary_size is saved but
             * before / during the bytes are copied to the buffer,
             * then it would go past the buffer, resulting
             * in a heap overflow from our race. Fixing this
             * problem by checking if n ever reaches past
             * the initial binary_size...
             */
            free(aeaShortcutArchive);
            fclose(fp);
            fprintf(stderr,"libshortcutsign: extract_signed_shortcut reached past binarySize\n");
            return -1;
        }
        aeaShortcutArchive[n++] = (char) c;
    }
    fclose(fp);
    /* Extract aar from aea using libNeoAppleArchive */
    NeoAEAArchive aea = neo_aea_archive_with_encoded_data_nocopy(aeaShortcutArchive, binarySize);
    if (!aea) {
        fprintf(stderr, "libshortcutsign: failed to allocate AEA\n");
        return -1;
    }
    size_t aarSize;
    uint8_t *aar = neo_aea_archive_extract_data(aea, &aarSize, 0, 0, 0, 0, 0, 0);
    if (!aar) {
        fprintf(stderr, "libshortcutsign: failed to extract aar from aea\n");
        return -1;
    }
    neo_aea_archive_destroy(aea);
    
    /* Unwrap Shortcut.wflow from Apple Archive into destPath */
    
    if (unwrap_file_out_of_neo_aa(aar, destPath, "Shortcut.wflow", aarSize)) {
        fprintf(stderr, "libshortcutsign: failed to unwrap Shortcut.wflow\n");
        return -1;
    }
    free(aar);
    return 0;
}

/*
 * extract_contact_signed_shortcut
 *
 * Extracts/Decrypts the unsigned shortcut from a contact signed shortcut
 *
 * Nowadays just a wrapper around the modern better xplat extract_signed_shortcut.
 *
 * If the function was successful, it will return 0.
 * If not, it will return a negative error code.
*/
int __attribute__((deprecated)) extract_contact_signed_shortcut(const char *signedShortcutPath, const char *destPath) {
    return extract_signed_shortcut(signedShortcutPath, destPath);
}

uint8_t *extract_signed_shortcut_buffer(uint8_t *signedShortcut, size_t signedShortcutSize, size_t *unsignedShortcutSize) {
    /* Extract aar from aea using libNeoAppleArchive */
    NeoAEAArchive aea = neo_aea_archive_with_encoded_data_nocopy(signedShortcut, signedShortcutSize);
    if (!aea) {
        fprintf(stderr, "libshortcutsign: failed to allocate AEA\n");
        return 0;
    }
    size_t aarSize;
    uint8_t *aar = neo_aea_archive_extract_data(aea, &aarSize, 0, 0, 0, 0, 0, 0);
    if (!aar) {
        fprintf(stderr, "libshortcutsign: failed to extract aar from aea\n");
        return 0;
    }
    free(aea);
    
    /* Unwrap Shortcut.wflow from Apple Archive into buffer */
    
    uint8_t *unsignedShortcut = unwrap_file_out_of_neo_aa_buffer(aar, "Shortcut.wflow", aarSize, unsignedShortcutSize);
    free(aar);
    return unsignedShortcut;
}

uint8_t *extract_signed_shortcut_buffer_aar(uint8_t *signedShortcut, size_t signedShortcutSize, size_t *aarSize) {
    /* Extract aar from aea using libNeoAppleArchive */
    NeoAEAArchive aea = neo_aea_archive_with_encoded_data_nocopy(signedShortcut, signedShortcutSize);
    if (!aea) {
        fprintf(stderr, "libshortcutsign: failed to allocate AEA\n");
        return 0;
    }
    uint8_t *aar = neo_aea_archive_extract_data(aea, aarSize, 0, 0, 0, 0, 0, 0);
    if (!aar) {
        fprintf(stderr, "libshortcutsign: failed to extract aar from aea\n");
        return 0;
    }
    free(aea);
    return aar;
}
