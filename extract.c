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
uint8_t *auth_data_from_shortcut(const char *filepath, size_t *bufferSize) {
    /* load shortcut into memory */
    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        fprintf(stderr,"libshortcutsign: failed to open file\n");
        return 0;
    }
    fseek(fp, 0, SEEK_END);
    size_t size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *archive = malloc(size * sizeof(char));
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
    memset(archive, 0, size * sizeof(char));
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
    size_t archive_size = n;
    fclose(fp);
    /* find the size of AEA_CONTEXT_FIELD_AUTH_DATA field blob */
    /* We assume it's located at 0x8-0xB */
    register const char *sptr = archive + 0xB;
    size_t buf_size = *sptr << 24;
    buf_size += *(sptr - 1) << 16;
    buf_size += *(sptr - 2) << 8;
    buf_size += *(sptr - 3);
    if (buf_size > archive_size-0x293c) {
     /* 
      * The encrypted data for for signed shortcuts, both contact signed
      * and icloud signed, should be at buf_size+0x293c. If our buf_size
      * reaches to or past the encrypted data, then it's too big.
     */
     fprintf(stderr,"libshortcutsign: buf_size reaches past data start\n");
     return 0;
    }
    /* we got buf_size, now fill buffer */
    uint8_t *buffer = (uint8_t *)malloc(buf_size);
    memset(buffer, 0, buf_size);
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
    unsigned int i = buf_size;
    fill_buffer:
    i--;
    buffer[i] = archive[i+0xc];
    if (i != 0) {goto fill_buffer;};
    free(archive);
    /* save bufferSize if it was specified */
    if (bufferSize) {
        *bufferSize = buf_size;
    }
    return buffer;
}

int unwrap_file_out_of_neo_aa(uint8_t *inputBuffer, const char *outputPath, char *pathString, size_t bufferSize) {
    NeoAAArchivePlain archive = neo_aa_archive_plain_create_with_encoded_data(bufferSize, inputBuffer);
    if (!archive) {
        fprintf(stderr,"Not enough free memory to allocate archive\n");
        return -1;
    }
    for (int i = 0; i < archive->itemCount; i++) {
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
            return 0;
        }
        free(patStr);
    }
    printf("Could not find file at the specified path in the project.\n");
    return -1;
}

/*
 * extract_aa_from_aea
 *
 * Extracts the AA Archive from a signed shortcut AEA.
 * Only meant for internal use. Don't call this yourself!
 */
uint8_t *extract_aa_from_aea(uint8_t *encodedAppleArchive, size_t encodedAEASize, unsigned long offset, size_t *aaSize) {
    uint8_t *aaLZFSEPtr = encodedAppleArchive + offset;
    size_t decode_size = 0x100000; /* Assume AA Archive is 1MB or less */
    uint8_t *buffer = malloc(decode_size);
    *aaSize = lzfse_decode_buffer(buffer, decode_size, aaLZFSEPtr, encodedAEASize, 0);
    if (!buffer) {
        fprintf(stderr,"libshortcutsign: failed to decompress LZFSE\n");
        return 0;
    }
    return buffer;
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
    size_t binary_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *aeaShortcutArchive = malloc(binary_size * sizeof(char));
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
    memset(aeaShortcutArchive, 0, binary_size * sizeof(char));
    /* copy bytes to binary, byte by byte... */
    int c;
    size_t n = 0;
    while ((c = fgetc(fp)) != EOF) {
        if (n > binary_size) {
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
    /* find the size of AEA_CONTEXT_FIELD_AUTH_DATA field blob */
    /* We assume it's located at 0x8-0xB */
    register const char *sptr = aeaShortcutArchive + 0xB;
    size_t buf_size = *sptr << 24;
    buf_size += *(sptr - 1) << 16;
    buf_size += *(sptr - 2) << 8;
    buf_size += *(sptr - 3);
    if (buf_size > binary_size-0x495c) {
        /*
         * The encrypted data for for signed shortcuts, both contact signed
         * and icloud signed, should be at buf_size+0x495c. If our buf_size
         * reaches to or past the encrypted data, then it's too big.
         */
        fprintf(stderr,"libshortcutsign: buf_size reaches past data start\n");
        return -1;
    }
    /* Decompress the LZFSE-compressed data */
    size_t aaSize;
    uint8_t *aaRawArchive = extract_aa_from_aea((uint8_t *)aeaShortcutArchive, binary_size, buf_size + 0x495c, &aaSize);
    free(aeaShortcutArchive);
    if (!aaRawArchive) {
        return -1;
    }
    
    /* Unwrap Shortcut.wflow from Apple Archive into destPath */
    
    if (unwrap_file_out_of_neo_aa(aaRawArchive, destPath, "Shortcut.wflow", aaSize)) {
        fprintf(stderr, "libshortcutsign: failed to unwrap Shortcut.wflow\n");
        return -1;
    }
    free(aaRawArchive);
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
int extract_contact_signed_shortcut(const char *signedShortcutPath, const char *destPath) {
    return extract_signed_shortcut(signedShortcutPath, destPath);
}