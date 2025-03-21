#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libshortcutsign.h>

__attribute__((visibility ("hidden"))) static const char* ssFormatToString(SSFormat format) {
    switch (format) {
        case SHORTCUT_UNKNOWN_FORMAT: return "SHORTCUT_UNKNOWN_FORMAT";
        case SHORTCUT_UNSIGNED: return "SHORTCUT_UNSIGNED";
        case SHORTCUT_SIGNED_CONTACT: return "SHORTCUT_SIGNED_CONTACT";
        case SHORTCUT_SIGNED_ICLOUD: return "SHORTCUT_SIGNED_ICLOUD";
        default: return "BAD_SSFORMAT";
    }
}

__attribute__((visibility ("hidden"))) static uint8_t *load_binary(const char *signedShortcutPath, size_t *binarySize) {
    /* load AEA archive into memory */
    FILE *fp = fopen(signedShortcutPath,"rb");
    if (!fp) {
        fprintf(stderr,"shortcut-sign: load_binary could not open path\n");
        return 0;
    }
    fseek(fp, 0, SEEK_END);
    size_t _binarySize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    uint8_t *aeaShortcutArchive = malloc(_binarySize);
    size_t n = fread(aeaShortcutArchive, 1, _binarySize, fp);
    fclose(fp);
    if (n != _binarySize) {
        fprintf(stderr,"shortcut-sign: load_binary could not read entire file\n");
        free(aeaShortcutArchive);
        return 0;
    }
    if (_binarySize) {
        *binarySize = _binarySize;
    }
    return aeaShortcutArchive;
}

int main(void) {
    printf("Starting tests...\n");
    size_t shortcutSize = 0;
    uint8_t *shortcut = load_binary("verificationTest.shortcut", &shortcutSize);
    if (!shortcut) {
        fprintf(stderr,"verificationTest.shortcut could not be loaded\n");
        return -1;
    }
    SSFormat verificationTestType = get_shortcut_format(shortcut, shortcutSize);
    if (verificationTestType != SHORTCUT_SIGNED_CONTACT) {
        fprintf(stderr,"verificationTest.shortcut failed get_shortcut_format: returned %s\n", ssFormatToString(verificationTestType));
        return -1;
    }
    if (verify_signed_shortcut_buffer(shortcut, shortcutSize)) {
        fprintf(stderr,"verificationTest.shortcut failed verify_signed_shortcut_buffer\n");
        return -1;
    }
    /* Load the not-so-private key to make sure that verification fails... */
    size_t keySize = 0;
    uint8_t *privateKey = load_binary("libshortcutsignPrivateKeyTestSubject.dat", &keySize);
    if (!privateKey) {
        fprintf(stderr,"libshortcutsignPrivateKeyTestSubject.dat could not be loaded\n");
        return -1;
    }
    if (resign_shortcut_prologue(shortcut, privateKey, keySize)) {
        fprintf(stderr,"verificationTest.shortcut failed resign_shortcut_prologue\n");
        return -1;
    }
    free(privateKey);
    if (!verify_signed_shortcut_buffer(shortcut, shortcutSize)) {
        fprintf(stderr,"verificationTest.shortcut failed verify_signed_shortcut_buffer test 2: was meant to fail, but verification returned yes\n");
        return -1;
    }
    /* Even after we resigned prologue so verification fails, auth data should still be valid */
    size_t authDataSize;
    uint8_t *authData = auth_data_from_shortcut_buffer(shortcut, shortcutSize, &authDataSize);
    if (!authData) {
        fprintf(stderr,"authData could not be loaded from verificationTest.shortcut\n");
        return -1;
    }
    free(shortcut);
    if (verify_dict_auth_data(authData, authDataSize)) {
        fprintf(stderr,"verificationTest.shortcut failed verify_dict_auth_data\n");
        return -1;
    }
    /* In the future, program extract_signed_shortcut tests, and check hash to ensure match */
    printf("Tests successful\n");
    return 0;
}