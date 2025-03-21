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
    /* In the future, call resign_shortcut_prologue to purposely mess up signature,
     * then call verify_signed_shortcut_buffer to further test verification
     */
    free(shortcut);
    
    return 0;
}