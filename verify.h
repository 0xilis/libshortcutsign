/*
 * Snoolie K, (c) 2024-2025.
 * verification libshortcutsign functions
*/

#ifndef libshortcutsign_verify_h
#define libshortcutsign_verify_h

#include <inttypes.h>

int verify_dict_auth_data(uint8_t *authData, size_t authDataSize);
int verify_contact_signed_auth_data(uint8_t *authData, size_t authDataSize);
int verify_contact_signed_shortcut(const char *signedShortcutPath);

/* Types of signed shortcuts */
typedef enum {
    SHORTCUT_UNKNOWN_FORMAT = 0,
    SHORTCUT_UNSIGNED = 1,
    SHORTCUT_SIGNED_CONTACT = 2,
    SHORTCUT_SIGNED_ICLOUD = 3,
} SSFormat;

#endif /* libshortcutsign_verify_h */