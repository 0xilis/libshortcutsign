/*
 * Snoolie K, (c) 2024-2025.
 * verification libshortcutsign functions
*/

#ifndef libshortcutsign_verify_h
#define libshortcutsign_verify_h

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

int verify_dict_auth_data(uint8_t *authData, size_t authDataSize);
int __attribute__((deprecated)) verify_contact_signed_auth_data(uint8_t *authData, size_t authDataSize); /* Use verify_dict_auth_data instead */
int __attribute__((deprecated)) verify_contact_signed_shortcut(const char *signedShortcutPath); /* Use verify_signed_shortcut instead */
int verify_signed_shortcut(const char *signedShortcutPath);
int verify_signed_shortcut_buffer(uint8_t *buffer, size_t bufferSize);

/* Types of signed shortcuts */
typedef enum {
    SHORTCUT_UNKNOWN_FORMAT = 0,
    SHORTCUT_UNSIGNED = 1,
    SHORTCUT_SIGNED_CONTACT = 2,
    SHORTCUT_SIGNED_ICLOUD = 3,
} SSFormat;

SSFormat get_shortcut_format(uint8_t *buffer, size_t bufferSize);
void print_shortcut_cert_info(uint8_t *buffer, size_t bufferSize);

#ifdef __cplusplus
}
#endif

#endif /* libshortcutsign_verify_h */
