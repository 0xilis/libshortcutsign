/*
 * Snoolie K, (c) 2024-2025.
 * extract libshortcutsign functions
*/

#ifndef libshortcutsign_extract_h
#define libshortcutsign_extract_h

#include <inttypes.h>

uint8_t *auth_data_from_shortcut(const char *path, size_t *authDataSize);
uint8_t *auth_data_from_shortcut_buffer(uint8_t *buffer, uint8_t bufferSize, size_t *authDataSize);
int extract_signed_shortcut(const char *signedShortcutPath, const char *destPath);
int extract_contact_signed_shortcut(const char *signedShortcutPath, const char *destPath) __attribute__((deprecated)); /* Use extract_signed_shortcut instead, same functionality */

#endif /* libshortcutsign_extract_h */