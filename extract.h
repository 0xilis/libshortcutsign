/*
 * Snoolie K, (c) 2024-2025.
 * cross compat libshortcutsign functions
*/

#ifndef libshortcutsign_xplat_h
#define libshortcutsign_xplat_h

#include <inttypes.h>

uint8_t *auth_data_from_shortcut(const char *filepath, size_t *bufferSize);
int extract_signed_shortcut(const char *signedShortcutPath, const char *destPath);
int extract_contact_signed_shortcut(const char *signedShortcutPath, const char *destPath);

#endif /* libshortcutsign_xplat_h */