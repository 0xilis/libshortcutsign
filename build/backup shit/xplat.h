/*
 * Snoolie K, (c) 2024-2025.
 * cross compat libshortcutsign functions
*/

#ifndef libshortcutsign_xplat_h
#define libshortcutsign_xplat_h

NSData *auth_data_from_shortcut(const char *filepath);
int extract_contact_signed_shortcut(const char *signedShortcutPath, const char *destPath);

#endif /* libshortcutsign_xplat_h */