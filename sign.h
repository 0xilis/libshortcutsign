/*
 * Snoolie K, (c) 2025.
 * extract libshortcutsign functions
*/

#ifndef libshortcutsign_sign_h
#define libshortcutsign_sign_h

#include <inttypes.h>

int resign_shortcut_prologue(uint8_t *signedShortcut, void *privateKey, size_t privateKeyLen);
int resign_shortcut_with_new_aa(uint8_t **signedShortcut, void *archivedDir, size_t archivedDirSize, size_t *newSize, void *privateKey);
int resign_shortcut_with_new_plist(uint8_t **signedShortcut, void *plist, size_t plistSize, size_t *newSize, void *privateKey);
uint8_t *sign_shortcut_aar_with_private_key_and_auth_data(void *aar, size_t aarSize, void *privateKey, uint8_t *authData, size_t authDataSize, size_t *outSize);
uint8_t *sign_shortcut_with_private_key_and_auth_data(void *plist, size_t plistSize, void *privateKey, uint8_t *authData, size_t authDataSize, size_t *outSize);

#endif /* libshortcutsign_sign_h */
