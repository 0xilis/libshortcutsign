/*
 * Snoolie K, (c) 2025.
 * extract libshortcutsign functions
*/

#ifndef libshortcutsign_sign_h
#define libshortcutsign_sign_h

#include <inttypes.h>

int resign_shortcut_prologue(uint8_t *aeaShortcutArchive, void *privateKey, size_t privateKeyLen);
int resign_shortcut_with_new_aa(uint8_t *aeaShortcutArchive, void *archivedDir, size_t archivedDirSize, size_t *newSize, void *privateKey);
int resign_shortcut_with_new_plist(uint8_t *aeaShortcutArchive, void *plist, size_t plistSize, size_t *newSize, void *privateKey);

#endif /* libshortcutsign_sign_h */
