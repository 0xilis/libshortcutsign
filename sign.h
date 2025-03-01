/*
 * Snoolie K, (c) 2025.
 * extract libshortcutsign functions
*/

#ifndef libshortcutsign_sign_h
#define libshortcutsign_sign_h

#include <inttypes.h>

void resign_shortcut_prologue(uint8_t *aeaShortcutArchive, void *privateKey, size_t privateKeyLen);
void resign_shortcut_with_new_aa(uint8_t *aeaShortcutArchive, void *archivedDir, size_t aeaShortcutArchiveSize, const char *outputPath, void *privateKey);

#endif /* libshortcutsign_sign_h */