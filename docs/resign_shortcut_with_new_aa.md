# resign_shortcut_with_new_aa
Resign the signed shortcut with a new or current Apple Archive.

```c
int resign_shortcut_with_new_aa(uint8_t **aeaShortcutArchive, void *archivedDir, size_t archivedDirSize, size_t *newSize, void *privateKey);
```

## Parameters

#### aeaShortcutArchive

A buffer containing the signed shortcut.

#### archivedDir

A buffer containing the uncompressed aar of the shortcut you want to resign. This can be a different shortcut than the one in the 1st argument if you wish.

#### archivedDir

The size of the uncompressed aar in bytes.

#### newSize

If this is not null, this parameter will be filled with new size of the resigned shortcut in bytes.

#### privateKey

A buffer containing a raw ECDSA-P256 key in X9.63 format.

## Return Value

On success, the return value will be 0. On failure, it will be a negative error code.

## Note

A shortcut Apple Archive is the unsigned shortcut wrapped in an aar, with the shortcut being named "Shortcut.wflow".

For resigning with the plist instead, check out [resign_shortcut_with_new_plist](resign_shortcut_with_new_plist.md).
