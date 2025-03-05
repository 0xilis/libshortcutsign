# resign_shortcut_with_new_plist
Resign the signed shortcut with a new or current shortcut plist.

```c
int resign_shortcut_with_new_plist(uint8_t *aeaShortcutArchive, void *plist, size_t plistSize, size_t *newSize, void *privateKey);
```

## Parameters

#### aeaShortcutArchive

A buffer containing the signed shortcut.

#### plist

A buffer containing the plist of the shortcut you want to resign. This can be a different shortcut than the one in the 1st argument if you wish.

#### plistSize

The size of the plist buffer.

#### newSize

If this is not null, this parameter will be filled with new size of the resigned shortcut in bytes.

#### privateKey

A buffer containing a raw ECDSA-P256 key in X9.63 format.

## Return Value

On success, the return value will be 0. On failure, it will be a negative error code.

## Note

For resigning with the aar instead, check out [resign_shortcut_with_new_aa](resign_shortcut_with_new_aa.md).
