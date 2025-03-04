# resign_shortcut_prologue
Resign the AEA prologue from a signed shortcut. **Note that this function is marked as private use, meaning APIs for it may change.**

```c
int resign_shortcut_with_new_aa(uint8_t *aeaShortcutArchive, void *archivedDir, size_t aeaShortcutArchiveSize, const char *outputPath, void *privateKey);
```

## Parameters

#### aeaShortcutArchive

A buffer containing the signed shortcut.

#### archivedDir

A buffer containing the uncompressed aar of the shortcut you want to resign. This can be a different shortcut than the one in the 1st argument if you wish.

#### aeaShortcutArchiveSize

The size of the signed shortcut buffer.

#### outputPath

The output path that the resigned shortcut will be written to.

#### privateKey

A buffer containing a raw ECDSA-P256 key in X9.63 format.

## Return Value

On success, the return value will be 0. On failure, it will be a negative error code.

## Note

A shortcut Apple Archive is the unsigned shortcut wrapped in an aar, with the shortcut being named "Shortcut.wflow".

In the future, a version of this function will be deemed public use.
