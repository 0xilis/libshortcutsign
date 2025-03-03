# resign_shortcut_prologue
Resign the AEA prologue from a signed shortcut.

```c
int resign_shortcut_prologue(uint8_t *aeaShortcutArchive, void *privateKey, size_t privateKeyLen);
```

## Parameters

#### aeaShortcutArchive

A buffer containing the signed shortcut.

#### privateKey

A buffer containing a raw ECDSA-P256 key in X9.63 format.

#### privateKeyLen

The size of the privateKey buffer.

## Return Value

On success, the return value will be 0. On failure, it will be a negative error code.