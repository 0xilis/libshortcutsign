# extract_signed_shortcut_buffer
Extracts the unsigned shortcut from the signed shortcut.

```c
uint8_t *extract_signed_shortcut_buffer(uint8_t *signedShortcut, size_t signedShortcutSize, size_t *unsignedShortcutSize);
```

## Parameters

#### signedShortcut

The signed shortcut encoded in a buffer.

#### signedShortcutSize

The size of the signed shortcut buffer in bytes.

#### unsignedShortcutSize

If this is not null, this parameter will be filled with the size of the unsigned shortcut in bytes.

## Return Value

A newly allocated buffer containing the unsigned shortcut. If the function fails, it returns null.