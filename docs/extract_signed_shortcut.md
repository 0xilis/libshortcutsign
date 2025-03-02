# extract_signed_shortcut
Extracts the unsigned shortcut from the signed shortcut.

`int extract_signed_shortcut(const char *signedShortcutPath, const char *destPath);`

## Parameters

#### signedShortcutPath

A path containing a signed shortcut.

#### destPath

A path where the unsigned shortcut will be written to.

## Return Value

On success, the return value will be 0. On failure, it will be a negative error code.