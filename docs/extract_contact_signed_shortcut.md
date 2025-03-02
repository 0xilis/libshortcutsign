# extract_contact_signed_shortcut
Extracts the unsigned shortcut from the signed shortcut. Nowadays just a wrapper around the modern better cross-compatible extract_signed_shortcut.

`int extract_contact_signed_shortcut(const char *signedShortcutPath, const char *destPath);`

# Deprecation Notice

This function has been deprecated in favor of `extract_signed_shortcut`. Please replace all calls to this function to `extract_signed_shortcut`. Compatibility is 1-1 with this old function.

## Parameters

#### signedShortcutPath

A path containing a signed shortcut.

#### destPath

A path where the unsigned shortcut will be written to.

## Return Value

On success, the return value will be 0. On failure, it will be a negative error code.