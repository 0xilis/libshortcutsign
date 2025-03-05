# sign_shortcut_aar_with_private_key_and_auth_data
Sign an Apple Archive containing the unsigned shortcut.

```c
uint8_t *sign_shortcut_aar_with_private_key_and_auth_data(void *aar, size_t aarSize, void *privateKey, uint8_t *authData, size_t authDataSize, size_t *outSize);
```

## Parameters

#### aar

A buffer containing the uncompressed aar of the shortcut you want to sign.

#### archivedDir

The size of the uncompressed aar in bytes.

#### privateKey

A buffer containing a raw ECDSA-P256 key in X9.63 format.

#### authData

A buffer containing the auth data.

#### authDataSize

The size of the auth data in bytes.

#### outSize

If this is not null, this parameter will be filled with the size of the signed shortcut in bytes.

## Return Value

A newly allocated buffer containing the signed shortcut. If the function fails, it returns null.

## Note

A shortcut Apple Archive is the unsigned shortcut wrapped in an aar, with the shortcut being named "Shortcut.wflow".

For signing with the plist instead (a regular unsigned shortcut file), check out [sign_shortcut_with_private_key_and_auth_data](sign_shortcut_with_private_key_and_auth_data.md).
