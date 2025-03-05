# sign_shortcut_with_private_key_and_auth_data
Sign a shortcut plist (a regular unsigned shortcut file).

```c
uint8_t *sign_shortcut_with_private_key_and_auth_data(void *plist, size_t plistSize, void *privateKey, uint8_t *authData, size_t authDataSize, size_t *outSize);
```

## Parameters

#### plist

A buffer containing the plist of the shortcut you want to sign.

#### plistSize

The size of the plist buffer in bytes.

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

For signing an aar instead, check out [sign_shortcut_aar_with_private_key_and_auth_data](sign_shortcut_aar_with_private_key_and_auth_data.md).
