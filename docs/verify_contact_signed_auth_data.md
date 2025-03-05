# verify_contact_signed_auth_data
Verify the authentication data of a contact signed shortcut.

```c
int verify_contact_signed_auth_data(uint8_t *authData, size_t authDataSize);
```

## Parameters

#### authData

A buffer containing the auth data.

#### authDataSize

The size of the auth data in bytes.

## Return Value

On success, the return value will be 0. On failure, it will be a negative error code.