# auth_data_from_shortcut
Retrieves the auth data from a signed shortcut.

```c
uint8_t *auth_data_from_shortcut(const char *path, size_t *authDataSize);
```

## Parameters

#### filepath

A filepath to the signed shortcut.

#### authDataSize

If this is not null, this parameter will be filled with the size of the auth data in bytes.

## Return Value

A newly allocated buffer containing the auth data. If the function cannot allocate the auth data, it returns null.

## Note

For the same functionality but from a buffer, check out [auth_data_from_shortcut_buffer](auth_data_from_shortcut_buffer.md).