# auth_data_from_shortcut_buffer
Retrieves the auth data from a signed shortcut.

`uint8_t *auth_data_from_shortcut_buffer(uint8_t *buffer, size_t bufferSize, size_t *authDataSize);`

## Parameters

#### buffer

The signed shortcut encoded in a buffer.

#### bufferSize

The size of the buffer in bytes.

#### authDataSize

If this is not null, this parameter will be filled with the size of the auth data in bytes.

## Return Value

A newly allocated buffer containing the auth data. If the function cannot allocate the auth data, it returns null.

## Note

For the same functionality but from a path, check out [auth_data_from_shortcut](auth_data_from_shortcut.md).