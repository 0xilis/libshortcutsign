# libshortcutsign

Library by Snoolie K for signed shortcuts.

# Dependencies

libshortcutsign requires these dependencies:

- libplist-2.0
- OpenSSL

Statically provided as submodules:

- libNeoAppleArchive
- liblzfse

# Compatibility

libshortcutsign is cross platform and works on Linux and macOS. iOS and FreeBSD are also supported but be aware the Makefile does not build for these platforms. A Windows version is planned, although be aware this may not be for a while. Android is not being considered at this time.

Do be aware however that verify_ functions are not yet complete: CMS AppleIDValidationRecord checking is currently not implemented, meaning it is possible for someone to change the phone number hash / email hash associated with a contact signed shortcut. This will be implemented in the future.

# Signing
libshortcutsign has a function, `sign_shortcut_with_private_key_and_auth_data`, for signing an unsigned shortcut file.

libshortcutsign allows you to (assuming you have already managed to extract your Apple ID Validation Record certificates; you may want to use [https://github.com/0xilis/appleid-key-dumper) ) contact sign a shortcut.

# CLI tool

I have made an official CLI tool using libshortcutsign that works on Linux and macOS, that being [shortcut-sign](https://github.com/0xilis/shortcut-sign). Much like libshortcutsign it is fully open source, although pre-compiled binaries are also available in the releases tab for x86_64 Linux+macOS.

# Compiling

libshortcutsign provides a Makefile for easily building it as a static library and shared library. Just run `make` and it will build `build/usr/lib/libshortcutsign.a`, as well as `build/usr/lib/libshortcutsign.dylib` on macOS and `build/usr/lib/libshortcutsign.so` on Linux.

# Contributing

Contributions are welcome! Not just to the code, but also better documentation would also be appreciated; shortcuts signing is highly undocumented and to be honest I'm not sure how to say exactly some of the things I know about it...

# TODO

* Once libNeoAppleArchive neo_aea_archive_sign function is implemented, implement it in libshortcutsign
* Function to get iCloud ID of iCloud signed shortcuts
* Improve Documentation
* Support MinGW for Windows

Special thanks to plx for contributions relating to OpenSSL 3.

Minor contributions will also be appreciated.
