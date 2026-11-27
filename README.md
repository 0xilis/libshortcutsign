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

libshortcutsign is cross platform and works on Linux, macOS, and Windows (Windows support is supported via mingw). iOS and FreeBSD are also supported but be aware the Makefile does not build for these platforms. A Windows version is planned, although be aware this may not be for a while. Android is not being considered at this time.

Do be aware however that verify_ functions are not yet complete: CMS AppleIDValidationRecord checking is currently not implemented, meaning it is possible for someone to change the phone number hash / email hash associated with a contact signed shortcut. This will be implemented in the future.

# Signing
libshortcutsign has a function, `sign_shortcut_with_private_key_and_auth_data`, for signing an unsigned shortcut file.

libshortcutsign allows you to (assuming you have already managed to extract your Apple ID Validation Record certificates; you may want to use [https://github.com/0xilis/appleid-key-dumper](https://github.com/0xilis/appleid-key-dumper)) contact sign a shortcut.

# CLI tool

I have made an official CLI tool using libshortcutsign that works on Linux and macOS, that being [shortcut-sign](https://github.com/0xilis/shortcut-sign). Much like libshortcutsign it is fully open source, although pre-compiled binaries are also available in the releases tab for x86_64 Linux+macOS.

# Compiling

Note that libshortcutsign depends a lot on submodules (ex, libNeoAppleArchive). To clone, use `git clone --recurse-submodules https://github.com/0xilis/libshortcutsign.git`

### Building on OS X / Linux

libshortcutsign provides a Makefile for easily building it as a static library and shared library. Just run `make` and it will build `build/usr/lib/libshortcutsign.a`, as well as `build/usr/lib/libshortcutsign.dylib` on macOS and `build/usr/lib/libshortcutsign.so` on Linux.

### Building on Windows

libshortcutsign is supported on Windows via mingw. Install mingw, and install the dependencies:

```
pacman -S --needed \
  git \
  make \
  mingw-w64-ucrt-x86_64-gcc \
  mingw-w64-ucrt-x86_64-binutils \
  mingw-w64-ucrt-x86_64-openssl \
  mingw-w64-ucrt-x86_64-zlib \
  mingw-w64-ucrt-x86_64-libplist
```

Afterwards, clone and `cd` to the directory, and `make CC=gcc`.

* Static library: `build/usr/lib/libshortcutsign.a`
* CLI tool: `build/usr/lib/libshortcutsign.dll`

Note that Windows builds, while tested, are not tested as well as Linux or OS X due to me not daily driving it, so contributions or reporting issues related to Windows are very appreciated.

# Contributing

Contributions are welcome! Not just to the code, but also better documentation would also be appreciated; shortcuts signing is highly undocumented and to be honest I'm not sure how to say exactly some of the things I know about it...

# TODO

* Support more formats of private keys and public keys
* Add a CommonCrypto option for sign.c and verify.c to allow macOS to use without installing OpenSSL
* Option to auto-update
* JavaScript implementation
* Once libNeoAppleArchive neo_aea_archive_sign function is implemented, implement it in libshortcutsign
* Function to get iCloud ID of iCloud signed shortcuts
* Improve Documentation
* Support MinGW for Windows

Special thanks to plx for contributions relating to OpenSSL 3.

Minor contributions will also be appreciated.
