# libshortcutsign

Library by 0xilis for signed shortcuts.

# Dependencies

libshortcutsign requires these dependencies:

- libplist (soon)
- OpenSSL

Statically provided as submodules:

- libNeoAppleArchive
- liblzfse

libshortcutsign also currently requires [the Apple Root CA](https://www.apple.com/appleca/AppleIncRootCertificate.cer) to be downloaded and named "AppleRootCA.cer" for verification functions.

# Compatibility

### App Store Guideline Friendly!
While libshortcutsign is based off of some WorkflowKit methods, **libshortcutsign never links/uses WorkflowKit directly.** Plus, (on macOS, at least) it does not need any entitlements to function.

The great thing about this is that it means libshortcutsign can be used in an App Store application, since it never uses private frameworks.

### Cross-platform! (Mostly)
Be aware that direct signing using the sign_shortcut_with_private_key_and_auth_data is currently restricted to iOS 15.0+ / macOS 12.0+. This is as libshortcutsign uses Security.framework as well as libAppleArchive. It is possible to use `resign_shortcut_with_new_aa` and replace the shortcut actions in the signed shortcut with another shortcut however, which I demo in my [shortcut-sign](https://github.com/0xilis/shortcut-sign) CLI.

**HOWEVER, all other functions are cross platform.** Check out the list.

| Function     | Universal | Notes |
|--------------|:---------:|-----------:|
| sign_shortcut_with_private_key_and_auth_data | NO | libAppleArchive & Security.framework needed |
| auth_data_from_shortcut | YES | No issues! |
| extract_signed_shortcut | YES | No issues! |
| verify_contact_signed_auth_data | YES | Currently only supports contact-signed shortcuts |
| verify_contact_signed_shortcut | YES | Currently only supports contact-signed shortcuts |
| resign_shortcut_with_new_aa | YES | No issues! |

(Special note about verify_ functions: CMS AppleIDValidationRecord checking is currently not implemented, meaning it is possible for someone to change the phone number hash / email hash associated with a contact signed shortcut. This will be implemented in the future)

# Signing
libshortcutsign has a function, `sign_shortcut_with_private_key_and_auth_data`, for signing an unsigned shortcut file. **Notice for usage: the passed in unsignedShortcutPath must point to a directory that contains the unsigned shortcut file, not to the directory itself. The directory must only contain the unsigned shortcut as "Shortcut.wflow" and nothing else. If you name it something different, shortcuts fails to decrypt it.**

libshortcutsign allows you to (assuming you have already managed to extract your Apple ID Validation Record certificates; you may want to use [https://github.com/seemoo-lab/airdrop-keychain-extractor](https://github.com/seemoo-lab/airdrop-keychain-extractor) ) contact sign a shortcut.

Be aware you'll need to construct the auth data yourself; you can try extracting the auth data from another contact signed shortcut (ex using libshortcutsign's own `auth_data_from_shortcut`) to get a better understanding. You can also try [libqmc](https://github.com/0xilis/QuickMergeHelper/tree/main/QuickMerge%20Helper/libqmc) to use the auth data from a qmc file.

# CLI tool

I have made an official CLI tool using libshortcutsign that works on Linux and macOS, that being [shortcut-sign](https://github.com/0xilis/shortcut-sign). Much like libshortcutsign it is fully open source, although pre-compiled binaries are also available in the releases tab for x86_64 Linux+macOS.

# Compiling

libshortcutsign provides a Makefile for easily building it as a static library. Just run `make` and it will build to `build/usr/lib/libshortcutsign.a`.

# Contributing

Contributions are welcome! Not just to the code, but also better documentation would also be appreciated; shortcuts signing is highly undocumented and to be honest I'm not sure how to say exactly some of the things I know about it...

Minor contributions will also be appreciated.
