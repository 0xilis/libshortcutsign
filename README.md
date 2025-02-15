# libshortcutsign

Library by 0xilis for contact signed shortcuts.

# Dependencies

libshortcutsign requires these dependencies:

- libplist (soon)
- OpenSSL

Statically provided as submodules:

- libNeoAppleArchive
- liblzfse

# Compatibility

### App Store Guideline Friendly!
While libshortcutsign is based off of some WorkflowKit methods, **libshortcutsign never links/uses WorkflowKit directly.** Plus, (on macOS, at least) it does not need any entitlements to function.

The great thing about this is that it means libshortcutsign can be used in an App Store application, since it never uses private frameworks.

### Sadly, only Apple devices supported :(... or are they?
Be aware though that unfortunately it is still restricted to iOS 15.0+ / macOS 12.0+. This is as libshortcutsign uses Security.framework as well as libAppleArchive.

While Security.framework is open source and (if I remember correctly?) some GNUstep folks may have gotten some functionality on other platforms ex linux, libAppleArchive is fully closed source sadly, and I doubt anyone would go through the pain of reversing it... (it is certianly above my skill level).

**HOWEVER, there are some functions that ARE cross-platform.** I've made a list of these below.

| Function     | Universal | Notes |
|--------------|:---------:|-----------:|
| sign_shortcut_with_private_key_and_auth_data | NO | libAppleArchive & Security.framework needed |
| auth_data_from_shortcut | YES | No issues! |
| extract_signed_shortcut | YES | Uses libcompression but just replace it with https://github.com/lzfse/lzfse |
| verify_contact_signed_auth_data | YES w/GNUstep | Security.framework use |
| verify_contact_signed_shortcut | YES w/GNUstep | Security.framework use |

# Signing
libshortcutsign has a function, `sign_shortcut_with_private_key_and_auth_data`, for signing an unsigned shortcut file. **Notice for usage: the passed in unsignedShortcutPath must point to a directory that contains the unsigned shortcut file, not to the directory itself. The directory must only contain the unsigned shortcut as "Shortcut.wflow" and nothing else. If you name it something different, shortcuts fails to decrypt it.**

libshortcutsign allows you to (assuming you have already managed to extract your Apple ID Validation Record certificates; you may want to use [https://github.com/seemoo-lab/airdrop-keychain-extractor](https://github.com/seemoo-lab/airdrop-keychain-extractor) ) contact sign a shortcut.

Be aware you'll need to construct the auth data yourself; you can try extracting the auth data from another contact signed shortcut (ex using libshortcutsign's own `auth_data_from_shortcut`) to get a better understanding. You can also try [https://github.com/0xilis/QuickMergeHelper/tree/main/QuickMerge%20Helper/libqmc](libqmc) to use the auth data from a qmc file.

# Compiling

Let's imagine you are using libshortcutsign in a main.m file which doesn't require any other libraries. You can compile it like this:

`clang -framework Foundation main.m -lAppleArchive -framework Security libshortcutsign/libshortcutsign.m -o main`

# Contributing

Contributions are welcome! Not just to the code, but also better documentation would also be appreciated; shortcuts signing is highly undocumented and TBH I'm not sure how to say exactly some of the things I know about it...

Minor contributions will also be appriecated.
