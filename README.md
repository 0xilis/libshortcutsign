# libshortcutsign

Library by 0xilis for contact signed shortcuts.

# Compatibility

### App Store Guideline Friendly!
While libshortcutsign is based off of some WorkflowKit methods, **libshortcutsign never links/uses WorkflowKit directly.** Plus, (on macOS, at least) it does not need any entitlements to function.

The great thing about this is that it means libshortcutsign can be used in an App Store application, since it never uses private frameworks.

### Sadly, only Apple devices supported :(
Be aware though that unfortunately it is still restricted to iOS 15.0+ / macOS 12.0+. This is as libshortcutsign uses Security.framework as well as libAppleArchive.

While Security.framework is open source and (if I remember correctly?) some GNUstep folks may have gotten some functionality on other platforms ex linux, libAppleArchive is fully closed source sadly, and I doubt anyone would go through the pain of reversing it... (it is certianly above my skill level).

# Signing
libshortcutsign allows you to (assuming you have already managed to extract your Apple ID Validation Record certificates; you may want to use [https://github.com/seemoo-lab/airdrop-keychain-extractor](https://github.com/seemoo-lab/airdrop-keychain-extractor) ) contact sign a shortcut.

Be aware you'll need to construct the auth data yourself; you can try extracting the auth data from another contact signed shortcut (ex using libshortcutsign's own `auth_data_from_shortcut`) to get a better understanding.

Another helpful resource you may also want to look at the decompilation for WorkflowKit shortcut signing, especially `WFShortcutPackageFile` and `WFShortcutSigningContext` in it; WorkflowKit uses `contextWithAppleIDAccount:signingKey:` to generate the auth data which you can find in the decomp. Of course, directly copy and pasting the decomplication shouldn't be done, at least for public projects as it would not only make your app against guidelines but also likely infringe copyright, but it is great to use as a reference for how you could build your own method to do this.

# Compiling

Let's imagine you are using libshortcutsign in a main.m file which doesn't require any other libraries. You can compile it like this:

`clang -framework Foundation main.m -lAppleArchive -framework Security libshortcutsign/libshortcutsign.m -o main`

# Contributing

Contributions are welcome! Not just to the code, but also better documentation would also be appreciated; shortcuts signing is highly undocumented and TBH I'm not sure how to say exactly some of the things I know about it...

Minor contributions will also be appriecated.

The only request is to not depend on PrivateFrameworks. If your contribution absolutely needs to have it, then *perhaps* I'll make a seperate branch for those who are comfortable using them, but the main branch will never have them as I feel like it would drive away people who need to use libshortcutsign in public app store apps...
