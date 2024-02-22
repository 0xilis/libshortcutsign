/*
 * Snoolie K, (c) 2024.
 * library for contact signing shortcuts with no WorkflowKit
 * (Albeit, still requires libAppleArchive)
 * Based on my research on reversing WorkflowKit.
*/

#ifndef libshortcutsign_h
#define libshortcutsign_h

#import <Foundation/Foundation.h>
#import <AppleArchive/AppleArchive.h>
#import <AppleArchive/AEAContext.h>
#import <CoreFoundation/CoreFoundation.h>
#import <Security/Security.h>

void sign_shortcut_with_private_key_and_auth_data(SecKeyRef privKey, NSData *authData, const char *unsignedShortcutPath, const char *destPath);
NSData *auth_data_from_shortcut(const char *restrict filepath);
void extract_contact_signed_shortcut(const char *signedShortcutPath, const char *destPath);

#endif /* libshortcutsign_h */