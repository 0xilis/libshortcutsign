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

#include "extract.h"
#include "verify.h"
#include "sign.h"

int sign_shortcut_with_private_key_and_auth_data(SecKeyRef privKey, NSData *authData, const char *unsignedShortcutPath, const char *destPath) __attribute__((deprecated)); /* This function will soon be replaced with a cross-compat alternative */

#endif /* libshortcutsign_h */
