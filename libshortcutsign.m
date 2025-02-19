/*
 * 0xilis, (c) 2024.
 * library for contact signing shortcuts with no WorkflowKit
 * (Albeit, still requires libAppleArchive)
 * Based on my research on reversing WorkflowKit.
*/

#import <Foundation/Foundation.h>
#import <AppleArchive/AppleArchive.h>
#import <AppleArchive/AEAContext.h>
#import <CoreFoundation/CoreFoundation.h>
#import <Security/Security.h>

#include "extract.h"

#ifndef COMPRESSION_LZFSE
#define COMPRESSION_LZFSE 0x801
#endif

/* 
 * sign_shortcut_with_private_key_and_auth_data
 *
 * Contact signs a shortcut with a signing key and auth data.
 *
 * unsignedShortcutPath should be the path to the unsigned .shortcut file.
 * destPath should be the path you want to output the signed shortcut, including
 * the file name and extension of the signed shortcut.
 *
 * If verified, this function returns 0.
 * If not verified, this function returns a negative error code.
*/
int sign_shortcut_with_private_key_and_auth_data(SecKeyRef privKey, NSData *authData, const char *unsignedShortcutPath, const char *destPath) {
 int succeed = -1;
 AEAContext context = AEAContextCreateWithProfile(0);
 if (context) {
  if (AEAContextSetFieldUInt(context, AEA_CONTEXT_FIELD_COMPRESSION_ALGORITHM, COMPRESSION_LZFSE) == 0) {
   CFErrorRef cferr = 0;
   NSData *key = (__bridge NSData *)SecKeyCopyExternalRepresentation(privKey, &cferr);
   if (key) {
    if (AEAContextSetFieldBlob(context, AEA_CONTEXT_FIELD_SIGNING_PRIVATE_KEY, AEA_CONTEXT_FIELD_REPRESENTATION_X963, [key bytes], [key length]) == 0) {
     AEAContextSetFieldBlob(context, AEA_CONTEXT_FIELD_AUTH_DATA, AEA_CONTEXT_FIELD_REPRESENTATION_RAW, [authData bytes], [authData length]);
     AAByteStream byteStream = AAFileStreamOpenWithPath(destPath,O_CREAT | O_RDWR, 420);
     AAByteStream encryptedStream = AEAEncryptionOutputStreamOpen(byteStream, context, 0, 0);
     AAFieldKeySet fields = AAFieldKeySetCreateWithString("TYP,PAT,LNK,DEV,DAT,MOD,FLG,MTM,BTM,CTM,HLC,CLC");
     if (fields) {
      AAPathList pathList = AAPathListCreateWithDirectoryContents(unsignedShortcutPath, 0, 0, 0, 0, 0);
      if (pathList) {
       AAArchiveStream archiveStream = AAEncodeArchiveOutputStreamOpen(encryptedStream, 0, 0, 0, 0);
       if (archiveStream) {
        /* If it was successful it will return 0 */
        succeed = AAArchiveStreamWritePathList(archiveStream, pathList, fields, unsignedShortcutPath, 0, 0, 0, 0);
        AAArchiveStreamClose(archiveStream);
       }
       AAPathListDestroy(pathList);
      }
      AAFieldKeySetDestroy(fields);
     }
     AAByteStreamClose(encryptedStream);
     AAByteStreamClose(byteStream);
    }
   }
  }
  AEAContextDestroy(context);
 }
 return succeed;
}

/*
 * generate_appleid_certs_with_data
 *
 * Generates an array of SecCertificateRef certs from 
 * an NSArray containing NSData for the certs.
 *
 * This can be used for getting a cert chain from the
 * extracted auth data of a shortcut.
 *
 * If the function fails, it returns 0/nil.
*/
NSArray *generate_appleid_certs_with_data(NSArray *appleIDCertDataChain) {
 int count = [appleIDCertDataChain count];
 if (count < 1) {
  fprintf(stderr,"libshortcutsign: no items in passed in cert data chain\n");
  return 0;
 }
 NSMutableArray *returnArray = [[NSMutableArray alloc]initWithCapacity:count];
 NSData *certData;
 SecCertificateRef cert;
 for (int i = 0; i < count; i++) {
  certData = appleIDCertDataChain[i];
  cert = SecCertificateCreateWithData(0, (__bridge CFDataRef)certData);
  returnArray[i] = (id)cert;
 }
 return [[NSArray alloc]initWithArray:returnArray];
}

/* We have to define these ourselves */
SecPolicyRef SecPolicyCreateAppleIDAuthorityPolicy(void);
extern const CFStringRef kSecPolicyCheckTemporalValidity;
void SecPolicySetOptionsValue(SecPolicyRef policy, CFStringRef key, CFTypeRef value);
SecPolicyRef SecPolicyCreateAppleIDValidationRecordSigningPolicy(void);
OSStatus SecCMSVerifyCopyDataAndAttributes(CFDataRef message, CFDataRef detached_contents, CFTypeRef policy, SecTrustRef *trustref, CFDataRef *attached_contents, CFDictionaryRef *signed_attributes);
