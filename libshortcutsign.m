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

#include "xplat.h"

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
  returnArray[i] = cert;
 }
 return [[NSArray alloc]initWithArray:returnArray];
}

/* We have to define these ourselves */
SecPolicyRef SecPolicyCreateAppleIDAuthorityPolicy(void);
extern const CFStringRef kSecPolicyCheckTemporalValidity;
void SecPolicySetOptionsValue(SecPolicyRef policy, CFStringRef key, CFTypeRef value);
SecPolicyRef SecPolicyCreateAppleIDValidationRecordSigningPolicy(void);
OSStatus SecCMSVerifyCopyDataAndAttributes(CFDataRef message, CFDataRef detached_contents, CFTypeRef policy, SecTrustRef *trustref, CFDataRef *attached_contents, CFDictionaryRef *signed_attributes);

/*
 * verify_dict_auth_data
 *
 * Replicates the 1st step of WorkflowKit's signature check process.
 * The first sort of signature checking is not actually from
 * validation methods at all, but rather inside of the method
 * to get the signing context from auth data.
 * This is intended for contact signed shortcuts, as if this step detects
 * SigningCertificateChain, it sees it as iCloud signed and forms context
 * from the certificate chain, and this step will not do any checking
 * and instead just return YES.
 *
 * For both steps of contact signed validation, call verify_contact_signed_shortcut.
 *
 * If verified, this function returns 0.
 * If not verified, this function returns a negative error code.
*/
int verify_dict_auth_data(NSDictionary *dict) {
 /* TODO: Finish this function. */
 NSArray *appleIDDataCertChain = dict[@"AppleIDCertificateChain"];
 if (appleIDDataCertChain && [appleIDDataCertChain isKindOfClass:[NSArray class]]) {
  NSArray *appleIDCertChain = generate_appleid_certs_with_data(appleIDDataCertChain);
  NSData *signingPublicKey = dict[@"SigningPublicKey"];
  if (![signingPublicKey isKindOfClass:[NSData class]]) {
   signingPublicKey = nil;
  }
  NSData *signingPublicKeySignature = dict[@"SigningPublicKeySignature"];
  if (![signingPublicKeySignature isKindOfClass:[NSData class]]) {
   signingPublicKeySignature = nil;
  }
  SecKeyRef publicKey = SecCertificateCopyKey([appleIDCertChain firstObject]);
  SecKeyCreateWithData((__bridge CFDataRef)signingPublicKey, (__bridge CFDictionaryRef)@{
   (__bridge NSString *)kSecAttrKeyType : (__bridge NSString *)kSecAttrKeyTypeECSECPrimeRandom,
   (__bridge NSString *)kSecAttrKeyClass : (__bridge NSString *)kSecAttrKeyClassPublic,
  }, nil);
  unsigned char isVerified = SecKeyVerifySignature(publicKey, kSecKeyAlgorithmRSASignatureMessagePSSSHA256, (__bridge CFDataRef)signingPublicKey, (__bridge CFDataRef)signingPublicKeySignature, nil);
  if (isVerified) {
   NSData *appleIDValidationRecord = dict[@"AppleIDValidationRecord"];
   if (appleIDValidationRecord) {
    dispatch_queue_attr_t attr = dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_USER_INITIATED, 0);
    dispatch_queue_t queue = dispatch_queue_create("SFAppleIDQueue",attr);
    (void)dispatch_semaphore_create(0);
    if (!queue) {
     queue = dispatch_get_global_queue(0, 0);
    }
    SecPolicyRef policy = SecPolicyCreateAppleIDValidationRecordSigningPolicy();
    if (policy) {
     SecPolicySetOptionsValue(policy, kSecPolicyCheckTemporalValidity, kCFBooleanFalse);
     SecTrustRef trust = 0;
     CFDataRef attachedRecordContents = 0;
     if (SecCMSVerifyCopyDataAndAttributes((__bridge CFDataRef)appleIDValidationRecord, 0, policy, &trust, &attachedRecordContents, 0) == 0) {
      if (trust && attachedRecordContents) {
       NSDictionary *authDict = [NSPropertyListSerialization propertyListWithData:(__bridge NSData *)attachedRecordContents options:0 format:0 error:0];
       if (authDict) {
        /* there is more checking here, but for now it isn't implemented. */
        return 0;
       }
      }
     }
    }
   }
  }
 }
 return -1;
}

/*
 * verify_dict_auth_data_cert_trust
 *
 * Replicates the 2nd step of WorkflowKit's signature check process.
 * validateAppleIDCertificatesWithError checks the trust of the cert chain.
 * It should be noted that WorkflowKit actually checks if SecTrustEvaluateWithError
 * returns errSecCertificateExpired, and if it does, it renders it as valid anyway.
 *
 * For both steps of contact signed validation, call verify_contact_signed_shortcut.
 *
 * If verified, this function returns 0.
 * If not verified, this function returns a negative error code.
*/
int verify_dict_auth_data_cert_trust(NSDictionary *dict) {
 NSArray *appleIDDataCertChain = dict[@"AppleIDCertificateChain"];
 if (appleIDDataCertChain && [appleIDDataCertChain isKindOfClass:[NSArray class]]) {
  NSArray *appleIDCertChain = generate_appleid_certs_with_data(appleIDDataCertChain);
  if (appleIDCertChain) {
   SecPolicyRef policy = SecPolicyCreateAppleIDAuthorityPolicy();
   SecPolicySetOptionsValue(policy,kSecPolicyCheckTemporalValidity,kCFBooleanFalse);
   if (policy) {
    SecTrustRef trust;
    OSStatus res = SecTrustCreateWithCertificates((__bridge CFArrayRef)appleIDCertChain, policy, &trust);
    if (res == 0) {
     if (trust) {
      /* if we got errSecCertificateExpired return valid anyway */
      CFErrorRef trustErr;
      if (SecTrustEvaluateWithError(trust, &trustErr) == 0) {
       CFErrorDomain domain = CFErrorGetDomain(trustErr);
       if (CFEqual(domain, NSOSStatusErrorDomain)) {
        if (CFErrorGetCode(trustErr) == errSecCertificateExpired) {
         return 0;
        }
       }
      } else {
       return 0;
      }
     }
    }
   }
  }
 }
 return -1;
}

/*
 * verify_contact_signed_auth_data
 *
 * Replicates WorkflowKit's signature check process
 * The first sort of signature checking is not actually from
 * validation methods at all, but rather inside of the method
 * to get the signing context from auth data.
 *
 * Then, next, it uses validateAppleIDCertificatesWithError to check the trust.
 * It should be noted that WorkflowKit actually checks if SecTrustEvaluateWithError
 * returns errSecCertificateExpired, and if it does, it renders it as valid anyway.
 *
 * Finally, it uses validateAppleIDValidationRecordWithCompletion to check
 * if you shared the shortcut via the AltDSID in the validation record, or
 * if it's from someone in your contacts via the SHA256 phone/email hashes.
 * libshortcutsign doesn't replicate this final part, as it's easy to check
 * yourself if you have that info. Everything else is implemented by libshortcutsign.
 *
 * Currently (as the name implies) this only checks contact signed shortcuts, though
 * in the future a function for checking iCloud signed shortcuts may be implemented.
 * 
 * If you just want to do the first step, call verify_dict_auth_data.
 * If you just want to do the second step, call verify_dict_auth_data_cert_trust.
 * If you want to use the path of the shortcut, call verify_contact_signed_shortcut.
 *
 * If verified, this function returns 0.
 * If not verified, this function returns a negative error code.
*/
int verify_contact_signed_auth_data(NSData *authData) {
 NSDictionary *dict = [NSPropertyListSerialization propertyListWithData:authData options:0 format:0 error:nil];
 if (dict && [dict isKindOfClass:[NSDictionary class]]) {
  if (verify_dict_auth_data(dict) == 0) {
   return verify_dict_auth_data_cert_trust(dict);
  }
 }
 /* validation failed :( */
 return -1;
}

/*
 * verify_contact_signed_shortcut
 *
 * Replicates WorkflowKit's signature check process
 * The first sort of signature checking is not actually from
 * validation methods at all, but rather inside of the method
 * to get the signing context from auth data.
 *
 * Then, next, it uses validateAppleIDCertificatesWithError to check the trust.
 * It should be noted that WorkflowKit actually checks if SecTrustEvaluateWithError
 * returns errSecCertificateExpired, and if it does, it renders it as valid anyway.
 *
 * Finally, it uses validateAppleIDValidationRecordWithCompletion to check
 * if you shared the shortcut via the AltDSID in the validation record, or
 * if it's from someone in your contacts via the SHA256 phone/email hashes.
 * libshortcutsign doesn't replicate this final part, as it's easy to check
 * yourself if you have that info. Everything else is implemented by libshortcutsign.
 *
 * Currently (as the name implies) this only checks contact signed shortcuts, though
 * in the future a function for checking iCloud signed shortcuts may be implemented.
 * 
 * If you just want to do the first step, call verify_dict_auth_data.
 * If you just want to do the second step, call verify_dict_auth_data_cert_trust.
 *
 * If verified, this function returns 0.
 * If not verified, this function returns a negative error code.
*/
int verify_contact_signed_shortcut(const char *signedShortcutPath) {
 size_t authDataBufferSize;
 uint8_t *authDataBuffer = auth_data_from_shortcut(signedShortcutPath, &authDataBufferSize);
 NSData *authData = [NSData dataWithBytesNoCopy:authDataBuffer length:authDataBufferSize];
 if (!authData) {
  fprintf(stderr,"libshortcutsign: verification failed to extract authData\n");
  return -1;
 }
 return verify_contact_signed_auth_data(authData);
}
