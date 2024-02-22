/*
 * Snoolie K, (c) 2024.
 * library for contact signing shortcuts with no WorkflowKit
 * (Albeit, still requires libAppleArchive)
 * Based on my research on reversing WorkflowKit.
*/

#import <Foundation/Foundation.h>
#import <AppleArchive/AppleArchive.h>
#import <AppleArchive/AEAContext.h>
#import <CoreFoundation/CoreFoundation.h>
#import <Security/Security.h>

#ifndef COMPRESSION_LZFSE
#define COMPRESSION_LZFSE 0x801
#endif

void sign_shortcut_with_private_key_and_auth_data(SecKeyRef privKey, NSData *authData, const char *unsignedShortcutPath, const char *destPath) {
 AEAContext context = AEAContextCreateWithProfile(0);
 if (context) {
  if (AEAContextSetFieldUInt(context, AEA_CONTEXT_FIELD_COMPRESSION_ALGORITHM, COMPRESSION_LZFSE) == 0) {
   CFErrorRef cferr = 0;
   NSData *key = (__bridge NSData *)SecKeyCopyExternalRepresentation(privKey, &cferr);
   if (key) {
    if (AEAContextSetFieldBlob(context, AEA_CONTEXT_FIELD_SIGNING_PRIVATE_KEY, AEA_CONTEXT_FIELD_REPRESENTATION_X963, [key bytes], [key length]) == 0) {
     AEAContextSetFieldBlob(context, AEA_CONTEXT_FIELD_AUTH_DATA, AEA_CONTEXT_FIELD_REPRESENTATION_RAW, [authData bytes], [authData length]);
     AAByteStream byteStream = AAFileStreamOpenWithPath(destPath,O_CREAT | O_RDWR, 0420);
     AAByteStream encryptedStream = AEAEncryptionOutputStreamOpen(byteStream, context, 0, 0);
     AAFieldKeySet fields = AAFieldKeySetCreateWithString("TYP,PAT,LNK,DEV,DAT,MOD,FLG,MTM,BTM,CTM,HLC,CLC");
     if (fields) {
      AAPathList pathList = AAPathListCreateWithDirectoryContents(unsignedShortcutPath, 0, 0, 0, 0, 0);
      if (pathList) {
       AAArchiveStream archiveStream = AAEncodeArchiveOutputStreamOpen(encryptedStream, 0, 0, 0, 0);
       if (archiveStream) {
        if (AAArchiveStreamWritePathList(archiveStream, pathList, fields, unsignedShortcutPath, 0, 0, 0, 0) == 0) {
         /* successfully contact signed shortcut */
        }
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
}

/* This function is libAppleArchive-less! */
NSData *auth_data_from_shortcut(const char *restrict filepath) {
 /* load shortcut into memory */
 FILE *fp = fopen(filepath, "r");
 if (!fp) {
  fprintf(stderr,"libshortcutsign: failed to open file\n");
  exit(1);
 }
 fseek(fp, 0, SEEK_END);
 size_t size = ftell(fp);
 fseek(fp, 0, SEEK_SET);
 char *archive = malloc(size * sizeof(char));
 /* copy bytes to binary */
 int c;
 size_t n = 0;
 while ((c = fgetc(fp)) != EOF) {
  archive[n++] = (char) c;
 }
 size_t archive_size = n;
 fclose(fp);
 /* find the size of AEA_CONTEXT_FIELD_AUTH_DATA field blob */
 /* We assume it's located at 0x8-0xB */
 register const char *sptr = archive + 0xB;
 size_t buf_size = *sptr << 24;
 buf_size += *(sptr - 1) << 16;
 buf_size += *(sptr - 2) << 8;
 buf_size += *(sptr - 3);
 if (buf_size > archive_size-0xB) {
  /* buf_size is bigger than our file, abort */
  fprintf(stderr,"libshortcutsign: context_buf_size bigger than archive_size.\n");
  exit(1);
 }
 /* we got buf_size, now fill buffer */
 uint8_t *buffer = (uint8_t *)malloc(buf_size);
 /*
  * the reason why we are doing a reverse
  * iteration is because doing it this way
  * will allow arm devices to take advantage
  * of the cbnz instruction, which should
  * mean about a 2 cycle save per iteration.
  *
  * also we're going to blindly trust that buf_size
  * is not larger than the buffer, because unless
  * you malform a aea file it should never be.
 */
 unsigned int i = buf_size;
 fill_buffer:
 i--;
 buffer[i] = archive[i+0xc];
 if (i != 0) {goto fill_buffer;};
 free(archive);
 /* make buffer NSData */
 NSData *authData = [NSData dataWithBytesNoCopy:buffer length:buf_size];
 return authData;
}

void decrypt_archive(AAByteStream byteStream, AEAContext context, const char *signedShortcutPath, const char *destPath) {
 //AAByteStream byteStream = AAFileStreamOpenWithPath(signedShortcutPath, 0, 420);
 AAArchiveStream archiveStream = AAExtractArchiveOutputStreamOpen(destPath, nil, nil, 1, 0);
 if (!archiveStream) {
  fprintf(stderr,"libshortcutsign: AAExtractArchiveOutputStreamOpen returned nil\n");
  exit(1);
 }
 AAByteStream decryptionInputStream = AEADecryptionInputStreamOpen(byteStream, context, 0, 0);
 if (!decryptionInputStream) {
  fprintf(stderr,"libshortcutsign: AEADecryptionInputStreamOpen returned nil\n");
  exit(1);
 }
 AAArchiveStream decodeStream = AADecodeArchiveInputStreamOpen(decryptionInputStream, nil, nil, 0, 0);
 if (!decodeStream) {
  fprintf(stderr,"libshortcutsign: AADecodeArchiveInputStreamOpen returned nil\n");
  exit(1);
 }
 /* Extracting Signed Shortcut Data */
 ssize_t archiveEntries = AAArchiveStreamProcess(decodeStream, archiveStream, nil, nil, 0, 0);
 /* archiveEntries will return a negative error code if failure */
 if (archiveEntries >= 0) {
  if (AAArchiveStreamClose(archiveStream) >= 0) {
   /* Success */
  } else {
   fprintf(stderr,"libshortcutsign: AAArchiveStreamClose failed\n");
   exit(1);
  }
 } else {
  fprintf(stderr,"libshortcutsign: failed to extract, error: %zu\n", archiveEntries);
  exit(1);
 }
}

void decrypt_signed_shortcut_with_context(AAByteStream byteStream, AEAContext context, NSData *authData, const char *signedShortcutPath, const char *destPath) {
 NSDictionary *dict = [NSPropertyListSerialization propertyListWithData:authData options:0 format:0 error:nil];
 if (dict) {
  if ([dict isKindOfClass:[NSDictionary class]]) {
   CFDataRef signingPublicKey = (__bridge CFDataRef)dict[@"SigningPublicKey"];

   SecKeyRef publicKey = SecKeyCreateWithData(signingPublicKey,(__bridge CFDictionaryRef)@{
    (__bridge NSString *)kSecAttrKeyType : (__bridge NSString *)kSecAttrKeyTypeECSECPrimeRandom,
    (__bridge NSString *)kSecAttrKeyClass : (__bridge NSString *)kSecAttrKeyClassPublic,
   }, nil);
   NSData *externalRep = (__bridge NSData*)SecKeyCopyExternalRepresentation(publicKey, nil);
   if (AEAContextSetFieldBlob(context, AEA_CONTEXT_FIELD_SIGNING_PUBLIC_KEY, AEA_CONTEXT_FIELD_REPRESENTATION_X963, [externalRep bytes], [externalRep length]) == 0) {
    decrypt_archive(byteStream, context, signedShortcutPath, destPath);
   } else {
    fprintf(stderr,"libshortcutsign: failed to set public key\n");
    exit(1);
   }
  }
 } else {
  printf("failed to create dict from auth data\n");
 }
}

/* Extracts/Decrypts the unsigned shortcut from a contact signed shortcut */
void extract_contact_signed_shortcut(const char *signedShortcutPath, const char *destPath) {
 if (!access(destPath, F_OK)) {
  fprintf(stderr,"libshortcutsign: directory not created specified in destPath\n");
  exit(1);
 }
 AAByteStream byteStream = AAFileStreamOpenWithPath(signedShortcutPath, 0, 420);
 if (byteStream) {
  AEAContext context = AEAContextCreateWithEncryptedStream(byteStream);
  if (context) {
   NSData *authData = auth_data_from_shortcut(signedShortcutPath);
   decrypt_signed_shortcut_with_context(byteStream, context, authData, signedShortcutPath, destPath);
  }
 }
}