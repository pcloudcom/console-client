/* Copyright (c) 2013-2014 Anton Titov.
 * Copyright (c) 2013-2014 pCloud Ltd.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of pCloud Ltd nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL pCloud Ltd BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "pssl.h"
#include "psynclib.h"
#include "plibs.h"
#include "pcompat.h"
#include "psettings.h"
#include <unistd.h>
#include <string.h>
#include <stddef.h>
#include <CommonCrypto/CommonHMAC.h>
#include <Security/SecureTransport.h>
#include <Security/SecImportExport.h>
#include <Security/Security.h>
#include <Security/SecKey.h>

#define kSecPaddingOAEP 2

OSStatus SecKeyEncrypt(
    SecKeyRef           key,
        SecPadding          padding,
        const uint8_t           *plainText,
        size_t              plainTextLen,
        uint8_t             *cipherText,
        size_t              *cipherTextLen);

OSStatus SecKeyDecrypt(
    SecKeyRef           key,
        SecPadding          padding,
        const uint8_t       *cipherText,
        size_t              cipherTextLen,
        uint8_t             *plainText, 
        size_t              *plainTextLen);

PSYNC_THREAD int psync_ssl_errno;

int psync_ssl_init(){
  return 0;
}

void psync_ssl_memclean(void *ptr, size_t len){
  volatile unsigned char *c=(volatile unsigned char *)ptr;
  while (len--)
    *c++=0;
}

static OSStatus psync_myread(SSLConnectionRef conn, void *data, size_t *len){
  psync_socket_t sock=(psync_socket_t)conn;
  size_t llen=*len;
  ssize_t rd=read(sock, data, llen);
  if (likely(rd>0)){
    *len=rd;
    if (rd==llen)
      return noErr;
    psync_ssl_errno=PSYNC_SSL_ERR_WANT_READ;
    return errSSLWouldBlock;
  }
  else if (rd==0){
    *len=0;
    return errSSLClosedNoNotify;
  }
  else {
    *len=0;
    if (errno==EAGAIN || errno==EINTR){
      psync_ssl_errno=PSYNC_SSL_ERR_WANT_READ;
      return errSSLWouldBlock;
    }
    else
      return errSSLClosedAbort;
  }
}

static OSStatus psync_mywrite(SSLConnectionRef conn, const void *data, size_t *len){
  psync_socket_t sock=(psync_socket_t)conn;
  size_t llen=*len;
  ssize_t rd=write(sock, data, llen);
  if (likely(rd>=0)){
    *len=rd;
    if (rd==llen)
      return noErr;
    psync_ssl_errno=PSYNC_SSL_ERR_WANT_WRITE;
    return errSSLWouldBlock;
  }
  else {
    *len=0;
    if (errno==EAGAIN || errno==EINTR){
      psync_ssl_errno=PSYNC_SSL_ERR_WANT_WRITE;
      return errSSLWouldBlock;
    }
    else
      return errSSLClosedAbort;
  }
}

int psync_ssl_connect(psync_socket_t sock, void **sslconn, const char *hostname){
  SSLContextRef ref;
  OSStatus st;
  ref=SSLCreateContext(kCFAllocatorDefault, kSSLClientSide, kSSLStreamType);
  if (unlikely_log(!ref))
    goto err1;
  if (unlikely_log(SSLSetIOFuncs(ref, psync_myread, psync_mywrite)!=noErr))
    goto err2;
  if (unlikely_log(SSLSetConnection(ref, (SSLConnectionRef)(uintptr_t)sock)!=noErr))
    goto err2;
  if (hostname && unlikely_log(SSLSetPeerDomainName(ref, hostname, strlen(hostname))!=noErr))
    goto err2;
  st=SSLHandshake(ref);
  if (st==noErr){
    *sslconn=ref;
    return PSYNC_SSL_SUCCESS;
  }
  else if (st==errSSLWouldBlock){
    *sslconn=ref;
    return PSYNC_SSL_NEED_FINISH;    
  }
  debug(D_WARNING, "connection failed with status %d", (int)st);
err2:
  CFRelease(ref);
err1:
  psync_ssl_errno=PSYNC_SSL_ERR_UNKNOWN;
  return PSYNC_SSL_FAIL;
}

int psync_ssl_connect_finish(void *sslconn, const char *hostname){
  SSLContextRef ref;
  OSStatus st;
  ref=(SSLContextRef)sslconn;
  st=SSLHandshake(ref);
  if (st==noErr)
    return PSYNC_SSL_SUCCESS;
  else if (st==errSSLWouldBlock)
    return PSYNC_SSL_NEED_FINISH;
  CFRelease(ref);
  debug(D_WARNING, "connection failed with status %d", (int)st);
  psync_ssl_errno=PSYNC_SSL_ERR_UNKNOWN;
  return PSYNC_SSL_FAIL;
}

int psync_ssl_shutdown(void *sslconn){
  SSLContextRef ref;
  OSStatus st;
  ref=(SSLContextRef)sslconn;
  st=SSLClose(ref);
  if (st==errSSLWouldBlock)
    return PSYNC_SSL_NEED_FINISH;
  CFRelease(ref);
  if (st==noErr)
    return PSYNC_SSL_SUCCESS;
  psync_ssl_errno=PSYNC_SSL_ERR_UNKNOWN;
  return PSYNC_SSL_FAIL;
}

void psync_ssl_free(void *sslconn){
  CFRelease((SSLContextRef)sslconn);
}

int psync_ssl_pendingdata(void *sslconn){
  size_t p;
  if (SSLGetBufferedReadSize((SSLContextRef)sslconn, &p)==noErr)
    return p;
  else
    return 0;
}

int psync_ssl_read(void *sslconn, void *buf, int num){
  size_t ret;
  OSStatus st;
  psync_ssl_errno=PSYNC_SSL_ERR_UNKNOWN;
  st=SSLRead((SSLContextRef)sslconn, buf, num, &ret);
  if (st!=noErr){
    if (st==errSSLWouldBlock && ret)
      return ret;
    else if (st==errSSLClosedGraceful)
      return 0;
    else{
      if (st!=errSSLWouldBlock)
        debug(D_WARNING, "read failed with error %d", (int)st);
      return PSYNC_SSL_FAIL;
    }
  }
  else
    return ret;  
}

int psync_ssl_write(void *sslconn, const void *buf, int num){
  size_t ret;
  OSStatus st;
  psync_ssl_errno=PSYNC_SSL_ERR_UNKNOWN;
  st=SSLWrite((SSLContextRef)sslconn, buf, num, &ret);
  if (st!=noErr){
    if (st==errSSLWouldBlock && ret)
      return ret;
    else{
      if (st!=errSSLWouldBlock)
        debug(D_WARNING, "write failed with error %d", (int)st);
      return PSYNC_SSL_FAIL;
    }
  }
  else
    return ret;
}

void psync_ssl_rand_strong(unsigned char *buf, int num){
  ssize_t ret;
  int fd;
  fd=open("/dev/random", O_RDONLY);
  if (unlikely_log(fd==-1))
    goto err;
  while (num){
    ret=read(fd, buf, num);
    if (unlikely_log(ret<=0))
      goto err;
    num-=ret;
    buf+=ret;
  }
  close(fd);
  return;
err:
  debug(D_CRITICAL, "could not open /dev/random");
  exit(1);
}

void psync_ssl_rand_weak(unsigned char *buf, int num){
  sqlite3_randomness(num, buf);
}

psync_rsa_t psync_ssl_gen_rsa(int bits){
  psync_rsa_t ret;
  SecKeyRef public_key, private_key;
  CFDictionaryRef dict;
  CFTypeRef keys[2], values[2];
  OSStatus st;
  keys[0]=kSecAttrKeyType;
  values[0]=kSecAttrKeyTypeRSA;
  keys[1]=kSecAttrKeySizeInBits;
  values[1]=CFNumberCreate(NULL, kCFNumberIntType, &bits);
  dict=CFDictionaryCreate(NULL, keys, values, ARRAY_SIZE(keys), NULL, NULL);
  st=SecKeyGeneratePair(dict, &public_key, &private_key);
  CFRelease(dict);
  CFRelease(values[1]);
  if (unlikely(st!=errSecSuccess)){
    debug(D_ERROR, "RSA key generation failed with error %d", (int)st);
    return PSYNC_INVALID_RSA;
  }
  ret=psync_new(psync_rsa_struct_t);
  ret->public_key=public_key;
  ret->private_key=private_key;
  return ret;
}

void psync_ssl_free_rsa(psync_rsa_t rsa){
  CFRelease(rsa->public_key);
  CFRelease(rsa->private_key);
  psync_free(rsa);
}

psync_rsa_publickey_t psync_ssl_rsa_get_public(psync_rsa_t rsa){
  CFRetain(rsa->public_key);
  return rsa->public_key;
}

void psync_ssl_rsa_free_public(psync_rsa_publickey_t key){
  CFRelease(key);
}

psync_rsa_privatekey_t psync_ssl_rsa_get_private(psync_rsa_t rsa){
  CFRetain(rsa->private_key);
  return rsa->private_key;
}

void psync_ssl_rsa_free_private(psync_rsa_privatekey_t key){
  CFRelease(key);
}

psync_binary_rsa_key_t psync_ssl_rsa_public_to_binary(psync_rsa_publickey_t rsa){
  psync_binary_rsa_key_t ret;
  CFDictionaryRef dict;
  CFTypeRef keys[4], values[4], arrval[1];
  CFArrayRef arr;
  OSStatus st;
  CFDataRef data;
  CFIndex len;
  arrval[0]=rsa;
  arr=CFArrayCreate(NULL, arrval, 1, NULL);
  keys[0]=kSecAttrKeyType;
  values[0]=kSecAttrKeyTypeRSA;
  keys[1]=kSecReturnData;
  values[1]=kCFBooleanTrue;
  keys[2]=kSecClass;
  values[2]=kSecClassKey;
  keys[3]=kSecMatchItemList;
  values[3]=arr;
  dict=CFDictionaryCreate(NULL, keys, values, ARRAY_SIZE(keys), NULL, NULL);
  data=NULL;
  st=SecItemCopyMatching(dict, (CFTypeRef *)&data);
  CFRelease(dict);
  CFRelease(arr);
  if (unlikely_log(st!=errSecSuccess))
    return PSYNC_INVALID_BIN_RSA;
  len=CFDataGetLength(data);
  ret=psync_malloc(offsetof(psync_encrypted_data_struct_t, data)+len);
  ret->datalen=len;
  memcpy(ret->data, CFDataGetBytePtr(data), len);
  CFRelease(data);
  return ret;
}

psync_binary_rsa_key_t psync_ssl_rsa_private_to_binary(psync_rsa_privatekey_t rsa){
  psync_binary_rsa_key_t ret;
  CFDictionaryRef dict;
  CFTypeRef keys[4], values[4], arrval[1];
  CFArrayRef arr;
  OSStatus st;
  CFDataRef data;
  CFIndex len;
  arrval[0]=rsa;
  arr=CFArrayCreate(NULL, arrval, 1, NULL);
  keys[0]=kSecAttrKeyType;
  values[0]=kSecAttrKeyTypeRSA;
  keys[1]=kSecReturnData;
  values[1]=kCFBooleanTrue;
  keys[2]=kSecClass;
  values[2]=kSecAttrKeyClassPrivate;
  keys[3]=kSecMatchItemList;
  values[3]=arr;
  dict=CFDictionaryCreate(NULL, keys, values, ARRAY_SIZE(keys), NULL, NULL);
  data=NULL;
  st=SecItemCopyMatching(dict, (CFTypeRef *)&data);
  CFRelease(dict);
  CFRelease(arr);
  if (unlikely_log(st!=errSecSuccess))
    return PSYNC_INVALID_BIN_RSA;
  len=CFDataGetLength(data);
  ret=psync_malloc(offsetof(psync_encrypted_data_struct_t, data)+len);
  ret->datalen=len;
  memcpy(ret->data, CFDataGetBytePtr(data), len);
  CFRelease(data);
  return ret;
}
psync_rsa_publickey_t psync_ssl_rsa_binary_to_public(psync_binary_rsa_key_t bin){
  /* on iOS SecKeyCreateRSAPublicKey can be used */
  SecKeyRef ret;
  SecExternalFormat form;
  SecExternalItemType type;
  CFDataRef data;
  CFArrayRef out;
  OSStatus st;
  
  form=kSecFormatUnknown;
  type=kSecItemTypePublicKey;
  data=CFDataCreate(NULL, bin->data, bin->datalen);
  st=SecItemImport(data, NULL, &form, &type, 0, NULL, NULL, &out);
  CFRelease(data);
  if (unlikely_log(st!=errSecSuccess))
    PSYNC_INVALID_RSA;    
  ret=(SecKeyRef)CFArrayGetValueAtIndex(out, 0);
  if (unlikely_log(ret==NULL)){
    CFRelease(out);
    return PSYNC_INVALID_RSA;
  }  
  CFRetain(ret);
  CFRelease(out);
  return ret;
}

psync_rsa_privatekey_t psync_ssl_rsa_binary_to_private(psync_binary_rsa_key_t bin){
  SecKeyRef ret;
  SecExternalFormat form;
  SecExternalItemType type;
  CFDataRef data;
  CFArrayRef out;
  OSStatus st;
  
  form=kSecFormatUnknown;
  type=kSecItemTypePrivateKey;
  data=CFDataCreate(NULL, bin->data, bin->datalen);
  st=SecItemImport(data, NULL, &form, &type, 0, NULL, NULL, &out);
  CFRelease(data);
  if (unlikely_log(st!=errSecSuccess))
    PSYNC_INVALID_RSA;    
  ret=(SecKeyRef)CFArrayGetValueAtIndex(out, 0);
  if (unlikely_log(ret==NULL)){
    CFRelease(out);
    return PSYNC_INVALID_RSA;
  }  
  CFRetain(ret);
  CFRelease(out);
  return ret;
}


static void PKCS5_PBKDF2_HMAC_SHA1(const char *pass, size_t passlen, const unsigned char *salt, size_t saltlen,
    unsigned long cnt, size_t keylen, unsigned char *out){
  unsigned char sha1hmacbin[CC_SHA1_DIGEST_LENGTH], itmp[4];
  size_t clen;
  uint32_t iter, i, j;
  CCHmacContext hctx;
  iter=1;
  while (keylen){
    if (keylen>CC_SHA1_DIGEST_LENGTH)
      clen=CC_SHA1_DIGEST_LENGTH;
    else
      clen=keylen;
    itmp[0]=(unsigned char)((iter>>24)&0xff);
    itmp[1]=(unsigned char)((iter>>16)&0xff);
    itmp[2]=(unsigned char)((iter>>8)&0xff);
    itmp[3]=(unsigned char)(iter&0xff);
    CCHmacInit(&hctx, kCCHmacAlgSHA1, pass, passlen);
    CCHmacUpdate(&hctx, salt, saltlen);
    CCHmacUpdate(&hctx, itmp, 4);
    CCHmacFinal(&hctx, sha1hmacbin);
    memcpy(out, sha1hmacbin, clen);
    for (i=1; i<cnt; i++){
      CCHmac(kCCHmacAlgSHA1, pass, passlen, sha1hmacbin, CC_SHA1_DIGEST_LENGTH, sha1hmacbin);
      for(j=0; j<clen; j++)
        out[j]^=sha1hmacbin[j];
    }
    out+=clen;
    keylen-=clen;
    iter++;
  }
}

psync_symmetric_key_t psync_ssl_gen_symmetric_key_from_pass(const char *password, size_t keylen, const char *salt, size_t saltlen){
  psync_symmetric_key_t key=(psync_symmetric_key_t)psync_malloc(keylen+offsetof(psync_symmetric_key_struct_t, key));
  key->keylen=keylen;
  PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), (const unsigned char *)salt, 
                                saltlen, PSYNC_CRYPTO_PASS_TO_KEY_ITERATIONS, keylen, key->key);
  return key;
/*  CFDictionaryRef dict;
  CFTypeRef keys[4], values[4];
  CFStringRef pass;
  SecKeyRef ret;
  int num;
  keys[0]=kSecAttrSalt;
  values[0]=CFDataCreate(kCFAllocatorDefault, (const unsigned char *)PSYNC_CRYPTO_PASS_TO_KEY_SALT, sizeof(PSYNC_CRYPTO_PASS_TO_KEY_SALT)-1);
  keys[1]=kSecAttrPRF;
  values[1]=kSecAttrPRFHmacAlgSHA1;
  num=PSYNC_CRYPTO_PASS_TO_KEY_ITERATIONS;
  keys[2]=kSecAttrRounds;
  values[2]=CFNumberCreate(NULL, kCFNumberIntType, &num);
  num=keylen*8;
  keys[3]=kSecAttrKeySizeInBits;
  values[3]=CFNumberCreate(NULL, kCFNumberIntType, &num);
  dict=CFDictionaryCreate(NULL, keys, values, ARRAY_SIZE(keys), NULL, NULL);
  pass=CFStringCreateWithCStringNoCopy(NULL, password, kCFStringEncodingUTF8, NULL);
  ret=SecKeyDeriveFromPassword(pass, dict, NULL);
  CFRelease(pass);
  CFRelease(dict);
  CFRelease(values[0]);
  CFRelease(values[2]);
  CFRelease(values[3]);
  return ret;*/
}

psync_encrypted_symmetric_key_t psync_ssl_rsa_encrypt_symmetric_key(psync_rsa_publickey_t rsa, const psync_symmetric_key_t key){
  size_t elen;
  psync_encrypted_symmetric_key_t ret;
  OSStatus st;
  elen=SecKeyGetBlockSize(rsa);
  ret=(psync_encrypted_symmetric_key_t)psync_malloc(offsetof(psync_encrypted_data_struct_t, data)+elen);
  st=SecKeyEncrypt(rsa, kSecPaddingOAEP, key->key, key->keylen, ret->data, &elen);
  if (unlikely_log(st!=errSecSuccess)){
    psync_free(ret);
    return PSYNC_INVALID_ENC_SYM_KEY;
  }
  ret->datalen=elen;
  return ret;
}

psync_symmetric_key_t psync_ssl_rsa_decrypt_symmetric_key(psync_rsa_privatekey_t rsa, const psync_encrypted_symmetric_key_t enckey){
  unsigned char buff[2048];
  size_t len;
  psync_symmetric_key_t ret;
  OSStatus st;
  st=SecKeyDecrypt(rsa, kSecPaddingOAEP, enckey->data, enckey->datalen, buff, &len);
  if (unlikely_log(st!=errSecSuccess))
    return PSYNC_INVALID_SYM_KEY;
  ret=(psync_symmetric_key_t)psync_malloc(offsetof(psync_symmetric_key_struct_t, key)+len);
  ret->keylen=len;
  memcpy(ret->key, buff, len);
  return ret;
}

psync_aes256_encoder psync_ssl_aes256_create_encoder(psync_symmetric_key_t key){
  CCCryptorRef ret;
  assert(key->keylen>=PSYNC_AES256_KEY_SIZE);
  if (unlikely_log(CCCryptorCreate(kCCEncrypt, kCCAlgorithmAES128, kCCOptionECBMode, key->key, PSYNC_AES256_KEY_SIZE, NULL, &ret)!=kCCSuccess))
    return PSYNC_INVALID_ENCODER;
  else
    return ret;
}

void psync_ssl_aes256_free_encoder(psync_aes256_encoder aes){
  CCCryptorRelease(aes);
}

psync_aes256_encoder psync_ssl_aes256_create_decoder(psync_symmetric_key_t key){
  CCCryptorRef ret;
  assert(key->keylen>=PSYNC_AES256_KEY_SIZE);
  if (unlikely_log(CCCryptorCreate(kCCDecrypt, kCCAlgorithmAES128, kCCOptionECBMode, key->key, PSYNC_AES256_KEY_SIZE, NULL, &ret)!=kCCSuccess))
    return PSYNC_INVALID_ENCODER;
  else
    return ret;
}

void psync_ssl_aes256_free_decoder(psync_aes256_encoder aes){
  CCCryptorRelease(aes);
}
