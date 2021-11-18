/* Copyright (c) 2014 Anton Titov.
 * Copyright (c) 2014 pCloud Ltd.
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
#include "pmemlock.h"
#include <string.h>
#include <stddef.h>

static void psync_ssl_free_psync_encrypted_data_t(psync_encrypted_data_t e){
  psync_ssl_memclean(e->data, e->datalen);
  psync_locked_free(e);
}

void psync_ssl_rsa_free_binary(psync_binary_rsa_key_t bin){
  psync_ssl_free_psync_encrypted_data_t(bin);
}

void psync_ssl_free_symmetric_key(psync_symmetric_key_t key){
  psync_ssl_memclean(key->key, key->keylen);
  psync_locked_free(key);
}

psync_encrypted_symmetric_key_t psync_ssl_alloc_encrypted_symmetric_key(size_t len){
  psync_encrypted_symmetric_key_t ret;
  ret=psync_malloc(offsetof(psync_encrypted_data_struct_t, data)+len);
  ret->datalen=len;
  return ret;
}

psync_encrypted_symmetric_key_t psync_ssl_copy_encrypted_symmetric_key(psync_encrypted_symmetric_key_t src){
  psync_encrypted_symmetric_key_t ret;
  ret=psync_malloc(offsetof(psync_encrypted_data_struct_t, data)+src->datalen);
  ret->datalen=src->datalen;
  memcpy(ret->data, src->data, src->datalen);
  return ret;
}
/**************************************************************************************************************************************************************************************/
psync_symmetric_key_t psync_ssl_rsa_decrypt_symm_key_lock(psync_rsa_privatekey_t* rsa, const psync_encrypted_symmetric_key_t* enckey) {
  psync_symmetric_key_t sym_key;

  debug(D_NOTICE, "Get RSA decrypt key lock.");
  pthread_mutex_lock(&rsa_decr_mutex);

  sym_key = psync_ssl_rsa_decrypt_symmetric_key(rsa, enckey);

  pthread_mutex_unlock(&rsa_decr_mutex);
  debug(D_NOTICE, "RSA decrypt key Lock released.");

  return sym_key;
}
/**************************************************************************************************************************************************************************************/