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

#include "pcompat.h"
#include "psettings.h"
#include "plibs.h"
#include "ptimer.h"
#include "pstatus.h"
#include "pssl.h"
#include "pdownload.h"
#include "pnetlibs.h"
#include "papi.h"
#include "pp2p.h"
#include "pcrypto.h"
#include "pfolder.h"
#include <string.h>

#define P2P_ENCTYPE_RSA_AES 0

typedef uint32_t packet_type_t;
typedef uint32_t packet_id_t;
typedef uint32_t packet_resp_t;

typedef PSYNC_PACKED_STRUCT {
  packet_type_t type;
  unsigned char hashstart[4];
  uint64_t filesize;
  unsigned char rand[PSYNC_HASH_BLOCK_SIZE-PSYNC_HASH_DIGEST_HEXLEN];
  unsigned char genhash[PSYNC_HASH_DIGEST_HEXLEN];
  unsigned char computername[PSYNC_HASH_DIGEST_HEXLEN];
} packet_check;

typedef PSYNC_PACKED_STRUCT {
  packet_resp_t type;
  uint32_t port;
  unsigned char rand[PSYNC_HASH_BLOCK_SIZE-PSYNC_HASH_DIGEST_HEXLEN];
  unsigned char genhash[PSYNC_HASH_DIGEST_HEXLEN];
} packet_check_resp;

typedef PSYNC_PACKED_STRUCT {
  packet_type_t type;
  unsigned char hashstart[4];
  uint64_t filesize;
  uint32_t keylen;
  uint32_t tokenlen;
  unsigned char rand[PSYNC_HASH_BLOCK_SIZE-PSYNC_HASH_DIGEST_HEXLEN];
  unsigned char genhash[PSYNC_HASH_DIGEST_HEXLEN];
  unsigned char computername[PSYNC_HASH_DIGEST_HEXLEN];
} packet_get;

static const int on=1;

static const size_t min_packet_size[]={
#define P2P_WAKE 0
  sizeof(packet_type_t),
#define P2P_CHECK 1
  sizeof(packet_check),
#define P2P_GET 2
  sizeof(packet_get)
};

#define P2P_RESP_NOPE   0
#define P2P_RESP_HAVEIT 1
#define P2P_RESP_WAIT   2

static pthread_mutex_t p2pmutex=PTHREAD_MUTEX_INITIALIZER;

static psync_socket_t udpsock;
static int files_serving=0;
static int running=0;
static int tcpport;

static char computername[PSYNC_HASH_DIGEST_HEXLEN];

static const uint32_t requiredstatuses[]={
  PSTATUS_COMBINE(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_PROVIDED),
  PSTATUS_COMBINE(PSTATUS_TYPE_RUN, PSTATUS_RUN_RUN),
  PSTATUS_COMBINE(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_ONLINE)
};

static struct sockaddr_storage paddr;
static socklen_t paddrlen;

static psync_rsa_publickey_t psync_rsa_public=PSYNC_INVALID_RSA;
static psync_rsa_privatekey_t psync_rsa_private=PSYNC_INVALID_RSA;
static psync_binary_rsa_key_t psync_rsa_public_bin=PSYNC_INVALID_BIN_RSA;

PSYNC_PURE static const char *p2p_get_address(void *addr){
  if (((struct sockaddr_in *)addr)->sin_family==AF_INET)
    return inet_ntoa(((struct sockaddr_in *)addr)->sin_addr);
  else{
#if defined(P_OS_POSIX)
    static char buff[80];
    return inet_ntop(AF_INET6, &((struct sockaddr_in6 *)addr)->sin6_addr, buff, sizeof(buff));
#else
    return "IPv6 address"; /* inet_ntop on Windows is Vista+ */
#endif
  }
}

PSYNC_PURE static const char *p2p_get_peer_address(){
  if (paddr.ss_family==AF_INET)
    return inet_ntoa(((struct sockaddr_in *)&paddr)->sin_addr);
  else{
#if defined(P_OS_POSIX)
    static char buff[80];
    return inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&paddr)->sin6_addr, buff, sizeof(buff));
#else
    return "IPv6 address"; /* inet_ntop on Windows is Vista+ */
#endif
  }
}

static psync_fileid_t psync_p2p_has_file(const unsigned char *hashstart, const unsigned char *genhash, const unsigned char *rand, uint64_t filesize,
                                         unsigned char *realhash){
  psync_sql_res *res;
  psync_variant_row row;
  psync_fileid_t ret;
  unsigned char hashsource[PSYNC_HASH_BLOCK_SIZE], hashbin[PSYNC_HASH_DIGEST_LEN], hashhex[PSYNC_HASH_DIGEST_HEXLEN];
  char like[PSYNC_P2P_HEXHASH_BYTES+1];
  memcpy(like, hashstart, PSYNC_P2P_HEXHASH_BYTES);
  like[PSYNC_P2P_HEXHASH_BYTES]='%';
  memcpy(hashsource+PSYNC_HASH_DIGEST_HEXLEN, rand, PSYNC_HASH_BLOCK_SIZE-PSYNC_HASH_DIGEST_HEXLEN);
  res=psync_sql_query_rdlock("SELECT id, checksum FROM localfile WHERE checksum LIKE ? AND size=?");
  psync_sql_bind_lstring(res, 1, like, PSYNC_P2P_HEXHASH_BYTES+1);
  psync_sql_bind_uint(res, 2, filesize);
  while ((row=psync_sql_fetch_row(res))){
    assertw(row[1].type==PSYNC_TSTRING && row[1].length==PSYNC_HASH_DIGEST_HEXLEN);
    memcpy(hashsource, row[1].str, PSYNC_HASH_DIGEST_HEXLEN);
    psync_hash(hashsource, PSYNC_HASH_BLOCK_SIZE, hashbin);
    psync_binhex(hashhex, hashbin, PSYNC_HASH_DIGEST_LEN);
    if (!memcmp(hashhex, genhash, PSYNC_HASH_DIGEST_HEXLEN)){
      if (realhash)
        memcpy(realhash, row[1].str, PSYNC_HASH_DIGEST_HEXLEN);
      ret=psync_get_number(row[0]);
      psync_sql_free_result(res);
      return ret;
    }
  }
  psync_sql_free_result(res);
  return 0;
}

static int psync_p2p_is_downloading(const unsigned char *hashstart, const unsigned char *genhash, const unsigned char *rand, uint64_t filesize,
                                    unsigned char *realhash){
  downloading_files_hashes *hashes;
  unsigned char hashsource[PSYNC_HASH_BLOCK_SIZE], hashbin[PSYNC_HASH_DIGEST_LEN], hashhex[PSYNC_HASH_DIGEST_HEXLEN];
  size_t i;
  hashes=psync_get_downloading_hashes();
  for (i=0; i<hashes->hashcnt; i++){
    if (memcmp(hashstart, hashes->hashes[i], PSYNC_P2P_HEXHASH_BYTES))
      continue;
    memcpy(hashsource, hashes->hashes[i], PSYNC_HASH_DIGEST_HEXLEN);
    memcpy(hashsource+PSYNC_HASH_DIGEST_HEXLEN, rand, PSYNC_HASH_BLOCK_SIZE-PSYNC_HASH_DIGEST_HEXLEN);
    psync_hash(hashsource, PSYNC_HASH_BLOCK_SIZE, hashbin);
    psync_binhex(hashhex, hashbin, PSYNC_HASH_DIGEST_LEN);
    if (!memcmp(hashhex, genhash, PSYNC_HASH_DIGEST_HEXLEN)){
      if (realhash)
        memcpy(realhash, hashsource, PSYNC_HASH_DIGEST_HEXLEN);
      psync_free(hashes);
      return 1;
    }
  }
  psync_free(hashes);
  return 0;
}

static void psync_p2p_check(const packet_check *packet){
  unsigned char hashhex[PSYNC_HASH_DIGEST_HEXLEN], hashsource[PSYNC_HASH_BLOCK_SIZE], hashbin[PSYNC_HASH_DIGEST_LEN];
  packet_check_resp resp;
  if (!memcmp(packet->computername, computername, PSYNC_HASH_DIGEST_HEXLEN))
    return;
  if (psync_p2p_has_file(packet->hashstart, packet->genhash, packet->rand, packet->filesize, hashhex))
    resp.type=P2P_RESP_HAVEIT;
  else if (psync_p2p_is_downloading(packet->hashstart, packet->genhash, packet->rand, packet->filesize, hashhex))
    resp.type=P2P_RESP_WAIT;
  else
    return;
  resp.port=tcpport;
  psync_ssl_rand_weak(resp.rand, sizeof(resp.rand));
  memcpy(hashsource, hashhex, PSYNC_HASH_DIGEST_HEXLEN);
  memcpy(hashsource+PSYNC_HASH_DIGEST_HEXLEN, resp.rand, sizeof(resp.rand));
  psync_hash(hashsource, PSYNC_HASH_BLOCK_SIZE, hashbin);
  psync_binhex(resp.genhash, hashbin, PSYNC_HASH_DIGEST_LEN);
  debug(D_NOTICE, "replying with %u to a check from %s, looking for %."NTO_STR(PSYNC_HASH_DIGEST_HEXLEN)"s", (unsigned int)resp.type, p2p_get_peer_address(), hashhex);
  if (files_serving)
    psync_milisleep(files_serving*10);
  if (resp.type==P2P_RESP_WAIT)
    psync_milisleep(PSYNC_P2P_INITIAL_TIMEOUT/4);
  if (!sendto(udpsock, (const char *)&resp, sizeof(resp), 0, (const struct sockaddr *)&paddr, paddrlen))
    debug(D_WARNING, "sendto to %s failed", p2p_get_peer_address());
}

static void psync_p2p_process_packet(const char *packet, size_t plen){
  packet_type_t type;
  if (unlikely(plen<sizeof(packet_type_t)))
    return;
  type=*((packet_type_t *)packet);
  if (type>=ARRAY_SIZE(min_packet_size) || min_packet_size[type]>plen)
    return;
  debug(D_NOTICE, "got %u packet from %s", (unsigned int)type, p2p_get_peer_address());
  switch (type){
    case P2P_WAKE:
      break;
    case P2P_CHECK:
      psync_p2p_check((packet_check *)packet);
      debug(D_NOTICE, "processed P2P packed");
      break;
    default:
      debug(D_BUG, "handler for packet type %u not implemented", (unsigned)type);
      break;
  }
}

static int socket_write_all(psync_socket_t sock, const void *buff, size_t len){
  ssize_t ret;
  while (len){
    ret=psync_write_socket(sock, buff, len);
    if (ret==SOCKET_ERROR){
      if (psync_sock_err()==P_INTR || psync_sock_err()==P_AGAIN || psync_sock_err()==P_WOULDBLOCK)
        continue;
      return -1;
    }
    buff=(const char *)buff+ret;
    len-=ret;
  }
  return 0;
}

static int socket_read_all(psync_socket_t sock, void *buff, size_t len){
  ssize_t ret;
  while (len){
    ret=psync_read_socket(sock, buff, len);
    if (ret==SOCKET_ERROR){
      if (psync_sock_err()==P_INTR || psync_sock_err()==P_AGAIN || psync_sock_err()==P_WOULDBLOCK)
        continue;
      return -1;
    }
    else if (ret==0)
      return -1;
    buff=(char *)buff+ret;
    len-=ret;
  }
  return 0;
}

static int check_token(char *token, uint32_t tlen, unsigned char *key, uint32_t keylen, unsigned char *hashhex){
  binparam params[]={P_LSTR(PSYNC_CHECKSUM, hashhex, PSYNC_HASH_DIGEST_HEXLEN),
                     P_LSTR("keydata", key, keylen), P_LSTR("token", token, tlen)};
  psync_socket *api;
  binresult *res;
  uint64_t result;
  api=psync_apipool_get();
  if (unlikely_log(!api))
    return 0;
  res=send_command(api, "checkfileownershiptoken", params);
  if (unlikely_log(!res)){
    psync_apipool_release_bad(api);
    return 0;
  }
  psync_apipool_release(api);
  result=psync_find_result(res, "result", PARAM_NUM)->num;
  psync_free(res);
  return result?0:1;
}

static void psync_p2p_tcphandler(void *ptr){
  packet_get packet;
  psync_fileid_t localfileid;
  psync_binary_rsa_key_t binpubrsa;
  psync_rsa_publickey_t pubrsa;
  psync_symmetric_key_t aeskey;
  psync_encrypted_symmetric_key_t encaeskey;
  psync_crypto_aes256_ctr_encoder_decoder_t encoder;
  char *token, *localpath;
  uint64_t off;
  size_t rd;
  psync_socket_t sock;
  psync_file_t fd;
  uint32_t keylen, enctype;
  unsigned char hashhex[PSYNC_HASH_DIGEST_HEXLEN], buff[4096];
  sock=*((psync_socket_t *)ptr);
  psync_free(ptr);
  debug(D_NOTICE, "got tcp connection");
  if (unlikely_log(socket_read_all(sock, &packet, sizeof(packet))))
    goto err0;
  if (unlikely_log(packet.keylen>PSYNC_P2P_RSA_SIZE) || unlikely_log(packet.tokenlen>512)) /* lets allow 8 times larger keys than we use */
    goto err0;
  localfileid=psync_p2p_has_file(packet.hashstart, packet.genhash, packet.rand, packet.filesize, hashhex);
  if (!localfileid){
    debug(D_WARNING, "got request for file that we do not have");
    goto err0;
  }
  binpubrsa=psync_ssl_alloc_binary_rsa(packet.keylen);
  if (unlikely_log(socket_read_all(sock, binpubrsa->data, binpubrsa->datalen))){
    psync_free(binpubrsa);
    goto err0;
  }
  token=psync_new_cnt(char, packet.tokenlen);
  if (unlikely_log(socket_read_all(sock, token, packet.tokenlen)) ||
      unlikely_log(!check_token(token, packet.tokenlen, binpubrsa->data, packet.keylen, hashhex))){
    psync_free(binpubrsa);
    psync_free(token);
    goto err0;
  }
  psync_free(token);
  pubrsa=psync_ssl_rsa_binary_to_public(binpubrsa);
  psync_free(binpubrsa);
  if (unlikely_log(pubrsa==PSYNC_INVALID_RSA))
    goto err0;
  localpath=psync_local_path_for_local_file(localfileid, NULL);
  if (unlikely_log(!localpath))
    goto err0;
  fd=psync_file_open(localpath, P_O_RDONLY, 0);
  debug(D_NOTICE, "sending file %s to peer", localpath);
  psync_free(localpath);
  if (fd==INVALID_HANDLE_VALUE){
    debug(D_WARNING, "could not open local file %lu", (unsigned long)localfileid);
    goto err0;
  }
  aeskey=psync_crypto_aes256_ctr_gen_key();
  encaeskey=psync_ssl_rsa_encrypt_symmetric_key(pubrsa, aeskey);
  encoder=psync_crypto_aes256_ctr_encoder_decoder_create(aeskey);
  psync_ssl_free_symmetric_key(aeskey);
  keylen=encaeskey->datalen;
  enctype=P2P_ENCTYPE_RSA_AES;
  if (unlikely_log(encaeskey==PSYNC_INVALID_ENC_SYM_KEY) || unlikely_log(encoder==PSYNC_CRYPTO_INVALID_ENCODER) ||
      unlikely_log(socket_write_all(sock, &keylen, sizeof(keylen)) || socket_write_all(sock, &enctype, sizeof(enctype)) ||
                   socket_write_all(sock, encaeskey->data, encaeskey->datalen))){
    if (encaeskey!=PSYNC_INVALID_ENC_SYM_KEY)
      psync_free(encaeskey);
    if (encoder!=PSYNC_CRYPTO_INVALID_ENCODER)
      psync_crypto_aes256_ctr_encoder_decoder_free(encoder);
    psync_file_close(fd);
    goto err0;
  }
  psync_free(encaeskey);
  off=0;
  while (off<packet.filesize){
    if (packet.filesize-off<sizeof(buff))
      rd=packet.filesize-off;
    else
      rd=sizeof(buff);
    if (unlikely_log(psync_file_read(fd, buff, rd)!=rd))
      break;
    psync_crypto_aes256_ctr_encode_decode_inplace(encoder, buff, rd, off);
    if (unlikely_log(socket_write_all(sock, buff, rd)))
      break;
    off+=rd;
  }
  psync_crypto_aes256_ctr_encoder_decoder_free(encoder);
  psync_file_close(fd);
  debug(D_NOTICE, "file sent successfuly");
err0:
  psync_close_socket(sock);
}

static void psync_p2p_thread(){
  ssize_t ret;
  char buff[2048];
/*  struct sockaddr_in6 addr; */
  struct sockaddr_in addr4;
  psync_socket_t tcpsock, socks[2], *inconn;
  socklen_t sl;
  int sret;
  psync_wait_statuses_array(requiredstatuses, ARRAY_SIZE(requiredstatuses));
  tcpsock=INVALID_SOCKET;
/*  udpsock=psync_create_socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (unlikely_log(udpsock==INVALID_SOCKET)){*/
    udpsock=psync_create_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (unlikely_log(udpsock==INVALID_SOCKET))
      goto ex;
    setsockopt(udpsock, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on));
    memset(&addr4, 0, sizeof(addr4));
    addr4.sin_family=AF_INET;
    addr4.sin_port  =htons(PSYNC_P2P_PORT);
    addr4.sin_addr.s_addr=INADDR_ANY;
    if (unlikely_log(bind(udpsock, (struct sockaddr *)&addr4, sizeof(addr4))==SOCKET_ERROR))
      goto ex;
/*  }
  else{
    setsockopt(udpsock, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on));
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family=AF_INET6;
    addr.sin6_port  =htons(PSYNC_P2P_PORT);
    addr.sin6_addr  =in6addr_any;
    if (unlikely_log(bind(udpsock, (struct sockaddr *)&addr, sizeof(addr))==SOCKET_ERROR))
      goto ex;
  }
  tcpsock=psync_create_socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
  if (unlikely_log(tcpsock==INVALID_SOCKET)){*/
    tcpsock=psync_create_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (unlikely_log(tcpsock==INVALID_SOCKET))
      goto ex;
    setsockopt(tcpsock, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on));
    memset(&addr4, 0, sizeof(addr4));
    addr4.sin_family=AF_INET;
    addr4.sin_port  =htons(0);
    addr4.sin_addr.s_addr=INADDR_ANY;
    if (unlikely_log(bind(tcpsock, (struct sockaddr *)&addr4, sizeof(addr4))==SOCKET_ERROR))
      goto ex;
    sl=sizeof(addr4);
    if (unlikely_log(getsockname(tcpsock, (struct sockaddr *)&addr4, &sl)==SOCKET_ERROR))
      goto ex;
    tcpport=ntohs(addr4.sin_port);
/*  }
  else{
    setsockopt(tcpsock, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on));
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family=AF_INET6;
    addr.sin6_port  =htons(0);
    addr.sin6_addr  =in6addr_any;
    if (unlikely_log(bind(tcpsock, (struct sockaddr *)&addr, sizeof(addr))==SOCKET_ERROR))
      goto ex;
    sl=sizeof(addr);
    if (unlikely_log(getsockname(tcpsock, (struct sockaddr *)&addr, &sl)==SOCKET_ERROR))
      goto ex;
    tcpport=ntohs(addr.sin6_port);
  }*/
  if (unlikely_log(listen(tcpsock, 2)))
    goto ex;
  socks[0]=udpsock;
  socks[1]=tcpsock;
  while (psync_do_run){
    if (unlikely(!psync_setting_get_bool(_PS(p2psync)))){
      pthread_mutex_lock(&p2pmutex);
      if (!psync_setting_get_bool(_PS(p2psync))){
        running=0;
        psync_close_socket(tcpsock);
        psync_close_socket(udpsock);
        pthread_mutex_unlock(&p2pmutex);
        return;
      }
      pthread_mutex_unlock(&p2pmutex);
    }
    psync_wait_statuses_array(requiredstatuses, ARRAY_SIZE(requiredstatuses));
    sret=psync_select_in(socks, 2, -1);
    if (unlikely_log(sret==-1)){
      psync_milisleep(1);
      continue;
    }
    if (sret==0){
      paddrlen=sizeof(paddr);
      ret=recvfrom(udpsock, buff, sizeof(buff), 0, (struct sockaddr *)&paddr, &paddrlen);
      if (likely_log(ret!=SOCKET_ERROR))
        psync_p2p_process_packet(buff, ret);
      else
        psync_milisleep(1);
    }
    else if (sret==1){
      inconn=psync_new(psync_socket_t);
      *inconn=accept(tcpsock, NULL, NULL);
      if (unlikely_log(*inconn==INVALID_SOCKET))
        psync_free(inconn);
      else
        psync_run_thread1("p2p tcp", psync_p2p_tcphandler, inconn);
    }
  }
ex:
  pthread_mutex_lock(&p2pmutex);
  running=0;
  psync_close_socket(tcpsock);
  psync_close_socket(udpsock);
  pthread_mutex_unlock(&p2pmutex);
}

static void psync_p2p_start(){
  pthread_mutex_lock(&p2pmutex);
  psync_run_thread("p2p", psync_p2p_thread);
  running=1;
  pthread_mutex_unlock(&p2pmutex);
}

static void psync_p2p_wake(){
  psync_socket_t sock;
  struct sockaddr_in addr;
  packet_type_t pack;
  sock=psync_create_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (unlikely_log(sock==INVALID_SOCKET))
    return;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family=AF_INET;
  addr.sin_port=htons(PSYNC_P2P_PORT);
  addr.sin_addr.s_addr=htonl(0x7f000001UL);
  pack=P2P_WAKE;
  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr))!=SOCKET_ERROR)
    assertw(psync_write_socket(sock, &pack, sizeof(pack))==sizeof(pack));
  psync_close_socket(sock);
}

void psync_p2p_init(){
  unsigned char computerbin[PSYNC_HASH_DIGEST_LEN];
  psync_ssl_rand_weak(computerbin, PSYNC_HASH_DIGEST_LEN);
  psync_binhex(computername, computerbin, PSYNC_HASH_DIGEST_LEN);
  psync_timer_exception_handler(psync_p2p_wake);
  if (!psync_setting_get_bool(_PS(p2psync)))
    return;
  psync_p2p_start();
}

void psync_p2p_change(){
  if (psync_setting_get_bool(_PS(p2psync)))
    psync_p2p_start();
  else
    psync_p2p_wake();
}

static int psync_p2p_check_rsa(){
  static pthread_mutex_t rsa_lock=PTHREAD_MUTEX_INITIALIZER;
  pthread_mutex_lock(&rsa_lock);
  if (psync_rsa_private==PSYNC_INVALID_RSA){
    psync_rsa_t rsa;
    psync_rsa_privatekey_t rsapriv;
    psync_rsa_publickey_t rsapub;
    psync_binary_rsa_key_t rsapubbin;
    debug(D_NOTICE, "generating %ubit RSA key", PSYNC_P2P_RSA_SIZE);
    rsa=psync_ssl_gen_rsa(PSYNC_P2P_RSA_SIZE);
    debug(D_NOTICE, "key generated");
    if (unlikely_log(rsa==PSYNC_INVALID_RSA))
      goto rete;
    rsapriv=psync_ssl_rsa_get_private(rsa);
    rsapub=psync_ssl_rsa_get_public(rsa);
    if (likely_log(rsapub!=PSYNC_INVALID_RSA))
      rsapubbin=psync_ssl_rsa_public_to_binary(rsapub);
    else
      rsapubbin=PSYNC_INVALID_BIN_RSA;
    psync_ssl_free_rsa(rsa);
    if (likely_log(rsapriv!=PSYNC_INVALID_RSA && rsapub!=PSYNC_INVALID_RSA && rsapubbin!=PSYNC_INVALID_BIN_RSA)){
      psync_rsa_private=rsapriv;
      psync_rsa_public=rsapub;
      psync_rsa_public_bin=rsapubbin;
      goto ret0;
    }
    else{
      if (rsapriv!=PSYNC_INVALID_RSA)
        psync_ssl_rsa_free_private(rsapriv);
      if (rsapub!=PSYNC_INVALID_RSA)
        psync_ssl_rsa_free_public(rsapub);
      if (rsapubbin!=PSYNC_INVALID_BIN_RSA)
        psync_ssl_rsa_free_binary(rsapubbin);
      goto rete;
    }
  }
ret0:
  pthread_mutex_unlock(&rsa_lock);
  return 0;
rete:
  pthread_mutex_unlock(&rsa_lock);
  return -1;
}

static int psync_p2p_get_download_token(psync_fileid_t fileid, const unsigned char *filehashhex, uint64_t fsize, unsigned char **token, size_t *tlen){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("fileid", fileid), P_NUM("filesize", fsize),
                     P_LSTR(PSYNC_CHECKSUM, filehashhex, PSYNC_HASH_DIGEST_HEXLEN),
                     P_LSTR("keydata", psync_rsa_public_bin->data, psync_rsa_public_bin->datalen)};
  psync_socket *api;
  binresult *res;
  const binresult *ctoken;
  *token=NULL; /* especially for gcc */
  *tlen=0;
  api=psync_apipool_get();
  if (unlikely_log(!api))
    return PSYNC_NET_TEMPFAIL;
  res=send_command(api, "getfileownershiptoken", params);
  if (unlikely_log(!res)){
    psync_apipool_release_bad(api);
    return PSYNC_NET_TEMPFAIL;
  }
  psync_apipool_release(api);
  if (unlikely_log(psync_find_result(res, "result", PARAM_NUM)->num!=0)){
    psync_free(res);
    return PSYNC_NET_PERMFAIL;
  }
  ctoken=psync_find_result(res, "token", PARAM_STR);
  *token=psync_malloc(ctoken->length+1);
  memcpy(*token, ctoken->str, ctoken->length+1);
  *tlen=ctoken->length;
  psync_free(res);
  return PSYNC_NET_OK;
}

static int psync_p2p_download(psync_socket_t sock, psync_fileid_t fileid, const unsigned char *filehashhex, uint64_t fsize, const char *filename){
  uint32_t keylen, enctype;
  psync_symmetric_key_t key;
  psync_encrypted_symmetric_key_t ekey;
  psync_crypto_aes256_ctr_encoder_decoder_t decoder;
  psync_hash_ctx hashctx;
  uint64_t off;
  size_t rd;
  psync_file_t fd;
  unsigned char buff[4096];
  unsigned char hashbin[PSYNC_HASH_DIGEST_LEN], hashhex[PSYNC_HASH_DIGEST_HEXLEN];
  if (unlikely_log(socket_read_all(sock, &keylen, sizeof(keylen)) || socket_read_all(sock, &enctype, sizeof(enctype))))
    return PSYNC_NET_TEMPFAIL;
  if (enctype!=P2P_ENCTYPE_RSA_AES){
    debug(D_ERROR, "unknown encryption type %u", (unsigned)enctype);
    return PSYNC_NET_PERMFAIL;
  }
  if (keylen>PSYNC_P2P_RSA_SIZE/8*2){ /* PSYNC_P2P_RSA_SIZE/8 is enough actually */
    debug(D_ERROR, "too long key - %u bytes", (unsigned)keylen);
    return PSYNC_NET_PERMFAIL;
  }
  ekey=psync_ssl_alloc_encrypted_symmetric_key(keylen);
  if (unlikely_log(socket_read_all(sock, ekey->data, keylen)) ||
    unlikely_log((key = psync_ssl_rsa_decrypt_symm_key_lock(psync_rsa_private, ekey)) == PSYNC_INVALID_SYM_KEY)) {
      //unlikely_log((key=psync_ssl_rsa_decrypt_symmetric_key(psync_rsa_private, ekey))==PSYNC_INVALID_SYM_KEY)){
    psync_free(ekey);
    return PSYNC_NET_TEMPFAIL;
  }
  psync_free(ekey);
  decoder=psync_crypto_aes256_ctr_encoder_decoder_create(key);
  psync_ssl_free_symmetric_key(key);
  if (decoder==PSYNC_CRYPTO_INVALID_ENCODER)
    return PSYNC_NET_PERMFAIL;
  fd=psync_file_open(filename, P_O_WRONLY, P_O_CREAT|P_O_TRUNC);
  if (unlikely(fd==INVALID_HANDLE_VALUE)){
    psync_crypto_aes256_ctr_encoder_decoder_free(decoder);
    debug(D_ERROR, "could not open %s", filename);
    return PSYNC_NET_PERMFAIL;
  }
  off=0;
  psync_hash_init(&hashctx);
  while (off<fsize){
    if (fsize-off>sizeof(buff))
      rd=sizeof(buff);
    else
      rd=fsize-off;
    if (unlikely_log(socket_read_all(sock, buff, rd)))
      goto err0;
    psync_crypto_aes256_ctr_encode_decode_inplace(decoder, buff, rd, off);
    if (unlikely_log(psync_file_write(fd, buff, rd)!=rd))
      goto err0;
    psync_hash_update(&hashctx, buff, rd);
    off+=rd;
  }
  psync_crypto_aes256_ctr_encoder_decoder_free(decoder);
  psync_file_close(fd);
  psync_hash_final(hashbin, &hashctx);
  psync_binhex(hashhex, hashbin, PSYNC_HASH_DIGEST_LEN);
  debug(D_NOTICE, "downloaded file %s from peer", filename);
  if (memcmp(hashhex, filehashhex, PSYNC_HASH_DIGEST_HEXLEN)){
    /* it is better to return permanent fail and let the block checksum algo to find bad blocks */
    debug(D_WARNING, "got bad checksum for file %s", filename);
    return PSYNC_NET_PERMFAIL;
  }
  else
    return PSYNC_NET_OK;
err0:
  psync_crypto_aes256_ctr_encoder_decoder_free(decoder);
  psync_file_close(fd);
  psync_hash_final(hashbin, &hashctx);
  return PSYNC_NET_TEMPFAIL;
}

int psync_p2p_check_download(psync_fileid_t fileid, const unsigned char *filehashhex, uint64_t fsize, const char *filename){
  struct sockaddr_in6 addr;
  fd_set rfds;
  packet_check pct1;
  packet_get pct2;
  packet_check_resp resp;
  struct timeval tv;
  psync_interface_list_t *il;
  psync_socket_t *sockets;
  size_t i, tlen;
  psync_socket_t sock, msock;
  packet_resp_t bresp;
  unsigned char hashsource[PSYNC_HASH_BLOCK_SIZE], hashbin[PSYNC_HASH_DIGEST_LEN], hashhex[PSYNC_HASH_DIGEST_HEXLEN];
  unsigned char *token;
  socklen_t slen;
  int sret;
  if (!psync_setting_get_bool(_PS(p2psync)))
    return PSYNC_NET_PERMFAIL;
  debug(D_NOTICE, "sending P2P_CHECK for file with hash %."NTO_STR(PSYNC_HASH_DIGEST_HEXLEN)"s", filehashhex);
  pct1.type=P2P_CHECK;
  memcpy(pct1.hashstart, filehashhex, PSYNC_P2P_HEXHASH_BYTES);
  pct1.filesize=fsize;
  psync_ssl_rand_weak(pct1.rand, sizeof(pct1.rand));
  memcpy(hashsource, filehashhex, PSYNC_HASH_DIGEST_HEXLEN);
  memcpy(hashsource+PSYNC_HASH_DIGEST_HEXLEN, pct1.rand, sizeof(pct1.rand));
  psync_hash(hashsource, PSYNC_HASH_BLOCK_SIZE, hashbin);
  psync_binhex(pct1.genhash, hashbin, PSYNC_HASH_DIGEST_LEN);
  memcpy(pct1.computername, computername, PSYNC_HASH_DIGEST_HEXLEN);
  il=psync_list_ip_adapters();
  sockets=psync_new_cnt(psync_socket_t, il->interfacecnt);
  FD_ZERO(&rfds);
  msock=0;
  for (i=0; i<il->interfacecnt; i++){
    sockets[i]=INVALID_SOCKET;
    sock=psync_create_socket(il->interfaces[i].address.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if (unlikely(sock==INVALID_SOCKET)){
      debug(D_NOTICE, "could not create a socket for address family %u", (unsigned)il->interfaces[i].address.ss_family);
      continue;
    }
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on));
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (const char *)&on, sizeof(on));
    if (unlikely_log(bind(sock, (struct sockaddr *)&il->interfaces[i].address, il->interfaces[i].addrsize)==SOCKET_ERROR)){
      psync_close_socket(sock);
      continue;
    }
    if (il->interfaces[i].broadcast.ss_family==AF_INET)
      ((struct sockaddr_in *)(&il->interfaces[i].broadcast))->sin_port=htons(PSYNC_P2P_PORT);
    else if (il->interfaces[i].broadcast.ss_family==AF_INET6)
      ((struct sockaddr_in6 *)(&il->interfaces[i].broadcast))->sin6_port=htons(PSYNC_P2P_PORT);
    if (sendto(sock, (const char *)&pct1, sizeof(pct1), 0, (struct sockaddr *)&il->interfaces[i].broadcast, il->interfaces[i].addrsize)!=SOCKET_ERROR){
      sockets[i]=sock;
      FD_SET(sock, &rfds);
      if (sock>=msock)
        msock=sock+1;
    }
    else
      psync_close_socket(sock);
  }
  if (unlikely_log(!msock))
    goto err_perm;
  tv.tv_sec=PSYNC_P2P_INITIAL_TIMEOUT/1000;
  tv.tv_usec=(PSYNC_P2P_INITIAL_TIMEOUT%1000)*1000;
  sret=select(msock, &rfds, NULL, NULL, &tv);
  if (sret==0 || unlikely_log(sret==SOCKET_ERROR))
    goto err_perm;
  bresp=P2P_RESP_NOPE;
  for (i=0; i<il->interfacecnt; i++)
    if (sockets[i]!=INVALID_SOCKET && FD_ISSET(sockets[i], &rfds)){
      slen=sizeof(addr);
      sret=recvfrom(sockets[i], (char *)&resp, sizeof(resp), 0, (struct sockaddr *)&addr, &slen);
      if (unlikely_log(sret==SOCKET_ERROR) || unlikely_log(sret<sizeof(resp)))
        continue;
      if (!memcmp(pct1.rand, resp.rand, sizeof(resp.rand))){
        debug(D_WARNING, "clients are supposed to generate random data, not to reuse mine");
        continue;
      }
      memcpy(hashsource, filehashhex, PSYNC_HASH_DIGEST_HEXLEN);
      memcpy(hashsource+PSYNC_HASH_DIGEST_HEXLEN, resp.rand, sizeof(resp.rand));
      psync_hash(hashsource, PSYNC_HASH_BLOCK_SIZE, hashbin);
      psync_binhex(hashhex, hashbin, PSYNC_HASH_DIGEST_LEN);
      if (unlikely_log(memcmp(hashhex, resp.genhash, PSYNC_HASH_DIGEST_HEXLEN)))
        continue;
      if (resp.type==P2P_RESP_HAVEIT){
        debug(D_NOTICE, "got P2P_RESP_HAVEIT");
        bresp=P2P_RESP_HAVEIT;
        break;
      }
      else if (resp.type==P2P_RESP_WAIT && bresp==P2P_RESP_NOPE)
        bresp=P2P_RESP_WAIT;
    }
  for (i=0; i<il->interfacecnt; i++)
    if (sockets[i]!=INVALID_SOCKET)
      psync_close_socket(sockets[i]);
  psync_free(il);
  psync_free(sockets);
  if (bresp==P2P_RESP_NOPE)
    goto err_perm2;
  else if (bresp==P2P_RESP_WAIT){
    uint32_t rnd;
    psync_ssl_rand_weak((unsigned char *)&rnd, sizeof(rnd));
    rnd&=0x7ff;
    psync_milisleep(PSYNC_P2P_SLEEP_WAIT_DOWNLOAD+rnd);
    goto err_temp2;
  }
  if (psync_p2p_check_rsa())
    goto err_perm2;
  sret=psync_p2p_get_download_token(fileid, filehashhex, fsize, &token, &tlen);
  debug(D_NOTICE, "got token");
  if (unlikely_log(sret!=PSYNC_NET_OK)){
    if (sret==PSYNC_NET_TEMPFAIL)
      goto err_temp2;
    else
      goto err_perm2;
  }
  if (addr.sin6_family==AF_INET6){
    sock=psync_create_socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    addr.sin6_port=htons(resp.port);
  }
  else if (addr.sin6_family==AF_INET){
    sock=psync_create_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ((struct sockaddr_in *)&addr)->sin_port=htons(resp.port);
  }
  else{
    debug(D_ERROR, "unknown address family %u", (unsigned)addr.sin6_family);
    goto err_perm2;
  }
  if (unlikely_log(sock==INVALID_SOCKET))
    goto err_perm3;
  if (unlikely(connect(sock, (struct sockaddr *)&addr, slen)==SOCKET_ERROR)){
    debug(D_WARNING, "could not connect to %s port %u", p2p_get_address(&addr), (unsigned)resp.port);
    goto err_perm3;
  }
  debug(D_NOTICE, "connected to peer");
  pct2.type=P2P_GET;
  memcpy(pct2.hashstart, filehashhex, PSYNC_P2P_HEXHASH_BYTES);
  pct2.filesize=fsize;
  pct2.keylen=psync_rsa_public_bin->datalen;
  pct2.tokenlen=tlen;
  memcpy(pct2.rand, pct1.rand, sizeof(pct1.rand));
  memcpy(pct2.genhash, pct1.genhash, sizeof(pct1.genhash));
  memcpy(pct2.computername, computername, PSYNC_HASH_DIGEST_HEXLEN);
  if (socket_write_all(sock, &pct2, sizeof(pct2)) ||
      socket_write_all(sock, psync_rsa_public_bin->data, psync_rsa_public_bin->datalen) ||
      socket_write_all(sock, token, tlen)){
    debug(D_WARNING, "writing to socket failed");
    goto err_temp3;
  }
  psync_free(token);
  sret=psync_p2p_download(sock, fileid, filehashhex, fsize, filename);
  psync_close_socket(sock);
  return sret;
err_perm3:
  psync_free(token);
  goto err_perm2;
err_perm:
  for (i=0; i<il->interfacecnt; i++)
    if (sockets[i]!=INVALID_SOCKET)
      psync_close_socket(sockets[i]);
  psync_free(il);
  psync_free(sockets);
err_perm2:
  return PSYNC_NET_PERMFAIL;
err_temp3:
  psync_close_socket(sock);
  psync_free(token);
err_temp2:
  return PSYNC_NET_TEMPFAIL;
}
