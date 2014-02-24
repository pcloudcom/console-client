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
#include <string.h>

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

static const int on=1;

static const size_t min_packet_size[]={
#define P2P_WAKE 0
  sizeof(packet_type_t),
#define P2P_CHECK 1
  sizeof(packet_check)
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

static psync_rsa_publickey_t rsa_public=PSYNC_INVALID_RSA;
static psync_rsa_privatekey_t rsa_private=PSYNC_INVALID_RSA;
static psync_binary_rsa_key_t rsa_public_bin=PSYNC_INVALID_BIN_RSA;

PSYNC_PURE static const char *p2p_get_peer_address(){
  if (paddr.ss_family==AF_INET)
    return inet_ntoa(((struct sockaddr_in *)&paddr)->sin_addr);
  else
    return "IPv6 address"; /* inet_ntop on Windows is Vista+ */
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
  res=psync_sql_query("SELECT id, checksum FROM localfile WHERE checksum LIKE ? AND size=?");
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

static void psync_p2p_check(packet_check *packet){
  unsigned char hashhex[PSYNC_HASH_DIGEST_HEXLEN], hashsource[PSYNC_HASH_BLOCK_SIZE], hashbin[PSYNC_HASH_DIGEST_LEN];
  packet_check_resp resp;
  int rlen;
  if (!memcpy(packet->computername, computername, PSYNC_HASH_DIGEST_HEXLEN))
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
  rlen=sizeof(resp);
  debug(D_NOTICE, "replying with %u to a check from %s", (unsigned int)resp.type, p2p_get_peer_address());
  if (files_serving)
    psync_milisleep(files_serving*10);
  if (!sendto(udpsock, (const char *)&resp, rlen, 0, (const struct sockaddr *)&paddr, paddrlen))
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
      break;
    default:
      debug(D_BUG, "handler for packet type %u not implemented", (unsigned)type);
      break;
  }
}

static void psync_p2p_thread(){
  ssize_t ret;
  char buff[2048];
  struct sockaddr_in6 addr;
  struct sockaddr_in addr4;
  psync_socket_t tcpsock;
  socklen_t sl;
  psync_wait_statuses_array(requiredstatuses, ARRAY_SIZE(requiredstatuses));
  tcpsock=INVALID_SOCKET;
  udpsock=psync_create_socket(AF_INET6, SOCK_DGRAM, 0);
  if (unlikely_log(udpsock==INVALID_SOCKET)){
    udpsock=psync_create_socket(AF_INET, SOCK_DGRAM, 0);
    if (unlikely_log(udpsock==INVALID_SOCKET))
      goto ex;
    setsockopt(udpsock, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on));
    memset(&addr4, 0, sizeof(addr4));
    addr4.sin_family=AF_INET;
    addr4.sin_port  =htons(PSYNC_P2P_PORT);
    addr4.sin_addr.s_addr=INADDR_ANY;
    if (unlikely_log(bind(udpsock, (struct sockaddr *)&addr4, sizeof(addr4))==SOCKET_ERROR))
      goto ex;
  }
  else{
    setsockopt(udpsock, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on));
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family=AF_INET6;
    addr.sin6_port  =htons(PSYNC_P2P_PORT);
    addr.sin6_addr  =in6addr_any;
    if (unlikely_log(bind(udpsock, (struct sockaddr *)&addr, sizeof(addr))==SOCKET_ERROR))
      goto ex;
  }
  tcpsock=psync_create_socket(AF_INET6, SOCK_STREAM, 0);
  if (unlikely_log(tcpsock==INVALID_SOCKET)){
    tcpsock=psync_create_socket(AF_INET, SOCK_STREAM, 0);
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
  }
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
  }
  if (unlikely_log(listen(tcpsock, 2)))
    goto ex;
  while (psync_do_run){
    if (unlikely(!psync_setting_get_bool(_PS(p2psync)))){
      pthread_mutex_lock(&p2pmutex);
      if (!psync_setting_get_bool(_PS(p2psync))){
        running=0;
        psync_close_socket(udpsock);
        pthread_mutex_unlock(&p2pmutex);
        return;
      }
      pthread_mutex_unlock(&p2pmutex);
    }
    psync_wait_statuses_array(requiredstatuses, ARRAY_SIZE(requiredstatuses));
    paddrlen=sizeof(paddr);
    ret=recvfrom(udpsock, buff, sizeof(buff), 0, (struct sockaddr *)&paddr, &paddrlen);
    if (likely_log(ret!=SOCKET_ERROR))
      psync_p2p_process_packet(buff, ret);
    else
      psync_milisleep(1);
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
  psync_run_thread(psync_p2p_thread);
  running=1;
  pthread_mutex_unlock(&p2pmutex);
}

static void psync_p2p_wake(){
  psync_socket_t sock;
  struct sockaddr_in addr;
  packet_type_t pack;
  sock=psync_create_socket(AF_INET, SOCK_DGRAM, 0);
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
  return;
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
  if (rsa_private==PSYNC_INVALID_RSA){
    psync_rsa_t rsa;
    psync_rsa_privatekey_t rsapriv;
    psync_rsa_publickey_t rsapub;
    psync_binary_rsa_key_t rsapubbin;
    rsa=psync_ssl_gen_rsa(PSYNC_P2P_RSA_SIZE);
    if (unlikely_log(rsa==PSYNC_INVALID_RSA))
      return -1;
    rsapriv=psync_ssl_rsa_get_private(rsa);
    rsapub=psync_ssl_rsa_get_public(rsa);
    if (likely_log(rsapub!=PSYNC_INVALID_RSA))
      rsapubbin=psync_ssl_rsa_public_to_binary(rsapub);
    else
      rsapubbin=PSYNC_INVALID_BIN_RSA;
    psync_ssl_free_rsa(rsa);
    if (likely_log(rsapriv!=PSYNC_INVALID_RSA && rsapub!=PSYNC_INVALID_RSA && rsapubbin!=PSYNC_INVALID_BIN_RSA)){
      rsa_private=rsapriv;
      rsa_public=rsapub;
      rsa_public_bin=rsapubbin;
      return 0;
    }
    else{
      if (rsapriv!=PSYNC_INVALID_RSA)
        psync_ssl_rsa_free_private(rsapriv);
      if (rsapub!=PSYNC_INVALID_RSA)
        psync_ssl_rsa_free_public(rsapub);
      if (rsapubbin!=PSYNC_INVALID_BIN_RSA)
        psync_ssl_rsa_free_binary(rsapubbin);
      return -1;
    }
    
  }
  else
    return 0;
}

static int psync_p2p_get_download_token(psync_fileid_t fileid, const unsigned char *filehashhex, uint64_t fsize, unsigned char **token, size_t *tlen){
  binparam params[]={P_STR("auth", psync_my_auth), P_NUM("fileid", fileid), P_NUM("filesize", fsize), 
                     P_LSTR(PSYNC_CHECKSUM, filehashhex, PSYNC_HASH_DIGEST_HEXLEN), 
                     P_LSTR("keydata", rsa_public_bin->data, rsa_public_bin->datalen)};
  psync_socket *api;
  binresult *res;
  const binresult *ctoken;
  api=psync_apipool_get();
  if (unlikely_log(!api))
    return PSYNC_NET_TEMPFAIL;
  res=send_command(api, "getfileownershiptoken", params);
  psync_apipool_release(api);
  if (unlikely_log(!res))
    return PSYNC_NET_TEMPFAIL;
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

int psync_p2p_check_download(psync_fileid_t fileid, const unsigned char *filehashhex, uint64_t fsize, const char *filename){
  fd_set rfds;
  packet_check pct1;
  packet_check_resp resp;
  struct timeval tv;
  psync_interface_list_t *il;
  psync_socket_t *sockets;
  size_t i, tlen;
  psync_socket_t sock, msock;
  packet_resp_t bresp;
  int sret;
  unsigned char hashsource[PSYNC_HASH_BLOCK_SIZE], hashbin[PSYNC_HASH_DIGEST_LEN];
  unsigned char *token;
  return PSYNC_NET_PERMFAIL;
  
  if (!psync_setting_get_bool(_PS(p2psync)))
    return PSYNC_NET_PERMFAIL;
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
    sock=psync_create_socket(il->interfaces[i].address.ss_family, SOCK_DGRAM, 0);
    if (sock==INVALID_SOCKET)
      continue;
    setsockopt(udpsock, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on));
    if (bind(sock, (struct sockaddr *)&il->interfaces[i].address, il->interfaces[i].addrsize)==SOCKET_ERROR){
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
  if (unlikely(!msock))
    goto err_perm;
  tv.tv_sec=PSYNC_P2P_INITIAL_TIMEOUT/1000;
  tv.tv_usec=(PSYNC_P2P_INITIAL_TIMEOUT%1000)*1000;
  sret=select(msock, &rfds, NULL, NULL, &tv);
  if (sret==0 || unlikely_log(sret==SOCKET_ERROR))
    goto err_perm;
  bresp=P2P_RESP_NOPE;
  for (i=0; i<il->interfacecnt; i++)
    if (sockets[i]!=INVALID_SOCKET && FD_ISSET(sockets[i], &rfds)){
      sret=recv(sockets[i], (char *)&resp, sizeof(resp), 0);
      if (sret==SOCKET_ERROR || sret<sizeof(resp))
        continue;
      memcpy(hashsource, filehashhex, PSYNC_HASH_DIGEST_HEXLEN);
      memcpy(hashsource+PSYNC_HASH_DIGEST_HEXLEN, resp.rand, sizeof(resp.rand));
      psync_hash(hashsource, PSYNC_HASH_BLOCK_SIZE, hashbin);
      psync_binhex(pct1.genhash, hashbin, PSYNC_HASH_DIGEST_LEN);
      if (unlikely_log(!memcmp(pct1.genhash, resp.genhash, PSYNC_HASH_DIGEST_HEXLEN)))
        continue;
      if (resp.type==P2P_RESP_HAVEIT)
        bresp=P2P_RESP_HAVEIT;
      else if (resp.type==P2P_RESP_WAIT && bresp==P2P_RESP_NOPE)
        bresp=P2P_RESP_WAIT;
    }
  if (bresp==P2P_RESP_NOPE)
    goto err_perm;
  else if (bresp==P2P_RESP_WAIT){
    psync_milisleep(PSYNC_P2P_SLEEP_WAIT_DOWNLOAD);
    goto err_temp;
  }
  if (psync_p2p_check_rsa())
    goto err_perm;
  sret=psync_p2p_get_download_token(fileid, filehashhex, fsize, &token, &tlen);
  if (unlikely_log(sret!=PSYNC_NET_OK)){
    if (sret==PSYNC_NET_TEMPFAIL)
      goto err_temp;
    else
      goto err_perm;
  }
  
err_perm:
  for (i=0; i<il->interfacecnt; i++)
    if (sockets[i]!=INVALID_SOCKET)
      psync_close_socket(sockets[i]);
  psync_free(il);
  psync_free(sockets);
  return PSYNC_NET_PERMFAIL;
err_temp:
  for (i=0; i<il->interfacecnt; i++)
    if (sockets[i]!=INVALID_SOCKET)
      psync_close_socket(sockets[i]);
  psync_free(il);
  psync_free(sockets);
  return PSYNC_NET_TEMPFAIL;
}
