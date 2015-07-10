/* Copyright (c) 2013-2015 pCloud Ltd.
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

#include "pcontacts.h"
#include "papi.h"
#include "plibs.h"
#include "pnetlibs.h"

#include <stdio.h>

int do_call_contactlist(result_visitor vis, void *param) {
  psync_socket *sock;
  binresult *bres;
  char *ids = NULL;
  int i;
  const binresult *contacts;
  
  binparam params[] = {P_STR("auth", psync_my_auth)};

  sock = psync_apipool_get();
  bres = send_command(sock, "contactlist", params);
  
  if (likely(bres))
    psync_apipool_release(sock);
  else {
    psync_apipool_release_bad(sock);
    debug(D_WARNING, "Send command returned invalid result.\n");
    return -1;
  }
  
  
  contacts = psync_find_result(bres, "contacts", PARAM_ARRAY);
  
  if (!contacts->length){
    psync_free(bres);
    psync_free(ids);
    debug(D_WARNING, "Account_users returned empty result!\n");
    return -2;
  } else {
    for (i = 0; i < contacts->length; ++i)
       vis(i, contacts->array[i], param);
  }
  
  psync_free(bres);
  psync_free(ids);
  return 0;
}

static void insert_cache_contact(int i, const binresult *user, void *_this) {
  const char *char_field = 0;
  uint64_t id = 0;
  psync_sql_res *q;
  
  char_field = psync_find_result(user, "name", PARAM_STR)->str;
  id = psync_find_result(user, "source", PARAM_NUM)->num;
  if ((id == 1) || (id == 3)) {
    q=psync_sql_prep_statement("REPLACE INTO contacts  (mail) VALUES (?)");
    char_field = psync_find_result(user, "value", PARAM_STR)->str;
    psync_sql_bind_lstring(q, 1, char_field, strlen(char_field));
    psync_sql_run_free(q);
  }
}

void cache_contacts() {
  void *params = 0;
  psync_sql_res *q;
  
  q=psync_sql_prep_statement("DELETE FROM contacts ");
  psync_sql_run_free(q);
  
  do_call_contactlist(&insert_cache_contact, params);
}


static int create_contact(psync_list_builder_t *builder, void *element, psync_variant_row row){
  contact_info_t *contact;
  const char *str;
  size_t len;
  contact=(contact_info_t *)element;
  str=psync_get_lstring(row[0], &len);
  contact->mail=str;
  psync_list_add_lstring_offset(builder, offsetof(contact_info_t, mail), len);
  str=psync_get_lstring(row[1], &len);
  contact->name=str;
  psync_list_add_lstring_offset(builder, offsetof(contact_info_t, name), len);
  contact->teamid=psync_get_number(row[2]);
  return 0;
}

pcontacts_list_t *do_psync_list_contacts() {
  psync_list_builder_t *builder;
  psync_sql_res *res;
  builder=psync_list_builder_create(sizeof(contact_info_t), offsetof(pcontacts_list_t, entries));
  res=psync_sql_query_rdlock("select mail, name , 0 as teamid from contacts "
                             "union all "
                             "select  mail, (firstname||' '||lastname) as name, 0 as teamid  from baccountemail "
                             "union all "
                             "select  '' as mail, name , id as teamid from baccountteam "
                             "ORDER BY name "
  );
  psync_list_bulder_add_sql(builder, res, create_contact);
  
  return (pcontacts_list_t *)psync_list_builder_finalize(builder);
}