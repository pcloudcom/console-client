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

#ifndef _PSYNC_BUSINESS_ACCOUNT_H
#define _PSYNC_BUSINESS_ACCOUNT_H

#include "psynclib.h"
#include "ptypes.h"

int do_psync_account_stopshare(psync_shareid_t usershareids[], int nusershareid, psync_shareid_t teamshareids[], int nteamshareid, char **err); 
int do_psync_account_modifyshare(psync_shareid_t usrshrids[], uint32_t uperms[], int nushid, 
                           psync_shareid_t tmshrids[], uint32_t tperms[], int ntmshid, char **err);

//int do_psync_account_users(psync_userid_t iserids[], int nids, result_visitor vis, void *param);
//int do_psync_account_teams(psync_userid_t teamids[], int nids, result_visitor vis, void *param);

void get_ba_member_email(uint64_t userid, char** email /*OUT*/, size_t *length /*OUT*/);
void get_ba_team_name(uint64_t teamid, char** name /*OUT*/, size_t *length /*OUT*/); 

void cache_account_emails();
void cache_account_teams();
void cache_ba_my_teams();
int api_error_result(binresult* res);

#endif //_PSYNC_BUSINESS_ACCOUNT_H