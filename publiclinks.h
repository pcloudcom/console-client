/* Copyright (c) 2013-2014 pCloud Ltd.
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

#ifndef _PUBLIC_LINKS_H
#define _PUBLIC_LINKS_H

#include "psynclib.h"

int64_t do_psync_file_public_link(const char *path, char **code /*OUT*/, char **err /*OUT*/, uint64_t expire, int maxdownloads, int maxtraffic);
int64_t do_psync_folder_public_link(const char *path, char **code /*OUT*/, char **err /*OUT*/, uint64_t expire, int maxdownloads, int maxtraffic);
int64_t do_psync_tree_public_link(const char *linkname, const char *root, char **folders, int numfolders, char **files, int numfiles, char **code /*OUT*/, char **err /*OUT*/, 
                                  uint64_t expire, int maxdownloads, int maxtraffic);
int do_psync_list_links(plink_info_list_t **info /*OUT*/, char **err /*OUT*/);
int do_psync_delete_link(int64_t linkid, char **err /*OUT*/);


#endif //_PUBLIC_LINKS_H
