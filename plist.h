/* Copyright (c) 2013 Anton Titov.
 * Copyright (c) 2013 pCloud Ltd.
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

#ifndef _PSYNC_LIST_H
#define _PSYNC_LIST_H

#include <stddef.h>

typedef struct _psync_list {
  struct _psync_list *next;
  struct _psync_list *prev;
} psync_list;

#define psync_list_init(l)\
  do {\
    (l)->next=(l);\
    (l)->prev=(l);\
  } while (0)
  
#define psync_add_between(l1, l2, a)\
  do {\
    (a)->next=(l2);\
    (a)->prev=(l1);\
    (l2)->prev=(a);\
    (l1)->next=(a);\
  } while (0)

#define psync_list_add_head(l, a) psync_add_between(l, (l)->next, a);
#define psync_list_add_tail(l, a) psync_add_between((l)->prev, l, a);

#define psync_list_del(a)\
  do {\
    (a)->next->prev=(a)->prev;\
    (a)->prev->next=(a)->next;\
  } while (0)
  
#define psync_list_element(a, t, n) ((t *)(char *)(a)-offsetof(t, n))

#define psync_list_for_each(a, l) for (a=(l)->next; a!=(l); a=a->next)
#define psync_list_for_each_safe(a, b, l) for (a=(l)->next, b=a->next; a!=(l); a=b, b=b->next)
#define psync_list_for_each_element(a, l, t, n) for (a=psync_list_element((l)->next, t, n); &a->n!=(l); a=psync_list_element(a->n.next, t, n))

#define psync_list_for_each_element_call(l, t, n, c)\
  do {\
    psync_list *___tmpa, *___tmpb;\
    psync_list_for_each_safe(___tmpa, ___tmpb, l)\
      c(psync_list_element(___tmpa, t, n));\
  } while (0)
  
#endif