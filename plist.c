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
#include "plist.h"

/* Fairly simple in-place merge sort with constant storage requirements.
 * 
 * Recursive approach might would use O(log N) storage on the stack but may
 * have better cache locality for lists that do not fit in processor cache,
 * may benefit from precise in-half splitting and can go without needless
 * iterating of the list to reach the half of it. 
 */

void psync_list_sort(psync_list *l, psync_list_compare cmp){
  psync_list *ls, *l1, *l2, **tail;
  psync_uint_t depth, cnt, i, l1len, l2len;
  if (psync_list_isempty(l))
    return;
  ls=l->next;
  l->prev->next=NULL;
  depth=1;
  while (1){
    l1=ls;
    tail=&ls;
    cnt=0;
    while (l1){
      cnt++;
      l2=l1;
      for (i=0; i<depth && l2; i++)
        l2=l2->next;
      if (!l2){
        *tail=l1;
        goto nol2;
      }
      l1len=i;
      l2len=depth;
      while (1){
        if (cmp(l1, l2)<=0){
          l1len--;
          *tail=l1;
          tail=&l1->next;
          if (!l1len)
            goto l1fin;
          l1=l1->next;
        }
        else{
          l2len--;
          *tail=l2;
          tail=&l2->next;
          l2=l2->next;
          if (!l2len || !l2)
            goto l2fin;
        }
      }
      l2fin:
      *tail=l1;
      for (i=0; i<l1len-1; i++)
        l1=l1->next;
      tail=&l1->next;
      l1=l2;
      continue;
      l1fin:
      *tail=l2;
      for (i=0; l2->next && i<l2len-1; i++)
        l2=l2->next;
      tail=&l2->next;
      l1=l2->next;
    }
    *tail=NULL;
    nol2:
    if (cnt<=1)
      break;
    depth*=2;
  }
  l->next=ls;
  l1=l;
  while (ls){
    ls->prev=l1;
    l1=ls;
    ls=ls->next;
  }
  l1->next=l;
  l->prev=l1;
}

void psync_list_extract_repeating(psync_list *l1, psync_list *l2, psync_list *extracted1, psync_list *extracted2, psync_list_compare cmp){
  psync_list *li1, *li2, *ln1, *ln2;
  int cr;
  psync_list_sort(l1, cmp);
  psync_list_sort(l2, cmp);
  li1=l1->next;
  li2=l2->next;
  while (li1!=l1 && li2!=l2){
    cr=cmp(li1, li2);
    if (cr<0)
      li1=li1->next;
    else if (cr>0)
      li2=li2->next;
    else{
      ln1=li1->next;
      ln2=li2->next;
      psync_list_del(li1);
      psync_list_add_tail(extracted1, li1);
      psync_list_del(li2);
      psync_list_add_tail(extracted2, li2);
      li1=ln1;
      li2=ln2;
    }
  }
}

