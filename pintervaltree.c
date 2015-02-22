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

#include "pintervaltree.h"
#include "plibs.h"

static psync_interval_tree_t *psync_interval_tree_new(uint64_t from, uint64_t to){
  psync_interval_tree_t *tree=psync_new(psync_interval_tree_t);
  tree->from=from;
  tree->to=to;
  return psync_interval_tree_element(psync_tree_get_add_after(PSYNC_TREE_EMPTY, NULL, &tree->tree));
}

static psync_interval_tree_t *psync_interval_new(uint64_t from, uint64_t to){
  psync_interval_tree_t *tree=psync_new(psync_interval_tree_t);
  tree->from=from;
  tree->to=to;
  return tree;
}

static psync_interval_tree_t *psync_interval_tree_consume_intervals(psync_interval_tree_t *tree, psync_interval_tree_t *e){
  psync_interval_tree_t *next;
  while ((next=psync_interval_tree_get_next(e))){
    if (next->from>e->to)
      break;
    psync_interval_tree_del(&tree, next);
    if (next->to>=e->to){
      e->to=next->to;
      psync_free(next);
      break;
    }
    psync_free(next);
  }
  return tree;
}

static psync_interval_tree_t *psync_interval_tree_get_add(psync_interval_tree_t *tree, uint64_t from, uint64_t to){
//  debug(D_NOTICE, "adding interval %lu %lu", from, to);
  assert(to>from);
  if (unlikely(!tree))
    return psync_interval_tree_new(from, to);
  else{
    psync_interval_tree_t *e, *e2;
    e=tree;
    while (1){
      assert(from<=to);
      if (e->from<=from && e->to>=from){
        if (e->to>=to)
          return tree;
        e->to=to;
        return psync_interval_tree_consume_intervals(tree, e);
      }
      else if (e->from>from){
        if (e->tree.left)
          e=psync_interval_tree_element(e->tree.left);
        else if (e->from<=to && e->to>=to){
          e->from=from;
          return tree;
        }
        else{
          e2=psync_interval_new(from, to);
          return psync_interval_tree_consume_intervals(psync_interval_tree_element(psync_tree_get_add_before(&tree->tree, &e->tree, &e2->tree)), e2);
        }
      }
      else{
        assert(e->to<from);
        if (e->tree.right)
          e=psync_interval_tree_element(e->tree.right);
        else{
          e2=psync_interval_new(from, to);
          return psync_interval_tree_consume_intervals(psync_interval_tree_element(psync_tree_get_add_after(&tree->tree, &e->tree, &e2->tree)), e2);
        }
      }
    }
  }
}

void psync_interval_tree_add(psync_interval_tree_t **tree, uint64_t from, uint64_t to){
  *tree=psync_interval_tree_get_add(*tree, from, to);
}

void psync_interval_tree_remove(psync_interval_tree_t **tree, uint64_t from, uint64_t to){
  psync_interval_tree_t *tr, *ntr;
  tr=psync_interval_tree_first_interval_containing_or_after(*tree, from);
  while (tr){
    if (tr->from<from && tr->to>to){
      // the only case we have to split interval
      psync_tree_add_after((psync_tree **)tree, &tr->tree, &psync_interval_new(to, tr->to)->tree);
      tr->to=from;
      break;
    }
    ntr=psync_interval_tree_get_next(tr);
    if (from<=tr->from && tr->from<to){
      tr->from=to;
      if (tr->from>=tr->to)
        psync_interval_tree_del(tree, tr);
    }
    else if (tr->from<from)
      tr->to=from;
    else
      break;
    tr=ntr;
  }
}

void psync_interval_tree_free(psync_interval_tree_t *tree){
  if (tree)
    psync_tree_for_each_element_call_safe(&tree->tree, psync_interval_tree_t, tree, psync_free);
}

static psync_interval_tree_t *psync_interval_tree_get_cut_end(psync_interval_tree_t *tree, uint64_t end){
  psync_interval_tree_t *last, *prev;
  last=psync_interval_tree_get_last(tree);
  while (last && last->to>end){
    if (last->from<end){
      last->to=end;
      break;
    }
    prev=psync_interval_tree_get_prev(last);
    tree=psync_interval_tree_element(psync_tree_get_del(&tree->tree, &last->tree));
    psync_free(last);
    last=prev;
  }
  return tree;
}

void psync_interval_tree_cut_end(psync_interval_tree_t **tree, uint64_t end){
  *tree=psync_interval_tree_get_cut_end(*tree, end);
}
