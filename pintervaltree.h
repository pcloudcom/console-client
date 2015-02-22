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

#ifndef _PSYNC_INTERVALTREE_H
#define _PSYNC_INTERVALTREE_H

#include "ptree.h"
#include <stdint.h>

typedef struct {
  psync_tree tree;
  uint64_t from;
  uint64_t to;
} psync_interval_tree_t;

#define psync_interval_tree_element(a) psync_tree_element(a, psync_interval_tree_t, tree)
#define psync_interval_tree_for_each(a, l) for (a=psync_interval_tree_get_first(l); a!=NULL; a=psync_interval_tree_get_next(a))

static inline psync_interval_tree_t *psync_interval_tree_get_first(psync_interval_tree_t *tree){
  return psync_interval_tree_element(psync_tree_get_first(&tree->tree));
}

static inline psync_interval_tree_t *psync_interval_tree_get_last(psync_interval_tree_t *tree){
  return psync_interval_tree_element(psync_tree_get_last(&tree->tree));
}

static inline psync_interval_tree_t *psync_interval_tree_get_next(psync_interval_tree_t *tree){
  return psync_interval_tree_element(psync_tree_get_next(&tree->tree));
}

static inline psync_interval_tree_t *psync_interval_tree_get_prev(psync_interval_tree_t *tree){
  return psync_interval_tree_element(psync_tree_get_prev(&tree->tree));
}

static inline void psync_interval_tree_del(psync_interval_tree_t **tree, psync_interval_tree_t *node){
  *tree=psync_interval_tree_element(psync_tree_get_del(&(*tree)->tree, &node->tree));
}

static inline psync_interval_tree_t *psync_interval_tree_first_interval_containing_or_after(psync_interval_tree_t *tree, uint64_t point){
  while (tree){
    if (point>=tree->to){
      if (tree->tree.right)
        tree=psync_interval_tree_element(tree->tree.right);
      else{
        tree=psync_interval_tree_get_next(tree);
        break;
      }
    }
    else if (point>=tree->from || !tree->tree.left)
      break;
    else
      tree=psync_interval_tree_element(tree->tree.left);
  }
  return tree;
}

void psync_interval_tree_add(psync_interval_tree_t **tree, uint64_t from, uint64_t to);
void psync_interval_tree_remove(psync_interval_tree_t **tree, uint64_t from, uint64_t to);
void psync_interval_tree_free(psync_interval_tree_t *tree);
void psync_interval_tree_cut_end(psync_interval_tree_t **tree, uint64_t end);

#endif
