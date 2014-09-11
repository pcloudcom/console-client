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

#include "ptree.h"
#include "plibs.h"
#include <string.h>

static inline long int psync_tree_max(long int a, long int b){
  return a>b?a:b;
}

static void psync_tree_recalc_height(psync_tree *e){
  e->height=psync_tree_max(psync_tree_height(e->left), psync_tree_height(e->right))+1;
}

static psync_tree *psync_tree_rotate_left(psync_tree *e){
  psync_tree *e2;
  e2=e->right;
  e2->parent=e->parent;
  e->right=e2->left;
  if (e->right){
    e->right->parent=e;
    psync_tree_recalc_height(e);
  }
  else
    e->height=psync_tree_height(e->left)+1;
  e->parent=e2;
  e2->left=e;
  psync_tree_recalc_height(e2);
  return e2;
}

static psync_tree *psync_tree_rotate_right(psync_tree *e){
  psync_tree *e2;
  e2=e->left;
  e2->parent=e->parent;
  e->left=e2->right;
  if (e->left){
    e->left->parent=e;
    psync_tree_recalc_height(e);
  }
  else
    e->height=psync_tree_height(e->right)+1;
  e->parent=e2;
  e2->right=e;
  psync_tree_recalc_height(e2);
  return e2;
}

psync_tree *psync_tree_init_node(psync_tree *node){
  node->left=NULL;
  node->right=NULL;
  node->parent=NULL;
  node->height=1;
  return node;
}

static psync_tree *psync_tree_go_up_rebalance_add(psync_tree *tree, psync_tree *e){
  long int lheight, rheight, dheight;
up:
  lheight=psync_tree_height(e->left);
  rheight=psync_tree_height(e->right);
  dheight=lheight-rheight;
  if (dheight==0)
    return tree;
  else if (dheight==1 || dheight==-1){
    e->height=rheight+(dheight+1)/2+1;
    if (e->parent){
      e=e->parent;
      goto up;
    }
    else{
      assert(tree==e);
      return tree;
    }
  }
  else if (dheight==2){
    if (psync_tree_height(e->left->right)>psync_tree_height(e->left->left))
      e->left=psync_tree_rotate_left(e->left);
    if (e==tree)
      return psync_tree_rotate_right(e);
    else{
      psync_tree *e2=e->parent;
      if (e2->left==e)
        e2->left=psync_tree_rotate_right(e);
      else{
        assert(e2->right==e);
        e2->right=psync_tree_rotate_right(e);
      }
      return tree;
    }
  }
  else{
    assert(dheight==-2);
    if (psync_tree_height(e->right->left)>psync_tree_height(e->right->right))
      e->right=psync_tree_rotate_right(e->right);
    if (e==tree)
      return psync_tree_rotate_left(e);
    else{
      psync_tree *e2=e->parent;
      if (e2->left==e)
        e2->left=psync_tree_rotate_left(e);
      else{
        assert(e2->right==e);
        e2->right=psync_tree_rotate_left(e);
      }
      return tree;
    }
  }
}

psync_tree *psync_tree_get_add_after(psync_tree *tree, psync_tree *node, psync_tree *newnode){
  if (!tree)
    return psync_tree_init_node(newnode);
  if (!node)
    return psync_tree_get_add_before(tree, psync_tree_get_first(tree), newnode);
  psync_tree_init_node(newnode);
  if (node->right){
    node=node->right;
    while (node->left)
      node=node->left;
    node->left=newnode;
  }
  else
    node->right=newnode;
  newnode->parent=node;
  return psync_tree_go_up_rebalance_add(tree, node);
}

psync_tree *psync_tree_get_add_before(psync_tree *tree, psync_tree *node, psync_tree *newnode){
  if (!tree)
    return psync_tree_init_node(newnode);
  if (!node)
    return psync_tree_get_add_after(tree, psync_tree_get_last(tree), newnode);
  psync_tree_init_node(newnode);
  if (node->left){
    node=node->left;
    while (node->right)
      node=node->right;
    node->right=newnode;
  }
  else
    node->left=newnode;
  newnode->parent=node;
  return psync_tree_go_up_rebalance_add(tree, node);
}

psync_tree *psync_tree_get_added_at(psync_tree *tree, psync_tree *parent, psync_tree *newnode){
  psync_tree_init_node(newnode);
  newnode->parent=parent;
  if (parent)
    return psync_tree_go_up_rebalance_add(tree, parent);
  else
    return tree;
}

static psync_tree *psync_tree_go_up_rebalance_del(psync_tree *tree, psync_tree *e){
  long int lheight, rheight, dheight;
up:
  lheight=psync_tree_height(e->left);
  rheight=psync_tree_height(e->right);
  dheight=lheight-rheight;
  if (dheight==0){
    e->height=rheight+1;
    if (e->parent){
      e=e->parent;
      goto up;
    }
    else{
      assert(tree==e);
      return tree;
    }
  }
  else if (dheight==1 || dheight==-1)
    return tree;
  else if (dheight==2){
    if (psync_tree_height(e->left->right)>psync_tree_height(e->left->left))
      e->left=psync_tree_rotate_left(e->left);
    if (e==tree)
      return psync_tree_rotate_right(e);
    else{
      psync_tree *e2=e->parent;
      if (e2->left==e)
        e2->left=psync_tree_rotate_right(e);
      else{
        assert(e2->right==e);
        e2->right=psync_tree_rotate_right(e);
      }
      e=e2;
      goto up;
    }
  }
  else{
    assert(dheight==-2);
    if (psync_tree_height(e->right->left)>psync_tree_height(e->right->right))
      e->right=psync_tree_rotate_right(e->right);
    if (e==tree)
      return psync_tree_rotate_left(e);
    else{
      psync_tree *e2=e->parent;
      if (e2->left==e)
        e2->left=psync_tree_rotate_left(e);
      else{
        assert(e2->right==e);
        e2->right=psync_tree_rotate_left(e);
      }
      e=e2;
      goto up;
    }
  }
}

static psync_tree *psync_tree_replace_me_with(psync_tree *tree, psync_tree *node, psync_tree *repl){
  psync_tree *parent;
  parent=node->parent;
  if (!parent){
    assert(tree==node);
    tree=repl;
  }
  else if (node==parent->left)
    parent->left=repl;
  else{
    assert(node==parent->right);
    parent->right=repl;
  }
  if (repl)
    repl->parent=parent;
  if (parent)
    return psync_tree_go_up_rebalance_del(tree, parent);
  else if (!tree)
    return NULL;
  else
    return psync_tree_go_up_rebalance_del(tree, tree);
}

psync_tree *psync_tree_get_del(psync_tree *tree, psync_tree *node){
  if (!node->left && !node->right)
    return psync_tree_replace_me_with(tree, node, NULL);
  else if (!node->left)
    return psync_tree_replace_me_with(tree, node, node->right);
  else if (!node->right)
    return psync_tree_replace_me_with(tree, node, node->left);
  else {
    psync_tree *el, *parent, **addr;
    if (node->left->height>node->right->height){
      el=node->left;
      addr=&node->left;
      while (el->right){
        addr=&el->right;
        el=el->right;
      }
      parent=el->parent;
      *addr=el->left;
      if (el->left)
        el->left->parent=parent;
    }
    else {
      el=node->right;
      addr=&node->right;
      while (el->left){
        addr=&el->left;
        el=el->left;
      }
      parent=el->parent;
      *addr=el->right;
      if (el->right)
        el->right->parent=parent;
    }
    memcpy(el, node, sizeof(psync_tree));
    if (parent==node)
      parent=el;
    if (node->left)
      node->left->parent=el;
    if (node->right)
      node->right->parent=el;
    if (node->parent){
      if (node->parent->left==node)
        node->parent->left=el;
      else{
        assert(node->parent->right==node);
        node->parent->right=el;
      }
    }
    else{
      assert(node==tree);
      tree=el;
    }
    return psync_tree_go_up_rebalance_del(tree, parent);
  }
}