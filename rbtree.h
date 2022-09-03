/*
 * The MIT License (MIT)
 *
 *  Copyright (c) Kacper Kokot
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 *
 * Single header generic red-black tree.
 * Define KK_RBTREE_IMPL to spawn the implementation.
 */

#ifndef _KK_RBTREE_H_
#define _KK_RBTREE_H_

/* 
 * 1) Every node is either red or black.
 * 2) Root node is always black.
 * 3) Every leaf node is NIL and black.
 * 4) Red node's children are always black.
 * 5) All simple paths from a node to it's descendant leafs 
 *    contains the same number of black nodes.
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include "arr.h"

#ifndef RB_REALLOC
# include <stdlib.h> 
# define RB_REALLOC(PTR, SIZE) realloc((PTR), (SIZE))
#endif

#ifndef RB_ASSERT
# include <assert.h>
# define RB_ASSERT(COND) assert(COND)
#endif

/* This macro definition controls whether we pass node itself 
 * or only the node'skk/
 */
#ifndef RBTREE_CMP_NODE
# define RBTREE_CMP_NODE 1
#endif

#ifndef RBTREE_CB_NODE
# define RBTREE_CB_NODE 1
#endif

#if RBTREE_STATIC
# define RBTREE_API static
#else
# define RBTREE_API
#endif

/* DEBUG */
#define DUMPPTR(PTR) do { printf("%s\t=\t%p\n", #PTR, PTR); fflush(stdout); } while(0)
#define DUMPNODE(PTR) do { printf("%s\t=\t%p, %d %s\n", #PTR, (PTR), \
    (PTR && (PTR)->data) ? *(int*)(PTR)->data :-1,\
    rb_is_black(PTR) ? "black" : "red"\
    ); fflush(stdout); } while(0)

#define RB_RED 1
#define RB_BLACK 0

/* TODO: require RB_REALLOC to return aligned address and store
 * colour in the  lower bits of the parent or data pointer, what about that?.
 */

/* keys and data are stored locally within the rbnode struct to save
 * dereference, this solution is more general and so if you wish to store 
 * either of them externally, you can set their size sizeof(void*) then cast 
 * and dereference them on retrieval. 
 * This also allows for mixed solution where e.g. you store a hash plus 
 * a pointer to the actual value in the key. */
struct rbnode {
  struct rbnode *p; 
  struct rbnode *l; 
  struct rbnode *r;
  bool col;
};

typedef int (rbtree_cmp_proc)(const void *, const void*);
typedef void *(rbtree_realloc_proc)(void *, size_t);

struct rbtree {
  struct rbnode *root;
  rbtree_cmp_proc *cmp;
  rbtree_realloc_proc *realloc;
  size_t cnt;
  uint32_t keysize;
  uint32_t datasize;
};

RBTREE_API
int rbtree_init(struct rbtree *t, 
    uint32_t keysize,
    uint32_t datasize,
    rbtree_cmp_proc *cmp_cb,
    rbtree_realloc_proc *realloc_cb);

RBTREE_API
struct rbnode *rbtree_insert(struct rbtree *t, const void *key);

RBTREE_API
struct rbnode *rbtree_search(const struct rbtree *t, const void *key);

static inline
const void *rbnode_get_key(const struct rbtree *t, struct rbnode *n)
{
  return ((uint8_t*)n + sizeof(struct rbnode));
}

static inline
void *rbnode_get_data(const struct rbtree *t, struct rbnode *n)
{
  return ((uint8_t*)n + sizeof(struct rbnode) + t->keysize);
}


#endif /* ifdef _KK_RBTREE_H_ */

/* implementation */

#ifdef KK_RBTREE_IMPL

static inline bool rb_is_red(struct rbnode *n) 
{
  return (n->col == RB_RED);
}

static inline bool rb_is_black(struct rbnode *n) 
{
  return (!n || n->col == RB_BLACK);
}

/* I am thinking that if node's addresses are aligned
 * we may store colour in the it's lower bits, hence function */
static inline void rb_set_color(struct rbnode *n, bool col) 
{
  n->col = col;
}

static inline bool rb_get_color(struct rbnode *n) 
{
  return n->col;
}

static inline void rb_copy_color(struct rbnode *dst, struct rbnode *src) 
{
  rb_set_color(dst, rb_get_color(src));
}

int rbtree_init(struct rbtree *t, 
    uint32_t keysize,
    uint32_t datasize,
    rbtree_cmp_proc *cmp_cb,
    rbtree_realloc_proc *realloc_cb) 
{
  memset(t, 0, sizeof(*t));
  t->keysize = keysize;
  t->datasize = datasize;
  t->cmp = cmp_cb;
  t->realloc = realloc_cb ? realloc_cb : realloc;
  return 0;
}

static
int rbnode_init(struct rbtree *t, struct rbnode *n, struct rbnode *parent) 
{
  return 0;
}

static
struct rbnode * rbnode_new(struct rbtree *t, struct rbnode *parent)
{
  size_t sz = sizeof(struct rbnode) + t->keysize + t->datasize;
  struct rbnode *n = t->realloc(NULL, sz);
  if(!n) 
    return NULL;

  memset(n, 0, sz);
  n->p = parent;
  rb_set_color(n, parent ? RB_RED : RB_BLACK);
  return n;
}

static
void rbnode_free(struct rbtree *t, struct rbnode *n) 
{
  t->realloc(n, 0);
}


static inline
struct rbnode **_rbnode_which_child(struct rbnode *n) 
{
  RB_ASSERT(n);
  if(n == n->p->r) {
    return &n->p->r;
  } else {
    RB_ASSERT(n == n->p->l);
    return &n->p->l;
  }
}

static inline void _rbnode_ptrswap(struct rbnode **a, struct rbnode **b)
{
  *(size_t*)a ^= *(size_t*)b; 
  *(size_t*)b ^= *(size_t*)a; 
  *(size_t*)a ^= *(size_t*)b; 
}

static inline void _rbtree_lrot(struct rbtree *t, struct rbnode *n)
{
  RB_ASSERT(n->r);

  if(n->p) {
    *_rbnode_which_child(n) = n->r;
  } else {
    RB_ASSERT(n == t->root);
    t->root = n->r;
  }

  if(n->r->l) 
    n->r->l->p = n;

  _rbnode_ptrswap(&n->r->p, &n->r->l);
  _rbnode_ptrswap(&n->p, &n->r->p);
  _rbnode_ptrswap(&n->p, &n->r);
}

static inline void _rbtree_rrot(struct rbtree *t, struct rbnode *n)
{
  RB_ASSERT(n->l);

  if(n->p) {
    *_rbnode_which_child(n) = n->l;
  } else {
    RB_ASSERT(n == t->root);
    t->root = n->l;
  }

  if(n->l->r) 
    n->l->r->p = n;

  _rbnode_ptrswap(&n->l->p, &n->l->r);
  _rbnode_ptrswap(&n->p, &n->l->p);
  _rbnode_ptrswap(&n->p, &n->l);
}

static inline void _rbtree_insert_fixup(struct rbtree *t, struct rbnode *n) 
{
  struct rbnode *gp;

  while(n->p && rb_is_red(n->p)) {
    gp = n->p->p;
    RB_ASSERT(n->p != t->root);

    if(n->p == gp->l) { 
      if(gp->r && rb_is_red(gp->r)) {
        rb_set_color(n->p, RB_BLACK);
        rb_set_color(gp->r, RB_BLACK);
        rb_set_color(gp, RB_RED);
        n = gp;
      } else {
        if(n == n->p->r) {
          n = n->p;
          _rbtree_lrot(t, n);
        }
        rb_set_color(n->p, RB_BLACK);
        rb_set_color(gp, RB_RED);
        _rbtree_rrot(t, gp);
      }
    } else {
      RB_ASSERT(n->p == gp->r);

      if(gp->l && rb_is_red(gp->l)) {
        rb_set_color(n->p, RB_BLACK);
        rb_set_color(gp->l, RB_BLACK);
        rb_set_color(gp, RB_RED);
        n = gp;
      } else {
        if(n == n->p->l) {
          n = n->p;
          _rbtree_rrot(t, n);
        }
        rb_set_color(n->p, RB_BLACK);
        rb_set_color(gp, RB_RED);
        _rbtree_lrot(t, gp);
      }
    }
  }

  rb_set_color(t->root, RB_BLACK);
}

/* FIXME: 
 * What happens to the data that got replaced? 
 * is it freed is it what?
 * Additional cleanup callback?
 * augmented rbtree_insert?
 */
RBTREE_API
struct rbnode *rbtree_insert(struct rbtree *t, const void *key)
{
  struct rbnode **node = &t->root, *parent = NULL;

  while(*node) {
    parent = *node;

    if(t->cmp(key, rbnode_get_key(t, *node)) > 0)
      node = &((*node)->r);
    else
      node = &((*node)->l);
  }

  *node = rbnode_new(t, parent);
  memcpy((char*)rbnode_get_key(t, *node), key, t->keysize);
  _rbtree_insert_fixup(t, *node);

  t->cnt++;
  return *node;
}


static inline size_t ullog2_ceil(size_t x)
{
  size_t tmp;
  for(int i = 63; i >= 0; --i)  {
    tmp = x & ((size_t)1 << i);
    if(tmp) return i + (tmp != x);
  }
  RB_ASSERT(0);
}

static inline size_t _rbtree_max_possible_height(struct rbtree *t)
{
  return (2 * ullog2_ceil(t->cnt));
}

static inline size_t _rbtree_max_possible_leafs(struct rbtree *t)
{
  return (1 << _rbtree_max_possible_height(t));
}

typedef void (rbtree_traverse_proc)(struct rbnode *, void *user);

void rbnode_sanity(struct rbnode *n) 
{
  //rbnode_test_print(n); puts("");
  RB_ASSERT(n != n->r);
  RB_ASSERT(n != n->l);

  if(n->p) {
    RB_ASSERT(n->p->r == n || n->p->l == n);
    RB_ASSERT(n->p != n->r);
    RB_ASSERT(n->p != n->l);
  }
}


int rbtree_preorder(
    struct rbtree *t, rbtree_traverse_proc *cb, void *user)
{
  size_t i = 0, 
         stack_cap = 4048;//; _rbtree_max_possible_leafs(t);

  struct rbnode *n, **stack = 
    RB_REALLOC(NULL, stack_cap * sizeof(struct rbnode*));

  if(!(n = t->root))
    goto exit;

  for(;;) {
    RB_ASSERT(i <= stack_cap);

    cb(n, user);

    if(n->l) { n = (stack[i++] = n)->l; continue; }

  checkright:
    if(n->r) { n = (stack[i++] = n)->r; continue; }

  backtrack:
    if(!i) break;

    if(stack[i-1]->r == n) {
      n = stack[--i]; goto backtrack;
    } else {
      RB_ASSERT(stack[i-1]->l == n);
      n = stack[--i]; goto checkright;
    }
  } 

exit:
  free(stack);
  return 0;
}


int rbtree_postorder(
    struct rbtree *t, rbtree_traverse_proc *cb, void *user)
{
  size_t i = 0, 
         stack_cap = _rbtree_max_possible_leafs(t);

  struct rbnode *n, **stack = 
    RB_REALLOC(NULL, stack_cap * sizeof(struct rbnode*));

  n = t->root;

  for(;;) {
    RB_ASSERT(i <= stack_cap);

    if(n->l) { n = (stack[i++] = n)->l; continue; }

  checkright:
    if(n->r) { n = (stack[i++] = n)->r; continue; }

  backtrack:
    // printf("%s node %d %s\n",__func__, *(int*)n->data, rb_is_black(n) ? "black" : "red");
    cb(n, user);

    if(!i) break;

    if(stack[i-1]->r == n) {
      n = stack[--i]; goto backtrack;
    } else {
      RB_ASSERT(stack[i-1]->l == n);
      n = stack[--i]; goto checkright;
    }
  } 

  free(stack);
  return 0;
}

int rbtree_levelorder(
    struct rbtree *t, rbtree_traverse_proc *cb, void *user) 
{
  size_t i = 0, queue_end = 0, 
         queue_cap = _rbtree_max_possible_leafs(t);

  struct rbnode *n, **queue = 
    RB_REALLOC(NULL, queue_cap * sizeof(struct rbnode*));

  /* enqueue */
  queue[queue_end++] = t->root; i++;
  if(queue_end == queue_cap) queue_end = 0;

  while(i) {
    RB_ASSERT(i <= queue_cap);
    /* dequeue */
    n = queue[
      queue_end >= i 
        ? queue_end - (i--)
        : queue_cap + queue_end - (i--)
    ];

    // printf("%s node %d %s\n",__func__, *(int*)n->data, rb_is_black(n) ? "black" : "red");

    //cb(n->data, user);

    /* enqueue */
    if(n->l) {
      queue[queue_end++] = n->l; i++;
      if(queue_end == queue_cap) queue_end = 0;
    }
    if(n->r) {
      queue[queue_end++] = n->r; i++;
      if(queue_end == queue_cap) queue_end = 0;
    }
  }
  free(queue);
}


void empty_callback(struct rbnode *n, void *user) {}

struct _rbtree_validate_data {
  size_t bheight;
  int result;
};

void _rbtree_validate_traverse_cb(struct rbnode *n, void *user) 
{
  struct _rbtree_validate_data *v = (struct _rbtree_validate_data*)user;
  size_t bheight = 0;

  if(n->r == NULL || n->l == NULL) {
    while(n) {
      if(rb_is_black(n))
        bheight++;
      else
        RB_ASSERT(rb_is_black(n->l) && rb_is_black(n->r));
      n = n->p;
    }

    /* if we have at least one node, this must be 
     * */
    if(v->bheight)
      RB_ASSERT(v->bheight == bheight);
    else
      v->bheight = bheight;
  }
}

int rbtree_validate(struct rbtree *t) {
  struct _rbtree_validate_data v = {};

  /* property 2 */
  RB_ASSERT(rb_is_black(t->root));

  /* property 4 & 5 */
  rbtree_preorder(t, _rbtree_validate_traverse_cb, &v);
}

void rbtree_print(struct rbtree *t)
{
}

struct rbnode *rbtree_min(struct rbnode *n) 
{
  while(n->l) 
    n = n->l;
  return n;
}

struct rbnode *rbtree_max(struct rbnode *n)
{
  while(n->r)
    n = n->r;
  return n;
}

struct rbnode *rbtree_successor(struct rbtree *t, struct rbnode *n) 
{
  if(n->r)
    return rbtree_min(n->r);

  while(n->p) {
    if(n == n->p->l)
      return n->p;

    n = n->p;
  }
  return NULL;
}

struct rbnode *rbtree_predecessor(struct rbtree *t, struct rbnode *n)
{
  if(n->l)
    return rbtree_max(n->l);

  while(n->p) {
    if(n == n->p->r)
      return n->p;

    n = n->p;
  }
  return NULL;
}

struct rbnode *rbtree_transplant(
    struct rbtree *t, struct rbnode *u, struct rbnode *v) 
{
  if(u->p) {
    *_rbnode_which_child(u) = v;
  } else {
    RB_ASSERT(u == t->root);
    t->root = v;
  }

  if(v) 
    v->p = u->p;

  return v;
}

struct rbnode *rbtree_search(const struct rbtree *t, const void *key) 
{
  int result;
  struct rbnode *node = t->root;

  while(node) {
    result = t->cmp(key, rbnode_get_key(t, node));

    /**/ if(result < 0) 
      node = node->l;
    else if(result > 0)
      node = node->r;
    else
      return node;
  }
  return NULL;
}

static
void _rbtree_delete_fixup(struct rbtree *t, struct rbnode *n) 
{
  struct rbnode *w;

  /* The node n is the deleted node's successor's right child before deletion.
   * When the successor takes place and colour of the deleted node, the successor's 
   * right child takes it's position but not necessarily it's colour,
   * if the successor had been black, this may violate the following properties:
   * 
   * 4th property - If n is red and the successor's original parent was red,
   *                the now we have a red node having a red child.
   * 5th property - Removed black successor node causes its original subtree
   *                to contain fewer black nodes and therefore having incorrect 
   *                black height. We denote the root of such subtree by '*', e.g. *A.
   * 
   * In case when both 4th and 5th property are violated we simply 
   * change n's colour to black, consequently restoring both properties.
   */

  RB_ASSERT(n);

  while(n->p && rb_is_black(n)) {
    //DUMPNODE(n->p);
    //DUMPNODE(n);
    //DUMPNODE(n->p->r);
    //DUMPNODE(n->p->l);

    if(n == n->p->l) {
      w = n->p->r;

      RB_ASSERT(w);

      if(rb_is_red(w)) {
        /* Case 1
         * The node is black and our sibling is red.
         * It follows that nodes B, D and E are black.
         *
         *     _B_                C
         *    /   \              / \
         *  *A(n)  C(w)  ->    _B_  E
         *        / \         /   \
         *       D   E      *A(n)  D(w)
         * 
         * This way we convert case 1 into case 2,3 or 4.
         */
        //printf("%s case 1\n", __func__);
        RB_ASSERT(rb_is_black(n->p));

        rb_set_color(n->p, RB_RED);
        rb_set_color(w, RB_BLACK);
        _rbtree_lrot(t, n->p);
        w = n->p->r;
      }

      RB_ASSERT(rb_is_black(w));

      if(rb_is_black(w->r) && rb_is_black(w->l)) {
          /* Case 2
           * The node, it's sibling w and w's children are all black.
           *
           *     _B_              _B(n)
           *    /   \            /   \
           *  *A(n)  C(w)  ->  *A    *C
           *        / \              / \
           *       D   E            D   E
           * 
           * Note that if node B has been red, like if we enter here through the case 1,
           * then the loop terminates and n - now pointing to B - is recoloured black 
           * at the end, restoring the 5th property. Otherwise we shift the problem up.
           */
          //printf("%s case 2\n", __func__);
          rb_set_color(w, RB_RED);
          n = n->p;
      } else {
        if(rb_is_black(w->r)) {
          /* Case 3
           * The node, it's sibling w, w's right child are black 
           * and w's left child is red.
           *
           *     _B_              _B_
           *    /   \            /   \
           *  *A(n)  C(w)  ->  *A(n)  D(w)
           *        / \              / \
           *       D   E            F   C
           *      / \                  / \
           *     F   G                G   E
           *
           * This way we convert case 3 into case 4.
           */
          //printf("%s case 3\n", __func__);
          rb_set_color(w, RB_RED);
          rb_set_color(w->l, RB_BLACK);
          _rbtree_rrot(t, w);
          RB_ASSERT(n->p->r == w->p); /* REMOVEME */
          w = n->p->r;
        }

        /* Case 4
         * The node, it's sibling w are black and w's right child is red. 
         *
         *     _B_                C
         *    /   \              / \
         *  *A(n)  C(w)  ->    _B_  E
         *        / \         /   \
         *       D   E       A     D(w)
         * 
         * One can verify that this will indeed restore the 5th property.
         */
        //printf("%s case 4\n", __func__);
        rb_copy_color(w, n->p);
        rb_set_color(w->r, RB_BLACK);
        rb_set_color(n->p, RB_BLACK);
        _rbtree_lrot(t, n->p);
        n = t->root;
      }
    } else {
      /* 
       * All cases in this branch are symmetric to the cases in the other branch
       */
      RB_ASSERT(n == n->p->r);

      w = n->p->l;
      RB_ASSERT(w);

      if(rb_is_red(w)) {
        /* Case 1 reversed */
        //printf("%s case 1\n", __func__);
        RB_ASSERT(rb_is_black(n->p));

        rb_set_color(n->p, RB_RED);
        rb_set_color(w, RB_BLACK);
        _rbtree_rrot(t, n->p);
        w = n->p->l;
      }

      RB_ASSERT(rb_is_black(w));

      if(rb_is_black(w->r) && rb_is_black(w->l)) {
          /* Case 2 reversed */
          //printf("%s case 2 reversed\n", __func__);
          rb_set_color(w, RB_RED);
          n = n->p;
      } else {
        //DUMPNODE(w);
        if(rb_is_black(w->l)) {
          /* Case 3 reversed */
          //printf("%s case 3 reversed\n", __func__);

          //DUMPNODE(n);
          //DUMPNODE(n->p);
          //DUMPNODE(w);
          //DUMPNODE(w->r);
          rb_set_color(w, RB_RED);
          rb_set_color(w->r, RB_BLACK);
          _rbtree_lrot(t, w);
          RB_ASSERT(n->p->l == w->p); /* REMOVEME */
          w = n->p->l;

          //DUMPNODE(w);
          //DUMPNODE(w->p->l);
          //DUMPNODE(w->p->r);
          //DUMPNODE(w->r);
          //DUMPNODE(w->l);
          //DUMPNODE(w->l->p);
        }
        /* Case 4 reversed */
        //printf("%s case 4 reversed\n", __func__);
        rb_copy_color(w, n->p);
        rb_set_color(w->l, RB_BLACK);
        rb_set_color(n->p, RB_BLACK);
        _rbtree_rrot(t, n->p);
        n = t->root;
      }
    }
  }
  rb_set_color(n, RB_BLACK);
}

void rbtree_delete(struct rbtree *t, struct rbnode *n) 
{
  struct rbnode *s, *x;

  struct rbnode dummy = {
    .col = RB_BLACK,
  };

  bool col = rb_get_color(n);

  /*  */ if(!n->l) {
    x = rbtree_transplant(t, n, n->r ? n->r : &dummy);
    n->r = NULL;
  } else if(!n->r) {
    x = rbtree_transplant(t, n, n->l ? n->l : &dummy);
    n->l = NULL;
  } else {
    s = rbtree_min(n->r);
    col = rb_get_color(s);
    x = s->r;

    if(!x) {
      x = &dummy;
      (s->r = x)->p = s;
    }

    RB_ASSERT(x);

    if(s->p == n) {
      RB_ASSERT(x->p == s);
      x->p = s;
    } else {
      rbtree_transplant(t, s, s->r);
      (s->r = n->r)->p = s;
    }

    rbtree_transplant(t, n, s);
    (s->l = n->l)->p = s;
    rb_copy_color(s, n);
  }

  if(!col)
    _rbtree_delete_fixup(t, x);

  if(x == &dummy)
    rbtree_transplant(t, &dummy, NULL);

  RB_ASSERT(dummy.r == NULL);
  RB_ASSERT(dummy.l == NULL);

  rbnode_free(t, n);
}

#endif /* #ifdef KK_RBTREE_IMPL */
