/*
 * ngtcp2
 *
 * Copyright (c) 2018 ngtcp2 contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifndef NGTCP2_KSL_H
#define NGTCP2_KSL_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>

#include <ngtcp2/ngtcp2.h>

/*
 * Skip List using single key instead of range.
 */

#define NGTCP2_KSL_DEGR 8
/* NGTCP2_KSL_MAX_NBLK is the maximum number of nodes which a single
   block can contain. */
#define NGTCP2_KSL_MAX_NBLK (2 * NGTCP2_KSL_DEGR - 1)
/* NGTCP2_KSL_MIN_NBLK is the minimum number of nodes which a single
   block other than root must contains. */
#define NGTCP2_KSL_MIN_NBLK (NGTCP2_KSL_DEGR - 1)

/*
 * ngtcp2_ksl_key represents key in ngtcp2_ksl.
 */
typedef union {
  int64_t i;
  const void *ptr;
} ngtcp2_ksl_key;

struct ngtcp2_ksl_node;
typedef struct ngtcp2_ksl_node ngtcp2_ksl_node;

struct ngtcp2_ksl_blk;
typedef struct ngtcp2_ksl_blk ngtcp2_ksl_blk;

/*
 * ngtcp2_ksl_node is a node which contains either ngtcp2_ksl_blk or
 * opaque data.  If a node is an internal node, it contains
 * ngtcp2_ksl_blk.  Otherwise, it has data.  The invariant is that the
 * key of internal node dictates the maximum key in its descendants,
 * and the corresponding leaf node must exist.
 */
struct ngtcp2_ksl_node {
  ngtcp2_ksl_key key;
  union {
    ngtcp2_ksl_blk *blk;
    void *data;
  };
};

/*
 * ngtcp2_ksl_blk contains ngtcp2_ksl_node objects.
 */
struct ngtcp2_ksl_blk {
  /* next points to the next block if leaf field is nonzero. */
  ngtcp2_ksl_blk *next;
  /* prev points to the previous block if leaf field is nonzero. */
  ngtcp2_ksl_blk *prev;
  /* n is the number of nodes this object contains in nodes. */
  size_t n;
  /* leaf is nonzero if this block contains leaf nodes. */
  int leaf;
  ngtcp2_ksl_node nodes[NGTCP2_KSL_MAX_NBLK];
};

/*
 * ngtcp2_ksl_compar is a function type which returns nonzero if key
 * |lhs| should be placed before |rhs|.  It returns 0 otherwise.
 */
typedef int (*ngtcp2_ksl_compar)(const ngtcp2_ksl_key *lhs,
                                 const ngtcp2_ksl_key *rhs);

struct ngtcp2_ksl_it;
typedef struct ngtcp2_ksl_it ngtcp2_ksl_it;

/*
 * ngtcp2_ksl_it is a forward iterator to iterate nodes.
 */
struct ngtcp2_ksl_it {
  const ngtcp2_ksl_blk *blk;
  size_t i;
  ngtcp2_ksl_compar compar;
  ngtcp2_ksl_key inf_key;
};

struct ngtcp2_ksl;
typedef struct ngtcp2_ksl ngtcp2_ksl;

/*
 * ngtcp2_ksl is a deterministic paged skip list.
 */
struct ngtcp2_ksl {
  /* head points to the root block. */
  ngtcp2_ksl_blk *head;
  /* front points to the first leaf block. */
  ngtcp2_ksl_blk *front;
  /* back points to the last leaf block. */
  ngtcp2_ksl_blk *back;
  ngtcp2_ksl_compar compar;
  ngtcp2_ksl_key inf_key;
  size_t n;
  const ngtcp2_mem *mem;
};

/*
 * ngtcp2_ksl_init initializes |ksl|.  |compar| specifies compare
 * function.  |inf_key| specifies the "infinite" key.
 *
 * It returns 0 if it succeeds, or one of the following negative error
 * codes:
 *
 * NGTCP2_ERR_NOMEM
 *   Out of memory.
 */
int ngtcp2_ksl_init(ngtcp2_ksl *ksl, ngtcp2_ksl_compar compar,
                    const ngtcp2_ksl_key *inf_key, const ngtcp2_mem *mem);

/*
 * ngtcp2_ksl_free frees resources allocated for |ksl|.  If |ksl| is
 * NULL, this function does nothing.  It does not free the memory
 * region pointed by |ksl| itself.
 */
void ngtcp2_ksl_free(ngtcp2_ksl *ksl);

/*
 * ngtcp2_ksl_insert inserts |key| with its associated |data|.  On
 * successful insertion, the iterator points to the inserted node is
 * stored in |*it|.
 *
 * This function assumes that |key| does not exist in |ksl|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *   Out of memory.
 */
int ngtcp2_ksl_insert(ngtcp2_ksl *ksl, ngtcp2_ksl_it *it,
                      const ngtcp2_ksl_key *key, void *data);

/*
 * ngtcp2_ksl_remove removes the |key| from |ksl|.  It assumes such
 * the key is included in |ksl|.
 *
 * This function assigns the iterator to |*it|, which points to the
 * node which is located at the right next of the removed node if |it|
 * is not NULL.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *   Out of memory.
 */
int ngtcp2_ksl_remove(ngtcp2_ksl *ksl, ngtcp2_ksl_it *it,
                      const ngtcp2_ksl_key *key);

/*
 * ngtcp2_ksl_lower_bound returns the iterator which points to the
 * first node which has the key which is equal to |key| or the last
 * node which satisfies !compar(&node->key, key).  If there is no such
 * node, it returns the iterator which satisfies ngtcp2_ksl_it_end(it)
 * != 0.
 */
ngtcp2_ksl_it ngtcp2_ksl_lower_bound(ngtcp2_ksl *ksl,
                                     const ngtcp2_ksl_key *key);

/*
 * ngtcp2_ksl_update_key replaces the key of nodes which has |old_key|
 * with |new_key|.  |new_key| must be strictly greater than the
 * previous node and strictly smaller than the next node.
 */
void ngtcp2_ksl_update_key(ngtcp2_ksl *ksl, const ngtcp2_ksl_key *old_key,
                           const ngtcp2_ksl_key *new_key);

/*
 * ngtcp2_ksl_begin returns the iterator which points to the first
 * node.  If there is no node in |ksl|, it returns the iterator which
 * satisfies ngtcp2_ksl_it_end(it) != 0.
 */
ngtcp2_ksl_it ngtcp2_ksl_begin(const ngtcp2_ksl *ksl);

/*
 * ngtcp2_ksl_end returns the iterator which points to the node
 * following the last node.  The returned object satisfies
 * ngtcp2_ksl_it_end().  If there is no node in |ksl|, it returns the
 * iterator which satisfies ngtcp2_ksl_it_begin(it) != 0.
 */
ngtcp2_ksl_it ngtcp2_ksl_end(const ngtcp2_ksl *ksl);

/*
 * ngtcp2_ksl_len returns the number of elements stored in |ksl|.
 */
size_t ngtcp2_ksl_len(ngtcp2_ksl *ksl);

/*
 * ngtcp2_ksl_clear removes all elements stored in |ksl|.
 */
void ngtcp2_ksl_clear(ngtcp2_ksl *ksl);

/*
 * ngtcp2_ksl_print prints its internal state in stderr.  This
 * function should be used for the debugging purpose only.
 */
void ngtcp2_ksl_print(ngtcp2_ksl *ksl);

/*
 * ngtcp2_ksl_it_init initializes |it|.
 */
void ngtcp2_ksl_it_init(ngtcp2_ksl_it *it, const ngtcp2_ksl_blk *blk, size_t i,
                        ngtcp2_ksl_compar compar,
                        const ngtcp2_ksl_key *inf_key);

/*
 * ngtcp2_ksl_it_get returns the data associated to the node which
 * |it| points to.  If this function is called when
 * ngtcp2_ksl_it_end(it) returns nonzero, it returns NULL.
 */
void *ngtcp2_ksl_it_get(const ngtcp2_ksl_it *it);

/*
 * ngtcp2_ksl_it_next advances the iterator by one.  It is undefined
 * if this function is called when ngtcp2_ksl_it_end(it) returns
 * nonzero.
 */
void ngtcp2_ksl_it_next(ngtcp2_ksl_it *it);

/*
 * ngtcp2_ksl_it_prev moves backward the iterator by one.  It is
 * undefined if this function is called when ngtcp2_ksl_it_begin(it)
 * returns nonzero.
 */
void ngtcp2_ksl_it_prev(ngtcp2_ksl_it *it);

/*
 * ngtcp2_ksl_it_end returns nonzero if |it| points to the beyond the
 * last node.
 */
int ngtcp2_ksl_it_end(const ngtcp2_ksl_it *it);

/*
 * ngtcp2_ksl_it_begin returns nonzero if |it| points to the first
 * node.  |it| might satisfy both ngtcp2_ksl_it_begin(&it) and
 * ngtcp2_ksl_it_end(&it) if the skip list has no node.
 */
int ngtcp2_ksl_it_begin(const ngtcp2_ksl_it *it);

/*
 * ngtcp2_ksl_key returns the key of the node which |it| points to.
 * It is OK to call this function when ngtcp2_ksl_it_end(it) returns
 * nonzero.  In this case, this function returns inf_key.
 */
ngtcp2_ksl_key ngtcp2_ksl_it_key(const ngtcp2_ksl_it *it);

/*
 * ngtcp2_ksl_key_i is a convenient function which initializes |key|
 * with |i| and returns |key|.
 */
ngtcp2_ksl_key *ngtcp2_ksl_key_i(ngtcp2_ksl_key *key, int64_t i);

/*
 * ngtcp2_ksl_key_ptr is a convenient function which initializes |key|
 * with |ptr| and returns |key|.
 */
ngtcp2_ksl_key *ngtcp2_ksl_key_ptr(ngtcp2_ksl_key *key, const void *ptr);

#endif /* NGTCP2_KSL_H */
