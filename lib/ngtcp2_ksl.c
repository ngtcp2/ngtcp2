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
#include "ngtcp2_ksl.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#include "ngtcp2_macro.h"
#include "ngtcp2_mem.h"

int ngtcp2_ksl_init(ngtcp2_ksl *ksl, ngtcp2_ksl_compar compar,
                    const ngtcp2_ksl_key *inf_key, ngtcp2_mem *mem) {
  ngtcp2_ksl_blk *head;

  ksl->head = ngtcp2_mem_malloc(mem, sizeof(ngtcp2_ksl_blk));
  if (!ksl->head) {
    return NGTCP2_ERR_NOMEM;
  }
  ksl->front = ksl->back = ksl->head;
  ksl->compar = compar;
  ksl->inf_key = *inf_key;
  ksl->n = 0;
  ksl->mem = mem;

  head = ksl->head;

  head->next = head->prev = NULL;
  head->n = 1;
  head->leaf = 1;
  head->nodes[0].key = ksl->inf_key;
  head->nodes[0].data = NULL;

  return 0;
}

/*
 * free_blk frees |blk| recursively.
 */
static void free_blk(ngtcp2_ksl_blk *blk, ngtcp2_mem *mem) {
  size_t i;

  if (!blk->leaf) {
    for (i = 0; i < blk->n; ++i) {
      free_blk(blk->nodes[i].blk, mem);
    }
  }

  ngtcp2_mem_free(mem, blk);
}

void ngtcp2_ksl_free(ngtcp2_ksl *ksl) {
  if (!ksl) {
    return;
  }

  free_blk(ksl->head, ksl->mem);
}

/*
 * ksl_split_blk splits |blk| into 2 ngtcp2_ksl_blk objects.  The new
 * ngtcp2_ksl_blk is always the "right" block.
 *
 * It returns the pointer to the ngtcp2_ksl_blk created which is the
 * located at the right of |blk|, or NULL which indicates out of
 * memory error.
 */
static ngtcp2_ksl_blk *ksl_split_blk(ngtcp2_ksl *ksl, ngtcp2_ksl_blk *blk) {
  ngtcp2_ksl_blk *rblk;

  rblk = ngtcp2_mem_malloc(ksl->mem, sizeof(ngtcp2_ksl_blk));
  if (rblk == NULL) {
    return NULL;
  }

  rblk->next = blk->next;
  blk->next = rblk;
  if (rblk->next) {
    rblk->next->prev = rblk;
  } else if (ksl->back == blk) {
    ksl->back = rblk;
  }
  rblk->prev = blk;
  rblk->leaf = blk->leaf;

  rblk->n = blk->n / 2;

  memcpy(rblk->nodes, &blk->nodes[blk->n - rblk->n],
         sizeof(ngtcp2_ksl_node) * rblk->n);

  blk->n -= rblk->n;

  assert(blk->n >= NGTCP2_KSL_MIN_NBLK);
  assert(rblk->n >= NGTCP2_KSL_MIN_NBLK);

  return rblk;
}

/*
 * ksl_split_node splits a node included in |blk| at the position |i|
 * into 2 adjacent nodes.  The new node is always inserted at the
 * position |i+1|.
 *
 * It returns 0 if it succeeds, or one of the following negative error
 * codes:
 *
 * NGTCP2_ERR_NOMEM
 *   Out of memory.
 */
static int ksl_split_node(ngtcp2_ksl *ksl, ngtcp2_ksl_blk *blk, size_t i) {
  ngtcp2_ksl_blk *lblk = blk->nodes[i].blk, *rblk;

  rblk = ksl_split_blk(ksl, lblk);
  if (rblk == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  memmove(&blk->nodes[i + 2], &blk->nodes[i + 1],
          sizeof(ngtcp2_ksl_node) * (blk->n - (i + 1)));

  blk->nodes[i + 1].blk = rblk;

  ++blk->n;

  blk->nodes[i].key = lblk->nodes[lblk->n - 1].key;
  blk->nodes[i + 1].key = rblk->nodes[rblk->n - 1].key;

  return 0;
}

/*
 * ksl_split_head splits a head (root) block.  It increases the height
 * of skip list by 1.
 *
 * It returns 0 if it succeeds, or one of the following negative error
 * codes:
 *
 * NGTCP2_ERR_NOMEM
 *   Out of memory.
 */
static int ksl_split_head(ngtcp2_ksl *ksl) {
  ngtcp2_ksl_blk *rblk = NULL, *lblk, *nhead = NULL;

  rblk = ksl_split_blk(ksl, ksl->head);
  if (rblk == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  lblk = ksl->head;

  nhead = ngtcp2_mem_malloc(ksl->mem, sizeof(ngtcp2_ksl_blk));
  if (nhead == NULL) {
    ngtcp2_mem_free(ksl->mem, rblk);
    return NGTCP2_ERR_NOMEM;
  }
  nhead->next = nhead->prev = NULL;
  nhead->n = 2;
  nhead->leaf = 0;

  nhead->nodes[0].key = lblk->nodes[lblk->n - 1].key;
  nhead->nodes[0].blk = lblk;
  nhead->nodes[1].key = rblk->nodes[rblk->n - 1].key;
  nhead->nodes[1].blk = rblk;

  ksl->head = nhead;

  return 0;
}

/*
 * insert_node inserts a node whose key is |key| with the associated
 * |data| at the index of |i|.  This function assumes that the number
 * of nodes contained by |blk| is strictly less than
 * NGTCP2_KSL_MAX_NBLK.
 */
static void insert_node(ngtcp2_ksl_blk *blk, size_t i,
                        const ngtcp2_ksl_key *key, void *data) {
  ngtcp2_ksl_node *node;

  assert(blk->n < NGTCP2_KSL_MAX_NBLK);

  memmove(&blk->nodes[i + 1], &blk->nodes[i],
          sizeof(ngtcp2_ksl_node) * (blk->n - i));

  node = &blk->nodes[i];
  node->key = *key;
  node->data = data;

  ++blk->n;
}

int ngtcp2_ksl_insert(ngtcp2_ksl *ksl, ngtcp2_ksl_it *it,
                      const ngtcp2_ksl_key *key, void *data) {
  ngtcp2_ksl_blk *blk = ksl->head;
  ngtcp2_ksl_node *node;
  size_t i;
  int rv;

  if (blk->n == NGTCP2_KSL_MAX_NBLK) {
    rv = ksl_split_head(ksl);
    if (rv != 0) {
      return rv;
    }
    blk = ksl->head;
  }

  for (;;) {
    for (i = 0, node = &blk->nodes[i]; ksl->compar(&node->key, key);
         ++i, ++node)
      ;

    if (blk->leaf) {
      insert_node(blk, i, key, data);
      ++ksl->n;
      if (it) {
        ngtcp2_ksl_it_init(it, blk, i, ksl->compar, &ksl->inf_key);
      }
      return 0;
    }

    if (node->blk->n == NGTCP2_KSL_MAX_NBLK) {
      rv = ksl_split_node(ksl, blk, i);
      if (rv != 0) {
        return rv;
      }
      if (ksl->compar(&node->key, key)) {
        node = &blk->nodes[i + 1];
      }
    }

    blk = node->blk;
  }
}

/*
 * remove_node removes the node included in |blk| at the index of |i|.
 */
static void remove_node(ngtcp2_ksl_blk *blk, size_t i) {
  memmove(&blk->nodes[i], &blk->nodes[i + 1],
          sizeof(ngtcp2_ksl_node) * (blk->n - (i + 1)));

  --blk->n;
}

/*
 * ksl_merge_node merges 2 nodes which are the nodes at the index of
 * |i| and |i + 1|.
 *
 * If |blk| is the direct descendant of head (root) block and the head
 * block contains just 2 nodes, the merged block becomes head block,
 * which decreases the height of |ksl| by 1.
 *
 * This function returns the pointer to the merged block.
 */
static ngtcp2_ksl_blk *ksl_merge_node(ngtcp2_ksl *ksl, ngtcp2_ksl_blk *blk,
                                      size_t i) {
  ngtcp2_ksl_blk *lblk, *rblk;

  assert(i + 1 < blk->n);

  lblk = blk->nodes[i].blk;
  rblk = blk->nodes[i + 1].blk;

  assert(lblk->n + rblk->n < NGTCP2_KSL_MAX_NBLK);

  memcpy(&lblk->nodes[lblk->n], &rblk->nodes[0],
         sizeof(ngtcp2_ksl_node) * rblk->n);

  lblk->n += rblk->n;
  lblk->next = rblk->next;
  if (lblk->next) {
    lblk->next->prev = lblk;
  } else if (ksl->back == rblk) {
    ksl->back = lblk;
  }

  ngtcp2_mem_free(ksl->mem, rblk);

  if (ksl->head == blk && blk->n == 2) {
    ngtcp2_mem_free(ksl->mem, ksl->head);
    ksl->head = lblk;
  } else {
    remove_node(blk, i + 1);
    blk->nodes[i].key = lblk->nodes[lblk->n - 1].key;
  }

  return lblk;
}

/*
 * ksl_relocate_node replaces the key at the index |*pi| in
 * *pblk->nodes with something other without violating contract.  It
 * might involve merging 2 nodes or moving a node to left or right.
 *
 * It assigns the index of the block in |*pblk| where the node is
 * moved to |*pi|.  If merging 2 nodes occurs and it becomes new head,
 * the new head is assigned to |*pblk| and it still contains the key.
 * The caller should handle this situation.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 */
static int ksl_relocate_node(ngtcp2_ksl *ksl, ngtcp2_ksl_blk **pblk,
                             size_t *pi) {
  ngtcp2_ksl_blk *blk = *pblk;
  size_t i = *pi;
  ngtcp2_ksl_node *node = &blk->nodes[i];
  ngtcp2_ksl_node *rnode = &blk->nodes[i + 1];
  size_t j;
  int rv;

  assert(i + 1 < blk->n);

  if (node->blk->n == NGTCP2_KSL_MIN_NBLK &&
      node->blk->n + rnode->blk->n < NGTCP2_KSL_MAX_NBLK) {
    j = node->blk->n - 1;
    blk = ksl_merge_node(ksl, blk, i);
    if (blk != ksl->head) {
      return 0;
    }
    *pblk = blk;
    i = j;
    if (blk->leaf) {
      *pi = i;
      return 0;
    }
    node = &blk->nodes[i];
    rnode = &blk->nodes[i + 1];

    if (node->blk->n == NGTCP2_KSL_MIN_NBLK &&
        node->blk->n + rnode->blk->n < NGTCP2_KSL_MAX_NBLK) {
      j = node->blk->n - 1;
      blk = ksl_merge_node(ksl, blk, i);
      assert(blk != ksl->head);
      *pi = j;
      return 0;
    }
  }

  if (node->blk->n < rnode->blk->n) {
    node->blk->nodes[node->blk->n] = rnode->blk->nodes[0];
    memmove(&rnode->blk->nodes[0], &rnode->blk->nodes[1],
            sizeof(ngtcp2_ksl_node) * (rnode->blk->n - 1));
    --rnode->blk->n;
    ++node->blk->n;
    node->key = node->blk->nodes[node->blk->n - 1].key;
    *pi = i;
    return 0;
  }

  if (rnode->blk->n == NGTCP2_KSL_MAX_NBLK) {
    rv = ksl_split_node(ksl, blk, i + 1);
    if (rv != 0) {
      return rv;
    }
  }

  memmove(&rnode->blk->nodes[1], &rnode->blk->nodes[0],
          sizeof(ngtcp2_ksl_node) * rnode->blk->n);

  rnode->blk->nodes[0] = node->blk->nodes[node->blk->n - 1];
  ++rnode->blk->n;

  --node->blk->n;

  node->key = node->blk->nodes[node->blk->n - 1].key;

  *pi = i + 1;
  return 0;
}

/*
 * shift_left moves the first node in blk->nodes[i]->blk->nodes to
 * blk->nodes[i - 1]->blk->nodes.
 */
static void shift_left(ngtcp2_ksl_blk *blk, size_t i) {
  ngtcp2_ksl_node *lnode, *rnode;

  assert(i > 0);

  lnode = &blk->nodes[i - 1];
  rnode = &blk->nodes[i];

  assert(lnode->blk->n < NGTCP2_KSL_MAX_NBLK);
  assert(rnode->blk->n > NGTCP2_KSL_MIN_NBLK);

  lnode->blk->nodes[lnode->blk->n] = rnode->blk->nodes[0];
  lnode->key = lnode->blk->nodes[lnode->blk->n].key;
  ++lnode->blk->n;

  --rnode->blk->n;
  memmove(&rnode->blk->nodes[0], &rnode->blk->nodes[1],
          sizeof(ngtcp2_ksl_node) * rnode->blk->n);
}

/*
 * shift_right moves the last node in blk->nodes[i]->blk->nodes to
 * blk->nodes[i + 1]->blk->nodes.
 */
static void shift_right(ngtcp2_ksl_blk *blk, size_t i) {
  ngtcp2_ksl_node *lnode, *rnode;

  assert(i < blk->n - 1);

  lnode = &blk->nodes[i];
  rnode = &blk->nodes[i + 1];

  assert(lnode->blk->n > NGTCP2_KSL_MIN_NBLK);
  assert(rnode->blk->n < NGTCP2_KSL_MAX_NBLK);

  memmove(&rnode->blk->nodes[1], &rnode->blk->nodes[0],
          sizeof(ngtcp2_ksl_node) * rnode->blk->n);
  ++rnode->blk->n;
  rnode->blk->nodes[0] = lnode->blk->nodes[lnode->blk->n - 1];

  --lnode->blk->n;
  lnode->key = lnode->blk->nodes[lnode->blk->n - 1].key;
}

/*
 * key_equal returns nonzero if |lhs| and |rhs| are equal using the
 * function |compar|.
 */
static int key_equal(ngtcp2_ksl_compar compar, const ngtcp2_ksl_key *lhs,
                     const ngtcp2_ksl_key *rhs) {
  return !compar(lhs, rhs) && !compar(rhs, lhs);
}

int ngtcp2_ksl_remove(ngtcp2_ksl *ksl, ngtcp2_ksl_it *it,
                      const ngtcp2_ksl_key *key) {
  ngtcp2_ksl_blk *blk = ksl->head, *lblk, *rblk;
  ngtcp2_ksl_node *node;
  size_t i, j;
  int rv;

  if (!blk->leaf && blk->n == NGTCP2_KSL_MAX_NBLK) {
    rv = ksl_split_head(ksl);
    if (rv != 0) {
      return rv;
    }
    blk = ksl->head;
  }

  for (;;) {
    for (i = 0, node = &blk->nodes[i]; ksl->compar(&node->key, key);
         ++i, ++node)
      ;

    if (blk->leaf) {
      assert(i < blk->n);
      remove_node(blk, i);
      --ksl->n;
      if (it) {
        if (blk->n == i) {
          ngtcp2_ksl_it_init(it, blk->next, 0, ksl->compar, &ksl->inf_key);
        } else {
          ngtcp2_ksl_it_init(it, blk, i, ksl->compar, &ksl->inf_key);
        }
      }
      return 0;
    }

    if (node->blk->n == NGTCP2_KSL_MAX_NBLK) {
      rv = ksl_split_node(ksl, blk, i);
      if (rv != 0) {
        return rv;
      }
      if (ksl->compar(&node->key, key)) {
        ++i;
        node = &blk->nodes[i];
      }
    }

    if (key_equal(ksl->compar, &node->key, key)) {
      rv = ksl_relocate_node(ksl, &blk, &i);
      if (rv != 0) {
        return rv;
      }
      if (!blk->leaf) {
        node = &blk->nodes[i];
        blk = node->blk;
      }
    } else if (node->blk->n == NGTCP2_KSL_MIN_NBLK) {
      j = i == 0 ? 0 : i - 1;

      lblk = blk->nodes[j].blk;
      rblk = blk->nodes[j + 1].blk;

      if (lblk->n + rblk->n < NGTCP2_KSL_MAX_NBLK) {
        blk = ksl_merge_node(ksl, blk, j);
      } else {
        if (i == j) {
          shift_left(blk, j + 1);
        } else {
          shift_right(blk, j);
        }
        blk = node->blk;
      }
    } else {
      blk = node->blk;
    }
  }
}

ngtcp2_ksl_it ngtcp2_ksl_lower_bound(ngtcp2_ksl *ksl,
                                     const ngtcp2_ksl_key *key) {
  ngtcp2_ksl_blk *blk = ksl->head;
  ngtcp2_ksl_node *node;
  size_t i;

  for (;;) {
    for (i = 0, node = &blk->nodes[i]; ksl->compar(&node->key, key);
         ++i, node = &blk->nodes[i])
      ;

    if (blk->leaf) {
      ngtcp2_ksl_it it;
      ngtcp2_ksl_it_init(&it, blk, i, ksl->compar, &ksl->inf_key);
      return it;
    }

    blk = node->blk;
  }
}

void ngtcp2_ksl_update_key(ngtcp2_ksl *ksl, const ngtcp2_ksl_key *old_key,
                           const ngtcp2_ksl_key *new_key) {
  ngtcp2_ksl_blk *blk = ksl->head;
  ngtcp2_ksl_node *node;
  size_t i;

  for (;;) {
    for (i = 0, node = &blk->nodes[i]; ksl->compar(&node->key, old_key);
         ++i, node = &blk->nodes[i])
      ;

    if (blk->leaf) {
      assert(key_equal(ksl->compar, &node->key, old_key));
      node->key = *new_key;
      return;
    }

    if (key_equal(ksl->compar, &node->key, old_key)) {
      node->key = *new_key;
    }

    blk = node->blk;
  }
}

static void ksl_print(ngtcp2_ksl *ksl, const ngtcp2_ksl_blk *blk,
                      size_t level) {
  size_t i;

  fprintf(stderr, "LV=%zu n=%zu\n", level, blk->n);

  if (blk->leaf) {
    for (i = 0; i < blk->n; ++i) {
      fprintf(stderr, " %" PRId64, blk->nodes[i].key.i);
    }
    fprintf(stderr, "\n");
    return;
  }

  for (i = 0; i < blk->n; ++i) {
    ksl_print(ksl, blk->nodes[i].blk, level + 1);
  }
}

size_t ngtcp2_ksl_len(ngtcp2_ksl *ksl) { return ksl->n; }

void ngtcp2_ksl_clear(ngtcp2_ksl *ksl) {
  size_t i;
  ngtcp2_ksl_blk *head;

  if (!ksl->head->leaf) {
    for (i = 0; i < ksl->head->n; ++i) {
      free_blk(ksl->head->nodes[i].blk, ksl->mem);
    }
  }

  ksl->front = ksl->back = ksl->head;
  ksl->n = 0;

  head = ksl->head;

  head->next = head->prev = NULL;
  head->n = 1;
  head->leaf = 1;
  head->nodes[0].key = ksl->inf_key;
  head->nodes[0].data = NULL;
}

void ngtcp2_ksl_print(ngtcp2_ksl *ksl) { ksl_print(ksl, ksl->head, 0); }

ngtcp2_ksl_it ngtcp2_ksl_begin(const ngtcp2_ksl *ksl) {
  ngtcp2_ksl_it it;
  ngtcp2_ksl_it_init(&it, ksl->front, 0, ksl->compar, &ksl->inf_key);
  return it;
}

ngtcp2_ksl_it ngtcp2_ksl_end(const ngtcp2_ksl *ksl) {
  ngtcp2_ksl_it it;
  ngtcp2_ksl_it_init(&it, ksl->back, ksl->back->n - 1, ksl->compar,
                     &ksl->inf_key);
  return it;
}

void ngtcp2_ksl_it_init(ngtcp2_ksl_it *it, const ngtcp2_ksl_blk *blk, size_t i,
                        ngtcp2_ksl_compar compar,
                        const ngtcp2_ksl_key *inf_key) {
  it->blk = blk;
  it->i = i;
  it->compar = compar;
  it->inf_key = *inf_key;
}

void *ngtcp2_ksl_it_get(const ngtcp2_ksl_it *it) {
  return it->blk->nodes[it->i].data;
}

void ngtcp2_ksl_it_next(ngtcp2_ksl_it *it) {
  if (++it->i == it->blk->n) {
    it->blk = it->blk->next;
    it->i = 0;
  }
}

void ngtcp2_ksl_it_prev(ngtcp2_ksl_it *it) {
  assert(!ngtcp2_ksl_it_begin(it));

  if (it->i == 0) {
    it->blk = it->blk->prev;
    it->i = it->blk->n - 1;
  } else {
    --it->i;
  }
}

int ngtcp2_ksl_it_end(const ngtcp2_ksl_it *it) {
  return key_equal(it->compar, &it->blk->nodes[it->i].key, &it->inf_key);
}

int ngtcp2_ksl_it_begin(const ngtcp2_ksl_it *it) {
  return it->i == 0 && it->blk->prev == NULL;
}

ngtcp2_ksl_key ngtcp2_ksl_it_key(const ngtcp2_ksl_it *it) {
  return it->blk->nodes[it->i].key;
}

ngtcp2_ksl_key *ngtcp2_ksl_key_i(ngtcp2_ksl_key *key, int64_t i) {
  key->i = i;
  return key;
}

ngtcp2_ksl_key *ngtcp2_ksl_key_ptr(ngtcp2_ksl_key *key, const void *ptr) {
  key->ptr = ptr;
  return key;
}
