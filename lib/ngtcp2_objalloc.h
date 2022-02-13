/*
 * ngtcp2
 *
 * Copyright (c) 2022 ngtcp2 contributors
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
#ifndef NGTCP2_OBJALLOC_H
#define NGTCP2_OBJALLOC_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <ngtcp2/ngtcp2.h>

#include "ngtcp2_balloc.h"
#include "ngtcp2_obj_pool.h"
#include "ngtcp2_macro.h"

typedef struct ngtcp2_objalloc {
  ngtcp2_balloc balloc;
  ngtcp2_obj_pool opl;
} ngtcp2_objalloc;

void ngtcp2_objalloc_init(ngtcp2_objalloc *objalloc, size_t blklen,
                          const ngtcp2_mem *mem);

void ngtcp2_objalloc_free(ngtcp2_objalloc *objalloc);

void ngtcp2_objalloc_clear(ngtcp2_objalloc *objalloc);

#define ngtcp2_objalloc_def(NAME, TYPE, OPLENTFIELD)                           \
  inline static void ngtcp2_objalloc_##NAME##_init(                            \
      ngtcp2_objalloc *objalloc, size_t nmemb, const ngtcp2_mem *mem) {        \
    ngtcp2_objalloc_init(objalloc,                                             \
                         ((sizeof(TYPE) + 0xfllu) & ~0xfllu) * nmemb, mem);    \
  }                                                                            \
                                                                               \
  inline static TYPE *ngtcp2_objalloc_##NAME##_get(                            \
      ngtcp2_objalloc *objalloc) {                                             \
    ngtcp2_obj_pool_entry *oplent = ngtcp2_obj_pool_pop(&objalloc->opl);       \
    TYPE *obj;                                                                 \
    int rv;                                                                    \
                                                                               \
    if (!oplent) {                                                             \
      rv = ngtcp2_balloc_get(&objalloc->balloc, (void **)&obj, sizeof(TYPE));  \
      if (rv != 0) {                                                           \
        return NULL;                                                           \
      }                                                                        \
                                                                               \
      return obj;                                                              \
    }                                                                          \
                                                                               \
    return ngtcp2_struct_of(oplent, TYPE, OPLENTFIELD);                        \
  }                                                                            \
                                                                               \
  inline static TYPE *ngtcp2_objalloc_##NAME##_len_get(                        \
      ngtcp2_objalloc *objalloc, size_t len) {                                 \
    ngtcp2_obj_pool_entry *oplent = ngtcp2_obj_pool_pop(&objalloc->opl);       \
    TYPE *obj;                                                                 \
    int rv;                                                                    \
                                                                               \
    if (!oplent) {                                                             \
      rv = ngtcp2_balloc_get(&objalloc->balloc, (void **)&obj, len);           \
      if (rv != 0) {                                                           \
        return NULL;                                                           \
      }                                                                        \
                                                                               \
      return obj;                                                              \
    }                                                                          \
                                                                               \
    return ngtcp2_struct_of(oplent, TYPE, OPLENTFIELD);                        \
  }                                                                            \
                                                                               \
  inline static void ngtcp2_objalloc_##NAME##_release(                         \
      ngtcp2_objalloc *objalloc, TYPE *obj) {                                  \
    ngtcp2_obj_pool_push(&objalloc->opl, &obj->OPLENTFIELD);                   \
  }

#endif /* NGTCP2_OBJALLOC_H */
