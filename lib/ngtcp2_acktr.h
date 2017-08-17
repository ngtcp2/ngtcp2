/*
 * ngtcp2
 *
 * Copyright (c) 2017 ngtcp2 contributors
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
#ifndef NGTCP2_ACKTR_H
#define NGTCP2_ACKTR_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <ngtcp2/ngtcp2.h>

#include "ngtcp2_mem.h"

typedef enum {
  NGTCP2_ACKTR_FLAG_NONE = 0x00,
  /* NGTCP2_ACKTR_FLAG_PASSIVE means that the ack should not be
     generated with passive entry only, but it should with at least
     one non-passive entry. */
  NGTCP2_ACKTR_FLAG_PASSIVE = 0x01,
} ngtcp2_acktr_flag;

struct ngtcp2_acktr_entry;
typedef struct ngtcp2_acktr_entry ngtcp2_acktr_entry;

/*
 * ngtcp2_acktr_entry is a single packet which needs to be acked.
 */
struct ngtcp2_acktr_entry {
  ngtcp2_acktr_entry *next;
  uint64_t pkt_num;
  ngtcp2_tstamp tstamp;
  /* flags is bitwise OR of zero or more of ngtcp2_acktr_flag. */
  uint8_t flags;
};

/*
 * ngtcp2_acktr_entry_new allocates memory for ent, and initializes it
 * with the given parameters.
 */
int ngtcp2_acktr_entry_new(ngtcp2_acktr_entry **ent, uint64_t pkt_num,
                           ngtcp2_tstamp tstamp, uint8_t flags,
                           ngtcp2_mem *mem);

/*
 * ngtcp2_acktr_entry_del deallocates memory allocated for |ent|.  It
 * deallocates memory pointed by |ent|.
 */
void ngtcp2_acktr_entry_del(ngtcp2_acktr_entry *ent, ngtcp2_mem *mem);

/*
 * ngtcp2_acktr tracks received packets which we have to send ack.
 */
typedef struct {
  /* ent points to the head of list which is ordered by the decreasing
     order of packet number. */
  ngtcp2_acktr_entry *ent;
  /* nactive_ack is the number of entries which do not have
     NGTCP2_ACKTR_FLAG_PASSIVE flag set. */
  size_t nactive_ack;
} ngtcp2_acktr;

/*
 * ngtcp2_acktr_init initializes |acktr|.
 */
void ngtcp2_acktr_init(ngtcp2_acktr *acktr);

/*
 * ngtcp2_acktr_free frees resources allocated for |acktr|.  It does
 * not free any ngtcp2_acktr_entry directly or indirectly pointed by
 * acktr->ent.
 */
void ngtcp2_acktr_free(ngtcp2_acktr *acktr);

/*
 * ngtcp2_acktr_add adds |ent|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_PROTO
 *     Same packet number has already been included in |acktr|.
 */
int ngtcp2_acktr_add(ngtcp2_acktr *acktr, ngtcp2_acktr_entry *ent);

/*
 * ngtcp2_acktr_get returns the entry which has the largest packet
 * number to be acked.  If there is no entry, this function returns
 * NULL.
 */
ngtcp2_acktr_entry *ngtcp2_acktr_get(ngtcp2_acktr *acktr);

/*
 * ngtcp2_acktr_remove removes the |ent|.
 */
void ngtcp2_acktr_remove(ngtcp2_acktr *acktr, const ngtcp2_acktr_entry *ent);

#endif /* NGTCP2_ACKTR_H */
