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
#include "ngtcp2_ringbuf.h"

/* NGTCP2_ACKTR_MAX_ENT is the maximum number of ngtcp2_acktr_entry
   which ngtcp2_acktr stores. */
#define NGTCP2_ACKTR_MAX_ENT 1024

struct ngtcp2_conn;
typedef struct ngtcp2_conn ngtcp2_conn;

struct ngtcp2_acktr_entry;
typedef struct ngtcp2_acktr_entry ngtcp2_acktr_entry;

/*
 * ngtcp2_acktr_entry is a single packet which needs to be acked.
 */
struct ngtcp2_acktr_entry {
  ngtcp2_acktr_entry **pprev, *next;
  uint64_t pkt_num;
  ngtcp2_tstamp tstamp;
  uint8_t unprotected;
};

/*
 * ngtcp2_acktr_entry_new allocates memory for ent, and initializes it
 * with the given parameters.
 */
int ngtcp2_acktr_entry_new(ngtcp2_acktr_entry **ent, uint64_t pkt_num,
                           ngtcp2_tstamp tstamp, uint8_t unprotected,
                           ngtcp2_mem *mem);

/*
 * ngtcp2_acktr_entry_del deallocates memory allocated for |ent|.  It
 * deallocates memory pointed by |ent|.
 */
void ngtcp2_acktr_entry_del(ngtcp2_acktr_entry *ent, ngtcp2_mem *mem);

typedef struct {
  ngtcp2_ack *ack;
  uint64_t pkt_num;
  ngtcp2_tstamp ts;
  uint8_t unprotected;
} ngtcp2_acktr_ack_entry;

/*
 * ngtcp2_acktr tracks received packets which we have to send ack.
 */
typedef struct {
  ngtcp2_ringbuf acks;
  /* ent points to the head of list which is ordered by the decreasing
     order of packet number. */
  ngtcp2_acktr_entry *ent, *tail;
  ngtcp2_mem *mem;
  size_t nack;
  /* active_ack is nonzero if ACK frame should be sent actively. */
  int active_ack;
} ngtcp2_acktr;

/*
 * ngtcp2_acktr_init initializes |acktr|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 */
int ngtcp2_acktr_init(ngtcp2_acktr *acktr, ngtcp2_mem *mem);

/*
 * ngtcp2_acktr_free frees resources allocated for |acktr|.  It frees
 * any ngtcp2_acktr_entry directly or indirectly pointed by
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
int ngtcp2_acktr_add(ngtcp2_acktr *acktr, ngtcp2_acktr_entry *ent,
                     int active_ack);

/*
 * ngtcp2_acktr_forget removes all entries from |ent| to the end of
 * the list.  This function assumes that |ent| is linked directly, or
 * indirectly from acktr->ent.
 */
void ngtcp2_acktr_forget(ngtcp2_acktr *acktr, ngtcp2_acktr_entry *ent);

/*
 * ngtcp2_acktr_get returns the pointer to the entry which has the
 * largest packet number to be acked.  If there is no entry, this
 * function returns NULL.
 */
ngtcp2_acktr_entry **ngtcp2_acktr_get(ngtcp2_acktr *acktr);

/*
 * ngtcp2_acktr_removes and frees the head of entries, which has the
 * largest packet number.
 */
void ngtcp2_acktr_pop(ngtcp2_acktr *acktr);

/*
 * ngtcp2_acktr_add_ack adds the outgoing ACK frame |fr| to |acktr|.
 * |pkt_num| is the packet number which |fr| belongs.  |unprotected|
 * is nonzero if the packet is an unprotected packet.  This function
 * transfers the ownership of |fr| to |acktr|.
 */
void ngtcp2_acktr_add_ack(ngtcp2_acktr *acktr, uint64_t pkt_num, ngtcp2_ack *fr,
                          ngtcp2_tstamp ts, uint8_t unprotected);

/*
 * ngtcp2_acktr_recv_ack processes the incoming ACK frame |fr|.
 * |pkt_num| is a packet number which includes |fr|.  |unprotected| is
 * nonzero if the packet which |fr| is included is an unprotected
 * packet.  If we receive ACK which acknowledges the ACKs added by
 * ngtcp2_acktr_add_ack, ngtcp2_acktr_entry which the outgoing ACK
 * acknowledges is removed.
 */
void ngtcp2_acktr_recv_ack(ngtcp2_acktr *acktr, uint64_t pkt_num,
                           const ngtcp2_ack *fr, uint8_t unprotected,
                           ngtcp2_conn *conn, ngtcp2_tstamp ts);

#endif /* NGTCP2_ACKTR_H */
