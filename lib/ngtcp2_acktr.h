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

/* ns */
#define NGTCP2_DEFAULT_ACK_DELAY 25000000

struct ngtcp2_conn;
typedef struct ngtcp2_conn ngtcp2_conn;

struct ngtcp2_acktr_entry;
typedef struct ngtcp2_acktr_entry ngtcp2_acktr_entry;

struct ngtcp2_log;
typedef struct ngtcp2_log ngtcp2_log;

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
                           ngtcp2_tstamp tstamp, int unprotected,
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
  uint8_t ack_only;
} ngtcp2_acktr_ack_entry;

typedef enum {
  NGTCP2_ACKTR_FLAG_NONE = 0x00,
  /* NGTCP2_ACKTR_FLAG_ACTIVE_ACK_UNPROTECTED indicates that there are
     pending unprotected packet to be acknowledged. */
  NGTCP2_ACKTR_FLAG_ACTIVE_ACK_UNPROTECTED = 0x01,
  /* NGTCP2_ACKTR_FLAG_ACTIVE_ACK_PROTECTED indicates that there are
     pending protected packet to be acknowledged. */
  NGTCP2_ACKTR_FLAG_ACTIVE_ACK_PROTECTED = 0x02,
  /* NGTCP2_ACKTR_FLAG_ACTIVE_ACK is bitwise OR of
     NGTCP2_ACKTR_FLAG_ACTIVE_ACK_UNPROTECTED and
     NGTCP2_ACKTR_FLAG_ACTIVE_ACK_PROTECTED. */
  NGTCP2_ACKTR_FLAG_ACTIVE_ACK = NGTCP2_ACKTR_FLAG_ACTIVE_ACK_UNPROTECTED |
                                 NGTCP2_ACKTR_FLAG_ACTIVE_ACK_PROTECTED,
  /* NGTCP2_ACKTR_FLAG_PENDING_ACK_FINISHED is set when server
     received TLSv1.3 Finished message, and its acknowledgement is
     pending. */
  NGTCP2_ACKTR_FLAG_PENDING_FINISHED_ACK = 0x40,
  /* NGTCP2_ACKTR_FLAG_ACK_FINISHED_ACK is set when server received
     acknowledgement for ACK which acknowledges the last handshake
     packet from client (which contains TLSv1.3 Finished message). */
  NGTCP2_ACKTR_FLAG_ACK_FINISHED_ACK = 0x80,
  /* NGTCP2_ACKTR_FLAG_DELAYED_ACK_EXPIRED is set when delayed ACK
     timer is expired. */
  NGTCP2_ACKTR_FLAG_DELAYED_ACK_EXPIRED = 0x0100,
} ngtcp2_acktr_flag;

/*
 * ngtcp2_acktr tracks received packets which we have to send ack.
 */
typedef struct {
  ngtcp2_ringbuf acks;
  ngtcp2_ringbuf hs_acks;
  /* ent points to the head of list which is ordered by the decreasing
     order of packet number. */
  ngtcp2_acktr_entry *ent, *tail;
  ngtcp2_log *log;
  ngtcp2_mem *mem;
  size_t nack;
  /* last_hs_ack_pkt_num is the earliest outgoing packet number which
     contains an acknowledgement for a last handshake packet.  This
     field is effectively used by server, and a last handshake packet
     contains client Finished message.  The current implementation
     does not remove ngtcp2_ack_entry unless it is acknowledged, or
     evicted due to the limitation of capacity.  When a local endpoint
     received an acknowledgement to this packet or later, unless
     ngtcp2_ack_entry is evicted, we are sure that peer knows that the
     local endpoint acknowledged peer's last handshake packet.  Then
     the local endpoint can start rejecting unprotected packet.*/
  uint64_t last_hs_ack_pkt_num;
  /* flags is bitwise OR of zero, or more of ngtcp2_ack_flag. */
  uint16_t flags;
  /* first_unacked_ts is timestamp when ngtcp2_acktr_entry is added
     first time after the last outgoing protected ACK frame. */
  ngtcp2_tstamp first_unacked_ts;
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
int ngtcp2_acktr_init(ngtcp2_acktr *acktr, ngtcp2_log *log, ngtcp2_mem *mem);

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
                     int active_ack, ngtcp2_tstamp ts);

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
 * transfers the ownership of |fr| to |acktr|.  |ack_only| is nonzero
 * if the packet contains an ACK frame only.  This function returns a
 * pointer to the object it adds.
 */
ngtcp2_acktr_ack_entry *ngtcp2_acktr_add_ack(ngtcp2_acktr *acktr,
                                             uint64_t pkt_num, ngtcp2_ack *fr,
                                             ngtcp2_tstamp ts, int unprotected,
                                             int ack_only);

/*
 * ngtcp2_acktr_recv_ack processes the incoming ACK frame |fr|.
 * |pkt_num| is a packet number which includes |fr|.  |unprotected| is
 * nonzero if the packet which |fr| is included is an unprotected
 * packet.  If we receive ACK which acknowledges the ACKs added by
 * ngtcp2_acktr_add_ack, ngtcp2_acktr_entry which the outgoing ACK
 * acknowledges is removed.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User-defined callback function failed.
 */
int ngtcp2_acktr_recv_ack(ngtcp2_acktr *acktr, const ngtcp2_ack *fr,
                          int unprotected, ngtcp2_conn *conn, ngtcp2_tstamp ts);

/*
 * ngtcp2_acktr_commit_ack tells |acktr| that ACK frame is generated.
 * If |unprotected| is nonzero, ACK frame will be sent in an
 * unprotected packet.
 */
void ngtcp2_acktr_commit_ack(ngtcp2_acktr *acktr, int unprotected);

/*
 * ngtcp2_acktr_require_active_ack returns nonzero if ACK frame should
 * be generated actively.  If |unprotected| is nonzero, entries sent
 * in an unprotected packet are taken into consideration.
 */
int ngtcp2_acktr_require_active_ack(ngtcp2_acktr *acktr, int unprotected,
                                    uint64_t max_ack_delay, ngtcp2_tstamp ts);

/*
 * ngtcp2_acktr_expire_delayed_ack expires delayed ACK timer.  This
 * function sets NGTCP2_ACKTR_FLAG_DELAYED_ACK_EXPIRED so that we know
 * that the timer has expired.
 */
void ngtcp2_acktr_expire_delayed_ack(ngtcp2_acktr *acktr);

/*
 * ngtcp2_acktr_include_protected_pkt returns nonzero if |acktr|
 * includes protected packet to ack.
 */
int ngtcp2_acktr_include_protected_pkt(ngtcp2_acktr *acktr);

#endif /* NGTCP2_ACKTR_H */
