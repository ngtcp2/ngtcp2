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
#ifndef NGTCP2_RTB_H
#define NGTCP2_RTB_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <ngtcp2/ngtcp2.h>

#include "ngtcp2_ksl.h"

struct ngtcp2_conn;
typedef struct ngtcp2_conn ngtcp2_conn;

struct ngtcp2_frame_chain;
typedef struct ngtcp2_frame_chain ngtcp2_frame_chain;

struct ngtcp2_log;
typedef struct ngtcp2_log ngtcp2_log;

/*
 * ngtcp2_frame_chain chains frames in a single packet.
 */
struct ngtcp2_frame_chain {
  ngtcp2_frame_chain *next;
  ngtcp2_frame fr;
};

/*
 * ngtcp2_frame_chain_new allocates ngtcp2_frame_chain object and
 * assigns its pointer to |*pfrc|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 */
int ngtcp2_frame_chain_new(ngtcp2_frame_chain **pfrc, ngtcp2_mem *mem);

/*
 * ngtcp2_frame_chain_del deallocates |frc|.  It also deallocates the
 * memory pointed by |frc|.
 */
void ngtcp2_frame_chain_del(ngtcp2_frame_chain *frc, ngtcp2_mem *mem);

/*
 * ngtcp2_frame_chain_init initializes |frc|.
 */
void ngtcp2_frame_chain_init(ngtcp2_frame_chain *frc);

/*
 * ngtcp2_frame_chain_list_copy creates a copy of |frc| following next
 * field.  It makes copy of each ngtcp2_frame_chain object pointed by
 * next field.
 *
 * This function returns the head of copied list if it succeeds, or
 * NULL.
 */
ngtcp2_frame_chain *ngtcp2_frame_chain_list_copy(ngtcp2_frame_chain *frc,
                                                 ngtcp2_mem *mem);

/*
 * ngtcp2_frame_chain_list_del deletes |frc|, and all objects
 * connected by next field.
 */
void ngtcp2_frame_chain_list_del(ngtcp2_frame_chain *frc, ngtcp2_mem *mem);

typedef enum {
  NGTCP2_RTB_FLAG_NONE = 0x00,
  /* NGTCP2_RTB_FLAG_UNPROTECTED indicates that the entry contains
     frames which were sent in an unprotected packet. */
  NGTCP2_RTB_FLAG_UNPROTECTED = 0x1,
  /* NGTCP2_RTB_FLAG_PROBE indicates that the entry includes a probe
     packet. */
  NGTCP2_RTB_FLAG_PROBE = 0x2,
} ngtcp2_rtb_flag;

struct ngtcp2_rtb_entry;
typedef struct ngtcp2_rtb_entry ngtcp2_rtb_entry;

/*
 * ngtcp2_rtb_entry is an object stored in ngtcp2_rtb.  It corresponds
 * to the one packet which is waiting for its ACK.
 */
struct ngtcp2_rtb_entry {
  ngtcp2_rtb_entry *next;

  ngtcp2_pkt_hd hd;
  ngtcp2_frame_chain *frc;
  /* ts is the time point when a packet included in this entry is sent
     to a peer. */
  ngtcp2_tstamp ts;
  /* pktlen is the length of QUIC packet */
  size_t pktlen;
  /* src_pkt_num is a packet number of a original packet if this entry
     includes a probe packet duplicating original. */
  int64_t src_pkt_num;
  /* flags is bitwise-OR of zero or more of ngtcp2_rtb_flag. */
  uint8_t flags;
};

/*
 * ngtcp2_rtb_entry_new allocates ngtcp2_rtb_entry object, and assigns
 * its pointer to |*pent|.  On success, |*pent| takes ownership of
 * |frc|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 */
int ngtcp2_rtb_entry_new(ngtcp2_rtb_entry **pent, const ngtcp2_pkt_hd *hd,
                         ngtcp2_frame_chain *frc, ngtcp2_tstamp ts,
                         size_t pktlen, uint8_t flags, ngtcp2_mem *mem);

/*
 * ngtcp2_rtb_entry_del deallocates |ent|.  It also frees memory
 * pointed by |ent|.
 */
void ngtcp2_rtb_entry_del(ngtcp2_rtb_entry *ent, ngtcp2_mem *mem);

typedef struct {
  uint64_t cwnd;
  uint64_t ssthresh;
  /* eor_pkt_num is "end_of_recovery" */
  uint64_t eor_pkt_num;
} ngtcp2_cc_stat;

/*
 * ngtcp2_rtb tracks sent packets, and its ACK timeout for
 * retransmission.
 */
typedef struct {
  ngtcp2_cc_stat ccs;
  /* ents includes ngtcp2_rtb_entry sorted by decreasing order of
     packet number. */
  ngtcp2_ksl ents;
  /* lost_unprotected_head is like head, but it only includes
     unprotected packet entries which are considered to be lost.
     Currently, this list is not listed in the particular order. */
  ngtcp2_rtb_entry *lost_unprotected_head;
  /* lost_protected_head is like head, but it only includes protected
     packet entries which are considered to be lost.  Currently, this
     list is not listed in the particular order. */
  ngtcp2_rtb_entry *lost_protected_head;
  ngtcp2_log *log;
  ngtcp2_mem *mem;
  /* bytes_in_flight is the sum of packet length linked from head. */
  size_t bytes_in_flight;
  /* largest_acked_tx_pkt_num is the largest packet number
     acknowledged by the peer. */
  int64_t largest_acked_tx_pkt_num;
  /* num_unprotected is the number of unprotected (handshake) packets
     in-flight. */
  size_t num_unprotected;
} ngtcp2_rtb;

/*
 * ngtcp2_rtb_init initializes |rtb|.
 */
void ngtcp2_rtb_init(ngtcp2_rtb *rtb, ngtcp2_log *log, ngtcp2_mem *mem);

/*
 * ngtcp2_rtb_free deallocates resources allocated for |rtb|.
 */
void ngtcp2_rtb_free(ngtcp2_rtb *rtb);

/*
 * ngtcp2_rtb_add adds |ent| to |rtb|.
 */
void ngtcp2_rtb_add(ngtcp2_rtb *rtb, ngtcp2_rtb_entry *ent);

/*
 * ngtcp2_rtb_insert_range inserts linked list pointed by |head| to
 * rtb->head keeping the assertion that rtb->head is sorted by
 * decreasing order of packet number.  The linked list pointed by
 * |head| is assumed to be sorted by decreasing order of packet
 * number.
 */
void ngtcp2_rtb_insert_range(ngtcp2_rtb *rtb, ngtcp2_rtb_entry *head);

/*
 * ngtcp2_rtb_head returns the iterator which points to the entry
 * which has the largest packet number.  If there is no entry,
 * returned value satisfies ngtcp2_ksl_it_end(&it) != 0.
 */
ngtcp2_ksl_it ngtcp2_rtb_head(ngtcp2_rtb *rtb);

/*
 * ngtcp2_rtb_lost_protected_head returns the first element of lost
 * protected packet.
 */
ngtcp2_rtb_entry *ngtcp2_rtb_lost_protected_head(ngtcp2_rtb *rtb);

/*
 * ngtcp2_rtb_lost_protected_pop removes the first entry of lost
 * protected packet.  It does nothing if there is no entry.
 */
void ngtcp2_rtb_lost_protected_pop(ngtcp2_rtb *rtb);

/*
 * ngtcp2_rtb_lost_unprotected_head returns the first element of lost
 * unprotected packet.
 */
ngtcp2_rtb_entry *ngtcp2_rtb_lost_unprotected_head(ngtcp2_rtb *rtb);

/*
 * ngtcp2_rtb_lost_unprotected_pop removes the first entry of lost
 * unprotected packet.  It does nothing if there is no entry.
 */
void ngtcp2_rtb_lost_unprotected_pop(ngtcp2_rtb *rtb);

/*
 * ngtcp2_rtb_recv_ack removes acked ngtcp2_rtb_entry from |rtb|.
 * |pkt_num| is a packet number which includes |fr|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User callback failed
 */
int ngtcp2_rtb_recv_ack(ngtcp2_rtb *rtb, const ngtcp2_ack *fr, int unprotected,
                        ngtcp2_conn *conn, ngtcp2_tstamp ts);

void ngtcp2_rtb_detect_lost_pkt(ngtcp2_rtb *rtb, ngtcp2_rcvry_stat *rcs,
                                uint64_t largest_ack, uint64_t last_tx_pkt_num,
                                ngtcp2_tstamp ts);

void ngtcp2_rtb_mark_unprotected_lost(ngtcp2_rtb *rtb);

/*
 * ngtcp2_rtb_lost_protected_add insert |ent| to the head of lost
 * protected packets list.
 */
void ngtcp2_rtb_lost_protected_insert(ngtcp2_rtb *rtb, ngtcp2_rtb_entry *ent);

/*
 * ngtcp2_rtb_lost_unprotected_add insert |ent| to the head of lost
 * unprotected packets list.
 */
void ngtcp2_rtb_lost_unprotected_insert(ngtcp2_rtb *rtb, ngtcp2_rtb_entry *ent);

/*
 * ngtcp2_rtb_has_lost_pkt returns nonzero if |rtb| has at least one
 * lost packet to retransmit.
 */
int ngtcp2_rtb_has_lost_pkt(ngtcp2_rtb *rtb);

#endif /* NGTCP2_RTB_H */
