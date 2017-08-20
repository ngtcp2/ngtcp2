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
#ifndef NGTCP2_CONN_H
#define NGTCP2_CONN_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <ngtcp2/ngtcp2.h>

#include "ngtcp2_mem.h"
#include "ngtcp2_crypto.h"
#include "ngtcp2_acktr.h"
#include "ngtcp2_rtb.h"
#include "ngtcp2_strm.h"
#include "ngtcp2_mem.h"
#include "ngtcp2_idtr.h"

typedef enum {
  /* Client specific handshake states */
  NGTCP2_CS_CLIENT_INITIAL,
  NGTCP2_CS_CLIENT_WAIT_HANDSHAKE,
  NGTCP2_CS_CLIENT_HANDSHAKE_ALMOST_FINISHED,
  NGTCP2_CS_CLIENT_TLS_HANDSHAKE_FAILED,
  /* Server specific handshake states */
  NGTCP2_CS_SERVER_INITIAL,
  NGTCP2_CS_SERVER_WAIT_HANDSHAKE,
  NGTCP2_CS_SERVER_TLS_HANDSHAKE_FAILED,
  /* Shared by both client and server */
  NGTCP2_CS_POST_HANDSHAKE,
  NGTCP2_CS_CLOSE_WAIT,
} ngtcp2_conn_state;

/* NGTCP2_INITIAL_EXPIRY is initial retransmission timeout in
   microsecond resolution. */
#define NGTCP2_INITIAL_EXPIRY 400000

/* NGTCP2_PKT_DEADLINE_PERIOD is the period of time when the library
   gives up re-sending packet, and closes connection. */
#define NGTCP2_PKT_DEADLINE_PERIOD 5000000

/* NGTCP2_DELAYED_ACK_TIMEOUT is the delayed ACK timeout in
   microsecond resolution. */
#define NGTCP2_DELAYED_ACK_TIMEOUT 25000

/* NGTCP2_MAX_NUM_BUFFED_RX_PPKTS is the maximum number of protected
   packets buffered which arrive before handshake completes. */
#define NGTCP2_MAX_NUM_BUFFED_RX_PPKTS 16

/* NGTCP2_STRM0_MAX_STREAM_DATA is the maximum stream offset that an
   endpoint can send initially. */
#define NGTCP2_STRM0_MAX_STREAM_DATA 65535

struct ngtcp2_pkt_chain;
typedef struct ngtcp2_pkt_chain ngtcp2_pkt_chain;

/*
 * ngtcp2_pkt_chain is the chain of incoming packets buffered.
 */
struct ngtcp2_pkt_chain {
  ngtcp2_pkt_chain *next;
  uint8_t *pkt;
  size_t pktlen;
  ngtcp2_tstamp ts;
};

/*
 * ngtcp2_pkt_chain_new allocates ngtcp2_pkt_chain objects, and
 * assigns its pointer to |*ppc|.  The content of buffer pointed by
 * |pkt| of length |pktlen| is copied into |*ppc|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 */
int ngtcp2_pkt_chain_new(ngtcp2_pkt_chain **ppc, const uint8_t *pkt,
                         size_t pktlen, ngtcp2_tstamp ts, ngtcp2_mem *mem);

/*
 * ngtcp2_pkt_chain_del deallocates |pc|.  It also frees the memory
 * pointed by |pc|.
 */
void ngtcp2_pkt_chain_del(ngtcp2_pkt_chain *pc, ngtcp2_mem *mem);

typedef enum {
  NGTCP2_CONN_FLAG_NONE = 0x00,
  /* NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED is set if handshake
     completed. */
  NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED = 0x01,
  /* NGTCP2_CONN_FLAG_CONN_ID_NEGOTIATED is set if connection ID is
     negotiated.  This is only used for client. */
  NGTCP2_CONN_FLAG_CONN_ID_NEGOTIATED = 0x02,
  /* NGTCP2_CONN_FLAG_TRANSPORT_PARAM_RECVED is set if transport
     parameters are received. */
  NGTCP2_CONN_FLAG_TRANSPORT_PARAM_RECVED = 0x04,
} ngtcp2_conn_flag;

struct ngtcp2_conn {
  int state;
  ngtcp2_conn_callbacks callbacks;
  ngtcp2_strm *strm0;
  ngtcp2_map strms;
  ngtcp2_strm *fc_strms;
  ngtcp2_idtr local_idtr;
  ngtcp2_idtr remote_idtr;
  uint64_t conn_id;
  /* last_tx_pkt_num is the packet number which the local endpoint
     sent last time.*/
  uint64_t last_tx_pkt_num;
  uint64_t max_rx_pkt_num;
  /* max_remote_stream_id is the maximum stream ID of peer initiated
     stream which the local endpoint can accept. */
  uint32_t max_remote_stream_id;
  /* unsent_max_rx_offset_high and unsent_max_rx_offset_low are the
     maximum offset that remote endpoint can send without extending
     MAX_DATA.  This limit is not yet notified to the remote
     endpoint. */
  uint64_t unsent_max_rx_offset_high;
  uint32_t unsent_max_rx_offset_low;
  /* max_rx_offset_high is the maximum offset that remote endpoint can
     send. */
  uint64_t max_rx_offset_high;
  /* rx_offset_high and rx_offset_low are the cumulative sum of stream
     data received for this connection. */
  uint64_t rx_offset_high;
  uint32_t rx_offset_low;
  /* tx_offset_high and tx_offset_low are the offset the local
     endpoint has sent to the remote endpoint. */
  uint64_t tx_offset_high;
  uint32_t tx_offset_low;
  /* max_tx_offset_high is the maximum offset that local endpoint can
     send. */
  uint64_t max_tx_offset_high;
  ngtcp2_frame_chain *frq;
  ngtcp2_mem *mem;
  void *user_data;
  ngtcp2_acktr acktr;
  ngtcp2_rtb rtb;
  uint32_t version;
  /* flags is bitwise OR of zero or more of ngtcp2_conn_flag. */
  uint8_t flags;
  int server;
  ngtcp2_crypto_km *tx_ckm;
  ngtcp2_crypto_km *rx_ckm;
  size_t aead_overhead;
  /* buffed_rx_ppkts is buffered protected packets which come before
     handshake completed due to packet reordering. */
  ngtcp2_pkt_chain *buffed_rx_ppkts;
  ngtcp2_settings local_settings;
  ngtcp2_settings remote_settings;
  /* next_ack_expiry is the timeout of delayed ack. */
  ngtcp2_tstamp next_ack_expiry;
};

/*
 * ngtcp2_conn_emit_pending_recv_handshake delivers pending stream
 * data to the application due to packet reordering.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User callback failed
 * NGTCP2_ERR_TLS_HANDSHAKE
 *     TLS handshake failed, and TLS alert was sent.
 */
int ngtcp2_conn_emit_pending_recv_handshake(ngtcp2_conn *conn,
                                            ngtcp2_strm *strm, uint64_t offset);

/*
 * ngtcp2_conn_sched_ack stores packet number |pkt_num| and its
 * reception timestamp |ts| in order to send its ACK.
 *
 * It returns 0 if it succeeds, or one of the following negative error
 * codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory
 * NGTCP2_ERR_PROTO
 *     Same packet number has already been added.
 */
int ngtcp2_conn_sched_ack(ngtcp2_conn *conn, uint64_t pkt_num,
                          uint8_t acktr_flags, ngtcp2_tstamp ts);

/*
 * ngtcp2_conn_find_stream returns a stream whose stream ID is
 * |stream_id|.  If no such stream is found, it returns NULL.
 */
ngtcp2_strm *ngtcp2_conn_find_stream(ngtcp2_conn *conn, uint32_t stream_id);

/*
 * conn_init_stream initializes |strm|.  Its stream ID is |stream_id|.
 * This function adds |strm| to conn->strms.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory
 */
int ngtcp2_conn_init_stream(ngtcp2_conn *conn, ngtcp2_strm *strm,
                            uint32_t stream_id, void *stream_user_data);

/*
 * ngtcp2_conn_close_stream closes stream |strm|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_INVALID_ARGUMENT
 *     Stream is not found.
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User-defined callback function failed.
 */
int ngtcp2_conn_close_stream(ngtcp2_conn *conn, ngtcp2_strm *strm,
                             uint32_t error_code);

/*
 * ngtcp2_conn_close_stream closes stream |strm| if no further
 * transmission and reception are allowed, and all reordered incoming
 * data are emitted to the application, and the transmitted data are
 * acked.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_INVALID_ARGUMENT
 *     Stream is not found.
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User-defined callback function failed.
 */
int ngtcp2_conn_close_stream_if_shut_rdwr(ngtcp2_conn *conn, ngtcp2_strm *strm);

/*
 * ngtcp2_increment_offset increases offset by |datalen|.  The actual
 * offset passed to this function is (*offset_high) * 1024 +
 * (*offset_low).  If adding datalen results in overflow, this
 * function sets offset to its maximum value.
 */
void ngtcp2_increment_offset(uint64_t *offset_high, uint32_t *offset_low,
                             uint64_t datalen);

#endif /* NGTCP2_CONN_H */
