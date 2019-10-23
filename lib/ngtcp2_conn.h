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
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <ngtcp2/ngtcp2.h>

#include "ngtcp2_mem.h"
#include "ngtcp2_crypto.h"
#include "ngtcp2_acktr.h"
#include "ngtcp2_rtb.h"
#include "ngtcp2_strm.h"
#include "ngtcp2_mem.h"
#include "ngtcp2_idtr.h"
#include "ngtcp2_str.h"
#include "ngtcp2_pkt.h"
#include "ngtcp2_log.h"
#include "ngtcp2_pq.h"
#include "ngtcp2_cc.h"
#include "ngtcp2_pv.h"
#include "ngtcp2_cid.h"
#include "ngtcp2_buf.h"
#include "ngtcp2_ppe.h"
#include "ngtcp2_qlog.h"

typedef enum {
  /* Client specific handshake states */
  NGTCP2_CS_CLIENT_INITIAL,
  NGTCP2_CS_CLIENT_WAIT_HANDSHAKE,
  NGTCP2_CS_CLIENT_TLS_HANDSHAKE_FAILED,
  /* Server specific handshake states */
  NGTCP2_CS_SERVER_INITIAL,
  NGTCP2_CS_SERVER_WAIT_HANDSHAKE,
  NGTCP2_CS_SERVER_TLS_HANDSHAKE_FAILED,
  /* Shared by both client and server */
  NGTCP2_CS_POST_HANDSHAKE,
  NGTCP2_CS_CLOSING,
  NGTCP2_CS_DRAINING,
} ngtcp2_conn_state;

/* NGTCP2_MAX_STREAMS is the maximum number of streams. */
#define NGTCP2_MAX_STREAMS (1LL << 60)

/* NGTCP2_MAX_NUM_BUFFED_RX_PKTS is the maximum number of buffered
   reordered packets. */
#define NGTCP2_MAX_NUM_BUFFED_RX_PKTS 16

/* NGTCP2_MAX_REORDERED_CRYPTO_DATA is the maximum offset of crypto
   data which is not continuous.  In other words, there is a gap of
   unreceived data. */
#define NGTCP2_MAX_REORDERED_CRYPTO_DATA 65536

/* NGTCP2_PKT_THRESHOLD is kPacketThreshold described in
   draft-ietf-quic-recovery-22. */
#define NGTCP2_PKT_THRESHOLD 3

/* NGTCP2_GRANULARITY is kGranularity described in
   draft-ietf-quic-recovery-17. */
#define NGTCP2_GRANULARITY NGTCP2_MILLISECONDS

#define NGTCP2_DEFAULT_INITIAL_RTT (500 * NGTCP2_MILLISECONDS)

/* NGTCP2_MAX_RX_INITIAL_CRYPTO_DATA is the maximum offset of received
   crypto stream in Initial packet.  We set this hard limit here
   because crypto stream is unbounded. */
#define NGTCP2_MAX_RX_INITIAL_CRYPTO_DATA 65536
/* NGTCP2_MAX_RX_HANDSHAKE_CRYPTO_DATA is the maximum offset of
   received crypto stream in Handshake packet.  We set this hard limit
   here because crypto stream is unbounded. */
#define NGTCP2_MAX_RX_HANDSHAKE_CRYPTO_DATA 65536

/* NGTCP2_MAX_RETRIES is the number of Retry packet which client can
   accept. */
#define NGTCP2_MAX_RETRIES 3

/* NGTCP2_MAX_DCID_POOL_SIZE is the maximum number of destination
   connection ID the remote endpoint provides to store.  It must be
   the power of 2. */
#define NGTCP2_MAX_DCID_POOL_SIZE 8
/* NGTCP2_MAX_DCID_RETIRED_SIZE is the maximum number of retired DCID
   kept to catch in-flight packet on retired path. */
#define NGTCP2_MAX_DCID_RETIRED_SIZE 2
/* NGTCP2_MAX_SCID_POOL_SIZE is the maximum number of source
   connection ID the local endpoint provides in NEW_CONNECTION_ID to
   the remote endpoint.  The chosen value was described in old draft.
   Now a remote endpoint tells the maximum value.  The value can be
   quite large, and we have to put the sane limit.*/
#define NGTCP2_MAX_SCID_POOL_SIZE 8

/*
 * ngtcp2_max_frame is defined so that it covers the largest ACK
 * frame.
 */
typedef union {
  ngtcp2_frame fr;
  struct {
    ngtcp2_ack ack;
    /* ack includes 1 ngtcp2_ack_blk. */
    ngtcp2_ack_blk blks[NGTCP2_MAX_ACK_BLKS - 1];
  } ackfr;
} ngtcp2_max_frame;

typedef struct {
  uint8_t data[8];
} ngtcp2_path_challenge_entry;

void ngtcp2_path_challenge_entry_init(ngtcp2_path_challenge_entry *pcent,
                                      const uint8_t *data);

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
  /* NGTCP2_CONN_FLAG_RECV_PROTECTED_PKT is set when a protected
     packet is received, and decrypted successfully.  This flag is
     used to stop retransmitting handshake packets.  It might be
     replaced with an another mechanism when we implement key
     update. */
  NGTCP2_CONN_FLAG_RECV_PROTECTED_PKT = 0x08,
  /* NGTCP2_CONN_FLAG_RECV_RETRY is set when a client receives Retry
     packet. */
  NGTCP2_CONN_FLAG_RECV_RETRY = 0x10,
  /* NGTCP2_CONN_FLAG_EARLY_DATA_REJECTED is set when 0-RTT packet is
     rejected by a peer. */
  NGTCP2_CONN_FLAG_EARLY_DATA_REJECTED = 0x20,
  /* NGTCP2_CONN_FLAG_SADDR_VERIFIED is set when source address is
     verified. */
  NGTCP2_CONN_FLAG_SADDR_VERIFIED = 0x40,
  /* NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED_HANDLED is set when the
     library transitions its state to "post handshake". */
  NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED_HANDLED = 0x0100,
  /* NGTCP2_CONN_FLAG_INITIAL_KEY_DISCARDED is set when Initial keys
     have been discarded. */
  NGTCP2_CONN_FLAG_INITIAL_KEY_DISCARDED = 0x0400,
  /* NGTCP2_CONN_FLAG_WAIT_FOR_REMOTE_KEY_UPDATE is set when local
     endpoint has initiated key update and waits for the remote
     endpoint to update key. */
  NGTCP2_CONN_FLAG_WAIT_FOR_REMOTE_KEY_UPDATE = 0x0800,
  /* NGTCP2_CONN_FLAG_PPE_PENDING is set when
     NGTCP2_WRITE_STREAM_FLAG_MORE is used and the intermediate state
     of ngtcp2_ppe is stored in pkt struct of ngtcp2_conn. */
  NGTCP2_CONN_FLAG_PPE_PENDING = 0x1000,
  /* NGTCP2_CONN_FLAG_RESTART_IDLE_TIMER_ON_WRITE is set when idle
     timer should be restarted on next write. */
  NGTCP2_CONN_FLAG_RESTART_IDLE_TIMER_ON_WRITE = 0x2000,
  /* NGTCP2_CONN_FLAG_SERVER_ADDR_VERIFIED indicates that server as
     peer verified client address.  This flag is only used by
     client. */
  NGTCP2_CONN_FLAG_SERVER_ADDR_VERIFIED = 0x4000,
} ngtcp2_conn_flag;

typedef struct {
  ngtcp2_buf buf;
  /* pkt_type is the type of packet to send data in buf.  If it is 0,
     it must be sent in Short packet.  Otherwise, it is sent the long
     packet type denoted by pkt_type. */
  uint8_t pkt_type;
} ngtcp2_crypto_data;

typedef struct {
  struct {
    /* last_pkt_num is the packet number which the local endpoint sent
       last time.*/
    int64_t last_pkt_num;
    ngtcp2_frame_chain *frq;
  } tx;

  struct {
    /* pngap tracks received packet number in order to suppress
       duplicated packet number. */
    ngtcp2_gaptr pngap;
    /* max_pkt_num is the largest packet number received so far. */
    int64_t max_pkt_num;
    /*
     * buffed_pkts is buffered packets which cannot be decrypted with
     * the current encryption level.
     *
     * In server Initial encryption level, 0-RTT packet may be buffered.
     * In server Handshake encryption level, Short packet may be buffered.
     *
     * In client Initial encryption level, Handshake or Short packet may
     * be buffered.  In client Handshake encryption level, Short packet
     * may be buffered.
     *
     * - 0-RTT packet is only buffered in server Initial encryption
     *   level ngtcp2_pktns.
     *
     * - Handshake packet is only buffered in client Initial encryption
     *   level ngtcp2_pktns.
     *
     * - Short packet is only buffered in Handshake encryption level
     *   ngtcp2_pktns.
     */
    ngtcp2_pkt_chain *buffed_pkts;
  } rx;

  struct {
    struct {
      /* frq contains crypto data sorted by their offset. */
      ngtcp2_ksl frq;
      /* offset is the offset of crypto stream in this packet number
         space. */
      uint64_t offset;
      /* ckm is a cryptographic key, and iv to encrypt outgoing
         packets. */
      ngtcp2_crypto_km *ckm;
      /* hp_key is header protection key. */
      ngtcp2_vec *hp_key;
    } tx;

    struct {
      /* ckm is a cryptographic key, and iv to decrypt incoming
         packets. */
      ngtcp2_crypto_km *ckm;
      /* hp_key is header protection key. */
      ngtcp2_vec *hp_key;
    } rx;

    ngtcp2_strm strm;
    ngtcp2_crypto_ctx ctx;
  } crypto;

  ngtcp2_acktr acktr;
  ngtcp2_rtb rtb;
} ngtcp2_pktns;

struct ngtcp2_conn {
  int state;
  ngtcp2_conn_callbacks callbacks;
  /* rcid is a connection ID present in Initial or 0-RTT packet from
     client as destination connection ID.  Server uses this field to
     check that duplicated Initial or 0-RTT packet are indeed sent to
     this connection.  Client uses this field to validate
     original_connection_id transport parameter. */
  ngtcp2_cid rcid;
  /* oscid is the source connection ID initially used by the local
     endpoint. */
  ngtcp2_cid oscid;
  /* odcid is the destination connection ID initially negotiated
     during handshake.  It is used to receive late handshake packets
     after handshake completion. */
  ngtcp2_cid odcid;
  ngtcp2_pktns in_pktns;
  ngtcp2_pktns hs_pktns;
  ngtcp2_pktns pktns;

  struct {
    /* current is the current destination connection ID. */
    ngtcp2_dcid current;
    /* unused is a set of unused CID received from peer. */
    ngtcp2_ringbuf unused;
    /* retired is a set of CID retired by local endpoint.  Keep them
       in 3*PTO to catch packets in flight along the old path. */
    ngtcp2_ringbuf retired;
  } dcid;

  struct {
    /* set is a set of CID sent to peer.  The peer can use any CIDs in
       this set.  This includes used CID as well as unused ones. */
    ngtcp2_ksl set;
    /* used is a set of CID used by peer.  The sort function of this
       priority queue takes timestamp when CID is retired and sorts
       them in ascending order. */
    ngtcp2_pq used;
    /* last_seq is the last sequence number of connection ID. */
    uint64_t last_seq;
    /* num_initial_id is the number of Connection ID initially offered
       to the remote endpoint and is not retired yet.  It includes the
       initial Connection ID used during handshake and the one in
       preferred_address transport parameter. */
    size_t num_initial_id;
    /* num_retired is the number of retired Connection ID still
       included in set. */
    size_t num_retired;
  } scid;

  struct {
    /* strmq contains ngtcp2_strm which has frames to send. */
    ngtcp2_pq strmq;
    /* ack is ACK frame.  The underlying buffer is resused. */
    ngtcp2_frame *ack;
    /* max_ack_blks is the number of additional ngtcp2_ack_blk which
       ack can contain. */
    size_t max_ack_blks;
    /* offset is the offset the local endpoint has sent to the remote
       endpoint. */
    uint64_t offset;
    /* max_offset is the maximum offset that local endpoint can
       send. */
    uint64_t max_offset;
  } tx;

  struct {
    /* unsent_max_offset is the maximum offset that remote endpoint
       can send without extending MAX_DATA.  This limit is not yet
       notified to the remote endpoint. */
    uint64_t unsent_max_offset;
    /* offset is the cumulative sum of stream data received for this
       connection. */
    uint64_t offset;
    /* max_offset is the maximum offset that remote endpoint can
       send. */
    uint64_t max_offset;
    /* path_challenge stores received PATH_CHALLENGE data. */
    ngtcp2_ringbuf path_challenge;
    /* ccec is the received connection close error code. */
    ngtcp2_connection_close_error_code ccec;
  } rx;

  struct {
    ngtcp2_crypto_km *ckm;
    ngtcp2_vec *hp_key;
  } early;

  struct {
    ngtcp2_settings settings;
    struct {
      /* max_streams is the maximum number of bidirectional streams which
         the local endpoint can open. */
      uint64_t max_streams;
      /* next_stream_id is the bidirectional stream ID which the local
         endpoint opens next. */
      int64_t next_stream_id;
    } bidi;

    struct {
      /* max_streams is the maximum number of unidirectional streams
         which the local endpoint can open. */
      uint64_t max_streams;
      /* next_stream_id is the unidirectional stream ID which the
         local endpoint opens next. */
      int64_t next_stream_id;
    } uni;
  } local;

  struct {
    /* transport_params is the received transport parameters during
       handshake.  It is used for Short packet only. */
    ngtcp2_transport_params transport_params;
    /* pending_transport_params is received transport parameters
       during handshake.  It is copied to transport_params when 1RTT
       key is available. */
    ngtcp2_transport_params pending_transport_params;
    struct {
      ngtcp2_idtr idtr;
      /* unsent_max_streams is the maximum number of streams of peer
         initiated bidirectional stream which the local endpoint can
         accept.  This limit is not yet notified to the remote
         endpoint. */
      uint64_t unsent_max_streams;
      /* max_streams is the maximum number of streams of peer
         initiated bidirectional stream which the local endpoint can
         accept. */
      uint64_t max_streams;
    } bidi;

    struct {
      ngtcp2_idtr idtr;
      /* unsent_max_streams is the maximum number of streams of peer
         initiated unidirectional stream which the local endpoint can
         accept.  This limit is not yet notified to the remote
         endpoint. */
      uint64_t unsent_max_streams;
      /* max_streams is the maximum number of streams of peer
         initiated unidirectional stream which the local endpoint can
         accept. */
      uint64_t max_streams;
    } uni;
  } remote;

  struct {
    struct {
      /* new_tx_ckm is a new sender 1RTT key which has not been
         used. */
      ngtcp2_crypto_km *new_tx_ckm;
      /* new_rx_ckm is a new receiver 1RTT key which has not
         successfully decrypted incoming packet yet. */
      ngtcp2_crypto_km *new_rx_ckm;
      /* old_rx_ckm is an old receiver 1RTT key. */
      ngtcp2_crypto_km *old_rx_ckm;
    } key_update;

    size_t aead_overhead;
    /* decrypt_buf is a buffer which is used to write decrypted data. */
    ngtcp2_vec decrypt_buf;
  } crypto;

  /* pkt contains the packet intermediate construction data to support
     NGTCP2_WRITE_STREAM_FLAG_MORE */
  struct {
    ngtcp2_crypto_cc cc;
    ngtcp2_pkt_hd hd;
    ngtcp2_ppe ppe;
    ngtcp2_frame_chain **pfrc;
    int pkt_empty;
    int hd_logged;
    uint8_t rtb_entry_flags;
    int was_client_initial;
    ssize_t hs_spktlen;
  } pkt;

  ngtcp2_map strms;
  ngtcp2_rcvry_stat rcs;
  ngtcp2_cc_stat ccs;
  ngtcp2_pv *pv;
  ngtcp2_log log;
  ngtcp2_qlog qlog;
  ngtcp2_default_cc cc;
  /* token is an address validation token received from server. */
  ngtcp2_buf token;
  /* hs_recved is the number of bytes received from client before its
     address is validated.  This field is only used by server to
     ensure "3 times received data" rule. */
  size_t hs_recved;
  /* hs_sent is the number of bytes sent from server during handshake.
     This field is only used by server to ensure "3 times received
     data" rule. */
  size_t hs_sent;
  const ngtcp2_mem *mem;
  /* idle_ts is the time instant when idle timer started. */
  ngtcp2_tstamp idle_ts;
  void *user_data;
  uint32_t version;
  /* flags is bitwise OR of zero or more of ngtcp2_conn_flag. */
  uint16_t flags;
  int server;
};

/**
 * @function
 *
 * `ngtcp2_conn_read_handshake` performs QUIC cryptographic handshake
 * by reading given data.  |pkt| points to the buffer to read and
 * |pktlen| is the length of the buffer.  |path| is the network path.
 *
 * The application should call `ngtcp2_conn_write_handshake` (or
 * `ngtcp2_conn_client_write_handshake` for client session) to make
 * handshake go forward after calling this function.
 *
 * Application should call this function until
 * `ngtcp2_conn_get_handshake_completed` returns nonzero.  After the
 * completion of handshake, `ngtcp2_conn_read_pkt` and
 * `ngtcp2_conn_write_pkt` should be called instead.
 *
 * This function must not be called from inside the callback
 * functions.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes: (TBD).
 */
int ngtcp2_conn_read_handshake(ngtcp2_conn *conn, const ngtcp2_path *path,
                               const uint8_t *pkt, size_t pktlen,
                               ngtcp2_tstamp ts);

/**
 * @function
 *
 * `ngtcp2_conn_write_handshake` performs QUIC cryptographic handshake
 * by writing handshake packets.  It may write a packet in the given
 * buffer pointed by |dest| whose capacity is given as |destlen|.
 * Application must ensure that the buffer pointed by |dest| is not
 * empty.
 *
 * Application should keep calling this function repeatedly until it
 * returns zero, or negative error code.
 *
 * Application should call this function until
 * `ngtcp2_conn_get_handshake_completed` returns nonzero.  After the
 * completion of handshake, `ngtcp2_conn_read_pkt` and
 * `ngtcp2_conn_write_pkt` should be called instead.
 *
 * During handshake, application can send 0-RTT data (or its response)
 * using `ngtcp2_conn_write_stream`.
 * `ngtcp2_conn_client_write_handshake` is generally efficient because
 * it can coalesce Handshake packet and 0-RTT packet into one UDP
 * packet.
 *
 * This function returns 0 if it cannot write any frame because buffer
 * is too small, or packet is congestion limited.  Application should
 * keep reading and wait for congestion window to grow.
 *
 * This function must not be called from inside the callback
 * functions.
 *
 * This function returns the number of bytes written to the buffer
 * pointed by |dest| if it succeeds, or one of the following negative
 * error codes: (TBD).
 */
ssize_t ngtcp2_conn_write_handshake(ngtcp2_conn *conn, uint8_t *dest,
                                    size_t destlen, ngtcp2_tstamp ts);

/**
 * @function
 *
 * `ngtcp2_conn_client_write_handshake` is just like
 * `ngtcp2_conn_write_handshake`, but it is for client only, and can
 * write 0-RTT data.  This function can coalesce handshake packet and
 * 0-RTT packet into single UDP packet, thus it is generally more
 * efficient than the combination of `ngtcp2_conn_write_handshake` and
 * `ngtcp2_conn_write_stream`.
 *
 * |stream_id|, |fin|, |datav|, and |datavcnt| are stream identifier
 * to which 0-RTT data is sent, whether it is a last data chunk in
 * this stream, a vector of 0-RTT data, and its number of elements
 * respectively.  If there is no 0RTT data to send, pass negative
 * integer to |stream_id|.  The amount of 0RTT data sent is assigned
 * to |*pdatalen|.  If no data is sent, -1 is assigned.  Note that 0
 * length STREAM frame is allowed in QUIC, so 0 might be assigned to
 * |*pdatalen|.
 *
 * This function returns 0 if it cannot write any frame because buffer
 * is too small, or packet is congestion limited.  Application should
 * keep reading and wait for congestion window to grow.
 *
 * This function returns the number of bytes written to the buffer
 * pointed by |dest| if it succeeds, or one of the following negative
 * error codes: (TBD).
 */
ssize_t ngtcp2_conn_client_write_handshake(ngtcp2_conn *conn, uint8_t *dest,
                                           size_t destlen, ssize_t *pdatalen,
                                           uint32_t flags, int64_t stream_id,
                                           int fin, const ngtcp2_vec *datav,
                                           size_t datavcnt, ngtcp2_tstamp ts);

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
int ngtcp2_conn_sched_ack(ngtcp2_conn *conn, ngtcp2_acktr *acktr,
                          int64_t pkt_num, int active_ack, ngtcp2_tstamp ts);

/*
 * ngtcp2_conn_find_stream returns a stream whose stream ID is
 * |stream_id|.  If no such stream is found, it returns NULL.
 */
ngtcp2_strm *ngtcp2_conn_find_stream(ngtcp2_conn *conn, int64_t stream_id);

/*
 * conn_init_stream initializes |strm|.  Its stream ID is |stream_id|.
 * This function adds |strm| to conn->strms.  |strm| must be allocated
 * by the caller.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User-callback function failed.
 */
int ngtcp2_conn_init_stream(ngtcp2_conn *conn, ngtcp2_strm *strm,
                            int64_t stream_id, void *stream_user_data);

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
                             uint64_t app_error_code);

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
int ngtcp2_conn_close_stream_if_shut_rdwr(ngtcp2_conn *conn, ngtcp2_strm *strm,
                                          uint64_t app_error_code);

/*
 * ngtcp2_conn_update_rtt updates RTT measurements.  |rtt| is a latest
 * RTT which is not adjusted by ack delay.  |ack_delay| is unscaled
 * ack_delay included in ACK frame.  |ack_delay| is actually tainted
 * (sent by peer), so don't assume that |ack_delay| is always smaller
 * than, or equals to |rtt|.
 */
void ngtcp2_conn_update_rtt(ngtcp2_conn *conn, uint64_t rtt,
                            uint64_t ack_delay);

void ngtcp2_conn_set_loss_detection_timer(ngtcp2_conn *conn);

/*
 * ngtcp2_conn_detect_lost_pkt detects lost packets.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 */
int ngtcp2_conn_detect_lost_pkt(ngtcp2_conn *conn, ngtcp2_pktns *pktns,
                                ngtcp2_rcvry_stat *rcs, ngtcp2_tstamp ts);

/*
 * ngtcp2_conn_tx_strmq_top returns the ngtcp2_strm which sits on the
 * top of queue.  tx_strmq must not be empty.
 */
ngtcp2_strm *ngtcp2_conn_tx_strmq_top(ngtcp2_conn *conn);

/*
 * ngtcp2_conn_tx_strmq_pop pops the ngtcp2_strm from the queue.
 * tx_strmq must not be empty.
 */
void ngtcp2_conn_tx_strmq_pop(ngtcp2_conn *conn);

/*
 * ngtcp2_conn_tx_strmq_push pushes |strm| into tx_strmq.
 *
 *  This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 */
int ngtcp2_conn_tx_strmq_push(ngtcp2_conn *conn, ngtcp2_strm *strm);

/*
 * ngtcp2_conn_internal_expiry returns the minimum expiry time among
 * all timers in |conn|.
 */
ngtcp2_tstamp ngtcp2_conn_internal_expiry(ngtcp2_conn *conn);

#endif /* NGTCP2_CONN_H */
