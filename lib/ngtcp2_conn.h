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

/* NGTCP2_MAX_NUM_BUFFED_RX_PKTS is the maximum number of buffered
   reordered packets. */
#define NGTCP2_MAX_NUM_BUFFED_RX_PKTS 16

/* NGTCP2_STRM0_MAX_STREAM_DATA is the maximum stream offset that an
   endpoint can send initially. */
#define NGTCP2_STRM0_MAX_STREAM_DATA 65535

/* NGTCP2_PACKET_THRESHOLD is kPacketThreshold described in
   draft-ietf-quic-recovery-17. */
#define NGTCP2_PACKET_THRESHOLD 3

/* NGTCP2_GRANULARITY is kGranularity described in
   draft-ietf-quic-recovery-17. */
#define NGTCP2_GRANULARITY NGTCP2_MILLISECONDS

#define NGTCP2_DEFAULT_INITIAL_RTT (100 * NGTCP2_MILLISECONDS)

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

/* NGTCP2_HS_ACK_DELAY is the ACK delay for Initial and Handshake
   packets. */
#define NGTCP2_HS_ACK_DELAY NGTCP2_MILLISECONDS

#define NGTCP2_MAX_SERVER_ID_BIDI 0x3fffffffffffff00ULL
#define NGTCP2_MAX_SERVER_ID_UNI 0x3fffffffffffff10ULL
#define NGTCP2_MAX_CLIENT_ID_BIDI 0x3fffffffffffff01ULL
#define NGTCP2_MAX_CLIENT_ID_UNI 0x3fffffffffffff11ULL

/* NGTCP2_MAX_BOUND_DCID_POOL_SIZE is the maximum number of
   destination connection ID which have been bound to a particular
   path, but not yet used as primary path and path validation is not
   performed from the local endpoint. */
#define NGTCP2_MAX_BOUND_DCID_POOL_SIZE 4
/* NGTCP2_MAX_DCID_POOL_SIZE is the maximum number of destination
   connection ID the remote endpoint provides to store.  It must be
   the power of 2. */
#define NGTCP2_MAX_DCID_POOL_SIZE 16
/* NGTCP2_MIN_SCID_POOL_SIZE is the minimum number of source
   connection ID the local endpoint provides to the remote endpoint.
   It must be at least 8 as per the spec. */
#define NGTCP2_MIN_SCID_POOL_SIZE 8

/* NGTCP2_MIN_DCID_CHANGE_DURATION is the minimum duration that local
   endpoint changes DCID. */
#define NGTCP2_MIN_DCID_CHANGE_DURATION (3ULL * NGTCP2_SECONDS)

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
  ngtcp2_path path;
  uint8_t data[8];
  uint8_t local_addrbuf[128];
  uint8_t remote_addrbuf[128];
} ngtcp2_path_challenge_entry;

void ngtcp2_path_challenge_entry_init(ngtcp2_path_challenge_entry *pcent,
                                      const ngtcp2_path *path,
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
  /* NGTCP2_CONN_FLAG_OCID_PRESENT is set when ocid field of
     ngtcp2_conn is set. */
  NGTCP2_CONN_FLAG_OCID_PRESENT = 0x80,
  /* NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED_HANDLED is set when the
     library transitions its state to "post handshake". */
  NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED_HANDLED = 0x0100,
  /* NGTCP2_CONN_FLAG_FORCE_SEND_INITIAL is set when client has to
     send Initial packets even if it has nothing to send. */
  NGTCP2_CONN_FLAG_FORCE_SEND_INITIAL = 0x0200,
  /* NGTCP2_CONN_FLAG_INITIAL_KEY_DISCARDED is set when Initial keys
     have been discarded. */
  NGTCP2_CONN_FLAG_INITIAL_KEY_DISCARDED = 0x0400,
  /* NGTCP2_CONN_FLAG_WAIT_FOR_REMOTE_KEY_UPDATE is set when local
     endpoint has initiated key update and waits for the remote
     endpoint to update key. */
  NGTCP2_CONN_FLAG_WAIT_FOR_REMOTE_KEY_UPDATE = 0x0800,
} ngtcp2_conn_flag;

typedef struct {
  ngtcp2_buf buf;
  /* pkt_type is the type of packet to send data in buf.  If it is 0,
     it must be sent in Short packet.  Otherwise, it is sent the long
     packet type denoted by pkt_type. */
  uint8_t pkt_type;
} ngtcp2_crypto_data;

typedef struct {
  /* pngap tracks received packet number in order to suppress
     duplicated packet number. */
  ngtcp2_gaptr pngap;
  /* last_tx_pkt_num is the packet number which the local endpoint
     sent last time.*/
  uint64_t last_tx_pkt_num;
  uint64_t max_rx_pkt_num;
  /* crypto_tx_offset is the offset of crypto stream in this packet
     number space. */
  uint64_t crypto_tx_offset;
  /* crypto_rx_offset_base is the offset of crypto stream in the
     global TLS stream and it specifies the offset where this local
     crypto stream starts. */
  uint64_t crypto_rx_offset_base;
  ngtcp2_acktr acktr;
  ngtcp2_rtb rtb;
  ngtcp2_pq cryptofrq;
  /* tx_ckm is a cryptographic key, and iv to encrypt outgoing
     packets. */
  ngtcp2_crypto_km *tx_ckm;
  /* rx_ckm is a cryptographic key, and iv to decrypt incoming
     packets. */
  ngtcp2_crypto_km *rx_ckm;
  ngtcp2_vec *tx_hp;
  ngtcp2_vec *rx_hp;
  ngtcp2_frame_chain *frq;
} ngtcp2_pktns;

struct ngtcp2_conn {
  int state;
  ngtcp2_conn_callbacks callbacks;
  /* rcid is a connection ID present in Initial or 0-RTT protected
     packet from client as destination connection ID.  Server uses
     this field to check that duplicated Initial or 0-RTT packet are
     indeed sent to this connection.  Client uses this field to
     validate original_connection_id transport parameter. */
  ngtcp2_cid rcid;
  /* ocid is a connection ID sent as original destination connection
     ID in Retry packet.  Only server uses this field to send this CID
     to client in original_connection_id transport parameter. */
  ngtcp2_cid ocid;
  /* oscid is the source connection ID initially used by the local
     endpoint. */
  ngtcp2_cid oscid;
  /* dcid is the destination connection ID. */
  ngtcp2_dcid dcid;
  /* bound_dcids is a set of destination connection ID which is bound
     to a particular path.  These paths are not validated yet. */
  ngtcp2_ringbuf bound_dcids;
  /* dcids is a set of unused CID received from peer.  The first CID
     is in use. */
  ngtcp2_ringbuf dcids;
  /* scids is a set of CID sent to peer.  The peer can use any CIDs in
     this set. */
  ngtcp2_ksl scids;
  ngtcp2_pq used_scids;
  ngtcp2_pktns in_pktns;
  ngtcp2_pktns hs_pktns;
  ngtcp2_pktns pktns;
  ngtcp2_strm crypto;
  ngtcp2_map strms;
  /* tx_strmq contains ngtcp2_strm which has frames to send. */
  ngtcp2_pq tx_strmq;
  ngtcp2_idtr remote_bidi_idtr;
  ngtcp2_idtr remote_uni_idtr;
  ngtcp2_rcvry_stat rcs;
  ngtcp2_cc_stat ccs;
  ngtcp2_pv *pv;
  ngtcp2_ringbuf rx_path_challenge;
  ngtcp2_log log;
  ngtcp2_default_cc cc;
  /* token is an address validation token received from server. */
  ngtcp2_buf token;
  /* unsent_max_remote_stream_id_bidi is the maximum stream ID of peer
     initiated bidirectional stream which the local endpoint can
     accept.  This limit is not yet notified to the remote
     endpoint. */
  uint64_t unsent_max_remote_stream_id_bidi;
  /* max_remote_stream_id_bidi is the maximum stream ID of peer
     initiated bidirectional stream which the local endpoint can
     accept. */
  uint64_t max_remote_stream_id_bidi;
  /* max_local_stream_id_bidi is the maximum bidirectional stream ID
     which the local endpoint can open. */
  uint64_t max_local_stream_id_bidi;
  /* next_local_stream_id_bidi is the bidirectional stream ID which
     the local endpoint opens next. */
  uint64_t next_local_stream_id_bidi;
  /* unsent_max_remote_stream_id_uni is an unidirectional stream
     version of unsent_max_remote_stream_id_bidi. */
  uint64_t unsent_max_remote_stream_id_uni;
  /* max_remote_stream_id_uni is an unidirectional stream version of
     max_remote_stream_id_bidi. */
  uint64_t max_remote_stream_id_uni;
  /* max_local_stream_id_uni is an unidirectional stream version of
     max_local_stream_id_bidi. */
  uint64_t max_local_stream_id_uni;
  /* next_local_stream_id_uni is an unidirectional stream version of
     next_local_stream_id_bidi. */
  uint64_t next_local_stream_id_uni;
  /* unsent_max_rx_offset is the maximum offset that remote endpoint
     can send without extending MAX_DATA.  This limit is not yet
     notified to the remote endpoint. */
  uint64_t unsent_max_rx_offset;
  /* max_rx_offset is the maximum offset that remote endpoint can
     send. */
  uint64_t max_rx_offset;
  /* rx_offset is the cumulative sum of stream data received for this
     connection. */
  uint64_t rx_offset;
  /* tx_offset is the offset the local endpoint has sent to the remote
     endpoint. */
  uint64_t tx_offset;
  /* max_tx_offset is the maximum offset that local endpoint can
     send. */
  uint64_t max_tx_offset;
  /* tx_last_cid_seq is the last sequence number of connection ID. */
  uint64_t tx_last_cid_seq;
  /* first_rx_bw_ts is a timestamp when bandwidth measurement is
     started. */
  ngtcp2_tstamp first_rx_bw_ts;
  /* rx_bw_datalen is the length of STREAM data received for bandwidth
     measurement. */
  uint64_t rx_bw_datalen;
  /* rx_bw is receiver side bandwidth. */
  double rx_bw;
  size_t probe_pkt_left;
  /* hs_recved is the number of bytes received from client before its
     address is validated.  This field is only used by server to
     ensure "3 times received data" rule. */
  size_t hs_recved;
  /* hs_sent is the number of bytes sent from server during handshake.
     This field is only used by server to ensure "3 times received
     data" rule. */
  size_t hs_sent;
  /* nretry is the number of Retry packet this client has received. */
  size_t nretry;
  ngtcp2_mem *mem;
  void *user_data;
  uint32_t version;
  /* flags is bitwise OR of zero or more of ngtcp2_conn_flag. */
  uint16_t flags;
  int server;
  ngtcp2_crypto_km *early_ckm;
  ngtcp2_vec *early_hp;
  /* old_ckm is an old 1RTT key. */
  ngtcp2_crypto_km *old_rx_ckm;
  /* new_tx_ckm is a new 1RTT key which has not been used. */
  ngtcp2_crypto_km *new_tx_ckm;
  /* new_rx_ckm is a new 1RTT key which has not successfully decrypted
     incoming packet. */
  ngtcp2_crypto_km *new_rx_ckm;
  size_t aead_overhead;
  /* buffed_rx_hs_pkts is buffered Handshake packets which come before
     Initial packet. */
  ngtcp2_pkt_chain *buffed_rx_hs_pkts;
  /* buffed_rx_ppkts is buffered (0-RTT) Protected packets which come
     before (Initial packet for 0-RTT, or) handshake completed due to
     packet reordering. */
  ngtcp2_pkt_chain *buffed_rx_ppkts;
  ngtcp2_settings local_settings;
  ngtcp2_settings remote_settings;
  /* decrypt_buf is a buffer which is used to write decrypted data. */
  ngtcp2_array decrypt_buf;
};

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
                          uint64_t pkt_num, int active_ack, ngtcp2_tstamp ts);

/*
 * ngtcp2_conn_find_stream returns a stream whose stream ID is
 * |stream_id|.  If no such stream is found, it returns NULL.
 */
ngtcp2_strm *ngtcp2_conn_find_stream(ngtcp2_conn *conn, uint64_t stream_id);

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
                            uint64_t stream_id, void *stream_user_data);

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
                             uint16_t app_error_code);

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
                                          uint16_t app_error_code);

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

#endif /* NGTCP2_CONN_H */
