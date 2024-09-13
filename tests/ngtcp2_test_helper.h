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
#ifndef NGTCP2_TEST_HELPER_H
#define NGTCP2_TEST_HELPER_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* defined(HAVE_CONFIG_H) */

#include <ngtcp2/ngtcp2.h>

#include "ngtcp2_conn.h"

/*
 * strsize macro returns the length of string literal |S|.
 */
#define strsize(S) (sizeof(S) - 1)

/*
 * NGTCP2_APP_ERRxx is an application error code solely used in test
 * code.
 */
#define NGTCP2_APP_ERR01 0xff01u
#define NGTCP2_APP_ERR02 0xff02u

/*
 * NGTCP2_FAKE_AEAD_OVERHEAD is AEAD overhead used in unit tests.
 * Because we use the same encryption/decryption function for both
 * handshake and post handshake packets, we have to use AEAD overhead
 * used in handshake packets.
 */
#define NGTCP2_FAKE_AEAD_OVERHEAD NGTCP2_INITIAL_AEAD_OVERHEAD

/* NGTCP2_FAKE_HP_MASK is a header protection mask used in unit
   tests. */
#define NGTCP2_FAKE_HP_MASK "\x00\x00\x00\x00\x00"

/*
 * ngtcp2_t_encode_stream_frame encodes STREAM frame into |out| with
 * the given parameters.  If NGTCP2_STREAM_LEN_BIT is set in |flags|,
 * |datalen| is encoded as Data Length, otherwise it is not written.
 * To set FIN bit in wire format, set NGTCP2_STREAM_FIN_BIT in
 * |flags|.  This function expects that |out| has enough length to
 * store entire STREAM frame, excluding the Stream Data.
 *
 * This function returns the number of bytes written to |out|.
 */
size_t ngtcp2_t_encode_stream_frame(uint8_t *out, uint8_t flags,
                                    uint64_t stream_id, uint64_t offset,
                                    uint16_t datalen);

/*
 * ngtcp2_t_encode_ack_frame encodes ACK frame into |out| with the
 * given parameters.  Currently, this function encodes 1 ACK Block
 * Section.  ACK Delay field is always 0.
 *
 * This function returns the number of bytes written to |out|.
 */
size_t ngtcp2_t_encode_ack_frame(uint8_t *out, uint64_t largest_ack,
                                 uint64_t first_ack_blklen, uint64_t gap,
                                 uint64_t ack_blklen);

/*
 * open_stream opens new stream denoted by |stream_id|.
 */
ngtcp2_strm *open_stream(ngtcp2_conn *conn, int64_t stream_id);

/*
 * rtb_entry_length returns the length of elements pointed by |ent|
 * list.
 */
size_t rtb_entry_length(const ngtcp2_rtb_entry *ent);

void scid_init(ngtcp2_cid *cid);
void dcid_init(ngtcp2_cid *cid);
void rcid_init(ngtcp2_cid *cid);

/*
 * read_pkt_payloadlen reads long header payload length field from
 * |pkt|.
 */
uint64_t read_pkt_payloadlen(const uint8_t *pkt, const ngtcp2_cid *dcid,
                             const ngtcp2_cid *scid);

/*
 * write_pkt_payloadlen writes long header payload length field into
 * |pkt|.
 */
void write_pkt_payloadlen(uint8_t *pkt, const ngtcp2_cid *dcid,
                          const ngtcp2_cid *scid, uint64_t payloadlen);

/*
 * pkt_decode_hd_long decodes long packet header from |pkt| of length
 * |pktlen|.  This function assumes that header protection has been
 * decrypted.
 */
ngtcp2_ssize pkt_decode_hd_long(ngtcp2_pkt_hd *dest, const uint8_t *pkt,
                                size_t pktlen);

/*
 * pkt_decode_hd_short decodes long packet header from |pkt| of length
 * |pktlen|.  This function assumes that header protection has been
 * decrypted.
 */
ngtcp2_ssize pkt_decode_hd_short(ngtcp2_pkt_hd *dest, const uint8_t *pkt,
                                 size_t pktlen, size_t dcidlen);

/*
 * pkt_decode_hd_short_mask decodes long packet header from |pkt| of
 * length |pktlen|.  NGTCP2_FAKE_HP_MASK is used to decrypt header
 * protection.
 */
ngtcp2_ssize pkt_decode_hd_short_mask(ngtcp2_pkt_hd *dest, const uint8_t *pkt,
                                      size_t pktlen, size_t dcidlen);

/*
 * path_init initializes |path| with the given arguments.  They form
 * IPv4 addresses.
 */
void path_init(ngtcp2_path_storage *path, uint32_t local_addr,
               uint16_t local_port, uint32_t remote_addr, uint16_t remote_port);

/* ngtcp2_tpe is a testing packet encoder.  It can encode all QUIC
   packet types for testing. */
typedef struct ngtcp2_tpe {
  /* dcid is a Destination Connection ID. */
  ngtcp2_cid dcid;
  /* scid is a Source Connection ID. */
  ngtcp2_cid scid;
  /* version is a QUIC version. */
  uint32_t version;
  /* token is a address validation token. */
  const uint8_t *token;
  /* tokenlen is a length of token. */
  size_t tokenlen;
  /* flags is a bitwise OR of one or more of NGTCP2_PKT_FLAG_*
     flags. */
  uint8_t flags;

  /* Initial packet number space. */
  struct {
    /* last_pkt_num is the last packet number in this packet number
       space. */
    int64_t last_pkt_num;
    /* ckm points to keying materials. */
    ngtcp2_crypto_km *ckm;
  } initial;

  /* Handshake packet number space. */
  struct {
    /* last_pkt_num is the last packet number in this packet number
       space. */
    int64_t last_pkt_num;
    /* ckm points to keying materials. */
    ngtcp2_crypto_km *ckm;
  } handshake;

  /* Early data. */
  struct {
    /* ckm points to keying materials. */
    ngtcp2_crypto_km *ckm;
  } early;

  /* Application data packet number space. */
  struct {
    /* last_pkt_num is the last packet number in this packet number
       space. */
    int64_t last_pkt_num;
    /* ckm points to keying materials. */
    ngtcp2_crypto_km *ckm;
  } app;
} ngtcp2_tpe;

/* ngtcp2_tpe_init initializes |tpe| with the given arguments. */
void ngtcp2_tpe_init(ngtcp2_tpe *tpe, const ngtcp2_cid *dcid,
                     const ngtcp2_cid *scid, uint32_t version);

/* ngtcp2_tpe_init_conn initializes |tpe| using values from |conn|. */
void ngtcp2_tpe_init_conn(ngtcp2_tpe *tpe, ngtcp2_conn *conn);

/* ngtcp2_tpe_write_initial encodes Initial packet which contains
   |frlen| frames pointed by |fr| to the buffer pointed by |out| of
   length |outlen|.  It returns the number of bytes written. */
size_t ngtcp2_tpe_write_initial(ngtcp2_tpe *tpe, uint8_t *out, size_t outlen,
                                ngtcp2_frame *fr, size_t frlen);

/* ngtcp2_tpe_write_handshake encodes Handshake packet which contains
   |frlen| frames pointed by |fr| to the buffer pointed by |out| of
   length |outlen|.  It returns the number of bytes written. */
size_t ngtcp2_tpe_write_handshake(ngtcp2_tpe *tpe, uint8_t *out, size_t outlen,
                                  ngtcp2_frame *fr, size_t frlen);

/* ngtcp2_tpe_write_0rtt encodes 0-RTT packet which contains |frlen|
   frames pointed by |fr| to the buffer pointed by |out| of length
   |outlen|.  It returns the number of bytes written. */
size_t ngtcp2_tpe_write_0rtt(ngtcp2_tpe *tpe, uint8_t *out, size_t outlen,
                             ngtcp2_frame *fr, size_t frlen);

/* ngtcp2_tpe_write_1rtt encodes 1-RTT packet which contains |frlen|
   frames pointed by |fr| to the buffer pointed by |out| of length
   |outlen|.  It returns the number of bytes written. */
size_t ngtcp2_tpe_write_1rtt(ngtcp2_tpe *tpe, uint8_t *out, size_t outlen,
                             ngtcp2_frame *fr, size_t frlen);

#endif /* !defined(NGTCP2_TEST_HELPER_H) */
