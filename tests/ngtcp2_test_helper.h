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
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <ngtcp2/ngtcp2.h>

#include "ngtcp2_conn.h"

/*
 * strsize macro returns the length of string literal |S|.
 */
#define strsize(S) (sizeof(S) - 1)

/*
 * arraylen macro returns the number of elements in array |A|.
 */
#define arraylen(A) (sizeof(A) / sizeof(A[0]))

/*
 * NGTCP2_APP_ERRxx is an application error code solely used in test
 * code.
 */
#define NGTCP2_APP_ERR01 0xff01u
#define NGTCP2_APP_ERR02 0xff02u

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
 * write_single_frame_pkt writes a QUIC packet containing single frame
 * |fr| in |out| whose capacity is |outlen|.  This function returns
 * the number of bytes written.
 */
size_t write_single_frame_pkt(ngtcp2_conn *conn, uint8_t *out, size_t outlen,
                              uint64_t conn_id, uint64_t pkt_num,
                              ngtcp2_frame *fr);

/*
 * write_single_frame_pkt_without_conn_id writes a QUIC packet
 * containing single frame |fr| in |out| whose capacity is |outlen|.
 * Connection ID is omitted.  This function returns the number of
 * bytes written.
 */
size_t write_single_frame_pkt_without_conn_id(ngtcp2_conn *conn, uint8_t *out,
                                              size_t outlen, uint64_t pkt_num,
                                              ngtcp2_frame *fr);

/*
 * write_single_frame_handshake_pkt writes a unprotected QUIC
 * handshake packet containing single frame |fr| in |out| whose
 * capacity is |outlen|.  This function returns the number of bytes
 * written.
 */
size_t write_single_frame_handshake_pkt(uint8_t *out, size_t outlen,
                                        uint8_t pkt_type, uint64_t conn_id,
                                        uint64_t pkt_num, uint32_t version,
                                        ngtcp2_frame *fr);

/*
 * open_stream opens new stream denoted by |stream_id|.
 */
ngtcp2_strm *open_stream(ngtcp2_conn *conn, uint64_t stream_id);

#endif /* NGTCP2_TEST_HELPER_H */
