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
#ifndef NGTCP2_PKT_H
#define NGTCP2_PKT_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <ngtcp2/ngtcp2.h>

#define NGTCP2_HEADER_FORM_BIT 0x80
#define NGTCP2_CONN_ID_BIT 0x40
#define NGTCP2_KEY_PHASE_BIT 0x20
#define NGTCP2_LONG_TYPE_MASK 0x7f
#define NGTCP2_SHORT_TYPE_MASK 0x1f

/* NGTCP2_LONG_HEADERLEN is the length of long header */
#define NGTCP2_LONG_HEADERLEN 17

#define NGTCP2_STREAM_FIN_BIT 0x20
#define NGTCP2_STREAM_SS_MASK 0x18
#define NGTCP2_STREAM_OO_MASK 0x06
#define NGTCP2_STREAM_D_BIT 0x01

#define NGTCP2_ACK_N_BIT 0x10
#define NGTCP2_ACK_LL_MASK 0x0c
#define NGTCP2_ACK_MM_MASK 0x03

/* The length of FNV-1a message digest for Unprotected packet */
#define NGTCP2_PKT_MDLEN 8

/*
 * ngtcp2_pkt_hd_init initializes |hd| with the given values.
 */
void ngtcp2_pkt_hd_init(ngtcp2_pkt_hd *hd, uint8_t flags, uint8_t type,
                        uint64_t conn_id, uint32_t pkt_num, uint32_t version);

/*
 * ngtcp2_pkt_decode_hd_long decodes QUIC long packet header in |pkt|
 * of length |pktlen|.  It stores the result in the object pointed by
 * |dest|, and returns the number of bytes decoded to read the packet
 * header if it succeeds, or one of the following error codes:
 *
 * NGTCP2_ERR_INVALID_ARGUMENT
 *     Packet is too short; or it is not a long header
 * NGTCP2_ERR_UNKNOWN_PKT_TYPE
 *     Packet type is unknown
 */
ssize_t ngtcp2_pkt_decode_hd_long(ngtcp2_pkt_hd *dest, const uint8_t *pkt,
                                  size_t pktlen);

/*
 * ngtcp2_pkt_decode_hd_short decodes QUIC short packet header in
 * |pkt| of length |pktlen|.  It stores the result in the object
 * pointed by |dest|, and returns the number of bytes decoded to read
 * the packet header if it succeeds, or one of the following error
 * codes:
 *
 * NGTCP2_ERR_INVALID_ARGUMENT
 *     Packet is too short; or it is not a short header
 * NGTCP2_ERR_UNKNOWN_PKT_TYPE
 *     Packet type is unknown
 */
ssize_t ngtcp2_pkt_decode_hd_short(ngtcp2_pkt_hd *dest, const uint8_t *pkt,
                                   size_t pktlen);

/*
 * ngtcp2_pkt_encode_hd_long encodes |hd| as QUIC long header into
 * |out| which has length |outlen|.  It returns the number of bytes
 * written into |outlen| if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOBUF
 *     Buffer is too short
 */
ssize_t ngtcp2_pkt_encode_hd_long(uint8_t *out, size_t outlen,
                                  const ngtcp2_pkt_hd *hd);

/*
 * ngtcp2_pkt_encode_hd_short encodes |hd| as QUIC short header into
 * |out| which has length |outlen|.  It returns the number of bytes
 * written into |outlen| if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOBUF
 *     Buffer is too short
 */
ssize_t ngtcp2_pkt_encode_hd_short(uint8_t *out, size_t outlen,
                                   const ngtcp2_pkt_hd *hd);

/*
 * ngtcp2_pkt_decode_stream_frame decodes STREAM frame from |payload|
 * of length |payloadlen|.  The result is stored in the object pointed
 * by |dest|.  STREAM frame must start at `payload[0]`.  This function
 * returns when it decodes one STREAM frame, and returns the exact
 * number of bytes for one STREAM frame if it succeeds, or one of the
 * following negative error codes:
 *
 * NGTCP2_ERR_INVALID_ARGUMENT
 *     Type indicates that payload does not include STREAM frame; or
 *     Payload is too short to include STREAM frame
 */
ssize_t ngtcp2_pkt_decode_stream_frame(ngtcp2_stream *dest,
                                       const uint8_t *payload,
                                       size_t payloadlen);

/*
 * ngtcp2_pkt_decode_ack_frame decodes ACK frame from |payload| of
 * length |payloadlen|.  The result is stored in the object pointed by
 * |dest|.  ACK frame must start at `payload[0]`.  This function
 * returns when it decodes one ACK frame, and returns the exact number
 * of bytes for one ACK frame if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_INVALID_ARGUMENT
 *     Type indicates that payload does not include ACK frame; or
 *     Payload is too short to include ACK frame
 */
ssize_t ngtcp2_pkt_decode_ack_frame(ngtcp2_ack *dest, const uint8_t *payload,
                                    size_t payloadlen);

/*
 * ngtcp2_pkt_decode_padding_frame decodes contiguous PADDING frames
 * from |payload| of length |payloadlen|.  It continues to parse
 * frames as long as the frame type is PADDING.  This function returns
 * when it encounters the frame type which is not PADDING.  The first
 * byte (``payload[0]``) must be NGTCP2_FRAME_PADDING.  This function
 * returns the exact number of bytes read for PADDING frames if it
 * succeeds, or one of the following negative error codes:
 *
 * NGTCP2_ERR_INVALID_ARGUMENT
 *     Type indicates that payload does not include PADDING frame.
 */
ssize_t ngtcp2_pkt_decode_padding_frame(ngtcp2_padding *dest,
                                        const uint8_t *payload,
                                        size_t payloadlen);

ssize_t ngtcp2_pkt_decode_rst_stream_frame(ngtcp2_rst_stream *dest,
                                           const uint8_t *payload,
                                           size_t payloadlen);

ssize_t ngtcp2_pkt_decode_connection_close_frame(ngtcp2_connection_close *dest,
                                                 const uint8_t *payload,
                                                 size_t payloadlen);

ssize_t ngtcp2_pkt_decode_goaway_frame(ngtcp2_goaway *dest,
                                       const uint8_t *payload,
                                       size_t payloadlen);

ssize_t ngtcp2_pkt_decode_max_data_frame(ngtcp2_max_data *dest,
                                         const uint8_t *payload,
                                         size_t payloadlen);

ssize_t ngtcp2_pkt_decode_max_stream_data_frame(ngtcp2_max_stream_data *dest,
                                                const uint8_t *payload,
                                                size_t payloadlen);

ssize_t ngtcp2_pkt_decode_max_stream_id_frame(ngtcp2_max_stream_id *dest,
                                              const uint8_t *payload,
                                              size_t payloadlen);

ssize_t ngtcp2_pkt_decode_ping_frame(ngtcp2_ping *dest, const uint8_t *payload,
                                     size_t payloadlen);

ssize_t ngtcp2_pkt_decode_blocked_frame(ngtcp2_blocked *dest,
                                        const uint8_t *payload,
                                        size_t payloadlen);

ssize_t ngtcp2_pkt_decode_stream_blocked_frame(ngtcp2_stream_blocked *dest,
                                               const uint8_t *payload,
                                               size_t payloadlen);

ssize_t ngtcp2_pkt_decode_stream_id_needed_frame(ngtcp2_stream_id_needed *dest,
                                                 const uint8_t *payload,
                                                 size_t payloadlen);

ssize_t ngtcp2_pkt_decode_new_connection_id_frame(
    ngtcp2_new_connection_id *dest, const uint8_t *payload, size_t payloadlen);

/**
 * ngtcp2_pkt_encode_stream_frame encodes STREAM frame |fm| into the
 * buffer pointed by |out| of length |outlen|.
 *
 * This function returns the number of bytes written if it succeeds,
 * or one of the following negative error codes:
 *
 * NGTCP2_ERR_NOBUF
 *     Buffer does not have enough capacity to write a frame.
 */
ssize_t ngtcp2_pkt_encode_stream_frame(uint8_t *out, size_t outlen,
                                       const ngtcp2_stream *fm);

/**
 * ngtcp2_pkt_encode_ack_frame encodes ACK frame |fm| into the buffer
 * pointed by |out| of length |outlen|.
 *
 * Currently, this function only encodes Largest Acknowledged and ACK
 * delay.
 *
 * This function returns the number of bytes written if it succeeds,
 * or one of the following negative error codes:
 *
 * NGTCP2_ERR_NOBUF
 *     Buffer does not have enough capacity to write a frame.
 */
ssize_t ngtcp2_pkt_encode_ack_frame(uint8_t *out, size_t outlen,
                                    const ngtcp2_ack *fm);

ssize_t ngtcp2_pkt_encode_padding_frame(uint8_t *out, size_t outlen,
                                        const ngtcp2_padding *fm);

#endif /* NGTCP2_PKT_H */
