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

#define NGTCP2_HEADER_FORM_MASK 0x80
#define NGTCP2_CONN_ID_MASK 0x40
#define NGTCP2_KEY_PHASE_MASK 0x20
#define NGTCP2_LONG_TYPE_MASK 0x7f
#define NGTCP2_SHORT_TYPE_MASK 0x1f

/* NGTCP2_LONG_HEADERLEN is the length of long header */
#define NGTCP2_LONG_HEADERLEN 17

#define NGTCP2_STREAM_FIN_BIT 0x20
#define NGTCP2_STREAM_SS_MASK 0x18
#define NGTCP2_STREAM_OO_MASK 0x06
#define NGTCP2_STREAM_D_BIT 0x01

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
 * NGTCP2_ERR_INVALID_ARGUMENT
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
 * NGTCP2_ERR_INVALID_ARGUMENT
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
ssize_t ngtcp2_pkt_decode_stream_frame(ngtcp2_frame *dest,
                                       const uint8_t *payload,
                                       size_t payloadlen);

ssize_t ngtcp2_pkt_decode_ack_frame(ngtcp2_frame *dest, const uint8_t *payload,
                                    size_t len);

ssize_t ngtcp2_pkt_decode_padding_frame(ngtcp2_frame *dest,
                                        const uint8_t *payload, size_t len);

ssize_t ngtcp2_pkt_decode_rst_stream_frame(ngtcp2_frame *dest,
                                           const uint8_t *payload, size_t len);

ssize_t ngtcp2_pkt_decode_connection_close_frame(ngtcp2_frame *dest,
                                                 const uint8_t *payload,
                                                 size_t len);

ssize_t ngtcp2_pkt_decode_goaway_frame(ngtcp2_frame *dest,
                                       const uint8_t *payload, size_t len);

ssize_t ngtcp2_pkt_decode_max_data_frame(ngtcp2_frame *dest,
                                         const uint8_t *payload, size_t len);

ssize_t ngtcp2_pkt_decode_max_stream_data_frame(ngtcp2_frame *dest,
                                                const uint8_t *payload,
                                                size_t len);

ssize_t ngtcp2_pkt_decode_max_stream_id_frame(ngtcp2_frame *dest,
                                              const uint8_t *payload,
                                              size_t len);

ssize_t ngtcp2_pkt_decode_ping_frame(ngtcp2_frame *dest, const uint8_t *payload,
                                     size_t len);

ssize_t ngtcp2_pkt_decode_blocked_frame(ngtcp2_frame *dest,
                                        const uint8_t *payload, size_t len);

ssize_t ngtcp2_pkt_decode_stream_blocked_frame(ngtcp2_frame *dest,
                                               const uint8_t *payload,
                                               size_t len);

ssize_t ngtcp2_pkt_decode_stream_id_needed_frame(ngtcp2_frame *dest,
                                                 const uint8_t *payload,
                                                 size_t len);

ssize_t ngtcp2_pkt_decode_new_connection_id_frame(ngtcp2_frame *dest,
                                                  const uint8_t *payload,
                                                  size_t len);

#endif /* NGTCP2_PKT_H */
