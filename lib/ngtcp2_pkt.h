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
#define NGTCP2_KEY_PHASE_BIT 0x40
#define NGTCP2_THIRD_BIT 0x20
#define NGTCP2_FOURTH_BIT 0x10
#define NGTCP2_GQUIC_BIT 0x08
#define NGTCP2_LONG_TYPE_MASK 0x7f
#define NGTCP2_SHORT_TYPE_MASK 0x03

/* NGTCP2_SR_TYPE is a Type field of Stateless Reset. */
#define NGTCP2_SR_TYPE 0x1f

/* NGTCP2_LONG_HEADERLEN is the length of long header */
#define NGTCP2_LONG_HEADERLEN 17

/* NGTCP2_MIN_LONG_HEADERLEN is the minimum length of long header.
   That is (1|TYPE)<1> + VERSION<4> + (DCIL|SCIL)<1> + PAYLOADLEN<1> +
   PKN<4> */
#define NGTCP2_MIN_LONG_HEADERLEN (1 + 4 + 1 + 1 + 4)

#define NGTCP2_STREAM_FIN_BIT 0x01
#define NGTCP2_STREAM_LEN_BIT 0x02
#define NGTCP2_STREAM_OFF_BIT 0x04

/* NGTCP2_STREAM_OVERHEAD is the maximum number of bytes required
   other than payload for STREAM frame.  That is from type field to
   the beginning of the payload. */
#define NGTCP2_STREAM_OVERHEAD 15

/* NGTCP2_MAX_VARINT is the maximum value which can be encoded in
   variable-length integer encoding */
#define NGTCP2_MAX_VARINT ((1ULL << 62) - 1)

/* NGTCP2_MAX_NUM_ACK_BLK is the maximum number of Additional ACK
   blocks which this library can create, or decode. */
#define NGTCP2_MAX_ACK_BLKS 255

/*
 * ngtcp2_pkt_hd_init initializes |hd| with the given values.  If
 * |dcid| and/or |scid| is NULL, DCID and SCID of |hd| is empty
 * respectively.
 */
void ngtcp2_pkt_hd_init(ngtcp2_pkt_hd *hd, uint8_t flags, uint8_t type,
                        const ngtcp2_cid *dcid, const ngtcp2_cid *scid,
                        uint64_t pkt_num, uint32_t version, size_t payloadlen);

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
 * ngtcp2_pkt_decode_version_negotiation decodes Version Negotiation
 * packet payload |payload| of length |payloadlen|, and stores the
 * result in |dest|.  |dest| must have enough capacity to store the
 * result.  |payloadlen| also must be a multiple of sizeof(uint32_t).
 *
 * This function returns the number of versions written in |dest|.
 */
size_t ngtcp2_pkt_decode_version_negotiation(uint32_t *dest,
                                             const uint8_t *payload,
                                             size_t payloadlen);

/*
 * ngtcp2_pkt_decode_stateless_reset decodes Stateless Reset payload
 * |payload| of length |payloadlen|.  The |payload| must start with
 * Stateless Reset Token.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_INVALID_ARGUMENT
 *     Payloadlen is too short.
 */
int ngtcp2_pkt_decode_stateless_reset(ngtcp2_pkt_stateless_reset *sr,
                                      const uint8_t *payload,
                                      size_t payloadlen);

/*
 * ngtcp2_pkt_decode_stream_frame decodes STREAM frame from |payload|
 * of length |payloadlen|.  The result is stored in the object pointed
 * by |dest|.  STREAM frame must start at payload[0].  This function
 * finishes when it decodes one STREAM frame, and returns the exact
 * number of bytes read to decode a frame if it succeeds, or one of
 * the following negative error codes:
 *
 * NGTCP2_ERR_FRAME_FORMAT
 *     Payload is too short to include STREAM frame.
 */
ssize_t ngtcp2_pkt_decode_stream_frame(ngtcp2_stream *dest,
                                       const uint8_t *payload,
                                       size_t payloadlen);

/*
 * ngtcp2_pkt_decode_ack_frame decodes ACK frame from |payload| of
 * length |payloadlen|.  The result is stored in the object pointed by
 * |dest|.  ACK frame must start at payload[0].  This function
 * finishes when it decodes one ACK frame, and returns the exact
 * number of bytes read to decode a frame if it succeeds, or one of
 * the following negative error codes:
 *
 * NGTCP2_ERR_FRAME_FORMAT
 *     Payload is too short to include ACK frame.
 */
ssize_t ngtcp2_pkt_decode_ack_frame(ngtcp2_ack *dest, const uint8_t *payload,
                                    size_t payloadlen);

/*
 * ngtcp2_pkt_decode_padding_frame decodes contiguous PADDING frames
 * from |payload| of length |payloadlen|.  It continues to parse
 * frames as long as the frame type is PADDING.  This finishes when it
 * encounters the frame type which is not PADDING, or all input data
 * is read.  The first byte (payload[0]) must be NGTCP2_FRAME_PADDING.
 * This function returns the exact number of bytes read to decode
 * PADDING frames.
 */
size_t ngtcp2_pkt_decode_padding_frame(ngtcp2_padding *dest,
                                       const uint8_t *payload,
                                       size_t payloadlen);

/*
 * ngtcp2_pkt_decode_rst_stream_frame decodes RST_STREAM frame from
 * |payload| of length |payloadlen|.  The result is stored in the
 * object pointed by |dest|.  RST_STREAM frame must start at
 * payload[0].  This function finishes when it decodes one RST_STREAM
 * frame, and returns the exact number of bytes read to decode a frame
 * if it succeeds, or one of the following negative error codes:
 *
 * NGTCP2_ERR_FRAME_FORMAT
 *     Payload is too short to include RST_STREAM frame.
 */
ssize_t ngtcp2_pkt_decode_rst_stream_frame(ngtcp2_rst_stream *dest,
                                           const uint8_t *payload,
                                           size_t payloadlen);

/*
 * ngtcp2_pkt_decode_connection_close_frame decodes CONNECTION_CLOSE
 * frame from |payload| of length |payloadlen|.  The result is stored
 * in the object pointed by |dest|.  CONNECTION_CLOSE frame must start
 * at payload[0].  This function finishes it decodes one
 * CONNECTION_CLOSE frame, and returns the exact number of bytes read
 * to decode a frame if it succeeds, or one of the following negative
 * error codes:
 *
 * NGTCP2_ERR_FRAME_FORMAT
 *     Payload is too short to include CONNECTION_CLOSE frame.
 */
ssize_t ngtcp2_pkt_decode_connection_close_frame(ngtcp2_connection_close *dest,
                                                 const uint8_t *payload,
                                                 size_t payloadlen);

/*
 * ngtcp2_pkt_decode_application_close_frame decodes APPLICATION_CLOSE
 * frame from |payload| of length |payloadlen|.  The result is stored
 * in the object pointed by |dest|.  APPLICATION_CLOSE frame must start
 * at payload[0].  This function finishes it decodes one
 * APPLICATION_CLOSE frame, and returns the exact number of bytes read
 * to decode a frame if it succeeds, or one of the following negative
 * error codes:
 *
 * NGTCP2_ERR_FRAME_FORMAT
 *     Payload is too short to include APPLICATION_CLOSE frame.
 */
ssize_t ngtcp2_pkt_decode_application_close_frame(
    ngtcp2_application_close *dest, const uint8_t *payload, size_t payloadlen);

/*
 * ngtcp2_pkt_decode_max_data_frame decodes MAX_DATA frame from
 * |payload| of length |payloadlen|.  The result is stored in the
 * object pointed by |dest|.  MAX_DATA frame must start at payload[0].
 * This function finishes when it decodes one MAX_DATA frame, and
 * returns the exact number of bytes read to decode a frame if it
 * succeeds, or one of the following negative error codes:
 *
 * NGTCP2_ERR_FRAME_FORMAT
 *     Payload is too short to include MAX_DATA frame.
 */
ssize_t ngtcp2_pkt_decode_max_data_frame(ngtcp2_max_data *dest,
                                         const uint8_t *payload,
                                         size_t payloadlen);

/*
 * ngtcp2_pkt_decode_max_stream_data_frame decodes MAX_STREAM_DATA
 * frame from |payload| of length |payloadlen|.  The result is stored
 * in the object pointed by |dest|.  MAX_STREAM_DATA frame must start
 * at payload[0].  This function finishes when it decodes one
 * MAX_STREAM_DATA frame, and returns the exact number of bytes read
 * to decode a frame if it succeeds, or one of the following negative
 * error codes:
 *
 * NGTCP2_ERR_FRAME_FORMAT
 *     Payload is too short to include MAX_STREAM_DATA frame.
 */
ssize_t ngtcp2_pkt_decode_max_stream_data_frame(ngtcp2_max_stream_data *dest,
                                                const uint8_t *payload,
                                                size_t payloadlen);

/*
 * ngtcp2_pkt_decode_max_stream_id_frame decodes MAX_STREAM_ID frame
 * from |payload| of length |payloadlen|.  The result is stored in the
 * object pointed by |dest|.  MAX_STREAM_ID frame must start at
 * payload[0].  This function finishes when it decodes one
 * MAX_STREAM_ID frame, and returns the exact number of bytes read to
 * decode a frame if it succeeds, or one of the following negative
 * error codes:
 *
 * NGTCP2_ERR_FRAME_FORMAT
 *     Payload is too short to include MAX_STREAM_ID frame.
 */
ssize_t ngtcp2_pkt_decode_max_stream_id_frame(ngtcp2_max_stream_id *dest,
                                              const uint8_t *payload,
                                              size_t payloadlen);

/*
 * ngtcp2_pkt_decode_ping_frame decodes PING frame from |payload| of
 * length |payloadlen|.  The result is stored in the object pointed by
 * |dest|.  PING frame must start at payload[0].  This function
 * finishes when it decodes one PING frame, and returns the exact
 * number of bytes read to decode a frame if it succeeds, or one of
 * the following negative error codes:
 *
 * NGTCP2_ERR_FRAME_FORMAT
 *     Payload is too short to include PING frame.
 */
ssize_t ngtcp2_pkt_decode_ping_frame(ngtcp2_ping *dest, const uint8_t *payload,
                                     size_t payloadlen);

/*
 * ngtcp2_pkt_decode_blocked_frame decodes BLOCKED frame from
 * |payload| of length |payloadlen|.  The result is stored in the
 * object pointed by |dest|.  BLOCKED frame must start at payload[0].
 * This function finishes when it decodes one BLOCKED frame, and
 * returns the exact number of bytes read to decode a frame if it
 * succeeds, or one of the following negative error codes:
 *
 * NGTCP2_ERR_FRAME_FORMAT
 *     Payload is too short to include BLOCKED frame.
 */
ssize_t ngtcp2_pkt_decode_blocked_frame(ngtcp2_blocked *dest,
                                        const uint8_t *payload,
                                        size_t payloadlen);

/*
 * ngtcp2_pkt_decode_stream_blocked_frame decodes STREAM_BLOCKED frame
 * from |payload| of length |payloadlen|.  The result is stored in the
 * object pointed by |dest|.  STREAM_BLOCKED frame must start at
 * payload[0].  This function finishes when it decodes one
 * STREAM_BLOCKED frame, and returns the exact number of bytes read to
 * decode a frame if it succeeds, or one of the following negative
 * error codes:
 *
 * NGTCP2_ERR_FRAME_FORMAT
 *     Payload is too short to include STREAM_BLOCKED frame.
 */
ssize_t ngtcp2_pkt_decode_stream_blocked_frame(ngtcp2_stream_blocked *dest,
                                               const uint8_t *payload,
                                               size_t payloadlen);

/*
 * ngtcp2_pkt_decode_stream_id_blocked_frame decodes STREAM_ID_BLOCKED
 * frame from |payload| of length |payloadlen|.  The result is stored
 * in the object pointed by |dest|.  STREAM_ID_BLOCKED frame must
 * start at payload[0].  This function finishes when it decodes one
 * STREAM_ID_BLOCKED frame, and returns the exact number of bytes read
 * to decode a frame if it succeeds, or one of the following negative
 * error codes:
 *
 * NGTCP2_ERR_FRAME_FORMAT
 *     Payload is too short to include STREAM_ID_BLOCKED frame.
 */
ssize_t ngtcp2_pkt_decode_stream_id_blocked_frame(
    ngtcp2_stream_id_blocked *dest, const uint8_t *payload, size_t payloadlen);

/*
 * ngtcp2_pkt_decode_new_connection_id_frame decodes NEW_CONNECTION_ID
 * frame from |payload| of length |payloadlen|.  The result is stored
 * in the object pointed by |dest|.  NEW_CONNECTION_ID frame must
 * start at payload[0].  This function finishes when it decodes one
 * NEW_CONNECTION_ID frame, and returns the exact number of bytes read
 * to decode a frame if it succeeds, or one of the following negative
 * error codes:
 *
 * NGTCP2_ERR_FRAME_FORMAT
 *     Payload is too short to include NEW_CONNECTION_ID frame.
 * NGTCP2_ERR_PROTO
 *     The length of CID is strictly less than 4 or greater than 18.
 */
ssize_t ngtcp2_pkt_decode_new_connection_id_frame(
    ngtcp2_new_connection_id *dest, const uint8_t *payload, size_t payloadlen);

/*
 * ngtcp2_pkt_decode_stop_sending_frame decodes STOP_SENDING frame
 * from |payload| of length |payloadlen|.  The result is stored in the
 * object pointed by |dest|.  STOP_SENDING frame must start at
 * payload[0].  This function finishes when it decodes one
 * STOP_SENDING frame, and returns the exact number of bytes read to
 * decode a frame if it succeeds, or one of the following negative
 * error codes:
 *
 * NGTCP2_ERR_FRAME_FORMAT
 *     Payload is too short to include STOP_SENDING frame.
 */
ssize_t ngtcp2_pkt_decode_stop_sending_frame(ngtcp2_stop_sending *dest,
                                             const uint8_t *payload,
                                             size_t payloadlen);

/*
 * ngtcp2_pkt_decode_path_challenge_frame decodes PATH_CHALLENGE frame
 * from |payload| of length |payloadlen|.  The result is stored in the
 * object pointed by |dest|.  PATH_CHALLENGE frame must start at
 * payload[0].  This function finishes when it decodes one
 * PATH_CHALLENGE frame, and returns the exact number of bytes read to
 * decode a frame if it succeeds, or one of the following negative
 * error codes:
 *
 * NGTCP2_ERR_FRAME_FORMAT
 *     Payload is too short to include PATH_CHALLENGE frame.
 */
ssize_t ngtcp2_pkt_decode_path_challenge_frame(ngtcp2_path_challenge *dest,
                                               const uint8_t *payload,
                                               size_t payloadlen);

/*
 * ngtcp2_pkt_decode_path_response_frame decodes PATH_RESPONSE frame
 * from |payload| of length |payloadlen|.  The result is stored in the
 * object pointed by |dest|.  PATH_RESPONSE frame must start at
 * payload[0].  This function finishes when it decodes one
 * PATH_RESPONSE frame, and returns the exact number of bytes read to
 * decode a frame if it succeeds, or one of the following negative
 * error codes:
 *
 * NGTCP2_ERR_FRAME_FORMAT
 *     Payload is too short to include PATH_RESPONSE frame.
 */
ssize_t ngtcp2_pkt_decode_path_response_frame(ngtcp2_path_response *dest,
                                              const uint8_t *payload,
                                              size_t payloadlen);

/*
 * ngtcp2_pkt_encode_stream_frame encodes STREAM frame |fr| into the
 * buffer pointed by |out| of length |outlen|.
 *
 * This function assigns <the serialized frame type> &
 * ~NGTCP2_FRAME_STREAM to fr->flags.
 *
 * This function returns the number of bytes written if it succeeds,
 * or one of the following negative error codes:
 *
 * NGTCP2_ERR_NOBUF
 *     Buffer does not have enough capacity to write a frame.
 */
ssize_t ngtcp2_pkt_encode_stream_frame(uint8_t *out, size_t outlen,
                                       ngtcp2_stream *fr);

/*
 * ngtcp2_pkt_encode_ack_frame encodes ACK frame |fr| into the buffer
 * pointed by |out| of length |outlen|.
 *
 * This function assigns <the serialized frame type> &
 * ~NGTCP2_FRAME_ACK to fr->flags.
 *
 * This function returns the number of bytes written if it succeeds,
 * or one of the following negative error codes:
 *
 * NGTCP2_ERR_NOBUF
 *     Buffer does not have enough capacity to write a frame.
 */
ssize_t ngtcp2_pkt_encode_ack_frame(uint8_t *out, size_t outlen,
                                    ngtcp2_ack *fr);

/*
 * ngtcp2_pkt_encode_padding_frame encodes PADDING frame |fr| into the
 * buffer pointed by |out| of length |outlen|.
 *
 * This function encodes consecutive fr->len PADDING frames.
 *
 * This function returns the number of bytes written if it succeeds,
 * or one of the following negative error codes:
 *
 * NGTCP2_ERR_NOBUF
 *     Buffer does not have enough capacity to write frame(s).
 */
ssize_t ngtcp2_pkt_encode_padding_frame(uint8_t *out, size_t outlen,
                                        const ngtcp2_padding *fr);

/*
 * ngtcp2_pkt_encode_rst_stream_frame encodes RST_STREAM frame |fr|
 * into the buffer pointed by |out| of length |buflen|.
 *
 * This function returns the number of bytes written if it succeeds,
 * or one of the following negative error codes:
 *
 * NGTCP2_ERR_NOBUF
 *     Buffer does not have enough capacity to write a frame.
 */
ssize_t ngtcp2_pkt_encode_rst_stream_frame(uint8_t *out, size_t outlen,
                                           const ngtcp2_rst_stream *fr);

/*
 * ngtcp2_pkt_encode_connection_close_frame encodes CONNECTION_CLOSE
 * frame |fr| into the buffer pointed by |out| of length |outlen|.
 *
 * This function returns the number of bytes written if it succeeds,
 * or one of the following negative error codes:
 *
 * NGTCP2_ERR_NOBUF
 *     Buffer does not have enough capacity to write a frame.
 */
ssize_t
ngtcp2_pkt_encode_connection_close_frame(uint8_t *out, size_t outlen,
                                         const ngtcp2_connection_close *fr);

/*
 * ngtcp2_pkt_encode_application_close_frame encodes APPLICATION_CLOSE
 * frame |fr| into the buffer pointed by |out| of length |outlen|.
 *
 * This function returns the number of bytes written if it succeeds,
 * or one of the following negative error codes:
 *
 * NGTCP2_ERR_NOBUF
 *     Buffer does not have enough capacity to write a frame.
 */
ssize_t
ngtcp2_pkt_encode_application_close_frame(uint8_t *out, size_t outlen,
                                          const ngtcp2_application_close *fr);

/*
 * ngtcp2_pkt_encode_max_data_frame encodes MAX_DATA frame |fr| into
 * the buffer pointed by |out| of length |outlen|.
 *
 * This function returns the number of bytes written if it succeeds,
 * or one of the following negative error codes:
 *
 * NGTCP2_ERR_NOBUF
 *     Buffer does not have enough capacity to write a frame.
 */
ssize_t ngtcp2_pkt_encode_max_data_frame(uint8_t *out, size_t outlen,
                                         const ngtcp2_max_data *fr);

/*
 * ngtcp2_pkt_encode_max_stream_data_frame encodes MAX_STREAM_DATA
 * frame |fr| into the buffer pointed by |out| of length |outlen|.
 *
 * This function returns the number of bytes written if it succeeds,
 * or one of the following negative error codes:
 *
 * NGTCP2_ERR_NOBUF
 *     Buffer does not have enough capacity to write a frame.
 */
ssize_t
ngtcp2_pkt_encode_max_stream_data_frame(uint8_t *out, size_t outlen,
                                        const ngtcp2_max_stream_data *fr);

/*
 * ngtcp2_pkt_encode_max_stream_id_frame encodes MAX_STREAM_ID frame
 * |fr| into the buffer pointed by |out| of length |outlen|.
 *
 * This function returns the number of bytes written if it succeeds,
 * or one of the following negative error codes:
 *
 * NGTCP2_ERR_NOBUF
 *     Buffer does not have enough capacity to write a frame.
 */
ssize_t ngtcp2_pkt_encode_max_stream_id_frame(uint8_t *out, size_t outlen,
                                              const ngtcp2_max_stream_id *fr);

/*
 * ngtcp2_pkt_encode_ping_frame encodes PING frame |fr| into the
 * buffer pointed by |out| of length |outlen|.
 *
 * This function returns the number of bytes written if it succeeds,
 * or one of the following negative error codes:
 *
 * NGTCP2_ERR_NOBUF
 *     Buffer does not have enough capacity to write a frame.
 */
ssize_t ngtcp2_pkt_encode_ping_frame(uint8_t *out, size_t outlen,
                                     const ngtcp2_ping *fr);

/*
 * ngtcp2_pkt_encode_blocked_frame encodes BLOCKED frame |fr| into the
 * buffer pointed by |out| of length |outlen|.
 *
 * This function returns the number of bytes written if it succeeds,
 * or one of the following negative error codes:
 *
 * NGTCP2_ERR_NOBUF
 *     Buffer does not have enough capacity to write a frame.
 */
ssize_t ngtcp2_pkt_encode_blocked_frame(uint8_t *out, size_t outlen,
                                        const ngtcp2_blocked *fr);

/*
 * ngtcp2_pkt_encode_stream_blocked_frame encodes STREAM_BLOCKED frame
 * |fr| into the buffer pointed by |out| of length |outlen|.
 *
 * This function returns the number of bytes written if it succeeds,
 * or one of the following negative error codes:
 *
 * NGTCP2_ERR_NOBUF
 *     Buffer does not have enough capacity to write a frame.
 */
ssize_t ngtcp2_pkt_encode_stream_blocked_frame(uint8_t *out, size_t outlen,
                                               const ngtcp2_stream_blocked *fr);

/*
 * ngtcp2_pkt_encode_stream_id_blocked_frame encodes STREAM_ID_BLOCKED
 * frame |fr| into the buffer pointed by |out| of length |outlen|.
 *
 * This function returns the number of bytes written if it succeeds,
 * or one of the following negative error codes:
 *
 * NGTCP2_ERR_NOBUF
 *     Buffer does not have enough capacity to write a frame.
 */
ssize_t
ngtcp2_pkt_encode_stream_id_blocked_frame(uint8_t *out, size_t outlen,
                                          const ngtcp2_stream_id_blocked *fr);

/*
 * ngtcp2_pkt_encode_new_connection_id_frame encodes NEW_CONNECTION_ID
 * frame |fr| into the buffer pointed by |out| of length |outlen|.
 *
 * This function returns the number of bytes written if it succeeds,
 * or one of the following negative error codes:
 *
 * NGTCP2_ERR_NOBUF
 *     Buffer does not have enough capacity to write a frame.
 */
ssize_t
ngtcp2_pkt_encode_new_connection_id_frame(uint8_t *out, size_t outlen,
                                          const ngtcp2_new_connection_id *fr);

/*
 * ngtcp2_pkt_encode_stop_sending_frame encodes STOP_SENDING frame
 * |fr| into the buffer pointed by |out| of length |outlen|.
 *
 * This function returns the number of bytes written if it succeeds,
 * or one of the following negative error codes:
 *
 * NGTCP2_ERR_NOBUF
 *     Buffer does not have enough capacity to write a frame.
 */
ssize_t ngtcp2_pkt_encode_stop_sending_frame(uint8_t *out, size_t outlen,
                                             const ngtcp2_stop_sending *fr);

/*
 * ngtcp2_pkt_encode_path_challenge_frame encodes PATH_CHALLENGE frame
 * |fr| into the buffer pointed by |out| of length |outlen|.
 *
 * This function returns the number of bytes written if it succeeds,
 * or one of the following negative error codes:
 *
 * NGTCP2_ERR_NOBUF
 *     Buffer does not have enough capacity to write a frame.
 */
ssize_t ngtcp2_pkt_encode_path_challenge_frame(uint8_t *out, size_t outlen,
                                               const ngtcp2_path_challenge *fr);

/*
 * ngtcp2_pkt_encode_path_response_frame encodes PATH_RESPONSE frame
 * |fr| into the buffer pointed by |out| of length |outlen|.
 *
 * This function returns the number of bytes written if it succeeds,
 * or one of the following negative error codes:
 *
 * NGTCP2_ERR_NOBUF
 *     Buffer does not have enough capacity to write a frame.
 */
ssize_t ngtcp2_pkt_encode_path_response_frame(uint8_t *out, size_t outlen,
                                              const ngtcp2_path_response *fr);

/*
 * ngtcp2_pkt_adjust_pkt_num find the full 64 bits packet number for
 * |pkt_num|, which is expected to be least significant |n| bits.  The
 * |max_pkt_num| is the highest successfully authenticated packet
 * number.
 */
uint64_t ngtcp2_pkt_adjust_pkt_num(uint64_t max_pkt_num, uint64_t pkt_num,
                                   size_t n);

/*
 * ngtcp2_pkt_adjust_ack_pkt_num adjusts all packet numbers in |ack|
 * using the maximum packet number |max_pkt_num| received so far.
 */
void ngtcp2_pkt_adjust_ack_pkt_num(ngtcp2_ack *ack, uint64_t max_pkt_num);

/*
 * ngtcp2_pkt_validate_ack checks that ack is malformed or not.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_ACK_FRAME
 *     ACK frame is malformed
 */
int ngtcp2_pkt_validate_ack(ngtcp2_ack *fr);

#endif /* NGTCP2_PKT_H */
