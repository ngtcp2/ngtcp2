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
#include "ngtcp2_pkt.h"

#include <assert.h>

#include "ngtcp2_conv.h"

void ngtcp2_pkt_hd_init(ngtcp2_pkt_hd *hd, uint8_t flags, uint8_t type,
                        uint64_t conn_id, uint32_t pkt_num, uint32_t version) {
  hd->flags = flags;
  hd->type = type;
  hd->conn_id = conn_id;
  hd->pkt_num = pkt_num;
  hd->version = version;
}

ssize_t ngtcp2_pkt_decode_hd(ngtcp2_pkt_hd *dest, const uint8_t *pkt,
                             size_t pktlen) {
  if (pktlen == 0) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  if (pkt[0] & NGTCP2_HEADER_FORM_MASK) {
    return ngtcp2_pkt_decode_hd_long(dest, pkt, pktlen);
  }

  return ngtcp2_pkt_decode_hd_short(dest, pkt, pktlen);
}

ssize_t ngtcp2_pkt_decode_hd_long(ngtcp2_pkt_hd *dest, const uint8_t *pkt,
                                  size_t pktlen) {
  uint8_t type;

  if (pktlen < NGTCP2_LONG_HEADERLEN) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  if ((pkt[0] & NGTCP2_HEADER_FORM_MASK) == 0) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  type = pkt[0] & NGTCP2_LONG_TYPE_MASK;
  switch (type) {
  case NGTCP2_PKT_VERSION_NEGOTIATION:
  case NGTCP2_PKT_CLIENT_INITIAL:
  case NGTCP2_PKT_SERVER_STATELESS_RETRY:
  case NGTCP2_PKT_SERVER_CLEARTEXT:
  case NGTCP2_PKT_CLIENT_CLEARTEXT:
  case NGTCP2_PKT_0RTT_PROTECTED:
  case NGTCP2_PKT_1RTT_PROTECTED_K0:
  case NGTCP2_PKT_1RTT_PROTECTED_K1:
  case NGTCP2_PKT_PUBLIC_RESET:
    break;
  default:
    return NGTCP2_ERR_UNKNOWN_PKT_TYPE;
  }

  dest->flags = NGTCP2_PKT_FLAG_LONG_FORM;
  dest->type = type;
  dest->conn_id = ngtcp2_get_uint64(&pkt[1]);
  dest->pkt_num = ngtcp2_get_uint32(&pkt[9]);
  dest->version = ngtcp2_get_uint32(&pkt[13]);

  return NGTCP2_LONG_HEADERLEN;
}

ssize_t ngtcp2_pkt_decode_hd_short(ngtcp2_pkt_hd *dest, const uint8_t *pkt,
                                   size_t pktlen) {
  uint8_t flags = 0;
  uint8_t type;
  size_t len = 1;
  const uint8_t *p = pkt;

  if (pktlen < 1) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  if (pkt[0] & NGTCP2_HEADER_FORM_MASK) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  if (pkt[0] & NGTCP2_CONN_ID_MASK) {
    flags |= NGTCP2_PKT_FLAG_CONN_ID;
    len += 8;
  }
  if (pkt[0] & NGTCP2_KEY_PHASE_MASK) {
    flags |= NGTCP2_PKT_FLAG_KEY_PHASE;
  }

  type = pkt[0] & NGTCP2_SHORT_TYPE_MASK;
  switch (type) {
  case NGTCP2_PKT_01:
    ++len;
    break;
  case NGTCP2_PKT_02:
    len += 2;
    break;
  case NGTCP2_PKT_03:
    len += 4;
    break;
  default:
    return NGTCP2_ERR_UNKNOWN_PKT_TYPE;
  }

  if (pktlen < len) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  ++p;

  if (flags & NGTCP2_PKT_FLAG_CONN_ID) {
    dest->conn_id = ngtcp2_get_uint64(p);
    p += 8;
  } else {
    dest->conn_id = 0;
  }

  switch (type) {
  case NGTCP2_PKT_01:
    dest->pkt_num = *p;
    break;
  case NGTCP2_PKT_02:
    dest->pkt_num = ngtcp2_get_uint16(p);
    break;
  case NGTCP2_PKT_03:
    dest->pkt_num = ngtcp2_get_uint32(p);
    break;
  }

  dest->flags = flags;
  dest->version = 0;

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_encode_hd_long(uint8_t *out, size_t outlen,
                                  const ngtcp2_pkt_hd *hd) {
  uint8_t *p;

  if (outlen < NGTCP2_LONG_HEADERLEN) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  p = out;

  *p++ = NGTCP2_HEADER_FORM_MASK | hd->type;
  p = ngtcp2_put_uint64be(p, hd->conn_id);
  p = ngtcp2_put_uint32be(p, hd->pkt_num);
  p = ngtcp2_put_uint32be(p, hd->version);

  assert(p - out == NGTCP2_LONG_HEADERLEN);

  return NGTCP2_LONG_HEADERLEN;
}

ssize_t ngtcp2_pkt_encode_hd_short(uint8_t *out, size_t outlen,
                                   const ngtcp2_pkt_hd *hd) {
  uint8_t *p;
  size_t len = 1;
  int need_conn_id = 0;

  if (hd->flags & NGTCP2_PKT_FLAG_CONN_ID) {
    need_conn_id = 1;
    len += 8;
  }

  switch (hd->type) {
  case NGTCP2_PKT_01:
    ++len;
    break;
  case NGTCP2_PKT_02:
    len += 2;
    break;
  case NGTCP2_PKT_03:
    len += 4;
    break;
  default:
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  if (outlen < len) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  p = out;

  *p = hd->type;
  if (need_conn_id) {
    *p |= NGTCP2_CONN_ID_MASK;
  }
  if (hd->flags & NGTCP2_PKT_FLAG_KEY_PHASE) {
    *p |= NGTCP2_KEY_PHASE_MASK;
  }

  ++p;

  if (need_conn_id) {
    p = ngtcp2_put_uint64be(p, hd->conn_id);
  }

  switch (hd->type) {
  case NGTCP2_PKT_01:
    *p++ = (uint8_t)hd->pkt_num;
    break;
  case NGTCP2_PKT_02:
    p = ngtcp2_put_uint16be(p, (uint16_t)hd->pkt_num);
    break;
  case NGTCP2_PKT_03:
    p = ngtcp2_put_uint32be(p, hd->pkt_num);
    break;
  default:
    assert(0);
  }

  assert((size_t)(p - out) == len);

  return p - out;
}

static int has_mask(uint8_t b, uint8_t mask) { return (b & mask) == mask; }

ssize_t ngtcp2_pkt_decode_frame(ngtcp2_frame *dest, const uint8_t *payload,
                                size_t payloadlen) {
  uint8_t type;

  if (payloadlen == 0) {
    return 0;
  }

  type = payload[0];

  if (has_mask(type, NGTCP2_FRAME_STREAM)) {
    return ngtcp2_pkt_decode_stream_frame(dest, payload, payloadlen);
  }

  if (has_mask(type, NGTCP2_FRAME_ACK)) {
    return ngtcp2_pkt_decode_ack_frame(dest, payload, payloadlen);
  }

  switch (type) {
  case NGTCP2_FRAME_PADDING:
    return ngtcp2_pkt_decode_padding_frame(dest, payload, payloadlen);
  case NGTCP2_FRAME_RST_STREAM:
    return ngtcp2_pkt_decode_rst_stream_frame(dest, payload, payloadlen);
  case NGTCP2_FRAME_CONNECTION_CLOSE:
    return ngtcp2_pkt_decode_connection_close_frame(dest, payload, payloadlen);
  case NGTCP2_FRAME_GOAWAY:
    return ngtcp2_pkt_decode_goaway_frame(dest, payload, payloadlen);
  case NGTCP2_FRAME_MAX_DATA:
    return ngtcp2_pkt_decode_max_data_frame(dest, payload, payloadlen);
  case NGTCP2_FRAME_MAX_STREAM_DATA:
    return ngtcp2_pkt_decode_max_stream_data_frame(dest, payload, payloadlen);
  case NGTCP2_FRAME_MAX_STREAM_ID:
    return ngtcp2_pkt_decode_max_stream_id_frame(dest, payload, payloadlen);
  case NGTCP2_FRAME_PING:
    return ngtcp2_pkt_decode_ping_frame(dest, payload, payloadlen);
  case NGTCP2_FRAME_BLOCKED:
    return ngtcp2_pkt_decode_blocked_frame(dest, payload, payloadlen);
  case NGTCP2_FRAME_STREAM_BLOCKED:
    return ngtcp2_pkt_decode_stream_blocked_frame(dest, payload, payloadlen);
  case NGTCP2_FRAME_STREAM_ID_NEEDED:
    return ngtcp2_pkt_decode_stream_id_needed_frame(dest, payload, payloadlen);
  case NGTCP2_FRAME_NEW_CONNECTION_ID:
    return ngtcp2_pkt_decode_new_connection_id_frame(dest, payload, payloadlen);
  default:
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }
}

ssize_t ngtcp2_pkt_decode_stream_frame(ngtcp2_frame *dest,
                                       const uint8_t *payload,
                                       size_t payloadlen) {
  uint8_t type;
  uint8_t fin = 0;
  size_t idlen;
  size_t offsetlen = 0;
  size_t datalen = 0;
  uint8_t b;
  size_t len = 1;
  const uint8_t *p;

  if (payloadlen == 0 || !has_mask(payload[0], NGTCP2_FRAME_STREAM)) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  type = payload[0];

  if (type & NGTCP2_STREAM_FIN_BIT) {
    fin = 1;
  }

  idlen = ((type & NGTCP2_STREAM_SS_MASK) >> 3) + 1;

  b = (type & NGTCP2_STREAM_OO_MASK) >> 1;
  if (b) {
    offsetlen = 1 << b;
  }

  len += idlen + offsetlen;

  if (type & NGTCP2_STREAM_D_BIT) {
    len += 2;

    if (payloadlen < len) {
      return NGTCP2_ERR_INVALID_ARGUMENT;
    }

    datalen = ngtcp2_get_uint16(&payload[len - 2]);
    len += datalen;
  }

  if (payloadlen < len) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  dest->type = NGTCP2_FRAME_STREAM;
  dest->stream.fin = fin;

  p = &payload[1];

  switch (idlen) {
  case 1:
    dest->stream.stream_id = *p++;
    break;
  case 2:
    dest->stream.stream_id = ngtcp2_get_uint16(p);
    p += 2;
    break;
  case 3:
    dest->stream.stream_id = ngtcp2_get_uint24(p);
    p += 3;
    break;
  case 4:
    dest->stream.stream_id = ngtcp2_get_uint32(p);
    p += 4;
    break;
  }

  switch (offsetlen) {
  case 2:
    dest->stream.offset = ngtcp2_get_uint16(p);
    break;
  case 4:
    dest->stream.offset = ngtcp2_get_uint32(p);
    break;
  case 8:
    dest->stream.offset = ngtcp2_get_uint64(p);
    break;
  }

  p += offsetlen;

  if (datalen) {
    dest->stream.datalen = datalen;
    p += 2;
    dest->stream.data = p;
    p += datalen;
  } else {
    dest->stream.datalen = payloadlen - (size_t)(p - payload);
    dest->stream.data = p;
  }

  assert((size_t)(p - payload) == len);

  return p - payload;
}

ssize_t ngtcp2_pkt_decode_ack_frame(ngtcp2_frame *dest, const uint8_t *payload,
                                    size_t payloadlen) {
  uint8_t type;
  size_t num_blks = 0;
  size_t num_ts;
  size_t lalen;
  size_t abllen;
  size_t len = 4;
  const uint8_t *p;

  /* We can expect at least 3 bytes (type, NumTS, and LA) */
  if (payloadlen < 3 || !has_mask(payload[0], NGTCP2_FRAME_ACK)) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  p = &payload[0];

  type = *p++;

  if (type & NGTCP2_ACK_N_BIT) {
    num_blks = *p++;
    ++len;
  }

  num_ts = *p++;

  switch ((type & NGTCP2_ACK_LL_MASK) >> 2) {
  case 0x00:
    lalen = 1;
    break;
  case 0x01:
    lalen = 2;
    break;
  case 0x02:
    lalen = 4;
    break;
  case 0x03:
    lalen = 6;
    break;
  }

  len += lalen;

  switch (type & NGTCP2_ACK_MM_MASK) {
  case 0x00:
    abllen = 1;
    break;
  case 0x01:
    abllen = 2;
    break;
  case 0x02:
    abllen = 4;
    break;
  case 0x03:
    abllen = 6;
    break;
  }

  /* Length of ACK Block Section */
  /* First ACK Block Length */
  len += lalen;
  len += num_blks * abllen;

  /* Length of Timestamp Section */
  if (num_ts > 0) {
    len += num_ts * 3 + 2;
  }

  if (payloadlen < len) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  dest->type = NGTCP2_FRAME_ACK;

  switch (lalen) {
  case 1:
    dest->ack.largest_ack = *p;
    break;
  case 2:
    dest->ack.largest_ack = ngtcp2_get_uint16(p);
    break;
  case 4:
    dest->ack.largest_ack = ngtcp2_get_uint32(p);
    break;
  case 6:
    dest->ack.largest_ack = ngtcp2_get_uint48(p);
    break;
  }

  p += lalen;

  /* TODO Parse remaining fields */

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_decode_padding_frame(ngtcp2_frame *dest,
                                        const uint8_t *payload, size_t len) {
  (void)dest;
  (void)payload;
  (void)len;
  return -1;
}

ssize_t ngtcp2_pkt_decode_rst_stream_frame(ngtcp2_frame *dest,
                                           const uint8_t *payload, size_t len) {
  (void)dest;
  (void)payload;
  (void)len;
  return -1;
}

ssize_t ngtcp2_pkt_decode_connection_close_frame(ngtcp2_frame *dest,
                                                 const uint8_t *payload,
                                                 size_t len) {
  (void)dest;
  (void)payload;
  (void)len;
  return -1;
}

ssize_t ngtcp2_pkt_decode_goaway_frame(ngtcp2_frame *dest,
                                       const uint8_t *payload, size_t len) {
  (void)dest;
  (void)payload;
  (void)len;
  return -1;
}

ssize_t ngtcp2_pkt_decode_max_data_frame(ngtcp2_frame *dest,
                                         const uint8_t *payload, size_t len) {
  (void)dest;
  (void)payload;
  (void)len;
  return -1;
}

ssize_t ngtcp2_pkt_decode_max_stream_data_frame(ngtcp2_frame *dest,
                                                const uint8_t *payload,
                                                size_t len) {
  (void)dest;
  (void)payload;
  (void)len;
  return -1;
}

ssize_t ngtcp2_pkt_decode_max_stream_id_frame(ngtcp2_frame *dest,
                                              const uint8_t *payload,
                                              size_t len) {
  (void)dest;
  (void)payload;
  (void)len;
  return -1;
}

ssize_t ngtcp2_pkt_decode_ping_frame(ngtcp2_frame *dest, const uint8_t *payload,
                                     size_t len) {
  (void)dest;
  (void)payload;
  (void)len;
  return -1;
}

ssize_t ngtcp2_pkt_decode_blocked_frame(ngtcp2_frame *dest,
                                        const uint8_t *payload, size_t len) {
  (void)dest;
  (void)payload;
  (void)len;
  return -1;
}

ssize_t ngtcp2_pkt_decode_stream_blocked_frame(ngtcp2_frame *dest,
                                               const uint8_t *payload,
                                               size_t len) {
  (void)dest;
  (void)payload;
  (void)len;
  return -1;
}

ssize_t ngtcp2_pkt_decode_stream_id_needed_frame(ngtcp2_frame *dest,
                                                 const uint8_t *payload,
                                                 size_t len) {
  (void)dest;
  (void)payload;
  (void)len;
  return -1;
}

ssize_t ngtcp2_pkt_decode_new_connection_id_frame(ngtcp2_frame *dest,
                                                  const uint8_t *payload,
                                                  size_t len) {
  (void)dest;
  (void)payload;
  (void)len;
  return -1;
}
