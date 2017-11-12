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
#include <string.h>

#include "ngtcp2_conv.h"
#include "ngtcp2_str.h"
#include "ngtcp2_macro.h"

void ngtcp2_pkt_hd_init(ngtcp2_pkt_hd *hd, uint8_t flags, uint8_t type,
                        uint64_t conn_id, uint64_t pkt_num, uint32_t version) {
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

  if (pkt[0] & NGTCP2_HEADER_FORM_BIT) {
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

  if ((pkt[0] & NGTCP2_HEADER_FORM_BIT) == 0) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  type = pkt[0] & NGTCP2_LONG_TYPE_MASK;
  switch (type) {
  case NGTCP2_PKT_VERSION_NEGOTIATION:
  case NGTCP2_PKT_INITIAL:
  case NGTCP2_PKT_RETRY:
  case NGTCP2_PKT_HANDSHAKE:
  case NGTCP2_PKT_0RTT_PROTECTED:
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

  if (pkt[0] & NGTCP2_HEADER_FORM_BIT) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  if (pkt[0] & NGTCP2_CONN_ID_BIT) {
    flags |= NGTCP2_PKT_FLAG_CONN_ID;
    len += 8;
  }
  if (pkt[0] & NGTCP2_KEY_PHASE_BIT) {
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

  dest->type = type;

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
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = NGTCP2_HEADER_FORM_BIT | hd->type;
  p = ngtcp2_put_uint64be(p, hd->conn_id);
  p = ngtcp2_put_uint32be(p, (uint32_t)hd->pkt_num);
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
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p = hd->type;
  if (need_conn_id) {
    *p |= NGTCP2_CONN_ID_BIT;
  }
  if (hd->flags & NGTCP2_PKT_FLAG_KEY_PHASE) {
    *p |= NGTCP2_KEY_PHASE_BIT;
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
    p = ngtcp2_put_uint32be(p, (uint32_t)hd->pkt_num);
    break;
  default:
    assert(0);
  }

  assert((size_t)(p - out) == len);

  return (ssize_t)len;
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
    return ngtcp2_pkt_decode_stream_frame(&dest->stream, payload, payloadlen);
  }

  if (has_mask(type, NGTCP2_FRAME_ACK)) {
    return ngtcp2_pkt_decode_ack_frame(&dest->ack, payload, payloadlen);
  }

  switch (type) {
  case NGTCP2_FRAME_PADDING:
    return (ssize_t)ngtcp2_pkt_decode_padding_frame(&dest->padding, payload,
                                                    payloadlen);
  case NGTCP2_FRAME_RST_STREAM:
    return ngtcp2_pkt_decode_rst_stream_frame(&dest->rst_stream, payload,
                                              payloadlen);
  case NGTCP2_FRAME_CONNECTION_CLOSE:
    return ngtcp2_pkt_decode_connection_close_frame(&dest->connection_close,
                                                    payload, payloadlen);
  case NGTCP2_FRAME_APPLICATION_CLOSE:
    return ngtcp2_pkt_decode_application_close_frame(&dest->application_close,
                                                     payload, payloadlen);
  case NGTCP2_FRAME_MAX_DATA:
    return ngtcp2_pkt_decode_max_data_frame(&dest->max_data, payload,
                                            payloadlen);
  case NGTCP2_FRAME_MAX_STREAM_DATA:
    return ngtcp2_pkt_decode_max_stream_data_frame(&dest->max_stream_data,
                                                   payload, payloadlen);
  case NGTCP2_FRAME_MAX_STREAM_ID:
    return ngtcp2_pkt_decode_max_stream_id_frame(&dest->max_stream_id, payload,
                                                 payloadlen);
  case NGTCP2_FRAME_PING:
    return ngtcp2_pkt_decode_ping_frame(&dest->ping, payload, payloadlen);
  case NGTCP2_FRAME_BLOCKED:
    return (ssize_t)ngtcp2_pkt_decode_blocked_frame(&dest->blocked, payload,
                                                    payloadlen);
  case NGTCP2_FRAME_STREAM_BLOCKED:
    return ngtcp2_pkt_decode_stream_blocked_frame(&dest->stream_blocked,
                                                  payload, payloadlen);
  case NGTCP2_FRAME_STREAM_ID_BLOCKED:
    return (ssize_t)ngtcp2_pkt_decode_stream_id_blocked_frame(
        &dest->stream_id_blocked, payload, payloadlen);
  case NGTCP2_FRAME_NEW_CONNECTION_ID:
    return ngtcp2_pkt_decode_new_connection_id_frame(&dest->new_connection_id,
                                                     payload, payloadlen);
  case NGTCP2_FRAME_STOP_SENDING:
    return ngtcp2_pkt_decode_stop_sending_frame(&dest->stop_sending, payload,
                                                payloadlen);
  default:
    return NGTCP2_ERR_FRAME_FORMAT;
  }
}

ssize_t ngtcp2_pkt_decode_stream_frame(ngtcp2_stream *dest,
                                       const uint8_t *payload,
                                       size_t payloadlen) {
  uint8_t type;
  size_t len = 1 + 1;
  const uint8_t *p;
  size_t datalen;
  size_t n;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  type = payload[0];

  p = payload + 1;

  n = ngtcp2_get_varint_len(p);
  len += n - 1;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  p += n;

  if (type & NGTCP2_STREAM_OFF_BIT) {
    ++len;
    if (payloadlen < len) {
      return NGTCP2_ERR_FRAME_FORMAT;
    }

    n = ngtcp2_get_varint_len(p);
    len += n - 1;

    if (payloadlen < len) {
      return NGTCP2_ERR_FRAME_FORMAT;
    }

    p += n;
  }

  if (type & NGTCP2_STREAM_LEN_BIT) {
    ++len;
    if (payloadlen < len) {
      return NGTCP2_ERR_FRAME_FORMAT;
    }

    n = ngtcp2_get_varint_len(p);
    len += n - 1;

    if (payloadlen < len) {
      return NGTCP2_ERR_FRAME_FORMAT;
    }

    datalen = ngtcp2_get_varint(&n, p);
    len += datalen;

    if (payloadlen < len) {
      return NGTCP2_ERR_FRAME_FORMAT;
    }
  }

  p = payload + 1;

  dest->type = NGTCP2_FRAME_STREAM;
  dest->flags = (uint8_t)(type & ~NGTCP2_FRAME_STREAM);
  dest->fin = (type & NGTCP2_STREAM_FIN_BIT) != 0;
  dest->stream_id = ngtcp2_get_varint(&n, p);
  p += n;

  if (type & NGTCP2_STREAM_OFF_BIT) {
    dest->offset = ngtcp2_get_varint(&n, p);
    p += n;
  } else {
    dest->offset = 0;
  }

  if (type & NGTCP2_STREAM_LEN_BIT) {
    dest->datalen = ngtcp2_get_varint(&n, p);
    p += n;
    dest->data = p;
    p += dest->datalen;

    assert((size_t)(p - payload) == len);

    return (ssize_t)len;
  }

  dest->datalen = payloadlen - (size_t)(p - payload);
  dest->data = p;

  return (ssize_t)payloadlen;
}

ssize_t ngtcp2_pkt_decode_ack_frame(ngtcp2_ack *dest, const uint8_t *payload,
                                    size_t payloadlen) {
  size_t num_blks, max_num_blks;
  size_t len = 1 + 1 + 1 + 1 + 1;
  const uint8_t *p;
  size_t i, j;
  ngtcp2_ack_blk *blk;
  size_t n;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  p = payload + 1;

  /* Largest Acknowledged */
  n = ngtcp2_get_varint_len(p);
  len += n - 1;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  p += n;

  /* ACK Delay */
  n = ngtcp2_get_varint_len(p);
  len += n - 1;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  p += n;

  /* ACK Block Count */
  n = ngtcp2_get_varint_len(p);
  len += n - 1;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  num_blks = ngtcp2_get_varint(&n, p);
  len += num_blks * (1 + 1);

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  p += n;

  /* First ACK Block */
  n = ngtcp2_get_varint_len(p);
  len += n - 1;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  p += n;

  for (i = 0; i < num_blks; ++i) {
    /* Gap, and Additional ACK Block */
    for (j = 0; j < 2; ++j) {
      n = ngtcp2_get_varint_len(p);
      len += n - 1;

      if (payloadlen < len) {
        return NGTCP2_ERR_FRAME_FORMAT;
      }

      p += n;
    }
  }

  /* TODO We might not decode all blocks.  It could be very large. */
  max_num_blks = ngtcp2_min(NGTCP2_MAX_ACK_BLKS, num_blks);

  p = payload + 1;

  dest->type = NGTCP2_FRAME_ACK;
  dest->largest_ack = ngtcp2_get_varint(&n, p);
  p += n;
  dest->ack_delay = ngtcp2_get_varint(&n, p);
  p += n;
  dest->num_blks = max_num_blks;
  p += ngtcp2_get_varint_len(p);
  dest->first_ack_blklen = ngtcp2_get_varint(&n, p);
  p += n;

  for (i = 0; i < max_num_blks; ++i) {
    blk = &dest->blks[i];
    blk->gap = ngtcp2_get_varint(&n, p);
    p += n;
    blk->blklen = ngtcp2_get_varint(&n, p);
    p += n;
  }
  for (i = max_num_blks; i < num_blks; ++i) {
    p += ngtcp2_get_varint_len(p);
    p += ngtcp2_get_varint_len(p);
  }

  assert((size_t)(p - payload) == len);

  return (ssize_t)len;
}

size_t ngtcp2_pkt_decode_padding_frame(ngtcp2_padding *dest,
                                       const uint8_t *payload,
                                       size_t payloadlen) {
  const uint8_t *p, *ep;

  assert(payloadlen > 0);

  p = payload + 1;
  ep = payload + payloadlen;

  for (; p != ep && *p == NGTCP2_FRAME_PADDING; ++p)
    ;

  dest->type = NGTCP2_FRAME_PADDING;
  dest->len = (size_t)(p - payload);

  return (size_t)(p - payload);
}

ssize_t ngtcp2_pkt_decode_rst_stream_frame(ngtcp2_rst_stream *dest,
                                           const uint8_t *payload,
                                           size_t payloadlen) {
  size_t len = 1 + 1 + 2 + 1;
  const uint8_t *p;
  size_t n;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  p = payload + 1;

  n = ngtcp2_get_varint_len(p);
  len += n - 1;
  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }
  p += n + 2;
  n = ngtcp2_get_varint_len(p);
  len += n - 1;
  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  p = payload + 1;

  dest->type = NGTCP2_FRAME_RST_STREAM;
  dest->stream_id = ngtcp2_get_varint(&n, p);
  p += n;
  dest->app_error_code = ngtcp2_get_uint16(p);
  p += 2;
  dest->final_offset = ngtcp2_get_varint(&n, p);
  p += n;

  assert((size_t)(p - payload) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_decode_connection_close_frame(ngtcp2_connection_close *dest,
                                                 const uint8_t *payload,
                                                 size_t payloadlen) {
  size_t len = 1 + 2 + 1;
  const uint8_t *p;
  size_t reasonlen;
  size_t n;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  p = payload + 1 + 2;

  n = ngtcp2_get_varint_len(p);
  len += n - 1;
  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  reasonlen = ngtcp2_get_varint(&n, p);
  len += reasonlen;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  p = payload + 1;

  dest->type = NGTCP2_FRAME_CONNECTION_CLOSE;
  dest->error_code = ngtcp2_get_uint16(p);
  p += 2;
  dest->reasonlen = reasonlen;
  p += n;
  if (reasonlen == 0) {
    dest->reason = NULL;
  } else {
    dest->reason = (uint8_t *)p;
    p += reasonlen;
  }

  assert((size_t)(p - payload) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_decode_application_close_frame(
    ngtcp2_application_close *dest, const uint8_t *payload, size_t payloadlen) {
  size_t len = 1 + 2 + 1;
  const uint8_t *p;
  size_t reasonlen;
  size_t n;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  p = payload + 1 + 2;

  n = ngtcp2_get_varint_len(p);
  len += n - 1;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  reasonlen = ngtcp2_get_varint(&n, p);
  len += reasonlen;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  p = payload + 1;

  dest->type = NGTCP2_FRAME_APPLICATION_CLOSE;
  dest->app_error_code = ngtcp2_get_uint16(p);
  p += 2;
  dest->reasonlen = reasonlen;
  p += n;
  if (reasonlen == 0) {
    dest->reason = NULL;
  } else {
    dest->reason = (uint8_t *)p;
    p += reasonlen;
  }

  assert((size_t)(p - payload) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_decode_max_data_frame(ngtcp2_max_data *dest,
                                         const uint8_t *payload,
                                         size_t payloadlen) {
  size_t len = 1 + 1;
  const uint8_t *p;
  size_t n;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  p = payload + 1;

  n = ngtcp2_get_varint_len(p);
  len += n - 1;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  dest->type = NGTCP2_FRAME_MAX_DATA;
  dest->max_data = ngtcp2_get_varint(&n, p);
  p += n;

  assert((size_t)(p - payload) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_decode_max_stream_data_frame(ngtcp2_max_stream_data *dest,
                                                const uint8_t *payload,
                                                size_t payloadlen) {
  size_t len = 1 + 1 + 1;
  const uint8_t *p;
  size_t n;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  p = payload + 1;

  n = ngtcp2_get_varint_len(p);
  len += n - 1;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  p += n;

  n = ngtcp2_get_varint_len(p);
  len += n - 1;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  p = payload + 1;

  dest->type = NGTCP2_FRAME_MAX_STREAM_DATA;
  dest->stream_id = ngtcp2_get_varint(&n, p);
  p += n;
  dest->max_stream_data = ngtcp2_get_varint(&n, p);
  p += n;

  assert((size_t)(p - payload) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_decode_max_stream_id_frame(ngtcp2_max_stream_id *dest,
                                              const uint8_t *payload,
                                              size_t payloadlen) {
  size_t len = 1 + 1;
  const uint8_t *p;
  size_t n;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  p = payload + 1;

  n = ngtcp2_get_varint_len(p);
  len += n - 1;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  dest->type = NGTCP2_FRAME_MAX_STREAM_ID;
  dest->max_stream_id = ngtcp2_get_varint(&n, p);
  p += n;

  assert((size_t)(p - payload) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_decode_ping_frame(ngtcp2_ping *dest, const uint8_t *payload,
                                     size_t payloadlen) {
  size_t len = 1 + 1;
  const uint8_t *p;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  p = payload + 1;

  len += *p;
  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  dest->type = NGTCP2_FRAME_PING;
  dest->datalen = *p++;
  if (dest->datalen) {
    dest->data = (uint8_t *)p;
    p += dest->datalen;
  } else {
    dest->data = NULL;
  }

  assert((size_t)(p - payload) == len);

  return (ssize_t)len;
}

size_t ngtcp2_pkt_decode_blocked_frame(ngtcp2_blocked *dest,
                                       const uint8_t *payload,
                                       size_t payloadlen) {
  (void)payload;
  (void)payloadlen;
  dest->type = NGTCP2_FRAME_BLOCKED;

  return 1;
}

ssize_t ngtcp2_pkt_decode_stream_blocked_frame(ngtcp2_stream_blocked *dest,
                                               const uint8_t *payload,
                                               size_t payloadlen) {
  size_t len = 1 + 1;
  const uint8_t *p;
  size_t n;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  p = payload + 1;

  n = ngtcp2_get_varint_len(p);
  len += n - 1;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  dest->type = NGTCP2_FRAME_STREAM_BLOCKED;
  dest->stream_id = ngtcp2_get_varint(&n, p);
  p += n;

  assert((size_t)(p - payload) == len);

  return (ssize_t)len;
}

size_t ngtcp2_pkt_decode_stream_id_blocked_frame(ngtcp2_stream_id_blocked *dest,
                                                 const uint8_t *payload,
                                                 size_t payloadlen) {
  (void)payload;
  (void)payloadlen;
  dest->type = NGTCP2_FRAME_STREAM_ID_BLOCKED;

  return 1;
}

ssize_t ngtcp2_pkt_decode_new_connection_id_frame(
    ngtcp2_new_connection_id *dest, const uint8_t *payload, size_t payloadlen) {
  size_t len = 1 + 1 + 8 + 16;
  const uint8_t *p;
  size_t n;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  p = payload + 1;

  n = ngtcp2_get_varint_len(p);
  len += n - 1;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  dest->type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  dest->seq = (uint16_t)ngtcp2_get_varint(&n, p);
  p += n;
  dest->conn_id = ngtcp2_get_uint64(p);
  p += 8;
  memcpy(dest->stateless_reset_token, p, NGTCP2_STATELESS_RESET_TOKENLEN);
  p += NGTCP2_STATELESS_RESET_TOKENLEN;

  assert((size_t)(p - payload) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_decode_stop_sending_frame(ngtcp2_stop_sending *dest,
                                             const uint8_t *payload,
                                             size_t payloadlen) {
  size_t len = 1 + 1 + 2;
  const uint8_t *p;
  size_t n;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  p = payload + 1;

  n = ngtcp2_get_varint_len(p);
  len += n - 1;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_FORMAT;
  }

  dest->type = NGTCP2_FRAME_STOP_SENDING;
  dest->stream_id = ngtcp2_get_varint(&n, p);
  p += n;
  dest->app_error_code = ngtcp2_get_uint16(p);
  p += 2;

  assert((size_t)(p - payload) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_encode_frame(uint8_t *out, size_t outlen, ngtcp2_frame *fr) {
  switch (fr->type) {
  case NGTCP2_FRAME_STREAM:
    return ngtcp2_pkt_encode_stream_frame(out, outlen, &fr->stream);
  case NGTCP2_FRAME_ACK:
    return ngtcp2_pkt_encode_ack_frame(out, outlen, &fr->ack);
  case NGTCP2_FRAME_PADDING:
    return ngtcp2_pkt_encode_padding_frame(out, outlen, &fr->padding);
  case NGTCP2_FRAME_RST_STREAM:
    return ngtcp2_pkt_encode_rst_stream_frame(out, outlen, &fr->rst_stream);
  case NGTCP2_FRAME_CONNECTION_CLOSE:
    return ngtcp2_pkt_encode_connection_close_frame(out, outlen,
                                                    &fr->connection_close);
  case NGTCP2_FRAME_APPLICATION_CLOSE:
    return ngtcp2_pkt_encode_application_close_frame(out, outlen,
                                                     &fr->application_close);
  case NGTCP2_FRAME_MAX_DATA:
    return ngtcp2_pkt_encode_max_data_frame(out, outlen, &fr->max_data);
  case NGTCP2_FRAME_MAX_STREAM_DATA:
    return ngtcp2_pkt_encode_max_stream_data_frame(out, outlen,
                                                   &fr->max_stream_data);
  case NGTCP2_FRAME_MAX_STREAM_ID:
    return ngtcp2_pkt_encode_max_stream_id_frame(out, outlen,
                                                 &fr->max_stream_id);
  case NGTCP2_FRAME_PING:
    return ngtcp2_pkt_encode_ping_frame(out, outlen, &fr->ping);
  case NGTCP2_FRAME_BLOCKED:
    return ngtcp2_pkt_encode_blocked_frame(out, outlen, &fr->blocked);
  case NGTCP2_FRAME_STREAM_BLOCKED:
    return ngtcp2_pkt_encode_stream_blocked_frame(out, outlen,
                                                  &fr->stream_blocked);
  case NGTCP2_FRAME_STREAM_ID_BLOCKED:
    return ngtcp2_pkt_encode_stream_id_blocked_frame(out, outlen,
                                                     &fr->stream_id_blocked);
  case NGTCP2_FRAME_NEW_CONNECTION_ID:
    return ngtcp2_pkt_encode_new_connection_id_frame(out, outlen,
                                                     &fr->new_connection_id);
  case NGTCP2_FRAME_STOP_SENDING:
    return ngtcp2_pkt_encode_stop_sending_frame(out, outlen, &fr->stop_sending);
  default:
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }
}

ssize_t ngtcp2_pkt_encode_stream_frame(uint8_t *out, size_t outlen,
                                       ngtcp2_stream *fr) {
  size_t len = 1;
  uint8_t flags = NGTCP2_STREAM_LEN_BIT;
  uint8_t *p;

  if (fr->fin) {
    flags |= NGTCP2_STREAM_FIN_BIT;
  }

  if (fr->offset) {
    flags |= NGTCP2_STREAM_OFF_BIT;
    len += ngtcp2_put_varint_len(fr->offset);
  }

  len += ngtcp2_put_varint_len(fr->stream_id);
  len += ngtcp2_put_varint_len(fr->datalen);
  len += fr->datalen;

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = flags | NGTCP2_FRAME_STREAM;

  fr->flags = flags;

  p = ngtcp2_put_varint(p, fr->stream_id);

  if (fr->offset) {
    p = ngtcp2_put_varint(p, fr->offset);
  }

  p = ngtcp2_put_varint(p, fr->datalen);

  if (fr->datalen) {
    p = ngtcp2_cpymem(p, fr->data, fr->datalen);
  }

  assert((size_t)(p - out) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_encode_ack_frame(uint8_t *out, size_t outlen,
                                    ngtcp2_ack *fr) {
  size_t len = 1 + ngtcp2_put_varint_len(fr->largest_ack) +
               ngtcp2_put_varint_len(fr->ack_delay) +
               ngtcp2_put_varint_len(fr->num_blks) +
               ngtcp2_put_varint_len(fr->first_ack_blklen);
  uint8_t *p;
  size_t i;
  const ngtcp2_ack_blk *blk;

  for (i = 0; i < fr->num_blks; ++i) {
    blk = &fr->blks[i];
    len += ngtcp2_put_varint_len(blk->gap);
    len += ngtcp2_put_varint_len(blk->blklen);
  }

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = NGTCP2_FRAME_ACK;
  p = ngtcp2_put_varint(p, fr->largest_ack);
  p = ngtcp2_put_varint(p, fr->ack_delay);
  p = ngtcp2_put_varint(p, fr->num_blks);
  p = ngtcp2_put_varint(p, fr->first_ack_blklen);

  for (i = 0; i < fr->num_blks; ++i) {
    blk = &fr->blks[i];
    p = ngtcp2_put_varint(p, blk->gap);
    p = ngtcp2_put_varint(p, blk->blklen);
  }

  assert((size_t)(p - out) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_encode_padding_frame(uint8_t *out, size_t outlen,
                                        const ngtcp2_padding *fr) {
  if (outlen < fr->len) {
    return NGTCP2_ERR_NOBUF;
  }

  memset(out, 0, fr->len);

  return (ssize_t)fr->len;
}

ssize_t ngtcp2_pkt_encode_rst_stream_frame(uint8_t *out, size_t outlen,
                                           const ngtcp2_rst_stream *fr) {
  size_t len = 1 + ngtcp2_put_varint_len(fr->stream_id) + 2 +
               ngtcp2_put_varint_len(fr->final_offset);
  uint8_t *p;

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = NGTCP2_FRAME_RST_STREAM;
  p = ngtcp2_put_varint(p, fr->stream_id);
  p = ngtcp2_put_uint16be(p, fr->app_error_code);
  p = ngtcp2_put_varint(p, fr->final_offset);

  assert((size_t)(p - out) == len);

  return (ssize_t)len;
}

ssize_t
ngtcp2_pkt_encode_connection_close_frame(uint8_t *out, size_t outlen,
                                         const ngtcp2_connection_close *fr) {
  size_t len = 1 + 2 + ngtcp2_put_varint_len(fr->reasonlen) + fr->reasonlen;
  uint8_t *p;

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = NGTCP2_FRAME_CONNECTION_CLOSE;
  p = ngtcp2_put_uint16be(p, fr->error_code);
  p = ngtcp2_put_varint(p, fr->reasonlen);
  if (fr->reasonlen) {
    p = ngtcp2_cpymem(p, fr->reason, fr->reasonlen);
  }

  assert((size_t)(p - out) == len);

  return (ssize_t)len;
}

ssize_t
ngtcp2_pkt_encode_application_close_frame(uint8_t *out, size_t outlen,
                                          const ngtcp2_application_close *fr) {
  size_t len = 1 + 2 + ngtcp2_put_varint_len(fr->reasonlen) + fr->reasonlen;
  uint8_t *p;

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = NGTCP2_FRAME_APPLICATION_CLOSE;
  p = ngtcp2_put_uint16be(p, fr->app_error_code);
  p = ngtcp2_put_varint(p, fr->reasonlen);
  if (fr->reasonlen) {
    p = ngtcp2_cpymem(p, fr->reason, fr->reasonlen);
  }

  assert((size_t)(p - out) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_encode_max_data_frame(uint8_t *out, size_t outlen,
                                         const ngtcp2_max_data *fr) {
  size_t len = 1 + ngtcp2_put_varint_len(fr->max_data);
  uint8_t *p;

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = NGTCP2_FRAME_MAX_DATA;
  p = ngtcp2_put_varint(p, fr->max_data);

  assert((size_t)(p - out) == len);

  return (ssize_t)len;
}

ssize_t
ngtcp2_pkt_encode_max_stream_data_frame(uint8_t *out, size_t outlen,
                                        const ngtcp2_max_stream_data *fr) {
  size_t len = 1 + ngtcp2_put_varint_len(fr->stream_id) +
               ngtcp2_put_varint_len(fr->max_stream_data);
  uint8_t *p;

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = NGTCP2_FRAME_MAX_STREAM_DATA;
  p = ngtcp2_put_varint(p, fr->stream_id);
  p = ngtcp2_put_varint(p, fr->max_stream_data);

  assert((size_t)(p - out) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_encode_max_stream_id_frame(uint8_t *out, size_t outlen,
                                              const ngtcp2_max_stream_id *fr) {
  size_t len = 1 + ngtcp2_put_varint_len(fr->max_stream_id);
  uint8_t *p;

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = NGTCP2_FRAME_MAX_STREAM_ID;
  p = ngtcp2_put_varint(p, fr->max_stream_id);

  assert((size_t)(p - out) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_encode_ping_frame(uint8_t *out, size_t outlen,
                                     const ngtcp2_ping *fr) {
  size_t len = 1 + 1 + fr->datalen;
  uint8_t *p;

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = NGTCP2_FRAME_PING;
  *p++ = (uint8_t)fr->datalen;
  if (fr->datalen) {
    p = ngtcp2_cpymem(p, fr->data, fr->datalen);
  }

  assert((size_t)(p - out) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_encode_blocked_frame(uint8_t *out, size_t outlen,
                                        const ngtcp2_blocked *fr) {
  (void)fr;

  if (outlen < 1) {
    return NGTCP2_ERR_NOBUF;
  }

  *out = NGTCP2_FRAME_BLOCKED;

  return 1;
}

ssize_t
ngtcp2_pkt_encode_stream_blocked_frame(uint8_t *out, size_t outlen,
                                       const ngtcp2_stream_blocked *fr) {
  size_t len = 1 + ngtcp2_put_varint_len(fr->stream_id);
  uint8_t *p;

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = NGTCP2_FRAME_STREAM_BLOCKED;
  p = ngtcp2_put_varint(p, fr->stream_id);

  assert((size_t)(p - out) == len);

  return (ssize_t)len;
}

ssize_t
ngtcp2_pkt_encode_stream_id_blocked_frame(uint8_t *out, size_t outlen,
                                          const ngtcp2_stream_id_blocked *fr) {
  (void)fr;

  if (outlen < 1) {
    return NGTCP2_ERR_NOBUF;
  }

  *out = NGTCP2_FRAME_STREAM_ID_BLOCKED;

  return 1;
}

ssize_t
ngtcp2_pkt_encode_new_connection_id_frame(uint8_t *out, size_t outlen,
                                          const ngtcp2_new_connection_id *fr) {
  size_t len =
      1 + ngtcp2_put_varint_len(fr->seq) + 8 + NGTCP2_STATELESS_RESET_TOKENLEN;
  uint8_t *p;

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = NGTCP2_FRAME_NEW_CONNECTION_ID;
  p = ngtcp2_put_varint(p, fr->seq);
  p = ngtcp2_put_uint64be(p, fr->conn_id);
  p = ngtcp2_cpymem(p, fr->stateless_reset_token,
                    NGTCP2_STATELESS_RESET_TOKENLEN);

  assert((size_t)(p - out) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_encode_stop_sending_frame(uint8_t *out, size_t outlen,
                                             const ngtcp2_stop_sending *fr) {
  size_t len = 1 + ngtcp2_put_varint_len(fr->stream_id) + 2;
  uint8_t *p;

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = NGTCP2_FRAME_STOP_SENDING;
  p = ngtcp2_put_varint(p, fr->stream_id);
  p = ngtcp2_put_uint16be(p, fr->app_error_code);

  assert((size_t)(p - out) == len);

  return (ssize_t)len;
}

size_t ngtcp2_pkt_decode_version_negotiation(uint32_t *dest,
                                             const uint8_t *payload,
                                             size_t payloadlen) {
  const uint8_t *end = payload + payloadlen;

  assert((payloadlen % sizeof(uint32_t)) == 0);

  for (; payload != end; payload += sizeof(uint32_t)) {
    *dest++ = ngtcp2_get_uint32(payload);
  }

  return payloadlen / sizeof(uint32_t);
}

int ngtcp2_pkt_decode_stateless_reset(ngtcp2_pkt_stateless_reset *sr,
                                      const uint8_t *payload,
                                      size_t payloadlen) {
  const uint8_t *p = payload;

  if (payloadlen < NGTCP2_STATELESS_RESET_TOKENLEN) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  sr->rand = p;
  sr->randlen = payloadlen - NGTCP2_STATELESS_RESET_TOKENLEN;
  p += sr->randlen;
  sr->stateless_reset_token = p;

  return 0;
}

uint64_t ngtcp2_pkt_adjust_pkt_num(uint64_t max_pkt_num, uint64_t pkt_num,
                                   size_t n) {
  uint64_t k = max_pkt_num == UINT64_MAX ? max_pkt_num : max_pkt_num + 1;
  uint64_t u = k & ~((1llu << n) - 1);
  uint64_t a = u | pkt_num;
  uint64_t b = (u + (1llu << n)) | pkt_num;
  uint64_t a1 = k < a ? a - k : k - a;
  uint64_t b1 = k < b ? b - k : k - b;

  if (a1 < b1) {
    return a;
  }
  return b;
}

int ngtcp2_pkt_validate_ack(ngtcp2_ack *fr) {
  uint64_t largest_ack = fr->largest_ack;
  size_t i;

  if (largest_ack < fr->first_ack_blklen) {
    return NGTCP2_ERR_ACK_FRAME;
  }

  largest_ack -= fr->first_ack_blklen;

  for (i = 0; i < fr->num_blks; ++i) {
    if (largest_ack < fr->blks[i].gap + 2) {
      return NGTCP2_ERR_ACK_FRAME;
    }

    largest_ack -= fr->blks[i].gap + 2;

    if (largest_ack < fr->blks[i].blklen) {
      return NGTCP2_ERR_ACK_FRAME;
    }

    largest_ack -= fr->blks[i].blklen;
  }

  return 0;
}

ssize_t ngtcp2_pkt_write_stateless_reset(uint8_t *dest, size_t destlen,
                                         const ngtcp2_pkt_hd *hd,
                                         uint8_t *stateless_reset_token,
                                         uint8_t *rand, size_t randlen) {
  uint8_t *p;
  ssize_t nwrite;
  size_t left;

  p = dest;

  nwrite = ngtcp2_pkt_encode_hd_short(p, destlen, hd);
  if (nwrite < 0) {
    return nwrite;
  }

  p += nwrite;

  left = destlen - (size_t)(p - dest);
  if (left < NGTCP2_STATELESS_RESET_TOKENLEN) {
    return NGTCP2_ERR_NOBUF;
  }

  randlen = ngtcp2_min(left - NGTCP2_STATELESS_RESET_TOKENLEN, randlen);

  p = ngtcp2_cpymem(p, rand, randlen);
  p = ngtcp2_cpymem(p, stateless_reset_token, NGTCP2_STATELESS_RESET_TOKENLEN);

  return p - dest;
}
