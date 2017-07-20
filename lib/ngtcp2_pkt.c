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
                                size_t payloadlen, uint64_t max_rx_pkt_num) {
  uint8_t type;

  if (payloadlen == 0) {
    return 0;
  }

  type = payload[0];

  if (has_mask(type, NGTCP2_FRAME_STREAM)) {
    return ngtcp2_pkt_decode_stream_frame(&dest->stream, payload, payloadlen);
  }

  if (has_mask(type, NGTCP2_FRAME_ACK)) {
    return ngtcp2_pkt_decode_ack_frame(&dest->ack, payload, payloadlen,
                                       max_rx_pkt_num);
  }

  switch (type) {
  case NGTCP2_FRAME_PADDING:
    return ngtcp2_pkt_decode_padding_frame(&dest->padding, payload, payloadlen);
  case NGTCP2_FRAME_RST_STREAM:
    return ngtcp2_pkt_decode_rst_stream_frame(&dest->rst_stream, payload,
                                              payloadlen);
  case NGTCP2_FRAME_CONNECTION_CLOSE:
    return ngtcp2_pkt_decode_connection_close_frame(&dest->connection_close,
                                                    payload, payloadlen);
  case NGTCP2_FRAME_GOAWAY:
    return ngtcp2_pkt_decode_goaway_frame(&dest->goaway, payload, payloadlen);
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
    return ngtcp2_pkt_decode_blocked_frame(&dest->blocked, payload, payloadlen);
  case NGTCP2_FRAME_STREAM_BLOCKED:
    return ngtcp2_pkt_decode_stream_blocked_frame(&dest->stream_blocked,
                                                  payload, payloadlen);
  case NGTCP2_FRAME_STREAM_ID_NEEDED:
    return ngtcp2_pkt_decode_stream_id_needed_frame(&dest->stream_id_needed,
                                                    payload, payloadlen);
  case NGTCP2_FRAME_NEW_CONNECTION_ID:
    return ngtcp2_pkt_decode_new_connection_id_frame(&dest->new_connection_id,
                                                     payload, payloadlen);
  default:
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }
}

ssize_t ngtcp2_pkt_decode_stream_frame(ngtcp2_stream *dest,
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

  idlen = (size_t)(((type & NGTCP2_STREAM_SS_MASK) >> 3) + 1);

  b = (uint8_t)((type & NGTCP2_STREAM_OO_MASK) >> 1);
  if (b) {
    offsetlen = (size_t)(1 << b);
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
  dest->flags = (uint8_t)(type & ~NGTCP2_FRAME_STREAM);
  dest->fin = fin;

  p = &payload[1];

  switch (idlen) {
  case 1:
    dest->stream_id = *p++;
    break;
  case 2:
    dest->stream_id = ngtcp2_get_uint16(p);
    p += 2;
    break;
  case 3:
    dest->stream_id = ngtcp2_get_uint24(p);
    p += 3;
    break;
  case 4:
    dest->stream_id = ngtcp2_get_uint32(p);
    p += 4;
    break;
  }

  switch (offsetlen) {
  case 0:
    dest->offset = 0;
    break;
  case 2:
    dest->offset = ngtcp2_get_uint16(p);
    break;
  case 4:
    dest->offset = ngtcp2_get_uint32(p);
    break;
  case 8:
    dest->offset = ngtcp2_get_uint64(p);
    break;
  }

  p += offsetlen;

  if (type & NGTCP2_STREAM_D_BIT) {
    dest->datalen = datalen;
    p += 2;
    dest->data = p;
    p += datalen;
    assert((size_t)(p - payload) == len);
    return p - payload;
  } else {
    dest->datalen = payloadlen - (size_t)(p - payload);
    dest->data = p;
    return (ssize_t)payloadlen;
  }
}

ssize_t ngtcp2_pkt_decode_ack_frame(ngtcp2_ack *dest, const uint8_t *payload,
                                    size_t payloadlen,
                                    uint64_t max_rx_pkt_num) {
  static const size_t len_def[] = {1, 2, 4, 8};
  uint8_t type;
  size_t num_blks = 0;
  size_t num_ts;
  size_t lalen;
  size_t abllen;
  size_t len = 4; /* type + NumTS + ACK Delay(2) */
  const uint8_t *p;
  size_t i;
  ngtcp2_ack_blk *blk;

  /* We can expect at least 4 bytes (type, NumTS, and ACK Delay(2)) */
  if (payloadlen < len || !has_mask(payload[0], NGTCP2_FRAME_ACK)) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  p = &payload[0];

  type = *p++;

  if (type & NGTCP2_ACK_N_BIT) {
    num_blks = *p++;
    ++len;
  }

  num_ts = *p++;

  lalen = len_def[(type & NGTCP2_ACK_LL_MASK) >> 2];

  len += lalen;

  abllen = len_def[type & NGTCP2_ACK_MM_MASK];

  /* Length of ACK Block Section */
  /* First ACK Block Length */
  len += abllen;
  len += num_blks * (1 + abllen);

  /* Length of Timestamp Section */
  if (num_ts > 0) {
    len += num_ts * 3 + 2;
  }

  if (payloadlen < len) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  dest->type = NGTCP2_FRAME_ACK;
  dest->flags = (uint8_t)(type & ~NGTCP2_FRAME_ACK);
  dest->num_blks = num_blks;
  dest->num_ts = num_ts;

  switch (lalen) {
  case 1:
    dest->largest_ack = ngtcp2_pkt_adjust_pkt_num(max_rx_pkt_num, *p, 8);
    break;
  case 2:
    dest->largest_ack =
        ngtcp2_pkt_adjust_pkt_num(max_rx_pkt_num, ngtcp2_get_uint16(p), 16);
    break;
  case 4:
    dest->largest_ack =
        ngtcp2_pkt_adjust_pkt_num(max_rx_pkt_num, ngtcp2_get_uint32(p), 32);
    break;
  case 8:
    dest->largest_ack = ngtcp2_get_uint64(p);
    break;
  }

  p += lalen;

  dest->ack_delay = ngtcp2_get_uint16(p);
  p += 2;

  switch (abllen) {
  case 1:
    dest->first_ack_blklen = *p++;
    for (i = 0; i < num_blks; ++i) {
      blk = &dest->blks[i];
      blk->gap = *p++;
      blk->blklen = *p++;
    }
    break;
  case 2:
    dest->first_ack_blklen = ngtcp2_get_uint16(p);
    p += abllen;
    for (i = 0; i < num_blks; ++i) {
      blk = &dest->blks[i];
      blk->gap = *p++;
      blk->blklen = ngtcp2_get_uint16(p);
      p += abllen;
    }
    break;
  case 4:
    dest->first_ack_blklen = ngtcp2_get_uint32(p);
    p += abllen;
    for (i = 0; i < num_blks; ++i) {
      blk = &dest->blks[i];
      blk->gap = *p++;
      blk->blklen = ngtcp2_get_uint32(p);
      p += abllen;
    }
    break;
  case 8:
    dest->first_ack_blklen = ngtcp2_get_uint64(p);
    p += abllen;
    for (i = 0; i < num_blks; ++i) {
      blk = &dest->blks[i];
      blk->gap = *p++;
      blk->blklen = ngtcp2_get_uint64(p);
      p += abllen;
    }
    break;
  }

  /* TODO Parse Timestamp section */

  if (num_ts) {
    p += num_ts * 3 + 2;
  }

  assert((size_t)(p - payload) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_decode_padding_frame(ngtcp2_padding *dest,
                                        const uint8_t *payload,
                                        size_t payloadlen) {
  const uint8_t *p, *ep;

  if (payloadlen == 0 || payload[0] != NGTCP2_FRAME_PADDING) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  p = payload + 1;
  ep = payload + payloadlen;

  for (; p != ep && *p == NGTCP2_FRAME_PADDING; ++p)
    ;

  dest->type = NGTCP2_FRAME_PADDING;
  dest->len = (size_t)(p - payload);

  return p - payload;
}

ssize_t ngtcp2_pkt_decode_rst_stream_frame(ngtcp2_rst_stream *dest,
                                           const uint8_t *payload,
                                           size_t payloadlen) {
  size_t len = 1 + 4 + 4 + 8;
  const uint8_t *p;

  if (payloadlen < len || payload[0] != NGTCP2_FRAME_RST_STREAM) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  p = payload + 1;

  dest->type = NGTCP2_FRAME_RST_STREAM;
  dest->stream_id = ngtcp2_get_uint32(p);
  p += 4;
  dest->error_code = ngtcp2_get_uint32(p);
  p += 4;
  dest->final_offset = ngtcp2_get_uint64(p);
  p += 8;

  assert((size_t)(p - payload) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_decode_connection_close_frame(ngtcp2_connection_close *dest,
                                                 const uint8_t *payload,
                                                 size_t payloadlen) {
  size_t len = 1 + 4 + 2;
  const uint8_t *p;
  size_t reasonlen;

  if (payloadlen < len || payload[0] != NGTCP2_FRAME_CONNECTION_CLOSE) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  reasonlen = ngtcp2_get_uint16(payload + 1 + 4);
  len += reasonlen;

  if (payloadlen < len) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  p = payload + 1;

  dest->type = NGTCP2_FRAME_CONNECTION_CLOSE;
  dest->error_code = ngtcp2_get_uint32(p);
  p += 4;
  dest->reasonlen = reasonlen;
  p += 2;
  if (reasonlen == 0) {
    dest->reason = NULL;
  } else {
    dest->reason = (uint8_t *)p;
    p += reasonlen;
  }

  assert((size_t)(p - payload) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_decode_goaway_frame(ngtcp2_goaway *dest,
                                       const uint8_t *payload,
                                       size_t payloadlen) {
  size_t len = 1 + 4 + 4;
  const uint8_t *p;

  if (payloadlen < len || payload[0] != NGTCP2_FRAME_GOAWAY) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  p = payload + 1;

  dest->type = NGTCP2_FRAME_GOAWAY;
  dest->largest_client_stream_id = ngtcp2_get_uint32(p);
  p += 4;
  dest->largest_server_stream_id = ngtcp2_get_uint32(p);
  p += 4;

  assert((size_t)(p - payload) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_decode_max_data_frame(ngtcp2_max_data *dest,
                                         const uint8_t *payload,
                                         size_t payloadlen) {
  size_t len = 1 + 8;
  const uint8_t *p;

  if (payloadlen < len || payload[0] != NGTCP2_FRAME_MAX_DATA) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  p = payload + 1;

  dest->type = NGTCP2_FRAME_MAX_DATA;
  dest->max_data = ngtcp2_get_uint64(p);
  p += 8;

  assert((size_t)(p - payload) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_decode_max_stream_data_frame(ngtcp2_max_stream_data *dest,
                                                const uint8_t *payload,
                                                size_t payloadlen) {
  size_t len = 1 + 4 + 8;
  const uint8_t *p;

  if (payloadlen < len || payload[0] != NGTCP2_FRAME_MAX_STREAM_DATA) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  p = payload + 1;

  dest->type = NGTCP2_FRAME_MAX_STREAM_DATA;
  dest->stream_id = ngtcp2_get_uint32(p);
  p += 4;
  dest->max_stream_data = ngtcp2_get_uint64(p);
  p += 8;

  assert((size_t)(p - payload) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_decode_max_stream_id_frame(ngtcp2_max_stream_id *dest,
                                              const uint8_t *payload,
                                              size_t payloadlen) {
  size_t len = 1 + 4;
  const uint8_t *p;

  if (payloadlen < len || payload[0] != NGTCP2_FRAME_MAX_STREAM_ID) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  p = payload + 1;

  dest->type = NGTCP2_FRAME_MAX_STREAM_ID;
  dest->max_stream_id = ngtcp2_get_uint32(p);
  p += 4;

  assert((size_t)(p - payload) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_decode_ping_frame(ngtcp2_ping *dest, const uint8_t *payload,
                                     size_t payloadlen) {
  if (payloadlen < 1 || payload[0] != NGTCP2_FRAME_PING) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  dest->type = NGTCP2_FRAME_PING;

  return 1;
}

ssize_t ngtcp2_pkt_decode_blocked_frame(ngtcp2_blocked *dest,
                                        const uint8_t *payload,
                                        size_t payloadlen) {
  if (payloadlen < 1 || payload[0] != NGTCP2_FRAME_BLOCKED) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  dest->type = NGTCP2_FRAME_BLOCKED;

  return 1;
}

ssize_t ngtcp2_pkt_decode_stream_blocked_frame(ngtcp2_stream_blocked *dest,
                                               const uint8_t *payload,
                                               size_t payloadlen) {
  size_t len = 1 + 4;
  const uint8_t *p;

  if (payloadlen < len || payload[0] != NGTCP2_FRAME_STREAM_BLOCKED) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  p = payload + 1;

  dest->type = NGTCP2_FRAME_STREAM_BLOCKED;
  dest->stream_id = ngtcp2_get_uint32(p);
  p += 4;

  assert((size_t)(p - payload) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_decode_stream_id_needed_frame(ngtcp2_stream_id_needed *dest,
                                                 const uint8_t *payload,
                                                 size_t payloadlen) {
  if (payloadlen < 1 || payload[0] != NGTCP2_FRAME_STREAM_ID_NEEDED) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  dest->type = NGTCP2_FRAME_STREAM_ID_NEEDED;

  return 1;
}

ssize_t ngtcp2_pkt_decode_new_connection_id_frame(
    ngtcp2_new_connection_id *dest, const uint8_t *payload, size_t payloadlen) {
  size_t len = 1 + 2 + 8;
  const uint8_t *p;

  if (payloadlen < len || payload[0] != NGTCP2_FRAME_NEW_CONNECTION_ID) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  p = payload + 1;

  dest->type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  dest->seq = ngtcp2_get_uint16(p);
  p += 2;
  dest->conn_id = ngtcp2_get_uint64(p);
  p += 8;

  assert((size_t)(p - payload) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_encode_frame(uint8_t *out, size_t outlen,
                                const ngtcp2_frame *fr) {
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
  case NGTCP2_FRAME_GOAWAY:
    return ngtcp2_pkt_encode_goaway_frame(out, outlen, &fr->goaway);
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
  case NGTCP2_FRAME_STREAM_ID_NEEDED:
    return ngtcp2_pkt_encode_stream_id_needed_frame(out, outlen,
                                                    &fr->stream_id_needed);
  case NGTCP2_FRAME_NEW_CONNECTION_ID:
    return ngtcp2_pkt_encode_new_connection_id_frame(out, outlen,
                                                     &fr->new_connection_id);
  default:
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }
}

ssize_t ngtcp2_pkt_encode_stream_frame(uint8_t *out, size_t outlen,
                                       const ngtcp2_stream *fr) {
  size_t len = 1;
  uint8_t flags = NGTCP2_STREAM_D_BIT;
  size_t idlen;
  size_t offsetlen;
  uint8_t *p;

  if (fr->fin) {
    flags |= NGTCP2_STREAM_FIN_BIT;
  }

  if (fr->stream_id > 0xffffff) {
    idlen = 4;
    flags |= 0x18;
  } else if (fr->stream_id > 0xffff) {
    idlen = 3;
    flags |= 0x10;
  } else if (fr->stream_id > 0xff) {
    idlen = 2;
    flags |= 0x08;
  } else {
    idlen = 1;
  }

  len += idlen;

  if (fr->offset > 0xffffffffu) {
    offsetlen = 8;
    flags |= 0x06;
  } else if (fr->offset > 0xffff) {
    offsetlen = 4;
    flags |= 0x04;
  } else if (fr->offset) {
    offsetlen = 2;
    flags |= 0x02;
  } else {
    offsetlen = 0;
  }

  len += offsetlen;

  /* Always write Data Length */
  len += 2;
  len += fr->datalen;

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = flags | NGTCP2_FRAME_STREAM;

  switch (idlen) {
  case 4:
    p = ngtcp2_put_uint32be(p, fr->stream_id);
    break;
  case 3:
    p = ngtcp2_put_uint24be(p, fr->stream_id);
    break;
  case 2:
    p = ngtcp2_put_uint16be(p, (uint16_t)fr->stream_id);
    break;
  case 1:
    *p++ = (uint8_t)fr->stream_id;
    break;
  }

  switch (offsetlen) {
  case 8:
    p = ngtcp2_put_uint64be(p, fr->offset);
    break;
  case 4:
    p = ngtcp2_put_uint32be(p, (uint32_t)fr->offset);
    break;
  case 2:
    p = ngtcp2_put_uint16be(p, (uint16_t)fr->offset);
    break;
  }

  p = ngtcp2_put_uint16be(p, (uint16_t)fr->datalen);
  if (fr->datalen) {
    p = ngtcp2_cpymem(p, fr->data, fr->datalen);
  }

  assert((size_t)(p - out) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_encode_ack_frame(uint8_t *out, size_t outlen,
                                    const ngtcp2_ack *fr) {
  size_t len = 1 + 1 + 4 /* LL = 02 */ + 2 + 4 /* MM = 02 */;
  uint8_t *p;
  size_t i;
  const ngtcp2_ack_blk *blk;

  if (fr->num_blks) {
    ++len;
  }

  /* Encode ACK Block N Length in 32 bits for now */
  len += fr->num_blks * 5;

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = NGTCP2_FRAME_ACK | NGTCP2_ACK_LL_02_MASK | NGTCP2_ACK_MM_02_MASK |
         (fr->num_blks ? NGTCP2_ACK_N_BIT : 0);
  /* Num Blocks */
  if (fr->num_blks) {
    *p++ = (uint8_t)fr->num_blks;
  }
  /* NumTS */
  *p++ = 0;
  p = ngtcp2_put_uint32be(p, (uint32_t)fr->largest_ack);
  p = ngtcp2_put_uint16be(p, fr->ack_delay);
  p = ngtcp2_put_uint32be(p, (uint32_t)fr->first_ack_blklen);
  for (i = 0; i < fr->num_blks; ++i) {
    blk = &fr->blks[i];
    *p++ = blk->gap;
    p = ngtcp2_put_uint32be(p, (uint32_t)blk->blklen);
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
  size_t len = 1 + 4 + 4 + 8;
  uint8_t *p;

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = NGTCP2_FRAME_RST_STREAM;
  p = ngtcp2_put_uint32be(p, fr->stream_id);
  p = ngtcp2_put_uint32be(p, fr->error_code);
  p = ngtcp2_put_uint64be(p, fr->final_offset);

  assert((size_t)(p - out) == len);

  return (ssize_t)len;
}

ssize_t
ngtcp2_pkt_encode_connection_close_frame(uint8_t *out, size_t outlen,
                                         const ngtcp2_connection_close *fr) {
  size_t len = 1 + 4 + 2 + fr->reasonlen;
  uint8_t *p;

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = NGTCP2_FRAME_CONNECTION_CLOSE;
  p = ngtcp2_put_uint32be(p, fr->error_code);
  p = ngtcp2_put_uint16be(p, (uint16_t)fr->reasonlen);
  if (fr->reasonlen) {
    p = ngtcp2_cpymem(p, fr->reason, fr->reasonlen);
  }

  assert((size_t)(p - out) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_encode_goaway_frame(uint8_t *out, size_t outlen,
                                       const ngtcp2_goaway *fr) {
  size_t len = 1 + 4 + 4;
  uint8_t *p;

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = NGTCP2_FRAME_GOAWAY;
  p = ngtcp2_put_uint32be(p, fr->largest_client_stream_id);
  p = ngtcp2_put_uint32be(p, fr->largest_server_stream_id);

  assert((size_t)(p - out) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_encode_max_data_frame(uint8_t *out, size_t outlen,
                                         const ngtcp2_max_data *fr) {
  size_t len = 1 + 8;
  uint8_t *p;

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = NGTCP2_FRAME_MAX_DATA;
  p = ngtcp2_put_uint64be(p, fr->max_data);

  assert((size_t)(p - out) == len);

  return (ssize_t)len;
}

ssize_t
ngtcp2_pkt_encode_max_stream_data_frame(uint8_t *out, size_t outlen,
                                        const ngtcp2_max_stream_data *fr) {
  size_t len = 1 + 4 + 8;
  uint8_t *p;

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = NGTCP2_FRAME_MAX_STREAM_DATA;
  p = ngtcp2_put_uint32be(p, fr->stream_id);
  p = ngtcp2_put_uint64be(p, fr->max_stream_data);

  assert((size_t)(p - out) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_encode_max_stream_id_frame(uint8_t *out, size_t outlen,
                                              const ngtcp2_max_stream_id *fr) {
  size_t len = 1 + 4;
  uint8_t *p;

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = NGTCP2_FRAME_MAX_STREAM_ID;
  p = ngtcp2_put_uint32be(p, fr->max_stream_id);

  assert((size_t)(p - out) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_encode_ping_frame(uint8_t *out, size_t outlen,
                                     const ngtcp2_ping *fr) {
  (void)fr;

  if (outlen < 1) {
    return NGTCP2_ERR_NOBUF;
  }

  *out = NGTCP2_FRAME_PING;

  return 1;
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
  size_t len = 1 + 4;
  uint8_t *p;

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = NGTCP2_FRAME_STREAM_BLOCKED;
  p = ngtcp2_put_uint32be(p, fr->stream_id);

  assert((size_t)(p - out) == len);

  return (ssize_t)len;
}

ssize_t
ngtcp2_pkt_encode_stream_id_needed_frame(uint8_t *out, size_t outlen,
                                         const ngtcp2_stream_id_needed *fr) {
  (void)fr;

  if (outlen < 1) {
    return NGTCP2_ERR_NOBUF;
  }

  *out = NGTCP2_FRAME_STREAM_ID_NEEDED;

  return 1;
}

ssize_t
ngtcp2_pkt_encode_new_connection_id_frame(uint8_t *out, size_t outlen,
                                          const ngtcp2_new_connection_id *fr) {
  size_t len = 1 + 2 + 8;
  uint8_t *p;

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = NGTCP2_FRAME_NEW_CONNECTION_ID;
  p = ngtcp2_put_uint16be(p, fr->seq);
  p = ngtcp2_put_uint64be(p, fr->conn_id);

  assert((size_t)(p - out) == len);

  return (ssize_t)len;
}

int ngtcp2_pkt_verify(const uint8_t *pkt, size_t pktlen) {
  uint64_t a, b;

  if (pktlen <= NGTCP2_PKT_MDLEN) {
    return -1;
  }

  a = ngtcp2_get_uint64(pkt + (pktlen - NGTCP2_PKT_MDLEN));
  b = ngtcp2_fnv1a(pkt, pktlen - NGTCP2_PKT_MDLEN);

  return a == b ? 0 : -1;
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

uint64_t ngtcp2_pkt_adjust_pkt_num(uint64_t max_pkt_num, uint64_t pkt_num,
                                   size_t n) {
  uint64_t k = max_pkt_num + 1;
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
