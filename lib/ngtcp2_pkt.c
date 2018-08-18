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
#include "ngtcp2_cid.h"

void ngtcp2_pkt_hd_init(ngtcp2_pkt_hd *hd, uint8_t flags, uint8_t type,
                        const ngtcp2_cid *dcid, const ngtcp2_cid *scid,
                        uint64_t pkt_num, size_t pkt_numlen, uint32_t version,
                        size_t len) {
  hd->flags = flags;
  hd->type = type;
  if (dcid) {
    hd->dcid = *dcid;
  } else {
    ngtcp2_cid_zero(&hd->dcid);
  }
  if (scid) {
    hd->scid = *scid;
  } else {
    ngtcp2_cid_zero(&hd->scid);
  }
  hd->pkt_num = pkt_num;
  hd->token = NULL;
  hd->tokenlen = 0;
  hd->pkt_numlen = pkt_numlen;
  hd->version = version;
  hd->len = len;
}

ssize_t ngtcp2_pkt_decode_hd_long(ngtcp2_pkt_hd *dest, const uint8_t *pkt,
                                  size_t pktlen) {
  uint8_t type;
  uint32_t version;
  size_t dcil, scil;
  const uint8_t *p;
  size_t len = 0;
  size_t n;
  size_t ntokenlen = 0;
  const uint8_t *token = NULL;
  size_t tokenlen = 0;

  if (pktlen < 5) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  if ((pkt[0] & NGTCP2_HEADER_FORM_BIT) == 0) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  version = ngtcp2_get_uint32(&pkt[1]);

  if (version == 0) {
    type = NGTCP2_PKT_VERSION_NEGOTIATION;
    /* This must be Version Negotiation packet which lacks packet
       number and payload length fields. */
    len = 5 + 1;
  } else {
    type = pkt[0] & NGTCP2_LONG_TYPE_MASK;
    switch (type) {
    case NGTCP2_PKT_INITIAL:
      len = 1 + NGTCP2_MIN_LONG_HEADERLEN - 1; /* Cut packet number field */
      break;
    case NGTCP2_PKT_RETRY:
      /* Retry packet does not have packet number and length fields */
      len = 5 + 1;
      break;
    case NGTCP2_PKT_HANDSHAKE:
    case NGTCP2_PKT_0RTT_PROTECTED:
      len = NGTCP2_MIN_LONG_HEADERLEN - 1; /* Cut packet number field */
      break;
    default:
      return NGTCP2_ERR_UNKNOWN_PKT_TYPE;
    }
  }

  if (pktlen < len) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  dcil = pkt[5] >> 4;
  scil = pkt[5] & 0xf;

  if (dcil) {
    dcil += 3;
  }
  if (scil) {
    scil += 3;
  }

  len += dcil + scil;

  if (pktlen < len) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  p = &pkt[6 + dcil + scil];

  if (type == NGTCP2_PKT_INITIAL) {
    /* Token Length */
    ntokenlen = ngtcp2_get_varint_len(p);
    len += ntokenlen - 1;

    if (pktlen < len) {
      return NGTCP2_ERR_INVALID_ARGUMENT;
    }

    tokenlen = ngtcp2_get_varint(&ntokenlen, p);
    len += tokenlen;

    if (pktlen < len) {
      return NGTCP2_ERR_INVALID_ARGUMENT;
    }

    p += ntokenlen;

    if (tokenlen) {
      token = p;
    }

    p += tokenlen;
  }

  switch (type) {
  case NGTCP2_PKT_VERSION_NEGOTIATION:
  case NGTCP2_PKT_RETRY:
    break;
  default:
    /* Length */
    n = ngtcp2_get_varint_len(p);
    len += n - 1;

    if (pktlen < len) {
      return NGTCP2_ERR_INVALID_ARGUMENT;
    }
  }

  dest->flags = NGTCP2_PKT_FLAG_LONG_FORM;
  dest->type = type;
  dest->version = version;
  dest->pkt_num = 0;
  dest->pkt_numlen = 0;

  p = &pkt[6];

  ngtcp2_cid_init(&dest->dcid, p, dcil);
  p += dcil;
  ngtcp2_cid_init(&dest->scid, p, scil);
  p += scil;

  dest->token = (uint8_t *)token;
  dest->tokenlen = tokenlen;
  p += ntokenlen + tokenlen;

  switch (type) {
  case NGTCP2_PKT_VERSION_NEGOTIATION:
  case NGTCP2_PKT_RETRY:
    dest->len = 0;
    break;
  default:
    dest->len = ngtcp2_get_varint(&n, p);
    p += n;
  }

  assert((size_t)(p - pkt) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_decode_hd_short(ngtcp2_pkt_hd *dest, const uint8_t *pkt,
                                   size_t pktlen, size_t dcidlen) {
  uint8_t flags = 0;
  size_t len = 1 + dcidlen;
  const uint8_t *p = pkt;

  if (pktlen < len) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  if (pkt[0] & NGTCP2_HEADER_FORM_BIT) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  if (pkt[0] & NGTCP2_KEY_PHASE_BIT) {
    flags |= NGTCP2_PKT_FLAG_KEY_PHASE;
  }

  if ((pkt[0] & (NGTCP2_THIRD_BIT | NGTCP2_FOURTH_BIT | NGTCP2_GQUIC_BIT)) !=
      0x30) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  p = &pkt[1];

  dest->type = NGTCP2_PKT_SHORT;

  ngtcp2_cid_init(&dest->dcid, p, dcidlen);
  p += dcidlen;

  /* Set 0 to SCID so that we don't accidentally reference it and gets
     garbage. */
  ngtcp2_cid_zero(&dest->scid);

  dest->flags = flags;
  dest->version = 0;
  dest->len = 0;
  dest->pkt_num = 0;
  dest->pkt_numlen = 0;

  assert((size_t)(p - pkt) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_encode_hd_long(uint8_t *out, size_t outlen,
                                  const ngtcp2_pkt_hd *hd) {
  uint8_t *p;
  size_t len = NGTCP2_MIN_LONG_HEADERLEN + hd->dcid.datalen + hd->scid.datalen -
               2; /* NGTCP2_MIN_LONG_HEADERLEN includes 1 byte for
                     len and 1 byte for packet number. */

  if (hd->type != NGTCP2_PKT_RETRY) {
    len += 2 /* Length */ + hd->pkt_numlen;
  }

  if (hd->type == NGTCP2_PKT_INITIAL) {
    len += ngtcp2_put_varint_len(hd->tokenlen) + hd->tokenlen;
  }

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = NGTCP2_HEADER_FORM_BIT | hd->type;
  p = ngtcp2_put_uint32be(p, hd->version);
  *p = 0;
  if (hd->dcid.datalen) {
    assert(hd->dcid.datalen > 3);
    *p |= (uint8_t)((hd->dcid.datalen - 3) << 4);
  }
  if (hd->scid.datalen) {
    assert(hd->scid.datalen > 3);
    *p = (uint8_t)(*p | ((hd->scid.datalen - 3) & 0xf));
  }
  ++p;
  if (hd->dcid.datalen) {
    p = ngtcp2_cpymem(p, hd->dcid.data, hd->dcid.datalen);
  }
  if (hd->scid.datalen) {
    p = ngtcp2_cpymem(p, hd->scid.data, hd->scid.datalen);
  }

  if (hd->type == NGTCP2_PKT_INITIAL) {
    p = ngtcp2_put_varint(p, hd->tokenlen);
    if (hd->tokenlen) {
      p = ngtcp2_cpymem(p, hd->token, hd->tokenlen);
    }
  }

  if (hd->type != NGTCP2_PKT_RETRY) {
    p = ngtcp2_put_varint14(p, (uint16_t)hd->len);
    p = ngtcp2_put_pkt_num(p, hd->pkt_num, hd->pkt_numlen);
  }

  assert((size_t)(p - out) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_encode_hd_short(uint8_t *out, size_t outlen,
                                   const ngtcp2_pkt_hd *hd) {
  uint8_t *p;
  size_t len = 1 + hd->dcid.datalen + hd->pkt_numlen;

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p = NGTCP2_THIRD_BIT | NGTCP2_FOURTH_BIT;
  if (hd->flags & NGTCP2_PKT_FLAG_KEY_PHASE) {
    *p |= NGTCP2_KEY_PHASE_BIT;
  }

  ++p;

  if (hd->dcid.datalen) {
    p = ngtcp2_cpymem(p, hd->dcid.data, hd->dcid.datalen);
  }

  p = ngtcp2_put_pkt_num(p, hd->pkt_num, hd->pkt_numlen);

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
    return ngtcp2_pkt_decode_blocked_frame(&dest->blocked, payload, payloadlen);
  case NGTCP2_FRAME_STREAM_BLOCKED:
    return ngtcp2_pkt_decode_stream_blocked_frame(&dest->stream_blocked,
                                                  payload, payloadlen);
  case NGTCP2_FRAME_STREAM_ID_BLOCKED:
    return ngtcp2_pkt_decode_stream_id_blocked_frame(&dest->stream_id_blocked,
                                                     payload, payloadlen);
  case NGTCP2_FRAME_NEW_CONNECTION_ID:
    return ngtcp2_pkt_decode_new_connection_id_frame(&dest->new_connection_id,
                                                     payload, payloadlen);
  case NGTCP2_FRAME_STOP_SENDING:
    return ngtcp2_pkt_decode_stop_sending_frame(&dest->stop_sending, payload,
                                                payloadlen);
  case NGTCP2_FRAME_ACK:
    return ngtcp2_pkt_decode_ack_frame(&dest->ack, payload, payloadlen);
  case NGTCP2_FRAME_PATH_CHALLENGE:
    return ngtcp2_pkt_decode_path_challenge_frame(&dest->path_challenge,
                                                  payload, payloadlen);
  case NGTCP2_FRAME_PATH_RESPONSE:
    return ngtcp2_pkt_decode_path_response_frame(&dest->path_response, payload,
                                                 payloadlen);
  case NGTCP2_FRAME_CRYPTO:
    return ngtcp2_pkt_decode_crypto_frame(&dest->crypto, payload, payloadlen);
  case NGTCP2_FRAME_NEW_TOKEN:
    return ngtcp2_pkt_decode_new_token_frame(&dest->new_token, payload,
                                             payloadlen);
  default:
    if (has_mask(type, NGTCP2_FRAME_STREAM)) {
      return ngtcp2_pkt_decode_stream_frame(&dest->stream, payload, payloadlen);
    }
    return NGTCP2_ERR_FRAME_ENCODING;
  }
}

ssize_t ngtcp2_pkt_decode_stream_frame(ngtcp2_stream *dest,
                                       const uint8_t *payload,
                                       size_t payloadlen) {
  uint8_t type;
  size_t len = 1 + 1;
  const uint8_t *p;
  size_t datalen;
  size_t ndatalen = 0;
  size_t n;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  type = payload[0];

  p = payload + 1;

  n = ngtcp2_get_varint_len(p);
  len += n - 1;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  p += n;

  if (type & NGTCP2_STREAM_OFF_BIT) {
    ++len;
    if (payloadlen < len) {
      return NGTCP2_ERR_FRAME_ENCODING;
    }

    n = ngtcp2_get_varint_len(p);
    len += n - 1;

    if (payloadlen < len) {
      return NGTCP2_ERR_FRAME_ENCODING;
    }

    p += n;
  }

  if (type & NGTCP2_STREAM_LEN_BIT) {
    ++len;
    if (payloadlen < len) {
      return NGTCP2_ERR_FRAME_ENCODING;
    }

    ndatalen = ngtcp2_get_varint_len(p);
    len += ndatalen - 1;

    if (payloadlen < len) {
      return NGTCP2_ERR_FRAME_ENCODING;
    }

    datalen = ngtcp2_get_varint(&ndatalen, p);
    len += datalen;

    if (payloadlen < len) {
      return NGTCP2_ERR_FRAME_ENCODING;
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
    dest->datalen = datalen;
    p += ndatalen;
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
  size_t nnum_blks;
  size_t len = 1 + 1 + 1 + 1 + 1;
  const uint8_t *p;
  size_t i, j;
  ngtcp2_ack_blk *blk;
  size_t n;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  p = payload + 1;

  /* Largest Acknowledged */
  n = ngtcp2_get_varint_len(p);
  len += n - 1;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  p += n;

  /* ACK Delay */
  n = ngtcp2_get_varint_len(p);
  len += n - 1;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  p += n;

  /* ACK Block Count */
  nnum_blks = ngtcp2_get_varint_len(p);
  len += nnum_blks - 1;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  num_blks = ngtcp2_get_varint(&nnum_blks, p);
  len += num_blks * (1 + 1);

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  p += nnum_blks;

  /* First ACK Block */
  n = ngtcp2_get_varint_len(p);
  len += n - 1;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  p += n;

  for (i = 0; i < num_blks; ++i) {
    /* Gap, and Additional ACK Block */
    for (j = 0; j < 2; ++j) {
      n = ngtcp2_get_varint_len(p);
      len += n - 1;

      if (payloadlen < len) {
        return NGTCP2_ERR_FRAME_ENCODING;
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
  /* This value will be assigned in the upper layer. */
  dest->ack_delay_unscaled = 0;
  p += n;
  dest->num_blks = max_num_blks;
  p += nnum_blks;
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
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  p = payload + 1;

  n = ngtcp2_get_varint_len(p);
  len += n - 1;
  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }
  p += n + 2;
  n = ngtcp2_get_varint_len(p);
  len += n - 1;
  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
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
  size_t len = 1 + 2 + 1 + 1;
  const uint8_t *p;
  size_t reasonlen;
  size_t nreasonlen;
  uint64_t frame_type;
  size_t n;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  p = payload + 1 + 2;

  n = ngtcp2_get_varint_len(p);
  len += n - 1;
  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  p += n;

  nreasonlen = ngtcp2_get_varint_len(p);
  len += nreasonlen - 1;
  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  reasonlen = ngtcp2_get_varint(&nreasonlen, p);
  len += reasonlen;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  p = payload + 1;

  dest->type = NGTCP2_FRAME_CONNECTION_CLOSE;
  dest->error_code = ngtcp2_get_uint16(p);
  p += 2;
  frame_type = ngtcp2_get_varint(&n, p);
  /* TODO Ignore large frame type for now */
  if (frame_type > 255) {
    dest->frame_type = 0;
  } else {
    dest->frame_type = (uint8_t)frame_type;
  }
  p += n;
  dest->reasonlen = reasonlen;
  p += nreasonlen;
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
  size_t nreasonlen;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  p = payload + 1 + 2;

  nreasonlen = ngtcp2_get_varint_len(p);
  len += nreasonlen - 1;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  reasonlen = ngtcp2_get_varint(&nreasonlen, p);
  len += reasonlen;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  p = payload + 1;

  dest->type = NGTCP2_FRAME_APPLICATION_CLOSE;
  dest->app_error_code = ngtcp2_get_uint16(p);
  p += 2;
  dest->reasonlen = reasonlen;
  p += nreasonlen;
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
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  p = payload + 1;

  n = ngtcp2_get_varint_len(p);
  len += n - 1;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
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
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  p = payload + 1;

  n = ngtcp2_get_varint_len(p);
  len += n - 1;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  p += n;

  n = ngtcp2_get_varint_len(p);
  len += n - 1;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
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
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  p = payload + 1;

  n = ngtcp2_get_varint_len(p);
  len += n - 1;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  dest->type = NGTCP2_FRAME_MAX_STREAM_ID;
  dest->max_stream_id = ngtcp2_get_varint(&n, p);
  p += n;

  assert((size_t)(p - payload) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_decode_ping_frame(ngtcp2_ping *dest, const uint8_t *payload,
                                     size_t payloadlen) {
  (void)payload;
  (void)payloadlen;

  dest->type = NGTCP2_FRAME_PING;
  return 1;
}

ssize_t ngtcp2_pkt_decode_blocked_frame(ngtcp2_blocked *dest,
                                        const uint8_t *payload,
                                        size_t payloadlen) {
  size_t len = 1 + 1;
  const uint8_t *p;
  size_t n;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  p = payload + 1;

  n = ngtcp2_get_varint_len(p);
  len += n - 1;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  dest->type = NGTCP2_FRAME_BLOCKED;
  dest->offset = ngtcp2_get_varint(&n, p);
  p += n;

  assert((size_t)(p - payload) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_decode_stream_blocked_frame(ngtcp2_stream_blocked *dest,
                                               const uint8_t *payload,
                                               size_t payloadlen) {
  size_t len = 1 + 1 + 1;
  const uint8_t *p;
  size_t n;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  p = payload + 1;

  n = ngtcp2_get_varint_len(p);
  len += n - 1;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  p += n;

  n = ngtcp2_get_varint_len(p);
  len += n - 1;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  p = payload + 1;

  dest->type = NGTCP2_FRAME_STREAM_BLOCKED;
  dest->stream_id = ngtcp2_get_varint(&n, p);
  p += n;
  dest->offset = ngtcp2_get_varint(&n, p);
  p += n;

  assert((size_t)(p - payload) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_decode_stream_id_blocked_frame(
    ngtcp2_stream_id_blocked *dest, const uint8_t *payload, size_t payloadlen) {
  size_t len = 1 + 1;
  const uint8_t *p;
  size_t n;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  p = payload + 1;

  n = ngtcp2_get_varint_len(p);
  len += n - 1;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  dest->type = NGTCP2_FRAME_STREAM_ID_BLOCKED;
  dest->stream_id = ngtcp2_get_varint(&n, p);
  p += n;

  assert((size_t)(p - payload) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_decode_new_connection_id_frame(
    ngtcp2_new_connection_id *dest, const uint8_t *payload, size_t payloadlen) {
  size_t len = 1 + 1 + 1 + 16;
  const uint8_t *p;
  size_t n;
  size_t cil;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  p = payload + 1;

  n = ngtcp2_get_varint_len(p);
  len += n - 1;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  p += n;
  cil = *p;
  if (cil < NGTCP2_MIN_CIDLEN || cil > NGTCP2_MAX_CIDLEN) {
    return NGTCP2_ERR_PROTO;
  }

  len += cil;
  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  p = payload + 1;

  dest->type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  dest->seq = (uint16_t)ngtcp2_get_varint(&n, p);
  p += n + 1;
  ngtcp2_cid_init(&dest->cid, p, cil);
  p += cil;
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
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  p = payload + 1;

  n = ngtcp2_get_varint_len(p);
  len += n - 1;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  dest->type = NGTCP2_FRAME_STOP_SENDING;
  dest->stream_id = ngtcp2_get_varint(&n, p);
  p += n;
  dest->app_error_code = ngtcp2_get_uint16(p);
  p += 2;

  assert((size_t)(p - payload) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_decode_path_challenge_frame(ngtcp2_path_challenge *dest,
                                               const uint8_t *payload,
                                               size_t payloadlen) {
  size_t len = 1 + 8;
  const uint8_t *p;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  p = payload + 1;

  dest->type = NGTCP2_FRAME_PATH_CHALLENGE;
  ngtcp2_cpymem(dest->data, p, sizeof(dest->data));
  p += sizeof(dest->data);

  assert((size_t)(p - payload) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_decode_path_response_frame(ngtcp2_path_response *dest,
                                              const uint8_t *payload,
                                              size_t payloadlen) {
  size_t len = 1 + 8;
  const uint8_t *p;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  p = payload + 1;

  dest->type = NGTCP2_FRAME_PATH_RESPONSE;
  ngtcp2_cpymem(dest->data, p, sizeof(dest->data));
  p += sizeof(dest->data);

  assert((size_t)(p - payload) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_decode_crypto_frame(ngtcp2_crypto *dest,
                                       const uint8_t *payload,
                                       size_t payloadlen) {
  size_t len = 1 + 1 + 1;
  const uint8_t *p;
  size_t datalen;
  size_t ndatalen;
  size_t n;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  p = payload + 1;

  n = ngtcp2_get_varint_len(p);
  len += n - 1;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  p += n;

  ndatalen = ngtcp2_get_varint_len(p);
  len += ndatalen - 1;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  datalen = ngtcp2_get_varint(&ndatalen, p);
  len += datalen;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  p = payload + 1;

  dest->type = NGTCP2_FRAME_CRYPTO;
  dest->offset = ngtcp2_get_varint(&n, p);
  p += n;
  dest->data[0].len = datalen;
  p += ndatalen;
  if (dest->data[0].len) {
    dest->data[0].base = (uint8_t *)p;
    p += dest->data[0].len;
    dest->datacnt = 1;
  } else {
    dest->data[0].base = NULL;
    dest->datacnt = 0;
  }

  assert((size_t)(p - payload) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_decode_new_token_frame(ngtcp2_new_token *dest,
                                          const uint8_t *payload,
                                          size_t payloadlen) {
  size_t len = 1 + 1;
  const uint8_t *p;
  size_t n;
  size_t datalen;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  p = payload + 1;

  n = ngtcp2_get_varint_len(p);
  len += n - 1;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  datalen = ngtcp2_get_varint(&n, p);
  len += datalen;

  if (payloadlen < len) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  dest->type = NGTCP2_FRAME_NEW_TOKEN;
  dest->tokenlen = datalen;
  p += n;
  dest->token = p;
  p += dest->tokenlen;

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
  case NGTCP2_FRAME_PATH_CHALLENGE:
    return ngtcp2_pkt_encode_path_challenge_frame(out, outlen,
                                                  &fr->path_challenge);
  case NGTCP2_FRAME_PATH_RESPONSE:
    return ngtcp2_pkt_encode_path_response_frame(out, outlen,
                                                 &fr->path_response);
  case NGTCP2_FRAME_CRYPTO:
    return ngtcp2_pkt_encode_crypto_frame(out, outlen, &fr->crypto);
  case NGTCP2_FRAME_NEW_TOKEN:
    return ngtcp2_pkt_encode_new_token_frame(out, outlen, &fr->new_token);
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
  size_t len = 1 + 2 + ngtcp2_put_varint_len(fr->frame_type) +
               ngtcp2_put_varint_len(fr->reasonlen) + fr->reasonlen;
  uint8_t *p;

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = NGTCP2_FRAME_CONNECTION_CLOSE;
  p = ngtcp2_put_uint16be(p, fr->error_code);
  p = ngtcp2_put_varint(p, fr->frame_type);
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
  (void)fr;

  if (outlen < 1) {
    return NGTCP2_ERR_NOBUF;
  }

  *out++ = NGTCP2_FRAME_PING;

  return 1;
}

ssize_t ngtcp2_pkt_encode_blocked_frame(uint8_t *out, size_t outlen,
                                        const ngtcp2_blocked *fr) {
  size_t len = 1 + ngtcp2_put_varint_len(fr->offset);
  uint8_t *p;

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = NGTCP2_FRAME_BLOCKED;
  p = ngtcp2_put_varint(p, fr->offset);

  assert((size_t)(p - out) == len);

  return (ssize_t)len;
}

ssize_t
ngtcp2_pkt_encode_stream_blocked_frame(uint8_t *out, size_t outlen,
                                       const ngtcp2_stream_blocked *fr) {
  size_t len = 1 + ngtcp2_put_varint_len(fr->stream_id) +
               ngtcp2_put_varint_len(fr->offset);
  uint8_t *p;

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = NGTCP2_FRAME_STREAM_BLOCKED;
  p = ngtcp2_put_varint(p, fr->stream_id);
  p = ngtcp2_put_varint(p, fr->offset);

  assert((size_t)(p - out) == len);

  return (ssize_t)len;
}

ssize_t
ngtcp2_pkt_encode_stream_id_blocked_frame(uint8_t *out, size_t outlen,
                                          const ngtcp2_stream_id_blocked *fr) {
  size_t len = 1 + ngtcp2_put_varint_len(fr->stream_id);
  uint8_t *p;

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = NGTCP2_FRAME_STREAM_ID_BLOCKED;
  p = ngtcp2_put_varint(p, fr->stream_id);

  assert((size_t)(p - out) == len);

  return (ssize_t)len;
}

ssize_t
ngtcp2_pkt_encode_new_connection_id_frame(uint8_t *out, size_t outlen,
                                          const ngtcp2_new_connection_id *fr) {
  size_t len = 1 + ngtcp2_put_varint_len(fr->seq) + 1 + fr->cid.datalen +
               NGTCP2_STATELESS_RESET_TOKENLEN;
  uint8_t *p;

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = NGTCP2_FRAME_NEW_CONNECTION_ID;
  p = ngtcp2_put_varint(p, fr->seq);
  *p++ = (uint8_t)fr->cid.datalen;
  p = ngtcp2_cpymem(p, fr->cid.data, fr->cid.datalen);
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

ssize_t
ngtcp2_pkt_encode_path_challenge_frame(uint8_t *out, size_t outlen,
                                       const ngtcp2_path_challenge *fr) {
  size_t len = 1 + 8;
  uint8_t *p;

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = NGTCP2_FRAME_PATH_CHALLENGE;
  p = ngtcp2_cpymem(p, fr->data, sizeof(fr->data));

  assert((size_t)(p - out) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_encode_path_response_frame(uint8_t *out, size_t outlen,
                                              const ngtcp2_path_response *fr) {
  size_t len = 1 + 8;
  uint8_t *p;

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = NGTCP2_FRAME_PATH_RESPONSE;
  p = ngtcp2_cpymem(p, fr->data, sizeof(fr->data));

  assert((size_t)(p - out) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_encode_crypto_frame(uint8_t *out, size_t outlen,
                                       const ngtcp2_crypto *fr) {
  size_t len = 1;
  uint8_t *p;
  size_t i;
  size_t datalen = 0;

  len += ngtcp2_put_varint_len(fr->offset);

  for (i = 0; i < fr->datacnt; ++i) {
    datalen += fr->data[i].len;
  }

  len += ngtcp2_put_varint_len(datalen);
  len += datalen;

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = NGTCP2_FRAME_CRYPTO;

  p = ngtcp2_put_varint(p, fr->offset);
  p = ngtcp2_put_varint(p, datalen);

  for (i = 0; i < fr->datacnt; ++i) {
    assert(fr->data[i].base);
    p = ngtcp2_cpymem(p, fr->data[i].base, fr->data[i].len);
  }

  assert((size_t)(p - out) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_encode_new_token_frame(uint8_t *out, size_t outlen,
                                          const ngtcp2_new_token *fr) {
  size_t len = 1 + ngtcp2_put_varint_len(fr->tokenlen) + fr->tokenlen;
  uint8_t *p;

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;

  *p++ = NGTCP2_FRAME_NEW_TOKEN;

  p = ngtcp2_put_varint(p, fr->tokenlen);
  if (fr->tokenlen) {
    p = ngtcp2_cpymem(p, fr->token, fr->tokenlen);
  }

  assert((size_t)(p - out) == len);

  return (ssize_t)len;
}

ssize_t ngtcp2_pkt_write_version_negotiation(uint8_t *dest, size_t destlen,
                                             uint8_t unused_random,
                                             const ngtcp2_cid *dcid,
                                             const ngtcp2_cid *scid,
                                             const uint32_t *sv, size_t nsv) {
  size_t len = 1 + 4 + 1 + dcid->datalen + scid->datalen + nsv * 4;
  uint8_t *p;
  size_t i;

  if (destlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = dest;

  *p++ = 0x80 | unused_random;
  p = ngtcp2_put_uint32be(p, 0);
  *p = 0;
  if (dcid->datalen) {
    assert(dcid->datalen > 3);
    *p |= (uint8_t)((dcid->datalen - 3) << 4);
  }
  if (scid->datalen) {
    assert(scid->datalen > 3);
    *p = (uint8_t)(*p | ((scid->datalen - 3) & 0xf));
  }
  ++p;
  if (dcid->datalen) {
    p = ngtcp2_cpymem(p, dcid->data, dcid->datalen);
  }
  if (scid->datalen) {
    p = ngtcp2_cpymem(p, scid->data, scid->datalen);
  }

  for (i = 0; i < nsv; ++i) {
    p = ngtcp2_put_uint32be(p, sv[i]);
  }

  assert((size_t)(p - dest) == len);

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

int ngtcp2_pkt_decode_retry(ngtcp2_pkt_retry *dest, const uint8_t *payload,
                            size_t payloadlen) {
  size_t len = 1;
  const uint8_t *p = payload;
  size_t odcil;

  if (payloadlen < len) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  odcil = *p & 0xf;
  if (odcil) {
    odcil += 3;
  }
  len += odcil;

  if (payloadlen < len) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  ++p;

  ngtcp2_cid_init(&dest->odcid, p, odcil);
  p += odcil;

  dest->tokenlen = (size_t)(payload + payloadlen - p);
  if (dest->tokenlen) {
    dest->token = p;
  } else {
    dest->token = NULL;
  }

  return 0;
}

uint64_t ngtcp2_pkt_adjust_pkt_num(uint64_t max_pkt_num, uint64_t pkt_num,
                                   size_t n) {
  uint64_t k =
      max_pkt_num == NGTCP2_MAX_PKT_NUM ? max_pkt_num : max_pkt_num + 1;
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

ssize_t ngtcp2_pkt_write_retry(uint8_t *dest, size_t destlen,
                               const ngtcp2_pkt_hd *hd, const ngtcp2_cid *odcid,
                               const uint8_t *token, size_t tokenlen) {
  uint8_t *p;
  ssize_t nwrite;

  assert(hd->flags & NGTCP2_PKT_FLAG_LONG_FORM);
  assert(hd->type == NGTCP2_PKT_RETRY);
  /* The specification requires that the initial random connection ID
     from client must be at least 8 octets.  But after first Retry,
     server might choose 0 length connection ID for client. */
  assert(odcid->datalen == 0 || odcid->datalen > 3);
  assert(tokenlen > 0);

  nwrite = ngtcp2_pkt_encode_hd_long(dest, destlen, hd);
  if (nwrite < 0) {
    return nwrite;
  }

  if (destlen < (size_t)nwrite + 1 + odcid->datalen + tokenlen) {
    return NGTCP2_ERR_NOBUF;
  }

  p = dest + nwrite;

  if (odcid->datalen == 0) {
    *p++ = 0;
  } else {
    *p++ = (uint8_t)(odcid->datalen - 3);
    p = ngtcp2_cpymem(p, odcid->data, odcid->datalen);
  }

  p = ngtcp2_cpymem(p, token, tokenlen);

  return p - dest;
}

int ngtcp2_pkt_handshake_pkt(const ngtcp2_pkt_hd *hd) {
  return (hd->flags & NGTCP2_PKT_FLAG_LONG_FORM) &&
         (hd->type == NGTCP2_PKT_INITIAL || hd->type == NGTCP2_PKT_HANDSHAKE ||
          hd->type == NGTCP2_PKT_0RTT_PROTECTED);
}
