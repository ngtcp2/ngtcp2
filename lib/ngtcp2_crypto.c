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
#include "ngtcp2_crypto.h"

#include <string.h>
#include <assert.h>

#include "ngtcp2_str.h"
#include "ngtcp2_conv.h"

int ngtcp2_crypto_km_new(ngtcp2_crypto_km **pckm, const uint8_t *key,
                         size_t keylen, const uint8_t *iv, size_t ivlen,
                         ngtcp2_mem *mem) {
  size_t len;
  uint8_t *p;

  len = sizeof(ngtcp2_crypto_km) + keylen + ivlen;

  *pckm = ngtcp2_mem_malloc(mem, len);
  if (*pckm == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  p = (uint8_t *)(*pckm) + sizeof(ngtcp2_crypto_km);
  (*pckm)->key.base = p;
  (*pckm)->key.len = keylen;
  p = ngtcp2_cpymem(p, key, keylen);
  (*pckm)->iv.base = p;
  (*pckm)->iv.len = ivlen;
  /* p = */ ngtcp2_cpymem(p, iv, ivlen);
  (*pckm)->pkt_num = 0;
  (*pckm)->flags = NGTCP2_CRYPTO_KM_FLAG_NONE;

  return 0;
}

void ngtcp2_crypto_km_del(ngtcp2_crypto_km *ckm, ngtcp2_mem *mem) {
  if (ckm == NULL) {
    return;
  }

  ngtcp2_mem_free(mem, ckm);
}

void ngtcp2_crypto_create_nonce(uint8_t *dest, const uint8_t *iv, size_t ivlen,
                                uint64_t pkt_num) {
  size_t i;

  memcpy(dest, iv, ivlen);
  pkt_num = bswap64(pkt_num);

  for (i = 0; i < 8; ++i) {
    dest[ivlen - 8 + i] ^= ((uint8_t *)&pkt_num)[i];
  }
}

ssize_t ngtcp2_encode_transport_params(uint8_t *dest, size_t destlen,
                                       uint8_t exttype,
                                       const ngtcp2_transport_params *params) {
  uint8_t *p;
  size_t len = 2 /* transport parameters length */;
  size_t i;
  size_t vlen;
  /* For some reason, gcc 7.3.0 requires this initialization. */
  size_t preferred_addrlen = 0;

  switch (exttype) {
  case NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO:
    vlen = sizeof(uint32_t);
    break;
  case NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS:
    vlen = sizeof(uint32_t) + 1 + params->v.ee.len * sizeof(uint32_t);
    if (params->stateless_reset_token_present) {
      len += 20;
    }
    if (params->preferred_address.ip_version != NGTCP2_IP_VERSION_NONE) {
      assert(params->preferred_address.ip_addresslen >= 4);
      assert(params->preferred_address.ip_addresslen < 256);
      assert(params->preferred_address.cid.datalen == 0 ||
             params->preferred_address.cid.datalen >= NGTCP2_MIN_CIDLEN);
      assert(params->preferred_address.cid.datalen <= NGTCP2_MAX_CIDLEN);
      preferred_addrlen =
          1 /* ip_version */ + 1 +
          params->preferred_address.ip_addresslen /* ip_address */ +
          2 /* port */ + 1 +
          params->preferred_address.cid.datalen /* connection_id */ +
          NGTCP2_STATELESS_RESET_TOKENLEN;
      len += 4 + preferred_addrlen;
    }
    if (params->original_connection_id_present) {
      len += 4 + params->original_connection_id.datalen;
    }
    break;
  default:
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  len += vlen;

  if (params->initial_max_stream_data_bidi_local) {
    len +=
        4 + ngtcp2_put_varint_len(params->initial_max_stream_data_bidi_local);
  }
  if (params->initial_max_stream_data_bidi_remote) {
    len +=
        4 + ngtcp2_put_varint_len(params->initial_max_stream_data_bidi_remote);
  }
  if (params->initial_max_stream_data_uni) {
    len += 4 + ngtcp2_put_varint_len(params->initial_max_stream_data_uni);
  }
  if (params->initial_max_data) {
    len += 4 + ngtcp2_put_varint_len(params->initial_max_data);
  }
  if (params->initial_max_streams_bidi) {
    len += 4 + ngtcp2_put_varint_len(params->initial_max_streams_bidi);
  }
  if (params->initial_max_streams_uni) {
    len += 4 + ngtcp2_put_varint_len(params->initial_max_streams_uni);
  }
  if (params->max_packet_size != NGTCP2_MAX_PKT_SIZE) {
    len += 4 + ngtcp2_put_varint_len(params->max_packet_size);
  }
  if (params->ack_delay_exponent != NGTCP2_DEFAULT_ACK_DELAY_EXPONENT) {
    len += 4 + ngtcp2_put_varint_len(params->ack_delay_exponent);
  }
  if (params->disable_migration) {
    len += 4;
  }
  if (params->max_ack_delay != NGTCP2_DEFAULT_MAX_ACK_DELAY) {
    len += 4 + ngtcp2_put_varint_len(params->max_ack_delay);
  }
  if (params->idle_timeout) {
    len += 4 + ngtcp2_put_varint_len(params->idle_timeout);
  }

  if (destlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = dest;

  switch (exttype) {
  case NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO:
    p = ngtcp2_put_uint32be(p, params->v.ch.initial_version);
    break;
  case NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS:
    p = ngtcp2_put_uint32be(p, params->v.ee.negotiated_version);
    *p++ = (uint8_t)(params->v.ee.len * sizeof(uint32_t));
    for (i = 0; i < params->v.ee.len; ++i) {
      p = ngtcp2_put_uint32be(p, params->v.ee.supported_versions[i]);
    }
    break;
  }

  p = ngtcp2_put_uint16be(p, (uint16_t)(len - vlen - sizeof(uint16_t)));

  if (exttype == NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS) {
    if (params->stateless_reset_token_present) {
      p = ngtcp2_put_uint16be(p, NGTCP2_TRANSPORT_PARAM_STATELESS_RESET_TOKEN);
      p = ngtcp2_put_uint16be(p, sizeof(params->stateless_reset_token));
      p = ngtcp2_cpymem(p, params->stateless_reset_token,
                        sizeof(params->stateless_reset_token));
    }
    if (params->preferred_address.ip_version != NGTCP2_IP_VERSION_NONE) {
      p = ngtcp2_put_uint16be(p, NGTCP2_TRANSPORT_PARAM_PREFERRED_ADDRESS);
      p = ngtcp2_put_uint16be(p, (uint16_t)preferred_addrlen);
      *p++ = params->preferred_address.ip_version;
      *p++ = (uint8_t)params->preferred_address.ip_addresslen;
      p = ngtcp2_cpymem(p, params->preferred_address.ip_address,
                        params->preferred_address.ip_addresslen);
      p = ngtcp2_put_uint16be(p, params->preferred_address.port);
      *p++ = (uint8_t)params->preferred_address.cid.datalen;
      if (params->preferred_address.cid.datalen) {
        p = ngtcp2_cpymem(p, params->preferred_address.cid.data,
                          params->preferred_address.cid.datalen);
      }
      p = ngtcp2_cpymem(
          p, params->preferred_address.stateless_reset_token,
          sizeof(params->preferred_address.stateless_reset_token));
    }
    if (params->original_connection_id_present) {
      p = ngtcp2_put_uint16be(p, NGTCP2_TRANSPORT_PARAM_ORIGINAL_CONNECTION_ID);
      p = ngtcp2_put_uint16be(p,
                              (uint16_t)params->original_connection_id.datalen);
      p = ngtcp2_cpymem(p, params->original_connection_id.data,
                        params->original_connection_id.datalen);
    }
  }

  if (params->initial_max_stream_data_bidi_local) {
    p = ngtcp2_put_uint16be(
        p, NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL);
    p = ngtcp2_put_uint16be(p, (uint16_t)ngtcp2_put_varint_len(
                                   params->initial_max_stream_data_bidi_local));
    p = ngtcp2_put_varint(p, params->initial_max_stream_data_bidi_local);
  }

  if (params->initial_max_stream_data_bidi_remote) {
    p = ngtcp2_put_uint16be(
        p, NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE);
    p = ngtcp2_put_uint16be(p,
                            (uint16_t)ngtcp2_put_varint_len(
                                params->initial_max_stream_data_bidi_remote));
    p = ngtcp2_put_varint(p, params->initial_max_stream_data_bidi_remote);
  }

  if (params->initial_max_stream_data_uni) {
    p = ngtcp2_put_uint16be(p,
                            NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_UNI);
    p = ngtcp2_put_uint16be(p, (uint16_t)ngtcp2_put_varint_len(
                                   params->initial_max_stream_data_uni));
    p = ngtcp2_put_varint(p, params->initial_max_stream_data_uni);
  }

  if (params->initial_max_data) {
    p = ngtcp2_put_uint16be(p, NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_DATA);
    p = ngtcp2_put_uint16be(
        p, (uint16_t)ngtcp2_put_varint_len(params->initial_max_data));
    p = ngtcp2_put_varint(p, params->initial_max_data);
  }

  if (params->initial_max_streams_bidi) {
    p = ngtcp2_put_uint16be(p, NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI);
    p = ngtcp2_put_uint16be(
        p, (uint16_t)ngtcp2_put_varint_len(params->initial_max_streams_bidi));
    p = ngtcp2_put_varint(p, params->initial_max_streams_bidi);
  }

  if (params->initial_max_streams_uni) {
    p = ngtcp2_put_uint16be(p, NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI);
    p = ngtcp2_put_uint16be(
        p, (uint16_t)ngtcp2_put_varint_len(params->initial_max_streams_uni));
    p = ngtcp2_put_varint(p, params->initial_max_streams_uni);
  }

  if (params->max_packet_size != NGTCP2_MAX_PKT_SIZE) {
    p = ngtcp2_put_uint16be(p, NGTCP2_TRANSPORT_PARAM_MAX_PACKET_SIZE);
    p = ngtcp2_put_uint16be(
        p, (uint16_t)ngtcp2_put_varint_len(params->max_packet_size));
    p = ngtcp2_put_varint(p, params->max_packet_size);
  }

  if (params->ack_delay_exponent != NGTCP2_DEFAULT_ACK_DELAY_EXPONENT) {
    p = ngtcp2_put_uint16be(p, NGTCP2_TRANSPORT_PARAM_ACK_DELAY_EXPONENT);
    p = ngtcp2_put_uint16be(
        p, (uint16_t)ngtcp2_put_varint_len(params->ack_delay_exponent));
    p = ngtcp2_put_varint(p, params->ack_delay_exponent);
  }

  if (params->disable_migration) {
    p = ngtcp2_put_uint16be(p, NGTCP2_TRANSPORT_PARAM_DISABLE_MIGRATION);
    p = ngtcp2_put_uint16be(p, 0);
  }

  if (params->max_ack_delay != NGTCP2_DEFAULT_MAX_ACK_DELAY) {
    p = ngtcp2_put_uint16be(p, NGTCP2_TRANSPORT_PARAM_MAX_ACK_DELAY);
    p = ngtcp2_put_uint16be(
        p, (uint16_t)ngtcp2_put_varint_len(params->max_ack_delay));
    p = ngtcp2_put_varint(p, params->max_ack_delay);
  }

  if (params->idle_timeout) {
    p = ngtcp2_put_uint16be(p, NGTCP2_TRANSPORT_PARAM_IDLE_TIMEOUT);
    p = ngtcp2_put_uint16be(
        p, (uint16_t)ngtcp2_put_varint_len(params->idle_timeout));
    p = ngtcp2_put_varint(p, params->idle_timeout);
  }

  assert((size_t)(p - dest) == len);

  return (ssize_t)len;
}

static ssize_t decode_varint(uint64_t *pdest, const uint8_t *p,
                             const uint8_t *end) {
  uint16_t len = ngtcp2_get_uint16(p);
  size_t n;

  p += sizeof(uint16_t);

  switch (len) {
  case 1:
  case 2:
  case 4:
  case 8:
    break;
  default:
    return -1;
  }

  if ((size_t)(end - p) < len) {
    return -1;
  }

  n = ngtcp2_get_varint_len(p);
  if (n != len) {
    return -1;
  }

  *pdest = ngtcp2_get_varint(&n, p);

  return (ssize_t)(sizeof(uint16_t) + len);
}

int ngtcp2_decode_transport_params(ngtcp2_transport_params *params,
                                   uint8_t exttype, const uint8_t *data,
                                   size_t datalen) {
  uint32_t flags = 0;
  const uint8_t *p, *end;
  size_t supported_versionslen;
  size_t i;
  uint16_t param_type;
  size_t valuelen;
  size_t vlen;
  size_t len;
  ssize_t nread;

  p = data;
  end = data + datalen;

  switch (exttype) {
  case NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO:
    if ((size_t)(end - p) < sizeof(uint32_t)) {
      return NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM;
    }
    params->v.ch.initial_version = ngtcp2_get_uint32(p);
    p += sizeof(uint32_t);
    vlen = sizeof(uint32_t);
    break;
  case NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS:
    if ((size_t)(end - p) < sizeof(uint32_t) + 1) {
      return NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM;
    }
    params->v.ee.negotiated_version = ngtcp2_get_uint32(p);
    p += sizeof(uint32_t);
    supported_versionslen = *p++;
    if ((size_t)(end - p) < supported_versionslen ||
        supported_versionslen % sizeof(uint32_t)) {
      return NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM;
    }
    params->v.ee.len = supported_versionslen / sizeof(uint32_t);
    for (i = 0; i < supported_versionslen;
         i += sizeof(uint32_t), p += sizeof(uint32_t)) {
      params->v.ee.supported_versions[i / sizeof(uint32_t)] =
          ngtcp2_get_uint32(p);
    }
    vlen = sizeof(uint32_t) + 1 + supported_versionslen;
    break;
  default:
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  if ((size_t)(end - p) < sizeof(uint16_t)) {
    return NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM;
  }

  if (vlen + sizeof(uint16_t) + ngtcp2_get_uint16(p) != datalen) {
    return NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM;
  }
  p += sizeof(uint16_t);

  /* Set default values */
  params->initial_max_streams_bidi = 0;
  params->initial_max_streams_uni = 0;
  params->initial_max_stream_data_bidi_local = 0;
  params->initial_max_stream_data_bidi_remote = 0;
  params->initial_max_stream_data_uni = 0;
  params->max_packet_size = NGTCP2_MAX_PKT_SIZE;
  params->ack_delay_exponent = NGTCP2_DEFAULT_ACK_DELAY_EXPONENT;
  params->stateless_reset_token_present = 0;
  params->preferred_address.ip_version = NGTCP2_IP_VERSION_NONE;
  params->disable_migration = 0;
  params->max_ack_delay = NGTCP2_DEFAULT_MAX_ACK_DELAY;
  params->idle_timeout = 0;
  params->original_connection_id_present = 0;

  for (; (size_t)(end - p) >= sizeof(uint16_t) * 2;) {
    param_type = ngtcp2_get_uint16(p);
    p += sizeof(uint16_t);
    switch (param_type) {
    case NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
      flags |= 1u << param_type;
      nread =
          decode_varint(&params->initial_max_stream_data_bidi_local, p, end);
      if (nread < 0) {
        return NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM;
      }
      p += nread;
      break;
    case NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
      flags |= 1u << param_type;
      nread =
          decode_varint(&params->initial_max_stream_data_bidi_remote, p, end);
      if (nread < 0) {
        return NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM;
      }
      p += nread;
      break;
    case NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_UNI:
      flags |= 1u << param_type;
      nread = decode_varint(&params->initial_max_stream_data_uni, p, end);
      if (nread < 0) {
        return NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM;
      }
      p += nread;
      break;
    case NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_DATA:
      flags |= 1u << param_type;
      nread = decode_varint(&params->initial_max_data, p, end);
      if (nread < 0) {
        return NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM;
      }
      p += nread;
      break;
    case NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI:
      flags |= 1u << param_type;
      nread = decode_varint(&params->initial_max_streams_bidi, p, end);
      if (nread < 0) {
        return NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM;
      }
      p += nread;
      break;
    case NGTCP2_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI:
      flags |= 1u << param_type;
      nread = decode_varint(&params->initial_max_streams_uni, p, end);
      if (nread < 0) {
        return NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM;
      }
      p += nread;
      break;
    case NGTCP2_TRANSPORT_PARAM_IDLE_TIMEOUT:
      flags |= 1u << param_type;
      nread = decode_varint(&params->idle_timeout, p, end);
      if (nread < 0) {
        return NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM;
      }
      p += nread;
      break;
    case NGTCP2_TRANSPORT_PARAM_MAX_PACKET_SIZE:
      flags |= 1u << param_type;
      nread = decode_varint(&params->max_packet_size, p, end);
      if (nread < 0) {
        return NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM;
      }
      p += nread;
      break;
    case NGTCP2_TRANSPORT_PARAM_STATELESS_RESET_TOKEN:
      if (exttype != NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS) {
        return NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM;
      }
      flags |= 1u << NGTCP2_TRANSPORT_PARAM_STATELESS_RESET_TOKEN;
      if (ngtcp2_get_uint16(p) != sizeof(params->stateless_reset_token)) {
        return NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM;
      }
      p += sizeof(uint16_t);
      if ((size_t)(end - p) < sizeof(params->stateless_reset_token)) {
        return NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM;
      }

      memcpy(params->stateless_reset_token, p,
             sizeof(params->stateless_reset_token));
      params->stateless_reset_token_present = 1;

      p += sizeof(params->stateless_reset_token);
      break;
    case NGTCP2_TRANSPORT_PARAM_ACK_DELAY_EXPONENT:
      flags |= 1u << param_type;
      nread = decode_varint(&params->ack_delay_exponent, p, end);
      if (nread < 0 || params->ack_delay_exponent > 20) {
        return NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM;
      }
      p += nread;
      break;
    case NGTCP2_TRANSPORT_PARAM_PREFERRED_ADDRESS:
      if (exttype != NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS) {
        return NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM;
      }
      flags |= 1u << NGTCP2_TRANSPORT_PARAM_PREFERRED_ADDRESS;
      valuelen = ngtcp2_get_uint16(p);
      p += sizeof(uint16_t);
      if ((size_t)(end - p) < valuelen) {
        return NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM;
      }
      len = 1 /* ip_version */ + 1 /* ip_address length */ +
            2
            /* port */
            + 1 /* cid length */ + NGTCP2_STATELESS_RESET_TOKENLEN;
      if (valuelen < len) {
        return NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM;
      }

      /* ip_version */
      params->preferred_address.ip_version = *p++;
      switch (params->preferred_address.ip_version) {
      case NGTCP2_IP_VERSION_4:
      case NGTCP2_IP_VERSION_6:
        break;
      default:
        return NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM;
      }

      /* ip_address */
      params->preferred_address.ip_addresslen = *p++;
      len += params->preferred_address.ip_addresslen;
      if (valuelen < len) {
        return NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM;
      }
      memcpy(params->preferred_address.ip_address, p,
             params->preferred_address.ip_addresslen);
      p += params->preferred_address.ip_addresslen;

      /* port */
      params->preferred_address.port = ngtcp2_get_uint16(p);
      p += sizeof(uint16_t);

      /* cid */
      params->preferred_address.cid.datalen = *p++;
      len += params->preferred_address.cid.datalen;
      if (valuelen != len ||
          params->preferred_address.cid.datalen > NGTCP2_MAX_CIDLEN ||
          (params->preferred_address.cid.datalen != 0 &&
           params->preferred_address.cid.datalen < NGTCP2_MIN_CIDLEN)) {
        return NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM;
      }
      if (params->preferred_address.cid.datalen) {
        memcpy(params->preferred_address.cid.data, p,
               params->preferred_address.cid.datalen);
        p += params->preferred_address.cid.datalen;
      }

      /* stateless reset token */
      memcpy(params->preferred_address.stateless_reset_token, p,
             sizeof(params->preferred_address.stateless_reset_token));
      p += sizeof(params->preferred_address.stateless_reset_token);
      break;
    case NGTCP2_TRANSPORT_PARAM_DISABLE_MIGRATION:
      flags |= 1u << NGTCP2_TRANSPORT_PARAM_DISABLE_MIGRATION;
      if (ngtcp2_get_uint16(p) != 0) {
        return NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM;
      }
      p += sizeof(uint16_t);
      params->disable_migration = 1;
      break;
    case NGTCP2_TRANSPORT_PARAM_ORIGINAL_CONNECTION_ID:
      if (exttype != NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS) {
        return NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM;
      }
      flags |= 1u << NGTCP2_TRANSPORT_PARAM_ORIGINAL_CONNECTION_ID;
      len = ngtcp2_get_uint16(p);
      p += sizeof(uint16_t);
      if ((size_t)(end - p) < len) {
        return NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM;
      }
      ngtcp2_cid_init(&params->original_connection_id, p, len);
      params->original_connection_id_present = 1;
      p += len;
      break;
    case NGTCP2_TRANSPORT_PARAM_MAX_ACK_DELAY:
      flags |= 1u << param_type;
      nread = decode_varint(&params->max_ack_delay, p, end);
      if (nread < 0) {
        return NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM;
      }
      p += nread;
      break;
    default:
      /* Ignore unknown parameter */
      valuelen = ngtcp2_get_uint16(p);
      p += sizeof(uint16_t);
      if ((size_t)(end - p) < valuelen) {
        return NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM;
      }
      p += valuelen;
      break;
    }
  }

  if (end - p != 0) {
    return NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM;
  }

  return 0;
}
