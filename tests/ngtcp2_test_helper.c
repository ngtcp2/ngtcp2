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
#include "ngtcp2_test_helper.h"

#include <string.h>

#include "ngtcp2_conv.h"
#include "ngtcp2_pkt.h"

size_t ngtcp2_t_encode_stream_frame(uint8_t *out, uint8_t flags,
                                    uint32_t stream_id, uint64_t offset,
                                    uint16_t datalen) {
  uint8_t *p = out;

  ++p;
  if (stream_id > 0xffffffu) {
    flags |= 0x18;
    p = ngtcp2_put_uint32be(p, stream_id);
  } else if (stream_id > 0xffff) {
    flags |= 0x10;
    p = ngtcp2_put_uint24be(p, stream_id);
  } else if (stream_id > 0xff) {
    flags |= 0x08;
    p = ngtcp2_put_uint16be(p, (uint16_t)stream_id);
  } else {
    *p++ = (uint8_t)stream_id;
  }

  if (offset > 0xffffffffu) {
    flags |= 0x06;
    p = ngtcp2_put_uint64be(p, offset);
  } else if (offset > 0xffff) {
    flags |= 0x04;
    p = ngtcp2_put_uint32be(p, (uint32_t)offset);
  } else if (offset > 0xff) {
    flags |= 0x02;
    p = ngtcp2_put_uint16be(p, (uint16_t)offset);
  }

  if (flags & NGTCP2_STREAM_D_BIT) {
    p = ngtcp2_put_uint16be(p, datalen);
    memset(p, 0, datalen);
    p += datalen;
  } else {
    memset(p, 0, datalen);
    p += datalen;
  }

  *out = NGTCP2_FRAME_STREAM | flags;

  return (size_t)(p - out);
}

size_t ngtcp2_t_encode_ack_frame(uint8_t *out, uint64_t largest_ack,
                                 uint64_t first_ack_blklen, uint8_t gap,
                                 uint64_t ack_blklen) {
  uint8_t *p = out;

  p = out;

  *p++ = 0x1f | NGTCP2_FRAME_ACK;
  /* Num Blocks */
  *p++ = 1;
  /* NumTS */
  *p++ = 0;
  /* Largest Acknowledged */
  p = ngtcp2_put_uint64be(p, largest_ack);
  /* ACK Delay */
  p = ngtcp2_put_uint16be(p, 0);
  /* First ACK Block Length */
  p = ngtcp2_put_uint64be(p, first_ack_blklen);
  /* Gap 1 */
  *p++ = gap;
  /* ACK Block 1 Length */
  p = ngtcp2_put_uint64be(p, ack_blklen);

  return (size_t)(p - out);
}
