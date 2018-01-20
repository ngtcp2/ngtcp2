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
#ifndef NGTCP2_UPE_H
#define NGTCP2_UPE_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <ngtcp2/ngtcp2.h>

#include "ngtcp2_buf.h"

/*
 * ngtcp2_upe is the Unprotected Packet Encoder.
 */
typedef struct {
  ngtcp2_buf buf;
} ngtcp2_upe;

/*
 * ngtcp2_upe_init initializes |upe| with the given buffer.
 */
void ngtcp2_upe_init(ngtcp2_upe *upe, uint8_t *out, size_t outlen);

/*
 * `ngtcp2_upe_encode_hd` encodes QUIC packet header |hd| in the
 * buffer.  |hd| is encoded as long header.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOBUF`
 *     Buffer does not have enough capacity to write a header.
 */
int ngtcp2_upe_encode_hd(ngtcp2_upe *upe, const ngtcp2_pkt_hd *hd);

/*
 * `ngtcp2_upe_encode_frame` encodes the frame |fm| in the buffer.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGTCP2_ERR_NOBUF`
 *     Buffer does not have enough capacity to write a header.
 */
int ngtcp2_upe_encode_frame(ngtcp2_upe *upe, ngtcp2_frame *fr);

/*
 * `ngtcp2_upe_padding` encodes PADDING frames to the end of the
 * buffer.  This function returns the number of bytes padded.
 */
size_t ngtcp2_upe_padding(ngtcp2_upe *upe);

/*
 * `ngtcp2_upe_final` stores the pointer to the packet into |*pkt| if
 * |*pkt| is not ``NULL``, and the length of packet is returned.
 */
size_t ngtcp2_upe_final(ngtcp2_upe *upe, const uint8_t **ppkt);

/*
 * `ngtcp2_upe_left` returns the number of bytes left to write
 * additional frames.
 */
size_t ngtcp2_upe_left(ngtcp2_upe *upe);

#endif /* NGTCP2_UPE_H */
