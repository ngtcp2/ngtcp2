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
#ifndef NGTCP2_TEST_HELPER_H
#define NGTCP2_TEST_HELPER_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <ngtcp2/ngtcp2.h>

/*
 * strsize macro returns the length of string literal |S|.
 */
#define strsize(S) (sizeof(S) - 1)

/*
 * ngtcp2_t_encode_stream_frame encodes STREAM frame into |out| with
 * the given parameters.  If NGTCP2_STREAM_D_BIT is set in |flags|,
 * |datalen| is encoded as Data Length, otherwise it is not written.
 * To set FIN bit in wire format, set NGTCP2_STREAM_FIN_BIT in
 * |flags|.  This function expects that |out| has enough length to
 * store entire STREAM frame, excluding the Stream Data.
 *
 * This function returns the number of bytes written to |out|.
 */
size_t ngtcp2_t_encode_stream_frame(uint8_t *out, uint8_t flags,
                                    uint32_t stream_id, uint64_t offset,
                                    uint16_t datalen);

/*
 * ngtcp2_t_encode_ack_frame encodes ACK frame into |out| with the
 * given parameters.  Currently, this function encodes |largest_ack|
 * in 48 bits, and omits Num Blocks field.  NumTS and ACK Delay fields
 * are always 0.
 *
 * This function returns the number of bytes written to |out|.
 */
size_t ngtcp2_t_encode_ack_frame(uint8_t *out, uint64_t largest_ack);

#endif /* NGTCP2_TEST_HELPER_H */
