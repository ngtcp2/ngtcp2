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
#ifndef NGTCP2_CONV_TEST_H
#define NGTCP2_CONV_TEST_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

void test_ngtcp2_get_varint(void);
void test_ngtcp2_get_uvarintlen(void);
void test_ngtcp2_put_uvarintlen(void);
void test_ngtcp2_get_uint64(void);
void test_ngtcp2_get_uint48(void);
void test_ngtcp2_get_uint32(void);
void test_ngtcp2_get_uint24(void);
void test_ngtcp2_get_uint16(void);
void test_ngtcp2_get_uint16be(void);
void test_ngtcp2_nth_server_bidi_id(void);
void test_ngtcp2_nth_server_uni_id(void);
void test_ngtcp2_nth_client_bidi_id(void);
void test_ngtcp2_nth_client_uni_id(void);

#endif /* NGTCP2_CONV_TEST_H */
