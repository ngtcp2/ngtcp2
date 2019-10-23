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
#ifndef NGTCP2_STR_H
#define NGTCP2_STR_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <ngtcp2/ngtcp2.h>

void *ngtcp2_cpymem(void *dest, const void *src, size_t n);

/*
 * ngtcp2_setmem writes a string of length |n| consisting only |b| to
 * the buffer pointed by |dest|.  It returns dest + n;
 */
uint8_t *ngtcp2_setmem(uint8_t *dest, uint8_t b, size_t n);
/*
 * ngtcp2_encode_hex encodes |data| of length |len| in hex string.  It
 * writes additional NULL bytes at the end of the buffer.  The buffer
 * pointed by |dest| must have at least |len| * 2 + 1 bytes space.
 * This function returns |dest|.
 */
uint8_t *ngtcp2_encode_hex(uint8_t *dest, const uint8_t *data, size_t len);

/*
 * ngtcp2_encode_printable_ascii encodes |data| of length |len| in
 * |dest| in the following manner: printable ascii characters are
 * copied as is.  The other characters are converted to ".".  It
 * writes additional NULL bytes at the end of the buffer.  |dest| must
 * have at least |len| + 1 bytes.  This function returns |dest|.
 */
char *ngtcp2_encode_printable_ascii(char *dest, const uint8_t *data,
                                    size_t len);

/*
 * ngtcp2_verify_stateless_retry_token verifies stateless retry token
 * |want| and |got|.  This function returns 0 if |want| equals |got|
 * and |got| is not all zero, or one of the following negative error
 * codes:
 *
 * NGTCP2_ERR_INVALID_ARGUMENT
 *     Token does not match; or token is all zero.
 */
int ngtcp2_verify_stateless_retry_token(const uint8_t *want,
                                        const uint8_t *got);

#endif /* NGTCP2_STR_H */
