/*
 * ngtcp2
 *
 * Copyright (c) 2018 ngtcp2 contributors
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
#ifndef NGTCP2_CID_H
#define NGTCP2_CID_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <ngtcp2/ngtcp2.h>

/* ngtcp2_cid_zero makes |cid| zero-length. */
void ngtcp2_cid_zero(ngtcp2_cid *cid);

/*
 * ngtcp2_cid_eq returns nonzero if |cid| and |other| share the same
 * connection ID.
 */
int ngtcp2_cid_eq(const ngtcp2_cid *cid, const ngtcp2_cid *other);

/*
 * ngtcp2_cid_less returns nonzero if |lhs| is lexicographical smaller
 * than |rhs|.
 */
int ngtcp2_cid_less(const ngtcp2_cid *lhs, const ngtcp2_cid *rhs);

/*
 * ngtcp2_cid_empty returns nonzero if |cid| includes empty connection
 * ID.
 */
int ngtcp2_cid_empty(const ngtcp2_cid *cid);

#endif /* NGTCP2_CID_H */
