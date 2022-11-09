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
#ifndef SHARED_H
#define SHARED_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif // HAVE_CONFIG_H

#include <optional>

#include <ngtcp2/ngtcp2.h>

#include "network.h"

namespace ngtcp2 {

enum class AppProtocol {
  H3,
  HQ,
};

constexpr uint8_t HQ_ALPN[] = "\xahq-interop\x5hq-29\x5hq-30\x5hq-31\x5hq-32";
constexpr uint8_t HQ_ALPN_DRAFT29[] = "\x5hq-29";
constexpr uint8_t HQ_ALPN_DRAFT30[] = "\x5hq-30";
constexpr uint8_t HQ_ALPN_DRAFT31[] = "\x5hq-31";
constexpr uint8_t HQ_ALPN_DRAFT32[] = "\x5hq-32";
constexpr uint8_t HQ_ALPN_V1[] = "\xahq-interop";

constexpr uint8_t H3_ALPN[] = "\x2h3\x5h3-29\x5h3-30\x5h3-31\x5h3-32";
constexpr uint8_t H3_ALPN_DRAFT29[] = "\x5h3-29";
constexpr uint8_t H3_ALPN_DRAFT30[] = "\x5h3-30";
constexpr uint8_t H3_ALPN_DRAFT31[] = "\x5h3-31";
constexpr uint8_t H3_ALPN_DRAFT32[] = "\x5h3-32";
constexpr uint8_t H3_ALPN_V1[] = "\x2h3";

constexpr uint32_t QUIC_VER_DRAFT29 = 0xff00001du;
constexpr uint32_t QUIC_VER_DRAFT30 = 0xff00001eu;
constexpr uint32_t QUIC_VER_DRAFT31 = 0xff00001fu;
constexpr uint32_t QUIC_VER_DRAFT32 = 0xff000020u;

// msghdr_get_ecn gets ECN bits from |msg|.  |family| is the address
// family from which packet is received.
unsigned int msghdr_get_ecn(msghdr *msg, int family);

// fd_set_ecn sets ECN bits |ecn| to |fd|.  |family| is the address
// family of |fd|.
void fd_set_ecn(int fd, int family, unsigned int ecn);

// fd_set_recv_ecn sets socket option to |fd| so that it can receive
// ECN bits.
void fd_set_recv_ecn(int fd, int family);

// fd_set_ip_mtu_discover sets IP(V6)_MTU_DISCOVER socket option to
// |fd|.
void fd_set_ip_mtu_discover(int fd, int family);

// fd_set_ip_dontfrag sets IP(V6)_DONTFRAG socket option to |fd|.
void fd_set_ip_dontfrag(int fd, int family);

std::optional<Address> msghdr_get_local_addr(msghdr *msg, int family);

void set_port(Address &dst, Address &src);

// get_local_addr stores preferred local address (interface address)
// in |iau| for a given destination address |remote_addr|.
int get_local_addr(in_addr_union &iau, const Address &remote_addr);

// addreq returns true if |sa| and |iau| contain the same address.
bool addreq(const sockaddr *sa, const in_addr_union &iau);

} // namespace ngtcp2

#endif // SHARED_H
