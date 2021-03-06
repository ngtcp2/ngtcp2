/*
 * ngtcp2
 *
 * Copyright (c) 2019 ngtcp2 contributors
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
#include "shared.h"

#include <nghttp3/nghttp3.h>

#include <cstring>
#include <cassert>
#include <iostream>

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif // HAVE_NETINET_IN_H

namespace ngtcp2 {

QUICError quic_err_transport(int liberr) {
  if (liberr == NGTCP2_ERR_RECV_VERSION_NEGOTIATION) {
    return {QUICErrorType::TransportVersionNegotiation, 0};
  }
  return {QUICErrorType::Transport,
          ngtcp2_err_infer_quic_transport_error_code(liberr)};
}

QUICError quic_err_idle_timeout() {
  return {QUICErrorType::TransportIdleTimeout, 0};
}

QUICError quic_err_tls(int alert) {
  return {QUICErrorType::Transport,
          static_cast<uint64_t>(NGTCP2_CRYPTO_ERROR | alert)};
}

QUICError quic_err_app(int liberr) {
  return {QUICErrorType::Application,
          nghttp3_err_infer_quic_app_error_code(liberr)};
}

unsigned int msghdr_get_ecn(msghdr *msg, int family) {
  switch (family) {
  case AF_INET:
    for (auto cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
      if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS &&
          cmsg->cmsg_len) {
        return *reinterpret_cast<uint8_t *>(CMSG_DATA(cmsg));
      }
    }
    break;
  case AF_INET6:
    for (auto cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
      if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_TCLASS &&
          cmsg->cmsg_len) {
        return *reinterpret_cast<uint8_t *>(CMSG_DATA(cmsg));
      }
    }
    break;
  }

  return 0;
}

void fd_set_ecn(int fd, int family, unsigned int ecn) {
  switch (family) {
  case AF_INET:
    if (setsockopt(fd, IPPROTO_IP, IP_TOS, &ecn,
                   static_cast<socklen_t>(sizeof(ecn))) == -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
    }
    break;
  case AF_INET6:
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &ecn,
                   static_cast<socklen_t>(sizeof(ecn))) == -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
    }
    break;
  }
}

void fd_set_recv_ecn(int fd, int family) {
  unsigned int tos = 1;
  switch (family) {
  case AF_INET:
    if (setsockopt(fd, IPPROTO_IP, IP_RECVTOS, &tos,
                   static_cast<socklen_t>(sizeof(tos))) == -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
    }
    break;
  case AF_INET6:
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVTCLASS, &tos,
                   static_cast<socklen_t>(sizeof(tos))) == -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
    }
    break;
  }
}

std::optional<Address> msghdr_get_local_addr(msghdr *msg, int family) {
  switch (family) {
  case AF_INET:
    for (auto cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
      if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
        auto pktinfo = reinterpret_cast<in_pktinfo *>(CMSG_DATA(cmsg));
        Address res{};
        res.ifindex = pktinfo->ipi_ifindex;
        res.len = sizeof(res.su.in);
        auto &sa = res.su.in;
        sa.sin_family = AF_INET;
        sa.sin_addr = pktinfo->ipi_addr;
        return res;
      }
    }
    return {};
  case AF_INET6:
    for (auto cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
      if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
        auto pktinfo = reinterpret_cast<in6_pktinfo *>(CMSG_DATA(cmsg));
        Address res{};
        res.ifindex = pktinfo->ipi6_ifindex;
        res.len = sizeof(res.su.in6);
        auto &sa = res.su.in6;
        sa.sin6_family = AF_INET6;
        sa.sin6_addr = pktinfo->ipi6_addr;
        return res;
      }
    }
    return {};
  }
  return {};
}

void set_port(Address &dst, Address &src) {
  switch (dst.su.storage.ss_family) {
  case AF_INET:
    assert(AF_INET == src.su.storage.ss_family);
    dst.su.in.sin_port = src.su.in.sin_port;
    return;
  case AF_INET6:
    assert(AF_INET6 == src.su.storage.ss_family);
    dst.su.in6.sin6_port = src.su.in6.sin6_port;
    return;
  default:
    assert(0);
  }
}

} // namespace ngtcp2
