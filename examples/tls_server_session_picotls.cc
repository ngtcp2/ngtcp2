/*
 * ngtcp2
 *
 * Copyright (c) 2022 ngtcp2 contributors
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
#include "tls_server_session_picotls.h"

#include <cassert>
#include <iostream>

#include <ngtcp2/ngtcp2_crypto_picotls.h>

#include "tls_server_context_picotls.h"
#include "server_base.h"
#include "util.h"

using namespace ngtcp2;

extern Config config;

TLSServerSession::TLSServerSession() {}

TLSServerSession::~TLSServerSession() {}

namespace {
int collect_extension(ptls_t *ptls,
                      struct st_ptls_handshake_properties_t *properties,
                      uint16_t type) {
  return type == NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS_V1;
}
} // namespace

namespace {
int collected_extensions(ptls_t *ptls,
                         struct st_ptls_handshake_properties_t *properties,
                         ptls_raw_extension_t *extensions) {
  assert(extensions->type == NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS_V1);

  auto h = static_cast<HandlerBase *>(*ptls_get_data_ptr(ptls));
  auto conn = h->conn();

  ngtcp2_transport_params params;

  if (auto rv = ngtcp2_decode_transport_params(
          &params, NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO,
          extensions->data.base, extensions->data.len);
      rv != 0) {
    std::cerr << "ngtcp2_decode_transport_params: " << ngtcp2_strerror(rv)
              << std::endl;
    return -1;
  }

  if (auto rv = ngtcp2_conn_set_remote_transport_params(conn, &params);
      rv != 0) {
    std::cerr << "ngtcp2_conn_set_remote_transport_params: "
              << ngtcp2_strerror(rv) << std::endl;
    return -1;
  }

  return 0;
}
} // namespace

int TLSServerSession::init(TLSServerContext &tls_ctx, HandlerBase *handler) {
  cptls_.ptls = ptls_server_new(tls_ctx.get_native_handle());
  if (!cptls_.ptls) {
    std::cerr << "ptls_server_new failed" << std::endl;
    return -1;
  }

  *ptls_get_data_ptr(cptls_.ptls) = handler;

  auto &hsprops = cptls_.handshake_properties;

  hsprops.collect_extension = collect_extension;
  hsprops.collected_extensions = collected_extensions;

  return 0;
}
