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
#ifndef CLIENT_H
#define CLIENT_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif // HAVE_CONFIG_H

#include <vector>
#include <deque>
#include <map>
#include <string_view>
#include <memory>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <nghttp3/nghttp3.h>

#include <ev.h>

#include "client_base.h"
#include "tls_client_context.h"
#include "tls_client_session.h"
#include "network.h"
#include "shared.h"

using namespace ngtcp2;

struct Stream {
  Stream(const Request &req, int64_t stream_id);
  ~Stream();

  int open_file(const std::string_view &path);

  Request req;
  int64_t stream_id;
  int fd;
};

class Client;

struct Endpoint {
  Address addr;
  ev_io rev;
  Client *client;
  int fd;
};

class Client : public ClientBase {
public:
  Client(struct ev_loop *loop);
  ~Client();

  int init(int fd, const Address &local_addr, const Address &remote_addr,
           const char *addr, const char *port, uint32_t version,
           const TLSClientContext &tls_ctx);
  void disconnect();

  void start_wev();

  int on_read(const Endpoint &ep);
  int on_write();
  int write_streams();
  int feed_data(const Endpoint &ep, const sockaddr *sa, socklen_t salen,
                const ngtcp2_pkt_info *pi, uint8_t *data, size_t datalen);
  int handle_expiry();
  void schedule_retransmit();
  int handshake_completed();
  int handshake_confirmed();

  int send_packet(const Endpoint &ep, const ngtcp2_addr &remote_addr,
                  unsigned int ecn, const uint8_t *data, size_t datalen);
  int on_stream_close(int64_t stream_id, uint64_t app_error_code);
  int on_extend_max_streams();
  int handle_error();
  int make_stream_early();
  int change_local_addr();
  void start_change_local_addr_timer();
  int update_key(uint8_t *rx_secret, uint8_t *tx_secret,
                 ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv,
                 ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
                 const uint8_t *current_rx_secret,
                 const uint8_t *current_tx_secret, size_t secretlen);
  int initiate_key_update();
  void start_key_update_timer();
  void start_delay_stream_timer();

  int select_preferred_address(Address &selected_addr,
                               const ngtcp2_preferred_addr *paddr);

  int setup_httpconn();
  int submit_http_request(const Stream *stream);
  int recv_stream_data(uint32_t flags, int64_t stream_id, const uint8_t *data,
                       size_t datalen);
  int acked_stream_data_offset(int64_t stream_id, uint64_t datalen);
  int http_acked_stream_data(int64_t stream_id, size_t datalen);
  void http_consume(int64_t stream_id, size_t nconsumed);
  void http_write_data(int64_t stream_id, const uint8_t *data, size_t datalen);
  int on_stream_reset(int64_t stream_id);
  int extend_max_stream_data(int64_t stream_id, uint64_t max_data);
  int send_stop_sending(int64_t stream_id, uint64_t app_error_code);
  int http_stream_close(int64_t stream_id, uint64_t app_error_code);

  void reset_idle_timer();

  void idle_timeout();

private:
  std::vector<Endpoint> endpoints_;
  Address remote_addr_;
  size_t max_pktlen_;
  ev_io wev_;
  ev_timer timer_;
  ev_timer rttimer_;
  ev_timer change_local_addr_timer_;
  ev_timer key_update_timer_;
  ev_timer delay_stream_timer_;
  ev_signal sigintev_;
  struct ev_loop *loop_;
  std::map<int64_t, std::unique_ptr<Stream>> streams_;
  nghttp3_conn *httpconn_;
  // addr_ is the server host address.
  const char *addr_;
  // port_ is the server port.
  const char *port_;
  // nstreams_done_ is the number of streams opened.
  size_t nstreams_done_;
  // nstreams_closed_ is the number of streams get closed.
  size_t nstreams_closed_;
  // nkey_update_ is the number of key update occurred.
  size_t nkey_update_;
  uint32_t version_;
  // early_data_ is true if client attempts to do 0RTT data transfer.
  bool early_data_;
  // should_exit_ is true if client should exit rather than waiting
  // for timeout.
  bool should_exit_;
  // handshake_confirmed_ gets true after handshake has been
  // confirmed.
  bool handshake_confirmed_;
};

#endif // CLIENT_H
