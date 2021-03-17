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
#ifndef SERVER_H
#define SERVER_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif // HAVE_CONFIG_H

#include <vector>
#include <unordered_map>
#include <string>
#include <deque>
#include <string_view>
#include <memory>
#include <set>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#include <ev.h>

#include "server_base.h"
#include "tls_server_context.h"
#include "network.h"
#include "shared.h"

using namespace ngtcp2;

class Handler;

struct Stream {
  Stream(int64_t stream_id, Handler *handler);

  int start_response();

  int64_t stream_id;
  Handler *handler;
  uint64_t bytes_left;
  std::array<uint8_t, sizeof(uint64_t)> data;
  size_t datalen;
};

struct StreamIDLess {
  constexpr bool operator()(const Stream *lhs, const Stream *rhs) const {
    return lhs->stream_id < rhs->stream_id;
  }
};

class Server;

// Endpoint is a local endpoint.
struct Endpoint {
  Address addr;
  ev_io rev;
  Server *server;
  int fd;
  // ecn is the last ECN bits set to fd.
  unsigned int ecn;
};

class Handler : public HandlerBase {
public:
  Handler(struct ev_loop *loop, Server *server, const ngtcp2_cid *rcid);
  ~Handler();

  int init(const Endpoint &ep, const Address &local_addr, const sockaddr *sa,
           socklen_t salen, const ngtcp2_cid *dcid, const ngtcp2_cid *scid,
           const ngtcp2_cid *ocid, const uint8_t *token, size_t tokenlen,
           uint32_t version, const TLSServerContext &tls_ctx);

  int on_read(const Endpoint &ep, const Address &local_addr, const sockaddr *sa,
              socklen_t salen, const ngtcp2_pkt_info *pi, uint8_t *data,
              size_t datalen);
  int on_write();
  int write_streams();
  int feed_data(const Endpoint &ep, const Address &local_addr,
                const sockaddr *sa, socklen_t salen, const ngtcp2_pkt_info *pi,
                uint8_t *data, size_t datalen);
  void schedule_retransmit();
  int handle_expiry();
  void signal_write();
  int handshake_completed();

  Server *server() const;
  int recv_stream_data(uint32_t flags, int64_t stream_id, const uint8_t *data,
                       size_t datalen);
  const ngtcp2_cid *scid() const;
  const ngtcp2_cid *pscid() const;
  const ngtcp2_cid *rcid() const;
  uint32_t version() const;
  void on_stream_open(int64_t stream_id);
  int on_stream_close(int64_t stream_id, uint64_t app_error_code);
  void start_draining_period();
  int start_closing_period();
  bool draining() const;
  int handle_error();
  int send_conn_close();

  int update_key(uint8_t *rx_secret, uint8_t *tx_secret,
                 ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv,
                 ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
                 const uint8_t *current_rx_secret,
                 const uint8_t *current_tx_secret, size_t secretlen);

  Stream *find_stream(int64_t stream_id);
  int extend_max_stream_data(int64_t stream_id, uint64_t max_data);
  void shutdown_read(int64_t stream_id, int app_error_code);

  void reset_idle_timer();

  void write_qlog(const void *data, size_t datalen);
  void singal_write();
  void add_sendq(Stream *stream);

private:
  size_t max_pktlen_;
  struct ev_loop *loop_;
  Server *server_;
  ev_io wev_;
  ev_timer timer_;
  ev_timer rttimer_;
  FILE *qlog_;
  ngtcp2_cid scid_;
  ngtcp2_cid pscid_;
  ngtcp2_cid rcid_;
  std::unordered_map<int64_t, std::unique_ptr<Stream>> streams_;
  std::set<Stream *, StreamIDLess> sendq_;
  // conn_closebuf_ contains a packet which contains CONNECTION_CLOSE.
  // This packet is repeatedly sent as a response to the incoming
  // packet in draining period.
  std::unique_ptr<Buffer> conn_closebuf_;
  // nkey_update_ is the number of key update occurred.
  size_t nkey_update_;
  // draining_ becomes true when draining period starts.
  bool draining_;
};

class Server {
public:
  Server(struct ev_loop *loop, const TLSServerContext &tls_ctx);
  ~Server();

  int init(const char *addr, const char *port);
  void disconnect();
  void close();

  int on_read(Endpoint &ep);
  int send_version_negotiation(uint32_t version, const uint8_t *dcid,
                               size_t dcidlen, const uint8_t *scid,
                               size_t scidlen, Endpoint &ep,
                               const Address &local_addr, const sockaddr *sa,
                               socklen_t salen);
  int send_retry(const ngtcp2_pkt_hd *chd, Endpoint &ep,
                 const Address &local_addr, const sockaddr *sa,
                 socklen_t salen);
  int send_stateless_connection_close(const ngtcp2_pkt_hd *chd, Endpoint &ep,
                                      const Address &local_addr,
                                      const sockaddr *sa, socklen_t salen);
  int generate_retry_token(uint8_t *token, size_t &tokenlen, const sockaddr *sa,
                           socklen_t salen, const ngtcp2_cid *scid,
                           const ngtcp2_cid *ocid);
  int verify_retry_token(ngtcp2_cid *ocid, const ngtcp2_pkt_hd *hd,
                         const sockaddr *sa, socklen_t salen);
  int generate_token(uint8_t *token, size_t &tokenlen, const sockaddr *sa);
  int verify_token(const ngtcp2_pkt_hd *hd, const sockaddr *sa,
                   socklen_t salen);
  int send_packet(Endpoint &ep, const ngtcp2_addr &local_addr,
                  const ngtcp2_addr &remote_addr, unsigned int ecn,
                  const uint8_t *data, size_t datalen, size_t gso_size);
  void remove(const Handler *h);

  int derive_token_key(uint8_t *key, size_t &keylen, uint8_t *iv, size_t &ivlen,
                       const uint8_t *rand_data, size_t rand_datalen);
  void generate_rand_data(uint8_t *buf, size_t len);
  void associate_cid(const ngtcp2_cid *cid, Handler *h);
  void dissociate_cid(const ngtcp2_cid *cid);

private:
  std::unordered_map<std::string, std::unique_ptr<Handler>> handlers_;
  // ctos_ is a mapping between client's initial destination
  // connection ID, and server source connection ID.
  std::unordered_map<std::string, std::string> ctos_;
  struct ev_loop *loop_;
  std::vector<Endpoint> endpoints_;
  const TLSServerContext &tls_ctx_;
  ngtcp2_crypto_aead token_aead_;
  ngtcp2_crypto_md token_md_;
  ev_signal sigintev_;
};

#endif // SERVER_H
