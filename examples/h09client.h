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
#ifndef H09CLIENT_H
#define H09CLIENT_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif // HAVE_CONFIG_H

#include <vector>
#include <deque>
#include <map>
#include <string_view>
#include <set>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#include <nghttp3/nghttp3.h>

#include <openssl/ssl.h>

#include <ev.h>

#include "network.h"
#include "shared.h"

using namespace ngtcp2;

struct Request {
  std::string_view scheme;
  std::string authority;
  std::string path;
};

struct Config {
  ngtcp2_cid dcid;
  // tx_loss_prob is probability of losing outgoing packet.
  double tx_loss_prob;
  // rx_loss_prob is probability of losing incoming packet.
  double rx_loss_prob;
  // fd is a file descriptor to read input for streams.
  int fd;
  // ciphers is the list of enabled ciphers.
  const char *ciphers;
  // groups is the list of supported groups.
  const char *groups;
  // nstreams is the number of streams to open.
  size_t nstreams;
  // data is the pointer to memory region which maps file denoted by
  // fd.
  uint8_t *data;
  // datalen is the length of file denoted by fd.
  size_t datalen;
  // version is a QUIC version to use.
  uint32_t version;
  // quiet suppresses the output normally shown except for the error
  // messages.
  bool quiet;
  // timeout is an idle timeout for QUIC connection.
  ngtcp2_duration timeout;
  // session_file is a path to a file to write, and read TLS session.
  const char *session_file;
  // tp_file is a path to a file to write, and read QUIC transport
  // parameters.
  const char *tp_file;
  // show_secret is true if transport secrets should be printed out.
  bool show_secret;
  // change_local_addr is the duration after which client changes
  // local address.
  ngtcp2_duration change_local_addr;
  // key_update is the duration after which client initiates key
  // update.
  ngtcp2_duration key_update;
  // delay_stream is the duration after which client sends the first
  // 1-RTT stream.
  ngtcp2_duration delay_stream;
  // nat_rebinding is true if simulated NAT rebinding is enabled.
  bool nat_rebinding;
  // no_preferred_addr is true if client do not follow preferred
  // address offered by server.
  bool no_preferred_addr;
  std::string_view http_method;
  // download is a path to a directory where a downloaded file is
  // saved.  If it is empty, no file is saved.
  std::string_view download;
  // requests contains URIs to request.
  std::vector<Request> requests;
  // no_quic_dump is true if hexdump of QUIC STREAM and CRYPTO data
  // should be disabled.
  bool no_quic_dump;
  // no_http_dump is true if hexdump of HTTP response body should be
  // disabled.
  bool no_http_dump;
  // qlog_file is the path to write qlog.
  std::string_view qlog_file;
  // qlog_dir is the path to directory where qlog is stored.  qlog_dir
  // and qlog_file are mutually exclusive.
  std::string_view qlog_dir;
  // max_data is the initial connection-level flow control window.
  uint64_t max_data;
  // max_stream_data_bidi_local is the initial stream-level flow
  // control window for a bidirectional stream that the local endpoint
  // initiates.
  uint64_t max_stream_data_bidi_local;
  // max_stream_data_bidi_remote is the initial stream-level flow
  // control window for a bidirectional stream that the remote
  // endpoint initiates.
  uint64_t max_stream_data_bidi_remote;
  // max_stream_data_uni is the initial stream-level flow control
  // window for a unidirectional stream.
  uint64_t max_stream_data_uni;
  // max_streams_bidi is the number of the concurrent bidirectional
  // streams.
  uint64_t max_streams_bidi;
  // max_streams_uni is the number of the concurrent unidirectional
  // streams.
  uint64_t max_streams_uni;
  // exit_on_first_stream_close is the flag that if it is true, client
  // exits when a first HTTP stream gets closed.  It is not
  // necessarily the same time when the underlying QUIC stream closes
  // due to the QPACK synchronization.
  bool exit_on_first_stream_close;
  // exit_on_all_streams_close is the flag that if it is true, client
  // exits when all HTTP streams get closed.
  bool exit_on_all_streams_close;
  // disable_early_data disables early data.
  bool disable_early_data;
  // static_secret is used to derive keying materials for Stateless
  // Retry token.
  std::array<uint8_t, 32> static_secret;
  // cc is the congestion controller algorithm.
  std::string_view cc;
  // token_file is a path to file to read or write token from
  // NEW_TOKEN frame.
  std::string_view token_file;
  // sni is the value sent in TLS SNI, overriding DNS name of the
  // remote host.
  std::string_view sni;
  // initial_rtt is an initial RTT.
  ngtcp2_duration initial_rtt;
};

struct Buffer {
  Buffer(const uint8_t *data, size_t datalen);
  explicit Buffer(size_t datalen);

  size_t size() const { return tail - buf.data(); }
  size_t left() const { return buf.data() + buf.size() - tail; }
  uint8_t *const wpos() { return tail; }
  const uint8_t *rpos() const { return buf.data(); }
  void push(size_t len) { tail += len; }
  void reset() { tail = buf.data(); }

  std::vector<uint8_t> buf;
  // tail points to the position of the buffer where write should
  // occur.
  uint8_t *tail;
};

struct Stream {
  Stream(const Request &req, int64_t stream_id);
  ~Stream();

  int open_file(const std::string_view &path);

  Request req;
  int64_t stream_id;
  int fd;
  std::string rawreqbuf;
  nghttp3_buf reqbuf;
};

struct StreamIDLess {
  constexpr bool operator()(const Stream *lhs, const Stream *rhs) const {
    return lhs->stream_id < rhs->stream_id;
  }
};

struct Crypto {
  /* data is unacknowledged data. */
  std::deque<Buffer> data;
  /* acked_offset is the size of acknowledged crypto data removed from
     |data| so far */
  uint64_t acked_offset;
};

class Client {
public:
  Client(struct ev_loop *loop, SSL_CTX *ssl_ctx);
  ~Client();

  int init(int fd, const Address &local_addr, const Address &remote_addr,
           const char *addr, const char *port, uint32_t version);
  int init_ssl();
  void disconnect();
  void close();

  void start_wev();

  int on_read();
  int on_write();
  int write_streams();
  int feed_data(const sockaddr *sa, socklen_t salen, const ngtcp2_pkt_info *pi,
                uint8_t *data, size_t datalen);
  int handle_expiry();
  void schedule_retransmit();
  int handshake_completed();

  void write_client_handshake(ngtcp2_crypto_level level, const uint8_t *data,
                              size_t datalen);

  int recv_crypto_data(ngtcp2_crypto_level crypto_level, const uint8_t *data,
                       size_t datalen);

  ngtcp2_conn *conn() const;
  void update_remote_addr(const ngtcp2_addr *addr, const ngtcp2_pkt_info *pi);
  int send_packet();
  void remove_tx_crypto_data(ngtcp2_crypto_level crypto_level, uint64_t offset,
                             uint64_t datalen);
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

  int on_key(ngtcp2_crypto_level level, const uint8_t *rx_secret,
             const uint8_t *tx_secret, size_t secretlen);

  void set_tls_alert(uint8_t alert);

  int select_preferred_address(Address &selected_addr,
                               const ngtcp2_preferred_addr *paddr);

  int submit_http_request(Stream *stream);
  int recv_stream_data(uint32_t flags, int64_t stream_id, const uint8_t *data,
                       size_t datalen);
  int acked_stream_data_offset(int64_t stream_id, uint64_t offset,
                               uint64_t datalen);
  int extend_max_stream_data(int64_t stream_id, uint64_t max_data);

  void reset_idle_timer();

  void write_qlog(const void *data, size_t datalen);

  void idle_timeout();

private:
  Address local_addr_;
  Address remote_addr_;
  unsigned int ecn_;
  size_t max_pktlen_;
  ev_io wev_;
  ev_io rev_;
  ev_timer timer_;
  ev_timer rttimer_;
  ev_timer change_local_addr_timer_;
  ev_timer key_update_timer_;
  ev_timer delay_stream_timer_;
  ev_signal sigintev_;
  struct ev_loop *loop_;
  SSL_CTX *ssl_ctx_;
  SSL *ssl_;
  int fd_;
  std::map<int64_t, std::unique_ptr<Stream>> streams_;
  std::set<Stream *, StreamIDLess> sendq_;
  Crypto crypto_[3];
  FILE *qlog_;
  ngtcp2_conn *conn_;
  // addr_ is the server host address.
  const char *addr_;
  // port_ is the server port.
  const char *port_;
  QUICError last_error_;
  // common buffer used to store packet data before sending
  Buffer sendbuf_;
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
};

#endif // CLIENT_H
