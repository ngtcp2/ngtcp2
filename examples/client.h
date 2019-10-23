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

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <nghttp3/nghttp3.h>

#include <openssl/ssl.h>

#include <ev.h>

#include "network.h"
#include "template.h"
#include "shared.h"

using namespace ngtcp2;

struct Request {
  std::string scheme;
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
  uint32_t timeout;
  // session_file is a path to a file to write, and read TLS session.
  const char *session_file;
  // tp_file is a path to a file to write, and read QUIC transport
  // parameters.
  const char *tp_file;
  // show_secret is true if transport secrets should be printed out.
  bool show_secret;
  // change_local_addr is the duration after which client changes
  // local address.
  double change_local_addr;
  // key_update is the duration after which client initiates key
  // update.
  double key_update;
  // delay_stream is the duration after which client sends the first
  // 1-RTT stream.
  double delay_stream;
  // nat_rebinding is true if simulated NAT rebinding is enabled.
  bool nat_rebinding;
  // no_preferred_addr is true if client do not follow preferred
  // address offered by server.
  bool no_preferred_addr;
  std::string http_method;
  // download is a path to a directory where a downloaded file is
  // saved.  If it is empty, no file is saved.
  std::string download;
  // requests contains URIs to request.
  std::vector<Request> requests;
  // no_quic_dump is true if hexdump of QUIC STREAM and CRYPTO data
  // should be disabled.
  bool no_quic_dump;
  // no_http_dump is true if hexdump of HTTP response body should be
  // disabled.
  bool no_http_dump;
  // qlog_file is the path to write qlog.
  std::string qlog_file;
};

struct Buffer {
  Buffer(const uint8_t *data, size_t datalen);
  Buffer(uint8_t *begin, uint8_t *end);
  explicit Buffer(size_t datalen);
  Buffer();

  size_t size() const { return tail - head; }
  size_t left() const { return buf.data() + buf.size() - tail; }
  uint8_t *const wpos() { return tail; }
  const uint8_t *rpos() const { return head; }
  void seek(size_t len) { head += len; }
  void push(size_t len) { tail += len; }
  void reset() {
    head = begin;
    tail = begin;
  }
  size_t bufsize() const { return tail - begin; }

  std::vector<uint8_t> buf;
  // begin points to the beginning of the buffer.  This might point to
  // buf.data() if a buffer space is allocated by this object.  It is
  // also allowed to point to the external shared buffer.
  uint8_t *begin;
  // head points to the position of the buffer where read should
  // occur.
  uint8_t *head;
  // tail points to the position of the buffer where write should
  // occur.
  uint8_t *tail;
};

struct Stream {
  Stream(const Request &req, int64_t stream_id);
  ~Stream();

  int open_file(const std::string &path);

  Request req;
  int64_t stream_id;
  int fd;
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
  int feed_data(const sockaddr *sa, socklen_t salen, uint8_t *data,
                size_t datalen);
  int handle_expiry();
  void schedule_retransmit();
  int handshake_completed();

  void write_client_handshake(ngtcp2_crypto_level level, const uint8_t *data,
                              size_t datalen);

  int recv_crypto_data(ngtcp2_crypto_level crypto_level, const uint8_t *data,
                       size_t datalen);

  int setup_initial_crypto_context();
  ngtcp2_conn *conn() const;
  void update_remote_addr(const ngtcp2_addr *addr);
  int send_packet();
  void remove_tx_crypto_data(ngtcp2_crypto_level crypto_level, uint64_t offset,
                             size_t datalen);
  int on_stream_close(int64_t stream_id, uint64_t app_error_code);
  int on_extend_max_streams();
  int handle_error();
  void make_stream_early();
  void on_recv_retry();
  int change_local_addr();
  void start_change_local_addr_timer();
  int update_key();
  int initiate_key_update();
  void start_key_update_timer();
  void start_delay_stream_timer();

  int on_key(ngtcp2_crypto_level level, const uint8_t *rx_secret,
             const uint8_t *tx_secret, size_t secretlen);

  void set_tls_alert(uint8_t alert);

  int select_preferred_address(Address &selected_addr,
                               const ngtcp2_preferred_addr *paddr);

  int setup_httpconn();
  int submit_http_request(const Stream *stream);
  int recv_stream_data(int64_t stream_id, int fin, const uint8_t *data,
                       size_t datalen);
  int acked_stream_data_offset(int64_t stream_id, size_t datalen);
  int http_acked_stream_data(int64_t stream_id, size_t datalen);
  void http_consume(int64_t stream_id, size_t nconsumed);
  void http_write_data(int64_t stream_id, const uint8_t *data, size_t datalen);
  int on_stream_reset(int64_t stream_id);
  int extend_max_stream_data(int64_t stream_id, uint64_t max_data);
  int send_stop_sending(int64_t stream_id, uint64_t app_error_code);

  void reset_idle_timer();

  void write_qlog(const void *data, size_t datalen);

private:
  Address local_addr_;
  Address remote_addr_;
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
  Crypto crypto_[3];
  std::vector<uint8_t> tx_secret_;
  std::vector<uint8_t> rx_secret_;
  FILE *qlog_;
  ngtcp2_conn *conn_;
  nghttp3_conn *httpconn_;
  // addr_ is the server host address.
  const char *addr_;
  // port_ is the server port.
  const char *port_;
  QUICError last_error_;
  // common buffer used to store packet data before sending
  Buffer sendbuf_;
  // nstreams_done_ is the number of streams opened.
  uint64_t nstreams_done_;
  // nkey_update_ is the number of key update occurred.
  size_t nkey_update_;
  uint32_t version_;
  // early_data_ is true if client attempts to do 0RTT data transfer.
  bool early_data_;
};

#endif // CLIENT_H
