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
#include <config.h>
#endif // HAVE_CONFIG_H

#include <vector>
#include <deque>
#include <map>

#include <ngtcp2/ngtcp2.h>

#include <openssl/ssl.h>

#include <ev.h>

#include "network.h"
#include "crypto.h"
#include "template.h"

using namespace ngtcp2;

struct Config {
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
  // interactive is true if interactive input mode is on.
  bool interactive;
};

struct Buffer {
  Buffer(const uint8_t *data, size_t datalen);
  explicit Buffer(size_t datalen);
  Buffer();

  size_t size() const { return tail - head; }
  size_t left() const { return buf.size() - tail; }
  uint8_t *const wpos() { return &buf[tail]; }
  const uint8_t *rpos() const { return &buf[head]; }
  void seek(size_t len) { head += len; }
  void push(size_t len) { tail += len; }
  void reset() {
    head = 0;
    tail = 0;
  }

  std::vector<uint8_t> buf;
  size_t head;
  size_t tail;
};

struct Stream {
  Stream(uint32_t stream_id);
  ~Stream();

  int buffer_file();

  uint32_t stream_id;
  std::deque<Buffer> streambuf;
  // streambuf_idx is the index in streambuf, which points to the
  // buffer to send next.
  size_t streambuf_idx;
  // tx_stream_offset is the offset where all data before offset is
  // acked by the remote endpoint.
  uint64_t tx_stream_offset;
  bool should_send_fin;
  int fd;
};

class Client {
public:
  Client(struct ev_loop *loop, SSL_CTX *ssl_ctx);
  ~Client();

  int init(int fd, const Address &remote_addr, const char *addr, int datafd);
  void disconnect();
  void disconnect(int liberr);
  void close();

  int tls_handshake();
  int on_read();
  int on_write();
  int on_write_stream(uint32_t stream_id, uint8_t fin, Buffer &data);
  int feed_data(uint8_t *data, size_t datalen);
  void schedule_retransmit();

  int write_client_handshake(const uint8_t *data, size_t datalen);
  size_t read_client_handshake(const uint8_t **pdest);

  size_t read_server_handshake(uint8_t *buf, size_t buflen);
  void write_server_handshake(const uint8_t *data, size_t datalen);

  int setup_crypto_context();
  ssize_t encrypt_data(uint8_t *dest, size_t destlen, const uint8_t *plaintext,
                       size_t plaintextlen, const uint8_t *key, size_t keylen,
                       const uint8_t *nonce, size_t noncelen, const uint8_t *ad,
                       size_t adlen);
  ssize_t decrypt_data(uint8_t *dest, size_t destlen, const uint8_t *ciphertext,
                       size_t ciphertextlen, const uint8_t *key, size_t keylen,
                       const uint8_t *nonce, size_t noncelen, const uint8_t *ad,
                       size_t adlen);
  ngtcp2_conn *conn() const;
  int send_packet();
  int start_interactive_input();
  int send_interactive_input();
  int stop_interactive_input();
  void remove_tx_stream_data(uint32_t stream_id, uint64_t offset,
                             size_t datalen);
  void on_stream_close(uint32_t stream_id, uint32_t error_code);
  int on_extend_max_stream_id(uint32_t max_stream_id);
  int handle_error(int liberr);

private:
  Address remote_addr_;
  size_t max_pktlen_;
  ev_io wev_;
  ev_io rev_;
  ev_io stdinrev_;
  ev_timer timer_;
  ev_timer rttimer_;
  ev_signal sigintev_;
  struct ev_loop *loop_;
  SSL_CTX *ssl_ctx_;
  SSL *ssl_;
  int fd_;
  int datafd_;
  std::map<uint32_t, std::unique_ptr<Stream>> streams_;
  std::deque<Buffer> chandshake_;
  // chandshake_idx_ is the index in chandshake_, which points to the
  // buffer to read next.
  size_t chandshake_idx_;
  uint64_t tx_stream0_offset_;
  std::vector<uint8_t> shandshake_;
  size_t nsread_;
  ngtcp2_conn *conn_;
  crypto::Context crypto_ctx_;
  // common buffer used to store packet data before sending
  Buffer sendbuf_;
  uint32_t next_stream_id_;
  uint32_t max_stream_id_;
};

#endif // CLIENT_H
