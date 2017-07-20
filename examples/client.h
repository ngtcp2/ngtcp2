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
  // fd is a file descriptor to read input for stream 1.
  int fd;
};

class Client {
public:
  Client(struct ev_loop *loop, SSL_CTX *ssl_ctx);
  ~Client();

  int init(int fd, const Address &remote_addr, const char *addr, int stdinfd);
  void disconnect();

  int tls_handshake();
  int on_read();
  int on_write();
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
  int start_interactive_input();
  int send_interactive_input();
  int stop_interactive_input();

private:
  Address remote_addr_;
  size_t max_pktlen_;
  ev_io wev_;
  ev_io rev_;
  ev_io stdinrev_;
  ev_timer timer_;
  ev_timer rttimer_;
  struct ev_loop *loop_;
  SSL_CTX *ssl_ctx_;
  SSL *ssl_;
  int fd_;
  int stdinfd_;
  uint32_t stream_id_;
  std::vector<uint8_t> chandshake_;
  size_t ncread_;
  std::vector<uint8_t> shandshake_;
  size_t nsread_;
  ngtcp2_conn *conn_;
  crypto::Context crypto_ctx_;
  std::array<uint8_t, 32_k> streambuf_;
  size_t stream_offset_;
};

#endif // CLIENT_H
