/*
 * ngtcp2
 *
 * Copyright (c) 2026 ngtcp2 contributors
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
#include "schannel_common.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  const char *port = argc > 2 ? argv[2] : "4433";
  struct addrinfo hints = {0}, *addresses = NULL, *address;
  struct sockaddr_storage local_addr, remote_addr;
  socklen_t local_addrlen = sizeof(local_addr);
  socklen_t remote_addrlen = sizeof(remote_addr);
  schannel_example_credential credential;
  schannel_example_endpoint endpoint;
  ngtcp2_pkt_hd hd;
  WSADATA wsadata;
  SOCKET fd = INVALID_SOCKET;
  uint8_t packet[65536];
  ngtcp2_tstamp started;
  int nread;
  int rv = EXIT_FAILURE;

  if (argc < 2 || argc > 3) {
    fprintf(stderr, "Usage: %s certificate-thumbprint [port]\n", argv[0]);
    return EXIT_FAILURE;
  }
  if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0) {
    return EXIT_FAILURE;
  }
  if (schannel_example_server_credential_new(&credential, argv[1]) != 0) {
    fprintf(stderr,
            "Could not find the certificate or acquire server credentials\n");
    goto cleanup_wsa;
  }

  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;
  if (getaddrinfo(NULL, port, &hints, &addresses) != 0) {
    fprintf(stderr, "Could not resolve UDP port %s\n", port);
    goto cleanup_credential;
  }
  for (address = addresses; address != NULL; address = address->ai_next) {
    fd = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
    if (fd == INVALID_SOCKET) {
      continue;
    }
    if (bind(fd, address->ai_addr, (int)address->ai_addrlen) == 0) {
      break;
    }
    closesocket(fd);
    fd = INVALID_SOCKET;
  }
  if (address == NULL ||
      getsockname(fd, (struct sockaddr *)&local_addr, &local_addrlen) != 0) {
    fprintf(stderr, "Could not bind UDP port %s: %d\n", port,
            WSAGetLastError());
    goto cleanup_addresses;
  }

  printf("Listening on UDP port %s\n", port);
  nread = recvfrom(fd, (char *)packet, sizeof(packet), 0,
                   (struct sockaddr *)&remote_addr, &remote_addrlen);
  if (nread == SOCKET_ERROR ||
      ngtcp2_accept(&hd, packet, (size_t)nread) != 0 ||
      hd.type != NGTCP2_PKT_INITIAL) {
    fprintf(stderr, "The first datagram is not a valid QUIC Initial packet\n");
    goto cleanup_addresses;
  }
  if (schannel_example_server_new(
        &endpoint, &credential, &hd, (const struct sockaddr *)&local_addr,
        local_addrlen, (const struct sockaddr *)&remote_addr,
        remote_addrlen) != 0) {
    fprintf(stderr, "Could not create QUIC server connection\n");
    goto cleanup_addresses;
  }
  if (schannel_example_read(&endpoint, packet, (size_t)nread) != 0) {
    goto cleanup_endpoint;
  }

  started = schannel_example_timestamp();
  while (!endpoint.handshake_completed &&
         schannel_example_timestamp() - started < SCHANNEL_EXAMPLE_TIMEOUT) {
    fd_set readfds;
    struct timeval timeout = {0, 50000};
    int selected;

    if (schannel_example_write(&endpoint, fd) != 0) {
      goto cleanup_endpoint;
    }
    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);
    selected = select(0, &readfds, NULL, NULL, &timeout);
    if (selected == SOCKET_ERROR) {
      fprintf(stderr, "select: %d\n", WSAGetLastError());
      goto cleanup_endpoint;
    }
    if (selected > 0) {
      remote_addrlen = sizeof(remote_addr);
      nread = recvfrom(fd, (char *)packet, sizeof(packet), 0,
                       (struct sockaddr *)&remote_addr, &remote_addrlen);
      if (nread == SOCKET_ERROR ||
          schannel_example_read(&endpoint, packet, (size_t)nread) != 0) {
        goto cleanup_endpoint;
      }
    }
    if (schannel_example_handle_expiry(&endpoint) != 0) {
      goto cleanup_endpoint;
    }
  }

  if (!endpoint.handshake_completed) {
    fprintf(stderr, "Handshake timed out\n");
    goto cleanup_endpoint;
  }
  schannel_example_print_result(&endpoint);
  rv = EXIT_SUCCESS;

cleanup_endpoint:
  schannel_example_endpoint_del(&endpoint);
cleanup_addresses:
  if (fd != INVALID_SOCKET) {
    closesocket(fd);
  }
  freeaddrinfo(addresses);
cleanup_credential:
  schannel_example_credential_del(&credential);
cleanup_wsa:
  WSACleanup();
  return rv;
}
