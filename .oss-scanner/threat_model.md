# Threat model

## What this project does and where untrusted input enters

This is RFC 9000 QUIC implementation.  It also implements RFC 9001,
RFC 9002, RFC 9221, RFC 9287, RFC 9368, and RFC 9369.

It reads payload of UDP datagram payload from internet which is
totally untrusted.

## Components that matter most / least

The primary object is ngtcp2_conn that is created per QUIC connection.
Both read and write matter, but read should be more important because
it reads untrusted inputs.  ngtcp2 itself does not do any I/O (aka
sans-I/O).  Instead, it reads and writes pure byte string that are
read or written into UDP datagram.

- Reading UDP datagram payload: Each UDP datagram payload contains one
  or more of QUIC packets.  Each QUIC packet is encrypted.
- Writing UDP datagram payload: The library encodes QUIC packet
  header, and one or more of QUIC frames, and encrypts it.
- Congestion control: The library supports 3 congestion controllers:
  new reno, cubic (default), and BBRv3
- TLS stack integration: The library is TLS library agnostic.  It
  offers the helper library for the following TLS stacks:
  - WolfSSL
  - quictls
  - aws-lc
  - boringssl
  - openssl
  - libressl
  They are under crypto directory.
- Connection migration: QUIC allows the client to migrate the new
  address in mid connection using Connection ID.  This involves the
  address and path validation.  Connection ID retirment is also
  involved.

## How to exercise it

tests contains unit tests.  examples directory contains client and
server examples.  lib/includes/ngtcp2/ngtcp2.h contains public API
with documentation.

## How you rate severity

Any buffer overflow, use-after-free, or double free is high+ at a
minimum. If the overflow is controlled and may lead to RCE then it
should be critical. All DoS is high.

## Anything to leave alone

Do not report anything about test code that is under tests directory.
Do not report anything about the source code under
third-party/http-parser.
