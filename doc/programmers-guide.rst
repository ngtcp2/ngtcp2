The ngtcp2 programmers' guide for early adopters
================================================

This document is written for early adopters of ngtcp2 library.  It
describes a brief introduction of programming ngtcp2.

Prerequisites
-------------

Reading QUIC transport and TLS draft helps you a lot to write QUIC
application.  They describes how TLS is integrated into QUIC and why
the existing TLS stack cannot be used with QUIC.

QUIC requires the special interface from TLS stack, which is probably
not available from most of the existing TLS stacks.  As far as I know,
the TLS stacks maintained by the active participants of QUIC working
group only get this interface at the time of this writing.  In order
to build QUIC application you have to choose one of them.  Here is the
list of TLS stacks which are supposed to provide such interface.
Please note that I only use my hacked OpenSSL.  Don't ask me how to
use other TLS libraries:

* `my OpenSSL fork
  <https://github.com/tatsuhiro-t/openssl/tree/quic-draft-15>`_
* picotls
* nss
* BoringSSL

You should use ngtcp2 draft-15 branch.  At the time of this writing,
interop is done with draft-15 or -16.

Creating ngtcp2_conn object
---------------------------

In order to start handshake, you need to first create ``ngtcp2_conn``
object.  Use `ngtcp2_conn_client_new()` for client application, and
`ngtcp2_conn_server_new()` for server.

They require ``ngtcp2_conn_callback`` and ``ngtcp2_settings`` objects.

The ``ngtcp2_conn_callback`` contains the callback functions which
``ngtcp2_conn`` calls when a specific event happens, say, receiving
stream data or stream is closed, etc.

In order to make handshake work for client application, at least the
following fields of ``ngtcp2_conn_callbacks`` must be set:

* client_initial
* recv_crypto_data
* in_encrypt
* in_decrypt
* encrypt
* decrypt
* in_encrypt_pn
* encrypt_pn
* acked_crypto_offset
* recv_retry

For server application:

* recv_client_initial
* recv_crypto_data
* in_encrypt
* in_decrypt
* encrypt
* decrypt
* in_encrypt_pn
* encrypt_pn
* acked_crypto_offset

``ngtcp2_settings`` contains the settings for QUIC connection.  All
fields must be set.  It would be very useful to enable debug logging
by setting logging function to ``log_printf`` field.  ngtcp2 library
relies on the timestamp fed from application.  The initial timestamp
must be passed to ``initial_ts`` field in nanosecond resolution.
ngtcp2 cares about the difference from that initial value.  It could
be any timestamp which increases monotonically, and actual value does
not matter.  ``max_packet_size``, ``ack_delay_component``, and
``max_ack_delay`` should be set to the draft default,
``NGTCP2_MAX_PKT_SIZE``, ``NGTCP2_DEFAULT_ACK_DELAY_EXPONENT``, and
``NGTCP2_DEFAULT_MAX_ACK_DELAY`` respectively.  Of course, you can
tweak these values if you know what you are doing.

Client application has to supply Connection IDs to
`ngtcp2_conn_client_new()`.  The *dcid* parameter is the destination
connection ID (DCID), and which should be random byte string and at
least 8 bytes long.  The *scid* is the source connection ID (SCID)
which identifies the client itself.  The *version* parameter is the
QUIC version to use.  It should be ``NGTCP2_PROTO_VER_MAX``.

Similarly, server application has to supply these parameters.  But the
*dcid* must be the same value which is received from client (which is
client SCID).  The *scid* is chosen by server.  Don't use DCID in
client packet as server SCID.  The *version* parameter is the QUIC
version to use.  It should be ``NGTCP2_PROTO_VER_MAX``.

Client application must create initial secret and derives packet
protection key and IV, and packet number encryption key.  See
https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.2

TLS integration
---------------

QUIC uses modified version of TLSv1.3.  The differences are:

* QUIC does not use TLS record layer protocol.  Each TLS message is
  directly encoded and encrypted by QUIC transport.
* QUIC does not use End of Early Data TLS message.
* QUIC does not send early (0-RTT) data through TLSv1.3 application
  message.  It is sent outside TLS.
* QUIC uses ``quic`` label instead of ``tls13`` to derive keying
  materials (this might change in the future).

QUIC has 4 types of packets: Initial, Handshake, 0-RTT Protected, and
Short.  They are encrypted with their own keys.

Initial packet is encrypted by the Initial key which is derived from
client DCID and static salt.

Handshake packet is encrypted by the Handshake key which is fed by TLS
stack.  It is the same key and IV derived from
client_handshake_traffic_secret for client and
server_handshake_traffic_secret for server.

0-RTT Protected packet is encrypted by the 0RTT key which is fed by
TLS stack.  It is the same key and IV derived from
client_early_traffic_secret.

Short packet is encrypted by the 1RTT key which is fed by TLS stack.
It is the same key and IV derived from
client_application_traffic_secret for client and
server_application_traffic_secret for server.

TLS stack has to implement the interface which notify these keying
materials.  They must be installed to `ngtcp2_conn` using the
following functions:

* `ngtcp2_conn_install_initial_tx_keys()`: Set encryption key for
  Initial packet.
* `ngtcp2_conn_install_initial_rx_keys()`: Set decryption key for
  Initial packet.
* `ngtcp2_conn_install_handshake_tx_keys()`: Set encryption key for
  Handshake packet.
* `ngtcp2_conn_install_handshake_rx_keys()`: Set decryption key for
  Handshake packet.
* `ngtcp2_conn_install_early_keys()`: Set key for 0RTT Protected
  packet for encryption and decryption.
* `ngtcp2_conn_install_tx_keys()`: Set encryption key for Short
  packet.
* `ngtcp2_conn_install_rx_keys()`: Set decryption key for Short
  packet.

Clarification of encryption and decryption keys: For client
application, encryption keys are derived from client_*_traffic_secret,
and decryption keys are derived from server_*_traffic_secret.  For
server application, encryption keys are derived from
server_*_traffic_secret, and decryption keys are derived from
client_*_traffic_secret.

After Handshake key is available, set AEAD overhead (tag length) using
`ngtcp2_conn_set_aead_overhead()` function.

`ngtcp2_conn_write_handshake()` initiates QUIC handshake.  The Initial
keys must be installed before calling this function.

For client application, it first calls
``ngtcp2_conn_callbacks.client_initial`` callback.  The callback must
ask TLS stack to produce first TLS message, which is typically
ClientHello.  The message must be passed to ``ngtcp2_conn`` object
using `ngtcp2_conn_submit_crypto_data()` function.  The function does
not own the passed data.  The application should keep the data alive
until ``ngtcp2_conn_callbacks.acked_crypto_offset`` callback tells
that the data is acknowledged by the peer and no longer used.  Next,
``ngtcp2_conn_callbacks.in_encrypt`` callback is called to tell
application to encrypt the data using AEAD_AES_128_GCM.  And then,
``ngtcp2_conn_callbacks.in_encrypt_pn`` callback is called to tell
application to encrypt the packet number using AES-CTR.  After
negotiated Handshake keys are available,
``ngtcp2_conn_callbacks.encrypt`` and
``ngtcp2_conn_callbacks.encrypt_pn`` are called instead.  Use the
negotiated cipher suites.  If ChaCha20 based cipher suite is
negotiated, ChaCha20 is used to protect packet number.

`ngtcp2_conn_read_handshake()` reads QUIC handshake packets.

For server application, it first calls
``ngtcp2_conn_callbacks.recv_client_initial`` callback.  The callback
must create the Initial key using client DCID and install it to
``ngtcp2_conn``.  The library calls
``ngtcp2_conn_callbacks.in_encrypt_pn`` callback to decrypt packet
number.  Then ``ngtcp2_conn_callbacks.in_decrypt`` callback is called
to decrypt packet payload.  ``ngtcp2_conn_callbacks.recv_crypto_data``
callback is called with the received TLS messages.  Feed them to TLS
stack.  If TLS stack produces any TLS message other than Alert, passes
them to ``ngtcp2_conn`` through `ngtcp2_conn_submit_crypto_data()`
function.  After negotiated Handshake keys are available,
``ngtcp2_conn_callbacks.encrypt_pn`` and
``ngtcp2_conn_callbacks.decrypt`` are called instead.  When peer
acknowledges TLS messages,
``ngtcp2_conn_callbacks.acked_crypto_offset`` callback is called.  The
application can throw away data acknowledged.

`ngtcp2_conn_read_handshake()` and `ngtcp2_conn_write_handshake()`
should be called until `ngtcp2_conn_get_handshake_completed()` returns
nonzero which means QUIC handshake has completed.

0RTT data transmission
----------------------

In order for client to send 0RTT data, it should use
`ngtcp2_conn_client_write_handshake()` function instead of
`ngtcp2_conn_write_handshake()`.
`ngtcp2_conn_client_write_handshake()` accepts 0RTT data to send.

Client application has to load resumed TLS session.  It also has to
set the remembered transport parameter using
`ngtcp2_conn_set_early_remote_transport_params()` function.

Before calling `ngtcp2_conn_client_write_handshake()`, client
application has to open stream to send data using
`ngtcp2_conn_open_bidi_stream()` (or `ngtcp2_conn_open_uni_stream()`
for unidirectional stream).

Stateless Retry
---------------

QUIC allows server to validate client address in a stateless manner.
When a client receives client address validation request from server,
``ngtcp2_conn_callbacks.recv_retry`` callback is called.  Most of the
retry logic is done by the library, but the client application has to
recreate TLS session from scratch to produce fresh keying materials.

0RTT data that has already passed to ``ngtcp2_conn`` is still alive.
Client application must not free them until
``ngtcp2_conn_callbacks.acked_stream_data_offset`` callback is called.

After QUIC handshake
--------------------

After QUIC handshake completed, call `ngtcp2_conn_read_pkt()` to read
incoming QUIC packets.  To write QUIC packets, call
`ngtcp2_conn_write_pkt()`.

In order to send stream data, the application has to first open a
stream.  Use `ngtcp2_conn_open_bidi_stream()` to open bidirectional
stream.  For unidirectional stream, call
`ngtcp2_conn_open_uni_stream()`.  Call `ngtcp2_conn_write_stream()` to
send stream data.

Closing connection
------------------

In order to close QUIC connection, call
`ngtcp2_conn_write_connection_close()` or
`ngtcp2_conn_write_application_close()`.

Error handling in general
-------------------------

In general, when error is returned from the ngtcp2 library function,
just close QUIC connection.

If `ngtcp2_err_is_fatal()` returns true with the returned error code,
``ngtcp2_conn`` object must be deleted with `ngtcp2_conn_del` without
any ngtcp2 library functions.  Otherwise, call
`ngtcp2_conn_write_connection_close()` to get terminal packet.
Sending it finishes QUIC connection.

The following error codes must be considered as transitional, and
application should keep connection alive:

* ``NGTCP2_ERR_EARLY_DATA_REJECTED``
* ``NGTCP2_ERR_STREAM_DATA_BLOCKED``
* ``NGTCP2_ERR_STREAM_SHUT_WR``
* ``NGTCP2_ERR_STREAM_NOT_FOUND``
* ``NGTCP2_ERR_STREAM_ID_BLOCKED``
