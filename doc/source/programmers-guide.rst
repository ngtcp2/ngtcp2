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
list of TLS stacks which are supposed to provide such interface and
for which we provide crypto helper libraries:

* `OpenSSL with QUIC support
  <https://github.com/quictls/openssl/tree/OpenSSL_1_1_1j+quic>`_
* GnuTLS >= 3.7.0
* BoringSSL

Creating ngtcp2_conn object
---------------------------

:type:`ngtcp2_conn` is the primary object to present a single QUIC
connection.  Use `ngtcp2_conn_client_new()` for client application,
and `ngtcp2_conn_server_new()` for server.

They require :type:`ngtcp2_callbacks`, :type:`ngtcp2_settings`, and
:type:`ngtcp2_transport_params` objects.

The :type:`ngtcp2_callbacks` contains the callback functions which
:type:`ngtcp2_conn` calls when a specific event happens, say,
receiving stream data or stream is closed, etc.  Some of the callback
functions are optional.  For client application, the following
callback functions must be set:

* :member:`client_initial <ngtcp2_callbacks.client_initial>`:
  `ngtcp2_crypto_client_initial_cb()` can be passed directly.
* :member:`recv_crypto_data <ngtcp2_callbacks.recv_crypto_data>`:
  `ngtcp2_crypto_recv_crypto_data_cb()` can be passed directly.
* :member:`encrypt <ngtcp2_callbacks.encrypt>`:
  `ngtcp2_crypto_encrypt_cb()` can be passed directly.
* :member:`decrypt <ngtcp2_callbacks.decrypt>`:
  `ngtcp2_crypto_decrypt_cb()` can be passed directly.
* :member:`hp_mask <ngtcp2_callbacks.hp_mask>`:
  `ngtcp2_crypto_hp_mask_cb()` can be passed directly.
* :member:`recv_retry <ngtcp2_callbacks.recv_retry>`:
  `ngtcp2_crypto_recv_retry_cb()` can be passed directly.
* :member:`rand <ngtcp2_callbacks.rand>`
* :member:`get_new_connection_id
  <ngtcp2_callbacks.get_new_connection_id>`
* :member:`update_key <ngtcp2_callbacks.update_key>`:
  `ngtcp2_crypto_update_key_cb()` can be passed directly.
* :member:`delete_crypto_aead_ctx
  <ngtcp2_callbacks.delete_crypto_aead_ctx>`:
  `ngtcp2_crypto_delete_crypto_aead_ctx_cb()` can be passed directly.
* :member:`delete_crypto_cipher_ctx
  <ngtcp2_callbacks.delete_crypto_cipher_ctx>`:
  `ngtcp2_crypto_delete_crypto_cipher_ctx_cb()` can be passed
  directly.

For server application, the following callback functions must be set:

* :member:`recv_client_initial
  <ngtcp2_callbacks.recv_client_initial>`:
  `ngtcp2_crypto_recv_client_initial_cb()` can be passed directly.
* :member:`recv_crypto_data <ngtcp2_callbacks.recv_crypto_data>`:
  `ngtcp2_crypto_recv_crypto_data_cb()` can be passed directly.
* :member:`encrypt <ngtcp2_callbacks.encrypt>`:
  `ngtcp2_crypto_encrypt_cb()` can be passed directly.
* :member:`decrypt <ngtcp2_callbacks.decrypt>`:
  `ngtcp2_crypto_decrypt_cb()` can be passed directly.
* :member:`hp_mask <ngtcp2_callbacks.hp_mask>`:
  `ngtcp2_crypto_hp_mask_cb()` can be passed directly.
* :member:`rand <ngtcp2_callbacks.rand>`
* :member:`get_new_connection_id
  <ngtcp2_callbacks.get_new_connection_id>`
* :member:`update_key <ngtcp2_callbacks.update_key>`:
  `ngtcp2_crypto_update_key_cb()` can be passed directly.
* :member:`delete_crypto_aead_ctx
  <ngtcp2_callbacks.delete_crypto_aead_ctx>`:
  `ngtcp2_crypto_delete_crypto_aead_ctx_cb()` can be passed directly.
* :member:`delete_crypto_cipher_ctx
  <ngtcp2_callbacks.delete_crypto_cipher_ctx>`:
  `ngtcp2_crypto_delete_crypto_cipher_ctx_cb()` can be passed
  directly.

``ngtcp2_crypto_*`` functions are a part of :doc:`ngtcp2 crypto API
<crypto_apiref>` which provides easy integration with the supported
TLS backend.  It vastly simplifies TLS integration and is strongly
recommended.

:type:`ngtcp2_settings` contains the settings for QUIC connection.
All fields must be set.  Application should call
`ngtcp2_settings_default()` to set the default values.  It would be
very useful to enable debug logging by setting logging function to
:member:`ngtcp2_settings.log_printf` field.  ngtcp2 library relies on
the timestamp fed from application.  The initial timestamp must be
passed to ``initial_ts`` field in nanosecond resolution.  ngtcp2 cares
about the difference from that initial value.  It could be any
timestamp which increases monotonically, and actual value does not
matter.

:type:`ngtcp2_transport_params` contains QUIC transport parameters
which is sent to a remote endpoint during handshake.  All fields must
be set.  Application should call `ngtcp2_transport_params_default()`
to set the default values.

Client application has to supply Connection IDs to
`ngtcp2_conn_client_new()`.  The *dcid* parameter is the destination
connection ID (DCID), and which should be random byte string and at
least 8 bytes long.  The *scid* is the source connection ID (SCID)
which identifies the client itself.  The *version* parameter is the
QUIC version to use.  It should be :macro:`NGTCP2_PROTO_VER_MIN` for
the maximum compatibility.

Similarly, server application has to supply these parameters to
`ngtcp2_conn_server_new()`.  But the *dcid* must be the same value
which is received from client (which is client SCID).  The *scid* is
chosen by server.  Don't use DCID in client packet as server SCID.
The *version* parameter is the QUIC version to use.  It should be
:macro:`NGTCP2_PROTO_VER_MIN` for the maximum compatibility.

A path is very important to QUIC connection.  It is the pair of
endpoints, local and remote.  The path passed to
`ngtcp2_conn_client_new()` and `ngtcp2_conn_server_new()` is a network
path that handshake is performed.  The path must not change during
handshake.  After handshake is confirmed, client can migrate to new
path.  An application must provide actual path to the API function to
tell the library where a packet comes from.  The "write" API function
takes path parameter and fills it to which the packet should be sent.

TLS integration
---------------

Use of :doc:`ngtcp2 crypto API <crypto_apiref>` is strongly
recommended because it vastly simplifies the TLS integration.

The most of the TLS work is done by the callback functions passed to
:type:`ngtcp2_callbacks` object.  There are some operations left to
application has to perform to make TLS integration work.

When TLS stack generates new secrets, they have to be installed to
:type:`ngtcp2_conn` by calling
`ngtcp2_crypto_derive_and_install_rx_key()` and
`ngtcp2_crypto_derive_and_install_tx_key()`.

When TLS stack generates new crypto data to send, they must be passed
to :type:`ngtcp2_conn` by calling `ngtcp2_conn_submit_crypto_data()`.

When QUIC handshake is completed,
:member:`ngtcp2_callbacks.handshake_completed` callback function is
called.  The local and remote endpoint independently declare handshake
completion.  The endpoint has to confirm that the other endpoint also
finished handshake.  When the handshake is confirmed, client side
:type:`ngtcp2_conn` will call
:member:`ngtcp2_callbacks.handshake_confirmed` callback function.
Server confirms handshake when it declares handshake completion,
therefore, separate handshake confirmation callback is not called.

Read and write packets
----------------------

`ngtcp2_conn_read_pkt()` processes the incoming QUIC packets.  In
order to write QUIC packets, call `ngtcp2_conn_writev_stream()` or
`ngtcp2_conn_write_pkt()`.

In order to send stream data, the application has to first open a
stream.  Use `ngtcp2_conn_open_bidi_stream()` to open bidirectional
stream.  For unidirectional stream, call
`ngtcp2_conn_open_uni_stream()`.  Call `ngtcp2_conn_writev_stream()`
to send stream data.

Dealing with early data
-----------------------

Client application has to load resumed TLS session.  It also has to
set the remembered transport parameters using
`ngtcp2_conn_set_early_remote_transport_params()` function.

Other than that, there is no difference between early data and 1RTT
data in terms of API usage.

If early data is rejected by a server, client must call
`ngtcp2_conn_early_data_rejected`.  All connection states altered
during early data transmission are undone.  The library does not
retransmit early data to server as 1RTT data.  If an application
wishes to resend data, it has to reopen streams and writes data again.
See `ngtcp2_conn_early_data_rejected`.

Stream and crypto data ownershp
-------------------------------

Stream and crypto data passed to :type:`ngtcp2_conn` must be held by
application until :member:`ngtcp2_callbacks.acked_stream_data_offset`
and :member:`ngtcp2_callbacks.acked_crypto_offset` callbacks,
respectively, telling that the those data are acknowledged by the
remote endpoint and no longer used by the library.

Timers
------

The library does not ask any timestamp to an operating system.
Instead, an application has to supply timestamp to the library.  The
type of timestamp in ngtcp2 library is :type:`ngtcp2_tstamp` which is
nanosecond resolution.  The library only cares the difference of
timestamp, so it does not have to be a system clock.  A monotonic
clock should work better.  It should be same clock passed to
:type:`ngtcp2_settings`.

`ngtcp2_conn_get_expiry()` tells an application when timer fires.
When timer fires, call `ngtcp2_conn_handle_expiry()` and
`ngtcp2_conn_write_pkt()` (or `ngtcp2_conn_writev_stream()`).

After calling these functions, new expiry will be set.  The
application should call `ngtcp2_conn_get_expiry()` to restart timer.

Application also handles connection idle timeout.
`ngtcp2_conn_get_idle_expiry()` returns the current idle expiry.  If
idle timer is expired, the connection should be closed without calling
`ngtcp2_conn_write_connection_close()`.

Connection migration
--------------------

In QUIC, client application can migrate to a new local address.
`ngtcp2_conn_initiate_immediate_migration()` migrates to a new local
address without checking reachability.  On the other hand,
`ngtcp2_conn_initiate_migration()` migrates to a new local address
after a new path is validated (thus reachability is established).

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
:type:`ngtcp2_conn` object must be deleted with `ngtcp2_conn_del()`
without any ngtcp2 library functions.  Otherwise, call
`ngtcp2_conn_write_connection_close()` to get terminal packet.
Sending it finishes QUIC connection.

If :macro:`NGTCP2_ERR_DROP_CONN` is returned from
`ngtcp2_conn_read_pkt`, a connection should be dropped without calling
`ngtcp2_conn_write_connection_close()`.

The following error codes must be considered as transitional, and
application should keep connection alive:

* :macro:`NGTCP2_ERR_STREAM_DATA_BLOCKED`
* :macro:`NGTCP2_ERR_STREAM_SHUT_WR`
* :macro:`NGTCP2_ERR_STREAM_NOT_FOUND`
* :macro:`NGTCP2_ERR_STREAM_ID_BLOCKED`
