ngtcp2
======

"Call it TCP/2.  One More Time."

ngtcp2 project is an effort to implement `RFC9000
<https://datatracker.ietf.org/doc/html/rfc9000>`_ QUIC protocol.

Documentation
-------------

`Online documentation <https://nghttp2.org/ngtcp2/>`_ is available.

Requirements
------------

The libngtcp2 C library itself does not depend on any external
libraries.  The example client, and server are written in C++17, and
should compile with the modern C++ compilers (e.g., clang >= 8.0, or
gcc >= 8.0).

The following packages are required to configure the build system:

- pkg-config >= 0.20
- autoconf
- automake
- autotools-dev
- libtool

libngtcp2 uses cunit for its unit test frame work:

- cunit >= 2.1

To build sources under the examples directory, libev and nghttp3 are
required:

- libev
- nghttp3 (https://github.com/ngtcp2/nghttp3) for HTTP/3

The client and server under examples directory require at least one of
the following TLS backends:

- `OpenSSL with QUIC support
  <https://github.com/quictls/openssl/tree/OpenSSL_1_1_1k+quic>`_
- GnuTLS
- BoringSSL

For crypto helper library:

- OpenSSL with QUIC support described above
- libgnutls28-dev >= 3.7.2
- BoringSSL (commit b09f283a030efc650cfcb3476932626c5000b921)

Build from git
--------------

.. code-block:: text

   $ git clone --depth 1 -b OpenSSL_1_1_1k+quic https://github.com/quictls/openssl
   $ cd openssl
   $ # For Linux
   $ ./config enable-tls1_3 --prefix=$PWD/build
   $ make -j$(nproc)
   $ make install_sw
   $ cd ..
   $ git clone https://github.com/ngtcp2/nghttp3
   $ cd nghttp3
   $ autoreconf -i
   $ ./configure --prefix=$PWD/build --enable-lib-only
   $ make -j$(nproc) check
   $ make install
   $ cd ..
   $ git clone https://github.com/ngtcp2/ngtcp2
   $ cd ngtcp2
   $ autoreconf -i
   $ # For Mac users who have installed libev with MacPorts, append
   $ # ',-L/opt/local/lib' to LDFLAGS, and also pass
   $ # CPPFLAGS="-I/opt/local/include" to ./configure.
   $ ./configure PKG_CONFIG_PATH=$PWD/../openssl/build/lib/pkgconfig:$PWD/../nghttp3/build/lib/pkgconfig LDFLAGS="-Wl,-rpath,$PWD/../openssl/build/lib"
   $ make -j$(nproc) check

Client/Server
-------------

After successful build, the client and server executable should be
found under examples directory.  They talk HTTP/3.

Client
~~~~~~

.. code-block:: text

   $ examples/client [OPTIONS] <HOST> <PORT> [<URI>...]

The notable options are:

- ``-d``, ``--data=<PATH>``: Read data from <PATH> and send it to a
  peer.

Server
~~~~~~

.. code-block:: text

   $ examples/server [OPTIONS] <ADDR> <PORT> <PRIVATE_KEY_FILE> <CERTIFICATE_FILE>

The notable options are:

- ``-V``, ``--validate-addr``: Enforce stateless address validation.

H09client/H09server
-------------------

There are h09client and h09server which speak HTTP/0.9.  They are
written just for `quic-interop-runner
<https://github.com/marten-seemann/quic-interop-runner>`_.  They share
the basic functionalities with HTTP/3 client and server but have less
functions (e.g., h09client does not have a capability to send request
body, and h09server does not understand numeric request path, like
/1000).

Resumption and 0-RTT
--------------------

In order to resume a session, a session ticket, and a transport
parameters must be fetched from server.  First, run examples/client
with --session-file, and --tp-file options which specify a path to
session ticket, and transport parameter files respectively to save
them locally.

Once these files are available, run examples/client with the same
arguments again.  You will see that session is resumed in your log if
resumption succeeds.  Resuming session makes server's first Handshake
packet pretty small because it does not send its certificates.

To send 0-RTT data, after making sure that resumption works, use -d
option to specify a file which contains data to send.

Token (Not  comes in Retry packet)
----------------------------------

QUIC server might send a token to client after connection has been
established.  Client can send this token in subsequent connection to
the server.  Server verifies the token and if it succeeds, the address
validation completes and lifts some restrictions on server which might
speed up transfer.  In order to save and/or load a token,
use --token-file option of examples/client.  The given file is
overwritten if it already exists when storing a token.

Crypto helper library
---------------------

In order to make TLS stack integration less painful, we provide a
crypto helper library which offers the basic crypto operations.

The header file exists under crypto/includes/ngtcp2 directory.

Each library file is built for a particular TLS backend.  The
available crypto helper libraries are:

- libngtcp2_crypto_openssl: Use OpenSSL as TLS backend
- libngtcp2_crypto_gnutls: Use GnuTLS as TLS backend
- libngtcp2_crypto_boringssl: Use BoringSSL as TLS backend

Because BoringSSL is an unversioned product, we only tested its
particular revision.  See Requirements section above.

The examples directory contains client and server that are linked to
those crypto helper libraries and TLS backends.  They are only built
if their corresponding crypto helper library is built:

- client: OpenSSL client
- server: OpenSSL server
- gtlsclient: GnuTLS client
- gtlsserver: GnuTLS server
- bsslclient: BoringSSL client
- bsslserver: BoringSSL server

QUIC protocol extensions
-------------------------

The library implements the following QUIC protocol extensions:

- `An Unreliable Datagram Extension to QUIC
  <https://quicwg.org/datagram/draft-ietf-quic-datagram.html>`_

Configuring Wireshark for QUIC
------------------------------

`Wireshark <https://www.wireshark.org/download.html>`_ can be configured to
analyze QUIC traffic using the following steps:

1. Set *SSLKEYLOGFILE* environment variable:

   .. code-block:: text

      $ export SSLKEYLOGFILE=quic_keylog_file

2. Set the port that QUIC uses

   Go to *Preferences->Protocols->QUIC* and set the port the program
   listens to.  In the case of the example application this would be
   the port specified on the command line.

3. Set Pre-Master-Secret logfile

   Go to *Preferences->Protocols->TLS* add set the *Pre-Master-Secret
   log file* to the same value that was specified for *SSLKEYLOGFILE*.

4. Choose the correct network interface for capturing

   Make sure you choose the correct network interface for
   capturing. For example, if using localhost choose the *loopback*
   network interface on macos.

5. Create a filter

   Create A filter for the udp.port and set the port to the port the
   application is listening to. For example:

   .. code-block:: text

      udp.port == 7777

License
-------

The MIT License

Copyright (c) 2016 ngtcp2 contributors
