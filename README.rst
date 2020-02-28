ngtcp2
======

"Call it TCP/2.  One More Time."

ngtcp2 project is an effort to implement QUIC protocol which is now
being discussed in IETF QUICWG for its standardization.

Branching strategy
------------------

As of the beginning of draft-23 development, the new branching
strategy has been introduced.  The master branch tracks the latest
QUIC draft development.  When new draft-*NN* is published, the new
branch named draft-*NN-1* is created based on the master branch.
Those draft-*NN* branches are considered as "archived", which means
that no update is expected.  PR should be made to the master branch
only.

For older draft implementations:

- `draft-25 <https://github.com/ngtcp2/ngtcp2/tree/draft-25>`_
- `draft-24 <https://github.com/ngtcp2/ngtcp2/tree/draft-24>`_
- `draft-23 <https://github.com/ngtcp2/ngtcp2/tree/draft-23>`_
- `draft-22 <https://github.com/ngtcp2/ngtcp2/tree/draft-22>`_

Requirements
------------

The libngtcp2 C library itself does not depend on any external
libraries.  The example client, and server are written in C++17, and
should compile with the modern C++ compilers (e.g., clang >= 8.0, or
gcc >= 8.0).

The following packages are required to configure the build system:

* pkg-config >= 0.20
* autoconf
* automake
* autotools-dev
* libtool

libngtcp2 uses cunit for its unit test frame work:

* cunit >= 2.1

To build sources under the examples directory, libev and nghttp3 are
required:

* libev
* nghttp3 (https://github.com/ngtcp2/nghttp3) for HTTP/3

The client and server under examples directory require patched OpenSSL
as crypto backend:

* Patched OpenSSL
  (https://github.com/tatsuhiro-t/openssl/tree/OpenSSL_1_1_1d-quic-draft-27)

Build from git
--------------

.. code-block:: text

   $ git clone --depth 1 -b OpenSSL_1_1_1d-quic-draft-27 https://github.com/tatsuhiro-t/openssl
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

   $ examples/client [OPTIONS] <ADDR> <PORT> <URI>

The notable options are:

- ``-d``, ``--data=<PATH>``: Read data from <PATH> and send it to a
  peer.

Server
~~~~~~

.. code-block:: text

   $ examples/server [OPTIONS] <ADDR> <PORT> <PRIVATE_KEY_FILE> <CERTIFICATE_FILE>

The notable options are:

- ``-V``, ``--validate-addr``: Enforce stateless address validation.

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

Crypto helper library
---------------------

In order to make TLS stack integration less painful, we provide a
crypto helper library which offers the basic crypto operations.

The header file exists under crypto/includes/ngtcp2 directory.

The library file is built for a particular TLS backend.  At the
moment, libngtcp2_crypto_openssl which uses OpenSSL as TLS backend is
provided.


Configuring Wireshark for QUIC
------------------------------
`Wireshark <https://www.wireshark.org/download.html>`_ can be configured to
analyze QUIC traffic using the following steps:

**1.** Set *SSLKEYLOGFILE* environment variable:

   .. code-block:: text

        $ export SSLKEYLOGFILE=quic_keylog_file

**2.** Set the port that QUIC uses

   Go to *Preferences->Protocols->QUIC* and set the port the program listens to.
   In the case of the example application this would be the port specified on the
   command line.

**3.** Set Pre-Master-Secret logfile

   Go to *Preferences->Protocols->TLS* add set the *Pre-Master-Secret log file*
   to the same value that was specified for *SSLKEYLOGFILE*.

**4.** Choose the correct network interface for capturing

   Make sure you choose the correct network interface for capturing. For example,
   if using localhost choose the *loopback* network inteface on macos.

**5.** Create a filter

   Create A filter for the udp.port and set the port to the port the application
   is listening to. For example:

   .. code-block:: text

        udp.port == 7777


License
-------

The MIT License

Copyright (c) 2016 ngtcp2 contributors
