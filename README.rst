ngtcp2
======

"Call it TCP/2.  One More Time."

ngtcp2 project is an effort to implement QUIC protocol which is now
being discussed in IETF QUICWG for its standardization.

Development status
------------------

First Implementation Draft
~~~~~~~~~~~~~~~~~~~~~~~~~~

We are focusing on implementing `First Implementation
<https://github.com/quicwg/base-drafts/wiki/First-Implementation>`_
which is a subset of editor's draft version of QUIC transport and QUIC
TLS (roughly called pre-05) at the time of this writing.

* https://quicwg.github.io/base-drafts/draft-ietf-quic-transport.html
* https://quicwg.github.io/base-drafts/draft-ietf-quic-tls.html

TLSv1.3 draft-21 should be used for interop.

Requirements
------------

The libngtcp2 C library itself does not depend on any external
libraries.  It should compile with the modern C++ compilers on the
recent Linux.

The following packages are required to configure the build system:

* pkg-config >= 0.20
* autoconf
* automake
* autotools-dev
* libtool

libngtcp2 uses cunit for its unit test frame work:

* cunit >= 2.1

To build sources under the examples directory, libev is required:

* libev

The client and server under examples directory require OpenSSL (master
branch) as crypto backend:

* OpenSSL (https://github.com/openssl/openssl/)

Build from git
--------------

.. code-block:: text

   $ git clone --depth 1 https://github.com/openssl/openssl
   $ cd openssl
   $ # For Linux
   $ ./config enable-tls1_3 --prefix=$PWD/build
   $ make -j$(nproc)
   $ make install_sw
   $ cd ..
   $ git clone https://github.com/ngtcp2/ngtcp2
   $ cd ngtcp2
   $ autoreconf -i
   $ # For Mac users who have installed libev with MacPorts, append
   $ # ',-L/opt/local/lib' to LDFLAGS, and also pass
   $ # CPPFLAGS="-I/opt/local/include" to ./configure.
   $ ./configure PKG_CONFIG_PATH=$PWD/../openssl/build/lib/pkgconfig LDFLAGS="-Wl,-rpath,$PWD/../openssl/build/lib"
   $ make -j$(nproc) check

Client/Server
-------------

After successful build, the client and server executable should be
found under examples directory.

examples/client has ``-i`` option to read data from stdin, and send
them as STREAM data to server.  examples/server responds them with
some modification.

Both program have ``--tx-loss`` and ``--rx-loss`` to simulate packet
loss.

.. code-block:: text

    $ examples/client 127.0.0.1 3000 -i -r 0.3 -t 0.3
    t=0.000376 TX Client Initial CID=892e74f16e48fae9 PKN=1577002470 V=ff000005
               STREAM
               stream_id=00000000 fin=0 offset=0 data_length=274
               PADDING
               length=949
    ** Simulated outgoing packet loss **
    t=0.800322 TX Client Initial CID=892e74f16e48fae9 PKN=1577002471 V=ff000005
               STREAM
               stream_id=00000000 fin=0 offset=0 data_length=274
               PADDING
               length=949
    t=0.809073 RX Server Cleartext CID=7cbb8b6f75703e7e PKN=932960310 V=ff000005
               ACK
               num_blks=0 num_ts=0 largest_ack=1577002471 ack_delay=7876
               first_ack_block_length=0
               STREAM
               stream_id=00000000 fin=0 offset=0 data_length=1200
    t=0.810240 TransportParameter received in EncryptedExtensions
               supported_version[0]=ff000005
               initial_max_stream_data=131072
               initial_max_data=128
               initial_max_stream_id=1
               idle_timeout=5
               omit_connection_id=0
               max_packet_size=65527
    t=0.810966 RX Server Cleartext CID=7cbb8b6f75703e7e PKN=932960311 V=ff000005
               STREAM
               stream_id=00000000 fin=0 offset=1200 data_length=315
    t=0.812505 Negotiated ALPN hq-05
    t=0.812546 QUIC handshake has completed
    Interactive session started.  Hit Ctrl-D to end the session.
    The stream 1 has opened.
    t=0.812904 TX Client Cleartext CID=7cbb8b6f75703e7e PKN=1577002472 V=ff000005
               ACK
               num_blks=0 num_ts=0 largest_ack=932960311 ack_delay=1939
               first_ack_block_length=1
               STREAM
               stream_id=00000000 fin=0 offset=274 data_length=74
    t=0.814378 RX Short 03 CID=7cbb8b6f75703e7e PKN=932960312
               ACK
               num_blks=0 num_ts=0 largest_ack=1577002472 ack_delay=1093
               first_ack_block_length=0
    Hello World!
    t=5.751208 TX Short 03 CID=7cbb8b6f75703e7e PKN=1577002473
               STREAM
               stream_id=00000001 fin=0 offset=0 data_length=13
    t=5.752136 RX Short 03 CID=7cbb8b6f75703e7e PKN=932960313
               ACK
               num_blks=0 num_ts=0 largest_ack=1577002473 ack_delay=435
               first_ack_block_length=0
               STREAM
               stream_id=00000001 fin=0 offset=0 data_length=28
    t=5.752283 STREAM data stream_id=00000001
    00000000  3c 62 6c 69 6e 6b 3e 48  65 6c 6c 6f 20 57 6f 72  |<blink>Hello Wor|
    00000010  6c 64 21 0a 3c 2f 62 6c  69 6e 6b 3e              |ld!.</blink>|
    0000001c
    t=5.752612 TX Short 03 CID=7cbb8b6f75703e7e PKN=1577002474
               ACK
               num_blks=0 num_ts=0 largest_ack=932960313 ack_delay=475
               first_ack_block_length=0
    Interactive session has ended.
    t=20.058077 TX Short 03 CID=7cbb8b6f75703e7e PKN=1577002475
               STREAM
               stream_id=00000001 fin=1 offset=13 data_length=0
    t=20.058259 RX Short 03 CID=7cbb8b6f75703e7e PKN=932960314
               ACK
               num_blks=0 num_ts=0 largest_ack=1577002475 ack_delay=40
               first_ack_block_length=0
    ^C

.. code-block:: text

    $ examples/server 127.0.0.1 3000 server.key server.crt
    t=2.057785 RX Client Initial CID=892e74f16e48fae9 PKN=1577002471 V=ff000005
               STREAM
               stream_id=00000000 fin=0 offset=0 data_length=274
    t=2.058707 TransportParameter received in ClientHello
               negotiated_version=ff000005
               initial_version=ff000005
               initial_max_stream_data=131072
               initial_max_data=128
               initial_max_stream_id=0
               idle_timeout=5
               omit_connection_id=0
               max_packet_size=65527
    t=2.058884 Negotiated ALPN hq-05
               PADDING
               length=949
    t=2.065653 TX Server Cleartext CID=7cbb8b6f75703e7e PKN=932960310 V=ff000005
               ACK
               num_blks=0 num_ts=0 largest_ack=1577002471 ack_delay=7876
               first_ack_block_length=0
               STREAM
               stream_id=00000000 fin=0 offset=0 data_length=1200
    t=2.065854 TX Server Cleartext CID=7cbb8b6f75703e7e PKN=932960311 V=ff000005
               STREAM
               stream_id=00000000 fin=0 offset=1200 data_length=315
    t=2.069977 RX Client Cleartext CID=7cbb8b6f75703e7e PKN=1577002472 V=ff000005
               ACK
               num_blks=0 num_ts=0 largest_ack=932960311 ack_delay=1939
               first_ack_block_length=1
               STREAM
               stream_id=00000000 fin=0 offset=274 data_length=74
    t=2.070732 QUIC handshake has completed
    t=2.071071 TX Short 03 CID=7cbb8b6f75703e7e PKN=932960312
               ACK
               num_blks=0 num_ts=0 largest_ack=1577002472 ack_delay=1093
               first_ack_block_length=0
    t=7.008381 RX Short 03 CID=7cbb8b6f75703e7e PKN=1577002473
               STREAM
               stream_id=00000001 fin=0 offset=0 data_length=13
    t=7.008529 STREAM data stream_id=00000001
    00000000  48 65 6c 6c 6f 20 57 6f  72 6c 64 21 0a           |Hello World!.|
    0000000d
    t=7.008817 TX Short 03 CID=7cbb8b6f75703e7e PKN=932960313
               ACK
               num_blks=0 num_ts=0 largest_ack=1577002473 ack_delay=435
               first_ack_block_length=0
               STREAM
               stream_id=00000001 fin=0 offset=0 data_length=28
    t=7.009641 RX Short 03 CID=7cbb8b6f75703e7e PKN=1577002474
               ACK
               num_blks=0 num_ts=0 largest_ack=932960313 ack_delay=475
               first_ack_block_length=0
    t=21.315054 RX Short 03 CID=7cbb8b6f75703e7e PKN=1577002475
               STREAM
               stream_id=00000001 fin=1 offset=13 data_length=0
    t=21.315093 TX Short 03 CID=7cbb8b6f75703e7e PKN=932960314
               ACK
               num_blks=0 num_ts=0 largest_ack=1577002475 ack_delay=40
               first_ack_block_length=0

License
-------

The MIT License

Copyright (c) 2016 ngtcp2 contributors
