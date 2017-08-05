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

    $ examples/client 127.0.0.1 4433 -i
    t=0.000412 TX Client Initial CID=82db2c51708b999f PKN=1003612304 V=ff000005
               STREAM
               stream_id=00000000 fin=0 offset=0 data_length=274
               PADDING
               length=949
    t=0.002432 RX Server Cleartext CID=c4ae8106ebe3f1ff PKN=567626255 V=ff000005
               ACK
               num_blks=0 num_ts=0 largest_ack=1003612304 ack_delay=1702
               first_ack_block_length=0; [1003612304..1003612304]
               MAX_STREAM_DATA
               stream_id=00000000 max_stream_data=65809
               STREAM
               stream_id=00000000 fin=0 offset=0 data_length=1187
               ; TransportParameter received in EncryptedExtensions
               ; supported_version[0]=ff000005
               ; initial_max_stream_data=262144
               ; initial_max_data=1024
               ; initial_max_stream_id=1
               ; idle_timeout=5
               ; omit_connection_id=0
               ; max_packet_size=65527
    t=0.002870 RX Server Cleartext CID=c4ae8106ebe3f1ff PKN=567626256 V=ff000005
               STREAM
               stream_id=00000000 fin=0 offset=1187 data_length=328
               ; Negotiated cipher suite is TLS13-AES-256-GCM-SHA384
               ; Negotiated ALPN is hq-05
    t=0.003112 QUIC handshake has completed
    Interactive session started.  Hit Ctrl-D to end the session.
    The stream 1 has opened.
    t=0.003212 TX Client Cleartext CID=c4ae8106ebe3f1ff PKN=1003612305 V=ff000005
               ACK
               num_blks=0 num_ts=0 largest_ack=567626256 ack_delay=343
               first_ack_block_length=1; [567626256..567626255]
               MAX_STREAM_DATA
               stream_id=00000000 max_stream_data=67050
               STREAM
               stream_id=00000000 fin=0 offset=274 data_length=74
    t=0.028810 RX Short 03 CID=c4ae8106ebe3f1ff PKN=567626257
               ACK
               num_blks=0 num_ts=0 largest_ack=1003612305 ack_delay=25448
               first_ack_block_length=0; [1003612305..1003612305]
    hello world!
    t=4.707194 TX Short 03 CID=c4ae8106ebe3f1ff PKN=1003612306
               STREAM
               stream_id=00000001 fin=0 offset=0 data_length=13
    t=4.708135 RX Short 03 CID=c4ae8106ebe3f1ff PKN=567626258
               STREAM
               stream_id=00000001 fin=0 offset=0 data_length=28
               ordered STREAM data stream_id=00000001
    00000000  3c 62 6c 69 6e 6b 3e 68  65 6c 6c 6f 20 77 6f 72  |<blink>hello wor|
    00000010  6c 64 21 0a 3c 2f 62 6c  69 6e 6b 3e              |ld!.</blink>|
    0000001c
    t=4.733601 TX Short 03 CID=c4ae8106ebe3f1ff PKN=1003612307
               ACK
               num_blks=0 num_ts=0 largest_ack=567626258 ack_delay=25462
               first_ack_block_length=0; [567626258..567626258]
    t=4.733636 RX Short 03 CID=c4ae8106ebe3f1ff PKN=567626259
               ACK
               num_blks=0 num_ts=0 largest_ack=1003612306 ack_delay=25966
               first_ack_block_length=0; [1003612306..1003612306]
    Interactive session has ended.
    t=20.560859 TX Short 03 CID=c4ae8106ebe3f1ff PKN=1003612308
               STREAM
               stream_id=00000001 fin=1 offset=13 data_length=0
    t=20.561530 RX Short 03 CID=c4ae8106ebe3f1ff PKN=567626260
               STREAM
               stream_id=00000001 fin=1 offset=28 data_length=0
               ordered STREAM data stream_id=00000001
    t=20.586864 TX Short 03 CID=c4ae8106ebe3f1ff PKN=1003612309
               ACK
               num_blks=0 num_ts=0 largest_ack=567626260 ack_delay=25320
               first_ack_block_length=0; [567626260..567626260]
    t=20.586910 RX Short 03 CID=c4ae8106ebe3f1ff PKN=567626261
               ACK
               num_blks=0 num_ts=0 largest_ack=1003612308 ack_delay=25577
               first_ack_block_length=0; [1003612308..1003612308]
    t=20.587061 RX Short 03 CID=c4ae8106ebe3f1ff PKN=567626262
               MAX_STREAM_ID
               max_stream_id=00000003
    t=20.612264 TX Short 03 CID=c4ae8106ebe3f1ff PKN=1003612310
               ACK
               num_blks=0 num_ts=0 largest_ack=567626262 ack_delay=25202
               first_ack_block_length=0; [567626262..567626262]
    t=50.616326 Timeout

.. code-block:: text

    $ examples/server 127.0.0.1 4433 server.key server.crt
    t=8.409850 RX Client Initial CID=82db2c51708b999f PKN=1003612304 V=ff000005
               STREAM
               stream_id=00000000 fin=0 offset=0 data_length=274
               ; TransportParameter received in ClientHello
               ; negotiated_version=ff000005
               ; initial_version=ff000005
               ; initial_max_stream_data=262144
               ; initial_max_data=1024
               ; initial_max_stream_id=0
               ; idle_timeout=5
               ; omit_connection_id=0
               ; max_packet_size=65527
               PADDING
               length=949
    t=8.411547 TX Server Cleartext CID=c4ae8106ebe3f1ff PKN=567626255 V=ff000005
               ACK
               num_blks=0 num_ts=0 largest_ack=1003612304 ack_delay=1702
               first_ack_block_length=0; [1003612304..1003612304]
               MAX_STREAM_DATA
               stream_id=00000000 max_stream_data=65809
               STREAM
               stream_id=00000000 fin=0 offset=0 data_length=1187
    t=8.411597 TX Server Cleartext CID=c4ae8106ebe3f1ff PKN=567626256 V=ff000005
               STREAM
               stream_id=00000000 fin=0 offset=1187 data_length=328
    t=8.412510 RX Client Cleartext CID=c4ae8106ebe3f1ff PKN=1003612305 V=ff000005
               ACK
               num_blks=0 num_ts=0 largest_ack=567626256 ack_delay=343
               first_ack_block_length=1; [567626256..567626255]
               MAX_STREAM_DATA
               stream_id=00000000 max_stream_data=67050
               STREAM
               stream_id=00000000 fin=0 offset=274 data_length=74
               ; Negotiated cipher suite is TLS13-AES-256-GCM-SHA384
               ; Negotiated ALPN is hq-05
    t=8.412694 QUIC handshake has completed
    t=8.437965 TX Short 03 CID=c4ae8106ebe3f1ff PKN=567626257
               ACK
               num_blks=0 num_ts=0 largest_ack=1003612305 ack_delay=25448
               first_ack_block_length=0; [1003612305..1003612305]
    t=13.116710 RX Short 03 CID=c4ae8106ebe3f1ff PKN=1003612306
               STREAM
               stream_id=00000001 fin=0 offset=0 data_length=13
               ordered STREAM data stream_id=00000001
    00000000  68 65 6c 6c 6f 20 77 6f  72 6c 64 21 0a           |hello world!.|
    0000000d
    t=13.117165 TX Short 03 CID=c4ae8106ebe3f1ff PKN=567626258
               STREAM
               stream_id=00000001 fin=0 offset=0 data_length=28
    t=13.142691 TX Short 03 CID=c4ae8106ebe3f1ff PKN=567626259
               ACK
               num_blks=0 num_ts=0 largest_ack=1003612306 ack_delay=25966
               first_ack_block_length=0; [1003612306..1003612306]
    t=13.142876 RX Short 03 CID=c4ae8106ebe3f1ff PKN=1003612307
               ACK
               num_blks=0 num_ts=0 largest_ack=567626258 ack_delay=25462
               first_ack_block_length=0; [567626258..567626258]
    t=28.970399 RX Short 03 CID=c4ae8106ebe3f1ff PKN=1003612308
               STREAM
               stream_id=00000001 fin=1 offset=13 data_length=0
               ordered STREAM data stream_id=00000001
    t=28.970528 TX Short 03 CID=c4ae8106ebe3f1ff PKN=567626260
               STREAM
               stream_id=00000001 fin=1 offset=28 data_length=0
    t=28.995992 TX Short 03 CID=c4ae8106ebe3f1ff PKN=567626261
               ACK
               num_blks=0 num_ts=0 largest_ack=1003612308 ack_delay=25577
               first_ack_block_length=0; [1003612308..1003612308]
    t=28.996151 RX Short 03 CID=c4ae8106ebe3f1ff PKN=1003612309
               ACK
               num_blks=0 num_ts=0 largest_ack=567626260 ack_delay=25320
               first_ack_block_length=0; [567626260..567626260]
    t=28.996213 TX Short 03 CID=c4ae8106ebe3f1ff PKN=567626262
               MAX_STREAM_ID
               max_stream_id=00000003
    t=29.021536 RX Short 03 CID=c4ae8106ebe3f1ff PKN=1003612310
               ACK
               num_blks=0 num_ts=0 largest_ack=567626262 ack_delay=25202
               first_ack_block_length=0; [567626262..567626262]
    t=59.050818 Timeout
    t=59.050834 Closing QUIC connection

License
-------

The MIT License

Copyright (c) 2016 ngtcp2 contributors
