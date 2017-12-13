ngtcp2
======

"Call it TCP/2.  One More Time."

ngtcp2 project is an effort to implement QUIC protocol which is now
being discussed in IETF QUICWG for its standardization.

Development status
------------------

Second Implementation Draft
~~~~~~~~~~~~~~~~~~~~~~~~~~

We are focusing on implementing `Second Implementation Draft
<https://github.com/quicwg/base-drafts/wiki/Second-Implementation-Draft>`_.

* https://quicwg.github.io/base-drafts/draft-ietf-quic-transport.html
* https://quicwg.github.io/base-drafts/draft-ietf-quic-tls.html

Requirements
------------

The libngtcp2 C library itself does not depend on any external
libraries.  The example client, and server are written in C++14, and
should compile with the modern C++ compilers (e.g., clang >= 4.0, or
gcc >= 5.0).

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

At the moment, the patched OpenSSL is required to compile ngtcp2 to
enable 0-RTT.  See below.

Build from git
--------------

.. code-block:: text

   $ git clone --depth 1 -b quic https://github.com/tatsuhiro-t/openssl
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
them as STREAM data to server.  examples/server parses stream data as
HTTP/1.x request.

Both program have ``--tx-loss`` and ``--rx-loss`` to simulate packet
loss.

.. code-block:: text

    $ examples/client 127.0.0.1 4433 -i
    t=0.000359 TX Client Initial(0x02) CID=0x737b2c1ecd75d64b PKN=139454351 V=0xff000005
               STREAM(0xc1) F=0x00 SS=0x00 OO=0x00 D=0x01
               stream_id=0x00000000 fin=0 offset=0 data_length=274
               PADDING(0x00)
               length=949
    t=0.002420 RX Server Cleartext(0x04) CID=0xfdeb3167833b8859 PKN=2044202911 V=0xff000005
               ACK(0xa8) N=0x00 LL=0x02 MM=0x00
               num_blks=0 num_ts=0 largest_ack=139454351 ack_delay=1708
               first_ack_block_length=0; [139454351..139454351]
               STREAM(0xc1) F=0x00 SS=0x00 OO=0x00 D=0x01
               stream_id=0x00000000 fin=0 offset=0 data_length=1203
               ; TransportParameter received in EncryptedExtensions
               ; supported_version[0]=0xff000005
               ; initial_max_stream_data=262144
               ; initial_max_data=1024
               ; initial_max_stream_id=199
               ; idle_timeout=30
               ; omit_connection_id=0
               ; max_packet_size=65527
               ; stateless_reset_token=8ed8f8a7f38d83318fc9aeac43baf2ae
    t=0.002913 RX Server Cleartext(0x04) CID=0xfdeb3167833b8859 PKN=2044202912 V=0xff000005
               STREAM(0xc3) F=0x00 SS=0x00 OO=0x01 D=0x01
               stream_id=0x00000000 fin=0 offset=1203 data_length=302
               ; Negotiated cipher suite is TLS13-AES-128-GCM-SHA256
               ; Negotiated ALPN is hq-05
    t=0.003159 QUIC handshake has completed
    Interactive session started.  Hit Ctrl-D to end the session.
    The stream 1 has opened.
    t=0.003235 TX Client Cleartext(0x05) CID=0xfdeb3167833b8859 PKN=139454352 V=0xff000005
               ACK(0xa8) N=0x00 LL=0x02 MM=0x00
               num_blks=0 num_ts=0 largest_ack=2044202912 ack_delay=323
               first_ack_block_length=1; [2044202912..2044202911]
               STREAM(0xc3) F=0x00 SS=0x00 OO=0x01 D=0x01
               stream_id=0x00000000 fin=0 offset=274 data_length=58
    t=0.028792 RX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=2044202913
               ACK(0xa8) N=0x00 LL=0x02 MM=0x00
               num_blks=0 num_ts=0 largest_ack=139454352 ack_delay=25442
               first_ack_block_length=0; [139454352..139454352]
    GET /helloworld
    t=5.139039 TX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=139454353
               STREAM(0xc1) F=0x00 SS=0x00 OO=0x00 D=0x01
               stream_id=0x00000001 fin=0 offset=0 data_length=16
    t=5.140105 RX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=2044202914
               STREAM(0xe1) F=0x01 SS=0x00 OO=0x00 D=0x01
               stream_id=0x00000001 fin=1 offset=0 data_length=177
               ordered STREAM data stream_id=0x00000001
    00000000  3c 68 74 6d 6c 3e 3c 62  6f 64 79 3e 3c 68 31 3e  |<html><body><h1>|
    00000010  49 74 20 77 6f 72 6b 73  21 3c 2f 68 31 3e 0a 3c  |It works!</h1>.<|
    00000020  70 3e 54 68 69 73 20 69  73 20 74 68 65 20 64 65  |p>This is the de|
    00000030  66 61 75 6c 74 20 77 65  62 20 70 61 67 65 20 66  |fault web page f|
    00000040  6f 72 20 74 68 69 73 20  73 65 72 76 65 72 2e 3c  |or this server.<|
    00000050  2f 70 3e 0a 3c 70 3e 54  68 65 20 77 65 62 20 73  |/p>.<p>The web s|
    00000060  65 72 76 65 72 20 73 6f  66 74 77 61 72 65 20 69  |erver software i|
    00000070  73 20 72 75 6e 6e 69 6e  67 20 62 75 74 20 6e 6f  |s running but no|
    00000080  20 63 6f 6e 74 65 6e 74  20 68 61 73 20 62 65 65  | content has bee|
    00000090  6e 20 61 64 64 65 64 2c  20 79 65 74 2e 3c 2f 70  |n added, yet.</p|
    000000a0  3e 0a 3c 2f 62 6f 64 79  3e 3c 2f 68 74 6d 6c 3e  |>.</body></html>|
    000000b0  0a                                                |.|
    000000b1
    t=5.165618 TX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=139454354
               ACK(0xa8) N=0x00 LL=0x02 MM=0x00
               num_blks=0 num_ts=0 largest_ack=2044202914 ack_delay=25490
               first_ack_block_length=1; [2044202914..2044202913]
    t=5.165781 RX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=2044202915
               ACK(0xa8) N=0x00 LL=0x02 MM=0x00
               num_blks=0 num_ts=0 largest_ack=139454353 ack_delay=26023
               first_ack_block_length=0; [139454353..139454353]
    t=5.166209 RX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=2044202916
               RST_STREAM(0x01)
               stream_id=0x00000001 error_code=NO_ERROR(0x80000000) final_offset=177
    t=5.166325 TX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=139454355
               RST_STREAM(0x01)
               stream_id=0x00000001 error_code=QUIC_RECEIVED_RST(0x80000035) final_offset=16
    t=5.191574 TX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=139454356
               ACK(0xa8) N=0x00 LL=0x02 MM=0x00
               num_blks=0 num_ts=0 largest_ack=2044202916 ack_delay=25359
               first_ack_block_length=1; [2044202916..2044202915]
    t=5.191928 RX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=2044202917
               ACK(0xa8) N=0x00 LL=0x02 MM=0x00
               num_blks=0 num_ts=0 largest_ack=139454355 ack_delay=25257
               first_ack_block_length=1; [139454355..139454354]
    t=35.220960 Timeout
    t=35.221026 TX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=139454357
               CONNECTION_CLOSE(0x02)
               error_code=NO_ERROR(0x80000000) reason_length=0

.. code-block:: text

    $ examples/server 127.0.0.1 4433 server.key server.crt
    t=8.165451 RX Client Initial(0x02) CID=0x737b2c1ecd75d64b PKN=139454351 V=0xff000005
               STREAM(0xc1) F=0x00 SS=0x00 OO=0x00 D=0x01
               stream_id=0x00000000 fin=0 offset=0 data_length=274
               ; TransportParameter received in ClientHello
               ; negotiated_version=0xff000005
               ; initial_version=0xff000005
               ; initial_max_stream_data=262144
               ; initial_max_data=1024
               ; initial_max_stream_id=0
               ; idle_timeout=30
               ; omit_connection_id=0
               ; max_packet_size=65527
               PADDING(0x00)
               length=949
    t=8.167158 TX Server Cleartext(0x04) CID=0xfdeb3167833b8859 PKN=2044202911 V=0xff000005
               ACK(0xa8) N=0x00 LL=0x02 MM=0x00
               num_blks=0 num_ts=0 largest_ack=139454351 ack_delay=1708
               first_ack_block_length=0; [139454351..139454351]
               STREAM(0xc1) F=0x00 SS=0x00 OO=0x00 D=0x01
               stream_id=0x00000000 fin=0 offset=0 data_length=1203
    t=8.167202 TX Server Cleartext(0x04) CID=0xfdeb3167833b8859 PKN=2044202912 V=0xff000005
               STREAM(0xc3) F=0x00 SS=0x00 OO=0x01 D=0x01
               stream_id=0x00000000 fin=0 offset=1203 data_length=302
    t=8.168142 RX Client Cleartext(0x05) CID=0xfdeb3167833b8859 PKN=139454352 V=0xff000005
               ACK(0xa8) N=0x00 LL=0x02 MM=0x00
               num_blks=0 num_ts=0 largest_ack=2044202912 ack_delay=323
               first_ack_block_length=1; [2044202912..2044202911]
               STREAM(0xc3) F=0x00 SS=0x00 OO=0x01 D=0x01
               stream_id=0x00000000 fin=0 offset=274 data_length=58
               ; Negotiated cipher suite is TLS13-AES-128-GCM-SHA256
               ; Negotiated ALPN is hq-05
    t=8.168343 QUIC handshake has completed
    t=8.193589 TX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=2044202913
               ACK(0xa8) N=0x00 LL=0x02 MM=0x00
               num_blks=0 num_ts=0 largest_ack=139454352 ack_delay=25442
               first_ack_block_length=0; [139454352..139454352]
    t=13.304143 RX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=139454353
               STREAM(0xc1) F=0x00 SS=0x00 OO=0x00 D=0x01
               stream_id=0x00000001 fin=0 offset=0 data_length=16
               ordered STREAM data stream_id=0x00000001
    00000000  47 45 54 20 2f 68 65 6c  6c 6f 77 6f 72 6c 64 0a  |GET /helloworld.|
    00000010
    t=13.304766 TX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=2044202914
               STREAM(0xe1) F=0x01 SS=0x00 OO=0x00 D=0x01
               stream_id=0x00000001 fin=1 offset=0 data_length=177
    t=13.330176 TX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=2044202915
               ACK(0xa8) N=0x00 LL=0x02 MM=0x00
               num_blks=0 num_ts=0 largest_ack=139454353 ack_delay=26023
               first_ack_block_length=0; [139454353..139454353]
    t=13.330642 RX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=139454354
               ACK(0xa8) N=0x00 LL=0x02 MM=0x00
               num_blks=0 num_ts=0 largest_ack=2044202914 ack_delay=25490
               first_ack_block_length=1; [2044202914..2044202913]
    t=13.330848 TX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=2044202916
               RST_STREAM(0x01)
               stream_id=0x00000001 error_code=NO_ERROR(0x80000000) final_offset=177
    t=13.331299 RX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=139454355
               RST_STREAM(0x01)
               stream_id=0x00000001 error_code=QUIC_RECEIVED_RST(0x80000035) final_offset=16
    t=13.356579 TX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=2044202917
               ACK(0xa8) N=0x00 LL=0x02 MM=0x00
               num_blks=0 num_ts=0 largest_ack=139454355 ack_delay=25257
               first_ack_block_length=1; [139454355..139454354]
    t=13.356769 RX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=139454356
               ACK(0xa8) N=0x00 LL=0x02 MM=0x00
               num_blks=0 num_ts=0 largest_ack=2044202916 ack_delay=25359
               first_ack_block_length=1; [2044202916..2044202915]
    t=43.386083 Timeout
    t=43.386132 TX Short 01(0x01) CID=0xfdeb3167833b8859 PKN=2044202918
               CONNECTION_CLOSE(0x02)
               error_code=NO_ERROR(0x80000000) reason_length=0
    t=43.386317 Closing QUIC connection

License
-------

The MIT License

Copyright (c) 2016 ngtcp2 contributors
