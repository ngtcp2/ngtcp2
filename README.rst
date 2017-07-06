ngtcp2
======

"Call it TCP/2.  One More Time."

ngtcp2 project is an effort to implement QUIC protocol which is now
being discussed in IETF QUICWG for its standardization.

Development status
------------------

First Implementation Draft
~~~~~~~~~~~~~~~~~~~~~~~~~~

We are focusing on implementing `First Implementation Draft
<https://github.com/quicwg/base-drafts/wiki/First-Implementation-Draft>`_
which is a subset of QUIC transport and QUIC TLS draft-04.

* https://tools.ietf.org/html/draft-ietf-quic-transport-04
* https://tools.ietf.org/html/draft-ietf-quic-tls-04

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

The client and server under examples directory require boringssl or
OpenSSL (master branch) as crypto backend:

* boringssl (https://boringssl.googlesource.com/boringssl/)
* or, OpenSSL (https://github.com/openssl/openssl/)

At the of time writing, choosing crypto backend from them dictates
TLSv1.3 draft version.  boringssl implements TLSv1.3 draft-18.  On the
other hand, OpenSSL implements TLSv1.3 draft-20.  They are
incompatible.  If you want TLSv1.3 draft-18, choose boringssl.  If you
want TLSv1.3 draft-20, choose OpenSSL.

To build boringssl, golang is required:

* golang

Build from git
--------------

If you choose boringssl, build it like so:

.. code-block:: text

   $ git clone https://boringssl.googlesource.com/boringssl
   $ cd boringssl
   $ mkdir build
   $ cd build
   $ cmake ..
   $ make -j$(nproc)
   $ cd ../../
   $ git clone https://github.com/ngtcp2/ngtcp2
   $ cd ngtcp2
   $ autoreconf -i
   $ ./configure OPENSSL_CFLAGS=-I$PWD/../boringssl/include OPENSSL_LIBS="-L$PWD/../boringssl/build/ssl -L$PWD/../boringssl/build/crypto -lssl -lcrypto -pthread"
   $ make -j$(nproc) check

Otherwise, you choose OpenSSL, build it like so:

.. code-block:: text

   $ git clone --depth 1 https://github.com/openssl/openssl
   $ cd openssl
   $ # For Linux
   $ ./Configure enable-tls1_3 --prefix=$PWD/build linux-x86_64
   $ make -j$(nproc)
   $ make install_sw
   $ cd ..
   $ git clone https://github.com/ngtcp2/ngtcp2
   $ cd ngtcp2
   $ autoreconf -i
   $ ./configure PKG_CONFIG_PATH=$PWD/../openssl/build/lib/pkgconfig LDFLAGS="-Wl,-rpath,$PWD/../openssl/build/lib"
   $ make -j$(nproc) check

Client/Server
-------------

After successful build, the client and server executable should be
found under examples directory.

.. code-block:: text

    $ examples/client 127.0.0.1 3000
    [  0.000213] send Client Initial packet
                 <conn_id=0x06675539ce47c609, pkt_num=417370691, ver=0xff000004>
                 STREAM frame
                 <stream_id=0x00000000, offset=0, data_length=147>
    [  0.003846] recv Server Cleartext packet
                 <conn_id=0x40dd4c3b28596d86, pkt_num=702747551, ver=0xff000004>
                 ACK frame
                 <num_blks=0, num_ts=0, largest_ack=417370691, ack_delay=3387>
                 ; first_ack_block_length=0
                 STREAM frame
                 <stream_id=0x00000000, offset=0, data_length=1196>
    [  0.004460] send Client Cleartext packet
                 <conn_id=0x40dd4c3b28596d86, pkt_num=417370692, ver=0xff000004>
                 ACK frame
                 <num_blks=0, num_ts=0, largest_ack=702747551, ack_delay=616>
                 ; first_ack_block_length=0
    [  0.004497] recv Server Cleartext packet
                 <conn_id=0x40dd4c3b28596d86, pkt_num=702747552, ver=0xff000004>
                 STREAM frame
                 <stream_id=0x00000000, offset=1196, data_length=203>
    [  0.005286] send Client Cleartext packet
                 <conn_id=0x40dd4c3b28596d86, pkt_num=417370693, ver=0xff000004>
                 ACK frame
                 <num_blks=0, num_ts=0, largest_ack=702747552, ack_delay=788>
                 ; first_ack_block_length=0
                 STREAM frame
                 <stream_id=0x00000000, offset=147, data_length=58>
    [  0.005309] QUIC handshake has completed
    [  0.005414] send Short 03 packet
                 <conn_id=0x40dd4c3b28596d86, pkt_num=417370694>
                 CONNECTION_CLOSE frame
                 <error_code=0x80000001, reason_length=0>
    [  0.005766] recv Short 03 packet
                 <conn_id=0x40dd4c3b28596d86, pkt_num=702747553>
                 ACK frame
                 <num_blks=0, num_ts=0, largest_ack=417370693, ack_delay=301>
                 ; first_ack_block_length=0
                 CONNECTION_CLOSE frame
                 <error_code=0x80000001, reason_length=0>
    [  5.001246] Timeout

.. code-block:: text

    $ examples/server 127.0.0.1 3000 server.key server.crt
    [  0.806688] recv Client Initial packet
                 <conn_id=0x06675539ce47c609, pkt_num=417370691, ver=0xff000004>
                 STREAM frame
                 <stream_id=0x00000000, offset=0, data_length=147>
                 PADDING frame
                 <length=1076>
    [  0.810082] send Server Cleartext packet
                 <conn_id=0x40dd4c3b28596d86, pkt_num=702747551, ver=0xff000004>
                 ACK frame
                 <num_blks=0, num_ts=0, largest_ack=417370691, ack_delay=3387>
                 ; first_ack_block_length=0
                 STREAM frame
                 <stream_id=0x00000000, offset=0, data_length=1196>
    [  0.810116] send Server Cleartext packet
                 <conn_id=0x40dd4c3b28596d86, pkt_num=702747552, ver=0xff000004>
                 STREAM frame
                 <stream_id=0x00000000, offset=1196, data_length=203>
    [  0.810785] recv Client Cleartext packet
                 <conn_id=0x40dd4c3b28596d86, pkt_num=417370692, ver=0xff000004>
                 ACK frame
                 <num_blks=0, num_ts=0, largest_ack=702747551, ack_delay=616>
                 ; first_ack_block_length=0
    [  0.811706] recv Client Cleartext packet
                 <conn_id=0x40dd4c3b28596d86, pkt_num=417370693, ver=0xff000004>
                 ACK frame
                 <num_blks=0, num_ts=0, largest_ack=702747552, ack_delay=788>
                 ; first_ack_block_length=0
                 STREAM frame
                 <stream_id=0x00000000, offset=147, data_length=58>
    [  0.811909] QUIC handshake has completed
    [  0.812010] send Short 03 packet
                 <conn_id=0x40dd4c3b28596d86, pkt_num=702747553>
                 ACK frame
                 <num_blks=0, num_ts=0, largest_ack=417370693, ack_delay=301>
                 ; first_ack_block_length=0
                 CONNECTION_CLOSE frame
                 <error_code=0x80000001, reason_length=0>
    [  0.812054] recv Short 03 packet
                 <conn_id=0x40dd4c3b28596d86, pkt_num=417370694>
                 CONNECTION_CLOSE frame
                 <error_code=0x80000001, reason_length=0>
    [  5.811097] Timeout
    [  5.811242] Closing QUIC connection

License
-------

The MIT License

Copyright (c) 2016 ngtcp2 contributors
