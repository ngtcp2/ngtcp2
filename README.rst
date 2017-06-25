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
which is a subset of QUIC transport and QUI TLS draft-04.

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

The client and server under examples directory require boringssl as
crypto backend:

* boringssl (https://boringssl.googlesource.com/boringssl/)

We plan to switch to OpenSSL once TLSv1.3 exporter is implemented in
OpenSSL (see `openssl/openssl#3680
<https://github.com/openssl/openssl/issues/3680>`_).

Build from git
--------------

Firstly, build boringssl:

.. code-block:: text

   $ git clone https://boringssl.googlesource.com/boringssl
   $ cd boringssl
   $ mkdir build
   $ cd build
   $ cmake ..
   $ make
   $ cd ../../

Then build ngtcp2:

.. code-block:: text

   $ git clone https://github.com/ngtcp2/ngtcp2
   $ cd ngtcp2
   $ autoreconf -i
   $ ./configure OPENSSL_CFLAGS=-I$PWD/../boringssl/include OPENSSL_LIBS="-L$PWD/../boringssl/build/ssl -L$PWD/../boringssl/build/crypto -lssl -lcrypto -pthread"

Client/Server
-------------

After successful build, the client and server executable should be
found under examples directory.

.. code-block:: text

    $ examples/client 127.0.0.1 3000
    [  0.000631] send Client Initial packet
                 <conn_id=0x663da7f3ec0fa005, pkt_num=2131773923, ver=0xff000004>
                 STREAM frame
                 <stream_id=0x00000000, offset=0, data_length=147>
    [  0.008070] recv Server Cleartext packet
                 <conn_id=0x0d2b3264360d37bc, pkt_num=113882351, ver=0xff000004>
                 ACK frame
                 <num_blks=0, num_ts=0, largest_ack=2131773923, ack_delay=7008>
                 ; first_ack_block_length=0
                 STREAM frame
                 <stream_id=0x00000000, offset=0, data_length=1196>
    [  0.009220] send Client Cleartext packet
                 <conn_id=0x0d2b3264360d37bc, pkt_num=2131773924, ver=0xff000004>
                 ACK frame
                 <num_blks=0, num_ts=0, largest_ack=113882351, ack_delay=1148>
                 ; first_ack_block_length=0
    [  0.009271] recv Server Cleartext packet
                 <conn_id=0x0d2b3264360d37bc, pkt_num=113882352, ver=0xff000004>
                 STREAM frame
                 <stream_id=0x00000000, offset=1196, data_length=203>
    [  0.010545] send Client Cleartext packet
                 <conn_id=0x0d2b3264360d37bc, pkt_num=2131773925, ver=0xff000004>
                 ACK frame
                 <num_blks=0, num_ts=0, largest_ack=113882352, ack_delay=1273>
                 ; first_ack_block_length=0
                 STREAM frame
                 <stream_id=0x00000000, offset=147, data_length=58>
    [  0.010583] QUIC handshake has completed


.. code-block:: text

    $ examples/server 127.0.0.1 3000 server.key server.crt
    [  1.859533] recv Client Initial packet
                 <conn_id=0x663da7f3ec0fa005, pkt_num=2131773923, ver=0xff000004>
                 STREAM frame
                 <stream_id=0x00000000, offset=0, data_length=147>
                 PADDING frame
                 <length=1076>
    [  1.866546] send Server Cleartext packet
                 <conn_id=0x0d2b3264360d37bc, pkt_num=113882351, ver=0xff000004>
                 ACK frame
                 <num_blks=0, num_ts=0, largest_ack=2131773923, ack_delay=7008>
                 ; first_ack_block_length=0
                 STREAM frame
                 <stream_id=0x00000000, offset=0, data_length=1196>
    [  1.866619] send Server Cleartext packet
                 <conn_id=0x0d2b3264360d37bc, pkt_num=113882352, ver=0xff000004>
                 STREAM frame
                 <stream_id=0x00000000, offset=1196, data_length=203>
    [  1.867923] recv Client Cleartext packet
                 <conn_id=0x0d2b3264360d37bc, pkt_num=2131773924, ver=0xff000004>
                 ACK frame
                 <num_blks=0, num_ts=0, largest_ack=113882351, ack_delay=1148>
                 ; first_ack_block_length=0
    [  1.869424] recv Client Cleartext packet
                 <conn_id=0x0d2b3264360d37bc, pkt_num=2131773925, ver=0xff000004>
                 ACK frame
                 <num_blks=0, num_ts=0, largest_ack=113882352, ack_delay=1273>
                 ; first_ack_block_length=0
                 STREAM frame
                 <stream_id=0x00000000, offset=147, data_length=58>
    [  1.869793] QUIC handshake has completed

License
-------

The MIT License

Copyright (c) 2016 ngtcp2 contributors
