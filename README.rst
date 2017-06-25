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

License
-------

The MIT License

Copyright (c) 2016 ngtcp2 contributors
