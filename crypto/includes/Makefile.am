# ngtcp2

# Copyright (c) 2019 ngtcp2 contributors

# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:

# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
EXTRA_DIST = CMakeLists.txt

nobase_include_HEADERS = ngtcp2/ngtcp2_crypto.h

if HAVE_QUICTLS
nobase_include_HEADERS += ngtcp2/ngtcp2_crypto_quictls.h
endif

if HAVE_GNUTLS
nobase_include_HEADERS += ngtcp2/ngtcp2_crypto_gnutls.h
endif

if HAVE_BORINGSSL
nobase_include_HEADERS += ngtcp2/ngtcp2_crypto_boringssl.h
endif

if HAVE_PICOTLS
nobase_include_HEADERS += ngtcp2/ngtcp2_crypto_picotls.h
endif

if HAVE_WOLFSSL
nobase_include_HEADERS += ngtcp2/ngtcp2_crypto_wolfssl.h
endif

if HAVE_OSSL
nobase_include_HEADERS += ngtcp2/ngtcp2_crypto_ossl.h
endif
