# ngtcp2

# Copyright (c) 2019 ngtcp2

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

if(HAVE_CRYPTO)
  add_subdirectory(includes)
endif()

if(HAVE_QUICTLS)
  add_subdirectory(quictls)
elseif(ENABLE_OPENSSL)
  message(WARNING "libngtcp2_crypto_quictls library is disabled due to lack of good quictls")
endif()

if(HAVE_GNUTLS)
  add_subdirectory(gnutls)
elseif(ENABLE_GNUTLS)
  message(WARNING "libngtcp2_crypto_gnutls library is disabled due to lack of good GnuTLS")
endif()

if(HAVE_BORINGSSL)
  add_subdirectory(boringssl)
elseif(ENABLE_BORINGSSL)
  message(WARNING "libngtcp2_crypto_boringssl library is disabled due to lack of good BoringSSL")
endif()

if(HAVE_PICOTLS)
  add_subdirectory(picotls)
elseif(ENABLE_PICOTLS)
  message(WARNING "libngtcp2_crypto_picotls library is disabled due to lack of good Picotls")
endif()

if(HAVE_WOLFSSL)
  add_subdirectory(wolfssl)
elseif(ENABLE_WOLFSSL)
  message(WARNING "libngtcp2_crypto_wolfssl library is disabled due to lack of good wolfSSL")
endif()

if(HAVE_OSSL)
  add_subdirectory(ossl)
elseif(ENABLE_OPENSSL)
  message(WARNING "libngtcp2_crypto_ossl library is disabled due to lack of good ossl")
endif()
