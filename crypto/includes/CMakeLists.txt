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

install(FILES
    ngtcp2/ngtcp2_crypto.h
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/ngtcp2")

if(HAVE_OPENSSL)
  install(FILES
      ngtcp2/ngtcp2_crypto_quictls.h
      DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/ngtcp2")
endif()

if(HAVE_GNUTLS)
  install(FILES
      ngtcp2/ngtcp2_crypto_gnutls.h
      DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/ngtcp2")
endif()

if(HAVE_BORINGSSL)
  install(FILES
      ngtcp2/ngtcp2_crypto_boringssl.h
      DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/ngtcp2")
endif()

if(HAVE_PICOTLS)
  install(FILES
      ngtcp2/ngtcp2_crypto_picotls.h
      DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/ngtcp2")
endif()

if(HAVE_WOLFSSL)
  install(FILES
      ngtcp2/ngtcp2_crypto_wolfssl.h
      DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/ngtcp2")
endif()
