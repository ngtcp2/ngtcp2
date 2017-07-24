# ngtcp2

# Copyright (c) 2016 ngtcp2 contributors

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
SUBDIRS = lib tests examples

ACLOCAL_AMFLAGS = -I m4

CERTIFICATE_PASS=QUIC
CERTIFICATE_INFO='/CN=localhost/O=QUIC./C=FR'
CERTIFICATE_KEY=cert/server.key
CERTIFICATE_TMP_KEY=$(CERTIFICATE_KEY).tmp
CERTIFICATE_CSR_FILE=cert/server.csr
CERTIFICATE_CRT_FILE=cert/server.crt

# Format source files using clang-format.  Don't format source files
# under third-party directory since we are not responsible for thier
# coding style.
clang-format:
	CLANGFORMAT=`git config --get clangformat.binary`; \
	test -z $${CLANGFORMAT} && CLANGFORMAT="clang-format"; \
	$${CLANGFORMAT} -i lib/*.{c,h} lib/includes/ngtcp2/*.h \
	examples/*.{cc,h}

#generate certificate (ONLY USE FOR DEMO !)
gen-certificate:
	mkdir -p cert
	openssl genrsa -aes256 -passout pass:$(CERTIFICATE_PASS) -out $(CERTIFICATE_KEY) 2048
	openssl req -passin pass:$(CERTIFICATE_PASS) -new -key $(CERTIFICATE_KEY) -out $(CERTIFICATE_CSR_FILE) -subj $(CERTIFICATE_INFO)
	cp $(CERTIFICATE_KEY) $(CERTIFICATE_TMP_KEY)
	openssl rsa -passin pass:$(CERTIFICATE_PASS) -in $(CERTIFICATE_TMP_KEY) -out $(CERTIFICATE_KEY)
	openssl x509 -req -days 30 -in $(CERTIFICATE_CSR_FILE) -signkey $(CERTIFICATE_KEY) -out $(CERTIFICATE_CRT_FILE)
	rm $(CERTIFICATE_TMP_KEY)

