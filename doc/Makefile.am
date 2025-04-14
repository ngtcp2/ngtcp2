# ngtcp2

# Copyright (c) 2020 ngtcp2 contributors

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

# Minimal makefile for Sphinx documentation
#

# You can set these variables from the command line, and also
# from the environment for the first two.
SPHINXOPTS    ?=
SPHINXBUILD   ?= sphinx-build
SOURCEDIR     = source
BUILDDIR      = build

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

.PHONY: help html apiref cryptoapiref

apiref: mkapiref.py \
	$(top_builddir)/lib/includes/ngtcp2/version.h \
	$(top_srcdir)/lib/includes/ngtcp2/ngtcp2.h
	$(top_srcdir)/doc/mkapiref.py \
	--title='ngtcp2 API reference' \
	source/apiref.rst source/macros.rst source/enums.rst source/types.rst \
	source $(wordlist 2, $(words $^), $^)

cryptoapiref: mkapiref.py \
	$(top_srcdir)/crypto/includes/ngtcp2/ngtcp2_crypto.h \
	$(top_srcdir)/crypto/includes/ngtcp2/ngtcp2_crypto_quictls.h \
	$(top_srcdir)/crypto/includes/ngtcp2/ngtcp2_crypto_gnutls.h \
	$(top_srcdir)/crypto/includes/ngtcp2/ngtcp2_crypto_boringssl.h \
	$(top_srcdir)/crypto/includes/ngtcp2/ngtcp2_crypto_picotls.h \
	$(top_srcdir)/crypto/includes/ngtcp2/ngtcp2_crypto_wolfssl.h \
	$(top_srcdir)/crypto/includes/ngtcp2/ngtcp2_crypto_ossl.h
	$(top_srcdir)/doc/mkapiref.py \
	--title='ngtcp2 crypto API reference' \
	source/crypto_apiref.rst source/crypto_macros.rst \
	source/crypto_enums.rst source/crypto_types.rst \
	source $(wordlist 2, $(words $^), $^)

html-local: apiref cryptoapiref
	@$(SPHINXBUILD) -M html "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

clean-local:
	-rm -rf "$(BUILDDIR)"
