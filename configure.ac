# ngtcp2
#
# Copyright (c) 2016 ngtcp2 contributors
# Copyright (c) 2012 nghttp2 contributors
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
AC_PREREQ(2.61)
AC_INIT([ngtcp2], [0.1.0-DEV], [t-tujikawa@users.sourceforge.net])
AC_CONFIG_AUX_DIR([.])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AC_USE_SYSTEM_EXTENSIONS

LT_PREREQ([2.2.6])
LT_INIT()

AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

AM_INIT_AUTOMAKE([subdir-objects])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# See versioning rule:
#  http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
AC_SUBST(LT_CURRENT, 0)
AC_SUBST(LT_REVISION, 0)
AC_SUBST(LT_AGE, 0)

AC_SUBST(CRYPTO_OPENSSL_LT_CURRENT, 0)
AC_SUBST(CRYPTO_OPENSSL_LT_REVISION, 0)
AC_SUBST(CRYPTO_OPENSSL_LT_AGE, 0)

# from nghttp2
major=`echo $PACKAGE_VERSION |cut -d. -f1 | sed -e "s/[^0-9]//g"`
minor=`echo $PACKAGE_VERSION |cut -d. -f2 | sed -e "s/[^0-9]//g"`
patch=`echo $PACKAGE_VERSION |cut -d. -f3 | cut -d- -f1 | sed -e "s/[^0-9]//g"`

PACKAGE_VERSION_NUM=`printf "0x%02x%02x%02x" "$major" "$minor" "$patch"`

AC_SUBST(PACKAGE_VERSION_NUM)

# Checks for command-line options from ngtcp2
AC_ARG_ENABLE([werror],
    [AS_HELP_STRING([--enable-werror],
                    [Turn on compile time warnings])],
    [werror=$enableval], [werror=no])

AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug],
                    [Turn on debug output])],
    [debug=$enableval], [debug=no])

if test "x${debug}" = "x${enableval}"; then
  DEBUGCFLAGS="-O0 -g3"
  AC_SUBST([DEBUGCFLAGS])
fi

AC_ARG_ENABLE(asan,
    AS_HELP_STRING([--enable-asan],
                   [Enable AddressSanitizer (ASAN)]),
    [asan=$enableval], [asan=no])

AC_ARG_WITH([jemalloc],
    [AS_HELP_STRING([--with-jemalloc],
                    [Use jemalloc [default=check]])],
    [request_jemalloc=$withval], [request_jemalloc=check])

# Checks for programs
AC_PROG_CC
AC_PROG_CXX
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_MKDIR_P

PKG_PROG_PKG_CONFIG([0.20])

AX_CXX_COMPILE_STDCXX([14], [noext], [optional])

# Checks for libraries.

# cunit
PKG_CHECK_MODULES([CUNIT], [cunit >= 2.1], [have_cunit=yes], [have_cunit=no])
# If pkg-config does not find cunit, check it using AC_CHECK_LIB.  We
# do this because Debian (Ubuntu) lacks pkg-config file for cunit.
if test "x${have_cunit}" = "xno"; then
  AC_MSG_WARN([${CUNIT_PKG_ERRORS}])
  AC_CHECK_LIB([cunit], [CU_initialize_registry],
               [have_cunit=yes], [have_cunit=no])
  if test "x${have_cunit}" = "xyes"; then
    CUNIT_LIBS="-lcunit"
    CUNIT_CFLAGS=""
    AC_SUBST([CUNIT_LIBS])
    AC_SUBST([CUNIT_CFLAGS])
  fi
fi
if test "x${have_cunit}" = "xyes"; then
  # cunit in Mac OS X requires ncurses. Note that in Mac OS X, test
  # program can be built without -lncurses, but it emits runtime
  # error.
  case "${build}" in
    *-apple-darwin*)
      CUNIT_LIBS="$CUNIT_LIBS -lncurses"
      AC_SUBST([CUNIT_LIBS])
      ;;
  esac
fi

AM_CONDITIONAL([HAVE_CUNIT], [ test "x${have_cunit}" = "xyes" ])

AM_CONDITIONAL([ENABLE_SHARED], [ test "x${enable_shared}" = "xyes" ])

# openssl (for examples)
PKG_CHECK_MODULES([OPENSSL], [openssl >= 1.1.1],
                  [have_openssl=yes], [have_openssl=no])
if test "x${have_openssl}" = "xno"; then
  AC_MSG_NOTICE($OPENSSL_PKG_ERRORS)
fi
AM_CONDITIONAL([HAVE_OPENSSL], [ test "x${have_openssl}" = "xyes" ])

# libnghttp3 (for examples)
PKG_CHECK_MODULES([LIBNGHTTP3], [libnghttp3 >= 0.0.0],
                  [have_libnghttp3=yes], [have_libnghttp3=no])
if test "${have_libnghttp3}" = "xno"; then
  AC_MSG_NOTICE($LIBNGHTTP3_PKG_ERRORS)
fi
AM_CONDITIONAL([HAVE_NGHTTP3], [ test "x${have_libnghttp3}" = "xyes" ])

# libev (for examples)
# libev does not have pkg-config file.  Check it in an old way.
save_LIBS=$LIBS
# android requires -lm for floor
AC_CHECK_LIB([ev], [ev_time], [have_libev=yes], [have_libev=no], [-lm])
if test "x${have_libev}" = "xyes"; then
  AC_CHECK_HEADER([ev.h], [have_libev=yes], [have_libev=no])
  if test "x${have_libev}" = "xyes"; then
    LIBEV_LIBS=-lev
    LIBEV_CFLAGS=
    AC_SUBST([LIBEV_LIBS])
    AC_SUBST([LIBEV_CFLAGS])
  fi
fi
LIBS=$save_LIBS

# jemalloc
have_jemalloc=no
if test "x${request_jemalloc}" != "xno"; then
  save_LIBS=$LIBS
  AC_SEARCH_LIBS([malloc_stats_print], [jemalloc], [have_jemalloc=yes], [],
                 [$PTHREAD_LDFLAGS])

  if test "x${have_jemalloc}" = "xyes"; then
    jemalloc_libs=${ac_cv_search_malloc_stats_print}
  else
    # On Darwin, malloc_stats_print is je_malloc_stats_print
    AC_SEARCH_LIBS([je_malloc_stats_print], [jemalloc], [have_jemalloc=yes], [],
                   [$PTHREAD_LDFLAGS])

    if test "x${have_jemalloc}" = "xyes"; then
      jemalloc_libs=${ac_cv_search_je_malloc_stats_print}
    fi
  fi

  LIBS=$save_LIBS

  if test "x${have_jemalloc}" = "xyes" &&
     test "x${jemalloc_libs}" != "xnone required"; then
    JEMALLOC_LIBS=${jemalloc_libs}
    AC_SUBST([JEMALLOC_LIBS])
  fi
fi

if test "x${request_jemalloc}" = "xyes" &&
   test "x${have_jemalloc}" != "xyes"; then
  AC_MSG_ERROR([jemalloc was requested (--with-jemalloc) but not found])
fi

# Checks for header files.
AC_CHECK_HEADERS([ \
  arpa/inet.h \
  netinet/in.h \
  stddef.h \
  stdint.h \
  stdlib.h \
  string.h \
  unistd.h \
])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_INT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_UID_T
AC_CHECK_TYPES([ptrdiff_t])
AC_C_BIGENDIAN
AC_C_INLINE
AC_SYS_LARGEFILE

# Checks for library functions.
AC_CHECK_FUNCS([ \
  memmove \
  memset \
])

# More compiler flags from nghttp2.
save_CFLAGS=$CFLAGS
save_CXXFLAGS=$CXXFLAGS

CFLAGS=
CXXFLAGS=

if test "x$werror" != "xno"; then
    # For C compiler
    AX_CHECK_COMPILE_FLAG([-Wall], [CFLAGS="$CFLAGS -Wall"])
    AX_CHECK_COMPILE_FLAG([-Wextra], [CFLAGS="$CFLAGS -Wextra"])
    AX_CHECK_COMPILE_FLAG([-Werror], [CFLAGS="$CFLAGS -Werror"])
    AX_CHECK_COMPILE_FLAG([-Wmissing-prototypes], [CFLAGS="$CFLAGS -Wmissing-prototypes"])
    AX_CHECK_COMPILE_FLAG([-Wstrict-prototypes], [CFLAGS="$CFLAGS -Wstrict-prototypes"])
    AX_CHECK_COMPILE_FLAG([-Wmissing-declarations], [CFLAGS="$CFLAGS -Wmissing-declarations"])
    AX_CHECK_COMPILE_FLAG([-Wpointer-arith], [CFLAGS="$CFLAGS -Wpointer-arith"])
    AX_CHECK_COMPILE_FLAG([-Wdeclaration-after-statement], [CFLAGS="$CFLAGS -Wdeclaration-after-statement"])
    AX_CHECK_COMPILE_FLAG([-Wformat-security], [CFLAGS="$CFLAGS -Wformat-security"])
    AX_CHECK_COMPILE_FLAG([-Wwrite-strings], [CFLAGS="$CFLAGS -Wwrite-strings"])
    AX_CHECK_COMPILE_FLAG([-Wshadow], [CFLAGS="$CFLAGS -Wshadow"])
    AX_CHECK_COMPILE_FLAG([-Winline], [CFLAGS="$CFLAGS -Winline"])
    AX_CHECK_COMPILE_FLAG([-Wnested-externs], [CFLAGS="$CFLAGS -Wnested-externs"])
    AX_CHECK_COMPILE_FLAG([-Wfloat-equal], [CFLAGS="$CFLAGS -Wfloat-equal"])
    AX_CHECK_COMPILE_FLAG([-Wundef], [CFLAGS="$CFLAGS -Wundef"])
    AX_CHECK_COMPILE_FLAG([-Wendif-labels], [CFLAGS="$CFLAGS -Wendif-labels"])
    AX_CHECK_COMPILE_FLAG([-Wempty-body], [CFLAGS="$CFLAGS -Wempty-body"])
    AX_CHECK_COMPILE_FLAG([-Wcast-align], [CFLAGS="$CFLAGS -Wcast-align"])
    AX_CHECK_COMPILE_FLAG([-Wclobbered], [CFLAGS="$CFLAGS -Wclobbered"])
    AX_CHECK_COMPILE_FLAG([-Wvla], [CFLAGS="$CFLAGS -Wvla"])
    AX_CHECK_COMPILE_FLAG([-Wpragmas], [CFLAGS="$CFLAGS -Wpragmas"])
    AX_CHECK_COMPILE_FLAG([-Wunreachable-code], [CFLAGS="$CFLAGS -Wunreachable-code"])
    AX_CHECK_COMPILE_FLAG([-Waddress], [CFLAGS="$CFLAGS -Waddress"])
    AX_CHECK_COMPILE_FLAG([-Wattributes], [CFLAGS="$CFLAGS -Wattributes"])
    AX_CHECK_COMPILE_FLAG([-Wdiv-by-zero], [CFLAGS="$CFLAGS -Wdiv-by-zero"])
    AX_CHECK_COMPILE_FLAG([-Wshorten-64-to-32], [CFLAGS="$CFLAGS -Wshorten-64-to-32"])

    AX_CHECK_COMPILE_FLAG([-Wconversion], [CFLAGS="$CFLAGS -Wconversion"])
    AX_CHECK_COMPILE_FLAG([-Wextended-offsetof], [CFLAGS="$CFLAGS -Wextended-offsetof"])
    AX_CHECK_COMPILE_FLAG([-Wformat-nonliteral], [CFLAGS="$CFLAGS -Wformat-nonliteral"])
    AX_CHECK_COMPILE_FLAG([-Wlanguage-extension-token], [CFLAGS="$CFLAGS -Wlanguage-extension-token"])
    AX_CHECK_COMPILE_FLAG([-Wmissing-field-initializers], [CFLAGS="$CFLAGS -Wmissing-field-initializers"])
    AX_CHECK_COMPILE_FLAG([-Wmissing-noreturn], [CFLAGS="$CFLAGS -Wmissing-noreturn"])
    AX_CHECK_COMPILE_FLAG([-Wmissing-variable-declarations], [CFLAGS="$CFLAGS -Wmissing-variable-declarations"])
    # Not used because we cannot change public structs
    # AX_CHECK_COMPILE_FLAG([-Wpadded], [CFLAGS="$CFLAGS -Wpadded"])
    AX_CHECK_COMPILE_FLAG([-Wsign-conversion], [CFLAGS="$CFLAGS -Wsign-conversion"])
    # Not used because this basically disallows default case
    # AX_CHECK_COMPILE_FLAG([-Wswitch-enum], [CFLAGS="$CFLAGS -Wswitch-enum"])
    AX_CHECK_COMPILE_FLAG([-Wunreachable-code-break], [CFLAGS="$CFLAGS -Wunreachable-code-break"])
    AX_CHECK_COMPILE_FLAG([-Wunused-macros], [CFLAGS="$CFLAGS -Wunused-macros"])
    AX_CHECK_COMPILE_FLAG([-Wunused-parameter], [CFLAGS="$CFLAGS -Wunused-parameter"])
    AX_CHECK_COMPILE_FLAG([-Wredundant-decls], [CFLAGS="$CFLAGS -Wredundant-decls"])
    # Only work with Clang for the moment
    AX_CHECK_COMPILE_FLAG([-Wheader-guard], [CFLAGS="$CFLAGS -Wheader-guard"])
    AX_CHECK_COMPILE_FLAG([-Wsometimes-uninitialized], [CFLAGS="$CFLAGS -Wsometimes-uninitialized"])

    # Only work with gcc7 for the moment
    AX_CHECK_COMPILE_FLAG([-Wduplicated-branches], [CFLAGS="$CFLAGS -Wduplicated-branches"])

    # This is required because we pass format string as "const char*.
    AX_CHECK_COMPILE_FLAG([-Wno-format-nonliteral], [CFLAGS="$CFLAGS -Wno-format-nonliteral"])

    # For C++ compiler
    AC_LANG_PUSH(C++)
    AX_CHECK_COMPILE_FLAG([-Wall], [CXXFLAGS="$CXXFLAGS -Wall"])
    # TODO separate option for -Werror and warnings?
    #AX_CHECK_COMPILE_FLAG([-Werror], [CXXFLAGS="$CXXFLAGS -Werror"])
    AX_CHECK_COMPILE_FLAG([-Wformat-security], [CXXFLAGS="$CXXFLAGS -Wformat-security"])
    AX_CHECK_COMPILE_FLAG([-Wsometimes-uninitialized], [CXXFLAGS="$CXXFLAGS -Wsometimes-uninitialized"])
    # Disable noexcept-type warning of g++-7.  This is not harmful as
    # long as all source files are compiled with the same compiler.
    AX_CHECK_COMPILE_FLAG([-Wno-noexcept-type], [CXXFLAGS="$CXXFLAGS -Wno-noexcept-type"])
    AC_LANG_POP()
fi

WARNCFLAGS=$CFLAGS
WARNCXXFLAGS=$CXXFLAGS

CFLAGS=$save_CFLAGS
CXXFLAGS=$save_CXXFLAGS

AC_SUBST([WARNCFLAGS])
AC_SUBST([WARNCXXFLAGS])

if test "x$asan" != "xno"; then
    # Assume both C and C++ compiler either support ASAN or not.
    LDFLAGS_saved="$LDFLAGS"
    LDFLAGS="$LDFLAGS -fsanitize=address"
    AX_CHECK_COMPILE_FLAG([-fsanitize=address],
                          [CFLAGS="$CFLAGS -fsanitize=address"; CXXFLAGS="$CXXFLAGS -fsanitize=address"],
                          [LDFLAGS="$LDFLAGS_saved"])
fi

# extra flags for API function visibility
EXTRACFLAG=
AX_CHECK_COMPILE_FLAG([-fvisibility=hidden], [EXTRACFLAG="-fvisibility=hidden"])

AC_SUBST([EXTRACFLAG])

# debug build
if test "x$debug" != "xno"; then
    AC_DEFINE([DEBUGBUILD], [1], [Define to 1 to enable debug output.])
fi

AC_CONFIG_FILES([
  Makefile
  lib/Makefile
  lib/libngtcp2.pc
  lib/includes/Makefile
  lib/includes/ngtcp2/version.h
  tests/Makefile
  crypto/Makefile
  crypto/openssl/Makefile
  crypto/openssl/libngtcp2_crypto_openssl.pc
  crypto/includes/Makefile
  third-party/Makefile
  examples/Makefile
])
AC_OUTPUT

AC_MSG_NOTICE([summary of build options:

    Package version: ${VERSION}
    Library version: $LT_CURRENT:$LT_REVISION:$LT_AGE
    Install prefix:  ${prefix}
    System types:
      Build:         ${build}
      Host:          ${host}
      Target:        ${target}
    Compiler:
      C preprocessor: ${CPP}
      CPPFLAGS:       ${CPPFLAGS}
      C compiler:     ${CC}
      CFLAGS:         ${CFLAGS}
      C++ compiler:   ${CXX}
      CXXFLAGS:       ${CXXFLAGS}
      LDFLAGS:        ${LDFLAGS}
      WARNCFLAGS:     ${WARNCFLAGS}
      WARNCXXFLAGS:   ${WARNCXXFLAGS}
      EXTRACFLAG:     ${EXTRACFLAG}
      LIBS:           ${LIBS}
    Library:
      Shared:         ${enable_shared}
      Static:         ${enable_static}
    Crypto helper libraries:
      libngtcp2_crypto_openssl: ${have_openssl}
    Test:
      CUnit:          ${have_cunit} (CFLAGS='${CUNIT_CFLAGS}' LIBS='${CUNIT_LIBS}')
    Debug:
      Debug:          ${debug} (CFLAGS='${DEBUGCFLAGS}')
    Libs:
      OpenSSL:        ${have_openssl} (CFLAGS='${OPENSSL_CFLAGS}' LIBS='${OPENSSL_LIBS}')
      Libev:          ${have_libev} (CFLAGS='${LIBEV_CFLAGS}' LIBS='${LIBEV_LIBS}')
      Libnghttp3:     ${have_libnghttp3} (CFLAGS='${LIBNGHTTP3_CFLAGS}' LIBS='${LIBNGHTTP3_LIBS}')
      Jemalloc:       ${have_jemalloc} (LIBS='${JEMALLOC_LIBS}')
])
