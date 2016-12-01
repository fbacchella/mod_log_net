#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT([mod_log_net], [0.3], [fbacchella@spamcop.net])
AC_CONFIG_SRCDIR([mod_log_net.c])

# Checks for programs.
AC_PROG_CC


#### Locate APXS
AC_MSG_NOTICE([Locating apxs])
AC_MSG_CHECKING([for --with-apxs])
AC_ARG_WITH(
        [apxs],
        [AS_HELP_STRING([--with-apxs],[/absolute/path/to/apxs])],
        [WITH_APXS=$with_apxs],
        [WITH_APXS=no]
)
AC_MSG_RESULT([$WITH_APXS])

if test -f "$WITH_APXS" && test -x "$WITH_APXS"
then
        APXS=$WITH_APXS
else
        AC_PATH_PROGS([APXS],[apxs apxs2])
fi

if test "$APXS"
then
        AC_MSG_NOTICE([apxs found at $APXS])
        AC_SUBST([APXS])
else
        AC_MSG_FAILURE([apxs not found])
fi

#### Locate iconv
AC_ARG_WITH(iconv,
  AS_HELP_STRING([--with-iconv=DIR], [iconv base directory]),
  [iconv="$withval"
   CPPFLAGS="$CPPFLAGS -I$withval/include"
   LDFLAGS="$LDFLAGS -L$withval/lib"]
)

AC_CHECK_HEADERS([iconv.h],[],[AC_MSG_FAILURE([iconv headers required])])

AC_SEARCH_LIBS(iconv_open, iconv,,AC_MSG_FAILURE("iconv library not found."))

#### Locate msgpack
AC_ARG_WITH(msgpack,
  AS_HELP_STRING([--with-msgpack=DIR], [msgpack base directory]),
  [msgpack="$withval"
   CPPFLAGS="$CPPFLAGS -I$withval/include"
   LDFLAGS="$LDFLAGS -L$withval/lib"]
)

AC_CHECK_HEADERS([msgpack.h],[],[AC_MSG_FAILURE([msgpack headers required])])

AC_SEARCH_LIBS(msgpack_version, msgpackc,,AC_MSG_FAILURE("msgpack library not found."))

# Checks for library functions.
AC_CHECK_FUNCS([memcpy])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
