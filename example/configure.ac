dnl Process this file with autoconf to produce a configure script.
AC_REVISION($Revision: 1.12 $)
AC_PREREQ(2.59)
test -z "$CFLAGS" && CFLAGS="-g"
AC_INIT([soft-pkcs11], 1.8, [lha@it.su.se])
AC_CONFIG_SRCDIR([main.c])
AM_CONFIG_HEADER(config.h)

AM_INIT_AUTOMAKE([foreign no-dependencies 1.9])
AM_MAINTAINER_MODE

dnl Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_CC_STDC

AC_PROG_LIBTOOL

AC_CONFIG_FILES(Makefile)

AH_TOP([#ifndef RCSID
#define RCSID(msg) \
static /**/const char *const rcsid[] = { (const char *)rcsid, "@(#)" msg }
#endif])

AC_OUTPUT

