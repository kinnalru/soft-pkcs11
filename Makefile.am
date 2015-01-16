# $Id: Makefile.am,v 1.4 2006/01/11 11:50:24 lha Exp $

lib_LTLIBRARIES = soft-pkcs11.la

INCLUDES = -I$(srcdir)/ref

soft_pkcs11_la_SOURCES =		\
	main.c

soft_pkcs11_la_LDFLAGS = -module
soft_pkcs11_la_LIBADD = -lcrypto

TESTS = run_tests

check_PROGRAMS = run_tests test_soft_pkcs11

test_main.c: main.c
	cp $(srcdir)/main.c test_main.c

test_soft_pkcs11_SOURCES = test_soft_pkcs11.c test_main.c
test_soft_pkcs11_LDADD = -lcrypto

do_subst = sed -e 's,[@]srcdir[@],$(srcdir),g'

run_tests: run_tests.in Makefile
	$(do_subst) < $(srcdir)/run_tests.in > run_tests.tmp
	chmod +x run_tests.tmp
	mv run_tests.tmp run_tests

CLEANFILES = test-rc-file.rc test_main.c

