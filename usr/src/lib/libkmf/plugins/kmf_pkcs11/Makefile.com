#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Makefile for KMF Plugins
#

LIBRARY=	kmf_pkcs11.a
VERS=		.1
OBJECTS=	pkcs11_spi.o

include	$(SRC)/lib/Makefile.lib

LIBLINKS=	$(DYNLIB:.so.1=.so)
KMFINC=		-I../../../include -I../../../ber_der/inc

PKCS11LIBS=	-lkmf -lkmfberder -lpkcs11 -lcryptoutil -lc

SRCDIR=		../common
INCDIR=		../../include

CFLAGS		+=	$(CCVERBOSE)
CPPFLAGS	+=	-D_REENTRANT $(KMFINC) -I$(INCDIR)  -I/usr/include/libxml2

PICS=	$(OBJECTS:%=pics/%)
SONAME=	$(PLUGIN)

LDLIBS	+=	$(PKCS11LIBS)

ROOTLIBDIR=	$(ROOT)/usr/lib/security
ROOTLIBDIR64=	$(ROOT)/usr/lib/security/$(MACH64)

.KEEP_STATE:

LIBS	=	$(DYNLIB)

all:	$(LIBS) $(LINTLIB)

lint: lintcheck

FRC:

include $(SRC)/lib/Makefile.targ