#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1998-1999 by Sun Microsystems, Inc.
# All rights reserved.
#
# lib/libresolv/spec/Makefile

#
# no sparcv9 build of libresolv
# if it is desirable to build one then uncomment the line below and delete
# the rest of the lines.
#
#include	$(SRC)/lib/Makefile.spec.arch

i386_ARCHITECTURES =	i386
sparc_ARCHITECTURES =	sparc

all		:=	TARGET= all
install		:=	TARGET= install
clean		:=	TARGET= clean
clobber		:=	TARGET= clobber
lint		:=	TARGET= lint

.KEEP_STATE:

all install clean clobber lint: $($(MACH)_ARCHITECTURES)

# spec files do not have msgs or catalogs
_msg catalog:

$($(MACH)_ARCHITECTURES): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
