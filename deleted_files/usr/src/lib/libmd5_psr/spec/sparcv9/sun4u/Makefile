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
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# lib/libmd5_psr/sparcv9/spec/sun4u/Makefile

.KEEP_STATE:

LIBRARY	=	libmd5_psr.a
VERS	=	.1

PLATFORM=	sun4u
CLASS=		64

OBJECTS	=	md5_psr-$(PLATFORM).o

SPECVERS=	-$(PLATFORM)

include	$(SRC)/lib/Makefile.lib
include	$(SRC)/lib/Makefile.lib.64
include $(SRC)/lib/libmd5_psr/spec/Makefile.com

# Uncomment the following if the linker complains
#sparcv9_C_PICFLAGS  = -K PIC

include	$(SRC)/lib/Makefile.spec
include $(SRC)/lib/Makefile.spec.psm

install:
