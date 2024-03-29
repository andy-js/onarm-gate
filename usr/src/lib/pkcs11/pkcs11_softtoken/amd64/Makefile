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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/pkcs11/pkcs11_softtoken/amd64/Makefile

AES_PSR_OBJECTS =
ARCFOUR_PSR_OBJECTS =  arcfour-x86_64.o
DES_PSR_OBJECTS =
RSA_PSR_OBJECTS =
BIGNUM_PSR_OBJECTS = bignum_amd64.o bignum_amd64_asm.o
BIGNUM_PSR_PICS = $(BIGNUM_PSR_OBJECTS:%=pics/%)
BIGNUM_CFG = -DPSR_MUL
BIGNUM_PSR_SRCS = \
	$(BIGNUMDIR)/amd64/bignum_amd64.c \
	$(BIGNUMDIR)/amd64/bignum_amd64_asm.s

pics/bignum_amd64.o := amd64_COPTFLAG = -xO3

include ../Makefile.com
include ../../../Makefile.lib.64

#
# Overrides
#
CLEANFILES	+= arcfour-x86_64.s

install: all $(ROOTLIBS64) $(ROOTLINKS64)

$(BIGNUM_PSR_PICS) := CFLAGS += $(C_BIGPICFLAGS) $(BIGNUM_CFG)

LINTFLAGS64 += $(BIGNUM_CFG)

pics/arcfour-x86_64.o: arcfour-x86_64.s
	$(COMPILE.s) -o $@ $(AS_BIGPICFLAGS) ${@F:.o=.s}
	$(POST_PROCESS_O)

arcfour-x86_64.s: $(ARCFOURDIR)/amd64/arcfour-x86_64.pl
	$(PERL) $? $@

pics/%.o: $(BIGNUMDIR)/$(MACH64)/%.c
	$(COMPILE.c) -o $@ $(C_BIGPICFLAGS) $(BIGNUM_CFG) $<
	$(POST_PROCESS_O)

pics/%.o: $(BIGNUMDIR)/$(MACH64)/%.s
	$(COMPILE.s) -o $@ $(AS_BIGPICFLAGS) $(BIGNUM_CFG) $<
	$(POST_PROCESS_O)
