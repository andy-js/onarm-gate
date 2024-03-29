#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libmapmalloc/spec/mapmalloc.spec

function	mallopt
include		<stdlib.h>, <malloc.h>
declaration	int mallopt(int cmd, int value )
version		SUNW_0.7
errno		ENOMEM EAGAIN
exception	$return != 0
binding		nodirect
end		

function	mallinfo
include		<stdlib.h>, <malloc.h>
declaration	struct mallinfo mallinfo(void )
version		SUNW_0.7
errno		ENOMEM EAGAIN
binding		nodirect
end		

function	malloc	extends	libc/spec/gen.spec	malloc
version		SUNW_0.7
binding		nodirect
end		

function	calloc	extends	libc/spec/gen.spec	calloc
version		SUNW_0.7
binding		nodirect
end		

function	free	extends	libc/spec/gen.spec	free
version		SUNW_0.7
binding		nodirect
end		

function	memalign	extends	libc/spec/gen.spec	memalign
version		SUNW_0.7
binding		nodirect
end		

function	realloc	extends	libc/spec/gen.spec	realloc
version		SUNW_0.7
binding		nodirect
end		

function	valloc	extends	libc/spec/gen.spec	valloc
version		SUNW_0.7
binding		nodirect
end		

function	cfree	extends	libc/spec/gen.spec	cfree
version		SUNW_0.7
binding		nodirect
end		

# required by sbcp.
function	__mallinfo
version		SUNWprivate_1.1
binding		nodirect
end		
