/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2006-2008 NEC Corporation
 */

	.ident	"@(#)_xtoull.s	1.12	05/06/08 SMI"
	
	.file	"_xtoull.s"

	.globl	__fixunsdfdi
		
#include <SYS.h>

	ENTRY(__xtoull)
	str	lr, [sp, #-8]!		/* stack pointer is 8byte alignment */
	bl	_fref_(__fixunsdfdi)	/* call double->ulong long convert
					   routine */
	ldr	pc, [sp], #8
	SET_SIZE(__xtoull)
