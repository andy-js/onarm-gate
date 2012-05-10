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

#pragma ident	"@(#)strcat.c	1.12	05/06/08 SMI"

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 2007 NEC Corporation
 */


#include "synonyms.h"

#include <string.h>
#include <sys/types.h>

#define WMASK	3
#define IS_WORD_ALIGN_SAME(s1, s2)	((unsigned int)s1 & WMASK) == \
					((unsigned int)s2 & WMASK)

extern char *__strcpy_asm(char *, const char *);

/*
 * Concatenate s2 on the end of s1.  S1's space must be large enough.
 * Return s1.
 */
char *
strcat(char *s1, const char *s2)
{
	char *os1 = s1;
	size_t len;

	len = strlen(s1);
	if (IS_WORD_ALIGN_SAME(s1 + len, s2))
		(void)__strcpy_asm(s1 + len, s2);
	else {
		while (*s1++)
			;
		--s1;
		while (*s1++ = *s2++)
			;
	}
	return (os1);
}
