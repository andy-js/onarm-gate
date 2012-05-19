/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright (c) 2008 NEC Corporation
 * All rights reserved.
 */

#ifndef	_SYS_LPG_CONFIG_H
#define	_SYS_LPG_CONFIG_H

#ident	"@(#)common/sys/lpg_config.h"

/*
 * Header file that determines large page feature should be enabled or not.
 * Kernel build tree private.
 */

#include <sys/types.h>
#include <sys/debug.h>
#include <vm/page.h>
#include <vm/seg_kmem.h>

#ifdef	__cplusplus
extern "C" {
#endif	/* __cplusplus */

#define	SZC_EVAL(szc)		(szc)
#define	SZC_ASSERT(szc)		((void)0)
#define	LPG_DISABLE_ASSERT(ex)	((void)0)
#define	LPG_EVAL(flag)		(flag)

#ifdef	__cplusplus
}
#endif	/* __cplusplus */

#endif	/* !_SYS_LPG_CONFIG_H */
