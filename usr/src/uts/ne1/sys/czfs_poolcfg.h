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
 * Copyright (c) 2008-2009 NEC Corporation
 * All rights reserved.
 */

#ifndef	_SYS_CZFS_POOLCFG_H
#define	_SYS_CZFS_POOLCFG_H

#pragma ident	"@(#)ne1/sys/czfs_poolcfg.h"

/* This value should be changed as appropriate. */
#define	CZFS_DEFAULT_PATH	"/sata@disk"

#define	CZFS_DEFAULT_POOL	"ZPOOL"

#define	CZFS_DEFAULT_GUID1	0x475549445f303031ULL		/* "GUID_001" */
#define	CZFS_DEFAULT_GUID2	0x475549445f303032ULL		/* "GUID_002" */

#endif	/* !_SYS_CZFS_POOLCFG_H */
