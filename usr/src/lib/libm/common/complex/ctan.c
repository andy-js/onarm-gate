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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2007 NEC Corporation
 */

#pragma ident	"@(#)ctan.c	1.3	06/01/31 SMI"

#pragma weak ctan = __ctan

/* INDENT OFF */
/*
 * dcomplex ctan(dcomplex z);
 *
 * If z = x+iy, then since ctan(iz) = i*ctanh(z),  we have
 *
 * ctan(z)	= ctan((-1)*(-z)) = ctan(i*i*(-z))
 *		= i*ctanh(i*(-z)) = i*ctanh(i*(-x-yi))
 *		= i*ctanh(y-ix)
 *		= -Im(ctanh(y-ix))+i*Re(ctanh(y-ix))
 */
/* INDENT ON */

#include "libm.h"
#include "complex_wrapper.h"

dcomplex
#if defined(__arm)
__ctan(dcomplex z)
#else
ctan(dcomplex z)
#endif
{
	double x, y;
	dcomplex ans, ct;

	x = D_RE(z);
	y = D_IM(z);
	D_RE(z) = y;
	D_IM(z) = -x;
	ct = ctanh(z);
	D_RE(ans) = -D_IM(ct);
	D_IM(ans) = D_RE(ct);
	return (ans);
}
