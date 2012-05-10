/*
 * Copyright 1996 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved. The Berkeley Software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 * Copyright (c) 2008 NEC Corporation
 */

#ifndef CSH_SIGNAL_H
#define CSH_SIGNAL_H

#pragma ident	"@(#)signal.h	1.3	05/05/13 SMI"

/*
 * 4.3BSD signal compatibility header
 *
 */
#define sigmask(m)	(m > 32 ? 0 : (1 << ((m)-1)))

/*
 * 4.3BSD signal vector structure used in sigvec call.
 */
struct  sigvec {
        void    (*sv_handler)();        /* signal handler */
        int     sv_mask;                /* signal mask to apply */
        int     sv_flags;               /* see signal options below */
};

#define SV_ONSTACK      0x0001  /* take signal on signal stack */
#define SV_INTERRUPT    0x0002  /* do not restart system on signal return */
#define SV_RESETHAND    0x0004  /* reset handler to SIG_DFL when signal taken */

#define sv_onstack sv_flags

/*
 * Machine dependent data structure
 */
struct  sigcontext {
	int	sc_onstack;		/* sigstack state to restore */
	int	sc_mask;		/* signal mask to restore */
	int	sc_sp;			/* sp to restore */
	int	sc_pc;			/* pc to retore */
	int	sc_lr;			/* lr to restore */
	int	sc_cpsr;		/* cpsr to restore */
};

#define SI_DFLCODE	1

#define BUS_HWERR	BUS_ADRERR	/* misc hardware error (e.g. timeout) */
#define BUS_ALIGN	BUS_ADRALN	/* hardware alignment error */

#define SEGV_NOMAP	SEGV_MAPERR	/* no mapping at the fault address */
#define SEGV_PROT	SEGV_ACCERR	/* access exceeded protections */

/*
 * The SEGV_CODE(code) will be SEGV_NOMAP, SEGV_PROT, or SEGV_OBJERR.
 * In the SEGV_OBJERR case, doing a SEGV_ERRNO(code) gives an errno value
 * reported by the underlying file object mapped at the fault address.
 */

#define SIG_NOADDR	((char *)~0)

#define	SEGV_MAKE_ERR(e) (((e) << 8) | SEGV_MAPERR)

#endif	/* CSH_SIGNAL_H */
