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
 * Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 */
package com.sun.audit;

// audit event:  AUE_passwd = 6163

public class AuditEvent_passwd extends AuditEvent {

	private native void putEvent(byte[]session, 
	    int status, int ret_val,
	    String	username);

	public AuditEvent_passwd(AuditSession session)
		throws Exception
	{
		super(session);
	}


	private String username_val;	// optional
	public void username(String setTo)
	{
		username_val = setTo;
	}

	public void putEvent(int status, int ret_val)
	{
		byte[]	session = super.sh.getSession();

		if ((super.sh.AuditIsOn) && (super.sh.ValidSession))
			putEvent(session, status, ret_val,
			    username_val);
	}
}
