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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Header File for Clients of Native Identity Mapping Service
 */

#ifndef _IDMAP_H
#define	_IDMAP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <ctype.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/idmap.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Status */
typedef int32_t	idmap_stat;

typedef uint32_t	idmap_rid_t;

/* Opaque client handle */
typedef struct idmap_handle idmap_handle_t;

/* Opaque "get-mapping" handle */
typedef struct idmap_get_handle idmap_get_handle_t;



/*
 * Setup API
 */
/* Create/Init handle for userland clients */
extern idmap_stat idmap_init(idmap_handle_t **);

/* Finalize/close handle */
extern idmap_stat idmap_fini(idmap_handle_t *);

/* Status code to string */
extern const char *idmap_stat2string(idmap_handle_t *, idmap_stat);

/* Free memory allocated by the API */
extern void idmap_free(void *);


/*
 * Directory based name map API
 */

/* Set namemap */
extern idmap_stat idmap_set_namemap(char *, char *, char *,
    char *, char *, char *, int, int, int);

/* Unset namemap */
extern idmap_stat idmap_unset_namemap(char *, char *, char *,
	char *, char *, char *, int, int, int);

extern idmap_stat idmap_get_namemap(int *, char **, char **, int *, char **,
    char **);

/*
 * API to batch SID to UID/GID mapping requests
 */
/* Create handle */
extern idmap_stat idmap_get_create(idmap_handle_t *, idmap_get_handle_t **);

/* Given SID, get UID */
extern idmap_stat idmap_get_uidbysid(idmap_get_handle_t *, char *,
	idmap_rid_t, int, uid_t *, idmap_stat *);

/* Given SID, get GID */
extern idmap_stat idmap_get_gidbysid(idmap_get_handle_t *, char *,
	idmap_rid_t, int, gid_t *, idmap_stat *);

/* Given SID, get UID or GID */
extern idmap_stat idmap_get_pidbysid(idmap_get_handle_t *, char *,
	idmap_rid_t, int, uid_t *, int *, idmap_stat *);

/* Given UID, get SID */
extern idmap_stat idmap_get_sidbyuid(idmap_get_handle_t *, uid_t, int,
	char **, idmap_rid_t *, idmap_stat *);

/* Given GID, get SID */
extern idmap_stat idmap_get_sidbygid(idmap_get_handle_t *, gid_t, int,
	char **, idmap_rid_t *, idmap_stat *);

/* Process the batched requests */
extern idmap_stat idmap_get_mappings(idmap_get_handle_t *);

/* Destroy the handle */
extern void idmap_get_destroy(idmap_get_handle_t *);


/*
 * API to get Windows name by UID/GID and vice-versa
 */
/* Given UID, get Windows name */
extern idmap_stat idmap_getwinnamebyuid(uid_t, char **, char **);

/* Given GID, get Windows name */
extern idmap_stat idmap_getwinnamebygid(gid_t, char **, char **);

/* Given Windows name, get UID */
extern idmap_stat idmap_getuidbywinname(const char *, const char *, uid_t *);

/* Given Windows name, get GID */
extern idmap_stat idmap_getgidbywinname(const char *, const char *, gid_t *);


#ifdef __cplusplus
}
#endif

#endif /* _IDMAP_H */
