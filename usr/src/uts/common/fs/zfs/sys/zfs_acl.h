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
 * Copyright (c) 2007-2008 NEC Corporation
 */

#ifndef	_SYS_FS_ZFS_ACL_H
#define	_SYS_FS_ZFS_ACL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef _KERNEL
#include <sys/isa_defs.h>
#include <sys/types32.h>
#endif
#include <sys/acl.h>
#include <sys/dmu.h>
#include <sys/zfs_fuid.h>
#include <zfs_types.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct znode_phys;

#define	ACE_SLOT_CNT	6
#define	ZFS_ACL_VERSION_INITIAL 0ULL
#define	ZFS_ACL_VERSION_FUID	1ULL
#define	ZFS_ACL_VERSION		ZFS_ACL_VERSION_FUID

/*
 * ZFS ACLs are store in various forms.
 * Files created with ACL version ZFS_ACL_VERSION_INITIAL
 * will all be created with fixed length ACEs of type
 * zfs_oldace_t.
 *
 * Files with ACL version ZFS_ACL_VERSION_FUID will be created
 * with various sized ACEs.  The abstraction entries will utilize
 * zfs_ace_hdr_t, normal user/group entries will use zfs_ace_t
 * and some specialized CIFS ACEs will use zfs_object_ace_t.
 */

/*
 * All ACEs have a common hdr.  For
 * owner@, group@, and everyone@ this is all
 * thats needed.
 */
typedef struct zfs_ace_hdr {
	uint16_t z_type;
	uint16_t z_flags;
	uint32_t z_access_mask;
} zfs_ace_hdr_t;

typedef zfs_ace_hdr_t zfs_ace_abstract_t;

/*
 * Standard ACE
 */
typedef struct zfs_ace {
	zfs_ace_hdr_t	z_hdr;
	uint64_t	z_fuid;
} zfs_ace_t;

/*
 * The following type only applies to ACE_ACCESS_ALLOWED|DENIED_OBJECT_ACE_TYPE
 * and will only be set/retrieved in a CIFS context.
 */

typedef struct zfs_object_ace {
	zfs_ace_t	z_ace;
	uint8_t		z_object_type[16]; /* object type */
	uint8_t		z_inherit_type[16]; /* inherited object type */
} zfs_object_ace_t;

typedef struct zfs_oldace {
	uint32_t	z_fuid;		/* "who" */
	uint32_t	z_access_mask;  /* access mask */
	uint16_t	z_flags;	/* flags, i.e inheritance */
	uint16_t	z_type;		/* type of entry allow/deny */
} zfs_oldace_t;

typedef struct zfs_acl_phys_v0 {
	objid_t		z_acl_extern_obj;	/* ext acl pieces */
	uint32_t	z_acl_count;		/* Number of ACEs */
	uint16_t	z_acl_version;		/* acl version */
	uint16_t	z_acl_pad;		/* pad */
	zfs_oldace_t	z_ace_data[ACE_SLOT_CNT]; /* 6 standard ACEs */
} zfs_acl_phys_v0_t;

#define	ZFS_ACE_SPACE	(sizeof (zfs_oldace_t) * ACE_SLOT_CNT)

typedef struct zfs_acl_phys {
	objid_t		z_acl_extern_obj;	  /* ext acl pieces */
	uint32_t	z_acl_size;		  /* Number of bytes in ACL */
	uint16_t	z_acl_version;		  /* acl version */
	uint16_t	z_acl_count;		  /* ace count */
	uint8_t		z_ace_data[ZFS_ACE_SPACE]; /* space for embedded ACEs */
} zfs_acl_phys_t;



typedef struct acl_ops {
	uint32_t	(*ace_mask_get) (void *acep); /* get  access mask */
	void 		(*ace_mask_set) (void *acep,
			    uint32_t mask); /* set access mask */
	uint16_t	(*ace_flags_get) (void *acep);	/* get flags */
	void		(*ace_flags_set) (void *acep,
			    uint16_t flags); /* set flags */
	uint16_t	(*ace_type_get)(void *acep); /* get type */
	void		(*ace_type_set)(void *acep,
			    uint16_t type); /* set type */
	uint64_t	(*ace_who_get)(void *acep); /* get who/fuid */
	void		(*ace_who_set)(void *acep,
			    uint64_t who); /* set who/fuid */
	size_t		(*ace_size)(void *acep); /* how big is this ace */
	size_t		(*ace_abstract_size)(void); /* sizeof abstract entry */
	int		(*ace_mask_off)(void); /* off of access mask in ace */
	int		(*ace_data)(void *acep, void **datap);
			    /* ptr to data if any */
} acl_ops_t;

/*
 * A zfs_acl_t structure is composed of a list of zfs_acl_node_t's.
 * Each node will have one or more ACEs associated with it.  You will
 * only have multiple nodes during a chmod operation.   Normally only
 * one node is required.
 */
typedef struct zfs_acl_node {
	list_node_t	z_next;		/* Next chunk of ACEs */
	void		*z_acldata;	/* pointer into actual ACE(s) */
	void		*z_allocdata;	/* pointer to kmem allocated memory */
	size_t		z_allocsize;	/* Size of blob in bytes */
	size_t		z_size;		/* length of ACL data */
	int		z_ace_count;	/* number of ACEs in this acl node */
	int		z_ace_idx;	/* ace iterator positioned on */
} zfs_acl_node_t;

typedef struct zfs_acl {
	int		z_acl_count;	/* Number of ACEs */
	size_t		z_acl_bytes;	/* Number of bytes in ACL */
	uint_t		z_version;	/* version of ACL */
	void		*z_next_ace;	/* pointer to next ACE */
	int		z_hints;	/* ACL hints (ZFS_INHERIT_ACE ...) */
	zfs_acl_node_t	*z_curr_node;	/* current node iterator is handling */
	list_t		z_acl;		/* chunks of ACE data */
	acl_ops_t	z_ops;		/* ACL operations */
	boolean_t	z_has_fuids;	/* FUIDs present in ACL? */
} zfs_acl_t;

#define	ACL_DATA_ALLOCED	0x1
#define	ZFS_ACL_SIZE(aclcnt)	(sizeof (ace_t) * (aclcnt))

/*
 * Property values for acl_mode and acl_inherit.
 *
 * acl_mode can take discard, noallow, groupmask and passthrough.
 * whereas acl_inherit has secure instead of groupmask.
 */

#define	ZFS_ACL_DISCARD		0
#define	ZFS_ACL_NOALLOW		1
#define	ZFS_ACL_GROUPMASK	2
#define	ZFS_ACL_PASSTHROUGH	3
#define	ZFS_ACL_SECURE		4

struct znode;
struct zfsvfs;
struct zfs_fuid_info;

#ifdef _KERNEL
void zfs_perm_init(struct znode *, struct znode *, int, vattr_t *,
    dmu_tx_t *, cred_t *, zfs_acl_t *, zfs_fuid_info_t **);
int zfs_getacl(struct znode *, vsecattr_t *, boolean_t, cred_t *);
int zfs_setacl(struct znode *, vsecattr_t *, boolean_t, cred_t *);
void zfs_acl_rele(void *);
void zfs_oldace_byteswap(ace_t *, int);
void zfs_ace_byteswap(void *, size_t, boolean_t);
extern int zfs_zaccess(struct znode *, int, int, boolean_t, cred_t *);
extern int zfs_zaccess_rwx(struct znode *, mode_t, int, cred_t *);
extern int zfs_zaccess_unix(struct znode *, mode_t, cred_t *);
extern int zfs_acl_access(struct znode *, int, cred_t *);
int zfs_acl_chmod_setattr(struct znode *, zfs_acl_t **, uint64_t);
int zfs_zaccess_delete(struct znode *, struct znode *, cred_t *);
int zfs_zaccess_rename(struct znode *, struct znode *,
    struct znode *, struct znode *, cred_t *cr);
void zfs_acl_free(zfs_acl_t *);
int zfs_vsec_2_aclp(struct zfsvfs *, vtype_t, vsecattr_t *, zfs_acl_t **);
int zfs_aclset_common(struct znode *, zfs_acl_t *, cred_t *,
    struct zfs_fuid_info **, dmu_tx_t *);

#endif

#ifdef	__cplusplus
}
#endif
#endif	/* _SYS_FS_ZFS_ACL_H */
