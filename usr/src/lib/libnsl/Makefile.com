#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
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
#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2007-2008 NEC Corporation
#
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

LIBRARY= libnsl.a
VERS=	.1

# objects are listed by source directory

# common utility code used in more than one directory
COMMON=		common.o daemon_utils.o

DES=		des_crypt.o des_soft.o

DIAL=		dial.o

IPSEC=		algs.o

NETDIR=		netdir.o

NSS= \
gethostbyname_r.o gethostent.o gethostent_r.o gethostent6.o gethostby_door.o \
getipnodeby_door.o getipnodeby.o getrpcent.o  getrpcent_r.o inet_pton.o \
inet_ntop.o netdir_inet.o netdir_inet_sundry.o \
parse.o getauthattr.o getprofattr.o getexecattr.o getuserattr.o getauuser.o

NETSELECT= netselect.o

NSL=  \
_conn_util.o    _data2.o        _errlst.o \
_utility.o      t_accept.o	t_alloc.o       t_bind.o        t_close.o \
t_connect.o     t_error.o	t_free.o        t_getinfo.o     t_getname.o \
t_getstate.o    t_listen.o	t_look.o        t_open.o        t_optmgmt.o \
t_rcv.o         t_rcvconnect.o	t_rcvdis.o      t_rcvrel.o      t_rcvudata.o \
t_rcvuderr.o    t_snd.o		t_snddis.o      t_sndrel.o      t_sndudata.o \
t_sndv.o	t_sndreldata.o  t_rcvv.o 	t_rcvreldata.o  t_sysconf.o \
t_sndvudata.o	t_rcvvudata.o   t_sync.o        t_unbind.o	t_strerror.o \
xti_wrappers.o

WRAPPERS= \
tli_wrappers.o

RPC= \
auth_des.o	auth_none.o	auth_sys.o	auth_time.o	authdes_prot.o \
authsys_prot.o	can_use_af.o \
clnt_bcast.o	clnt_dg.o	clnt_door.o	clnt_generic.o	clnt_perror.o \
clnt_raw.o	clnt_simple.o	clnt_vc.o	fdsync.o	getdname.o \
inet_ntoa.o	key_call.o	key_prot.o	mt_misc.o \
netname.o	netnamer.o	pmap_clnt.o	pmap_prot.o \
rpc_callmsg.o	rpc_comdata.o	rpc_comdata1.o	rpc_generic.o	rpc_prot.o \
rpc_sel2poll.o \
rpc_soc.o	rpc_td.o	rpcb_clnt.o	rpcb_prot.o \
rpcb_st_xdr.o	rpcdname.o	rpcsec_gss_if.o	rtime_tli.o	svc.o \
svc_auth.o	svc_auth_loopb.o	svc_auth_sys.o	svc_dg.o \
svc_door.o	svc_generic.o	svc_raw.o	svc_run.o	svc_simple.o \
svc_vc.o	svcauth_des.o	svid_funcs.o	ti_opts.o	xdr.o \
xdr_array.o	xdr_float.o	xdr_mem.o	xdr_rec.o	xdr_refer.o \
xdr_sizeof.o	xdr_stdio.o

SAF= checkver.o  doconfig.o

YP=  \
dbm.o           yp_all.o        yp_b_clnt.o     yp_b_xdr.o      yp_bind.o  \
yp_enum.o       yp_master.o     yp_match.o      yp_order.o      yp_update.o \
yperr_string.o  yp_xdr.o        ypprot_err.o    ypupd.o 	\
yp_rsvd.o \
yppasswd_xdr.o

NIS_GEN=  \
nislib.o          nis_callback.o   nis_xdr.o      nis_subr.o     nis_names.o  \
nis_cback_xdr.o   print_obj.o      nis_perror.o   nis_groups.o   nis_tags.o   \
nis_misc.o        nis_lookup.o     nis_rpc.o      nis_clnt.o	 nis_cast.o   \
nis_hash.o	  nis_misc_proc.o  nis_sec_mechs.o npd_lib.o

NIS_CACHE=  cache.o cache_api.o cold_start.o local_cache.o \
	mapped_cache.o client_cache.o mgr_cache.o \
	nis_cache_clnt.o nis_cache_xdr.o

NIS= $(NIS_GEN) $(NIS_CACHE)

KEY= publickey.o xcrypt.o gen_dhkeys.o

$(__ARLIB)$(ARM_BLD)STRADDR= straddr.o

OBJECTS= $(COMMON) $(DES) $(DIAL) $(IPSEC) $(NETDIR) $(NSS) $(NETSELECT) \
	 $(NSL) $(WRAPPERS) $(RPC) $(SAF) $(YP) $(NIS) $(KEY) $(STRADDR)

# libnsl build rules
pics/%.o: ../common/%.c
	$(COMPILE.c)  -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../des/%.c
	$(COMPILE.c)  -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../dial/%.c
	$(COMPILE.c)  -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../ipsec/%.c
	$(COMPILE.c)  -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../netdir/%.c
	$(COMPILE.c)  -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../nss/%.c
	$(COMPILE.c)  -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../netselect/%.c
	$(COMPILE.c)  -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../nsl/%.c
	$(COMPILE.c)  -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../rpc/%.c
	$(COMPILE.c) -DPORTMAP -DNIS  -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../saf/%.c
	$(COMPILE.c)  -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../yp/%.c
	$(COMPILE.c)   -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../key/%.c
	$(COMPILE.c)   -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../nis/gen/%.c ../nis/gen/nis_clnt.h
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../nis/cache/%.c ../nis/cache/nis_clnt.h
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../nis/cache/%.cc ../nis/gen/nis_clnt.h \
	../nis/cache/nis_clnt.h ../nis/cache/nis_cache.h
	$(COMPILE.cc) -o $@ $<
	$(POST_PROCESS_O)

$(__ARLIB)$(ARM_BLD)pics/%.o: ../../nametoaddr/straddr/common/%.c
$(__ARLIB)$(ARM_BLD)	$(COMPILE.c) -o $@ $<
$(__ARLIB)$(ARM_BLD)	$(POST_PROCESS_O)

# include library definitions
include ../../Makefile.lib

# install this library in the root filesystem
include ../../Makefile.rootfs

LIBS =		$(ARLIB) $(DYNLIB) $(LINTLIB)

SRCDIR=		../common
MAPFILES +=	mapfile-vers

# Override the position-independent code generation flags.
#
# These files are particularly rich with references to global things.
# Ordering is by number of got references per file of files that have
# non-performance sensitive code in them.
#
# If you need to add more files and the GOT overflows with "pic" items,
# then use the environment variable LD_OPTIONS=-Dgot,detail to have the
# linker print out the list of GOT hogs..

GOTHOGS =	dial.o print_obj.o clnt_perror.o nsl_stdio_prv.o netdir.o \
		algs.o netselect.o
BIGPICS =	$(GOTHOGS:%=pics/%)
$(BIGPICS) :=	sparc_C_PICFLAGS = $(C_BIGPICFLAGS)
$(BIGPICS) :=	i386_C_PICFLAGS = $(C_BIGPICFLAGS)

# Compile C++ code without exceptions to avoid a dependence on libC.
NOEXCEPTIONS= -noex
CCFLAGS += $(NOEXCEPTIONS)
CCFLAGS64 += $(NOEXCEPTIONS)

CPPFLAGS +=	-I$(SRC)/lib/common/inc -I$(SRC)/lib/libnsl/include -D_REENTRANT
CPPFLAGS +=	-I$(SRC)/lib/libnsl/dial
$(__ARLIB)$(ARM_BLD)CPPFLAGS +=	-DSTATIC_LINK

CFLAGS +=	$(CCVERBOSE)

LIBSCF =	-lscf
$(ARM_BLD)LIBSCF =
LAZYLIBS = $(ZLAZYLOAD) -lmp -lmd $(LIBSCF) $(ZNOLAZYLOAD)
lint := LAZYLIBS = -lmd
LDLIBS +=	$(LAZYLIBS) -lc

$(LINTLIB):=	SRCS=$(SRCDIR)/$(LINTSRC)
LINTFLAGS +=	-m -DPORTMAP
LINTFLAGS64 +=	-m -DPORTMAP

.KEEP_STATE:

all: $(LIBS) fnamecheck

# Don't lint WRAPPERS as they are explicitly unclean
SRCS=	$(DES:%.o=../des/%.c)			\
	$(DIAL:%.o=../dial/%.c)			\
	$(IPSEC:%.o=../ipsec/%.c)		\
	$(NETDIR:%.o=../netdir/%.c)		\
	$(NSS:%.o=../nss/%.c)			\
	$(NETSELECT:%.o=../netselect/%.c)	\
	$(NSL:%.o=../nsl/%.c)			\
	$(RPC:%.o=../rpc/%.c)			\
	$(SAF:%.o=../saf/%.c)			\
	$(YP:%.o=../yp/%.c)			\
	$(NIS_GEN:%.o=../nis/gen/%.c)		\
	$(COMMON:%.o=../common/%.c)		\
	$(STRADDR:%.o=../../nametoaddr/straddr/common/%.c)

lint:
	@$(LINT.c) $(SRCS) $(LDLIBS)

# include library targets
include ../../Makefile.targ
