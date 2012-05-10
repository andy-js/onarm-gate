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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Copyright (c) 2006-2009 NEC Corporation
#

# ident	"@(#)Makefile.com	1.26	06/08/12 SMI"
#

LIB_PIC= libc_pic.a
VERS=	.1
CPP=	$(arm_CPP)
TARGET_ARCH=	arm

VALUES=	values-Xa.o

# objects are grouped by source directory

# local objects
STRETS=

CRTOBJS=			\
	cerror.o		\
	cerror64.o

DYNOBJS=

FPOBJS=				\
	_D_cplx_div.o		\
	_D_cplx_div_ix.o	\
	_D_cplx_div_rx.o	\
	_D_cplx_lr_div.o	\
	_D_cplx_lr_div_ix.o	\
	_D_cplx_lr_div_rx.o	\
	_D_cplx_mul.o		\
	_F_cplx_div.o		\
	_F_cplx_div_ix.o	\
	_F_cplx_div_rx.o	\
	_F_cplx_lr_div.o	\
	_F_cplx_lr_div_ix.o	\
	_F_cplx_lr_div_rx.o	\
	_F_cplx_mul.o		\
	_X_cplx_div.o		\
	_X_cplx_div_ix.o	\
	_X_cplx_div_rx.o	\
	_X_cplx_lr_div.o	\
	_X_cplx_lr_div_ix.o	\
	_X_cplx_lr_div_rx.o	\
	_X_cplx_mul.o		\
	_base_il.o		\
	isnan.o			\
	fpgetmask.o		\
	fpgetround.o		\
	fpgetsticky.o		\
	fpsetmask.o		\
	fpsetround.o		\
	fpsetsticky.o		\
	fpstart.o		\
	modf.o

FPASMOBJS=			\
	__xgetRD.o		\
	_xtoll.o		\
	_xtoull.o		\
	fpcw.o

ATOMICOBJS=			\
	atomic.o

XATTROBJS=			\
	xattr_common.o

COMOBJS=			\
	bcmp.o			\
	bcopy.o			\
	bsearch.o		\
	bzero.o			\
	ffs.o			\
	qsort.o			\
	strtol.o		\
	strtoul.o

# On ARM, fasttrap is not supported.
#DTRACEOBJS=			\
#	dtrace_data.o

COPYOBJS=			\
	__memccpy_asm.o		\
	__memcmp_asm.o		\
	__memcpy_asm.o		\
	__memcpyr_asm.o		\
	__strcpy_asm.o		\

GENOBJS=			\
	__cxa_atexit.o		\
	_convert_fl_ll.o	\
	__udivrem.o		\
	__udivrem_int.o		\
	__udivrem_ll.o		\
	_div64.o		\
	_ext_help.o		\
	_ext_misc.o		\
	_getsp.o		\
	_mul64.o		\
	abs.o			\
	alloca.o		\
	byteorder.o		\
	cuexit.o		\
	ecvt.o			\
	errlst.o		\
	arm_data.o		\
	ladd.o			\
	ldivide.o		\
	lexp10.o		\
	llog10.o		\
	lmul.o			\
	lock.o			\
	lshiftl.o		\
	lsign.o			\
	lsub.o			\
	ltostr.o		\
	makectxt.o		\
	memccpy.o		\
	memchr.o		\
	memcmp.o		\
	memcpy.o		\
	memset.o		\
	new_list.o		\
	setjmp.o		\
	siginfolst.o		\
	siglongjmp.o		\
	strcat.o		\
	strchr.o		\
	strcmp.o		\
	strcpy.o		\
	strlen.o		\
	strncat.o		\
	strncmp.o		\
	strncpy.o		\
	strnlen.o		\
	strrchr.o		\
	gcc_util_sub.o		\
	sync_instruction_memory.o

GENOBJS +=			\
	_arithmetic_fl.o	\
	_cmp_fl.o		\
	_convert_fl.o		\
	_divdi3.o		\
	_divrem.o

# sysobjs that contain large-file interfaces
COMSYSOBJS64=			\
	creat64.o		\
	fstat64.o		\
	fstatvfs64.o		\
	getdents64.o		\
	getrlimit64.o		\
	lseek64.o		\
	lstat64.o		\
	open64.o		\
	pread64.o		\
	pwrite64.o		\
	setrlimit64.o		\
	stat64.o		\
	statvfs64.o

SYSOBJS64=			\
	mmap64.o

COMSYSOBJS=			\
	__clock_timer.o		\
	__getloadavg.o		\
	__rusagesys.o		\
	__signotify.o		\
	__sigrt.o		\
	__time.o		\
	_lgrp_home_fast.o	\
	_lgrpsys.o		\
	_nfssys.o		\
	_portfs.o		\
	_pset.o			\
	_rpcsys.o		\
	_sigaction.o		\
	_so_accept.o		\
	_so_bind.o		\
	_so_connect.o		\
	_so_getpeername.o	\
	_so_getsockname.o	\
	_so_getsockopt.o	\
	_so_listen.o		\
	_so_recv.o		\
	_so_recvfrom.o		\
	_so_recvmsg.o		\
	_so_send.o		\
	_so_sendmsg.o		\
	_so_sendto.o		\
	_so_setsockopt.o	\
	_so_shutdown.o		\
	_so_socket.o		\
	_so_socketpair.o	\
	_sockconfig.o		\
	access.o		\
	acct.o			\
	acl.o			\
	adjtime.o		\
	alarm.o			\
	brk.o			\
	chdir.o			\
	chmod.o			\
	chown.o			\
	chroot.o		\
	cladm.o			\
	close.o			\
	creat.o			\
	dup.o			\
	execve.o		\
	exit.o			\
	facl.o			\
	fchdir.o		\
	fchmod.o		\
	fchown.o		\
	fchroot.o		\
	fcntl.o			\
	fdsync.o		\
	fpathconf.o		\
	fstat.o			\
	fstatfs.o		\
	fstatvfs.o		\
	getcpuid.o		\
	getdents.o		\
	getegid.o		\
	geteuid.o		\
	getgid.o		\
	getgroups.o		\
	gethrtime.o		\
	getitimer.o		\
	getmsg.o		\
	getpid.o		\
	getpmsg.o		\
	getppid.o		\
	getrlimit.o		\
	getuid.o		\
	gtty.o			\
	install_utrap.o		\
	ioctl.o			\
	kaio.o			\
	kill.o			\
	lchown.o		\
	link.o			\
	llseek.o		\
	lseek.o			\
	lstat.o			\
	memcntl.o		\
	mincore.o		\
	mkdir.o			\
	mknod.o			\
	mmap.o			\
	modctl.o		\
	mount.o			\
	mprotect.o		\
	munmap.o		\
	nice.o			\
	ntp_adjtime.o		\
	ntp_gettime.o		\
	open.o			\
	p_online.o		\
	pathconf.o		\
	pause.o			\
	pcsample.o		\
	pollsys.o		\
	pread.o			\
	priocntlset.o		\
	processor_bind.o	\
	processor_info.o	\
	profil.o		\
	putmsg.o		\
	putpmsg.o		\
	pwrite.o		\
	read.o			\
	readlink.o		\
	readv.o			\
	rename.o		\
	resolvepath.o		\
	rmdir.o			\
	seteguid.o		\
	setgid.o		\
	setgroups.o		\
	setitimer.o		\
	setreid.o		\
	setrlimit.o		\
	setuid.o		\
	sigaltstk.o		\
	sigprocmsk.o		\
	sigsendset.o		\
	sigsuspend.o		\
	stat.o			\
	statfs.o		\
	statvfs.o		\
	stty.o			\
	symlink.o		\
	sync.o			\
	sysconfig.o		\
	sysfs.o			\
	sysinfo.o		\
	syslwp.o		\
	times.o			\
	ulimit.o		\
	umask.o			\
	umount2.o		\
	unlink.o		\
	utime.o			\
	utimes.o		\
	utssys.o		\
	uucopy.o		\
	vhangup.o		\
	waitid.o		\
	write.o			\
	writev.o		\
	yield.o

SYSOBJS=			\
	__clock_gettime.o	\
	__getcontext.o		\
	_lwp_mutex_unlock.o	\
	_stack_grow.o		\
	door.o			\
	forkx.o			\
	forkallx.o		\
	getcontext.o		\
	gettimeofday.o		\
	pipe.o			\
	ptrace.o		\
	sysarm.o		\
	syscall.o		\
	tls_get_addr.o		\
	uadmin.o		\
	umount.o		\
	uname.o			\
	vforkx.o

# objects under ../port which contain transitional large file interfaces
PORTGEN64=			\
	_xftw64.o		\
	attropen64.o		\
	ftw64.o			\
	mkstemp64.o		\
	nftw64.o		\
	tell64.o		\
	truncate64.o

# objects from source under ../port
PORTFP=				\
	__flt_decim.o		\
	__flt_rounds.o		\
	__tbl_10_b.o		\
	__tbl_10_h.o		\
	__tbl_10_s.o		\
	__tbl_2_b.o		\
	__tbl_2_h.o		\
	__tbl_2_s.o		\
	__tbl_fdq.o		\
	__tbl_tens.o		\
	__x_power.o		\
	_base_sup.o		\
	aconvert.o		\
	decimal_bin.o		\
	double_decim.o		\
	econvert.o		\
	fconvert.o		\
	file_decim.o		\
	finite.o		\
	fp_data.o		\
	func_decim.o		\
	gconvert.o		\
	hex_bin.o		\
	ieee_globals.o		\
	pack_float.o		\
	sigfpe.o		\
	string_decim.o		\
	qdivrem.o

PORTFP +=			\
	ashldi3.o		\
	ashrdi3.o		\
	cmpdi2.o		\
	divdi3.o		\
	floatdidf.o		\
	floatdisf.o		\
	lshrdi3.o		\
	moddi3.o		\
	muldi3.o		\
	ucmpdi2.o		\
	udivdi3.o		\
	umoddi3.o

PORTGEN=			\
	_env_data.o		\
	_xftw.o			\
	a64l.o			\
	abort.o			\
	addsev.o		\
	assert.o		\
	atof.o			\
	atoi.o			\
	atol.o			\
	atoll.o			\
	attrat.o		\
	attropen.o		\
	atexit.o		\
	atfork.o		\
	basename.o		\
	calloc.o		\
	catgets.o		\
	catopen.o		\
	cfgetispeed.o		\
	cfgetospeed.o		\
	cfree.o			\
	cfsetispeed.o		\
	cfsetospeed.o		\
	cftime.o		\
	clock.o			\
	closedir.o		\
	closefrom.o		\
	confstr.o		\
	crypt.o			\
	csetlen.o		\
	ctime.o			\
	ctime_r.o		\
	deflt.o			\
	directio.o		\
	dirname.o		\
	div.o			\
	drand48.o		\
	dup2.o			\
	env_data.o		\
	err.o			\
	errno.o			\
	euclen.o		\
	event_port.o		\
	execvp.o		\
	fattach.o		\
	fdetach.o		\
	fdopendir.o		\
	fmtmsg.o		\
	ftime.o			\
	ftok.o			\
	ftw.o			\
	gcvt.o			\
	getauxv.o		\
	getcwd.o		\
	getdate_err.o		\
	getdtblsize.o		\
	getenv.o		\
	getexecname.o		\
	getgrnam.o		\
	getgrnam_r.o		\
	gethostid.o		\
	gethostname.o		\
	gethz.o			\
	getisax.o		\
	getloadavg.o		\
	getlogin.o		\
	getmntent.o		\
	getnetgrent.o		\
	getopt.o		\
	getopt_long.o		\
	getpagesize.o		\
	getpw.o			\
	getpwnam.o		\
	getpwnam_r.o		\
	getrusage.o		\
	getspent.o		\
	getspent_r.o		\
	getsubopt.o		\
	gettxt.o		\
	getusershell.o		\
	getut.o			\
	getutx.o		\
	getvfsent.o		\
	getwd.o			\
	getwidth.o		\
	getxby_door.o		\
	gtxt.o			\
	hsearch.o		\
	iconv.o			\
	imaxabs.o		\
	imaxdiv.o		\
	index.o			\
	initgroups.o		\
	insque.o		\
	isaexec.o		\
	isastream.o		\
	isatty.o		\
	killpg.o		\
	klpdlib.o		\
	l64a.o			\
	lckpwdf.o		\
	lconstants.o		\
	lfind.o			\
	lfmt.o			\
	lfmt_log.o		\
	llabs.o			\
	lldiv.o			\
	lltostr.o		\
	localtime.o		\
	lsearch.o		\
	madvise.o		\
	malloc.o		\
	memalign.o		\
	mkdev.o			\
	mkdtemp.o		\
	mkfifo.o		\
	mkstemp.o		\
	mktemp.o		\
	mlock.o			\
	mlockall.o		\
	mon.o			\
	msync.o			\
	munlock.o		\
	munlockall.o		\
	ndbm.o			\
	nftw.o			\
	nlspath_checks.o	\
	nsparse.o		\
	nss_common.o		\
	nss_dbdefs.o		\
	nss_deffinder.o		\
	opendir.o		\
	opt_data.o		\
	perror.o		\
	pfmt.o			\
	pfmt_data.o		\
	pfmt_print.o		\
	plock.o			\
	poll.o			\
	priocntl.o		\
	privlib.o		\
	priv_str_xlate.o	\
	psiginfo.o		\
	psignal.o		\
	pt.o			\
	putpwent.o		\
	putspent.o		\
	raise.o			\
	rand.o			\
	random.o		\
	rctlops.o		\
	readdir.o		\
	readdir_r.o		\
	realpath.o		\
	reboot.o		\
	regexpr.o		\
	remove.o		\
	rewinddir.o		\
	rindex.o		\
	scandir.o		\
	seekdir.o		\
	select.o		\
	select_large_fdset.o	\
	setlabel.o		\
	setpriority.o		\
	settimeofday.o		\
	sh_locks.o		\
	sigflag.o		\
	siglist.o		\
	sigsend.o		\
	sigsetops.o		\
	ssignal.o		\
	stack.o			\
	str2sig.o		\
	strcase_charmap.o	\
	strcasecmp.o		\
	strcspn.o		\
	strdup.o		\
	strerror.o		\
	strlcat.o		\
	strlcpy.o		\
	strncasecmp.o		\
	strpbrk.o		\
	strsignal.o		\
	strspn.o		\
	strstr.o		\
	strtod.o		\
	strtoimax.o		\
	strtok.o		\
	strtok_r.o		\
	strtoll.o		\
	strtoull.o		\
	strtoumax.o		\
	swab.o			\
	swapctl.o		\
	sysconf.o		\
	syslog.o		\
	tcdrain.o		\
	tcflow.o		\
	tcflush.o		\
	tcgetattr.o		\
	tcgetpgrp.o		\
	tcgetsid.o		\
	tcsendbreak.o		\
	tcsetattr.o		\
	tcsetpgrp.o		\
	tell.o			\
	telldir.o		\
	tfind.o			\
	time_data.o		\
	time_gdata.o		\
	truncate.o		\
	tsdalloc.o		\
	tsearch.o		\
	ttyname.o		\
	ttyslot.o		\
	ualarm.o		\
	ucred.o			\
	valloc.o		\
	vlfmt.o			\
	vpfmt.o			\
	waitpid.o		\
	walkstack.o		\
	wdata.o			\
	xgetwidth.o		\
	xpg4.o			\
	xpg6.o

PORTPRINT_W=			\
	doprnt_w.o

PORTPRINT=			\
	doprnt.o		\
	fprintf.o		\
	printf.o		\
	snprintf.o		\
	sprintf.o		\
	vfprintf.o		\
	vprintf.o		\
	vsnprintf.o		\
	vsprintf.o		\
	vwprintf.o		\
	wprintf.o

# c89 variants to support 32-bit size of c89 u/intmax_t (32-bit libc only)
PORTPRINT_C89=			\
	vfprintf_c89.o		\
	vprintf_c89.o		\
	vsnprintf_c89.o		\
	vsprintf_c89.o		\
	vwprintf_c89.o

PORTSTDIO_C89=			\
	vscanf_c89.o		\
	vwscanf_c89.o		\

# portable stdio objects that contain large file interfaces.
# Note: fopen64 is a special case, as we build it small.
PORTSTDIO64=			\
	fopen64.o		\
	fpos64.o

PORTSTDIO_W=			\
	doscan_w.o

PORTSTDIO=			\
	__extensions.o		\
	_endopen.o		\
	_filbuf.o		\
	_findbuf.o		\
	_flsbuf.o		\
	_wrtchk.o		\
	clearerr.o		\
	ctermid.o		\
	ctermid_r.o		\
	cuserid.o		\
	data.o			\
	doscan.o		\
	fdopen.o		\
	feof.o			\
	ferror.o		\
	fgetc.o			\
	fgets.o			\
	fileno.o		\
	flockf.o		\
	flush.o			\
	fopen.o			\
	fpos.o			\
	fputc.o			\
	fputs.o			\
	fread.o			\
	fseek.o			\
	fseeko.o		\
	ftell.o			\
	ftello.o		\
	fwrite.o		\
	getc.o			\
	getchar.o		\
	getpass.o		\
	gets.o			\
	getw.o			\
	mse.o			\
	popen.o			\
	putc.o			\
	putchar.o		\
	puts.o			\
	putw.o			\
	rewind.o		\
	scanf.o			\
	setbuf.o		\
	setbuffer.o		\
	setvbuf.o		\
	system.o		\
	tempnam.o		\
	tmpfile.o		\
	tmpnam_r.o		\
	ungetc.o		\
	vscanf.o		\
	vwscanf.o		\
	wscanf.o

PORTI18N=			\
	__fgetwc_xpg5.o		\
	__fgetws_xpg5.o		\
	__fputwc_xpg5.o		\
	__fputws_xpg5.o		\
	__ungetwc_xpg5.o	\
	getwchar.o		\
	putwchar.o		\
	putws.o			\
	strtows.o		\
	wcsstr.o		\
	wcstoimax.o		\
	wcstol.o		\
	wcstoul.o		\
	wcswcs.o		\
	wmemchr.o		\
	wmemcmp.o		\
	wmemcpy.o		\
	wmemmove.o		\
	wmemset.o		\
	wscasecmp.o		\
	wscat.o			\
	wschr.o			\
	wscmp.o			\
	wscpy.o			\
	wscspn.o		\
	wsdup.o			\
	wslen.o			\
	wsncasecmp.o		\
	wsncat.o		\
	wsncmp.o		\
	wsncpy.o		\
	wspbrk.o		\
	wsprintf.o		\
	wsrchr.o		\
	wsscanf.o		\
	wsspn.o			\
	wstod.o			\
	wstok.o			\
	wstol.o			\
	wstoll.o		\
	wsxfrm.o		\
	gettext.o		\
	gettext_gnu.o		\
	gettext_real.o		\
	gettext_util.o		\
	plural_parser.o		\
	wdresolve.o		\
	_ctype.o		\
	isascii.o		\
	toascii.o

PORTI18N_COND=			\
	wcstol_longlong.o	\
	wcstoul_longlong.o

AIOOBJS=			\
	aio.o			\
	aio_alloc.o		\
	posix_aio.o

RTOBJS=				\
	clock_timer.o		\
	fallocate.o		\
	mqueue.o		\
	pos4obj.o		\
	sched.o			\
	sem.o			\
	shm.o			\
	sigev_thread.o

TPOOLOBJS=			\
	thread_pool.o

THREADSOBJS=			\
	alloc.o			\
	assfail.o		\
	cancel.o		\
	door_calls.o		\
	pthr_attr.o		\
	pthr_barrier.o		\
	pthr_cond.o		\
	pthr_mutex.o		\
	pthr_rwlock.o		\
	pthread.o		\
	rtsched.o		\
	rwlock.o		\
	scalls.o		\
	sema.o			\
	sigaction.o		\
	spawn.o			\
	spawn_fast.o		\
	synch.o			\
	tdb_agent.o		\
	thr.o			\
	thread_interface.o	\
	tls.o			\
	tsd.o

THREADSMACHOBJS=		\
	machdep.o		\
	nodtrace.o

THREADSASMOBJS=			\
	asm_subr.o

UNICODEOBJS=			\
	u8_textprep.o		\
	uconv.o

UNWINDMACHOBJS=			\
	unwind.o

UNWINDASMOBJS=			\
	unwind_frame.o

# objects that implement the transitional large file API
PORTSYS64=			\
	fstatat64.o		\
	lockf64.o		\
	openat64.o

PORTSYS=			\
	_autofssys.o		\
	acctctl.o		\
	bsd_signal.o		\
	corectl.o		\
	exacctsys.o		\
	execl.o			\
	execle.o		\
	execv.o			\
	faccessat.o		\
	fsmisc.o		\
	fstatat.o		\
	getpagesizes.o		\
	getpeerucred.o		\
	inst_sync.o		\
	issetugid.o		\
	label.o			\
	libc_fcntl.o		\
	libc_link.o		\
	libc_open.o		\
	lockf.o			\
	lwp.o			\
	lwp_cond.o		\
	lwp_rwlock.o		\
	lwp_sigmask.o		\
	meminfosys.o		\
	msgsys.o		\
	nfssys.o		\
	openat.o		\
	pgrpsys.o		\
	posix_sigwait.o		\
	ppriv.o			\
	psetsys.o		\
	rctlsys.o		\
	sbrk.o			\
	semsys.o		\
	set_errno.o		\
	sharefs.o		\
	shmsys.o		\
	sidsys.o		\
	siginterrupt.o		\
	signal.o		\
	sigpending.o		\
	sigstack.o		\
	tasksys.o		\
	time.o			\
	time_util.o		\
	ucontext.o		\
	ustat.o			\
	zone.o

PORTREGEX=			\
	glob.o			\
	regcmp.o		\
	regex.o			\
	wordexp.o

MOSTOBJS=			\
	$(STRETS)		\
	$(CRTOBJS)		\
	$(DYNOBJS)		\
	$(FPOBJS)		\
	$(FPASMOBJS)		\
	$(ATOMICOBJS)		\
	$(XATTROBJS)		\
	$(COMOBJS)		\
	$(DTRACEOBJS)		\
	$(COPYOBJS)		\
	$(GENOBJS)		\
	$(PORTFP)		\
	$(PORTGEN)		\
	$(PORTGEN64)		\
	$(PORTI18N)		\
	$(PORTI18N_COND)	\
	$(PORTPRINT)		\
	$(PORTPRINT_C89)	\
	$(PORTPRINT_W)		\
	$(PORTREGEX)		\
	$(PORTSTDIO)		\
	$(PORTSTDIO64)		\
	$(PORTSTDIO_C89)	\
	$(PORTSTDIO_W)		\
	$(PORTSYS)		\
	$(PORTSYS64)		\
	$(AIOOBJS)		\
	$(RTOBJS)		\
	$(TPOOLOBJS)		\
	$(THREADSOBJS)		\
	$(THREADSMACHOBJS)	\
	$(THREADSASMOBJS)	\
	$(UNWINDMACHOBJS)	\
	$(UNWINDASMOBJS)	\
	$(COMSYSOBJS)		\
	$(SYSOBJS)		\
	$(COMSYSOBJS64)		\
	$(SYSOBJS64)		\
	$(VALUES)

$(__GNU_LD)MOSTOBJS +=		\
	$(UNICODEOBJS)

TRACEOBJS=			\
#	plockstat.o

# NOTE:	libc.so.1 must be linked with the minimal crti.o and crtn.o
# modules whose source is provided in the $(SRC)/lib/common directory.
# This must be done because otherwise the Sun C compiler would insert
# its own versions of these modules and those versions contain code
# to call out to C++ initialization functions.  Such C++ initialization
# functions can call back into libc before thread initialization is
# complete and this leads to segmentation violations and other problems.
# Since libc contains no C++ code, linking with the minimal crti.o and
# crtn.o modules is safe and avoids the problems described above.
OBJECTS= $(CRTI) $(MOSTOBJS) $(CRTN)
$(GNUC_ARM_EABI)OBJECTS= $(MOSTOBJS)
CRTSRCS= ../../common/arm

LDPASS_OFF=	$(POUND_SIGN)

# include common library definitions
include ../../Makefile.lib

$(__GNULD)GENOBJS 	+= filter_symbols.o
$(__GNULD)RTLDINFO_OBJS	= sunw_rtldinf.o

# NOTE: libc_i18n.a will be part of libc.so.1.  Therefore, the compilation
# conditions such as the settings of CFLAGS and CPPFLAGS for the libc_i18n stuff
# need to be compatible with the ones for the libc stuff.  Whenever the changes
# that affect the compilation conditions of libc happened, those for libc_i18n
# also need to be updated.

# we need to override the default SONAME here because we might
# be building a variant object (still libc.so.1, but different filename)
SONAME = libc.so.1

CFLAGS += $(CCVERBOSE) $(CTF_FLAGS)

# This is necessary to avoid problems with calling _ex_unwind().
# We probably don't want any inlining anyway.
XINLINE = -xinline=
CFLAGS += $(XINLINE)

# Setting THREAD_DEBUG = -DTHREAD_DEBUG (make THREAD_DEBUG=-DTHREAD_DEBUG ...)
# enables ASSERT() checking in the threads portion of the library.
# This is automatically enabled for DEBUG builds, not for non-debug builds.
THREAD_DEBUG =
$(NOT_RELEASE_BUILD)THREAD_DEBUG = -DTHREAD_DEBUG

CFLAGS += $(THREAD_DEBUG)

ALTPICS= $(TRACEOBJS:%=pics/%)
RTLDINFO_PICS	= $(RTLDINFO_OBJS:%=pics/%)

ZALLEXTRACT		= -zallextract
$(__GNULD)ZALLEXTRACT	= --whole-archive

$(DYNLIB) := PICS += $(ROOTFS_LIBDIR)/libc_i18n.a
$(__GNUC)DYNFLAGS +=	-zforceplt
$(__GNULD)DYNFLAGS +=	$(ZALLEXTRACT)
$(DYNLIB)	:= BUILD.SO = \
	$(LD) -o $@ $(GSHARED) $(LDFLAGS.SO) $(DYNFLAGS) $(PICS) $(ALTPICS) \
		$(RTLDINFO_PICS) $(GCC_SHLIB) $(LDLIBS)

MAPFILE_LIBGCC	= mapfile-libgcc
MAPFILES =	../port/mapfile-vers mapfile-vers $(MAPFILE_LIBGCC)
# XXX: This line must be removed when b86 version of libc_i18n is available.
MAPFILES =	port-mapfile-vers mapfile-vers $(MAPFILE_LIBGCC)

$(__GNULD)MAPFILES =

# Discard all local symbols if GNU ld is used.
$(__GNULD)REDUCE_LOCAL	= --discard-all
DYNFLAGS		+= $(REDUCE_LOCAL)

#
# EXTN_CPPFLAGS and EXTN_CFLAGS set in enclosing Makefile
#
CFLAGS +=	$(EXTN_CFLAGS)
CPPFLAGS=	-D_REENTRANT -D__arm $(EXTN_CPPFLAGS) $(EXTRA_CPPFLAGS)  \
		-I$(LIBCBASE)/inc -I../inc $(CPPFLAGS.master) \
		-D_LMALLOC_NO_PROT_EXEC

# Conditionally add support for making |wordexp()| check whether
# /usr/bin/ksh is ksh93 or not
include ../../../Makefile.ksh93switch
CPPFLAGS +=	-DWORDEXP_KSH93=$(ON_BUILD_KSH93_AS_BINKSH)

$(GNUC_ARM_EABI)arm_EABI_AS_CPPFLAGS	+= -D__VFP_FP__=1
$(GNUC_ARM_OABI)arm_EABI_AS_CPPFLAGS	+= -U__VFP_FP__
ASFLAGS =	-P -_cpp=-P -D_ASM $(CPPFLAGS) $(arm_AS_XARCH) \
		-D__STRICT_ANSI__ $(arm_EABI_AS_CPPFLAGS)
ASFLAGS += $(AS_PICFLAGS)

# Inform the run-time linker about libc specialized initialization
RTLDINFO =	-z rtldinfo=tls_rtldinfo
# Override RTLDINFO for GNU ld
$(__GNULD)RTLDINFO =

DYNFLAGS +=	$(RTLDINFO)

# This value is used to keep room for DT_SUNW_RTLDINF.
$(__GNULD)RTLDINFO_TAG  = 0xdeadbeef
$(__GNULD)ASFLAGS      += -D__RTLDINFO_TAG=$(RTLDINFO_TAG)

# Set RTLDINFO using helper command.
$(__GNULD)SET_RTLDINFO  = $(SYMFILTER) -R -r $(RTLDINFO_TAG):tls_rtldinfo $@
$(__GNULD)POST_PROCESS_SO += ; $(SET_RTLDINFO)

# Current ARM libc doesn't support __rtboot.
#DYNFLAGS +=	-e __rtboot

DYNFLAGS +=	$(EXTN_DYNFLAGS)

# Inform the kernel about the initial DTrace area (in case
# libc is being used as the interpreter / runtime linker).
#DTRACE_DATA		= -zdtrace=dtrace_data
DYNFLAGS		+= $(DTRACE_DATA)

# DTrace needs an executable data segment.
MAPFILE.NED=

$(__GNULD)VERS_SCRIPT	= vers-script

BUILD.s=	$(AS) $(ASFLAGS) $< -o $@

# Override this top level flag so the compiler builds in its native
# C99 mode.  This has been enabled to support the complex arithmetic
# added to libc.
C99MODE=	$(C99_ENABLE)

# libc method of building an archive
BUILD.AR= $(RM) $@ ; \
	$(AR) q $@ `$(LORDER) $(MOSTOBJS:%=$(DIR)/%)| $(TSORT)`

# extra files for the clean target
CLEANFILES=			\
	../port/gen/errlst.c	\
	../port/gen/new_list.c	\
	assym.h			\
	genassym		\
	crt/_rtld.s		\
	crt/_rtbootld.s		\
	pics/_rtbootld.o	\
	pics/crti.o		\
	pics/crtn.o		\
	$(GCC_SHLIB)		\
	$(ALTPICS)		\
	$(RTLDINFO_PICS)

CLOBBERFILES +=	$(LIB_PIC)

# list of C source for lint
SRCS=							\
	$(ATOMICOBJS:%.o=$(SRC)/common/atomic/%.c)	\
	$(XATTROBJS:%.o=$(SRC)/common/xattr/%.c)	\
	$(COMOBJS:%.o=$(SRC)/common/util/%.c)		\
	$(DTRACEOBJS:%.o=$(SRC)/common/dtrace/%.c)	\
	$(PORTFP:%.o=../port/fp/%.c)			\
	$(PORTGEN:%.o=../port/gen/%.c)			\
	$(PORTI18N:%.o=../port/i18n/%.c)		\
	$(PORTPRINT:%.o=../port/print/%.c)		\
	$(PORTREGEX:%.o=../port/regex/%.c)		\
	$(PORTSTDIO:%.o=../port/stdio/%.c)		\
	$(PORTSYS:%.o=../port/sys/%.c)			\
	$(AIOOBJS:%.o=../port/aio/%.c)			\
	$(RTOBJS:%.o=../port/rt/%.c)			\
	$(TPOOLOBJS:%.o=../port/tpool/%.c)		\
	$(THREADSOBJS:%.o=../port/threads/%.c)		\
	$(THREADSMACHOBJS:%.o=../$(MACH)/threads/%.c)	\
	$(UNICODEOBJS:%.o=$(SRC)/common/unicode/%.c)	\
	$(UNWINDMACHOBJS:%.o=../port/unwind/%.c)	\
	$(FPOBJS:%.o=../$(MACH)/fp/%.c)			\
	$(LIBCBASE)/gen/ecvt.c				\
	$(LIBCBASE)/gen/lexp10.c			\
	$(LIBCBASE)/gen/llog10.c			\
	$(LIBCBASE)/gen/ltostr.c			\
	$(LIBCBASE)/gen/makectxt.c			\
	$(LIBCBASE)/gen/siginfolst.c			\
	$(LIBCBASE)/gen/siglongjmp.c			\
	$(LIBCBASE)/gen/strcmp.c			\
	$(LIBCBASE)/gen/sync_instruction_memory.c	\
	$(LIBCBASE)/sys/ptrace.c			\
	$(LIBCBASE)/sys/uadmin.s

# conditional assignments
$(DYNLIB) $(LIB_PIC) := DYNOBJS = _rtbootld.o
$(DYNLIB) := CRTI = crti.o
$(DYNLIB) := CRTN = crtn.o

# Files which need the threads .il inline template
TIL=				\
	aio.o			\
	alloc.o			\
	assfail.o		\
	atexit.o		\
	atfork.o		\
	cancel.o		\
	door_calls.o		\
	errno.o			\
	lwp.o			\
	ma.o			\
	machdep.o		\
	posix_aio.o		\
	pthr_attr.o		\
	pthr_barrier.o		\
	pthr_cond.o		\
	pthr_mutex.o		\
	pthr_rwlock.o		\
	pthread.o		\
	rand.o			\
	rtsched.o		\
	rwlock.o		\
	scalls.o		\
	sema.o			\
	sigaction.o		\
	sigev_thread.o		\
	spawn.o			\
	spawn_fast.o		\
	stack.o			\
	synch.o			\
	tdb_agent.o		\
	thr.o			\
	thread_interface.o	\
	thread_pool.o		\
	tls.o			\
	tsd.o			\
	unwind.o

THREADS_INLINES = $(LIBCBASE)/threads/arm.il
$(TIL:%=pics/%) := CFLAGS += $(THREADS_INLINES)

# pics/mul64.o := CFLAGS += $(LIBCBASE)/crt/mul64.il

# large-file-aware components that should be built large

$(COMSYSOBJS64:%=pics/%) := \
	CPPFLAGS += -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64

$(SYSOBJS64:%=pics/%) := \
	CPPFLAGS += -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64

$(PORTGEN64:%=pics/%) := \
	CPPFLAGS += -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64

$(PORTSTDIO64:%=pics/%) := \
	CPPFLAGS += -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64

$(PORTSYS64:%=pics/%) := \
	CPPFLAGS += -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64

$(PORTSTDIO_W:%=pics/%) := \
	CPPFLAGS += -D_WIDE

$(PORTPRINT_W:%=pics/%) := \
	CPPFLAGS += -D_WIDE

$(PORTPRINT_C89:%=pics/%) := \
	CPPFLAGS += -D_C89_INTMAX32

$(PORTSTDIO_C89:%=pics/%) := \
	CPPFLAGS += -D_C89_INTMAX32

$(PORTI18N_COND:%=pics/%) := \
	CPPFLAGS += -D_WCS_LONGLONG

.KEEP_STATE:

all: $(LIBS) $(LIB_PIC)

lint	:=	CPPFLAGS += -I../$(MACH)/fp
lint	:=	CPPFLAGS += -D_MSE_INT_H -D_LCONV_C99
lint	:=	LINTFLAGS += -mn -erroff=E_SUPPRESSION_DIRECTIVE_UNUSED

lint:
	@echo $(LINT.c) ...
	@$(LINT.c) $(SRCS) $(LDLIBS)

$(LINTLIB):= SRCS=../port/llib-lc
$(LINTLIB):= CPPFLAGS += -D_MSE_INT_H
$(LINTLIB):= LINTFLAGS=-nvx

# object files that depend on inline template
$(TIL:%=pics/%): $(LIBCBASE)/threads/arm.il
# pics/mul64.o: $(LIBCBASE)/crt/mul64.il

# include common libc targets
include ../Makefile.targ

# The Processing mcs was removed for ARM & GNULD
$(ARM_BLD)$(__GNULD)MCS = :

# We need to strip out all CTF and DOF data from the static library
$(LIB_PIC) := DIR = pics
$(LIB_PIC): pics $$(PICS)
	$(BUILD.AR)
	$(MCS) -d -n .SUNW_ctf $@ > /dev/null 2>&1
	$(MCS) -d -n .SUNW_dof $@ > /dev/null 2>&1
	$(AR) -ts $@ > /dev/null
	$(POST_PROCESS_A)

$(LIBCBASE)/crt/_rtbootld.s: $(LIBCBASE)/crt/_rtboot.s $(LIBCBASE)/crt/_rtld.c
	$(CC) $(CPPFLAGS) $(CTF_FLAGS) -O -S $(C_PICFLAGS) \
	    $(LIBCBASE)/crt/_rtld.c -o $(LIBCBASE)/crt/_rtld.s
	$(CAT) $(LIBCBASE)/crt/_rtboot.s $(LIBCBASE)/crt/_rtld.s > $@
	$(RM) $(LIBCBASE)/crt/_rtld.s

# partially built from C source
pics/_rtbootld.o: $(LIBCBASE)/crt/_rtbootld.s
	$(AS) $(ASFLAGS) $(LIBCBASE)/crt/_rtbootld.s -o $@
	$(CTFCONVERT_O)

ASSYMDEP_OBJS=			\
	lock.o			\
	_lwp_mutex_unlock.o	\
	_stack_grow.o		\
	getcontext.o		\
	tls_get_addr.o		\
	vforkx.o		\
	__clock_gettime.o	\
	asm_subr.o

$(ASSYMDEP_OBJS:%=pics/%)	:=	CPPFLAGS += -I.

$(ASSYMDEP_OBJS:%=pics/%): assym.h

# assym.h build rules

CONSTANTS_IN	= ../$(MACH)/constants.in
OFFSETS = ../$(MACH)/offsets.in

assym.h: $(CONSTANTS_IN) $(OFFSETS)
	$(CONSTANTS_CREATE) -o $@ $(CONSTANTS_IN) $(GENCONST_COMPILER)
	$(OFFSETS_CREATE) <$(OFFSETS) >> $@

#
# Setup libc_i18n.a for target ABI mode.
#
# LIBC_I18N_ABI_A			= libc_i18n_EABI.a
# $(GNUC_ARM_OABI)LIBC_I18N_ABI_A	= libc_i18n_OABI.a

# setup_i18n:	$(ROOTFS_LIBDIR)/libc_i18n.a

# $(ROOTFS_LIBDIR)/libc_i18n.a:	$(ROOTFS_LIBDIR)/$(LIBC_I18N_ABI_A)
# 	$(RM) $(ROOTFS_LIBDIR)/libc_i18n.a
# 	$(SYMLINK) $(LIBC_I18N_ABI_A) $(ROOTFS_LIBDIR)/libc_i18n.a

$(DYNLIB):	$(ROOTFS_LIBDIR)/libc_i18n.a

$(__GNUC)$(GCC_SHLIB):
$(__GNUC)$(DYNLIB):	$(GCC_SHLIB)

$(__GNULD)$(DYNLIB):	$(RTLDINFO_PICS) $(MAPFILES)

# derived C source and related explicit dependencies
../port/gen/errlst.c + \
../port/gen/new_list.c: ../port/gen/errlist ../port/gen/errlist.awk
	cd ../port/gen; pwd; $(AWK) -f errlist.awk < errlist

pics/errlst.o: ../port/gen/errlst.c

pics/new_list.o: ../port/gen/new_list.c
