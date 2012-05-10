
# line 2 "../ipf_y.y"
/*
 * Copyright (C) 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "ipf.h"
#include <sys/ioctl.h>
#include <syslog.h>
#ifdef IPFILTER_BPF
# include "pcap-bpf.h"
# define _NET_BPF_H_
# include <pcap.h>
#endif
#include "netinet/ip_pool.h"
#include "netinet/ip_htable.h"
#include "netinet/ipl.h"
#include "ipf_l.h"

#define	YYDEBUG	1
#define	DOALL(x)	for (fr = frc; fr != NULL; fr = fr->fr_next) { x }
#define	DOREM(x)	for (; fr != NULL; fr = fr->fr_next) { x }

#define OPTION_LOG              0x1
#define OPTION_QUICK            0x2
#define OPTION_DUP              0x4
#define OPTION_PROUTE           0x8
#define OPTION_ON               0x10
#define OPTION_REPLYTO          0x20
#define OPTION_FROUTE           0x40

extern	void	yyerror __P((char *));
extern	int	yyparse __P((void));
extern	int	yylex __P((void));
extern	int	yydebug;
extern	FILE	*yyin;
extern	int	yylineNum;

static	void	newrule __P((void));
static	void	setipftype __P((void));
static	u_32_t	lookuphost __P((char *, i6addr_t *));
static	void	dobpf __P((int, char *));
static	void	resetaddr __P((void));
static	struct	alist_s	*newalist __P((struct alist_s *));
static	u_int	makehash __P((struct alist_s *));
static	int	makepool __P((struct alist_s *));
static	frentry_t *addrule __P((void));
static	void	setsyslog __P((void));
static	void	unsetsyslog __P((void));
static	void	fillgroup __P((frentry_t *));

frentry_t	*fr = NULL, *frc = NULL, *frtop = NULL, *frold = NULL;

static	int		ifpflag = 0;
static	int		nowith = 0;
static	int		dynamic = -1;
static	int		pooled = 0;
static	int		hashed = 0;
static	int		nrules = 0;
static	int		newlist = 0;
static	int		added = 0;
static	int		ipffd = -1;
static  int             ruleopts = 0;
static	int		*yycont = 0;
static	ioctlfunc_t	ipfioctl[IPL_LOGSIZE];
static	addfunc_t	ipfaddfunc = NULL;
static	struct	wordtab ipfwords[96];
static	struct	wordtab	addrwords[4];
static	struct	wordtab	maskwords[5];
static	struct	wordtab icmpcodewords[17];
static	struct	wordtab icmptypewords[16];
static	struct	wordtab ipv4optwords[25];
static	struct	wordtab ipv4secwords[9];
static	struct	wordtab ipv6optwords[8];
static	struct	wordtab logwords[33];
static  int             set_ipv6_addr = 0;


# line 85 "../ipf_y.y"
typedef union
#ifdef __cplusplus
	YYSTYPE
#endif
	{
	char	*str;
	u_32_t	num;
	struct	in_addr	ipa;
	frentry_t	fr;
	frtuc_t	*frt;
	struct	alist_s	*alist;
	u_short	port;
	struct	{
		u_short	p1;
		u_short	p2;
		int	pc;
	} pc;
	struct	{
		union	i6addr	a;
		union	i6addr	m;
	} ipp;
	union	i6addr	ip6;
} YYSTYPE;
# define YY_NUMBER 257
# define YY_HEX 258
# define YY_STR 259
# define YY_COMMENT 260
# define YY_CMP_EQ 261
# define YY_CMP_NE 262
# define YY_CMP_LE 263
# define YY_CMP_GE 264
# define YY_CMP_LT 265
# define YY_CMP_GT 266
# define YY_RANGE_OUT 267
# define YY_RANGE_IN 268
# define YY_IPV6 269
# define IPFY_PASS 270
# define IPFY_BLOCK 271
# define IPFY_COUNT 272
# define IPFY_CALL 273
# define IPFY_RETICMP 274
# define IPFY_RETRST 275
# define IPFY_RETICMPASDST 276
# define IPFY_IN 277
# define IPFY_OUT 278
# define IPFY_QUICK 279
# define IPFY_ON 280
# define IPFY_OUTVIA 281
# define IPFY_INVIA 282
# define IPFY_DUPTO 283
# define IPFY_TO 284
# define IPFY_FROUTE 285
# define IPFY_REPLY_TO 286
# define IPFY_ROUTETO 287
# define IPFY_TOS 288
# define IPFY_TTL 289
# define IPFY_PROTO 290
# define IPFY_HEAD 291
# define IPFY_GROUP 292
# define IPFY_AUTH 293
# define IPFY_PREAUTH 294
# define IPFY_LOG 295
# define IPFY_BODY 296
# define IPFY_FIRST 297
# define IPFY_LEVEL 298
# define IPFY_ORBLOCK 299
# define IPFY_LOGTAG 300
# define IPFY_MATCHTAG 301
# define IPFY_SETTAG 302
# define IPFY_SKIP 303
# define IPFY_FROM 304
# define IPFY_ALL 305
# define IPFY_ANY 306
# define IPFY_BPFV4 307
# define IPFY_BPFV6 308
# define IPFY_POOL 309
# define IPFY_HASH 310
# define IPFY_PPS 311
# define IPFY_ESP 312
# define IPFY_AH 313
# define IPFY_WITH 314
# define IPFY_AND 315
# define IPFY_NOT 316
# define IPFY_NO 317
# define IPFY_OPT 318
# define IPFY_TCPUDP 319
# define IPFY_TCP 320
# define IPFY_UDP 321
# define IPFY_FLAGS 322
# define IPFY_MULTICAST 323
# define IPFY_MASK 324
# define IPFY_BROADCAST 325
# define IPFY_NETWORK 326
# define IPFY_NETMASKED 327
# define IPFY_PEER 328
# define IPFY_PORT 329
# define IPFY_NOW 330
# define IPFY_ICMP 331
# define IPFY_ICMPTYPE 332
# define IPFY_ICMPCODE 333
# define IPFY_IPOPTS 334
# define IPFY_SHORT 335
# define IPFY_NAT 336
# define IPFY_BADSRC 337
# define IPFY_LOWTTL 338
# define IPFY_FRAG 339
# define IPFY_MBCAST 340
# define IPFY_BAD 341
# define IPFY_BADNAT 342
# define IPFY_OOW 343
# define IPFY_NEWISN 344
# define IPFY_NOICMPERR 345
# define IPFY_KEEP 346
# define IPFY_STATE 347
# define IPFY_FRAGS 348
# define IPFY_LIMIT 349
# define IPFY_STRICT 350
# define IPFY_AGE 351
# define IPFY_SYNC 352
# define IPFY_FRAGBODY 353
# define IPFY_IPOPT_NOP 354
# define IPFY_IPOPT_RR 355
# define IPFY_IPOPT_ZSU 356
# define IPFY_IPOPT_MTUP 357
# define IPFY_IPOPT_MTUR 358
# define IPFY_IPOPT_ENCODE 359
# define IPFY_IPOPT_TS 360
# define IPFY_IPOPT_TR 361
# define IPFY_IPOPT_SEC 362
# define IPFY_IPOPT_LSRR 363
# define IPFY_IPOPT_ESEC 364
# define IPFY_IPOPT_CIPSO 365
# define IPFY_IPOPT_SATID 366
# define IPFY_IPOPT_SSRR 367
# define IPFY_IPOPT_ADDEXT 368
# define IPFY_IPOPT_VISA 369
# define IPFY_IPOPT_IMITD 370
# define IPFY_IPOPT_EIP 371
# define IPFY_IPOPT_FINN 372
# define IPFY_IPOPT_DPS 373
# define IPFY_IPOPT_SDB 374
# define IPFY_IPOPT_NSAPA 375
# define IPFY_IPOPT_RTRALRT 376
# define IPFY_IPOPT_UMP 377
# define IPFY_SECCLASS 378
# define IPFY_SEC_UNC 379
# define IPFY_SEC_CONF 380
# define IPFY_SEC_RSV1 381
# define IPFY_SEC_RSV2 382
# define IPFY_SEC_RSV4 383
# define IPFY_SEC_SEC 384
# define IPFY_SEC_TS 385
# define IPFY_SEC_RSV3 386
# define IPF6_V6HDRS 387
# define IPFY_IPV6OPT 388
# define IPFY_IPV6OPT_DSTOPTS 389
# define IPFY_IPV6OPT_HOPOPTS 390
# define IPFY_IPV6OPT_IPV6 391
# define IPFY_IPV6OPT_NONE 392
# define IPFY_IPV6OPT_ROUTING 393
# define IPFY_ICMPT_UNR 394
# define IPFY_ICMPT_ECHO 395
# define IPFY_ICMPT_ECHOR 396
# define IPFY_ICMPT_SQUENCH 397
# define IPFY_ICMPT_REDIR 398
# define IPFY_ICMPT_TIMEX 399
# define IPFY_ICMPT_PARAMP 400
# define IPFY_ICMPT_TIMEST 401
# define IPFY_ICMPT_TIMESTREP 402
# define IPFY_ICMPT_INFOREQ 403
# define IPFY_ICMPT_INFOREP 404
# define IPFY_ICMPT_MASKREQ 405
# define IPFY_ICMPT_MASKREP 406
# define IPFY_ICMPT_ROUTERAD 407
# define IPFY_ICMPT_ROUTERSOL 408
# define IPFY_ICMPC_NETUNR 409
# define IPFY_ICMPC_HSTUNR 410
# define IPFY_ICMPC_PROUNR 411
# define IPFY_ICMPC_PORUNR 412
# define IPFY_ICMPC_NEEDF 413
# define IPFY_ICMPC_SRCFAIL 414
# define IPFY_ICMPC_NETUNK 415
# define IPFY_ICMPC_HSTUNK 416
# define IPFY_ICMPC_ISOLATE 417
# define IPFY_ICMPC_NETPRO 418
# define IPFY_ICMPC_HSTPRO 419
# define IPFY_ICMPC_NETTOS 420
# define IPFY_ICMPC_HSTTOS 421
# define IPFY_ICMPC_FLTPRO 422
# define IPFY_ICMPC_HSTPRE 423
# define IPFY_ICMPC_CUTPRE 424
# define IPFY_FAC_KERN 425
# define IPFY_FAC_USER 426
# define IPFY_FAC_MAIL 427
# define IPFY_FAC_DAEMON 428
# define IPFY_FAC_AUTH 429
# define IPFY_FAC_SYSLOG 430
# define IPFY_FAC_LPR 431
# define IPFY_FAC_NEWS 432
# define IPFY_FAC_UUCP 433
# define IPFY_FAC_CRON 434
# define IPFY_FAC_LOCAL0 435
# define IPFY_FAC_LOCAL1 436
# define IPFY_FAC_LOCAL2 437
# define IPFY_FAC_LOCAL3 438
# define IPFY_FAC_LOCAL4 439
# define IPFY_FAC_LOCAL5 440
# define IPFY_FAC_LOCAL6 441
# define IPFY_FAC_LOCAL7 442
# define IPFY_FAC_SECURITY 443
# define IPFY_FAC_FTP 444
# define IPFY_FAC_AUTHPRIV 445
# define IPFY_FAC_AUDIT 446
# define IPFY_FAC_LFMT 447
# define IPFY_FAC_CONSOLE 448
# define IPFY_PRI_EMERG 449
# define IPFY_PRI_ALERT 450
# define IPFY_PRI_CRIT 451
# define IPFY_PRI_ERR 452
# define IPFY_PRI_WARN 453
# define IPFY_PRI_NOTICE 454
# define IPFY_PRI_INFO 455
# define IPFY_PRI_DEBUG 456
# define IPFY_SET_LOOPBACK 457
# define IPFY_SET 458

#include <inttypes.h>

#ifdef __STDC__
#include <stdlib.h>
#include <string.h>
#define	YYCONST	const
#else
#include <malloc.h>
#include <memory.h>
#define	YYCONST
#endif

#include <values.h>

#if defined(__cplusplus) || defined(__STDC__)

#if defined(__cplusplus) && defined(__EXTERN_C__)
extern "C" {
#endif
#ifndef yyerror
#if defined(__cplusplus)
	void yyerror(YYCONST char *);
#endif
#endif
#ifndef yylex
	int yylex(void);
#endif
	int yyparse(void);
#if defined(__cplusplus) && defined(__EXTERN_C__)
}
#endif

#endif

#define yyclearin yychar = -1
#define yyerrok yyerrflag = 0
extern int yychar;
extern int yyerrflag;
YYSTYPE yylval;
YYSTYPE yyval;
typedef int yytabelem;
#ifndef YYMAXDEPTH
#define YYMAXDEPTH 150
#endif
#if YYMAXDEPTH > 0
int yy_yys[YYMAXDEPTH], *yys = yy_yys;
YYSTYPE yy_yyv[YYMAXDEPTH], *yyv = yy_yyv;
#else	/* user does initial allocation */
int *yys;
YYSTYPE *yyv;
#endif
static int yymaxdepth = YYMAXDEPTH;
# define YYERRCODE 256

# line 1547 "../ipf_y.y"



static	struct	wordtab ipfwords[96] = {
	{ "age",			IPFY_AGE },
	{ "ah",				IPFY_AH },
	{ "all",			IPFY_ALL },
	{ "and",			IPFY_AND },
	{ "auth",			IPFY_AUTH },
	{ "bad",			IPFY_BAD },
	{ "bad-nat",			IPFY_BADNAT },
	{ "bad-src",			IPFY_BADSRC },
	{ "bcast",			IPFY_BROADCAST },
	{ "block",			IPFY_BLOCK },
	{ "body",			IPFY_BODY },
	{ "bpf-v4",			IPFY_BPFV4 },
#ifdef USE_INET6
	{ "bpf-v6",			IPFY_BPFV6 },
#endif
	{ "call",			IPFY_CALL },
	{ "code",			IPFY_ICMPCODE },
	{ "count",			IPFY_COUNT },
	{ "dup-to",			IPFY_DUPTO },
	{ "eq",				YY_CMP_EQ },
	{ "esp",			IPFY_ESP },
	{ "fastroute",			IPFY_FROUTE },
	{ "first",			IPFY_FIRST },
	{ "flags",			IPFY_FLAGS },
	{ "frag",			IPFY_FRAG },
	{ "frag-body",			IPFY_FRAGBODY },
	{ "frags",			IPFY_FRAGS },
	{ "from",			IPFY_FROM },
	{ "ge",				YY_CMP_GE },
	{ "group",			IPFY_GROUP },
	{ "gt",				YY_CMP_GT },
	{ "head",			IPFY_HEAD },
	{ "icmp",			IPFY_ICMP },
	{ "icmp-type",			IPFY_ICMPTYPE },
	{ "in",				IPFY_IN },
	{ "in-via",			IPFY_INVIA },
	{ "intercept_loopback",		IPFY_SET_LOOPBACK },
	{ "ipopt",			IPFY_IPOPTS },
	{ "ipopts",			IPFY_IPOPTS },
	{ "keep",			IPFY_KEEP },
	{ "le",				YY_CMP_LE },
	{ "level",			IPFY_LEVEL },
	{ "limit",			IPFY_LIMIT },
	{ "log",			IPFY_LOG },
	{ "lowttl",			IPFY_LOWTTL },
	{ "lt",				YY_CMP_LT },
	{ "mask",			IPFY_MASK },
	{ "match-tag",			IPFY_MATCHTAG },
	{ "mbcast",			IPFY_MBCAST },
	{ "mcast",			IPFY_MULTICAST },
	{ "multicast",			IPFY_MULTICAST },
	{ "nat",			IPFY_NAT },
	{ "ne",				YY_CMP_NE },
	{ "net",			IPFY_NETWORK },
	{ "newisn",			IPFY_NEWISN },
	{ "no",				IPFY_NO },
	{ "no-icmp-err",		IPFY_NOICMPERR },
	{ "now",			IPFY_NOW },
	{ "not",			IPFY_NOT },
	{ "oow",			IPFY_OOW },
	{ "on",				IPFY_ON },
	{ "opt",			IPFY_OPT },
	{ "or-block",			IPFY_ORBLOCK },
	{ "out",			IPFY_OUT },
	{ "out-via",			IPFY_OUTVIA },
	{ "pass",			IPFY_PASS },
	{ "port",			IPFY_PORT },
	{ "pps",			IPFY_PPS },
	{ "preauth",			IPFY_PREAUTH },
	{ "proto",			IPFY_PROTO },
	{ "quick",			IPFY_QUICK },
	{ "reply-to",			IPFY_REPLY_TO },
	{ "return-icmp",		IPFY_RETICMP },
	{ "return-icmp-as-dest",	IPFY_RETICMPASDST },
	{ "return-rst",			IPFY_RETRST },
	{ "route-to",			IPFY_ROUTETO },
	{ "sec-class",			IPFY_SECCLASS },
	{ "set-tag",			IPFY_SETTAG },
	{ "set",			IPFY_SET },
	{ "skip",			IPFY_SKIP },
	{ "short",			IPFY_SHORT },
	{ "state",			IPFY_STATE },
	{ "state-age",			IPFY_AGE },
	{ "strict",			IPFY_STRICT },
	{ "sync",			IPFY_SYNC },
	{ "tcp",			IPFY_TCP },
	{ "tcp-udp",			IPFY_TCPUDP },
	{ "tos",			IPFY_TOS },
	{ "to",				IPFY_TO },
	{ "ttl",			IPFY_TTL },
	{ "udp",			IPFY_UDP },
	{ "v6hdrs",			IPF6_V6HDRS },
	{ "with",			IPFY_WITH },
	{ NULL,				0 }
};

static	struct	wordtab	addrwords[4] = {
	{ "any",			IPFY_ANY },
	{ "hash",			IPFY_HASH },
	{ "pool",			IPFY_POOL },
	{ NULL,				0 }
};

static	struct	wordtab	maskwords[5] = {
	{ "broadcast",			IPFY_BROADCAST },
	{ "netmasked",			IPFY_NETMASKED },
	{ "network",			IPFY_NETWORK },
	{ "peer",			IPFY_PEER },
	{ NULL,				0 }
};

static	struct	wordtab icmptypewords[16] = {
	{ "echo",			IPFY_ICMPT_ECHO },
	{ "echorep",			IPFY_ICMPT_ECHOR },
	{ "inforeq",			IPFY_ICMPT_INFOREQ },
	{ "inforep",			IPFY_ICMPT_INFOREP },
	{ "maskrep",			IPFY_ICMPT_MASKREP },
	{ "maskreq",			IPFY_ICMPT_MASKREQ },
	{ "paramprob",			IPFY_ICMPT_PARAMP },
	{ "redir",			IPFY_ICMPT_REDIR },
	{ "unreach",			IPFY_ICMPT_UNR },
	{ "routerad",			IPFY_ICMPT_ROUTERAD },
	{ "routersol",			IPFY_ICMPT_ROUTERSOL },
	{ "squench",			IPFY_ICMPT_SQUENCH },
	{ "timest",			IPFY_ICMPT_TIMEST },
	{ "timestrep",			IPFY_ICMPT_TIMESTREP },
	{ "timex",			IPFY_ICMPT_TIMEX },
	{ NULL,				0 },
};

static	struct	wordtab icmpcodewords[17] = {
	{ "cutoff-preced",		IPFY_ICMPC_CUTPRE },
	{ "filter-prohib",		IPFY_ICMPC_FLTPRO },
	{ "isolate",			IPFY_ICMPC_ISOLATE },
	{ "needfrag",			IPFY_ICMPC_NEEDF },
	{ "net-prohib",			IPFY_ICMPC_NETPRO },
	{ "net-tos",			IPFY_ICMPC_NETTOS },
	{ "host-preced",		IPFY_ICMPC_HSTPRE },
	{ "host-prohib",		IPFY_ICMPC_HSTPRO },
	{ "host-tos",			IPFY_ICMPC_HSTTOS },
	{ "host-unk",			IPFY_ICMPC_HSTUNK },
	{ "host-unr",			IPFY_ICMPC_HSTUNR },
	{ "net-unk",			IPFY_ICMPC_NETUNK },
	{ "net-unr",			IPFY_ICMPC_NETUNR },
	{ "port-unr",			IPFY_ICMPC_PORUNR },
	{ "proto-unr",			IPFY_ICMPC_PROUNR },
	{ "srcfail",			IPFY_ICMPC_SRCFAIL },
	{ NULL,				0 },
};

static	struct	wordtab ipv4optwords[25] = {
	{ "addext",			IPFY_IPOPT_ADDEXT },
	{ "cipso",			IPFY_IPOPT_CIPSO },
	{ "dps",			IPFY_IPOPT_DPS },
	{ "e-sec",			IPFY_IPOPT_ESEC },
	{ "eip",			IPFY_IPOPT_EIP },
	{ "encode",			IPFY_IPOPT_ENCODE },
	{ "finn",			IPFY_IPOPT_FINN },
	{ "imitd",			IPFY_IPOPT_IMITD },
	{ "lsrr",			IPFY_IPOPT_LSRR },
	{ "mtup",			IPFY_IPOPT_MTUP },
	{ "mtur",			IPFY_IPOPT_MTUR },
	{ "nop",			IPFY_IPOPT_NOP },
	{ "nsapa",			IPFY_IPOPT_NSAPA },
	{ "rr",				IPFY_IPOPT_RR },
	{ "rtralrt",			IPFY_IPOPT_RTRALRT },
	{ "satid",			IPFY_IPOPT_SATID },
	{ "sdb",			IPFY_IPOPT_SDB },
	{ "sec",			IPFY_IPOPT_SEC },
	{ "ssrr",			IPFY_IPOPT_SSRR },
	{ "tr",				IPFY_IPOPT_TR },
	{ "ts",				IPFY_IPOPT_TS },
	{ "ump",			IPFY_IPOPT_UMP },
	{ "visa",			IPFY_IPOPT_VISA },
	{ "zsu",			IPFY_IPOPT_ZSU },
	{ NULL,				0 },
};

static	struct	wordtab ipv4secwords[9] = {
	{ "confid",			IPFY_SEC_CONF },
	{ "reserv-1",			IPFY_SEC_RSV1 },
	{ "reserv-2",			IPFY_SEC_RSV2 },
	{ "reserv-3",			IPFY_SEC_RSV3 },
	{ "reserv-4",			IPFY_SEC_RSV4 },
	{ "secret",			IPFY_SEC_SEC },
	{ "topsecret",			IPFY_SEC_TS },
	{ "unclass",			IPFY_SEC_UNC },
	{ NULL,				0 },
};

static	struct	wordtab ipv6optwords[8] = {
	{ "dstopts",			IPFY_IPV6OPT_DSTOPTS },
	{ "esp",			IPFY_ESP },
	{ "frag",			IPFY_FRAG },
	{ "hopopts",			IPFY_IPV6OPT_HOPOPTS },
	{ "ipv6",			IPFY_IPV6OPT_IPV6 },
	{ "none",			IPFY_IPV6OPT_NONE },
	{ "routing",			IPFY_IPV6OPT_ROUTING },
	{ NULL,				0 },
};

static	struct	wordtab logwords[33] = {
	{ "kern",			IPFY_FAC_KERN },
	{ "user",			IPFY_FAC_USER },
	{ "mail",			IPFY_FAC_MAIL },
	{ "daemon",			IPFY_FAC_DAEMON },
	{ "auth",			IPFY_FAC_AUTH },
	{ "syslog",			IPFY_FAC_SYSLOG },
	{ "lpr",			IPFY_FAC_LPR },
	{ "news",			IPFY_FAC_NEWS },
	{ "uucp",			IPFY_FAC_UUCP },
	{ "cron",			IPFY_FAC_CRON },
	{ "ftp",			IPFY_FAC_FTP },
	{ "authpriv",			IPFY_FAC_AUTHPRIV },
	{ "audit",			IPFY_FAC_AUDIT },
	{ "logalert",			IPFY_FAC_LFMT },
	{ "console",			IPFY_FAC_CONSOLE },
	{ "security",			IPFY_FAC_SECURITY },
	{ "local0",			IPFY_FAC_LOCAL0 },
	{ "local1",			IPFY_FAC_LOCAL1 },
	{ "local2",			IPFY_FAC_LOCAL2 },
	{ "local3",			IPFY_FAC_LOCAL3 },
	{ "local4",			IPFY_FAC_LOCAL4 },
	{ "local5",			IPFY_FAC_LOCAL5 },
	{ "local6",			IPFY_FAC_LOCAL6 },
	{ "local7",			IPFY_FAC_LOCAL7 },
	{ "emerg",			IPFY_PRI_EMERG },
	{ "alert",			IPFY_PRI_ALERT },
	{ "crit",			IPFY_PRI_CRIT },
	{ "err",			IPFY_PRI_ERR },
	{ "warn",			IPFY_PRI_WARN },
	{ "notice",			IPFY_PRI_NOTICE },
	{ "info",			IPFY_PRI_INFO },
	{ "debug",			IPFY_PRI_DEBUG },
	{ NULL,				0 },
};




int ipf_parsefile(fd, addfunc, iocfuncs, filename)
int fd;
addfunc_t addfunc;
ioctlfunc_t *iocfuncs;
char *filename;
{
	FILE *fp = NULL;
	char *s;

	yylineNum = 1;
	yysettab(ipfwords);

	s = getenv("YYDEBUG");
	if (s != NULL)
		yydebug = atoi(s);
	else
		yydebug = 0;

	if (strcmp(filename, "-")) {
		fp = fopen(filename, "r");
		if (fp == NULL) {
			fprintf(stderr, "fopen(%s) failed: %s\n", filename,
				STRERROR(errno));
			return -1;
		}
	} else
		fp = stdin;

	while (ipf_parsesome(fd, addfunc, iocfuncs, fp) == 1)
		;
	if (fp != NULL)
		fclose(fp);
	return 0;
}


int ipf_parsesome(fd, addfunc, iocfuncs, fp)
int fd;
addfunc_t addfunc;
ioctlfunc_t *iocfuncs;
FILE *fp;
{
	char *s;
	int i;

	ipffd = fd;
	for (i = 0; i <= IPL_LOGMAX; i++)
		ipfioctl[i] = iocfuncs[i];
	ipfaddfunc = addfunc;

	if (feof(fp))
		return 0;
	i = fgetc(fp);
	if (i == EOF)
		return 0;
	if (ungetc(i, fp) == 0)
		return 0;
	if (feof(fp))
		return 0;
	s = getenv("YYDEBUG");
	if (s != NULL)
		yydebug = atoi(s);
	else
		yydebug = 0;

	yyin = fp;
	yyparse();
	return 1;
}


static void newrule()
{
	frentry_t *frn;

	frn = (frentry_t *)calloc(1, sizeof(frentry_t));
	if (frn == NULL)
		yyerror("sorry, out of memory");
	for (fr = frtop; fr != NULL && fr->fr_next != NULL; fr = fr->fr_next)
		;
	if (fr != NULL)
		fr->fr_next = frn;
	if (frtop == NULL)
		frtop = frn;
	fr = frn;
	frc = frn;
	fr->fr_loglevel = 0xffff;
	fr->fr_isc = (void *)-1;
	fr->fr_logtag = FR_NOLOGTAG;
	fr->fr_type = FR_T_NONE;
	if (use_inet6 != 0)
		fr->fr_v = 6;
	else
		fr->fr_v = 4;

	nrules = 1;
}


static void setipftype()
{
	for (fr = frc; fr != NULL; fr = fr->fr_next) {
		if (fr->fr_type == FR_T_NONE) {
			fr->fr_type = FR_T_IPF;
			fr->fr_data = (void *)calloc(sizeof(fripf_t), 1);
			if (fr->fr_data == NULL)
				yyerror("sorry, out of memory");
			fr->fr_dsize = sizeof(fripf_t);
			fr->fr_ip.fi_v = frc->fr_v;
			fr->fr_mip.fi_v = 0xf;
			fr->fr_ipf->fri_sifpidx = -1;
			fr->fr_ipf->fri_difpidx = -1;
		}
		if (fr->fr_type != FR_T_IPF) {
			fprintf(stderr, "IPF Type not set\n");
		}
	}
}


static frentry_t *addrule()
{
	frentry_t *f, *f1, *f2;
	int count;

	for (f2 = frc; f2->fr_next != NULL; f2 = f2->fr_next)
		;

	count = nrules;
	if (count == 0) {
		f = (frentry_t *)calloc(sizeof(*f), 1);
		if (f == NULL)
			yyerror("sorry, out of memory");
		added++;
		f2->fr_next = f;
		bcopy(f2, f, sizeof(*f));
		if (f2->fr_caddr != NULL) {
			f->fr_caddr = malloc(f->fr_dsize);
			if (f->fr_caddr == NULL)
				yyerror("sorry, out of memory");
			bcopy(f2->fr_caddr, f->fr_caddr, f->fr_dsize);
		}
		f->fr_next = NULL;
		return f;
	}
	f = f2;
	for (f1 = frc; count > 0; count--, f1 = f1->fr_next) {
		f->fr_next = (frentry_t *)calloc(sizeof(*f), 1);
		if (f->fr_next == NULL) 
			yyerror("sorry, out of memory");
		added++;
		f = f->fr_next;
		bcopy(f1, f, sizeof(*f));
		f->fr_next = NULL;
		if (f->fr_caddr != NULL) {
			f->fr_caddr = malloc(f->fr_dsize);
			if (f->fr_caddr == NULL)
				yyerror("sorry, out of memory");
			bcopy(f1->fr_caddr, f->fr_caddr, f->fr_dsize);
		}
	}

	return f2->fr_next;
}


static u_32_t lookuphost(name, addr)
char *name;
i6addr_t *addr;
{
	int i;

	hashed = 0;
	pooled = 0;
	dynamic = -1;

	for (i = 0; i < 4; i++) {
		if (strncmp(name, frc->fr_ifnames[i],
			    sizeof(frc->fr_ifnames[i])) == 0) {
			ifpflag = FRI_DYNAMIC;
			dynamic = i;
			return 0;
		}
	}

	if (gethost(name, addr, use_inet6) == -1) {
		fprintf(stderr, "unknown name \"%s\"\n", name);
		return 0;
	}
	return 1;
}


static void dobpf(v, phrase)
int v;
char *phrase;
{
#ifdef IPFILTER_BPF
	struct bpf_program bpf;
	struct pcap *p;
#endif
	fakebpf_t *fb;
	u_32_t l;
	char *s;
	int i;

	for (fr = frc; fr != NULL; fr = fr->fr_next) {
		if (fr->fr_type != FR_T_NONE) {
			fprintf(stderr, "cannot mix IPF and BPF matching\n");
			return;
		}
		fr->fr_v = v;
		fr->fr_type = FR_T_BPFOPC;

		if (!strncmp(phrase, "\"0x", 2)) {
			phrase++;
			fb = malloc(sizeof(fakebpf_t));
			if (fb == NULL)
				yyerror("sorry, out of memory");

			for (i = 0, s = strtok(phrase, " \r\n\t"); s != NULL;
			     s = strtok(NULL, " \r\n\t"), i++) {
				fb = realloc(fb, (i / 4 + 1) * sizeof(*fb));
				if (fb == NULL)
					yyerror("sorry, out of memory");
				l = (u_32_t)strtol(s, NULL, 0);
				switch (i & 3)
				{
				case 0 :
					fb[i / 4].fb_c = l & 0xffff;
					break;
				case 1 :
					fb[i / 4].fb_t = l & 0xff;
					break;
				case 2 :
					fb[i / 4].fb_f = l & 0xff;
					break;
				case 3 :
					fb[i / 4].fb_k = l;
					break;
				}
			}
			if ((i & 3) != 0) {
				fprintf(stderr,
					"Odd number of bytes in BPF code\n");
				exit(1);
			}
			i--;
			fr->fr_dsize = (i / 4 + 1) * sizeof(*fb);
			fr->fr_data = fb;
			return;
		}

#ifdef IPFILTER_BPF
		bzero((char *)&bpf, sizeof(bpf));
		p = pcap_open_dead(DLT_RAW, 1);
		if (!p) {
			fprintf(stderr, "pcap_open_dead failed\n");
			return;
		}

		if (pcap_compile(p, &bpf, phrase, 1, 0xffffffff)) {
			pcap_perror(p, "ipf");
			pcap_close(p);
			fprintf(stderr, "pcap parsing failed (%s)\n", phrase);
			return;
		}
		pcap_close(p);

		fr->fr_dsize = bpf.bf_len * sizeof(struct bpf_insn);
		fr->fr_data = malloc(fr->fr_dsize);
		if (fr->fr_data == NULL)
			yyerror("sorry, out of memory");
		bcopy((char *)bpf.bf_insns, fr->fr_data, fr->fr_dsize);
		if (!bpf_validate(fr->fr_data, bpf.bf_len)) {
			fprintf(stderr, "BPF validation failed\n");
			return;
		}
#endif
	}

#ifdef IPFILTER_BPF
	if (opts & OPT_DEBUG)
		bpf_dump(&bpf, 0);
#else
	fprintf(stderr, "BPF filter expressions not supported\n");
	exit(1);
#endif
}


static void resetaddr()
{
	hashed = 0;
	pooled = 0;
	dynamic = -1;
}


static alist_t *newalist(ptr)
alist_t *ptr;
{
	alist_t *al;

	al = malloc(sizeof(*al));
	if (al == NULL)
		return NULL;
	al->al_not = 0;
	al->al_next = ptr;
	return al;
}


static int makepool(list)
alist_t *list;
{
	ip_pool_node_t *n, *top;
	ip_pool_t pool;
	alist_t *a;
	int num;

	if (list == NULL)
		return 0;
	top = calloc(1, sizeof(*top));
	if (top == NULL)
		return 0;
	
	for (n = top, a = list; (n != NULL) && (a != NULL); a = a->al_next) {
		n->ipn_addr.adf_family = a->al_family;
		n->ipn_mask.adf_family = a->al_family;
		(void *)bcopy((void *)&a->al_i6addr,
			      (void *)&n->ipn_addr.adf_addr,
			      sizeof(n->ipn_addr.adf_addr));
		(void *)bcopy((void *)&a->al_i6mask,
			      (void *)&n->ipn_mask.adf_addr,
			      sizeof(n->ipn_mask.adf_addr));
		n->ipn_info = a->al_not;
		if (a->al_next != NULL) {
			n->ipn_next = calloc(1, sizeof(*n));
			if (n->ipn_next == NULL)
				yyerror("sorry, out of memory");
			n = n->ipn_next;
		}
	}

	bzero((char *)&pool, sizeof(pool));
	pool.ipo_unit = IPL_LOGIPF;
	pool.ipo_list = top;
	num = load_pool(&pool, ipfioctl[IPL_LOGLOOKUP]);

	while ((n = top) != NULL) {
		top = n->ipn_next;
		free(n);
	}
	return num;
}


static u_int makehash(list)
alist_t *list;
{
	iphtent_t *n, *top;
	iphtable_t iph;
	alist_t *a;
	int num;

	if (list == NULL)
		return 0;
	top = calloc(1, sizeof(*top));
	if (top == NULL)
		return 0;
	
	for (n = top, a = list; (n != NULL) && (a != NULL); a = a->al_next) {
		n->ipe_family = a->al_family;
		(void *)bcopy((void *)&a->al_i6addr,
			      (void *)&n->ipe_addr,
			      sizeof(n->ipe_addr));
		(void *)bcopy((void *)&a->al_i6mask,
			      (void *)&n->ipe_mask,
			      sizeof(n->ipe_mask));
		n->ipe_value = 0;
		if (a->al_next != NULL) {
			n->ipe_next = calloc(1, sizeof(*n));
			if (n->ipe_next == NULL)
				yyerror("sorry, out of memory");
			n = n->ipe_next;
		}
	}

	bzero((char *)&iph, sizeof(iph));
	iph.iph_unit = IPL_LOGIPF;
	iph.iph_type = IPHASH_LOOKUP;
	*iph.iph_name = '\0';

	if (load_hash(&iph, top, ipfioctl[IPL_LOGLOOKUP]) == 0)
		sscanf(iph.iph_name, "%u", &num);
	else
		num = 0;

	while ((n = top) != NULL) {
		top = n->ipe_next;
		free(n);
	}
	return num;
}


void ipf_addrule(fd, ioctlfunc, ptr)
int fd;
ioctlfunc_t ioctlfunc;
void *ptr;
{
	ioctlcmd_t add, del;
	frentry_t *fr;
	ipfobj_t obj;

	fr = ptr;
	add = 0;
	del = 0;

	bzero((char *)&obj, sizeof(obj));
	obj.ipfo_rev = IPFILTER_VERSION;
	obj.ipfo_size = sizeof(*fr);
	obj.ipfo_type = IPFOBJ_FRENTRY;
	obj.ipfo_ptr = ptr;

	if ((opts & OPT_DONOTHING) != 0)
		fd = -1;

	if (opts & OPT_ZERORULEST) {
		add = SIOCZRLST;
	} else if (opts & OPT_INACTIVE) {
		add = (u_int)fr->fr_hits ? SIOCINIFR :
					   SIOCADIFR;
		del = SIOCRMIFR;
	} else {
		add = (u_int)fr->fr_hits ? SIOCINAFR :
					   SIOCADAFR;
		del = SIOCRMAFR;
	}

	if (fr && (opts & OPT_OUTQUE))
		fr->fr_flags |= FR_OUTQUE;
	if (fr->fr_hits)
		fr->fr_hits--;
	if (fr && (opts & OPT_VERBOSE))
		printfr(fr, ioctlfunc);

	if (opts & OPT_DEBUG) {
		binprint(fr, sizeof(*fr));
		if (fr->fr_data != NULL)
			binprint(fr->fr_data, fr->fr_dsize);
	}

	if ((opts & OPT_ZERORULEST) != 0) {
		if ((*ioctlfunc)(fd, add, (void *)&obj) == -1) {
			if ((opts & OPT_DONOTHING) == 0) {
				fprintf(stderr, "%d:", yylineNum);
				perror("ioctl(SIOCZRLST)");
			}
		} else {
#ifdef	USE_QUAD_T
			printf("hits %qd bytes %qd ",
				(long long)fr->fr_hits,
				(long long)fr->fr_bytes);
#else
			printf("hits %ld bytes %ld ",
				fr->fr_hits, fr->fr_bytes);
#endif
			printfr(fr, ioctlfunc);
		}
	} else if ((opts & OPT_REMOVE) != 0) {
		if ((*ioctlfunc)(fd, del, (void *)&obj) == -1) {
			if ((opts & OPT_DONOTHING) != 0) {
				fprintf(stderr, "%d:", yylineNum);
				perror("ioctl(delete rule)");
			}
		}
	} else {
		if ((*ioctlfunc)(fd, add, (void *)&obj) == -1) {
			if (!(opts & OPT_DONOTHING)) {
				fprintf(stderr, "%d:", yylineNum);
				perror("ioctl(add/insert rule)");
			}
		}
	}
}

static void setsyslog()
{
	yysetdict(logwords);
	yybreakondot = 1;
}


static void unsetsyslog()
{
	yyresetdict();
	yybreakondot = 0;
}


static void fillgroup(fr)
frentry_t *fr;
{
	frentry_t *f;

	for (f = frold; f != NULL; f = f->fr_next)
		if (strncmp(f->fr_grhead, fr->fr_group, FR_GROUPLEN) == 0)
			break;
	if (f == NULL)
		return;

	/*
	 * Only copy down matching fields if the rules are of the same type
	 * and are of ipf type.   The only fields that are copied are those
	 * that impact the rule parsing itself, eg. need for knowing what the
	 * protocol should be for rules with port comparisons in them.
	 */
	if (f->fr_type != fr->fr_type || f->fr_type != FR_T_IPF)
		return;

	if (fr->fr_v == 0 && f->fr_v != 0)
		fr->fr_v = f->fr_v;

	if (fr->fr_mproto == 0 && f->fr_mproto != 0)
		fr->fr_mproto = f->fr_mproto;
	if (fr->fr_proto == 0 && f->fr_proto != 0)
		fr->fr_proto = f->fr_proto;

	if ((fr->fr_mproto == 0) && ((fr->fr_flx & FI_TCPUDP) == 0) &&
	    ((f->fr_flx & FI_TCPUDP) != 0))
		fr->fr_flx |= FI_TCPUDP;
}
static YYCONST yytabelem yyexca[] ={
-1, 1,
	0, -1,
	-2, 8,
-1, 386,
	324, 229,
	47, 229,
	-2, 228,
-1, 387,
	324, 233,
	47, 233,
	-2, 232,
-1, 423,
	41, 296,
	-2, 90,
-1, 430,
	41, 291,
	-2, 90,
-1, 452,
	257, 261,
	259, 261,
	-2, 257,
	};
# define YYNPROD 466
# define YYLAST 796
static YYCONST yytabelem yyact[]={

   382,   572,   144,   317,   595,   327,   392,   502,   586,   439,
   571,   429,   603,   422,   343,   342,   393,     3,     2,    10,
     9,    87,    88,    89,    90,    91,    92,    93,    94,    95,
    96,   101,   102,   103,   104,   105,   106,   107,   108,   109,
    97,    98,    99,   100,   454,    79,    80,    81,    82,    83,
    84,    85,    86,   406,   455,   547,   456,   470,    79,    80,
    81,    82,    83,    84,    85,    86,   559,     7,     5,   453,
    21,   388,   361,   504,     1,   341,   311,   340,   376,   213,
   214,   215,   390,   330,   252,   300,   209,   286,   210,   257,
   289,   287,   337,   431,   248,   351,   246,   198,   199,   200,
   203,   204,   205,   208,   201,   202,   212,   350,   247,   501,
   211,   207,   191,   405,   438,   145,   206,   294,   258,   259,
   260,   261,   262,   263,   264,   265,   266,   267,   268,   269,
   270,   271,   272,   273,   274,   275,   276,   277,   278,   279,
   280,   281,   283,   452,   344,   548,   240,   373,   182,   237,
   216,   362,   363,   364,   365,   367,   368,   369,   366,   215,
   606,   605,   189,   250,   209,   250,   210,   288,   290,   291,
   292,   293,   249,   248,   249,   198,   199,   200,   203,   204,
   205,   208,   201,   202,   212,   345,   221,    51,   211,   207,
   426,   427,   166,   167,   206,   424,   425,   334,   428,   242,
     7,     5,   347,   245,   176,   302,   178,   179,   219,   170,
   505,   506,   507,   508,   509,   510,   511,   512,   513,   514,
   515,   516,   517,   518,   519,   301,   297,   302,   607,   608,
   609,   610,   225,   224,   125,   126,    63,   328,   127,   132,
   128,   130,   133,   134,    27,    28,   177,   318,   319,   320,
    38,   183,   620,   183,    58,    59,    62,    60,    50,   387,
   477,   175,   122,   123,   223,   222,     8,   146,   147,   148,
   149,   150,   151,   152,   153,   154,   155,   156,   157,   158,
   159,   160,   161,   402,   403,   183,   125,   126,   233,   234,
   127,   132,   532,   130,   133,   134,   385,    51,    45,   383,
   384,    44,    38,    53,    55,    54,   378,   183,   569,   443,
   442,   397,   396,   576,   122,   123,   379,   318,   319,   320,
    31,    41,    33,    36,   318,   319,   320,    18,   560,   387,
   440,   545,   391,   568,   443,   442,   326,   543,   495,   183,
   377,   490,   482,    39,    40,    38,   528,   183,   529,   481,
   408,   407,   480,    35,   408,   407,   213,   214,   215,   318,
   319,   320,   492,   209,   491,   210,   385,   522,   443,   442,
   419,   324,   418,   478,   198,   199,   200,   203,   204,   205,
   208,   201,   202,   212,   378,   412,   459,   211,   207,   318,
   319,   320,   338,   206,   379,   349,   304,   348,   305,     8,
   476,   316,   314,   307,   143,    48,    43,    17,   255,    77,
   196,   193,   310,   309,   354,   194,   163,   308,   411,   172,
   446,   238,   549,   171,   417,   462,   460,   216,   416,    20,
   447,   174,   448,    66,   467,   471,   581,   183,   386,   463,
   461,   120,    65,   119,   468,   472,   469,   473,   421,   432,
   521,   526,   530,   413,   503,    23,   457,   117,   434,   420,
   444,   523,   229,   542,   541,   525,    32,   116,   180,   181,
   145,   227,   520,   539,   474,   479,   318,   319,   320,   115,
   555,   554,   483,    71,   487,   486,   551,    57,   387,   395,
   552,   489,   533,   534,   536,   538,   535,   537,   228,    70,
   408,   407,   504,   563,    10,     9,   498,   494,   561,   562,
   142,   566,   141,   399,   497,   114,   524,   564,   110,   471,
    17,   550,   575,   574,   220,   385,   140,   540,    49,   472,
   567,   473,   553,   570,   124,   124,   139,   401,    74,   557,
   441,   443,   442,   400,    75,   580,   162,   583,   138,   578,
   577,   331,   184,   587,   587,   433,   318,   319,   320,   398,
   329,   588,   589,   331,   318,   319,   320,   591,   387,   370,
   593,   592,   186,   359,   226,   596,   387,   594,   601,    69,
   496,   602,   600,   597,   137,   493,   185,   135,   604,   604,
   183,   613,   612,   613,   614,   616,   615,   618,   611,   598,
   619,   617,   599,   621,   251,   385,   254,   556,   383,   384,
   415,   253,   546,   385,   544,   622,   383,   384,   404,   623,
   355,   624,   146,   147,   148,   149,   150,   151,   152,   153,
   154,   155,   156,   157,   158,   159,   160,   161,   312,   505,
   506,   507,   508,   509,   510,   511,   512,   513,   514,   515,
   516,   517,   518,   519,   318,   319,   320,   332,   313,    29,
   318,   319,   320,   358,   357,   356,   387,   315,   488,   323,
   325,   485,   387,   484,   353,   339,   485,   230,   231,   414,
   335,   243,   415,    73,    15,    22,   282,   284,   197,   195,
   423,   430,   352,   590,   500,   565,   437,   499,   436,    24,
   450,    42,    64,   385,   451,   585,   383,   384,   465,   385,
   584,   464,   381,   380,   475,   466,   389,   458,   445,   375,
   372,   192,   165,   374,   299,   394,   298,    72,    76,    61,
   129,   173,   558,   410,   435,   371,   296,   303,   218,   306,
   169,   232,   131,   136,   118,   111,    56,    52,    37,    34,
    30,   333,   236,   241,   188,   409,   336,   239,   346,   244,
   190,   164,   295,   217,   168,   121,   113,   112,    16,   235,
    68,    47,    26,   187,    67,    46,    25,    14,    13,    12,
    19,     6,    11,     4,   579,   582,   527,   321,   322,   449,
   285,   256,   573,   531,   360,    78 };
static YYCONST yytabelem yypact[]={

  -192,  -192,-10000000,-10000000,   263,-10000000,-10000000,   368,  -387,-10000000,
-10000000,-10000000,   396,   396,   -33,    50,   150,-10000000,   149,    42,
-10000000,    39,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,
-10000000,-10000000,-10000000,-10000000,-10000000,   148,   -72,    29,   -42,   -39,
-10000000,-10000000,    50,-10000000,   383,   374,-10000000,-10000000,-10000000,-10000000,
    38,   452,-10000000,   643,   643,-10000000,   -42,-10000000,-10000000,-10000000,
-10000000,  -404,-10000000,-10000000,-10000000,-10000000,-10000000,   -45,     7,-10000000,
   147,-10000000,  -142,-10000000,-10000000,-10000000,-10000000,-10000000,   500,-10000000,
-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,
-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,
-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,
  -122,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,
-10000000,   -80,   300,   296,-10000000,-10000000,     2,   -13,-10000000,   -13,
   -13,   211,-10000000,-10000000,-10000000,  -122,-10000000,-10000000,-10000000,-10000000,
-10000000,-10000000,-10000000,-10000000,   545,-10000000,-10000000,-10000000,-10000000,-10000000,
-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,
-10000000,-10000000,  -391,  -140,  -234,  -237,-10000000,-10000000,   -82,   267,
-10000000,     6,     5,   -49,   530,   413,   404,-10000000,   404,   404,
-10000000,-10000000,    31,-10000000,  -153,-10000000,-10000000,  -165,  -102,   641,
   -88,  -174,    40,-10000000,-10000000,  -159,  -236,  -222,-10000000,-10000000,
-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,
-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,   -79,   139,-10000000,
-10000000,   146,   292,   288,   -13,   -13,     2,   145,   132,-10000000,
   102,    67,   519,-10000000,-10000000,  -165,  -104,   640,-10000000,  -259,
   135,-10000000,   635,  -151,   -90,   138,  -239,  -251,   634,   580,
   580,-10000000,  -237,-10000000,  -236,-10000000,   529,-10000000,-10000000,-10000000,
-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,
-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,
-10000000,-10000000,  -228,-10000000,-10000000,   525,-10000000,-10000000,-10000000,-10000000,
-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,  -175,-10000000,-10000000,   307,
   299,-10000000,-10000000,-10000000,-10000000,   442,   519,-10000000,-10000000,-10000000,
-10000000,   515,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,   467,-10000000,
-10000000,   497,   491,-10000000,-10000000,-10000000,-10000000,-10000000,    26,-10000000,
-10000000,-10000000,-10000000,-10000000,   578,  -151,   295,   128,-10000000,  -151,
   638,-10000000,-10000000,-10000000,   367,   363,-10000000,   113,-10000000,-10000000,
  -176,  -253,-10000000,  -154,-10000000,  -257,-10000000,-10000000,-10000000,  -236,
   511,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,
  -222,  -218,   283,-10000000,   -57,  -186,  -186,   397,-10000000,   -10,
   379,   378,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,  -186,
  -186,   397,-10000000,   -10,     1,-10000000,-10000000,   116,   -13,    95,
    92,    85,-10000000,-10000000,  -151,   632,-10000000,-10000000,-10000000,-10000000,
  -192,-10000000,   437,   627,-10000000,  -151,    84,   105,-10000000,-10000000,
-10000000,-10000000,   544,   507,    81,-10000000,-10000000,-10000000,-10000000,   539,
   507,-10000000,-10000000,  -228,-10000000,-10000000,  -224,   245,-10000000,   425,
   110,   414,-10000000,-10000000,   299,-10000000,-10000000,-10000000,   550,    89,
    89,   231,-10000000,-10000000,-10000000,-10000000,   550,  -186,   519,-10000000,
    80,   574,    74,   572,    98,    98,-10000000,-10000000,-10000000,   550,
-10000000,-10000000,-10000000,   550,  -186,   519,-10000000,-10000000,-10000000,-10000000,
-10000000,-10000000,-10000000,   566,-10000000,  -151,   -59,    71,-10000000,-10000000,
-10000000,-10000000,-10000000,-10000000,  -154,-10000000,-10000000,  -257,-10000000,-10000000,
   213,-10000000,-10000000,  -184,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,
-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,
    76,-10000000,-10000000,    51,-10000000,    89,-10000000,-10000000,-10000000,-10000000,
   255,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,    89,
-10000000,-10000000,   -10,-10000000,   403,-10000000,    60,-10000000,-10000000,-10000000,
-10000000,    89,    89,-10000000,-10000000,   -10,-10000000,-10000000,-10000000,-10000000,
-10000000,-10000000,-10000000,-10000000,  -142,   519,-10000000,-10000000,-10000000,-10000000,
-10000000,   519,-10000000,    89,-10000000,-10000000,-10000000,   519,-10000000,   558,
-10000000,    60,   537,-10000000,   -97,   -97,   519,-10000000,   519,-10000000,
   519,-10000000,-10000000,  -184,-10000000,    89,-10000000,-10000000,-10000000,   219,
-10000000,-10000000,    60,-10000000,-10000000,-10000000,   467,-10000000,-10000000,-10000000,
-10000000,-10000000,-10000000,    89,-10000000,-10000000,  -142,-10000000,-10000000,-10000000,
    60,-10000000,-10000000,-10000000,-10000000 };
static YYCONST yytabelem yypgo[]={

     0,     1,   795,   409,     2,    72,   794,     7,    89,   793,
   792,   415,     9,   791,   790,    87,   789,    56,     3,   788,
   787,   438,    12,     6,     0,   786,    76,   431,    54,    44,
   785,   784,    74,    18,    17,   783,   782,   781,   780,   779,
   685,   778,   777,   776,   775,   774,   518,   416,   773,   421,
   772,   771,   770,   769,   684,   659,   768,   767,   766,   765,
   764,   763,   762,   761,   760,   759,   758,   757,   756,   755,
   754,   753,   752,   751,   750,   466,   749,   528,   748,   747,
   483,   746,   745,   515,   479,   467,   457,   744,   443,   441,
   743,   742,    16,   741,     5,     4,   740,   739,    83,   738,
   737,   736,   735,   734,    77,    75,    15,    14,   113,    53,
   733,   732,   731,   412,   498,   730,   487,   729,   728,   727,
   726,   725,   724,   723,    85,    71,   722,   721,   720,   719,
   718,    78,    69,   717,    10,   716,   715,    82,    57,   714,
     8,   713,   712,   711,    55,   710,   708,   705,   704,   700,
   698,   697,   696,   695,   694,   693,    96,   108,   692,   414,
    11,   691,    13,   690,   411,   689,   410,   408,   688,   687,
   686 };
static YYCONST yytabelem yyr1[]={

     0,    32,    32,    32,    32,    33,    33,    33,    35,    34,
    38,    37,    36,    36,    40,    40,    44,    39,    51,    41,
    42,    42,    43,    50,    46,    46,    57,    58,    58,    47,
    49,    48,    53,    56,    54,    54,    55,    55,    55,    55,
    55,    55,    55,    55,    74,    74,    78,    79,    79,    79,
    79,    79,    75,    75,    76,    76,    76,    77,    45,    45,
    82,    82,    82,    82,    82,    82,    82,    52,    52,    90,
    90,    90,    90,    90,    90,    59,    59,    59,    59,    91,
    93,    93,    93,    93,    60,    60,    60,    92,    94,    95,
    98,    98,    96,    97,    97,    61,    61,    99,    62,    66,
    66,    66,    65,    65,    65,    70,    70,   104,   104,   105,
   105,   107,   107,   106,    72,    72,   108,   108,   109,   109,
    71,    71,    73,    73,    67,    67,    69,    69,   110,   111,
    83,    84,    85,    85,    85,   112,   112,   113,   113,    86,
    86,    86,   114,    87,    88,    88,    88,   115,   115,    89,
    89,    89,    81,    81,   116,   116,   116,   116,    80,   119,
   101,   101,   101,   100,   100,   100,   121,   120,   120,   120,
   122,   124,    63,    63,   126,   126,   102,   102,   102,   102,
   102,   102,   102,   102,   102,   128,    12,    12,   129,   123,
   123,   123,   131,   131,   133,   133,   132,   132,   132,   132,
   130,   130,   130,   134,   134,   135,   125,   125,   125,   137,
   137,   139,   139,   138,   138,   138,   138,   136,   136,   136,
   140,   140,    23,    23,    23,    23,    23,    24,    24,   143,
   145,    24,    24,   146,   147,    24,   144,   144,    22,    22,
    22,    22,    22,    22,    22,    21,    21,    21,    21,    30,
    30,   141,   142,    31,    31,    31,    31,   148,    16,    16,
    17,   149,    29,    28,   103,   103,   150,   150,   152,   151,
   151,   151,   154,   153,   153,   155,   155,    68,    68,    68,
    64,    64,    64,    64,    64,   156,   157,   157,   159,   159,
   160,   160,   161,   158,   158,   162,   162,   163,   163,   163,
   163,   163,     1,     1,   127,   127,   127,   164,   164,   164,
   164,   164,   166,   168,   165,   165,    11,    11,    11,    11,
    11,    11,    11,    11,    11,    11,    11,    11,    11,    11,
    11,   167,    13,    13,   169,    14,    14,     6,     6,     5,
     5,     5,     5,     5,     5,     5,     5,     7,     7,     7,
     7,     7,     7,     7,     7,     7,     7,     7,     7,     7,
     7,     7,     7,     4,     4,     4,     4,     4,     4,     4,
     4,     4,     4,     4,     4,     4,     4,     4,     4,     4,
     8,     8,     8,     8,     8,     8,     8,     8,     8,     8,
     8,     8,     8,     8,     8,     8,     8,     8,     8,     8,
     8,     8,     8,     8,     8,   170,    15,    15,    15,    15,
    15,    15,    15,    15,   117,   118,   118,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     3,     3,     3,     3,     3,     3,     3,     3,     9,     9,
     9,     9,     9,     9,    10,    10,    10,    25,    27,    27,
    26,    19,    20,    18,    18,    18 };
static YYCONST yytabelem yyr2[]={

     0,     2,     2,     4,     4,     5,     2,     2,     1,     9,
     3,     9,     4,     4,     0,     2,     1,    16,     1,    16,
     4,     6,     3,     3,     2,     2,     8,     9,     9,     8,
     6,     4,     4,     5,     0,     3,     2,     3,     2,     3,
     2,     5,     4,     7,     2,     4,     3,     3,     5,     3,
     5,     3,     3,     5,     3,     5,     3,     7,     0,     4,
     3,     3,     3,     3,     3,     3,     3,     0,     4,     3,
     3,     3,     3,     3,     3,     0,     5,     5,     8,     3,
     3,     3,     7,     7,     0,     5,     8,     3,     3,     3,
     0,     2,     3,     3,     7,     0,     5,     3,     6,     0,
     5,     5,     0,     5,     5,     0,     8,     2,     6,     2,
     2,     7,     7,     7,     0,     8,     2,     6,     2,     2,
     0,     8,     0,     8,     0,     5,     0,     6,     2,     2,
     2,     3,     4,     8,     8,     3,     7,     3,     7,     5,
     9,     9,     3,     3,     5,     9,     9,     2,     2,     5,
     9,     9,     2,     4,     3,     3,     3,     5,     7,     3,
     0,     2,     2,     3,     3,     7,     3,     9,     5,     5,
     3,     3,     0,     4,     3,     3,     0,     5,     9,     7,
     5,     7,     9,     9,     9,     3,     3,     3,     1,     4,
     4,     7,     3,     6,     3,     7,     0,     3,     3,     9,
     3,     3,     9,     3,     7,     1,     4,     4,     7,     3,
     6,     3,     7,     0,     3,     3,     9,     3,     3,     9,
     3,     7,     7,    11,     7,    11,     3,     3,     3,     1,
     1,    11,     3,     1,     1,    11,     2,     2,     3,     3,
     3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
     7,     3,     3,     3,     5,     7,     9,     3,     5,     3,
     5,     3,     5,     9,     0,     4,     5,     9,     3,     0,
     5,     9,     3,     3,     7,     3,     7,     0,     5,     9,
     0,     4,     4,     8,     8,     5,     5,     5,     0,     6,
     6,     2,     3,     0,     6,     6,     2,     5,     3,     3,
     3,     3,     3,     3,     2,     4,     6,     3,     5,     5,
     7,     5,     3,     3,     3,     3,     3,     3,     3,     3,
     3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
     3,     3,     3,     7,     3,     3,     7,     3,     7,     3,
     3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
     3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
     3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
     3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
     3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
     3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
     3,     3,     3,     3,     5,     3,     3,     3,     3,     3,
     3,     3,     3,     3,     3,     3,     7,     3,     3,     3,
     3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
     3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
     3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
     3,     3,     3,     3,     3,     3,     3,     3,     3,     7,
     3,     7,     7,     7,     2,     2 };
static YYCONST yytabelem yychk[]={

-10000000,   -32,   -33,   -34,   -35,   260,   -37,   259,   458,   -33,
   -34,   -36,   -39,   -41,   -42,   -54,   -56,   257,    64,   -38,
    61,   457,   -40,    59,   -40,   -43,   -50,   277,   278,   -55,
   -74,   270,   -75,   272,   -76,   303,   273,   -78,   295,   293,
   294,   271,   -54,   257,   259,   259,   -44,   -51,   257,   -77,
   330,   259,   -79,   274,   276,   275,   -81,  -116,   296,   297,
   299,  -117,   298,   275,   -55,    59,    59,   -45,   -52,   -77,
    47,   -80,  -119,    40,   -80,  -116,  -118,    -3,    -2,   449,
   450,   451,   452,   453,   454,   455,   456,   425,   426,   427,
   428,   429,   430,   431,   432,   433,   434,   444,   445,   446,
   447,   435,   436,   437,   438,   439,   440,   441,   442,   443,
   -46,   -82,   -57,   -58,   -83,   -84,   -85,   -86,   -87,   -88,
   -89,   -59,   307,   308,   -75,   279,   280,   283,   285,  -115,
   286,   -91,   284,   287,   288,   -46,   -90,   -83,   -84,   -85,
   -86,   -88,   -89,   257,    -4,   257,   409,   410,   411,   412,
   413,   414,   415,   416,   417,   418,   419,   420,   421,   422,
   423,   424,    46,   -47,   -63,  -126,   314,   315,   -60,   -96,
   289,   123,   123,  -112,   -27,   259,   -26,   259,   -26,   -26,
   257,   258,   -92,    40,   -47,    41,    -3,   -48,   -70,   302,
   -64,   346,  -127,  -164,   -11,  -165,  -166,  -168,   334,   335,
   336,   341,   342,   337,   338,   339,   353,   348,   340,   323,
   325,   347,   343,   316,   317,   318,   387,   -61,   -99,   290,
   257,   -92,   259,   259,   282,   281,    44,    58,  -114,    58,
  -114,  -114,   -93,   257,   258,   -53,   -72,   302,   -49,   -67,
   311,   -71,   301,    40,   -65,   291,  -156,  -157,   347,   348,
   339,  -164,    44,   -11,  -166,  -167,   -13,    -8,   354,   355,
   356,   357,   358,   359,   360,   361,   362,   363,   364,   365,
   366,   367,   368,   369,   370,   371,   372,   373,   374,   375,
   376,   377,  -170,   378,  -169,   -14,   -15,   313,   389,   312,
   390,   391,   392,   393,   339,   -62,  -101,   305,  -120,  -122,
  -124,   304,   284,  -100,   257,   259,   -97,   257,   125,   125,
  -113,   -26,  -113,   -27,   257,   -21,   269,   -18,   257,   258,
   259,   -20,   -19,   -21,   269,   -21,   269,   -94,   -95,    41,
   -98,    44,   -49,   -73,   301,    40,   -68,   351,   257,    40,
  -104,  -105,  -106,  -107,   295,   336,   -66,   292,   259,   257,
   346,   346,  -158,    40,  -159,    40,  -159,  -164,  -167,    44,
    -6,    -5,   379,   380,   381,   382,   386,   383,   384,   385,
    44,  -102,  -128,   322,  -123,  -129,  -131,    33,   -23,   -92,
  -141,  -142,   -24,   309,   310,   306,   -21,   269,  -125,  -135,
  -137,    33,   -23,   -92,  -121,    47,   -94,   -95,    44,    46,
    46,    46,   257,   258,    40,  -108,  -109,  -106,  -107,   -69,
  -110,   123,   257,  -108,    41,    44,    61,    61,   259,   257,
  -157,  -156,  -162,  -163,   349,   350,   344,   345,   352,  -160,
  -161,   350,    -8,    44,   -15,  -103,  -150,  -152,   332,   -12,
    47,   257,   259,   258,  -124,  -130,   -29,   -28,   -17,   -16,
  -149,  -148,   329,  -132,   -29,   -28,   -17,  -131,  -133,   -23,
    47,    61,    47,    61,  -143,  -146,  -136,   -29,   -28,   -17,
  -138,   -29,   -28,   -17,  -137,  -139,   -23,   259,   257,   -26,
   257,   257,   257,  -104,    41,    44,   -32,    47,    41,  -105,
   257,   259,   257,    41,   -98,   257,    41,   -98,    -5,  -151,
  -154,   333,    -7,   -92,   257,   394,   395,   396,   397,   398,
   399,   400,   401,   402,   403,   404,   405,   406,   407,   408,
    47,   -12,   257,    47,  -125,   -92,    -1,   -25,   257,   259,
    -1,    -9,    61,   261,   262,   265,   263,   266,   264,   -92,
  -132,   -94,   -95,   257,    40,   257,    40,  -144,    47,   324,
  -144,   -92,   -92,  -138,   -94,   -95,    41,  -109,  -111,   125,
   257,  -162,  -160,    -4,   -92,  -153,    -7,   -12,   257,   257,
   -12,  -134,    -1,   -10,   268,   267,    58,  -134,   -23,   -31,
   -24,    33,   -30,   -24,  -145,  -147,  -140,    -1,  -140,   -23,
  -155,    -4,   -94,   -95,   -94,   -95,    -1,   -94,    41,    44,
   -24,    41,    44,   -22,   -18,   258,   257,   325,   326,   327,
   328,   -22,   -94,   -95,   -94,   -94,   -95,    -7,    -1,   -24,
    33,   -24,    -1,    -4,   -24 };
static YYCONST yytabelem yydef[]={

     8,    -2,     1,     2,    34,     6,     7,     0,     0,     3,
     4,     5,    14,    14,     0,     0,    34,    35,     0,     0,
    10,     0,    12,    15,    13,    16,    18,    22,    23,    20,
    36,    37,    38,    39,    40,     0,     0,    44,    52,    54,
    56,    46,     0,    33,     0,     0,    58,    67,    41,    42,
     0,     0,    45,    47,    49,    51,    53,   152,   154,   155,
   156,     0,   414,    55,    21,     9,    11,    75,    75,    43,
     0,    48,     0,   159,    50,   153,   157,   415,     0,   440,
   441,   442,   443,   444,   445,   446,   447,   417,   418,   419,
   420,   421,   422,   423,   424,   425,   426,   427,   428,   429,
   430,   431,   432,   433,   434,   435,   436,   437,   438,   439,
   172,    59,    24,    25,    60,    61,    62,    63,    64,    65,
    66,    84,     0,     0,   130,   131,     0,     0,   143,     0,
     0,     0,   147,   148,    79,   172,    68,    69,    70,    71,
    72,    73,    74,    57,     0,   363,   364,   365,   366,   367,
   368,   369,   370,   371,   372,   373,   374,   375,   376,   377,
   378,   379,     0,   105,   280,     0,   174,   175,    95,     0,
    92,     0,     0,   132,   135,   458,   139,   460,   144,   149,
    76,    77,     0,    87,   114,   158,   416,   124,   120,     0,
   102,     0,   173,   304,   307,     0,     0,     0,   316,   317,
   318,   319,   320,   321,   322,   323,   324,   325,   326,   327,
   328,   329,   330,   314,   315,   312,   313,   160,     0,    97,
    85,     0,     0,     0,     0,     0,     0,     0,     0,   142,
     0,     0,    90,    80,    81,   124,   122,     0,    17,   277,
     0,    31,     0,     0,    99,     0,   281,   282,   293,   288,
   288,   305,     0,   308,     0,   309,   331,   332,   380,   381,
   382,   383,   384,   385,   386,   387,   388,   389,   390,   391,
   392,   393,   394,   395,   396,   397,   398,   399,   400,   401,
   402,   403,     0,   405,   311,   334,   335,   406,   407,   408,
   409,   410,   411,   412,   413,    26,   176,   161,   162,   188,
   205,   170,   171,    96,   163,   164,    90,    93,    27,    28,
   133,   137,   134,   136,   459,   140,   141,   245,   246,   247,
   248,   464,   465,   145,   146,   150,   151,    78,     0,    88,
    89,    91,    19,    32,     0,     0,   126,     0,   125,     0,
     0,   107,   109,   110,     0,     0,    29,     0,   103,   104,
     0,     0,   285,     0,   286,     0,   287,   306,   310,     0,
   404,   337,   339,   340,   341,   342,   343,   344,   345,   346,
     0,   264,     0,   185,   169,     0,   196,     0,   192,     0,
     0,     0,   226,   251,   252,   227,    -2,    -2,   168,     0,
   213,     0,   209,     0,     0,   166,    86,     0,     0,     0,
     0,     0,    82,    83,     0,     0,   116,   118,   119,    30,
     8,   128,   278,     0,   106,     0,     0,     0,   100,   101,
   283,   284,     0,    -2,     0,   298,   299,   300,   301,     0,
    -2,   292,   333,     0,   336,    98,   269,     0,   268,   177,
     0,   180,   186,   187,   205,   189,   200,   201,   259,     0,
     0,     0,    -2,   190,   197,   198,   259,   196,    90,   194,
     0,     0,     0,     0,     0,     0,   206,   217,   218,   259,
   207,   214,   215,   259,   213,    90,   211,   165,    94,   138,
   461,   463,   462,     0,   115,     0,     8,     0,   121,   108,
   113,   111,   112,   294,     0,   297,   289,     0,   338,   265,
     0,   272,   266,     0,   347,   348,   349,   350,   351,   352,
   353,   354,   355,   356,   357,   358,   359,   360,   361,   362,
     0,   179,   181,     0,   167,     0,   262,   302,   303,   457,
     0,   258,   260,   448,   449,   450,   451,   452,   453,     0,
   191,   193,     0,   222,     0,   224,     0,   230,   236,   237,
   234,     0,     0,   208,   210,     0,   123,   117,   127,   129,
   279,   295,   290,   270,     0,    90,   273,   178,   183,   182,
   184,    90,   203,     0,   454,   455,   456,    90,   195,     0,
   253,     0,     0,   249,     0,     0,    90,   220,    90,   212,
    90,   275,   267,     0,   202,     0,   263,   199,   223,     0,
   254,   225,     0,   231,   238,   239,   240,   241,   242,   243,
   244,   235,   219,     0,   216,   271,     0,   274,   204,   255,
     0,   250,   221,   276,   256 };
typedef struct
#ifdef __cplusplus
	yytoktype
#endif
{
#ifdef __cplusplus
const
#endif
char *t_name; int t_val; } yytoktype;
#ifndef YYDEBUG
#	define YYDEBUG	0	/* don't allow debugging */
#endif

#if YYDEBUG

yytoktype yytoks[] =
{
	"YY_NUMBER",	257,
	"YY_HEX",	258,
	"YY_STR",	259,
	"YY_COMMENT",	260,
	"YY_CMP_EQ",	261,
	"YY_CMP_NE",	262,
	"YY_CMP_LE",	263,
	"YY_CMP_GE",	264,
	"YY_CMP_LT",	265,
	"YY_CMP_GT",	266,
	"YY_RANGE_OUT",	267,
	"YY_RANGE_IN",	268,
	"YY_IPV6",	269,
	"IPFY_PASS",	270,
	"IPFY_BLOCK",	271,
	"IPFY_COUNT",	272,
	"IPFY_CALL",	273,
	"IPFY_RETICMP",	274,
	"IPFY_RETRST",	275,
	"IPFY_RETICMPASDST",	276,
	"IPFY_IN",	277,
	"IPFY_OUT",	278,
	"IPFY_QUICK",	279,
	"IPFY_ON",	280,
	"IPFY_OUTVIA",	281,
	"IPFY_INVIA",	282,
	"IPFY_DUPTO",	283,
	"IPFY_TO",	284,
	"IPFY_FROUTE",	285,
	"IPFY_REPLY_TO",	286,
	"IPFY_ROUTETO",	287,
	"IPFY_TOS",	288,
	"IPFY_TTL",	289,
	"IPFY_PROTO",	290,
	"IPFY_HEAD",	291,
	"IPFY_GROUP",	292,
	"IPFY_AUTH",	293,
	"IPFY_PREAUTH",	294,
	"IPFY_LOG",	295,
	"IPFY_BODY",	296,
	"IPFY_FIRST",	297,
	"IPFY_LEVEL",	298,
	"IPFY_ORBLOCK",	299,
	"IPFY_LOGTAG",	300,
	"IPFY_MATCHTAG",	301,
	"IPFY_SETTAG",	302,
	"IPFY_SKIP",	303,
	"IPFY_FROM",	304,
	"IPFY_ALL",	305,
	"IPFY_ANY",	306,
	"IPFY_BPFV4",	307,
	"IPFY_BPFV6",	308,
	"IPFY_POOL",	309,
	"IPFY_HASH",	310,
	"IPFY_PPS",	311,
	"IPFY_ESP",	312,
	"IPFY_AH",	313,
	"IPFY_WITH",	314,
	"IPFY_AND",	315,
	"IPFY_NOT",	316,
	"IPFY_NO",	317,
	"IPFY_OPT",	318,
	"IPFY_TCPUDP",	319,
	"IPFY_TCP",	320,
	"IPFY_UDP",	321,
	"IPFY_FLAGS",	322,
	"IPFY_MULTICAST",	323,
	"IPFY_MASK",	324,
	"IPFY_BROADCAST",	325,
	"IPFY_NETWORK",	326,
	"IPFY_NETMASKED",	327,
	"IPFY_PEER",	328,
	"IPFY_PORT",	329,
	"IPFY_NOW",	330,
	"IPFY_ICMP",	331,
	"IPFY_ICMPTYPE",	332,
	"IPFY_ICMPCODE",	333,
	"IPFY_IPOPTS",	334,
	"IPFY_SHORT",	335,
	"IPFY_NAT",	336,
	"IPFY_BADSRC",	337,
	"IPFY_LOWTTL",	338,
	"IPFY_FRAG",	339,
	"IPFY_MBCAST",	340,
	"IPFY_BAD",	341,
	"IPFY_BADNAT",	342,
	"IPFY_OOW",	343,
	"IPFY_NEWISN",	344,
	"IPFY_NOICMPERR",	345,
	"IPFY_KEEP",	346,
	"IPFY_STATE",	347,
	"IPFY_FRAGS",	348,
	"IPFY_LIMIT",	349,
	"IPFY_STRICT",	350,
	"IPFY_AGE",	351,
	"IPFY_SYNC",	352,
	"IPFY_FRAGBODY",	353,
	"IPFY_IPOPT_NOP",	354,
	"IPFY_IPOPT_RR",	355,
	"IPFY_IPOPT_ZSU",	356,
	"IPFY_IPOPT_MTUP",	357,
	"IPFY_IPOPT_MTUR",	358,
	"IPFY_IPOPT_ENCODE",	359,
	"IPFY_IPOPT_TS",	360,
	"IPFY_IPOPT_TR",	361,
	"IPFY_IPOPT_SEC",	362,
	"IPFY_IPOPT_LSRR",	363,
	"IPFY_IPOPT_ESEC",	364,
	"IPFY_IPOPT_CIPSO",	365,
	"IPFY_IPOPT_SATID",	366,
	"IPFY_IPOPT_SSRR",	367,
	"IPFY_IPOPT_ADDEXT",	368,
	"IPFY_IPOPT_VISA",	369,
	"IPFY_IPOPT_IMITD",	370,
	"IPFY_IPOPT_EIP",	371,
	"IPFY_IPOPT_FINN",	372,
	"IPFY_IPOPT_DPS",	373,
	"IPFY_IPOPT_SDB",	374,
	"IPFY_IPOPT_NSAPA",	375,
	"IPFY_IPOPT_RTRALRT",	376,
	"IPFY_IPOPT_UMP",	377,
	"IPFY_SECCLASS",	378,
	"IPFY_SEC_UNC",	379,
	"IPFY_SEC_CONF",	380,
	"IPFY_SEC_RSV1",	381,
	"IPFY_SEC_RSV2",	382,
	"IPFY_SEC_RSV4",	383,
	"IPFY_SEC_SEC",	384,
	"IPFY_SEC_TS",	385,
	"IPFY_SEC_RSV3",	386,
	"IPF6_V6HDRS",	387,
	"IPFY_IPV6OPT",	388,
	"IPFY_IPV6OPT_DSTOPTS",	389,
	"IPFY_IPV6OPT_HOPOPTS",	390,
	"IPFY_IPV6OPT_IPV6",	391,
	"IPFY_IPV6OPT_NONE",	392,
	"IPFY_IPV6OPT_ROUTING",	393,
	"IPFY_ICMPT_UNR",	394,
	"IPFY_ICMPT_ECHO",	395,
	"IPFY_ICMPT_ECHOR",	396,
	"IPFY_ICMPT_SQUENCH",	397,
	"IPFY_ICMPT_REDIR",	398,
	"IPFY_ICMPT_TIMEX",	399,
	"IPFY_ICMPT_PARAMP",	400,
	"IPFY_ICMPT_TIMEST",	401,
	"IPFY_ICMPT_TIMESTREP",	402,
	"IPFY_ICMPT_INFOREQ",	403,
	"IPFY_ICMPT_INFOREP",	404,
	"IPFY_ICMPT_MASKREQ",	405,
	"IPFY_ICMPT_MASKREP",	406,
	"IPFY_ICMPT_ROUTERAD",	407,
	"IPFY_ICMPT_ROUTERSOL",	408,
	"IPFY_ICMPC_NETUNR",	409,
	"IPFY_ICMPC_HSTUNR",	410,
	"IPFY_ICMPC_PROUNR",	411,
	"IPFY_ICMPC_PORUNR",	412,
	"IPFY_ICMPC_NEEDF",	413,
	"IPFY_ICMPC_SRCFAIL",	414,
	"IPFY_ICMPC_NETUNK",	415,
	"IPFY_ICMPC_HSTUNK",	416,
	"IPFY_ICMPC_ISOLATE",	417,
	"IPFY_ICMPC_NETPRO",	418,
	"IPFY_ICMPC_HSTPRO",	419,
	"IPFY_ICMPC_NETTOS",	420,
	"IPFY_ICMPC_HSTTOS",	421,
	"IPFY_ICMPC_FLTPRO",	422,
	"IPFY_ICMPC_HSTPRE",	423,
	"IPFY_ICMPC_CUTPRE",	424,
	"IPFY_FAC_KERN",	425,
	"IPFY_FAC_USER",	426,
	"IPFY_FAC_MAIL",	427,
	"IPFY_FAC_DAEMON",	428,
	"IPFY_FAC_AUTH",	429,
	"IPFY_FAC_SYSLOG",	430,
	"IPFY_FAC_LPR",	431,
	"IPFY_FAC_NEWS",	432,
	"IPFY_FAC_UUCP",	433,
	"IPFY_FAC_CRON",	434,
	"IPFY_FAC_LOCAL0",	435,
	"IPFY_FAC_LOCAL1",	436,
	"IPFY_FAC_LOCAL2",	437,
	"IPFY_FAC_LOCAL3",	438,
	"IPFY_FAC_LOCAL4",	439,
	"IPFY_FAC_LOCAL5",	440,
	"IPFY_FAC_LOCAL6",	441,
	"IPFY_FAC_LOCAL7",	442,
	"IPFY_FAC_SECURITY",	443,
	"IPFY_FAC_FTP",	444,
	"IPFY_FAC_AUTHPRIV",	445,
	"IPFY_FAC_AUDIT",	446,
	"IPFY_FAC_LFMT",	447,
	"IPFY_FAC_CONSOLE",	448,
	"IPFY_PRI_EMERG",	449,
	"IPFY_PRI_ALERT",	450,
	"IPFY_PRI_CRIT",	451,
	"IPFY_PRI_ERR",	452,
	"IPFY_PRI_WARN",	453,
	"IPFY_PRI_NOTICE",	454,
	"IPFY_PRI_INFO",	455,
	"IPFY_PRI_DEBUG",	456,
	"IPFY_SET_LOOPBACK",	457,
	"IPFY_SET",	458,
	"-unknown-",	-1	/* ends search */
};

#ifdef __cplusplus
const
#endif
char * yyreds[] =
{
	"-no such reduction-",
	"file : line",
	"file : assign",
	"file : file line",
	"file : file assign",
	"line : xx rule",
	"line : YY_COMMENT",
	"line : set",
	"xx : /* empty */",
	"assign : YY_STR assigning YY_STR ';'",
	"assigning : '='",
	"set : IPFY_SET IPFY_SET_LOOPBACK YY_STR ';'",
	"rule : inrule eol",
	"rule : outrule eol",
	"eol : /* empty */",
	"eol : ';'",
	"inrule : rulehead markin",
	"inrule : rulehead markin inopts rulemain ruletail intag ruletail2",
	"outrule : rulehead markout",
	"outrule : rulehead markout outopts rulemain ruletail outtag ruletail2",
	"rulehead : collection action",
	"rulehead : insert collection action",
	"markin : IPFY_IN",
	"markout : IPFY_OUT",
	"rulemain : ipfrule",
	"rulemain : bpfrule",
	"ipfrule : tos ttl proto ip",
	"bpfrule : IPFY_BPFV4 '{' YY_STR '}'",
	"bpfrule : IPFY_BPFV6 '{' YY_STR '}'",
	"ruletail : with keep head group",
	"ruletail2 : pps age new",
	"intag : settagin matchtagin",
	"outtag : settagout matchtagout",
	"insert : '@' YY_NUMBER",
	"collection : /* empty */",
	"collection : YY_NUMBER",
	"action : block",
	"action : IPFY_PASS",
	"action : log",
	"action : IPFY_COUNT",
	"action : auth",
	"action : IPFY_SKIP YY_NUMBER",
	"action : IPFY_CALL func",
	"action : IPFY_CALL IPFY_NOW func",
	"block : blocked",
	"block : blocked blockreturn",
	"blocked : IPFY_BLOCK",
	"blockreturn : IPFY_RETICMP",
	"blockreturn : IPFY_RETICMP returncode",
	"blockreturn : IPFY_RETICMPASDST",
	"blockreturn : IPFY_RETICMPASDST returncode",
	"blockreturn : IPFY_RETRST",
	"log : IPFY_LOG",
	"log : IPFY_LOG logoptions",
	"auth : IPFY_AUTH",
	"auth : IPFY_AUTH IPFY_RETRST",
	"auth : IPFY_PREAUTH",
	"func : YY_STR '/' YY_NUMBER",
	"inopts : /* empty */",
	"inopts : inopts inopt",
	"inopt : logopt",
	"inopt : quick",
	"inopt : on",
	"inopt : dup",
	"inopt : froute",
	"inopt : proute",
	"inopt : replyto",
	"outopts : /* empty */",
	"outopts : outopts outopt",
	"outopt : logopt",
	"outopt : quick",
	"outopt : on",
	"outopt : dup",
	"outopt : proute",
	"outopt : replyto",
	"tos : /* empty */",
	"tos : settos YY_NUMBER",
	"tos : settos YY_HEX",
	"tos : settos lstart toslist lend",
	"settos : IPFY_TOS",
	"toslist : YY_NUMBER",
	"toslist : YY_HEX",
	"toslist : toslist lmore YY_NUMBER",
	"toslist : toslist lmore YY_HEX",
	"ttl : /* empty */",
	"ttl : setttl YY_NUMBER",
	"ttl : setttl lstart ttllist lend",
	"lstart : '('",
	"lend : ')'",
	"lmore : lanother",
	"lanother : /* empty */",
	"lanother : ','",
	"setttl : IPFY_TTL",
	"ttllist : YY_NUMBER",
	"ttllist : ttllist lmore YY_NUMBER",
	"proto : /* empty */",
	"proto : protox protocol",
	"protox : IPFY_PROTO",
	"ip : srcdst flags icmp",
	"group : /* empty */",
	"group : IPFY_GROUP YY_STR",
	"group : IPFY_GROUP YY_NUMBER",
	"head : /* empty */",
	"head : IPFY_HEAD YY_STR",
	"head : IPFY_HEAD YY_NUMBER",
	"settagin : /* empty */",
	"settagin : IPFY_SETTAG '(' taginlist ')'",
	"taginlist : taginspec",
	"taginlist : taginlist ',' taginspec",
	"taginspec : logtag",
	"taginspec : nattag",
	"nattag : IPFY_NAT '=' YY_STR",
	"nattag : IPFY_NAT '=' YY_NUMBER",
	"logtag : IPFY_LOG '=' YY_NUMBER",
	"settagout : /* empty */",
	"settagout : IPFY_SETTAG '(' tagoutlist ')'",
	"tagoutlist : tagoutspec",
	"tagoutlist : tagoutlist ',' tagoutspec",
	"tagoutspec : logtag",
	"tagoutspec : nattag",
	"matchtagin : /* empty */",
	"matchtagin : IPFY_MATCHTAG '(' tagoutlist ')'",
	"matchtagout : /* empty */",
	"matchtagout : IPFY_MATCHTAG '(' taginlist ')'",
	"pps : /* empty */",
	"pps : IPFY_PPS YY_NUMBER",
	"new : /* empty */",
	"new : savegroup file restoregroup",
	"savegroup : '{'",
	"restoregroup : '}'",
	"logopt : log",
	"quick : IPFY_QUICK",
	"on : IPFY_ON onname",
	"on : IPFY_ON onname IPFY_INVIA vianame",
	"on : IPFY_ON onname IPFY_OUTVIA vianame",
	"onname : interfacename",
	"onname : interfacename ',' interfacename",
	"vianame : name",
	"vianame : name ',' name",
	"dup : IPFY_DUPTO name",
	"dup : IPFY_DUPTO name duptoseparator hostname",
	"dup : IPFY_DUPTO name duptoseparator YY_IPV6",
	"duptoseparator : ':'",
	"froute : IPFY_FROUTE",
	"proute : routeto name",
	"proute : routeto name duptoseparator hostname",
	"proute : routeto name duptoseparator YY_IPV6",
	"routeto : IPFY_TO",
	"routeto : IPFY_ROUTETO",
	"replyto : IPFY_REPLY_TO name",
	"replyto : IPFY_REPLY_TO name duptoseparator hostname",
	"replyto : IPFY_REPLY_TO name duptoseparator YY_IPV6",
	"logoptions : logoption",
	"logoptions : logoptions logoption",
	"logoption : IPFY_BODY",
	"logoption : IPFY_FIRST",
	"logoption : IPFY_ORBLOCK",
	"logoption : level loglevel",
	"returncode : starticmpcode icmpcode ')'",
	"starticmpcode : '('",
	"srcdst : /* empty */",
	"srcdst : IPFY_ALL",
	"srcdst : fromto",
	"protocol : YY_NUMBER",
	"protocol : YY_STR",
	"protocol : YY_STR nextstring YY_STR",
	"nextstring : '/'",
	"fromto : from srcobject to dstobject",
	"fromto : to dstobject",
	"fromto : from srcobject",
	"from : IPFY_FROM",
	"to : IPFY_TO",
	"with : /* empty */",
	"with : andwith withlist",
	"andwith : IPFY_WITH",
	"andwith : IPFY_AND",
	"flags : /* empty */",
	"flags : startflags flagset",
	"flags : startflags flagset '/' flagset",
	"flags : startflags '/' flagset",
	"flags : startflags YY_NUMBER",
	"flags : startflags '/' YY_NUMBER",
	"flags : startflags YY_NUMBER '/' YY_NUMBER",
	"flags : startflags flagset '/' YY_NUMBER",
	"flags : startflags YY_NUMBER '/' flagset",
	"startflags : IPFY_FLAGS",
	"flagset : YY_STR",
	"flagset : YY_HEX",
	"srcobject : /* empty */",
	"srcobject : fromport",
	"srcobject : srcaddr srcport",
	"srcobject : '!' srcaddr srcport",
	"srcaddr : addr",
	"srcaddr : lstart srcaddrlist lend",
	"srcaddrlist : addr",
	"srcaddrlist : srcaddrlist lmore addr",
	"srcport : /* empty */",
	"srcport : portcomp",
	"srcport : portrange",
	"srcport : porteq lstart srcportlist lend",
	"fromport : portcomp",
	"fromport : portrange",
	"fromport : porteq lstart srcportlist lend",
	"srcportlist : portnum",
	"srcportlist : srcportlist lmore portnum",
	"dstobject : /* empty */",
	"dstobject : toport",
	"dstobject : dstaddr dstport",
	"dstobject : '!' dstaddr dstport",
	"dstaddr : addr",
	"dstaddr : lstart dstaddrlist lend",
	"dstaddrlist : addr",
	"dstaddrlist : dstaddrlist lmore addr",
	"dstport : /* empty */",
	"dstport : portcomp",
	"dstport : portrange",
	"dstport : porteq lstart dstportlist lend",
	"toport : portcomp",
	"toport : portrange",
	"toport : porteq lstart dstportlist lend",
	"dstportlist : portnum",
	"dstportlist : dstportlist lmore portnum",
	"addr : pool '/' YY_NUMBER",
	"addr : pool '=' '(' poollist ')'",
	"addr : hash '/' YY_NUMBER",
	"addr : hash '=' '(' addrlist ')'",
	"addr : ipaddr",
	"ipaddr : IPFY_ANY",
	"ipaddr : hostname",
	"ipaddr : hostname",
	"ipaddr : hostname maskspace",
	"ipaddr : hostname maskspace mask",
	"ipaddr : YY_IPV6",
	"ipaddr : YY_IPV6",
	"ipaddr : YY_IPV6 maskspace",
	"ipaddr : YY_IPV6 maskspace mask",
	"maskspace : '/'",
	"maskspace : IPFY_MASK",
	"mask : ipv4",
	"mask : YY_HEX",
	"mask : YY_NUMBER",
	"mask : IPFY_BROADCAST",
	"mask : IPFY_NETWORK",
	"mask : IPFY_NETMASKED",
	"mask : IPFY_PEER",
	"hostname : ipv4",
	"hostname : YY_NUMBER",
	"hostname : YY_HEX",
	"hostname : YY_STR",
	"addrlist : ipaddr",
	"addrlist : addrlist ',' ipaddr",
	"pool : IPFY_POOL",
	"hash : IPFY_HASH",
	"poollist : ipaddr",
	"poollist : '!' ipaddr",
	"poollist : poollist ',' ipaddr",
	"poollist : poollist ',' '!' ipaddr",
	"port : IPFY_PORT",
	"portc : port compare",
	"portc : porteq",
	"porteq : port '='",
	"portr : IPFY_PORT",
	"portcomp : portc portnum",
	"portrange : portr portnum range portnum",
	"icmp : /* empty */",
	"icmp : itype icode",
	"itype : seticmptype icmptype",
	"itype : seticmptype lstart typelist lend",
	"seticmptype : IPFY_ICMPTYPE",
	"icode : /* empty */",
	"icode : seticmpcode icmpcode",
	"icode : seticmpcode lstart codelist lend",
	"seticmpcode : IPFY_ICMPCODE",
	"typelist : icmptype",
	"typelist : typelist lmore icmptype",
	"codelist : icmpcode",
	"codelist : codelist lmore icmpcode",
	"age : /* empty */",
	"age : IPFY_AGE YY_NUMBER",
	"age : IPFY_AGE YY_NUMBER '/' YY_NUMBER",
	"keep : /* empty */",
	"keep : IPFY_KEEP keepstate",
	"keep : IPFY_KEEP keepfrag",
	"keep : IPFY_KEEP keepstate IPFY_KEEP keepfrag",
	"keep : IPFY_KEEP keepfrag IPFY_KEEP keepstate",
	"keepstate : IPFY_STATE stateoptlist",
	"keepfrag : IPFY_FRAGS fragoptlist",
	"keepfrag : IPFY_FRAG fragoptlist",
	"fragoptlist : /* empty */",
	"fragoptlist : '(' fragopts ')'",
	"fragopts : fragopt lanother fragopts",
	"fragopts : fragopt",
	"fragopt : IPFY_STRICT",
	"stateoptlist : /* empty */",
	"stateoptlist : '(' stateopts ')'",
	"stateopts : stateopt lanother stateopts",
	"stateopts : stateopt",
	"stateopt : IPFY_LIMIT YY_NUMBER",
	"stateopt : IPFY_STRICT",
	"stateopt : IPFY_NEWISN",
	"stateopt : IPFY_NOICMPERR",
	"stateopt : IPFY_SYNC",
	"portnum : servicename",
	"portnum : YY_NUMBER",
	"withlist : withopt",
	"withlist : withlist withopt",
	"withlist : withlist ',' withopt",
	"withopt : opttype",
	"withopt : notwith opttype",
	"withopt : ipopt ipopts",
	"withopt : notwith ipopt ipopts",
	"withopt : startv6hdrs ipv6hdrs",
	"ipopt : IPFY_OPT",
	"startv6hdrs : IPF6_V6HDRS",
	"notwith : IPFY_NOT",
	"notwith : IPFY_NO",
	"opttype : IPFY_IPOPTS",
	"opttype : IPFY_SHORT",
	"opttype : IPFY_NAT",
	"opttype : IPFY_BAD",
	"opttype : IPFY_BADNAT",
	"opttype : IPFY_BADSRC",
	"opttype : IPFY_LOWTTL",
	"opttype : IPFY_FRAG",
	"opttype : IPFY_FRAGBODY",
	"opttype : IPFY_FRAGS",
	"opttype : IPFY_MBCAST",
	"opttype : IPFY_MULTICAST",
	"opttype : IPFY_BROADCAST",
	"opttype : IPFY_STATE",
	"opttype : IPFY_OOW",
	"ipopts : optlist",
	"optlist : opt",
	"optlist : optlist ',' opt",
	"ipv6hdrs : ipv6hdrlist",
	"ipv6hdrlist : ipv6hdr",
	"ipv6hdrlist : ipv6hdrlist ',' ipv6hdr",
	"secname : seclevel",
	"secname : secname ',' seclevel",
	"seclevel : IPFY_SEC_UNC",
	"seclevel : IPFY_SEC_CONF",
	"seclevel : IPFY_SEC_RSV1",
	"seclevel : IPFY_SEC_RSV2",
	"seclevel : IPFY_SEC_RSV3",
	"seclevel : IPFY_SEC_RSV4",
	"seclevel : IPFY_SEC_SEC",
	"seclevel : IPFY_SEC_TS",
	"icmptype : YY_NUMBER",
	"icmptype : IPFY_ICMPT_UNR",
	"icmptype : IPFY_ICMPT_ECHO",
	"icmptype : IPFY_ICMPT_ECHOR",
	"icmptype : IPFY_ICMPT_SQUENCH",
	"icmptype : IPFY_ICMPT_REDIR",
	"icmptype : IPFY_ICMPT_TIMEX",
	"icmptype : IPFY_ICMPT_PARAMP",
	"icmptype : IPFY_ICMPT_TIMEST",
	"icmptype : IPFY_ICMPT_TIMESTREP",
	"icmptype : IPFY_ICMPT_INFOREQ",
	"icmptype : IPFY_ICMPT_INFOREP",
	"icmptype : IPFY_ICMPT_MASKREQ",
	"icmptype : IPFY_ICMPT_MASKREP",
	"icmptype : IPFY_ICMPT_ROUTERAD",
	"icmptype : IPFY_ICMPT_ROUTERSOL",
	"icmpcode : YY_NUMBER",
	"icmpcode : IPFY_ICMPC_NETUNR",
	"icmpcode : IPFY_ICMPC_HSTUNR",
	"icmpcode : IPFY_ICMPC_PROUNR",
	"icmpcode : IPFY_ICMPC_PORUNR",
	"icmpcode : IPFY_ICMPC_NEEDF",
	"icmpcode : IPFY_ICMPC_SRCFAIL",
	"icmpcode : IPFY_ICMPC_NETUNK",
	"icmpcode : IPFY_ICMPC_HSTUNK",
	"icmpcode : IPFY_ICMPC_ISOLATE",
	"icmpcode : IPFY_ICMPC_NETPRO",
	"icmpcode : IPFY_ICMPC_HSTPRO",
	"icmpcode : IPFY_ICMPC_NETTOS",
	"icmpcode : IPFY_ICMPC_HSTTOS",
	"icmpcode : IPFY_ICMPC_FLTPRO",
	"icmpcode : IPFY_ICMPC_HSTPRE",
	"icmpcode : IPFY_ICMPC_CUTPRE",
	"opt : IPFY_IPOPT_NOP",
	"opt : IPFY_IPOPT_RR",
	"opt : IPFY_IPOPT_ZSU",
	"opt : IPFY_IPOPT_MTUP",
	"opt : IPFY_IPOPT_MTUR",
	"opt : IPFY_IPOPT_ENCODE",
	"opt : IPFY_IPOPT_TS",
	"opt : IPFY_IPOPT_TR",
	"opt : IPFY_IPOPT_SEC",
	"opt : IPFY_IPOPT_LSRR",
	"opt : IPFY_IPOPT_ESEC",
	"opt : IPFY_IPOPT_CIPSO",
	"opt : IPFY_IPOPT_SATID",
	"opt : IPFY_IPOPT_SSRR",
	"opt : IPFY_IPOPT_ADDEXT",
	"opt : IPFY_IPOPT_VISA",
	"opt : IPFY_IPOPT_IMITD",
	"opt : IPFY_IPOPT_EIP",
	"opt : IPFY_IPOPT_FINN",
	"opt : IPFY_IPOPT_DPS",
	"opt : IPFY_IPOPT_SDB",
	"opt : IPFY_IPOPT_NSAPA",
	"opt : IPFY_IPOPT_RTRALRT",
	"opt : IPFY_IPOPT_UMP",
	"opt : setsecclass secname",
	"setsecclass : IPFY_SECCLASS",
	"ipv6hdr : IPFY_AH",
	"ipv6hdr : IPFY_IPV6OPT_DSTOPTS",
	"ipv6hdr : IPFY_ESP",
	"ipv6hdr : IPFY_IPV6OPT_HOPOPTS",
	"ipv6hdr : IPFY_IPV6OPT_IPV6",
	"ipv6hdr : IPFY_IPV6OPT_NONE",
	"ipv6hdr : IPFY_IPV6OPT_ROUTING",
	"ipv6hdr : IPFY_FRAG",
	"level : IPFY_LEVEL",
	"loglevel : priority",
	"loglevel : facility '.' priority",
	"facility : IPFY_FAC_KERN",
	"facility : IPFY_FAC_USER",
	"facility : IPFY_FAC_MAIL",
	"facility : IPFY_FAC_DAEMON",
	"facility : IPFY_FAC_AUTH",
	"facility : IPFY_FAC_SYSLOG",
	"facility : IPFY_FAC_LPR",
	"facility : IPFY_FAC_NEWS",
	"facility : IPFY_FAC_UUCP",
	"facility : IPFY_FAC_CRON",
	"facility : IPFY_FAC_FTP",
	"facility : IPFY_FAC_AUTHPRIV",
	"facility : IPFY_FAC_AUDIT",
	"facility : IPFY_FAC_LFMT",
	"facility : IPFY_FAC_LOCAL0",
	"facility : IPFY_FAC_LOCAL1",
	"facility : IPFY_FAC_LOCAL2",
	"facility : IPFY_FAC_LOCAL3",
	"facility : IPFY_FAC_LOCAL4",
	"facility : IPFY_FAC_LOCAL5",
	"facility : IPFY_FAC_LOCAL6",
	"facility : IPFY_FAC_LOCAL7",
	"facility : IPFY_FAC_SECURITY",
	"priority : IPFY_PRI_EMERG",
	"priority : IPFY_PRI_ALERT",
	"priority : IPFY_PRI_CRIT",
	"priority : IPFY_PRI_ERR",
	"priority : IPFY_PRI_WARN",
	"priority : IPFY_PRI_NOTICE",
	"priority : IPFY_PRI_INFO",
	"priority : IPFY_PRI_DEBUG",
	"compare : YY_CMP_EQ",
	"compare : YY_CMP_NE",
	"compare : YY_CMP_LT",
	"compare : YY_CMP_LE",
	"compare : YY_CMP_GT",
	"compare : YY_CMP_GE",
	"range : YY_RANGE_IN",
	"range : YY_RANGE_OUT",
	"range : ':'",
	"servicename : YY_STR",
	"interfacename : YY_STR",
	"interfacename : YY_STR ':' YY_NUMBER",
	"name : YY_STR",
	"ipv4_16 : YY_NUMBER '.' YY_NUMBER",
	"ipv4_24 : ipv4_16 '.' YY_NUMBER",
	"ipv4 : ipv4_24 '.' YY_NUMBER",
	"ipv4 : ipv4_24",
	"ipv4 : ipv4_16",
};
#endif /* YYDEBUG */
# line	1 "/usr/share/lib/ccs/yaccpar"
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
 * Copyright 1993 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1988 AT&T */
/* All Rights Reserved */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
** Skeleton parser driver for yacc output
*/

/*
** yacc user known macros and defines
*/
#define YYERROR		goto yyerrlab
#define YYACCEPT	return(0)
#define YYABORT		return(1)
#define YYBACKUP( newtoken, newvalue )\
{\
	if ( yychar >= 0 || ( yyr2[ yytmp ] >> 1 ) != 1 )\
	{\
		yyerror( "syntax error - cannot backup" );\
		goto yyerrlab;\
	}\
	yychar = newtoken;\
	yystate = *yyps;\
	yylval = newvalue;\
	goto yynewstate;\
}
#define YYRECOVERING()	(!!yyerrflag)
#define YYNEW(type)	malloc(sizeof(type) * yynewmax)
#define YYCOPY(to, from, type) \
	(type *) memcpy(to, (char *) from, yymaxdepth * sizeof (type))
#define YYENLARGE( from, type) \
	(type *) realloc((char *) from, yynewmax * sizeof(type))
#ifndef YYDEBUG
#	define YYDEBUG	1	/* make debugging available */
#endif

/*
** user known globals
*/
int yydebug;			/* set to 1 to get debugging */

/*
** driver internal defines
*/
#define YYFLAG		(-10000000)

/*
** global variables used by the parser
*/
YYSTYPE *yypv;			/* top of value stack */
int *yyps;			/* top of state stack */

int yystate;			/* current state */
int yytmp;			/* extra var (lasts between blocks) */

int yynerrs;			/* number of errors */
int yyerrflag;			/* error recovery flag */
int yychar;			/* current input token number */



#ifdef YYNMBCHARS
#define YYLEX()		yycvtok(yylex())
/*
** yycvtok - return a token if i is a wchar_t value that exceeds 255.
**	If i<255, i itself is the token.  If i>255 but the neither 
**	of the 30th or 31st bit is on, i is already a token.
*/
#if defined(__STDC__) || defined(__cplusplus)
int yycvtok(int i)
#else
int yycvtok(i) int i;
#endif
{
	int first = 0;
	int last = YYNMBCHARS - 1;
	int mid;
	wchar_t j;

	if(i&0x60000000){/*Must convert to a token. */
		if( yymbchars[last].character < i ){
			return i;/*Giving up*/
		}
		while ((last>=first)&&(first>=0)) {/*Binary search loop*/
			mid = (first+last)/2;
			j = yymbchars[mid].character;
			if( j==i ){/*Found*/ 
				return yymbchars[mid].tvalue;
			}else if( j<i ){
				first = mid + 1;
			}else{
				last = mid -1;
			}
		}
		/*No entry in the table.*/
		return i;/* Giving up.*/
	}else{/* i is already a token. */
		return i;
	}
}
#else/*!YYNMBCHARS*/
#define YYLEX()		yylex()
#endif/*!YYNMBCHARS*/

/*
** yyparse - return 0 if worked, 1 if syntax error not recovered from
*/
#if defined(__STDC__) || defined(__cplusplus)
int yyparse(void)
#else
int yyparse()
#endif
{
	register YYSTYPE *yypvt = 0;	/* top of value stack for $vars */

#if defined(__cplusplus) || defined(lint)
/*
	hacks to please C++ and lint - goto's inside
	switch should never be executed
*/
	static int __yaccpar_lint_hack__ = 0;
	switch (__yaccpar_lint_hack__)
	{
		case 1: goto yyerrlab;
		case 2: goto yynewstate;
	}
#endif

	/*
	** Initialize externals - yyparse may be called more than once
	*/
	yypv = &yyv[-1];
	yyps = &yys[-1];
	yystate = 0;
	yytmp = 0;
	yynerrs = 0;
	yyerrflag = 0;
	yychar = -1;

#if YYMAXDEPTH <= 0
	if (yymaxdepth <= 0)
	{
		if ((yymaxdepth = YYEXPAND(0)) <= 0)
		{
			yyerror("yacc initialization error");
			YYABORT;
		}
	}
#endif

	{
		register YYSTYPE *yy_pv;	/* top of value stack */
		register int *yy_ps;		/* top of state stack */
		register int yy_state;		/* current state */
		register int  yy_n;		/* internal state number info */
	goto yystack;	/* moved from 6 lines above to here to please C++ */

		/*
		** get globals into registers.
		** branch to here only if YYBACKUP was called.
		*/
	yynewstate:
		yy_pv = yypv;
		yy_ps = yyps;
		yy_state = yystate;
		goto yy_newstate;

		/*
		** get globals into registers.
		** either we just started, or we just finished a reduction
		*/
	yystack:
		yy_pv = yypv;
		yy_ps = yyps;
		yy_state = yystate;

		/*
		** top of for (;;) loop while no reductions done
		*/
	yy_stack:
		/*
		** put a state and value onto the stacks
		*/
#if YYDEBUG
		/*
		** if debugging, look up token value in list of value vs.
		** name pairs.  0 and negative (-1) are special values.
		** Note: linear search is used since time is not a real
		** consideration while debugging.
		*/
		if ( yydebug )
		{
			register int yy_i;

			printf( "State %d, token ", yy_state );
			if ( yychar == 0 )
				printf( "end-of-file\n" );
			else if ( yychar < 0 )
				printf( "-none-\n" );
			else
			{
				for ( yy_i = 0; yytoks[yy_i].t_val >= 0;
					yy_i++ )
				{
					if ( yytoks[yy_i].t_val == yychar )
						break;
				}
				printf( "%s\n", yytoks[yy_i].t_name );
			}
		}
#endif /* YYDEBUG */
		if ( ++yy_ps >= &yys[ yymaxdepth ] )	/* room on stack? */
		{
			/*
			** reallocate and recover.  Note that pointers
			** have to be reset, or bad things will happen
			*/
			long yyps_index = (yy_ps - yys);
			long yypv_index = (yy_pv - yyv);
			long yypvt_index = (yypvt - yyv);
			int yynewmax;
#ifdef YYEXPAND
			yynewmax = YYEXPAND(yymaxdepth);
#else
			yynewmax = 2 * yymaxdepth;	/* double table size */
			if (yymaxdepth == YYMAXDEPTH)	/* first time growth */
			{
				char *newyys = (char *)YYNEW(int);
				char *newyyv = (char *)YYNEW(YYSTYPE);
				if (newyys != 0 && newyyv != 0)
				{
					yys = YYCOPY(newyys, yys, int);
					yyv = YYCOPY(newyyv, yyv, YYSTYPE);
				}
				else
					yynewmax = 0;	/* failed */
			}
			else				/* not first time */
			{
				yys = YYENLARGE(yys, int);
				yyv = YYENLARGE(yyv, YYSTYPE);
				if (yys == 0 || yyv == 0)
					yynewmax = 0;	/* failed */
			}
#endif
			if (yynewmax <= yymaxdepth)	/* tables not expanded */
			{
				yyerror( "yacc stack overflow" );
				YYABORT;
			}
			yymaxdepth = yynewmax;

			yy_ps = yys + yyps_index;
			yy_pv = yyv + yypv_index;
			yypvt = yyv + yypvt_index;
		}
		*yy_ps = yy_state;
		*++yy_pv = yyval;

		/*
		** we have a new state - find out what to do
		*/
	yy_newstate:
		if ( ( yy_n = yypact[ yy_state ] ) <= YYFLAG )
			goto yydefault;		/* simple state */
#if YYDEBUG
		/*
		** if debugging, need to mark whether new token grabbed
		*/
		yytmp = yychar < 0;
#endif
		if ( ( yychar < 0 ) && ( ( yychar = YYLEX() ) < 0 ) )
			yychar = 0;		/* reached EOF */
#if YYDEBUG
		if ( yydebug && yytmp )
		{
			register int yy_i;

			printf( "Received token " );
			if ( yychar == 0 )
				printf( "end-of-file\n" );
			else if ( yychar < 0 )
				printf( "-none-\n" );
			else
			{
				for ( yy_i = 0; yytoks[yy_i].t_val >= 0;
					yy_i++ )
				{
					if ( yytoks[yy_i].t_val == yychar )
						break;
				}
				printf( "%s\n", yytoks[yy_i].t_name );
			}
		}
#endif /* YYDEBUG */
		if ( ( ( yy_n += yychar ) < 0 ) || ( yy_n >= YYLAST ) )
			goto yydefault;
		if ( yychk[ yy_n = yyact[ yy_n ] ] == yychar )	/*valid shift*/
		{
			yychar = -1;
			yyval = yylval;
			yy_state = yy_n;
			if ( yyerrflag > 0 )
				yyerrflag--;
			goto yy_stack;
		}

	yydefault:
		if ( ( yy_n = yydef[ yy_state ] ) == -2 )
		{
#if YYDEBUG
			yytmp = yychar < 0;
#endif
			if ( ( yychar < 0 ) && ( ( yychar = YYLEX() ) < 0 ) )
				yychar = 0;		/* reached EOF */
#if YYDEBUG
			if ( yydebug && yytmp )
			{
				register int yy_i;

				printf( "Received token " );
				if ( yychar == 0 )
					printf( "end-of-file\n" );
				else if ( yychar < 0 )
					printf( "-none-\n" );
				else
				{
					for ( yy_i = 0;
						yytoks[yy_i].t_val >= 0;
						yy_i++ )
					{
						if ( yytoks[yy_i].t_val
							== yychar )
						{
							break;
						}
					}
					printf( "%s\n", yytoks[yy_i].t_name );
				}
			}
#endif /* YYDEBUG */
			/*
			** look through exception table
			*/
			{
				register YYCONST int *yyxi = yyexca;

				while ( ( *yyxi != -1 ) ||
					( yyxi[1] != yy_state ) )
				{
					yyxi += 2;
				}
				while ( ( *(yyxi += 2) >= 0 ) &&
					( *yyxi != yychar ) )
					;
				if ( ( yy_n = yyxi[1] ) < 0 )
					YYACCEPT;
			}
		}

		/*
		** check for syntax error
		*/
		if ( yy_n == 0 )	/* have an error */
		{
			/* no worry about speed here! */
			switch ( yyerrflag )
			{
			case 0:		/* new error */
				yyerror( "syntax error" );
				goto skip_init;
			yyerrlab:
				/*
				** get globals into registers.
				** we have a user generated syntax type error
				*/
				yy_pv = yypv;
				yy_ps = yyps;
				yy_state = yystate;
			skip_init:
				yynerrs++;
				/* FALLTHRU */
			case 1:
			case 2:		/* incompletely recovered error */
					/* try again... */
				yyerrflag = 3;
				/*
				** find state where "error" is a legal
				** shift action
				*/
				while ( yy_ps >= yys )
				{
					yy_n = yypact[ *yy_ps ] + YYERRCODE;
					if ( yy_n >= 0 && yy_n < YYLAST &&
						yychk[yyact[yy_n]] == YYERRCODE)					{
						/*
						** simulate shift of "error"
						*/
						yy_state = yyact[ yy_n ];
						goto yy_stack;
					}
					/*
					** current state has no shift on
					** "error", pop stack
					*/
#if YYDEBUG
#	define _POP_ "Error recovery pops state %d, uncovers state %d\n"
					if ( yydebug )
						printf( _POP_, *yy_ps,
							yy_ps[-1] );
#	undef _POP_
#endif
					yy_ps--;
					yy_pv--;
				}
				/*
				** there is no state on stack with "error" as
				** a valid shift.  give up.
				*/
				YYABORT;
			case 3:		/* no shift yet; eat a token */
#if YYDEBUG
				/*
				** if debugging, look up token in list of
				** pairs.  0 and negative shouldn't occur,
				** but since timing doesn't matter when
				** debugging, it doesn't hurt to leave the
				** tests here.
				*/
				if ( yydebug )
				{
					register int yy_i;

					printf( "Error recovery discards " );
					if ( yychar == 0 )
						printf( "token end-of-file\n" );
					else if ( yychar < 0 )
						printf( "token -none-\n" );
					else
					{
						for ( yy_i = 0;
							yytoks[yy_i].t_val >= 0;
							yy_i++ )
						{
							if ( yytoks[yy_i].t_val
								== yychar )
							{
								break;
							}
						}
						printf( "token %s\n",
							yytoks[yy_i].t_name );
					}
				}
#endif /* YYDEBUG */
				if ( yychar == 0 )	/* reached EOF. quit */
					YYABORT;
				yychar = -1;
				goto yy_newstate;
			}
		}/* end if ( yy_n == 0 ) */
		/*
		** reduction by production yy_n
		** put stack tops, etc. so things right after switch
		*/
#if YYDEBUG
		/*
		** if debugging, print the string that is the user's
		** specification of the reduction which is just about
		** to be done.
		*/
		if ( yydebug )
			printf( "Reduce by (%d) \"%s\"\n",
				yy_n, yyreds[ yy_n ] );
#endif
		yytmp = yy_n;			/* value to switch over */
		yypvt = yy_pv;			/* $vars top of value stack */
		/*
		** Look in goto table for next state
		** Sorry about using yy_state here as temporary
		** register variable, but why not, if it works...
		** If yyr2[ yy_n ] doesn't have the low order bit
		** set, then there is no action to be done for
		** this reduction.  So, no saving & unsaving of
		** registers done.  The only difference between the
		** code just after the if and the body of the if is
		** the goto yy_stack in the body.  This way the test
		** can be made before the choice of what to do is needed.
		*/
		{
			/* length of production doubled with extra bit */
			register int yy_len = yyr2[ yy_n ];

			if ( !( yy_len & 01 ) )
			{
				yy_len >>= 1;
				yyval = ( yy_pv -= yy_len )[1];	/* $$ = $1 */
				yy_state = yypgo[ yy_n = yyr1[ yy_n ] ] +
					*( yy_ps -= yy_len ) + 1;
				if ( yy_state >= YYLAST ||
					yychk[ yy_state =
					yyact[ yy_state ] ] != -yy_n )
				{
					yy_state = yyact[ yypgo[ yy_n ] ];
				}
				goto yy_stack;
			}
			yy_len >>= 1;
			yyval = ( yy_pv -= yy_len )[1];	/* $$ = $1 */
			yy_state = yypgo[ yy_n = yyr1[ yy_n ] ] +
				*( yy_ps -= yy_len ) + 1;
			if ( yy_state >= YYLAST ||
				yychk[ yy_state = yyact[ yy_state ] ] != -yy_n )
			{
				yy_state = yyact[ yypgo[ yy_n ] ];
			}
		}
					/* save until reenter driver code */
		yystate = yy_state;
		yyps = yy_ps;
		yypv = yy_pv;
	}
	/*
	** code supplied by user is placed in this switch
	*/
	switch( yytmp )
	{
		
case 5:
# line 188 "../ipf_y.y"
{ while ((fr = frtop) != NULL) {
				frtop = fr->fr_next;
				fr->fr_next = NULL;
				(*ipfaddfunc)(ipffd, ipfioctl[IPL_LOGIPF], fr);
				fr->fr_next = frold;
				frold = fr;
			  }
			  resetlexer();
			} break;
case 8:
# line 201 "../ipf_y.y"
{ newrule(); } break;
case 9:
# line 204 "../ipf_y.y"
{ set_variable(yypvt[-3].str, yypvt[-1].str);
					  resetlexer();
					  free(yypvt[-3].str);
					  free(yypvt[-1].str);
					} break;
case 10:
# line 212 "../ipf_y.y"
{ yyvarnext = 1; } break;
case 11:
# line 217 "../ipf_y.y"
{
			  int data;
			  if (frold != NULL) {
				yyerror("ipf rules before \"set\"");
				return 0;
			  }
			  if (!strcmp(yypvt[-1].str, "true"))
				data = 1;
			  else if (!strcmp(yypvt[-1].str, "false"))
				data = 0;
			  else {
				yyerror("invalid argument for ipf_loopback");
				return 0;
			  }
			  if (((opts & OPT_DONOTHING) == 0) &&
			      (ioctl(ipffd, SIOCIPFLP, &data) == -1))
				perror("ioctl(SIOCIPFLP)");
			} break;
case 16:
# line 245 "../ipf_y.y"
{ ruleopts = 0; } break;
case 18:
# line 249 "../ipf_y.y"
{ ruleopts = 0; } break;
case 22:
# line 257 "../ipf_y.y"
{ fr->fr_flags |= FR_INQUE; } break;
case 23:
# line 261 "../ipf_y.y"
{ fr->fr_flags |= FR_OUTQUE; } break;
case 27:
# line 274 "../ipf_y.y"
{ dobpf(4, yypvt[-1].str); free(yypvt[-1].str); } break;
case 28:
# line 275 "../ipf_y.y"
{ dobpf(6, yypvt[-1].str); free(yypvt[-1].str); } break;
case 33:
# line 293 "../ipf_y.y"
{ fr->fr_hits = (U_QUAD_T)yypvt[-0].num + 1; } break;
case 35:
# line 297 "../ipf_y.y"
{ fr->fr_collect = yypvt[-0].num; } break;
case 37:
# line 301 "../ipf_y.y"
{ fr->fr_flags |= FR_PASS; } break;
case 39:
# line 303 "../ipf_y.y"
{ fr->fr_flags |= FR_ACCOUNT; } break;
case 41:
# line 305 "../ipf_y.y"
{ fr->fr_flags |= FR_SKIP;
					  fr->fr_arg = yypvt[-0].num; } break;
case 43:
# line 308 "../ipf_y.y"
{ fr->fr_flags |= FR_CALLNOW; } break;
case 46:
# line 316 "../ipf_y.y"
{ fr->fr_flags = FR_BLOCK; } break;
case 47:
# line 319 "../ipf_y.y"
{ fr->fr_flags |= FR_RETICMP; } break;
case 48:
# line 320 "../ipf_y.y"
{ fr->fr_flags |= FR_RETICMP; } break;
case 49:
# line 321 "../ipf_y.y"
{ fr->fr_flags |= FR_FAKEICMP; } break;
case 50:
# line 322 "../ipf_y.y"
{ fr->fr_flags |= FR_FAKEICMP; } break;
case 51:
# line 323 "../ipf_y.y"
{ fr->fr_flags |= FR_RETRST; } break;
case 52:
# line 326 "../ipf_y.y"
{ fr->fr_flags |= FR_LOG; } break;
case 53:
# line 327 "../ipf_y.y"
{ fr->fr_flags |= FR_LOG; } break;
case 54:
# line 330 "../ipf_y.y"
{ fr->fr_flags |= FR_AUTH; } break;
case 55:
# line 331 "../ipf_y.y"
{ fr->fr_flags |= (FR_AUTH|FR_RETRST);} break;
case 56:
# line 332 "../ipf_y.y"
{ fr->fr_flags |= FR_PREAUTH; } break;
case 57:
# line 335 "../ipf_y.y"
{ fr->fr_func = nametokva(yypvt[-2].str,
							  ipfioctl[IPL_LOGIPF]);
				  fr->fr_arg = yypvt[-0].num;
				  free(yypvt[-2].str); } break;
case 60:
# line 347 "../ipf_y.y"
{
		if ( ruleopts & OPTION_LOG )
			yyerror("Duplicate log option");
		ruleopts |= OPTION_LOG;
	} break;
case 61:
# line 353 "../ipf_y.y"
{
		if ( ruleopts & OPTION_QUICK )
			yyerror("Duplicate quick option");
		ruleopts |= OPTION_QUICK;
	} break;
case 62:
# line 359 "../ipf_y.y"
{
		if ( ruleopts & OPTION_ON )
			yyerror("Duplicate on option");
		ruleopts |= OPTION_ON;
	} break;
case 63:
# line 365 "../ipf_y.y"
{
		if ( ruleopts & OPTION_DUP )
			yyerror("Duplicate dup option");
		ruleopts |= OPTION_DUP;
	} break;
case 64:
# line 371 "../ipf_y.y"
{
		if ( ruleopts & OPTION_FROUTE )
			yyerror("Duplicate froute option");
		ruleopts |= OPTION_FROUTE;
	} break;
case 65:
# line 377 "../ipf_y.y"
{
		if ( ruleopts & OPTION_PROUTE )
			yyerror("Duplicate proute option");
		ruleopts |= OPTION_PROUTE;
	} break;
case 66:
# line 383 "../ipf_y.y"
{
		if ( ruleopts & OPTION_REPLYTO )
			yyerror("Duplicate replyto option");
		ruleopts |= OPTION_REPLYTO;
	} break;
case 69:
# line 396 "../ipf_y.y"
{
		if ( ruleopts & OPTION_LOG )
			yyerror("Duplicate log option");
		ruleopts |= OPTION_LOG;
	} break;
case 70:
# line 402 "../ipf_y.y"
{
		if ( ruleopts & OPTION_QUICK )
			yyerror("Duplicate quick option");
		ruleopts |= OPTION_QUICK;
	} break;
case 71:
# line 408 "../ipf_y.y"
{
		if ( ruleopts & OPTION_ON )
			yyerror("Duplicate on option");
		ruleopts |= OPTION_ON;
	} break;
case 72:
# line 414 "../ipf_y.y"
{
		if ( ruleopts & OPTION_DUP )
			yyerror("Duplicate dup option");
		ruleopts |= OPTION_DUP;
	} break;
case 73:
# line 420 "../ipf_y.y"
{
		if ( ruleopts & OPTION_PROUTE )
			yyerror("Duplicate proute option");
		ruleopts |= OPTION_PROUTE;
	} break;
case 74:
# line 426 "../ipf_y.y"
{
		if ( ruleopts & OPTION_REPLYTO )
			yyerror("Duplicate replyto option");
		ruleopts |= OPTION_REPLYTO;
	} break;
case 76:
# line 433 "../ipf_y.y"
{ DOALL(fr->fr_tos = yypvt[-0].num; fr->fr_mtos = 0xff;) } break;
case 77:
# line 434 "../ipf_y.y"
{ DOALL(fr->fr_tos = yypvt[-0].num; fr->fr_mtos = 0xff;) } break;
case 79:
# line 438 "../ipf_y.y"
{ setipftype(); } break;
case 80:
# line 442 "../ipf_y.y"
{ DOALL(fr->fr_tos = yypvt[-0].num; fr->fr_mtos = 0xff;) } break;
case 81:
# line 443 "../ipf_y.y"
{ DOREM(fr->fr_tos = yypvt[-0].num; fr->fr_mtos = 0xff;) } break;
case 82:
# line 445 "../ipf_y.y"
{ DOREM(fr->fr_tos = yypvt[-0].num; fr->fr_mtos = 0xff;) } break;
case 83:
# line 447 "../ipf_y.y"
{ DOREM(fr->fr_tos = yypvt[-0].num; fr->fr_mtos = 0xff;) } break;
case 85:
# line 451 "../ipf_y.y"
{ DOALL(fr->fr_ttl = yypvt[-0].num; fr->fr_mttl = 0xff;) } break;
case 87:
# line 455 "../ipf_y.y"
{ newlist = 1; fr = frc; added = 0; } break;
case 88:
# line 458 "../ipf_y.y"
{ nrules += added; } break;
case 89:
# line 461 "../ipf_y.y"
{ if (newlist == 1) {
						newlist = 0;
					  }
					  fr = addrule();
					  if (yycont != NULL)
						*yycont = 1;
					} break;
case 92:
# line 474 "../ipf_y.y"
{ setipftype(); } break;
case 93:
# line 478 "../ipf_y.y"
{ DOREM(fr->fr_ttl = yypvt[-0].num; fr->fr_mttl = 0xff;) } break;
case 94:
# line 480 "../ipf_y.y"
{ DOREM(fr->fr_ttl = yypvt[-0].num; fr->fr_mttl = 0xff;) } break;
case 96:
# line 483 "../ipf_y.y"
{ yyresetdict(); } break;
case 97:
# line 486 "../ipf_y.y"
{ setipftype();
					  fr = frc;
					  yysetdict(NULL); } break;
case 100:
# line 494 "../ipf_y.y"
{ DOALL(strncpy(fr->fr_group, yypvt[-0].str, \
							FR_GROUPLEN); \
							fillgroup(fr););
					  free(yypvt[-0].str); } break;
case 101:
# line 498 "../ipf_y.y"
{ DOALL(sprintf(fr->fr_group, "%d", \
							yypvt[-0].num); \
							fillgroup(fr);) } break;
case 103:
# line 503 "../ipf_y.y"
{ DOALL(strncpy(fr->fr_grhead, yypvt[-0].str, \
							FR_GROUPLEN););
					  free(yypvt[-0].str); } break;
case 104:
# line 506 "../ipf_y.y"
{ DOALL(sprintf(fr->fr_grhead, "%d", \
							yypvt[-0].num);) } break;
case 111:
# line 524 "../ipf_y.y"
{ DOALL(strncpy(fr->fr_nattag.ipt_tag,\
						yypvt[-0].str, IPFTAG_LEN););
					  free(yypvt[-0].str); } break;
case 112:
# line 527 "../ipf_y.y"
{ DOALL(sprintf(fr->fr_nattag.ipt_tag,\
						"%d", yypvt[-0].num & 0xffffffff);) } break;
case 113:
# line 531 "../ipf_y.y"
{ DOALL(fr->fr_logtag = yypvt[-0].num;) } break;
case 125:
# line 556 "../ipf_y.y"
{ DOALL(fr->fr_pps = yypvt[-0].num;) } break;
case 131:
# line 574 "../ipf_y.y"
{ fr->fr_flags |= FR_QUICK; } break;
case 135:
# line 583 "../ipf_y.y"
{ strncpy(fr->fr_ifnames[0], yypvt[-0].str, sizeof(fr->fr_ifnames[0]));
		  free(yypvt[-0].str);
		} break;
case 136:
# line 587 "../ipf_y.y"
{ strncpy(fr->fr_ifnames[0], yypvt[-2].str, sizeof(fr->fr_ifnames[0]));
		  free(yypvt[-2].str);
		  strncpy(fr->fr_ifnames[1], yypvt[-0].str, sizeof(fr->fr_ifnames[1]));
		  free(yypvt[-0].str);
		} break;
case 137:
# line 596 "../ipf_y.y"
{ strncpy(fr->fr_ifnames[2], yypvt[-0].str, sizeof(fr->fr_ifnames[2]));
		  free(yypvt[-0].str);
		} break;
case 138:
# line 600 "../ipf_y.y"
{ strncpy(fr->fr_ifnames[2], yypvt[-2].str, sizeof(fr->fr_ifnames[2]));
		  free(yypvt[-2].str);
		  strncpy(fr->fr_ifnames[3], yypvt[-0].str, sizeof(fr->fr_ifnames[3]));
		  free(yypvt[-0].str);
		} break;
case 139:
# line 608 "../ipf_y.y"
{ strncpy(fr->fr_dif.fd_ifname, yypvt[-0].str, sizeof(fr->fr_dif.fd_ifname));
	  free(yypvt[-0].str);
	} break;
case 140:
# line 612 "../ipf_y.y"
{ strncpy(fr->fr_dif.fd_ifname, yypvt[-2].str, sizeof(fr->fr_dif.fd_ifname));
	  if (use_inet6 == 0)
		fr->fr_dif.fd_ip = yypvt[-0].ip6.in4;
	  else
	  	bcopy(&yypvt[-0].ip6, &fr->fr_dif.fd_ip6, sizeof(fr->fr_dif.fd_ip6));
	  yyexpectaddr = 0;
	  free(yypvt[-2].str);
	} break;
case 141:
# line 621 "../ipf_y.y"
{ strncpy(fr->fr_dif.fd_ifname, yypvt[-2].str, sizeof(fr->fr_dif.fd_ifname));
	  bcopy(&yypvt[-0].ip6, &fr->fr_dif.fd_ip6, sizeof(fr->fr_dif.fd_ip6));
	  yyexpectaddr = 0;
	  free(yypvt[-2].str);
	} break;
case 142:
# line 629 "../ipf_y.y"
{ yyexpectaddr = 1; yycont = &yyexpectaddr; resetaddr(); } break;
case 143:
# line 632 "../ipf_y.y"
{ fr->fr_flags |= FR_FASTROUTE; } break;
case 144:
# line 636 "../ipf_y.y"
{ strncpy(fr->fr_tif.fd_ifname, yypvt[-0].str, sizeof(fr->fr_tif.fd_ifname));
	  free(yypvt[-0].str);
	} break;
case 145:
# line 640 "../ipf_y.y"
{ strncpy(fr->fr_tif.fd_ifname, yypvt[-2].str, sizeof(fr->fr_tif.fd_ifname));
	  if (use_inet6 == 0)
		fr->fr_tif.fd_ip = yypvt[-0].ip6.in4;
	  else
	  	bcopy(&yypvt[-0].ip6, &fr->fr_tif.fd_ip6, sizeof(fr->fr_tif.fd_ip6));
	  yyexpectaddr = 0;
	  free(yypvt[-2].str);
	} break;
case 146:
# line 649 "../ipf_y.y"
{ strncpy(fr->fr_tif.fd_ifname, yypvt[-2].str, sizeof(fr->fr_tif.fd_ifname));
	  bcopy(&yypvt[-0].ip6, &fr->fr_tif.fd_ip6, sizeof(fr->fr_tif.fd_ip6));
	  yyexpectaddr = 0;
	  free(yypvt[-2].str);
	} break;
case 149:
# line 663 "../ipf_y.y"
{ strncpy(fr->fr_rif.fd_ifname, yypvt[-0].str, sizeof(fr->fr_rif.fd_ifname));
	  free(yypvt[-0].str);
	} break;
case 150:
# line 667 "../ipf_y.y"
{ strncpy(fr->fr_rif.fd_ifname, yypvt[-2].str, sizeof(fr->fr_rif.fd_ifname));
	  if (use_inet6 == 0)
		fr->fr_rif.fd_ip = yypvt[-0].ip6.in4;
	  else
		bcopy(&yypvt[-0].ip6, &fr->fr_rif.fd_ip6, sizeof(fr->fr_rif.fd_ip6));
	  yyexpectaddr = 0;
	  free(yypvt[-2].str);
	} break;
case 151:
# line 676 "../ipf_y.y"
{ strncpy(fr->fr_rif.fd_ifname, yypvt[-2].str, sizeof(fr->fr_rif.fd_ifname));
	  bcopy(&yypvt[-0].ip6, &fr->fr_rif.fd_ip6, sizeof(fr->fr_rif.fd_ip6));
	  yyexpectaddr = 0;
	  free(yypvt[-2].str);
	} break;
case 154:
# line 689 "../ipf_y.y"
{ fr->fr_flags |= FR_LOGBODY; } break;
case 155:
# line 690 "../ipf_y.y"
{ fr->fr_flags |= FR_LOGFIRST; } break;
case 156:
# line 691 "../ipf_y.y"
{ fr->fr_flags |= FR_LOGORBLOCK; } break;
case 157:
# line 692 "../ipf_y.y"
{ unsetsyslog(); } break;
case 158:
# line 696 "../ipf_y.y"
{ fr->fr_icode = yypvt[-1].num; yyresetdict(); } break;
case 159:
# line 700 "../ipf_y.y"
{ yysetdict(icmpcodewords); } break;
case 163:
# line 708 "../ipf_y.y"
{ DOREM(fr->fr_proto = yypvt[-0].num; \
					fr->fr_mproto = 0xff;) } break;
case 164:
# line 710 "../ipf_y.y"
{ if (!strcmp(yypvt[-0].str, "tcp-udp")) {
					DOREM(fr->fr_flx |= FI_TCPUDP; \
					      fr->fr_mflx |= FI_TCPUDP;)
				  } else {
					int p = getproto(yypvt[-0].str);
					if (p == -1)
						yyerror("protocol unknown");
					DOREM(fr->fr_proto = p; \
						fr->fr_mproto = 0xff;)
				  }
				  free(yypvt[-0].str);
				} break;
case 165:
# line 723 "../ipf_y.y"
{ if (!strcmp(yypvt[-2].str, "tcp") &&
				      !strcmp(yypvt[-0].str, "udp")) {
					DOREM(fr->fr_flx |= FI_TCPUDP; \
					      fr->fr_mflx |= FI_TCPUDP;)
				  } else
					YYERROR;
				  free(yypvt[-2].str);
				  free(yypvt[-0].str);
				} break;
case 166:
# line 735 "../ipf_y.y"
{ yysetdict(NULL); } break;
case 167:
# line 738 "../ipf_y.y"
{ yyexpectaddr = 0; yycont = NULL; } break;
case 168:
# line 739 "../ipf_y.y"
{ yyexpectaddr = 0; yycont = NULL; } break;
case 169:
# line 740 "../ipf_y.y"
{ yyexpectaddr = 0; yycont = NULL; } break;
case 170:
# line 743 "../ipf_y.y"
{ setipftype();
					  if (fr == NULL)
						fr = frc;
					  yyexpectaddr = 1;
					  if (yydebug)
						printf("set yyexpectaddr\n");
					  yycont = &yyexpectaddr;
					  yysetdict(addrwords);
					  resetaddr(); } break;
case 171:
# line 754 "../ipf_y.y"
{ if (fr == NULL)
						fr = frc;
					  yyexpectaddr = 1;
					  if (yydebug)
						printf("set yyexpectaddr\n");
					  yycont = &yyexpectaddr;
					  yysetdict(addrwords);
					  resetaddr(); } break;
case 174:
# line 768 "../ipf_y.y"
{ nowith = 0; setipftype(); } break;
case 175:
# line 769 "../ipf_y.y"
{ nowith = 0; setipftype(); } break;
case 177:
# line 773 "../ipf_y.y"
{ DOALL(fr->fr_tcpf = yypvt[-0].num; fr->fr_tcpfm = FR_TCPFMAX;) } break;
case 178:
# line 775 "../ipf_y.y"
{ DOALL(fr->fr_tcpf = yypvt[-2].num; fr->fr_tcpfm = yypvt[-0].num;) } break;
case 179:
# line 777 "../ipf_y.y"
{ DOALL(fr->fr_tcpf = 0; fr->fr_tcpfm = yypvt[-0].num;) } break;
case 180:
# line 779 "../ipf_y.y"
{ DOALL(fr->fr_tcpf = yypvt[-0].num; fr->fr_tcpfm = FR_TCPFMAX;) } break;
case 181:
# line 781 "../ipf_y.y"
{ DOALL(fr->fr_tcpf = 0; fr->fr_tcpfm = yypvt[-0].num;) } break;
case 182:
# line 783 "../ipf_y.y"
{ DOALL(fr->fr_tcpf = yypvt[-2].num; fr->fr_tcpfm = yypvt[-0].num;) } break;
case 183:
# line 785 "../ipf_y.y"
{ DOALL(fr->fr_tcpf = yypvt[-2].num; fr->fr_tcpfm = yypvt[-0].num;) } break;
case 184:
# line 787 "../ipf_y.y"
{ DOALL(fr->fr_tcpf = yypvt[-2].num; fr->fr_tcpfm = yypvt[-0].num;) } break;
case 185:
# line 791 "../ipf_y.y"
{ if (frc->fr_type != FR_T_IPF)
				yyerror("flags with non-ipf type rule");
			  if (frc->fr_proto != IPPROTO_TCP)
				yyerror("flags with non-TCP rule");
			} break;
case 186:
# line 799 "../ipf_y.y"
{ yyval.num = tcpflags(yypvt[-0].str); free(yypvt[-0].str); } break;
case 187:
# line 800 "../ipf_y.y"
{ yyval.num = yypvt[-0].num; } break;
case 188:
# line 804 "../ipf_y.y"
{ yyresetdict(); } break;
case 191:
# line 807 "../ipf_y.y"
{ DOALL(fr->fr_flags |= FR_NOTSRCIP;) } break;
case 192:
# line 811 "../ipf_y.y"
{ DOREM(bcopy(&(yypvt[-0].ipp.a), &fr->fr_ip.fi_src, sizeof(yypvt[-0].ipp.a)); \
			bcopy(&(yypvt[-0].ipp.m), &fr->fr_mip.fi_src, sizeof(yypvt[-0].ipp.m)); \
			if (dynamic != -1) { \
				fr->fr_satype = ifpflag; \
				fr->fr_ipf->fri_sifpidx = dynamic; \
			} else if (pooled || hashed) \
				fr->fr_satype = FRI_LOOKUP;)
		} break;
case 194:
# line 823 "../ipf_y.y"
{ DOREM(bcopy(&(yypvt[-0].ipp.a), &fr->fr_ip.fi_src, sizeof(yypvt[-0].ipp.a)); \
			bcopy(&(yypvt[-0].ipp.m), &fr->fr_mip.fi_src, sizeof(yypvt[-0].ipp.m)); \
			if (dynamic != -1) { \
				fr->fr_satype = ifpflag; \
				fr->fr_ipf->fri_sifpidx = dynamic; \
			} else if (pooled || hashed) \
				fr->fr_satype = FRI_LOOKUP;)
		} break;
case 195:
# line 832 "../ipf_y.y"
{ DOREM(bcopy(&(yypvt[-0].ipp.a), &fr->fr_ip.fi_src, sizeof(yypvt[-0].ipp.a)); \
			bcopy(&(yypvt[-0].ipp.m), &fr->fr_mip.fi_src, sizeof(yypvt[-0].ipp.m)); \
			if (dynamic != -1) { \
				fr->fr_satype = ifpflag; \
				fr->fr_ipf->fri_sifpidx = dynamic; \
			} else if (pooled || hashed) \
				fr->fr_satype = FRI_LOOKUP;)
		} break;
case 197:
# line 844 "../ipf_y.y"
{ DOALL(fr->fr_scmp = yypvt[-0].pc.pc; fr->fr_sport = yypvt[-0].pc.p1;) } break;
case 198:
# line 846 "../ipf_y.y"
{ DOALL(fr->fr_scmp = yypvt[-0].pc.pc; fr->fr_sport = yypvt[-0].pc.p1; \
			fr->fr_stop = yypvt[-0].pc.p2;) } break;
case 199:
# line 849 "../ipf_y.y"
{ yyresetdict(); } break;
case 200:
# line 854 "../ipf_y.y"
{ DOALL(fr->fr_scmp = yypvt[-0].pc.pc; fr->fr_sport = yypvt[-0].pc.p1;) } break;
case 201:
# line 856 "../ipf_y.y"
{ DOALL(fr->fr_scmp = yypvt[-0].pc.pc; fr->fr_sport = yypvt[-0].pc.p1; \
			fr->fr_stop = yypvt[-0].pc.p2;) } break;
case 202:
# line 859 "../ipf_y.y"
{ yyresetdict(); } break;
case 203:
# line 863 "../ipf_y.y"
{ DOREM(fr->fr_scmp = FR_EQUAL; fr->fr_sport = yypvt[-0].port;) } break;
case 204:
# line 865 "../ipf_y.y"
{ DOREM(fr->fr_scmp = FR_EQUAL; fr->fr_sport = yypvt[-0].port;) } break;
case 205:
# line 869 "../ipf_y.y"
{ yyresetdict(); } break;
case 208:
# line 872 "../ipf_y.y"
{ DOALL(fr->fr_flags |= FR_NOTDSTIP;) } break;
case 209:
# line 876 "../ipf_y.y"
{ DOREM(bcopy(&(yypvt[-0].ipp.a), &fr->fr_ip.fi_dst, sizeof(yypvt[-0].ipp.a)); \
			bcopy(&(yypvt[-0].ipp.m), &fr->fr_mip.fi_dst, sizeof(yypvt[-0].ipp.m)); \
			if (dynamic != -1) { \
				fr->fr_datype = ifpflag; \
				fr->fr_ipf->fri_difpidx = dynamic; \
			  } else if (pooled || hashed) \
				fr->fr_datype = FRI_LOOKUP;)
		} break;
case 211:
# line 888 "../ipf_y.y"
{ DOREM(bcopy(&(yypvt[-0].ipp.a), &fr->fr_ip.fi_dst, sizeof(yypvt[-0].ipp.a)); \
			bcopy(&(yypvt[-0].ipp.m), &fr->fr_mip.fi_dst, sizeof(yypvt[-0].ipp.m)); \
			if (dynamic != -1) { \
				fr->fr_datype = ifpflag; \
				fr->fr_ipf->fri_difpidx = dynamic; \
			} else if (pooled || hashed) \
				fr->fr_datype = FRI_LOOKUP;)
		} break;
case 212:
# line 897 "../ipf_y.y"
{ DOREM(bcopy(&(yypvt[-0].ipp.a), &fr->fr_ip.fi_dst, sizeof(yypvt[-0].ipp.a)); \
			bcopy(&(yypvt[-0].ipp.m), &fr->fr_mip.fi_dst, sizeof(yypvt[-0].ipp.m)); \
			if (dynamic != -1) { \
				fr->fr_datype = ifpflag; \
				fr->fr_ipf->fri_difpidx = dynamic; \
			} else if (pooled || hashed) \
				fr->fr_datype = FRI_LOOKUP;)
		} break;
case 214:
# line 910 "../ipf_y.y"
{ DOALL(fr->fr_dcmp = yypvt[-0].pc.pc; fr->fr_dport = yypvt[-0].pc.p1;) } break;
case 215:
# line 912 "../ipf_y.y"
{ DOALL(fr->fr_dcmp = yypvt[-0].pc.pc; fr->fr_dport = yypvt[-0].pc.p1; \
			fr->fr_dtop = yypvt[-0].pc.p2;) } break;
case 216:
# line 915 "../ipf_y.y"
{ yyresetdict(); } break;
case 217:
# line 920 "../ipf_y.y"
{ DOALL(fr->fr_dcmp = yypvt[-0].pc.pc; fr->fr_dport = yypvt[-0].pc.p1;) } break;
case 218:
# line 922 "../ipf_y.y"
{ DOALL(fr->fr_dcmp = yypvt[-0].pc.pc; fr->fr_dport = yypvt[-0].pc.p1; \
			fr->fr_dtop = yypvt[-0].pc.p2;) } break;
case 219:
# line 925 "../ipf_y.y"
{ yyresetdict(); } break;
case 220:
# line 929 "../ipf_y.y"
{ DOREM(fr->fr_dcmp = FR_EQUAL; fr->fr_dport = yypvt[-0].port;) } break;
case 221:
# line 931 "../ipf_y.y"
{ DOREM(fr->fr_dcmp = FR_EQUAL; fr->fr_dport = yypvt[-0].port;) } break;
case 222:
# line 934 "../ipf_y.y"
{ pooled = 1;
					  yyexpectaddr = 0;
					  yyval.ipp.a.iplookuptype = IPLT_POOL;
					  yyval.ipp.a.iplookupnum = yypvt[-0].num; } break;
case 223:
# line 938 "../ipf_y.y"
{ pooled = 1;
					  yyexpectaddr = 0;
					  yyval.ipp.a.iplookuptype = IPLT_POOL;
					  yyval.ipp.a.iplookupnum = makepool(yypvt[-1].alist); } break;
case 224:
# line 942 "../ipf_y.y"
{ hashed = 1;
					  yyexpectaddr = 0;
					  yyval.ipp.a.iplookuptype = IPLT_HASH;
					  yyval.ipp.a.iplookupnum = yypvt[-0].num; } break;
case 225:
# line 946 "../ipf_y.y"
{ hashed = 1;
					  yyexpectaddr = 0;
					  yyval.ipp.a.iplookuptype = IPLT_HASH;
					  yyval.ipp.a.iplookupnum = makehash(yypvt[-1].alist); } break;
case 226:
# line 950 "../ipf_y.y"
{ bcopy(&yypvt[-0].ipp, &yyval.ipp, sizeof(yyval.ipp));
					  yyexpectaddr = 0; } break;
case 227:
# line 954 "../ipf_y.y"
{ bzero(&(yyval.ipp), sizeof(yyval.ipp));
					  yyresetdict();
					  yyexpectaddr = 0; } break;
case 228:
# line 957 "../ipf_y.y"
{ if (use_inet6 == 0) { 
						yyval.ipp.a.in4 = yypvt[-0].ip6.in4; 
						yyval.ipp.m.in4_addr = 0xffffffff;
					  } else {
						set_ipv6_addr = 1;
						bcopy(&yypvt[-0].ip6, &yyval.ipp.a, sizeof(yyval.ipp.a));
						fill6bits(128, (u_32_t *)&yyval.ipp.m);
					  }
					  yyexpectaddr = 0; } break;
case 229:
# line 966 "../ipf_y.y"
{ yyresetdict();
					  if (use_inet6 == 0) 
						yyval.ipp.a.in4 = yypvt[-0].ip6.in4; 
					  else { 
						set_ipv6_addr = 1; 
						bcopy(&yypvt[-0].ip6, &yyval.ipp.a, sizeof(yyval.ipp.a)); 
					  } 
					} break;
case 230:
# line 974 "../ipf_y.y"
{ yysetdict(maskwords); } break;
case 231:
# line 975 "../ipf_y.y"
{ if (use_inet6 == 0) { 
						yyval.ipp.m.in4_addr = yypvt[-0].ip6.in4.s_addr; 
						yyval.ipp.a.in4_addr &= yypvt[-0].ip6.in4.s_addr; 
					  } else 
						bcopy(&yypvt[-0].ip6, &yyval.ipp.m, sizeof(yyval.ipp.m)); 
					  yyresetdict();
					  yyexpectaddr = 0; } break;
case 232:
# line 982 "../ipf_y.y"
{ set_ipv6_addr = 1;
					  bcopy(&yypvt[-0].ip6, &yyval.ipp.a, sizeof(yyval.ipp.a));
					  fill6bits(128, (u_32_t *)&yyval.ipp.m);
					  yyresetdict();
					  yyexpectaddr = 0; } break;
case 233:
# line 987 "../ipf_y.y"
{ set_ipv6_addr = 1;
					  yyresetdict();
					  bcopy(&yypvt[-0].ip6, &yyval.ipp.a, sizeof(yyval.ipp.a)); } break;
case 234:
# line 990 "../ipf_y.y"
{ yysetdict(maskwords); } break;
case 235:
# line 991 "../ipf_y.y"
{ bcopy(&yypvt[-0].ip6, &yyval.ipp.m, sizeof(yyval.ipp.m)); 
					  yyresetdict();
					  yyexpectaddr = 0; } break;
case 238:
# line 1002 "../ipf_y.y"
{ yyval.ip6.in4 = yypvt[-0].ipa; } break;
case 239:
# line 1003 "../ipf_y.y"
{ yyval.ip6.in4.s_addr = htonl(yypvt[-0].num); } break;
case 240:
# line 1004 "../ipf_y.y"
{ if ((use_inet6 == 0) && (yypvt[-0].num <= 32)) 
						ntomask(4, yypvt[-0].num, (u_32_t *)&yyval.ip6.in4); 
					  else if ((use_inet6 != 0) && (yypvt[-0].num <= 128)) 
						ntomask(6, yypvt[-0].num, yyval.ip6.i6); 
					  else { 
						yyerror("Bad value specified for netmask"); 
						return 0; 
					  }
					} break;
case 241:
# line 1013 "../ipf_y.y"
{ if (ifpflag == FRI_DYNAMIC) {
						bzero(&yyval.ip6, sizeof(yyval.ip6));
						ifpflag = FRI_BROADCAST;
					  } else
						YYERROR;
					} break;
case 242:
# line 1019 "../ipf_y.y"
{ if (ifpflag == FRI_DYNAMIC) {
						bzero(&yyval.ip6, sizeof(yyval.ip6));
						ifpflag = FRI_NETWORK;
					  } else
						YYERROR;
					} break;
case 243:
# line 1025 "../ipf_y.y"
{ if (ifpflag == FRI_DYNAMIC) {
						bzero(&yyval.ip6, sizeof(yyval.ip6));
						ifpflag = FRI_NETMASKED;
					  } else
						YYERROR;
					} break;
case 244:
# line 1031 "../ipf_y.y"
{ if (ifpflag == FRI_DYNAMIC) {
						bzero(&yyval.ip6, sizeof(yyval.ip6));
						ifpflag = FRI_PEERADDR;
					  } else
						YYERROR;
					} break;
case 245:
# line 1040 "../ipf_y.y"
{ yyval.ip6.in4 = yypvt[-0].ipa; } break;
case 246:
# line 1041 "../ipf_y.y"
{ yyval.ip6.in4.s_addr = yypvt[-0].num; } break;
case 247:
# line 1042 "../ipf_y.y"
{ yyval.ip6.in4.s_addr = yypvt[-0].num; } break;
case 248:
# line 1043 "../ipf_y.y"
{ if (lookuphost(yypvt[-0].str, &yyval.ip6) == 1) 
						free(yypvt[-0].str);
					  else { 
						free(yypvt[-0].str); 
						if (ifpflag != FRI_DYNAMIC) 
							yyerror("Unknown hostname");
					  }
					} break;
case 249:
# line 1054 "../ipf_y.y"
{ yyval.alist = newalist(NULL);
			  if (set_ipv6_addr)
				  yyval.alist->al_family = AF_INET6;
			  else
				  yyval.alist->al_family = AF_INET;
			  set_ipv6_addr = 0;
			  bcopy(&(yypvt[-0].ipp.a), &(yyval.alist->al_i6addr), sizeof(yypvt[-0].ipp.a));
			  bcopy(&(yypvt[-0].ipp.m), &(yyval.alist->al_i6mask), sizeof(yypvt[-0].ipp.m)); } break;
case 250:
# line 1063 "../ipf_y.y"
{ yyval.alist = newalist(yypvt[-2].alist);
			  if (set_ipv6_addr)
				  yyval.alist->al_family = AF_INET6;
			  else
				  yyval.alist->al_family = AF_INET;
			  set_ipv6_addr = 0;
			  bcopy(&(yypvt[-0].ipp.a), &(yyval.alist->al_i6addr), sizeof(yypvt[-0].ipp.a));
			  bcopy(&(yypvt[-0].ipp.m), &(yyval.alist->al_i6mask), sizeof(yypvt[-0].ipp.m)); } break;
case 251:
# line 1073 "../ipf_y.y"
{ yyexpectaddr = 0; yycont = NULL; yyresetdict(); } break;
case 252:
# line 1076 "../ipf_y.y"
{ yyexpectaddr = 0; yycont = NULL; yyresetdict(); } break;
case 253:
# line 1080 "../ipf_y.y"
{ yyval.alist = newalist(NULL);
			  if (set_ipv6_addr)
				  yyval.alist->al_family = AF_INET6;
			  else
				  yyval.alist->al_family = AF_INET;
			  set_ipv6_addr = 0;
			  bcopy(&(yypvt[-0].ipp.a), &(yyval.alist->al_i6addr), sizeof(yypvt[-0].ipp.a));
			  bcopy(&(yypvt[-0].ipp.m), &(yyval.alist->al_i6mask), sizeof(yypvt[-0].ipp.m)); } break;
case 254:
# line 1088 "../ipf_y.y"
{ yyval.alist = newalist(NULL);
			  yyval.alist->al_not = 1;
			  if (set_ipv6_addr)
				  yyval.alist->al_family = AF_INET6;
			  else
				  yyval.alist->al_family = AF_INET;
			  set_ipv6_addr = 0;
			  bcopy(&(yypvt[-0].ipp.a), &(yyval.alist->al_i6addr), sizeof(yypvt[-0].ipp.a));
			  bcopy(&(yypvt[-0].ipp.m), &(yyval.alist->al_i6mask), sizeof(yypvt[-0].ipp.m)); } break;
case 255:
# line 1098 "../ipf_y.y"
{ yyval.alist = newalist(yypvt[-2].alist);
			  if (set_ipv6_addr)
				  yyval.alist->al_family = AF_INET6;
			  else
				  yyval.alist->al_family = AF_INET;
			  set_ipv6_addr = 0;
			  bcopy(&(yypvt[-0].ipp.a), &(yyval.alist->al_i6addr), sizeof(yypvt[-0].ipp.a));
			  bcopy(&(yypvt[-0].ipp.m), &(yyval.alist->al_i6mask), sizeof(yypvt[-0].ipp.m)); } break;
case 256:
# line 1107 "../ipf_y.y"
{ yyval.alist = newalist(yypvt[-3].alist);
			  yyval.alist->al_not = 1;
			  if (set_ipv6_addr)
				  yyval.alist->al_family = AF_INET6;
			  else
				  yyval.alist->al_family = AF_INET;
			  set_ipv6_addr = 0;
			  bcopy(&(yypvt[-0].ipp.a), &(yyval.alist->al_i6addr), sizeof(yypvt[-0].ipp.a));
			  bcopy(&(yypvt[-0].ipp.m), &(yyval.alist->al_i6mask), sizeof(yypvt[-0].ipp.m)); } break;
case 257:
# line 1118 "../ipf_y.y"
{ yyexpectaddr = 0;
					  yycont = NULL;
					} break;
case 258:
# line 1123 "../ipf_y.y"
{ yyval.num = yypvt[-0].num;
					  yysetdict(NULL); } break;
case 259:
# line 1125 "../ipf_y.y"
{ yyval.num = yypvt[-0].num; } break;
case 260:
# line 1128 "../ipf_y.y"
{ yyval.num = FR_EQUAL;
					  yysetdict(NULL); } break;
case 261:
# line 1132 "../ipf_y.y"
{ yyexpectaddr = 0;
					  yycont = NULL;
					  yysetdict(NULL); } break;
case 262:
# line 1138 "../ipf_y.y"
{ yyval.pc.pc = yypvt[-1].num;
					  yyval.pc.p1 = yypvt[-0].port;
					  yyresetdict(); } break;
case 263:
# line 1144 "../ipf_y.y"
{ yyval.pc.p1 = yypvt[-2].port;
					  yyval.pc.pc = yypvt[-1].num;
					  yyval.pc.p2 = yypvt[-0].port;
					  yyresetdict(); } break;
case 266:
# line 1154 "../ipf_y.y"
{ DOALL(fr->fr_icmp = htons(yypvt[-0].num << 8); fr->fr_icmpm = htons(0xff00););
	  yyresetdict();
	} break;
case 267:
# line 1157 "../ipf_y.y"
{ yyresetdict(); } break;
case 268:
# line 1161 "../ipf_y.y"
{ setipftype();
						  yysetdict(icmptypewords); } break;
case 270:
# line 1166 "../ipf_y.y"
{ DOALL(fr->fr_icmp |= htons(yypvt[-0].num); fr->fr_icmpm |= htons(0xff););
	  yyresetdict();
	} break;
case 271:
# line 1169 "../ipf_y.y"
{ yyresetdict(); } break;
case 272:
# line 1173 "../ipf_y.y"
{ yysetdict(icmpcodewords); } break;
case 273:
# line 1178 "../ipf_y.y"
{ DOREM(fr->fr_icmp = htons(yypvt[-0].num << 8); fr->fr_icmpm = htons(0xff00);) } break;
case 274:
# line 1180 "../ipf_y.y"
{ DOREM(fr->fr_icmp = htons(yypvt[-0].num << 8); fr->fr_icmpm = htons(0xff00);) } break;
case 275:
# line 1185 "../ipf_y.y"
{ DOREM(fr->fr_icmp |= htons(yypvt[-0].num); fr->fr_icmpm |= htons(0xff);) } break;
case 276:
# line 1187 "../ipf_y.y"
{ DOREM(fr->fr_icmp |= htons(yypvt[-0].num); fr->fr_icmpm |= htons(0xff);) } break;
case 278:
# line 1190 "../ipf_y.y"
{ DOALL(fr->fr_age[0] = yypvt[-0].num; \
						fr->fr_age[1] = yypvt[-0].num;) } break;
case 279:
# line 1193 "../ipf_y.y"
{ DOALL(fr->fr_age[0] = yypvt[-2].num; \
						fr->fr_age[1] = yypvt[-0].num;) } break;
case 285:
# line 1204 "../ipf_y.y"
{ DOALL(fr->fr_flags |= FR_KEEPSTATE;)} break;
case 286:
# line 1208 "../ipf_y.y"
{ DOALL(fr->fr_flags |= FR_KEEPFRAG;) } break;
case 287:
# line 1209 "../ipf_y.y"
{ DOALL(fr->fr_flags |= FR_KEEPFRAG;) } break;
case 292:
# line 1222 "../ipf_y.y"
{ DOALL(fr->fr_flags |= FR_FRSTRICT;) } break;
case 297:
# line 1235 "../ipf_y.y"
{ DOALL(fr->fr_statemax = yypvt[-0].num;) } break;
case 298:
# line 1236 "../ipf_y.y"
{ DOALL(if (fr->fr_proto != IPPROTO_TCP) { \
						YYERROR; \
					  } else \
						fr->fr_flags |= FR_STSTRICT;)
				} break;
case 299:
# line 1241 "../ipf_y.y"
{ DOALL(if (fr->fr_proto != IPPROTO_TCP) { \
						YYERROR; \
					  } else \
						fr->fr_flags |= FR_NEWISN;)
				} break;
case 300:
# line 1246 "../ipf_y.y"
{ DOALL(fr->fr_flags |= FR_NOICMPERR;) } break;
case 301:
# line 1248 "../ipf_y.y"
{ DOALL(fr->fr_flags |= FR_STATESYNC;) } break;
case 302:
# line 1252 "../ipf_y.y"
{ if (getport(frc, yypvt[-0].str, &(yyval.port)) == -1)
						yyerror("service unknown");
					  else
						yyval.port = ntohs(yyval.port);
					  free(yypvt[-0].str);
					} break;
case 303:
# line 1258 "../ipf_y.y"
{ if (yypvt[-0].num > 65535)	/* Unsigned */
						yyerror("invalid port number");
					  else
						yyval.port = yypvt[-0].num;
					} break;
case 307:
# line 1272 "../ipf_y.y"
{ DOALL(fr->fr_flx |= yypvt[-0].num; fr->fr_mflx |= yypvt[-0].num;) } break;
case 308:
# line 1274 "../ipf_y.y"
{ DOALL(fr->fr_mflx |= yypvt[-0].num;) } break;
case 309:
# line 1275 "../ipf_y.y"
{ yyresetdict(); } break;
case 310:
# line 1276 "../ipf_y.y"
{ yyresetdict(); } break;
case 311:
# line 1277 "../ipf_y.y"
{ yyresetdict(); } break;
case 312:
# line 1280 "../ipf_y.y"
{ yysetdict(ipv4optwords); } break;
case 313:
# line 1284 "../ipf_y.y"
{ if (use_inet6 == 0)
				yyerror("only available with IPv6");
			  yysetdict(ipv6optwords);
			} break;
case 314:
# line 1291 "../ipf_y.y"
{ nowith = 1; } break;
case 315:
# line 1292 "../ipf_y.y"
{ nowith = 1; } break;
case 316:
# line 1296 "../ipf_y.y"
{ yyval.num = FI_OPTIONS; } break;
case 317:
# line 1297 "../ipf_y.y"
{ yyval.num = FI_SHORT; } break;
case 318:
# line 1298 "../ipf_y.y"
{ yyval.num = FI_NATED; } break;
case 319:
# line 1299 "../ipf_y.y"
{ yyval.num = FI_BAD; } break;
case 320:
# line 1300 "../ipf_y.y"
{ yyval.num = FI_BADNAT; } break;
case 321:
# line 1301 "../ipf_y.y"
{ yyval.num = FI_BADSRC; } break;
case 322:
# line 1302 "../ipf_y.y"
{ yyval.num = FI_LOWTTL; } break;
case 323:
# line 1303 "../ipf_y.y"
{ yyval.num = FI_FRAG; } break;
case 324:
# line 1304 "../ipf_y.y"
{ yyval.num = FI_FRAGBODY; } break;
case 325:
# line 1305 "../ipf_y.y"
{ yyval.num = FI_FRAG; } break;
case 326:
# line 1306 "../ipf_y.y"
{ yyval.num = FI_MBCAST; } break;
case 327:
# line 1307 "../ipf_y.y"
{ yyval.num = FI_MULTICAST; } break;
case 328:
# line 1308 "../ipf_y.y"
{ yyval.num = FI_BROADCAST; } break;
case 329:
# line 1309 "../ipf_y.y"
{ yyval.num = FI_STATE; } break;
case 330:
# line 1310 "../ipf_y.y"
{ yyval.num = FI_OOW; } break;
case 331:
# line 1313 "../ipf_y.y"
{ DOALL(fr->fr_mip.fi_optmsk |= yypvt[-0].num;
				if (!nowith)
					fr->fr_ip.fi_optmsk |= yypvt[-0].num;)
			} break;
case 332:
# line 1320 "../ipf_y.y"
{ yyval.num |= yypvt[-0].num; } break;
case 333:
# line 1321 "../ipf_y.y"
{ yyval.num |= yypvt[-2].num | yypvt[-0].num; } break;
case 334:
# line 1325 "../ipf_y.y"
{ DOALL(fr->fr_mip.fi_optmsk |= yypvt[-0].num;
				if (!nowith)
					fr->fr_ip.fi_optmsk |= yypvt[-0].num;)
			} break;
case 335:
# line 1332 "../ipf_y.y"
{ yyval.num |= yypvt[-0].num; } break;
case 336:
# line 1333 "../ipf_y.y"
{ yyval.num |= yypvt[-2].num | yypvt[-0].num; } break;
case 337:
# line 1337 "../ipf_y.y"
{ yyval.num |= yypvt[-0].num; } break;
case 338:
# line 1338 "../ipf_y.y"
{ yyval.num |= yypvt[-2].num | yypvt[-0].num; } break;
case 339:
# line 1342 "../ipf_y.y"
{ yyval.num = secbit(IPSO_CLASS_UNCL); } break;
case 340:
# line 1343 "../ipf_y.y"
{ yyval.num = secbit(IPSO_CLASS_CONF); } break;
case 341:
# line 1344 "../ipf_y.y"
{ yyval.num = secbit(IPSO_CLASS_RES1); } break;
case 342:
# line 1345 "../ipf_y.y"
{ yyval.num = secbit(IPSO_CLASS_RES2); } break;
case 343:
# line 1346 "../ipf_y.y"
{ yyval.num = secbit(IPSO_CLASS_RES3); } break;
case 344:
# line 1347 "../ipf_y.y"
{ yyval.num = secbit(IPSO_CLASS_RES4); } break;
case 345:
# line 1348 "../ipf_y.y"
{ yyval.num = secbit(IPSO_CLASS_SECR); } break;
case 346:
# line 1349 "../ipf_y.y"
{ yyval.num = secbit(IPSO_CLASS_TOPS); } break;
case 347:
# line 1353 "../ipf_y.y"
{ yyval.num = yypvt[-0].num; } break;
case 348:
# line 1354 "../ipf_y.y"
{ yyval.num = ICMP_UNREACH; } break;
case 349:
# line 1355 "../ipf_y.y"
{ yyval.num = ICMP_ECHO; } break;
case 350:
# line 1356 "../ipf_y.y"
{ yyval.num = ICMP_ECHOREPLY; } break;
case 351:
# line 1357 "../ipf_y.y"
{ yyval.num = ICMP_SOURCEQUENCH; } break;
case 352:
# line 1358 "../ipf_y.y"
{ yyval.num = ICMP_REDIRECT; } break;
case 353:
# line 1359 "../ipf_y.y"
{ yyval.num = ICMP_TIMXCEED; } break;
case 354:
# line 1360 "../ipf_y.y"
{ yyval.num = ICMP_PARAMPROB; } break;
case 355:
# line 1361 "../ipf_y.y"
{ yyval.num = ICMP_TSTAMP; } break;
case 356:
# line 1362 "../ipf_y.y"
{ yyval.num = ICMP_TSTAMPREPLY; } break;
case 357:
# line 1363 "../ipf_y.y"
{ yyval.num = ICMP_IREQ; } break;
case 358:
# line 1364 "../ipf_y.y"
{ yyval.num = ICMP_IREQREPLY; } break;
case 359:
# line 1365 "../ipf_y.y"
{ yyval.num = ICMP_MASKREQ; } break;
case 360:
# line 1366 "../ipf_y.y"
{ yyval.num = ICMP_MASKREPLY; } break;
case 361:
# line 1367 "../ipf_y.y"
{ yyval.num = ICMP_ROUTERADVERT; } break;
case 362:
# line 1368 "../ipf_y.y"
{ yyval.num = ICMP_ROUTERSOLICIT; } break;
case 363:
# line 1372 "../ipf_y.y"
{ yyval.num = yypvt[-0].num; } break;
case 364:
# line 1373 "../ipf_y.y"
{ yyval.num = ICMP_UNREACH_NET; } break;
case 365:
# line 1374 "../ipf_y.y"
{ yyval.num = ICMP_UNREACH_HOST; } break;
case 366:
# line 1375 "../ipf_y.y"
{ yyval.num = ICMP_UNREACH_PROTOCOL; } break;
case 367:
# line 1376 "../ipf_y.y"
{ yyval.num = ICMP_UNREACH_PORT; } break;
case 368:
# line 1377 "../ipf_y.y"
{ yyval.num = ICMP_UNREACH_NEEDFRAG; } break;
case 369:
# line 1378 "../ipf_y.y"
{ yyval.num = ICMP_UNREACH_SRCFAIL; } break;
case 370:
# line 1379 "../ipf_y.y"
{ yyval.num = ICMP_UNREACH_NET_UNKNOWN; } break;
case 371:
# line 1380 "../ipf_y.y"
{ yyval.num = ICMP_UNREACH_HOST_UNKNOWN; } break;
case 372:
# line 1381 "../ipf_y.y"
{ yyval.num = ICMP_UNREACH_ISOLATED; } break;
case 373:
# line 1382 "../ipf_y.y"
{ yyval.num = ICMP_UNREACH_NET_PROHIB; } break;
case 374:
# line 1383 "../ipf_y.y"
{ yyval.num = ICMP_UNREACH_HOST_PROHIB; } break;
case 375:
# line 1384 "../ipf_y.y"
{ yyval.num = ICMP_UNREACH_TOSNET; } break;
case 376:
# line 1385 "../ipf_y.y"
{ yyval.num = ICMP_UNREACH_TOSHOST; } break;
case 377:
# line 1386 "../ipf_y.y"
{ yyval.num = ICMP_UNREACH_ADMIN_PROHIBIT; } break;
case 378:
# line 1387 "../ipf_y.y"
{ yyval.num = 14; } break;
case 379:
# line 1388 "../ipf_y.y"
{ yyval.num = 15; } break;
case 380:
# line 1392 "../ipf_y.y"
{ yyval.num = getoptbyvalue(IPOPT_NOP); } break;
case 381:
# line 1393 "../ipf_y.y"
{ yyval.num = getoptbyvalue(IPOPT_RR); } break;
case 382:
# line 1394 "../ipf_y.y"
{ yyval.num = getoptbyvalue(IPOPT_ZSU); } break;
case 383:
# line 1395 "../ipf_y.y"
{ yyval.num = getoptbyvalue(IPOPT_MTUP); } break;
case 384:
# line 1396 "../ipf_y.y"
{ yyval.num = getoptbyvalue(IPOPT_MTUR); } break;
case 385:
# line 1397 "../ipf_y.y"
{ yyval.num = getoptbyvalue(IPOPT_ENCODE); } break;
case 386:
# line 1398 "../ipf_y.y"
{ yyval.num = getoptbyvalue(IPOPT_TS); } break;
case 387:
# line 1399 "../ipf_y.y"
{ yyval.num = getoptbyvalue(IPOPT_TR); } break;
case 388:
# line 1400 "../ipf_y.y"
{ yyval.num = getoptbyvalue(IPOPT_SECURITY); } break;
case 389:
# line 1401 "../ipf_y.y"
{ yyval.num = getoptbyvalue(IPOPT_LSRR); } break;
case 390:
# line 1402 "../ipf_y.y"
{ yyval.num = getoptbyvalue(IPOPT_E_SEC); } break;
case 391:
# line 1403 "../ipf_y.y"
{ yyval.num = getoptbyvalue(IPOPT_CIPSO); } break;
case 392:
# line 1404 "../ipf_y.y"
{ yyval.num = getoptbyvalue(IPOPT_SATID); } break;
case 393:
# line 1405 "../ipf_y.y"
{ yyval.num = getoptbyvalue(IPOPT_SSRR); } break;
case 394:
# line 1406 "../ipf_y.y"
{ yyval.num = getoptbyvalue(IPOPT_ADDEXT); } break;
case 395:
# line 1407 "../ipf_y.y"
{ yyval.num = getoptbyvalue(IPOPT_VISA); } break;
case 396:
# line 1408 "../ipf_y.y"
{ yyval.num = getoptbyvalue(IPOPT_IMITD); } break;
case 397:
# line 1409 "../ipf_y.y"
{ yyval.num = getoptbyvalue(IPOPT_EIP); } break;
case 398:
# line 1410 "../ipf_y.y"
{ yyval.num = getoptbyvalue(IPOPT_FINN); } break;
case 399:
# line 1411 "../ipf_y.y"
{ yyval.num = getoptbyvalue(IPOPT_DPS); } break;
case 400:
# line 1412 "../ipf_y.y"
{ yyval.num = getoptbyvalue(IPOPT_SDB); } break;
case 401:
# line 1413 "../ipf_y.y"
{ yyval.num = getoptbyvalue(IPOPT_NSAPA); } break;
case 402:
# line 1414 "../ipf_y.y"
{ yyval.num = getoptbyvalue(IPOPT_RTRALRT); } break;
case 403:
# line 1415 "../ipf_y.y"
{ yyval.num = getoptbyvalue(IPOPT_UMP); } break;
case 404:
# line 1417 "../ipf_y.y"
{ DOALL(fr->fr_mip.fi_secmsk |= yypvt[-0].num;
				if (!nowith)
					fr->fr_ip.fi_secmsk |= yypvt[-0].num;)
			  yyval.num = 0;
			  yyresetdict();
			} break;
case 405:
# line 1426 "../ipf_y.y"
{ yysetdict(ipv4secwords); } break;
case 406:
# line 1430 "../ipf_y.y"
{ yyval.num = getv6optbyvalue(IPPROTO_AH); } break;
case 407:
# line 1431 "../ipf_y.y"
{ yyval.num = getv6optbyvalue(IPPROTO_DSTOPTS); } break;
case 408:
# line 1432 "../ipf_y.y"
{ yyval.num = getv6optbyvalue(IPPROTO_ESP); } break;
case 409:
# line 1433 "../ipf_y.y"
{ yyval.num = getv6optbyvalue(IPPROTO_HOPOPTS); } break;
case 410:
# line 1434 "../ipf_y.y"
{ yyval.num = getv6optbyvalue(IPPROTO_IPV6); } break;
case 411:
# line 1435 "../ipf_y.y"
{ yyval.num = getv6optbyvalue(IPPROTO_NONE); } break;
case 412:
# line 1436 "../ipf_y.y"
{ yyval.num = getv6optbyvalue(IPPROTO_ROUTING); } break;
case 413:
# line 1437 "../ipf_y.y"
{ yyval.num = getv6optbyvalue(IPPROTO_FRAGMENT); } break;
case 414:
# line 1440 "../ipf_y.y"
{ setsyslog(); } break;
case 415:
# line 1444 "../ipf_y.y"
{ fr->fr_loglevel = LOG_LOCAL0|yypvt[-0].num; } break;
case 416:
# line 1445 "../ipf_y.y"
{ fr->fr_loglevel = yypvt[-2].num | yypvt[-0].num; } break;
case 417:
# line 1449 "../ipf_y.y"
{ yyval.num = LOG_KERN; } break;
case 418:
# line 1450 "../ipf_y.y"
{ yyval.num = LOG_USER; } break;
case 419:
# line 1451 "../ipf_y.y"
{ yyval.num = LOG_MAIL; } break;
case 420:
# line 1452 "../ipf_y.y"
{ yyval.num = LOG_DAEMON; } break;
case 421:
# line 1453 "../ipf_y.y"
{ yyval.num = LOG_AUTH; } break;
case 422:
# line 1454 "../ipf_y.y"
{ yyval.num = LOG_SYSLOG; } break;
case 423:
# line 1455 "../ipf_y.y"
{ yyval.num = LOG_LPR; } break;
case 424:
# line 1456 "../ipf_y.y"
{ yyval.num = LOG_NEWS; } break;
case 425:
# line 1457 "../ipf_y.y"
{ yyval.num = LOG_UUCP; } break;
case 426:
# line 1458 "../ipf_y.y"
{ yyval.num = LOG_CRON; } break;
case 427:
# line 1459 "../ipf_y.y"
{ yyval.num = LOG_FTP; } break;
case 428:
# line 1460 "../ipf_y.y"
{ yyval.num = LOG_AUTHPRIV; } break;
case 429:
# line 1461 "../ipf_y.y"
{ yyval.num = LOG_AUDIT; } break;
case 430:
# line 1462 "../ipf_y.y"
{ yyval.num = LOG_LFMT; } break;
case 431:
# line 1463 "../ipf_y.y"
{ yyval.num = LOG_LOCAL0; } break;
case 432:
# line 1464 "../ipf_y.y"
{ yyval.num = LOG_LOCAL1; } break;
case 433:
# line 1465 "../ipf_y.y"
{ yyval.num = LOG_LOCAL2; } break;
case 434:
# line 1466 "../ipf_y.y"
{ yyval.num = LOG_LOCAL3; } break;
case 435:
# line 1467 "../ipf_y.y"
{ yyval.num = LOG_LOCAL4; } break;
case 436:
# line 1468 "../ipf_y.y"
{ yyval.num = LOG_LOCAL5; } break;
case 437:
# line 1469 "../ipf_y.y"
{ yyval.num = LOG_LOCAL6; } break;
case 438:
# line 1470 "../ipf_y.y"
{ yyval.num = LOG_LOCAL7; } break;
case 439:
# line 1471 "../ipf_y.y"
{ yyval.num = LOG_SECURITY; } break;
case 440:
# line 1475 "../ipf_y.y"
{ yyval.num = LOG_EMERG; } break;
case 441:
# line 1476 "../ipf_y.y"
{ yyval.num = LOG_ALERT; } break;
case 442:
# line 1477 "../ipf_y.y"
{ yyval.num = LOG_CRIT; } break;
case 443:
# line 1478 "../ipf_y.y"
{ yyval.num = LOG_ERR; } break;
case 444:
# line 1479 "../ipf_y.y"
{ yyval.num = LOG_WARNING; } break;
case 445:
# line 1480 "../ipf_y.y"
{ yyval.num = LOG_NOTICE; } break;
case 446:
# line 1481 "../ipf_y.y"
{ yyval.num = LOG_INFO; } break;
case 447:
# line 1482 "../ipf_y.y"
{ yyval.num = LOG_DEBUG; } break;
case 448:
# line 1486 "../ipf_y.y"
{ yyval.num = FR_EQUAL; } break;
case 449:
# line 1487 "../ipf_y.y"
{ yyval.num = FR_NEQUAL; } break;
case 450:
# line 1488 "../ipf_y.y"
{ yyval.num = FR_LESST; } break;
case 451:
# line 1489 "../ipf_y.y"
{ yyval.num = FR_LESSTE; } break;
case 452:
# line 1490 "../ipf_y.y"
{ yyval.num = FR_GREATERT; } break;
case 453:
# line 1491 "../ipf_y.y"
{ yyval.num = FR_GREATERTE; } break;
case 454:
# line 1494 "../ipf_y.y"
{ yyval.num = FR_INRANGE; } break;
case 455:
# line 1495 "../ipf_y.y"
{ yyval.num = FR_OUTRANGE; } break;
case 456:
# line 1496 "../ipf_y.y"
{ yyval.num = FR_INCRANGE; } break;
case 457:
# line 1500 "../ipf_y.y"
{ yyval.str = yypvt[-0].str; } break;
case 458:
# line 1503 "../ipf_y.y"
{ yyval.str = yypvt[-0].str; } break;
case 459:
# line 1505 "../ipf_y.y"
{ yyval.str = yypvt[-2].str;
		  fprintf(stderr, "%d: Logical interface %s:%d unsupported, "
			  "use the physical interface %s instead.\n",
			  yylineNum, yypvt[-2].str, yypvt[-0].num, yypvt[-2].str);
		} break;
case 460:
# line 1512 "../ipf_y.y"
{ yyval.str = yypvt[-0].str; } break;
case 461:
# line 1517 "../ipf_y.y"
{ if (yypvt[-2].num > 255 || yypvt[-0].num > 255) {
			yyerror("Invalid octet string for IP address");
			return 0;
		  }
		  yyval.ipa.s_addr = (yypvt[-2].num << 24) | (yypvt[-0].num << 16);
		  yyval.ipa.s_addr = htonl(yyval.ipa.s_addr);
		} break;
case 462:
# line 1528 "../ipf_y.y"
{ if (yypvt[-0].num > 255) {
			yyerror("Invalid octet string for IP address");
			return 0;
		  }
		  yyval.ipa.s_addr |= htonl(yypvt[-0].num << 8);
		} break;
case 463:
# line 1537 "../ipf_y.y"
{ if (yypvt[-0].num > 255) {
			yyerror("Invalid octet string for IP address");
			return 0;
		  }
		  yyval.ipa.s_addr |= htonl(yypvt[-0].num);
		} break;
# line	556 "/usr/share/lib/ccs/yaccpar"
	}
	goto yystack;		/* reset registers in driver code */
}

