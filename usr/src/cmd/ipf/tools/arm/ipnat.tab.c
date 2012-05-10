
# line 2 "../ipnat_y.y"
/*
 * Copyright (C) 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef  __FreeBSD__
# ifndef __FreeBSD_cc_version
#  include <osreldate.h>
# else
#  if __FreeBSD_cc_version < 430000
#   include <osreldate.h>
#  endif
# endif
#endif
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#if !defined(__SVR4) && !defined(__GNUC__)
#include <strings.h>
#endif
#include <sys/types.h>
#include <sys/param.h>
#include <sys/file.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <sys/time.h>
#include <syslog.h>
#include <net/if.h>
#if __FreeBSD_version >= 300000
# include <net/if_var.h>
#endif
#include <netdb.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include "ipf.h"
#include "netinet/ipl.h"
#include "ipnat_l.h"

#define	YYDEBUG	1

extern	void	yyerror __P((char *));
extern	int	yyparse __P((void));
extern	int	yylex __P((void));
extern	int	yydebug;
extern	FILE	*yyin;
extern	int	yylineNum;

static	ipnat_t		*nattop = NULL;
static	ipnat_t		*nat = NULL;
static	int		natfd = -1;
static	ioctlfunc_t	natioctlfunc = NULL;
static	addfunc_t	nataddfunc = NULL;

static	void	newnatrule __P((void));
static	void	setnatproto __P((int));
static  u_32_t  lookuphost __P((char *));


# line 72 "../ipnat_y.y"
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
	u_short	port;
	struct	{
		u_short	p1;
		u_short	p2;
		int	pc;
	} pc;
	struct	{
		struct	in_addr	a;
		struct	in_addr	m;
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
# define IPNY_MAPBLOCK 270
# define IPNY_RDR 271
# define IPNY_PORT 272
# define IPNY_PORTS 273
# define IPNY_AUTO 274
# define IPNY_RANGE 275
# define IPNY_MAP 276
# define IPNY_BIMAP 277
# define IPNY_FROM 278
# define IPNY_TO 279
# define IPNY_MASK 280
# define IPNY_PORTMAP 281
# define IPNY_ANY 282
# define IPNY_ROUNDROBIN 283
# define IPNY_FRAG 284
# define IPNY_AGE 285
# define IPNY_ICMPIDMAP 286
# define IPNY_PROXY 287
# define IPNY_TCP 288
# define IPNY_UDP 289
# define IPNY_TCPUDP 290
# define IPNY_STICKY 291
# define IPNY_MSSCLAMP 292
# define IPNY_TAG 293
# define IPNY_TLATE 294

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

# line 598 "../ipnat_y.y"



static	wordtab_t	yywords[] = {
	{ "age",	IPNY_AGE },
	{ "any",	IPNY_ANY },
	{ "auto",	IPNY_AUTO },
	{ "bimap",	IPNY_BIMAP },
	{ "frag",	IPNY_FRAG },
	{ "from",	IPNY_FROM },
	{ "icmpidmap",	IPNY_ICMPIDMAP },
	{ "mask",	IPNY_MASK },
	{ "map",	IPNY_MAP },
	{ "map-block",	IPNY_MAPBLOCK },
	{ "mssclamp",	IPNY_MSSCLAMP },
	{ "netmask",	IPNY_MASK },
	{ "port",	IPNY_PORT },
	{ "portmap",	IPNY_PORTMAP },
	{ "ports",	IPNY_PORTS },
	{ "proxy",	IPNY_PROXY },
	{ "range",	IPNY_RANGE },
	{ "rdr",	IPNY_RDR },
	{ "round-robin",IPNY_ROUNDROBIN },
	{ "sticky",	IPNY_STICKY },
	{ "tag",	IPNY_TAG },
	{ "tcp",	IPNY_TCP },
	{ "tcpudp",	IPNY_TCPUDP },
	{ "to",		IPNY_TO },
	{ "udp",	IPNY_UDP },
	{ "-",		'-' },
	{ "->",		IPNY_TLATE },
	{ "eq",		YY_CMP_EQ },
	{ "ne",		YY_CMP_NE },
	{ "lt",		YY_CMP_LT },
	{ "gt",		YY_CMP_GT },
	{ "le",		YY_CMP_LE },
	{ "ge",		YY_CMP_GE },
	{ NULL,		0 }
};


int ipnat_parsefile(fd, addfunc, ioctlfunc, filename)
int fd;
addfunc_t addfunc;
ioctlfunc_t ioctlfunc;
char *filename;
{
	FILE *fp = NULL;
	char *s;

	(void) yysettab(yywords);

	s = getenv("YYDEBUG");
	if (s)
		yydebug = atoi(s);
	else
		yydebug = 0;

	if (strcmp(filename, "-")) {
		fp = fopen(filename, "r");
		if (!fp) {
			fprintf(stderr, "fopen(%s) failed: %s\n", filename,
				STRERROR(errno));
			return -1;
		}
	} else
		fp = stdin;

	while (ipnat_parsesome(fd, addfunc, ioctlfunc, fp) == 1)
		;
	if (fp != NULL)
		fclose(fp);
	return 0;
}


int ipnat_parsesome(fd, addfunc, ioctlfunc, fp)
int fd;
addfunc_t addfunc;
ioctlfunc_t ioctlfunc;
FILE *fp;
{
	char *s;
	int i;

	yylineNum = 1;

	natfd = fd;
	nataddfunc = addfunc;
	natioctlfunc = ioctlfunc;

	if (feof(fp))
		return 0;
	i = fgetc(fp);
	if (i == EOF)
		return 0;
	if (ungetc(i, fp) == EOF)
		return 0;
	if (feof(fp))
		return 0;
	s = getenv("YYDEBUG");
	if (s)
		yydebug = atoi(s);
	else
		yydebug = 0;

	yyin = fp;
	yyparse();
	return 1;
}


static void newnatrule()
{
	ipnat_t *n;

	n = calloc(1, sizeof(*n));
	if (n == NULL)
		return;

	if (nat == NULL)
		nattop = nat = n;
	else {
		nat->in_next = n;
		nat = n;
	}
}


static void setnatproto(p)
int p;
{
	nat->in_p = p;

	switch (p)
	{
	case IPPROTO_TCP :
		nat->in_flags |= IPN_TCP;
		nat->in_flags &= ~IPN_UDP;
		break;
	case IPPROTO_UDP :
		nat->in_flags |= IPN_UDP;
		nat->in_flags &= ~IPN_TCP;
		break;
	case IPPROTO_ICMP :
		nat->in_flags &= ~IPN_TCPUDP;
		if (!(nat->in_flags & IPN_ICMPQUERY)) {
			nat->in_dcmp = 0;
			nat->in_scmp = 0;
			nat->in_pmin = 0;
			nat->in_pmax = 0;
			nat->in_pnext = 0;
		}
		break;
	default :
		if ((nat->in_redir & NAT_MAPBLK) == 0) {
			/* Only reset dcmp/scmp in case dport/sport not set */
			if (0 == nat->in_tuc.ftu_dport)
				nat->in_dcmp = 0;
			if (0 == nat->in_tuc.ftu_sport)
				nat->in_scmp = 0;
			nat->in_pmin = 0;
			nat->in_pmax = 0;
			nat->in_pnext = 0;
			nat->in_flags &= ~IPN_TCPUDP;
		}
		break;
	}

	if ((nat->in_flags & (IPN_TCPUDP|IPN_FIXEDDPORT)) == IPN_FIXEDDPORT)
		nat->in_flags &= ~IPN_FIXEDDPORT;
}


void ipnat_addrule(fd, ioctlfunc, ptr)
int fd;
ioctlfunc_t ioctlfunc;
void *ptr;
{
	ioctlcmd_t add, del;
	ipfobj_t obj;
	ipnat_t *ipn;

	ipn = ptr;
	bzero((char *)&obj, sizeof(obj));
	obj.ipfo_rev = IPFILTER_VERSION;
	obj.ipfo_size = sizeof(ipnat_t);
	obj.ipfo_type = IPFOBJ_IPNAT;
	obj.ipfo_ptr = ptr;
	add = 0;
	del = 0;

	if ((opts & OPT_DONOTHING) != 0)
		fd = -1;

	if (opts & OPT_ZERORULEST) {
		add = SIOCZRLST;
	} else if (opts & OPT_INACTIVE) {
		add = SIOCADNAT;
		del = SIOCRMNAT;
	} else {
		add = SIOCADNAT;
		del = SIOCRMNAT;
	}

	if (ipn && (opts & OPT_VERBOSE))
		printnat(ipn, opts);

	if (opts & OPT_DEBUG)
		binprint(ipn, sizeof(*ipn));

	if ((opts & OPT_ZERORULEST) != 0) {
		if ((*ioctlfunc)(fd, add, (void *)&obj) == -1) {
			if ((opts & OPT_DONOTHING) == 0) {
				fprintf(stderr, "%d:", yylineNum);
				perror("ioctl(SIOCZRLST)");
			}
		} else {
#ifdef	USE_QUAD_T
/*
			printf("hits %qd bytes %qd ",
				(long long)fr->fr_hits,
				(long long)fr->fr_bytes);
*/
#else
/*
			printf("hits %ld bytes %ld ",
				fr->fr_hits, fr->fr_bytes);
*/
#endif
			printnat(ipn, opts);
		}
	} else if ((opts & OPT_REMOVE) != 0) {
		if ((*ioctlfunc)(fd, del, (void *)&obj) == -1) {
			if ((opts & OPT_DONOTHING) == 0) {
				fprintf(stderr, "%d:", yylineNum);
				perror("ioctl(delete nat rule)");
			}
		}
	} else {
		if ((*ioctlfunc)(fd, add, (void *)&obj) == -1) {
			if ((opts & OPT_DONOTHING) == 0) {
				fprintf(stderr, "%d:", yylineNum);
				perror("ioctl(add/insert nat rule)");
			}
		}
	}
}

static u_32_t lookuphost(name)
char *name;
{
	i6addr_t addr;

	if (gethost(name, &addr, 0) == -1) {
		return 0;
	}
	return addr.in4_addr;
}
static YYCONST yytabelem yyexca[] ={
-1, 1,
	0, -1,
	-2, 9,
	};
# define YYNPROD 118
# define YYLAST 311
static YYCONST yytabelem yyact[]={

    62,   121,    82,   123,    63,    59,    50,    49,   204,   195,
   121,   202,   123,   138,   139,   140,   189,   215,   181,    94,
    47,   185,    61,   168,    95,    93,    39,    39,    38,    38,
   134,    51,   120,   122,   119,    39,    78,    38,   131,   102,
    89,   208,   122,    41,    68,    86,   153,    87,    41,    18,
    19,    34,    34,   106,   218,    16,    17,   115,   129,   145,
    34,   212,   172,   154,   136,    79,   187,   136,   149,   150,
   165,     6,     5,    86,    86,    87,   170,    39,   186,    38,
   141,    76,    73,    72,    73,   203,    58,    31,    28,   213,
   205,   200,   196,   191,    76,   174,   159,   151,    80,    91,
   194,   105,   184,   117,   167,   118,   133,   156,    99,    40,
    36,   132,    83,   128,   103,    92,    53,    21,   126,    48,
   101,    23,   190,   188,    71,    37,   125,   206,    66,   124,
   198,   127,   197,   173,   158,   178,   113,    56,   142,    42,
    22,     3,   214,     8,    26,   201,     2,    32,     7,   100,
    43,    44,    24,    25,    54,   137,    46,    57,    55,    29,
    30,    70,    74,    64,    85,    27,    45,    55,    60,    97,
    67,    67,    84,    65,    84,    15,    88,    75,    96,    69,
    81,   114,    90,    14,    33,    98,    55,    13,    12,    11,
    10,    20,     9,    84,     4,   116,     1,    35,   130,   148,
   104,     0,     0,     0,   135,     0,   147,     0,     0,   143,
   144,   146,     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,   157,     0,   152,     0,   161,   162,
   155,   164,   163,     0,     0,     0,   160,     0,   169,   171,
   166,     0,     0,     0,    39,     0,    38,     0,     0,    86,
   177,    87,   175,   107,   108,   110,   112,   109,   111,   179,
   176,     0,   180,     0,    52,    41,    86,   183,    87,    34,
   157,   182,     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,    77,   193,     0,     0,   157,   192,     0,     0,
   199,     0,     0,     0,     0,     0,     0,     0,     0,     0,
   217,     0,   210,   207,   209,     0,     0,   211,     0,     0,
   216 };
static YYCONST yytabelem yypact[]={

  -188,  -188,-10000000,-10000000,  -221,-10000000,    56,-10000000,-10000000,-10000000,
    62,    62,    62,  -171,  -171,  -171,-10000000,-10000000,-10000000,-10000000,
  -172,-10000000,-10000000,-10000000,-10000000,-10000000,  -230,    95,-10000000,  -222,
   -13,    60,  -287,  -288,-10000000,-10000000,   -16,  -222,-10000000,    91,
-10000000,-10000000,  -173,  -289,  -272,  -290,  -222,  -235,-10000000,  -231,
  -231,  -174,  -176,     3,  -207,-10000000,  -159,-10000000,-10000000,  -222,
  -292,  -180,  -184,  -180,  -239,  -222,  -262,-10000000,  -163,  -262,
-10000000,-10000000,    91,-10000000,-10000000,-10000000,    91,  -222,  -240,    -8,
    90,  -216,  -180,  -256,    82,    73,-10000000,-10000000,  -214,  -222,
  -241,  -253,  -253,  -208,  -275,  -179,    93,  -253,  -253,-10000000,
  -213,-10000000,  -222,-10000000,  -184,  -199,-10000000,-10000000,-10000000,-10000000,
-10000000,-10000000,-10000000,  -160,  -253,  -211,  -214,  -253,-10000000,-10000000,
    87,-10000000,-10000000,-10000000,  -161,  -180,  -184,  -184,  -256,     9,
-10000000,  -222,-10000000,  -261,-10000000,-10000000,  -183,  -212,    86,-10000000,
-10000000,  -162,  -163,-10000000,-10000000,    -8,-10000000,-10000000,  -184,-10000000,
-10000000,    89,-10000000,-10000000,-10000000,  -256,-10000000,  -261,  -271,-10000000,
-10000000,-10000000,-10000000,  -253,-10000000,  -184,-10000000,  -264,-10000000,  -181,
  -193,    65,-10000000,  -273,    64,-10000000,-10000000,-10000000,  -164,  -253,
  -264,-10000000,-10000000,-10000000,  -283,  -165,    85,    83,  -184,-10000000,
  -166,-10000000,-10000000,  -280,  -285,  -167,    80,  -247,  -247,-10000000,
-10000000,  -283,-10000000,  -256,  -198,-10000000,  -168,-10000000,-10000000,-10000000,
  -270,-10000000,-10000000,-10000000,  -285,  -205,-10000000,-10000000,-10000000 };
static YYCONST yytabelem yypgo[]={

     0,   101,   124,   200,   199,   105,   110,   109,   120,   197,
   128,   114,   196,   146,   141,   194,   192,   191,   190,   140,
   189,   188,   187,   144,    99,   111,   115,   184,   183,   181,
   175,   168,   112,   113,   103,   107,   166,   125,   116,   108,
   165,   157,   155,   154,   149,   106,   104,   102,   100,    85,
   145,   142 };
static YYCONST yytabelem yyr1[]={

     0,    12,    12,    12,    12,    13,    13,    14,    17,    15,
    16,    16,    16,    19,    19,    18,    18,    18,    18,    20,
    21,    21,    21,    24,    24,    24,    34,    34,    34,    34,
    10,    10,    32,    32,    32,     1,     1,    31,    31,    31,
    31,    33,    33,    29,    29,    29,    22,    22,    30,    28,
    27,    27,    36,    36,    37,    23,    23,    40,    41,    26,
    26,    26,    38,    38,    43,    39,    39,    44,     8,     8,
     8,     8,     8,     8,     9,     9,    11,    11,    25,    35,
    49,    49,    45,    45,    46,    46,    47,    47,    47,    50,
    50,    48,    48,    42,    42,    42,    42,    42,    51,    51,
     5,     5,     5,     5,     2,     6,     6,     6,     3,     3,
     3,     3,     3,     3,     3,     4,     4,     7 };
static YYCONST yytabelem yyr2[]={

     0,     2,     2,     4,     4,     5,     2,     9,     3,     1,
     4,     4,     4,     0,     2,    15,    15,    15,    15,    15,
    19,    17,    15,     0,    13,    13,     0,     3,     3,     7,
     3,     9,     3,     7,     7,     3,     3,     0,     5,     9,
     9,     5,     7,     0,     5,     5,     3,     3,     3,     3,
     8,    11,     8,    11,     3,     2,     6,     3,     3,    11,
     7,    11,     2,     7,     3,     2,     7,     3,     3,     3,
     7,     7,     7,     7,     3,     7,     5,     7,    12,    14,
     0,     5,     0,     3,     0,     3,     0,     5,     9,     0,
     3,     0,     5,     0,     3,     3,     3,     7,     5,     3,
     3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
     3,     3,     3,     3,     3,     3,     3,    15 };
static YYCONST yytabelem yychk[]={

-10000000,   -12,   -13,   -14,   -15,   260,   259,   -13,   -14,   -16,
   -18,   -20,   -21,   -22,   -28,   -30,   276,   277,   270,   271,
   -17,    61,   -19,    59,   -19,   -19,   -23,   -40,   259,   -23,
   -23,   259,    -8,   -27,   282,    -9,    -6,   -37,   259,   257,
    -7,   278,    44,    -8,    -8,   -36,   -37,    33,    59,   294,
   294,    47,   280,   -38,   -43,    -8,    46,   -41,   259,   294,
   -31,   294,   272,   294,   -38,   -37,   -10,    -8,   275,   -10,
    -7,    -2,   257,   258,    -7,    -2,   257,   279,    33,   272,
   257,    -8,   294,   -32,    -6,    -1,   257,   259,   -32,   279,
   -38,   -24,   -26,   287,   281,   286,    -7,   -24,   -26,   -39,
   -44,    -8,   279,   -11,    -3,    -1,    61,   261,   262,   265,
   263,   266,   264,    46,   -29,   273,   -32,   -34,    -5,   290,
   288,   257,   289,   259,    47,    44,    45,    58,   -33,   272,
   -39,   279,   -25,   -45,   283,   -25,   272,   -42,   288,   289,
   290,   259,    45,   -25,   -25,   272,   -39,    -1,    -4,   267,
   268,   257,   -25,   257,   274,   -33,   -35,   -45,    47,   257,
    -6,    -1,    -1,   -34,    -1,    61,   -39,   -46,   284,    -1,
   259,    -1,   274,    47,   257,    -7,   -11,    -1,    46,   -34,
   -46,   289,   -35,    -1,   -47,   285,   259,   259,    58,   289,
    58,   257,   -35,   -47,   -48,   292,   257,    47,    47,    -1,
   257,   -50,   291,   -49,   293,   257,    47,    -5,   288,    -5,
   -48,   -34,   259,   257,   -51,   287,   -24,   -49,   259 };
static YYCONST yytabelem yydef[]={

     9,    -2,     1,     2,     0,     6,     0,     3,     4,     5,
    13,    13,    13,     0,     0,     0,    46,    47,    49,    48,
     0,     8,    10,    14,    11,    12,     0,    55,    57,     0,
     0,     0,     0,     0,    68,    69,    74,     0,   105,   106,
   107,    54,     0,     0,     0,     0,     0,     0,     7,     0,
     0,     0,     0,     0,    62,    64,     0,    56,    58,     0,
     0,     0,     0,     0,     0,     0,    23,    30,     0,    23,
    70,    71,    75,   104,    72,    73,     0,     0,     0,     0,
     0,    43,     0,    26,    32,    38,    35,    36,     0,     0,
     0,    82,    82,     0,    93,     0,     0,    82,    82,    50,
    65,    67,     0,    63,     0,     0,   108,   109,   110,   111,
   112,   113,   114,     0,    82,     0,     0,    82,    27,    28,
   101,   100,   102,   103,     0,     0,     0,     0,    26,     0,
    52,     0,    15,    84,    83,    16,     0,     0,    94,    95,
    96,     0,     0,    17,    18,     0,    51,    76,     0,   115,
   116,     0,    19,    44,    45,    26,    22,    84,     0,    33,
    34,    39,    40,    82,    41,     0,    53,    86,    85,     0,
     0,     0,    60,     0,     0,    31,    66,    77,     0,    82,
    86,    29,    21,    42,    91,     0,     0,     0,     0,    97,
     0,   117,    20,    89,    80,     0,    87,     0,     0,    59,
    61,    91,    90,    26,     0,    92,     0,    24,   101,    25,
    23,    78,    81,    88,    80,     0,    99,    79,    98 };
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
	"IPNY_MAPBLOCK",	270,
	"IPNY_RDR",	271,
	"IPNY_PORT",	272,
	"IPNY_PORTS",	273,
	"IPNY_AUTO",	274,
	"IPNY_RANGE",	275,
	"IPNY_MAP",	276,
	"IPNY_BIMAP",	277,
	"IPNY_FROM",	278,
	"IPNY_TO",	279,
	"IPNY_MASK",	280,
	"IPNY_PORTMAP",	281,
	"IPNY_ANY",	282,
	"IPNY_ROUNDROBIN",	283,
	"IPNY_FRAG",	284,
	"IPNY_AGE",	285,
	"IPNY_ICMPIDMAP",	286,
	"IPNY_PROXY",	287,
	"IPNY_TCP",	288,
	"IPNY_UDP",	289,
	"IPNY_TCPUDP",	290,
	"IPNY_STICKY",	291,
	"IPNY_MSSCLAMP",	292,
	"IPNY_TAG",	293,
	"IPNY_TLATE",	294,
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
	"assign : YY_STR assigning YY_STR ';'",
	"assigning : '='",
	"xx : /* empty */",
	"rule : map eol",
	"rule : mapblock eol",
	"rule : redir eol",
	"eol : /* empty */",
	"eol : ';'",
	"map : mapit ifnames addr IPNY_TLATE rhaddr proxy mapoptions",
	"map : mapit ifnames addr IPNY_TLATE rhaddr mapport mapoptions",
	"map : mapit ifnames mapfrom IPNY_TLATE rhaddr proxy mapoptions",
	"map : mapit ifnames mapfrom IPNY_TLATE rhaddr mapport mapoptions",
	"mapblock : mapblockit ifnames addr IPNY_TLATE addr ports mapoptions",
	"redir : rdrit ifnames addr dport IPNY_TLATE dip nport setproto rdroptions",
	"redir : rdrit ifnames rdrfrom IPNY_TLATE dip nport setproto rdroptions",
	"redir : rdrit ifnames addr IPNY_TLATE dip setproto rdroptions",
	"proxy : /* empty */",
	"proxy : IPNY_PROXY IPNY_PORT portspec YY_STR '/' proto",
	"proxy : IPNY_PROXY IPNY_PORT YY_STR YY_STR '/' proto",
	"setproto : /* empty */",
	"setproto : proto",
	"setproto : IPNY_TCPUDP",
	"setproto : IPNY_TCP '/' IPNY_UDP",
	"rhaddr : addr",
	"rhaddr : IPNY_RANGE ipv4 '-' ipv4",
	"dip : hostname",
	"dip : hostname '/' YY_NUMBER",
	"dip : hostname ',' hostname",
	"portspec : YY_NUMBER",
	"portspec : YY_STR",
	"dport : /* empty */",
	"dport : IPNY_PORT portspec",
	"dport : IPNY_PORT portspec '-' portspec",
	"dport : IPNY_PORT portspec ':' portspec",
	"nport : IPNY_PORT portspec",
	"nport : IPNY_PORT '=' portspec",
	"ports : /* empty */",
	"ports : IPNY_PORTS YY_NUMBER",
	"ports : IPNY_PORTS IPNY_AUTO",
	"mapit : IPNY_MAP",
	"mapit : IPNY_BIMAP",
	"rdrit : IPNY_RDR",
	"mapblockit : IPNY_MAPBLOCK",
	"mapfrom : from sobject IPNY_TO dobject",
	"mapfrom : from sobject '!' IPNY_TO dobject",
	"rdrfrom : from sobject IPNY_TO dobject",
	"rdrfrom : '!' from sobject IPNY_TO dobject",
	"from : IPNY_FROM",
	"ifnames : ifname",
	"ifnames : ifname ',' otherifname",
	"ifname : YY_STR",
	"otherifname : YY_STR",
	"mapport : IPNY_PORTMAP tcpudp portspec ':' portspec",
	"mapport : IPNY_PORTMAP tcpudp IPNY_AUTO",
	"mapport : IPNY_ICMPIDMAP YY_STR YY_NUMBER ':' YY_NUMBER",
	"sobject : saddr",
	"sobject : saddr IPNY_PORT portstuff",
	"saddr : addr",
	"dobject : daddr",
	"dobject : daddr IPNY_PORT portstuff",
	"daddr : addr",
	"addr : IPNY_ANY",
	"addr : nummask",
	"addr : hostname '/' ipv4",
	"addr : hostname '/' hexnumber",
	"addr : hostname IPNY_MASK ipv4",
	"addr : hostname IPNY_MASK hexnumber",
	"nummask : hostname",
	"nummask : hostname '/' YY_NUMBER",
	"portstuff : compare portspec",
	"portstuff : portspec range portspec",
	"mapoptions : rr frag age mssclamp nattag setproto",
	"rdroptions : rr frag age sticky mssclamp rdrproxy nattag",
	"nattag : /* empty */",
	"nattag : IPNY_TAG YY_STR",
	"rr : /* empty */",
	"rr : IPNY_ROUNDROBIN",
	"frag : /* empty */",
	"frag : IPNY_FRAG",
	"age : /* empty */",
	"age : IPNY_AGE YY_NUMBER",
	"age : IPNY_AGE YY_NUMBER '/' YY_NUMBER",
	"sticky : /* empty */",
	"sticky : IPNY_STICKY",
	"mssclamp : /* empty */",
	"mssclamp : IPNY_MSSCLAMP YY_NUMBER",
	"tcpudp : /* empty */",
	"tcpudp : IPNY_TCP",
	"tcpudp : IPNY_UDP",
	"tcpudp : IPNY_TCPUDP",
	"tcpudp : IPNY_TCP '/' IPNY_UDP",
	"rdrproxy : IPNY_PROXY YY_STR",
	"rdrproxy : proxy",
	"proto : YY_NUMBER",
	"proto : IPNY_TCP",
	"proto : IPNY_UDP",
	"proto : YY_STR",
	"hexnumber : YY_HEX",
	"hostname : YY_STR",
	"hostname : YY_NUMBER",
	"hostname : ipv4",
	"compare : '='",
	"compare : YY_CMP_EQ",
	"compare : YY_CMP_NE",
	"compare : YY_CMP_LT",
	"compare : YY_CMP_LE",
	"compare : YY_CMP_GT",
	"compare : YY_CMP_GE",
	"range : YY_RANGE_OUT",
	"range : YY_RANGE_IN",
	"ipv4 : YY_NUMBER '.' YY_NUMBER '.' YY_NUMBER '.' YY_NUMBER",
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
# line 115 "../ipnat_y.y"
{ while ((nat = nattop) != NULL) {
				nattop = nat->in_next;
				(*nataddfunc)(natfd, natioctlfunc, nat);
				free(nat);
			  }
			  resetlexer();
			} break;
case 7:
# line 125 "../ipnat_y.y"
{ set_variable(yypvt[-3].str, yypvt[-1].str);
					  resetlexer();
					  free(yypvt[-3].str);
					  free(yypvt[-1].str);
					} break;
case 8:
# line 133 "../ipnat_y.y"
{ yyvarnext = 1; } break;
case 9:
# line 136 "../ipnat_y.y"
{ newnatrule(); } break;
case 15:
# line 148 "../ipnat_y.y"
{ nat->in_v = 4;
				  nat->in_inip = yypvt[-4].ipp.a.s_addr;
				  nat->in_inmsk = yypvt[-4].ipp.m.s_addr;
				  nat->in_outip = yypvt[-2].ipp.a.s_addr;
				  nat->in_outmsk = yypvt[-2].ipp.m.s_addr;
				  if (nat->in_ifnames[1][0] == '\0')
					strncpy(nat->in_ifnames[1],
						nat->in_ifnames[0],
						sizeof(nat->in_ifnames[0]));
				  if ((nat->in_flags & IPN_TCPUDP) == 0)
					setnatproto(nat->in_p);
				  if (((nat->in_redir & NAT_MAPBLK) != 0) ||
				      ((nat->in_flags & IPN_AUTOPORTMAP) != 0))
					nat_setgroupmap(nat);
				} break;
case 16:
# line 164 "../ipnat_y.y"
{ nat->in_v = 4;
				  nat->in_inip = yypvt[-4].ipp.a.s_addr;
				  nat->in_inmsk = yypvt[-4].ipp.m.s_addr;
				  nat->in_outip = yypvt[-2].ipp.a.s_addr;
				  nat->in_outmsk = yypvt[-2].ipp.m.s_addr;
				  if (nat->in_ifnames[1][0] == '\0')
					strncpy(nat->in_ifnames[1],
						nat->in_ifnames[0],
						sizeof(nat->in_ifnames[0]));
				  if ((nat->in_flags & IPN_TCPUDPICMPQ) == 0)
					setnatproto(nat->in_p);
				  if (((nat->in_redir & NAT_MAPBLK) != 0) ||
				      ((nat->in_flags & IPN_AUTOPORTMAP) != 0))
					nat_setgroupmap(nat);
				} break;
case 17:
# line 180 "../ipnat_y.y"
{ nat->in_v = 4;
				  nat->in_outip = yypvt[-2].ipp.a.s_addr;
				  nat->in_outmsk = yypvt[-2].ipp.m.s_addr;
				  if (nat->in_ifnames[1][0] == '\0')
					strncpy(nat->in_ifnames[1],
						nat->in_ifnames[0],
						sizeof(nat->in_ifnames[0]));
				  if ((nat->in_flags & IPN_TCPUDP) == 0)
					setnatproto(nat->in_p);
				  if (((nat->in_redir & NAT_MAPBLK) != 0) ||
				      ((nat->in_flags & IPN_AUTOPORTMAP) != 0))
					nat_setgroupmap(nat);
				} break;
case 18:
# line 194 "../ipnat_y.y"
{ nat->in_v = 4;
				  nat->in_outip = yypvt[-2].ipp.a.s_addr;
				  nat->in_outmsk = yypvt[-2].ipp.m.s_addr;
				  if (nat->in_ifnames[1][0] == '\0')
					strncpy(nat->in_ifnames[1],
						nat->in_ifnames[0],
						sizeof(nat->in_ifnames[0]));
				  if ((nat->in_flags & IPN_TCPUDPICMPQ) == 0)
					setnatproto(nat->in_p);
				  if (((nat->in_redir & NAT_MAPBLK) != 0) ||
				      ((nat->in_flags & IPN_AUTOPORTMAP) != 0))
					nat_setgroupmap(nat);
				} break;
case 19:
# line 211 "../ipnat_y.y"
{ nat->in_v = 4;
				  nat->in_inip = yypvt[-4].ipp.a.s_addr;
				  nat->in_inmsk = yypvt[-4].ipp.m.s_addr;
				  nat->in_outip = yypvt[-2].ipp.a.s_addr;
				  nat->in_outmsk = yypvt[-2].ipp.m.s_addr;
				  if (nat->in_ifnames[1][0] == '\0')
					strncpy(nat->in_ifnames[1],
						nat->in_ifnames[0],
						sizeof(nat->in_ifnames[0]));
				  if ((nat->in_flags & IPN_TCPUDP) == 0)
					setnatproto(nat->in_p);
				  if (((nat->in_redir & NAT_MAPBLK) != 0) ||
				      ((nat->in_flags & IPN_AUTOPORTMAP) != 0))
					nat_setgroupmap(nat);
				} break;
case 20:
# line 229 "../ipnat_y.y"
{ nat->in_v = 4;
				  nat->in_outip = yypvt[-6].ipp.a.s_addr;
				  nat->in_outmsk = yypvt[-6].ipp.m.s_addr;
				  if (nat->in_ifnames[1][0] == '\0')
					strncpy(nat->in_ifnames[1],
						nat->in_ifnames[0],
						sizeof(nat->in_ifnames[0]));
				  if ((nat->in_p == 0) &&
				      ((nat->in_flags & IPN_TCPUDP) == 0) &&
				      (nat->in_pmin != 0 ||
				       nat->in_pmax != 0 ||
				       nat->in_pnext != 0))
						setnatproto(IPPROTO_TCP);
				} break;
case 21:
# line 244 "../ipnat_y.y"
{ nat->in_v = 4;
				  if ((nat->in_p == 0) &&
				      ((nat->in_flags & IPN_TCPUDP) == 0) &&
				      (nat->in_pmin != 0 ||
				       nat->in_pmax != 0 ||
				       nat->in_pnext != 0))
					setnatproto(IPPROTO_TCP);
				  if (nat->in_ifnames[1][0] == '\0')
					strncpy(nat->in_ifnames[1],
						nat->in_ifnames[0],
						sizeof(nat->in_ifnames[0]));
				} break;
case 22:
# line 257 "../ipnat_y.y"
{ nat->in_v = 4;
				  nat->in_outip = yypvt[-4].ipp.a.s_addr;
				  nat->in_outmsk = yypvt[-4].ipp.m.s_addr;
				  if (nat->in_ifnames[1][0] == '\0')
					strncpy(nat->in_ifnames[1],
						nat->in_ifnames[0],
						sizeof(nat->in_ifnames[0]));
				} break;
case 24:
# line 268 "../ipnat_y.y"
{ strncpy(nat->in_plabel, yypvt[-2].str, sizeof(nat->in_plabel));
			  if (nat->in_dcmp == 0) {
				nat->in_dport = htons(yypvt[-3].port);
			  } else if (yypvt[-3].port != nat->in_dport) {
				yyerror("proxy port numbers not consistant");
			  }
			  setnatproto(yypvt[-0].num);
			  free(yypvt[-2].str);
			} break;
case 25:
# line 278 "../ipnat_y.y"
{ int pnum;
			  strncpy(nat->in_plabel, yypvt[-2].str, sizeof(nat->in_plabel));
			  pnum = getportproto(yypvt[-3].str, yypvt[-0].num);
			  if (pnum == -1)
				yyerror("invalid port number");
			  nat->in_dport = pnum;
			  setnatproto(yypvt[-0].num);
			  free(yypvt[-3].str);
			  free(yypvt[-2].str);
			} break;
case 27:
# line 291 "../ipnat_y.y"
{ if (nat->in_p != 0 ||
					      nat->in_flags & IPN_TCPUDP)
						yyerror("protocol set twice");
					  setnatproto(yypvt[-0].num);
					} break;
case 28:
# line 296 "../ipnat_y.y"
{ if (nat->in_p != 0 ||
					      nat->in_flags & IPN_TCPUDP)
						yyerror("protocol set twice");
					  nat->in_flags |= IPN_TCPUDP;
					  nat->in_p = 0;
					} break;
case 29:
# line 302 "../ipnat_y.y"
{ if (nat->in_p != 0 ||
					      nat->in_flags & IPN_TCPUDP)
						yyerror("protocol set twice");
					  nat->in_flags |= IPN_TCPUDP;
					  nat->in_p = 0;
					} break;
case 30:
# line 310 "../ipnat_y.y"
{ yyval.ipp.a = yypvt[-0].ipp.a; yyval.ipp.m = yypvt[-0].ipp.m; } break;
case 31:
# line 312 "../ipnat_y.y"
{ yyval.ipp.a = yypvt[-2].ipa; yyval.ipp.m = yypvt[-0].ipa;
					  nat->in_flags |= IPN_IPRANGE; } break;
case 32:
# line 317 "../ipnat_y.y"
{ nat->in_inip = yypvt[-0].ipa.s_addr;
					  nat->in_inmsk = 0xffffffff; } break;
case 33:
# line 319 "../ipnat_y.y"
{ nat->in_inip = yypvt[-2].ipa.s_addr;
					  if (nat->in_inip != 0 ||
					      (yypvt[-0].num != 0 && yypvt[-0].num != 32))
						yyerror("Invalid mask for dip");
					  ntomask(4, yypvt[-0].num, &nat->in_inmsk); } break;
case 34:
# line 324 "../ipnat_y.y"
{ nat->in_flags |= IPN_SPLIT;
					  nat->in_inip = yypvt[-2].ipa.s_addr;
					  nat->in_inmsk = yypvt[-0].ipa.s_addr; } break;
case 35:
# line 330 "../ipnat_y.y"
{ if (yypvt[-0].num > 65535)	/* Unsigned */
						yyerror("invalid port number");
					  else
						yyval.port = yypvt[-0].num;
					} break;
case 36:
# line 335 "../ipnat_y.y"
{ if (getport(NULL, yypvt[-0].str, &(yyval.port)) == -1)
						yyerror("invalid port number");
					  yyval.port = ntohs(yyval.port);
					} break;
case 38:
# line 341 "../ipnat_y.y"
{ nat->in_pmin = htons(yypvt[-0].port);
						  nat->in_pmax = htons(yypvt[-0].port); } break;
case 39:
# line 343 "../ipnat_y.y"
{ nat->in_pmin = htons(yypvt[-2].port);
						  nat->in_pmax = htons(yypvt[-0].port); } break;
case 40:
# line 345 "../ipnat_y.y"
{ nat->in_pmin = htons(yypvt[-2].port);
						  nat->in_pmax = htons(yypvt[-0].port); } break;
case 41:
# line 349 "../ipnat_y.y"
{ nat->in_pnext = htons(yypvt[-0].port); } break;
case 42:
# line 350 "../ipnat_y.y"
{ nat->in_pnext = htons(yypvt[-0].port);
					  nat->in_flags |= IPN_FIXEDDPORT;
					} break;
case 44:
# line 355 "../ipnat_y.y"
{ nat->in_pmin = yypvt[-0].num; } break;
case 45:
# line 356 "../ipnat_y.y"
{ nat->in_flags |= IPN_AUTOPORTMAP; } break;
case 46:
# line 359 "../ipnat_y.y"
{ nat->in_redir = NAT_MAP; } break;
case 47:
# line 360 "../ipnat_y.y"
{ nat->in_redir = NAT_BIMAP; } break;
case 48:
# line 363 "../ipnat_y.y"
{ nat->in_redir = NAT_REDIRECT; } break;
case 49:
# line 367 "../ipnat_y.y"
{ nat->in_redir = NAT_MAPBLK; } break;
case 51:
# line 373 "../ipnat_y.y"
{ nat->in_flags |= IPN_NOTDST; } break;
case 53:
# line 379 "../ipnat_y.y"
{ nat->in_flags |= IPN_NOTSRC; } break;
case 54:
# line 382 "../ipnat_y.y"
{ nat->in_flags |= IPN_FILTER; } break;
case 57:
# line 390 "../ipnat_y.y"
{ strncpy(nat->in_ifnames[0], yypvt[-0].str,
					  sizeof(nat->in_ifnames[0]));
				  nat->in_ifnames[0][LIFNAMSIZ - 1] = '\0';
				  free(yypvt[-0].str);
				} break;
case 58:
# line 398 "../ipnat_y.y"
{ strncpy(nat->in_ifnames[1], yypvt[-0].str,
					  sizeof(nat->in_ifnames[1]));
				  nat->in_ifnames[1][LIFNAMSIZ - 1] = '\0';
				  free(yypvt[-0].str);
				} break;
case 59:
# line 407 "../ipnat_y.y"
{ nat->in_pmin = htons(yypvt[-2].port);
			  nat->in_pmax = htons(yypvt[-0].port);
			} break;
case 60:
# line 411 "../ipnat_y.y"
{ nat->in_flags |= IPN_AUTOPORTMAP;
			  nat->in_pmin = htons(1024);
			  nat->in_pmax = htons(65535);
			} break;
case 61:
# line 416 "../ipnat_y.y"
{ if (strcmp(yypvt[-3].str, "icmp") != 0) {
				yyerror("icmpidmap not followed by icmp");
			  }
			  free(yypvt[-3].str);
			  if (yypvt[-2].num < 0 || yypvt[-2].num > 65535)
				yyerror("invalid ICMP Id number");
			  if (yypvt[-0].num < 0 || yypvt[-0].num > 65535)
				yyerror("invalid ICMP Id number");
			  nat->in_flags = IPN_ICMPQUERY;
			  nat->in_pmin = htons(yypvt[-2].num);
			  nat->in_pmax = htons(yypvt[-0].num);
			} break;
case 63:
# line 432 "../ipnat_y.y"
{ nat->in_sport = yypvt[-0].pc.p1;
					  nat->in_stop = yypvt[-0].pc.p2;
					  nat->in_scmp = yypvt[-0].pc.pc; } break;
case 64:
# line 437 "../ipnat_y.y"
{ if (nat->in_redir == NAT_REDIRECT) {
						nat->in_srcip = yypvt[-0].ipp.a.s_addr;
						nat->in_srcmsk = yypvt[-0].ipp.m.s_addr;
					  } else {
						nat->in_inip = yypvt[-0].ipp.a.s_addr;
						nat->in_inmsk = yypvt[-0].ipp.m.s_addr;
					  }
					} break;
case 66:
# line 449 "../ipnat_y.y"
{ nat->in_dport = yypvt[-0].pc.p1;
					  nat->in_dtop = yypvt[-0].pc.p2;
					  nat->in_dcmp = yypvt[-0].pc.pc;
					  if (nat->in_redir == NAT_REDIRECT)
						nat->in_pmin = htons(yypvt[-0].pc.p1);
					} break;
case 67:
# line 457 "../ipnat_y.y"
{ if (nat->in_redir == NAT_REDIRECT) {
						nat->in_outip = yypvt[-0].ipp.a.s_addr;
						nat->in_outmsk = yypvt[-0].ipp.m.s_addr;
					  } else {
						nat->in_srcip = yypvt[-0].ipp.a.s_addr;
						nat->in_srcmsk = yypvt[-0].ipp.m.s_addr;
					  }
					} break;
case 68:
# line 467 "../ipnat_y.y"
{ yyval.ipp.a.s_addr = 0; yyval.ipp.m.s_addr = 0; } break;
case 69:
# line 468 "../ipnat_y.y"
{ yyval.ipp.a = yypvt[-0].ipp.a; yyval.ipp.m = yypvt[-0].ipp.m;
					  yyval.ipp.a.s_addr &= yyval.ipp.m.s_addr; } break;
case 70:
# line 470 "../ipnat_y.y"
{ yyval.ipp.a = yypvt[-2].ipa; yyval.ipp.m = yypvt[-0].ipa;
					  yyval.ipp.a.s_addr &= yyval.ipp.m.s_addr; } break;
case 71:
# line 472 "../ipnat_y.y"
{ yyval.ipp.a = yypvt[-2].ipa; yyval.ipp.m.s_addr = yypvt[-0].num;
					  yyval.ipp.a.s_addr &= yyval.ipp.m.s_addr; } break;
case 72:
# line 474 "../ipnat_y.y"
{ yyval.ipp.a = yypvt[-2].ipa; yyval.ipp.m = yypvt[-0].ipa;
					  yyval.ipp.a.s_addr &= yyval.ipp.m.s_addr; } break;
case 73:
# line 476 "../ipnat_y.y"
{ yyval.ipp.a = yypvt[-2].ipa; yyval.ipp.m.s_addr = yypvt[-0].num;
					  yyval.ipp.a.s_addr &= yyval.ipp.m.s_addr; } break;
case 74:
# line 481 "../ipnat_y.y"
{ yyval.ipp.a = yypvt[-0].ipa;
					  yyval.ipp.m.s_addr = 0xffffffff; } break;
case 75:
# line 483 "../ipnat_y.y"
{ yyval.ipp.a = yypvt[-2].ipa;
					  ntomask(4, yypvt[-0].num, &yyval.ipp.m.s_addr); } break;
case 76:
# line 488 "../ipnat_y.y"
{ yyval.pc.pc = yypvt[-1].num; yyval.pc.p1 = yypvt[-0].port; } break;
case 77:
# line 489 "../ipnat_y.y"
{ yyval.pc.pc = yypvt[-1].num; yyval.pc.p1 = yypvt[-2].port; yyval.pc.p2 = yypvt[-0].port; } break;
case 81:
# line 500 "../ipnat_y.y"
{ strncpy(nat->in_tag.ipt_tag, yypvt[-0].str,
						  sizeof(nat->in_tag.ipt_tag));
					} break;
case 83:
# line 503 "../ipnat_y.y"
{ nat->in_flags |= IPN_ROUNDR; } break;
case 85:
# line 506 "../ipnat_y.y"
{ nat->in_flags |= IPN_FRAG; } break;
case 87:
# line 509 "../ipnat_y.y"
{ nat->in_age[0] = yypvt[-0].num;
						  nat->in_age[1] = yypvt[-0].num; } break;
case 88:
# line 511 "../ipnat_y.y"
{ nat->in_age[0] = yypvt[-2].num;
						  nat->in_age[1] = yypvt[-0].num; } break;
case 90:
# line 515 "../ipnat_y.y"
{ if (!(nat->in_flags & IPN_ROUNDR) &&
					      !(nat->in_flags & IPN_SPLIT)) {
						fprintf(stderr,
		"'sticky' for use with round-robin/IP splitting only\n");
					  } else
						nat->in_flags |= IPN_STICKY;
					} break;
case 92:
# line 525 "../ipnat_y.y"
{ nat->in_mssclamp = yypvt[-0].num; } break;
case 94:
# line 528 "../ipnat_y.y"
{ setnatproto(IPPROTO_TCP); } break;
case 95:
# line 529 "../ipnat_y.y"
{ setnatproto(IPPROTO_UDP); } break;
case 96:
# line 530 "../ipnat_y.y"
{ nat->in_flags |= IPN_TCPUDP;
					  nat->in_p = 0;
					} break;
case 97:
# line 533 "../ipnat_y.y"
{ nat->in_flags |= IPN_TCPUDP;
					  nat->in_p = 0;
					} break;
case 98:
# line 540 "../ipnat_y.y"
{ strncpy(nat->in_plabel, yypvt[-0].str,
						  sizeof(nat->in_plabel));
					  nat->in_dport = nat->in_pnext;
					  nat->in_dport = htons(nat->in_dport);
					  free(yypvt[-0].str);
					} break;
case 99:
# line 546 "../ipnat_y.y"
{ if (nat->in_plabel[0] != '\0') {
						  nat->in_pmin = nat->in_dport;
						  nat->in_pmax = nat->in_pmin;
						  nat->in_pnext = nat->in_pmin;
					  }
					} break;
case 100:
# line 554 "../ipnat_y.y"
{ yyval.num = yypvt[-0].num; } break;
case 101:
# line 555 "../ipnat_y.y"
{ yyval.num = IPPROTO_TCP; } break;
case 102:
# line 556 "../ipnat_y.y"
{ yyval.num = IPPROTO_UDP; } break;
case 103:
# line 557 "../ipnat_y.y"
{ yyval.num = getproto(yypvt[-0].str); free(yypvt[-0].str); } break;
case 104:
# line 561 "../ipnat_y.y"
{ yyval.num = yypvt[-0].num; } break;
case 105:
# line 565 "../ipnat_y.y"
{ yyval.ipa.s_addr = lookuphost(yypvt[-0].str);
					  free(yypvt[-0].str);
					  if (yyval.ipa.s_addr == 0)
						yyerror("Unknown hostname");
					} break;
case 106:
# line 570 "../ipnat_y.y"
{ yyval.ipa.s_addr = htonl(yypvt[-0].num); } break;
case 107:
# line 571 "../ipnat_y.y"
{ yyval.ipa.s_addr = yypvt[-0].ipa.s_addr; } break;
case 108:
# line 575 "../ipnat_y.y"
{ yyval.num = FR_EQUAL; } break;
case 109:
# line 576 "../ipnat_y.y"
{ yyval.num = FR_EQUAL; } break;
case 110:
# line 577 "../ipnat_y.y"
{ yyval.num = FR_NEQUAL; } break;
case 111:
# line 578 "../ipnat_y.y"
{ yyval.num = FR_LESST; } break;
case 112:
# line 579 "../ipnat_y.y"
{ yyval.num = FR_LESSTE; } break;
case 113:
# line 580 "../ipnat_y.y"
{ yyval.num = FR_GREATERT; } break;
case 114:
# line 581 "../ipnat_y.y"
{ yyval.num = FR_GREATERTE; } break;
case 115:
# line 584 "../ipnat_y.y"
{ yyval.num = FR_OUTRANGE; } break;
case 116:
# line 585 "../ipnat_y.y"
{ yyval.num = FR_INRANGE; } break;
case 117:
# line 589 "../ipnat_y.y"
{ if (yypvt[-6].num > 255 || yypvt[-4].num > 255 || yypvt[-2].num > 255 || yypvt[-0].num > 255) {
			yyerror("Invalid octet string for IP address");
			return 0;
		  }
		  yyval.ipa.s_addr = (yypvt[-6].num << 24) | (yypvt[-4].num << 16) | (yypvt[-2].num << 8) | yypvt[-0].num;
		  yyval.ipa.s_addr = htonl(yyval.ipa.s_addr);
		} break;
# line	556 "/usr/share/lib/ccs/yaccpar"
	}
	goto yystack;		/* reset registers in driver code */
}

