
# line 2 "../ippool_y.y"
/*
 * Copyright (C) 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/socket.h>
#if defined(BSD) && (BSD >= 199306)
# include <sys/cdefs.h>
#endif
#include <sys/ioctl.h>

#include <net/if.h>
#if __FreeBSD_version >= 300000
# include <net/if_var.h>
#endif
#include <netinet/in.h>

#include <arpa/inet.h>

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <ctype.h>
#include <unistd.h>

#include "ipf.h"
#include "netinet/ip_lookup.h"
#include "netinet/ip_pool.h"
#include "netinet/ip_htable.h"
#include "ippool_l.h"
#include "kmem.h"

#define	YYDEBUG	1

extern	int	yyparse __P((void));
extern	int	yydebug;
extern	FILE	*yyin;

static	iphtable_t	ipht;
static	iphtent_t	iphte;
static	ip_pool_t	iplo;
static	ioctlfunc_t	poolioctl = NULL;
static	char		poolname[FR_GROUPLEN];
static	int		set_ipv6_addr = 0;


# line 60 "../ippool_y.y"
typedef union
#ifdef __cplusplus
	YYSTYPE
#endif
	{
	char	*str;
	u_32_t	num;
	struct	in_addr	addr;
	struct	alist_s	*alist;
	union   i6addr	adrmsk[2];
	iphtent_t	*ipe;
	ip_pool_node_t	*ipp;
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
# define IPT_IPF 270
# define IPT_NAT 271
# define IPT_COUNT 272
# define IPT_AUTH 273
# define IPT_IN 274
# define IPT_OUT 275
# define IPT_TABLE 276
# define IPT_GROUPMAP 277
# define IPT_HASH 278
# define IPT_ROLE 279
# define IPT_TYPE 280
# define IPT_TREE 281
# define IPT_GROUP 282
# define IPT_SIZE 283
# define IPT_SEED 284
# define IPT_NUM 285
# define IPT_NAME 286

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

# line 399 "../ippool_y.y"

static	wordtab_t	yywords[] = {
	{ "auth",	IPT_AUTH },
	{ "count",	IPT_COUNT },
	{ "group",	IPT_GROUP },
	{ "group-map",	IPT_GROUPMAP },
	{ "hash",	IPT_HASH },
	{ "in",		IPT_IN },
	{ "ipf",	IPT_IPF },
	{ "name",	IPT_NAME },
	{ "nat",	IPT_NAT },
	{ "number",	IPT_NUM },
	{ "out",	IPT_OUT },
	{ "role",	IPT_ROLE },
	{ "seed",	IPT_SEED },
	{ "size",	IPT_SIZE },
	{ "table",	IPT_TABLE },
	{ "tree",	IPT_TREE },
	{ "type",	IPT_TYPE },
	{ NULL,		0 }
};


int ippool_parsefile(fd, filename, iocfunc)
int fd;
char *filename;
ioctlfunc_t iocfunc;
{
	FILE *fp = NULL;
	char *s;

	yylineNum = 1;
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

	while (ippool_parsesome(fd, fp, iocfunc) == 1)
		;
	if (fp != NULL)
		fclose(fp);
	return 0;
}


int ippool_parsesome(fd, fp, iocfunc)
int fd;
FILE *fp;
ioctlfunc_t iocfunc;
{
	char *s;
	int i;

	poolioctl = iocfunc;

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
static YYCONST yytabelem yyexca[] ={
-1, 1,
	0, -1,
	-2, 0,
	};
# define YYNPROD 67
# define YYLAST 256
static YYCONST yytabelem yyact[]={

    25,    26,    39,    42,    43,    42,    43,    43,    39,    48,
    22,    13,    47,     7,     6,    32,    33,    35,    34,    93,
    18,    19,   109,    78,    58,    68,    63,    70,    27,   121,
     8,     9,    72,   118,    71,   104,   102,    69,    74,    73,
    57,    82,    80,    52,   108,    90,    89,    83,    77,    79,
    67,    62,    81,    56,    51,    38,    55,    53,    45,    44,
    31,    23,    16,    84,    98,    29,    46,    41,    87,   120,
   114,    24,    88,    86,    28,   100,    12,    40,    85,    85,
    15,     3,    14,    11,     2,     5,    10,     1,   101,    66,
   110,    21,    36,    50,    65,    91,    30,    20,    17,     4,
    37,    64,     0,     0,     0,    61,     0,     0,    54,     0,
     0,    49,     0,     0,    75,     0,    76,     0,    92,    59,
    60,     0,     0,     0,     0,     0,    65,    96,    97,     0,
    95,    94,     0,    64,     0,    99,   107,   111,   103,   106,
     0,     0,   105,     0,     0,   112,   113,     0,     0,    92,
     0,     0,     0,   115,     0,     0,     0,     0,   117,     0,
   111,   116,   119,     0,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
    68,    68,    70,    70,    68,     0,    70,     0,     0,     0,
     0,     0,    69,    69,     0,     0,    69,     0,     0,     0,
     0,     0,     0,    68,     0,    70,     0,     0,     0,     0,
     0,     0,     0,     0,     0,    69 };
static YYCONST yytabelem yypact[]={

  -246,  -246,-10000000,-10000000,  -268,  -268,-10000000,     1,-10000000,  -254,
-10000000,-10000000,  -270,     0,  -285,  -231,-10000000,-10000000,-10000000,-10000000,
     6,     6,    -1,  -255,  -280,    -2,    -3,     7,-10000000,-10000000,
-10000000,  -269,-10000000,-10000000,-10000000,-10000000,     6,  -278,   -80,    -4,
  -277,-10000000,    -5,    -8,  -217,  -235,-10000000,  -285,  -285,-10000000,
   -80,   -33,-10000000,  -225,-10000000,  -218,  -219,-10000000,-10000000,   -80,
  -278,   -36,   -84,-10000000,    19,    29,    21,-10000000,    26,-10000000,
-10000000,-10000000,-10000000,-10000000,-10000000,   -14,   -80,   -84,-10000000,    19,
    20,-10000000,-10000000,   -33,-10000000,-10000000,  -274,  -221,  -222,   -84,
-10000000,    19,-10000000,  -232,   -37,-10000000,   -36,   -36,  -274,-10000000,
-10000000,-10000000,    26,-10000000,    24,-10000000,   -14,-10000000,   -84,-10000000,
    19,-10000000,-10000000,-10000000,  -224,-10000000,-10000000,   -37,    23,-10000000,
  -228,-10000000 };
static YYCONST yytabelem yypgo[]={

     0,    76,    99,    98,    97,    95,    46,    42,    92,    91,
    44,    90,    49,    51,    48,    89,    88,    50,    71,    75,
    87,    84,    81,    74,    85,    80,    54,    52,    55,    77,
    67,    47 };
static YYCONST yytabelem yyr1[]={

     0,    20,    20,    20,    20,    21,    21,    21,    21,    23,
    22,    25,     2,    24,     3,     3,     1,     1,     1,     1,
     4,     9,     8,     8,    18,    18,    18,    19,    19,    28,
    28,    28,    28,     6,     6,     6,     6,    14,    14,    14,
    14,    14,    13,    13,    13,    12,     5,     5,    10,    10,
    10,    11,     7,     7,    15,    15,    15,    15,    16,    16,
    26,    27,    31,    31,    29,    30,    17 };
static YYCONST yytabelem yyr2[]={

     0,     2,     2,     4,     4,     9,     9,    11,     2,     2,
     9,     3,     3,     5,     3,     3,     7,     7,     7,     7,
    15,    17,    11,     9,     7,     7,     1,     7,     7,     0,
     2,     2,     4,     3,     7,     5,     2,     3,     7,     7,
     5,     5,     3,     5,     7,     7,     3,     5,     3,     5,
     7,     3,     7,     3,     3,     3,     3,     3,     3,     3,
     3,     3,     3,     3,     7,     7,    15 };
static YYCONST yytabelem yychk[]={

-10000000,   -20,   -21,   -22,    -2,   -24,   260,   259,   276,   277,
   -21,   -22,    -1,   279,    -1,   -25,    61,    -3,   274,   275,
    -4,    -9,   280,    61,   -18,   285,   286,   259,   -23,    59,
   -23,    61,   270,   271,   273,   272,    -8,   -19,   -28,   282,
   -29,   -30,   283,   284,    61,    61,    59,   281,   278,   -23,
   -28,   -26,   123,    61,   -30,    61,    61,   257,   259,   -18,
   -18,   -26,   -13,    59,   -12,    -7,   -15,   -17,   257,   269,
   259,   259,   257,   257,   257,   -26,   -28,   -14,    59,   -12,
    -7,   -27,   125,   -31,    44,    59,    44,    47,    46,    -6,
    59,    -5,    -7,    33,   -26,   -27,   -31,   -31,    44,   -13,
   -19,   -16,   257,   -17,   257,   -27,   -31,    -7,   -10,    59,
   -11,    -7,   -14,   -14,    46,    -6,   -27,   -31,   257,   -10,
    46,   257 };
static YYCONST yytabelem yydef[]={

     0,    -2,     1,     2,     0,     0,     8,     0,    12,     0,
     3,     4,     0,     0,    26,     0,    11,    13,    14,    15,
     0,     0,     0,     0,    29,     0,     0,     0,     5,     9,
     6,     0,    16,    17,    18,    19,     0,    29,     0,     0,
    30,    31,     0,     0,     0,     0,    10,    26,    26,     7,
     0,     0,    60,     0,    32,     0,     0,    24,    25,     0,
    29,     0,     0,    42,     0,     0,    53,    54,    55,    56,
    57,    27,    28,    64,    65,     0,     0,     0,    37,     0,
     0,    23,    61,    43,    62,    63,     0,     0,     0,     0,
    33,    36,    46,     0,     0,    22,    40,    41,    62,    44,
    45,    52,    58,    59,     0,    20,    35,    47,     0,    48,
     0,    51,    38,    39,     0,    34,    21,    49,     0,    50,
     0,    66 };
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
	"IPT_IPF",	270,
	"IPT_NAT",	271,
	"IPT_COUNT",	272,
	"IPT_AUTH",	273,
	"IPT_IN",	274,
	"IPT_OUT",	275,
	"IPT_TABLE",	276,
	"IPT_GROUPMAP",	277,
	"IPT_HASH",	278,
	"IPT_ROLE",	279,
	"IPT_TYPE",	280,
	"IPT_TREE",	281,
	"IPT_GROUP",	282,
	"IPT_SIZE",	283,
	"IPT_SEED",	284,
	"IPT_NUM",	285,
	"IPT_NAME",	286,
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
	"line : table role ipftree eol",
	"line : table role ipfhash eol",
	"line : groupmap role number ipfgroup eol",
	"line : YY_COMMENT",
	"eol : ';'",
	"assign : YY_STR assigning YY_STR ';'",
	"assigning : '='",
	"table : IPT_TABLE",
	"groupmap : IPT_GROUPMAP inout",
	"inout : IPT_IN",
	"inout : IPT_OUT",
	"role : IPT_ROLE '=' IPT_IPF",
	"role : IPT_ROLE '=' IPT_NAT",
	"role : IPT_ROLE '=' IPT_AUTH",
	"role : IPT_ROLE '=' IPT_COUNT",
	"ipftree : IPT_TYPE '=' IPT_TREE number start addrlist end",
	"ipfhash : IPT_TYPE '=' IPT_HASH number hashopts start hashlist end",
	"ipfgroup : setgroup hashopts start grouplist end",
	"ipfgroup : hashopts start setgrouplist end",
	"number : IPT_NUM '=' YY_NUMBER",
	"number : IPT_NAME '=' YY_STR",
	"number : /* empty */",
	"setgroup : IPT_GROUP '=' YY_STR",
	"setgroup : IPT_GROUP '=' YY_NUMBER",
	"hashopts : /* empty */",
	"hashopts : size",
	"hashopts : seed",
	"hashopts : size seed",
	"addrlist : ';'",
	"addrlist : range next addrlist",
	"addrlist : range next",
	"addrlist : range",
	"grouplist : ';'",
	"grouplist : groupentry next grouplist",
	"grouplist : addrmask next grouplist",
	"grouplist : groupentry next",
	"grouplist : addrmask next",
	"setgrouplist : ';'",
	"setgrouplist : groupentry next",
	"setgrouplist : groupentry next setgrouplist",
	"groupentry : addrmask ',' setgroup",
	"range : addrmask",
	"range : '!' addrmask",
	"hashlist : ';'",
	"hashlist : hashentry next",
	"hashlist : hashentry next hashlist",
	"hashentry : addrmask",
	"addrmask : ipaddr '/' mask",
	"addrmask : ipaddr",
	"ipaddr : ipv4",
	"ipaddr : YY_NUMBER",
	"ipaddr : YY_IPV6",
	"ipaddr : YY_STR",
	"mask : YY_NUMBER",
	"mask : ipv4",
	"start : '{'",
	"end : '}'",
	"next : ','",
	"next : ';'",
	"size : IPT_SIZE '=' YY_NUMBER",
	"seed : IPT_SEED '=' YY_NUMBER",
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
# line 97 "../ippool_y.y"
{ iplo.ipo_unit = yypvt[-2].num;
					  iplo.ipo_list = yypvt[-1].ipp;
					  load_pool(&iplo, poolioctl);
					  resetlexer();
					} break;
case 6:
# line 102 "../ippool_y.y"
{ ipht.iph_unit = yypvt[-2].num;
					  ipht.iph_type = IPHASH_LOOKUP;
					  load_hash(&ipht, yypvt[-1].ipe, poolioctl);
					  resetlexer();
					} break;
case 7:
# line 108 "../ippool_y.y"
{ ipht.iph_unit = yypvt[-3].num;
					  strncpy(ipht.iph_name, yypvt[-2].str,
						  sizeof(ipht.iph_name));
					  ipht.iph_type = IPHASH_GROUPMAP;
					  load_hash(&ipht, yypvt[-1].ipe, poolioctl);
					  resetlexer();
					} break;
case 10:
# line 121 "../ippool_y.y"
{ set_variable(yypvt[-3].str, yypvt[-1].str);
					  resetlexer();
					  free(yypvt[-3].str);
					  free(yypvt[-1].str);
					} break;
case 11:
# line 129 "../ippool_y.y"
{ yyvarnext = 1; } break;
case 12:
# line 132 "../ippool_y.y"
{ bzero((char *)&ipht, sizeof(ipht));
				  bzero((char *)&iphte, sizeof(iphte));
				  bzero((char *)&iplo, sizeof(iplo));
				  *ipht.iph_name = '\0';
				  iplo.ipo_flags = IPHASH_ANON;
				  iplo.ipo_name[0] = '\0';
				} break;
case 13:
# line 142 "../ippool_y.y"
{ bzero((char *)&ipht, sizeof(ipht));
				  bzero((char *)&iphte, sizeof(iphte));
				  *ipht.iph_name = '\0';
				  ipht.iph_unit = IPHASH_GROUPMAP;
				  ipht.iph_flags = yypvt[-0].num;
				} break;
case 14:
# line 150 "../ippool_y.y"
{ yyval.num = FR_INQUE; } break;
case 15:
# line 151 "../ippool_y.y"
{ yyval.num = FR_OUTQUE; } break;
case 16:
# line 154 "../ippool_y.y"
{ yyval.num = IPL_LOGIPF; } break;
case 17:
# line 155 "../ippool_y.y"
{ yyval.num = IPL_LOGNAT; } break;
case 18:
# line 156 "../ippool_y.y"
{ yyval.num = IPL_LOGAUTH; } break;
case 19:
# line 157 "../ippool_y.y"
{ yyval.num = IPL_LOGCOUNT; } break;
case 20:
# line 162 "../ippool_y.y"
{ strncpy(iplo.ipo_name, yypvt[-3].str,
						  sizeof(iplo.ipo_name));
					  yyval.ipp = yypvt[-1].ipp;
					} break;
case 21:
# line 170 "../ippool_y.y"
{ strncpy(ipht.iph_name, yypvt[-4].str,
						  sizeof(ipht.iph_name));
					  yyval.ipe = yypvt[-1].ipe;
					} break;
case 22:
# line 178 "../ippool_y.y"
{ iphtent_t *e;
					  for (e = yypvt[-1].ipe; e != NULL;
					       e = e->ipe_next)
						if (e->ipe_group[0] == '\0')
							strncpy(e->ipe_group,
								yypvt[-4].str,
								FR_GROUPLEN);
					  yyval.ipe = yypvt[-1].ipe;
					} break;
case 23:
# line 187 "../ippool_y.y"
{ yyval.ipe = yypvt[-1].ipe; } break;
case 24:
# line 190 "../ippool_y.y"
{ snprintf(poolname, FR_GROUPLEN, "%u", yypvt[-0].num);
						  yyval.str = poolname;
						} break;
case 25:
# line 193 "../ippool_y.y"
{ yyval.str = yypvt[-0].str; } break;
case 26:
# line 194 "../ippool_y.y"
{ yyval.str = ""; } break;
case 27:
# line 198 "../ippool_y.y"
{ char tmp[FR_GROUPLEN+1];
					  strncpy(tmp, yypvt[-0].str, FR_GROUPLEN);
					  yyval.str = strdup(tmp);
					} break;
case 28:
# line 202 "../ippool_y.y"
{ char tmp[FR_GROUPLEN+1];
					  snprintf(tmp, FR_GROUPLEN, "%u", yypvt[-0].num);
					  yyval.str = strdup(tmp);
					} break;
case 33:
# line 215 "../ippool_y.y"
{ yyval.ipp = NULL; } break;
case 34:
# line 216 "../ippool_y.y"
{ yypvt[-2].ipp->ipn_next = yypvt[-0].ipp; yyval.ipp = yypvt[-2].ipp; } break;
case 35:
# line 217 "../ippool_y.y"
{ yyval.ipp = yypvt[-1].ipp; } break;
case 37:
# line 222 "../ippool_y.y"
{ yyval.ipe = NULL; } break;
case 38:
# line 223 "../ippool_y.y"
{ yyval.ipe = yypvt[-2].ipe; yypvt[-2].ipe->ipe_next = yypvt[-0].ipe; } break;
case 39:
# line 224 "../ippool_y.y"
{ yyval.ipe = calloc(1, sizeof(iphtent_t));
					  if (yyval.ipe == NULL)
						yyerror("sorry, out of memory");
					  if  (set_ipv6_addr)
					  	yyval.ipe->ipe_family = AF_INET6;
					  else
						yyval.ipe->ipe_family = AF_INET;
					  bcopy((char *)&(yypvt[-2].adrmsk[0]),
						(char *)&(yyval.ipe->ipe_addr),
						sizeof(yyval.ipe->ipe_addr));
					  bcopy((char *)&(yypvt[-2].adrmsk[1]),
						(char *)&(yyval.ipe->ipe_mask),
						sizeof(yyval.ipe->ipe_mask));
					  set_ipv6_addr = 0;
					  yyval.ipe->ipe_next = yypvt[-0].ipe;
					} break;
case 40:
# line 240 "../ippool_y.y"
{ yyval.ipe = yypvt[-1].ipe; } break;
case 41:
# line 241 "../ippool_y.y"
{ yyval.ipe = calloc(1, sizeof(iphtent_t));
					  if (yyval.ipe == NULL)
						yyerror("sorry, out of memory");
					  if  (set_ipv6_addr)
					  	yyval.ipe->ipe_family = AF_INET6;
					  else
						yyval.ipe->ipe_family = AF_INET;
					  bcopy((char *)&(yypvt[-1].adrmsk[0]),
						(char *)&(yyval.ipe->ipe_addr),
						sizeof(yyval.ipe->ipe_addr));
					  bcopy((char *)&(yypvt[-1].adrmsk[1]),
						(char *)&(yyval.ipe->ipe_mask),
						sizeof(yyval.ipe->ipe_mask));
					  set_ipv6_addr = 0;
					} break;
case 42:
# line 259 "../ippool_y.y"
{ yyval.ipe = NULL; } break;
case 43:
# line 260 "../ippool_y.y"
{ yyval.ipe = yypvt[-1].ipe; } break;
case 44:
# line 261 "../ippool_y.y"
{ yypvt[-2].ipe->ipe_next = yypvt[-0].ipe; yyval.ipe = yypvt[-2].ipe; } break;
case 45:
# line 265 "../ippool_y.y"
{ yyval.ipe = calloc(1, sizeof(iphtent_t));
					  if (yyval.ipe == NULL)
						yyerror("sorry, out of memory");
					  if  (set_ipv6_addr)
					  	yyval.ipe->ipe_family = AF_INET6;
					  else
						yyval.ipe->ipe_family = AF_INET;
					  bcopy((char *)&(yypvt[-2].adrmsk[0]),
						(char *)&(yyval.ipe->ipe_addr),
						sizeof(yyval.ipe->ipe_addr));
					  bcopy((char *)&(yypvt[-2].adrmsk[1]),
						(char *)&(yyval.ipe->ipe_mask),
						sizeof(yyval.ipe->ipe_mask));
					  set_ipv6_addr = 0;
					  strncpy(yyval.ipe->ipe_group, yypvt[-0].str,
						  FR_GROUPLEN);
					  free(yypvt[-0].str);
					} break;
case 46:
# line 285 "../ippool_y.y"
{ yyval.ipp = calloc(1, sizeof(*yyval.ipp));
			  if (yyval.ipp == NULL)
				yyerror("sorry, out of memory");
			  yyval.ipp->ipn_info = 0;
			  yyval.ipp->ipn_addr.adf_len = sizeof(yyval.ipp->ipn_addr);
			  yyval.ipp->ipn_mask.adf_len = sizeof(yyval.ipp->ipn_mask);
			  if (set_ipv6_addr) {
				  yyval.ipp->ipn_addr.adf_family = AF_INET6;
				  yyval.ipp->ipn_addr.adf_addr = yypvt[-0].adrmsk[0];
				  yyval.ipp->ipn_mask.adf_addr = yypvt[-0].adrmsk[1];

			  } else {
				  yyval.ipp->ipn_addr.adf_family = AF_INET;
				  yyval.ipp->ipn_addr.adf_addr.in4.s_addr = yypvt[-0].adrmsk[0].in4.s_addr;
				  yyval.ipp->ipn_mask.adf_addr.in4.s_addr = yypvt[-0].adrmsk[1].in4.s_addr;
			  }
			  set_ipv6_addr = 0;
			} break;
case 47:
# line 303 "../ippool_y.y"
{ yyval.ipp = calloc(1, sizeof(*yyval.ipp));
			  if (yyval.ipp == NULL)
				yyerror("sorry, out of memory");
			  yyval.ipp->ipn_info = 1;
			  yyval.ipp->ipn_addr.adf_len = sizeof(yyval.ipp->ipn_addr);
			  yyval.ipp->ipn_mask.adf_len = sizeof(yyval.ipp->ipn_mask);
			  if (set_ipv6_addr) {
				  yyval.ipp->ipn_addr.adf_family = AF_INET6;
				  yyval.ipp->ipn_addr.adf_addr = yypvt[-0].adrmsk[0];
				  yyval.ipp->ipn_mask.adf_addr = yypvt[-0].adrmsk[1];
			  } else {
				  yyval.ipp->ipn_addr.adf_family = AF_INET;
				  yyval.ipp->ipn_addr.adf_addr.in4.s_addr = yypvt[-0].adrmsk[0].in4.s_addr;
				  yyval.ipp->ipn_mask.adf_addr.in4.s_addr = yypvt[-0].adrmsk[1].in4.s_addr;
			  }
			  set_ipv6_addr = 0;
			} break;
case 48:
# line 322 "../ippool_y.y"
{ yyval.ipe = NULL; } break;
case 49:
# line 323 "../ippool_y.y"
{ yyval.ipe = yypvt[-1].ipe; } break;
case 50:
# line 324 "../ippool_y.y"
{ yypvt[-2].ipe->ipe_next = yypvt[-0].ipe; yyval.ipe = yypvt[-2].ipe; } break;
case 51:
# line 328 "../ippool_y.y"
{ yyval.ipe = calloc(1, sizeof(iphtent_t));
					  if (yyval.ipe == NULL)
						yyerror("sorry, out of memory");
					  if  (set_ipv6_addr)
					  	yyval.ipe->ipe_family = AF_INET6;
					  else
						yyval.ipe->ipe_family = AF_INET;
					  bcopy((char *)&(yypvt[-0].adrmsk[0]),
						(char *)&(yyval.ipe->ipe_addr),
						sizeof(yyval.ipe->ipe_addr));
					  bcopy((char *)&(yypvt[-0].adrmsk[1]),
						(char *)&(yyval.ipe->ipe_mask),
						sizeof(yyval.ipe->ipe_mask));
					} break;
case 52:
# line 345 "../ippool_y.y"
{ yyval.adrmsk[0] = yypvt[-2].ip6; yyval.adrmsk[1] = yypvt[-0].ip6;
				  yyexpectaddr = 0;
				} break;
case 53:
# line 348 "../ippool_y.y"
{ yyval.adrmsk[0] = yypvt[-0].ip6; 
				  yyexpectaddr = 0;
				  if (set_ipv6_addr) 
				  	fill6bits(128, (u_32_t *)yyval.adrmsk[1].in6.s6_addr);
				  else
				  	yyval.adrmsk[1].in4.s_addr = 0xffffffff;
				} break;
case 54:
# line 357 "../ippool_y.y"
{ yyval.ip6 = yypvt[-0].ip6; } break;
case 55:
# line 358 "../ippool_y.y"
{ yyval.ip6.in4.s_addr = htonl(yypvt[-0].num); } break;
case 56:
# line 359 "../ippool_y.y"
{ set_ipv6_addr = 1;
				  bcopy(&yypvt[-0].ip6, &yyval.ip6, sizeof(yyval.ip6));
				  yyexpectaddr = 0; } break;
case 57:
# line 362 "../ippool_y.y"
{ if (gethost(yypvt[-0].str, &yyval.ip6, 0) == -1)
					yyerror("Unknown hostname");
				} break;
case 58:
# line 367 "../ippool_y.y"
{ if (set_ipv6_addr)
					ntomask(6, yypvt[-0].num, (u_32_t *)yyval.ip6.in6.s6_addr);
				  else
				  	ntomask(4, yypvt[-0].num, (u_32_t *)&yyval.ip6.in4.s_addr); } break;
case 59:
# line 371 "../ippool_y.y"
{ yyval.ip6 = yypvt[-0].ip6; } break;
case 60:
# line 374 "../ippool_y.y"
{ yyexpectaddr = 1; } break;
case 61:
# line 377 "../ippool_y.y"
{ yyexpectaddr = 0; } break;
case 62:
# line 380 "../ippool_y.y"
{ yyexpectaddr = 1; } break;
case 63:
# line 381 "../ippool_y.y"
{ yyexpectaddr = 1; } break;
case 64:
# line 384 "../ippool_y.y"
{ ipht.iph_size = yypvt[-0].num; } break;
case 65:
# line 387 "../ippool_y.y"
{ ipht.iph_seed = yypvt[-0].num; } break;
case 66:
# line 391 "../ippool_y.y"
{ if (yypvt[-6].num > 255 || yypvt[-4].num > 255 || yypvt[-2].num > 255 || yypvt[-0].num > 255) {
			yyerror("Invalid octet string for IP address");
			return 0;
		  }
		  yyval.ip6.in4.s_addr = (yypvt[-6].num << 24) | (yypvt[-4].num << 16) | (yypvt[-2].num << 8) | yypvt[-0].num;
		  yyval.ip6.in4.s_addr = htonl(yyval.ip6.in4.s_addr);
		} break;
# line	556 "/usr/share/lib/ccs/yaccpar"
	}
	goto yystack;		/* reset registers in driver code */
}

