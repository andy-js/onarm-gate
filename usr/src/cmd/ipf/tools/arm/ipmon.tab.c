
# line 7 "../ipmon_y.y"
#include "ipf.h"
#include <syslog.h>
#undef	OPT_NAT
#undef	OPT_VERBOSE
#include "ipmon_l.h"
#include "ipmon.h"

#define	YYDEBUG	1

extern	void	yyerror __P((char *));
extern	int	yyparse __P((void));
extern	int	yylex __P((void));
extern	int	yydebug;
extern	FILE	*yyin;
extern	int	yylineNum;

typedef	struct	opt	{
	struct	opt	*o_next;
	int		o_line;
	int		o_type;
	int		o_num;
	char		*o_str;
	struct in_addr	o_ip;
} opt_t;

static	void	build_action __P((struct opt *));
static	opt_t	*new_opt __P((int));
static	void	free_action __P((ipmon_action_t *));

static	ipmon_action_t	*alist = NULL;

# line 39 "../ipmon_y.y"
typedef union
#ifdef __cplusplus
	YYSTYPE
#endif
	{
	char	*str;
	u_32_t	num;
	struct in_addr	addr;
	struct opt	*opt;
	union	i6addr	ip6;
} YYSTYPE;
# define YY_NUMBER 257
# define YY_HEX 258
# define YY_STR 259
# define YY_IPV6 260
# define YY_COMMENT 261
# define YY_CMP_EQ 262
# define YY_CMP_NE 263
# define YY_CMP_LE 264
# define YY_CMP_GE 265
# define YY_CMP_LT 266
# define YY_CMP_GT 267
# define YY_RANGE_OUT 268
# define YY_RANGE_IN 269
# define IPM_MATCH 270
# define IPM_BODY 271
# define IPM_COMMENT 272
# define IPM_DIRECTION 273
# define IPM_DSTIP 274
# define IPM_DSTPORT 275
# define IPM_EVERY 276
# define IPM_EXECUTE 277
# define IPM_GROUP 278
# define IPM_INTERFACE 279
# define IPM_IN 280
# define IPM_NO 281
# define IPM_OUT 282
# define IPM_PACKET 283
# define IPM_PACKETS 284
# define IPM_POOL 285
# define IPM_PROTOCOL 286
# define IPM_RESULT 287
# define IPM_RULE 288
# define IPM_SECOND 289
# define IPM_SECONDS 290
# define IPM_SRCIP 291
# define IPM_SRCPORT 292
# define IPM_LOGTAG 293
# define IPM_WITH 294
# define IPM_DO 295
# define IPM_SAVE 296
# define IPM_SYSLOG 297
# define IPM_NOTHING 298
# define IPM_RAW 299
# define IPM_TYPE 300
# define IPM_NAT 301
# define IPM_STATE 302
# define IPM_NATTAG 303
# define IPM_IPF 304

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

# line 245 "../ipmon_y.y"

static	struct	wordtab	yywords[] = {
	{ "body",	IPM_BODY },
	{ "direction",	IPM_DIRECTION },
	{ "do",		IPM_DO },
	{ "dstip",	IPM_DSTIP },
	{ "dstport",	IPM_DSTPORT },
	{ "every",	IPM_EVERY },
	{ "execute",	IPM_EXECUTE },
	{ "group",	IPM_GROUP },
	{ "in",		IPM_IN },
	{ "interface",	IPM_INTERFACE },
	{ "ipf",	IPM_IPF },
	{ "logtag",	IPM_LOGTAG },
	{ "match",	IPM_MATCH },
	{ "nat",	IPM_NAT },
	{ "nattag",	IPM_NATTAG },
	{ "no",		IPM_NO },
	{ "nothing",	IPM_NOTHING },
	{ "out",	IPM_OUT },
	{ "packet",	IPM_PACKET },
	{ "packets",	IPM_PACKETS },
	{ "protocol",	IPM_PROTOCOL },
	{ "result",	IPM_RESULT },
	{ "rule",	IPM_RULE },
	{ "save",	IPM_SAVE },
	{ "raw",	IPM_RAW },
	{ "second",	IPM_SECOND },
	{ "seconds",	IPM_SECONDS },
	{ "srcip",	IPM_SRCIP },
	{ "srcport",	IPM_SRCPORT },
	{ "state",	IPM_STATE },
	{ "syslog",	IPM_SYSLOG },
	{ "with",	IPM_WITH },
	{ NULL,		0 }
};

static int macflags[17][2] = {
	{ IPM_DIRECTION,	IPMAC_DIRECTION	},
	{ IPM_DSTIP,		IPMAC_DSTIP	},
	{ IPM_DSTPORT,		IPMAC_DSTPORT	},
	{ IPM_GROUP,		IPMAC_GROUP	},
	{ IPM_INTERFACE,	IPMAC_INTERFACE	},
	{ IPM_LOGTAG,		IPMAC_LOGTAG 	},
	{ IPM_NATTAG,		IPMAC_NATTAG 	},
	{ IPM_PACKET,		IPMAC_EVERY	},
	{ IPM_PROTOCOL,		IPMAC_PROTOCOL	},
	{ IPM_RESULT,		IPMAC_RESULT	},
	{ IPM_RULE,		IPMAC_RULE	},
	{ IPM_SECOND,		IPMAC_EVERY	},
	{ IPM_SRCIP,		IPMAC_SRCIP	},
	{ IPM_SRCPORT,		IPMAC_SRCPORT	},
	{ IPM_TYPE,		IPMAC_TYPE 	},
	{ IPM_WITH,		IPMAC_WITH 	},
	{ 0, 0 }
};

static opt_t *new_opt(type)
int type;
{
	opt_t *o;

	o = (opt_t *)malloc(sizeof(*o));
	if (o == NULL)
		yyerror("sorry, out of memory");
	o->o_type = type;
	o->o_line = yylineNum;
	o->o_num = 0;
	o->o_str = (char *)0;
	o->o_next = NULL;
	return o;
}

static void build_action(olist)
opt_t *olist;
{
	ipmon_action_t *a;
	opt_t *o;
	char c;
	int i;

	a = (ipmon_action_t *)calloc(1, sizeof(*a));
	if (a == NULL)
		return;
	while ((o = olist) != NULL) {
		/*
		 * Check to see if the same comparator is being used more than
		 * once per matching statement.
		 */
		for (i = 0; macflags[i][0]; i++)
			if (macflags[i][0] == o->o_type)
				break;
		if (macflags[i][1] & a->ac_mflag) {
			fprintf(stderr, "%s redfined on line %d\n",
				yykeytostr(o->o_type), yylineNum);
			if (o->o_str != NULL)
				free(o->o_str);
			olist = o->o_next;
			free(o);
			continue;
		}

		a->ac_mflag |= macflags[i][1];

		switch (o->o_type)
		{
		case IPM_DIRECTION :
			a->ac_direction = o->o_num;
			break;
		case IPM_DSTIP :
			a->ac_dip = o->o_ip.s_addr;
			a->ac_dmsk = htonl(0xffffffff << (32 - o->o_num));
			break;
		case IPM_DSTPORT :
			a->ac_dport = htons(o->o_num);
			break;
		case IPM_EXECUTE :
			a->ac_exec = o->o_str;
			c = *o->o_str;
			if (c== '"'|| c == '\'') {
				if (o->o_str[strlen(o->o_str) - 1] == c) {
					a->ac_run = strdup(o->o_str + 1);
					a->ac_run[strlen(a->ac_run) - 1] ='\0';
				} else
					a->ac_run = o->o_str;
			} else
				a->ac_run = o->o_str;
			o->o_str = NULL;
			break;
		case IPM_INTERFACE :
			a->ac_iface = o->o_str;
			o->o_str = NULL;
			break;
		case IPM_GROUP : 
			if (o->o_str != NULL)
				strncpy(a->ac_group, o->o_str, FR_GROUPLEN);
			else
				sprintf(a->ac_group, "%d", o->o_num);
			break;
		case IPM_LOGTAG :
			a->ac_logtag = o->o_num;
			break;
		case IPM_NATTAG :
			strncpy(a->ac_nattag, o->o_str, sizeof(a->ac_nattag));
			break;
		case IPM_PACKET :
			a->ac_packet = o->o_num;
			break;
		case IPM_PROTOCOL :
			a->ac_proto = o->o_num;
			break;
		case IPM_RULE :
			a->ac_rule = o->o_num;
			break;
		case IPM_RESULT :
			if (!strcasecmp(o->o_str, "pass"))
				a->ac_result = IPMR_PASS;
			else if (!strcasecmp(o->o_str, "block"))
				a->ac_result = IPMR_BLOCK;
			else if (!strcasecmp(o->o_str, "nomatch"))
				a->ac_result = IPMR_NOMATCH;
			else if (!strcasecmp(o->o_str, "log"))
				a->ac_result = IPMR_LOG;
			break;
		case IPM_SECOND :
			a->ac_second = o->o_num;
			break;
		case IPM_SRCIP :
			a->ac_sip = o->o_ip.s_addr;
			a->ac_smsk = htonl(0xffffffff << (32 - o->o_num));
			break;
		case IPM_SRCPORT :
			a->ac_sport = htons(o->o_num);
			break;
		case IPM_SAVE :
			if (a->ac_savefile != NULL) {
				fprintf(stderr, "%s redfined on line %d\n",
					yykeytostr(o->o_type), yylineNum);
				break;
			}
			a->ac_savefile = strdup(o->o_str);
			a->ac_savefp = fopen(o->o_str, "a");
			a->ac_dflag |= o->o_num & IPMDO_SAVERAW;
			break;
		case IPM_SYSLOG :
			if (a->ac_syslog != 0) {
				fprintf(stderr, "%s redfined on line %d\n",
					yykeytostr(o->o_type), yylineNum);
				break;
			}
			a->ac_syslog = 1;
			break;
		case IPM_TYPE :
			a->ac_type = o->o_num;
			break;
		case IPM_WITH :
			break;
		default :
			break;
		}

		olist = o->o_next;
		if (o->o_str != NULL)
			free(o->o_str);
		free(o);
	}
	a->ac_next = alist;
	alist = a;
}


int check_action(buf, log, opts, lvl)
char *buf, *log;
int opts, lvl;
{
	ipmon_action_t *a;
	struct timeval tv;
	ipflog_t *ipf;
	tcphdr_t *tcp;
	iplog_t *ipl;
	int matched;
	u_long t1;
	ip_t *ip;

	matched = 0;
	ipl = (iplog_t *)buf;
	ipf = (ipflog_t *)(ipl +1);
	ip = (ip_t *)(ipf + 1);
	tcp = (tcphdr_t *)((char *)ip + (IP_HL(ip) << 2));

	for (a = alist; a != NULL; a = a->ac_next) {
		if ((a->ac_mflag & IPMAC_DIRECTION) != 0) {
			if (a->ac_direction == IPM_IN) {
				if ((ipf->fl_flags & FR_INQUE) == 0)
					continue;
			} else if (a->ac_direction == IPM_OUT) {
				if ((ipf->fl_flags & FR_OUTQUE) == 0)
					continue;
			}
		}

		if ((a->ac_type != 0) && (a->ac_type != ipl->ipl_magic))
			continue;

		if ((a->ac_mflag & IPMAC_EVERY) != 0) {
			gettimeofday(&tv, NULL);
			t1 = tv.tv_sec - a->ac_lastsec;
			if (tv.tv_usec <= a->ac_lastusec)
				t1--;
			if (a->ac_second != 0) {
				if (t1 < a->ac_second)
					continue;
				a->ac_lastsec = tv.tv_sec;
				a->ac_lastusec = tv.tv_usec;
			}

			if (a->ac_packet != 0) {
				if (a->ac_pktcnt == 0)
					a->ac_pktcnt++;
				else if (a->ac_pktcnt == a->ac_packet) {
					a->ac_pktcnt = 0;
					continue;
				} else {
					a->ac_pktcnt++;
					continue;
				}
			}
		}

		if ((a->ac_mflag & IPMAC_DSTIP) != 0) {
			if ((ip->ip_dst.s_addr & a->ac_dmsk) != a->ac_dip)
				continue;
		}

		if ((a->ac_mflag & IPMAC_DSTPORT) != 0) {
			if (ip->ip_p != IPPROTO_UDP && ip->ip_p != IPPROTO_TCP)
				continue;
			if (tcp->th_dport != a->ac_dport)
				continue;
		}

		if ((a->ac_mflag & IPMAC_GROUP) != 0) {
			if (strncmp(a->ac_group, ipf->fl_group,
				    FR_GROUPLEN) != 0)
				continue;
		}

		if ((a->ac_mflag & IPMAC_INTERFACE) != 0) {
			if (strcmp(a->ac_iface, ipf->fl_ifname))
				continue;
		}

		if ((a->ac_mflag & IPMAC_PROTOCOL) != 0) {
			if (a->ac_proto != ip->ip_p)
				continue;
		}

		if ((a->ac_mflag & IPMAC_RESULT) != 0) {
			if ((ipf->fl_flags & FF_LOGNOMATCH) != 0) {
				if (a->ac_result != IPMR_NOMATCH)
					continue;
			} else if (FR_ISPASS(ipf->fl_flags)) {
				if (a->ac_result != IPMR_PASS)
					continue;
			} else if (FR_ISBLOCK(ipf->fl_flags)) {
				if (a->ac_result != IPMR_BLOCK)
					continue;
			} else {	/* Log only */
				if (a->ac_result != IPMR_LOG)
					continue;
			}
		}

		if ((a->ac_mflag & IPMAC_RULE) != 0) {
			if (a->ac_rule != ipf->fl_rule)
				continue;
		}

		if ((a->ac_mflag & IPMAC_SRCIP) != 0) {
			if ((ip->ip_src.s_addr & a->ac_smsk) != a->ac_sip)
				continue;
		}

		if ((a->ac_mflag & IPMAC_SRCPORT) != 0) {
			if (ip->ip_p != IPPROTO_UDP && ip->ip_p != IPPROTO_TCP)
				continue;
			if (tcp->th_sport != a->ac_sport)
				continue;
		}

		if ((a->ac_mflag & IPMAC_LOGTAG) != 0) {
			if (a->ac_logtag != ipf->fl_logtag)
				continue;
		}

		if ((a->ac_mflag & IPMAC_NATTAG) != 0) {
			if (strncmp(a->ac_nattag, ipf->fl_nattag.ipt_tag,
				    IPFTAG_LEN) != 0)
				continue;
		}

		matched = 1;

		/*
		 * It matched so now execute the command
		 */
		if (a->ac_syslog != 0) {
			syslog(lvl, "%s", log);
		}

		if (a->ac_savefp != NULL) {
			if (a->ac_dflag & IPMDO_SAVERAW)
				fwrite(ipl, 1, ipl->ipl_dsize, a->ac_savefp);
			else
				fputs(log, a->ac_savefp);
		}

		if (a->ac_exec != NULL) {
			switch (fork())
			{
			case 0 :
			{
				FILE *pi;

				pi = popen(a->ac_run, "w");
				if (pi != NULL) {
					fprintf(pi, "%s\n", log);
					if ((opts & OPT_HEXHDR) != 0) {
						dumphex(pi, 0, buf,
							sizeof(*ipl) +
							sizeof(*ipf));
					}
					if ((opts & OPT_HEXBODY) != 0) {
						dumphex(pi, 0, (char *)ip,
							ipf->fl_hlen +
							ipf->fl_plen);
					}
					pclose(pi);
				}
				exit(1);
			}
			case -1 :
				break;
			default :
				break;
			}
		}
	}

	return matched;
}


static void free_action(a)
ipmon_action_t *a;
{
	if (a->ac_savefile != NULL) {
		free(a->ac_savefile);
		a->ac_savefile = NULL;
	}
	if (a->ac_savefp != NULL) {
		fclose(a->ac_savefp);
		a->ac_savefp = NULL;
	}
	if (a->ac_exec != NULL) {
		free(a->ac_exec);
		if (a->ac_run == a->ac_exec)
			a->ac_run = NULL;
		a->ac_exec = NULL;
	}
	if (a->ac_run != NULL) {
		free(a->ac_run);
		a->ac_run = NULL;
	}
	if (a->ac_iface != NULL) {
		free(a->ac_iface);
		a->ac_iface = NULL;
	}
	a->ac_next = NULL;
	free(a);
}


int load_config(file)
char *file;
{
	ipmon_action_t *a;
	FILE *fp;
	char *s;

	s = getenv("YYDEBUG");
	if (s != NULL)
		yydebug = atoi(s);
	else
		yydebug = 0;

	while ((a = alist) != NULL) {
		alist = a->ac_next;
		free_action(a);
	}

	yylineNum = 1;

	(void) yysettab(yywords);

	fp = fopen(file, "r");
	if (!fp) {
		perror("load_config:fopen:");
		return -1;
	}
	yyin = fp;
	while (!feof(fp))
		yyparse();
	fclose(fp);
	return 0;
}
static YYCONST yytabelem yyexca[] ={
-1, 1,
	0, -1,
	-2, 0,
	};
# define YYNPROD 66
# define YYLAST 178
static YYCONST yytabelem yyact[]={

    29,    30,    31,    32,   111,    33,    34,    87,    88,    63,
    86,    50,    99,    35,    36,    37,    72,   115,    38,    39,
    40,    65,    71,    66,    81,   108,    82,    42,    84,    78,
    41,   100,   101,   102,     7,    75,     6,    51,    76,    73,
    77,    74,    69,    49,    70,     4,    43,     5,   120,   117,
   105,   104,   103,    83,    68,    79,   106,    44,    89,    10,
   109,    93,    61,    60,    59,    58,    57,    56,    55,    54,
    53,    52,    48,    47,    46,    12,   113,    62,    67,    92,
    90,   119,   112,    91,    13,   116,   107,    45,     3,     2,
     9,     8,    11,     1,    85,   110,    98,    97,    96,    94,
    28,    27,    14,    26,    25,    24,    23,    22,    21,    20,
    19,    95,    18,    17,    16,    15,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
    64,     0,     0,     0,     0,     0,    80,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,     0,   114,
     0,     0,     0,     0,     0,     0,     0,   118 };
static YYCONST yytabelem yypact[]={

  -225,  -225,-10000000,-10000000,   -64,-10000000,-10000000,    14,-10000000,-10000000,
  -273,  -213,-10000000,   -68,    43,-10000000,-10000000,-10000000,-10000000,-10000000,
-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,    13,
    12,    11,  -246,    10,     9,     8,     7,     6,     5,     4,
     3,     2,     1,    18,  -286,  -273,  -259,  -203,  -215,-10000000,
  -268,-10000000,  -218,  -224,  -219,  -230,  -202,  -203,  -233,  -204,
  -231,  -294,-10000000,   -65,-10000000,-10000000,-10000000,    33,    37,-10000000,
-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,
    32,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,  -265,
  -205,  -206,  -207,   -69,    42,-10000000,-10000000,-10000000,-10000000,  -234,
  -295,-10000000,-10000000,-10000000,    36,-10000000,    17,  -265,-10000000,  -242,
    41,-10000000,  -208,-10000000,-10000000,-10000000,  -295,    35,-10000000,  -209,
-10000000 };
static YYCONST yytabelem yypgo[]={

     0,    78,   115,   114,   113,   112,   111,   110,   109,   108,
   107,   106,   105,   104,   103,    84,   102,   101,   100,    99,
    61,    98,    97,    96,    60,    95,    94,    93,    89,    88,
    92 };
static YYCONST yytabelem yyr1[]={

     0,    27,    27,    27,    27,    28,    28,    28,    29,    30,
    15,    15,    16,    16,    16,    16,    16,    16,    16,    16,
    16,    16,    16,    16,    16,    16,    20,    20,    19,    19,
    19,    19,     2,     2,     3,     4,     4,     5,     5,     5,
     5,     7,     7,     8,    14,    17,     9,     9,    10,    11,
    12,    13,    13,    18,    26,    26,    26,     6,    21,    24,
    24,    24,    25,    22,    23,     1 };
static YYCONST yytabelem yyr2[]={

     0,     2,     2,     4,     4,    19,     2,     2,     9,     3,
     3,     7,     3,     3,     3,     3,     3,     3,     3,     3,
     3,     3,     3,     3,     3,     3,     3,     7,     3,     3,
     3,     3,     7,     7,    11,     7,     7,     5,     7,     5,
     7,     7,     7,     7,     7,     7,     7,     7,     7,     7,
    11,     7,     7,     7,     3,     3,     3,     5,     7,     1,
     3,     7,     3,     3,     3,    15 };
static YYCONST yytabelem yychk[]={

-10000000,   -27,   -28,   -29,   270,   272,   261,   259,   -28,   -29,
   123,   -30,    61,   -15,   -16,    -2,    -3,    -4,    -5,    -7,
    -8,    -9,   -10,   -11,   -12,   -13,   -14,   -17,   -18,   273,
   274,   275,   276,   278,   279,   286,   287,   288,   291,   292,
   293,   303,   300,   259,   125,    44,    61,    61,    61,   289,
   257,   283,    61,    61,    61,    61,    61,    61,    61,    61,
    61,    61,    59,   295,   -15,   280,   282,    -1,   257,   257,
   259,   290,   284,   257,   259,   259,   257,   259,   259,   257,
    -1,   257,   259,   257,   259,   -26,   304,   301,   302,   123,
    47,    46,    47,   -20,   -19,    -6,   -21,   -22,   -23,   277,
   296,   297,   298,   257,   257,   257,   125,    44,   259,   -24,
   -25,   299,    46,    59,   -20,   259,    44,   257,   -24,    46,
   257 };
static YYCONST yytabelem yydef[]={

     0,    -2,     1,     2,     0,     6,     7,     0,     3,     4,
     0,     0,     9,     0,    10,    12,    13,    14,    15,    16,
    17,    18,    19,    20,    21,    22,    23,    24,    25,     0,
     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,     0,    37,
     0,    39,     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,     8,     0,    11,    32,    33,     0,     0,    35,
    36,    38,    40,    41,    42,    43,    46,    47,    48,    49,
     0,    51,    52,    44,    45,    53,    54,    55,    56,     0,
     0,     0,     0,     0,    26,    28,    29,    30,    31,     0,
    59,    63,    64,    34,     0,    50,     0,     0,    57,     0,
    60,    62,     0,     5,    27,    58,    59,     0,    61,     0,
    65 };
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
	"YY_IPV6",	260,
	"YY_COMMENT",	261,
	"YY_CMP_EQ",	262,
	"YY_CMP_NE",	263,
	"YY_CMP_LE",	264,
	"YY_CMP_GE",	265,
	"YY_CMP_LT",	266,
	"YY_CMP_GT",	267,
	"YY_RANGE_OUT",	268,
	"YY_RANGE_IN",	269,
	"IPM_MATCH",	270,
	"IPM_BODY",	271,
	"IPM_COMMENT",	272,
	"IPM_DIRECTION",	273,
	"IPM_DSTIP",	274,
	"IPM_DSTPORT",	275,
	"IPM_EVERY",	276,
	"IPM_EXECUTE",	277,
	"IPM_GROUP",	278,
	"IPM_INTERFACE",	279,
	"IPM_IN",	280,
	"IPM_NO",	281,
	"IPM_OUT",	282,
	"IPM_PACKET",	283,
	"IPM_PACKETS",	284,
	"IPM_POOL",	285,
	"IPM_PROTOCOL",	286,
	"IPM_RESULT",	287,
	"IPM_RULE",	288,
	"IPM_SECOND",	289,
	"IPM_SECONDS",	290,
	"IPM_SRCIP",	291,
	"IPM_SRCPORT",	292,
	"IPM_LOGTAG",	293,
	"IPM_WITH",	294,
	"IPM_DO",	295,
	"IPM_SAVE",	296,
	"IPM_SYSLOG",	297,
	"IPM_NOTHING",	298,
	"IPM_RAW",	299,
	"IPM_TYPE",	300,
	"IPM_NAT",	301,
	"IPM_STATE",	302,
	"IPM_NATTAG",	303,
	"IPM_IPF",	304,
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
	"line : IPM_MATCH '{' matching '}' IPM_DO '{' doing '}' ';'",
	"line : IPM_COMMENT",
	"line : YY_COMMENT",
	"assign : YY_STR assigning YY_STR ';'",
	"assigning : '='",
	"matching : matchopt",
	"matching : matchopt ',' matching",
	"matchopt : direction",
	"matchopt : dstip",
	"matchopt : dstport",
	"matchopt : every",
	"matchopt : group",
	"matchopt : interface",
	"matchopt : protocol",
	"matchopt : result",
	"matchopt : rule",
	"matchopt : srcip",
	"matchopt : srcport",
	"matchopt : logtag",
	"matchopt : nattag",
	"matchopt : type",
	"doing : doopt",
	"doing : doopt ',' doing",
	"doopt : execute",
	"doopt : save",
	"doopt : syslog",
	"doopt : nothing",
	"direction : IPM_DIRECTION '=' IPM_IN",
	"direction : IPM_DIRECTION '=' IPM_OUT",
	"dstip : IPM_DSTIP '=' ipv4 '/' YY_NUMBER",
	"dstport : IPM_DSTPORT '=' YY_NUMBER",
	"dstport : IPM_DSTPORT '=' YY_STR",
	"every : IPM_EVERY IPM_SECOND",
	"every : IPM_EVERY YY_NUMBER IPM_SECONDS",
	"every : IPM_EVERY IPM_PACKET",
	"every : IPM_EVERY YY_NUMBER IPM_PACKETS",
	"group : IPM_GROUP '=' YY_NUMBER",
	"group : IPM_GROUP '=' YY_STR",
	"interface : IPM_INTERFACE '=' YY_STR",
	"logtag : IPM_LOGTAG '=' YY_NUMBER",
	"nattag : IPM_NATTAG '=' YY_STR",
	"protocol : IPM_PROTOCOL '=' YY_NUMBER",
	"protocol : IPM_PROTOCOL '=' YY_STR",
	"result : IPM_RESULT '=' YY_STR",
	"rule : IPM_RULE '=' YY_NUMBER",
	"srcip : IPM_SRCIP '=' ipv4 '/' YY_NUMBER",
	"srcport : IPM_SRCPORT '=' YY_NUMBER",
	"srcport : IPM_SRCPORT '=' YY_STR",
	"type : IPM_TYPE '=' typeopt",
	"typeopt : IPM_IPF",
	"typeopt : IPM_NAT",
	"typeopt : IPM_STATE",
	"execute : IPM_EXECUTE YY_STR",
	"save : IPM_SAVE saveopts YY_STR",
	"saveopts : /* empty */",
	"saveopts : saveopt",
	"saveopts : saveopt ',' saveopts",
	"saveopt : IPM_RAW",
	"syslog : IPM_SYSLOG",
	"nothing : IPM_NOTHING",
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
# line 74 "../ipmon_y.y"
{ build_action(yypvt[-6].opt); resetlexer(); } break;
case 8:
# line 79 "../ipmon_y.y"
{ set_variable(yypvt[-3].str, yypvt[-1].str);
						  resetlexer();
						  free(yypvt[-3].str);
						  free(yypvt[-1].str);
						} break;
case 9:
# line 87 "../ipmon_y.y"
{ yyvarnext = 1; } break;
case 10:
# line 91 "../ipmon_y.y"
{ yyval.opt = yypvt[-0].opt; } break;
case 11:
# line 92 "../ipmon_y.y"
{ yypvt[-2].opt->o_next = yypvt[-0].opt; yyval.opt = yypvt[-2].opt; } break;
case 12:
# line 96 "../ipmon_y.y"
{ yyval.opt = yypvt[-0].opt; } break;
case 13:
# line 97 "../ipmon_y.y"
{ yyval.opt = yypvt[-0].opt; } break;
case 14:
# line 98 "../ipmon_y.y"
{ yyval.opt = yypvt[-0].opt; } break;
case 15:
# line 99 "../ipmon_y.y"
{ yyval.opt = yypvt[-0].opt; } break;
case 16:
# line 100 "../ipmon_y.y"
{ yyval.opt = yypvt[-0].opt; } break;
case 17:
# line 101 "../ipmon_y.y"
{ yyval.opt = yypvt[-0].opt; } break;
case 18:
# line 102 "../ipmon_y.y"
{ yyval.opt = yypvt[-0].opt; } break;
case 19:
# line 103 "../ipmon_y.y"
{ yyval.opt = yypvt[-0].opt; } break;
case 20:
# line 104 "../ipmon_y.y"
{ yyval.opt = yypvt[-0].opt; } break;
case 21:
# line 105 "../ipmon_y.y"
{ yyval.opt = yypvt[-0].opt; } break;
case 22:
# line 106 "../ipmon_y.y"
{ yyval.opt = yypvt[-0].opt; } break;
case 23:
# line 107 "../ipmon_y.y"
{ yyval.opt = yypvt[-0].opt; } break;
case 24:
# line 108 "../ipmon_y.y"
{ yyval.opt = yypvt[-0].opt; } break;
case 25:
# line 109 "../ipmon_y.y"
{ yyval.opt = yypvt[-0].opt; } break;
case 26:
# line 113 "../ipmon_y.y"
{ yyval.opt = yypvt[-0].opt; } break;
case 27:
# line 114 "../ipmon_y.y"
{ yypvt[-2].opt->o_next = yypvt[-0].opt; yyval.opt = yypvt[-2].opt; } break;
case 28:
# line 118 "../ipmon_y.y"
{ yyval.opt = yypvt[-0].opt; } break;
case 29:
# line 119 "../ipmon_y.y"
{ yyval.opt = yypvt[-0].opt; } break;
case 30:
# line 120 "../ipmon_y.y"
{ yyval.opt = yypvt[-0].opt; } break;
case 31:
# line 121 "../ipmon_y.y"
{ yyval.opt = yypvt[-0].opt; } break;
case 32:
# line 125 "../ipmon_y.y"
{ yyval.opt = new_opt(IPM_DIRECTION);
						  yyval.opt->o_num = IPM_IN; } break;
case 33:
# line 127 "../ipmon_y.y"
{ yyval.opt = new_opt(IPM_DIRECTION);
						  yyval.opt->o_num = IPM_OUT; } break;
case 34:
# line 131 "../ipmon_y.y"
{ yyval.opt = new_opt(IPM_DSTIP);
						  yyval.opt->o_ip = yypvt[-2].addr;
						  yyval.opt->o_num = yypvt[-0].num; } break;
case 35:
# line 137 "../ipmon_y.y"
{ yyval.opt = new_opt(IPM_DSTPORT);
						  yyval.opt->o_num = yypvt[-0].num; } break;
case 36:
# line 139 "../ipmon_y.y"
{ yyval.opt = new_opt(IPM_DSTPORT);
						  yyval.opt->o_str = yypvt[-0].str; } break;
case 37:
# line 143 "../ipmon_y.y"
{ yyval.opt = new_opt(IPM_SECOND);
						  yyval.opt->o_num = 1; } break;
case 38:
# line 145 "../ipmon_y.y"
{ yyval.opt = new_opt(IPM_SECOND);
						  yyval.opt->o_num = yypvt[-1].num; } break;
case 39:
# line 147 "../ipmon_y.y"
{ yyval.opt = new_opt(IPM_PACKET);
						  yyval.opt->o_num = 1; } break;
case 40:
# line 149 "../ipmon_y.y"
{ yyval.opt = new_opt(IPM_PACKET);
						  yyval.opt->o_num = yypvt[-1].num; } break;
case 41:
# line 153 "../ipmon_y.y"
{ yyval.opt = new_opt(IPM_GROUP);
						  yyval.opt->o_num = yypvt[-0].num; } break;
case 42:
# line 155 "../ipmon_y.y"
{ yyval.opt = new_opt(IPM_GROUP);
						  yyval.opt->o_str = yypvt[-0].str; } break;
case 43:
# line 160 "../ipmon_y.y"
{ yyval.opt = new_opt(IPM_INTERFACE);
						  yyval.opt->o_str = yypvt[-0].str; } break;
case 44:
# line 164 "../ipmon_y.y"
{ yyval.opt = new_opt(IPM_LOGTAG);
						  yyval.opt->o_num = yypvt[-0].num; } break;
case 45:
# line 168 "../ipmon_y.y"
{ yyval.opt = new_opt(IPM_NATTAG);
						  yyval.opt->o_str = yypvt[-0].str; } break;
case 46:
# line 173 "../ipmon_y.y"
{ yyval.opt = new_opt(IPM_PROTOCOL);
						  yyval.opt->o_num = yypvt[-0].num; } break;
case 47:
# line 175 "../ipmon_y.y"
{ yyval.opt = new_opt(IPM_PROTOCOL);
						  yyval.opt->o_num = getproto(yypvt[-0].str);
						  free(yypvt[-0].str);
						} break;
case 48:
# line 181 "../ipmon_y.y"
{ yyval.opt = new_opt(IPM_RESULT);
						  yyval.opt->o_str = yypvt[-0].str; } break;
case 49:
# line 185 "../ipmon_y.y"
{ yyval.opt = new_opt(IPM_RULE);
						  yyval.opt->o_num = YY_NUMBER; } break;
case 50:
# line 189 "../ipmon_y.y"
{ yyval.opt = new_opt(IPM_SRCIP);
						  yyval.opt->o_ip = yypvt[-2].addr;
						  yyval.opt->o_num = yypvt[-0].num; } break;
case 51:
# line 195 "../ipmon_y.y"
{ yyval.opt = new_opt(IPM_SRCPORT);
						  yyval.opt->o_num = yypvt[-0].num; } break;
case 52:
# line 197 "../ipmon_y.y"
{ yyval.opt = new_opt(IPM_SRCPORT);
						  yyval.opt->o_str = yypvt[-0].str; } break;
case 53:
# line 201 "../ipmon_y.y"
{ yyval.opt = new_opt(IPM_TYPE);
						  yyval.opt->o_num = yypvt[-0].num; } break;
case 54:
# line 206 "../ipmon_y.y"
{ yyval.num = IPL_MAGIC; } break;
case 55:
# line 207 "../ipmon_y.y"
{ yyval.num = IPL_MAGIC_NAT; } break;
case 56:
# line 208 "../ipmon_y.y"
{ yyval.num = IPL_MAGIC_STATE; } break;
case 57:
# line 212 "../ipmon_y.y"
{ yyval.opt = new_opt(IPM_EXECUTE);
						  yyval.opt->o_str = yypvt[-0].str; } break;
case 58:
# line 216 "../ipmon_y.y"
{ yyval.opt = new_opt(IPM_SAVE);
						  yyval.opt->o_num = yypvt[-1].num;
						  yyval.opt->o_str = yypvt[-0].str; } break;
case 59:
# line 221 "../ipmon_y.y"
{ yyval.num = 0; } break;
case 60:
# line 222 "../ipmon_y.y"
{ yyval.num = yypvt[-0].num; } break;
case 61:
# line 223 "../ipmon_y.y"
{ yyval.num = yypvt[-2].num | yypvt[-0].num; } break;
case 62:
# line 227 "../ipmon_y.y"
{ yyval.num = IPMDO_SAVERAW; } break;
case 63:
# line 230 "../ipmon_y.y"
{ yyval.opt = new_opt(IPM_SYSLOG); } break;
case 64:
# line 234 "../ipmon_y.y"
{ yyval.opt = 0; } break;
case 65:
# line 238 "../ipmon_y.y"
{ if (yypvt[-6].num > 255 || yypvt[-4].num > 255 || yypvt[-2].num > 255 || yypvt[-0].num > 255) {
			yyerror("Invalid octet string for IP address");
			return 0;
		  }
		  yyval.addr.s_addr = (yypvt[-6].num << 24) | (yypvt[-4].num << 16) | (yypvt[-2].num << 8) | yypvt[-0].num;
		  yyval.addr.s_addr = htonl(yyval.addr.s_addr);
		} break;
# line	556 "/usr/share/lib/ccs/yaccpar"
	}
	goto yystack;		/* reset registers in driver code */
}

