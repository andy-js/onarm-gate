#ifndef	_SYMINFO_MSG_DOT_H
#define	_SYMINFO_MSG_DOT_H

#ifndef	__lint

typedef int	Msg;

#define	MSG_ORIG(x)	&__sgs_msg[x]

extern	const char *	_sgs_msg(Msg);

#define	MSG_INTL(x)	_sgs_msg(x)


#define	MSG_SYMINFO_FLG_DIRECT	6
#define	MSG_SYMINFO_FLG_DIRECT_SIZE	6

#define	MSG_SYMINFO_FLG_COPY	13
#define	MSG_SYMINFO_FLG_COPY_SIZE	4

#define	MSG_SYMINFO_FLG_LAZYLOAD	18
#define	MSG_SYMINFO_FLG_LAZYLOAD_SIZE	8

#define	MSG_SYMINFO_FLG_DIRECTBIND	27
#define	MSG_SYMINFO_FLG_DIRECTBIND_SIZE	10

#define	MSG_SYMINFO_FLG_NOEXTDIRECT	1
#define	MSG_SYMINFO_FLG_NOEXTDIRECT_SIZE	11

#define	MSG_GBL_ZERO	38
#define	MSG_GBL_ZERO_SIZE	1

static const char __sgs_msg[40] = { 
/*    0 */ 0x00,  0x4e,  0x4f,  0x45,  0x58,  0x54,  0x44,  0x49,  0x52,  0x45,
/*   10 */ 0x43,  0x54,  0x00,  0x43,  0x4f,  0x50,  0x59,  0x00,  0x4c,  0x41,
/*   20 */ 0x5a,  0x59,  0x4c,  0x4f,  0x41,  0x44,  0x00,  0x44,  0x49,  0x52,
/*   30 */ 0x45,  0x43,  0x54,  0x42,  0x49,  0x4e,  0x44,  0x00,  0x30,  0x00 };

#else	/* __lint */


typedef char *	Msg;

extern	const char *	_sgs_msg(Msg);

#define MSG_ORIG(x)	x
#define MSG_INTL(x)	x

#define	MSG_SYMINFO_FLG_DIRECT	"DIRECT"
#define	MSG_SYMINFO_FLG_DIRECT_SIZE	6

#define	MSG_SYMINFO_FLG_COPY	"COPY"
#define	MSG_SYMINFO_FLG_COPY_SIZE	4

#define	MSG_SYMINFO_FLG_LAZYLOAD	"LAZYLOAD"
#define	MSG_SYMINFO_FLG_LAZYLOAD_SIZE	8

#define	MSG_SYMINFO_FLG_DIRECTBIND	"DIRECTBIND"
#define	MSG_SYMINFO_FLG_DIRECTBIND_SIZE	10

#define	MSG_SYMINFO_FLG_NOEXTDIRECT	"NOEXTDIRECT"
#define	MSG_SYMINFO_FLG_NOEXTDIRECT_SIZE	11

#define	MSG_GBL_ZERO	"0"
#define	MSG_GBL_ZERO_SIZE	1

#endif	/* __lint */

#endif
