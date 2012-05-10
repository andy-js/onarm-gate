
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
extern YYSTYPE yylval;
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
