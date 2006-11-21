/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2001 Atsushi Onoe
 * Copyright (c) 2002-2005 Sam Leffler, Errno Consulting
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _SYS_NET80211_H
#define	_SYS_NET80211_H

#include <sys/mac.h>
#include <sys/ethernet.h>
#include <sys/net80211_proto.h>
#include <sys/net80211_crypto.h>

/*
 * IEEE802.11 kernel support module
 */

#ifdef	__cplusplus
extern "C" {
#endif

/* ic_caps */
#define	IEEE80211_C_WEP		0x00000001	/* CAPABILITY: WEP available */
#define	IEEE80211_C_TKIP	0x00000002	/* CAPABILITY: TKIP available */
#define	IEEE80211_C_AES		0x00000004	/* CAPABILITY: AES OCB avail */
#define	IEEE80211_C_AES_CCM	0x00000008	/* CAPABILITY: AES CCM avail */
#define	IEEE80211_C_CKIP	0x00000010	/* CAPABILITY: CKIP available */
#define	IEEE80211_C_FF		0x00000040	/* CAPABILITY: ATH FF avail */
#define	IEEE80211_C_TURBOP	0x00000080
				/* CAPABILITY: ATH Turbo available */
#define	IEEE80211_C_IBSS	0x00000100	/* CAPABILITY: IBSS available */
#define	IEEE80211_C_PMGT	0x00000200	/* CAPABILITY: Power mgmt */
#define	IEEE80211_C_HOSTAP	0x00000400	/* CAPABILITY: HOSTAP avail */
#define	IEEE80211_C_AHDEMO	0x00000800	/* CAPABILITY: Old Adhoc Demo */
#define	IEEE80211_C_SWRETRY	0x00001000	/* CAPABILITY: sw tx retry */
#define	IEEE80211_C_TXPMGT	0x00002000	/* CAPABILITY: tx power mgmt */
#define	IEEE80211_C_SHSLOT	0x00004000	/* CAPABILITY: short slottime */
#define	IEEE80211_C_SHPREAMBLE	0x00008000	/* CAPABILITY: short preamble */
#define	IEEE80211_C_MONITOR	0x00010000	/* CAPABILITY: monitor mode */
#define	IEEE80211_C_TKIPMIC	0x00020000	/* CAPABILITY: TKIP MIC avail */
#define	IEEE80211_C_WPA1	0x00800000	/* CAPABILITY: WPA1 avail */
#define	IEEE80211_C_WPA2	0x01000000	/* CAPABILITY: WPA2 avail */
#define	IEEE80211_C_WPA		0x01800000
				/* CAPABILITY: WPA1+WPA2 avail */
#define	IEEE80211_C_BURST	0x02000000	/* CAPABILITY: frame bursting */
#define	IEEE80211_C_WME		0x04000000	/* CAPABILITY: WME avail */
#define	IEEE80211_C_WDS		0x08000000	/* CAPABILITY: 4-addr support */
/* 0x10000000 reserved */
#define	IEEE80211_C_BGSCAN	0x20000000	/* CAPABILITY: bg scanning */
#define	IEEE80211_C_TXFRAG	0x40000000	/* CAPABILITY: tx fragments */
/* XXX protection/barker? */

#define	IEEE80211_C_CRYPTO	0x0000001f	/* CAPABILITY: crypto alg's */

/* ic_flags */
/* NB: bits 0x4c available */
#define	IEEE80211_F_FF		0x00000001	/* CONF: ATH FF enabled */
#define	IEEE80211_F_TURBOP	0x00000002	/* CONF: ATH Turbo enabled */
#define	IEEE80211_F_BURST	0x00000004	/* CONF: bursting enabled */
/* NB: this is intentionally setup to be IEEE80211_CAPINFO_PRIVACY */
#define	IEEE80211_F_PRIVACY	0x00000010	/* CONF: privacy enabled */
#define	IEEE80211_F_PUREG	0x00000020	/* CONF: 11g w/o 11b sta's */
#define	IEEE80211_F_SCANONLY	0x00000040	/* CONF: scan only */
#define	IEEE80211_F_SCAN	0x00000080	/* STATUS: scanning */
#define	IEEE80211_F_ASCAN	0x00000100	/* STATUS: active scan */
#define	IEEE80211_F_SIBSS	0x00000200	/* STATUS: start IBSS */
/* NB: this is intentionally setup to be IEEE80211_CAPINFO_SHORT_SLOTTIME */
#define	IEEE80211_F_SHSLOT	0x00000400
				/* STATUS: use short slot time */
#define	IEEE80211_F_PMGTON	0x00000800	/* CONF: Power mgmt enable */
#define	IEEE80211_F_DESBSSID	0x00001000	/* CONF: des_bssid is set */
#define	IEEE80211_F_WME		0x00002000	/* CONF: enable WME use */
#define	IEEE80211_F_BGSCAN	0x00004000
				/* CONF: bg scan enabled (???) */
#define	IEEE80211_F_SWRETRY	0x00008000	/* CONF: sw tx retry enabled */
#define	IEEE80211_F_TXPOW_FIXED	0x00010000	/* TX Power: fixed rate */
#define	IEEE80211_F_IBSSON	0x00020000	/* CONF: IBSS creation enable */
#define	IEEE80211_F_SHPREAMBLE	0x00040000	/* STATUS: use short preamble */
#define	IEEE80211_F_DATAPAD	0x00080000	/* CONF: do alignment pad */
#define	IEEE80211_F_USEPROT	0x00100000	/* STATUS: protection enabled */
#define	IEEE80211_F_USEBARKER	0x00200000
				/* STATUS: use barker preamble */
#define	IEEE80211_F_TIMUPDATE	0x00400000	/* STATUS: update beacon tim */
#define	IEEE80211_F_WPA1	0x00800000	/* CONF: WPA enabled */
#define	IEEE80211_F_WPA2	0x01000000	/* CONF: WPA2 enabled */
#define	IEEE80211_F_WPA		0x01800000	/* CONF: WPA/WPA2 enabled */
#define	IEEE80211_F_DROPUNENC	0x02000000	/* CONF: drop unencrypted */
#define	IEEE80211_F_COUNTERM	0x04000000	/* CONF: TKIP countermeasures */
#define	IEEE80211_F_HIDESSID	0x08000000	/* CONF: hide SSID in beacon */
#define	IEEE80211_F_NOBRIDGE	0x10000000	/* CONF: dis. internal bridge */
#define	IEEE80211_F_WMEUPDATE	0x20000000	/* STATUS: update beacon wme */

/* ic_flags_ext */
#define	IEEE80211_FEXT_WDS	0x00000001	/* CONF: 4 addr allowed */
/* 0x00000006 reserved */
#define	IEEE80211_FEXT_BGSCAN	0x00000008
				/* STATUS: enable full bgscan completion */
#define	IEEE80211_FEXT_ERPUPDATE 0x00000200	/* STATUS: update ERP element */
#define	IEEE80211_FEXT_SWBMISS	0x00000400	/* CONF: do bmiss in s/w */

/*
 * Channel attributes (ich_flags)
 * bits 0-3 are for private use by drivers
 */
#define	IEEE80211_CHAN_TURBO	0x0010	/* Turbo channel */
#define	IEEE80211_CHAN_CCK	0x0020	/* CCK channel */
#define	IEEE80211_CHAN_OFDM	0x0040	/* OFDM channel */
#define	IEEE80211_CHAN_2GHZ	0x0080	/* 2 GHz spectrum channel. */
#define	IEEE80211_CHAN_5GHZ	0x0100	/* 5 GHz spectrum channel */
#define	IEEE80211_CHAN_PASSIVE	0x0200	/* Only passive scan allowed */
#define	IEEE80211_CHAN_DYN	0x0400	/* Dynamic CCK-OFDM channel */
#define	IEEE80211_CHAN_GFSK	0x0800	/* GFSK channel (FHSS PHY) */

#define	IEEE80211_CHAN_MAX	255
#define	IEEE80211_CHAN_BYTES	32	/* howmany(IEEE80211_CHAN_MAX, NBBY) */
#define	IEEE80211_CHAN_ANY	0xffff	/* token for ``any channel'' */
#define	IEEE80211_CHAN_ANYC	\
	((struct ieee80211_channel *)IEEE80211_CHAN_ANY)

#define	IEEE80211_IS_CHAN_2GHZ(_c)	\
	(((_c)->ich_flags & IEEE80211_CHAN_2GHZ) != 0)
#define	IEEE80211_IS_CHAN_5GHZ(_c)	\
	(((_c)->ich_flags & IEEE80211_CHAN_5GHZ) != 0)

#define	IEEE80211_NODE_HASHSIZE	32

#define	IEEE80211_FIXED_RATE_NONE	0
#define	IEEE80211_MCAST_RATE_DEFAULT	(2*1)	/* default mcast rate (1M) */

/* WME stream classes */
#define	WME_AC_BE		0	/* best effort */
#define	WME_AC_BK		1	/* background */
#define	WME_AC_VI		2	/* video */
#define	WME_AC_VO		3	/* voice */

/*
 * Authentication mode.
 */
enum ieee80211_authmode {
	IEEE80211_AUTH_NONE	= 0,
	IEEE80211_AUTH_OPEN	= 1,	/* open */
	IEEE80211_AUTH_SHARED	= 2,	/* shared-key */
	IEEE80211_AUTH_8021X	= 3,	/* 802.1x */
	IEEE80211_AUTH_AUTO	= 4,	/* auto-select/accept */
	/* NB: these are used only for ioctls */
	IEEE80211_AUTH_WPA	= 5	/* WPA/RSN w/ 802.1x/PSK */
};

enum ieee80211_state {
	IEEE80211_S_INIT	= 0,	/* default state */
	IEEE80211_S_SCAN	= 1,	/* scanning */
	IEEE80211_S_AUTH	= 2,	/* try to authenticate */
	IEEE80211_S_ASSOC	= 3,	/* try to assoc */
	IEEE80211_S_RUN		= 4	/* associated */
};
#define	IEEE80211_S_MAX	(IEEE80211_S_RUN+1)

/*
 * 802.11 rate set.
 */
#define	IEEE80211_RATE_MAXSIZE	15	/* max rates we'll handle */
#define	IEEE80211_RATE_SIZE	8	/* 802.11 standard */
#define	IEEE80211_XRATE_SIZE	(IEEE80211_RATE_MAXSIZE - IEEE80211_RATE_SIZE)
					/* size of extended supported rates */
struct ieee80211_rateset {
	uint8_t			ir_nrates;
	uint8_t			ir_rates[IEEE80211_RATE_MAXSIZE];
};

/*
 * Channels are specified by frequency and attributes.
 */
struct ieee80211_channel {
	uint16_t		ich_freq;	/* setting in Mhz */
	uint16_t		ich_flags;	/* see below */
};

struct ieee80211_device_stats {
	uint32_t		is_tx_frags;
	uint32_t		is_tx_bytes;
	uint32_t		is_tx_mcast;
	uint32_t		is_tx_failed;
	uint32_t		is_tx_retries;
	uint32_t		is_rts_success;
	uint32_t		is_rts_failure;
	uint32_t		is_ack_failure;
	uint32_t		is_rx_frags;
	uint32_t		is_rx_bytes;
	uint32_t		is_rx_mcast;
	uint32_t		is_rx_dups;
	uint32_t		is_fcs_errors;
	uint32_t		is_wep_errors;
	uint32_t		is_tx_nobuf;
	uint32_t		is_tx_unknownmgt;
};

struct ieee80211_crypto_state;
typedef struct ieee80211_node_table ieee80211_node_table_t;
typedef struct ieee80211_node ieee80211_node_t;
typedef struct ieee80211com ieee80211com_t;

struct ieee80211_node_table {
	struct ieee80211com	*nt_ic;		/* back reference */

	const char		*nt_name;	/* for debugging */
	/* For node inactivity processing */
	int			nt_inact_timer;	/* inactivity timer */
	int			nt_inact_init;	/* initial node inact setting */
	void			(*nt_timeout)(struct ieee80211_node_table *);
	uint32_t		nt_scangen;	/* gen# for timeout scan */
	kmutex_t		nt_scanlock;    /* on nt_scangen */
	kmutex_t		nt_nodelock;	/* on node table */

	int			nt_keyixmax;	/* keyixmap size */
	struct ieee80211_node	**nt_keyixmap;	/* key ix -> node map */

	list_t			nt_node;	/* information of all nodes */
	list_t			nt_hash[IEEE80211_NODE_HASHSIZE];
};

/*
 * Node specific information.  Note that drivers are expected
 * to derive from this structure to add device-specific per-node
 * state.  This is done by overriding the ic_node_* methods in
 * the ieee80211com structure.
 */
struct ieee80211_node {
	struct ieee80211com		*in_ic;
	struct ieee80211_node_table	*in_table;

	uint8_t			in_authmode;	/* authentication algorithm */
	uint16_t		in_flags;	/* special purpose state */
	uint16_t		in_associd;	/* assoc response */
	uint16_t		in_txpower;	/* current transmit power */
	uint16_t		in_vlan;	/* vlan tag */
	/*
	 * Tx/Rx sequence number.
	 * index 0 is used when QoS is not enabled. index 1-16 is used
	 * when QoS is enabled. 1-16 corresponds to TID 0-15.
	 */
	uint16_t		in_txseqs[17];	/* tx seq per-tid */
	uint16_t		in_rxseqs[17];	/* rx seq previous per-tid */
	clock_t			in_rxfragstamp;	/* time stamp of last rx frag */
	mblk_t			*in_rxfrag;	/* rx frag reassembly */
	uint32_t		in_scangen;	/* gen# for timeout scan */
	uint32_t		in_refcnt;

	/* hardware */
	uint32_t		in_rstamp;	/* recv timestamp */
	uint8_t			in_rssi;	/* recv ssi */

	/* header */
	uint8_t			in_macaddr[IEEE80211_ADDR_LEN];
	uint8_t			in_bssid[IEEE80211_ADDR_LEN];

	/* beacon, probe response */
	union {
		uint8_t		data[8];
		uint64_t	tsf;
	} in_tstamp;				/* from last rcv'd beacon */
	uint16_t		in_intval;	/* beacon interval */
	uint16_t		in_capinfo;	/* capabilities */
	uint8_t			in_esslen;
	uint8_t			in_essid[IEEE80211_NWID_LEN];
	struct ieee80211_rateset in_rates;	/* negotiated rate set */
	struct ieee80211_channel *in_chan;	/* XXX multiple uses */
	enum ieee80211_phytype	in_phytype;
	uint16_t		in_fhdwell;	/* FH only */
	uint8_t			in_fhindex;	/* FH only */
	uint8_t			in_erp;		/* ERP from beacon/probe resp */
	uint16_t		in_tim_off;	/* byte offset to TIM ie */
	uint8_t			in_dtim_period;	/* DTIM period */
	uint8_t			in_dtim_count;	/* DTIM count for last bcn */

	uint32_t		*in_challenge;	/* shared-key challenge */
	struct ieee80211_key	in_ucastkey;	/* unicast key */

	/* others */
	int32_t			in_fails;	/* failure count to associate */
	int16_t			in_inact;	/* inactivity mark count */
	int16_t			in_inact_reload; /* inactivity reload value */
	int32_t			in_txrate;	/* index to ni_rates[] */

	list_node_t		in_node;	/* element of nt->nt_node */
	list_node_t		in_hash;	/* element of nt->nt_hash */
};

struct ieee80211com {
	mac_handle_t		ic_mach;

	/* Initialized by driver */
	uint8_t			ic_macaddr[IEEE80211_ADDR_LEN];
	uint32_t		ic_caps;	/* capabilities */
	enum ieee80211_phytype	ic_phytype;	/* XXX wrong for multi-mode */
	enum ieee80211_opmode	ic_opmode;	/* current operation mode */
	enum ieee80211_state	ic_state;	/* current 802.11 state */
	struct ieee80211_channel	ic_sup_channels[IEEE80211_CHAN_MAX+1];
	struct ieee80211_rateset	ic_sup_rates[IEEE80211_MODE_MAX];
	enum ieee80211_phymode		ic_curmode;  /* OPT current mode */
	struct ieee80211_channel	*ic_curchan; /* OPT current channel */
	struct ieee80211_channel	*ic_ibss_chan;	/* OPT bss channel */
	uint8_t				ic_maxrssi;  /* maximum hardware RSSI */

	/* INITIALIZED by IEEE80211, used/overridden by driver */
	uint16_t		ic_modecaps;	/* set of mode capabilities */
	uint8_t			ic_chan_active[IEEE80211_CHAN_BYTES];
	enum ieee80211_protmode	ic_protmode;	/* 802.11g protection mode */
	uint16_t		ic_bintval;	/* beacon interval */
	uint16_t		ic_lintval;	/* listen interval */
	uint16_t		ic_txpowlimit;	/* global tx power limit */
	uint8_t			ic_bmissthreshold;
	uint16_t		ic_rtsthreshold;
	uint16_t		ic_fragthreshold;
	int32_t			ic_mcast_rate;	/* rate for mcast frames */
	uint8_t			ic_fixed_rate;	/* value of fixed rate */
	int32_t			ic_des_esslen;	/* length of desired essid */
	uint8_t			ic_des_essid[IEEE80211_NWID_LEN];
	uint8_t			ic_des_bssid[IEEE80211_ADDR_LEN];
	struct ieee80211_channel	*ic_des_chan;	/* desired channel */
	void			*ic_opt_ie;	/* user-specified IE's */
	uint16_t		ic_opt_ie_len;	/* length of ic_opt_ie */
	uint8_t			ic_nickname[IEEE80211_NWID_LEN];
	uint16_t		ic_tim_len;	/* ic_tim_bitmap size (bytes) */
	uint8_t			*ic_tim_bitmap;	/* powersave stations w/ data */
	timeout_id_t		ic_watchdog_timer;	/* watchdog timer */
	/* Cipher state/configuration. */
	struct ieee80211_crypto_state	ic_crypto;

	/* Runtime states */
	uint32_t		ic_flags;	/* state/conf flags */
	uint32_t		ic_flags_ext;	/* extended state flags */
	struct ieee80211_node	*ic_bss;	/* information for this node */
	struct ieee80211_device_stats	ic_stats;
	struct ieee80211_node_table	ic_scan; /* STA: scan candidates */
	struct ieee80211_node_table	ic_sta; /* AP:stations/IBSS:neighbors */

	/* callback functions */
	/*
	 * Functions initialized by driver before calling ieee80211_attach()
	 * Those must be initialized are marked with M(andatory)
	 *
	 *  ic_xmit		- [M] transmit a management or null data frame
	 *			return 0 on success, non-zero on error
	 *  ic_watchdog		- [O] periodic run function, enabled by
	 *			ieee80211_start_watchdog()
	 *  ic_set_tim		- [O] set/clear traffic indication map
	 *  ic_set_shortslot	- [O] enable/disable short slot timing
	 *  ic_node_newassoc	- [O] driver specific operation on a newly
	 *			associated or re-assoced node
	 */
	int			(*ic_xmit)(ieee80211com_t *, mblk_t *, uint8_t);
	void			(*ic_watchdog)(void *);
	void			(*ic_set_tim)(ieee80211com_t *,
					ieee80211_node_t *, int);
	void			(*ic_set_shortslot)(ieee80211com_t *, int);
	void			(*ic_node_newassoc)(ieee80211_node_t *, int);
	/*
	 * Functions initialized by ieee80211_attach(), driver could
	 * override these functions after calling ieee80211_attach()
	 *
	 *  ic_reset		- reset
	 *  ic_recv_mgmt	- handle received management frames
	 *  ic_send_mgmt	- construct and transmit management frames
	 *  ic_newstate		- handle state transition
	 *  ic_node_alloc	- allocate a new BSS info node
	 *  ic_node_cleanup	- cleanup or free memory spaces of a node
	 *  ic_node_free	- free a node
	 *  ic_node_getrssi	- get node's rssi
	 */
	int			(*ic_reset)(ieee80211com_t *);
	void			(*ic_recv_mgmt)(ieee80211com_t *,
					mblk_t *, ieee80211_node_t *,
					int, int, uint32_t);
	int			(*ic_send_mgmt)(ieee80211com_t *,
					ieee80211_node_t *, int, int);
	int			(*ic_newstate)(ieee80211com_t *,
					enum ieee80211_state, int);
	struct ieee80211_node	*(*ic_node_alloc)(ieee80211com_t *);
	void			(*ic_node_cleanup)(ieee80211_node_t *);
	void			(*ic_node_free)(ieee80211_node_t *);
	uint8_t			(*ic_node_getrssi)(const ieee80211_node_t *);

	kmutex_t		ic_genlock;
	void			*ic_private;	/* ieee80211 private data */
};
#define	ic_nw_keys		ic_crypto.cs_nw_keys
#define	ic_def_txkey		ic_crypto.cs_def_txkey

extern	const char *ieee80211_state_name[IEEE80211_S_MAX];

#define	IEEE80211_RATE(_ix)			\
	(in->in_rates.ir_rates[(_ix)] & IEEE80211_RATE_VAL)

#define	ieee80211_new_state(_ic, _nstate, _arg)	\
	(((_ic)->ic_newstate)((_ic), (_nstate), (_arg)))

#define	ieee80211_macaddr_sprintf(_addr)	\
	ether_sprintf((struct ether_addr *)(_addr))

/*
 * Node reference counting definitions.
 *
 * ieee80211_node_initref	initialize the reference count to 1
 * ieee80211_node_incref	add a reference
 * ieee80211_node_decref	remove a reference
 * ieee80211_node_decref_nv	remove a reference and return new value
 * ieee80211_node_refcnt	reference count for printing (only)
 */
#include <sys/atomic.h>
#define	ieee80211_node_initref(_in)		\
	((_in)->in_refcnt = 1)
#define	ieee80211_node_incref(_in)		\
	atomic_inc_uint(&(_in)->in_refcnt)
#define	ieee80211_node_decref(_in)		\
	atomic_dec_uint(&(_in)->in_refcnt)
#define	ieee80211_node_decref_nv(_in)		\
	atomic_dec_uint_nv(&(_in)->in_refcnt)
#define	ieee80211_node_refcnt(_in)		\
	(_in)->in_refcnt

typedef void ieee80211_iter_func(void *, ieee80211_node_t *);

/* Initialization */
void ieee80211_attach(ieee80211com_t *);
void ieee80211_detach(ieee80211com_t *);
void ieee80211_media_init(ieee80211com_t *);
int ieee80211_ioctl(ieee80211com_t *, queue_t *, mblk_t *);

/* Protocol Processing */
int ieee80211_input(ieee80211com_t *, mblk_t *, ieee80211_node_t *,
	int32_t, uint32_t);
mblk_t *ieee80211_encap(ieee80211com_t *, mblk_t *, ieee80211_node_t *);

mblk_t *ieee80211_beacon_alloc(ieee80211com_t *, ieee80211_node_t *,
	struct ieee80211_beacon_offsets *);
int ieee80211_beacon_update(ieee80211com_t *, ieee80211_node_t *,
	struct ieee80211_beacon_offsets *, mblk_t *, int);
void ieee80211_beacon_miss(ieee80211com_t *);

void ieee80211_begin_scan(ieee80211com_t *, boolean_t);
void ieee80211_next_scan(ieee80211com_t *);
void ieee80211_end_scan(ieee80211com_t *);
void ieee80211_cancel_scan(ieee80211com_t *);

void ieee80211_sta_join(ieee80211com_t *, ieee80211_node_t *);
void ieee80211_sta_leave(ieee80211com_t *, ieee80211_node_t *);
boolean_t ieee80211_ibss_merge(ieee80211_node_t *);

/* Node Operation */
ieee80211_node_t *ieee80211_ref_node(ieee80211_node_t *);
void ieee80211_unref_node(ieee80211_node_t **);
void ieee80211_node_authorize(ieee80211_node_t *);
void ieee80211_node_unauthorize(ieee80211_node_t *);
ieee80211_node_t *ieee80211_alloc_node(ieee80211com_t *,
	ieee80211_node_table_t *, const uint8_t *);
void ieee80211_free_node(ieee80211_node_t *);
void ieee80211_node_table_reset(ieee80211_node_table_t *);
void ieee80211_iterate_nodes(ieee80211_node_table_t *, ieee80211_iter_func *,
	void *);
ieee80211_node_t *ieee80211_find_node(ieee80211_node_table_t *,
	const uint8_t *);
ieee80211_node_t *ieee80211_find_txnode(ieee80211com_t *,
	const uint8_t daddr[IEEE80211_ADDR_LEN]);
ieee80211_node_t *ieee80211_find_rxnode(ieee80211com_t *,
	const struct ieee80211_frame *);


/* Crypto */
extern struct ieee80211_key *ieee80211_crypto_encap(ieee80211com_t *, mblk_t *);
extern struct ieee80211_key *ieee80211_crypto_decap(ieee80211com_t *, mblk_t *,
	int);
extern int ieee80211_crypto_newkey(ieee80211com_t *, int, int,
	struct ieee80211_key *);
extern int ieee80211_crypto_delkey(ieee80211com_t *, struct ieee80211_key *);
extern int ieee80211_crypto_setkey(ieee80211com_t *, struct ieee80211_key *,
	const uint8_t macaddr[IEEE80211_ADDR_LEN]);

/* Helper Functions */
int ieee80211_stat(ieee80211com_t *ic, uint_t stat, uint64_t *val);
uint32_t ieee80211_chan2ieee(ieee80211com_t *, struct ieee80211_channel *);
enum ieee80211_phymode ieee80211_chan2mode(ieee80211com_t *,
	struct ieee80211_channel *);
uint32_t ieee80211_ieee2mhz(uint32_t, uint32_t);
void ieee80211_reset_chan(ieee80211com_t *);
void ieee80211_dump_pkt(const uint8_t *, int32_t, int32_t, int32_t);
void ieee80211_watchdog(void *);
void ieee80211_start_watchdog(ieee80211com_t *, uint32_t);
void ieee80211_stop_watchdog(ieee80211com_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NET80211_H */