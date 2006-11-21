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

/*
 * IEEE 802.11 generic handler
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/modctl.h>
#include "net80211_impl.h"

uint32_t ieee80211_debug = 0x0;	/* debug msg flags */

const char *ieee80211_phymode_name[] = {
	"auto",		/* IEEE80211_MODE_AUTO */
	"11a",		/* IEEE80211_MODE_11A */
	"11b",		/* IEEE80211_MODE_11B */
	"11g",		/* IEEE80211_MODE_11G */
	"FH",		/* IEEE80211_MODE_FH */
	"turboA",	/* IEEE80211_MODE_TURBO_A */
	"turboG",	/* IEEE80211_MODE_TURBO_G */
};

#define	IEEE80211_DPRINT(_level, _fmt)	do {	\
		_NOTE(CONSTCOND)		\
		va_list ap;			\
		va_start(ap, (_fmt));		\
		vcmn_err((_level), (_fmt), ap);	\
		va_end(ap);			\
		_NOTE(CONSTCOND)		\
	} while (0)

/*
 * Print error messages
 */
void
ieee80211_err(const int8_t *fmt, ...)
{
	IEEE80211_DPRINT(CE_WARN, fmt);
}

/*
 * Print debug messages
 */
void
ieee80211_dbg(uint32_t flag, const int8_t *fmt, ...)
{
	if (flag & ieee80211_debug)
		IEEE80211_DPRINT(CE_CONT, fmt);
}

/*
 * Default reset method for use with the ioctl support.  This
 * method is invoked after any state change in the 802.11
 * layer that should be propagated to the hardware but not
 * require re-initialization of the 802.11 state machine (e.g
 * rescanning for an ap).  We always return ENETRESET which
 * should cause the driver to re-initialize the device. Drivers
 * can override this method to implement more optimized support.
 */
/* ARGSUSED */
static int
ieee80211_default_reset(ieee80211com_t *ic)
{
	return (ENETRESET);
}

/*
 * Convert channel to IEEE channel number.
 */
uint32_t
ieee80211_chan2ieee(ieee80211com_t *ic, struct ieee80211_channel *ch)
{
	if ((ic->ic_sup_channels <= ch) &&
	    (ch <= &ic->ic_sup_channels[IEEE80211_CHAN_MAX])) {
		return (ch - ic->ic_sup_channels);
	} else if (ch == IEEE80211_CHAN_ANYC) {
		return (IEEE80211_CHAN_ANY);
	} else if (ch != NULL) {
		ieee80211_err("invalid channel freq %u flags %x\n",
			ch->ich_freq, ch->ich_flags);
		return (0);
	}
	ieee80211_err("invalid channel (NULL)\n");	/* ch == NULL */
	return (0);
}

/*
 * Convert IEEE channel number to MHz frequency.
 *    chan    IEEE channel number
 *    flags   specify whether the frequency is in the 2GHz ISM
 *            band or the 5GHz band
 *
 * 802.11b 2GHz: 14 channels, each 5 MHz wide. Channel 1 is placed
 * at 2.412 GHz, channel 2 at 2.417 GHz, and so on up to channel 13
 * at 2.472 GHz. Channel 14 was defined especially for operation in
 * Japan, and has a center frequency 2.484 GHz.
 * 802.11g 2GHz: adopts the frequency plan of 802.11b. Japan only
 * allows 802.11g operation in channels 1-13
 * 802.11a 5GHz: starting every 5 MHz
 * 802.11b/g channels 15-24 (2512-2692) are used by some implementation
 * (Atheros etc.)
 */
uint32_t
ieee80211_ieee2mhz(uint32_t chan, uint32_t flags)
{
	if (flags & IEEE80211_CHAN_2GHZ) {	/* 2GHz band */
		if (chan == 14)
			return (2484);
		if (chan < 14)
			return (2412 + (chan - 1) * 5);
		else
			return (2512 + ((chan - 15) * 20));
	} else if (flags & IEEE80211_CHAN_5GHZ) {	/* 5Ghz band */
		return (5000 + (chan * 5));	/* OFDM */
	} else {				/* either, guess */
		if (chan == 14)
			return (2484);
		if (chan < 14)			/* 0-13 */
			return (2412 + (chan - 1) * 5);
		if (chan < 27)			/* 15-26 */
			return (2512 + ((chan - 15) * 20));
		return (5000 + (chan * 5));
	}
}

/*
 * Do late attach work. It must be called by the driver after
 * calling ieee80211_attach() and before calling most ieee80211
 * functions.
 */
void
ieee80211_media_init(ieee80211com_t *ic)
{
	/*
	 * Do late attach work that must wait for any subclass
	 * (i.e. driver) work such as overriding methods.
	 */
	ieee80211_node_lateattach(ic);
}

/*
 * Start Watchdog timer. After count down timer(s), ic_watchdog
 * will be called
 */
void
ieee80211_start_watchdog(ieee80211com_t *ic, uint32_t timer)
{
	if (ic->ic_watchdog_timer == 0 && ic->ic_watchdog != NULL) {
		ic->ic_watchdog_timer = timeout(ic->ic_watchdog, ic,
			drv_usectohz(1000000 * timer));
	}
}

/*
 * Stop watchdog timer.
 */
void
ieee80211_stop_watchdog(ieee80211com_t *ic)
{
	if (ic->ic_watchdog_timer != 0) {
		if (ic->ic_watchdog != NULL)
			(void) untimeout(ic->ic_watchdog_timer);
		ic->ic_watchdog_timer = 0;
	}
}

/*
 * Called from a driver's xxx_watchdog routine. It is used to
 * perform periodic cleanup of state for net80211, as well as
 * timeout scans.
 */
void
ieee80211_watchdog(void *arg)
{
	ieee80211com_t *ic = arg;
	struct ieee80211_impl *im = ic->ic_private;
	ieee80211_node_table_t *nt;
	int inact_timer = 0;

	if (ic->ic_state == IEEE80211_S_INIT)
		return;

	IEEE80211_LOCK(ic);
	if ((im->im_mgt_timer != 0) && (--im->im_mgt_timer == 0)) {
		IEEE80211_UNLOCK(ic);
		ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
		IEEE80211_LOCK(ic);
	}

	nt = &ic->ic_scan;
	if (nt->nt_inact_timer != 0) {
		if (--nt->nt_inact_timer == 0)
			nt->nt_timeout(nt);
		inact_timer += nt->nt_inact_timer;
	}
	nt = &ic->ic_sta;
	if (nt->nt_inact_timer != 0) {
		if (--nt->nt_inact_timer == 0)
			nt->nt_timeout(nt);
		inact_timer += nt->nt_inact_timer;
	}

	IEEE80211_UNLOCK(ic);

	if (im->im_mgt_timer != 0 || inact_timer > 0)
		ieee80211_start_watchdog(ic, 1);
}

/*
 * Set the current phy mode and recalculate the active channel
 * set and supported rates based on the available channels for
 * this mode. Also select a new BSS channel if the current one
 * is inappropriate for this mode.
 * This function is called by net80211, and not intended to be
 * called directly.
 */
static int
ieee80211_setmode(ieee80211com_t *ic, enum ieee80211_phymode mode)
{
	static const uint32_t chanflags[] = {
		0,			/* IEEE80211_MODE_AUTO */
		IEEE80211_CHAN_A,	/* IEEE80211_MODE_11A */
		IEEE80211_CHAN_B,	/* IEEE80211_MODE_11B */
		IEEE80211_CHAN_PUREG,	/* IEEE80211_MODE_11G */
		IEEE80211_CHAN_FHSS,	/* IEEE80211_MODE_FH */
		IEEE80211_CHAN_T,	/* IEEE80211_MODE_TURBO_A */
		IEEE80211_CHAN_108G,	/* IEEE80211_MODE_TURBO_G */
	};
	struct ieee80211_channel *ch;
	uint32_t modeflags;
	int i;
	int achannels = 0;

	/* validate new mode */
	if ((ic->ic_modecaps & (1 << mode)) == 0) {
		ieee80211_err("ieee80211_setmode(): mode %u not supported"
			" (caps 0x%x)\n", mode, ic->ic_modecaps);
		return (EINVAL);
	}

	/*
	 * Verify at least one channel is present in the available
	 * channel list before committing to the new mode.
	 * Calculate the active channel set.
	 */
	ASSERT(mode < IEEE80211_N(chanflags));
	modeflags = chanflags[mode];
	bzero(ic->ic_chan_active, sizeof (ic->ic_chan_active));
	for (i = 0; i <= IEEE80211_CHAN_MAX; i++) {
		ch = &ic->ic_sup_channels[i];
		if (ch->ich_flags == 0)
			continue;
		if (mode == IEEE80211_MODE_AUTO) {
			/* take anything but pure turbo channels */
			if ((ch->ich_flags & ~IEEE80211_CHAN_TURBO) != 0) {
				ieee80211_setbit(ic->ic_chan_active, i);
				achannels++;
			}
		} else {
			if ((ch->ich_flags & modeflags) == modeflags) {
				ieee80211_setbit(ic->ic_chan_active, i);
				achannels++;
			}
		}
	}
	if (achannels == 0) {
		ieee80211_err("ieee80211_setmode(): "
			"no channel found for mode %u\n", mode);
		return (EINVAL);
	}

	/*
	 * If no current/default channel is setup or the current
	 * channel is wrong for the mode then pick the first
	 * available channel from the active list.  This is likely
	 * not the right one.
	 */
	if (ic->ic_ibss_chan == NULL ||
	    ieee80211_isclr(ic->ic_chan_active,
	    ieee80211_chan2ieee(ic, ic->ic_ibss_chan))) {
		for (i = 0; i <= IEEE80211_CHAN_MAX; i++) {
			if (ieee80211_isset(ic->ic_chan_active, i)) {
				ic->ic_ibss_chan = &ic->ic_sup_channels[i];
				break;
			}
		}
	}
	/*
	 * If the desired channel is set but no longer valid then reset it.
	 */
	if (ic->ic_des_chan != IEEE80211_CHAN_ANYC &&
	    ieee80211_isclr(ic->ic_chan_active,
	    ieee80211_chan2ieee(ic, ic->ic_des_chan))) {
		ic->ic_des_chan = IEEE80211_CHAN_ANYC;
	}

	/*
	 * Do mode-specific rate setup.
	 */
	if (mode == IEEE80211_MODE_11G || mode == IEEE80211_MODE_11B)
		ieee80211_setbasicrates(&ic->ic_sup_rates[mode], mode);

	/*
	 * Setup an initial rate set according to the
	 * current/default channel.  This will be changed
	 * when scanning but must exist now so drivers have
	 * consistent state of ic_bsschan.
	 */
	if (ic->ic_bss != NULL)
		ic->ic_bss->in_rates = ic->ic_sup_rates[mode];
	ic->ic_curmode = mode;
	ieee80211_reset_erp(ic);	/* reset ERP state */

	return (0);
}

/*
 * Return the phy mode for with the specified channel so the
 * caller can select a rate set.  This is problematic for channels
 * where multiple operating modes are possible (e.g. 11g+11b).
 * In those cases we defer to the current operating mode when set.
 */
enum ieee80211_phymode
ieee80211_chan2mode(ieee80211com_t *ic, struct ieee80211_channel *chan)
{
	if (IEEE80211_IS_CHAN_T(chan)) {
		return (IEEE80211_MODE_TURBO_A);
	} else if (IEEE80211_IS_CHAN_5GHZ(chan)) {
		return (IEEE80211_MODE_11A);
	} else if (IEEE80211_IS_CHAN_FHSS(chan)) {
		return (IEEE80211_MODE_FH);
	} else if (chan->ich_flags & (IEEE80211_CHAN_OFDM|IEEE80211_CHAN_DYN)) {
		/*
		 * This assumes all 11g channels are also usable
		 * for 11b, which is currently true.
		 */
		if (ic->ic_curmode == IEEE80211_MODE_TURBO_G)
			return (IEEE80211_MODE_TURBO_G);
		if (ic->ic_curmode == IEEE80211_MODE_11B)
			return (IEEE80211_MODE_11B);
		return (IEEE80211_MODE_11G);
	} else {
		return (IEEE80211_MODE_11B);
	}
}

/*
 * Return the size of the 802.11 header for a management or data frame.
 */
int
ieee80211_hdrspace(const void *data)
{
	const struct ieee80211_frame *wh = data;
	int size = sizeof (struct ieee80211_frame);

	/* NB: we don't handle control frames */
	ASSERT((wh->i_fc[0]&IEEE80211_FC0_TYPE_MASK) !=
		IEEE80211_FC0_TYPE_CTL);
	if ((wh->i_fc[1] & IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_DSTODS)
		size += IEEE80211_ADDR_LEN;

	return (size);
}

/*
 * Allocate and setup a management frame of the specified
 * size.  We return the mblk and a pointer to the start
 * of the contiguous data area that's been reserved based
 * on the packet length.
 */
mblk_t *
ieee80211_getmgtframe(uint8_t **frm, int pktlen)
{
	mblk_t *mp;
	int len;

	len = sizeof (struct ieee80211_frame) + pktlen;
	mp = allocb(len, BPRI_MED);
	if (mp != NULL) {
		*frm = mp->b_rptr + sizeof (struct ieee80211_frame);
		mp->b_wptr = mp->b_rptr + len;
	} else {
		ieee80211_err("ieee80211_getmgtframe: "
			"alloc frame failed, %d\n", len);
	}
	return (mp);
}

/*
 * Send system messages to notify the device has joined a WLAN.
 * This is an OS specific function. Solaris marks link status
 * as up.
 */
void
ieee80211_notify_node_join(ieee80211com_t *ic, ieee80211_node_t *in)
{
	if (in == ic->ic_bss)
		mac_link_update(ic->ic_mach, LINK_STATE_UP);
}

/*
 * Send system messages to notify the device has left a WLAN.
 * This is an OS specific function. Solaris marks link status
 * as down.
 */
void
ieee80211_notify_node_leave(ieee80211com_t *ic, ieee80211_node_t *in)
{
	if (in == ic->ic_bss)
		mac_link_update(ic->ic_mach, LINK_STATE_DOWN);
}

/*
 * Get 802.11 kstats defined in ieee802.11(5)
 *
 * Return 0 on success
 */
int
ieee80211_stat(ieee80211com_t *ic, uint_t stat, uint64_t *val)
{
	ASSERT(val != NULL);
	IEEE80211_LOCK(ic);
	switch (stat) {
	case WIFI_STAT_TX_FRAGS:
		*val = ic->ic_stats.is_tx_frags;
		break;
	case WIFI_STAT_MCAST_TX:
		*val = ic->ic_stats.is_tx_mcast;
		break;
	case WIFI_STAT_TX_FAILED:
		*val = ic->ic_stats.is_tx_failed;
		break;
	case WIFI_STAT_TX_RETRANS:
		*val = ic->ic_stats.is_tx_retries;
		break;
	case WIFI_STAT_RTS_SUCCESS:
		*val = ic->ic_stats.is_rts_success;
		break;
	case WIFI_STAT_RTS_FAILURE:
		*val = ic->ic_stats.is_rts_failure;
		break;
	case WIFI_STAT_ACK_FAILURE:
		*val = ic->ic_stats.is_ack_failure;
		break;
	case WIFI_STAT_RX_FRAGS:
		*val = ic->ic_stats.is_rx_frags;
		break;
	case WIFI_STAT_MCAST_RX:
		*val = ic->ic_stats.is_rx_mcast;
		break;
	case WIFI_STAT_RX_DUPS:
		*val = ic->ic_stats.is_rx_dups;
		break;
	case WIFI_STAT_FCS_ERRORS:
		*val = ic->ic_stats.is_fcs_errors;
		break;
	case WIFI_STAT_WEP_ERRORS:
		*val = ic->ic_stats.is_wep_errors;
		break;
	}
	IEEE80211_UNLOCK(ic);
	return (0);
}

/*
 * Attach network interface to the 802.11 support module. This
 * function must be called before using any of the ieee80211
 * functionss. The parameter "ic" MUST be initialized to tell
 * net80211 about interface's capabilities.
 */
void
ieee80211_attach(ieee80211com_t *ic)
{
	struct ieee80211_impl		*im;
	struct ieee80211_channel	*ch;
	int				i;

	/* Check mandatory callback functions not NULL */
	ASSERT(ic->ic_xmit != NULL);

	mutex_init(&ic->ic_genlock, NULL, MUTEX_DRIVER, NULL);

	im = kmem_alloc(sizeof (ieee80211_impl_t), KM_SLEEP);
	ic->ic_private = im;
	cv_init(&im->im_scan_cv, NULL, CV_DRIVER, NULL);

	/*
	 * Fill in 802.11 available channel set, mark
	 * all available channels as active, and pick
	 * a default channel if not already specified.
	 */
	bzero(im->im_chan_avail, sizeof (im->im_chan_avail));
	ic->ic_modecaps |= 1 << IEEE80211_MODE_AUTO;
	for (i = 0; i <= IEEE80211_CHAN_MAX; i++) {
		ch = &ic->ic_sup_channels[i];
		if (ch->ich_flags) {
			/* Verify driver passed us valid data */
			if (i != ieee80211_chan2ieee(ic, ch)) {
				ieee80211_err("bad channel ignored: "
					"freq %u flags%x number %u\n",
					ch->ich_freq, ch->ich_flags, i);
				ch->ich_flags = 0;
				continue;
			}
			ieee80211_setbit(im->im_chan_avail, i);
			/* Identify mode capabilities */
			if (IEEE80211_IS_CHAN_A(ch))
				ic->ic_modecaps |= 1 << IEEE80211_MODE_11A;
			if (IEEE80211_IS_CHAN_B(ch))
				ic->ic_modecaps |= 1 << IEEE80211_MODE_11B;
			if (IEEE80211_IS_CHAN_PUREG(ch))
				ic->ic_modecaps |= 1 << IEEE80211_MODE_11G;
			if (IEEE80211_IS_CHAN_FHSS(ch))
				ic->ic_modecaps |= 1 << IEEE80211_MODE_FH;
			if (IEEE80211_IS_CHAN_T(ch))
				ic->ic_modecaps |= 1 << IEEE80211_MODE_TURBO_A;
			if (IEEE80211_IS_CHAN_108G(ch))
				ic->ic_modecaps |= 1 << IEEE80211_MODE_TURBO_G;
			if (ic->ic_curchan == NULL) {
				/* arbitrarily pick the first channel */
				ic->ic_curchan = &ic->ic_sup_channels[i];
			}
		}
	}
	/* validate ic->ic_curmode */
	if ((ic->ic_modecaps & (1 << ic->ic_curmode)) == 0)
		ic->ic_curmode = IEEE80211_MODE_AUTO;
	ic->ic_des_chan = IEEE80211_CHAN_ANYC;	/* any channel is ok */
	(void) ieee80211_setmode(ic, ic->ic_curmode);

	if (ic->ic_caps & IEEE80211_C_BURST)
		ic->ic_flags |= IEEE80211_F_BURST;
	ic->ic_bintval = IEEE80211_BINTVAL_DEFAULT;
	ic->ic_lintval = ic->ic_bintval;
	ic->ic_txpowlimit = IEEE80211_TXPOWER_MAX;
	ic->ic_bmissthreshold = IEEE80211_HWBMISS_DEFAULT;

	ic->ic_reset = ieee80211_default_reset;

	ieee80211_node_attach(ic);
	ieee80211_proto_attach(ic);
	ieee80211_crypto_attach(ic);

	ic->ic_watchdog_timer = 0;
}

/*
 * Free any ieee80211 structures associated with the driver.
 */
void
ieee80211_detach(ieee80211com_t *ic)
{
	struct ieee80211_impl *im = ic->ic_private;

	ieee80211_stop_watchdog(ic);
	cv_destroy(&im->im_scan_cv);
	kmem_free(im, sizeof (ieee80211_impl_t));

	ieee80211_node_detach(ic);
	ieee80211_crypto_detach(ic);

	mutex_destroy(&ic->ic_genlock);
}

static struct modlmisc	i_wifi_modlmisc = {
	&mod_miscops,
	"IEEE80211 Kernel Misc Module"
};

static struct modlinkage	i_wifi_modlinkage = {
	MODREV_1,
	&i_wifi_modlmisc,
	NULL
};

/*
 * modlinkage functions
 */
int
_init(void)
{
	return (mod_install(&i_wifi_modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&i_wifi_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&i_wifi_modlinkage, modinfop));
}