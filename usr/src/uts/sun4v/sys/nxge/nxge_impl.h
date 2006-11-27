/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_NXGE_NXGE_IMPL_H
#define	_SYS_NXGE_NXGE_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * NIU HV API version definitions.
 */
#define	NIU_MAJOR_VER		1
#define	NIU_MINOR_VER		1

/*
 * NIU HV API v1.0 definitions
 */
#define	N2NIU_RX_LP_CONF		0x142
#define	N2NIU_RX_LP_INFO		0x143
#define	N2NIU_TX_LP_CONF		0x144
#define	N2NIU_TX_LP_INFO		0x145

#ifndef _ASM

#include	<sys/types.h>
#include	<sys/byteorder.h>
#include	<sys/debug.h>
#include	<sys/stropts.h>
#include	<sys/stream.h>
#include	<sys/strlog.h>
#ifndef	COSIM
#include	<sys/strsubr.h>
#endif
#include	<sys/cmn_err.h>
#include	<sys/vtrace.h>
#include	<sys/kmem.h>
#include	<sys/ddi.h>
#include	<sys/sunddi.h>
#include	<sys/strsun.h>
#include	<sys/stat.h>
#include	<sys/cpu.h>
#include	<sys/kstat.h>
#include	<inet/common.h>
#include	<inet/ip.h>
#include	<sys/dlpi.h>
#include	<inet/nd.h>
#include	<netinet/in.h>
#include	<sys/ethernet.h>
#include	<sys/vlan.h>
#include	<sys/pci.h>
#include	<sys/taskq.h>
#include	<sys/atomic.h>

#include 	<sys/nxge/nxge_defs.h>
#include 	<sys/nxge/nxge_hw.h>
#include 	<sys/nxge/nxge_mac.h>
#include	<sys/nxge/nxge_mii.h>
#include	<sys/nxge/nxge_fm.h>
#if !defined(IODIAG)
#include	<sys/netlb.h>
#endif

#include	<sys/ddi_intr.h>

#if	defined(_KERNEL)
#include 	<sys/mac.h>
#include	<sys/mac_impl.h>
#include 	<sys/mac_ether.h>
#endif

#if	defined(sun4v)
#include	<sys/hypervisor_api.h>
#include 	<sys/machsystm.h>
#include 	<sys/hsvc.h>
#endif

/*
 * Handy macros (taken from bge driver)
 */
#define	RBR_SIZE			4
#define	DMA_COMMON_CHANNEL(area)	((area.dma_channel))
#define	DMA_COMMON_VPTR(area)		((area.kaddrp))
#define	DMA_COMMON_VPTR_INDEX(area, index)	\
					(((char *)(area.kaddrp)) + \
					(index * RBR_SIZE))
#define	DMA_COMMON_HANDLE(area)		((area.dma_handle))
#define	DMA_COMMON_ACC_HANDLE(area)	((area.acc_handle))
#define	DMA_COMMON_IOADDR(area)		((area.dma_cookie.dmac_laddress))
#define	DMA_COMMON_IOADDR_INDEX(area, index)	\
					((area.dma_cookie.dmac_laddress) + \
						(index * RBR_SIZE))

#define	DMA_NPI_HANDLE(area)		((area.npi_handle)

#define	DMA_COMMON_SYNC(area, flag)	((void) ddi_dma_sync((area).dma_handle,\
						(area).offset, (area).alength, \
						(flag)))
#define	DMA_COMMON_SYNC_OFFSET(area, bufoffset, len, flag)	\
					((void) ddi_dma_sync((area).dma_handle,\
					(area.offset + bufoffset), len, \
					(flag)))

#define	DMA_COMMON_SYNC_RBR_DESC(area, index, flag)	\
				((void) ddi_dma_sync((area).dma_handle,\
				(index * RBR_SIZE), RBR_SIZE,	\
				(flag)))

#define	DMA_COMMON_SYNC_RBR_DESC_MULTI(area, index, count, flag)	\
			((void) ddi_dma_sync((area).dma_handle,\
			(index * RBR_SIZE), count * RBR_SIZE,	\
				(flag)))
#define	DMA_COMMON_SYNC_ENTRY(area, index, flag)	\
				((void) ddi_dma_sync((area).dma_handle,\
				(index * (area).block_size),	\
				(area).block_size, \
				(flag)))

#define	NEXT_ENTRY(index, wrap)		((index + 1) & wrap)
#define	NEXT_ENTRY_PTR(ptr, first, last)	\
					((ptr == last) ? first : (ptr + 1))

/*
 * NPI related macros
 */
#define	NXGE_DEV_NPI_HANDLE(nxgep)	(nxgep->npi_handle)

#define	NPI_PCI_ACC_HANDLE_SET(nxgep, ah) (nxgep->npi_pci_handle.regh = ah)
#define	NPI_PCI_ADD_HANDLE_SET(nxgep, ap) (nxgep->npi_pci_handle.regp = ap)

#define	NPI_ACC_HANDLE_SET(nxgep, ah)	(nxgep->npi_handle.regh = ah)
#define	NPI_ADD_HANDLE_SET(nxgep, ap)	\
		nxgep->npi_handle.is_vraddr = B_FALSE;	\
		nxgep->npi_handle.function.instance = nxgep->instance;   \
		nxgep->npi_handle.function.function = nxgep->function_num;   \
		nxgep->npi_handle.nxgep = (void *) nxgep;   \
		nxgep->npi_handle.regp = ap;

#define	NPI_REG_ACC_HANDLE_SET(nxgep, ah) (nxgep->npi_reg_handle.regh = ah)
#define	NPI_REG_ADD_HANDLE_SET(nxgep, ap)	\
		nxgep->npi_reg_handle.is_vraddr = B_FALSE;	\
		nxgep->npi_handle.function.instance = nxgep->instance;   \
		nxgep->npi_handle.function.function = nxgep->function_num;   \
		nxgep->npi_reg_handle.nxgep = (void *) nxgep;   \
		nxgep->npi_reg_handle.regp = ap;

#define	NPI_MSI_ACC_HANDLE_SET(nxgep, ah) (nxgep->npi_msi_handle.regh = ah)
#define	NPI_MSI_ADD_HANDLE_SET(nxgep, ap) (nxgep->npi_msi_handle.regp = ap)

#define	NPI_VREG_ACC_HANDLE_SET(nxgep, ah) (nxgep->npi_vreg_handle.regh = ah)
#define	NPI_VREG_ADD_HANDLE_SET(nxgep, ap)	\
		nxgep->npi_vreg_handle.is_vraddr = B_TRUE; \
		nxgep->npi_handle.function.instance = nxgep->instance;   \
		nxgep->npi_handle.function.function = nxgep->function_num;   \
		nxgep->npi_vreg_handle.nxgep = (void *) nxgep;   \
		nxgep->npi_vreg_handle.regp = ap;

#define	NPI_V2REG_ACC_HANDLE_SET(nxgep, ah) (nxgep->npi_v2reg_handle.regh = ah)
#define	NPI_V2REG_ADD_HANDLE_SET(nxgep, ap)	\
		nxgep->npi_v2reg_handle.is_vraddr = B_TRUE; \
		nxgep->npi_handle.function.instance = nxgep->instance;   \
		nxgep->npi_handle.function.function = nxgep->function_num;   \
		nxgep->npi_v2reg_handle.nxgep = (void *) nxgep;   \
		nxgep->npi_v2reg_handle.regp = ap;

#define	NPI_PCI_ACC_HANDLE_GET(nxgep) (nxgep->npi_pci_handle.regh)
#define	NPI_PCI_ADD_HANDLE_GET(nxgep) (nxgep->npi_pci_handle.regp)
#define	NPI_ACC_HANDLE_GET(nxgep) (nxgep->npi_handle.regh)
#define	NPI_ADD_HANDLE_GET(nxgep) (nxgep->npi_handle.regp)
#define	NPI_REG_ACC_HANDLE_GET(nxgep) (nxgep->npi_reg_handle.regh)
#define	NPI_REG_ADD_HANDLE_GET(nxgep) (nxgep->npi_reg_handle.regp)
#define	NPI_MSI_ACC_HANDLE_GET(nxgep) (nxgep->npi_msi_handle.regh)
#define	NPI_MSI_ADD_HANDLE_GET(nxgep) (nxgep->npi_msi_handle.regp)
#define	NPI_VREG_ACC_HANDLE_GET(nxgep) (nxgep->npi_vreg_handle.regh)
#define	NPI_VREG_ADD_HANDLE_GET(nxgep) (nxgep->npi_vreg_handle.regp)
#define	NPI_V2REG_ACC_HANDLE_GET(nxgep) (nxgep->npi_v2reg_handle.regh)
#define	NPI_V2REG_ADD_HANDLE_GET(nxgep) (nxgep->npi_v2reg_handle.regp)

#define	NPI_DMA_ACC_HANDLE_SET(dmap, ah) (dmap->npi_handle.regh = ah)
#define	NPI_DMA_ACC_HANDLE_GET(dmap) 	(dmap->npi_handle.regh)

/*
 * DMA handles.
 */
#define	NXGE_DESC_D_HANDLE_GET(desc)	(desc.dma_handle)
#define	NXGE_DESC_D_IOADD_GET(desc)	(desc.dma_cookie.dmac_laddress)
#define	NXGE_DMA_IOADD_GET(dma_cookie) (dma_cookie.dmac_laddress)
#define	NXGE_DMA_AREA_IOADD_GET(dma_area) (dma_area.dma_cookie.dmac_laddress)

#define	LDV_ON(ldv, vector)	((vector >> ldv) & 0x1)
#define	LDV2_ON_1(ldv, vector)	((vector >> (ldv - 64)) & 0x1)
#define	LDV2_ON_2(ldv, vector)	(((vector >> 5) >> (ldv - 64)) & 0x1)

typedef uint32_t		nxge_status_t;

typedef enum  {
	IDLE,
	PROGRESS,
	CONFIGURED
} dev_func_shared_t;

typedef enum  {
	DVMA,
	DMA,
	SDMA
} dma_method_t;

typedef enum  {
	BKSIZE_4K,
	BKSIZE_8K,
	BKSIZE_16K,
	BKSIZE_32K
} nxge_rx_block_size_t;

#ifdef TX_ONE_BUF
#define	TX_BCOPY_MAX 1514
#else
#if	defined(sun4v) && defined(NIU_LP_WORKAROUND)
#define	TX_BCOPY_MAX	4096
#define	TX_BCOPY_SIZE	4096
#else
#define	TX_BCOPY_MAX	2048
#define	TX_BCOPY_SIZE	2048
#endif
#endif

#define	TX_STREAM_MIN 512
#define	TX_FASTDVMA_MIN 1024

#define	NXGE_ERROR_SHOW_MAX	0

/*
 * Defaults
 */
#define	NXGE_RDC_RCR_THRESHOLD		8
#define	NXGE_RDC_RCR_TIMEOUT		16

#define	NXGE_RDC_RCR_THRESHOLD_MAX	256
#define	NXGE_RDC_RCR_TIMEOUT_MAX	64
#define	NXGE_RDC_RCR_THRESHOLD_MIN	1
#define	NXGE_RDC_RCR_TIMEOUT_MIN	1
#define	NXGE_RCR_FULL_HEADER		1

#define	NXGE_IS_VLAN_PACKET(ptr)				\
	((((struct ether_vlan_header *)ptr)->ether_tpid) ==	\
	htons(VLAN_ETHERTYPE))

typedef enum {
	NONE,
	SMALL,
	MEDIUM,
	LARGE
} dma_size_t;

typedef enum {
	USE_NONE,
	USE_BCOPY,
	USE_DVMA,
	USE_DMA,
	USE_SDMA
} dma_type_t;

typedef enum {
	NOT_IN_USE,
	HDR_BUF,
	MTU_BUF,
	RE_ASSEMBLY_BUF,
	FREE_BUF
} rx_page_state_t;

struct _nxge_block_mv_t {
	uint32_t msg_type;
	dma_type_t dma_type;
};

typedef struct _nxge_block_mv_t nxge_block_mv_t, *p_nxge_block_mv_t;

typedef enum {
	NEPTUNE,	/* 4 ports */
	NEPTUNE_2,	/* 2 ports */
	N2_NIU		/* N2/NIU 2 ports */
} niu_type_t;

typedef enum {
	CFG_DEFAULT = 0,	/* default cfg */
	CFG_EQUAL,	/* Equal */
	CFG_FAIR,	/* Equal */
	CFG_CLASSIFY,
	CFG_L2_CLASSIFY,
	CFG_L3_CLASSIFY,
	CFG_L3_DISTRIBUTE,
	CFG_L3_WEB,
	CFG_L3_TCAM,
	CFG_NOT_SPECIFIED,
	CFG_CUSTOM	/* Custom */
} cfg_type_t;

typedef enum {
	NO_MSG = 0x0,		/* No message output or storage. */
	CONSOLE = 0x1,		/* Messages are go to the console. */
	BUFFER = 0x2,		/* Messages are go to the system buffer. */
	CON_BUF = 0x3,		/* Messages are go to the console and */
				/* system buffer. */
	VERBOSE = 0x4		/* Messages are go out only in VERBOSE node. */
} out_msg_t, *p_out_msg_t;

typedef enum {
	DBG_NO_MSG = 0x0,	/* No message output or storage. */
	DBG_CONSOLE = 0x1,	/* Messages are go to the console. */
	DBG_BUFFER = 0x2,	/* Messages are go to the system buffer. */
	DBG_CON_BUF = 0x3,	/* Messages are go to the console and */
				/* system buffer. */
	STR_LOG = 4		/* Sessage sent to streams logging driver. */
} out_dbgmsg_t, *p_out_dbgmsg_t;



#if defined(_KERNEL) || defined(COSIM)

typedef struct ether_addr ether_addr_st, *p_ether_addr_t;
typedef struct ether_header ether_header_t, *p_ether_header_t;
typedef queue_t *p_queue_t;

#if !defined(IODIAG)
typedef mblk_t *p_mblk_t;
#endif

/*
 * Common DMA data elements.
 */
struct _nxge_dma_common_t {
	uint16_t		dma_channel;
	void			*kaddrp;
	void			*first_kaddrp;
	void			*last_kaddrp;
	void			*ioaddr_pp;
	void			*first_ioaddr_pp;
	void			*last_ioaddr_pp;
	ddi_dma_cookie_t 	dma_cookie;
	uint32_t		ncookies;

	nxge_block_mv_t		msg_dma_flags;
	ddi_dma_handle_t	dma_handle;
	nxge_os_acc_handle_t	acc_handle;
	npi_handle_t		npi_handle;

	size_t			block_size;
	uint32_t		nblocks;
	size_t			alength;
	uint_t			offset;
	uint_t			dma_chunk_index;
	void			*orig_ioaddr_pp;
	uint64_t		orig_vatopa;
	void			*orig_kaddrp;
	size_t			orig_alength;
	boolean_t		contig_alloc_type;
};

typedef struct _nxge_t nxge_t, *p_nxge_t;
typedef struct _nxge_dma_common_t nxge_dma_common_t, *p_nxge_dma_common_t;

typedef struct _nxge_dma_pool_t {
	p_nxge_dma_common_t	*dma_buf_pool_p;
	uint32_t		ndmas;
	uint32_t		*num_chunks;
	boolean_t		buf_allocated;
} nxge_dma_pool_t, *p_nxge_dma_pool_t;

/*
 * Each logical device (69):
 *	- LDG #
 *	- flag bits
 *	- masks.
 *	- interrupt handler function.
 *
 * Generic system interrupt handler with two arguments:
 *	(nxge_sys_intr_t)
 *	Per device instance data structure
 *	Logical group data structure.
 *
 * Logical device interrupt handler with two arguments:
 *	(nxge_ldv_intr_t)
 *	Per device instance data structure
 *	Logical device number
 */
typedef struct	_nxge_ldg_t nxge_ldg_t, *p_nxge_ldg_t;
typedef struct	_nxge_ldv_t nxge_ldv_t, *p_nxge_ldv_t;
typedef uint_t	(*nxge_sys_intr_t)(void *arg1, void *arg2);
typedef uint_t	(*nxge_ldv_intr_t)(void *arg1, void *arg2);

/*
 * Each logical device Group (64) needs to have the following
 * configurations:
 *	- timer counter (6 bits)
 *	- timer resolution (20 bits, number of system clocks)
 *	- system data (7 bits)
 */
struct _nxge_ldg_t {
	uint8_t			ldg;		/* logical group number */
	uint8_t			vldg_index;
	boolean_t		arm;
	boolean_t		interrupted;
	uint16_t		ldg_timer;	/* counter */
	uint8_t			func;
	uint8_t			vector;
	uint8_t			intdata;
	uint8_t			nldvs;
	p_nxge_ldv_t		ldvp;
	nxge_sys_intr_t		sys_intr_handler;
	uint_t			(*ih_cb_func)(caddr_t, caddr_t);
	p_nxge_t		nxgep;
};

struct _nxge_ldv_t {
	uint8_t			ldg_assigned;
	uint8_t			ldv;
	boolean_t		is_rxdma;
	boolean_t		is_txdma;
	boolean_t		is_mif;
	boolean_t		is_mac;
	boolean_t		is_syserr;
	boolean_t		use_timer;
	uint8_t			channel;
	uint8_t			vdma_index;
	uint8_t			func;
	p_nxge_ldg_t		ldgp;
	uint8_t			ldv_flags;
	boolean_t		is_leve;
	boolean_t		is_edge;
	uint8_t			ldv_ldf_masks;
	nxge_ldv_intr_t		ldv_intr_handler;
	uint_t			(*ih_cb_func)(caddr_t, caddr_t);
	p_nxge_t		nxgep;
};
#endif

typedef struct _nxge_logical_page_t {
	uint16_t		dma;
	uint16_t		page;
	boolean_t		valid;
	uint64_t		mask;
	uint64_t		value;
	uint64_t		reloc;
	uint32_t		handle;
} nxge_logical_page_t, *p_nxge_logical_page_t;

/*
 * (Internal) return values from ioctl subroutines.
 */
enum nxge_ioc_reply {
	IOC_INVAL = -1,				/* bad, NAK with EINVAL	*/
	IOC_DONE,				/* OK, reply sent	*/
	IOC_ACK,				/* OK, just send ACK	*/
	IOC_REPLY,				/* OK, just send reply	*/
	IOC_RESTART_ACK,			/* OK, restart & ACK	*/
	IOC_RESTART_REPLY			/* OK, restart & reply	*/
};

typedef struct _pci_cfg_t {
	uint16_t vendorid;
	uint16_t devid;
	uint16_t command;
	uint16_t status;
	uint8_t  revid;
	uint8_t  res0;
	uint16_t junk1;
	uint8_t  cache_line;
	uint8_t  latency;
	uint8_t  header;
	uint8_t  bist;
	uint32_t base;
	uint32_t base14;
	uint32_t base18;
	uint32_t base1c;
	uint32_t base20;
	uint32_t base24;
	uint32_t base28;
	uint32_t base2c;
	uint32_t base30;
	uint32_t res1[2];
	uint8_t int_line;
	uint8_t int_pin;
	uint8_t	min_gnt;
	uint8_t max_lat;
} pci_cfg_t, *p_pci_cfg_t;

#if defined(_KERNEL) || defined(COSIM)

typedef struct _dev_regs_t {
	nxge_os_acc_handle_t	nxge_pciregh;	/* PCI config DDI IO handle */
	p_pci_cfg_t		nxge_pciregp;	/* mapped PCI registers */

	nxge_os_acc_handle_t	nxge_regh;	/* device DDI IO (BAR 0) */
	void			*nxge_regp;	/* mapped device registers */

	nxge_os_acc_handle_t	nxge_msix_regh;	/* MSI/X DDI handle (BAR 2) */
	void 			*nxge_msix_regp; /* MSI/X register */

	nxge_os_acc_handle_t	nxge_vir_regh;	/* virtualization (BAR 4) */
	unsigned char		*nxge_vir_regp;	/* virtualization register */

	nxge_os_acc_handle_t	nxge_vir2_regh;	/* second virtualization */
	unsigned char		*nxge_vir2_regp; /* second virtualization */

	nxge_os_acc_handle_t	nxge_romh;	/* fcode rom handle */
	unsigned char		*nxge_romp;	/* fcode pointer */
} dev_regs_t, *p_dev_regs_t;

/*
 * Driver alternate mac address structure.
 */
typedef struct _nxge_mmac_t {
	kmutex_t	mmac_lock;
	uint8_t		max_num_mmac;	/* Max allocated per card */
	uint8_t		num_mmac;	/* Mac addr. per function */
	struct ether_addr mmac_pool[16]; /* Mac addr pool per function in s/w */
	boolean_t	rsv_mmac[16];	/* Reserved mac addr. in the pool */
	uint8_t		num_avail_mmac;	/* # of rsv.ed mac addr. in the pool */
} nxge_mmac_t;

/*
 * mmac stats structure
 */
typedef struct _nxge_mmac_stats_t {
	uint8_t mmac_max_cnt;
	uint8_t	mmac_avail_cnt;
	struct ether_addr mmac_avail_pool[16];
} nxge_mmac_stats_t, *p_nxge_mmac_stats_t;

#define	NXGE_MAX_MMAC_ADDRS	32
#define	NXGE_NUM_MMAC_ADDRS	8
#define	NXGE_NUM_OF_PORTS	4

#endif

#include 	<sys/nxge/nxge_common_impl.h>
#include 	<sys/nxge/nxge_common.h>
#include	<sys/nxge/nxge_txc.h>
#include	<sys/nxge/nxge_rxdma.h>
#include	<sys/nxge/nxge_txdma.h>
#include	<sys/nxge/nxge_fflp.h>
#include	<sys/nxge/nxge_ipp.h>
#include	<sys/nxge/nxge_zcp.h>
#include	<sys/nxge/nxge_fzc.h>
#include	<sys/nxge/nxge_flow.h>
#include	<sys/nxge/nxge_virtual.h>

#include 	<sys/nxge/nxge.h>

#include	<sys/modctl.h>
#include	<sys/pattr.h>

#include	<npi_vir.h>

/*
 * Reconfiguring the network devices requires the net_config privilege
 * in Solaris 10+.  Prior to this, root privilege is required.  In order
 * that the driver binary can run on both S10+ and earlier versions, we
 * make the decisiion as to which to use at runtime.  These declarations
 * allow for either (or both) to exist ...
 */
extern int secpolicy_net_config(const cred_t *, boolean_t);
extern int drv_priv(cred_t *);
extern void nxge_fm_report_error(p_nxge_t, uint8_t,
			uint8_t, nxge_fm_ereport_id_t);

#pragma weak    secpolicy_net_config

/* nxge_classify.c */
nxge_status_t nxge_classify_init(p_nxge_t);
nxge_status_t nxge_set_hw_classify_config(p_nxge_t);

/* nxge_fflp.c */
void nxge_put_tcam(p_nxge_t, p_mblk_t);
void nxge_get_tcam(p_nxge_t, p_mblk_t);
nxge_status_t nxge_classify_init_hw(p_nxge_t);
nxge_status_t nxge_classify_init_sw(p_nxge_t);
nxge_status_t nxge_fflp_ip_class_config_all(p_nxge_t);
nxge_status_t nxge_fflp_ip_class_config(p_nxge_t, tcam_class_t,
				    uint32_t);

nxge_status_t nxge_fflp_ip_class_config_get(p_nxge_t,
				    tcam_class_t,
				    uint32_t *);

nxge_status_t nxge_cfg_ip_cls_flow_key(p_nxge_t, tcam_class_t,
				    uint32_t);

nxge_status_t nxge_fflp_ip_usr_class_config(p_nxge_t, tcam_class_t,
				    uint32_t);

uint64_t nxge_classify_get_cfg_value(p_nxge_t, uint8_t, uint8_t);
nxge_status_t nxge_add_flow(p_nxge_t, flow_resource_t *);
nxge_status_t nxge_fflp_config_tcam_enable(p_nxge_t);
nxge_status_t nxge_fflp_config_tcam_disable(p_nxge_t);

nxge_status_t nxge_fflp_config_hash_lookup_enable(p_nxge_t);
nxge_status_t nxge_fflp_config_hash_lookup_disable(p_nxge_t);

nxge_status_t nxge_fflp_config_llc_snap_enable(p_nxge_t);
nxge_status_t nxge_fflp_config_llc_snap_disable(p_nxge_t);

nxge_status_t nxge_logical_mac_assign_rdc_table(p_nxge_t, uint8_t);
nxge_status_t nxge_fflp_config_vlan_table(p_nxge_t, uint16_t);

nxge_status_t nxge_fflp_set_hash1(p_nxge_t, uint32_t);

nxge_status_t nxge_fflp_set_hash2(p_nxge_t, uint16_t);

nxge_status_t nxge_fflp_init_hostinfo(p_nxge_t);

void nxge_handle_tcam_fragment_bug(p_nxge_t);
nxge_status_t nxge_fflp_hw_reset(p_nxge_t);
nxge_status_t nxge_fflp_handle_sys_errors(p_nxge_t);
nxge_status_t nxge_zcp_handle_sys_errors(p_nxge_t);

/* nxge_kstats.c */
void nxge_init_statsp(p_nxge_t);
void nxge_setup_kstats(p_nxge_t);
void nxge_destroy_kstats(p_nxge_t);
int nxge_port_kstat_update(kstat_t *, int);
void nxge_save_cntrs(p_nxge_t);

int nxge_m_stat(void *arg, uint_t, uint64_t *);

/* nxge_hw.c */
void
nxge_hw_ioctl(p_nxge_t, queue_t *, mblk_t *, struct iocblk *);
void nxge_loopback_ioctl(p_nxge_t, queue_t *, mblk_t *, struct iocblk *);
void nxge_global_reset(p_nxge_t);
uint_t nxge_intr(void *, void *);
void nxge_intr_enable(p_nxge_t);
void nxge_intr_disable(p_nxge_t);
void nxge_hw_blank(void *arg, time_t, uint_t);
void nxge_hw_id_init(p_nxge_t);
void nxge_hw_init_niu_common(p_nxge_t);
void nxge_intr_hw_enable(p_nxge_t);
void nxge_intr_hw_disable(p_nxge_t);
void nxge_hw_stop(p_nxge_t);
void nxge_global_reset(p_nxge_t);
void nxge_check_hw_state(p_nxge_t);

void nxge_rxdma_channel_put64(nxge_os_acc_handle_t,
	void *, uint32_t, uint16_t,
	uint64_t);
uint64_t nxge_rxdma_channel_get64(nxge_os_acc_handle_t, void *,
	uint32_t, uint16_t);


void nxge_get32(p_nxge_t, p_mblk_t);
void nxge_put32(p_nxge_t, p_mblk_t);

void nxge_hw_set_mac_modes(p_nxge_t);

/* nxge_send.c. */
uint_t nxge_reschedule(caddr_t);

/* nxge_rxdma.c */
nxge_status_t nxge_rxdma_cfg_rdcgrp_default_rdc(p_nxge_t,
					    uint8_t, uint8_t);

nxge_status_t nxge_rxdma_cfg_port_default_rdc(p_nxge_t,
				    uint8_t, uint8_t);
nxge_status_t nxge_rxdma_cfg_rcr_threshold(p_nxge_t, uint8_t,
				    uint16_t);
nxge_status_t nxge_rxdma_cfg_rcr_timeout(p_nxge_t, uint8_t,
				    uint16_t, uint8_t);

/* nxge_ndd.c */
void nxge_get_param_soft_properties(p_nxge_t);
void nxge_copy_hw_default_to_param(p_nxge_t);
void nxge_copy_param_hw_to_config(p_nxge_t);
void nxge_setup_param(p_nxge_t);
void nxge_init_param(p_nxge_t);
void nxge_destroy_param(p_nxge_t);
boolean_t nxge_check_rxdma_rdcgrp_member(p_nxge_t, uint8_t, uint8_t);
boolean_t nxge_check_rxdma_port_member(p_nxge_t, uint8_t);
boolean_t nxge_check_rdcgrp_port_member(p_nxge_t, uint8_t);

boolean_t nxge_check_txdma_port_member(p_nxge_t, uint8_t);

int nxge_param_get_generic(p_nxge_t, queue_t *, mblk_t *, caddr_t);
int nxge_param_set_generic(p_nxge_t, queue_t *, mblk_t *, char *, caddr_t);
int nxge_get_default(p_nxge_t, queue_t *, p_mblk_t, caddr_t);
int nxge_set_default(p_nxge_t, queue_t *, p_mblk_t, char *, caddr_t);
int nxge_nd_get_names(p_nxge_t, queue_t *, p_mblk_t, caddr_t);
int nxge_mk_mblk_tail_space(p_mblk_t, p_mblk_t *, size_t);
long nxge_strtol(char *, char **, int);
boolean_t nxge_param_get_instance(queue_t *, mblk_t *);
void nxge_param_ioctl(p_nxge_t, queue_t *, mblk_t *, struct iocblk *);
boolean_t nxge_nd_load(caddr_t *, char *, pfi_t, pfi_t, caddr_t);
void nxge_nd_free(caddr_t *);
int nxge_nd_getset(p_nxge_t, queue_t *, caddr_t, p_mblk_t);

void nxge_set_lb_normal(p_nxge_t);
boolean_t nxge_set_lb(p_nxge_t, queue_t *, p_mblk_t);

/* nxge_virtual.c */
nxge_status_t nxge_cntlops(dev_info_t *, nxge_ctl_enum_t, void *, void *);
void nxge_common_lock_get(p_nxge_t);
void nxge_common_lock_free(p_nxge_t);

nxge_status_t nxge_get_config_properties(p_nxge_t);
void nxge_get_xcvr_properties(p_nxge_t);
void nxge_init_vlan_config(p_nxge_t);
void nxge_init_mac_config(p_nxge_t);


void nxge_init_logical_devs(p_nxge_t);
int nxge_init_ldg_intrs(p_nxge_t);

void nxge_set_ldgimgmt(p_nxge_t, uint32_t, boolean_t,
	uint32_t);

void nxge_init_fzc_txdma_channels(p_nxge_t);

nxge_status_t nxge_init_fzc_txdma_channel(p_nxge_t, uint16_t,
	p_tx_ring_t, p_tx_mbox_t);
nxge_status_t nxge_init_fzc_txdma_port(p_nxge_t);

nxge_status_t nxge_init_fzc_rxdma_channel(p_nxge_t, uint16_t,
	p_rx_rbr_ring_t, p_rx_rcr_ring_t, p_rx_mbox_t);

nxge_status_t nxge_init_fzc_rdc_tbl(p_nxge_t);
nxge_status_t nxge_init_fzc_rx_common(p_nxge_t);
nxge_status_t nxge_init_fzc_rxdma_port(p_nxge_t);

nxge_status_t nxge_init_fzc_rxdma_channel_pages(p_nxge_t,
	uint16_t, p_rx_rbr_ring_t);
nxge_status_t nxge_init_fzc_rxdma_channel_red(p_nxge_t,
	uint16_t, p_rx_rcr_ring_t);

nxge_status_t nxge_init_fzc_rxdma_channel_clrlog(p_nxge_t,
	uint16_t, p_rx_rbr_ring_t);


nxge_status_t nxge_init_fzc_txdma_channel_pages(p_nxge_t,
	uint16_t, p_tx_ring_t);

nxge_status_t nxge_init_fzc_txdma_channel_drr(p_nxge_t, uint16_t,
	p_tx_ring_t);

nxge_status_t nxge_init_fzc_txdma_port(p_nxge_t);

void nxge_init_fzc_ldg_num(p_nxge_t);
void nxge_init_fzc_sys_int_data(p_nxge_t);
void nxge_init_fzc_ldg_int_timer(p_nxge_t);
nxge_status_t nxge_intr_mask_mgmt_set(p_nxge_t, boolean_t on);

/* MAC functions */
nxge_status_t nxge_mac_init(p_nxge_t);
nxge_status_t nxge_link_init(p_nxge_t);
nxge_status_t nxge_xif_init(p_nxge_t);
nxge_status_t nxge_pcs_init(p_nxge_t);
nxge_status_t nxge_serdes_init(p_nxge_t);
nxge_status_t nxge_n2_serdes_init(p_nxge_t);
nxge_status_t nxge_neptune_serdes_init(p_nxge_t);
nxge_status_t nxge_xcvr_find(p_nxge_t);
nxge_status_t nxge_get_xcvr_type(p_nxge_t);
nxge_status_t nxge_xcvr_init(p_nxge_t);
nxge_status_t nxge_tx_mac_init(p_nxge_t);
nxge_status_t nxge_rx_mac_init(p_nxge_t);
nxge_status_t nxge_tx_mac_enable(p_nxge_t);
nxge_status_t nxge_tx_mac_disable(p_nxge_t);
nxge_status_t nxge_rx_mac_enable(p_nxge_t);
nxge_status_t nxge_rx_mac_disable(p_nxge_t);
nxge_status_t nxge_tx_mac_reset(p_nxge_t);
nxge_status_t nxge_rx_mac_reset(p_nxge_t);
nxge_status_t nxge_link_intr(p_nxge_t, link_intr_enable_t);
nxge_status_t nxge_mii_xcvr_init(p_nxge_t);
nxge_status_t nxge_mii_read(p_nxge_t, uint8_t,
			uint8_t, uint16_t *);
nxge_status_t nxge_mii_write(p_nxge_t, uint8_t,
			uint8_t, uint16_t);
nxge_status_t nxge_mdio_read(p_nxge_t, uint8_t, uint8_t,
			uint16_t, uint16_t *);
nxge_status_t nxge_mdio_write(p_nxge_t, uint8_t,
			uint8_t, uint16_t, uint16_t);
nxge_status_t nxge_mii_check(p_nxge_t, mii_bmsr_t,
			mii_bmsr_t);
nxge_status_t nxge_add_mcast_addr(p_nxge_t, struct ether_addr *);
nxge_status_t nxge_del_mcast_addr(p_nxge_t, struct ether_addr *);
nxge_status_t nxge_set_mac_addr(p_nxge_t, struct ether_addr *);
nxge_status_t nxge_check_mii_link(p_nxge_t);
nxge_status_t nxge_check_10g_link(p_nxge_t);
nxge_status_t nxge_check_serdes_link(p_nxge_t);
nxge_status_t nxge_check_bcm8704_link(p_nxge_t, boolean_t *);
void nxge_link_is_down(p_nxge_t);
void nxge_link_is_up(p_nxge_t);
nxge_status_t nxge_link_monitor(p_nxge_t, link_mon_enable_t);
uint32_t crc32_mchash(p_ether_addr_t);
nxge_status_t nxge_set_promisc(p_nxge_t, boolean_t);
nxge_status_t nxge_mac_handle_sys_errors(p_nxge_t);
nxge_status_t nxge_10g_link_led_on(p_nxge_t);
nxge_status_t nxge_10g_link_led_off(p_nxge_t);

/* espc (sprom) prototypes */
nxge_status_t nxge_espc_mac_addrs_get(p_nxge_t);
nxge_status_t nxge_espc_num_macs_get(p_nxge_t, uint8_t *);
nxge_status_t nxge_espc_num_ports_get(p_nxge_t);
nxge_status_t nxge_espc_phy_type_get(p_nxge_t);


void nxge_debug_msg(p_nxge_t, uint64_t, char *, ...);

uint64_t hv_niu_rx_logical_page_conf(uint64_t, uint64_t,
	uint64_t, uint64_t);
#pragma weak	hv_niu_rx_logical_page_conf

uint64_t hv_niu_rx_logical_page_info(uint64_t, uint64_t,
	uint64_t *, uint64_t *);
#pragma weak	hv_niu_rx_logical_page_info

uint64_t hv_niu_tx_logical_page_conf(uint64_t, uint64_t,
	uint64_t, uint64_t);
#pragma weak	hv_niu_tx_logical_page_conf

uint64_t hv_niu_tx_logical_page_info(uint64_t, uint64_t,
	uint64_t *, uint64_t *);
#pragma weak	hv_niu_tx_logical_page_info

#ifdef NXGE_DEBUG
char *nxge_dump_packet(char *, int);
#endif

#endif	/* !_ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NXGE_NXGE_IMPL_H */