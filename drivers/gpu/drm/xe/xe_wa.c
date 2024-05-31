// SPDX-License-Identifier: MIT
/*
 * Copyright © 2022 Intel Corporation
 */

#include "xe_wa.h"

#include <drm/drm_managed.h>
#include <kunit/visibility.h>
#include <linux/compiler_types.h>

#include "generated/xe_wa_oob.h"
#include "regs/xe_engine_regs.h"
#include "regs/xe_gt_regs.h"
#include "regs/xe_regs.h"
#include "xe_device_types.h"
#include "xe_force_wake.h"
#include "xe_gt.h"
#include "xe_hw_engine_types.h"
#include "xe_mmio.h"
#include "xe_platform_types.h"
#include "xe_rtp.h"
#include "xe_step.h"

/**
 * DOC: Hardware workarounds
 *
 * Hardware workarounds are register programming documented to be executed in
 * the driver that fall outside of the normal programming sequences for a
 * platform. There are some basic categories of workarounds, depending on
 * how/when they are applied:
 *
 * - LRC workarounds: workarounds that touch registers that are
 *   saved/restored to/from the HW context image. The list is emitted (via Load
 *   Register Immediate commands) once when initializing the device and saved in
 *   the default context. That default context is then used on every context
 *   creation to have a "primed golden context", i.e. a context image that
 *   already contains the changes needed to all the registers.
 *
 * - Engine workarounds: the list of these WAs is applied whenever the specific
 *   engine is reset. It's also possible that a set of engine classes share a
 *   common power domain and they are reset together. This happens on some
 *   platforms with render and compute engines. In this case (at least) one of
 *   them need to keeep the workaround programming: the approach taken in the
 *   driver is to tie those workarounds to the first compute/render engine that
 *   is registered.  When executing with GuC submission, engine resets are
 *   outside of kernel driver control, hence the list of registers involved in
 *   written once, on engine initialization, and then passed to GuC, that
 *   saves/restores their values before/after the reset takes place. See
 *   ``drivers/gpu/drm/xe/xe_guc_ads.c`` for reference.
 *
 * - GT workarounds: the list of these WAs is applied whenever these registers
 *   revert to their default values: on GPU reset, suspend/resume [1]_, etc.
 *
 * - Register whitelist: some workarounds need to be implemented in userspace,
 *   but need to touch privileged registers. The whitelist in the kernel
 *   instructs the hardware to allow the access to happen. From the kernel side,
 *   this is just a special case of a MMIO workaround (as we write the list of
 *   these to/be-whitelisted registers to some special HW registers).
 *
 * - Workaround batchbuffers: buffers that get executed automatically by the
 *   hardware on every HW context restore. These buffers are created and
 *   programmed in the default context so the hardware always go through those
 *   programming sequences when switching contexts. The support for workaround
 *   batchbuffers is enabled these hardware mechanisms:
 *
 *   #. INDIRECT_CTX: A batchbuffer and an offset are provided in the default
 *      context, pointing the hardware to jump to that location when that offset
 *      is reached in the context restore. Workaround batchbuffer in the driver
 *      currently uses this mechanism for all platforms.
 *
 *   #. BB_PER_CTX_PTR: A batchbuffer is provided in the default context,
 *      pointing the hardware to a buffer to continue executing after the
 *      engine registers are restored in a context restore sequence. This is
 *      currently not used in the driver.
 *
 * - Other/OOB:  There are WAs that, due to their nature, cannot be applied from
 *   a central place. Those are peppered around the rest of the code, as needed.
 *   Workarounds related to the display IP are the main example.
 *
 * .. [1] Technically, some registers are powercontext saved & restored, so they
 *    survive a suspend/resume. In practice, writing them again is not too
 *    costly and simplifies things, so it's the approach taken in the driver.
 *
 * .. note::
 *    Hardware workarounds in xe work the same way as in i915, with the
 *    difference of how they are maintained in the code. In xe it uses the
 *    xe_rtp infrastructure so the workarounds can be kept in tables, following
 *    a more declarative approach rather than procedural.
 */

#undef XE_REG_MCR
#define XE_REG_MCR(...)     XE_REG(__VA_ARGS__, .mcr = 1)

__diag_push();
__diag_ignore_all("-Woverride-init", "Allow field overrides in table");

static const struct xe_rtp_entry_sr gt_was[] = {
	{ XE_RTP_NAME("14011060649"),
	  XE_RTP_RULES(MEDIA_VERSION_RANGE(1200, 1255),
		       ENGINE_CLASS(VIDEO_DECODE),
		       FUNC(xe_rtp_match_even_instance)),
	  XE_RTP_ACTIONS(SET(VDBOX_CGCTL3F10(0), IECPUNIT_CLKGATE_DIS)),
	  XE_RTP_ENTRY_FLAG(FOREACH_ENGINE),
	},
	{ XE_RTP_NAME("14011059788"),
	  XE_RTP_RULES(GRAPHICS_VERSION_RANGE(1200, 1210)),
	  XE_RTP_ACTIONS(SET(DFR_RATIO_EN_AND_CHICKEN, DFR_DISABLE))
	},
	{ XE_RTP_NAME("14015795083"),
	  XE_RTP_RULES(GRAPHICS_VERSION_RANGE(1200, 1260)),
	  XE_RTP_ACTIONS(CLR(MISCCPCTL, DOP_CLOCK_GATE_RENDER_ENABLE))
	},

	/* DG1 */

	{ XE_RTP_NAME("1409420604"),
	  XE_RTP_RULES(PLATFORM(DG1)),
	  XE_RTP_ACTIONS(SET(SUBSLICE_UNIT_LEVEL_CLKGATE2, CPSSUNIT_CLKGATE_DIS))
	},
	{ XE_RTP_NAME("1408615072"),
	  XE_RTP_RULES(PLATFORM(DG1)),
	  XE_RTP_ACTIONS(SET(UNSLICE_UNIT_LEVEL_CLKGATE2, VSUNIT_CLKGATE2_DIS))
	},

	/* DG2 */

	{ XE_RTP_NAME("16010515920"),
	  XE_RTP_RULES(SUBPLATFORM(DG2, G10),
		       GRAPHICS_STEP(A0, B0),
		       ENGINE_CLASS(VIDEO_DECODE)),
	  XE_RTP_ACTIONS(SET(VDBOX_CGCTL3F18(0), ALNUNIT_CLKGATE_DIS)),
	  XE_RTP_ENTRY_FLAG(FOREACH_ENGINE),
	},
	{ XE_RTP_NAME("22010523718"),
	  XE_RTP_RULES(SUBPLATFORM(DG2, G10)),
	  XE_RTP_ACTIONS(SET(UNSLICE_UNIT_LEVEL_CLKGATE, CG3DDISCFEG_CLKGATE_DIS))
	},
	{ XE_RTP_NAME("14011006942"),
	  XE_RTP_RULES(SUBPLATFORM(DG2, G10)),
	  XE_RTP_ACTIONS(SET(SUBSLICE_UNIT_LEVEL_CLKGATE, DSS_ROUTER_CLKGATE_DIS))
	},
	{ XE_RTP_NAME("14012362059"),
	  XE_RTP_RULES(SUBPLATFORM(DG2, G10), GRAPHICS_STEP(A0, B0)),
	  XE_RTP_ACTIONS(SET(XEHP_MERT_MOD_CTRL, FORCE_MISS_FTLB))
	},
	{ XE_RTP_NAME("14012362059"),
	  XE_RTP_RULES(SUBPLATFORM(DG2, G11), GRAPHICS_STEP(A0, B0)),
	  XE_RTP_ACTIONS(SET(XEHP_MERT_MOD_CTRL, FORCE_MISS_FTLB))
	},
	{ XE_RTP_NAME("14010948348"),
	  XE_RTP_RULES(SUBPLATFORM(DG2, G10), GRAPHICS_STEP(A0, B0)),
	  XE_RTP_ACTIONS(SET(UNSLCGCTL9430, MSQDUNIT_CLKGATE_DIS))
	},
	{ XE_RTP_NAME("14011037102"),
	  XE_RTP_RULES(SUBPLATFORM(DG2, G10), GRAPHICS_STEP(A0, B0)),
	  XE_RTP_ACTIONS(SET(UNSLCGCTL9444, LTCDD_CLKGATE_DIS))
	},
	{ XE_RTP_NAME("14011371254"),
	  XE_RTP_RULES(SUBPLATFORM(DG2, G10), GRAPHICS_STEP(A0, B0)),
	  XE_RTP_ACTIONS(SET(XEHP_SLICE_UNIT_LEVEL_CLKGATE, NODEDSS_CLKGATE_DIS))
	},
	{ XE_RTP_NAME("14011431319"),
	  XE_RTP_RULES(SUBPLATFORM(DG2, G10), GRAPHICS_STEP(A0, B0)),
	  XE_RTP_ACTIONS(SET(UNSLCGCTL9440,
			     GAMTLBOACS_CLKGATE_DIS |
			     GAMTLBVDBOX7_CLKGATE_DIS | GAMTLBVDBOX6_CLKGATE_DIS |
			     GAMTLBVDBOX5_CLKGATE_DIS | GAMTLBVDBOX4_CLKGATE_DIS |
			     GAMTLBVDBOX3_CLKGATE_DIS | GAMTLBVDBOX2_CLKGATE_DIS |
			     GAMTLBVDBOX1_CLKGATE_DIS | GAMTLBVDBOX0_CLKGATE_DIS |
			     GAMTLBKCR_CLKGATE_DIS | GAMTLBGUC_CLKGATE_DIS |
			     GAMTLBBLT_CLKGATE_DIS),
			 SET(UNSLCGCTL9444,
			     GAMTLBGFXA0_CLKGATE_DIS | GAMTLBGFXA1_CLKGATE_DIS |
			     GAMTLBCOMPA0_CLKGATE_DIS | GAMTLBCOMPA1_CLKGATE_DIS |
			     GAMTLBCOMPB0_CLKGATE_DIS | GAMTLBCOMPB1_CLKGATE_DIS |
			     GAMTLBCOMPC0_CLKGATE_DIS | GAMTLBCOMPC1_CLKGATE_DIS |
			     GAMTLBCOMPD0_CLKGATE_DIS | GAMTLBCOMPD1_CLKGATE_DIS |
			     GAMTLBMERT_CLKGATE_DIS |
			     GAMTLBVEBOX3_CLKGATE_DIS | GAMTLBVEBOX2_CLKGATE_DIS |
			     GAMTLBVEBOX1_CLKGATE_DIS | GAMTLBVEBOX0_CLKGATE_DIS))
	},
	{ XE_RTP_NAME("14010569222"),
	  XE_RTP_RULES(SUBPLATFORM(DG2, G10), GRAPHICS_STEP(A0, B0)),
	  XE_RTP_ACTIONS(SET(UNSLICE_UNIT_LEVEL_CLKGATE, GAMEDIA_CLKGATE_DIS))
	},
	{ XE_RTP_NAME("14011028019"),
	  XE_RTP_RULES(SUBPLATFORM(DG2, G10), GRAPHICS_STEP(A0, B0)),
	  XE_RTP_ACTIONS(SET(SSMCGCTL9530, RTFUNIT_CLKGATE_DIS))
	},
	{ XE_RTP_NAME("14010680813"),
	  XE_RTP_RULES(SUBPLATFORM(DG2, G10), GRAPHICS_STEP(A0, B0)),
	  XE_RTP_ACTIONS(SET(XEHP_GAMSTLB_CTRL,
			     CONTROL_BLOCK_CLKGATE_DIS |
			     EGRESS_BLOCK_CLKGATE_DIS |
			     TAG_BLOCK_CLKGATE_DIS))
	},
	{ XE_RTP_NAME("14014830051"),
	  XE_RTP_RULES(PLATFORM(DG2)),
	  XE_RTP_ACTIONS(CLR(SARB_CHICKEN1, COMP_CKN_IN))
	},
	{ XE_RTP_NAME("18018781329"),
	  XE_RTP_RULES(PLATFORM(DG2)),
	  XE_RTP_ACTIONS(SET(RENDER_MOD_CTRL, FORCE_MISS_FTLB),
			 SET(COMP_MOD_CTRL, FORCE_MISS_FTLB),
			 SET(XEHP_VDBX_MOD_CTRL, FORCE_MISS_FTLB),
			 SET(XEHP_VEBX_MOD_CTRL, FORCE_MISS_FTLB))
	},
	{ XE_RTP_NAME("1509235366"),
	  XE_RTP_RULES(PLATFORM(DG2)),
	  XE_RTP_ACTIONS(SET(XEHP_GAMCNTRL_CTRL,
			     INVALIDATION_BROADCAST_MODE_DIS |
			     GLOBAL_INVALIDATION_MODE))
	},
	{ XE_RTP_NAME("14010648519"),
	  XE_RTP_RULES(PLATFORM(DG2)),
	  XE_RTP_ACTIONS(SET(XEHP_L3NODEARBCFG, XEHP_LNESPARE))
	},

	/* PVC */

	{ XE_RTP_NAME("18018781329"),
	  XE_RTP_RULES(PLATFORM(PVC)),
	  XE_RTP_ACTIONS(SET(RENDER_MOD_CTRL, FORCE_MISS_FTLB),
			 SET(COMP_MOD_CTRL, FORCE_MISS_FTLB),
			 SET(XEHP_VDBX_MOD_CTRL, FORCE_MISS_FTLB),
			 SET(XEHP_VEBX_MOD_CTRL, FORCE_MISS_FTLB))
	},
	{ XE_RTP_NAME("16016694945"),
	  XE_RTP_RULES(PLATFORM(PVC)),
	  XE_RTP_ACTIONS(SET(XEHPC_LNCFMISCCFGREG0, XEHPC_OVRLSCCC))
	},

	/* Xe_LPG */

	{ XE_RTP_NAME("14015795083"),
	  XE_RTP_RULES(GRAPHICS_VERSION_RANGE(1270, 1271), GRAPHICS_STEP(A0, B0)),
	  XE_RTP_ACTIONS(CLR(MISCCPCTL, DOP_CLOCK_GATE_RENDER_ENABLE))
	},
	{ XE_RTP_NAME("14018575942"),
	  XE_RTP_RULES(GRAPHICS_VERSION_RANGE(1270, 1271)),
	  XE_RTP_ACTIONS(SET(COMP_MOD_CTRL, FORCE_MISS_FTLB))
	},
	{ XE_RTP_NAME("22016670082"),
	  XE_RTP_RULES(GRAPHICS_VERSION_RANGE(1270, 1271)),
	  XE_RTP_ACTIONS(SET(SQCNT1, ENFORCE_RAR))
	},

	/* Xe_LPM+ */

	{ XE_RTP_NAME("16021867713"),
	  XE_RTP_RULES(MEDIA_VERSION(1300),
		       ENGINE_CLASS(VIDEO_DECODE)),
	  XE_RTP_ACTIONS(SET(VDBOX_CGCTL3F1C(0), MFXPIPE_CLKGATE_DIS)),
	  XE_RTP_ENTRY_FLAG(FOREACH_ENGINE),
	},
	{ XE_RTP_NAME("22016670082"),
	  XE_RTP_RULES(MEDIA_VERSION(1300)),
	  XE_RTP_ACTIONS(SET(XELPMP_SQCNT1, ENFORCE_RAR))
	},

	/* Xe2_LPG */

	{ XE_RTP_NAME("16020975621"),
	  XE_RTP_RULES(GRAPHICS_VERSION(2004), GRAPHICS_STEP(A0, B0)),
	  XE_RTP_ACTIONS(SET(XEHP_SLICE_UNIT_LEVEL_CLKGATE, SBEUNIT_CLKGATE_DIS))
	},
	{ XE_RTP_NAME("14018157293"),
	  XE_RTP_RULES(GRAPHICS_VERSION(2004), GRAPHICS_STEP(A0, B0)),
	  XE_RTP_ACTIONS(SET(XEHPC_L3CLOS_MASK(0), ~0),
			 SET(XEHPC_L3CLOS_MASK(1), ~0),
			 SET(XEHPC_L3CLOS_MASK(2), ~0),
			 SET(XEHPC_L3CLOS_MASK(3), ~0))
	},

	/* Xe2_LPM */

	{ XE_RTP_NAME("14017421178"),
	  XE_RTP_RULES(MEDIA_VERSION(2000),
		       ENGINE_CLASS(VIDEO_DECODE)),
	  XE_RTP_ACTIONS(SET(VDBOX_CGCTL3F10(0), IECPUNIT_CLKGATE_DIS)),
	  XE_RTP_ENTRY_FLAG(FOREACH_ENGINE),
	},
	{ XE_RTP_NAME("16021867713"),
	  XE_RTP_RULES(MEDIA_VERSION(2000),
		       ENGINE_CLASS(VIDEO_DECODE)),
	  XE_RTP_ACTIONS(SET(VDBOX_CGCTL3F1C(0), MFXPIPE_CLKGATE_DIS)),
	  XE_RTP_ENTRY_FLAG(FOREACH_ENGINE),
	},
	{ XE_RTP_NAME("14019449301"),
	  XE_RTP_RULES(MEDIA_VERSION(2000), ENGINE_CLASS(VIDEO_DECODE)),
	  XE_RTP_ACTIONS(SET(VDBOX_CGCTL3F08(0), CG3DDISHRS_CLKGATE_DIS)),
	  XE_RTP_ENTRY_FLAG(FOREACH_ENGINE),
	},

	{}
};

static const struct xe_rtp_entry_sr engine_was[] = {
	{ XE_RTP_NAME("22010931296, 18011464164, 14010919138"),
	  XE_RTP_RULES(GRAPHICS_VERSION(1200), ENGINE_CLASS(RENDER)),
	  XE_RTP_ACTIONS(SET(FF_THREAD_MODE(RENDER_RING_BASE),
			     FF_TESSELATION_DOP_GATE_DISABLE))
	},
	{ XE_RTP_NAME("1409804808"),
	  XE_RTP_RULES(GRAPHICS_VERSION(1200),
		       ENGINE_CLASS(RENDER),
		       IS_INTEGRATED),
	  XE_RTP_ACTIONS(SET(ROW_CHICKEN2, PUSH_CONST_DEREF_HOLD_DIS))
	},
	{ XE_RTP_NAME("14010229206, 1409085225"),
	  XE_RTP_RULES(GRAPHICS_VERSION(1200),
		       ENGINE_CLASS(RENDER),
		       IS_INTEGRATED),
	  XE_RTP_ACTIONS(SET(ROW_CHICKEN4, DISABLE_TDL_PUSH))
	},
	{ XE_RTP_NAME("1606931601"),
	  XE_RTP_RULES(GRAPHICS_VERSION_RANGE(1200, 1210), ENGINE_CLASS(RENDER)),
	  XE_RTP_ACTIONS(SET(ROW_CHICKEN2, DISABLE_EARLY_READ))
	},
	{ XE_RTP_NAME("14010826681, 1606700617, 22010271021, 18019627453"),
	  XE_RTP_RULES(GRAPHICS_VERSION_RANGE(1200, 1255), ENGINE_CLASS(RENDER)),
	  XE_RTP_ACTIONS(SET(CS_DEBUG_MODE1(RENDER_RING_BASE),
			     FF_DOP_CLOCK_GATE_DISABLE))
	},
	{ XE_RTP_NAME("1406941453"),
	  XE_RTP_RULES(GRAPHICS_VERSION_RANGE(1200, 1210), ENGINE_CLASS(RENDER)),
	  XE_RTP_ACTIONS(SET(SAMPLER_MODE, ENABLE_SMALLPL))
	},
	{ XE_RTP_NAME("FtrPerCtxtPreemptionGranularityControl"),
	  XE_RTP_RULES(GRAPHICS_VERSION_RANGE(1200, 1250), ENGINE_CLASS(RENDER)),
	  XE_RTP_ACTIONS(SET(FF_SLICE_CS_CHICKEN1(RENDER_RING_BASE),
			     FFSC_PERCTX_PREEMPT_CTRL))
	},

	/* TGL */

	{ XE_RTP_NAME("1607297627, 1607030317, 1607186500"),
	  XE_RTP_RULES(PLATFORM(TIGERLAKE), ENGINE_CLASS(RENDER)),
	  XE_RTP_ACTIONS(SET(RING_PSMI_CTL(RENDER_RING_BASE),
			     WAIT_FOR_EVENT_POWER_DOWN_DISABLE |
			     RC_SEMA_IDLE_MSG_DISABLE))
	},

	/* RKL */

	{ XE_RTP_NAME("1607297627, 1607030317, 1607186500"),
	  XE_RTP_RULES(PLATFORM(ROCKETLAKE), ENGINE_CLASS(RENDER)),
	  XE_RTP_ACTIONS(SET(RING_PSMI_CTL(RENDER_RING_BASE),
			     WAIT_FOR_EVENT_POWER_DOWN_DISABLE |
			     RC_SEMA_IDLE_MSG_DISABLE))
	},

	/* ADL-P */

	{ XE_RTP_NAME("1607297627, 1607030317, 1607186500"),
	  XE_RTP_RULES(PLATFORM(ALDERLAKE_P), ENGINE_CLASS(RENDER)),
	  XE_RTP_ACTIONS(SET(RING_PSMI_CTL(RENDER_RING_BASE),
			     WAIT_FOR_EVENT_POWER_DOWN_DISABLE |
			     RC_SEMA_IDLE_MSG_DISABLE))
	},

	/* DG2 */

	{ XE_RTP_NAME("22013037850"),
	  XE_RTP_RULES(PLATFORM(DG2), FUNC(xe_rtp_match_first_render_or_compute)),
	  XE_RTP_ACTIONS(SET(LSC_CHICKEN_BIT_0_UDW,
			     DISABLE_128B_EVICTION_COMMAND_UDW))
	},
	{ XE_RTP_NAME("22014226127"),
	  XE_RTP_RULES(PLATFORM(DG2), FUNC(xe_rtp_match_first_render_or_compute)),
	  XE_RTP_ACTIONS(SET(LSC_CHICKEN_BIT_0, DISABLE_D8_D16_COASLESCE))
	},
	{ XE_RTP_NAME("18017747507"),
	  XE_RTP_RULES(PLATFORM(DG2), FUNC(xe_rtp_match_first_render_or_compute)),
	  XE_RTP_ACTIONS(SET(VFG_PREEMPTION_CHICKEN,
			     POLYGON_TRIFAN_LINELOOP_DISABLE))
	},
	{ XE_RTP_NAME("22012826095, 22013059131"),
	  XE_RTP_RULES(SUBPLATFORM(DG2, G10), GRAPHICS_STEP(B0, C0),
		       FUNC(xe_rtp_match_first_render_or_compute)),
	  XE_RTP_ACTIONS(FIELD_SET(LSC_CHICKEN_BIT_0_UDW,
				   MAXREQS_PER_BANK,
				   REG_FIELD_PREP(MAXREQS_PER_BANK, 2)))
	},
	{ XE_RTP_NAME("22012826095, 22013059131"),
	  XE_RTP_RULES(SUBPLATFORM(DG2, G11),
		       FUNC(xe_rtp_match_first_render_or_compute)),
	  XE_RTP_ACTIONS(FIELD_SET(LSC_CHICKEN_BIT_0_UDW,
				   MAXREQS_PER_BANK,
				   REG_FIELD_PREP(MAXREQS_PER_BANK, 2)))
	},
	{ XE_RTP_NAME("22013059131"),
	  XE_RTP_RULES(SUBPLATFORM(DG2, G10), GRAPHICS_STEP(B0, C0),
		       FUNC(xe_rtp_match_first_render_or_compute)),
	  XE_RTP_ACTIONS(SET(LSC_CHICKEN_BIT_0, FORCE_1_SUB_MESSAGE_PER_FRAGMENT))
	},
	{ XE_RTP_NAME("22013059131"),
	  XE_RTP_RULES(SUBPLATFORM(DG2, G11),
		       FUNC(xe_rtp_match_first_render_or_compute)),
	  XE_RTP_ACTIONS(SET(LSC_CHICKEN_BIT_0, FORCE_1_SUB_MESSAGE_PER_FRAGMENT))
	},
	{ XE_RTP_NAME("14010918519"),
	  XE_RTP_RULES(SUBPLATFORM(DG2, G10), GRAPHICS_STEP(A0, B0),
		       FUNC(xe_rtp_match_first_render_or_compute)),
	  XE_RTP_ACTIONS(SET(LSC_CHICKEN_BIT_0_UDW,
			     FORCE_SLM_FENCE_SCOPE_TO_TILE |
			     FORCE_UGM_FENCE_SCOPE_TO_TILE,
			     /*
			      * Ignore read back as it always returns 0 in these
			      * steps
			      */
			     .read_mask = 0))
	},
	{ XE_RTP_NAME("14015227452"),
	  XE_RTP_RULES(PLATFORM(DG2),
		       FUNC(xe_rtp_match_first_render_or_compute)),
	  XE_RTP_ACTIONS(SET(ROW_CHICKEN4, XEHP_DIS_BBL_SYSPIPE))
	},
	{ XE_RTP_NAME("16015675438"),
	  XE_RTP_RULES(PLATFORM(DG2),
		       FUNC(xe_rtp_match_first_render_or_compute)),
	  XE_RTP_ACTIONS(SET(FF_SLICE_CS_CHICKEN2(RENDER_RING_BASE),
			     PERF_FIX_BALANCING_CFE_DISABLE))
	},
	{ XE_RTP_NAME("18028616096"),
	  XE_RTP_RULES(PLATFORM(DG2),
		       FUNC(xe_rtp_match_first_render_or_compute)),
	  XE_RTP_ACTIONS(SET(LSC_CHICKEN_BIT_0_UDW, UGM_FRAGMENT_THRESHOLD_TO_3))
	},
	{ XE_RTP_NAME("16011620976, 22015475538"),
	  XE_RTP_RULES(PLATFORM(DG2),
		       FUNC(xe_rtp_match_first_render_or_compute)),
	  XE_RTP_ACTIONS(SET(LSC_CHICKEN_BIT_0_UDW, DIS_CHAIN_2XSIMD8))
	},
	{ XE_RTP_NAME("22012654132"),
	  XE_RTP_RULES(SUBPLATFORM(DG2, G10), GRAPHICS_STEP(A0, C0),
		       FUNC(xe_rtp_match_first_render_or_compute)),
	  XE_RTP_ACTIONS(SET(CACHE_MODE_SS, ENABLE_PREFETCH_INTO_IC,
			     /*
			      * Register can't be read back for verification on
			      * DG2 due to Wa_14012342262
			      */
			     .read_mask = 0))
	},
	{ XE_RTP_NAME("22012654132"),
	  XE_RTP_RULES(SUBPLATFORM(DG2, G11),
		       FUNC(xe_rtp_match_first_render_or_compute)),
	  XE_RTP_ACTIONS(SET(CACHE_MODE_SS, ENABLE_PREFETCH_INTO_IC,
			     /*
			      * Register can't be read back for verification on
			      * DG2 due to Wa_14012342262
			      */
			     .read_mask = 0))
	},
	{ XE_RTP_NAME("1509727124"),
	  XE_RTP_RULES(PLATFORM(DG2), ENGINE_CLASS(RENDER)),
	  XE_RTP_ACTIONS(SET(SAMPLER_MODE, SC_DISABLE_POWER_OPTIMIZATION_EBB))
	},
	{ XE_RTP_NAME("22012856258"),
	  XE_RTP_RULES(PLATFORM(DG2), ENGINE_CLASS(RENDER)),
	  XE_RTP_ACTIONS(SET(ROW_CHICKEN2, DISABLE_READ_SUPPRESSION))
	},
	{ XE_RTP_NAME("14013392000"),
	  XE_RTP_RULES(SUBPLATFORM(DG2, G11), GRAPHICS_STEP(A0, B0),
		       ENGINE_CLASS(RENDER)),
	  XE_RTP_ACTIONS(SET(ROW_CHICKEN2, ENABLE_LARGE_GRF_MODE))
	},
	{ XE_RTP_NAME("14012419201"),
	  XE_RTP_RULES(SUBPLATFORM(DG2, G10), GRAPHICS_STEP(A0, B0),
		       ENGINE_CLASS(RENDER)),
	  XE_RTP_ACTIONS(SET(ROW_CHICKEN4,
			     DISABLE_HDR_PAST_PAYLOAD_HOLD_FIX))
	},
	{ XE_RTP_NAME("14012419201"),
	  XE_RTP_RULES(SUBPLATFORM(DG2, G11), GRAPHICS_STEP(A0, B0),
		       ENGINE_CLASS(RENDER)),
	  XE_RTP_ACTIONS(SET(ROW_CHICKEN4,
			     DISABLE_HDR_PAST_PAYLOAD_HOLD_FIX))
	},
	{ XE_RTP_NAME("1308578152"),
	  XE_RTP_RULES(SUBPLATFORM(DG2, G10), GRAPHICS_STEP(B0, C0),
		       ENGINE_CLASS(RENDER),
		       FUNC(xe_rtp_match_first_gslice_fused_off)),
	  XE_RTP_ACTIONS(CLR(CS_DEBUG_MODE1(RENDER_RING_BASE),
			     REPLAY_MODE_GRANULARITY))
	},
	{ XE_RTP_NAME("22010960976, 14013347512"),
	  XE_RTP_RULES(PLATFORM(DG2), ENGINE_CLASS(RENDER)),
	  XE_RTP_ACTIONS(CLR(XEHP_HDC_CHICKEN0,
			     LSC_L1_FLUSH_CTL_3D_DATAPORT_FLUSH_EVENTS_MASK))
	},
	{ XE_RTP_NAME("1608949956, 14010198302"),
	  XE_RTP_RULES(PLATFORM(DG2), ENGINE_CLASS(RENDER)),
	  XE_RTP_ACTIONS(SET(ROW_CHICKEN,
			     MDQ_ARBITRATION_MODE | UGM_BACKUP_MODE))
	},
	{ XE_RTP_NAME("22010430635"),
	  XE_RTP_RULES(SUBPLATFORM(DG2, G10), GRAPHICS_STEP(A0, B0),
		       ENGINE_CLASS(RENDER)),
	  XE_RTP_ACTIONS(SET(ROW_CHICKEN4,
			     DISABLE_GRF_CLEAR))
	},
	{ XE_RTP_NAME("14013202645"),
	  XE_RTP_RULES(SUBPLATFORM(DG2, G10), GRAPHICS_STEP(B0, C0),
		       ENGINE_CLASS(RENDER)),
	  XE_RTP_ACTIONS(SET(RT_CTRL, DIS_NULL_QUERY))
	},
	{ XE_RTP_NAME("14013202645"),
	  XE_RTP_RULES(SUBPLATFORM(DG2, G11), GRAPHICS_STEP(A0, B0),
		       ENGINE_CLASS(RENDER)),
	  XE_RTP_ACTIONS(SET(RT_CTRL, DIS_NULL_QUERY))
	},
	{ XE_RTP_NAME("22012532006"),
	  XE_RTP_RULES(SUBPLATFORM(DG2, G10), GRAPHICS_STEP(A0, C0),
		       ENGINE_CLASS(RENDER)),
	  XE_RTP_ACTIONS(SET(HALF_SLICE_CHICKEN7,
			     DG2_DISABLE_ROUND_ENABLE_ALLOW_FOR_SSLA))
	},
	{ XE_RTP_NAME("22012532006"),
	  XE_RTP_RULES(SUBPLATFORM(DG2, G11), GRAPHICS_STEP(A0, B0),
		       ENGINE_CLASS(RENDER)),
	  XE_RTP_ACTIONS(SET(HALF_SLICE_CHICKEN7,
			     DG2_DISABLE_ROUND_ENABLE_ALLOW_FOR_SSLA))
	},
	{ XE_RTP_NAME("14015150844"),
	  XE_RTP_RULES(PLATFORM(DG2), FUNC(xe_rtp_match_first_render_or_compute)),
	  XE_RTP_ACTIONS(SET(XEHP_HDC_CHICKEN0, DIS_ATOMIC_CHAINING_TYPED_WRITES,
			     XE_RTP_NOCHECK))
	},

	/* PVC */

	{ XE_RTP_NAME("22014226127"),
	  XE_RTP_RULES(PLATFORM(PVC), FUNC(xe_rtp_match_first_render_or_compute)),
	  XE_RTP_ACTIONS(SET(LSC_CHICKEN_BIT_0, DISABLE_D8_D16_COASLESCE))
	},
	{ XE_RTP_NAME("14015227452"),
	  XE_RTP_RULES(PLATFORM(PVC), FUNC(xe_rtp_match_first_render_or_compute)),
	  XE_RTP_ACTIONS(SET(ROW_CHICKEN4, XEHP_DIS_BBL_SYSPIPE))
	},
	{ XE_RTP_NAME("16015675438"),
	  XE_RTP_RULES(PLATFORM(PVC), FUNC(xe_rtp_match_first_render_or_compute)),
	  XE_RTP_ACTIONS(SET(FF_SLICE_CS_CHICKEN2(RENDER_RING_BASE),
			     PERF_FIX_BALANCING_CFE_DISABLE))
	},
	{ XE_RTP_NAME("14014999345"),
	  XE_RTP_RULES(PLATFORM(PVC), ENGINE_CLASS(COMPUTE),
		       GRAPHICS_STEP(B0, C0)),
	  XE_RTP_ACTIONS(SET(CACHE_MODE_SS, DISABLE_ECC))
	},

	/* Xe_LPG */

	{ XE_RTP_NAME("14017856879"),
	  XE_RTP_RULES(GRAPHICS_VERSION_RANGE(1270, 1271),
		       FUNC(xe_rtp_match_first_render_or_compute)),
	  XE_RTP_ACTIONS(SET(ROW_CHICKEN3, DIS_FIX_EOT1_FLUSH))
	},
	{ XE_RTP_NAME("14015150844"),
	  XE_RTP_RULES(GRAPHICS_VERSION_RANGE(1270, 1271),
		       FUNC(xe_rtp_match_first_render_or_compute)),
	  XE_RTP_ACTIONS(SET(XEHP_HDC_CHICKEN0, DIS_ATOMIC_CHAINING_TYPED_WRITES,
			     XE_RTP_NOCHECK))
	},

	/* Xe2_LPG */

	{ XE_RTP_NAME("18032247524"),
	  XE_RTP_RULES(GRAPHICS_VERSION(2004),
		       FUNC(xe_rtp_match_first_render_or_compute)),
	  XE_RTP_ACTIONS(SET(LSC_CHICKEN_BIT_0, SEQUENTIAL_ACCESS_UPGRADE_DISABLE))
	},
	{ XE_RTP_NAME("16018712365"),
	  XE_RTP_RULES(GRAPHICS_VERSION(2004), FUNC(xe_rtp_match_first_render_or_compute)),
	  XE_RTP_ACTIONS(SET(LSC_CHICKEN_BIT_0_UDW, XE2_ALLOC_DPA_STARVE_FIX_DIS))
	},
	{ XE_RTP_NAME("14018957109"),
	  XE_RTP_RULES(GRAPHICS_VERSION(2004), GRAPHICS_STEP(A0, B0),
		       FUNC(xe_rtp_match_first_render_or_compute)),
	  XE_RTP_ACTIONS(SET(HALF_SLICE_CHICKEN5, DISABLE_SAMPLE_G_PERFORMANCE))
	},
	{ XE_RTP_NAME("16021540221"),
	  XE_RTP_RULES(GRAPHICS_VERSION(2004), GRAPHICS_STEP(A0, B0),
		       FUNC(xe_rtp_match_first_render_or_compute)),
	  XE_RTP_ACTIONS(SET(ROW_CHICKEN4, DISABLE_TDL_PUSH))
	},
	{ XE_RTP_NAME("14019322943"),
	  XE_RTP_RULES(GRAPHICS_VERSION(2004), GRAPHICS_STEP(A0, B0),
		       FUNC(xe_rtp_match_first_render_or_compute)),
	  XE_RTP_ACTIONS(SET(LSC_CHICKEN_BIT_0, TGM_WRITE_EOM_FORCE))
	},
	{ XE_RTP_NAME("14018471104"),
	  XE_RTP_RULES(GRAPHICS_VERSION(2004), FUNC(xe_rtp_match_first_render_or_compute)),
	  XE_RTP_ACTIONS(SET(LSC_CHICKEN_BIT_0_UDW, ENABLE_SMP_LD_RENDER_SURFACE_CONTROL))
	},
	{ XE_RTP_NAME("16018737384"),
	  XE_RTP_RULES(GRAPHICS_VERSION(2004), FUNC(xe_rtp_match_first_render_or_compute)),
	  XE_RTP_ACTIONS(SET(ROW_CHICKEN, EARLY_EOT_DIS))
	},
	/*
	 * These two workarounds are the same, just applying to different
	 * engines.  Although Wa_18032095049 (for the RCS) isn't required on
	 * all steppings, disabling these reports has no impact for our
	 * driver or the GuC, so we go ahead and treat it the same as
	 * Wa_16021639441 which does apply to all steppings.
	 */
	{ XE_RTP_NAME("18032095049, 16021639441"),
	  XE_RTP_RULES(GRAPHICS_VERSION(2004)),
	  XE_RTP_ACTIONS(SET(CSFE_CHICKEN1(0),
			     GHWSP_CSB_REPORT_DIS |
			     PPHWSP_CSB_AND_TIMESTAMP_REPORT_DIS,
			     XE_RTP_ACTION_FLAG(ENGINE_BASE)))
	},

	{}
};

static const struct xe_rtp_entry_sr lrc_was[] = {
	{ XE_RTP_NAME("1409342910, 14010698770, 14010443199, 1408979724, 1409178076, 1409207793, 1409217633, 1409252684, 1409347922, 1409142259"),
	  XE_RTP_RULES(GRAPHICS_VERSION_RANGE(1200, 1210)),
	  XE_RTP_ACTIONS(SET(COMMON_SLICE_CHICKEN3,
			     DISABLE_CPS_AWARE_COLOR_PIPE))
	},
	{ XE_RTP_NAME("WaDisableGPGPUMidThreadPreemption"),
	  XE_RTP_RULES(GRAPHICS_VERSION_RANGE(1200, 1210)),
	  XE_RTP_ACTIONS(FIELD_SET(CS_CHICKEN1(RENDER_RING_BASE),
				   PREEMPT_GPGPU_LEVEL_MASK,
				   PREEMPT_GPGPU_THREAD_GROUP_LEVEL))
	},
	{ XE_RTP_NAME("1806527549"),
	  XE_RTP_RULES(GRAPHICS_VERSION(1200)),
	  XE_RTP_ACTIONS(SET(HIZ_CHICKEN, HZ_DEPTH_TEST_LE_GE_OPT_DISABLE))
	},
	{ XE_RTP_NAME("1606376872"),
	  XE_RTP_RULES(GRAPHICS_VERSION(1200)),
	  XE_RTP_ACTIONS(SET(COMMON_SLICE_CHICKEN4, DISABLE_TDC_LOAD_BALANCING_CALC))
	},

	/* DG1 */

	{ XE_RTP_NAME("1409044764"),
	  XE_RTP_RULES(PLATFORM(DG1)),
	  XE_RTP_ACTIONS(CLR(COMMON_SLICE_CHICKEN3,
			     DG1_FLOAT_POINT_BLEND_OPT_STRICT_MODE_EN))
	},
	{ XE_RTP_NAME("22010493298"),
	  XE_RTP_RULES(PLATFORM(DG1)),
	  XE_RTP_ACTIONS(SET(HIZ_CHICKEN,
			     DG1_HZ_READ_SUPPRESSION_OPTIMIZATION_DISABLE))
	},

	/* DG2 */

	{ XE_RTP_NAME("16011186671"),
	  XE_RTP_RULES(SUBPLATFORM(DG2, G11), GRAPHICS_STEP(A0, B0)),
	  XE_RTP_ACTIONS(CLR(VFLSKPD, DIS_MULT_MISS_RD_SQUASH),
			 SET(VFLSKPD, DIS_OVER_FETCH_CACHE))
	},
	{ XE_RTP_NAME("14010469329"),
	  XE_RTP_RULES(SUBPLATFORM(DG2, G10), GRAPHICS_STEP(A0, B0)),
	  XE_RTP_ACTIONS(SET(XEHP_COMMON_SLICE_CHICKEN3,
			     XEHP_DUAL_SIMD8_SEQ_MERGE_DISABLE))
	},
	{ XE_RTP_NAME("14010698770, 22010613112, 22010465075"),
	  XE_RTP_RULES(SUBPLATFORM(DG2, G10), GRAPHICS_STEP(A0, B0)),
	  XE_RTP_ACTIONS(SET(XEHP_COMMON_SLICE_CHICKEN3,
			     DISABLE_CPS_AWARE_COLOR_PIPE))
	},
	{ XE_RTP_NAME("16013271637"),
	  XE_RTP_RULES(PLATFORM(DG2)),
	  XE_RTP_ACTIONS(SET(XEHP_SLICE_COMMON_ECO_CHICKEN1,
			     MSC_MSAA_REODER_BUF_BYPASS_DISABLE))
	},
	{ XE_RTP_NAME("14014947963"),
	  XE_RTP_RULES(PLATFORM(DG2)),
	  XE_RTP_ACTIONS(FIELD_SET(VF_PREEMPTION,
				   PREEMPTION_VERTEX_COUNT,
				   0x4000))
	},
	{ XE_RTP_NAME("18018764978"),
	  XE_RTP_RULES(PLATFORM(DG2)),
	  XE_RTP_ACTIONS(SET(XEHP_PSS_MODE2,
			     SCOREBOARD_STALL_FLUSH_CONTROL))
	},
	{ XE_RTP_NAME("18019271663"),
	  XE_RTP_RULES(PLATFORM(DG2)),
	  XE_RTP_ACTIONS(SET(CACHE_MODE_1, MSAA_OPTIMIZATION_REDUC_DISABLE))
	},
	{ XE_RTP_NAME("14019877138"),
	  XE_RTP_RULES(PLATFORM(DG2)),
	  XE_RTP_ACTIONS(SET(XEHP_PSS_CHICKEN, FD_END_COLLECT))
	},

	/* PVC */

	{ XE_RTP_NAME("16017236439"),
	  XE_RTP_RULES(PLATFORM(PVC), ENGINE_CLASS(COPY),
		       FUNC(xe_rtp_match_even_instance)),
	  XE_RTP_ACTIONS(SET(BCS_SWCTRL(0),
			     BCS_SWCTRL_DISABLE_256B,
			     XE_RTP_ACTION_FLAG(ENGINE_BASE))),
	},

	/* Xe_LPG */

	{ XE_RTP_NAME("18019271663"),
	  XE_RTP_RULES(GRAPHICS_VERSION_RANGE(1270, 1271)),
	  XE_RTP_ACTIONS(SET(CACHE_MODE_1, MSAA_OPTIMIZATION_REDUC_DISABLE))
	},

	/* Xe2_LPG */

	{ XE_RTP_NAME("16020518922"),
	  XE_RTP_RULES(GRAPHICS_VERSION(2004), GRAPHICS_STEP(A0, B0),
		       ENGINE_CLASS(RENDER)),
	  XE_RTP_ACTIONS(SET(FF_MODE,
			     DIS_TE_AUTOSTRIP |
			     DIS_MESH_PARTIAL_AUTOSTRIP |
			     DIS_MESH_AUTOSTRIP),
			 SET(VFLSKPD,
			     DIS_PARTIAL_AUTOSTRIP |
			     DIS_AUTOSTRIP))
	},
	{ XE_RTP_NAME("14019386621"),
	  XE_RTP_RULES(GRAPHICS_VERSION(2004), ENGINE_CLASS(RENDER)),
	  XE_RTP_ACTIONS(SET(VF_SCRATCHPAD, XE2_VFG_TED_CREDIT_INTERFACE_DISABLE))
	},
	{ XE_RTP_NAME("14019877138"),
	  XE_RTP_RULES(GRAPHICS_VERSION(2004), ENGINE_CLASS(RENDER)),
	  XE_RTP_ACTIONS(SET(XEHP_PSS_CHICKEN, FD_END_COLLECT))
	},
	{ XE_RTP_NAME("14020013138"),
	  XE_RTP_RULES(GRAPHICS_VERSION(2004), GRAPHICS_STEP(A0, B0),
		       ENGINE_CLASS(RENDER)),
	  XE_RTP_ACTIONS(SET(WM_CHICKEN3, HIZ_PLANE_COMPRESSION_DIS))
	},
	{ XE_RTP_NAME("14019988906"),
	  XE_RTP_RULES(GRAPHICS_VERSION(2004), ENGINE_CLASS(RENDER)),
	  XE_RTP_ACTIONS(SET(XEHP_PSS_CHICKEN, FLSH_IGNORES_PSD))
	},

	{}
};

static __maybe_unused const struct xe_rtp_entry oob_was[] = {
#include <generated/xe_wa_oob.c>
	{}
};

static_assert(ARRAY_SIZE(oob_was) - 1 == _XE_WA_OOB_COUNT);

__diag_pop();

/**
 * xe_wa_process_oob - process OOB workaround table
 * @gt: GT instance to process workarounds for
 *
 * Process OOB workaround table for this platform, marking in @gt the
 * workarounds that are active.
 */
void xe_wa_process_oob(struct xe_gt *gt)
{
	struct xe_rtp_process_ctx ctx = XE_RTP_PROCESS_CTX_INITIALIZER(gt);

	xe_rtp_process_ctx_enable_active_tracking(&ctx, gt->wa_active.oob,
						  ARRAY_SIZE(oob_was));
	xe_rtp_process(&ctx, oob_was);
}

/**
 * xe_wa_process_gt - process GT workaround table
 * @gt: GT instance to process workarounds for
 *
 * Process GT workaround table for this platform, saving in @gt all the
 * workarounds that need to be applied at the GT level.
 */
void xe_wa_process_gt(struct xe_gt *gt)
{
	struct xe_rtp_process_ctx ctx = XE_RTP_PROCESS_CTX_INITIALIZER(gt);

	xe_rtp_process_ctx_enable_active_tracking(&ctx, gt->wa_active.gt,
						  ARRAY_SIZE(gt_was));
	xe_rtp_process_to_sr(&ctx, gt_was, &gt->reg_sr);
}
EXPORT_SYMBOL_IF_KUNIT(xe_wa_process_gt);

/**
 * xe_wa_process_engine - process engine workaround table
 * @hwe: engine instance to process workarounds for
 *
 * Process engine workaround table for this platform, saving in @hwe all the
 * workarounds that need to be applied at the engine level that match this
 * engine.
 */
void xe_wa_process_engine(struct xe_hw_engine *hwe)
{
	struct xe_rtp_process_ctx ctx = XE_RTP_PROCESS_CTX_INITIALIZER(hwe);

	xe_rtp_process_ctx_enable_active_tracking(&ctx, hwe->gt->wa_active.engine,
						  ARRAY_SIZE(engine_was));
	xe_rtp_process_to_sr(&ctx, engine_was, &hwe->reg_sr);
}

/**
 * xe_wa_process_lrc - process context workaround table
 * @hwe: engine instance to process workarounds for
 *
 * Process context workaround table for this platform, saving in @hwe all the
 * workarounds that need to be applied on context restore. These are workarounds
 * touching registers that are part of the HW context image.
 */
void xe_wa_process_lrc(struct xe_hw_engine *hwe)
{
	struct xe_rtp_process_ctx ctx = XE_RTP_PROCESS_CTX_INITIALIZER(hwe);

	xe_rtp_process_ctx_enable_active_tracking(&ctx, hwe->gt->wa_active.lrc,
						  ARRAY_SIZE(lrc_was));
	xe_rtp_process_to_sr(&ctx, lrc_was, &hwe->reg_lrc);
}

/**
 * xe_wa_init - initialize gt with workaround bookkeeping
 * @gt: GT instance to initialize
 *
 * Returns 0 for success, negative error code otherwise.
 */
int xe_wa_init(struct xe_gt *gt)
{
	struct xe_device *xe = gt_to_xe(gt);
	size_t n_oob, n_lrc, n_engine, n_gt, total;
	unsigned long *p;

	n_gt = BITS_TO_LONGS(ARRAY_SIZE(gt_was));
	n_engine = BITS_TO_LONGS(ARRAY_SIZE(engine_was));
	n_lrc = BITS_TO_LONGS(ARRAY_SIZE(lrc_was));
	n_oob = BITS_TO_LONGS(ARRAY_SIZE(oob_was));
	total = n_gt + n_engine + n_lrc + n_oob;

	p = drmm_kzalloc(&xe->drm, sizeof(*p) * total, GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	gt->wa_active.gt = p;
	p += n_gt;
	gt->wa_active.engine = p;
	p += n_engine;
	gt->wa_active.lrc = p;
	p += n_lrc;
	gt->wa_active.oob = p;

	return 0;
}

void xe_wa_dump(struct xe_gt *gt, struct drm_printer *p)
{
	size_t idx;

	drm_printf(p, "GT Workarounds\n");
	for_each_set_bit(idx, gt->wa_active.gt, ARRAY_SIZE(gt_was))
		drm_printf_indent(p, 1, "%s\n", gt_was[idx].name);

	drm_printf(p, "\nEngine Workarounds\n");
	for_each_set_bit(idx, gt->wa_active.engine, ARRAY_SIZE(engine_was))
		drm_printf_indent(p, 1, "%s\n", engine_was[idx].name);

	drm_printf(p, "\nLRC Workarounds\n");
	for_each_set_bit(idx, gt->wa_active.lrc, ARRAY_SIZE(lrc_was))
		drm_printf_indent(p, 1, "%s\n", lrc_was[idx].name);

	drm_printf(p, "\nOOB Workarounds\n");
	for_each_set_bit(idx, gt->wa_active.oob, ARRAY_SIZE(oob_was))
		if (oob_was[idx].name)
			drm_printf_indent(p, 1, "%s\n", oob_was[idx].name);
}

/*
 * Apply tile (non-GT, non-display) workarounds.  Think very carefully before
 * adding anything to this function; most workarounds should be implemented
 * elsewhere.  The programming here is primarily for sgunit/soc workarounds,
 * which are relatively rare.  Since the registers these workarounds target are
 * outside the GT, they should only need to be applied once at device
 * probe/resume; they will not lose their values on any kind of GT or engine
 * reset.
 *
 * TODO:  We may want to move this over to xe_rtp in the future once we have
 * enough workarounds to justify the work.
 */
void xe_wa_apply_tile_workarounds(struct xe_tile *tile)
{
	struct xe_gt *mmio = tile->primary_gt;

	if (XE_WA(mmio, 22010954014))
		xe_mmio_rmw32(mmio, XEHP_CLOCK_GATE_DIS, 0, SGSI_SIDECLK_DIS);
}
