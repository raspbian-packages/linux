/*
 * Copyright © 2013 Intel Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "i915_drv.h"
#include "intel_drv.h"
#include "i915_vgpu.h"

#include <asm/iosf_mbi.h>
#include <linux/pm_runtime.h>

#define FORCEWAKE_ACK_TIMEOUT_MS 50

#define __raw_posting_read(dev_priv__, reg__) (void)__raw_i915_read32((dev_priv__), (reg__))

static const char * const forcewake_domain_names[] = {
	"render",
	"blitter",
	"media",
};

const char *
intel_uncore_forcewake_domain_to_str(const enum forcewake_domain_id id)
{
	BUILD_BUG_ON(ARRAY_SIZE(forcewake_domain_names) != FW_DOMAIN_ID_COUNT);

	if (id >= 0 && id < FW_DOMAIN_ID_COUNT)
		return forcewake_domain_names[id];

	WARN_ON(id);

	return "unknown";
}

static inline void
fw_domain_reset(struct drm_i915_private *i915,
		const struct intel_uncore_forcewake_domain *d)
{
	__raw_i915_write32(i915, d->reg_set, i915->uncore.fw_reset);
}

static inline void
fw_domain_arm_timer(struct intel_uncore_forcewake_domain *d)
{
	d->wake_count++;
	hrtimer_start_range_ns(&d->timer,
			       NSEC_PER_MSEC,
			       NSEC_PER_MSEC,
			       HRTIMER_MODE_REL);
}

static inline void
fw_domain_wait_ack_clear(const struct drm_i915_private *i915,
			 const struct intel_uncore_forcewake_domain *d)
{
	if (wait_for_atomic((__raw_i915_read32(i915, d->reg_ack) &
			     FORCEWAKE_KERNEL) == 0,
			    FORCEWAKE_ACK_TIMEOUT_MS))
		DRM_ERROR("%s: timed out waiting for forcewake ack to clear.\n",
			  intel_uncore_forcewake_domain_to_str(d->id));
}

static inline void
fw_domain_get(struct drm_i915_private *i915,
	      const struct intel_uncore_forcewake_domain *d)
{
	__raw_i915_write32(i915, d->reg_set, i915->uncore.fw_set);
}

static inline void
fw_domain_wait_ack(const struct drm_i915_private *i915,
		   const struct intel_uncore_forcewake_domain *d)
{
	if (wait_for_atomic((__raw_i915_read32(i915, d->reg_ack) &
			     FORCEWAKE_KERNEL),
			    FORCEWAKE_ACK_TIMEOUT_MS))
		DRM_ERROR("%s: timed out waiting for forcewake ack request.\n",
			  intel_uncore_forcewake_domain_to_str(d->id));
}

static inline void
fw_domain_put(const struct drm_i915_private *i915,
	      const struct intel_uncore_forcewake_domain *d)
{
	__raw_i915_write32(i915, d->reg_set, i915->uncore.fw_clear);
}

static void
fw_domains_get(struct drm_i915_private *i915, enum forcewake_domains fw_domains)
{
	struct intel_uncore_forcewake_domain *d;
	unsigned int tmp;

	GEM_BUG_ON(fw_domains & ~i915->uncore.fw_domains);

	for_each_fw_domain_masked(d, fw_domains, i915, tmp) {
		fw_domain_wait_ack_clear(i915, d);
		fw_domain_get(i915, d);
	}

	for_each_fw_domain_masked(d, fw_domains, i915, tmp)
		fw_domain_wait_ack(i915, d);

	i915->uncore.fw_domains_active |= fw_domains;
}

static void
fw_domains_put(struct drm_i915_private *i915, enum forcewake_domains fw_domains)
{
	struct intel_uncore_forcewake_domain *d;
	unsigned int tmp;

	GEM_BUG_ON(fw_domains & ~i915->uncore.fw_domains);

	for_each_fw_domain_masked(d, fw_domains, i915, tmp)
		fw_domain_put(i915, d);

	i915->uncore.fw_domains_active &= ~fw_domains;
}

static void
fw_domains_reset(struct drm_i915_private *i915,
		 enum forcewake_domains fw_domains)
{
	struct intel_uncore_forcewake_domain *d;
	unsigned int tmp;

	if (!fw_domains)
		return;

	GEM_BUG_ON(fw_domains & ~i915->uncore.fw_domains);

	for_each_fw_domain_masked(d, fw_domains, i915, tmp)
		fw_domain_reset(i915, d);
}

static void __gen6_gt_wait_for_thread_c0(struct drm_i915_private *dev_priv)
{
	/* w/a for a sporadic read returning 0 by waiting for the GT
	 * thread to wake up.
	 */
	if (wait_for_atomic_us((__raw_i915_read32(dev_priv, GEN6_GT_THREAD_STATUS_REG) &
				GEN6_GT_THREAD_STATUS_CORE_MASK) == 0, 500))
		DRM_ERROR("GT thread status wait timed out\n");
}

static void fw_domains_get_with_thread_status(struct drm_i915_private *dev_priv,
					      enum forcewake_domains fw_domains)
{
	fw_domains_get(dev_priv, fw_domains);

	/* WaRsForcewakeWaitTC0:snb,ivb,hsw,bdw,vlv */
	__gen6_gt_wait_for_thread_c0(dev_priv);
}

static void gen6_gt_check_fifodbg(struct drm_i915_private *dev_priv)
{
	u32 gtfifodbg;

	gtfifodbg = __raw_i915_read32(dev_priv, GTFIFODBG);
	if (WARN(gtfifodbg, "GT wake FIFO error 0x%x\n", gtfifodbg))
		__raw_i915_write32(dev_priv, GTFIFODBG, gtfifodbg);
}

static void fw_domains_put_with_fifo(struct drm_i915_private *dev_priv,
				     enum forcewake_domains fw_domains)
{
	fw_domains_put(dev_priv, fw_domains);
	gen6_gt_check_fifodbg(dev_priv);
}

static inline u32 fifo_free_entries(struct drm_i915_private *dev_priv)
{
	u32 count = __raw_i915_read32(dev_priv, GTFIFOCTL);

	return count & GT_FIFO_FREE_ENTRIES_MASK;
}

static int __gen6_gt_wait_for_fifo(struct drm_i915_private *dev_priv)
{
	int ret = 0;

	/* On VLV, FIFO will be shared by both SW and HW.
	 * So, we need to read the FREE_ENTRIES everytime */
	if (IS_VALLEYVIEW(dev_priv))
		dev_priv->uncore.fifo_count = fifo_free_entries(dev_priv);

	if (dev_priv->uncore.fifo_count < GT_FIFO_NUM_RESERVED_ENTRIES) {
		int loop = 500;
		u32 fifo = fifo_free_entries(dev_priv);

		while (fifo <= GT_FIFO_NUM_RESERVED_ENTRIES && loop--) {
			udelay(10);
			fifo = fifo_free_entries(dev_priv);
		}
		if (WARN_ON(loop < 0 && fifo <= GT_FIFO_NUM_RESERVED_ENTRIES))
			++ret;
		dev_priv->uncore.fifo_count = fifo;
	}
	dev_priv->uncore.fifo_count--;

	return ret;
}

static enum hrtimer_restart
intel_uncore_fw_release_timer(struct hrtimer *timer)
{
	struct intel_uncore_forcewake_domain *domain =
	       container_of(timer, struct intel_uncore_forcewake_domain, timer);
	struct drm_i915_private *dev_priv =
		container_of(domain, struct drm_i915_private, uncore.fw_domain[domain->id]);
	unsigned long irqflags;

	assert_rpm_device_not_suspended(dev_priv);

	spin_lock_irqsave(&dev_priv->uncore.lock, irqflags);
	if (WARN_ON(domain->wake_count == 0))
		domain->wake_count++;

	if (--domain->wake_count == 0)
		dev_priv->uncore.funcs.force_wake_put(dev_priv, domain->mask);

	spin_unlock_irqrestore(&dev_priv->uncore.lock, irqflags);

	return HRTIMER_NORESTART;
}

static void intel_uncore_forcewake_reset(struct drm_i915_private *dev_priv,
					 bool restore)
{
	unsigned long irqflags;
	struct intel_uncore_forcewake_domain *domain;
	int retry_count = 100;
	enum forcewake_domains fw, active_domains;

	/* Hold uncore.lock across reset to prevent any register access
	 * with forcewake not set correctly. Wait until all pending
	 * timers are run before holding.
	 */
	while (1) {
		unsigned int tmp;

		active_domains = 0;

		for_each_fw_domain(domain, dev_priv, tmp) {
			if (hrtimer_cancel(&domain->timer) == 0)
				continue;

			intel_uncore_fw_release_timer(&domain->timer);
		}

		spin_lock_irqsave(&dev_priv->uncore.lock, irqflags);

		for_each_fw_domain(domain, dev_priv, tmp) {
			if (hrtimer_active(&domain->timer))
				active_domains |= domain->mask;
		}

		if (active_domains == 0)
			break;

		if (--retry_count == 0) {
			DRM_ERROR("Timed out waiting for forcewake timers to finish\n");
			break;
		}

		spin_unlock_irqrestore(&dev_priv->uncore.lock, irqflags);
		cond_resched();
	}

	WARN_ON(active_domains);

	fw = dev_priv->uncore.fw_domains_active;
	if (fw)
		dev_priv->uncore.funcs.force_wake_put(dev_priv, fw);

	fw_domains_reset(dev_priv, dev_priv->uncore.fw_domains);

	if (restore) { /* If reset with a user forcewake, try to restore */
		if (fw)
			dev_priv->uncore.funcs.force_wake_get(dev_priv, fw);

		if (IS_GEN6(dev_priv) || IS_GEN7(dev_priv))
			dev_priv->uncore.fifo_count =
				fifo_free_entries(dev_priv);
	}

	if (!restore)
		assert_forcewakes_inactive(dev_priv);

	spin_unlock_irqrestore(&dev_priv->uncore.lock, irqflags);
}

static u64 gen9_edram_size(struct drm_i915_private *dev_priv)
{
	const unsigned int ways[8] = { 4, 8, 12, 16, 16, 16, 16, 16 };
	const unsigned int sets[4] = { 1, 1, 2, 2 };
	const u32 cap = dev_priv->edram_cap;

	return EDRAM_NUM_BANKS(cap) *
		ways[EDRAM_WAYS_IDX(cap)] *
		sets[EDRAM_SETS_IDX(cap)] *
		1024 * 1024;
}

u64 intel_uncore_edram_size(struct drm_i915_private *dev_priv)
{
	if (!HAS_EDRAM(dev_priv))
		return 0;

	/* The needed capability bits for size calculation
	 * are not there with pre gen9 so return 128MB always.
	 */
	if (INTEL_GEN(dev_priv) < 9)
		return 128 * 1024 * 1024;

	return gen9_edram_size(dev_priv);
}

static void intel_uncore_edram_detect(struct drm_i915_private *dev_priv)
{
	if (IS_HASWELL(dev_priv) ||
	    IS_BROADWELL(dev_priv) ||
	    INTEL_GEN(dev_priv) >= 9) {
		dev_priv->edram_cap = __raw_i915_read32(dev_priv,
							HSW_EDRAM_CAP);

		/* NB: We can't write IDICR yet because we do not have gt funcs
		 * set up */
	} else {
		dev_priv->edram_cap = 0;
	}

	if (HAS_EDRAM(dev_priv))
		DRM_INFO("Found %lluMB of eDRAM\n",
			 intel_uncore_edram_size(dev_priv) / (1024 * 1024));
}

static bool
fpga_check_for_unclaimed_mmio(struct drm_i915_private *dev_priv)
{
	u32 dbg;

	dbg = __raw_i915_read32(dev_priv, FPGA_DBG);
	if (likely(!(dbg & FPGA_DBG_RM_NOCLAIM)))
		return false;

	__raw_i915_write32(dev_priv, FPGA_DBG, FPGA_DBG_RM_NOCLAIM);

	return true;
}

static bool
vlv_check_for_unclaimed_mmio(struct drm_i915_private *dev_priv)
{
	u32 cer;

	cer = __raw_i915_read32(dev_priv, CLAIM_ER);
	if (likely(!(cer & (CLAIM_ER_OVERFLOW | CLAIM_ER_CTR_MASK))))
		return false;

	__raw_i915_write32(dev_priv, CLAIM_ER, CLAIM_ER_CLR);

	return true;
}

static bool
check_for_unclaimed_mmio(struct drm_i915_private *dev_priv)
{
	if (HAS_FPGA_DBG_UNCLAIMED(dev_priv))
		return fpga_check_for_unclaimed_mmio(dev_priv);

	if (IS_VALLEYVIEW(dev_priv) || IS_CHERRYVIEW(dev_priv))
		return vlv_check_for_unclaimed_mmio(dev_priv);

	return false;
}

static void __intel_uncore_early_sanitize(struct drm_i915_private *dev_priv,
					  bool restore_forcewake)
{
	struct intel_device_info *info = mkwrite_device_info(dev_priv);

	/* clear out unclaimed reg detection bit */
	if (check_for_unclaimed_mmio(dev_priv))
		DRM_DEBUG("unclaimed mmio detected on uncore init, clearing\n");

	/* clear out old GT FIFO errors */
	if (IS_GEN6(dev_priv) || IS_GEN7(dev_priv))
		__raw_i915_write32(dev_priv, GTFIFODBG,
				   __raw_i915_read32(dev_priv, GTFIFODBG));

	/* WaDisableShadowRegForCpd:chv */
	if (IS_CHERRYVIEW(dev_priv)) {
		__raw_i915_write32(dev_priv, GTFIFOCTL,
				   __raw_i915_read32(dev_priv, GTFIFOCTL) |
				   GT_FIFO_CTL_BLOCK_ALL_POLICY_STALL |
				   GT_FIFO_CTL_RC6_POLICY_STALL);
	}

	if (IS_BXT_REVID(dev_priv, 0, BXT_REVID_B_LAST))
		info->has_decoupled_mmio = false;

	intel_uncore_forcewake_reset(dev_priv, restore_forcewake);
}

void intel_uncore_suspend(struct drm_i915_private *dev_priv)
{
	iosf_mbi_unregister_pmic_bus_access_notifier(
		&dev_priv->uncore.pmic_bus_access_nb);
	intel_uncore_forcewake_reset(dev_priv, false);
}

void intel_uncore_resume_early(struct drm_i915_private *dev_priv)
{
	__intel_uncore_early_sanitize(dev_priv, true);
	iosf_mbi_register_pmic_bus_access_notifier(
		&dev_priv->uncore.pmic_bus_access_nb);
	i915_check_and_clear_faults(dev_priv);
}

void intel_uncore_sanitize(struct drm_i915_private *dev_priv)
{
	i915.enable_rc6 = sanitize_rc6_option(dev_priv, i915.enable_rc6);

	/* BIOS often leaves RC6 enabled, but disable it for hw init */
	intel_sanitize_gt_powersave(dev_priv);
}

static void __intel_uncore_forcewake_get(struct drm_i915_private *dev_priv,
					 enum forcewake_domains fw_domains)
{
	struct intel_uncore_forcewake_domain *domain;
	unsigned int tmp;

	fw_domains &= dev_priv->uncore.fw_domains;

	for_each_fw_domain_masked(domain, fw_domains, dev_priv, tmp)
		if (domain->wake_count++)
			fw_domains &= ~domain->mask;

	if (fw_domains)
		dev_priv->uncore.funcs.force_wake_get(dev_priv, fw_domains);
}

/**
 * intel_uncore_forcewake_get - grab forcewake domain references
 * @dev_priv: i915 device instance
 * @fw_domains: forcewake domains to get reference on
 *
 * This function can be used get GT's forcewake domain references.
 * Normal register access will handle the forcewake domains automatically.
 * However if some sequence requires the GT to not power down a particular
 * forcewake domains this function should be called at the beginning of the
 * sequence. And subsequently the reference should be dropped by symmetric
 * call to intel_unforce_forcewake_put(). Usually caller wants all the domains
 * to be kept awake so the @fw_domains would be then FORCEWAKE_ALL.
 */
void intel_uncore_forcewake_get(struct drm_i915_private *dev_priv,
				enum forcewake_domains fw_domains)
{
	unsigned long irqflags;

	if (!dev_priv->uncore.funcs.force_wake_get)
		return;

	assert_rpm_wakelock_held(dev_priv);

	spin_lock_irqsave(&dev_priv->uncore.lock, irqflags);
	__intel_uncore_forcewake_get(dev_priv, fw_domains);
	spin_unlock_irqrestore(&dev_priv->uncore.lock, irqflags);
}

/**
 * intel_uncore_forcewake_get__locked - grab forcewake domain references
 * @dev_priv: i915 device instance
 * @fw_domains: forcewake domains to get reference on
 *
 * See intel_uncore_forcewake_get(). This variant places the onus
 * on the caller to explicitly handle the dev_priv->uncore.lock spinlock.
 */
void intel_uncore_forcewake_get__locked(struct drm_i915_private *dev_priv,
					enum forcewake_domains fw_domains)
{
	lockdep_assert_held(&dev_priv->uncore.lock);

	if (!dev_priv->uncore.funcs.force_wake_get)
		return;

	__intel_uncore_forcewake_get(dev_priv, fw_domains);
}

static void __intel_uncore_forcewake_put(struct drm_i915_private *dev_priv,
					 enum forcewake_domains fw_domains)
{
	struct intel_uncore_forcewake_domain *domain;
	unsigned int tmp;

	fw_domains &= dev_priv->uncore.fw_domains;

	for_each_fw_domain_masked(domain, fw_domains, dev_priv, tmp) {
		if (WARN_ON(domain->wake_count == 0))
			continue;

		if (--domain->wake_count)
			continue;

		fw_domain_arm_timer(domain);
	}
}

/**
 * intel_uncore_forcewake_put - release a forcewake domain reference
 * @dev_priv: i915 device instance
 * @fw_domains: forcewake domains to put references
 *
 * This function drops the device-level forcewakes for specified
 * domains obtained by intel_uncore_forcewake_get().
 */
void intel_uncore_forcewake_put(struct drm_i915_private *dev_priv,
				enum forcewake_domains fw_domains)
{
	unsigned long irqflags;

	if (!dev_priv->uncore.funcs.force_wake_put)
		return;

	spin_lock_irqsave(&dev_priv->uncore.lock, irqflags);
	__intel_uncore_forcewake_put(dev_priv, fw_domains);
	spin_unlock_irqrestore(&dev_priv->uncore.lock, irqflags);
}

/**
 * intel_uncore_forcewake_put__locked - grab forcewake domain references
 * @dev_priv: i915 device instance
 * @fw_domains: forcewake domains to get reference on
 *
 * See intel_uncore_forcewake_put(). This variant places the onus
 * on the caller to explicitly handle the dev_priv->uncore.lock spinlock.
 */
void intel_uncore_forcewake_put__locked(struct drm_i915_private *dev_priv,
					enum forcewake_domains fw_domains)
{
	lockdep_assert_held(&dev_priv->uncore.lock);

	if (!dev_priv->uncore.funcs.force_wake_put)
		return;

	__intel_uncore_forcewake_put(dev_priv, fw_domains);
}

void assert_forcewakes_inactive(struct drm_i915_private *dev_priv)
{
	if (!dev_priv->uncore.funcs.force_wake_get)
		return;

	WARN_ON(dev_priv->uncore.fw_domains_active);
}

/* We give fast paths for the really cool registers */
#define NEEDS_FORCE_WAKE(reg) ((reg) < 0x40000)

#define __gen6_reg_read_fw_domains(offset) \
({ \
	enum forcewake_domains __fwd; \
	if (NEEDS_FORCE_WAKE(offset)) \
		__fwd = FORCEWAKE_RENDER; \
	else \
		__fwd = 0; \
	__fwd; \
})

static int fw_range_cmp(u32 offset, const struct intel_forcewake_range *entry)
{
	if (offset < entry->start)
		return -1;
	else if (offset > entry->end)
		return 1;
	else
		return 0;
}

/* Copied and "macroized" from lib/bsearch.c */
#define BSEARCH(key, base, num, cmp) ({                                 \
	unsigned int start__ = 0, end__ = (num);                        \
	typeof(base) result__ = NULL;                                   \
	while (start__ < end__) {                                       \
		unsigned int mid__ = start__ + (end__ - start__) / 2;   \
		int ret__ = (cmp)((key), (base) + mid__);               \
		if (ret__ < 0) {                                        \
			end__ = mid__;                                  \
		} else if (ret__ > 0) {                                 \
			start__ = mid__ + 1;                            \
		} else {                                                \
			result__ = (base) + mid__;                      \
			break;                                          \
		}                                                       \
	}                                                               \
	result__;                                                       \
})

static enum forcewake_domains
find_fw_domain(struct drm_i915_private *dev_priv, u32 offset)
{
	const struct intel_forcewake_range *entry;

	entry = BSEARCH(offset,
			dev_priv->uncore.fw_domains_table,
			dev_priv->uncore.fw_domains_table_entries,
			fw_range_cmp);

	if (!entry)
		return 0;

	WARN(entry->domains & ~dev_priv->uncore.fw_domains,
	     "Uninitialized forcewake domain(s) 0x%x accessed at 0x%x\n",
	     entry->domains & ~dev_priv->uncore.fw_domains, offset);

	return entry->domains;
}

#define GEN_FW_RANGE(s, e, d) \
	{ .start = (s), .end = (e), .domains = (d) }

#define HAS_FWTABLE(dev_priv) \
	(IS_GEN9(dev_priv) || \
	 IS_CHERRYVIEW(dev_priv) || \
	 IS_VALLEYVIEW(dev_priv))

/* *Must* be sorted by offset ranges! See intel_fw_table_check(). */
static const struct intel_forcewake_range __vlv_fw_ranges[] = {
	GEN_FW_RANGE(0x2000, 0x3fff, FORCEWAKE_RENDER),
	GEN_FW_RANGE(0x5000, 0x7fff, FORCEWAKE_RENDER),
	GEN_FW_RANGE(0xb000, 0x11fff, FORCEWAKE_RENDER),
	GEN_FW_RANGE(0x12000, 0x13fff, FORCEWAKE_MEDIA),
	GEN_FW_RANGE(0x22000, 0x23fff, FORCEWAKE_MEDIA),
	GEN_FW_RANGE(0x2e000, 0x2ffff, FORCEWAKE_RENDER),
	GEN_FW_RANGE(0x30000, 0x3ffff, FORCEWAKE_MEDIA),
};

#define __fwtable_reg_read_fw_domains(offset) \
({ \
	enum forcewake_domains __fwd = 0; \
	if (NEEDS_FORCE_WAKE((offset))) \
		__fwd = find_fw_domain(dev_priv, offset); \
	__fwd; \
})

/* *Must* be sorted by offset! See intel_shadow_table_check(). */
static const i915_reg_t gen8_shadowed_regs[] = {
	RING_TAIL(RENDER_RING_BASE),	/* 0x2000 (base) */
	GEN6_RPNSWREQ,			/* 0xA008 */
	GEN6_RC_VIDEO_FREQ,		/* 0xA00C */
	RING_TAIL(GEN6_BSD_RING_BASE),	/* 0x12000 (base) */
	RING_TAIL(VEBOX_RING_BASE),	/* 0x1a000 (base) */
	RING_TAIL(BLT_RING_BASE),	/* 0x22000 (base) */
	/* TODO: Other registers are not yet used */
};

static int mmio_reg_cmp(u32 key, const i915_reg_t *reg)
{
	u32 offset = i915_mmio_reg_offset(*reg);

	if (key < offset)
		return -1;
	else if (key > offset)
		return 1;
	else
		return 0;
}

static bool is_gen8_shadowed(u32 offset)
{
	const i915_reg_t *regs = gen8_shadowed_regs;

	return BSEARCH(offset, regs, ARRAY_SIZE(gen8_shadowed_regs),
		       mmio_reg_cmp);
}

#define __gen8_reg_write_fw_domains(offset) \
({ \
	enum forcewake_domains __fwd; \
	if (NEEDS_FORCE_WAKE(offset) && !is_gen8_shadowed(offset)) \
		__fwd = FORCEWAKE_RENDER; \
	else \
		__fwd = 0; \
	__fwd; \
})

/* *Must* be sorted by offset ranges! See intel_fw_table_check(). */
static const struct intel_forcewake_range __chv_fw_ranges[] = {
	GEN_FW_RANGE(0x2000, 0x3fff, FORCEWAKE_RENDER),
	GEN_FW_RANGE(0x4000, 0x4fff, FORCEWAKE_RENDER | FORCEWAKE_MEDIA),
	GEN_FW_RANGE(0x5200, 0x7fff, FORCEWAKE_RENDER),
	GEN_FW_RANGE(0x8000, 0x82ff, FORCEWAKE_RENDER | FORCEWAKE_MEDIA),
	GEN_FW_RANGE(0x8300, 0x84ff, FORCEWAKE_RENDER),
	GEN_FW_RANGE(0x8500, 0x85ff, FORCEWAKE_RENDER | FORCEWAKE_MEDIA),
	GEN_FW_RANGE(0x8800, 0x88ff, FORCEWAKE_MEDIA),
	GEN_FW_RANGE(0x9000, 0xafff, FORCEWAKE_RENDER | FORCEWAKE_MEDIA),
	GEN_FW_RANGE(0xb000, 0xb47f, FORCEWAKE_RENDER),
	GEN_FW_RANGE(0xd000, 0xd7ff, FORCEWAKE_MEDIA),
	GEN_FW_RANGE(0xe000, 0xe7ff, FORCEWAKE_RENDER),
	GEN_FW_RANGE(0xf000, 0xffff, FORCEWAKE_RENDER | FORCEWAKE_MEDIA),
	GEN_FW_RANGE(0x12000, 0x13fff, FORCEWAKE_MEDIA),
	GEN_FW_RANGE(0x1a000, 0x1bfff, FORCEWAKE_MEDIA),
	GEN_FW_RANGE(0x1e800, 0x1e9ff, FORCEWAKE_MEDIA),
	GEN_FW_RANGE(0x30000, 0x37fff, FORCEWAKE_MEDIA),
};

#define __fwtable_reg_write_fw_domains(offset) \
({ \
	enum forcewake_domains __fwd = 0; \
	if (NEEDS_FORCE_WAKE((offset)) && !is_gen8_shadowed(offset)) \
		__fwd = find_fw_domain(dev_priv, offset); \
	__fwd; \
})

/* *Must* be sorted by offset ranges! See intel_fw_table_check(). */
static const struct intel_forcewake_range __gen9_fw_ranges[] = {
	GEN_FW_RANGE(0x0, 0xaff, FORCEWAKE_BLITTER),
	GEN_FW_RANGE(0xb00, 0x1fff, 0), /* uncore range */
	GEN_FW_RANGE(0x2000, 0x26ff, FORCEWAKE_RENDER),
	GEN_FW_RANGE(0x2700, 0x2fff, FORCEWAKE_BLITTER),
	GEN_FW_RANGE(0x3000, 0x3fff, FORCEWAKE_RENDER),
	GEN_FW_RANGE(0x4000, 0x51ff, FORCEWAKE_BLITTER),
	GEN_FW_RANGE(0x5200, 0x7fff, FORCEWAKE_RENDER),
	GEN_FW_RANGE(0x8000, 0x812f, FORCEWAKE_BLITTER),
	GEN_FW_RANGE(0x8130, 0x813f, FORCEWAKE_MEDIA),
	GEN_FW_RANGE(0x8140, 0x815f, FORCEWAKE_RENDER),
	GEN_FW_RANGE(0x8160, 0x82ff, FORCEWAKE_BLITTER),
	GEN_FW_RANGE(0x8300, 0x84ff, FORCEWAKE_RENDER),
	GEN_FW_RANGE(0x8500, 0x87ff, FORCEWAKE_BLITTER),
	GEN_FW_RANGE(0x8800, 0x89ff, FORCEWAKE_MEDIA),
	GEN_FW_RANGE(0x8a00, 0x8bff, FORCEWAKE_BLITTER),
	GEN_FW_RANGE(0x8c00, 0x8cff, FORCEWAKE_RENDER),
	GEN_FW_RANGE(0x8d00, 0x93ff, FORCEWAKE_BLITTER),
	GEN_FW_RANGE(0x9400, 0x97ff, FORCEWAKE_RENDER | FORCEWAKE_MEDIA),
	GEN_FW_RANGE(0x9800, 0xafff, FORCEWAKE_BLITTER),
	GEN_FW_RANGE(0xb000, 0xb47f, FORCEWAKE_RENDER),
	GEN_FW_RANGE(0xb480, 0xcfff, FORCEWAKE_BLITTER),
	GEN_FW_RANGE(0xd000, 0xd7ff, FORCEWAKE_MEDIA),
	GEN_FW_RANGE(0xd800, 0xdfff, FORCEWAKE_BLITTER),
	GEN_FW_RANGE(0xe000, 0xe8ff, FORCEWAKE_RENDER),
	GEN_FW_RANGE(0xe900, 0x11fff, FORCEWAKE_BLITTER),
	GEN_FW_RANGE(0x12000, 0x13fff, FORCEWAKE_MEDIA),
	GEN_FW_RANGE(0x14000, 0x19fff, FORCEWAKE_BLITTER),
	GEN_FW_RANGE(0x1a000, 0x1e9ff, FORCEWAKE_MEDIA),
	GEN_FW_RANGE(0x1ea00, 0x243ff, FORCEWAKE_BLITTER),
	GEN_FW_RANGE(0x24400, 0x247ff, FORCEWAKE_RENDER),
	GEN_FW_RANGE(0x24800, 0x2ffff, FORCEWAKE_BLITTER),
	GEN_FW_RANGE(0x30000, 0x3ffff, FORCEWAKE_MEDIA),
};

static void
ilk_dummy_write(struct drm_i915_private *dev_priv)
{
	/* WaIssueDummyWriteToWakeupFromRC6:ilk Issue a dummy write to wake up
	 * the chip from rc6 before touching it for real. MI_MODE is masked,
	 * hence harmless to write 0 into. */
	__raw_i915_write32(dev_priv, MI_MODE, 0);
}

static void
__unclaimed_reg_debug(struct drm_i915_private *dev_priv,
		      const i915_reg_t reg,
		      const bool read,
		      const bool before)
{
	if (WARN(check_for_unclaimed_mmio(dev_priv) && !before,
		 "Unclaimed %s register 0x%x\n",
		 read ? "read from" : "write to",
		 i915_mmio_reg_offset(reg)))
		i915.mmio_debug--; /* Only report the first N failures */
}

static inline void
unclaimed_reg_debug(struct drm_i915_private *dev_priv,
		    const i915_reg_t reg,
		    const bool read,
		    const bool before)
{
	if (likely(!i915.mmio_debug))
		return;

	__unclaimed_reg_debug(dev_priv, reg, read, before);
}

static const enum decoupled_power_domain fw2dpd_domain[] = {
	GEN9_DECOUPLED_PD_RENDER,
	GEN9_DECOUPLED_PD_BLITTER,
	GEN9_DECOUPLED_PD_ALL,
	GEN9_DECOUPLED_PD_MEDIA,
	GEN9_DECOUPLED_PD_ALL,
	GEN9_DECOUPLED_PD_ALL,
	GEN9_DECOUPLED_PD_ALL
};

/*
 * Decoupled MMIO access for only 1 DWORD
 */
static void __gen9_decoupled_mmio_access(struct drm_i915_private *dev_priv,
					 u32 reg,
					 enum forcewake_domains fw_domain,
					 enum decoupled_ops operation)
{
	enum decoupled_power_domain dp_domain;
	u32 ctrl_reg_data = 0;

	dp_domain = fw2dpd_domain[fw_domain - 1];

	ctrl_reg_data |= reg;
	ctrl_reg_data |= (operation << GEN9_DECOUPLED_OP_SHIFT);
	ctrl_reg_data |= (dp_domain << GEN9_DECOUPLED_PD_SHIFT);
	ctrl_reg_data |= GEN9_DECOUPLED_DW1_GO;
	__raw_i915_write32(dev_priv, GEN9_DECOUPLED_REG0_DW1, ctrl_reg_data);

	if (wait_for_atomic((__raw_i915_read32(dev_priv,
			    GEN9_DECOUPLED_REG0_DW1) &
			    GEN9_DECOUPLED_DW1_GO) == 0,
			    FORCEWAKE_ACK_TIMEOUT_MS))
		DRM_ERROR("Decoupled MMIO wait timed out\n");
}

static inline u32
__gen9_decoupled_mmio_read32(struct drm_i915_private *dev_priv,
			     u32 reg,
			     enum forcewake_domains fw_domain)
{
	__gen9_decoupled_mmio_access(dev_priv, reg, fw_domain,
				     GEN9_DECOUPLED_OP_READ);

	return __raw_i915_read32(dev_priv, GEN9_DECOUPLED_REG0_DW0);
}

static inline void
__gen9_decoupled_mmio_write(struct drm_i915_private *dev_priv,
			    u32 reg, u32 data,
			    enum forcewake_domains fw_domain)
{

	__raw_i915_write32(dev_priv, GEN9_DECOUPLED_REG0_DW0, data);

	__gen9_decoupled_mmio_access(dev_priv, reg, fw_domain,
				     GEN9_DECOUPLED_OP_WRITE);
}


#define GEN2_READ_HEADER(x) \
	u##x val = 0; \
	assert_rpm_wakelock_held(dev_priv);

#define GEN2_READ_FOOTER \
	trace_i915_reg_rw(false, reg, val, sizeof(val), trace); \
	return val

#define __gen2_read(x) \
static u##x \
gen2_read##x(struct drm_i915_private *dev_priv, i915_reg_t reg, bool trace) { \
	GEN2_READ_HEADER(x); \
	val = __raw_i915_read##x(dev_priv, reg); \
	GEN2_READ_FOOTER; \
}

#define __gen5_read(x) \
static u##x \
gen5_read##x(struct drm_i915_private *dev_priv, i915_reg_t reg, bool trace) { \
	GEN2_READ_HEADER(x); \
	ilk_dummy_write(dev_priv); \
	val = __raw_i915_read##x(dev_priv, reg); \
	GEN2_READ_FOOTER; \
}

__gen5_read(8)
__gen5_read(16)
__gen5_read(32)
__gen5_read(64)
__gen2_read(8)
__gen2_read(16)
__gen2_read(32)
__gen2_read(64)

#undef __gen5_read
#undef __gen2_read

#undef GEN2_READ_FOOTER
#undef GEN2_READ_HEADER

#define GEN6_READ_HEADER(x) \
	u32 offset = i915_mmio_reg_offset(reg); \
	unsigned long irqflags; \
	u##x val = 0; \
	assert_rpm_wakelock_held(dev_priv); \
	spin_lock_irqsave(&dev_priv->uncore.lock, irqflags); \
	unclaimed_reg_debug(dev_priv, reg, true, true)

#define GEN6_READ_FOOTER \
	unclaimed_reg_debug(dev_priv, reg, true, false); \
	spin_unlock_irqrestore(&dev_priv->uncore.lock, irqflags); \
	trace_i915_reg_rw(false, reg, val, sizeof(val), trace); \
	return val

static noinline void ___force_wake_auto(struct drm_i915_private *dev_priv,
					enum forcewake_domains fw_domains)
{
	struct intel_uncore_forcewake_domain *domain;
	unsigned int tmp;

	GEM_BUG_ON(fw_domains & ~dev_priv->uncore.fw_domains);

	for_each_fw_domain_masked(domain, fw_domains, dev_priv, tmp)
		fw_domain_arm_timer(domain);

	dev_priv->uncore.funcs.force_wake_get(dev_priv, fw_domains);
}

static inline void __force_wake_auto(struct drm_i915_private *dev_priv,
				     enum forcewake_domains fw_domains)
{
	if (WARN_ON(!fw_domains))
		return;

	/* Turn on all requested but inactive supported forcewake domains. */
	fw_domains &= dev_priv->uncore.fw_domains;
	fw_domains &= ~dev_priv->uncore.fw_domains_active;

	if (fw_domains)
		___force_wake_auto(dev_priv, fw_domains);
}

#define __gen_read(func, x) \
static u##x \
func##_read##x(struct drm_i915_private *dev_priv, i915_reg_t reg, bool trace) { \
	enum forcewake_domains fw_engine; \
	GEN6_READ_HEADER(x); \
	fw_engine = __##func##_reg_read_fw_domains(offset); \
	if (fw_engine) \
		__force_wake_auto(dev_priv, fw_engine); \
	val = __raw_i915_read##x(dev_priv, reg); \
	GEN6_READ_FOOTER; \
}
#define __gen6_read(x) __gen_read(gen6, x)
#define __fwtable_read(x) __gen_read(fwtable, x)

#define __gen9_decoupled_read(x) \
static u##x \
gen9_decoupled_read##x(struct drm_i915_private *dev_priv, \
		       i915_reg_t reg, bool trace) { \
	enum forcewake_domains fw_engine; \
	GEN6_READ_HEADER(x); \
	fw_engine = __fwtable_reg_read_fw_domains(offset); \
	if (fw_engine & ~dev_priv->uncore.fw_domains_active) { \
		unsigned i; \
		u32 *ptr_data = (u32 *) &val; \
		for (i = 0; i < x/32; i++, offset += sizeof(u32), ptr_data++) \
			*ptr_data = __gen9_decoupled_mmio_read32(dev_priv, \
								 offset, \
								 fw_engine); \
	} else { \
		val = __raw_i915_read##x(dev_priv, reg); \
	} \
	GEN6_READ_FOOTER; \
}

__gen9_decoupled_read(32)
__gen9_decoupled_read(64)
__fwtable_read(8)
__fwtable_read(16)
__fwtable_read(32)
__fwtable_read(64)
__gen6_read(8)
__gen6_read(16)
__gen6_read(32)
__gen6_read(64)

#undef __fwtable_read
#undef __gen6_read
#undef GEN6_READ_FOOTER
#undef GEN6_READ_HEADER

#define GEN2_WRITE_HEADER \
	trace_i915_reg_rw(true, reg, val, sizeof(val), trace); \
	assert_rpm_wakelock_held(dev_priv); \

#define GEN2_WRITE_FOOTER

#define __gen2_write(x) \
static void \
gen2_write##x(struct drm_i915_private *dev_priv, i915_reg_t reg, u##x val, bool trace) { \
	GEN2_WRITE_HEADER; \
	__raw_i915_write##x(dev_priv, reg, val); \
	GEN2_WRITE_FOOTER; \
}

#define __gen5_write(x) \
static void \
gen5_write##x(struct drm_i915_private *dev_priv, i915_reg_t reg, u##x val, bool trace) { \
	GEN2_WRITE_HEADER; \
	ilk_dummy_write(dev_priv); \
	__raw_i915_write##x(dev_priv, reg, val); \
	GEN2_WRITE_FOOTER; \
}

__gen5_write(8)
__gen5_write(16)
__gen5_write(32)
__gen2_write(8)
__gen2_write(16)
__gen2_write(32)

#undef __gen5_write
#undef __gen2_write

#undef GEN2_WRITE_FOOTER
#undef GEN2_WRITE_HEADER

#define GEN6_WRITE_HEADER \
	u32 offset = i915_mmio_reg_offset(reg); \
	unsigned long irqflags; \
	trace_i915_reg_rw(true, reg, val, sizeof(val), trace); \
	assert_rpm_wakelock_held(dev_priv); \
	spin_lock_irqsave(&dev_priv->uncore.lock, irqflags); \
	unclaimed_reg_debug(dev_priv, reg, false, true)

#define GEN6_WRITE_FOOTER \
	unclaimed_reg_debug(dev_priv, reg, false, false); \
	spin_unlock_irqrestore(&dev_priv->uncore.lock, irqflags)

#define __gen6_write(x) \
static void \
gen6_write##x(struct drm_i915_private *dev_priv, i915_reg_t reg, u##x val, bool trace) { \
	u32 __fifo_ret = 0; \
	GEN6_WRITE_HEADER; \
	if (NEEDS_FORCE_WAKE(offset)) { \
		__fifo_ret = __gen6_gt_wait_for_fifo(dev_priv); \
	} \
	__raw_i915_write##x(dev_priv, reg, val); \
	if (unlikely(__fifo_ret)) { \
		gen6_gt_check_fifodbg(dev_priv); \
	} \
	GEN6_WRITE_FOOTER; \
}

#define __gen_write(func, x) \
static void \
func##_write##x(struct drm_i915_private *dev_priv, i915_reg_t reg, u##x val, bool trace) { \
	enum forcewake_domains fw_engine; \
	GEN6_WRITE_HEADER; \
	fw_engine = __##func##_reg_write_fw_domains(offset); \
	if (fw_engine) \
		__force_wake_auto(dev_priv, fw_engine); \
	__raw_i915_write##x(dev_priv, reg, val); \
	GEN6_WRITE_FOOTER; \
}
#define __gen8_write(x) __gen_write(gen8, x)
#define __fwtable_write(x) __gen_write(fwtable, x)

#define __gen9_decoupled_write(x) \
static void \
gen9_decoupled_write##x(struct drm_i915_private *dev_priv, \
			i915_reg_t reg, u##x val, \
		bool trace) { \
	enum forcewake_domains fw_engine; \
	GEN6_WRITE_HEADER; \
	fw_engine = __fwtable_reg_write_fw_domains(offset); \
	if (fw_engine & ~dev_priv->uncore.fw_domains_active) \
		__gen9_decoupled_mmio_write(dev_priv, \
					    offset, \
					    val, \
					    fw_engine); \
	else \
		__raw_i915_write##x(dev_priv, reg, val); \
	GEN6_WRITE_FOOTER; \
}

__gen9_decoupled_write(32)
__fwtable_write(8)
__fwtable_write(16)
__fwtable_write(32)
__gen8_write(8)
__gen8_write(16)
__gen8_write(32)
__gen6_write(8)
__gen6_write(16)
__gen6_write(32)

#undef __fwtable_write
#undef __gen8_write
#undef __gen6_write
#undef GEN6_WRITE_FOOTER
#undef GEN6_WRITE_HEADER

#define ASSIGN_WRITE_MMIO_VFUNCS(x) \
do { \
	dev_priv->uncore.funcs.mmio_writeb = x##_write8; \
	dev_priv->uncore.funcs.mmio_writew = x##_write16; \
	dev_priv->uncore.funcs.mmio_writel = x##_write32; \
} while (0)

#define ASSIGN_READ_MMIO_VFUNCS(x) \
do { \
	dev_priv->uncore.funcs.mmio_readb = x##_read8; \
	dev_priv->uncore.funcs.mmio_readw = x##_read16; \
	dev_priv->uncore.funcs.mmio_readl = x##_read32; \
	dev_priv->uncore.funcs.mmio_readq = x##_read64; \
} while (0)


static void fw_domain_init(struct drm_i915_private *dev_priv,
			   enum forcewake_domain_id domain_id,
			   i915_reg_t reg_set,
			   i915_reg_t reg_ack)
{
	struct intel_uncore_forcewake_domain *d;

	if (WARN_ON(domain_id >= FW_DOMAIN_ID_COUNT))
		return;

	d = &dev_priv->uncore.fw_domain[domain_id];

	WARN_ON(d->wake_count);

	WARN_ON(!i915_mmio_reg_valid(reg_set));
	WARN_ON(!i915_mmio_reg_valid(reg_ack));

	d->wake_count = 0;
	d->reg_set = reg_set;
	d->reg_ack = reg_ack;

	d->id = domain_id;

	BUILD_BUG_ON(FORCEWAKE_RENDER != (1 << FW_DOMAIN_ID_RENDER));
	BUILD_BUG_ON(FORCEWAKE_BLITTER != (1 << FW_DOMAIN_ID_BLITTER));
	BUILD_BUG_ON(FORCEWAKE_MEDIA != (1 << FW_DOMAIN_ID_MEDIA));

	d->mask = BIT(domain_id);

	hrtimer_init(&d->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	d->timer.function = intel_uncore_fw_release_timer;

	dev_priv->uncore.fw_domains |= BIT(domain_id);

	fw_domain_reset(dev_priv, d);
}

static void intel_uncore_fw_domains_init(struct drm_i915_private *dev_priv)
{
	if (INTEL_GEN(dev_priv) <= 5 || intel_vgpu_active(dev_priv))
		return;

	if (IS_GEN6(dev_priv)) {
		dev_priv->uncore.fw_reset = 0;
		dev_priv->uncore.fw_set = FORCEWAKE_KERNEL;
		dev_priv->uncore.fw_clear = 0;
	} else {
		/* WaRsClearFWBitsAtReset:bdw,skl */
		dev_priv->uncore.fw_reset = _MASKED_BIT_DISABLE(0xffff);
		dev_priv->uncore.fw_set = _MASKED_BIT_ENABLE(FORCEWAKE_KERNEL);
		dev_priv->uncore.fw_clear = _MASKED_BIT_DISABLE(FORCEWAKE_KERNEL);
	}

	if (IS_GEN9(dev_priv)) {
		dev_priv->uncore.funcs.force_wake_get = fw_domains_get;
		dev_priv->uncore.funcs.force_wake_put = fw_domains_put;
		fw_domain_init(dev_priv, FW_DOMAIN_ID_RENDER,
			       FORCEWAKE_RENDER_GEN9,
			       FORCEWAKE_ACK_RENDER_GEN9);
		fw_domain_init(dev_priv, FW_DOMAIN_ID_BLITTER,
			       FORCEWAKE_BLITTER_GEN9,
			       FORCEWAKE_ACK_BLITTER_GEN9);
		fw_domain_init(dev_priv, FW_DOMAIN_ID_MEDIA,
			       FORCEWAKE_MEDIA_GEN9, FORCEWAKE_ACK_MEDIA_GEN9);
	} else if (IS_VALLEYVIEW(dev_priv) || IS_CHERRYVIEW(dev_priv)) {
		dev_priv->uncore.funcs.force_wake_get = fw_domains_get;
		if (!IS_CHERRYVIEW(dev_priv))
			dev_priv->uncore.funcs.force_wake_put =
				fw_domains_put_with_fifo;
		else
			dev_priv->uncore.funcs.force_wake_put = fw_domains_put;
		fw_domain_init(dev_priv, FW_DOMAIN_ID_RENDER,
			       FORCEWAKE_VLV, FORCEWAKE_ACK_VLV);
		fw_domain_init(dev_priv, FW_DOMAIN_ID_MEDIA,
			       FORCEWAKE_MEDIA_VLV, FORCEWAKE_ACK_MEDIA_VLV);
	} else if (IS_HASWELL(dev_priv) || IS_BROADWELL(dev_priv)) {
		dev_priv->uncore.funcs.force_wake_get =
			fw_domains_get_with_thread_status;
		if (IS_HASWELL(dev_priv))
			dev_priv->uncore.funcs.force_wake_put =
				fw_domains_put_with_fifo;
		else
			dev_priv->uncore.funcs.force_wake_put = fw_domains_put;
		fw_domain_init(dev_priv, FW_DOMAIN_ID_RENDER,
			       FORCEWAKE_MT, FORCEWAKE_ACK_HSW);
	} else if (IS_IVYBRIDGE(dev_priv)) {
		u32 ecobus;

		/* IVB configs may use multi-threaded forcewake */

		/* A small trick here - if the bios hasn't configured
		 * MT forcewake, and if the device is in RC6, then
		 * force_wake_mt_get will not wake the device and the
		 * ECOBUS read will return zero. Which will be
		 * (correctly) interpreted by the test below as MT
		 * forcewake being disabled.
		 */
		dev_priv->uncore.funcs.force_wake_get =
			fw_domains_get_with_thread_status;
		dev_priv->uncore.funcs.force_wake_put =
			fw_domains_put_with_fifo;

		/* We need to init first for ECOBUS access and then
		 * determine later if we want to reinit, in case of MT access is
		 * not working. In this stage we don't know which flavour this
		 * ivb is, so it is better to reset also the gen6 fw registers
		 * before the ecobus check.
		 */

		__raw_i915_write32(dev_priv, FORCEWAKE, 0);
		__raw_posting_read(dev_priv, ECOBUS);

		fw_domain_init(dev_priv, FW_DOMAIN_ID_RENDER,
			       FORCEWAKE_MT, FORCEWAKE_MT_ACK);

		spin_lock_irq(&dev_priv->uncore.lock);
		fw_domains_get_with_thread_status(dev_priv, FORCEWAKE_RENDER);
		ecobus = __raw_i915_read32(dev_priv, ECOBUS);
		fw_domains_put_with_fifo(dev_priv, FORCEWAKE_RENDER);
		spin_unlock_irq(&dev_priv->uncore.lock);

		if (!(ecobus & FORCEWAKE_MT_ENABLE)) {
			DRM_INFO("No MT forcewake available on Ivybridge, this can result in issues\n");
			DRM_INFO("when using vblank-synced partial screen updates.\n");
			fw_domain_init(dev_priv, FW_DOMAIN_ID_RENDER,
				       FORCEWAKE, FORCEWAKE_ACK);
		}
	} else if (IS_GEN6(dev_priv)) {
		dev_priv->uncore.funcs.force_wake_get =
			fw_domains_get_with_thread_status;
		dev_priv->uncore.funcs.force_wake_put =
			fw_domains_put_with_fifo;
		fw_domain_init(dev_priv, FW_DOMAIN_ID_RENDER,
			       FORCEWAKE, FORCEWAKE_ACK);
	}

	/* All future platforms are expected to require complex power gating */
	WARN_ON(dev_priv->uncore.fw_domains == 0);
}

#define ASSIGN_FW_DOMAINS_TABLE(d) \
{ \
	dev_priv->uncore.fw_domains_table = \
			(struct intel_forcewake_range *)(d); \
	dev_priv->uncore.fw_domains_table_entries = ARRAY_SIZE((d)); \
}

static int i915_pmic_bus_access_notifier(struct notifier_block *nb,
					 unsigned long action, void *data)
{
	struct drm_i915_private *dev_priv = container_of(nb,
			struct drm_i915_private, uncore.pmic_bus_access_nb);

	switch (action) {
	case MBI_PMIC_BUS_ACCESS_BEGIN:
		/*
		 * forcewake all now to make sure that we don't need to do a
		 * forcewake later which on systems where this notifier gets
		 * called requires the punit to access to the shared pmic i2c
		 * bus, which will be busy after this notification, leading to:
		 * "render: timed out waiting for forcewake ack request."
		 * errors.
		 */
		intel_uncore_forcewake_get(dev_priv, FORCEWAKE_ALL);
		break;
	case MBI_PMIC_BUS_ACCESS_END:
		intel_uncore_forcewake_put(dev_priv, FORCEWAKE_ALL);
		break;
	}

	return NOTIFY_OK;
}

void intel_uncore_init(struct drm_i915_private *dev_priv)
{
	i915_check_vgpu(dev_priv);

	intel_uncore_edram_detect(dev_priv);
	intel_uncore_fw_domains_init(dev_priv);
	__intel_uncore_early_sanitize(dev_priv, false);

	dev_priv->uncore.unclaimed_mmio_check = 1;
	dev_priv->uncore.pmic_bus_access_nb.notifier_call =
		i915_pmic_bus_access_notifier;

	if (IS_GEN(dev_priv, 2, 4) || intel_vgpu_active(dev_priv)) {
		ASSIGN_WRITE_MMIO_VFUNCS(gen2);
		ASSIGN_READ_MMIO_VFUNCS(gen2);
	} else if (IS_GEN5(dev_priv)) {
		ASSIGN_WRITE_MMIO_VFUNCS(gen5);
		ASSIGN_READ_MMIO_VFUNCS(gen5);
	} else if (IS_GEN(dev_priv, 6, 7)) {
		ASSIGN_WRITE_MMIO_VFUNCS(gen6);

		if (IS_VALLEYVIEW(dev_priv)) {
			ASSIGN_FW_DOMAINS_TABLE(__vlv_fw_ranges);
			ASSIGN_READ_MMIO_VFUNCS(fwtable);
		} else {
			ASSIGN_READ_MMIO_VFUNCS(gen6);
		}
	} else if (IS_GEN8(dev_priv)) {
		if (IS_CHERRYVIEW(dev_priv)) {
			ASSIGN_FW_DOMAINS_TABLE(__chv_fw_ranges);
			ASSIGN_WRITE_MMIO_VFUNCS(fwtable);
			ASSIGN_READ_MMIO_VFUNCS(fwtable);

		} else {
			ASSIGN_WRITE_MMIO_VFUNCS(gen8);
			ASSIGN_READ_MMIO_VFUNCS(gen6);
		}
	} else {
		ASSIGN_FW_DOMAINS_TABLE(__gen9_fw_ranges);
		ASSIGN_WRITE_MMIO_VFUNCS(fwtable);
		ASSIGN_READ_MMIO_VFUNCS(fwtable);
		if (HAS_DECOUPLED_MMIO(dev_priv)) {
			dev_priv->uncore.funcs.mmio_readl =
						gen9_decoupled_read32;
			dev_priv->uncore.funcs.mmio_readq =
						gen9_decoupled_read64;
			dev_priv->uncore.funcs.mmio_writel =
						gen9_decoupled_write32;
		}
	}

	iosf_mbi_register_pmic_bus_access_notifier(
		&dev_priv->uncore.pmic_bus_access_nb);

	i915_check_and_clear_faults(dev_priv);
}
#undef ASSIGN_WRITE_MMIO_VFUNCS
#undef ASSIGN_READ_MMIO_VFUNCS

void intel_uncore_fini(struct drm_i915_private *dev_priv)
{
	iosf_mbi_unregister_pmic_bus_access_notifier(
		&dev_priv->uncore.pmic_bus_access_nb);

	/* Paranoia: make sure we have disabled everything before we exit. */
	intel_uncore_sanitize(dev_priv);
	intel_uncore_forcewake_reset(dev_priv, false);
}

#define GEN_RANGE(l, h) GENMASK((h) - 1, (l) - 1)

static const struct register_whitelist {
	i915_reg_t offset_ldw, offset_udw;
	uint32_t size;
	/* supported gens, 0x10 for 4, 0x30 for 4 and 5, etc. */
	uint32_t gen_bitmask;
} whitelist[] = {
	{ .offset_ldw = RING_TIMESTAMP(RENDER_RING_BASE),
	  .offset_udw = RING_TIMESTAMP_UDW(RENDER_RING_BASE),
	  .size = 8, .gen_bitmask = GEN_RANGE(4, 9) },
};

int i915_reg_read_ioctl(struct drm_device *dev,
			void *data, struct drm_file *file)
{
	struct drm_i915_private *dev_priv = to_i915(dev);
	struct drm_i915_reg_read *reg = data;
	struct register_whitelist const *entry = whitelist;
	unsigned size;
	i915_reg_t offset_ldw, offset_udw;
	int i, ret = 0;

	for (i = 0; i < ARRAY_SIZE(whitelist); i++, entry++) {
		if (i915_mmio_reg_offset(entry->offset_ldw) == (reg->offset & -entry->size) &&
		    (INTEL_INFO(dev_priv)->gen_mask & entry->gen_bitmask))
			break;
	}

	if (i == ARRAY_SIZE(whitelist))
		return -EINVAL;

	/* We use the low bits to encode extra flags as the register should
	 * be naturally aligned (and those that are not so aligned merely
	 * limit the available flags for that register).
	 */
	offset_ldw = entry->offset_ldw;
	offset_udw = entry->offset_udw;
	size = entry->size;
	size |= reg->offset ^ i915_mmio_reg_offset(offset_ldw);

	intel_runtime_pm_get(dev_priv);

	switch (size) {
	case 8 | 1:
		reg->val = I915_READ64_2x32(offset_ldw, offset_udw);
		break;
	case 8:
		reg->val = I915_READ64(offset_ldw);
		break;
	case 4:
		reg->val = I915_READ(offset_ldw);
		break;
	case 2:
		reg->val = I915_READ16(offset_ldw);
		break;
	case 1:
		reg->val = I915_READ8(offset_ldw);
		break;
	default:
		ret = -EINVAL;
		goto out;
	}

out:
	intel_runtime_pm_put(dev_priv);
	return ret;
}

static int i915_reset_complete(struct pci_dev *pdev)
{
	u8 gdrst;
	pci_read_config_byte(pdev, I915_GDRST, &gdrst);
	return (gdrst & GRDOM_RESET_STATUS) == 0;
}

static int i915_do_reset(struct drm_i915_private *dev_priv, unsigned engine_mask)
{
	struct pci_dev *pdev = dev_priv->drm.pdev;

	/* assert reset for at least 20 usec */
	pci_write_config_byte(pdev, I915_GDRST, GRDOM_RESET_ENABLE);
	udelay(20);
	pci_write_config_byte(pdev, I915_GDRST, 0);

	return wait_for(i915_reset_complete(pdev), 500);
}

static int g4x_reset_complete(struct pci_dev *pdev)
{
	u8 gdrst;
	pci_read_config_byte(pdev, I915_GDRST, &gdrst);
	return (gdrst & GRDOM_RESET_ENABLE) == 0;
}

static int g33_do_reset(struct drm_i915_private *dev_priv, unsigned engine_mask)
{
	struct pci_dev *pdev = dev_priv->drm.pdev;
	pci_write_config_byte(pdev, I915_GDRST, GRDOM_RESET_ENABLE);
	return wait_for(g4x_reset_complete(pdev), 500);
}

static int g4x_do_reset(struct drm_i915_private *dev_priv, unsigned engine_mask)
{
	struct pci_dev *pdev = dev_priv->drm.pdev;
	int ret;

	pci_write_config_byte(pdev, I915_GDRST,
			      GRDOM_RENDER | GRDOM_RESET_ENABLE);
	ret =  wait_for(g4x_reset_complete(pdev), 500);
	if (ret)
		return ret;

	/* WaVcpClkGateDisableForMediaReset:ctg,elk */
	I915_WRITE(VDECCLK_GATE_D, I915_READ(VDECCLK_GATE_D) | VCP_UNIT_CLOCK_GATE_DISABLE);
	POSTING_READ(VDECCLK_GATE_D);

	pci_write_config_byte(pdev, I915_GDRST,
			      GRDOM_MEDIA | GRDOM_RESET_ENABLE);
	ret =  wait_for(g4x_reset_complete(pdev), 500);
	if (ret)
		return ret;

	/* WaVcpClkGateDisableForMediaReset:ctg,elk */
	I915_WRITE(VDECCLK_GATE_D, I915_READ(VDECCLK_GATE_D) & ~VCP_UNIT_CLOCK_GATE_DISABLE);
	POSTING_READ(VDECCLK_GATE_D);

	pci_write_config_byte(pdev, I915_GDRST, 0);

	return 0;
}

static int ironlake_do_reset(struct drm_i915_private *dev_priv,
			     unsigned engine_mask)
{
	int ret;

	I915_WRITE(ILK_GDSR,
		   ILK_GRDOM_RENDER | ILK_GRDOM_RESET_ENABLE);
	ret = intel_wait_for_register(dev_priv,
				      ILK_GDSR, ILK_GRDOM_RESET_ENABLE, 0,
				      500);
	if (ret)
		return ret;

	I915_WRITE(ILK_GDSR,
		   ILK_GRDOM_MEDIA | ILK_GRDOM_RESET_ENABLE);
	ret = intel_wait_for_register(dev_priv,
				      ILK_GDSR, ILK_GRDOM_RESET_ENABLE, 0,
				      500);
	if (ret)
		return ret;

	I915_WRITE(ILK_GDSR, 0);

	return 0;
}

/* Reset the hardware domains (GENX_GRDOM_*) specified by mask */
static int gen6_hw_domain_reset(struct drm_i915_private *dev_priv,
				u32 hw_domain_mask)
{
	/* GEN6_GDRST is not in the gt power well, no need to check
	 * for fifo space for the write or forcewake the chip for
	 * the read
	 */
	__raw_i915_write32(dev_priv, GEN6_GDRST, hw_domain_mask);

	/* Spin waiting for the device to ack the reset requests */
	return intel_wait_for_register_fw(dev_priv,
					  GEN6_GDRST, hw_domain_mask, 0,
					  500);
}

/**
 * gen6_reset_engines - reset individual engines
 * @dev_priv: i915 device
 * @engine_mask: mask of intel_ring_flag() engines or ALL_ENGINES for full reset
 *
 * This function will reset the individual engines that are set in engine_mask.
 * If you provide ALL_ENGINES as mask, full global domain reset will be issued.
 *
 * Note: It is responsibility of the caller to handle the difference between
 * asking full domain reset versus reset for all available individual engines.
 *
 * Returns 0 on success, nonzero on error.
 */
static int gen6_reset_engines(struct drm_i915_private *dev_priv,
			      unsigned engine_mask)
{
	struct intel_engine_cs *engine;
	const u32 hw_engine_mask[I915_NUM_ENGINES] = {
		[RCS] = GEN6_GRDOM_RENDER,
		[BCS] = GEN6_GRDOM_BLT,
		[VCS] = GEN6_GRDOM_MEDIA,
		[VCS2] = GEN8_GRDOM_MEDIA2,
		[VECS] = GEN6_GRDOM_VECS,
	};
	u32 hw_mask;
	int ret;

	if (engine_mask == ALL_ENGINES) {
		hw_mask = GEN6_GRDOM_FULL;
	} else {
		unsigned int tmp;

		hw_mask = 0;
		for_each_engine_masked(engine, dev_priv, engine_mask, tmp)
			hw_mask |= hw_engine_mask[engine->id];
	}

	ret = gen6_hw_domain_reset(dev_priv, hw_mask);

	intel_uncore_forcewake_reset(dev_priv, true);

	return ret;
}

/**
 * intel_wait_for_register_fw - wait until register matches expected state
 * @dev_priv: the i915 device
 * @reg: the register to read
 * @mask: mask to apply to register value
 * @value: expected value
 * @timeout_ms: timeout in millisecond
 *
 * This routine waits until the target register @reg contains the expected
 * @value after applying the @mask, i.e. it waits until ::
 *
 *     (I915_READ_FW(reg) & mask) == value
 *
 * Otherwise, the wait will timeout after @timeout_ms milliseconds.
 *
 * Note that this routine assumes the caller holds forcewake asserted, it is
 * not suitable for very long waits. See intel_wait_for_register() if you
 * wish to wait without holding forcewake for the duration (i.e. you expect
 * the wait to be slow).
 *
 * Returns 0 if the register matches the desired condition, or -ETIMEOUT.
 */
int intel_wait_for_register_fw(struct drm_i915_private *dev_priv,
			       i915_reg_t reg,
			       const u32 mask,
			       const u32 value,
			       const unsigned long timeout_ms)
{
#define done ((I915_READ_FW(reg) & mask) == value)
	int ret = wait_for_us(done, 2);
	if (ret)
		ret = wait_for(done, timeout_ms);
	return ret;
#undef done
}

/**
 * intel_wait_for_register - wait until register matches expected state
 * @dev_priv: the i915 device
 * @reg: the register to read
 * @mask: mask to apply to register value
 * @value: expected value
 * @timeout_ms: timeout in millisecond
 *
 * This routine waits until the target register @reg contains the expected
 * @value after applying the @mask, i.e. it waits until ::
 *
 *     (I915_READ(reg) & mask) == value
 *
 * Otherwise, the wait will timeout after @timeout_ms milliseconds.
 *
 * Returns 0 if the register matches the desired condition, or -ETIMEOUT.
 */
int intel_wait_for_register(struct drm_i915_private *dev_priv,
			    i915_reg_t reg,
			    const u32 mask,
			    const u32 value,
			    const unsigned long timeout_ms)
{

	unsigned fw =
		intel_uncore_forcewake_for_reg(dev_priv, reg, FW_REG_READ);
	int ret;

	intel_uncore_forcewake_get(dev_priv, fw);
	ret = wait_for_us((I915_READ_FW(reg) & mask) == value, 2);
	intel_uncore_forcewake_put(dev_priv, fw);
	if (ret)
		ret = wait_for((I915_READ_NOTRACE(reg) & mask) == value,
			       timeout_ms);

	return ret;
}

static int gen8_request_engine_reset(struct intel_engine_cs *engine)
{
	struct drm_i915_private *dev_priv = engine->i915;
	int ret;

	I915_WRITE_FW(RING_RESET_CTL(engine->mmio_base),
		      _MASKED_BIT_ENABLE(RESET_CTL_REQUEST_RESET));

	ret = intel_wait_for_register_fw(dev_priv,
					 RING_RESET_CTL(engine->mmio_base),
					 RESET_CTL_READY_TO_RESET,
					 RESET_CTL_READY_TO_RESET,
					 700);
	if (ret)
		DRM_ERROR("%s: reset request timeout\n", engine->name);

	return ret;
}

static void gen8_unrequest_engine_reset(struct intel_engine_cs *engine)
{
	struct drm_i915_private *dev_priv = engine->i915;

	I915_WRITE_FW(RING_RESET_CTL(engine->mmio_base),
		      _MASKED_BIT_DISABLE(RESET_CTL_REQUEST_RESET));
}

static int gen8_reset_engines(struct drm_i915_private *dev_priv,
			      unsigned engine_mask)
{
	struct intel_engine_cs *engine;
	unsigned int tmp;

	for_each_engine_masked(engine, dev_priv, engine_mask, tmp)
		if (gen8_request_engine_reset(engine))
			goto not_ready;

	return gen6_reset_engines(dev_priv, engine_mask);

not_ready:
	for_each_engine_masked(engine, dev_priv, engine_mask, tmp)
		gen8_unrequest_engine_reset(engine);

	return -EIO;
}

typedef int (*reset_func)(struct drm_i915_private *, unsigned engine_mask);

static reset_func intel_get_gpu_reset(struct drm_i915_private *dev_priv)
{
	if (!i915.reset)
		return NULL;

	if (INTEL_INFO(dev_priv)->gen >= 8)
		return gen8_reset_engines;
	else if (INTEL_INFO(dev_priv)->gen >= 6)
		return gen6_reset_engines;
	else if (IS_GEN5(dev_priv))
		return ironlake_do_reset;
	else if (IS_G4X(dev_priv))
		return g4x_do_reset;
	else if (IS_G33(dev_priv) || IS_PINEVIEW(dev_priv))
		return g33_do_reset;
	else if (INTEL_INFO(dev_priv)->gen >= 3)
		return i915_do_reset;
	else
		return NULL;
}

int intel_gpu_reset(struct drm_i915_private *dev_priv, unsigned engine_mask)
{
	reset_func reset;
	int ret;

	reset = intel_get_gpu_reset(dev_priv);
	if (reset == NULL)
		return -ENODEV;

	/* If the power well sleeps during the reset, the reset
	 * request may be dropped and never completes (causing -EIO).
	 */
	intel_uncore_forcewake_get(dev_priv, FORCEWAKE_ALL);
	ret = reset(dev_priv, engine_mask);
	intel_uncore_forcewake_put(dev_priv, FORCEWAKE_ALL);

	return ret;
}

bool intel_has_gpu_reset(struct drm_i915_private *dev_priv)
{
	return intel_get_gpu_reset(dev_priv) != NULL;
}

int intel_guc_reset(struct drm_i915_private *dev_priv)
{
	int ret;
	unsigned long irqflags;

	if (!HAS_GUC(dev_priv))
		return -EINVAL;

	intel_uncore_forcewake_get(dev_priv, FORCEWAKE_ALL);
	spin_lock_irqsave(&dev_priv->uncore.lock, irqflags);

	ret = gen6_hw_domain_reset(dev_priv, GEN9_GRDOM_GUC);

	spin_unlock_irqrestore(&dev_priv->uncore.lock, irqflags);
	intel_uncore_forcewake_put(dev_priv, FORCEWAKE_ALL);

	return ret;
}

bool intel_uncore_unclaimed_mmio(struct drm_i915_private *dev_priv)
{
	return check_for_unclaimed_mmio(dev_priv);
}

bool
intel_uncore_arm_unclaimed_mmio_detection(struct drm_i915_private *dev_priv)
{
	if (unlikely(i915.mmio_debug ||
		     dev_priv->uncore.unclaimed_mmio_check <= 0))
		return false;

	if (unlikely(intel_uncore_unclaimed_mmio(dev_priv))) {
		DRM_DEBUG("Unclaimed register detected, "
			  "enabling oneshot unclaimed register reporting. "
			  "Please use i915.mmio_debug=N for more information.\n");
		i915.mmio_debug++;
		dev_priv->uncore.unclaimed_mmio_check--;
		return true;
	}

	return false;
}

static enum forcewake_domains
intel_uncore_forcewake_for_read(struct drm_i915_private *dev_priv,
				i915_reg_t reg)
{
	u32 offset = i915_mmio_reg_offset(reg);
	enum forcewake_domains fw_domains;

	if (HAS_FWTABLE(dev_priv)) {
		fw_domains = __fwtable_reg_read_fw_domains(offset);
	} else if (INTEL_GEN(dev_priv) >= 6) {
		fw_domains = __gen6_reg_read_fw_domains(offset);
	} else {
		WARN_ON(!IS_GEN(dev_priv, 2, 5));
		fw_domains = 0;
	}

	WARN_ON(fw_domains & ~dev_priv->uncore.fw_domains);

	return fw_domains;
}

static enum forcewake_domains
intel_uncore_forcewake_for_write(struct drm_i915_private *dev_priv,
				 i915_reg_t reg)
{
	u32 offset = i915_mmio_reg_offset(reg);
	enum forcewake_domains fw_domains;

	if (HAS_FWTABLE(dev_priv) && !IS_VALLEYVIEW(dev_priv)) {
		fw_domains = __fwtable_reg_write_fw_domains(offset);
	} else if (IS_GEN8(dev_priv)) {
		fw_domains = __gen8_reg_write_fw_domains(offset);
	} else if (IS_GEN(dev_priv, 6, 7)) {
		fw_domains = FORCEWAKE_RENDER;
	} else {
		WARN_ON(!IS_GEN(dev_priv, 2, 5));
		fw_domains = 0;
	}

	WARN_ON(fw_domains & ~dev_priv->uncore.fw_domains);

	return fw_domains;
}

/**
 * intel_uncore_forcewake_for_reg - which forcewake domains are needed to access
 * 				    a register
 * @dev_priv: pointer to struct drm_i915_private
 * @reg: register in question
 * @op: operation bitmask of FW_REG_READ and/or FW_REG_WRITE
 *
 * Returns a set of forcewake domains required to be taken with for example
 * intel_uncore_forcewake_get for the specified register to be accessible in the
 * specified mode (read, write or read/write) with raw mmio accessors.
 *
 * NOTE: On Gen6 and Gen7 write forcewake domain (FORCEWAKE_RENDER) requires the
 * callers to do FIFO management on their own or risk losing writes.
 */
enum forcewake_domains
intel_uncore_forcewake_for_reg(struct drm_i915_private *dev_priv,
			       i915_reg_t reg, unsigned int op)
{
	enum forcewake_domains fw_domains = 0;

	WARN_ON(!op);

	if (intel_vgpu_active(dev_priv))
		return 0;

	if (op & FW_REG_READ)
		fw_domains = intel_uncore_forcewake_for_read(dev_priv, reg);

	if (op & FW_REG_WRITE)
		fw_domains |= intel_uncore_forcewake_for_write(dev_priv, reg);

	return fw_domains;
}

#if IS_ENABLED(CONFIG_DRM_I915_SELFTEST)
#include "selftests/intel_uncore.c"
#endif
