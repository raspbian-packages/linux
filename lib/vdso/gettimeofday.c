// SPDX-License-Identifier: GPL-2.0
/*
 * Generic userspace implementations of gettimeofday() and similar.
 */
#include <linux/compiler.h>
#include <linux/math64.h>
#include <linux/time.h>
#include <linux/kernel.h>
#include <linux/hrtimer_defs.h>
#include <vdso/datapage.h>
#include <vdso/helpers.h>

/*
 * The generic vDSO implementation requires that gettimeofday.h
 * provides:
 * - __arch_get_vdso_data(): to get the vdso datapage.
 * - __arch_get_hw_counter(): to get the hw counter based on the
 *   clock_mode.
 * - gettimeofday_fallback(): fallback for gettimeofday.
 * - clock_gettime_fallback(): fallback for clock_gettime.
 * - clock_getres_fallback(): fallback for clock_getres.
 */
#ifdef ENABLE_COMPAT_VDSO
#include <asm/vdso/compat_gettimeofday.h>
#else
#include <asm/vdso/gettimeofday.h>
#endif /* ENABLE_COMPAT_VDSO */

#ifndef vdso_calc_delta
/*
 * Default implementation which works for all sane clocksources. That
 * obviously excludes x86/TSC.
 */
static __always_inline
u64 vdso_calc_delta(u64 cycles, u64 last, u64 mask, u32 mult)
{
	return ((cycles - last) & mask) * mult;
}
#endif

#ifdef CONFIG_TIME_NS
static int do_hres_timens(const struct vdso_data *vdns, clockid_t clk,
			  struct __kernel_timespec *ts)
{
	const struct vdso_data *vd = __arch_get_timens_vdso_data();
	const struct timens_offset *offs = &vdns->offset[clk];
	const struct vdso_timestamp *vdso_ts;
	u64 cycles, last, ns;
	u32 seq;
	s64 sec;

	if (clk != CLOCK_MONOTONIC_RAW)
		vd = &vd[CS_HRES_COARSE];
	else
		vd = &vd[CS_RAW];
	vdso_ts = &vd->basetime[clk];

	do {
		seq = vdso_read_begin(vd);
		cycles = __arch_get_hw_counter(vd->clock_mode);
		ns = vdso_ts->nsec;
		last = vd->cycle_last;
		if (unlikely((s64)cycles < 0))
			return -1;

		ns += vdso_calc_delta(cycles, last, vd->mask, vd->mult);
		ns >>= vd->shift;
		sec = vdso_ts->sec;
	} while (unlikely(vdso_read_retry(vd, seq)));

	/* Add the namespace offset */
	sec += offs->sec;
	ns += offs->nsec;

	/*
	 * Do this outside the loop: a race inside the loop could result
	 * in __iter_div_u64_rem() being extremely slow.
	 */
	ts->tv_sec = sec + __iter_div_u64_rem(ns, NSEC_PER_SEC, &ns);
	ts->tv_nsec = ns;

	return 0;
}
#else
static __always_inline const struct vdso_data *__arch_get_timens_vdso_data(void)
{
	return NULL;
}

static int do_hres_timens(const struct vdso_data *vdns, clockid_t clk,
			  struct __kernel_timespec *ts)
{
	return -EINVAL;
}
#endif

static __always_inline int do_hres(const struct vdso_data *vd, clockid_t clk,
				   struct __kernel_timespec *ts)
{
	const struct vdso_timestamp *vdso_ts = &vd->basetime[clk];
	u64 cycles, last, sec, ns;
	u32 seq;

	do {
		/*
		 * Open coded to handle VCLOCK_TIMENS. Time namespace
		 * enabled tasks have a special VVAR page installed which
		 * has vd->seq set to 1 and vd->clock_mode set to
		 * VCLOCK_TIMENS. For non time namespace affected tasks
		 * this does not affect performance because if vd->seq is
		 * odd, i.e. a concurrent update is in progress the extra
		 * check for vd->clock_mode is just a few extra
		 * instructions while spin waiting for vd->seq to become
		 * even again.
		 */
		while (unlikely((seq = READ_ONCE(vd->seq)) & 1)) {
			if (IS_ENABLED(CONFIG_TIME_NS) &&
			    vd->clock_mode == VCLOCK_TIMENS)
				return do_hres_timens(vd, clk, ts);
			cpu_relax();
		}
		smp_rmb();

		cycles = __arch_get_hw_counter(vd->clock_mode);
		ns = vdso_ts->nsec;
		last = vd->cycle_last;
		if (unlikely((s64)cycles < 0))
			return -1;

		ns += vdso_calc_delta(cycles, last, vd->mask, vd->mult);
		ns >>= vd->shift;
		sec = vdso_ts->sec;
	} while (unlikely(vdso_read_retry(vd, seq)));

	/*
	 * Do this outside the loop: a race inside the loop could result
	 * in __iter_div_u64_rem() being extremely slow.
	 */
	ts->tv_sec = sec + __iter_div_u64_rem(ns, NSEC_PER_SEC, &ns);
	ts->tv_nsec = ns;

	return 0;
}

#ifdef CONFIG_TIME_NS
static int do_coarse_timens(const struct vdso_data *vdns, clockid_t clk,
			    struct __kernel_timespec *ts)
{
	const struct vdso_data *vd = __arch_get_timens_vdso_data();
	const struct vdso_timestamp *vdso_ts = &vd->basetime[clk];
	const struct timens_offset *offs = &vdns->offset[clk];
	u64 nsec;
	s64 sec;
	s32 seq;

	do {
		seq = vdso_read_begin(vd);
		sec = vdso_ts->sec;
		nsec = vdso_ts->nsec;
	} while (unlikely(vdso_read_retry(vd, seq)));

	/* Add the namespace offset */
	sec += offs->sec;
	nsec += offs->nsec;

	/*
	 * Do this outside the loop: a race inside the loop could result
	 * in __iter_div_u64_rem() being extremely slow.
	 */
	ts->tv_sec = sec + __iter_div_u64_rem(nsec, NSEC_PER_SEC, &nsec);
	ts->tv_nsec = nsec;
	return 0;
}
#else
static int do_coarse_timens(const struct vdso_data *vdns, clockid_t clk,
			    struct __kernel_timespec *ts)
{
	return -1;
}
#endif

static __always_inline int do_coarse(const struct vdso_data *vd, clockid_t clk,
				     struct __kernel_timespec *ts)
{
	const struct vdso_timestamp *vdso_ts = &vd->basetime[clk];
	u32 seq;

	do {
		/*
		 * Open coded to handle VCLOCK_TIMENS. See comment in
		 * do_hres().
		 */
		while ((seq = READ_ONCE(vd->seq)) & 1) {
			if (IS_ENABLED(CONFIG_TIME_NS) &&
			    vd->clock_mode == VCLOCK_TIMENS)
				return do_coarse_timens(vd, clk, ts);
			cpu_relax();
		}
		smp_rmb();

		ts->tv_sec = vdso_ts->sec;
		ts->tv_nsec = vdso_ts->nsec;
	} while (unlikely(vdso_read_retry(vd, seq)));

	return 0;
}

static __maybe_unused int
__cvdso_clock_gettime_common(clockid_t clock, struct __kernel_timespec *ts)
{
	const struct vdso_data *vd = __arch_get_vdso_data();
	u32 msk;

	/* Check for negative values or invalid clocks */
	if (unlikely((u32) clock >= MAX_CLOCKS))
		return -1;

	/*
	 * Convert the clockid to a bitmask and use it to check which
	 * clocks are handled in the VDSO directly.
	 */
	msk = 1U << clock;
	if (likely(msk & VDSO_HRES))
		vd = &vd[CS_HRES_COARSE];
	else if (msk & VDSO_COARSE)
		return do_coarse(&vd[CS_HRES_COARSE], clock, ts);
	else if (msk & VDSO_RAW)
		vd = &vd[CS_RAW];
	else
		return -1;

	return do_hres(vd, clock, ts);
}

static __maybe_unused int
__cvdso_clock_gettime(clockid_t clock, struct __kernel_timespec *ts)
{
	int ret = __cvdso_clock_gettime_common(clock, ts);

	if (unlikely(ret))
		return clock_gettime_fallback(clock, ts);
	return 0;
}

#ifdef BUILD_VDSO32
static __maybe_unused int
__cvdso_clock_gettime32(clockid_t clock, struct old_timespec32 *res)
{
	struct __kernel_timespec ts;
	int ret;

	ret = __cvdso_clock_gettime_common(clock, &ts);

	if (unlikely(ret))
		return clock_gettime32_fallback(clock, res);

	/* For ret == 0 */
	res->tv_sec = ts.tv_sec;
	res->tv_nsec = ts.tv_nsec;

	return ret;
}
#endif /* BUILD_VDSO32 */

static __maybe_unused int
__cvdso_gettimeofday(struct __kernel_old_timeval *tv, struct timezone *tz)
{
	const struct vdso_data *vd = __arch_get_vdso_data();

	if (likely(tv != NULL)) {
		struct __kernel_timespec ts;

		if (do_hres(&vd[CS_HRES_COARSE], CLOCK_REALTIME, &ts))
			return gettimeofday_fallback(tv, tz);

		tv->tv_sec = ts.tv_sec;
		tv->tv_usec = (u32)ts.tv_nsec / NSEC_PER_USEC;
	}

	if (unlikely(tz != NULL)) {
		if (IS_ENABLED(CONFIG_TIME_NS) &&
		    vd->clock_mode == VCLOCK_TIMENS)
			vd = __arch_get_timens_vdso_data();

		tz->tz_minuteswest = vd[CS_HRES_COARSE].tz_minuteswest;
		tz->tz_dsttime = vd[CS_HRES_COARSE].tz_dsttime;
	}

	return 0;
}

#ifdef VDSO_HAS_TIME
static __maybe_unused __kernel_old_time_t __cvdso_time(__kernel_old_time_t *time)
{
	const struct vdso_data *vd = __arch_get_vdso_data();
	__kernel_old_time_t t;

	if (IS_ENABLED(CONFIG_TIME_NS) && vd->clock_mode == VCLOCK_TIMENS)
		vd = __arch_get_timens_vdso_data();

	t = READ_ONCE(vd[CS_HRES_COARSE].basetime[CLOCK_REALTIME].sec);

	if (time)
		*time = t;

	return t;
}
#endif /* VDSO_HAS_TIME */

#ifdef VDSO_HAS_CLOCK_GETRES
static __maybe_unused
int __cvdso_clock_getres_common(clockid_t clock, struct __kernel_timespec *res)
{
	const struct vdso_data *vd = __arch_get_vdso_data();
	u32 msk;
	u64 ns;

	/* Check for negative values or invalid clocks */
	if (unlikely((u32) clock >= MAX_CLOCKS))
		return -1;

	if (IS_ENABLED(CONFIG_TIME_NS) && vd->clock_mode == VCLOCK_TIMENS)
		vd = __arch_get_timens_vdso_data();

	/*
	 * Convert the clockid to a bitmask and use it to check which
	 * clocks are handled in the VDSO directly.
	 */
	msk = 1U << clock;
	if (msk & (VDSO_HRES | VDSO_RAW)) {
		/*
		 * Preserves the behaviour of posix_get_hrtimer_res().
		 */
		ns = READ_ONCE(vd[CS_HRES_COARSE].hrtimer_res);
	} else if (msk & VDSO_COARSE) {
		/*
		 * Preserves the behaviour of posix_get_coarse_res().
		 */
		ns = LOW_RES_NSEC;
	} else {
		return -1;
	}

	if (likely(res)) {
		res->tv_sec = 0;
		res->tv_nsec = ns;
	}
	return 0;
}

static __maybe_unused
int __cvdso_clock_getres(clockid_t clock, struct __kernel_timespec *res)
{
	int ret = __cvdso_clock_getres_common(clock, res);

	if (unlikely(ret))
		return clock_getres_fallback(clock, res);
	return 0;
}

#ifdef BUILD_VDSO32
static __maybe_unused int
__cvdso_clock_getres_time32(clockid_t clock, struct old_timespec32 *res)
{
	struct __kernel_timespec ts;
	int ret;

	ret = __cvdso_clock_getres_common(clock, &ts);

	if (unlikely(ret))
		return clock_getres32_fallback(clock, res);

	if (likely(res)) {
		res->tv_sec = ts.tv_sec;
		res->tv_nsec = ts.tv_nsec;
	}
	return ret;
}
#endif /* BUILD_VDSO32 */
#endif /* VDSO_HAS_CLOCK_GETRES */
