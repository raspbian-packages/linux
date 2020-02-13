// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019, Vladimir Oltean <olteanv@gmail.com>
 */
#include "sja1105.h"

/* The adjfine API clamps ppb between [-32,768,000, 32,768,000], and
 * therefore scaled_ppm between [-2,147,483,648, 2,147,483,647].
 * Set the maximum supported ppb to a round value smaller than the maximum.
 *
 * Percentually speaking, this is a +/- 0.032x adjustment of the
 * free-running counter (0.968x to 1.032x).
 */
#define SJA1105_MAX_ADJ_PPB		32000000
#define SJA1105_SIZE_PTP_CMD		4

/* Timestamps are in units of 8 ns clock ticks (equivalent to a fixed
 * 125 MHz clock) so the scale factor (MULT / SHIFT) needs to be 8.
 * Furthermore, wisely pick SHIFT as 28 bits, which translates
 * MULT into 2^31 (0x80000000).  This is the same value around which
 * the hardware PTPCLKRATE is centered, so the same ppb conversion
 * arithmetic can be reused.
 */
#define SJA1105_CC_SHIFT		28
#define SJA1105_CC_MULT			(8 << SJA1105_CC_SHIFT)

/* Having 33 bits of cycle counter left until a 64-bit overflow during delta
 * conversion, we multiply this by the 8 ns counter resolution and arrive at
 * a comfortable 68.71 second refresh interval until the delta would cause
 * an integer overflow, in absence of any other readout.
 * Approximate to 1 minute.
 */
#define SJA1105_REFRESH_INTERVAL	(HZ * 60)

/*            This range is actually +/- SJA1105_MAX_ADJ_PPB
 *            divided by 1000 (ppb -> ppm) and with a 16-bit
 *            "fractional" part (actually fixed point).
 *                                    |
 *                                    v
 * Convert scaled_ppm from the +/- ((10^6) << 16) range
 * into the +/- (1 << 31) range.
 *
 * This forgoes a "ppb" numeric representation (up to NSEC_PER_SEC)
 * and defines the scaling factor between scaled_ppm and the actual
 * frequency adjustments (both cycle counter and hardware).
 *
 *   ptpclkrate = scaled_ppm * 2^31 / (10^6 * 2^16)
 *   simplifies to
 *   ptpclkrate = scaled_ppm * 2^9 / 5^6
 */
#define SJA1105_CC_MULT_NUM		(1 << 9)
#define SJA1105_CC_MULT_DEM		15625

#define ptp_to_sja1105(d) container_of((d), struct sja1105_private, ptp_caps)
#define cc_to_sja1105(d) container_of((d), struct sja1105_private, tstamp_cc)
#define dw_to_sja1105(d) container_of((d), struct sja1105_private, refresh_work)

struct sja1105_ptp_cmd {
	u64 resptp;       /* reset */
};

int sja1105_get_ts_info(struct dsa_switch *ds, int port,
			struct ethtool_ts_info *info)
{
	struct sja1105_private *priv = ds->priv;

	/* Called during cleanup */
	if (!priv->clock)
		return -ENODEV;

	info->so_timestamping = SOF_TIMESTAMPING_TX_HARDWARE |
				SOF_TIMESTAMPING_RX_HARDWARE |
				SOF_TIMESTAMPING_RAW_HARDWARE;
	info->tx_types = (1 << HWTSTAMP_TX_OFF) |
			 (1 << HWTSTAMP_TX_ON);
	info->rx_filters = (1 << HWTSTAMP_FILTER_NONE) |
			   (1 << HWTSTAMP_FILTER_PTP_V2_L2_EVENT);
	info->phc_index = ptp_clock_index(priv->clock);
	return 0;
}

int sja1105et_ptp_cmd(const void *ctx, const void *data)
{
	const struct sja1105_ptp_cmd *cmd = data;
	const struct sja1105_private *priv = ctx;
	const struct sja1105_regs *regs = priv->info->regs;
	const int size = SJA1105_SIZE_PTP_CMD;
	u8 buf[SJA1105_SIZE_PTP_CMD] = {0};
	/* No need to keep this as part of the structure */
	u64 valid = 1;

	sja1105_pack(buf, &valid,           31, 31, size);
	sja1105_pack(buf, &cmd->resptp,      2,  2, size);

	return sja1105_spi_send_packed_buf(priv, SPI_WRITE, regs->ptp_control,
					   buf, SJA1105_SIZE_PTP_CMD);
}

int sja1105pqrs_ptp_cmd(const void *ctx, const void *data)
{
	const struct sja1105_ptp_cmd *cmd = data;
	const struct sja1105_private *priv = ctx;
	const struct sja1105_regs *regs = priv->info->regs;
	const int size = SJA1105_SIZE_PTP_CMD;
	u8 buf[SJA1105_SIZE_PTP_CMD] = {0};
	/* No need to keep this as part of the structure */
	u64 valid = 1;

	sja1105_pack(buf, &valid,           31, 31, size);
	sja1105_pack(buf, &cmd->resptp,      3,  3, size);

	return sja1105_spi_send_packed_buf(priv, SPI_WRITE, regs->ptp_control,
					   buf, SJA1105_SIZE_PTP_CMD);
}

/* The switch returns partial timestamps (24 bits for SJA1105 E/T, which wrap
 * around in 0.135 seconds, and 32 bits for P/Q/R/S, wrapping around in 34.35
 * seconds).
 *
 * This receives the RX or TX MAC timestamps, provided by hardware as
 * the lower bits of the cycle counter, sampled at the time the timestamp was
 * collected.
 *
 * To reconstruct into a full 64-bit-wide timestamp, the cycle counter is
 * read and the high-order bits are filled in.
 *
 * Must be called within one wraparound period of the partial timestamp since
 * it was generated by the MAC.
 */
u64 sja1105_tstamp_reconstruct(struct sja1105_private *priv, u64 now,
			       u64 ts_partial)
{
	u64 partial_tstamp_mask = CYCLECOUNTER_MASK(priv->info->ptp_ts_bits);
	u64 ts_reconstructed;

	ts_reconstructed = (now & ~partial_tstamp_mask) | ts_partial;

	/* Check lower bits of current cycle counter against the timestamp.
	 * If the current cycle counter is lower than the partial timestamp,
	 * then wraparound surely occurred and must be accounted for.
	 */
	if ((now & partial_tstamp_mask) <= ts_partial)
		ts_reconstructed -= (partial_tstamp_mask + 1);

	return ts_reconstructed;
}

/* Reads the SPI interface for an egress timestamp generated by the switch
 * for frames sent using management routes.
 *
 * SJA1105 E/T layout of the 4-byte SPI payload:
 *
 * 31    23    15    7     0
 * |     |     |     |     |
 * +-----+-----+-----+     ^
 *          ^              |
 *          |              |
 *  24-bit timestamp   Update bit
 *
 *
 * SJA1105 P/Q/R/S layout of the 8-byte SPI payload:
 *
 * 31    23    15    7     0     63    55    47    39    32
 * |     |     |     |     |     |     |     |     |     |
 *                         ^     +-----+-----+-----+-----+
 *                         |                 ^
 *                         |                 |
 *                    Update bit    32-bit timestamp
 *
 * Notice that the update bit is in the same place.
 * To have common code for E/T and P/Q/R/S for reading the timestamp,
 * we need to juggle with the offset and the bit indices.
 */
int sja1105_ptpegr_ts_poll(struct sja1105_private *priv, int port, u64 *ts)
{
	const struct sja1105_regs *regs = priv->info->regs;
	int tstamp_bit_start, tstamp_bit_end;
	int timeout = 10;
	u8 packed_buf[8];
	u64 update;
	int rc;

	do {
		rc = sja1105_spi_send_packed_buf(priv, SPI_READ,
						 regs->ptpegr_ts[port],
						 packed_buf,
						 priv->info->ptpegr_ts_bytes);
		if (rc < 0)
			return rc;

		sja1105_unpack(packed_buf, &update, 0, 0,
			       priv->info->ptpegr_ts_bytes);
		if (update)
			break;

		usleep_range(10, 50);
	} while (--timeout);

	if (!timeout)
		return -ETIMEDOUT;

	/* Point the end bit to the second 32-bit word on P/Q/R/S,
	 * no-op on E/T.
	 */
	tstamp_bit_end = (priv->info->ptpegr_ts_bytes - 4) * 8;
	/* Shift the 24-bit timestamp on E/T to be collected from 31:8.
	 * No-op on P/Q/R/S.
	 */
	tstamp_bit_end += 32 - priv->info->ptp_ts_bits;
	tstamp_bit_start = tstamp_bit_end + priv->info->ptp_ts_bits - 1;

	*ts = 0;

	sja1105_unpack(packed_buf, ts, tstamp_bit_start, tstamp_bit_end,
		       priv->info->ptpegr_ts_bytes);

	return 0;
}

int sja1105_ptp_reset(struct sja1105_private *priv)
{
	struct dsa_switch *ds = priv->ds;
	struct sja1105_ptp_cmd cmd = {0};
	int rc;

	mutex_lock(&priv->ptp_lock);

	cmd.resptp = 1;
	dev_dbg(ds->dev, "Resetting PTP clock\n");
	rc = priv->info->ptp_cmd(priv, &cmd);

	timecounter_init(&priv->tstamp_tc, &priv->tstamp_cc,
			 ktime_to_ns(ktime_get_real()));

	mutex_unlock(&priv->ptp_lock);

	return rc;
}

static int sja1105_ptp_gettime(struct ptp_clock_info *ptp,
			       struct timespec64 *ts)
{
	struct sja1105_private *priv = ptp_to_sja1105(ptp);
	u64 ns;

	mutex_lock(&priv->ptp_lock);
	ns = timecounter_read(&priv->tstamp_tc);
	mutex_unlock(&priv->ptp_lock);

	*ts = ns_to_timespec64(ns);

	return 0;
}

static int sja1105_ptp_settime(struct ptp_clock_info *ptp,
			       const struct timespec64 *ts)
{
	struct sja1105_private *priv = ptp_to_sja1105(ptp);
	u64 ns = timespec64_to_ns(ts);

	mutex_lock(&priv->ptp_lock);
	timecounter_init(&priv->tstamp_tc, &priv->tstamp_cc, ns);
	mutex_unlock(&priv->ptp_lock);

	return 0;
}

static int sja1105_ptp_adjfine(struct ptp_clock_info *ptp, long scaled_ppm)
{
	struct sja1105_private *priv = ptp_to_sja1105(ptp);
	s64 clkrate;

	clkrate = (s64)scaled_ppm * SJA1105_CC_MULT_NUM;
	clkrate = div_s64(clkrate, SJA1105_CC_MULT_DEM);

	mutex_lock(&priv->ptp_lock);

	/* Force a readout to update the timer *before* changing its frequency.
	 *
	 * This way, its corrected time curve can at all times be modeled
	 * as a linear "A * x + B" function, where:
	 *
	 * - B are past frequency adjustments and offset shifts, all
	 *   accumulated into the cycle_last variable.
	 *
	 * - A is the new frequency adjustments we're just about to set.
	 *
	 * Reading now makes B accumulate the correct amount of time,
	 * corrected at the old rate, before changing it.
	 *
	 * Hardware timestamps then become simple points on the curve and
	 * are approximated using the above function.  This is still better
	 * than letting the switch take the timestamps using the hardware
	 * rate-corrected clock (PTPCLKVAL) - the comparison in this case would
	 * be that we're shifting the ruler at the same time as we're taking
	 * measurements with it.
	 *
	 * The disadvantage is that it's possible to receive timestamps when
	 * a frequency adjustment took place in the near past.
	 * In this case they will be approximated using the new ppb value
	 * instead of a compound function made of two segments (one at the old
	 * and the other at the new rate) - introducing some inaccuracy.
	 */
	timecounter_read(&priv->tstamp_tc);

	priv->tstamp_cc.mult = SJA1105_CC_MULT + clkrate;

	mutex_unlock(&priv->ptp_lock);

	return 0;
}

static int sja1105_ptp_adjtime(struct ptp_clock_info *ptp, s64 delta)
{
	struct sja1105_private *priv = ptp_to_sja1105(ptp);

	mutex_lock(&priv->ptp_lock);
	timecounter_adjtime(&priv->tstamp_tc, delta);
	mutex_unlock(&priv->ptp_lock);

	return 0;
}

static u64 sja1105_ptptsclk_read(const struct cyclecounter *cc)
{
	struct sja1105_private *priv = cc_to_sja1105(cc);
	const struct sja1105_regs *regs = priv->info->regs;
	u64 ptptsclk = 0;
	int rc;

	rc = sja1105_spi_send_int(priv, SPI_READ, regs->ptptsclk,
				  &ptptsclk, 8);
	if (rc < 0)
		dev_err_ratelimited(priv->ds->dev,
				    "failed to read ptp cycle counter: %d\n",
				    rc);
	return ptptsclk;
}

static void sja1105_ptp_overflow_check(struct work_struct *work)
{
	struct delayed_work *dw = to_delayed_work(work);
	struct sja1105_private *priv = dw_to_sja1105(dw);
	struct timespec64 ts;

	sja1105_ptp_gettime(&priv->ptp_caps, &ts);

	schedule_delayed_work(&priv->refresh_work, SJA1105_REFRESH_INTERVAL);
}

static const struct ptp_clock_info sja1105_ptp_caps = {
	.owner		= THIS_MODULE,
	.name		= "SJA1105 PHC",
	.adjfine	= sja1105_ptp_adjfine,
	.adjtime	= sja1105_ptp_adjtime,
	.gettime64	= sja1105_ptp_gettime,
	.settime64	= sja1105_ptp_settime,
	.max_adj	= SJA1105_MAX_ADJ_PPB,
};

int sja1105_ptp_clock_register(struct sja1105_private *priv)
{
	struct dsa_switch *ds = priv->ds;

	/* Set up the cycle counter */
	priv->tstamp_cc = (struct cyclecounter) {
		.read = sja1105_ptptsclk_read,
		.mask = CYCLECOUNTER_MASK(64),
		.shift = SJA1105_CC_SHIFT,
		.mult = SJA1105_CC_MULT,
	};
	mutex_init(&priv->ptp_lock);
	priv->ptp_caps = sja1105_ptp_caps;

	priv->clock = ptp_clock_register(&priv->ptp_caps, ds->dev);
	if (IS_ERR_OR_NULL(priv->clock))
		return PTR_ERR(priv->clock);

	INIT_DELAYED_WORK(&priv->refresh_work, sja1105_ptp_overflow_check);
	schedule_delayed_work(&priv->refresh_work, SJA1105_REFRESH_INTERVAL);

	return sja1105_ptp_reset(priv);
}

void sja1105_ptp_clock_unregister(struct sja1105_private *priv)
{
	if (IS_ERR_OR_NULL(priv->clock))
		return;

	cancel_delayed_work_sync(&priv->refresh_work);
	ptp_clock_unregister(priv->clock);
	priv->clock = NULL;
}
