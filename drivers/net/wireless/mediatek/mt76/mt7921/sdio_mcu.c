// SPDX-License-Identifier: ISC
/* Copyright (C) 2021 MediaTek Inc. */

#include <linux/kernel.h>
#include <linux/mmc/sdio_func.h>
#include <linux/module.h>
#include <linux/iopoll.h>

#include "mt7921.h"
#include "../sdio.h"
#include "mac.h"
#include "mcu.h"
#include "regs.h"

static int
mt7921s_mcu_send_message(struct mt76_dev *mdev, struct sk_buff *skb,
			 int cmd, int *seq)
{
	struct mt7921_dev *dev = container_of(mdev, struct mt7921_dev, mt76);
	enum mt7921_sdio_pkt_type type = MT7921_SDIO_CMD;
	enum mt76_mcuq_id txq = MT_MCUQ_WM;
	int ret, pad;

	/* We just return in case firmware assertion to avoid blocking the
	 * common workqueue to run, for example, the coredump work might be
	 * blocked by mt7921_mac_work that is excuting register access via sdio
	 * bus.
	 */
	if (dev->fw_assert)
		return -EBUSY;

	ret = mt7921_mcu_fill_message(mdev, skb, cmd, seq);
	if (ret)
		return ret;

	if (cmd == MCU_CMD_FW_SCATTER)
		type = MT7921_SDIO_FWDL;

	mt7921_skb_add_sdio_hdr(skb, type);
	pad = round_up(skb->len, 4) - skb->len;
	__skb_put_zero(skb, pad);

	ret = mt76_tx_queue_skb_raw(dev, mdev->q_mcu[txq], skb, 0);
	if (ret)
		return ret;

	mt76_queue_kick(dev, mdev->q_mcu[txq]);

	return ret;
}

int mt7921s_mcu_init(struct mt7921_dev *dev)
{
	static const struct mt76_mcu_ops mt7921s_mcu_ops = {
		.headroom = MT_SDIO_HDR_SIZE + sizeof(struct mt7921_mcu_txd),
		.tailroom = MT_SDIO_TAIL_SIZE,
		.mcu_skb_send_msg = mt7921s_mcu_send_message,
		.mcu_parse_response = mt7921_mcu_parse_response,
		.mcu_rr = mt76_connac_mcu_reg_rr,
		.mcu_wr = mt76_connac_mcu_reg_wr,
	};
	int ret;

	mt7921s_mcu_drv_pmctrl(dev);

	dev->mt76.mcu_ops = &mt7921s_mcu_ops;

	ret = mt7921_run_firmware(dev);
	if (ret)
		return ret;

	set_bit(MT76_STATE_MCU_RUNNING, &dev->mphy.state);

	return 0;
}

int mt7921s_mcu_drv_pmctrl(struct mt7921_dev *dev)
{
	struct sdio_func *func = dev->mt76.sdio.func;
	struct mt76_phy *mphy = &dev->mt76.phy;
	struct mt76_connac_pm *pm = &dev->pm;
	int err = 0;
	u32 status;

	sdio_claim_host(func);

	sdio_writel(func, WHLPCR_FW_OWN_REQ_CLR, MCR_WHLPCR, NULL);

	err = readx_poll_timeout(mt76s_read_pcr, &dev->mt76, status,
				 status & WHLPCR_IS_DRIVER_OWN, 2000, 1000000);
	sdio_release_host(func);

	if (err < 0) {
		dev_err(dev->mt76.dev, "driver own failed\n");
		err = -EIO;
		goto out;
	}

	clear_bit(MT76_STATE_PM, &mphy->state);

	pm->stats.last_wake_event = jiffies;
	pm->stats.doze_time += pm->stats.last_wake_event -
			       pm->stats.last_doze_event;
out:
	return err;
}

int mt7921s_mcu_fw_pmctrl(struct mt7921_dev *dev)
{
	struct sdio_func *func = dev->mt76.sdio.func;
	struct mt76_phy *mphy = &dev->mt76.phy;
	struct mt76_connac_pm *pm = &dev->pm;
	int err = 0;
	u32 status;

	sdio_claim_host(func);

	sdio_writel(func, WHLPCR_FW_OWN_REQ_SET, MCR_WHLPCR, NULL);

	err = readx_poll_timeout(mt76s_read_pcr, &dev->mt76, status,
				 !(status & WHLPCR_IS_DRIVER_OWN), 2000, 1000000);
	sdio_release_host(func);

	if (err < 0) {
		dev_err(dev->mt76.dev, "firmware own failed\n");
		clear_bit(MT76_STATE_PM, &mphy->state);
		err = -EIO;
	}

	pm->stats.last_doze_event = jiffies;
	pm->stats.awake_time += pm->stats.last_doze_event -
				pm->stats.last_wake_event;

	return err;
}
