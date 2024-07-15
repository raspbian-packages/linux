// SPDX-License-Identifier: GPL-2.0
/*
 * System Control and Management Interface (SCMI) Message Mailbox Transport
 * driver.
 *
 * Copyright (C) 2019 ARM Ltd.
 */

#include <linux/err.h>
#include <linux/device.h>
#include <linux/mailbox_client.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/slab.h>

#include "common.h"

/**
 * struct scmi_mailbox - Structure representing a SCMI mailbox transport
 *
 * @cl: Mailbox Client
 * @chan: Transmit/Receive mailbox channel
 * @cinfo: SCMI channel info
 * @shmem: Transmit/Receive shared memory area
 */
struct scmi_mailbox {
	struct mbox_client cl;
	struct mbox_chan *chan;
	struct scmi_chan_info *cinfo;
	struct scmi_shared_mem __iomem *shmem;
};

#define client_to_scmi_mailbox(c) container_of(c, struct scmi_mailbox, cl)

static void tx_prepare(struct mbox_client *cl, void *m)
{
	struct scmi_mailbox *smbox = client_to_scmi_mailbox(cl);

	shmem_tx_prepare(smbox->shmem, m, smbox->cinfo);
}

static void rx_callback(struct mbox_client *cl, void *m)
{
	struct scmi_mailbox *smbox = client_to_scmi_mailbox(cl);

	/*
	 * An A2P IRQ is NOT valid when received while the platform still has
	 * the ownership of the channel, because the platform at first releases
	 * the SMT channel and then sends the completion interrupt.
	 *
	 * This addresses a possible race condition in which a spurious IRQ from
	 * a previous timed-out reply which arrived late could be wrongly
	 * associated with the next pending transaction.
	 */
	if (cl->knows_txdone && !shmem_channel_free(smbox->shmem)) {
		dev_warn(smbox->cinfo->dev, "Ignoring spurious A2P IRQ !\n");
		return;
	}

	scmi_rx_callback(smbox->cinfo, shmem_read_header(smbox->shmem), NULL);
}

static bool mailbox_chan_available(struct device *dev, int idx)
{
	return !of_parse_phandle_with_args(dev->of_node, "mboxes",
					   "#mbox-cells", idx, NULL);
}

static int mailbox_chan_validate(struct device *cdev)
{
	int num_mb, num_sh, ret = 0;
	struct device_node *np = cdev->of_node;

	num_mb = of_count_phandle_with_args(np, "mboxes", "#mbox-cells");
	num_sh = of_count_phandle_with_args(np, "shmem", NULL);
	/* Bail out if mboxes and shmem descriptors are inconsistent */
	if (num_mb <= 0 || num_sh > 2 || num_mb != num_sh) {
		dev_warn(cdev, "Invalid channel descriptor for '%s'\n",
			 of_node_full_name(np));
		return -EINVAL;
	}

	if (num_sh > 1) {
		struct device_node *np_tx, *np_rx;

		np_tx = of_parse_phandle(np, "shmem", 0);
		np_rx = of_parse_phandle(np, "shmem", 1);
		/* SCMI Tx and Rx shared mem areas have to be distinct */
		if (!np_tx || !np_rx || np_tx == np_rx) {
			dev_warn(cdev, "Invalid shmem descriptor for '%s'\n",
				 of_node_full_name(np));
			ret = -EINVAL;
		}

		of_node_put(np_tx);
		of_node_put(np_rx);
	}

	return ret;
}

static int mailbox_chan_setup(struct scmi_chan_info *cinfo, struct device *dev,
			      bool tx)
{
	const char *desc = tx ? "Tx" : "Rx";
	struct device *cdev = cinfo->dev;
	struct scmi_mailbox *smbox;
	struct device_node *shmem;
	int ret, idx = tx ? 0 : 1;
	struct mbox_client *cl;
	resource_size_t size;
	struct resource res;

	ret = mailbox_chan_validate(cdev);
	if (ret)
		return ret;

	smbox = devm_kzalloc(dev, sizeof(*smbox), GFP_KERNEL);
	if (!smbox)
		return -ENOMEM;

	shmem = of_parse_phandle(cdev->of_node, "shmem", idx);
	if (!of_device_is_compatible(shmem, "arm,scmi-shmem")) {
		of_node_put(shmem);
		return -ENXIO;
	}

	ret = of_address_to_resource(shmem, 0, &res);
	of_node_put(shmem);
	if (ret) {
		dev_err(cdev, "failed to get SCMI %s shared memory\n", desc);
		return ret;
	}

	size = resource_size(&res);
	smbox->shmem = devm_ioremap(dev, res.start, size);
	if (!smbox->shmem) {
		dev_err(dev, "failed to ioremap SCMI %s shared memory\n", desc);
		return -EADDRNOTAVAIL;
	}

	cl = &smbox->cl;
	cl->dev = cdev;
	cl->tx_prepare = tx ? tx_prepare : NULL;
	cl->rx_callback = rx_callback;
	cl->tx_block = false;
	cl->knows_txdone = tx;

	smbox->chan = mbox_request_channel(cl, tx ? 0 : 1);
	if (IS_ERR(smbox->chan)) {
		ret = PTR_ERR(smbox->chan);
		if (ret != -EPROBE_DEFER)
			dev_err(cdev, "failed to request SCMI %s mailbox\n",
				tx ? "Tx" : "Rx");
		return ret;
	}

	cinfo->transport_info = smbox;
	smbox->cinfo = cinfo;

	return 0;
}

static int mailbox_chan_free(int id, void *p, void *data)
{
	struct scmi_chan_info *cinfo = p;
	struct scmi_mailbox *smbox = cinfo->transport_info;

	if (smbox && !IS_ERR(smbox->chan)) {
		mbox_free_channel(smbox->chan);
		cinfo->transport_info = NULL;
		smbox->chan = NULL;
		smbox->cinfo = NULL;
	}

	scmi_free_channel(cinfo, data, id);

	return 0;
}

static int mailbox_send_message(struct scmi_chan_info *cinfo,
				struct scmi_xfer *xfer)
{
	struct scmi_mailbox *smbox = cinfo->transport_info;
	int ret;

	ret = mbox_send_message(smbox->chan, xfer);

	/* mbox_send_message returns non-negative value on success, so reset */
	if (ret > 0)
		ret = 0;

	return ret;
}

static void mailbox_mark_txdone(struct scmi_chan_info *cinfo, int ret,
				struct scmi_xfer *__unused)
{
	struct scmi_mailbox *smbox = cinfo->transport_info;

	/*
	 * NOTE: we might prefer not to need the mailbox ticker to manage the
	 * transfer queueing since the protocol layer queues things by itself.
	 * Unfortunately, we have to kick the mailbox framework after we have
	 * received our message.
	 */
	mbox_client_txdone(smbox->chan, ret);
}

static void mailbox_fetch_response(struct scmi_chan_info *cinfo,
				   struct scmi_xfer *xfer)
{
	struct scmi_mailbox *smbox = cinfo->transport_info;

	shmem_fetch_response(smbox->shmem, xfer);
}

static void mailbox_fetch_notification(struct scmi_chan_info *cinfo,
				       size_t max_len, struct scmi_xfer *xfer)
{
	struct scmi_mailbox *smbox = cinfo->transport_info;

	shmem_fetch_notification(smbox->shmem, max_len, xfer);
}

static void mailbox_clear_channel(struct scmi_chan_info *cinfo)
{
	struct scmi_mailbox *smbox = cinfo->transport_info;

	shmem_clear_channel(smbox->shmem);
}

static bool
mailbox_poll_done(struct scmi_chan_info *cinfo, struct scmi_xfer *xfer)
{
	struct scmi_mailbox *smbox = cinfo->transport_info;

	return shmem_poll_done(smbox->shmem, xfer);
}

static const struct scmi_transport_ops scmi_mailbox_ops = {
	.chan_available = mailbox_chan_available,
	.chan_setup = mailbox_chan_setup,
	.chan_free = mailbox_chan_free,
	.send_message = mailbox_send_message,
	.mark_txdone = mailbox_mark_txdone,
	.fetch_response = mailbox_fetch_response,
	.fetch_notification = mailbox_fetch_notification,
	.clear_channel = mailbox_clear_channel,
	.poll_done = mailbox_poll_done,
};

const struct scmi_desc scmi_mailbox_desc = {
	.ops = &scmi_mailbox_ops,
	.max_rx_timeout_ms = 30, /* We may increase this if required */
	.max_msg = 20, /* Limited by MBOX_TX_QUEUE_LEN */
	.max_msg_size = 128,
};
