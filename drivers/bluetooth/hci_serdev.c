/*
 *  Bluetooth HCI serdev driver lib
 *
 *  Copyright (C) 2017  Linaro, Ltd., Rob Herring <robh@kernel.org>
 *
 *  Based on hci_ldisc.c:
 *
 *  Copyright (C) 2000-2001  Qualcomm Incorporated
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2004-2005  Marcel Holtmann <marcel@holtmann.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/serdev.h>
#include <linux/skbuff.h>

#include <net/bluetooth/bluetooth.h>
#include <net/bluetooth/hci_core.h>

#include "hci_uart.h"

struct serdev_device_ops hci_serdev_client_ops;

static inline void hci_uart_tx_complete(struct hci_uart *hu, int pkt_type)
{
	struct hci_dev *hdev = hu->hdev;

	/* Update HCI stat counters */
	switch (pkt_type) {
	case HCI_COMMAND_PKT:
		hdev->stat.cmd_tx++;
		break;

	case HCI_ACLDATA_PKT:
		hdev->stat.acl_tx++;
		break;

	case HCI_SCODATA_PKT:
		hdev->stat.sco_tx++;
		break;
	}
}

static inline struct sk_buff *hci_uart_dequeue(struct hci_uart *hu)
{
	struct sk_buff *skb = hu->tx_skb;

	if (!skb)
		skb = hu->proto->dequeue(hu);
	else
		hu->tx_skb = NULL;

	return skb;
}

static void hci_uart_write_work(struct work_struct *work)
{
	struct hci_uart *hu = container_of(work, struct hci_uart, write_work);
	struct serdev_device *serdev = hu->serdev;
	struct hci_dev *hdev = hu->hdev;
	struct sk_buff *skb;

	/* REVISIT:
	 * should we cope with bad skbs or ->write() returning an error value?
	 */
	do {
		clear_bit(HCI_UART_TX_WAKEUP, &hu->tx_state);

		while ((skb = hci_uart_dequeue(hu))) {
			int len;

			len = serdev_device_write_buf(serdev,
						      skb->data, skb->len);
			hdev->stat.byte_tx += len;

			skb_pull(skb, len);
			if (skb->len) {
				hu->tx_skb = skb;
				break;
			}

			hci_uart_tx_complete(hu, hci_skb_pkt_type(skb));
			kfree_skb(skb);
		}
	} while(test_bit(HCI_UART_TX_WAKEUP, &hu->tx_state));

	clear_bit(HCI_UART_SENDING, &hu->tx_state);
}

/* ------- Interface to HCI layer ------ */

/* Initialize device */
static int hci_uart_open(struct hci_dev *hdev)
{
	BT_DBG("%s %p", hdev->name, hdev);

	return 0;
}

/* Reset device */
static int hci_uart_flush(struct hci_dev *hdev)
{
	struct hci_uart *hu  = hci_get_drvdata(hdev);

	BT_DBG("hdev %p serdev %p", hdev, hu->serdev);

	if (hu->tx_skb) {
		kfree_skb(hu->tx_skb); hu->tx_skb = NULL;
	}

	/* Flush any pending characters in the driver and discipline. */
	serdev_device_write_flush(hu->serdev);

	if (test_bit(HCI_UART_PROTO_READY, &hu->flags))
		hu->proto->flush(hu);

	return 0;
}

/* Close device */
static int hci_uart_close(struct hci_dev *hdev)
{
	BT_DBG("hdev %p", hdev);

	hci_uart_flush(hdev);
	hdev->flush = NULL;

	return 0;
}

/* Send frames from HCI layer */
static int hci_uart_send_frame(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_uart *hu = hci_get_drvdata(hdev);

	BT_DBG("%s: type %d len %d", hdev->name, hci_skb_pkt_type(skb),
	       skb->len);

	hu->proto->enqueue(hu, skb);

	hci_uart_tx_wakeup(hu);

	return 0;
}

static int hci_uart_setup(struct hci_dev *hdev)
{
	struct hci_uart *hu = hci_get_drvdata(hdev);
	struct hci_rp_read_local_version *ver;
	struct sk_buff *skb;
	unsigned int speed;
	int err;

	/* Init speed if any */
	if (hu->init_speed)
		speed = hu->init_speed;
	else if (hu->proto->init_speed)
		speed = hu->proto->init_speed;
	else
		speed = 0;

	if (speed)
		serdev_device_set_baudrate(hu->serdev, speed);

	/* Operational speed if any */
	if (hu->oper_speed)
		speed = hu->oper_speed;
	else if (hu->proto->oper_speed)
		speed = hu->proto->oper_speed;
	else
		speed = 0;

	if (hu->proto->set_baudrate && speed) {
		err = hu->proto->set_baudrate(hu, speed);
		if (err)
			BT_ERR("%s: failed to set baudrate", hdev->name);
		else
			serdev_device_set_baudrate(hu->serdev, speed);
	}

	if (hu->proto->setup)
		return hu->proto->setup(hu);

	if (!test_bit(HCI_UART_VND_DETECT, &hu->hdev_flags))
		return 0;

	skb = __hci_cmd_sync(hdev, HCI_OP_READ_LOCAL_VERSION, 0, NULL,
			     HCI_INIT_TIMEOUT);
	if (IS_ERR(skb)) {
		BT_ERR("%s: Reading local version information failed (%ld)",
		       hdev->name, PTR_ERR(skb));
		return 0;
	}

	if (skb->len != sizeof(*ver)) {
		BT_ERR("%s: Event length mismatch for version information",
		       hdev->name);
	}

	kfree_skb(skb);
	return 0;
}

/** hci_uart_write_wakeup - transmit buffer wakeup
 * @serdev: serial device
 *
 * This function is called by the serdev framework when it accepts
 * more data being sent.
 */
static void hci_uart_write_wakeup(struct serdev_device *serdev)
{
	struct hci_uart *hu = serdev_device_get_drvdata(serdev);

	BT_DBG("");

	if (!hu || serdev != hu->serdev) {
		WARN_ON(1);
		return;
	}

	if (test_bit(HCI_UART_PROTO_READY, &hu->flags))
		hci_uart_tx_wakeup(hu);
}

/** hci_uart_receive_buf - receive buffer wakeup
 * @serdev: serial device
 * @data:   pointer to received data
 * @count:  count of received data in bytes
 *
 * This function is called by the serdev framework when it received data
 * in the RX buffer.
 *
 * Return: number of processed bytes
 */
static int hci_uart_receive_buf(struct serdev_device *serdev, const u8 *data,
				   size_t count)
{
	struct hci_uart *hu = serdev_device_get_drvdata(serdev);

	if (!hu || serdev != hu->serdev) {
		WARN_ON(1);
		return 0;
	}

	if (!test_bit(HCI_UART_PROTO_READY, &hu->flags))
		return 0;

	/* It does not need a lock here as it is already protected by a mutex in
	 * tty caller
	 */
	hu->proto->recv(hu, data, count);

	if (hu->hdev)
		hu->hdev->stat.byte_rx += count;

	return count;
}

struct serdev_device_ops hci_serdev_client_ops = {
	.receive_buf = hci_uart_receive_buf,
	.write_wakeup = hci_uart_write_wakeup,
};

int hci_uart_register_device(struct hci_uart *hu,
			     const struct hci_uart_proto *p)
{
	int err;
	struct hci_dev *hdev;

	BT_DBG("");

	serdev_device_set_client_ops(hu->serdev, &hci_serdev_client_ops);

	err = p->open(hu);
	if (err)
		return err;

	hu->proto = p;
	set_bit(HCI_UART_PROTO_READY, &hu->flags);

	/* Initialize and register HCI device */
	hdev = hci_alloc_dev();
	if (!hdev) {
		BT_ERR("Can't allocate HCI device");
		err = -ENOMEM;
		goto err_alloc;
	}

	hu->hdev = hdev;

	hdev->bus = HCI_UART;
	hci_set_drvdata(hdev, hu);

	INIT_WORK(&hu->write_work, hci_uart_write_work);

	/* Only when vendor specific setup callback is provided, consider
	 * the manufacturer information valid. This avoids filling in the
	 * value for Ericsson when nothing is specified.
	 */
	if (hu->proto->setup)
		hdev->manufacturer = hu->proto->manufacturer;

	hdev->open  = hci_uart_open;
	hdev->close = hci_uart_close;
	hdev->flush = hci_uart_flush;
	hdev->send  = hci_uart_send_frame;
	hdev->setup = hci_uart_setup;
	SET_HCIDEV_DEV(hdev, &hu->serdev->dev);

	if (test_bit(HCI_UART_RAW_DEVICE, &hu->hdev_flags))
		set_bit(HCI_QUIRK_RAW_DEVICE, &hdev->quirks);

	if (test_bit(HCI_UART_EXT_CONFIG, &hu->hdev_flags))
		set_bit(HCI_QUIRK_EXTERNAL_CONFIG, &hdev->quirks);

	if (!test_bit(HCI_UART_RESET_ON_INIT, &hu->hdev_flags))
		set_bit(HCI_QUIRK_RESET_ON_CLOSE, &hdev->quirks);

	if (test_bit(HCI_UART_CREATE_AMP, &hu->hdev_flags))
		hdev->dev_type = HCI_AMP;
	else
		hdev->dev_type = HCI_PRIMARY;

	if (test_bit(HCI_UART_INIT_PENDING, &hu->hdev_flags))
		return 0;

	if (hci_register_dev(hdev) < 0) {
		BT_ERR("Can't register HCI device");
		err = -ENODEV;
		goto err_register;
	}

	set_bit(HCI_UART_REGISTERED, &hu->flags);

	return 0;

err_register:
	hci_free_dev(hdev);
err_alloc:
	clear_bit(HCI_UART_PROTO_READY, &hu->flags);
	p->close(hu);
	return err;
}
EXPORT_SYMBOL_GPL(hci_uart_register_device);
