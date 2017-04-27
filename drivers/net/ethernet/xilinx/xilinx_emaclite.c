/*
 * Xilinx EmacLite Linux driver for the Xilinx Ethernet MAC Lite device.
 *
 * This is a new flat driver which is based on the original emac_lite
 * driver from John Williams <john.williams@petalogix.com>.
 *
 * 2007-2009 (c) Xilinx, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/of_platform.h>
#include <linux/of_mdio.h>
#include <linux/of_net.h>
#include <linux/phy.h>
#include <linux/interrupt.h>

#define DRIVER_NAME "xilinx_emaclite"

/* Register offsets for the EmacLite Core */
#define XEL_TXBUFF_OFFSET 	0x0		/* Transmit Buffer */
#define XEL_MDIOADDR_OFFSET	0x07E4		/* MDIO Address Register */
#define XEL_MDIOWR_OFFSET	0x07E8		/* MDIO Write Data Register */
#define XEL_MDIORD_OFFSET	0x07EC		/* MDIO Read Data Register */
#define XEL_MDIOCTRL_OFFSET	0x07F0		/* MDIO Control Register */
#define XEL_GIER_OFFSET		0x07F8		/* GIE Register */
#define XEL_TSR_OFFSET		0x07FC		/* Tx status */
#define XEL_TPLR_OFFSET		0x07F4		/* Tx packet length */

#define XEL_RXBUFF_OFFSET	0x1000		/* Receive Buffer */
#define XEL_RPLR_OFFSET		0x100C		/* Rx packet length */
#define XEL_RSR_OFFSET		0x17FC		/* Rx status */

#define XEL_BUFFER_OFFSET	0x0800		/* Next Tx/Rx buffer's offset */

/* MDIO Address Register Bit Masks */
#define XEL_MDIOADDR_REGADR_MASK  0x0000001F	/* Register Address */
#define XEL_MDIOADDR_PHYADR_MASK  0x000003E0	/* PHY Address */
#define XEL_MDIOADDR_PHYADR_SHIFT 5
#define XEL_MDIOADDR_OP_MASK	  0x00000400	/* RD/WR Operation */

/* MDIO Write Data Register Bit Masks */
#define XEL_MDIOWR_WRDATA_MASK	  0x0000FFFF	/* Data to be Written */

/* MDIO Read Data Register Bit Masks */
#define XEL_MDIORD_RDDATA_MASK	  0x0000FFFF	/* Data to be Read */

/* MDIO Control Register Bit Masks */
#define XEL_MDIOCTRL_MDIOSTS_MASK 0x00000001	/* MDIO Status Mask */
#define XEL_MDIOCTRL_MDIOEN_MASK  0x00000008	/* MDIO Enable */

/* Global Interrupt Enable Register (GIER) Bit Masks */
#define XEL_GIER_GIE_MASK	0x80000000 	/* Global Enable */

/* Transmit Status Register (TSR) Bit Masks */
#define XEL_TSR_XMIT_BUSY_MASK	 0x00000001 	/* Tx complete */
#define XEL_TSR_PROGRAM_MASK	 0x00000002 	/* Program the MAC address */
#define XEL_TSR_XMIT_IE_MASK	 0x00000008 	/* Tx interrupt enable bit */
#define XEL_TSR_XMIT_ACTIVE_MASK 0x80000000 	/* Buffer is active, SW bit
						 * only. This is not documented
						 * in the HW spec */

/* Define for programming the MAC address into the EmacLite */
#define XEL_TSR_PROG_MAC_ADDR	(XEL_TSR_XMIT_BUSY_MASK | XEL_TSR_PROGRAM_MASK)

/* Receive Status Register (RSR) */
#define XEL_RSR_RECV_DONE_MASK	0x00000001 	/* Rx complete */
#define XEL_RSR_RECV_IE_MASK	0x00000008 	/* Rx interrupt enable bit */

/* Transmit Packet Length Register (TPLR) */
#define XEL_TPLR_LENGTH_MASK	0x0000FFFF 	/* Tx packet length */

/* Receive Packet Length Register (RPLR) */
#define XEL_RPLR_LENGTH_MASK	0x0000FFFF 	/* Rx packet length */

#define XEL_HEADER_OFFSET	12 		/* Offset to length field */
#define XEL_HEADER_SHIFT	16 		/* Shift value for length */

/* General Ethernet Definitions */
#define XEL_ARP_PACKET_SIZE		28 	/* Max ARP packet size */
#define XEL_HEADER_IP_LENGTH_OFFSET	16 	/* IP Length Offset */



#define TX_TIMEOUT		(60*HZ)		/* Tx timeout is 60 seconds. */
#define ALIGNMENT		4

/* BUFFER_ALIGN(adr) calculates the number of bytes to the next alignment. */
#define BUFFER_ALIGN(adr) ((ALIGNMENT - ((u32) adr)) % ALIGNMENT)

/**
 * struct net_local - Our private per device data
 * @ndev:		instance of the network device
 * @tx_ping_pong:	indicates whether Tx Pong buffer is configured in HW
 * @rx_ping_pong:	indicates whether Rx Pong buffer is configured in HW
 * @next_tx_buf_to_use:	next Tx buffer to write to
 * @next_rx_buf_to_use:	next Rx buffer to read from
 * @base_addr:		base address of the Emaclite device
 * @reset_lock:		lock used for synchronization
 * @deferred_skb:	holds an skb (for transmission at a later time) when the
 *			Tx buffer is not free
 * @phy_dev:		pointer to the PHY device
 * @phy_node:		pointer to the PHY device node
 * @mii_bus:		pointer to the MII bus
 * @mdio_irqs:		IRQs table for MDIO bus
 * @last_link:		last link status
 * @has_mdio:		indicates whether MDIO is included in the HW
 */
struct net_local {

	struct net_device *ndev;

	bool tx_ping_pong;
	bool rx_ping_pong;
	u32 next_tx_buf_to_use;
	u32 next_rx_buf_to_use;
	void __iomem *base_addr;

	spinlock_t reset_lock;
	struct sk_buff *deferred_skb;

	struct phy_device *phy_dev;
	struct device_node *phy_node;

	struct mii_bus *mii_bus;
	int mdio_irqs[PHY_MAX_ADDR];

	int last_link;
	bool has_mdio;
};


/*************************/
/* EmacLite driver calls */
/*************************/

/**
 * xemaclite_enable_interrupts - Enable the interrupts for the EmacLite device
 * @drvdata:	Pointer to the Emaclite device private data
 *
 * This function enables the Tx and Rx interrupts for the Emaclite device along
 * with the Global Interrupt Enable.
 */
static void xemaclite_enable_interrupts(struct net_local *drvdata)
{
	u32 reg_data;

	/* Enable the Tx interrupts for the first Buffer */
	reg_data = in_be32(drvdata->base_addr + XEL_TSR_OFFSET);
	out_be32(drvdata->base_addr + XEL_TSR_OFFSET,
		 reg_data | XEL_TSR_XMIT_IE_MASK);

	/* Enable the Tx interrupts for the second Buffer if
	 * configured in HW */
	if (drvdata->tx_ping_pong != 0) {
		reg_data = in_be32(drvdata->base_addr +
				   XEL_BUFFER_OFFSET + XEL_TSR_OFFSET);
		out_be32(drvdata->base_addr + XEL_BUFFER_OFFSET +
			 XEL_TSR_OFFSET,
			 reg_data | XEL_TSR_XMIT_IE_MASK);
	}

	/* Enable the Rx interrupts for the first buffer */
	out_be32(drvdata->base_addr + XEL_RSR_OFFSET,
		 XEL_RSR_RECV_IE_MASK);

	/* Enable the Rx interrupts for the second Buffer if
	 * configured in HW */
	if (drvdata->rx_ping_pong != 0) {
		out_be32(drvdata->base_addr + XEL_BUFFER_OFFSET +
			 XEL_RSR_OFFSET,
			 XEL_RSR_RECV_IE_MASK);
	}

	/* Enable the Global Interrupt Enable */
	out_be32(drvdata->base_addr + XEL_GIER_OFFSET, XEL_GIER_GIE_MASK);
}

/**
 * xemaclite_disable_interrupts - Disable the interrupts for the EmacLite device
 * @drvdata:	Pointer to the Emaclite device private data
 *
 * This function disables the Tx and Rx interrupts for the Emaclite device,
 * along with the Global Interrupt Enable.
 */
static void xemaclite_disable_interrupts(struct net_local *drvdata)
{
	u32 reg_data;

	/* Disable the Global Interrupt Enable */
	out_be32(drvdata->base_addr + XEL_GIER_OFFSET, XEL_GIER_GIE_MASK);

	/* Disable the Tx interrupts for the first buffer */
	reg_data = in_be32(drvdata->base_addr + XEL_TSR_OFFSET);
	out_be32(drvdata->base_addr + XEL_TSR_OFFSET,
		 reg_data & (~XEL_TSR_XMIT_IE_MASK));

	/* Disable the Tx interrupts for the second Buffer
	 * if configured in HW */
	if (drvdata->tx_ping_pong != 0) {
		reg_data = in_be32(drvdata->base_addr + XEL_BUFFER_OFFSET +
				   XEL_TSR_OFFSET);
		out_be32(drvdata->base_addr + XEL_BUFFER_OFFSET +
			 XEL_TSR_OFFSET,
			 reg_data & (~XEL_TSR_XMIT_IE_MASK));
	}

	/* Disable the Rx interrupts for the first buffer */
	reg_data = in_be32(drvdata->base_addr + XEL_RSR_OFFSET);
	out_be32(drvdata->base_addr + XEL_RSR_OFFSET,
		 reg_data & (~XEL_RSR_RECV_IE_MASK));

	/* Disable the Rx interrupts for the second buffer
	 * if configured in HW */
	if (drvdata->rx_ping_pong != 0) {

		reg_data = in_be32(drvdata->base_addr + XEL_BUFFER_OFFSET +
				   XEL_RSR_OFFSET);
		out_be32(drvdata->base_addr + XEL_BUFFER_OFFSET +
			 XEL_RSR_OFFSET,
			 reg_data & (~XEL_RSR_RECV_IE_MASK));
	}
}

/**
 * xemaclite_aligned_write - Write from 16-bit aligned to 32-bit aligned address
 * @src_ptr:	Void pointer to the 16-bit aligned source address
 * @dest_ptr:	Pointer to the 32-bit aligned destination address
 * @length:	Number bytes to write from source to destination
 *
 * This function writes data from a 16-bit aligned buffer to a 32-bit aligned
 * address in the EmacLite device.
 */
static void xemaclite_aligned_write(void *src_ptr, u32 *dest_ptr,
				    unsigned length)
{
	u32 align_buffer;
	u32 *to_u32_ptr;
	u16 *from_u16_ptr, *to_u16_ptr;

	to_u32_ptr = dest_ptr;
	from_u16_ptr = src_ptr;
	align_buffer = 0;

	for (; length > 3; length -= 4) {
		to_u16_ptr = (u16 *)&align_buffer;
		*to_u16_ptr++ = *from_u16_ptr++;
		*to_u16_ptr++ = *from_u16_ptr++;

		/* Output a word */
		*to_u32_ptr++ = align_buffer;
	}
	if (length) {
		u8 *from_u8_ptr, *to_u8_ptr;

		/* Set up to output the remaining data */
		align_buffer = 0;
		to_u8_ptr = (u8 *) &align_buffer;
		from_u8_ptr = (u8 *) from_u16_ptr;

		/* Output the remaining data */
		for (; length > 0; length--)
			*to_u8_ptr++ = *from_u8_ptr++;

		*to_u32_ptr = align_buffer;
	}
}

/**
 * xemaclite_aligned_read - Read from 32-bit aligned to 16-bit aligned buffer
 * @src_ptr:	Pointer to the 32-bit aligned source address
 * @dest_ptr:	Pointer to the 16-bit aligned destination address
 * @length:	Number bytes to read from source to destination
 *
 * This function reads data from a 32-bit aligned address in the EmacLite device
 * to a 16-bit aligned buffer.
 */
static void xemaclite_aligned_read(u32 *src_ptr, u8 *dest_ptr,
				   unsigned length)
{
	u16 *to_u16_ptr, *from_u16_ptr;
	u32 *from_u32_ptr;
	u32 align_buffer;

	from_u32_ptr = src_ptr;
	to_u16_ptr = (u16 *) dest_ptr;

	for (; length > 3; length -= 4) {
		/* Copy each word into the temporary buffer */
		align_buffer = *from_u32_ptr++;
		from_u16_ptr = (u16 *)&align_buffer;

		/* Read data from source */
		*to_u16_ptr++ = *from_u16_ptr++;
		*to_u16_ptr++ = *from_u16_ptr++;
	}

	if (length) {
		u8 *to_u8_ptr, *from_u8_ptr;

		/* Set up to read the remaining data */
		to_u8_ptr = (u8 *) to_u16_ptr;
		align_buffer = *from_u32_ptr++;
		from_u8_ptr = (u8 *) &align_buffer;

		/* Read the remaining data */
		for (; length > 0; length--)
			*to_u8_ptr = *from_u8_ptr;
	}
}

/**
 * xemaclite_send_data - Send an Ethernet frame
 * @drvdata:	Pointer to the Emaclite device private data
 * @data:	Pointer to the data to be sent
 * @byte_count:	Total frame size, including header
 *
 * This function checks if the Tx buffer of the Emaclite device is free to send
 * data. If so, it fills the Tx buffer with data for transmission. Otherwise, it
 * returns an error.
 *
 * Return:	0 upon success or -1 if the buffer(s) are full.
 *
 * Note:	The maximum Tx packet size can not be more than Ethernet header
 *		(14 Bytes) + Maximum MTU (1500 bytes). This is excluding FCS.
 */
static int xemaclite_send_data(struct net_local *drvdata, u8 *data,
			       unsigned int byte_count)
{
	u32 reg_data;
	void __iomem *addr;

	/* Determine the expected Tx buffer address */
	addr = drvdata->base_addr + drvdata->next_tx_buf_to_use;

	/* If the length is too large, truncate it */
	if (byte_count > ETH_FRAME_LEN)
		byte_count = ETH_FRAME_LEN;

	/* Check if the expected buffer is available */
	reg_data = in_be32(addr + XEL_TSR_OFFSET);
	if ((reg_data & (XEL_TSR_XMIT_BUSY_MASK |
	     XEL_TSR_XMIT_ACTIVE_MASK)) == 0) {

		/* Switch to next buffer if configured */
		if (drvdata->tx_ping_pong != 0)
			drvdata->next_tx_buf_to_use ^= XEL_BUFFER_OFFSET;
	} else if (drvdata->tx_ping_pong != 0) {
		/* If the expected buffer is full, try the other buffer,
		 * if it is configured in HW */

		addr = (void __iomem __force *)((u32 __force)addr ^
						 XEL_BUFFER_OFFSET);
		reg_data = in_be32(addr + XEL_TSR_OFFSET);

		if ((reg_data & (XEL_TSR_XMIT_BUSY_MASK |
		     XEL_TSR_XMIT_ACTIVE_MASK)) != 0)
			return -1; /* Buffers were full, return failure */
	} else
		return -1; /* Buffer was full, return failure */

	/* Write the frame to the buffer */
	xemaclite_aligned_write(data, (u32 __force *) addr, byte_count);

	out_be32(addr + XEL_TPLR_OFFSET, (byte_count & XEL_TPLR_LENGTH_MASK));

	/* Update the Tx Status Register to indicate that there is a
	 * frame to send. Set the XEL_TSR_XMIT_ACTIVE_MASK flag which
	 * is used by the interrupt handler to check whether a frame
	 * has been transmitted */
	reg_data = in_be32(addr + XEL_TSR_OFFSET);
	reg_data |= (XEL_TSR_XMIT_BUSY_MASK | XEL_TSR_XMIT_ACTIVE_MASK);
	out_be32(addr + XEL_TSR_OFFSET, reg_data);

	return 0;
}

/**
 * xemaclite_recv_data - Receive a frame
 * @drvdata:	Pointer to the Emaclite device private data
 * @data:	Address where the data is to be received
 *
 * This function is intended to be called from the interrupt context or
 * with a wrapper which waits for the receive frame to be available.
 *
 * Return:	Total number of bytes received
 */
static u16 xemaclite_recv_data(struct net_local *drvdata, u8 *data, int maxlen)
{
	void __iomem *addr;
	u16 length, proto_type;
	u32 reg_data;

	/* Determine the expected buffer address */
	addr = (drvdata->base_addr + drvdata->next_rx_buf_to_use);

	/* Verify which buffer has valid data */
	reg_data = in_be32(addr + XEL_RSR_OFFSET);

	if ((reg_data & XEL_RSR_RECV_DONE_MASK) == XEL_RSR_RECV_DONE_MASK) {
		if (drvdata->rx_ping_pong != 0)
			drvdata->next_rx_buf_to_use ^= XEL_BUFFER_OFFSET;
	} else {
		/* The instance is out of sync, try other buffer if other
		 * buffer is configured, return 0 otherwise. If the instance is
		 * out of sync, do not update the 'next_rx_buf_to_use' since it
		 * will correct on subsequent calls */
		if (drvdata->rx_ping_pong != 0)
			addr = (void __iomem __force *)((u32 __force)addr ^
							 XEL_BUFFER_OFFSET);
		else
			return 0;	/* No data was available */

		/* Verify that buffer has valid data */
		reg_data = in_be32(addr + XEL_RSR_OFFSET);
		if ((reg_data & XEL_RSR_RECV_DONE_MASK) !=
		     XEL_RSR_RECV_DONE_MASK)
			return 0;	/* No data was available */
	}

	/* Get the protocol type of the ethernet frame that arrived */
	proto_type = ((ntohl(in_be32(addr + XEL_HEADER_OFFSET +
			XEL_RXBUFF_OFFSET)) >> XEL_HEADER_SHIFT) &
			XEL_RPLR_LENGTH_MASK);

	/* Check if received ethernet frame is a raw ethernet frame
	 * or an IP packet or an ARP packet */
	if (proto_type > ETH_DATA_LEN) {

		if (proto_type == ETH_P_IP) {
			length = ((ntohl(in_be32(addr +
					XEL_HEADER_IP_LENGTH_OFFSET +
					XEL_RXBUFF_OFFSET)) >>
					XEL_HEADER_SHIFT) &
					XEL_RPLR_LENGTH_MASK);
			length = min_t(u16, length, ETH_DATA_LEN);
			length += ETH_HLEN + ETH_FCS_LEN;

		} else if (proto_type == ETH_P_ARP)
			length = XEL_ARP_PACKET_SIZE + ETH_HLEN + ETH_FCS_LEN;
		else
			/* Field contains type other than IP or ARP, use max
			 * frame size and let user parse it */
			length = ETH_FRAME_LEN + ETH_FCS_LEN;
	} else
		/* Use the length in the frame, plus the header and trailer */
		length = proto_type + ETH_HLEN + ETH_FCS_LEN;

	if (WARN_ON(length > maxlen))
		length = maxlen;

	/* Read from the EmacLite device */
	xemaclite_aligned_read((u32 __force *) (addr + XEL_RXBUFF_OFFSET),
				data, length);

	/* Acknowledge the frame */
	reg_data = in_be32(addr + XEL_RSR_OFFSET);
	reg_data &= ~XEL_RSR_RECV_DONE_MASK;
	out_be32(addr + XEL_RSR_OFFSET, reg_data);

	return length;
}

/**
 * xemaclite_update_address - Update the MAC address in the device
 * @drvdata:	Pointer to the Emaclite device private data
 * @address_ptr:Pointer to the MAC address (MAC address is a 48-bit value)
 *
 * Tx must be idle and Rx should be idle for deterministic results.
 * It is recommended that this function should be called after the
 * initialization and before transmission of any packets from the device.
 * The MAC address can be programmed using any of the two transmit
 * buffers (if configured).
 */
static void xemaclite_update_address(struct net_local *drvdata,
				     u8 *address_ptr)
{
	void __iomem *addr;
	u32 reg_data;

	/* Determine the expected Tx buffer address */
	addr = drvdata->base_addr + drvdata->next_tx_buf_to_use;

	xemaclite_aligned_write(address_ptr, (u32 __force *) addr, ETH_ALEN);

	out_be32(addr + XEL_TPLR_OFFSET, ETH_ALEN);

	/* Update the MAC address in the EmacLite */
	reg_data = in_be32(addr + XEL_TSR_OFFSET);
	out_be32(addr + XEL_TSR_OFFSET, reg_data | XEL_TSR_PROG_MAC_ADDR);

	/* Wait for EmacLite to finish with the MAC address update */
	while ((in_be32(addr + XEL_TSR_OFFSET) &
		XEL_TSR_PROG_MAC_ADDR) != 0)
		;
}

/**
 * xemaclite_set_mac_address - Set the MAC address for this device
 * @dev:	Pointer to the network device instance
 * @addr:	Void pointer to the sockaddr structure
 *
 * This function copies the HW address from the sockaddr strucutre to the
 * net_device structure and updates the address in HW.
 *
 * Return:	Error if the net device is busy or 0 if the addr is set
 *		successfully
 */
static int xemaclite_set_mac_address(struct net_device *dev, void *address)
{
	struct net_local *lp = netdev_priv(dev);
	struct sockaddr *addr = address;

	if (netif_running(dev))
		return -EBUSY;

	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);
	xemaclite_update_address(lp, dev->dev_addr);
	return 0;
}

/**
 * xemaclite_tx_timeout - Callback for Tx Timeout
 * @dev:	Pointer to the network device
 *
 * This function is called when Tx time out occurs for Emaclite device.
 */
static void xemaclite_tx_timeout(struct net_device *dev)
{
	struct net_local *lp = netdev_priv(dev);
	unsigned long flags;

	dev_err(&lp->ndev->dev, "Exceeded transmit timeout of %lu ms\n",
		TX_TIMEOUT * 1000UL / HZ);

	dev->stats.tx_errors++;

	/* Reset the device */
	spin_lock_irqsave(&lp->reset_lock, flags);

	/* Shouldn't really be necessary, but shouldn't hurt */
	netif_stop_queue(dev);

	xemaclite_disable_interrupts(lp);
	xemaclite_enable_interrupts(lp);

	if (lp->deferred_skb) {
		dev_kfree_skb(lp->deferred_skb);
		lp->deferred_skb = NULL;
		dev->stats.tx_errors++;
	}

	/* To exclude tx timeout */
	dev->trans_start = jiffies; /* prevent tx timeout */

	/* We're all ready to go. Start the queue */
	netif_wake_queue(dev);
	spin_unlock_irqrestore(&lp->reset_lock, flags);
}

/**********************/
/* Interrupt Handlers */
/**********************/

/**
 * xemaclite_tx_handler - Interrupt handler for frames sent
 * @dev:	Pointer to the network device
 *
 * This function updates the number of packets transmitted and handles the
 * deferred skb, if there is one.
 */
static void xemaclite_tx_handler(struct net_device *dev)
{
	struct net_local *lp = netdev_priv(dev);

	dev->stats.tx_packets++;
	if (lp->deferred_skb) {
		if (xemaclite_send_data(lp,
					(u8 *) lp->deferred_skb->data,
					lp->deferred_skb->len) != 0)
			return;
		else {
			dev->stats.tx_bytes += lp->deferred_skb->len;
			dev_kfree_skb_irq(lp->deferred_skb);
			lp->deferred_skb = NULL;
			dev->trans_start = jiffies; /* prevent tx timeout */
			netif_wake_queue(dev);
		}
	}
}

/**
 * xemaclite_rx_handler- Interrupt handler for frames received
 * @dev:	Pointer to the network device
 *
 * This function allocates memory for a socket buffer, fills it with data
 * received and hands it over to the TCP/IP stack.
 */
static void xemaclite_rx_handler(struct net_device *dev)
{
	struct net_local *lp = netdev_priv(dev);
	struct sk_buff *skb;
	unsigned int align;
	u32 len;

	len = ETH_FRAME_LEN + ETH_FCS_LEN;
	skb = dev_alloc_skb(len + ALIGNMENT);
	if (!skb) {
		/* Couldn't get memory. */
		dev->stats.rx_dropped++;
		dev_err(&lp->ndev->dev, "Could not allocate receive buffer\n");
		return;
	}

	/*
	 * A new skb should have the data halfword aligned, but this code is
	 * here just in case that isn't true. Calculate how many
	 * bytes we should reserve to get the data to start on a word
	 * boundary */
	align = BUFFER_ALIGN(skb->data);
	if (align)
		skb_reserve(skb, align);

	skb_reserve(skb, 2);

	len = xemaclite_recv_data(lp, (u8 *) skb->data, len);

	if (!len) {
		dev->stats.rx_errors++;
		dev_kfree_skb_irq(skb);
		return;
	}

	skb_put(skb, len);	/* Tell the skb how much data we got */

	skb->protocol = eth_type_trans(skb, dev);
	skb_checksum_none_assert(skb);

	dev->stats.rx_packets++;
	dev->stats.rx_bytes += len;

	if (!skb_defer_rx_timestamp(skb))
		netif_rx(skb);	/* Send the packet upstream */
}

/**
 * xemaclite_interrupt - Interrupt handler for this driver
 * @irq:	Irq of the Emaclite device
 * @dev_id:	Void pointer to the network device instance used as callback
 *		reference
 *
 * This function handles the Tx and Rx interrupts of the EmacLite device.
 */
static irqreturn_t xemaclite_interrupt(int irq, void *dev_id)
{
	bool tx_complete = 0;
	struct net_device *dev = dev_id;
	struct net_local *lp = netdev_priv(dev);
	void __iomem *base_addr = lp->base_addr;
	u32 tx_status;

	/* Check if there is Rx Data available */
	if ((in_be32(base_addr + XEL_RSR_OFFSET) & XEL_RSR_RECV_DONE_MASK) ||
			(in_be32(base_addr + XEL_BUFFER_OFFSET + XEL_RSR_OFFSET)
			 & XEL_RSR_RECV_DONE_MASK))

		xemaclite_rx_handler(dev);

	/* Check if the Transmission for the first buffer is completed */
	tx_status = in_be32(base_addr + XEL_TSR_OFFSET);
	if (((tx_status & XEL_TSR_XMIT_BUSY_MASK) == 0) &&
		(tx_status & XEL_TSR_XMIT_ACTIVE_MASK) != 0) {

		tx_status &= ~XEL_TSR_XMIT_ACTIVE_MASK;
		out_be32(base_addr + XEL_TSR_OFFSET, tx_status);

		tx_complete = 1;
	}

	/* Check if the Transmission for the second buffer is completed */
	tx_status = in_be32(base_addr + XEL_BUFFER_OFFSET + XEL_TSR_OFFSET);
	if (((tx_status & XEL_TSR_XMIT_BUSY_MASK) == 0) &&
		(tx_status & XEL_TSR_XMIT_ACTIVE_MASK) != 0) {

		tx_status &= ~XEL_TSR_XMIT_ACTIVE_MASK;
		out_be32(base_addr + XEL_BUFFER_OFFSET + XEL_TSR_OFFSET,
			 tx_status);

		tx_complete = 1;
	}

	/* If there was a Tx interrupt, call the Tx Handler */
	if (tx_complete != 0)
		xemaclite_tx_handler(dev);

	return IRQ_HANDLED;
}

/**********************/
/* MDIO Bus functions */
/**********************/

/**
 * xemaclite_mdio_wait - Wait for the MDIO to be ready to use
 * @lp:		Pointer to the Emaclite device private data
 *
 * This function waits till the device is ready to accept a new MDIO
 * request.
 *
 * Return:	0 for success or ETIMEDOUT for a timeout
 */

static int xemaclite_mdio_wait(struct net_local *lp)
{
	long end = jiffies + 2;

	/* wait for the MDIO interface to not be busy or timeout
	   after some time.
	*/
	while (in_be32(lp->base_addr + XEL_MDIOCTRL_OFFSET) &
			XEL_MDIOCTRL_MDIOSTS_MASK) {
		if (end - jiffies <= 0) {
			WARN_ON(1);
			return -ETIMEDOUT;
		}
		msleep(1);
	}
	return 0;
}

/**
 * xemaclite_mdio_read - Read from a given MII management register
 * @bus:	the mii_bus struct
 * @phy_id:	the phy address
 * @reg:	register number to read from
 *
 * This function waits till the device is ready to accept a new MDIO
 * request and then writes the phy address to the MDIO Address register
 * and reads data from MDIO Read Data register, when its available.
 *
 * Return:	Value read from the MII management register
 */
static int xemaclite_mdio_read(struct mii_bus *bus, int phy_id, int reg)
{
	struct net_local *lp = bus->priv;
	u32 ctrl_reg;
	u32 rc;

	if (xemaclite_mdio_wait(lp))
		return -ETIMEDOUT;

	/* Write the PHY address, register number and set the OP bit in the
	 * MDIO Address register. Set the Status bit in the MDIO Control
	 * register to start a MDIO read transaction.
	 */
	ctrl_reg = in_be32(lp->base_addr + XEL_MDIOCTRL_OFFSET);
	out_be32(lp->base_addr + XEL_MDIOADDR_OFFSET,
		 XEL_MDIOADDR_OP_MASK |
		 ((phy_id << XEL_MDIOADDR_PHYADR_SHIFT) | reg));
	out_be32(lp->base_addr + XEL_MDIOCTRL_OFFSET,
		 ctrl_reg | XEL_MDIOCTRL_MDIOSTS_MASK);

	if (xemaclite_mdio_wait(lp))
		return -ETIMEDOUT;

	rc = in_be32(lp->base_addr + XEL_MDIORD_OFFSET);

	dev_dbg(&lp->ndev->dev,
		"xemaclite_mdio_read(phy_id=%i, reg=%x) == %x\n",
		phy_id, reg, rc);

	return rc;
}

/**
 * xemaclite_mdio_write - Write to a given MII management register
 * @bus:	the mii_bus struct
 * @phy_id:	the phy address
 * @reg:	register number to write to
 * @val:	value to write to the register number specified by reg
 *
 * This function waits till the device is ready to accept a new MDIO
 * request and then writes the val to the MDIO Write Data register.
 */
static int xemaclite_mdio_write(struct mii_bus *bus, int phy_id, int reg,
				u16 val)
{
	struct net_local *lp = bus->priv;
	u32 ctrl_reg;

	dev_dbg(&lp->ndev->dev,
		"xemaclite_mdio_write(phy_id=%i, reg=%x, val=%x)\n",
		phy_id, reg, val);

	if (xemaclite_mdio_wait(lp))
		return -ETIMEDOUT;

	/* Write the PHY address, register number and clear the OP bit in the
	 * MDIO Address register and then write the value into the MDIO Write
	 * Data register. Finally, set the Status bit in the MDIO Control
	 * register to start a MDIO write transaction.
	 */
	ctrl_reg = in_be32(lp->base_addr + XEL_MDIOCTRL_OFFSET);
	out_be32(lp->base_addr + XEL_MDIOADDR_OFFSET,
		 ~XEL_MDIOADDR_OP_MASK &
		 ((phy_id << XEL_MDIOADDR_PHYADR_SHIFT) | reg));
	out_be32(lp->base_addr + XEL_MDIOWR_OFFSET, val);
	out_be32(lp->base_addr + XEL_MDIOCTRL_OFFSET,
		 ctrl_reg | XEL_MDIOCTRL_MDIOSTS_MASK);

	return 0;
}

/**
 * xemaclite_mdio_reset - Reset the mdio bus.
 * @bus:	Pointer to the MII bus
 *
 * This function is required(?) as per Documentation/networking/phy.txt.
 * There is no reset in this device; this function always returns 0.
 */
static int xemaclite_mdio_reset(struct mii_bus *bus)
{
	return 0;
}

/**
 * xemaclite_mdio_setup - Register mii_bus for the Emaclite device
 * @lp:		Pointer to the Emaclite device private data
 * @ofdev:	Pointer to OF device structure
 *
 * This function enables MDIO bus in the Emaclite device and registers a
 * mii_bus.
 *
 * Return:	0 upon success or a negative error upon failure
 */
static int xemaclite_mdio_setup(struct net_local *lp, struct device *dev)
{
	struct mii_bus *bus;
	int rc;
	struct resource res;
	struct device_node *np = of_get_parent(lp->phy_node);

	/* Don't register the MDIO bus if the phy_node or its parent node
	 * can't be found.
	 */
	if (!np)
		return -ENODEV;

	/* Enable the MDIO bus by asserting the enable bit in MDIO Control
	 * register.
	 */
	out_be32(lp->base_addr + XEL_MDIOCTRL_OFFSET,
		 XEL_MDIOCTRL_MDIOEN_MASK);

	bus = mdiobus_alloc();
	if (!bus)
		return -ENOMEM;

	of_address_to_resource(np, 0, &res);
	snprintf(bus->id, MII_BUS_ID_SIZE, "%.8llx",
		 (unsigned long long)res.start);
	bus->priv = lp;
	bus->name = "Xilinx Emaclite MDIO";
	bus->read = xemaclite_mdio_read;
	bus->write = xemaclite_mdio_write;
	bus->reset = xemaclite_mdio_reset;
	bus->parent = dev;
	bus->irq = lp->mdio_irqs; /* preallocated IRQ table */

	lp->mii_bus = bus;

	rc = of_mdiobus_register(bus, np);
	if (rc)
		goto err_register;

	return 0;

err_register:
	mdiobus_free(bus);
	return rc;
}

/**
 * xemaclite_adjust_link - Link state callback for the Emaclite device
 * @ndev: pointer to net_device struct
 *
 * There's nothing in the Emaclite device to be configured when the link
 * state changes. We just print the status.
 */
void xemaclite_adjust_link(struct net_device *ndev)
{
	struct net_local *lp = netdev_priv(ndev);
	struct phy_device *phy = lp->phy_dev;
	int link_state;

	/* hash together the state values to decide if something has changed */
	link_state = phy->speed | (phy->duplex << 1) | phy->link;

	if (lp->last_link != link_state) {
		lp->last_link = link_state;
		phy_print_status(phy);
	}
}

/**
 * xemaclite_open - Open the network device
 * @dev:	Pointer to the network device
 *
 * This function sets the MAC address, requests an IRQ and enables interrupts
 * for the Emaclite device and starts the Tx queue.
 * It also connects to the phy device, if MDIO is included in Emaclite device.
 */
static int xemaclite_open(struct net_device *dev)
{
	struct net_local *lp = netdev_priv(dev);
	int retval;

	/* Just to be safe, stop the device first */
	xemaclite_disable_interrupts(lp);

	if (lp->phy_node) {
		u32 bmcr;

		lp->phy_dev = of_phy_connect(lp->ndev, lp->phy_node,
					     xemaclite_adjust_link, 0,
					     PHY_INTERFACE_MODE_MII);
		if (!lp->phy_dev) {
			dev_err(&lp->ndev->dev, "of_phy_connect() failed\n");
			return -ENODEV;
		}

		/* EmacLite doesn't support giga-bit speeds */
		lp->phy_dev->supported &= (PHY_BASIC_FEATURES);
		lp->phy_dev->advertising = lp->phy_dev->supported;

		/* Don't advertise 1000BASE-T Full/Half duplex speeds */
		phy_write(lp->phy_dev, MII_CTRL1000, 0);

		/* Advertise only 10 and 100mbps full/half duplex speeds */
		phy_write(lp->phy_dev, MII_ADVERTISE, ADVERTISE_ALL);

		/* Restart auto negotiation */
		bmcr = phy_read(lp->phy_dev, MII_BMCR);
		bmcr |= (BMCR_ANENABLE | BMCR_ANRESTART);
		phy_write(lp->phy_dev, MII_BMCR, bmcr);

		phy_start(lp->phy_dev);
	}

	/* Set the MAC address each time opened */
	xemaclite_update_address(lp, dev->dev_addr);

	/* Grab the IRQ */
	retval = request_irq(dev->irq, xemaclite_interrupt, 0, dev->name, dev);
	if (retval) {
		dev_err(&lp->ndev->dev, "Could not allocate interrupt %d\n",
			dev->irq);
		if (lp->phy_dev)
			phy_disconnect(lp->phy_dev);
		lp->phy_dev = NULL;

		return retval;
	}

	/* Enable Interrupts */
	xemaclite_enable_interrupts(lp);

	/* We're ready to go */
	netif_start_queue(dev);

	return 0;
}

/**
 * xemaclite_close - Close the network device
 * @dev:	Pointer to the network device
 *
 * This function stops the Tx queue, disables interrupts and frees the IRQ for
 * the Emaclite device.
 * It also disconnects the phy device associated with the Emaclite device.
 */
static int xemaclite_close(struct net_device *dev)
{
	struct net_local *lp = netdev_priv(dev);

	netif_stop_queue(dev);
	xemaclite_disable_interrupts(lp);
	free_irq(dev->irq, dev);

	if (lp->phy_dev)
		phy_disconnect(lp->phy_dev);
	lp->phy_dev = NULL;

	return 0;
}

/**
 * xemaclite_send - Transmit a frame
 * @orig_skb:	Pointer to the socket buffer to be transmitted
 * @dev:	Pointer to the network device
 *
 * This function checks if the Tx buffer of the Emaclite device is free to send
 * data. If so, it fills the Tx buffer with data from socket buffer data,
 * updates the stats and frees the socket buffer. The Tx completion is signaled
 * by an interrupt. If the Tx buffer isn't free, then the socket buffer is
 * deferred and the Tx queue is stopped so that the deferred socket buffer can
 * be transmitted when the Emaclite device is free to transmit data.
 *
 * Return:	0, always.
 */
static int xemaclite_send(struct sk_buff *orig_skb, struct net_device *dev)
{
	struct net_local *lp = netdev_priv(dev);
	struct sk_buff *new_skb;
	unsigned int len;
	unsigned long flags;

	len = orig_skb->len;

	new_skb = orig_skb;

	spin_lock_irqsave(&lp->reset_lock, flags);
	if (xemaclite_send_data(lp, (u8 *) new_skb->data, len) != 0) {
		/* If the Emaclite Tx buffer is busy, stop the Tx queue and
		 * defer the skb for transmission during the ISR, after the
		 * current transmission is complete */
		netif_stop_queue(dev);
		lp->deferred_skb = new_skb;
		/* Take the time stamp now, since we can't do this in an ISR. */
		skb_tx_timestamp(new_skb);
		spin_unlock_irqrestore(&lp->reset_lock, flags);
		return 0;
	}
	spin_unlock_irqrestore(&lp->reset_lock, flags);

	skb_tx_timestamp(new_skb);

	dev->stats.tx_bytes += len;
	dev_kfree_skb(new_skb);

	return 0;
}

/**
 * xemaclite_remove_ndev - Free the network device
 * @ndev:	Pointer to the network device to be freed
 *
 * This function un maps the IO region of the Emaclite device and frees the net
 * device.
 */
static void xemaclite_remove_ndev(struct net_device *ndev)
{
	if (ndev) {
		struct net_local *lp = netdev_priv(ndev);

		if (lp->base_addr)
			iounmap((void __iomem __force *) (lp->base_addr));
		free_netdev(ndev);
	}
}

/**
 * get_bool - Get a parameter from the OF device
 * @ofdev:	Pointer to OF device structure
 * @s:		Property to be retrieved
 *
 * This function looks for a property in the device node and returns the value
 * of the property if its found or 0 if the property is not found.
 *
 * Return:	Value of the parameter if the parameter is found, or 0 otherwise
 */
static bool get_bool(struct platform_device *ofdev, const char *s)
{
	u32 *p = (u32 *)of_get_property(ofdev->dev.of_node, s, NULL);

	if (p) {
		return (bool)*p;
	} else {
		dev_warn(&ofdev->dev, "Parameter %s not found,"
			"defaulting to false\n", s);
		return 0;
	}
}

static struct net_device_ops xemaclite_netdev_ops;

/**
 * xemaclite_of_probe - Probe method for the Emaclite device.
 * @ofdev:	Pointer to OF device structure
 * @match:	Pointer to the structure used for matching a device
 *
 * This function probes for the Emaclite device in the device tree.
 * It initializes the driver data structure and the hardware, sets the MAC
 * address and registers the network device.
 * It also registers a mii_bus for the Emaclite device, if MDIO is included
 * in the device.
 *
 * Return:	0, if the driver is bound to the Emaclite device, or
 *		a negative error if there is failure.
 */
static int __devinit xemaclite_of_probe(struct platform_device *ofdev)
{
	struct resource r_irq; /* Interrupt resources */
	struct resource r_mem; /* IO mem resources */
	struct net_device *ndev = NULL;
	struct net_local *lp = NULL;
	struct device *dev = &ofdev->dev;
	const void *mac_address;

	int rc = 0;

	dev_info(dev, "Device Tree Probing\n");

	/* Get iospace for the device */
	rc = of_address_to_resource(ofdev->dev.of_node, 0, &r_mem);
	if (rc) {
		dev_err(dev, "invalid address\n");
		return rc;
	}

	/* Get IRQ for the device */
	rc = of_irq_to_resource(ofdev->dev.of_node, 0, &r_irq);
	if (rc == NO_IRQ) {
		dev_err(dev, "no IRQ found\n");
		return rc;
	}

	/* Create an ethernet device instance */
	ndev = alloc_etherdev(sizeof(struct net_local));
	if (!ndev) {
		dev_err(dev, "Could not allocate network device\n");
		return -ENOMEM;
	}

	dev_set_drvdata(dev, ndev);
	SET_NETDEV_DEV(ndev, &ofdev->dev);

	ndev->irq = r_irq.start;
	ndev->mem_start = r_mem.start;
	ndev->mem_end = r_mem.end;

	lp = netdev_priv(ndev);
	lp->ndev = ndev;

	if (!request_mem_region(ndev->mem_start,
				ndev->mem_end - ndev->mem_start + 1,
				DRIVER_NAME)) {
		dev_err(dev, "Couldn't lock memory region at %p\n",
			(void *)ndev->mem_start);
		rc = -EBUSY;
		goto error2;
	}

	/* Get the virtual base address for the device */
	lp->base_addr = ioremap(r_mem.start, resource_size(&r_mem));
	if (NULL == lp->base_addr) {
		dev_err(dev, "EmacLite: Could not allocate iomem\n");
		rc = -EIO;
		goto error1;
	}

	spin_lock_init(&lp->reset_lock);
	lp->next_tx_buf_to_use = 0x0;
	lp->next_rx_buf_to_use = 0x0;
	lp->tx_ping_pong = get_bool(ofdev, "xlnx,tx-ping-pong");
	lp->rx_ping_pong = get_bool(ofdev, "xlnx,rx-ping-pong");
	mac_address = of_get_mac_address(ofdev->dev.of_node);

	if (mac_address)
		/* Set the MAC address. */
		memcpy(ndev->dev_addr, mac_address, 6);
	else
		dev_warn(dev, "No MAC address found\n");

	/* Clear the Tx CSR's in case this is a restart */
	out_be32(lp->base_addr + XEL_TSR_OFFSET, 0);
	out_be32(lp->base_addr + XEL_BUFFER_OFFSET + XEL_TSR_OFFSET, 0);

	/* Set the MAC address in the EmacLite device */
	xemaclite_update_address(lp, ndev->dev_addr);

	lp->phy_node = of_parse_phandle(ofdev->dev.of_node, "phy-handle", 0);
	rc = xemaclite_mdio_setup(lp, &ofdev->dev);
	if (rc)
		dev_warn(&ofdev->dev, "error registering MDIO bus\n");

	dev_info(dev, "MAC address is now %pM\n", ndev->dev_addr);

	ndev->netdev_ops = &xemaclite_netdev_ops;
	ndev->flags &= ~IFF_MULTICAST;
	ndev->watchdog_timeo = TX_TIMEOUT;

	/* Finally, register the device */
	rc = register_netdev(ndev);
	if (rc) {
		dev_err(dev,
			"Cannot register network device, aborting\n");
		goto error1;
	}

	dev_info(dev,
		 "Xilinx EmacLite at 0x%08X mapped to 0x%08X, irq=%d\n",
		 (unsigned int __force)ndev->mem_start,
		 (unsigned int __force)lp->base_addr, ndev->irq);
	return 0;

error1:
	release_mem_region(ndev->mem_start, resource_size(&r_mem));

error2:
	xemaclite_remove_ndev(ndev);
	return rc;
}

/**
 * xemaclite_of_remove - Unbind the driver from the Emaclite device.
 * @of_dev:	Pointer to OF device structure
 *
 * This function is called if a device is physically removed from the system or
 * if the driver module is being unloaded. It frees any resources allocated to
 * the device.
 *
 * Return:	0, always.
 */
static int __devexit xemaclite_of_remove(struct platform_device *of_dev)
{
	struct device *dev = &of_dev->dev;
	struct net_device *ndev = dev_get_drvdata(dev);

	struct net_local *lp = netdev_priv(ndev);

	/* Un-register the mii_bus, if configured */
	if (lp->has_mdio) {
		mdiobus_unregister(lp->mii_bus);
		kfree(lp->mii_bus->irq);
		mdiobus_free(lp->mii_bus);
		lp->mii_bus = NULL;
	}

	unregister_netdev(ndev);

	if (lp->phy_node)
		of_node_put(lp->phy_node);
	lp->phy_node = NULL;

	release_mem_region(ndev->mem_start, ndev->mem_end-ndev->mem_start + 1);

	xemaclite_remove_ndev(ndev);
	dev_set_drvdata(dev, NULL);

	return 0;
}

#ifdef CONFIG_NET_POLL_CONTROLLER
static void
xemaclite_poll_controller(struct net_device *ndev)
{
	disable_irq(ndev->irq);
	xemaclite_interrupt(ndev->irq, ndev);
	enable_irq(ndev->irq);
}
#endif

static struct net_device_ops xemaclite_netdev_ops = {
	.ndo_open		= xemaclite_open,
	.ndo_stop		= xemaclite_close,
	.ndo_start_xmit		= xemaclite_send,
	.ndo_set_mac_address	= xemaclite_set_mac_address,
	.ndo_tx_timeout		= xemaclite_tx_timeout,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller = xemaclite_poll_controller,
#endif
};

/* Match table for OF platform binding */
static struct of_device_id xemaclite_of_match[] __devinitdata = {
	{ .compatible = "xlnx,opb-ethernetlite-1.01.a", },
	{ .compatible = "xlnx,opb-ethernetlite-1.01.b", },
	{ .compatible = "xlnx,xps-ethernetlite-1.00.a", },
	{ .compatible = "xlnx,xps-ethernetlite-2.00.a", },
	{ .compatible = "xlnx,xps-ethernetlite-2.01.a", },
	{ .compatible = "xlnx,xps-ethernetlite-3.00.a", },
	{ /* end of list */ },
};
MODULE_DEVICE_TABLE(of, xemaclite_of_match);

static struct platform_driver xemaclite_of_driver = {
	.driver = {
		.name = DRIVER_NAME,
		.owner = THIS_MODULE,
		.of_match_table = xemaclite_of_match,
	},
	.probe		= xemaclite_of_probe,
	.remove		= __devexit_p(xemaclite_of_remove),
};

/**
 * xgpiopss_init - Initial driver registration call
 *
 * Return:	0 upon success, or a negative error upon failure.
 */
static int __init xemaclite_init(void)
{
	/* No kernel boot options used, we just need to register the driver */
	return platform_driver_register(&xemaclite_of_driver);
}

/**
 * xemaclite_cleanup - Driver un-registration call
 */
static void __exit xemaclite_cleanup(void)
{
	platform_driver_unregister(&xemaclite_of_driver);
}

module_init(xemaclite_init);
module_exit(xemaclite_cleanup);

MODULE_AUTHOR("Xilinx, Inc.");
MODULE_DESCRIPTION("Xilinx Ethernet MAC Lite driver");
MODULE_LICENSE("GPL");
