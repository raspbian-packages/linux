// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2007 - 2012 Realtek Corporation. */

#define _OSDEP_SERVICE_C_

#include "../include/osdep_service.h"
#include "../include/drv_types.h"
#include "../include/recv_osdep.h"
#include "../include/rtw_ioctl_set.h"

/*
* Translate the OS dependent @param error_code to OS independent RTW_STATUS_CODE
* @return: one of RTW_STATUS_CODE
*/
inline int RTW_STATUS_CODE(int error_code)
{
	if (error_code >= 0)
		return _SUCCESS;
	return _FAIL;
}

void *rtw_malloc2d(int h, int w, int size)
{
	int j;

	void **a = kzalloc(h * sizeof(void *) + h * w * size, GFP_KERNEL);
	if (!a)
		return NULL;

	for (j = 0; j < h; j++)
		a[j] = ((char *)(a + h)) + j * w * size;

	return a;
}

/*
For the following list_xxx operations,
caller must guarantee the atomic context.
Otherwise, there will be racing condition.
*/
/*
Caller must check if the list is empty before calling rtw_list_delete
*/

static const struct device_type wlan_type = {
	.name = "wlan",
};

struct net_device *rtw_alloc_etherdev_with_old_priv(int sizeof_priv,
						    void *old_priv)
{
	struct net_device *pnetdev;
	struct rtw_netdev_priv_indicator *pnpi;

	pnetdev = alloc_etherdev_mq(sizeof(struct rtw_netdev_priv_indicator), 4);
	if (!pnetdev)
		goto RETURN;

	pnetdev->dev.type = &wlan_type;
	pnpi = netdev_priv(pnetdev);
	pnpi->priv = old_priv;
	pnpi->sizeof_priv = sizeof_priv;

RETURN:
	return pnetdev;
}

struct net_device *rtw_alloc_etherdev(int sizeof_priv)
{
	struct net_device *pnetdev;
	struct rtw_netdev_priv_indicator *pnpi;

	pnetdev = alloc_etherdev_mq(sizeof(struct rtw_netdev_priv_indicator), 4);
	if (!pnetdev)
		goto RETURN;

	pnpi = netdev_priv(pnetdev);

	pnpi->priv = vzalloc(sizeof_priv);
	if (!pnpi->priv) {
		free_netdev(pnetdev);
		pnetdev = NULL;
		goto RETURN;
	}

	pnpi->sizeof_priv = sizeof_priv;
RETURN:
	return pnetdev;
}

void rtw_free_netdev(struct net_device *netdev)
{
	struct rtw_netdev_priv_indicator *pnpi;

	pnpi = netdev_priv(netdev);

	vfree(pnpi->priv);
	free_netdev(netdev);
}

int rtw_change_ifname(struct adapter *padapter, const char *ifname)
{
	struct net_device *pnetdev;
	struct net_device *cur_pnetdev;
	struct rereg_nd_name_data *rereg_priv;
	int ret;

	if (!padapter)
		goto error;

	cur_pnetdev = padapter->pnetdev;
	rereg_priv = &padapter->rereg_nd_name_priv;

	/* free the old_pnetdev */
	if (rereg_priv->old_pnetdev) {
		free_netdev(rereg_priv->old_pnetdev);
		rereg_priv->old_pnetdev = NULL;
	}

	if (!rtnl_is_locked())
		unregister_netdev(cur_pnetdev);
	else
		unregister_netdevice(cur_pnetdev);

	rereg_priv->old_pnetdev = cur_pnetdev;

	pnetdev = rtw_init_netdev(padapter);
	if (!pnetdev)  {
		ret = -1;
		goto error;
	}

	SET_NETDEV_DEV(pnetdev, dvobj_to_dev(adapter_to_dvobj(padapter)));

	rtw_init_netdev_name(pnetdev, ifname);

	eth_hw_addr_set(pnetdev, padapter->eeprompriv.mac_addr);

	if (!rtnl_is_locked())
		ret = register_netdev(pnetdev);
	else
		ret = register_netdevice(pnetdev);
	if (ret != 0)
		goto error;

	return 0;
error:
	return -1;
}

void rtw_buf_update(u8 **buf, u32 *buf_len, u8 *src, u32 src_len)
{
	u32 dup_len = 0;
	u8 *ori = NULL;
	u8 *dup = NULL;

	if (!buf || !buf_len)
		return;

	if (!src || !src_len)
		goto keep_ori;

	/* duplicate src */
	dup = kmalloc(src_len, GFP_ATOMIC);
	if (dup) {
		dup_len = src_len;
		memcpy(dup, src, dup_len);
	}

keep_ori:
	ori = *buf;

	/* replace buf with dup */
	*buf_len = 0;
	*buf = dup;
	*buf_len = dup_len;

	/* free ori */
	kfree(ori);
}

/**
 * rtw_cbuf_empty - test if cbuf is empty
 * @cbuf: pointer of struct rtw_cbuf
 *
 * Returns: true if cbuf is empty
 */
inline bool rtw_cbuf_empty(struct rtw_cbuf *cbuf)
{
	return cbuf->write == cbuf->read;
}

/**
 * rtw_cbuf_pop - pop a pointer from cbuf
 * @cbuf: pointer of struct rtw_cbuf
 *
 * Lock free operation, be careful of the use scheme
 * Returns: pointer popped out
 */
void *rtw_cbuf_pop(struct rtw_cbuf *cbuf)
{
	void *buf;
	if (rtw_cbuf_empty(cbuf))
		return NULL;

	buf = cbuf->bufs[cbuf->read];
	cbuf->read = (cbuf->read + 1) % cbuf->size;

	return buf;
}

/**
 * rtw_cbuf_alloc - allocate a rtw_cbuf with given size and do initialization
 * @size: size of pointer
 *
 * Returns: pointer of srtuct rtw_cbuf, NULL for allocation failure
 */
struct rtw_cbuf *rtw_cbuf_alloc(u32 size)
{
	struct rtw_cbuf *cbuf;

	cbuf = kmalloc(struct_size(cbuf, bufs, size), GFP_KERNEL);

	if (cbuf) {
		cbuf->write = 0;
		cbuf->read = 0;
		cbuf->size = size;
	}
	return cbuf;
}
