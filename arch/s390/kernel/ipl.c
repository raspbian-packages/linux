// SPDX-License-Identifier: GPL-2.0
/*
 *    ipl/reipl/dump support for Linux on s390.
 *
 *    Copyright IBM Corp. 2005, 2012
 *    Author(s): Michael Holzheu <holzheu@de.ibm.com>
 *		 Heiko Carstens <heiko.carstens@de.ibm.com>
 *		 Volker Sameske <sameske@de.ibm.com>
 */

#include <linux/types.h>
#include <linux/export.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/delay.h>
#include <linux/reboot.h>
#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/crash_dump.h>
#include <linux/debug_locks.h>
#include <asm/diag.h>
#include <asm/ipl.h>
#include <asm/smp.h>
#include <asm/setup.h>
#include <asm/cpcmd.h>
#include <asm/ebcdic.h>
#include <asm/sclp.h>
#include <asm/checksum.h>
#include <asm/debug.h>
#include <asm/os_info.h>
#include "entry.h"

#define IPL_PARM_BLOCK_VERSION 0

#define IPL_UNKNOWN_STR		"unknown"
#define IPL_CCW_STR		"ccw"
#define IPL_FCP_STR		"fcp"
#define IPL_FCP_DUMP_STR	"fcp_dump"
#define IPL_NSS_STR		"nss"

#define DUMP_CCW_STR		"ccw"
#define DUMP_FCP_STR		"fcp"
#define DUMP_NONE_STR		"none"

/*
 * Four shutdown trigger types are supported:
 * - panic
 * - halt
 * - power off
 * - reipl
 * - restart
 */
#define ON_PANIC_STR		"on_panic"
#define ON_HALT_STR		"on_halt"
#define ON_POFF_STR		"on_poff"
#define ON_REIPL_STR		"on_reboot"
#define ON_RESTART_STR		"on_restart"

struct shutdown_action;
struct shutdown_trigger {
	char *name;
	struct shutdown_action *action;
};

/*
 * The following shutdown action types are supported:
 */
#define SHUTDOWN_ACTION_IPL_STR		"ipl"
#define SHUTDOWN_ACTION_REIPL_STR	"reipl"
#define SHUTDOWN_ACTION_DUMP_STR	"dump"
#define SHUTDOWN_ACTION_VMCMD_STR	"vmcmd"
#define SHUTDOWN_ACTION_STOP_STR	"stop"
#define SHUTDOWN_ACTION_DUMP_REIPL_STR	"dump_reipl"

struct shutdown_action {
	char *name;
	void (*fn) (struct shutdown_trigger *trigger);
	int (*init) (void);
	int init_rc;
};

static char *ipl_type_str(enum ipl_type type)
{
	switch (type) {
	case IPL_TYPE_CCW:
		return IPL_CCW_STR;
	case IPL_TYPE_FCP:
		return IPL_FCP_STR;
	case IPL_TYPE_FCP_DUMP:
		return IPL_FCP_DUMP_STR;
	case IPL_TYPE_NSS:
		return IPL_NSS_STR;
	case IPL_TYPE_UNKNOWN:
	default:
		return IPL_UNKNOWN_STR;
	}
}

enum dump_type {
	DUMP_TYPE_NONE	= 1,
	DUMP_TYPE_CCW	= 2,
	DUMP_TYPE_FCP	= 4,
};

static char *dump_type_str(enum dump_type type)
{
	switch (type) {
	case DUMP_TYPE_NONE:
		return DUMP_NONE_STR;
	case DUMP_TYPE_CCW:
		return DUMP_CCW_STR;
	case DUMP_TYPE_FCP:
		return DUMP_FCP_STR;
	default:
		return NULL;
	}
}

static int ipl_block_valid;
static struct ipl_parameter_block ipl_block;

static int reipl_capabilities = IPL_TYPE_UNKNOWN;

static enum ipl_type reipl_type = IPL_TYPE_UNKNOWN;
static struct ipl_parameter_block *reipl_block_fcp;
static struct ipl_parameter_block *reipl_block_ccw;
static struct ipl_parameter_block *reipl_block_nss;
static struct ipl_parameter_block *reipl_block_actual;

static int dump_capabilities = DUMP_TYPE_NONE;
static enum dump_type dump_type = DUMP_TYPE_NONE;
static struct ipl_parameter_block *dump_block_fcp;
static struct ipl_parameter_block *dump_block_ccw;

static struct sclp_ipl_info sclp_ipl_info;

static inline int __diag308(unsigned long subcode, void *addr)
{
	register unsigned long _addr asm("0") = (unsigned long) addr;
	register unsigned long _rc asm("1") = 0;

	asm volatile(
		"	diag	%0,%2,0x308\n"
		"0:	nopr	%%r7\n"
		EX_TABLE(0b,0b)
		: "+d" (_addr), "+d" (_rc)
		: "d" (subcode) : "cc", "memory");
	return _rc;
}

int diag308(unsigned long subcode, void *addr)
{
	diag_stat_inc(DIAG_STAT_X308);
	return __diag308(subcode, addr);
}
EXPORT_SYMBOL_GPL(diag308);

/* SYSFS */

#define IPL_ATTR_SHOW_FN(_prefix, _name, _format, args...)		\
static ssize_t sys_##_prefix##_##_name##_show(struct kobject *kobj,	\
		struct kobj_attribute *attr,				\
		char *page)						\
{									\
	return snprintf(page, PAGE_SIZE, _format, ##args);		\
}

#define IPL_ATTR_CCW_STORE_FN(_prefix, _name, _ipl_blk)			\
static ssize_t sys_##_prefix##_##_name##_store(struct kobject *kobj,	\
		struct kobj_attribute *attr,				\
		const char *buf, size_t len)				\
{									\
	unsigned long long ssid, devno;					\
									\
	if (sscanf(buf, "0.%llx.%llx\n", &ssid, &devno) != 2)		\
		return -EINVAL;						\
									\
	if (ssid > __MAX_SSID || devno > __MAX_SUBCHANNEL)		\
		return -EINVAL;						\
									\
	_ipl_blk.ssid = ssid;						\
	_ipl_blk.devno = devno;						\
	return len;							\
}

#define DEFINE_IPL_CCW_ATTR_RW(_prefix, _name, _ipl_blk)		\
IPL_ATTR_SHOW_FN(_prefix, _name, "0.%x.%04x\n",				\
		 _ipl_blk.ssid, _ipl_blk.devno);			\
IPL_ATTR_CCW_STORE_FN(_prefix, _name, _ipl_blk);			\
static struct kobj_attribute sys_##_prefix##_##_name##_attr =		\
	__ATTR(_name, (S_IRUGO | S_IWUSR),				\
	       sys_##_prefix##_##_name##_show,				\
	       sys_##_prefix##_##_name##_store)				\

#define DEFINE_IPL_ATTR_RO(_prefix, _name, _format, _value)		\
IPL_ATTR_SHOW_FN(_prefix, _name, _format, _value)			\
static struct kobj_attribute sys_##_prefix##_##_name##_attr =		\
	__ATTR(_name, S_IRUGO, sys_##_prefix##_##_name##_show, NULL)

#define DEFINE_IPL_ATTR_RW(_prefix, _name, _fmt_out, _fmt_in, _value)	\
IPL_ATTR_SHOW_FN(_prefix, _name, _fmt_out, (unsigned long long) _value)	\
static ssize_t sys_##_prefix##_##_name##_store(struct kobject *kobj,	\
		struct kobj_attribute *attr,				\
		const char *buf, size_t len)				\
{									\
	unsigned long long value;					\
	if (sscanf(buf, _fmt_in, &value) != 1)				\
		return -EINVAL;						\
	_value = value;							\
	return len;							\
}									\
static struct kobj_attribute sys_##_prefix##_##_name##_attr =		\
	__ATTR(_name,(S_IRUGO | S_IWUSR),				\
			sys_##_prefix##_##_name##_show,			\
			sys_##_prefix##_##_name##_store)

#define DEFINE_IPL_ATTR_STR_RW(_prefix, _name, _fmt_out, _fmt_in, _value)\
IPL_ATTR_SHOW_FN(_prefix, _name, _fmt_out, _value)			\
static ssize_t sys_##_prefix##_##_name##_store(struct kobject *kobj,	\
		struct kobj_attribute *attr,				\
		const char *buf, size_t len)				\
{									\
	strncpy(_value, buf, sizeof(_value) - 1);			\
	strim(_value);							\
	return len;							\
}									\
static struct kobj_attribute sys_##_prefix##_##_name##_attr =		\
	__ATTR(_name,(S_IRUGO | S_IWUSR),				\
			sys_##_prefix##_##_name##_show,			\
			sys_##_prefix##_##_name##_store)

/*
 * ipl section
 */

static __init enum ipl_type get_ipl_type(void)
{
	if (!ipl_block_valid)
		return IPL_TYPE_UNKNOWN;

	switch (ipl_block.hdr.pbt) {
	case DIAG308_IPL_TYPE_CCW:
		return IPL_TYPE_CCW;
	case DIAG308_IPL_TYPE_FCP:
		if (ipl_block.ipl_info.fcp.opt == DIAG308_IPL_OPT_DUMP)
			return IPL_TYPE_FCP_DUMP;
		else
			return IPL_TYPE_FCP;
	}
	return IPL_TYPE_UNKNOWN;
}

struct ipl_info ipl_info;
EXPORT_SYMBOL_GPL(ipl_info);

static ssize_t ipl_type_show(struct kobject *kobj, struct kobj_attribute *attr,
			     char *page)
{
	return sprintf(page, "%s\n", ipl_type_str(ipl_info.type));
}

static struct kobj_attribute sys_ipl_type_attr = __ATTR_RO(ipl_type);

/* VM IPL PARM routines */
static size_t reipl_get_ascii_vmparm(char *dest, size_t size,
				     const struct ipl_parameter_block *ipb)
{
	int i;
	size_t len;
	char has_lowercase = 0;

	len = 0;
	if ((ipb->ipl_info.ccw.vm_flags & DIAG308_VM_FLAGS_VP_VALID) &&
	    (ipb->ipl_info.ccw.vm_parm_len > 0)) {

		len = min_t(size_t, size - 1, ipb->ipl_info.ccw.vm_parm_len);
		memcpy(dest, ipb->ipl_info.ccw.vm_parm, len);
		/* If at least one character is lowercase, we assume mixed
		 * case; otherwise we convert everything to lowercase.
		 */
		for (i = 0; i < len; i++)
			if ((dest[i] > 0x80 && dest[i] < 0x8a) || /* a-i */
			    (dest[i] > 0x90 && dest[i] < 0x9a) || /* j-r */
			    (dest[i] > 0xa1 && dest[i] < 0xaa)) { /* s-z */
				has_lowercase = 1;
				break;
			}
		if (!has_lowercase)
			EBC_TOLOWER(dest, len);
		EBCASC(dest, len);
	}
	dest[len] = 0;

	return len;
}

size_t append_ipl_vmparm(char *dest, size_t size)
{
	size_t rc;

	rc = 0;
	if (ipl_block_valid && ipl_block.hdr.pbt == DIAG308_IPL_TYPE_CCW)
		rc = reipl_get_ascii_vmparm(dest, size, &ipl_block);
	else
		dest[0] = 0;
	return rc;
}

static ssize_t ipl_vm_parm_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *page)
{
	char parm[DIAG308_VMPARM_SIZE + 1] = {};

	append_ipl_vmparm(parm, sizeof(parm));
	return sprintf(page, "%s\n", parm);
}

static size_t scpdata_length(const char* buf, size_t count)
{
	while (count) {
		if (buf[count - 1] != '\0' && buf[count - 1] != ' ')
			break;
		count--;
	}
	return count;
}

static size_t reipl_append_ascii_scpdata(char *dest, size_t size,
					 const struct ipl_parameter_block *ipb)
{
	size_t count;
	size_t i;
	int has_lowercase;

	count = min(size - 1, scpdata_length(ipb->ipl_info.fcp.scp_data,
					     ipb->ipl_info.fcp.scp_data_len));
	if (!count)
		goto out;

	has_lowercase = 0;
	for (i = 0; i < count; i++) {
		if (!isascii(ipb->ipl_info.fcp.scp_data[i])) {
			count = 0;
			goto out;
		}
		if (!has_lowercase && islower(ipb->ipl_info.fcp.scp_data[i]))
			has_lowercase = 1;
	}

	if (has_lowercase)
		memcpy(dest, ipb->ipl_info.fcp.scp_data, count);
	else
		for (i = 0; i < count; i++)
			dest[i] = tolower(ipb->ipl_info.fcp.scp_data[i]);
out:
	dest[count] = '\0';
	return count;
}

size_t append_ipl_scpdata(char *dest, size_t len)
{
	size_t rc;

	rc = 0;
	if (ipl_block_valid && ipl_block.hdr.pbt == DIAG308_IPL_TYPE_FCP)
		rc = reipl_append_ascii_scpdata(dest, len, &ipl_block);
	else
		dest[0] = 0;
	return rc;
}


static struct kobj_attribute sys_ipl_vm_parm_attr =
	__ATTR(parm, S_IRUGO, ipl_vm_parm_show, NULL);

static ssize_t sys_ipl_device_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *page)
{
	switch (ipl_info.type) {
	case IPL_TYPE_CCW:
		return sprintf(page, "0.%x.%04x\n", ipl_block.ipl_info.ccw.ssid,
			       ipl_block.ipl_info.ccw.devno);
	case IPL_TYPE_FCP:
	case IPL_TYPE_FCP_DUMP:
		return sprintf(page, "0.0.%04x\n",
			       ipl_block.ipl_info.fcp.devno);
	default:
		return 0;
	}
}

static struct kobj_attribute sys_ipl_device_attr =
	__ATTR(device, S_IRUGO, sys_ipl_device_show, NULL);

static ssize_t ipl_parameter_read(struct file *filp, struct kobject *kobj,
				  struct bin_attribute *attr, char *buf,
				  loff_t off, size_t count)
{
	return memory_read_from_buffer(buf, count, &off, &ipl_block,
				       ipl_block.hdr.len);
}
static struct bin_attribute ipl_parameter_attr =
	__BIN_ATTR(binary_parameter, S_IRUGO, ipl_parameter_read, NULL,
		   PAGE_SIZE);

static ssize_t ipl_scp_data_read(struct file *filp, struct kobject *kobj,
				 struct bin_attribute *attr, char *buf,
				 loff_t off, size_t count)
{
	unsigned int size = ipl_block.ipl_info.fcp.scp_data_len;
	void *scp_data = &ipl_block.ipl_info.fcp.scp_data;

	return memory_read_from_buffer(buf, count, &off, scp_data, size);
}
static struct bin_attribute ipl_scp_data_attr =
	__BIN_ATTR(scp_data, S_IRUGO, ipl_scp_data_read, NULL, PAGE_SIZE);

static struct bin_attribute *ipl_fcp_bin_attrs[] = {
	&ipl_parameter_attr,
	&ipl_scp_data_attr,
	NULL,
};

/* FCP ipl device attributes */

DEFINE_IPL_ATTR_RO(ipl_fcp, wwpn, "0x%016llx\n",
		   (unsigned long long)ipl_block.ipl_info.fcp.wwpn);
DEFINE_IPL_ATTR_RO(ipl_fcp, lun, "0x%016llx\n",
		   (unsigned long long)ipl_block.ipl_info.fcp.lun);
DEFINE_IPL_ATTR_RO(ipl_fcp, bootprog, "%lld\n",
		   (unsigned long long)ipl_block.ipl_info.fcp.bootprog);
DEFINE_IPL_ATTR_RO(ipl_fcp, br_lba, "%lld\n",
		   (unsigned long long)ipl_block.ipl_info.fcp.br_lba);

static ssize_t ipl_ccw_loadparm_show(struct kobject *kobj,
				     struct kobj_attribute *attr, char *page)
{
	char loadparm[LOADPARM_LEN + 1] = {};

	if (!sclp_ipl_info.is_valid)
		return sprintf(page, "#unknown#\n");
	memcpy(loadparm, &sclp_ipl_info.loadparm, LOADPARM_LEN);
	EBCASC(loadparm, LOADPARM_LEN);
	strim(loadparm);
	return sprintf(page, "%s\n", loadparm);
}

static struct kobj_attribute sys_ipl_ccw_loadparm_attr =
	__ATTR(loadparm, 0444, ipl_ccw_loadparm_show, NULL);

static struct attribute *ipl_fcp_attrs[] = {
	&sys_ipl_type_attr.attr,
	&sys_ipl_device_attr.attr,
	&sys_ipl_fcp_wwpn_attr.attr,
	&sys_ipl_fcp_lun_attr.attr,
	&sys_ipl_fcp_bootprog_attr.attr,
	&sys_ipl_fcp_br_lba_attr.attr,
	&sys_ipl_ccw_loadparm_attr.attr,
	NULL,
};

static struct attribute_group ipl_fcp_attr_group = {
	.attrs = ipl_fcp_attrs,
	.bin_attrs = ipl_fcp_bin_attrs,
};

/* CCW ipl device attributes */

static struct attribute *ipl_ccw_attrs_vm[] = {
	&sys_ipl_type_attr.attr,
	&sys_ipl_device_attr.attr,
	&sys_ipl_ccw_loadparm_attr.attr,
	&sys_ipl_vm_parm_attr.attr,
	NULL,
};

static struct attribute *ipl_ccw_attrs_lpar[] = {
	&sys_ipl_type_attr.attr,
	&sys_ipl_device_attr.attr,
	&sys_ipl_ccw_loadparm_attr.attr,
	NULL,
};

static struct attribute_group ipl_ccw_attr_group_vm = {
	.attrs = ipl_ccw_attrs_vm,
};

static struct attribute_group ipl_ccw_attr_group_lpar = {
	.attrs = ipl_ccw_attrs_lpar
};

/* UNKNOWN ipl device attributes */

static struct attribute *ipl_unknown_attrs[] = {
	&sys_ipl_type_attr.attr,
	NULL,
};

static struct attribute_group ipl_unknown_attr_group = {
	.attrs = ipl_unknown_attrs,
};

static struct kset *ipl_kset;

static void __ipl_run(void *unused)
{
	__bpon();
	diag308(DIAG308_LOAD_CLEAR, NULL);
}

static void ipl_run(struct shutdown_trigger *trigger)
{
	smp_call_ipl_cpu(__ipl_run, NULL);
}

static int __init ipl_init(void)
{
	int rc;

	ipl_kset = kset_create_and_add("ipl", NULL, firmware_kobj);
	if (!ipl_kset) {
		rc = -ENOMEM;
		goto out;
	}
	switch (ipl_info.type) {
	case IPL_TYPE_CCW:
		if (MACHINE_IS_VM)
			rc = sysfs_create_group(&ipl_kset->kobj,
						&ipl_ccw_attr_group_vm);
		else
			rc = sysfs_create_group(&ipl_kset->kobj,
						&ipl_ccw_attr_group_lpar);
		break;
	case IPL_TYPE_FCP:
	case IPL_TYPE_FCP_DUMP:
		rc = sysfs_create_group(&ipl_kset->kobj, &ipl_fcp_attr_group);
		break;
	default:
		rc = sysfs_create_group(&ipl_kset->kobj,
					&ipl_unknown_attr_group);
		break;
	}
out:
	if (rc)
		panic("ipl_init failed: rc = %i\n", rc);

	return 0;
}

static struct shutdown_action __refdata ipl_action = {
	.name	= SHUTDOWN_ACTION_IPL_STR,
	.fn	= ipl_run,
	.init	= ipl_init,
};

/*
 * reipl shutdown action: Reboot Linux on shutdown.
 */

/* VM IPL PARM attributes */
static ssize_t reipl_generic_vmparm_show(struct ipl_parameter_block *ipb,
					  char *page)
{
	char vmparm[DIAG308_VMPARM_SIZE + 1] = {};

	reipl_get_ascii_vmparm(vmparm, sizeof(vmparm), ipb);
	return sprintf(page, "%s\n", vmparm);
}

static ssize_t reipl_generic_vmparm_store(struct ipl_parameter_block *ipb,
					  size_t vmparm_max,
					  const char *buf, size_t len)
{
	int i, ip_len;

	/* ignore trailing newline */
	ip_len = len;
	if ((len > 0) && (buf[len - 1] == '\n'))
		ip_len--;

	if (ip_len > vmparm_max)
		return -EINVAL;

	/* parm is used to store kernel options, check for common chars */
	for (i = 0; i < ip_len; i++)
		if (!(isalnum(buf[i]) || isascii(buf[i]) || isprint(buf[i])))
			return -EINVAL;

	memset(ipb->ipl_info.ccw.vm_parm, 0, DIAG308_VMPARM_SIZE);
	ipb->ipl_info.ccw.vm_parm_len = ip_len;
	if (ip_len > 0) {
		ipb->ipl_info.ccw.vm_flags |= DIAG308_VM_FLAGS_VP_VALID;
		memcpy(ipb->ipl_info.ccw.vm_parm, buf, ip_len);
		ASCEBC(ipb->ipl_info.ccw.vm_parm, ip_len);
	} else {
		ipb->ipl_info.ccw.vm_flags &= ~DIAG308_VM_FLAGS_VP_VALID;
	}

	return len;
}

/* NSS wrapper */
static ssize_t reipl_nss_vmparm_show(struct kobject *kobj,
				     struct kobj_attribute *attr, char *page)
{
	return reipl_generic_vmparm_show(reipl_block_nss, page);
}

static ssize_t reipl_nss_vmparm_store(struct kobject *kobj,
				      struct kobj_attribute *attr,
				      const char *buf, size_t len)
{
	return reipl_generic_vmparm_store(reipl_block_nss, 56, buf, len);
}

/* CCW wrapper */
static ssize_t reipl_ccw_vmparm_show(struct kobject *kobj,
				     struct kobj_attribute *attr, char *page)
{
	return reipl_generic_vmparm_show(reipl_block_ccw, page);
}

static ssize_t reipl_ccw_vmparm_store(struct kobject *kobj,
				      struct kobj_attribute *attr,
				      const char *buf, size_t len)
{
	return reipl_generic_vmparm_store(reipl_block_ccw, 64, buf, len);
}

static struct kobj_attribute sys_reipl_nss_vmparm_attr =
	__ATTR(parm, S_IRUGO | S_IWUSR, reipl_nss_vmparm_show,
					reipl_nss_vmparm_store);
static struct kobj_attribute sys_reipl_ccw_vmparm_attr =
	__ATTR(parm, S_IRUGO | S_IWUSR, reipl_ccw_vmparm_show,
					reipl_ccw_vmparm_store);

/* FCP reipl device attributes */

static ssize_t reipl_fcp_scpdata_read(struct file *filp, struct kobject *kobj,
				      struct bin_attribute *attr,
				      char *buf, loff_t off, size_t count)
{
	size_t size = reipl_block_fcp->ipl_info.fcp.scp_data_len;
	void *scp_data = reipl_block_fcp->ipl_info.fcp.scp_data;

	return memory_read_from_buffer(buf, count, &off, scp_data, size);
}

static ssize_t reipl_fcp_scpdata_write(struct file *filp, struct kobject *kobj,
				       struct bin_attribute *attr,
				       char *buf, loff_t off, size_t count)
{
	size_t scpdata_len = count;
	size_t padding;


	if (off)
		return -EINVAL;

	memcpy(reipl_block_fcp->ipl_info.fcp.scp_data, buf, count);
	if (scpdata_len % 8) {
		padding = 8 - (scpdata_len % 8);
		memset(reipl_block_fcp->ipl_info.fcp.scp_data + scpdata_len,
		       0, padding);
		scpdata_len += padding;
	}

	reipl_block_fcp->ipl_info.fcp.scp_data_len = scpdata_len;
	reipl_block_fcp->hdr.len = IPL_PARM_BLK_FCP_LEN + scpdata_len;
	reipl_block_fcp->hdr.blk0_len = IPL_PARM_BLK0_FCP_LEN + scpdata_len;

	return count;
}
static struct bin_attribute sys_reipl_fcp_scp_data_attr =
	__BIN_ATTR(scp_data, (S_IRUGO | S_IWUSR), reipl_fcp_scpdata_read,
		   reipl_fcp_scpdata_write, DIAG308_SCPDATA_SIZE);

static struct bin_attribute *reipl_fcp_bin_attrs[] = {
	&sys_reipl_fcp_scp_data_attr,
	NULL,
};

DEFINE_IPL_ATTR_RW(reipl_fcp, wwpn, "0x%016llx\n", "%llx\n",
		   reipl_block_fcp->ipl_info.fcp.wwpn);
DEFINE_IPL_ATTR_RW(reipl_fcp, lun, "0x%016llx\n", "%llx\n",
		   reipl_block_fcp->ipl_info.fcp.lun);
DEFINE_IPL_ATTR_RW(reipl_fcp, bootprog, "%lld\n", "%lld\n",
		   reipl_block_fcp->ipl_info.fcp.bootprog);
DEFINE_IPL_ATTR_RW(reipl_fcp, br_lba, "%lld\n", "%lld\n",
		   reipl_block_fcp->ipl_info.fcp.br_lba);
DEFINE_IPL_ATTR_RW(reipl_fcp, device, "0.0.%04llx\n", "0.0.%llx\n",
		   reipl_block_fcp->ipl_info.fcp.devno);

static void reipl_get_ascii_loadparm(char *loadparm,
				     struct ipl_parameter_block *ibp)
{
	memcpy(loadparm, ibp->hdr.loadparm, LOADPARM_LEN);
	EBCASC(loadparm, LOADPARM_LEN);
	loadparm[LOADPARM_LEN] = 0;
	strim(loadparm);
}

static ssize_t reipl_generic_loadparm_show(struct ipl_parameter_block *ipb,
					   char *page)
{
	char buf[LOADPARM_LEN + 1];

	reipl_get_ascii_loadparm(buf, ipb);
	return sprintf(page, "%s\n", buf);
}

static ssize_t reipl_generic_loadparm_store(struct ipl_parameter_block *ipb,
					    const char *buf, size_t len)
{
	int i, lp_len;

	/* ignore trailing newline */
	lp_len = len;
	if ((len > 0) && (buf[len - 1] == '\n'))
		lp_len--;
	/* loadparm can have max 8 characters and must not start with a blank */
	if ((lp_len > LOADPARM_LEN) || ((lp_len > 0) && (buf[0] == ' ')))
		return -EINVAL;
	/* loadparm can only contain "a-z,A-Z,0-9,SP,." */
	for (i = 0; i < lp_len; i++) {
		if (isalpha(buf[i]) || isdigit(buf[i]) || (buf[i] == ' ') ||
		    (buf[i] == '.'))
			continue;
		return -EINVAL;
	}
	/* initialize loadparm with blanks */
	memset(ipb->hdr.loadparm, ' ', LOADPARM_LEN);
	/* copy and convert to ebcdic */
	memcpy(ipb->hdr.loadparm, buf, lp_len);
	ASCEBC(ipb->hdr.loadparm, LOADPARM_LEN);
	ipb->hdr.flags |= DIAG308_FLAGS_LP_VALID;
	return len;
}

/* FCP wrapper */
static ssize_t reipl_fcp_loadparm_show(struct kobject *kobj,
				       struct kobj_attribute *attr, char *page)
{
	return reipl_generic_loadparm_show(reipl_block_fcp, page);
}

static ssize_t reipl_fcp_loadparm_store(struct kobject *kobj,
					struct kobj_attribute *attr,
					const char *buf, size_t len)
{
	return reipl_generic_loadparm_store(reipl_block_fcp, buf, len);
}

static struct kobj_attribute sys_reipl_fcp_loadparm_attr =
	__ATTR(loadparm, S_IRUGO | S_IWUSR, reipl_fcp_loadparm_show,
					    reipl_fcp_loadparm_store);

static struct attribute *reipl_fcp_attrs[] = {
	&sys_reipl_fcp_device_attr.attr,
	&sys_reipl_fcp_wwpn_attr.attr,
	&sys_reipl_fcp_lun_attr.attr,
	&sys_reipl_fcp_bootprog_attr.attr,
	&sys_reipl_fcp_br_lba_attr.attr,
	&sys_reipl_fcp_loadparm_attr.attr,
	NULL,
};

static struct attribute_group reipl_fcp_attr_group = {
	.attrs = reipl_fcp_attrs,
	.bin_attrs = reipl_fcp_bin_attrs,
};

/* CCW reipl device attributes */
DEFINE_IPL_CCW_ATTR_RW(reipl_ccw, device, reipl_block_ccw->ipl_info.ccw);

/* NSS wrapper */
static ssize_t reipl_nss_loadparm_show(struct kobject *kobj,
				       struct kobj_attribute *attr, char *page)
{
	return reipl_generic_loadparm_show(reipl_block_nss, page);
}

static ssize_t reipl_nss_loadparm_store(struct kobject *kobj,
					struct kobj_attribute *attr,
					const char *buf, size_t len)
{
	return reipl_generic_loadparm_store(reipl_block_nss, buf, len);
}

/* CCW wrapper */
static ssize_t reipl_ccw_loadparm_show(struct kobject *kobj,
				       struct kobj_attribute *attr, char *page)
{
	return reipl_generic_loadparm_show(reipl_block_ccw, page);
}

static ssize_t reipl_ccw_loadparm_store(struct kobject *kobj,
					struct kobj_attribute *attr,
					const char *buf, size_t len)
{
	return reipl_generic_loadparm_store(reipl_block_ccw, buf, len);
}

static struct kobj_attribute sys_reipl_ccw_loadparm_attr =
	__ATTR(loadparm, S_IRUGO | S_IWUSR, reipl_ccw_loadparm_show,
					    reipl_ccw_loadparm_store);

static struct attribute *reipl_ccw_attrs_vm[] = {
	&sys_reipl_ccw_device_attr.attr,
	&sys_reipl_ccw_loadparm_attr.attr,
	&sys_reipl_ccw_vmparm_attr.attr,
	NULL,
};

static struct attribute *reipl_ccw_attrs_lpar[] = {
	&sys_reipl_ccw_device_attr.attr,
	&sys_reipl_ccw_loadparm_attr.attr,
	NULL,
};

static struct attribute_group reipl_ccw_attr_group_vm = {
	.name  = IPL_CCW_STR,
	.attrs = reipl_ccw_attrs_vm,
};

static struct attribute_group reipl_ccw_attr_group_lpar = {
	.name  = IPL_CCW_STR,
	.attrs = reipl_ccw_attrs_lpar,
};


/* NSS reipl device attributes */
static void reipl_get_ascii_nss_name(char *dst,
				     struct ipl_parameter_block *ipb)
{
	memcpy(dst, ipb->ipl_info.ccw.nss_name, NSS_NAME_SIZE);
	EBCASC(dst, NSS_NAME_SIZE);
	dst[NSS_NAME_SIZE] = 0;
}

static ssize_t reipl_nss_name_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *page)
{
	char nss_name[NSS_NAME_SIZE + 1] = {};

	reipl_get_ascii_nss_name(nss_name, reipl_block_nss);
	return sprintf(page, "%s\n", nss_name);
}

static ssize_t reipl_nss_name_store(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buf, size_t len)
{
	int nss_len;

	/* ignore trailing newline */
	nss_len = len;
	if ((len > 0) && (buf[len - 1] == '\n'))
		nss_len--;

	if (nss_len > NSS_NAME_SIZE)
		return -EINVAL;

	memset(reipl_block_nss->ipl_info.ccw.nss_name, 0x40, NSS_NAME_SIZE);
	if (nss_len > 0) {
		reipl_block_nss->ipl_info.ccw.vm_flags |=
			DIAG308_VM_FLAGS_NSS_VALID;
		memcpy(reipl_block_nss->ipl_info.ccw.nss_name, buf, nss_len);
		ASCEBC(reipl_block_nss->ipl_info.ccw.nss_name, nss_len);
		EBC_TOUPPER(reipl_block_nss->ipl_info.ccw.nss_name, nss_len);
	} else {
		reipl_block_nss->ipl_info.ccw.vm_flags &=
			~DIAG308_VM_FLAGS_NSS_VALID;
	}

	return len;
}

static struct kobj_attribute sys_reipl_nss_name_attr =
	__ATTR(name, S_IRUGO | S_IWUSR, reipl_nss_name_show,
					reipl_nss_name_store);

static struct kobj_attribute sys_reipl_nss_loadparm_attr =
	__ATTR(loadparm, S_IRUGO | S_IWUSR, reipl_nss_loadparm_show,
					    reipl_nss_loadparm_store);

static struct attribute *reipl_nss_attrs[] = {
	&sys_reipl_nss_name_attr.attr,
	&sys_reipl_nss_loadparm_attr.attr,
	&sys_reipl_nss_vmparm_attr.attr,
	NULL,
};

static struct attribute_group reipl_nss_attr_group = {
	.name  = IPL_NSS_STR,
	.attrs = reipl_nss_attrs,
};

void set_os_info_reipl_block(void)
{
	os_info_entry_add(OS_INFO_REIPL_BLOCK, reipl_block_actual,
			  reipl_block_actual->hdr.len);
}

/* reipl type */

static int reipl_set_type(enum ipl_type type)
{
	if (!(reipl_capabilities & type))
		return -EINVAL;

	switch(type) {
	case IPL_TYPE_CCW:
		reipl_block_actual = reipl_block_ccw;
		break;
	case IPL_TYPE_FCP:
		reipl_block_actual = reipl_block_fcp;
		break;
	case IPL_TYPE_NSS:
		reipl_block_actual = reipl_block_nss;
		break;
	default:
		break;
	}
	reipl_type = type;
	return 0;
}

static ssize_t reipl_type_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *page)
{
	return sprintf(page, "%s\n", ipl_type_str(reipl_type));
}

static ssize_t reipl_type_store(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t len)
{
	int rc = -EINVAL;

	if (strncmp(buf, IPL_CCW_STR, strlen(IPL_CCW_STR)) == 0)
		rc = reipl_set_type(IPL_TYPE_CCW);
	else if (strncmp(buf, IPL_FCP_STR, strlen(IPL_FCP_STR)) == 0)
		rc = reipl_set_type(IPL_TYPE_FCP);
	else if (strncmp(buf, IPL_NSS_STR, strlen(IPL_NSS_STR)) == 0)
		rc = reipl_set_type(IPL_TYPE_NSS);
	return (rc != 0) ? rc : len;
}

static struct kobj_attribute reipl_type_attr =
	__ATTR(reipl_type, 0644, reipl_type_show, reipl_type_store);

static struct kset *reipl_kset;
static struct kset *reipl_fcp_kset;

static void __reipl_run(void *unused)
{
	switch (reipl_type) {
	case IPL_TYPE_CCW:
		diag308(DIAG308_SET, reipl_block_ccw);
		diag308(DIAG308_LOAD_CLEAR, NULL);
		break;
	case IPL_TYPE_FCP:
		diag308(DIAG308_SET, reipl_block_fcp);
		diag308(DIAG308_LOAD_CLEAR, NULL);
		break;
	case IPL_TYPE_NSS:
		diag308(DIAG308_SET, reipl_block_nss);
		diag308(DIAG308_LOAD_CLEAR, NULL);
		break;
	case IPL_TYPE_UNKNOWN:
		diag308(DIAG308_LOAD_CLEAR, NULL);
		break;
	case IPL_TYPE_FCP_DUMP:
		break;
	}
	disabled_wait((unsigned long) __builtin_return_address(0));
}

static void reipl_run(struct shutdown_trigger *trigger)
{
	smp_call_ipl_cpu(__reipl_run, NULL);
}

static void reipl_block_ccw_init(struct ipl_parameter_block *ipb)
{
	ipb->hdr.len = IPL_PARM_BLK_CCW_LEN;
	ipb->hdr.version = IPL_PARM_BLOCK_VERSION;
	ipb->hdr.blk0_len = IPL_PARM_BLK0_CCW_LEN;
	ipb->hdr.pbt = DIAG308_IPL_TYPE_CCW;
}

static void reipl_block_ccw_fill_parms(struct ipl_parameter_block *ipb)
{
	/* LOADPARM */
	/* check if read scp info worked and set loadparm */
	if (sclp_ipl_info.is_valid)
		memcpy(ipb->hdr.loadparm, &sclp_ipl_info.loadparm, LOADPARM_LEN);
	else
		/* read scp info failed: set empty loadparm (EBCDIC blanks) */
		memset(ipb->hdr.loadparm, 0x40, LOADPARM_LEN);
	ipb->hdr.flags = DIAG308_FLAGS_LP_VALID;

	/* VM PARM */
	if (MACHINE_IS_VM && ipl_block_valid &&
	    (ipl_block.ipl_info.ccw.vm_flags & DIAG308_VM_FLAGS_VP_VALID)) {

		ipb->ipl_info.ccw.vm_flags |= DIAG308_VM_FLAGS_VP_VALID;
		ipb->ipl_info.ccw.vm_parm_len =
					ipl_block.ipl_info.ccw.vm_parm_len;
		memcpy(ipb->ipl_info.ccw.vm_parm,
		       ipl_block.ipl_info.ccw.vm_parm, DIAG308_VMPARM_SIZE);
	}
}

static int __init reipl_nss_init(void)
{
	int rc;

	if (!MACHINE_IS_VM)
		return 0;

	reipl_block_nss = (void *) get_zeroed_page(GFP_KERNEL);
	if (!reipl_block_nss)
		return -ENOMEM;

	rc = sysfs_create_group(&reipl_kset->kobj, &reipl_nss_attr_group);
	if (rc)
		return rc;

	reipl_block_ccw_init(reipl_block_nss);
	reipl_capabilities |= IPL_TYPE_NSS;
	return 0;
}

static int __init reipl_ccw_init(void)
{
	int rc;

	reipl_block_ccw = (void *) get_zeroed_page(GFP_KERNEL);
	if (!reipl_block_ccw)
		return -ENOMEM;

	rc = sysfs_create_group(&reipl_kset->kobj,
				MACHINE_IS_VM ? &reipl_ccw_attr_group_vm
					      : &reipl_ccw_attr_group_lpar);
	if (rc)
		return rc;

	reipl_block_ccw_init(reipl_block_ccw);
	if (ipl_info.type == IPL_TYPE_CCW) {
		reipl_block_ccw->ipl_info.ccw.ssid = ipl_block.ipl_info.ccw.ssid;
		reipl_block_ccw->ipl_info.ccw.devno = ipl_block.ipl_info.ccw.devno;
		reipl_block_ccw_fill_parms(reipl_block_ccw);
	}

	reipl_capabilities |= IPL_TYPE_CCW;
	return 0;
}

static int __init reipl_fcp_init(void)
{
	int rc;

	reipl_block_fcp = (void *) get_zeroed_page(GFP_KERNEL);
	if (!reipl_block_fcp)
		return -ENOMEM;

	/* sysfs: create fcp kset for mixing attr group and bin attrs */
	reipl_fcp_kset = kset_create_and_add(IPL_FCP_STR, NULL,
					     &reipl_kset->kobj);
	if (!reipl_fcp_kset) {
		free_page((unsigned long) reipl_block_fcp);
		return -ENOMEM;
	}

	rc = sysfs_create_group(&reipl_fcp_kset->kobj, &reipl_fcp_attr_group);
	if (rc) {
		kset_unregister(reipl_fcp_kset);
		free_page((unsigned long) reipl_block_fcp);
		return rc;
	}

	if (ipl_info.type == IPL_TYPE_FCP) {
		memcpy(reipl_block_fcp, &ipl_block, sizeof(ipl_block));
		/*
		 * Fix loadparm: There are systems where the (SCSI) LOADPARM
		 * is invalid in the SCSI IPL parameter block, so take it
		 * always from sclp_ipl_info.
		 */
		memcpy(reipl_block_fcp->hdr.loadparm, sclp_ipl_info.loadparm,
		       LOADPARM_LEN);
	} else {
		reipl_block_fcp->hdr.len = IPL_PARM_BLK_FCP_LEN;
		reipl_block_fcp->hdr.version = IPL_PARM_BLOCK_VERSION;
		reipl_block_fcp->hdr.blk0_len = IPL_PARM_BLK0_FCP_LEN;
		reipl_block_fcp->hdr.pbt = DIAG308_IPL_TYPE_FCP;
		reipl_block_fcp->ipl_info.fcp.opt = DIAG308_IPL_OPT_IPL;
	}
	reipl_capabilities |= IPL_TYPE_FCP;
	return 0;
}

static int __init reipl_type_init(void)
{
	enum ipl_type reipl_type = ipl_info.type;
	struct ipl_parameter_block *reipl_block;
	unsigned long size;

	reipl_block = os_info_old_entry(OS_INFO_REIPL_BLOCK, &size);
	if (!reipl_block)
		goto out;
	/*
	 * If we have an OS info reipl block, this will be used
	 */
	if (reipl_block->hdr.pbt == DIAG308_IPL_TYPE_FCP) {
		memcpy(reipl_block_fcp, reipl_block, size);
		reipl_type = IPL_TYPE_FCP;
	} else if (reipl_block->hdr.pbt == DIAG308_IPL_TYPE_CCW) {
		memcpy(reipl_block_ccw, reipl_block, size);
		reipl_type = IPL_TYPE_CCW;
	}
out:
	return reipl_set_type(reipl_type);
}

static int __init reipl_init(void)
{
	int rc;

	reipl_kset = kset_create_and_add("reipl", NULL, firmware_kobj);
	if (!reipl_kset)
		return -ENOMEM;
	rc = sysfs_create_file(&reipl_kset->kobj, &reipl_type_attr.attr);
	if (rc) {
		kset_unregister(reipl_kset);
		return rc;
	}
	rc = reipl_ccw_init();
	if (rc)
		return rc;
	rc = reipl_fcp_init();
	if (rc)
		return rc;
	rc = reipl_nss_init();
	if (rc)
		return rc;
	return reipl_type_init();
}

static struct shutdown_action __refdata reipl_action = {
	.name	= SHUTDOWN_ACTION_REIPL_STR,
	.fn	= reipl_run,
	.init	= reipl_init,
};

/*
 * dump shutdown action: Dump Linux on shutdown.
 */

/* FCP dump device attributes */

DEFINE_IPL_ATTR_RW(dump_fcp, wwpn, "0x%016llx\n", "%llx\n",
		   dump_block_fcp->ipl_info.fcp.wwpn);
DEFINE_IPL_ATTR_RW(dump_fcp, lun, "0x%016llx\n", "%llx\n",
		   dump_block_fcp->ipl_info.fcp.lun);
DEFINE_IPL_ATTR_RW(dump_fcp, bootprog, "%lld\n", "%lld\n",
		   dump_block_fcp->ipl_info.fcp.bootprog);
DEFINE_IPL_ATTR_RW(dump_fcp, br_lba, "%lld\n", "%lld\n",
		   dump_block_fcp->ipl_info.fcp.br_lba);
DEFINE_IPL_ATTR_RW(dump_fcp, device, "0.0.%04llx\n", "0.0.%llx\n",
		   dump_block_fcp->ipl_info.fcp.devno);

static struct attribute *dump_fcp_attrs[] = {
	&sys_dump_fcp_device_attr.attr,
	&sys_dump_fcp_wwpn_attr.attr,
	&sys_dump_fcp_lun_attr.attr,
	&sys_dump_fcp_bootprog_attr.attr,
	&sys_dump_fcp_br_lba_attr.attr,
	NULL,
};

static struct attribute_group dump_fcp_attr_group = {
	.name  = IPL_FCP_STR,
	.attrs = dump_fcp_attrs,
};

/* CCW dump device attributes */
DEFINE_IPL_CCW_ATTR_RW(dump_ccw, device, dump_block_ccw->ipl_info.ccw);

static struct attribute *dump_ccw_attrs[] = {
	&sys_dump_ccw_device_attr.attr,
	NULL,
};

static struct attribute_group dump_ccw_attr_group = {
	.name  = IPL_CCW_STR,
	.attrs = dump_ccw_attrs,
};

/* dump type */

static int dump_set_type(enum dump_type type)
{
	if (!(dump_capabilities & type))
		return -EINVAL;
	dump_type = type;
	return 0;
}

static ssize_t dump_type_show(struct kobject *kobj,
			      struct kobj_attribute *attr, char *page)
{
	return sprintf(page, "%s\n", dump_type_str(dump_type));
}

static ssize_t dump_type_store(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       const char *buf, size_t len)
{
	int rc = -EINVAL;

	if (strncmp(buf, DUMP_NONE_STR, strlen(DUMP_NONE_STR)) == 0)
		rc = dump_set_type(DUMP_TYPE_NONE);
	else if (strncmp(buf, DUMP_CCW_STR, strlen(DUMP_CCW_STR)) == 0)
		rc = dump_set_type(DUMP_TYPE_CCW);
	else if (strncmp(buf, DUMP_FCP_STR, strlen(DUMP_FCP_STR)) == 0)
		rc = dump_set_type(DUMP_TYPE_FCP);
	return (rc != 0) ? rc : len;
}

static struct kobj_attribute dump_type_attr =
	__ATTR(dump_type, 0644, dump_type_show, dump_type_store);

static struct kset *dump_kset;

static void diag308_dump(void *dump_block)
{
	diag308(DIAG308_SET, dump_block);
	while (1) {
		if (diag308(DIAG308_LOAD_NORMAL_DUMP, NULL) != 0x302)
			break;
		udelay_simple(USEC_PER_SEC);
	}
}

static void __dump_run(void *unused)
{
	switch (dump_type) {
	case DUMP_TYPE_CCW:
		diag308_dump(dump_block_ccw);
		break;
	case DUMP_TYPE_FCP:
		diag308_dump(dump_block_fcp);
		break;
	default:
		break;
	}
}

static void dump_run(struct shutdown_trigger *trigger)
{
	if (dump_type == DUMP_TYPE_NONE)
		return;
	smp_send_stop();
	smp_call_ipl_cpu(__dump_run, NULL);
}

static int __init dump_ccw_init(void)
{
	int rc;

	dump_block_ccw = (void *) get_zeroed_page(GFP_KERNEL);
	if (!dump_block_ccw)
		return -ENOMEM;
	rc = sysfs_create_group(&dump_kset->kobj, &dump_ccw_attr_group);
	if (rc) {
		free_page((unsigned long)dump_block_ccw);
		return rc;
	}
	dump_block_ccw->hdr.len = IPL_PARM_BLK_CCW_LEN;
	dump_block_ccw->hdr.version = IPL_PARM_BLOCK_VERSION;
	dump_block_ccw->hdr.blk0_len = IPL_PARM_BLK0_CCW_LEN;
	dump_block_ccw->hdr.pbt = DIAG308_IPL_TYPE_CCW;
	dump_capabilities |= DUMP_TYPE_CCW;
	return 0;
}

static int __init dump_fcp_init(void)
{
	int rc;

	if (!sclp_ipl_info.has_dump)
		return 0; /* LDIPL DUMP is not installed */
	dump_block_fcp = (void *) get_zeroed_page(GFP_KERNEL);
	if (!dump_block_fcp)
		return -ENOMEM;
	rc = sysfs_create_group(&dump_kset->kobj, &dump_fcp_attr_group);
	if (rc) {
		free_page((unsigned long)dump_block_fcp);
		return rc;
	}
	dump_block_fcp->hdr.len = IPL_PARM_BLK_FCP_LEN;
	dump_block_fcp->hdr.version = IPL_PARM_BLOCK_VERSION;
	dump_block_fcp->hdr.blk0_len = IPL_PARM_BLK0_FCP_LEN;
	dump_block_fcp->hdr.pbt = DIAG308_IPL_TYPE_FCP;
	dump_block_fcp->ipl_info.fcp.opt = DIAG308_IPL_OPT_DUMP;
	dump_capabilities |= DUMP_TYPE_FCP;
	return 0;
}

static int __init dump_init(void)
{
	int rc;

	dump_kset = kset_create_and_add("dump", NULL, firmware_kobj);
	if (!dump_kset)
		return -ENOMEM;
	rc = sysfs_create_file(&dump_kset->kobj, &dump_type_attr.attr);
	if (rc) {
		kset_unregister(dump_kset);
		return rc;
	}
	rc = dump_ccw_init();
	if (rc)
		return rc;
	rc = dump_fcp_init();
	if (rc)
		return rc;
	dump_set_type(DUMP_TYPE_NONE);
	return 0;
}

static struct shutdown_action __refdata dump_action = {
	.name	= SHUTDOWN_ACTION_DUMP_STR,
	.fn	= dump_run,
	.init	= dump_init,
};

static void dump_reipl_run(struct shutdown_trigger *trigger)
{
	unsigned long ipib = (unsigned long) reipl_block_actual;
	unsigned int csum;

	csum = (__force unsigned int)
	       csum_partial(reipl_block_actual, reipl_block_actual->hdr.len, 0);
	mem_assign_absolute(S390_lowcore.ipib, ipib);
	mem_assign_absolute(S390_lowcore.ipib_checksum, csum);
	dump_run(trigger);
}

static struct shutdown_action __refdata dump_reipl_action = {
	.name	= SHUTDOWN_ACTION_DUMP_REIPL_STR,
	.fn	= dump_reipl_run,
};

/*
 * vmcmd shutdown action: Trigger vm command on shutdown.
 */

static char vmcmd_on_reboot[128];
static char vmcmd_on_panic[128];
static char vmcmd_on_halt[128];
static char vmcmd_on_poff[128];
static char vmcmd_on_restart[128];

DEFINE_IPL_ATTR_STR_RW(vmcmd, on_reboot, "%s\n", "%s\n", vmcmd_on_reboot);
DEFINE_IPL_ATTR_STR_RW(vmcmd, on_panic, "%s\n", "%s\n", vmcmd_on_panic);
DEFINE_IPL_ATTR_STR_RW(vmcmd, on_halt, "%s\n", "%s\n", vmcmd_on_halt);
DEFINE_IPL_ATTR_STR_RW(vmcmd, on_poff, "%s\n", "%s\n", vmcmd_on_poff);
DEFINE_IPL_ATTR_STR_RW(vmcmd, on_restart, "%s\n", "%s\n", vmcmd_on_restart);

static struct attribute *vmcmd_attrs[] = {
	&sys_vmcmd_on_reboot_attr.attr,
	&sys_vmcmd_on_panic_attr.attr,
	&sys_vmcmd_on_halt_attr.attr,
	&sys_vmcmd_on_poff_attr.attr,
	&sys_vmcmd_on_restart_attr.attr,
	NULL,
};

static struct attribute_group vmcmd_attr_group = {
	.attrs = vmcmd_attrs,
};

static struct kset *vmcmd_kset;

static void vmcmd_run(struct shutdown_trigger *trigger)
{
	char *cmd;

	if (strcmp(trigger->name, ON_REIPL_STR) == 0)
		cmd = vmcmd_on_reboot;
	else if (strcmp(trigger->name, ON_PANIC_STR) == 0)
		cmd = vmcmd_on_panic;
	else if (strcmp(trigger->name, ON_HALT_STR) == 0)
		cmd = vmcmd_on_halt;
	else if (strcmp(trigger->name, ON_POFF_STR) == 0)
		cmd = vmcmd_on_poff;
	else if (strcmp(trigger->name, ON_RESTART_STR) == 0)
		cmd = vmcmd_on_restart;
	else
		return;

	if (strlen(cmd) == 0)
		return;
	__cpcmd(cmd, NULL, 0, NULL);
}

static int vmcmd_init(void)
{
	if (!MACHINE_IS_VM)
		return -EOPNOTSUPP;
	vmcmd_kset = kset_create_and_add("vmcmd", NULL, firmware_kobj);
	if (!vmcmd_kset)
		return -ENOMEM;
	return sysfs_create_group(&vmcmd_kset->kobj, &vmcmd_attr_group);
}

static struct shutdown_action vmcmd_action = {SHUTDOWN_ACTION_VMCMD_STR,
					      vmcmd_run, vmcmd_init};

/*
 * stop shutdown action: Stop Linux on shutdown.
 */

static void stop_run(struct shutdown_trigger *trigger)
{
	if (strcmp(trigger->name, ON_PANIC_STR) == 0 ||
	    strcmp(trigger->name, ON_RESTART_STR) == 0)
		disabled_wait((unsigned long) __builtin_return_address(0));
	smp_stop_cpu();
}

static struct shutdown_action stop_action = {SHUTDOWN_ACTION_STOP_STR,
					     stop_run, NULL};

/* action list */

static struct shutdown_action *shutdown_actions_list[] = {
	&ipl_action, &reipl_action, &dump_reipl_action, &dump_action,
	&vmcmd_action, &stop_action};
#define SHUTDOWN_ACTIONS_COUNT (sizeof(shutdown_actions_list) / sizeof(void *))

/*
 * Trigger section
 */

static struct kset *shutdown_actions_kset;

static int set_trigger(const char *buf, struct shutdown_trigger *trigger,
		       size_t len)
{
	int i;

	for (i = 0; i < SHUTDOWN_ACTIONS_COUNT; i++) {
		if (sysfs_streq(buf, shutdown_actions_list[i]->name)) {
			if (shutdown_actions_list[i]->init_rc) {
				return shutdown_actions_list[i]->init_rc;
			} else {
				trigger->action = shutdown_actions_list[i];
				return len;
			}
		}
	}
	return -EINVAL;
}

/* on reipl */

static struct shutdown_trigger on_reboot_trigger = {ON_REIPL_STR,
						    &reipl_action};

static ssize_t on_reboot_show(struct kobject *kobj,
			      struct kobj_attribute *attr, char *page)
{
	return sprintf(page, "%s\n", on_reboot_trigger.action->name);
}

static ssize_t on_reboot_store(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       const char *buf, size_t len)
{
	return set_trigger(buf, &on_reboot_trigger, len);
}
static struct kobj_attribute on_reboot_attr = __ATTR_RW(on_reboot);

static void do_machine_restart(char *__unused)
{
	smp_send_stop();
	on_reboot_trigger.action->fn(&on_reboot_trigger);
	reipl_run(NULL);
}
void (*_machine_restart)(char *command) = do_machine_restart;

/* on panic */

static struct shutdown_trigger on_panic_trigger = {ON_PANIC_STR, &stop_action};

static ssize_t on_panic_show(struct kobject *kobj,
			     struct kobj_attribute *attr, char *page)
{
	return sprintf(page, "%s\n", on_panic_trigger.action->name);
}

static ssize_t on_panic_store(struct kobject *kobj,
			      struct kobj_attribute *attr,
			      const char *buf, size_t len)
{
	return set_trigger(buf, &on_panic_trigger, len);
}
static struct kobj_attribute on_panic_attr = __ATTR_RW(on_panic);

static void do_panic(void)
{
	lgr_info_log();
	on_panic_trigger.action->fn(&on_panic_trigger);
	stop_run(&on_panic_trigger);
}

/* on restart */

static struct shutdown_trigger on_restart_trigger = {ON_RESTART_STR,
	&stop_action};

static ssize_t on_restart_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *page)
{
	return sprintf(page, "%s\n", on_restart_trigger.action->name);
}

static ssize_t on_restart_store(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t len)
{
	return set_trigger(buf, &on_restart_trigger, len);
}
static struct kobj_attribute on_restart_attr = __ATTR_RW(on_restart);

static void __do_restart(void *ignore)
{
	__arch_local_irq_stosm(0x04); /* enable DAT */
	smp_send_stop();
#ifdef CONFIG_CRASH_DUMP
	crash_kexec(NULL);
#endif
	on_restart_trigger.action->fn(&on_restart_trigger);
	stop_run(&on_restart_trigger);
}

void do_restart(void)
{
	tracing_off();
	debug_locks_off();
	lgr_info_log();
	smp_call_online_cpu(__do_restart, NULL);
}

/* on halt */

static struct shutdown_trigger on_halt_trigger = {ON_HALT_STR, &stop_action};

static ssize_t on_halt_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *page)
{
	return sprintf(page, "%s\n", on_halt_trigger.action->name);
}

static ssize_t on_halt_store(struct kobject *kobj,
			     struct kobj_attribute *attr,
			     const char *buf, size_t len)
{
	return set_trigger(buf, &on_halt_trigger, len);
}
static struct kobj_attribute on_halt_attr = __ATTR_RW(on_halt);

static void do_machine_halt(void)
{
	smp_send_stop();
	on_halt_trigger.action->fn(&on_halt_trigger);
	stop_run(&on_halt_trigger);
}
void (*_machine_halt)(void) = do_machine_halt;

/* on power off */

static struct shutdown_trigger on_poff_trigger = {ON_POFF_STR, &stop_action};

static ssize_t on_poff_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *page)
{
	return sprintf(page, "%s\n", on_poff_trigger.action->name);
}

static ssize_t on_poff_store(struct kobject *kobj,
			     struct kobj_attribute *attr,
			     const char *buf, size_t len)
{
	return set_trigger(buf, &on_poff_trigger, len);
}
static struct kobj_attribute on_poff_attr = __ATTR_RW(on_poff);

static void do_machine_power_off(void)
{
	smp_send_stop();
	on_poff_trigger.action->fn(&on_poff_trigger);
	stop_run(&on_poff_trigger);
}
void (*_machine_power_off)(void) = do_machine_power_off;

static struct attribute *shutdown_action_attrs[] = {
	&on_restart_attr.attr,
	&on_reboot_attr.attr,
	&on_panic_attr.attr,
	&on_halt_attr.attr,
	&on_poff_attr.attr,
	NULL,
};

static struct attribute_group shutdown_action_attr_group = {
	.attrs = shutdown_action_attrs,
};

static void __init shutdown_triggers_init(void)
{
	shutdown_actions_kset = kset_create_and_add("shutdown_actions", NULL,
						    firmware_kobj);
	if (!shutdown_actions_kset)
		goto fail;
	if (sysfs_create_group(&shutdown_actions_kset->kobj,
			       &shutdown_action_attr_group))
		goto fail;
	return;
fail:
	panic("shutdown_triggers_init failed\n");
}

static void __init shutdown_actions_init(void)
{
	int i;

	for (i = 0; i < SHUTDOWN_ACTIONS_COUNT; i++) {
		if (!shutdown_actions_list[i]->init)
			continue;
		shutdown_actions_list[i]->init_rc =
			shutdown_actions_list[i]->init();
	}
}

static int __init s390_ipl_init(void)
{
	char str[8] = {0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40};

	sclp_early_get_ipl_info(&sclp_ipl_info);
	/*
	 * Fix loadparm: There are systems where the (SCSI) LOADPARM
	 * returned by read SCP info is invalid (contains EBCDIC blanks)
	 * when the system has been booted via diag308. In that case we use
	 * the value from diag308, if available.
	 *
	 * There are also systems where diag308 store does not work in
	 * case the system is booted from HMC. Fortunately in this case
	 * READ SCP info provides the correct value.
	 */
	if (memcmp(sclp_ipl_info.loadparm, str, sizeof(str)) == 0 && ipl_block_valid)
		memcpy(sclp_ipl_info.loadparm, ipl_block.hdr.loadparm, LOADPARM_LEN);
	shutdown_actions_init();
	shutdown_triggers_init();
	return 0;
}

__initcall(s390_ipl_init);

static void __init strncpy_skip_quote(char *dst, char *src, int n)
{
	int sx, dx;

	dx = 0;
	for (sx = 0; src[sx] != 0; sx++) {
		if (src[sx] == '"')
			continue;
		dst[dx++] = src[sx];
		if (dx >= n)
			break;
	}
}

static int __init vmcmd_on_reboot_setup(char *str)
{
	if (!MACHINE_IS_VM)
		return 1;
	strncpy_skip_quote(vmcmd_on_reboot, str, 127);
	vmcmd_on_reboot[127] = 0;
	on_reboot_trigger.action = &vmcmd_action;
	return 1;
}
__setup("vmreboot=", vmcmd_on_reboot_setup);

static int __init vmcmd_on_panic_setup(char *str)
{
	if (!MACHINE_IS_VM)
		return 1;
	strncpy_skip_quote(vmcmd_on_panic, str, 127);
	vmcmd_on_panic[127] = 0;
	on_panic_trigger.action = &vmcmd_action;
	return 1;
}
__setup("vmpanic=", vmcmd_on_panic_setup);

static int __init vmcmd_on_halt_setup(char *str)
{
	if (!MACHINE_IS_VM)
		return 1;
	strncpy_skip_quote(vmcmd_on_halt, str, 127);
	vmcmd_on_halt[127] = 0;
	on_halt_trigger.action = &vmcmd_action;
	return 1;
}
__setup("vmhalt=", vmcmd_on_halt_setup);

static int __init vmcmd_on_poff_setup(char *str)
{
	if (!MACHINE_IS_VM)
		return 1;
	strncpy_skip_quote(vmcmd_on_poff, str, 127);
	vmcmd_on_poff[127] = 0;
	on_poff_trigger.action = &vmcmd_action;
	return 1;
}
__setup("vmpoff=", vmcmd_on_poff_setup);

static int on_panic_notify(struct notifier_block *self,
			   unsigned long event, void *data)
{
	do_panic();
	return NOTIFY_OK;
}

static struct notifier_block on_panic_nb = {
	.notifier_call = on_panic_notify,
	.priority = INT_MIN,
};

void __init setup_ipl(void)
{
	BUILD_BUG_ON(sizeof(struct ipl_parameter_block) != PAGE_SIZE);

	ipl_info.type = get_ipl_type();
	switch (ipl_info.type) {
	case IPL_TYPE_CCW:
		ipl_info.data.ccw.dev_id.ssid = ipl_block.ipl_info.ccw.ssid;
		ipl_info.data.ccw.dev_id.devno = ipl_block.ipl_info.ccw.devno;
		break;
	case IPL_TYPE_FCP:
	case IPL_TYPE_FCP_DUMP:
		ipl_info.data.fcp.dev_id.ssid = 0;
		ipl_info.data.fcp.dev_id.devno = ipl_block.ipl_info.fcp.devno;
		ipl_info.data.fcp.wwpn = ipl_block.ipl_info.fcp.wwpn;
		ipl_info.data.fcp.lun = ipl_block.ipl_info.fcp.lun;
		break;
	case IPL_TYPE_NSS:
	case IPL_TYPE_UNKNOWN:
		/* We have no info to copy */
		break;
	}
	atomic_notifier_chain_register(&panic_notifier_list, &on_panic_nb);
}

void __init ipl_store_parameters(void)
{
	int rc;

	rc = diag308(DIAG308_STORE, &ipl_block);
	if (rc == DIAG308_RC_OK && ipl_block.hdr.version <= IPL_MAX_SUPPORTED_VERSION)
		ipl_block_valid = 1;
}

void s390_reset_system(void)
{
	/* Disable prefixing */
	set_prefix(0);

	/* Disable lowcore protection */
	__ctl_clear_bit(0, 28);
	diag308_reset();
}
