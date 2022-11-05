/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright(c) 2020-2021 Intel Corporation. */
#ifndef __CXL_MEM_H__
#define __CXL_MEM_H__
#include <uapi/linux/cxl_mem.h>
#include <linux/cdev.h>
#include "cxl.h"

/* CXL 2.0 8.2.8.5.1.1 Memory Device Status Register */
#define CXLMDEV_STATUS_OFFSET 0x0
#define   CXLMDEV_DEV_FATAL BIT(0)
#define   CXLMDEV_FW_HALT BIT(1)
#define   CXLMDEV_STATUS_MEDIA_STATUS_MASK GENMASK(3, 2)
#define     CXLMDEV_MS_NOT_READY 0
#define     CXLMDEV_MS_READY 1
#define     CXLMDEV_MS_ERROR 2
#define     CXLMDEV_MS_DISABLED 3
#define CXLMDEV_READY(status)                                                  \
	(FIELD_GET(CXLMDEV_STATUS_MEDIA_STATUS_MASK, status) ==                \
	 CXLMDEV_MS_READY)
#define   CXLMDEV_MBOX_IF_READY BIT(4)
#define   CXLMDEV_RESET_NEEDED_MASK GENMASK(7, 5)
#define     CXLMDEV_RESET_NEEDED_NOT 0
#define     CXLMDEV_RESET_NEEDED_COLD 1
#define     CXLMDEV_RESET_NEEDED_WARM 2
#define     CXLMDEV_RESET_NEEDED_HOT 3
#define     CXLMDEV_RESET_NEEDED_CXL 4
#define CXLMDEV_RESET_NEEDED(status)                                           \
	(FIELD_GET(CXLMDEV_RESET_NEEDED_MASK, status) !=                       \
	 CXLMDEV_RESET_NEEDED_NOT)

/**
 * struct cxl_memdev - CXL bus object representing a Type-3 Memory Device
 * @dev: driver core device object
 * @cdev: char dev core object for ioctl operations
 * @cxlds: The device state backing this device
 * @detach_work: active memdev lost a port in its ancestry
 * @id: id number of this memdev instance.
 */
struct cxl_memdev {
	struct device dev;
	struct cdev cdev;
	struct cxl_dev_state *cxlds;
	struct work_struct detach_work;
	int id;
};

static inline struct cxl_memdev *to_cxl_memdev(struct device *dev)
{
	return container_of(dev, struct cxl_memdev, dev);
}

static inline struct cxl_port *cxled_to_port(struct cxl_endpoint_decoder *cxled)
{
	return to_cxl_port(cxled->cxld.dev.parent);
}

static inline struct cxl_port *cxlrd_to_port(struct cxl_root_decoder *cxlrd)
{
	return to_cxl_port(cxlrd->cxlsd.cxld.dev.parent);
}

static inline struct cxl_memdev *
cxled_to_memdev(struct cxl_endpoint_decoder *cxled)
{
	struct cxl_port *port = to_cxl_port(cxled->cxld.dev.parent);

	return to_cxl_memdev(port->uport);
}

bool is_cxl_memdev(struct device *dev);
static inline bool is_cxl_endpoint(struct cxl_port *port)
{
	return is_cxl_memdev(port->uport);
}

struct cxl_memdev *devm_cxl_add_memdev(struct cxl_dev_state *cxlds);

/**
 * struct cxl_mbox_cmd - A command to be submitted to hardware.
 * @opcode: (input) The command set and command submitted to hardware.
 * @payload_in: (input) Pointer to the input payload.
 * @payload_out: (output) Pointer to the output payload. Must be allocated by
 *		 the caller.
 * @size_in: (input) Number of bytes to load from @payload_in.
 * @size_out: (input) Max number of bytes loaded into @payload_out.
 *            (output) Number of bytes generated by the device. For fixed size
 *            outputs commands this is always expected to be deterministic. For
 *            variable sized output commands, it tells the exact number of bytes
 *            written.
 * @return_code: (output) Error code returned from hardware.
 *
 * This is the primary mechanism used to send commands to the hardware.
 * All the fields except @payload_* correspond exactly to the fields described in
 * Command Register section of the CXL 2.0 8.2.8.4.5. @payload_in and
 * @payload_out are written to, and read from the Command Payload Registers
 * defined in CXL 2.0 8.2.8.4.8.
 */
struct cxl_mbox_cmd {
	u16 opcode;
	void *payload_in;
	void *payload_out;
	size_t size_in;
	size_t size_out;
	u16 return_code;
};

/*
 * Per CXL 2.0 Section 8.2.8.4.5.1
 */
#define CMD_CMD_RC_TABLE							\
	C(SUCCESS, 0, NULL),							\
	C(BACKGROUND, -ENXIO, "background cmd started successfully"),           \
	C(INPUT, -ENXIO, "cmd input was invalid"),				\
	C(UNSUPPORTED, -ENXIO, "cmd is not supported"),				\
	C(INTERNAL, -ENXIO, "internal device error"),				\
	C(RETRY, -ENXIO, "temporary error, retry once"),			\
	C(BUSY, -ENXIO, "ongoing background operation"),			\
	C(MEDIADISABLED, -ENXIO, "media access is disabled"),			\
	C(FWINPROGRESS, -ENXIO,	"one FW package can be transferred at a time"), \
	C(FWOOO, -ENXIO, "FW package content was transferred out of order"),    \
	C(FWAUTH, -ENXIO, "FW package authentication failed"),			\
	C(FWSLOT, -ENXIO, "FW slot is not supported for requested operation"),  \
	C(FWROLLBACK, -ENXIO, "rolled back to the previous active FW"),         \
	C(FWRESET, -ENXIO, "FW failed to activate, needs cold reset"),		\
	C(HANDLE, -ENXIO, "one or more Event Record Handles were invalid"),     \
	C(PADDR, -ENXIO, "physical address specified is invalid"),		\
	C(POISONLMT, -ENXIO, "poison injection limit has been reached"),        \
	C(MEDIAFAILURE, -ENXIO, "permanent issue with the media"),		\
	C(ABORT, -ENXIO, "background cmd was aborted by device"),               \
	C(SECURITY, -ENXIO, "not valid in the current security state"),         \
	C(PASSPHRASE, -ENXIO, "phrase doesn't match current set passphrase"),   \
	C(MBUNSUPPORTED, -ENXIO, "unsupported on the mailbox it was issued on"),\
	C(PAYLOADLEN, -ENXIO, "invalid payload length")

#undef C
#define C(a, b, c) CXL_MBOX_CMD_RC_##a
enum  { CMD_CMD_RC_TABLE };
#undef C
#define C(a, b, c) { b, c }
struct cxl_mbox_cmd_rc {
	int err;
	const char *desc;
};

static const
struct cxl_mbox_cmd_rc cxl_mbox_cmd_rctable[] ={ CMD_CMD_RC_TABLE };
#undef C

static inline const char *cxl_mbox_cmd_rc2str(struct cxl_mbox_cmd *mbox_cmd)
{
	return cxl_mbox_cmd_rctable[mbox_cmd->return_code].desc;
}

static inline int cxl_mbox_cmd_rc2errno(struct cxl_mbox_cmd *mbox_cmd)
{
	return cxl_mbox_cmd_rctable[mbox_cmd->return_code].err;
}

/*
 * CXL 2.0 - Memory capacity multiplier
 * See Section 8.2.9.5
 *
 * Volatile, Persistent, and Partition capacities are specified to be in
 * multiples of 256MB - define a multiplier to convert to/from bytes.
 */
#define CXL_CAPACITY_MULTIPLIER SZ_256M

/**
 * struct cxl_endpoint_dvsec_info - Cached DVSEC info
 * @mem_enabled: cached value of mem_enabled in the DVSEC, PCIE_DEVICE
 * @ranges: Number of active HDM ranges this device uses.
 * @dvsec_range: cached attributes of the ranges in the DVSEC, PCIE_DEVICE
 */
struct cxl_endpoint_dvsec_info {
	bool mem_enabled;
	int ranges;
	struct range dvsec_range[2];
};

/**
 * struct cxl_dev_state - The driver device state
 *
 * cxl_dev_state represents the CXL driver/device state.  It provides an
 * interface to mailbox commands as well as some cached data about the device.
 * Currently only memory devices are represented.
 *
 * @dev: The device associated with this CXL state
 * @regs: Parsed register blocks
 * @cxl_dvsec: Offset to the PCIe device DVSEC
 * @payload_size: Size of space for payload
 *                (CXL 2.0 8.2.8.4.3 Mailbox Capabilities Register)
 * @lsa_size: Size of Label Storage Area
 *                (CXL 2.0 8.2.9.5.1.1 Identify Memory Device)
 * @mbox_mutex: Mutex to synchronize mailbox access.
 * @firmware_version: Firmware version for the memory device.
 * @enabled_cmds: Hardware commands found enabled in CEL.
 * @exclusive_cmds: Commands that are kernel-internal only
 * @dpa_res: Overall DPA resource tree for the device
 * @pmem_res: Active Persistent memory capacity configuration
 * @ram_res: Active Volatile memory capacity configuration
 * @total_bytes: sum of all possible capacities
 * @volatile_only_bytes: hard volatile capacity
 * @persistent_only_bytes: hard persistent capacity
 * @partition_align_bytes: alignment size for partition-able capacity
 * @active_volatile_bytes: sum of hard + soft volatile
 * @active_persistent_bytes: sum of hard + soft persistent
 * @next_volatile_bytes: volatile capacity change pending device reset
 * @next_persistent_bytes: persistent capacity change pending device reset
 * @component_reg_phys: register base of component registers
 * @info: Cached DVSEC information about the device.
 * @serial: PCIe Device Serial Number
 * @doe_mbs: PCI DOE mailbox array
 * @mbox_send: @dev specific transport for transmitting mailbox commands
 *
 * See section 8.2.9.5.2 Capacity Configuration and Label Storage for
 * details on capacity parameters.
 */
struct cxl_dev_state {
	struct device *dev;

	struct cxl_regs regs;
	int cxl_dvsec;

	size_t payload_size;
	size_t lsa_size;
	struct mutex mbox_mutex; /* Protects device mailbox and firmware */
	char firmware_version[0x10];
	DECLARE_BITMAP(enabled_cmds, CXL_MEM_COMMAND_ID_MAX);
	DECLARE_BITMAP(exclusive_cmds, CXL_MEM_COMMAND_ID_MAX);

	struct resource dpa_res;
	struct resource pmem_res;
	struct resource ram_res;
	u64 total_bytes;
	u64 volatile_only_bytes;
	u64 persistent_only_bytes;
	u64 partition_align_bytes;

	u64 active_volatile_bytes;
	u64 active_persistent_bytes;
	u64 next_volatile_bytes;
	u64 next_persistent_bytes;

	resource_size_t component_reg_phys;
	u64 serial;

	struct xarray doe_mbs;

	int (*mbox_send)(struct cxl_dev_state *cxlds, struct cxl_mbox_cmd *cmd);
};

enum cxl_opcode {
	CXL_MBOX_OP_INVALID		= 0x0000,
	CXL_MBOX_OP_RAW			= CXL_MBOX_OP_INVALID,
	CXL_MBOX_OP_GET_FW_INFO		= 0x0200,
	CXL_MBOX_OP_ACTIVATE_FW		= 0x0202,
	CXL_MBOX_OP_GET_SUPPORTED_LOGS	= 0x0400,
	CXL_MBOX_OP_GET_LOG		= 0x0401,
	CXL_MBOX_OP_IDENTIFY		= 0x4000,
	CXL_MBOX_OP_GET_PARTITION_INFO	= 0x4100,
	CXL_MBOX_OP_SET_PARTITION_INFO	= 0x4101,
	CXL_MBOX_OP_GET_LSA		= 0x4102,
	CXL_MBOX_OP_SET_LSA		= 0x4103,
	CXL_MBOX_OP_GET_HEALTH_INFO	= 0x4200,
	CXL_MBOX_OP_GET_ALERT_CONFIG	= 0x4201,
	CXL_MBOX_OP_SET_ALERT_CONFIG	= 0x4202,
	CXL_MBOX_OP_GET_SHUTDOWN_STATE	= 0x4203,
	CXL_MBOX_OP_SET_SHUTDOWN_STATE	= 0x4204,
	CXL_MBOX_OP_GET_POISON		= 0x4300,
	CXL_MBOX_OP_INJECT_POISON	= 0x4301,
	CXL_MBOX_OP_CLEAR_POISON	= 0x4302,
	CXL_MBOX_OP_GET_SCAN_MEDIA_CAPS	= 0x4303,
	CXL_MBOX_OP_SCAN_MEDIA		= 0x4304,
	CXL_MBOX_OP_GET_SCAN_MEDIA	= 0x4305,
	CXL_MBOX_OP_MAX			= 0x10000
};

#define DEFINE_CXL_CEL_UUID                                                    \
	UUID_INIT(0xda9c0b5, 0xbf41, 0x4b78, 0x8f, 0x79, 0x96, 0xb1, 0x62,     \
		  0x3b, 0x3f, 0x17)

#define DEFINE_CXL_VENDOR_DEBUG_UUID                                           \
	UUID_INIT(0xe1819d9, 0x11a9, 0x400c, 0x81, 0x1f, 0xd6, 0x07, 0x19,     \
		  0x40, 0x3d, 0x86)

struct cxl_mbox_get_supported_logs {
	__le16 entries;
	u8 rsvd[6];
	struct cxl_gsl_entry {
		uuid_t uuid;
		__le32 size;
	} __packed entry[];
}  __packed;

struct cxl_cel_entry {
	__le16 opcode;
	__le16 effect;
} __packed;

struct cxl_mbox_get_log {
	uuid_t uuid;
	__le32 offset;
	__le32 length;
} __packed;

/* See CXL 2.0 Table 175 Identify Memory Device Output Payload */
struct cxl_mbox_identify {
	char fw_revision[0x10];
	__le64 total_capacity;
	__le64 volatile_capacity;
	__le64 persistent_capacity;
	__le64 partition_align;
	__le16 info_event_log_size;
	__le16 warning_event_log_size;
	__le16 failure_event_log_size;
	__le16 fatal_event_log_size;
	__le32 lsa_size;
	u8 poison_list_max_mer[3];
	__le16 inject_poison_limit;
	u8 poison_caps;
	u8 qos_telemetry_caps;
} __packed;

struct cxl_mbox_get_partition_info {
	__le64 active_volatile_cap;
	__le64 active_persistent_cap;
	__le64 next_volatile_cap;
	__le64 next_persistent_cap;
} __packed;

struct cxl_mbox_get_lsa {
	__le32 offset;
	__le32 length;
} __packed;

struct cxl_mbox_set_lsa {
	__le32 offset;
	__le32 reserved;
	u8 data[];
} __packed;

struct cxl_mbox_set_partition_info {
	__le64 volatile_capacity;
	u8 flags;
} __packed;

#define  CXL_SET_PARTITION_IMMEDIATE_FLAG	BIT(0)

/**
 * struct cxl_mem_command - Driver representation of a memory device command
 * @info: Command information as it exists for the UAPI
 * @opcode: The actual bits used for the mailbox protocol
 * @flags: Set of flags effecting driver behavior.
 *
 *  * %CXL_CMD_FLAG_FORCE_ENABLE: In cases of error, commands with this flag
 *    will be enabled by the driver regardless of what hardware may have
 *    advertised.
 *
 * The cxl_mem_command is the driver's internal representation of commands that
 * are supported by the driver. Some of these commands may not be supported by
 * the hardware. The driver will use @info to validate the fields passed in by
 * the user then submit the @opcode to the hardware.
 *
 * See struct cxl_command_info.
 */
struct cxl_mem_command {
	struct cxl_command_info info;
	enum cxl_opcode opcode;
	u32 flags;
#define CXL_CMD_FLAG_NONE 0
#define CXL_CMD_FLAG_FORCE_ENABLE BIT(0)
};

int cxl_mbox_send_cmd(struct cxl_dev_state *cxlds, u16 opcode, void *in,
		      size_t in_size, void *out, size_t out_size);
int cxl_dev_state_identify(struct cxl_dev_state *cxlds);
int cxl_await_media_ready(struct cxl_dev_state *cxlds);
int cxl_enumerate_cmds(struct cxl_dev_state *cxlds);
int cxl_mem_create_range_info(struct cxl_dev_state *cxlds);
struct cxl_dev_state *cxl_dev_state_create(struct device *dev);
void set_exclusive_cxl_commands(struct cxl_dev_state *cxlds, unsigned long *cmds);
void clear_exclusive_cxl_commands(struct cxl_dev_state *cxlds, unsigned long *cmds);
#ifdef CONFIG_CXL_SUSPEND
void cxl_mem_active_inc(void);
void cxl_mem_active_dec(void);
#else
static inline void cxl_mem_active_inc(void)
{
}
static inline void cxl_mem_active_dec(void)
{
}
#endif

struct cxl_hdm {
	struct cxl_component_regs regs;
	unsigned int decoder_count;
	unsigned int target_count;
	unsigned int interleave_mask;
	struct cxl_port *port;
};

struct seq_file;
struct dentry *cxl_debugfs_create_dir(const char *dir);
void cxl_dpa_debug(struct seq_file *file, struct cxl_dev_state *cxlds);
#endif /* __CXL_MEM_H__ */
