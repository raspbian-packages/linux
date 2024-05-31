// SPDX-License-Identifier: GPL-2.0

#include <linux/compiler.h>
#include <linux/bits.h>
#include <string.h>
#include <cpuid.h>
#include <sched.h>

#include "intel-pt-decoder/intel-pt-pkt-decoder.h"

#include "debug.h"
#include "tests/tests.h"
#include "arch-tests.h"
#include "cpumap.h"

/**
 * struct test_data - Test data.
 * @len: number of bytes to decode
 * @bytes: bytes to decode
 * @ctx: packet context to decode
 * @packet: expected packet
 * @new_ctx: expected new packet context
 * @ctx_unchanged: the packet context must not change
 */
static const struct test_data {
	int len;
	u8 bytes[INTEL_PT_PKT_MAX_SZ];
	enum intel_pt_pkt_ctx ctx;
	struct intel_pt_pkt packet;
	enum intel_pt_pkt_ctx new_ctx;
	int ctx_unchanged;
} data[] = {
	/* Padding Packet */
	{1, {0}, 0, {INTEL_PT_PAD, 0, 0}, 0, 1 },
	/* Short Taken/Not Taken Packet */
	{1, {4}, 0, {INTEL_PT_TNT, 1, 0}, 0, 0 },
	{1, {6}, 0, {INTEL_PT_TNT, 1, 0x20ULL << 58}, 0, 0 },
	{1, {0x80}, 0, {INTEL_PT_TNT, 6, 0}, 0, 0 },
	{1, {0xfe}, 0, {INTEL_PT_TNT, 6, 0x3fULL << 58}, 0, 0 },
	/* Long Taken/Not Taken Packet */
	{8, {0x02, 0xa3, 2}, 0, {INTEL_PT_TNT, 1, 0xa302ULL << 47}, 0, 0 },
	{8, {0x02, 0xa3, 3}, 0, {INTEL_PT_TNT, 1, 0x1a302ULL << 47}, 0, 0 },
	{8, {0x02, 0xa3, 0, 0, 0, 0, 0, 0x80}, 0, {INTEL_PT_TNT, 47, 0xa302ULL << 1}, 0, 0 },
	{8, {0x02, 0xa3, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 0, {INTEL_PT_TNT, 47, 0xffffffffffffa302ULL << 1}, 0, 0 },
	/* Target IP Packet */
	{1, {0x0d}, 0, {INTEL_PT_TIP, 0, 0}, 0, 0 },
	{3, {0x2d, 1, 2}, 0, {INTEL_PT_TIP, 1, 0x201}, 0, 0 },
	{5, {0x4d, 1, 2, 3, 4}, 0, {INTEL_PT_TIP, 2, 0x4030201}, 0, 0 },
	{7, {0x6d, 1, 2, 3, 4, 5, 6}, 0, {INTEL_PT_TIP, 3, 0x60504030201}, 0, 0 },
	{7, {0x8d, 1, 2, 3, 4, 5, 6}, 0, {INTEL_PT_TIP, 4, 0x60504030201}, 0, 0 },
	{9, {0xcd, 1, 2, 3, 4, 5, 6, 7, 8}, 0, {INTEL_PT_TIP, 6, 0x807060504030201}, 0, 0 },
	/* Packet Generation Enable */
	{1, {0x11}, 0, {INTEL_PT_TIP_PGE, 0, 0}, 0, 0 },
	{3, {0x31, 1, 2}, 0, {INTEL_PT_TIP_PGE, 1, 0x201}, 0, 0 },
	{5, {0x51, 1, 2, 3, 4}, 0, {INTEL_PT_TIP_PGE, 2, 0x4030201}, 0, 0 },
	{7, {0x71, 1, 2, 3, 4, 5, 6}, 0, {INTEL_PT_TIP_PGE, 3, 0x60504030201}, 0, 0 },
	{7, {0x91, 1, 2, 3, 4, 5, 6}, 0, {INTEL_PT_TIP_PGE, 4, 0x60504030201}, 0, 0 },
	{9, {0xd1, 1, 2, 3, 4, 5, 6, 7, 8}, 0, {INTEL_PT_TIP_PGE, 6, 0x807060504030201}, 0, 0 },
	/* Packet Generation Disable */
	{1, {0x01}, 0, {INTEL_PT_TIP_PGD, 0, 0}, 0, 0 },
	{3, {0x21, 1, 2}, 0, {INTEL_PT_TIP_PGD, 1, 0x201}, 0, 0 },
	{5, {0x41, 1, 2, 3, 4}, 0, {INTEL_PT_TIP_PGD, 2, 0x4030201}, 0, 0 },
	{7, {0x61, 1, 2, 3, 4, 5, 6}, 0, {INTEL_PT_TIP_PGD, 3, 0x60504030201}, 0, 0 },
	{7, {0x81, 1, 2, 3, 4, 5, 6}, 0, {INTEL_PT_TIP_PGD, 4, 0x60504030201}, 0, 0 },
	{9, {0xc1, 1, 2, 3, 4, 5, 6, 7, 8}, 0, {INTEL_PT_TIP_PGD, 6, 0x807060504030201}, 0, 0 },
	/* Flow Update Packet */
	{1, {0x1d}, 0, {INTEL_PT_FUP, 0, 0}, 0, 0 },
	{3, {0x3d, 1, 2}, 0, {INTEL_PT_FUP, 1, 0x201}, 0, 0 },
	{5, {0x5d, 1, 2, 3, 4}, 0, {INTEL_PT_FUP, 2, 0x4030201}, 0, 0 },
	{7, {0x7d, 1, 2, 3, 4, 5, 6}, 0, {INTEL_PT_FUP, 3, 0x60504030201}, 0, 0 },
	{7, {0x9d, 1, 2, 3, 4, 5, 6}, 0, {INTEL_PT_FUP, 4, 0x60504030201}, 0, 0 },
	{9, {0xdd, 1, 2, 3, 4, 5, 6, 7, 8}, 0, {INTEL_PT_FUP, 6, 0x807060504030201}, 0, 0 },
	/* Paging Information Packet */
	{8, {0x02, 0x43, 2, 4, 6, 8, 10, 12}, 0, {INTEL_PT_PIP, 0, 0xC0A08060402}, 0, 0 },
	{8, {0x02, 0x43, 3, 4, 6, 8, 10, 12}, 0, {INTEL_PT_PIP, 0, 0xC0A08060403}, 0, 0 },
	/* Mode Exec Packet */
	{2, {0x99, 0x00}, 0, {INTEL_PT_MODE_EXEC, 0, 16}, 0, 0 },
	{2, {0x99, 0x01}, 0, {INTEL_PT_MODE_EXEC, 1, 64}, 0, 0 },
	{2, {0x99, 0x02}, 0, {INTEL_PT_MODE_EXEC, 2, 32}, 0, 0 },
	{2, {0x99, 0x04}, 0, {INTEL_PT_MODE_EXEC, 4, 16}, 0, 0 },
	{2, {0x99, 0x05}, 0, {INTEL_PT_MODE_EXEC, 5, 64}, 0, 0 },
	{2, {0x99, 0x06}, 0, {INTEL_PT_MODE_EXEC, 6, 32}, 0, 0 },
	/* Mode TSX Packet */
	{2, {0x99, 0x20}, 0, {INTEL_PT_MODE_TSX, 0, 0}, 0, 0 },
	{2, {0x99, 0x21}, 0, {INTEL_PT_MODE_TSX, 0, 1}, 0, 0 },
	{2, {0x99, 0x22}, 0, {INTEL_PT_MODE_TSX, 0, 2}, 0, 0 },
	/* Trace Stop Packet */
	{2, {0x02, 0x83}, 0, {INTEL_PT_TRACESTOP, 0, 0}, 0, 0 },
	/* Core:Bus Ratio Packet */
	{4, {0x02, 0x03, 0x12, 0}, 0, {INTEL_PT_CBR, 0, 0x12}, 0, 1 },
	/* Timestamp Counter Packet */
	{8, {0x19, 1, 2, 3, 4, 5, 6, 7}, 0, {INTEL_PT_TSC, 0, 0x7060504030201}, 0, 1 },
	/* Mini Time Counter Packet */
	{2, {0x59, 0x12}, 0, {INTEL_PT_MTC, 0, 0x12}, 0, 1 },
	/* TSC / MTC Alignment Packet */
	{7, {0x02, 0x73}, 0, {INTEL_PT_TMA, 0, 0}, 0, 1 },
	{7, {0x02, 0x73, 1, 2}, 0, {INTEL_PT_TMA, 0, 0x201}, 0, 1 },
	{7, {0x02, 0x73, 0, 0, 0, 0xff, 1}, 0, {INTEL_PT_TMA, 0x1ff, 0}, 0, 1 },
	{7, {0x02, 0x73, 0x80, 0xc0, 0, 0xff, 1}, 0, {INTEL_PT_TMA, 0x1ff, 0xc080}, 0, 1 },
	/* Cycle Count Packet */
	{1, {0x03}, 0, {INTEL_PT_CYC, 0, 0}, 0, 1 },
	{1, {0x0b}, 0, {INTEL_PT_CYC, 0, 1}, 0, 1 },
	{1, {0xfb}, 0, {INTEL_PT_CYC, 0, 0x1f}, 0, 1 },
	{2, {0x07, 2}, 0, {INTEL_PT_CYC, 0, 0x20}, 0, 1 },
	{2, {0xff, 0xfe}, 0, {INTEL_PT_CYC, 0, 0xfff}, 0, 1 },
	{3, {0x07, 1, 2}, 0, {INTEL_PT_CYC, 0, 0x1000}, 0, 1 },
	{3, {0xff, 0xff, 0xfe}, 0, {INTEL_PT_CYC, 0, 0x7ffff}, 0, 1 },
	{4, {0x07, 1, 1, 2}, 0, {INTEL_PT_CYC, 0, 0x80000}, 0, 1 },
	{4, {0xff, 0xff, 0xff, 0xfe}, 0, {INTEL_PT_CYC, 0, 0x3ffffff}, 0, 1 },
	{5, {0x07, 1, 1, 1, 2}, 0, {INTEL_PT_CYC, 0, 0x4000000}, 0, 1 },
	{5, {0xff, 0xff, 0xff, 0xff, 0xfe}, 0, {INTEL_PT_CYC, 0, 0x1ffffffff}, 0, 1 },
	{6, {0x07, 1, 1, 1, 1, 2}, 0, {INTEL_PT_CYC, 0, 0x200000000}, 0, 1 },
	{6, {0xff, 0xff, 0xff, 0xff, 0xff, 0xfe}, 0, {INTEL_PT_CYC, 0, 0xffffffffff}, 0, 1 },
	{7, {0x07, 1, 1, 1, 1, 1, 2}, 0, {INTEL_PT_CYC, 0, 0x10000000000}, 0, 1 },
	{7, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe}, 0, {INTEL_PT_CYC, 0, 0x7fffffffffff}, 0, 1 },
	{8, {0x07, 1, 1, 1, 1, 1, 1, 2}, 0, {INTEL_PT_CYC, 0, 0x800000000000}, 0, 1 },
	{8, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe}, 0, {INTEL_PT_CYC, 0, 0x3fffffffffffff}, 0, 1 },
	{9, {0x07, 1, 1, 1, 1, 1, 1, 1, 2}, 0, {INTEL_PT_CYC, 0, 0x40000000000000}, 0, 1 },
	{9, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe}, 0, {INTEL_PT_CYC, 0, 0x1fffffffffffffff}, 0, 1 },
	{10, {0x07, 1, 1, 1, 1, 1, 1, 1, 1, 2}, 0, {INTEL_PT_CYC, 0, 0x2000000000000000}, 0, 1 },
	{10, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe}, 0, {INTEL_PT_CYC, 0, 0xffffffffffffffff}, 0, 1 },
	/* Virtual-Machine Control Structure Packet */
	{7, {0x02, 0xc8, 1, 2, 3, 4, 5}, 0, {INTEL_PT_VMCS, 5, 0x504030201}, 0, 0 },
	/* Overflow Packet */
	{2, {0x02, 0xf3}, 0, {INTEL_PT_OVF, 0, 0}, 0, 0 },
	{2, {0x02, 0xf3}, INTEL_PT_BLK_4_CTX, {INTEL_PT_OVF, 0, 0}, 0, 0 },
	{2, {0x02, 0xf3}, INTEL_PT_BLK_8_CTX, {INTEL_PT_OVF, 0, 0}, 0, 0 },
	/* Packet Stream Boundary*/
	{16, {0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82}, 0, {INTEL_PT_PSB, 0, 0}, 0, 0 },
	{16, {0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82}, INTEL_PT_BLK_4_CTX, {INTEL_PT_PSB, 0, 0}, 0, 0 },
	{16, {0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82}, INTEL_PT_BLK_8_CTX, {INTEL_PT_PSB, 0, 0}, 0, 0 },
	/* PSB End Packet */
	{2, {0x02, 0x23}, 0, {INTEL_PT_PSBEND, 0, 0}, 0, 0 },
	/* Maintenance Packet */
	{11, {0x02, 0xc3, 0x88, 1, 2, 3, 4, 5, 6, 7}, 0, {INTEL_PT_MNT, 0, 0x7060504030201}, 0, 1 },
	/* Write Data to PT Packet */
	{6, {0x02, 0x12, 1, 2, 3, 4}, 0, {INTEL_PT_PTWRITE, 0, 0x4030201}, 0, 0 },
	{10, {0x02, 0x32, 1, 2, 3, 4, 5, 6, 7, 8}, 0, {INTEL_PT_PTWRITE, 1, 0x807060504030201}, 0, 0 },
	{6, {0x02, 0x92, 1, 2, 3, 4}, 0, {INTEL_PT_PTWRITE_IP, 0, 0x4030201}, 0, 0 },
	{10, {0x02, 0xb2, 1, 2, 3, 4, 5, 6, 7, 8}, 0, {INTEL_PT_PTWRITE_IP, 1, 0x807060504030201}, 0, 0 },
	/* Execution Stop Packet */
	{2, {0x02, 0x62}, 0, {INTEL_PT_EXSTOP, 0, 0}, 0, 1 },
	{2, {0x02, 0xe2}, 0, {INTEL_PT_EXSTOP_IP, 0, 0}, 0, 1 },
	/* Monitor Wait Packet */
	{10, {0x02, 0xc2}, 0, {INTEL_PT_MWAIT, 0, 0}, 0, 0 },
	{10, {0x02, 0xc2, 1, 2, 3, 4, 5, 6, 7, 8}, 0, {INTEL_PT_MWAIT, 0, 0x807060504030201}, 0, 0 },
	{10, {0x02, 0xc2, 0xff, 2, 3, 4, 7, 6, 7, 8}, 0, {INTEL_PT_MWAIT, 0, 0x8070607040302ff}, 0, 0 },
	/* Power Entry Packet */
	{4, {0x02, 0x22}, 0, {INTEL_PT_PWRE, 0, 0}, 0, 1 },
	{4, {0x02, 0x22, 1, 2}, 0, {INTEL_PT_PWRE, 0, 0x0201}, 0, 1 },
	{4, {0x02, 0x22, 0x80, 0x34}, 0, {INTEL_PT_PWRE, 0, 0x3480}, 0, 1 },
	{4, {0x02, 0x22, 0x00, 0x56}, 0, {INTEL_PT_PWRE, 0, 0x5600}, 0, 1 },
	/* Power Exit Packet */
	{7, {0x02, 0xa2}, 0, {INTEL_PT_PWRX, 0, 0}, 0, 1 },
	{7, {0x02, 0xa2, 1, 2, 3, 4, 5}, 0, {INTEL_PT_PWRX, 0, 0x504030201}, 0, 1 },
	{7, {0x02, 0xa2, 0xff, 0xff, 0xff, 0xff, 0xff}, 0, {INTEL_PT_PWRX, 0, 0xffffffffff}, 0, 1 },
	/* Block Begin Packet */
	{3, {0x02, 0x63, 0x00}, 0, {INTEL_PT_BBP, 0, 0}, INTEL_PT_BLK_8_CTX, 0 },
	{3, {0x02, 0x63, 0x80}, 0, {INTEL_PT_BBP, 1, 0}, INTEL_PT_BLK_4_CTX, 0 },
	{3, {0x02, 0x63, 0x1f}, 0, {INTEL_PT_BBP, 0, 0x1f}, INTEL_PT_BLK_8_CTX, 0 },
	{3, {0x02, 0x63, 0x9f}, 0, {INTEL_PT_BBP, 1, 0x1f}, INTEL_PT_BLK_4_CTX, 0 },
	/* 4-byte Block Item Packet */
	{5, {0x04}, INTEL_PT_BLK_4_CTX, {INTEL_PT_BIP, 0, 0}, INTEL_PT_BLK_4_CTX, 0 },
	{5, {0xfc}, INTEL_PT_BLK_4_CTX, {INTEL_PT_BIP, 0x1f, 0}, INTEL_PT_BLK_4_CTX, 0 },
	{5, {0x04, 1, 2, 3, 4}, INTEL_PT_BLK_4_CTX, {INTEL_PT_BIP, 0, 0x04030201}, INTEL_PT_BLK_4_CTX, 0 },
	{5, {0xfc, 1, 2, 3, 4}, INTEL_PT_BLK_4_CTX, {INTEL_PT_BIP, 0x1f, 0x04030201}, INTEL_PT_BLK_4_CTX, 0 },
	/* 8-byte Block Item Packet */
	{9, {0x04}, INTEL_PT_BLK_8_CTX, {INTEL_PT_BIP, 0, 0}, INTEL_PT_BLK_8_CTX, 0 },
	{9, {0xfc}, INTEL_PT_BLK_8_CTX, {INTEL_PT_BIP, 0x1f, 0}, INTEL_PT_BLK_8_CTX, 0 },
	{9, {0x04, 1, 2, 3, 4, 5, 6, 7, 8}, INTEL_PT_BLK_8_CTX, {INTEL_PT_BIP, 0, 0x0807060504030201}, INTEL_PT_BLK_8_CTX, 0 },
	{9, {0xfc, 1, 2, 3, 4, 5, 6, 7, 8}, INTEL_PT_BLK_8_CTX, {INTEL_PT_BIP, 0x1f, 0x0807060504030201}, INTEL_PT_BLK_8_CTX, 0 },
	/* Block End Packet */
	{2, {0x02, 0x33}, INTEL_PT_BLK_4_CTX, {INTEL_PT_BEP, 0, 0}, 0, 0 },
	{2, {0x02, 0xb3}, INTEL_PT_BLK_4_CTX, {INTEL_PT_BEP_IP, 0, 0}, 0, 0 },
	{2, {0x02, 0x33}, INTEL_PT_BLK_8_CTX, {INTEL_PT_BEP, 0, 0}, 0, 0 },
	{2, {0x02, 0xb3}, INTEL_PT_BLK_8_CTX, {INTEL_PT_BEP_IP, 0, 0}, 0, 0 },
	/* Control Flow Event Packet */
	{4, {0x02, 0x13, 0x01, 0x03}, 0, {INTEL_PT_CFE, 1, 3}, 0, 0 },
	{4, {0x02, 0x13, 0x81, 0x03}, 0, {INTEL_PT_CFE_IP, 1, 3}, 0, 0 },
	{4, {0x02, 0x13, 0x1f, 0x00}, 0, {INTEL_PT_CFE, 0x1f, 0}, 0, 0 },
	{4, {0x02, 0x13, 0x9f, 0xff}, 0, {INTEL_PT_CFE_IP, 0x1f, 0xff}, 0, 0 },
	/*  */
	{11, {0x02, 0x53, 0x09, 1, 2, 3, 4, 5, 6, 7}, 0, {INTEL_PT_EVD, 0x09, 0x7060504030201}, 0, 0 },
	{11, {0x02, 0x53, 0x3f, 2, 3, 4, 5, 6, 7, 8}, 0, {INTEL_PT_EVD, 0x3f, 0x8070605040302}, 0, 0 },
	/* Terminator */
	{0, {0}, 0, {0, 0, 0}, 0, 0 },
};

static int dump_packet(const struct intel_pt_pkt *packet, const u8 *bytes, int len)
{
	char desc[INTEL_PT_PKT_DESC_MAX];
	int ret, i;

	for (i = 0; i < len; i++)
		pr_debug(" %02x", bytes[i]);
	for (; i < INTEL_PT_PKT_MAX_SZ; i++)
		pr_debug("   ");
	pr_debug("   ");
	ret = intel_pt_pkt_desc(packet, desc, INTEL_PT_PKT_DESC_MAX);
	if (ret < 0) {
		pr_debug("intel_pt_pkt_desc failed!\n");
		return TEST_FAIL;
	}
	pr_debug("%s\n", desc);

	return TEST_OK;
}

static void decoding_failed(const struct test_data *d)
{
	pr_debug("Decoding failed!\n");
	pr_debug("Decoding:  ");
	dump_packet(&d->packet, d->bytes, d->len);
}

static int fail(const struct test_data *d, struct intel_pt_pkt *packet, int len,
		enum intel_pt_pkt_ctx new_ctx)
{
	decoding_failed(d);

	if (len != d->len)
		pr_debug("Expected length: %d   Decoded length %d\n",
			 d->len, len);

	if (packet->type != d->packet.type)
		pr_debug("Expected type: %d   Decoded type %d\n",
			 d->packet.type, packet->type);

	if (packet->count != d->packet.count)
		pr_debug("Expected count: %d   Decoded count %d\n",
			 d->packet.count, packet->count);

	if (packet->payload != d->packet.payload)
		pr_debug("Expected payload: 0x%llx   Decoded payload 0x%llx\n",
			 (unsigned long long)d->packet.payload,
			 (unsigned long long)packet->payload);

	if (new_ctx != d->new_ctx)
		pr_debug("Expected packet context: %d   Decoded packet context %d\n",
			 d->new_ctx, new_ctx);

	return TEST_FAIL;
}

static int test_ctx_unchanged(const struct test_data *d, struct intel_pt_pkt *packet,
			      enum intel_pt_pkt_ctx ctx)
{
	enum intel_pt_pkt_ctx old_ctx = ctx;

	intel_pt_upd_pkt_ctx(packet, &ctx);

	if (ctx != old_ctx) {
		decoding_failed(d);
		pr_debug("Packet context changed!\n");
		return TEST_FAIL;
	}

	return TEST_OK;
}

static int test_one(const struct test_data *d)
{
	struct intel_pt_pkt packet;
	enum intel_pt_pkt_ctx ctx = d->ctx;
	int ret;

	memset(&packet, 0xff, sizeof(packet));

	/* Decode a packet */
	ret = intel_pt_get_packet(d->bytes, d->len, &packet, &ctx);
	if (ret < 0 || ret > INTEL_PT_PKT_MAX_SZ) {
		decoding_failed(d);
		pr_debug("intel_pt_get_packet returned %d\n", ret);
		return TEST_FAIL;
	}

	/* Some packets must always leave the packet context unchanged */
	if (d->ctx_unchanged) {
		int err;

		err = test_ctx_unchanged(d, &packet, INTEL_PT_NO_CTX);
		if (err)
			return err;
		err = test_ctx_unchanged(d, &packet, INTEL_PT_BLK_4_CTX);
		if (err)
			return err;
		err = test_ctx_unchanged(d, &packet, INTEL_PT_BLK_8_CTX);
		if (err)
			return err;
	}

	/* Compare to the expected values */
	if (ret != d->len || packet.type != d->packet.type ||
	    packet.count != d->packet.count ||
	    packet.payload != d->packet.payload || ctx != d->new_ctx)
		return fail(d, &packet, ret, ctx);

	pr_debug("Decoded ok:");
	ret = dump_packet(&d->packet, d->bytes, d->len);

	return ret;
}

/*
 * This test feeds byte sequences to the Intel PT packet decoder and checks the
 * results. Changes to the packet context are also checked.
 */
int test__intel_pt_pkt_decoder(struct test_suite *test __maybe_unused, int subtest __maybe_unused)
{
	const struct test_data *d = data;
	int ret;

	for (d = data; d->len; d++) {
		ret = test_one(d);
		if (ret)
			return ret;
	}

	return TEST_OK;
}

static int setaffinity(int cpu)
{
	cpu_set_t cpu_set;

	CPU_ZERO(&cpu_set);
	CPU_SET(cpu, &cpu_set);
	if (sched_setaffinity(0, sizeof(cpu_set), &cpu_set)) {
		pr_debug("sched_setaffinity() failed for CPU %d\n", cpu);
		return -1;
	}
	return 0;
}

#define INTEL_PT_ADDR_FILT_CNT_MASK	GENMASK(2, 0)
#define INTEL_PT_SUBLEAF_CNT		2
#define CPUID_REG_CNT			4

struct cpuid_result {
	union {
		struct {
			unsigned int eax;
			unsigned int ebx;
			unsigned int ecx;
			unsigned int edx;
		};
		unsigned int reg[CPUID_REG_CNT];
	};
};

struct pt_caps {
	struct cpuid_result subleaf[INTEL_PT_SUBLEAF_CNT];
};

static int get_pt_caps(int cpu, struct pt_caps *caps)
{
	struct cpuid_result r;
	int i;

	if (setaffinity(cpu))
		return -1;

	memset(caps, 0, sizeof(*caps));

	for (i = 0; i < INTEL_PT_SUBLEAF_CNT; i++) {
		__get_cpuid_count(20, i, &r.eax, &r.ebx, &r.ecx, &r.edx);
		pr_debug("CPU %d CPUID leaf 20 subleaf %d\n", cpu, i);
		pr_debug("eax = 0x%08x\n", r.eax);
		pr_debug("ebx = 0x%08x\n", r.ebx);
		pr_debug("ecx = 0x%08x\n", r.ecx);
		pr_debug("edx = 0x%08x\n", r.edx);
		caps->subleaf[i] = r;
	}

	return 0;
}

static bool is_hydrid(void)
{
	unsigned int eax, ebx, ecx, edx = 0;
	bool result;

	__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx);
	result = edx & BIT(15);
	pr_debug("Is %shybrid : CPUID leaf 7 subleaf 0 edx %#x (bit-15 indicates hybrid)\n",
		 result ? "" : "not ", edx);
	return result;
}

static int compare_caps(int cpu, struct pt_caps *caps, struct pt_caps *caps0)
{
	struct pt_caps mask = { /* Mask of bits to check*/
		.subleaf = {
			[0] = {
				.ebx = GENMASK(8, 0),
				.ecx = GENMASK(3, 0),
			},
			[1] = {
				.eax = GENMASK(31, 16),
				.ebx = GENMASK(31, 0),
			}
		}
	};
	unsigned int m, reg, reg0;
	int ret = 0;
	int i, j;

	for (i = 0; i < INTEL_PT_SUBLEAF_CNT; i++) {
		for (j = 0; j < CPUID_REG_CNT; j++) {
			m = mask.subleaf[i].reg[j];
			reg = m & caps->subleaf[i].reg[j];
			reg0 = m & caps0->subleaf[i].reg[j];
			if ((reg & reg0) != reg0) {
				pr_debug("CPU %d subleaf %d reg %d FAIL %#x vs %#x\n",
					 cpu, i, j, reg, reg0);
				ret = -1;
			}
		}
	}

	m = INTEL_PT_ADDR_FILT_CNT_MASK;
	reg = m & caps->subleaf[1].eax;
	reg0 = m & caps0->subleaf[1].eax;
	if (reg < reg0) {
		pr_debug("CPU %d subleaf 1 reg 0 FAIL address filter count %#x vs %#x\n",
			 cpu, reg, reg0);
		ret = -1;
	}

	if (!ret)
		pr_debug("CPU %d OK\n", cpu);

	return ret;
}

int test__intel_pt_hybrid_compat(struct test_suite *test, int subtest)
{
	int max_cpu = cpu__max_cpu().cpu;
	struct pt_caps last_caps;
	struct pt_caps caps0;
	int ret = TEST_OK;
	int cpu;

	if (!is_hydrid()) {
		test->test_cases[subtest].skip_reason = "not hybrid";
		return TEST_SKIP;
	}

	if (get_pt_caps(0, &caps0))
		return TEST_FAIL;

	for (cpu = 1, last_caps = caps0; cpu < max_cpu; cpu++) {
		struct pt_caps caps;

		if (get_pt_caps(cpu, &caps)) {
			pr_debug("CPU %d not found\n", cpu);
			continue;
		}
		if (!memcmp(&caps, &last_caps, sizeof(caps))) {
			pr_debug("CPU %d same caps as previous CPU\n", cpu);
			continue;
		}
		if (compare_caps(cpu, &caps, &caps0))
			ret = TEST_FAIL;
		last_caps = caps;
	}

	return ret;
}
