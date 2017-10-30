/* ir-rc5-decoder.c - decoder for RC5(x) and StreamZap protocols
 *
 * Copyright (C) 2010 by Mauro Carvalho Chehab
 * Copyright (C) 2010 by Jarod Wilson <jarod@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation version 2 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */

/*
 * This decoder handles the 14 bit RC5 protocol, 15 bit "StreamZap" protocol
 * and 20 bit RC5x protocol.
 */

#include "rc-core-priv.h"
#include <linux/module.h>

#define RC5_NBITS		14
#define RC5_SZ_NBITS		15
#define RC5X_NBITS		20
#define CHECK_RC5X_NBITS	8
#define RC5_UNIT		888888 /* ns */
#define RC5_BIT_START		(1 * RC5_UNIT)
#define RC5_BIT_END		(1 * RC5_UNIT)
#define RC5X_SPACE		(4 * RC5_UNIT)
#define RC5_TRAILER		(6 * RC5_UNIT) /* In reality, approx 100 */

enum rc5_state {
	STATE_INACTIVE,
	STATE_BIT_START,
	STATE_BIT_END,
	STATE_CHECK_RC5X,
	STATE_FINISHED,
};

/**
 * ir_rc5_decode() - Decode one RC-5 pulse or space
 * @dev:	the struct rc_dev descriptor of the device
 * @ev:		the struct ir_raw_event descriptor of the pulse/space
 *
 * This function returns -EINVAL if the pulse violates the state machine
 */
static int ir_rc5_decode(struct rc_dev *dev, struct ir_raw_event ev)
{
	struct rc5_dec *data = &dev->raw->rc5;
	u8 toggle;
	u32 scancode;
	enum rc_type protocol;

	if (!is_timing_event(ev)) {
		if (ev.reset)
			data->state = STATE_INACTIVE;
		return 0;
	}

	if (!geq_margin(ev.duration, RC5_UNIT, RC5_UNIT / 2))
		goto out;

again:
	IR_dprintk(2, "RC5(x/sz) decode started at state %i (%uus %s)\n",
		   data->state, TO_US(ev.duration), TO_STR(ev.pulse));

	if (!geq_margin(ev.duration, RC5_UNIT, RC5_UNIT / 2))
		return 0;

	switch (data->state) {

	case STATE_INACTIVE:
		if (!ev.pulse)
			break;

		data->state = STATE_BIT_START;
		data->count = 1;
		decrease_duration(&ev, RC5_BIT_START);
		goto again;

	case STATE_BIT_START:
		if (!ev.pulse && geq_margin(ev.duration, RC5_TRAILER, RC5_UNIT / 2)) {
			data->state = STATE_FINISHED;
			goto again;
		}

		if (!eq_margin(ev.duration, RC5_BIT_START, RC5_UNIT / 2))
			break;

		data->bits <<= 1;
		if (!ev.pulse)
			data->bits |= 1;
		data->count++;
		data->state = STATE_BIT_END;
		return 0;

	case STATE_BIT_END:
		if (!is_transition(&ev, &dev->raw->prev_ev))
			break;

		if (data->count == CHECK_RC5X_NBITS)
			data->state = STATE_CHECK_RC5X;
		else
			data->state = STATE_BIT_START;

		decrease_duration(&ev, RC5_BIT_END);
		goto again;

	case STATE_CHECK_RC5X:
		if (!ev.pulse && geq_margin(ev.duration, RC5X_SPACE, RC5_UNIT / 2)) {
			data->is_rc5x = true;
			decrease_duration(&ev, RC5X_SPACE);
		} else
			data->is_rc5x = false;
		data->state = STATE_BIT_START;
		goto again;

	case STATE_FINISHED:
		if (ev.pulse)
			break;

		if (data->is_rc5x && data->count == RC5X_NBITS) {
			/* RC5X */
			u8 xdata, command, system;
			if (!(dev->enabled_protocols & RC_BIT_RC5X_20)) {
				data->state = STATE_INACTIVE;
				return 0;
			}
			xdata    = (data->bits & 0x0003F) >> 0;
			command  = (data->bits & 0x00FC0) >> 6;
			system   = (data->bits & 0x1F000) >> 12;
			toggle   = (data->bits & 0x20000) ? 1 : 0;
			command += (data->bits & 0x40000) ? 0 : 0x40;
			scancode = system << 16 | command << 8 | xdata;
			protocol = RC_TYPE_RC5X_20;

		} else if (!data->is_rc5x && data->count == RC5_NBITS) {
			/* RC5 */
			u8 command, system;
			if (!(dev->enabled_protocols & RC_BIT_RC5)) {
				data->state = STATE_INACTIVE;
				return 0;
			}
			command  = (data->bits & 0x0003F) >> 0;
			system   = (data->bits & 0x007C0) >> 6;
			toggle   = (data->bits & 0x00800) ? 1 : 0;
			command += (data->bits & 0x01000) ? 0 : 0x40;
			scancode = system << 8 | command;
			protocol = RC_TYPE_RC5;

		} else if (!data->is_rc5x && data->count == RC5_SZ_NBITS) {
			/* RC5 StreamZap */
			u8 command, system;
			if (!(dev->enabled_protocols & RC_BIT_RC5_SZ)) {
				data->state = STATE_INACTIVE;
				return 0;
			}
			command  = (data->bits & 0x0003F) >> 0;
			system   = (data->bits & 0x02FC0) >> 6;
			toggle   = (data->bits & 0x01000) ? 1 : 0;
			scancode = system << 6 | command;
			protocol = RC_TYPE_RC5_SZ;

		} else
			break;

		IR_dprintk(1, "RC5(x/sz) scancode 0x%06x (p: %u, t: %u)\n",
			   scancode, protocol, toggle);

		rc_keydown(dev, protocol, scancode, toggle);
		data->state = STATE_INACTIVE;
		return 0;
	}

out:
	IR_dprintk(1, "RC5(x/sz) decode failed at state %i count %d (%uus %s)\n",
		   data->state, data->count, TO_US(ev.duration), TO_STR(ev.pulse));
	data->state = STATE_INACTIVE;
	return -EINVAL;
}

static const struct ir_raw_timings_manchester ir_rc5_timings = {
	.leader			= RC5_UNIT,
	.pulse_space_start	= 0,
	.clock			= RC5_UNIT,
	.trailer_space		= RC5_UNIT * 10,
};

static const struct ir_raw_timings_manchester ir_rc5x_timings[2] = {
	{
		.leader			= RC5_UNIT,
		.pulse_space_start	= 0,
		.clock			= RC5_UNIT,
		.trailer_space		= RC5X_SPACE,
	},
	{
		.clock			= RC5_UNIT,
		.trailer_space		= RC5_UNIT * 10,
	},
};

static const struct ir_raw_timings_manchester ir_rc5_sz_timings = {
	.leader				= RC5_UNIT,
	.pulse_space_start		= 0,
	.clock				= RC5_UNIT,
	.trailer_space			= RC5_UNIT * 10,
};

/**
 * ir_rc5_encode() - Encode a scancode as a stream of raw events
 *
 * @protocol:	protocol variant to encode
 * @scancode:	scancode to encode
 * @events:	array of raw ir events to write into
 * @max:	maximum size of @events
 *
 * Returns:	The number of events written.
 *		-ENOBUFS if there isn't enough space in the array to fit the
 *		encoding. In this case all @max events will have been written.
 *		-EINVAL if the scancode is ambiguous or invalid.
 */
static int ir_rc5_encode(enum rc_type protocol, u32 scancode,
			 struct ir_raw_event *events, unsigned int max)
{
	int ret;
	struct ir_raw_event *e = events;
	unsigned int data, xdata, command, commandx, system, pre_space_data;

	/* Detect protocol and convert scancode to raw data */
	if (protocol == RC_TYPE_RC5) {
		/* decode scancode */
		command  = (scancode & 0x003f) >> 0;
		commandx = (scancode & 0x0040) >> 6;
		system   = (scancode & 0x1f00) >> 8;
		/* encode data */
		data = !commandx << 12 | system << 6 | command;

		/* Modulate the data */
		ret = ir_raw_gen_manchester(&e, max, &ir_rc5_timings,
					    RC5_NBITS, data);
		if (ret < 0)
			return ret;
	} else if (protocol == RC_TYPE_RC5X_20) {
		/* decode scancode */
		xdata    = (scancode & 0x00003f) >> 0;
		command  = (scancode & 0x003f00) >> 8;
		commandx = !(scancode & 0x004000);
		system   = (scancode & 0x1f0000) >> 16;

		/* encode data */
		data = commandx << 18 | system << 12 | command << 6 | xdata;

		/* Modulate the data */
		pre_space_data = data >> (RC5X_NBITS - CHECK_RC5X_NBITS);
		ret = ir_raw_gen_manchester(&e, max, &ir_rc5x_timings[0],
					    CHECK_RC5X_NBITS, pre_space_data);
		if (ret < 0)
			return ret;
		ret = ir_raw_gen_manchester(&e, max - (e - events),
					    &ir_rc5x_timings[1],
					    RC5X_NBITS - CHECK_RC5X_NBITS,
					    data);
		if (ret < 0)
			return ret;
	} else if (protocol == RC_TYPE_RC5_SZ) {
		/* RC5-SZ scancode is raw enough for Manchester as it is */
		ret = ir_raw_gen_manchester(&e, max, &ir_rc5_sz_timings,
					    RC5_SZ_NBITS, scancode & 0x2fff);
		if (ret < 0)
			return ret;
	} else {
		return -EINVAL;
	}

	return e - events;
}

static struct ir_raw_handler rc5_handler = {
	.protocols	= RC_BIT_RC5 | RC_BIT_RC5X_20 | RC_BIT_RC5_SZ,
	.decode		= ir_rc5_decode,
	.encode		= ir_rc5_encode,
};

static int __init ir_rc5_decode_init(void)
{
	ir_raw_handler_register(&rc5_handler);

	printk(KERN_INFO "IR RC5(x/sz) protocol handler initialized\n");
	return 0;
}

static void __exit ir_rc5_decode_exit(void)
{
	ir_raw_handler_unregister(&rc5_handler);
}

module_init(ir_rc5_decode_init);
module_exit(ir_rc5_decode_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mauro Carvalho Chehab and Jarod Wilson");
MODULE_AUTHOR("Red Hat Inc. (http://www.redhat.com)");
MODULE_DESCRIPTION("RC5(x/sz) IR protocol decoder");
