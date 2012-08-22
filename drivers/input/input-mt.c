/*
 * Input Multitouch Library
 *
 * Copyright (c) 2008-2010 Henrik Rydberg
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#include <linux/input/mt.h>
#include <linux/export.h>
#include <linux/slab.h>

#define TRKID_SGN	((TRKID_MAX + 1) >> 1)

#define input_dev_to_mt(dev)						\
	((dev)->mt ? container_of((dev)->mt, struct input_mt, slots[0]) : NULL)

static void copy_abs(struct input_dev *dev, unsigned int dst, unsigned int src)
{
	if (dev->absinfo && test_bit(src, dev->absbit)) {
		dev->absinfo[dst] = dev->absinfo[src];
		dev->absbit[BIT_WORD(dst)] |= BIT_MASK(dst);
	}
}

/**
 * input_mt_init_slots() - initialize MT input slots
 * @dev: input device supporting MT events and finger tracking
 * @num_slots: number of slots used by the device
 *
 * This function allocates all necessary memory for MT slot handling
 * in the input device, prepares the ABS_MT_SLOT and
 * ABS_MT_TRACKING_ID events for use and sets up appropriate buffers.
 * May be called repeatedly. Returns -EINVAL if attempting to
 * reinitialize with a different number of slots.
 */
int input_mt_init_slots_flags(struct input_dev *dev, unsigned int num_slots,
			unsigned int flags)
{
	struct input_mt *mt;
	int i;

	if (!num_slots)
		return 0;
	if (dev->mt)
		return dev->mtsize != num_slots ? -EINVAL : 0;

	mt = kzalloc(sizeof(*mt) + num_slots * sizeof(*mt->slots) +
		     num_slots * sizeof(*mt->slot_frame), GFP_KERNEL);
	if (!mt)
		return -ENOMEM;

	dev->mtsize = num_slots;
	mt->num_slots = num_slots;
	mt->flags = flags;
	mt->slot_frame = (unsigned int *)&mt->slots[num_slots];
	input_set_abs_params(dev, ABS_MT_SLOT, 0, num_slots - 1, 0, 0);
	input_set_abs_params(dev, ABS_MT_TRACKING_ID, 0, TRKID_MAX, 0, 0);
	input_set_events_per_packet(dev, 6 * num_slots);

	if (flags & (INPUT_MT_POINTER | INPUT_MT_DIRECT)) {
		__set_bit(EV_KEY, dev->evbit);
		__set_bit(BTN_TOUCH, dev->keybit);

		copy_abs(dev, ABS_X, ABS_MT_POSITION_X);
		copy_abs(dev, ABS_Y, ABS_MT_POSITION_Y);
		copy_abs(dev, ABS_PRESSURE, ABS_MT_PRESSURE);
	}
	if (flags & INPUT_MT_POINTER) {
		__set_bit(BTN_TOOL_FINGER, dev->keybit);
		__set_bit(BTN_TOOL_DOUBLETAP, dev->keybit);
		if (num_slots >= 3)
			__set_bit(BTN_TOOL_TRIPLETAP, dev->keybit);
		if (num_slots >= 4)
			__set_bit(BTN_TOOL_QUADTAP, dev->keybit);
		if (num_slots >= 5)
			__set_bit(BTN_TOOL_QUINTTAP, dev->keybit);
		__set_bit(INPUT_PROP_POINTER, dev->propbit);
	}
	if (flags & INPUT_MT_DIRECT)
		__set_bit(INPUT_PROP_DIRECT, dev->propbit);

	/* Mark slots as 'unused' */
	for (i = 0; i < num_slots; i++)
		input_mt_set_value(&mt->slots[i], ABS_MT_TRACKING_ID, -1);

	dev->mt = &mt->slots[0];
	return 0;
}
EXPORT_SYMBOL(input_mt_init_slots_flags);

int input_mt_init_slots(struct input_dev *dev, unsigned int num_slots)
{
	return input_mt_init_slots_flags(dev, num_slots, 0);
}
EXPORT_SYMBOL(input_mt_init_slots);

/**
 * input_mt_destroy_slots() - frees the MT slots of the input device
 * @dev: input device with allocated MT slots
 *
 * This function is only needed in error path as the input core will
 * automatically free the MT slots when the device is destroyed.
 */
void input_mt_destroy_slots(struct input_dev *dev)
{
	kfree(input_dev_to_mt(dev));
	dev->mt = NULL;
	dev->mtsize = 0;
	dev->slot = 0;
	dev->trkid = 0;
}
EXPORT_SYMBOL(input_mt_destroy_slots);

/**
 * input_mt_report_slot_state() - report contact state
 * @dev: input device with allocated MT slots
 * @tool_type: the tool type to use in this slot
 * @active: true if contact is active, false otherwise
 *
 * Reports a contact via ABS_MT_TRACKING_ID, and optionally
 * ABS_MT_TOOL_TYPE. If active is true and the slot is currently
 * inactive, or if the tool type is changed, a new tracking id is
 * assigned to the slot. The tool type is only reported if the
 * corresponding absbit field is set.
 */
void input_mt_report_slot_state(struct input_dev *dev,
				unsigned int tool_type, bool active)
{
	struct input_mt *mt = input_dev_to_mt(dev);
	struct input_mt_slot *slot;
	int id;

	if (!mt)
		return;

	slot = &mt->slots[dev->slot];
	mt->slot_frame[dev->slot] = mt->frame;

	if (!active) {
		input_event(dev, EV_ABS, ABS_MT_TRACKING_ID, -1);
		return;
	}

	id = input_mt_get_value(slot, ABS_MT_TRACKING_ID);
	if (id < 0 || input_mt_get_value(slot, ABS_MT_TOOL_TYPE) != tool_type)
		id = input_mt_new_trkid(dev);

	input_event(dev, EV_ABS, ABS_MT_TRACKING_ID, id);
	input_event(dev, EV_ABS, ABS_MT_TOOL_TYPE, tool_type);
}
EXPORT_SYMBOL(input_mt_report_slot_state);

/**
 * input_mt_report_finger_count() - report contact count
 * @dev: input device with allocated MT slots
 * @count: the number of contacts
 *
 * Reports the contact count via BTN_TOOL_FINGER, BTN_TOOL_DOUBLETAP,
 * BTN_TOOL_TRIPLETAP and BTN_TOOL_QUADTAP.
 *
 * The input core ensures only the KEY events already setup for
 * this device will produce output.
 */
void input_mt_report_finger_count(struct input_dev *dev, int count)
{
	input_event(dev, EV_KEY, BTN_TOOL_FINGER, count == 1);
	input_event(dev, EV_KEY, BTN_TOOL_DOUBLETAP, count == 2);
	input_event(dev, EV_KEY, BTN_TOOL_TRIPLETAP, count == 3);
	input_event(dev, EV_KEY, BTN_TOOL_QUADTAP, count == 4);
	input_event(dev, EV_KEY, BTN_TOOL_QUINTTAP, count == 5);
}
EXPORT_SYMBOL(input_mt_report_finger_count);

/**
 * input_mt_report_pointer_emulation() - common pointer emulation
 * @dev: input device with allocated MT slots
 * @use_count: report number of active contacts as finger count
 *
 * Performs legacy pointer emulation via BTN_TOUCH, ABS_X, ABS_Y and
 * ABS_PRESSURE. Touchpad finger count is emulated if use_count is true.
 *
 * The input core ensures only the KEY and ABS axes already setup for
 * this device will produce output.
 */
void input_mt_report_pointer_emulation(struct input_dev *dev, bool use_count)
{
	struct input_mt_slot *oldest = 0;
	int oldid = dev->trkid;
	int count = 0;
	int i;

	for (i = 0; i < dev->mtsize; ++i) {
		struct input_mt_slot *ps = &dev->mt[i];
		int id = input_mt_get_value(ps, ABS_MT_TRACKING_ID);

		if (id < 0)
			continue;
		if ((id - oldid) & TRKID_SGN) {
			oldest = ps;
			oldid = id;
		}
		count++;
	}

	input_event(dev, EV_KEY, BTN_TOUCH, count > 0);
	if (use_count)
		input_mt_report_finger_count(dev, count);

	if (oldest) {
		int x = input_mt_get_value(oldest, ABS_MT_POSITION_X);
		int y = input_mt_get_value(oldest, ABS_MT_POSITION_Y);
		int p = input_mt_get_value(oldest, ABS_MT_PRESSURE);

		input_event(dev, EV_ABS, ABS_X, x);
		input_event(dev, EV_ABS, ABS_Y, y);
		input_event(dev, EV_ABS, ABS_PRESSURE, p);
	} else {
		input_event(dev, EV_ABS, ABS_PRESSURE, 0);
	}
}
EXPORT_SYMBOL(input_mt_report_pointer_emulation);

/**
 * input_mt_sync_frame() - synchronize mt frame
 * @dev: input device with allocated MT slots
 *
 * Close the frame and prepare the internal state for a new one.
 * Depending on the flags, marks unused slots as inactive and performs
 * pointer emulation.
 */
void input_mt_sync_frame(struct input_dev *dev)
{
	struct input_mt *mt = input_dev_to_mt(dev);
	unsigned int i;

	if (!mt)
		return;

	if (mt->flags & INPUT_MT_DROP_UNUSED) {
		for (i = 0; i < mt->num_slots; i++) {
			if (mt->slot_frame[i] == mt->frame)
				continue;
			input_mt_slot(dev, i);
			input_event(dev, EV_ABS, ABS_MT_TRACKING_ID, -1);
		}
	}

	input_mt_report_pointer_emulation(dev, (mt->flags & INPUT_MT_POINTER));

	mt->frame++;
}
EXPORT_SYMBOL(input_mt_sync_frame);
