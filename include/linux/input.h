/*
 * Copyright (c) 1999-2002 Vojtech Pavlik
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */
#ifndef _INPUT_H
#define _INPUT_H

#include <linux/time.h>
#include <linux/list.h>
#include <uapi/linux/input.h>
/* Implementation details, userspace should not care about these */
#define ABS_MT_FIRST		ABS_MT_TOUCH_MAJOR
#define ABS_MT_LAST		ABS_MT_TOOL_Y

/*
 * In-kernel definitions.
 */

#include <linux/device.h>
#include <linux/fs.h>
#include <linux/timer.h>
#include <linux/mod_devicetable.h>

/**
 * struct input_value - input value representation
 * @type: type of value (EV_KEY, EV_ABS, etc)
 * @code: the value code
 * @value: the value
 */
struct input_value {
	__u16 type;
	__u16 code;
	__s32 value;
};

/**
 * struct input_dev - represents an input device
 * @name: name of the device
 * @phys: physical path to the device in the system hierarchy
 * @uniq: unique identification code for the device (if device has it)
 * @id: id of the device (struct input_id)
 * @propbit: bitmap of device properties and quirks
 * @evbit: bitmap of types of events supported by the device (EV_KEY,
 *	EV_REL, etc.)
 * @keybit: bitmap of keys/buttons this device has
 * @relbit: bitmap of relative axes for the device
 * @absbit: bitmap of absolute axes for the device
 * @mscbit: bitmap of miscellaneous events supported by the device
 * @ledbit: bitmap of leds present on the device
 * @sndbit: bitmap of sound effects supported by the device
 * @ffbit: bitmap of force feedback effects supported by the device
 * @swbit: bitmap of switches present on the device
 * @hint_events_per_packet: average number of events generated by the
 *	device in a packet (between EV_SYN/SYN_REPORT events). Used by
 *	event handlers to estimate size of the buffer needed to hold
 *	events.
 * @keycodemax: size of keycode table
 * @keycodesize: size of elements in keycode table
 * @keycode: map of scancodes to keycodes for this device
 * @getkeycode: optional legacy method to retrieve current keymap.
 * @setkeycode: optional method to alter current keymap, used to implement
 *	sparse keymaps. If not supplied default mechanism will be used.
 *	The method is being called while holding event_lock and thus must
 *	not sleep
 * @ff: force feedback structure associated with the device if device
 *	supports force feedback effects
 * @repeat_key: stores key code of the last key pressed; used to implement
 *	software autorepeat
 * @timer: timer for software autorepeat
 * @rep: current values for autorepeat parameters (delay, rate)
 * @mt: pointer to multitouch state
 * @absinfo: array of &struct input_absinfo elements holding information
 *	about absolute axes (current value, min, max, flat, fuzz,
 *	resolution)
 * @key: reflects current state of device's keys/buttons
 * @led: reflects current state of device's LEDs
 * @snd: reflects current state of sound effects
 * @sw: reflects current state of device's switches
 * @open: this method is called when the very first user calls
 *	input_open_device(). The driver must prepare the device
 *	to start generating events (start polling thread,
 *	request an IRQ, submit URB, etc.)
 * @close: this method is called when the very last user calls
 *	input_close_device().
 * @flush: purges the device. Most commonly used to get rid of force
 *	feedback effects loaded into the device when disconnecting
 *	from it
 * @event: event handler for events sent _to_ the device, like EV_LED
 *	or EV_SND. The device is expected to carry out the requested
 *	action (turn on a LED, play sound, etc.) The call is protected
 *	by @event_lock and must not sleep
 * @grab: input handle that currently has the device grabbed (via
 *	EVIOCGRAB ioctl). When a handle grabs a device it becomes sole
 *	recipient for all input events coming from the device
 * @event_lock: this spinlock is is taken when input core receives
 *	and processes a new event for the device (in input_event()).
 *	Code that accesses and/or modifies parameters of a device
 *	(such as keymap or absmin, absmax, absfuzz, etc.) after device
 *	has been registered with input core must take this lock.
 * @mutex: serializes calls to open(), close() and flush() methods
 * @users: stores number of users (input handlers) that opened this
 *	device. It is used by input_open_device() and input_close_device()
 *	to make sure that dev->open() is only called when the first
 *	user opens device and dev->close() is called when the very
 *	last user closes the device
 * @going_away: marks devices that are in a middle of unregistering and
 *	causes input_open_device*() fail with -ENODEV.
 * @dev: driver model's view of this device
 * @h_list: list of input handles associated with the device. When
 *	accessing the list dev->mutex must be held
 * @node: used to place the device onto input_dev_list
 * @num_vals: number of values queued in the current frame
 * @max_vals: maximum number of values queued in a frame
 * @vals: array of values queued in the current frame
 * @devres_managed: indicates that devices is managed with devres framework
 *	and needs not be explicitly unregistered or freed.
 */
struct input_dev {
	const char *name;
	const char *phys;
	const char *uniq;
	struct input_id id;

	unsigned long propbit[BITS_TO_LONGS(INPUT_PROP_CNT)];

	unsigned long evbit[BITS_TO_LONGS(EV_CNT)];
	unsigned long keybit[BITS_TO_LONGS(KEY_CNT)];
	unsigned long relbit[BITS_TO_LONGS(REL_CNT)];
	unsigned long absbit[BITS_TO_LONGS(ABS_CNT)];
	unsigned long mscbit[BITS_TO_LONGS(MSC_CNT)];
	unsigned long ledbit[BITS_TO_LONGS(LED_CNT)];
	unsigned long sndbit[BITS_TO_LONGS(SND_CNT)];
	unsigned long ffbit[BITS_TO_LONGS(FF_CNT)];
	unsigned long swbit[BITS_TO_LONGS(SW_CNT)];

	unsigned int hint_events_per_packet;

	unsigned int keycodemax;
	unsigned int keycodesize;
	void *keycode;

	int (*setkeycode)(struct input_dev *dev,
			  const struct input_keymap_entry *ke,
			  unsigned int *old_keycode);
	int (*getkeycode)(struct input_dev *dev,
			  struct input_keymap_entry *ke);

	struct ff_device *ff;

	unsigned int repeat_key;
	struct timer_list timer;

	int rep[REP_CNT];

	struct input_mt *mt;

	struct input_absinfo *absinfo;

	unsigned long key[BITS_TO_LONGS(KEY_CNT)];
	unsigned long led[BITS_TO_LONGS(LED_CNT)];
	unsigned long snd[BITS_TO_LONGS(SND_CNT)];
	unsigned long sw[BITS_TO_LONGS(SW_CNT)];

	int (*open)(struct input_dev *dev);
	void (*close)(struct input_dev *dev);
	int (*flush)(struct input_dev *dev, struct file *file);
	int (*event)(struct input_dev *dev, unsigned int type, unsigned int code, int value);

	struct input_handle __rcu *grab;

	spinlock_t event_lock;
	struct mutex mutex;

	unsigned int users;
	bool going_away;

	struct device dev;

	struct list_head	h_list;
	struct list_head	node;

	unsigned int num_vals;
	unsigned int max_vals;
	struct input_value *vals;

	bool devres_managed;
};
#define to_input_dev(d) container_of(d, struct input_dev, dev)

/*
 * Verify that we are in sync with input_device_id mod_devicetable.h #defines
 */

#if EV_MAX != INPUT_DEVICE_ID_EV_MAX
#error "EV_MAX and INPUT_DEVICE_ID_EV_MAX do not match"
#endif

#if KEY_MIN_INTERESTING != INPUT_DEVICE_ID_KEY_MIN_INTERESTING
#error "KEY_MIN_INTERESTING and INPUT_DEVICE_ID_KEY_MIN_INTERESTING do not match"
#endif

#if KEY_MAX != INPUT_DEVICE_ID_KEY_MAX
#error "KEY_MAX and INPUT_DEVICE_ID_KEY_MAX do not match"
#endif

#if REL_MAX != INPUT_DEVICE_ID_REL_MAX
#error "REL_MAX and INPUT_DEVICE_ID_REL_MAX do not match"
#endif

#if ABS_MAX != INPUT_DEVICE_ID_ABS_MAX
#error "ABS_MAX and INPUT_DEVICE_ID_ABS_MAX do not match"
#endif

#if MSC_MAX != INPUT_DEVICE_ID_MSC_MAX
#error "MSC_MAX and INPUT_DEVICE_ID_MSC_MAX do not match"
#endif

#if LED_MAX != INPUT_DEVICE_ID_LED_MAX
#error "LED_MAX and INPUT_DEVICE_ID_LED_MAX do not match"
#endif

#if SND_MAX != INPUT_DEVICE_ID_SND_MAX
#error "SND_MAX and INPUT_DEVICE_ID_SND_MAX do not match"
#endif

#if FF_MAX != INPUT_DEVICE_ID_FF_MAX
#error "FF_MAX and INPUT_DEVICE_ID_FF_MAX do not match"
#endif

#if SW_MAX != INPUT_DEVICE_ID_SW_MAX
#error "SW_MAX and INPUT_DEVICE_ID_SW_MAX do not match"
#endif

#define INPUT_DEVICE_ID_MATCH_DEVICE \
	(INPUT_DEVICE_ID_MATCH_BUS | INPUT_DEVICE_ID_MATCH_VENDOR | INPUT_DEVICE_ID_MATCH_PRODUCT)
#define INPUT_DEVICE_ID_MATCH_DEVICE_AND_VERSION \
	(INPUT_DEVICE_ID_MATCH_DEVICE | INPUT_DEVICE_ID_MATCH_VERSION)

struct input_handle;

/**
 * struct input_handler - implements one of interfaces for input devices
 * @private: driver-specific data
 * @event: event handler. This method is being called by input core with
 *	interrupts disabled and dev->event_lock spinlock held and so
 *	it may not sleep
 * @events: event sequence handler. This method is being called by
 *	input core with interrupts disabled and dev->event_lock
 *	spinlock held and so it may not sleep
 * @filter: similar to @event; separates normal event handlers from
 *	"filters".
 * @match: called after comparing device's id with handler's id_table
 *	to perform fine-grained matching between device and handler
 * @connect: called when attaching a handler to an input device
 * @disconnect: disconnects a handler from input device
 * @start: starts handler for given handle. This function is called by
 *	input core right after connect() method and also when a process
 *	that "grabbed" a device releases it
 * @legacy_minors: set to %true by drivers using legacy minor ranges
 * @minor: beginning of range of 32 legacy minors for devices this driver
 *	can provide
 * @name: name of the handler, to be shown in /proc/bus/input/handlers
 * @id_table: pointer to a table of input_device_ids this driver can
 *	handle
 * @h_list: list of input handles associated with the handler
 * @node: for placing the driver onto input_handler_list
 *
 * Input handlers attach to input devices and create input handles. There
 * are likely several handlers attached to any given input device at the
 * same time. All of them will get their copy of input event generated by
 * the device.
 *
 * The very same structure is used to implement input filters. Input core
 * allows filters to run first and will not pass event to regular handlers
 * if any of the filters indicate that the event should be filtered (by
 * returning %true from their filter() method).
 *
 * Note that input core serializes calls to connect() and disconnect()
 * methods.
 */
struct input_handler {

	void *private;

	void (*event)(struct input_handle *handle, unsigned int type, unsigned int code, int value);
	void (*events)(struct input_handle *handle,
		       const struct input_value *vals, unsigned int count);
	bool (*filter)(struct input_handle *handle, unsigned int type, unsigned int code, int value);
	bool (*match)(struct input_handler *handler, struct input_dev *dev);
	int (*connect)(struct input_handler *handler, struct input_dev *dev, const struct input_device_id *id);
	void (*disconnect)(struct input_handle *handle);
	void (*start)(struct input_handle *handle);

	bool legacy_minors;
	int minor;
	const char *name;

	const struct input_device_id *id_table;

	struct list_head	h_list;
	struct list_head	node;
};

/**
 * struct input_handle - links input device with an input handler
 * @private: handler-specific data
 * @open: counter showing whether the handle is 'open', i.e. should deliver
 *	events from its device
 * @name: name given to the handle by handler that created it
 * @dev: input device the handle is attached to
 * @handler: handler that works with the device through this handle
 * @d_node: used to put the handle on device's list of attached handles
 * @h_node: used to put the handle on handler's list of handles from which
 *	it gets events
 */
struct input_handle {

	void *private;

	int open;
	const char *name;

	struct input_dev *dev;
	struct input_handler *handler;

	struct list_head	d_node;
	struct list_head	h_node;
};

struct input_dev __must_check *input_allocate_device(void);
struct input_dev __must_check *devm_input_allocate_device(struct device *);
void input_free_device(struct input_dev *dev);

static inline struct input_dev *input_get_device(struct input_dev *dev)
{
	return dev ? to_input_dev(get_device(&dev->dev)) : NULL;
}

static inline void input_put_device(struct input_dev *dev)
{
	if (dev)
		put_device(&dev->dev);
}

static inline void *input_get_drvdata(struct input_dev *dev)
{
	return dev_get_drvdata(&dev->dev);
}

static inline void input_set_drvdata(struct input_dev *dev, void *data)
{
	dev_set_drvdata(&dev->dev, data);
}

int __must_check input_register_device(struct input_dev *);
void input_unregister_device(struct input_dev *);

void input_reset_device(struct input_dev *);

int __must_check input_register_handler(struct input_handler *);
void input_unregister_handler(struct input_handler *);

int __must_check input_get_new_minor(int legacy_base, unsigned int legacy_num,
				     bool allow_dynamic);
void input_free_minor(unsigned int minor);

int input_handler_for_each_handle(struct input_handler *, void *data,
				  int (*fn)(struct input_handle *, void *));

int input_register_handle(struct input_handle *);
void input_unregister_handle(struct input_handle *);

int input_grab_device(struct input_handle *);
void input_release_device(struct input_handle *);

int input_open_device(struct input_handle *);
void input_close_device(struct input_handle *);

int input_flush_device(struct input_handle *handle, struct file *file);

void input_event(struct input_dev *dev, unsigned int type, unsigned int code, int value);
void input_inject_event(struct input_handle *handle, unsigned int type, unsigned int code, int value);

static inline void input_report_key(struct input_dev *dev, unsigned int code, int value)
{
	input_event(dev, EV_KEY, code, !!value);
}

static inline void input_report_rel(struct input_dev *dev, unsigned int code, int value)
{
	input_event(dev, EV_REL, code, value);
}

static inline void input_report_abs(struct input_dev *dev, unsigned int code, int value)
{
	input_event(dev, EV_ABS, code, value);
}

static inline void input_report_ff_status(struct input_dev *dev, unsigned int code, int value)
{
	input_event(dev, EV_FF_STATUS, code, value);
}

static inline void input_report_switch(struct input_dev *dev, unsigned int code, int value)
{
	input_event(dev, EV_SW, code, !!value);
}

static inline void input_sync(struct input_dev *dev)
{
	input_event(dev, EV_SYN, SYN_REPORT, 0);
}

static inline void input_mt_sync(struct input_dev *dev)
{
	input_event(dev, EV_SYN, SYN_MT_REPORT, 0);
}

void input_set_capability(struct input_dev *dev, unsigned int type, unsigned int code);

/**
 * input_set_events_per_packet - tell handlers about the driver event rate
 * @dev: the input device used by the driver
 * @n_events: the average number of events between calls to input_sync()
 *
 * If the event rate sent from a device is unusually large, use this
 * function to set the expected event rate. This will allow handlers
 * to set up an appropriate buffer size for the event stream, in order
 * to minimize information loss.
 */
static inline void input_set_events_per_packet(struct input_dev *dev, int n_events)
{
	dev->hint_events_per_packet = n_events;
}

void input_alloc_absinfo(struct input_dev *dev);
void input_set_abs_params(struct input_dev *dev, unsigned int axis,
			  int min, int max, int fuzz, int flat);

#define INPUT_GENERATE_ABS_ACCESSORS(_suffix, _item)			\
static inline int input_abs_get_##_suffix(struct input_dev *dev,	\
					  unsigned int axis)		\
{									\
	return dev->absinfo ? dev->absinfo[axis]._item : 0;		\
}									\
									\
static inline void input_abs_set_##_suffix(struct input_dev *dev,	\
					   unsigned int axis, int val)	\
{									\
	input_alloc_absinfo(dev);					\
	if (dev->absinfo)						\
		dev->absinfo[axis]._item = val;				\
}

INPUT_GENERATE_ABS_ACCESSORS(val, value)
INPUT_GENERATE_ABS_ACCESSORS(min, minimum)
INPUT_GENERATE_ABS_ACCESSORS(max, maximum)
INPUT_GENERATE_ABS_ACCESSORS(fuzz, fuzz)
INPUT_GENERATE_ABS_ACCESSORS(flat, flat)
INPUT_GENERATE_ABS_ACCESSORS(res, resolution)

int input_scancode_to_scalar(const struct input_keymap_entry *ke,
			     unsigned int *scancode);

int input_get_keycode(struct input_dev *dev, struct input_keymap_entry *ke);
int input_set_keycode(struct input_dev *dev,
		      const struct input_keymap_entry *ke);

extern struct class input_class;

/**
 * struct ff_device - force-feedback part of an input device
 * @upload: Called to upload an new effect into device
 * @erase: Called to erase an effect from device
 * @playback: Called to request device to start playing specified effect
 * @set_gain: Called to set specified gain
 * @set_autocenter: Called to auto-center device
 * @destroy: called by input core when parent input device is being
 *	destroyed
 * @private: driver-specific data, will be freed automatically
 * @ffbit: bitmap of force feedback capabilities truly supported by
 *	device (not emulated like ones in input_dev->ffbit)
 * @mutex: mutex for serializing access to the device
 * @max_effects: maximum number of effects supported by device
 * @effects: pointer to an array of effects currently loaded into device
 * @effect_owners: array of effect owners; when file handle owning
 *	an effect gets closed the effect is automatically erased
 *
 * Every force-feedback device must implement upload() and playback()
 * methods; erase() is optional. set_gain() and set_autocenter() need
 * only be implemented if driver sets up FF_GAIN and FF_AUTOCENTER
 * bits.
 *
 * Note that playback(), set_gain() and set_autocenter() are called with
 * dev->event_lock spinlock held and interrupts off and thus may not
 * sleep.
 */
struct ff_device {
	int (*upload)(struct input_dev *dev, struct ff_effect *effect,
		      struct ff_effect *old);
	int (*erase)(struct input_dev *dev, int effect_id);

	int (*playback)(struct input_dev *dev, int effect_id, int value);
	void (*set_gain)(struct input_dev *dev, u16 gain);
	void (*set_autocenter)(struct input_dev *dev, u16 magnitude);

	void (*destroy)(struct ff_device *);

	void *private;

	unsigned long ffbit[BITS_TO_LONGS(FF_CNT)];

	struct mutex mutex;

	int max_effects;
	struct ff_effect *effects;
	struct file *effect_owners[];
};

int input_ff_create(struct input_dev *dev, unsigned int max_effects);
void input_ff_destroy(struct input_dev *dev);

int input_ff_event(struct input_dev *dev, unsigned int type, unsigned int code, int value);

int input_ff_upload(struct input_dev *dev, struct ff_effect *effect, struct file *file);
int input_ff_erase(struct input_dev *dev, int effect_id, struct file *file);
int input_ff_flush(struct input_dev *dev, struct file *file);

int input_ff_create_memless(struct input_dev *dev, void *data,
		int (*play_effect)(struct input_dev *, void *, struct ff_effect *));

#endif
