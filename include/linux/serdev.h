/*
 * Copyright (C) 2016-2017 Linaro Ltd., Rob Herring <robh@kernel.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#ifndef _LINUX_SERDEV_H
#define _LINUX_SERDEV_H

#include <linux/types.h>
#include <linux/device.h>

struct serdev_controller;
struct serdev_device;

/*
 * serdev device structures
 */

/**
 * struct serdev_device_ops - Callback operations for a serdev device
 * @receive_buf:	Function called with data received from device.
 * @write_wakeup:	Function called when ready to transmit more data.
 */
struct serdev_device_ops {
	int (*receive_buf)(struct serdev_device *, const unsigned char *, size_t);
	void (*write_wakeup)(struct serdev_device *);
};

/**
 * struct serdev_device - Basic representation of an serdev device
 * @dev:	Driver model representation of the device.
 * @nr:		Device number on serdev bus.
 * @ctrl:	serdev controller managing this device.
 * @ops:	Device operations.
 */
struct serdev_device {
	struct device dev;
	int nr;
	struct serdev_controller *ctrl;
	const struct serdev_device_ops *ops;
};

static inline struct serdev_device *to_serdev_device(struct device *d)
{
	return container_of(d, struct serdev_device, dev);
}

/**
 * struct serdev_device_driver - serdev slave device driver
 * @driver:	serdev device drivers should initialize name field of this
 *		structure.
 * @probe:	binds this driver to a serdev device.
 * @remove:	unbinds this driver from the serdev device.
 */
struct serdev_device_driver {
	struct device_driver driver;
	int	(*probe)(struct serdev_device *);
	void	(*remove)(struct serdev_device *);
};

static inline struct serdev_device_driver *to_serdev_device_driver(struct device_driver *d)
{
	return container_of(d, struct serdev_device_driver, driver);
}

/*
 * serdev controller structures
 */
struct serdev_controller_ops {
	int (*write_buf)(struct serdev_controller *, const unsigned char *, size_t);
	void (*write_flush)(struct serdev_controller *);
	int (*write_room)(struct serdev_controller *);
	int (*open)(struct serdev_controller *);
	void (*close)(struct serdev_controller *);
	void (*set_flow_control)(struct serdev_controller *, bool);
	unsigned int (*set_baudrate)(struct serdev_controller *, unsigned int);
};

/**
 * struct serdev_controller - interface to the serdev controller
 * @dev:	Driver model representation of the device.
 * @nr:		number identifier for this controller/bus.
 * @serdev:	Pointer to slave device for this controller.
 * @ops:	Controller operations.
 */
struct serdev_controller {
	struct device		dev;
	unsigned int		nr;
	struct serdev_device	*serdev;
	const struct serdev_controller_ops *ops;
};

static inline struct serdev_controller *to_serdev_controller(struct device *d)
{
	return container_of(d, struct serdev_controller, dev);
}

static inline void *serdev_device_get_drvdata(const struct serdev_device *serdev)
{
	return dev_get_drvdata(&serdev->dev);
}

static inline void serdev_device_set_drvdata(struct serdev_device *serdev, void *data)
{
	dev_set_drvdata(&serdev->dev, data);
}

/**
 * serdev_device_put() - decrement serdev device refcount
 * @serdev	serdev device.
 */
static inline void serdev_device_put(struct serdev_device *serdev)
{
	if (serdev)
		put_device(&serdev->dev);
}

static inline void serdev_device_set_client_ops(struct serdev_device *serdev,
					      const struct serdev_device_ops *ops)
{
	serdev->ops = ops;
}

static inline
void *serdev_controller_get_drvdata(const struct serdev_controller *ctrl)
{
	return ctrl ? dev_get_drvdata(&ctrl->dev) : NULL;
}

static inline void serdev_controller_set_drvdata(struct serdev_controller *ctrl,
					       void *data)
{
	dev_set_drvdata(&ctrl->dev, data);
}

/**
 * serdev_controller_put() - decrement controller refcount
 * @ctrl	serdev controller.
 */
static inline void serdev_controller_put(struct serdev_controller *ctrl)
{
	if (ctrl)
		put_device(&ctrl->dev);
}

struct serdev_device *serdev_device_alloc(struct serdev_controller *);
int serdev_device_add(struct serdev_device *);
void serdev_device_remove(struct serdev_device *);

struct serdev_controller *serdev_controller_alloc(struct device *, size_t);
int serdev_controller_add(struct serdev_controller *);
void serdev_controller_remove(struct serdev_controller *);

static inline void serdev_controller_write_wakeup(struct serdev_controller *ctrl)
{
	struct serdev_device *serdev = ctrl->serdev;

	if (!serdev || !serdev->ops->write_wakeup)
		return;

	serdev->ops->write_wakeup(ctrl->serdev);
}

static inline int serdev_controller_receive_buf(struct serdev_controller *ctrl,
					      const unsigned char *data,
					      size_t count)
{
	struct serdev_device *serdev = ctrl->serdev;

	if (!serdev || !serdev->ops->receive_buf)
		return -EINVAL;

	return serdev->ops->receive_buf(ctrl->serdev, data, count);
}

#if IS_ENABLED(CONFIG_SERIAL_DEV_BUS)

int serdev_device_open(struct serdev_device *);
void serdev_device_close(struct serdev_device *);
unsigned int serdev_device_set_baudrate(struct serdev_device *, unsigned int);
void serdev_device_set_flow_control(struct serdev_device *, bool);
int serdev_device_write_buf(struct serdev_device *, const unsigned char *, size_t);
void serdev_device_write_flush(struct serdev_device *);
int serdev_device_write_room(struct serdev_device *);

/*
 * serdev device driver functions
 */
int __serdev_device_driver_register(struct serdev_device_driver *, struct module *);
#define serdev_device_driver_register(sdrv) \
	__serdev_device_driver_register(sdrv, THIS_MODULE)

/**
 * serdev_device_driver_unregister() - unregister an serdev client driver
 * @sdrv:	the driver to unregister
 */
static inline void serdev_device_driver_unregister(struct serdev_device_driver *sdrv)
{
	if (sdrv)
		driver_unregister(&sdrv->driver);
}

#define module_serdev_device_driver(__serdev_device_driver) \
	module_driver(__serdev_device_driver, serdev_device_driver_register, \
			serdev_device_driver_unregister)

#else

static inline int serdev_device_open(struct serdev_device *sdev)
{
	return -ENODEV;
}
static inline void serdev_device_close(struct serdev_device *sdev) {}
static inline unsigned int serdev_device_set_baudrate(struct serdev_device *sdev, unsigned int baudrate)
{
	return 0;
}
static inline void serdev_device_set_flow_control(struct serdev_device *sdev, bool enable) {}
static inline int serdev_device_write_buf(struct serdev_device *sdev, const unsigned char *buf, size_t count)
{
	return -ENODEV;
}
static inline void serdev_device_write_flush(struct serdev_device *sdev) {}
static inline int serdev_device_write_room(struct serdev_device *sdev)
{
	return 0;
}

#define serdev_device_driver_register(x)
#define serdev_device_driver_unregister(x)

#endif /* CONFIG_SERIAL_DEV_BUS */

/*
 * serdev hooks into TTY core
 */
struct tty_port;
struct tty_driver;

#ifdef CONFIG_SERIAL_DEV_CTRL_TTYPORT
struct device *serdev_tty_port_register(struct tty_port *port,
					struct device *parent,
					struct tty_driver *drv, int idx);
void serdev_tty_port_unregister(struct tty_port *port);
#else
static inline struct device *serdev_tty_port_register(struct tty_port *port,
					   struct device *parent,
					   struct tty_driver *drv, int idx)
{
	return ERR_PTR(-ENODEV);
}
static inline void serdev_tty_port_unregister(struct tty_port *port) {}
#endif /* CONFIG_SERIAL_DEV_CTRL_TTYPORT */

#endif /*_LINUX_SERDEV_H */
