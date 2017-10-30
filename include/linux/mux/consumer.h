/*
 * mux/consumer.h - definitions for the multiplexer consumer interface
 *
 * Copyright (C) 2017 Axentia Technologies AB
 *
 * Author: Peter Rosin <peda@axentia.se>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _LINUX_MUX_CONSUMER_H
#define _LINUX_MUX_CONSUMER_H

struct device;
struct mux_control;

unsigned int mux_control_states(struct mux_control *mux);
int __must_check mux_control_select(struct mux_control *mux,
				    unsigned int state);
int __must_check mux_control_try_select(struct mux_control *mux,
					unsigned int state);
int mux_control_deselect(struct mux_control *mux);

struct mux_control *mux_control_get(struct device *dev, const char *mux_name);
void mux_control_put(struct mux_control *mux);

struct mux_control *devm_mux_control_get(struct device *dev,
					 const char *mux_name);

#endif /* _LINUX_MUX_CONSUMER_H */
