/*
 *  Driver for the Conexant CX23885/7/8 PCIe bridge
 *
 *  Copyright (C) 2010  Andy Walls <awalls@md.metrocast.net>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 *  02110-1301, USA.
 */

#ifndef _CX23885_VIDEO_H_
#define _CX23885_VIDEO_H_
int cx23885_flatiron_write(struct cx23885_dev *dev, u8 reg, u8 data);
u8 cx23885_flatiron_read(struct cx23885_dev *dev, u8 reg);
#endif
