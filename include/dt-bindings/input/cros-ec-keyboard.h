/* SPDX-License-Identifier: GPL-2.0 */
/*
 * This header provides the constants of the standard Chrome OS key matrix
 * for cros-ec keyboard-controller bindings.
 *
 * Copyright (c) 2021 Google, Inc
 */

#ifndef _CROS_EC_KEYBOARD_H
#define _CROS_EC_KEYBOARD_H

#define CROS_STD_TOP_ROW_KEYMAP	\
	MATRIX_KEY(0x00, 0x02, KEY_F1)	\
	MATRIX_KEY(0x03, 0x02, KEY_F2)	\
	MATRIX_KEY(0x02, 0x02, KEY_F3)	\
	MATRIX_KEY(0x01, 0x02, KEY_F4)	\
	MATRIX_KEY(0x03, 0x04, KEY_F5)	\
	MATRIX_KEY(0x02, 0x04, KEY_F6)	\
	MATRIX_KEY(0x01, 0x04, KEY_F7)	\
	MATRIX_KEY(0x02, 0x09, KEY_F8)	\
	MATRIX_KEY(0x01, 0x09, KEY_F9)	\
	MATRIX_KEY(0x00, 0x04, KEY_F10)

#define CROS_STD_MAIN_KEYMAP	\
	MATRIX_KEY(0x00, 0x01, KEY_LEFTMETA)	\
	MATRIX_KEY(0x00, 0x03, KEY_B)		\
	MATRIX_KEY(0x00, 0x05, KEY_RO)		\
	MATRIX_KEY(0x00, 0x06, KEY_N)		\
	MATRIX_KEY(0x00, 0x08, KEY_EQUAL)	\
	MATRIX_KEY(0x00, 0x0a, KEY_RIGHTALT)	\
	MATRIX_KEY(0x01, 0x01, KEY_ESC)		\
	MATRIX_KEY(0x01, 0x03, KEY_G)		\
	MATRIX_KEY(0x01, 0x06, KEY_H)		\
	MATRIX_KEY(0x01, 0x08, KEY_APOSTROPHE)	\
	MATRIX_KEY(0x01, 0x0b, KEY_BACKSPACE)	\
	MATRIX_KEY(0x01, 0x0c, KEY_HENKAN)	\
						\
	MATRIX_KEY(0x02, 0x00, KEY_LEFTCTRL)	\
	MATRIX_KEY(0x02, 0x01, KEY_TAB)		\
	MATRIX_KEY(0x02, 0x03, KEY_T)		\
	MATRIX_KEY(0x02, 0x05, KEY_RIGHTBRACE)	\
	MATRIX_KEY(0x02, 0x06, KEY_Y)		\
	MATRIX_KEY(0x02, 0x07, KEY_102ND)	\
	MATRIX_KEY(0x02, 0x08, KEY_LEFTBRACE)	\
	MATRIX_KEY(0x02, 0x0a, KEY_YEN)		\
						\
	MATRIX_KEY(0x03, 0x00, KEY_LEFTMETA)	\
	MATRIX_KEY(0x03, 0x01, KEY_GRAVE)	\
	MATRIX_KEY(0x03, 0x03, KEY_5)		\
	MATRIX_KEY(0x03, 0x06, KEY_6)		\
	MATRIX_KEY(0x03, 0x08, KEY_MINUS)	\
	MATRIX_KEY(0x03, 0x09, KEY_SLEEP)	\
	MATRIX_KEY(0x03, 0x0b, KEY_BACKSLASH)	\
	MATRIX_KEY(0x03, 0x0c, KEY_MUHENKAN)	\
						\
	MATRIX_KEY(0x04, 0x00, KEY_RIGHTCTRL)	\
	MATRIX_KEY(0x04, 0x01, KEY_A)		\
	MATRIX_KEY(0x04, 0x02, KEY_D)		\
	MATRIX_KEY(0x04, 0x03, KEY_F)		\
	MATRIX_KEY(0x04, 0x04, KEY_S)		\
	MATRIX_KEY(0x04, 0x05, KEY_K)		\
	MATRIX_KEY(0x04, 0x06, KEY_J)		\
	MATRIX_KEY(0x04, 0x08, KEY_SEMICOLON)	\
	MATRIX_KEY(0x04, 0x09, KEY_L)		\
	MATRIX_KEY(0x04, 0x0a, KEY_BACKSLASH)	\
	MATRIX_KEY(0x04, 0x0b, KEY_ENTER)	\
						\
	MATRIX_KEY(0x05, 0x01, KEY_Z)		\
	MATRIX_KEY(0x05, 0x02, KEY_C)		\
	MATRIX_KEY(0x05, 0x03, KEY_V)		\
	MATRIX_KEY(0x05, 0x04, KEY_X)		\
	MATRIX_KEY(0x05, 0x05, KEY_COMMA)	\
	MATRIX_KEY(0x05, 0x06, KEY_M)		\
	MATRIX_KEY(0x05, 0x07, KEY_LEFTSHIFT)	\
	MATRIX_KEY(0x05, 0x08, KEY_SLASH)	\
	MATRIX_KEY(0x05, 0x09, KEY_DOT)		\
	MATRIX_KEY(0x05, 0x0b, KEY_SPACE)	\
						\
	MATRIX_KEY(0x06, 0x01, KEY_1)		\
	MATRIX_KEY(0x06, 0x02, KEY_3)		\
	MATRIX_KEY(0x06, 0x03, KEY_4)		\
	MATRIX_KEY(0x06, 0x04, KEY_2)		\
	MATRIX_KEY(0x06, 0x05, KEY_8)		\
	MATRIX_KEY(0x06, 0x06, KEY_7)		\
	MATRIX_KEY(0x06, 0x08, KEY_0)		\
	MATRIX_KEY(0x06, 0x09, KEY_9)		\
	MATRIX_KEY(0x06, 0x0a, KEY_LEFTALT)	\
	MATRIX_KEY(0x06, 0x0b, KEY_DOWN)	\
	MATRIX_KEY(0x06, 0x0c, KEY_RIGHT)	\
						\
	MATRIX_KEY(0x07, 0x01, KEY_Q)		\
	MATRIX_KEY(0x07, 0x02, KEY_E)		\
	MATRIX_KEY(0x07, 0x03, KEY_R)		\
	MATRIX_KEY(0x07, 0x04, KEY_W)		\
	MATRIX_KEY(0x07, 0x05, KEY_I)		\
	MATRIX_KEY(0x07, 0x06, KEY_U)		\
	MATRIX_KEY(0x07, 0x07, KEY_RIGHTSHIFT)	\
	MATRIX_KEY(0x07, 0x08, KEY_P)		\
	MATRIX_KEY(0x07, 0x09, KEY_O)		\
	MATRIX_KEY(0x07, 0x0b, KEY_UP)		\
	MATRIX_KEY(0x07, 0x0c, KEY_LEFT)

#endif /* _CROS_EC_KEYBOARD_H */
