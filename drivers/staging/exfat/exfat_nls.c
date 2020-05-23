// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  Copyright (C) 2012-2013 Samsung Electronics Co., Ltd.
 */

#include <linux/string.h>
#include <linux/nls.h>
#include "exfat.h"

static u16 bad_uni_chars[] = {
	/* " * / : < > ? \ | */
	0x0022,         0x002A, 0x002F, 0x003A,
	0x003C, 0x003E, 0x003F, 0x005C, 0x007C,
	0
};

static int convert_ch_to_uni(struct nls_table *nls, u16 *uni, u8 *ch,
			     bool *lossy)
{
	int len;

	*uni = 0x0;

	if (ch[0] < 0x80) {
		*uni = (u16)ch[0];
		return 1;
	}

	len = nls->char2uni(ch, NLS_MAX_CHARSET_SIZE, uni);
	if (len < 0) {
		/* conversion failed */
		pr_info("%s: fail to use nls\n", __func__);
		if (lossy)
			*lossy = true;
		*uni = (u16)'_';
		if (!strcmp(nls->charset, "utf8"))
			return 1;
		else
			return 2;
	}

	return len;
}

static int convert_uni_to_ch(struct nls_table *nls, u8 *ch, u16 uni,
			     bool *lossy)
{
	int len;

	ch[0] = 0x0;

	if (uni < 0x0080) {
		ch[0] = (u8)uni;
		return 1;
	}

	len = nls->uni2char(uni, ch, NLS_MAX_CHARSET_SIZE);
	if (len < 0) {
		/* conversion failed */
		pr_info("%s: fail to use nls\n", __func__);
		if (lossy)
			*lossy = true;
		ch[0] = '_';
		return 1;
	}

	return len;
}

u16 nls_upper(struct super_block *sb, u16 a)
{
	struct fs_info_t *p_fs = &(EXFAT_SB(sb)->fs_info);

	if (EXFAT_SB(sb)->options.casesensitive)
		return a;
	if (p_fs->vol_utbl && p_fs->vol_utbl[get_col_index(a)])
		return p_fs->vol_utbl[get_col_index(a)][get_row_index(a)];
	else
		return a;
}

static u16 *nls_wstrchr(u16 *str, u16 wchar)
{
	while (*str) {
		if (*(str++) == wchar)
			return str;
	}

	return NULL;
}

int nls_uniname_cmp(struct super_block *sb, u16 *a, u16 *b)
{
	int i;

	for (i = 0; i < MAX_NAME_LENGTH; i++, a++, b++) {
		if (nls_upper(sb, *a) != nls_upper(sb, *b))
			return 1;
		if (*a == 0x0)
			return 0;
	}
	return 0;
}

void nls_uniname_to_cstring(struct super_block *sb, u8 *p_cstring,
			    struct uni_name_t *p_uniname)
{
	int i, j, len;
	u8 buf[MAX_CHARSET_SIZE];
	u16 *uniname = p_uniname->name;
	struct nls_table *nls = EXFAT_SB(sb)->nls_io;

	if (!nls) {
		len = utf16s_to_utf8s(uniname, MAX_NAME_LENGTH,
				      UTF16_HOST_ENDIAN, p_cstring,
				      MAX_NAME_LENGTH);
		p_cstring[len] = 0;
		return;
	}

	i = 0;
	while (i < (MAX_NAME_LENGTH - 1)) {
		if (*uniname == (u16)'\0')
			break;

		len = convert_uni_to_ch(nls, buf, *uniname, NULL);

		if (len > 1) {
			for (j = 0; j < len; j++)
				*p_cstring++ = (char)*(buf + j);
		} else { /* len == 1 */
			*p_cstring++ = (char)*buf;
		}

		uniname++;
		i++;
	}

	*p_cstring = '\0';
}

void nls_cstring_to_uniname(struct super_block *sb,
			    struct uni_name_t *p_uniname, u8 *p_cstring,
			    bool *p_lossy)
{
	int i, j;
	bool lossy = false;
	u8 *end_of_name;
	u8 upname[MAX_NAME_LENGTH * 2];
	u16 *uniname = p_uniname->name;
	struct nls_table *nls = EXFAT_SB(sb)->nls_io;

	/* strip all trailing spaces */
	end_of_name = p_cstring + strlen(p_cstring);

	while (*(--end_of_name) == ' ') {
		if (end_of_name < p_cstring)
			break;
	}
	*(++end_of_name) = '\0';

	if (strcmp(p_cstring, ".") && strcmp(p_cstring, "..")) {
		/* strip all trailing periods */
		while (*(--end_of_name) == '.') {
			if (end_of_name < p_cstring)
				break;
		}
		*(++end_of_name) = '\0';
	}

	if (*p_cstring == '\0')
		lossy = true;

	if (!nls) {
		i = utf8s_to_utf16s(p_cstring, MAX_NAME_LENGTH,
				    UTF16_HOST_ENDIAN, uniname,
				    MAX_NAME_LENGTH);
		for (j = 0; j < i; j++)
			SET16_A(upname + j * 2, nls_upper(sb, uniname[j]));
		uniname[i] = '\0';
	} else {
		i = 0;
		j = 0;
		while (j < (MAX_NAME_LENGTH - 1)) {
			if (*(p_cstring + i) == '\0')
				break;

			i += convert_ch_to_uni(nls, uniname,
					       (u8 *)(p_cstring + i), &lossy);

			if ((*uniname < 0x0020) ||
			    nls_wstrchr(bad_uni_chars, *uniname))
				lossy = true;

			SET16_A(upname + j * 2, nls_upper(sb, *uniname));

			uniname++;
			j++;
		}

		if (*(p_cstring + i) != '\0')
			lossy = true;
		*uniname = (u16)'\0';
	}

	p_uniname->name_len = j;
	p_uniname->name_hash = calc_checksum_2byte(upname, j << 1, 0,
						   CS_DEFAULT);

	if (p_lossy)
		*p_lossy = lossy;
}
