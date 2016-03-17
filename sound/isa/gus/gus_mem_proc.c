/*
 *  Copyright (c) by Jaroslav Kysela <perex@perex.cz>
 *  GUS's memory access via proc filesystem
 *
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 */

#include <linux/slab.h>
#include <sound/core.h>
#include <sound/gus.h>
#include <sound/info.h>

struct gus_proc_private {
	int rom;		/* data are in ROM */
	unsigned int address;
	unsigned int size;
	struct snd_gus_card * gus;
};

static ssize_t snd_gf1_mem_proc_dump(struct snd_info_entry *entry,
				     void *file_private_data,
				     struct file *file, char __user *buf,
				     size_t count, loff_t pos)
{
	struct gus_proc_private *priv = entry->private_data;
	struct snd_gus_card *gus = priv->gus;
	int err;

	err = snd_gus_dram_read(gus, buf, pos, count, priv->rom);
	if (err < 0)
		return err;
	return count;
}			

static void snd_gf1_mem_proc_free(struct snd_info_entry *entry)
{
	struct gus_proc_private *priv = entry->private_data;
	kfree(priv);
}

static struct snd_info_entry_ops snd_gf1_mem_proc_ops = {
	.read = snd_gf1_mem_proc_dump,
};

int snd_gf1_mem_proc_init(struct snd_gus_card * gus)
{
	int idx;
	char name[16];
	struct gus_proc_private *priv;
	struct snd_info_entry *entry;

	for (idx = 0; idx < 4; idx++) {
		if (gus->gf1.mem_alloc.banks_8[idx].size > 0) {
			priv = kzalloc(sizeof(*priv), GFP_KERNEL);
			if (priv == NULL)
				return -ENOMEM;
			priv->gus = gus;
			sprintf(name, "gus-ram-%i", idx);
			if (! snd_card_proc_new(gus->card, name, &entry)) {
				entry->content = SNDRV_INFO_CONTENT_DATA;
				entry->private_data = priv;
				entry->private_free = snd_gf1_mem_proc_free;
				entry->c.ops = &snd_gf1_mem_proc_ops;
				priv->address = gus->gf1.mem_alloc.banks_8[idx].address;
				priv->size = entry->size = gus->gf1.mem_alloc.banks_8[idx].size;
			}
		}
	}
	for (idx = 0; idx < 4; idx++) {
		if (gus->gf1.rom_present & (1 << idx)) {
			priv = kzalloc(sizeof(*priv), GFP_KERNEL);
			if (priv == NULL)
				return -ENOMEM;
			priv->rom = 1;
			priv->gus = gus;
			sprintf(name, "gus-rom-%i", idx);
			if (! snd_card_proc_new(gus->card, name, &entry)) {
				entry->content = SNDRV_INFO_CONTENT_DATA;
				entry->private_data = priv;
				entry->private_free = snd_gf1_mem_proc_free;
				entry->c.ops = &snd_gf1_mem_proc_ops;
				priv->address = idx * 4096 * 1024;
				priv->size = entry->size = gus->gf1.rom_memory;
			}
		}
	}
	return 0;
}
