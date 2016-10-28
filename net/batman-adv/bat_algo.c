/* Copyright (C) 2007-2016  B.A.T.M.A.N. contributors:
 *
 * Marek Lindner, Simon Wunderlich
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "main.h"

#include <linux/errno.h>
#include <linux/list.h>
#include <linux/moduleparam.h>
#include <linux/printk.h>
#include <linux/seq_file.h>
#include <linux/stddef.h>
#include <linux/string.h>

#include "bat_algo.h"

char batadv_routing_algo[20] = "BATMAN_IV";
static struct hlist_head batadv_algo_list;

/**
 * batadv_algo_init - Initialize batman-adv algorithm management data structures
 */
void batadv_algo_init(void)
{
	INIT_HLIST_HEAD(&batadv_algo_list);
}

static struct batadv_algo_ops *batadv_algo_get(char *name)
{
	struct batadv_algo_ops *bat_algo_ops = NULL, *bat_algo_ops_tmp;

	hlist_for_each_entry(bat_algo_ops_tmp, &batadv_algo_list, list) {
		if (strcmp(bat_algo_ops_tmp->name, name) != 0)
			continue;

		bat_algo_ops = bat_algo_ops_tmp;
		break;
	}

	return bat_algo_ops;
}

int batadv_algo_register(struct batadv_algo_ops *bat_algo_ops)
{
	struct batadv_algo_ops *bat_algo_ops_tmp;

	bat_algo_ops_tmp = batadv_algo_get(bat_algo_ops->name);
	if (bat_algo_ops_tmp) {
		pr_info("Trying to register already registered routing algorithm: %s\n",
			bat_algo_ops->name);
		return -EEXIST;
	}

	/* all algorithms must implement all ops (for now) */
	if (!bat_algo_ops->iface.enable ||
	    !bat_algo_ops->iface.disable ||
	    !bat_algo_ops->iface.update_mac ||
	    !bat_algo_ops->iface.primary_set ||
	    !bat_algo_ops->neigh.cmp ||
	    !bat_algo_ops->neigh.is_similar_or_better) {
		pr_info("Routing algo '%s' does not implement required ops\n",
			bat_algo_ops->name);
		return -EINVAL;
	}

	INIT_HLIST_NODE(&bat_algo_ops->list);
	hlist_add_head(&bat_algo_ops->list, &batadv_algo_list);

	return 0;
}

int batadv_algo_select(struct batadv_priv *bat_priv, char *name)
{
	struct batadv_algo_ops *bat_algo_ops;

	bat_algo_ops = batadv_algo_get(name);
	if (!bat_algo_ops)
		return -EINVAL;

	bat_priv->algo_ops = bat_algo_ops;

	return 0;
}

int batadv_algo_seq_print_text(struct seq_file *seq, void *offset)
{
	struct batadv_algo_ops *bat_algo_ops;

	seq_puts(seq, "Available routing algorithms:\n");

	hlist_for_each_entry(bat_algo_ops, &batadv_algo_list, list) {
		seq_printf(seq, " * %s\n", bat_algo_ops->name);
	}

	return 0;
}

static int batadv_param_set_ra(const char *val, const struct kernel_param *kp)
{
	struct batadv_algo_ops *bat_algo_ops;
	char *algo_name = (char *)val;
	size_t name_len = strlen(algo_name);

	if (name_len > 0 && algo_name[name_len - 1] == '\n')
		algo_name[name_len - 1] = '\0';

	bat_algo_ops = batadv_algo_get(algo_name);
	if (!bat_algo_ops) {
		pr_err("Routing algorithm '%s' is not supported\n", algo_name);
		return -EINVAL;
	}

	return param_set_copystring(algo_name, kp);
}

static const struct kernel_param_ops batadv_param_ops_ra = {
	.set = batadv_param_set_ra,
	.get = param_get_string,
};

static struct kparam_string batadv_param_string_ra = {
	.maxlen = sizeof(batadv_routing_algo),
	.string = batadv_routing_algo,
};

module_param_cb(routing_algo, &batadv_param_ops_ra, &batadv_param_string_ra,
		0644);
