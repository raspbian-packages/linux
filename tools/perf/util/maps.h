/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PERF_MAPS_H
#define __PERF_MAPS_H

#include <linux/refcount.h>
#include <linux/rbtree.h>
#include <stdio.h>
#include <stdbool.h>
#include <linux/types.h>
#include "rwsem.h"
#include <internal/rc_check.h>

struct ref_reloc_sym;
struct machine;
struct map;
struct maps;

struct map_list_node {
	struct list_head node;
	struct map *map;
};

static inline struct map_list_node *map_list_node__new(void)
{
	return malloc(sizeof(struct map_list_node));
}

struct map *maps__find(struct maps *maps, u64 addr);

DECLARE_RC_STRUCT(maps) {
	struct rb_root      entries;
	struct rw_semaphore lock;
	struct machine	 *machine;
	struct map	 *last_search_by_name;
	struct map	 **maps_by_name;
	refcount_t	 refcnt;
	unsigned int	 nr_maps;
	unsigned int	 nr_maps_allocated;
#ifdef HAVE_LIBUNWIND_SUPPORT
	void				*addr_space;
	const struct unwind_libunwind_ops *unwind_libunwind_ops;
#endif
};

#define KMAP_NAME_LEN 256

struct kmap {
	struct ref_reloc_sym *ref_reloc_sym;
	struct maps	     *kmaps;
	char		     name[KMAP_NAME_LEN];
};

struct maps *maps__new(struct machine *machine);
bool maps__empty(struct maps *maps);
int maps__copy_from(struct maps *maps, struct maps *parent);

struct maps *maps__get(struct maps *maps);
void maps__put(struct maps *maps);

static inline void __maps__zput(struct maps **map)
{
	maps__put(*map);
	*map = NULL;
}

#define maps__zput(map) __maps__zput(&map)

/* Iterate over map calling cb for each entry. */
int maps__for_each_map(struct maps *maps, int (*cb)(struct map *map, void *data), void *data);
/* Iterate over map removing an entry if cb returns true. */
void maps__remove_maps(struct maps *maps, bool (*cb)(struct map *map, void *data), void *data);

static inline struct machine *maps__machine(struct maps *maps)
{
	return RC_CHK_ACCESS(maps)->machine;
}

static inline unsigned int maps__nr_maps(const struct maps *maps)
{
	return RC_CHK_ACCESS(maps)->nr_maps;
}

static inline refcount_t *maps__refcnt(struct maps *maps)
{
	return &RC_CHK_ACCESS(maps)->refcnt;
}

#ifdef HAVE_LIBUNWIND_SUPPORT
static inline void *maps__addr_space(struct maps *maps)
{
	return RC_CHK_ACCESS(maps)->addr_space;
}

static inline const struct unwind_libunwind_ops *maps__unwind_libunwind_ops(const struct maps *maps)
{
	return RC_CHK_ACCESS(maps)->unwind_libunwind_ops;
}
#endif

size_t maps__fprintf(struct maps *maps, FILE *fp);

int maps__insert(struct maps *maps, struct map *map);
void maps__remove(struct maps *maps, struct map *map);

struct symbol *maps__find_symbol(struct maps *maps, u64 addr, struct map **mapp);
struct symbol *maps__find_symbol_by_name(struct maps *maps, const char *name, struct map **mapp);

struct addr_map_symbol;

int maps__find_ams(struct maps *maps, struct addr_map_symbol *ams);

int maps__fixup_overlap_and_insert(struct maps *maps, struct map *new);

struct map *maps__find_by_name(struct maps *maps, const char *name);

struct map *maps__find_next_entry(struct maps *maps, struct map *map);

int maps__merge_in(struct maps *kmaps, struct map *new_map);

void __maps__sort_by_name(struct maps *maps);

void maps__fixup_end(struct maps *maps);

void maps__load_first(struct maps *maps);

#endif // __PERF_MAPS_H
