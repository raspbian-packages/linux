/*
 * Copyright IBM Corporation, 2012
 * Author Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2.1 of the GNU Lesser General Public License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

#ifndef _LINUX_HUGETLB_CGROUP_H
#define _LINUX_HUGETLB_CGROUP_H

#include <linux/mmdebug.h>

struct hugetlb_cgroup;
struct resv_map;
struct file_region;

#ifdef CONFIG_CGROUP_HUGETLB
/*
 * Minimum page order trackable by hugetlb cgroup.
 * At least 4 pages are necessary for all the tracking information.
 * The second tail page (hpage[SUBPAGE_INDEX_CGROUP]) is the fault
 * usage cgroup. The third tail page (hpage[SUBPAGE_INDEX_CGROUP_RSVD])
 * is the reservation usage cgroup.
 */
#define HUGETLB_CGROUP_MIN_ORDER order_base_2(__MAX_CGROUP_SUBPAGE_INDEX + 1)

enum hugetlb_memory_event {
	HUGETLB_MAX,
	HUGETLB_NR_MEMORY_EVENTS,
};

struct hugetlb_cgroup_per_node {
	/* hugetlb usage in pages over all hstates. */
	unsigned long usage[HUGE_MAX_HSTATE];
};

struct hugetlb_cgroup {
	struct cgroup_subsys_state css;

	/*
	 * the counter to account for hugepages from hugetlb.
	 */
	struct page_counter hugepage[HUGE_MAX_HSTATE];

	/*
	 * the counter to account for hugepage reservations from hugetlb.
	 */
	struct page_counter rsvd_hugepage[HUGE_MAX_HSTATE];

	atomic_long_t events[HUGE_MAX_HSTATE][HUGETLB_NR_MEMORY_EVENTS];
	atomic_long_t events_local[HUGE_MAX_HSTATE][HUGETLB_NR_MEMORY_EVENTS];

	/* Handle for "hugetlb.events" */
	struct cgroup_file events_file[HUGE_MAX_HSTATE];

	/* Handle for "hugetlb.events.local" */
	struct cgroup_file events_local_file[HUGE_MAX_HSTATE];

	struct hugetlb_cgroup_per_node *nodeinfo[];
};

static inline struct hugetlb_cgroup *
__hugetlb_cgroup_from_folio(struct folio *folio, bool rsvd)
{
	struct page *tail;

	VM_BUG_ON_FOLIO(!folio_test_hugetlb(folio), folio);
	if (folio_order(folio) < HUGETLB_CGROUP_MIN_ORDER)
		return NULL;

	if (rsvd) {
		tail = folio_page(folio, SUBPAGE_INDEX_CGROUP_RSVD);
		return (void *)page_private(tail);
	}

	else {
		tail = folio_page(folio, SUBPAGE_INDEX_CGROUP);
		return (void *)page_private(tail);
	}
}

static inline struct hugetlb_cgroup *hugetlb_cgroup_from_folio(struct folio *folio)
{
	return __hugetlb_cgroup_from_folio(folio, false);
}

static inline struct hugetlb_cgroup *
hugetlb_cgroup_from_folio_rsvd(struct folio *folio)
{
	return __hugetlb_cgroup_from_folio(folio, true);
}

static inline void __set_hugetlb_cgroup(struct folio *folio,
				       struct hugetlb_cgroup *h_cg, bool rsvd)
{
	VM_BUG_ON_FOLIO(!folio_test_hugetlb(folio), folio);

	if (folio_order(folio) < HUGETLB_CGROUP_MIN_ORDER)
		return;
	if (rsvd)
		set_page_private(folio_page(folio, SUBPAGE_INDEX_CGROUP_RSVD),
				 (unsigned long)h_cg);
	else
		set_page_private(folio_page(folio, SUBPAGE_INDEX_CGROUP),
				 (unsigned long)h_cg);
}

static inline void set_hugetlb_cgroup(struct page *page,
				     struct hugetlb_cgroup *h_cg)
{
	__set_hugetlb_cgroup(page_folio(page), h_cg, false);
}

static inline void set_hugetlb_cgroup_rsvd(struct page *page,
					  struct hugetlb_cgroup *h_cg)
{
	__set_hugetlb_cgroup(page_folio(page), h_cg, true);
}

static inline bool hugetlb_cgroup_disabled(void)
{
	return !cgroup_subsys_enabled(hugetlb_cgrp_subsys);
}

static inline void hugetlb_cgroup_put_rsvd_cgroup(struct hugetlb_cgroup *h_cg)
{
	css_put(&h_cg->css);
}

static inline void resv_map_dup_hugetlb_cgroup_uncharge_info(
						struct resv_map *resv_map)
{
	if (resv_map->css)
		css_get(resv_map->css);
}

static inline void resv_map_put_hugetlb_cgroup_uncharge_info(
						struct resv_map *resv_map)
{
	if (resv_map->css)
		css_put(resv_map->css);
}

extern int hugetlb_cgroup_charge_cgroup(int idx, unsigned long nr_pages,
					struct hugetlb_cgroup **ptr);
extern int hugetlb_cgroup_charge_cgroup_rsvd(int idx, unsigned long nr_pages,
					     struct hugetlb_cgroup **ptr);
extern void hugetlb_cgroup_commit_charge(int idx, unsigned long nr_pages,
					 struct hugetlb_cgroup *h_cg,
					 struct page *page);
extern void hugetlb_cgroup_commit_charge_rsvd(int idx, unsigned long nr_pages,
					      struct hugetlb_cgroup *h_cg,
					      struct page *page);
extern void hugetlb_cgroup_uncharge_folio(int idx, unsigned long nr_pages,
					 struct folio *folio);
extern void hugetlb_cgroup_uncharge_folio_rsvd(int idx, unsigned long nr_pages,
					      struct folio *folio);

extern void hugetlb_cgroup_uncharge_cgroup(int idx, unsigned long nr_pages,
					   struct hugetlb_cgroup *h_cg);
extern void hugetlb_cgroup_uncharge_cgroup_rsvd(int idx, unsigned long nr_pages,
						struct hugetlb_cgroup *h_cg);
extern void hugetlb_cgroup_uncharge_counter(struct resv_map *resv,
					    unsigned long start,
					    unsigned long end);

extern void hugetlb_cgroup_uncharge_file_region(struct resv_map *resv,
						struct file_region *rg,
						unsigned long nr_pages,
						bool region_del);

extern void hugetlb_cgroup_file_init(void) __init;
extern void hugetlb_cgroup_migrate(struct page *oldhpage,
				   struct page *newhpage);

#else
static inline void hugetlb_cgroup_uncharge_file_region(struct resv_map *resv,
						       struct file_region *rg,
						       unsigned long nr_pages,
						       bool region_del)
{
}

static inline struct hugetlb_cgroup *hugetlb_cgroup_from_folio(struct folio *folio)
{
	return NULL;
}

static inline struct hugetlb_cgroup *
hugetlb_cgroup_from_folio_rsvd(struct folio *folio)
{
	return NULL;
}

static inline void set_hugetlb_cgroup(struct page *page,
				     struct hugetlb_cgroup *h_cg)
{
}

static inline void set_hugetlb_cgroup_rsvd(struct page *page,
					  struct hugetlb_cgroup *h_cg)
{
}

static inline bool hugetlb_cgroup_disabled(void)
{
	return true;
}

static inline void hugetlb_cgroup_put_rsvd_cgroup(struct hugetlb_cgroup *h_cg)
{
}

static inline void resv_map_dup_hugetlb_cgroup_uncharge_info(
						struct resv_map *resv_map)
{
}

static inline void resv_map_put_hugetlb_cgroup_uncharge_info(
						struct resv_map *resv_map)
{
}

static inline int hugetlb_cgroup_charge_cgroup(int idx, unsigned long nr_pages,
					       struct hugetlb_cgroup **ptr)
{
	return 0;
}

static inline int hugetlb_cgroup_charge_cgroup_rsvd(int idx,
						    unsigned long nr_pages,
						    struct hugetlb_cgroup **ptr)
{
	return 0;
}

static inline void hugetlb_cgroup_commit_charge(int idx, unsigned long nr_pages,
						struct hugetlb_cgroup *h_cg,
						struct page *page)
{
}

static inline void
hugetlb_cgroup_commit_charge_rsvd(int idx, unsigned long nr_pages,
				  struct hugetlb_cgroup *h_cg,
				  struct page *page)
{
}

static inline void hugetlb_cgroup_uncharge_folio(int idx, unsigned long nr_pages,
						struct folio *folio)
{
}

static inline void hugetlb_cgroup_uncharge_folio_rsvd(int idx,
						     unsigned long nr_pages,
						     struct folio *folio)
{
}
static inline void hugetlb_cgroup_uncharge_cgroup(int idx,
						  unsigned long nr_pages,
						  struct hugetlb_cgroup *h_cg)
{
}

static inline void
hugetlb_cgroup_uncharge_cgroup_rsvd(int idx, unsigned long nr_pages,
				    struct hugetlb_cgroup *h_cg)
{
}

static inline void hugetlb_cgroup_uncharge_counter(struct resv_map *resv,
						   unsigned long start,
						   unsigned long end)
{
}

static inline void hugetlb_cgroup_file_init(void)
{
}

static inline void hugetlb_cgroup_migrate(struct page *oldhpage,
					  struct page *newhpage)
{
}

#endif  /* CONFIG_MEM_RES_CTLR_HUGETLB */
#endif
