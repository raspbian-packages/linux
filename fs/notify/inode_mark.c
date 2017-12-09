/*
 *  Copyright (C) 2008 Red Hat, Inc., Eric Paris <eparis@redhat.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; see the file COPYING.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>

#include <linux/atomic.h>

#include <linux/fsnotify_backend.h>
#include "fsnotify.h"

#include "../internal.h"

/*
 * Recalculate the mask of events relevant to a given inode locked.
 */
static void fsnotify_recalc_inode_mask_locked(struct inode *inode)
{
	struct fsnotify_mark *mark;
	struct hlist_node *pos;
	__u32 new_mask = 0;

	assert_spin_locked(&inode->i_lock);

	hlist_for_each_entry(mark, pos, &inode->i_fsnotify_marks, i.i_list)
		new_mask |= mark->mask;
	inode->i_fsnotify_mask = new_mask;
}

/*
 * Recalculate the inode->i_fsnotify_mask, or the mask of all FS_* event types
 * any notifier is interested in hearing for this inode.
 */
void fsnotify_recalc_inode_mask(struct inode *inode)
{
	spin_lock(&inode->i_lock);
	fsnotify_recalc_inode_mask_locked(inode);
	spin_unlock(&inode->i_lock);

	__fsnotify_update_child_dentry_flags(inode);
}

void fsnotify_destroy_inode_mark(struct fsnotify_mark *mark)
{
	struct inode *inode = mark->i.inode;

	assert_spin_locked(&mark->lock);
	assert_spin_locked(&mark->group->mark_lock);

	spin_lock(&inode->i_lock);

	hlist_del_init_rcu(&mark->i.i_list);
	mark->i.inode = NULL;

	/*
	 * this mark is now off the inode->i_fsnotify_marks list and we
	 * hold the inode->i_lock, so this is the perfect time to update the
	 * inode->i_fsnotify_mask
	 */
	fsnotify_recalc_inode_mask_locked(inode);

	spin_unlock(&inode->i_lock);
}

/*
 * Given an inode, destroy all of the marks associated with that inode.
 */
void fsnotify_clear_marks_by_inode(struct inode *inode)
{
	struct fsnotify_mark *mark, *lmark;
	struct hlist_node *pos, *n;
	LIST_HEAD(free_list);

	spin_lock(&inode->i_lock);
	hlist_for_each_entry_safe(mark, pos, n, &inode->i_fsnotify_marks, i.i_list) {
		list_add(&mark->i.free_i_list, &free_list);
		hlist_del_init_rcu(&mark->i.i_list);
		fsnotify_get_mark(mark);
	}
	spin_unlock(&inode->i_lock);

	list_for_each_entry_safe(mark, lmark, &free_list, i.free_i_list) {
		fsnotify_destroy_mark(mark);
		fsnotify_put_mark(mark);
	}
}

/*
 * Given a group clear all of the inode marks associated with that group.
 */
void fsnotify_clear_inode_marks_by_group(struct fsnotify_group *group)
{
	fsnotify_clear_marks_by_group_flags(group, FSNOTIFY_MARK_FLAG_INODE);
}

/*
 * given a group and inode, find the mark associated with that combination.
 * if found take a reference to that mark and return it, else return NULL
 */
struct fsnotify_mark *fsnotify_find_inode_mark_locked(struct fsnotify_group *group,
						      struct inode *inode)
{
	struct fsnotify_mark *mark;
	struct hlist_node *pos;

	assert_spin_locked(&inode->i_lock);

	hlist_for_each_entry(mark, pos, &inode->i_fsnotify_marks, i.i_list) {
		if (mark->group == group) {
			fsnotify_get_mark(mark);
			return mark;
		}
	}
	return NULL;
}

/*
 * given a group and inode, find the mark associated with that combination.
 * if found take a reference to that mark and return it, else return NULL
 */
struct fsnotify_mark *fsnotify_find_inode_mark(struct fsnotify_group *group,
					       struct inode *inode)
{
	struct fsnotify_mark *mark;

	spin_lock(&inode->i_lock);
	mark = fsnotify_find_inode_mark_locked(group, inode);
	spin_unlock(&inode->i_lock);

	return mark;
}

/*
 * If we are setting a mark mask on an inode mark we should pin the inode
 * in memory.
 */
void fsnotify_set_inode_mark_mask_locked(struct fsnotify_mark *mark,
					 __u32 mask)
{
	struct inode *inode;

	assert_spin_locked(&mark->lock);

	if (mask &&
	    mark->i.inode &&
	    !(mark->flags & FSNOTIFY_MARK_FLAG_OBJECT_PINNED)) {
		mark->flags |= FSNOTIFY_MARK_FLAG_OBJECT_PINNED;
		inode = igrab(mark->i.inode);
		/*
		 * we shouldn't be able to get here if the inode wasn't
		 * already safely held in memory.  But bug in case it
		 * ever is wrong.
		 */
		BUG_ON(!inode);
	}
}

/*
 * Attach an initialized mark to a given inode.
 * These marks may be used for the fsnotify backend to determine which
 * event types should be delivered to which group and for which inodes.  These
 * marks are ordered according to priority, highest number first, and then by
 * the group's location in memory.
 */
int fsnotify_add_inode_mark(struct fsnotify_mark *mark,
			    struct fsnotify_group *group, struct inode *inode,
			    int allow_dups)
{
	struct fsnotify_mark *lmark;
	struct hlist_node *node, *last = NULL;
	int ret = 0;

	mark->flags |= FSNOTIFY_MARK_FLAG_INODE;

	assert_spin_locked(&mark->lock);
	assert_spin_locked(&group->mark_lock);

	spin_lock(&inode->i_lock);

	mark->i.inode = inode;

	/* is mark the first mark? */
	if (hlist_empty(&inode->i_fsnotify_marks)) {
		hlist_add_head_rcu(&mark->i.i_list, &inode->i_fsnotify_marks);
		goto out;
	}

	/* should mark be in the middle of the current list? */
	hlist_for_each_entry(lmark, node, &inode->i_fsnotify_marks, i.i_list) {
		last = node;

		if ((lmark->group == group) && !allow_dups) {
			ret = -EEXIST;
			goto out;
		}

		if (mark->group->priority < lmark->group->priority)
			continue;

		if ((mark->group->priority == lmark->group->priority) &&
		    (mark->group < lmark->group))
			continue;

		hlist_add_before_rcu(&mark->i.i_list, &lmark->i.i_list);
		goto out;
	}

	BUG_ON(last == NULL);
	/* mark should be the last entry.  last is the current last entry */
	hlist_add_after_rcu(last, &mark->i.i_list);
out:
	fsnotify_recalc_inode_mask_locked(inode);
	spin_unlock(&inode->i_lock);

	return ret;
}

/**
 * fsnotify_unmount_inodes - an sb is unmounting.  handle any watched inodes.
 * @list: list of inodes being unmounted (sb->s_inodes)
 *
 * Called during unmount with no locks held, so needs to be safe against
 * concurrent modifiers. We temporarily drop inode_sb_list_lock and CAN block.
 */
void fsnotify_unmount_inodes(struct list_head *list)
{
	struct inode *inode, *iput_inode = NULL;

	spin_lock(&inode_sb_list_lock);
	list_for_each_entry(inode, list, i_sb_list) {
		/*
		 * We cannot __iget() an inode in state I_FREEING,
		 * I_WILL_FREE, or I_NEW which is fine because by that point
		 * the inode cannot have any associated watches.
		 */
		spin_lock(&inode->i_lock);
		if (inode->i_state & (I_FREEING|I_WILL_FREE|I_NEW)) {
			spin_unlock(&inode->i_lock);
			continue;
		}

		/*
		 * If i_count is zero, the inode cannot have any watches and
		 * doing an __iget/iput with MS_ACTIVE clear would actually
		 * evict all inodes with zero i_count from icache which is
		 * unnecessarily violent and may in fact be illegal to do.
		 */
		if (!atomic_read(&inode->i_count)) {
			spin_unlock(&inode->i_lock);
			continue;
		}

		__iget(inode);
		spin_unlock(&inode->i_lock);
		spin_unlock(&inode_sb_list_lock);

		if (iput_inode)
			iput(iput_inode);

		/* for each watch, send FS_UNMOUNT and then remove it */
		fsnotify(inode, FS_UNMOUNT, inode, FSNOTIFY_EVENT_INODE, NULL, 0);

		fsnotify_inode_delete(inode);

		iput_inode = inode;

		spin_lock(&inode_sb_list_lock);
	}
	spin_unlock(&inode_sb_list_lock);

	if (iput_inode)
		iput(iput_inode);
}
