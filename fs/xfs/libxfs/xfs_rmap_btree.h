/*
 * Copyright (c) 2014 Red Hat, Inc.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write the Free Software Foundation,
 * Inc.,  51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef __XFS_RMAP_BTREE_H__
#define __XFS_RMAP_BTREE_H__

struct xfs_buf;
struct xfs_btree_cur;
struct xfs_mount;

/* rmaps only exist on crc enabled filesystems */
#define XFS_RMAP_BLOCK_LEN	XFS_BTREE_SBLOCK_CRC_LEN

/*
 * Record, key, and pointer address macros for btree blocks.
 *
 * (note that some of these may appear unused, but they are used in userspace)
 */
#define XFS_RMAP_REC_ADDR(block, index) \
	((struct xfs_rmap_rec *) \
		((char *)(block) + XFS_RMAP_BLOCK_LEN + \
		 (((index) - 1) * sizeof(struct xfs_rmap_rec))))

#define XFS_RMAP_KEY_ADDR(block, index) \
	((struct xfs_rmap_key *) \
		((char *)(block) + XFS_RMAP_BLOCK_LEN + \
		 ((index) - 1) * 2 * sizeof(struct xfs_rmap_key)))

#define XFS_RMAP_HIGH_KEY_ADDR(block, index) \
	((struct xfs_rmap_key *) \
		((char *)(block) + XFS_RMAP_BLOCK_LEN + \
		 sizeof(struct xfs_rmap_key) + \
		 ((index) - 1) * 2 * sizeof(struct xfs_rmap_key)))

#define XFS_RMAP_PTR_ADDR(block, index, maxrecs) \
	((xfs_rmap_ptr_t *) \
		((char *)(block) + XFS_RMAP_BLOCK_LEN + \
		 (maxrecs) * 2 * sizeof(struct xfs_rmap_key) + \
		 ((index) - 1) * sizeof(xfs_rmap_ptr_t)))

struct xfs_btree_cur *xfs_rmapbt_init_cursor(struct xfs_mount *mp,
				struct xfs_trans *tp, struct xfs_buf *bp,
				xfs_agnumber_t agno);
int xfs_rmapbt_maxrecs(struct xfs_mount *mp, int blocklen, int leaf);
extern void xfs_rmapbt_compute_maxlevels(struct xfs_mount *mp);

extern xfs_extlen_t xfs_rmapbt_calc_size(struct xfs_mount *mp,
		unsigned long long len);
extern xfs_extlen_t xfs_rmapbt_max_size(struct xfs_mount *mp,
		xfs_agblock_t agblocks);

extern int xfs_rmapbt_calc_reserves(struct xfs_mount *mp,
		xfs_agnumber_t agno, xfs_extlen_t *ask, xfs_extlen_t *used);

#endif	/* __XFS_RMAP_BTREE_H__ */
