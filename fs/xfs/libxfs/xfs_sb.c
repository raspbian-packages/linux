// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#include "xfs.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_bit.h"
#include "xfs_sb.h"
#include "xfs_mount.h"
#include "xfs_ialloc.h"
#include "xfs_alloc.h"
#include "xfs_error.h"
#include "xfs_trans.h"
#include "xfs_buf_item.h"
#include "xfs_bmap_btree.h"
#include "xfs_alloc_btree.h"
#include "xfs_log.h"
#include "xfs_rmap_btree.h"
#include "xfs_refcount_btree.h"
#include "xfs_da_format.h"
#include "xfs_health.h"
#include "xfs_ag.h"
#include "xfs_rtbitmap.h"

/*
 * Physical superblock buffer manipulations. Shared with libxfs in userspace.
 */

/*
 * Check that all the V4 feature bits that the V5 filesystem format requires are
 * correctly set.
 */
static bool
xfs_sb_validate_v5_features(
	struct xfs_sb	*sbp)
{
	/* We must not have any unknown V4 feature bits set */
	if (sbp->sb_versionnum & ~XFS_SB_VERSION_OKBITS)
		return false;

	/*
	 * The CRC bit is considered an invalid V4 flag, so we have to add it
	 * manually to the OKBITS mask.
	 */
	if (sbp->sb_features2 & ~(XFS_SB_VERSION2_OKBITS |
				  XFS_SB_VERSION2_CRCBIT))
		return false;

	/* Now check all the required V4 feature flags are set. */

#define V5_VERS_FLAGS	(XFS_SB_VERSION_NLINKBIT	| \
			XFS_SB_VERSION_ALIGNBIT		| \
			XFS_SB_VERSION_LOGV2BIT		| \
			XFS_SB_VERSION_EXTFLGBIT	| \
			XFS_SB_VERSION_DIRV2BIT		| \
			XFS_SB_VERSION_MOREBITSBIT)

#define V5_FEAT_FLAGS	(XFS_SB_VERSION2_LAZYSBCOUNTBIT	| \
			XFS_SB_VERSION2_ATTR2BIT	| \
			XFS_SB_VERSION2_PROJID32BIT	| \
			XFS_SB_VERSION2_CRCBIT)

	if ((sbp->sb_versionnum & V5_VERS_FLAGS) != V5_VERS_FLAGS)
		return false;
	if ((sbp->sb_features2 & V5_FEAT_FLAGS) != V5_FEAT_FLAGS)
		return false;
	return true;
}

/*
 * We current support XFS v5 formats with known features and v4 superblocks with
 * at least V2 directories.
 */
bool
xfs_sb_good_version(
	struct xfs_sb	*sbp)
{
	/*
	 * All v5 filesystems are supported, but we must check that all the
	 * required v4 feature flags are enabled correctly as the code checks
	 * those flags and not for v5 support.
	 */
	if (xfs_sb_is_v5(sbp))
		return xfs_sb_validate_v5_features(sbp);

	/* versions prior to v4 are not supported */
	if (XFS_SB_VERSION_NUM(sbp) != XFS_SB_VERSION_4)
		return false;

	/* We must not have any unknown v4 feature bits set */
	if ((sbp->sb_versionnum & ~XFS_SB_VERSION_OKBITS) ||
	    ((sbp->sb_versionnum & XFS_SB_VERSION_MOREBITSBIT) &&
	     (sbp->sb_features2 & ~XFS_SB_VERSION2_OKBITS)))
		return false;

	/* V4 filesystems need v2 directories and unwritten extents */
	if (!(sbp->sb_versionnum & XFS_SB_VERSION_DIRV2BIT))
		return false;
	if (!(sbp->sb_versionnum & XFS_SB_VERSION_EXTFLGBIT))
		return false;

	/* It's a supported v4 filesystem */
	return true;
}

uint64_t
xfs_sb_version_to_features(
	struct xfs_sb	*sbp)
{
	uint64_t	features = 0;

	/* optional V4 features */
	if (sbp->sb_rblocks > 0)
		features |= XFS_FEAT_REALTIME;
	if (sbp->sb_versionnum & XFS_SB_VERSION_NLINKBIT)
		features |= XFS_FEAT_NLINK;
	if (sbp->sb_versionnum & XFS_SB_VERSION_ATTRBIT)
		features |= XFS_FEAT_ATTR;
	if (sbp->sb_versionnum & XFS_SB_VERSION_QUOTABIT)
		features |= XFS_FEAT_QUOTA;
	if (sbp->sb_versionnum & XFS_SB_VERSION_ALIGNBIT)
		features |= XFS_FEAT_ALIGN;
	if (sbp->sb_versionnum & XFS_SB_VERSION_LOGV2BIT)
		features |= XFS_FEAT_LOGV2;
	if (sbp->sb_versionnum & XFS_SB_VERSION_DALIGNBIT)
		features |= XFS_FEAT_DALIGN;
	if (sbp->sb_versionnum & XFS_SB_VERSION_EXTFLGBIT)
		features |= XFS_FEAT_EXTFLG;
	if (sbp->sb_versionnum & XFS_SB_VERSION_SECTORBIT)
		features |= XFS_FEAT_SECTOR;
	if (sbp->sb_versionnum & XFS_SB_VERSION_BORGBIT)
		features |= XFS_FEAT_ASCIICI;
	if (sbp->sb_versionnum & XFS_SB_VERSION_MOREBITSBIT) {
		if (sbp->sb_features2 & XFS_SB_VERSION2_LAZYSBCOUNTBIT)
			features |= XFS_FEAT_LAZYSBCOUNT;
		if (sbp->sb_features2 & XFS_SB_VERSION2_ATTR2BIT)
			features |= XFS_FEAT_ATTR2;
		if (sbp->sb_features2 & XFS_SB_VERSION2_PROJID32BIT)
			features |= XFS_FEAT_PROJID32;
		if (sbp->sb_features2 & XFS_SB_VERSION2_FTYPE)
			features |= XFS_FEAT_FTYPE;
	}

	if (!xfs_sb_is_v5(sbp))
		return features;

	/* Always on V5 features */
	features |= XFS_FEAT_ALIGN | XFS_FEAT_LOGV2 | XFS_FEAT_EXTFLG |
		    XFS_FEAT_LAZYSBCOUNT | XFS_FEAT_ATTR2 | XFS_FEAT_PROJID32 |
		    XFS_FEAT_V3INODES | XFS_FEAT_CRC | XFS_FEAT_PQUOTINO;

	/* Optional V5 features */
	if (sbp->sb_features_ro_compat & XFS_SB_FEAT_RO_COMPAT_FINOBT)
		features |= XFS_FEAT_FINOBT;
	if (sbp->sb_features_ro_compat & XFS_SB_FEAT_RO_COMPAT_RMAPBT)
		features |= XFS_FEAT_RMAPBT;
	if (sbp->sb_features_ro_compat & XFS_SB_FEAT_RO_COMPAT_REFLINK)
		features |= XFS_FEAT_REFLINK;
	if (sbp->sb_features_ro_compat & XFS_SB_FEAT_RO_COMPAT_INOBTCNT)
		features |= XFS_FEAT_INOBTCNT;
	if (sbp->sb_features_incompat & XFS_SB_FEAT_INCOMPAT_FTYPE)
		features |= XFS_FEAT_FTYPE;
	if (sbp->sb_features_incompat & XFS_SB_FEAT_INCOMPAT_SPINODES)
		features |= XFS_FEAT_SPINODES;
	if (sbp->sb_features_incompat & XFS_SB_FEAT_INCOMPAT_META_UUID)
		features |= XFS_FEAT_META_UUID;
	if (sbp->sb_features_incompat & XFS_SB_FEAT_INCOMPAT_BIGTIME)
		features |= XFS_FEAT_BIGTIME;
	if (sbp->sb_features_incompat & XFS_SB_FEAT_INCOMPAT_NEEDSREPAIR)
		features |= XFS_FEAT_NEEDSREPAIR;
	if (sbp->sb_features_incompat & XFS_SB_FEAT_INCOMPAT_NREXT64)
		features |= XFS_FEAT_NREXT64;

	return features;
}

/* Check all the superblock fields we care about when reading one in. */
STATIC int
xfs_validate_sb_read(
	struct xfs_mount	*mp,
	struct xfs_sb		*sbp)
{
	if (!xfs_sb_is_v5(sbp))
		return 0;

	/*
	 * Version 5 superblock feature mask validation. Reject combinations
	 * the kernel cannot support up front before checking anything else.
	 */
	if (xfs_sb_has_compat_feature(sbp, XFS_SB_FEAT_COMPAT_UNKNOWN)) {
		xfs_warn(mp,
"Superblock has unknown compatible features (0x%x) enabled.",
			(sbp->sb_features_compat & XFS_SB_FEAT_COMPAT_UNKNOWN));
		xfs_warn(mp,
"Using a more recent kernel is recommended.");
	}

	if (xfs_sb_has_ro_compat_feature(sbp, XFS_SB_FEAT_RO_COMPAT_UNKNOWN)) {
		xfs_alert(mp,
"Superblock has unknown read-only compatible features (0x%x) enabled.",
			(sbp->sb_features_ro_compat &
					XFS_SB_FEAT_RO_COMPAT_UNKNOWN));
		if (!xfs_is_readonly(mp)) {
			xfs_warn(mp,
"Attempted to mount read-only compatible filesystem read-write.");
			xfs_warn(mp,
"Filesystem can only be safely mounted read only.");

			return -EINVAL;
		}
	}
	if (xfs_sb_has_incompat_feature(sbp, XFS_SB_FEAT_INCOMPAT_UNKNOWN)) {
		xfs_warn(mp,
"Superblock has unknown incompatible features (0x%x) enabled.",
			(sbp->sb_features_incompat &
					XFS_SB_FEAT_INCOMPAT_UNKNOWN));
		xfs_warn(mp,
"Filesystem cannot be safely mounted by this kernel.");
		return -EINVAL;
	}

	return 0;
}

/* Check all the superblock fields we care about when writing one out. */
STATIC int
xfs_validate_sb_write(
	struct xfs_mount	*mp,
	struct xfs_buf		*bp,
	struct xfs_sb		*sbp)
{
	/*
	 * Carry out additional sb summary counter sanity checks when we write
	 * the superblock.  We skip this in the read validator because there
	 * could be newer superblocks in the log and if the values are garbage
	 * even after replay we'll recalculate them at the end of log mount.
	 *
	 * mkfs has traditionally written zeroed counters to inprogress and
	 * secondary superblocks, so allow this usage to continue because
	 * we never read counters from such superblocks.
	 */
	if (xfs_buf_daddr(bp) == XFS_SB_DADDR && !sbp->sb_inprogress &&
	    (sbp->sb_fdblocks > sbp->sb_dblocks ||
	     !xfs_verify_icount(mp, sbp->sb_icount) ||
	     sbp->sb_ifree > sbp->sb_icount)) {
		xfs_warn(mp, "SB summary counter sanity check failed");
		return -EFSCORRUPTED;
	}

	if (!xfs_sb_is_v5(sbp))
		return 0;

	/*
	 * Version 5 superblock feature mask validation. Reject combinations
	 * the kernel cannot support since we checked for unsupported bits in
	 * the read verifier, which means that memory is corrupt.
	 */
	if (xfs_sb_has_compat_feature(sbp, XFS_SB_FEAT_COMPAT_UNKNOWN)) {
		xfs_warn(mp,
"Corruption detected in superblock compatible features (0x%x)!",
			(sbp->sb_features_compat & XFS_SB_FEAT_COMPAT_UNKNOWN));
		return -EFSCORRUPTED;
	}

	if (!xfs_is_readonly(mp) &&
	    xfs_sb_has_ro_compat_feature(sbp, XFS_SB_FEAT_RO_COMPAT_UNKNOWN)) {
		xfs_alert(mp,
"Corruption detected in superblock read-only compatible features (0x%x)!",
			(sbp->sb_features_ro_compat &
					XFS_SB_FEAT_RO_COMPAT_UNKNOWN));
		return -EFSCORRUPTED;
	}
	if (xfs_sb_has_incompat_feature(sbp, XFS_SB_FEAT_INCOMPAT_UNKNOWN)) {
		xfs_warn(mp,
"Corruption detected in superblock incompatible features (0x%x)!",
			(sbp->sb_features_incompat &
					XFS_SB_FEAT_INCOMPAT_UNKNOWN));
		return -EFSCORRUPTED;
	}
	if (xfs_sb_has_incompat_log_feature(sbp,
			XFS_SB_FEAT_INCOMPAT_LOG_UNKNOWN)) {
		xfs_warn(mp,
"Corruption detected in superblock incompatible log features (0x%x)!",
			(sbp->sb_features_log_incompat &
					XFS_SB_FEAT_INCOMPAT_LOG_UNKNOWN));
		return -EFSCORRUPTED;
	}

	/*
	 * We can't read verify the sb LSN because the read verifier is called
	 * before the log is allocated and processed. We know the log is set up
	 * before write verifier calls, so check it here.
	 */
	if (!xfs_log_check_lsn(mp, sbp->sb_lsn))
		return -EFSCORRUPTED;

	return 0;
}

/* Check the validity of the SB. */
STATIC int
xfs_validate_sb_common(
	struct xfs_mount	*mp,
	struct xfs_buf		*bp,
	struct xfs_sb		*sbp)
{
	struct xfs_dsb		*dsb = bp->b_addr;
	uint32_t		agcount = 0;
	uint32_t		rem;
	bool			has_dalign;

	if (!xfs_verify_magic(bp, dsb->sb_magicnum)) {
		xfs_warn(mp,
"Superblock has bad magic number 0x%x. Not an XFS filesystem?",
			be32_to_cpu(dsb->sb_magicnum));
		return -EWRONGFS;
	}

	if (!xfs_sb_good_version(sbp)) {
		xfs_warn(mp,
"Superblock has unknown features enabled or corrupted feature masks.");
		return -EWRONGFS;
	}

	/*
	 * Validate feature flags and state
	 */
	if (xfs_sb_is_v5(sbp)) {
		if (sbp->sb_blocksize < XFS_MIN_CRC_BLOCKSIZE) {
			xfs_notice(mp,
"Block size (%u bytes) too small for Version 5 superblock (minimum %d bytes)",
				sbp->sb_blocksize, XFS_MIN_CRC_BLOCKSIZE);
			return -EFSCORRUPTED;
		}

		/* V5 has a separate project quota inode */
		if (sbp->sb_qflags & (XFS_OQUOTA_ENFD | XFS_OQUOTA_CHKD)) {
			xfs_notice(mp,
			   "Version 5 of Super block has XFS_OQUOTA bits.");
			return -EFSCORRUPTED;
		}

		/*
		 * Full inode chunks must be aligned to inode chunk size when
		 * sparse inodes are enabled to support the sparse chunk
		 * allocation algorithm and prevent overlapping inode records.
		 */
		if (sbp->sb_features_incompat & XFS_SB_FEAT_INCOMPAT_SPINODES) {
			uint32_t	align;

			align = XFS_INODES_PER_CHUNK * sbp->sb_inodesize
					>> sbp->sb_blocklog;
			if (sbp->sb_inoalignmt != align) {
				xfs_warn(mp,
"Inode block alignment (%u) must match chunk size (%u) for sparse inodes.",
					 sbp->sb_inoalignmt, align);
				return -EINVAL;
			}
		}
	} else if (sbp->sb_qflags & (XFS_PQUOTA_ENFD | XFS_GQUOTA_ENFD |
				XFS_PQUOTA_CHKD | XFS_GQUOTA_CHKD)) {
			xfs_notice(mp,
"Superblock earlier than Version 5 has XFS_{P|G}QUOTA_{ENFD|CHKD} bits.");
			return -EFSCORRUPTED;
	}

	if (unlikely(
	    sbp->sb_logstart == 0 && mp->m_logdev_targp == mp->m_ddev_targp)) {
		xfs_warn(mp,
		"filesystem is marked as having an external log; "
		"specify logdev on the mount command line.");
		return -EINVAL;
	}

	if (unlikely(
	    sbp->sb_logstart != 0 && mp->m_logdev_targp != mp->m_ddev_targp)) {
		xfs_warn(mp,
		"filesystem is marked as having an internal log; "
		"do not specify logdev on the mount command line.");
		return -EINVAL;
	}

	/* Compute agcount for this number of dblocks and agblocks */
	if (sbp->sb_agblocks) {
		agcount = div_u64_rem(sbp->sb_dblocks, sbp->sb_agblocks, &rem);
		if (rem)
			agcount++;
	}

	/*
	 * More sanity checking.  Most of these were stolen directly from
	 * xfs_repair.
	 */
	if (unlikely(
	    sbp->sb_agcount <= 0					||
	    sbp->sb_sectsize < XFS_MIN_SECTORSIZE			||
	    sbp->sb_sectsize > XFS_MAX_SECTORSIZE			||
	    sbp->sb_sectlog < XFS_MIN_SECTORSIZE_LOG			||
	    sbp->sb_sectlog > XFS_MAX_SECTORSIZE_LOG			||
	    sbp->sb_sectsize != (1 << sbp->sb_sectlog)			||
	    sbp->sb_blocksize < XFS_MIN_BLOCKSIZE			||
	    sbp->sb_blocksize > XFS_MAX_BLOCKSIZE			||
	    sbp->sb_blocklog < XFS_MIN_BLOCKSIZE_LOG			||
	    sbp->sb_blocklog > XFS_MAX_BLOCKSIZE_LOG			||
	    sbp->sb_blocksize != (1 << sbp->sb_blocklog)		||
	    sbp->sb_dirblklog + sbp->sb_blocklog > XFS_MAX_BLOCKSIZE_LOG ||
	    sbp->sb_inodesize < XFS_DINODE_MIN_SIZE			||
	    sbp->sb_inodesize > XFS_DINODE_MAX_SIZE			||
	    sbp->sb_inodelog < XFS_DINODE_MIN_LOG			||
	    sbp->sb_inodelog > XFS_DINODE_MAX_LOG			||
	    sbp->sb_inodesize != (1 << sbp->sb_inodelog)		||
	    sbp->sb_inopblock != howmany(sbp->sb_blocksize,sbp->sb_inodesize) ||
	    XFS_FSB_TO_B(mp, sbp->sb_agblocks) < XFS_MIN_AG_BYTES	||
	    XFS_FSB_TO_B(mp, sbp->sb_agblocks) > XFS_MAX_AG_BYTES	||
	    sbp->sb_agblklog != xfs_highbit32(sbp->sb_agblocks - 1) + 1	||
	    agcount == 0 || agcount != sbp->sb_agcount			||
	    (sbp->sb_blocklog - sbp->sb_inodelog != sbp->sb_inopblog)	||
	    (sbp->sb_rextsize * sbp->sb_blocksize > XFS_MAX_RTEXTSIZE)	||
	    (sbp->sb_rextsize * sbp->sb_blocksize < XFS_MIN_RTEXTSIZE)	||
	    (sbp->sb_imax_pct > 100 /* zero sb_imax_pct is valid */)	||
	    sbp->sb_dblocks == 0					||
	    sbp->sb_dblocks > XFS_MAX_DBLOCKS(sbp)			||
	    sbp->sb_dblocks < XFS_MIN_DBLOCKS(sbp)			||
	    sbp->sb_shared_vn != 0)) {
		xfs_notice(mp, "SB sanity check failed");
		return -EFSCORRUPTED;
	}

	/*
	 * Logs that are too large are not supported at all. Reject them
	 * outright. Logs that are too small are tolerated on v4 filesystems,
	 * but we can only check that when mounting the log. Hence we skip
	 * those checks here.
	 */
	if (sbp->sb_logblocks > XFS_MAX_LOG_BLOCKS) {
		xfs_notice(mp,
		"Log size 0x%x blocks too large, maximum size is 0x%llx blocks",
			 sbp->sb_logblocks, XFS_MAX_LOG_BLOCKS);
		return -EFSCORRUPTED;
	}

	if (XFS_FSB_TO_B(mp, sbp->sb_logblocks) > XFS_MAX_LOG_BYTES) {
		xfs_warn(mp,
		"log size 0x%llx bytes too large, maximum size is 0x%llx bytes",
			 XFS_FSB_TO_B(mp, sbp->sb_logblocks),
			 XFS_MAX_LOG_BYTES);
		return -EFSCORRUPTED;
	}

	/*
	 * Do not allow filesystems with corrupted log sector or stripe units to
	 * be mounted. We cannot safely size the iclogs or write to the log if
	 * the log stripe unit is not valid.
	 */
	if (sbp->sb_versionnum & XFS_SB_VERSION_SECTORBIT) {
		if (sbp->sb_logsectsize != (1U << sbp->sb_logsectlog)) {
			xfs_notice(mp,
			"log sector size in bytes/log2 (0x%x/0x%x) must match",
				sbp->sb_logsectsize, 1U << sbp->sb_logsectlog);
			return -EFSCORRUPTED;
		}
	} else if (sbp->sb_logsectsize || sbp->sb_logsectlog) {
		xfs_notice(mp,
		"log sector size in bytes/log2 (0x%x/0x%x) are not zero",
			sbp->sb_logsectsize, sbp->sb_logsectlog);
		return -EFSCORRUPTED;
	}

	if (sbp->sb_logsunit > 1) {
		if (sbp->sb_logsunit % sbp->sb_blocksize) {
			xfs_notice(mp,
		"log stripe unit 0x%x bytes must be a multiple of block size",
				sbp->sb_logsunit);
			return -EFSCORRUPTED;
		}
		if (sbp->sb_logsunit > XLOG_MAX_RECORD_BSIZE) {
			xfs_notice(mp,
		"log stripe unit 0x%x bytes over maximum size (0x%x bytes)",
				sbp->sb_logsunit, XLOG_MAX_RECORD_BSIZE);
			return -EFSCORRUPTED;
		}
	}

	/* Validate the realtime geometry; stolen from xfs_repair */
	if (sbp->sb_rextsize * sbp->sb_blocksize > XFS_MAX_RTEXTSIZE ||
	    sbp->sb_rextsize * sbp->sb_blocksize < XFS_MIN_RTEXTSIZE) {
		xfs_notice(mp,
			"realtime extent sanity check failed");
		return -EFSCORRUPTED;
	}

	if (sbp->sb_rblocks == 0) {
		if (sbp->sb_rextents != 0 || sbp->sb_rbmblocks != 0 ||
		    sbp->sb_rextslog != 0 || sbp->sb_frextents != 0) {
			xfs_notice(mp,
				"realtime zeroed geometry check failed");
			return -EFSCORRUPTED;
		}
	} else {
		uint64_t	rexts;
		uint64_t	rbmblocks;

		rexts = div_u64(sbp->sb_rblocks, sbp->sb_rextsize);
		rbmblocks = howmany_64(sbp->sb_rextents,
				       NBBY * sbp->sb_blocksize);

		if (!xfs_validate_rtextents(rexts) ||
		    sbp->sb_rextents != rexts ||
		    sbp->sb_rextslog != xfs_compute_rextslog(rexts) ||
		    sbp->sb_rbmblocks != rbmblocks) {
			xfs_notice(mp,
				"realtime geometry sanity check failed");
			return -EFSCORRUPTED;
		}
	}

	/*
	 * Either (sb_unit and !hasdalign) or (!sb_unit and hasdalign)
	 * would imply the image is corrupted.
	 */
	has_dalign = sbp->sb_versionnum & XFS_SB_VERSION_DALIGNBIT;
	if (!!sbp->sb_unit ^ has_dalign) {
		xfs_notice(mp, "SB stripe alignment sanity check failed");
		return -EFSCORRUPTED;
	}

	if (!xfs_validate_stripe_geometry(mp, XFS_FSB_TO_B(mp, sbp->sb_unit),
			XFS_FSB_TO_B(mp, sbp->sb_width), 0, false))
		return -EFSCORRUPTED;

	/*
	 * Currently only very few inode sizes are supported.
	 */
	switch (sbp->sb_inodesize) {
	case 256:
	case 512:
	case 1024:
	case 2048:
		break;
	default:
		xfs_warn(mp, "inode size of %d bytes not supported",
				sbp->sb_inodesize);
		return -ENOSYS;
	}

	return 0;
}

void
xfs_sb_quota_from_disk(struct xfs_sb *sbp)
{
	/*
	 * older mkfs doesn't initialize quota inodes to NULLFSINO. This
	 * leads to in-core values having two different values for a quota
	 * inode to be invalid: 0 and NULLFSINO. Change it to a single value
	 * NULLFSINO.
	 *
	 * Note that this change affect only the in-core values. These
	 * values are not written back to disk unless any quota information
	 * is written to the disk. Even in that case, sb_pquotino field is
	 * not written to disk unless the superblock supports pquotino.
	 */
	if (sbp->sb_uquotino == 0)
		sbp->sb_uquotino = NULLFSINO;
	if (sbp->sb_gquotino == 0)
		sbp->sb_gquotino = NULLFSINO;
	if (sbp->sb_pquotino == 0)
		sbp->sb_pquotino = NULLFSINO;

	/*
	 * We need to do these manipilations only if we are working
	 * with an older version of on-disk superblock.
	 */
	if (xfs_sb_is_v5(sbp))
		return;

	if (sbp->sb_qflags & XFS_OQUOTA_ENFD)
		sbp->sb_qflags |= (sbp->sb_qflags & XFS_PQUOTA_ACCT) ?
					XFS_PQUOTA_ENFD : XFS_GQUOTA_ENFD;
	if (sbp->sb_qflags & XFS_OQUOTA_CHKD)
		sbp->sb_qflags |= (sbp->sb_qflags & XFS_PQUOTA_ACCT) ?
					XFS_PQUOTA_CHKD : XFS_GQUOTA_CHKD;
	sbp->sb_qflags &= ~(XFS_OQUOTA_ENFD | XFS_OQUOTA_CHKD);

	if (sbp->sb_qflags & XFS_PQUOTA_ACCT &&
	    sbp->sb_gquotino != NULLFSINO)  {
		/*
		 * In older version of superblock, on-disk superblock only
		 * has sb_gquotino, and in-core superblock has both sb_gquotino
		 * and sb_pquotino. But, only one of them is supported at any
		 * point of time. So, if PQUOTA is set in disk superblock,
		 * copy over sb_gquotino to sb_pquotino.  The NULLFSINO test
		 * above is to make sure we don't do this twice and wipe them
		 * both out!
		 */
		sbp->sb_pquotino = sbp->sb_gquotino;
		sbp->sb_gquotino = NULLFSINO;
	}
}

static void
__xfs_sb_from_disk(
	struct xfs_sb	*to,
	struct xfs_dsb	*from,
	bool		convert_xquota)
{
	to->sb_magicnum = be32_to_cpu(from->sb_magicnum);
	to->sb_blocksize = be32_to_cpu(from->sb_blocksize);
	to->sb_dblocks = be64_to_cpu(from->sb_dblocks);
	to->sb_rblocks = be64_to_cpu(from->sb_rblocks);
	to->sb_rextents = be64_to_cpu(from->sb_rextents);
	memcpy(&to->sb_uuid, &from->sb_uuid, sizeof(to->sb_uuid));
	to->sb_logstart = be64_to_cpu(from->sb_logstart);
	to->sb_rootino = be64_to_cpu(from->sb_rootino);
	to->sb_rbmino = be64_to_cpu(from->sb_rbmino);
	to->sb_rsumino = be64_to_cpu(from->sb_rsumino);
	to->sb_rextsize = be32_to_cpu(from->sb_rextsize);
	to->sb_agblocks = be32_to_cpu(from->sb_agblocks);
	to->sb_agcount = be32_to_cpu(from->sb_agcount);
	to->sb_rbmblocks = be32_to_cpu(from->sb_rbmblocks);
	to->sb_logblocks = be32_to_cpu(from->sb_logblocks);
	to->sb_versionnum = be16_to_cpu(from->sb_versionnum);
	to->sb_sectsize = be16_to_cpu(from->sb_sectsize);
	to->sb_inodesize = be16_to_cpu(from->sb_inodesize);
	to->sb_inopblock = be16_to_cpu(from->sb_inopblock);
	memcpy(&to->sb_fname, &from->sb_fname, sizeof(to->sb_fname));
	to->sb_blocklog = from->sb_blocklog;
	to->sb_sectlog = from->sb_sectlog;
	to->sb_inodelog = from->sb_inodelog;
	to->sb_inopblog = from->sb_inopblog;
	to->sb_agblklog = from->sb_agblklog;
	to->sb_rextslog = from->sb_rextslog;
	to->sb_inprogress = from->sb_inprogress;
	to->sb_imax_pct = from->sb_imax_pct;
	to->sb_icount = be64_to_cpu(from->sb_icount);
	to->sb_ifree = be64_to_cpu(from->sb_ifree);
	to->sb_fdblocks = be64_to_cpu(from->sb_fdblocks);
	to->sb_frextents = be64_to_cpu(from->sb_frextents);
	to->sb_uquotino = be64_to_cpu(from->sb_uquotino);
	to->sb_gquotino = be64_to_cpu(from->sb_gquotino);
	to->sb_qflags = be16_to_cpu(from->sb_qflags);
	to->sb_flags = from->sb_flags;
	to->sb_shared_vn = from->sb_shared_vn;
	to->sb_inoalignmt = be32_to_cpu(from->sb_inoalignmt);
	to->sb_unit = be32_to_cpu(from->sb_unit);
	to->sb_width = be32_to_cpu(from->sb_width);
	to->sb_dirblklog = from->sb_dirblklog;
	to->sb_logsectlog = from->sb_logsectlog;
	to->sb_logsectsize = be16_to_cpu(from->sb_logsectsize);
	to->sb_logsunit = be32_to_cpu(from->sb_logsunit);
	to->sb_features2 = be32_to_cpu(from->sb_features2);
	to->sb_bad_features2 = be32_to_cpu(from->sb_bad_features2);
	to->sb_features_compat = be32_to_cpu(from->sb_features_compat);
	to->sb_features_ro_compat = be32_to_cpu(from->sb_features_ro_compat);
	to->sb_features_incompat = be32_to_cpu(from->sb_features_incompat);
	to->sb_features_log_incompat =
				be32_to_cpu(from->sb_features_log_incompat);
	/* crc is only used on disk, not in memory; just init to 0 here. */
	to->sb_crc = 0;
	to->sb_spino_align = be32_to_cpu(from->sb_spino_align);
	to->sb_pquotino = be64_to_cpu(from->sb_pquotino);
	to->sb_lsn = be64_to_cpu(from->sb_lsn);
	/*
	 * sb_meta_uuid is only on disk if it differs from sb_uuid and the
	 * feature flag is set; if not set we keep it only in memory.
	 */
	if (xfs_sb_is_v5(to) &&
	    (to->sb_features_incompat & XFS_SB_FEAT_INCOMPAT_META_UUID))
		uuid_copy(&to->sb_meta_uuid, &from->sb_meta_uuid);
	else
		uuid_copy(&to->sb_meta_uuid, &from->sb_uuid);
	/* Convert on-disk flags to in-memory flags? */
	if (convert_xquota)
		xfs_sb_quota_from_disk(to);
}

void
xfs_sb_from_disk(
	struct xfs_sb	*to,
	struct xfs_dsb	*from)
{
	__xfs_sb_from_disk(to, from, true);
}

static void
xfs_sb_quota_to_disk(
	struct xfs_dsb	*to,
	struct xfs_sb	*from)
{
	uint16_t	qflags = from->sb_qflags;

	to->sb_uquotino = cpu_to_be64(from->sb_uquotino);

	/*
	 * The in-memory superblock quota state matches the v5 on-disk format so
	 * just write them out and return
	 */
	if (xfs_sb_is_v5(from)) {
		to->sb_qflags = cpu_to_be16(from->sb_qflags);
		to->sb_gquotino = cpu_to_be64(from->sb_gquotino);
		to->sb_pquotino = cpu_to_be64(from->sb_pquotino);
		return;
	}

	/*
	 * For older superblocks (v4), the in-core version of sb_qflags do not
	 * have XFS_OQUOTA_* flags, whereas the on-disk version does.  So,
	 * convert incore XFS_{PG}QUOTA_* flags to on-disk XFS_OQUOTA_* flags.
	 */
	qflags &= ~(XFS_PQUOTA_ENFD | XFS_PQUOTA_CHKD |
			XFS_GQUOTA_ENFD | XFS_GQUOTA_CHKD);

	if (from->sb_qflags &
			(XFS_PQUOTA_ENFD | XFS_GQUOTA_ENFD))
		qflags |= XFS_OQUOTA_ENFD;
	if (from->sb_qflags &
			(XFS_PQUOTA_CHKD | XFS_GQUOTA_CHKD))
		qflags |= XFS_OQUOTA_CHKD;
	to->sb_qflags = cpu_to_be16(qflags);

	/*
	 * GQUOTINO and PQUOTINO cannot be used together in versions
	 * of superblock that do not have pquotino. from->sb_flags
	 * tells us which quota is active and should be copied to
	 * disk. If neither are active, we should NULL the inode.
	 *
	 * In all cases, the separate pquotino must remain 0 because it
	 * is beyond the "end" of the valid non-pquotino superblock.
	 */
	if (from->sb_qflags & XFS_GQUOTA_ACCT)
		to->sb_gquotino = cpu_to_be64(from->sb_gquotino);
	else if (from->sb_qflags & XFS_PQUOTA_ACCT)
		to->sb_gquotino = cpu_to_be64(from->sb_pquotino);
	else {
		/*
		 * We can't rely on just the fields being logged to tell us
		 * that it is safe to write NULLFSINO - we should only do that
		 * if quotas are not actually enabled. Hence only write
		 * NULLFSINO if both in-core quota inodes are NULL.
		 */
		if (from->sb_gquotino == NULLFSINO &&
		    from->sb_pquotino == NULLFSINO)
			to->sb_gquotino = cpu_to_be64(NULLFSINO);
	}

	to->sb_pquotino = 0;
}

void
xfs_sb_to_disk(
	struct xfs_dsb	*to,
	struct xfs_sb	*from)
{
	xfs_sb_quota_to_disk(to, from);

	to->sb_magicnum = cpu_to_be32(from->sb_magicnum);
	to->sb_blocksize = cpu_to_be32(from->sb_blocksize);
	to->sb_dblocks = cpu_to_be64(from->sb_dblocks);
	to->sb_rblocks = cpu_to_be64(from->sb_rblocks);
	to->sb_rextents = cpu_to_be64(from->sb_rextents);
	memcpy(&to->sb_uuid, &from->sb_uuid, sizeof(to->sb_uuid));
	to->sb_logstart = cpu_to_be64(from->sb_logstart);
	to->sb_rootino = cpu_to_be64(from->sb_rootino);
	to->sb_rbmino = cpu_to_be64(from->sb_rbmino);
	to->sb_rsumino = cpu_to_be64(from->sb_rsumino);
	to->sb_rextsize = cpu_to_be32(from->sb_rextsize);
	to->sb_agblocks = cpu_to_be32(from->sb_agblocks);
	to->sb_agcount = cpu_to_be32(from->sb_agcount);
	to->sb_rbmblocks = cpu_to_be32(from->sb_rbmblocks);
	to->sb_logblocks = cpu_to_be32(from->sb_logblocks);
	to->sb_versionnum = cpu_to_be16(from->sb_versionnum);
	to->sb_sectsize = cpu_to_be16(from->sb_sectsize);
	to->sb_inodesize = cpu_to_be16(from->sb_inodesize);
	to->sb_inopblock = cpu_to_be16(from->sb_inopblock);
	memcpy(&to->sb_fname, &from->sb_fname, sizeof(to->sb_fname));
	to->sb_blocklog = from->sb_blocklog;
	to->sb_sectlog = from->sb_sectlog;
	to->sb_inodelog = from->sb_inodelog;
	to->sb_inopblog = from->sb_inopblog;
	to->sb_agblklog = from->sb_agblklog;
	to->sb_rextslog = from->sb_rextslog;
	to->sb_inprogress = from->sb_inprogress;
	to->sb_imax_pct = from->sb_imax_pct;
	to->sb_icount = cpu_to_be64(from->sb_icount);
	to->sb_ifree = cpu_to_be64(from->sb_ifree);
	to->sb_fdblocks = cpu_to_be64(from->sb_fdblocks);
	to->sb_frextents = cpu_to_be64(from->sb_frextents);

	to->sb_flags = from->sb_flags;
	to->sb_shared_vn = from->sb_shared_vn;
	to->sb_inoalignmt = cpu_to_be32(from->sb_inoalignmt);
	to->sb_unit = cpu_to_be32(from->sb_unit);
	to->sb_width = cpu_to_be32(from->sb_width);
	to->sb_dirblklog = from->sb_dirblklog;
	to->sb_logsectlog = from->sb_logsectlog;
	to->sb_logsectsize = cpu_to_be16(from->sb_logsectsize);
	to->sb_logsunit = cpu_to_be32(from->sb_logsunit);

	/*
	 * We need to ensure that bad_features2 always matches features2.
	 * Hence we enforce that here rather than having to remember to do it
	 * everywhere else that updates features2.
	 */
	from->sb_bad_features2 = from->sb_features2;
	to->sb_features2 = cpu_to_be32(from->sb_features2);
	to->sb_bad_features2 = cpu_to_be32(from->sb_bad_features2);

	if (!xfs_sb_is_v5(from))
		return;

	to->sb_features_compat = cpu_to_be32(from->sb_features_compat);
	to->sb_features_ro_compat =
			cpu_to_be32(from->sb_features_ro_compat);
	to->sb_features_incompat =
			cpu_to_be32(from->sb_features_incompat);
	to->sb_features_log_incompat =
			cpu_to_be32(from->sb_features_log_incompat);
	to->sb_spino_align = cpu_to_be32(from->sb_spino_align);
	to->sb_lsn = cpu_to_be64(from->sb_lsn);
	if (from->sb_features_incompat & XFS_SB_FEAT_INCOMPAT_META_UUID)
		uuid_copy(&to->sb_meta_uuid, &from->sb_meta_uuid);
}

/*
 * If the superblock has the CRC feature bit set or the CRC field is non-null,
 * check that the CRC is valid.  We check the CRC field is non-null because a
 * single bit error could clear the feature bit and unused parts of the
 * superblock are supposed to be zero. Hence a non-null crc field indicates that
 * we've potentially lost a feature bit and we should check it anyway.
 *
 * However, past bugs (i.e. in growfs) left non-zeroed regions beyond the
 * last field in V4 secondary superblocks.  So for secondary superblocks,
 * we are more forgiving, and ignore CRC failures if the primary doesn't
 * indicate that the fs version is V5.
 */
static void
xfs_sb_read_verify(
	struct xfs_buf		*bp)
{
	struct xfs_sb		sb;
	struct xfs_mount	*mp = bp->b_mount;
	struct xfs_dsb		*dsb = bp->b_addr;
	int			error;

	/*
	 * open code the version check to avoid needing to convert the entire
	 * superblock from disk order just to check the version number
	 */
	if (dsb->sb_magicnum == cpu_to_be32(XFS_SB_MAGIC) &&
	    (((be16_to_cpu(dsb->sb_versionnum) & XFS_SB_VERSION_NUMBITS) ==
						XFS_SB_VERSION_5) ||
	     dsb->sb_crc != 0)) {

		if (!xfs_buf_verify_cksum(bp, XFS_SB_CRC_OFF)) {
			/* Only fail bad secondaries on a known V5 filesystem */
			if (xfs_buf_daddr(bp) == XFS_SB_DADDR ||
			    xfs_has_crc(mp)) {
				error = -EFSBADCRC;
				goto out_error;
			}
		}
	}

	/*
	 * Check all the superblock fields.  Don't byteswap the xquota flags
	 * because _verify_common checks the on-disk values.
	 */
	__xfs_sb_from_disk(&sb, dsb, false);
	error = xfs_validate_sb_common(mp, bp, &sb);
	if (error)
		goto out_error;
	error = xfs_validate_sb_read(mp, &sb);

out_error:
	if (error == -EFSCORRUPTED || error == -EFSBADCRC)
		xfs_verifier_error(bp, error, __this_address);
	else if (error)
		xfs_buf_ioerror(bp, error);
}

/*
 * We may be probed for a filesystem match, so we may not want to emit
 * messages when the superblock buffer is not actually an XFS superblock.
 * If we find an XFS superblock, then run a normal, noisy mount because we are
 * really going to mount it and want to know about errors.
 */
static void
xfs_sb_quiet_read_verify(
	struct xfs_buf	*bp)
{
	struct xfs_dsb	*dsb = bp->b_addr;

	if (dsb->sb_magicnum == cpu_to_be32(XFS_SB_MAGIC)) {
		/* XFS filesystem, verify noisily! */
		xfs_sb_read_verify(bp);
		return;
	}
	/* quietly fail */
	xfs_buf_ioerror(bp, -EWRONGFS);
}

static void
xfs_sb_write_verify(
	struct xfs_buf		*bp)
{
	struct xfs_sb		sb;
	struct xfs_mount	*mp = bp->b_mount;
	struct xfs_buf_log_item	*bip = bp->b_log_item;
	struct xfs_dsb		*dsb = bp->b_addr;
	int			error;

	/*
	 * Check all the superblock fields.  Don't byteswap the xquota flags
	 * because _verify_common checks the on-disk values.
	 */
	__xfs_sb_from_disk(&sb, dsb, false);
	error = xfs_validate_sb_common(mp, bp, &sb);
	if (error)
		goto out_error;
	error = xfs_validate_sb_write(mp, bp, &sb);
	if (error)
		goto out_error;

	if (!xfs_sb_is_v5(&sb))
		return;

	if (bip)
		dsb->sb_lsn = cpu_to_be64(bip->bli_item.li_lsn);

	xfs_buf_update_cksum(bp, XFS_SB_CRC_OFF);
	return;

out_error:
	xfs_verifier_error(bp, error, __this_address);
}

const struct xfs_buf_ops xfs_sb_buf_ops = {
	.name = "xfs_sb",
	.magic = { cpu_to_be32(XFS_SB_MAGIC), cpu_to_be32(XFS_SB_MAGIC) },
	.verify_read = xfs_sb_read_verify,
	.verify_write = xfs_sb_write_verify,
};

const struct xfs_buf_ops xfs_sb_quiet_buf_ops = {
	.name = "xfs_sb_quiet",
	.magic = { cpu_to_be32(XFS_SB_MAGIC), cpu_to_be32(XFS_SB_MAGIC) },
	.verify_read = xfs_sb_quiet_read_verify,
	.verify_write = xfs_sb_write_verify,
};

/*
 * xfs_mount_common
 *
 * Mount initialization code establishing various mount
 * fields from the superblock associated with the given
 * mount structure.
 *
 * Inode geometry are calculated in xfs_ialloc_setup_geometry.
 */
void
xfs_sb_mount_common(
	struct xfs_mount	*mp,
	struct xfs_sb		*sbp)
{
	mp->m_agfrotor = 0;
	atomic_set(&mp->m_agirotor, 0);
	mp->m_maxagi = mp->m_sb.sb_agcount;
	mp->m_blkbit_log = sbp->sb_blocklog + XFS_NBBYLOG;
	mp->m_blkbb_log = sbp->sb_blocklog - BBSHIFT;
	mp->m_sectbb_log = sbp->sb_sectlog - BBSHIFT;
	mp->m_agno_log = xfs_highbit32(sbp->sb_agcount - 1) + 1;
	mp->m_blockmask = sbp->sb_blocksize - 1;
	mp->m_blockwsize = sbp->sb_blocksize >> XFS_WORDLOG;
	mp->m_blockwmask = mp->m_blockwsize - 1;
	mp->m_rtxblklog = log2_if_power2(sbp->sb_rextsize);
	mp->m_rtxblkmask = mask64_if_power2(sbp->sb_rextsize);

	mp->m_alloc_mxr[0] = xfs_allocbt_maxrecs(mp, sbp->sb_blocksize, 1);
	mp->m_alloc_mxr[1] = xfs_allocbt_maxrecs(mp, sbp->sb_blocksize, 0);
	mp->m_alloc_mnr[0] = mp->m_alloc_mxr[0] / 2;
	mp->m_alloc_mnr[1] = mp->m_alloc_mxr[1] / 2;

	mp->m_bmap_dmxr[0] = xfs_bmbt_maxrecs(mp, sbp->sb_blocksize, 1);
	mp->m_bmap_dmxr[1] = xfs_bmbt_maxrecs(mp, sbp->sb_blocksize, 0);
	mp->m_bmap_dmnr[0] = mp->m_bmap_dmxr[0] / 2;
	mp->m_bmap_dmnr[1] = mp->m_bmap_dmxr[1] / 2;

	mp->m_rmap_mxr[0] = xfs_rmapbt_maxrecs(sbp->sb_blocksize, 1);
	mp->m_rmap_mxr[1] = xfs_rmapbt_maxrecs(sbp->sb_blocksize, 0);
	mp->m_rmap_mnr[0] = mp->m_rmap_mxr[0] / 2;
	mp->m_rmap_mnr[1] = mp->m_rmap_mxr[1] / 2;

	mp->m_refc_mxr[0] = xfs_refcountbt_maxrecs(sbp->sb_blocksize, true);
	mp->m_refc_mxr[1] = xfs_refcountbt_maxrecs(sbp->sb_blocksize, false);
	mp->m_refc_mnr[0] = mp->m_refc_mxr[0] / 2;
	mp->m_refc_mnr[1] = mp->m_refc_mxr[1] / 2;

	mp->m_bsize = XFS_FSB_TO_BB(mp, 1);
	mp->m_alloc_set_aside = xfs_alloc_set_aside(mp);
	mp->m_ag_max_usable = xfs_alloc_ag_max_usable(mp);
}

/*
 * xfs_log_sb() can be used to copy arbitrary changes to the in-core superblock
 * into the superblock buffer to be logged.  It does not provide the higher
 * level of locking that is needed to protect the in-core superblock from
 * concurrent access.
 */
void
xfs_log_sb(
	struct xfs_trans	*tp)
{
	struct xfs_mount	*mp = tp->t_mountp;
	struct xfs_buf		*bp = xfs_trans_getsb(tp);

	/*
	 * Lazy sb counters don't update the in-core superblock so do that now.
	 * If this is at unmount, the counters will be exactly correct, but at
	 * any other time they will only be ballpark correct because of
	 * reservations that have been taken out percpu counters. If we have an
	 * unclean shutdown, this will be corrected by log recovery rebuilding
	 * the counters from the AGF block counts.
	 *
	 * Do not update sb_frextents here because it is not part of the lazy
	 * sb counters, despite having a percpu counter. It is always kept
	 * consistent with the ondisk rtbitmap by xfs_trans_apply_sb_deltas()
	 * and hence we don't need have to update it here.
	 */
	if (xfs_has_lazysbcount(mp)) {
		mp->m_sb.sb_icount = percpu_counter_sum(&mp->m_icount);
		mp->m_sb.sb_ifree = min_t(uint64_t,
				percpu_counter_sum(&mp->m_ifree),
				mp->m_sb.sb_icount);
		mp->m_sb.sb_fdblocks = percpu_counter_sum(&mp->m_fdblocks);
	}

	xfs_sb_to_disk(bp->b_addr, &mp->m_sb);
	xfs_trans_buf_set_type(tp, bp, XFS_BLFT_SB_BUF);
	xfs_trans_log_buf(tp, bp, 0, sizeof(struct xfs_dsb) - 1);
}

/*
 * xfs_sync_sb
 *
 * Sync the superblock to disk.
 *
 * Note that the caller is responsible for checking the frozen state of the
 * filesystem. This procedure uses the non-blocking transaction allocator and
 * thus will allow modifications to a frozen fs. This is required because this
 * code can be called during the process of freezing where use of the high-level
 * allocator would deadlock.
 */
int
xfs_sync_sb(
	struct xfs_mount	*mp,
	bool			wait)
{
	struct xfs_trans	*tp;
	int			error;

	error = xfs_trans_alloc(mp, &M_RES(mp)->tr_sb, 0, 0,
			XFS_TRANS_NO_WRITECOUNT, &tp);
	if (error)
		return error;

	xfs_log_sb(tp);
	if (wait)
		xfs_trans_set_sync(tp);
	return xfs_trans_commit(tp);
}

/*
 * Update all the secondary superblocks to match the new state of the primary.
 * Because we are completely overwriting all the existing fields in the
 * secondary superblock buffers, there is no need to read them in from disk.
 * Just get a new buffer, stamp it and write it.
 *
 * The sb buffers need to be cached here so that we serialise against other
 * operations that access the secondary superblocks, but we don't want to keep
 * them in memory once it is written so we mark it as a one-shot buffer.
 */
int
xfs_update_secondary_sbs(
	struct xfs_mount	*mp)
{
	struct xfs_perag	*pag;
	xfs_agnumber_t		agno = 1;
	int			saved_error = 0;
	int			error = 0;
	LIST_HEAD		(buffer_list);

	/* update secondary superblocks. */
	for_each_perag_from(mp, agno, pag) {
		struct xfs_buf		*bp;

		error = xfs_buf_get(mp->m_ddev_targp,
				 XFS_AG_DADDR(mp, pag->pag_agno, XFS_SB_DADDR),
				 XFS_FSS_TO_BB(mp, 1), &bp);
		/*
		 * If we get an error reading or writing alternate superblocks,
		 * continue.  xfs_repair chooses the "best" superblock based
		 * on most matches; if we break early, we'll leave more
		 * superblocks un-updated than updated, and xfs_repair may
		 * pick them over the properly-updated primary.
		 */
		if (error) {
			xfs_warn(mp,
		"error allocating secondary superblock for ag %d",
				pag->pag_agno);
			if (!saved_error)
				saved_error = error;
			continue;
		}

		bp->b_ops = &xfs_sb_buf_ops;
		xfs_buf_oneshot(bp);
		xfs_buf_zero(bp, 0, BBTOB(bp->b_length));
		xfs_sb_to_disk(bp->b_addr, &mp->m_sb);
		xfs_buf_delwri_queue(bp, &buffer_list);
		xfs_buf_relse(bp);

		/* don't hold too many buffers at once */
		if (agno % 16)
			continue;

		error = xfs_buf_delwri_submit(&buffer_list);
		if (error) {
			xfs_warn(mp,
		"write error %d updating a secondary superblock near ag %d",
				error, pag->pag_agno);
			if (!saved_error)
				saved_error = error;
			continue;
		}
	}
	error = xfs_buf_delwri_submit(&buffer_list);
	if (error) {
		xfs_warn(mp,
		"write error %d updating a secondary superblock near ag %d",
			error, agno);
	}

	return saved_error ? saved_error : error;
}

/*
 * Same behavior as xfs_sync_sb, except that it is always synchronous and it
 * also writes the superblock buffer to disk sector 0 immediately.
 */
int
xfs_sync_sb_buf(
	struct xfs_mount	*mp)
{
	struct xfs_trans	*tp;
	struct xfs_buf		*bp;
	int			error;

	error = xfs_trans_alloc(mp, &M_RES(mp)->tr_sb, 0, 0, 0, &tp);
	if (error)
		return error;

	bp = xfs_trans_getsb(tp);
	xfs_log_sb(tp);
	xfs_trans_bhold(tp, bp);
	xfs_trans_set_sync(tp);
	error = xfs_trans_commit(tp);
	if (error)
		goto out;
	/*
	 * write out the sb buffer to get the changes to disk
	 */
	error = xfs_bwrite(bp);
out:
	xfs_buf_relse(bp);
	return error;
}

void
xfs_fs_geometry(
	struct xfs_mount	*mp,
	struct xfs_fsop_geom	*geo,
	int			struct_version)
{
	struct xfs_sb		*sbp = &mp->m_sb;

	memset(geo, 0, sizeof(struct xfs_fsop_geom));

	geo->blocksize = sbp->sb_blocksize;
	geo->rtextsize = sbp->sb_rextsize;
	geo->agblocks = sbp->sb_agblocks;
	geo->agcount = sbp->sb_agcount;
	geo->logblocks = sbp->sb_logblocks;
	geo->sectsize = sbp->sb_sectsize;
	geo->inodesize = sbp->sb_inodesize;
	geo->imaxpct = sbp->sb_imax_pct;
	geo->datablocks = sbp->sb_dblocks;
	geo->rtblocks = sbp->sb_rblocks;
	geo->rtextents = sbp->sb_rextents;
	geo->logstart = sbp->sb_logstart;
	BUILD_BUG_ON(sizeof(geo->uuid) != sizeof(sbp->sb_uuid));
	memcpy(geo->uuid, &sbp->sb_uuid, sizeof(sbp->sb_uuid));

	if (struct_version < 2)
		return;

	geo->sunit = sbp->sb_unit;
	geo->swidth = sbp->sb_width;

	if (struct_version < 3)
		return;

	geo->version = XFS_FSOP_GEOM_VERSION;
	geo->flags = XFS_FSOP_GEOM_FLAGS_NLINK |
		     XFS_FSOP_GEOM_FLAGS_DIRV2 |
		     XFS_FSOP_GEOM_FLAGS_EXTFLG;
	if (xfs_has_attr(mp))
		geo->flags |= XFS_FSOP_GEOM_FLAGS_ATTR;
	if (xfs_has_quota(mp))
		geo->flags |= XFS_FSOP_GEOM_FLAGS_QUOTA;
	if (xfs_has_align(mp))
		geo->flags |= XFS_FSOP_GEOM_FLAGS_IALIGN;
	if (xfs_has_dalign(mp))
		geo->flags |= XFS_FSOP_GEOM_FLAGS_DALIGN;
	if (xfs_has_asciici(mp))
		geo->flags |= XFS_FSOP_GEOM_FLAGS_DIRV2CI;
	if (xfs_has_lazysbcount(mp))
		geo->flags |= XFS_FSOP_GEOM_FLAGS_LAZYSB;
	if (xfs_has_attr2(mp))
		geo->flags |= XFS_FSOP_GEOM_FLAGS_ATTR2;
	if (xfs_has_projid32(mp))
		geo->flags |= XFS_FSOP_GEOM_FLAGS_PROJID32;
	if (xfs_has_crc(mp))
		geo->flags |= XFS_FSOP_GEOM_FLAGS_V5SB;
	if (xfs_has_ftype(mp))
		geo->flags |= XFS_FSOP_GEOM_FLAGS_FTYPE;
	if (xfs_has_finobt(mp))
		geo->flags |= XFS_FSOP_GEOM_FLAGS_FINOBT;
	if (xfs_has_sparseinodes(mp))
		geo->flags |= XFS_FSOP_GEOM_FLAGS_SPINODES;
	if (xfs_has_rmapbt(mp))
		geo->flags |= XFS_FSOP_GEOM_FLAGS_RMAPBT;
	if (xfs_has_reflink(mp))
		geo->flags |= XFS_FSOP_GEOM_FLAGS_REFLINK;
	if (xfs_has_bigtime(mp))
		geo->flags |= XFS_FSOP_GEOM_FLAGS_BIGTIME;
	if (xfs_has_inobtcounts(mp))
		geo->flags |= XFS_FSOP_GEOM_FLAGS_INOBTCNT;
	if (xfs_has_sector(mp)) {
		geo->flags |= XFS_FSOP_GEOM_FLAGS_SECTOR;
		geo->logsectsize = sbp->sb_logsectsize;
	} else {
		geo->logsectsize = BBSIZE;
	}
	if (xfs_has_large_extent_counts(mp))
		geo->flags |= XFS_FSOP_GEOM_FLAGS_NREXT64;
	geo->rtsectsize = sbp->sb_blocksize;
	geo->dirblocksize = xfs_dir2_dirblock_bytes(sbp);

	if (struct_version < 4)
		return;

	if (xfs_has_logv2(mp))
		geo->flags |= XFS_FSOP_GEOM_FLAGS_LOGV2;

	geo->logsunit = sbp->sb_logsunit;

	if (struct_version < 5)
		return;

	geo->version = XFS_FSOP_GEOM_VERSION_V5;
}

/* Read a secondary superblock. */
int
xfs_sb_read_secondary(
	struct xfs_mount	*mp,
	struct xfs_trans	*tp,
	xfs_agnumber_t		agno,
	struct xfs_buf		**bpp)
{
	struct xfs_buf		*bp;
	int			error;

	ASSERT(agno != 0 && agno != NULLAGNUMBER);
	error = xfs_trans_read_buf(mp, tp, mp->m_ddev_targp,
			XFS_AG_DADDR(mp, agno, XFS_SB_BLOCK(mp)),
			XFS_FSS_TO_BB(mp, 1), 0, &bp, &xfs_sb_buf_ops);
	if (error)
		return error;
	xfs_buf_set_ref(bp, XFS_SSB_REF);
	*bpp = bp;
	return 0;
}

/* Get an uninitialised secondary superblock buffer. */
int
xfs_sb_get_secondary(
	struct xfs_mount	*mp,
	struct xfs_trans	*tp,
	xfs_agnumber_t		agno,
	struct xfs_buf		**bpp)
{
	struct xfs_buf		*bp;
	int			error;

	ASSERT(agno != 0 && agno != NULLAGNUMBER);
	error = xfs_trans_get_buf(tp, mp->m_ddev_targp,
			XFS_AG_DADDR(mp, agno, XFS_SB_BLOCK(mp)),
			XFS_FSS_TO_BB(mp, 1), 0, &bp);
	if (error)
		return error;
	bp->b_ops = &xfs_sb_buf_ops;
	xfs_buf_oneshot(bp);
	*bpp = bp;
	return 0;
}

/*
 * sunit, swidth, sectorsize(optional with 0) should be all in bytes,
 * so users won't be confused by values in error messages.
 */
bool
xfs_validate_stripe_geometry(
	struct xfs_mount	*mp,
	__s64			sunit,
	__s64			swidth,
	int			sectorsize,
	bool			silent)
{
	if (swidth > INT_MAX) {
		if (!silent)
			xfs_notice(mp,
"stripe width (%lld) is too large", swidth);
		return false;
	}

	if (sunit > swidth) {
		if (!silent)
			xfs_notice(mp,
"stripe unit (%lld) is larger than the stripe width (%lld)", sunit, swidth);
		return false;
	}

	if (sectorsize && (int)sunit % sectorsize) {
		if (!silent)
			xfs_notice(mp,
"stripe unit (%lld) must be a multiple of the sector size (%d)",
				   sunit, sectorsize);
		return false;
	}

	if (sunit && !swidth) {
		if (!silent)
			xfs_notice(mp,
"invalid stripe unit (%lld) and stripe width of 0", sunit);
		return false;
	}

	if (!sunit && swidth) {
		if (!silent)
			xfs_notice(mp,
"invalid stripe width (%lld) and stripe unit of 0", swidth);
		return false;
	}

	if (sunit && (int)swidth % (int)sunit) {
		if (!silent)
			xfs_notice(mp,
"stripe width (%lld) must be a multiple of the stripe unit (%lld)",
				   swidth, sunit);
		return false;
	}
	return true;
}

/*
 * Compute the maximum level number of the realtime summary file, as defined by
 * mkfs.  The historic use of highbit32 on a 64-bit quantity prohibited correct
 * use of rt volumes with more than 2^32 extents.
 */
uint8_t
xfs_compute_rextslog(
	xfs_rtbxlen_t		rtextents)
{
	if (!rtextents)
		return 0;
	return xfs_highbit64(rtextents);
}
