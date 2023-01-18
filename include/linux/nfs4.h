/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  include/linux/nfs4.h
 *
 *  NFSv4 protocol definitions.
 *
 *  Copyright (c) 2002 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Kendrick Smith <kmsmith@umich.edu>
 *  Andy Adamson   <andros@umich.edu>
 */
#ifndef _LINUX_NFS4_H
#define _LINUX_NFS4_H

#include <linux/list.h>
#include <linux/uidgid.h>
#include <uapi/linux/nfs4.h>
#include <linux/sunrpc/msg_prot.h>

enum nfs4_acl_whotype {
	NFS4_ACL_WHO_NAMED = 0,
	NFS4_ACL_WHO_OWNER,
	NFS4_ACL_WHO_GROUP,
	NFS4_ACL_WHO_EVERYONE,
};

struct nfs4_ace {
	uint32_t	type;
	uint32_t	flag;
	uint32_t	access_mask;
	int		whotype;
	union {
		kuid_t	who_uid;
		kgid_t	who_gid;
	};
};

struct nfs4_acl {
	uint32_t	naces;
	struct nfs4_ace	aces[];
};

#define NFS4_MAXLABELLEN	2048

struct nfs4_label {
	uint32_t	lfs;
	uint32_t	pi;
	u32		len;
	char	*label;
};

typedef struct { char data[NFS4_VERIFIER_SIZE]; } nfs4_verifier;

struct nfs4_stateid_struct {
	union {
		char data[NFS4_STATEID_SIZE];
		struct {
			__be32 seqid;
			char other[NFS4_STATEID_OTHER_SIZE];
		} __attribute__ ((packed));
	};

	enum {
		NFS4_INVALID_STATEID_TYPE = 0,
		NFS4_SPECIAL_STATEID_TYPE,
		NFS4_OPEN_STATEID_TYPE,
		NFS4_LOCK_STATEID_TYPE,
		NFS4_DELEGATION_STATEID_TYPE,
		NFS4_LAYOUT_STATEID_TYPE,
		NFS4_PNFS_DS_STATEID_TYPE,
		NFS4_REVOKED_STATEID_TYPE,
	} type;
};

typedef struct nfs4_stateid_struct nfs4_stateid;

enum nfs_opnum4 {
	OP_ACCESS = 3,
	OP_CLOSE = 4,
	OP_COMMIT = 5,
	OP_CREATE = 6,
	OP_DELEGPURGE = 7,
	OP_DELEGRETURN = 8,
	OP_GETATTR = 9,
	OP_GETFH = 10,
	OP_LINK = 11,
	OP_LOCK = 12,
	OP_LOCKT = 13,
	OP_LOCKU = 14,
	OP_LOOKUP = 15,
	OP_LOOKUPP = 16,
	OP_NVERIFY = 17,
	OP_OPEN = 18,
	OP_OPENATTR = 19,
	OP_OPEN_CONFIRM = 20,
	OP_OPEN_DOWNGRADE = 21,
	OP_PUTFH = 22,
	OP_PUTPUBFH = 23,
	OP_PUTROOTFH = 24,
	OP_READ = 25,
	OP_READDIR = 26,
	OP_READLINK = 27,
	OP_REMOVE = 28,
	OP_RENAME = 29,
	OP_RENEW = 30,
	OP_RESTOREFH = 31,
	OP_SAVEFH = 32,
	OP_SECINFO = 33,
	OP_SETATTR = 34,
	OP_SETCLIENTID = 35,
	OP_SETCLIENTID_CONFIRM = 36,
	OP_VERIFY = 37,
	OP_WRITE = 38,
	OP_RELEASE_LOCKOWNER = 39,

	/* nfs41 */
	OP_BACKCHANNEL_CTL = 40,
	OP_BIND_CONN_TO_SESSION = 41,
	OP_EXCHANGE_ID = 42,
	OP_CREATE_SESSION = 43,
	OP_DESTROY_SESSION = 44,
	OP_FREE_STATEID = 45,
	OP_GET_DIR_DELEGATION = 46,
	OP_GETDEVICEINFO = 47,
	OP_GETDEVICELIST = 48,
	OP_LAYOUTCOMMIT = 49,
	OP_LAYOUTGET = 50,
	OP_LAYOUTRETURN = 51,
	OP_SECINFO_NO_NAME = 52,
	OP_SEQUENCE = 53,
	OP_SET_SSV = 54,
	OP_TEST_STATEID = 55,
	OP_WANT_DELEGATION = 56,
	OP_DESTROY_CLIENTID = 57,
	OP_RECLAIM_COMPLETE = 58,

	/* nfs42 */
	OP_ALLOCATE = 59,
	OP_COPY = 60,
	OP_COPY_NOTIFY = 61,
	OP_DEALLOCATE = 62,
	OP_IO_ADVISE = 63,
	OP_LAYOUTERROR = 64,
	OP_LAYOUTSTATS = 65,
	OP_OFFLOAD_CANCEL = 66,
	OP_OFFLOAD_STATUS = 67,
	OP_READ_PLUS = 68,
	OP_SEEK = 69,
	OP_WRITE_SAME = 70,
	OP_CLONE = 71,

	/* xattr support (RFC8726) */
	OP_GETXATTR                = 72,
	OP_SETXATTR                = 73,
	OP_LISTXATTRS              = 74,
	OP_REMOVEXATTR             = 75,

	OP_ILLEGAL = 10044,
};

/*Defining first and last NFS4 operations implemented.
Needs to be updated if more operations are defined in future.*/

#define FIRST_NFS4_OP	OP_ACCESS
#define LAST_NFS40_OP	OP_RELEASE_LOCKOWNER
#define LAST_NFS41_OP	OP_RECLAIM_COMPLETE
#define LAST_NFS42_OP	OP_REMOVEXATTR
#define LAST_NFS4_OP	LAST_NFS42_OP

enum nfsstat4 {
	NFS4_OK = 0,
	NFS4ERR_PERM = 1,
	NFS4ERR_NOENT = 2,
	NFS4ERR_IO = 5,
	NFS4ERR_NXIO = 6,
	NFS4ERR_ACCESS = 13,
	NFS4ERR_EXIST = 17,
	NFS4ERR_XDEV = 18,
	/* Unused/reserved 19 */
	NFS4ERR_NOTDIR = 20,
	NFS4ERR_ISDIR = 21,
	NFS4ERR_INVAL = 22,
	NFS4ERR_FBIG = 27,
	NFS4ERR_NOSPC = 28,
	NFS4ERR_ROFS = 30,
	NFS4ERR_MLINK = 31,
	NFS4ERR_NAMETOOLONG = 63,
	NFS4ERR_NOTEMPTY = 66,
	NFS4ERR_DQUOT = 69,
	NFS4ERR_STALE = 70,
	NFS4ERR_BADHANDLE = 10001,
	NFS4ERR_BAD_COOKIE = 10003,
	NFS4ERR_NOTSUPP = 10004,
	NFS4ERR_TOOSMALL = 10005,
	NFS4ERR_SERVERFAULT = 10006,
	NFS4ERR_BADTYPE = 10007,
	NFS4ERR_DELAY = 10008,
	NFS4ERR_SAME = 10009,
	NFS4ERR_DENIED = 10010,
	NFS4ERR_EXPIRED = 10011,
	NFS4ERR_LOCKED = 10012,
	NFS4ERR_GRACE = 10013,
	NFS4ERR_FHEXPIRED = 10014,
	NFS4ERR_SHARE_DENIED = 10015,
	NFS4ERR_WRONGSEC = 10016,
	NFS4ERR_CLID_INUSE = 10017,
	NFS4ERR_RESOURCE = 10018,
	NFS4ERR_MOVED = 10019,
	NFS4ERR_NOFILEHANDLE = 10020,
	NFS4ERR_MINOR_VERS_MISMATCH = 10021,
	NFS4ERR_STALE_CLIENTID = 10022,
	NFS4ERR_STALE_STATEID = 10023,
	NFS4ERR_OLD_STATEID = 10024,
	NFS4ERR_BAD_STATEID = 10025,
	NFS4ERR_BAD_SEQID = 10026,
	NFS4ERR_NOT_SAME = 10027,
	NFS4ERR_LOCK_RANGE = 10028,
	NFS4ERR_SYMLINK = 10029,
	NFS4ERR_RESTOREFH = 10030,
	NFS4ERR_LEASE_MOVED = 10031,
	NFS4ERR_ATTRNOTSUPP = 10032,
	NFS4ERR_NO_GRACE = 10033,
	NFS4ERR_RECLAIM_BAD = 10034,
	NFS4ERR_RECLAIM_CONFLICT = 10035,
	NFS4ERR_BADXDR = 10036,
	NFS4ERR_LOCKS_HELD = 10037,
	NFS4ERR_OPENMODE = 10038,
	NFS4ERR_BADOWNER = 10039,
	NFS4ERR_BADCHAR = 10040,
	NFS4ERR_BADNAME = 10041,
	NFS4ERR_BAD_RANGE = 10042,
	NFS4ERR_LOCK_NOTSUPP = 10043,
	NFS4ERR_OP_ILLEGAL = 10044,
	NFS4ERR_DEADLOCK = 10045,
	NFS4ERR_FILE_OPEN = 10046,
	NFS4ERR_ADMIN_REVOKED = 10047,
	NFS4ERR_CB_PATH_DOWN = 10048,

	/* nfs41 */
	NFS4ERR_BADIOMODE	= 10049,
	NFS4ERR_BADLAYOUT	= 10050,
	NFS4ERR_BAD_SESSION_DIGEST = 10051,
	NFS4ERR_BADSESSION	= 10052,
	NFS4ERR_BADSLOT		= 10053,
	NFS4ERR_COMPLETE_ALREADY = 10054,
	NFS4ERR_CONN_NOT_BOUND_TO_SESSION = 10055,
	NFS4ERR_DELEG_ALREADY_WANTED = 10056,
	NFS4ERR_BACK_CHAN_BUSY	= 10057,	/* backchan reqs outstanding */
	NFS4ERR_LAYOUTTRYLATER	= 10058,
	NFS4ERR_LAYOUTUNAVAILABLE = 10059,
	NFS4ERR_NOMATCHING_LAYOUT = 10060,
	NFS4ERR_RECALLCONFLICT	= 10061,
	NFS4ERR_UNKNOWN_LAYOUTTYPE = 10062,
	NFS4ERR_SEQ_MISORDERED = 10063, 	/* unexpected seq.id in req */
	NFS4ERR_SEQUENCE_POS	= 10064,	/* [CB_]SEQ. op not 1st op */
	NFS4ERR_REQ_TOO_BIG	= 10065,	/* request too big */
	NFS4ERR_REP_TOO_BIG	= 10066,	/* reply too big */
	NFS4ERR_REP_TOO_BIG_TO_CACHE = 10067,	/* rep. not all cached */
	NFS4ERR_RETRY_UNCACHED_REP = 10068,	/* retry & rep. uncached */
	NFS4ERR_UNSAFE_COMPOUND = 10069,	/* retry/recovery too hard */
	NFS4ERR_TOO_MANY_OPS	= 10070,	/* too many ops in [CB_]COMP */
	NFS4ERR_OP_NOT_IN_SESSION = 10071,	/* op needs [CB_]SEQ. op */
	NFS4ERR_HASH_ALG_UNSUPP = 10072,	/* hash alg. not supp. */
						/* Error 10073 is unused. */
	NFS4ERR_CLIENTID_BUSY	= 10074,	/* clientid has state */
	NFS4ERR_PNFS_IO_HOLE	= 10075,	/* IO to _SPARSE file hole */
	NFS4ERR_SEQ_FALSE_RETRY	= 10076,	/* retry not original */
	NFS4ERR_BAD_HIGH_SLOT	= 10077,	/* sequence arg bad */
	NFS4ERR_DEADSESSION	= 10078,	/* persistent session dead */
	NFS4ERR_ENCR_ALG_UNSUPP = 10079,	/* SSV alg mismatch */
	NFS4ERR_PNFS_NO_LAYOUT	= 10080,	/* direct I/O with no layout */
	NFS4ERR_NOT_ONLY_OP	= 10081,	/* bad compound */
	NFS4ERR_WRONG_CRED	= 10082,	/* permissions:state change */
	NFS4ERR_WRONG_TYPE	= 10083,	/* current operation mismatch */
	NFS4ERR_DIRDELEG_UNAVAIL = 10084,	/* no directory delegation */
	NFS4ERR_REJECT_DELEG	= 10085,	/* on callback */
	NFS4ERR_RETURNCONFLICT	= 10086,	/* outstanding layoutreturn */
	NFS4ERR_DELEG_REVOKED	= 10087,	/* deleg./layout revoked */

	/* nfs42 */
	NFS4ERR_PARTNER_NOTSUPP	= 10088,
	NFS4ERR_PARTNER_NO_AUTH	= 10089,
	NFS4ERR_UNION_NOTSUPP = 10090,
	NFS4ERR_OFFLOAD_DENIED = 10091,
	NFS4ERR_WRONG_LFS = 10092,
	NFS4ERR_BADLABEL = 10093,
	NFS4ERR_OFFLOAD_NO_REQS = 10094,

	/* xattr (RFC8276) */
	NFS4ERR_NOXATTR        = 10095,
	NFS4ERR_XATTR2BIG      = 10096,
};

/* error codes for internal client use */
#define NFS4ERR_RESET_TO_MDS   12001
#define NFS4ERR_RESET_TO_PNFS  12002

static inline bool seqid_mutating_err(u32 err)
{
	/* See RFC 7530, section 9.1.7 */
	switch (err) {
	case NFS4ERR_STALE_CLIENTID:
	case NFS4ERR_STALE_STATEID:
	case NFS4ERR_BAD_STATEID:
	case NFS4ERR_BAD_SEQID:
	case NFS4ERR_BADXDR:
	case NFS4ERR_RESOURCE:
	case NFS4ERR_NOFILEHANDLE:
	case NFS4ERR_MOVED:
		return false;
	}
	return true;
}

/*
 * Note: NF4BAD is not actually part of the protocol; it is just used
 * internally by nfsd.
 */
enum nfs_ftype4 {
	NF4BAD		= 0,
        NF4REG          = 1,    /* Regular File */
        NF4DIR          = 2,    /* Directory */
        NF4BLK          = 3,    /* Special File - block device */
        NF4CHR          = 4,    /* Special File - character device */
        NF4LNK          = 5,    /* Symbolic Link */
        NF4SOCK         = 6,    /* Special File - socket */
        NF4FIFO         = 7,    /* Special File - fifo */
        NF4ATTRDIR      = 8,    /* Attribute Directory */
        NF4NAMEDATTR    = 9     /* Named Attribute */
};

enum open_claim_type4 {
	NFS4_OPEN_CLAIM_NULL = 0,
	NFS4_OPEN_CLAIM_PREVIOUS = 1,
	NFS4_OPEN_CLAIM_DELEGATE_CUR = 2,
	NFS4_OPEN_CLAIM_DELEGATE_PREV = 3,
	NFS4_OPEN_CLAIM_FH = 4, /* 4.1 */
	NFS4_OPEN_CLAIM_DELEG_CUR_FH = 5, /* 4.1 */
	NFS4_OPEN_CLAIM_DELEG_PREV_FH = 6, /* 4.1 */
};

enum opentype4 {
	NFS4_OPEN_NOCREATE = 0,
	NFS4_OPEN_CREATE = 1
};

enum createmode4 {
	NFS4_CREATE_UNCHECKED = 0,
	NFS4_CREATE_GUARDED = 1,
	NFS4_CREATE_EXCLUSIVE = 2,
	/*
	 * New to NFSv4.1. If session is persistent,
	 * GUARDED4 MUST be used. Otherwise, use
	 * EXCLUSIVE4_1 instead of EXCLUSIVE4.
	 */
	NFS4_CREATE_EXCLUSIVE4_1 = 3
};

enum limit_by4 {
	NFS4_LIMIT_SIZE = 1,
	NFS4_LIMIT_BLOCKS = 2
};

enum open_delegation_type4 {
	NFS4_OPEN_DELEGATE_NONE = 0,
	NFS4_OPEN_DELEGATE_READ = 1,
	NFS4_OPEN_DELEGATE_WRITE = 2,
	NFS4_OPEN_DELEGATE_NONE_EXT = 3, /* 4.1 */
};

enum why_no_delegation4 { /* new to v4.1 */
	WND4_NOT_WANTED = 0,
	WND4_CONTENTION = 1,
	WND4_RESOURCE = 2,
	WND4_NOT_SUPP_FTYPE = 3,
	WND4_WRITE_DELEG_NOT_SUPP_FTYPE = 4,
	WND4_NOT_SUPP_UPGRADE = 5,
	WND4_NOT_SUPP_DOWNGRADE = 6,
	WND4_CANCELLED = 7,
	WND4_IS_DIR = 8,
};

enum lock_type4 {
	NFS4_UNLOCK_LT = 0,
	NFS4_READ_LT = 1,
	NFS4_WRITE_LT = 2,
	NFS4_READW_LT = 3,
	NFS4_WRITEW_LT = 4
};


/* Mandatory Attributes */
#define FATTR4_WORD0_SUPPORTED_ATTRS    (1UL << 0)
#define FATTR4_WORD0_TYPE               (1UL << 1)
#define FATTR4_WORD0_FH_EXPIRE_TYPE     (1UL << 2)
#define FATTR4_WORD0_CHANGE             (1UL << 3)
#define FATTR4_WORD0_SIZE               (1UL << 4)
#define FATTR4_WORD0_LINK_SUPPORT       (1UL << 5)
#define FATTR4_WORD0_SYMLINK_SUPPORT    (1UL << 6)
#define FATTR4_WORD0_NAMED_ATTR         (1UL << 7)
#define FATTR4_WORD0_FSID               (1UL << 8)
#define FATTR4_WORD0_UNIQUE_HANDLES     (1UL << 9)
#define FATTR4_WORD0_LEASE_TIME         (1UL << 10)
#define FATTR4_WORD0_RDATTR_ERROR       (1UL << 11)
/* Mandatory in NFSv4.1 */
#define FATTR4_WORD2_SUPPATTR_EXCLCREAT (1UL << 11)

/* Recommended Attributes */
#define FATTR4_WORD0_ACL                (1UL << 12)
#define FATTR4_WORD0_ACLSUPPORT         (1UL << 13)
#define FATTR4_WORD0_ARCHIVE            (1UL << 14)
#define FATTR4_WORD0_CANSETTIME         (1UL << 15)
#define FATTR4_WORD0_CASE_INSENSITIVE   (1UL << 16)
#define FATTR4_WORD0_CASE_PRESERVING    (1UL << 17)
#define FATTR4_WORD0_CHOWN_RESTRICTED   (1UL << 18)
#define FATTR4_WORD0_FILEHANDLE         (1UL << 19)
#define FATTR4_WORD0_FILEID             (1UL << 20)
#define FATTR4_WORD0_FILES_AVAIL        (1UL << 21)
#define FATTR4_WORD0_FILES_FREE         (1UL << 22)
#define FATTR4_WORD0_FILES_TOTAL        (1UL << 23)
#define FATTR4_WORD0_FS_LOCATIONS       (1UL << 24)
#define FATTR4_WORD0_HIDDEN             (1UL << 25)
#define FATTR4_WORD0_HOMOGENEOUS        (1UL << 26)
#define FATTR4_WORD0_MAXFILESIZE        (1UL << 27)
#define FATTR4_WORD0_MAXLINK            (1UL << 28)
#define FATTR4_WORD0_MAXNAME            (1UL << 29)
#define FATTR4_WORD0_MAXREAD            (1UL << 30)
#define FATTR4_WORD0_MAXWRITE           (1UL << 31)
#define FATTR4_WORD1_MIMETYPE           (1UL << 0)
#define FATTR4_WORD1_MODE               (1UL << 1)
#define FATTR4_WORD1_NO_TRUNC           (1UL << 2)
#define FATTR4_WORD1_NUMLINKS           (1UL << 3)
#define FATTR4_WORD1_OWNER              (1UL << 4)
#define FATTR4_WORD1_OWNER_GROUP        (1UL << 5)
#define FATTR4_WORD1_QUOTA_HARD         (1UL << 6)
#define FATTR4_WORD1_QUOTA_SOFT         (1UL << 7)
#define FATTR4_WORD1_QUOTA_USED         (1UL << 8)
#define FATTR4_WORD1_RAWDEV             (1UL << 9)
#define FATTR4_WORD1_SPACE_AVAIL        (1UL << 10)
#define FATTR4_WORD1_SPACE_FREE         (1UL << 11)
#define FATTR4_WORD1_SPACE_TOTAL        (1UL << 12)
#define FATTR4_WORD1_SPACE_USED         (1UL << 13)
#define FATTR4_WORD1_SYSTEM             (1UL << 14)
#define FATTR4_WORD1_TIME_ACCESS        (1UL << 15)
#define FATTR4_WORD1_TIME_ACCESS_SET    (1UL << 16)
#define FATTR4_WORD1_TIME_BACKUP        (1UL << 17)
#define FATTR4_WORD1_TIME_CREATE        (1UL << 18)
#define FATTR4_WORD1_TIME_DELTA         (1UL << 19)
#define FATTR4_WORD1_TIME_METADATA      (1UL << 20)
#define FATTR4_WORD1_TIME_MODIFY        (1UL << 21)
#define FATTR4_WORD1_TIME_MODIFY_SET    (1UL << 22)
#define FATTR4_WORD1_MOUNTED_ON_FILEID  (1UL << 23)
#define FATTR4_WORD1_DACL               (1UL << 26)
#define FATTR4_WORD1_SACL               (1UL << 27)
#define FATTR4_WORD1_FS_LAYOUT_TYPES    (1UL << 30)
#define FATTR4_WORD2_LAYOUT_TYPES       (1UL << 0)
#define FATTR4_WORD2_LAYOUT_BLKSIZE     (1UL << 1)
#define FATTR4_WORD2_MDSTHRESHOLD       (1UL << 4)
#define FATTR4_WORD2_CLONE_BLKSIZE	(1UL << 13)
#define FATTR4_WORD2_CHANGE_ATTR_TYPE	(1UL << 15)
#define FATTR4_WORD2_SECURITY_LABEL     (1UL << 16)
#define FATTR4_WORD2_MODE_UMASK		(1UL << 17)
#define FATTR4_WORD2_XATTR_SUPPORT	(1UL << 18)

/* MDS threshold bitmap bits */
#define THRESHOLD_RD                    (1UL << 0)
#define THRESHOLD_WR                    (1UL << 1)
#define THRESHOLD_RD_IO                 (1UL << 2)
#define THRESHOLD_WR_IO                 (1UL << 3)

#define NFSPROC4_NULL 0
#define NFSPROC4_COMPOUND 1
#define NFS4_VERSION 4
#define NFS4_MINOR_VERSION 0

#define NFS4_DEBUG 1

/*
 * Index of predefined Linux client operations
 *
 * To ensure that /proc/net/rpc/nfs remains correctly ordered, please
 * append only to this enum when adding new client operations.
 */

enum {
	NFSPROC4_CLNT_NULL = 0,		/* Unused */
	NFSPROC4_CLNT_READ,
	NFSPROC4_CLNT_WRITE,
	NFSPROC4_CLNT_COMMIT,
	NFSPROC4_CLNT_OPEN,
	NFSPROC4_CLNT_OPEN_CONFIRM,
	NFSPROC4_CLNT_OPEN_NOATTR,
	NFSPROC4_CLNT_OPEN_DOWNGRADE,
	NFSPROC4_CLNT_CLOSE,
	NFSPROC4_CLNT_SETATTR,
	NFSPROC4_CLNT_FSINFO,
	NFSPROC4_CLNT_RENEW,
	NFSPROC4_CLNT_SETCLIENTID,
	NFSPROC4_CLNT_SETCLIENTID_CONFIRM,
	NFSPROC4_CLNT_LOCK,
	NFSPROC4_CLNT_LOCKT,
	NFSPROC4_CLNT_LOCKU,
	NFSPROC4_CLNT_ACCESS,
	NFSPROC4_CLNT_GETATTR,
	NFSPROC4_CLNT_LOOKUP,
	NFSPROC4_CLNT_LOOKUP_ROOT,
	NFSPROC4_CLNT_REMOVE,
	NFSPROC4_CLNT_RENAME,
	NFSPROC4_CLNT_LINK,
	NFSPROC4_CLNT_SYMLINK,
	NFSPROC4_CLNT_CREATE,
	NFSPROC4_CLNT_PATHCONF,
	NFSPROC4_CLNT_STATFS,
	NFSPROC4_CLNT_READLINK,
	NFSPROC4_CLNT_READDIR,
	NFSPROC4_CLNT_SERVER_CAPS,
	NFSPROC4_CLNT_DELEGRETURN,
	NFSPROC4_CLNT_GETACL,
	NFSPROC4_CLNT_SETACL,
	NFSPROC4_CLNT_FS_LOCATIONS,
	NFSPROC4_CLNT_RELEASE_LOCKOWNER,
	NFSPROC4_CLNT_SECINFO,
	NFSPROC4_CLNT_FSID_PRESENT,

	NFSPROC4_CLNT_EXCHANGE_ID,
	NFSPROC4_CLNT_CREATE_SESSION,
	NFSPROC4_CLNT_DESTROY_SESSION,
	NFSPROC4_CLNT_SEQUENCE,
	NFSPROC4_CLNT_GET_LEASE_TIME,
	NFSPROC4_CLNT_RECLAIM_COMPLETE,
	NFSPROC4_CLNT_LAYOUTGET,
	NFSPROC4_CLNT_GETDEVICEINFO,
	NFSPROC4_CLNT_LAYOUTCOMMIT,
	NFSPROC4_CLNT_LAYOUTRETURN,
	NFSPROC4_CLNT_SECINFO_NO_NAME,
	NFSPROC4_CLNT_TEST_STATEID,
	NFSPROC4_CLNT_FREE_STATEID,
	NFSPROC4_CLNT_GETDEVICELIST,
	NFSPROC4_CLNT_BIND_CONN_TO_SESSION,
	NFSPROC4_CLNT_DESTROY_CLIENTID,

	NFSPROC4_CLNT_SEEK,
	NFSPROC4_CLNT_ALLOCATE,
	NFSPROC4_CLNT_DEALLOCATE,
	NFSPROC4_CLNT_LAYOUTSTATS,
	NFSPROC4_CLNT_CLONE,
	NFSPROC4_CLNT_COPY,
	NFSPROC4_CLNT_OFFLOAD_CANCEL,

	NFSPROC4_CLNT_LOOKUPP,
	NFSPROC4_CLNT_LAYOUTERROR,
	NFSPROC4_CLNT_COPY_NOTIFY,

	NFSPROC4_CLNT_GETXATTR,
	NFSPROC4_CLNT_SETXATTR,
	NFSPROC4_CLNT_LISTXATTRS,
	NFSPROC4_CLNT_REMOVEXATTR,
	NFSPROC4_CLNT_READ_PLUS,
};

/* nfs41 types */
struct nfs4_sessionid {
	unsigned char data[NFS4_MAX_SESSIONID_LEN];
};

/* Create Session Flags */
#define SESSION4_PERSIST	0x001
#define SESSION4_BACK_CHAN	0x002
#define SESSION4_RDMA		0x004

#define SESSION4_FLAG_MASK_A	0x007

enum state_protect_how4 {
	SP4_NONE	= 0,
	SP4_MACH_CRED	= 1,
	SP4_SSV		= 2
};

enum pnfs_layouttype {
	LAYOUT_NFSV4_1_FILES  = 1,
	LAYOUT_OSD2_OBJECTS = 2,
	LAYOUT_BLOCK_VOLUME = 3,
	LAYOUT_FLEX_FILES = 4,
	LAYOUT_SCSI = 5,
	LAYOUT_TYPE_MAX
};

/* used for both layout return and recall */
enum pnfs_layoutreturn_type {
	RETURN_FILE = 1,
	RETURN_FSID = 2,
	RETURN_ALL  = 3
};

enum pnfs_iomode {
	IOMODE_READ = 1,
	IOMODE_RW = 2,
	IOMODE_ANY = 3,
};

enum pnfs_notify_deviceid_type4 {
	NOTIFY_DEVICEID4_CHANGE = 1 << 1,
	NOTIFY_DEVICEID4_DELETE = 1 << 2,
};

enum pnfs_block_volume_type {
	PNFS_BLOCK_VOLUME_SIMPLE	= 0,
	PNFS_BLOCK_VOLUME_SLICE		= 1,
	PNFS_BLOCK_VOLUME_CONCAT	= 2,
	PNFS_BLOCK_VOLUME_STRIPE	= 3,
	PNFS_BLOCK_VOLUME_SCSI		= 4,
};

enum pnfs_block_extent_state {
	PNFS_BLOCK_READWRITE_DATA	= 0,
	PNFS_BLOCK_READ_DATA		= 1,
	PNFS_BLOCK_INVALID_DATA		= 2,
	PNFS_BLOCK_NONE_DATA		= 3,
};

/* on the wire size of a block layout extent */
#define PNFS_BLOCK_EXTENT_SIZE \
	(7 * sizeof(__be32) + NFS4_DEVICEID4_SIZE)

/* on the wire size of a scsi commit range */
#define PNFS_SCSI_RANGE_SIZE \
	(4 * sizeof(__be32))

enum scsi_code_set {
	PS_CODE_SET_BINARY	= 1,
	PS_CODE_SET_ASCII	= 2,
	PS_CODE_SET_UTF8	= 3
};

enum scsi_designator_type {
	PS_DESIGNATOR_T10	= 1,
	PS_DESIGNATOR_EUI64	= 2,
	PS_DESIGNATOR_NAA	= 3,
	PS_DESIGNATOR_NAME	= 8
};

#define NFL4_UFLG_MASK			0x0000003F
#define NFL4_UFLG_DENSE			0x00000001
#define NFL4_UFLG_COMMIT_THRU_MDS	0x00000002
#define NFL4_UFLG_STRIPE_UNIT_SIZE_MASK	0xFFFFFFC0

/* Encoded in the loh_body field of type layouthint4 */
enum filelayout_hint_care4 {
	NFLH4_CARE_DENSE		= NFL4_UFLG_DENSE,
	NFLH4_CARE_COMMIT_THRU_MDS	= NFL4_UFLG_COMMIT_THRU_MDS,
	NFLH4_CARE_STRIPE_UNIT_SIZE	= 0x00000040,
	NFLH4_CARE_STRIPE_COUNT		= 0x00000080
};

#define NFS4_DEVICEID4_SIZE 16

struct nfs4_deviceid {
	char data[NFS4_DEVICEID4_SIZE];
};

enum data_content4 {
	NFS4_CONTENT_DATA		= 0,
	NFS4_CONTENT_HOLE		= 1,
};

enum pnfs_update_layout_reason {
	PNFS_UPDATE_LAYOUT_UNKNOWN = 0,
	PNFS_UPDATE_LAYOUT_NO_PNFS,
	PNFS_UPDATE_LAYOUT_RD_ZEROLEN,
	PNFS_UPDATE_LAYOUT_MDSTHRESH,
	PNFS_UPDATE_LAYOUT_NOMEM,
	PNFS_UPDATE_LAYOUT_BULK_RECALL,
	PNFS_UPDATE_LAYOUT_IO_TEST_FAIL,
	PNFS_UPDATE_LAYOUT_FOUND_CACHED,
	PNFS_UPDATE_LAYOUT_RETURN,
	PNFS_UPDATE_LAYOUT_RETRY,
	PNFS_UPDATE_LAYOUT_BLOCKED,
	PNFS_UPDATE_LAYOUT_INVALID_OPEN,
	PNFS_UPDATE_LAYOUT_SEND_LAYOUTGET,
	PNFS_UPDATE_LAYOUT_EXIT,
};

#define NFS4_OP_MAP_NUM_LONGS					\
	DIV_ROUND_UP(LAST_NFS4_OP, 8 * sizeof(unsigned long))
#define NFS4_OP_MAP_NUM_WORDS \
	(NFS4_OP_MAP_NUM_LONGS * sizeof(unsigned long) / sizeof(u32))
struct nfs4_op_map {
	union {
		unsigned long longs[NFS4_OP_MAP_NUM_LONGS];
		u32 words[NFS4_OP_MAP_NUM_WORDS];
	} u;
};

struct nfs42_netaddr {
	char		netid[RPCBIND_MAXNETIDLEN];
	char		addr[RPCBIND_MAXUADDRLEN + 1];
	u32		netid_len;
	u32		addr_len;
};

enum netloc_type4 {
	NL4_NAME		= 1,
	NL4_URL			= 2,
	NL4_NETADDR		= 3,
};

struct nl4_server {
	enum netloc_type4	nl4_type;
	union {
		struct { /* NL4_NAME, NL4_URL */
			int	nl4_str_sz;
			char	nl4_str[NFS4_OPAQUE_LIMIT + 1];
		};
		struct nfs42_netaddr	nl4_addr; /* NL4_NETADDR */
	} u;
};

enum nfs4_change_attr_type {
	NFS4_CHANGE_TYPE_IS_MONOTONIC_INCR = 0,
	NFS4_CHANGE_TYPE_IS_VERSION_COUNTER = 1,
	NFS4_CHANGE_TYPE_IS_VERSION_COUNTER_NOPNFS = 2,
	NFS4_CHANGE_TYPE_IS_TIME_METADATA = 3,
	NFS4_CHANGE_TYPE_IS_UNDEFINED = 4,
};

/*
 * Options for setxattr. These match the flags for setxattr(2).
 */
enum nfs4_setxattr_options {
	SETXATTR4_EITHER	= 0,
	SETXATTR4_CREATE	= 1,
	SETXATTR4_REPLACE	= 2,
};
#endif
