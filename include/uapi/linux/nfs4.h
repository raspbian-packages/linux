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

#ifndef _UAPI_LINUX_NFS4_H
#define _UAPI_LINUX_NFS4_H

#include <linux/types.h>

#define NFS4_BITMAP_SIZE	3
#define NFS4_VERIFIER_SIZE	8
#define NFS4_STATEID_SEQID_SIZE 4
#define NFS4_STATEID_OTHER_SIZE 12
#define NFS4_STATEID_SIZE	(NFS4_STATEID_SEQID_SIZE + NFS4_STATEID_OTHER_SIZE)
#define NFS4_FHSIZE		128
#define NFS4_MAXPATHLEN		PATH_MAX
#define NFS4_MAXNAMLEN		NAME_MAX
#define NFS4_OPAQUE_LIMIT	1024
#define NFS4_MAX_SESSIONID_LEN	16

#define NFS4_ACCESS_READ        0x0001
#define NFS4_ACCESS_LOOKUP      0x0002
#define NFS4_ACCESS_MODIFY      0x0004
#define NFS4_ACCESS_EXTEND      0x0008
#define NFS4_ACCESS_DELETE      0x0010
#define NFS4_ACCESS_EXECUTE     0x0020

#define NFS4_FH_PERSISTENT		0x0000
#define NFS4_FH_NOEXPIRE_WITH_OPEN	0x0001
#define NFS4_FH_VOLATILE_ANY		0x0002
#define NFS4_FH_VOL_MIGRATION		0x0004
#define NFS4_FH_VOL_RENAME		0x0008

#define NFS4_OPEN_RESULT_CONFIRM		0x0002
#define NFS4_OPEN_RESULT_LOCKTYPE_POSIX		0x0004
#define NFS4_OPEN_RESULT_MAY_NOTIFY_LOCK	0x0020

#define NFS4_SHARE_ACCESS_MASK	0x000F
#define NFS4_SHARE_ACCESS_READ	0x0001
#define NFS4_SHARE_ACCESS_WRITE	0x0002
#define NFS4_SHARE_ACCESS_BOTH	0x0003
#define NFS4_SHARE_DENY_READ	0x0001
#define NFS4_SHARE_DENY_WRITE	0x0002
#define NFS4_SHARE_DENY_BOTH	0x0003

/* nfs41 */
#define NFS4_SHARE_WANT_MASK		0xFF00
#define NFS4_SHARE_WANT_NO_PREFERENCE	0x0000
#define NFS4_SHARE_WANT_READ_DELEG	0x0100
#define NFS4_SHARE_WANT_WRITE_DELEG	0x0200
#define NFS4_SHARE_WANT_ANY_DELEG	0x0300
#define NFS4_SHARE_WANT_NO_DELEG	0x0400
#define NFS4_SHARE_WANT_CANCEL		0x0500

#define NFS4_SHARE_WHEN_MASK		0xF0000
#define NFS4_SHARE_SIGNAL_DELEG_WHEN_RESRC_AVAIL	0x10000
#define NFS4_SHARE_PUSH_DELEG_WHEN_UNCONTENDED		0x20000

#define NFS4_CDFC4_FORE	0x1
#define NFS4_CDFC4_BACK 0x2
#define NFS4_CDFC4_BOTH 0x3
#define NFS4_CDFC4_FORE_OR_BOTH 0x3
#define NFS4_CDFC4_BACK_OR_BOTH 0x7

#define NFS4_CDFS4_FORE 0x1
#define NFS4_CDFS4_BACK 0x2
#define NFS4_CDFS4_BOTH 0x3

#define NFS4_SET_TO_SERVER_TIME	0
#define NFS4_SET_TO_CLIENT_TIME	1

#define NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE 0
#define NFS4_ACE_ACCESS_DENIED_ACE_TYPE  1
#define NFS4_ACE_SYSTEM_AUDIT_ACE_TYPE   2
#define NFS4_ACE_SYSTEM_ALARM_ACE_TYPE   3

#define ACL4_SUPPORT_ALLOW_ACL 0x01
#define ACL4_SUPPORT_DENY_ACL  0x02
#define ACL4_SUPPORT_AUDIT_ACL 0x04
#define ACL4_SUPPORT_ALARM_ACL 0x08

#define NFS4_ACL_AUTO_INHERIT 0x00000001
#define NFS4_ACL_PROTECTED    0x00000002
#define NFS4_ACL_DEFAULTED    0x00000004

#define NFS4_ACE_FILE_INHERIT_ACE             0x00000001
#define NFS4_ACE_DIRECTORY_INHERIT_ACE        0x00000002
#define NFS4_ACE_NO_PROPAGATE_INHERIT_ACE     0x00000004
#define NFS4_ACE_INHERIT_ONLY_ACE             0x00000008
#define NFS4_ACE_SUCCESSFUL_ACCESS_ACE_FLAG   0x00000010
#define NFS4_ACE_FAILED_ACCESS_ACE_FLAG       0x00000020
#define NFS4_ACE_IDENTIFIER_GROUP             0x00000040
#define NFS4_ACE_INHERITED_ACE                0x00000080

#define NFS4_ACE_READ_DATA                    0x00000001
#define NFS4_ACE_LIST_DIRECTORY               0x00000001
#define NFS4_ACE_WRITE_DATA                   0x00000002
#define NFS4_ACE_ADD_FILE                     0x00000002
#define NFS4_ACE_APPEND_DATA                  0x00000004
#define NFS4_ACE_ADD_SUBDIRECTORY             0x00000004
#define NFS4_ACE_READ_NAMED_ATTRS             0x00000008
#define NFS4_ACE_WRITE_NAMED_ATTRS            0x00000010
#define NFS4_ACE_EXECUTE                      0x00000020
#define NFS4_ACE_DELETE_CHILD                 0x00000040
#define NFS4_ACE_READ_ATTRIBUTES              0x00000080
#define NFS4_ACE_WRITE_ATTRIBUTES             0x00000100
#define NFS4_ACE_WRITE_RETENTION              0x00000200
#define NFS4_ACE_WRITE_RETENTION_HOLD         0x00000400
#define NFS4_ACE_DELETE                       0x00010000
#define NFS4_ACE_READ_ACL                     0x00020000
#define NFS4_ACE_WRITE_ACL                    0x00040000
#define NFS4_ACE_WRITE_OWNER                  0x00080000
#define NFS4_ACE_SYNCHRONIZE                  0x00100000
#define NFS4_ACE_GENERIC_READ                 0x00120081
#define NFS4_ACE_GENERIC_WRITE                0x00160106
#define NFS4_ACE_GENERIC_EXECUTE              0x001200A0
#define NFS4_ACE_MASK_ALL                     0x001F01FF

#define EXCHGID4_FLAG_SUPP_MOVED_REFER		0x00000001
#define EXCHGID4_FLAG_SUPP_MOVED_MIGR		0x00000002
#define EXCHGID4_FLAG_BIND_PRINC_STATEID	0x00000100

#define EXCHGID4_FLAG_USE_NON_PNFS		0x00010000
#define EXCHGID4_FLAG_USE_PNFS_MDS		0x00020000
#define EXCHGID4_FLAG_USE_PNFS_DS		0x00040000
#define EXCHGID4_FLAG_MASK_PNFS			0x00070000

#define EXCHGID4_FLAG_UPD_CONFIRMED_REC_A	0x40000000
#define EXCHGID4_FLAG_CONFIRMED_R		0x80000000
/*
 * Since the validity of these bits depends on whether
 * they're set in the argument or response, have separate
 * invalid flag masks for arg (_A) and resp (_R).
 */
#define EXCHGID4_FLAG_MASK_A			0x40070103
#define EXCHGID4_FLAG_MASK_R			0x80070103

#define SEQ4_STATUS_CB_PATH_DOWN		0x00000001
#define SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRING	0x00000002
#define SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRED	0x00000004
#define SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED	0x00000008
#define SEQ4_STATUS_EXPIRED_SOME_STATE_REVOKED	0x00000010
#define SEQ4_STATUS_ADMIN_STATE_REVOKED		0x00000020
#define SEQ4_STATUS_RECALLABLE_STATE_REVOKED	0x00000040
#define SEQ4_STATUS_LEASE_MOVED			0x00000080
#define SEQ4_STATUS_RESTART_RECLAIM_NEEDED	0x00000100
#define SEQ4_STATUS_CB_PATH_DOWN_SESSION	0x00000200
#define SEQ4_STATUS_BACKCHANNEL_FAULT		0x00000400

#define NFS4_SECINFO_STYLE4_CURRENT_FH	0
#define NFS4_SECINFO_STYLE4_PARENT	1

#define NFS4_MAX_UINT64	(~(__u64)0)

/* An NFS4 sessions server must support at least NFS4_MAX_OPS operations.
 * If a compound requires more operations, adjust NFS4_MAX_OPS accordingly.
 */
#define NFS4_MAX_OPS   8

/* Our NFS4 client back channel server only wants the cb_sequene and the
 * actual operation per compound
 */
#define NFS4_MAX_BACK_CHANNEL_OPS 2

#endif /* _UAPI_LINUX_NFS4_H */

/*
 * Local variables:
 *  c-basic-offset: 8
 * End:
 */
