/* SPDX-License-Identifier: LGPL-2.1 */
/*
 *
 *   Copyright (c) International Business Machines  Corp., 2002,2004
 *   Author(s): Steve French (sfrench@us.ibm.com)
 *
 *   See Error Codes section of the SNIA CIFS Specification
 *   for more information
 *
 */

#define SUCCESS	0x00	/* The request was successful. */
#define ERRDOS	0x01	/* Error is from the core DOS operating system set */
#define ERRSRV	0x02	/* Error is generated by the file server daemon */
#define ERRHRD	0x03	/* Error is a hardware error. */
#define ERRCMD	0xFF	/* Command was not in the "SMB" format. */

/* The following error codes may be generated with the SUCCESS error class.*/

/*#define SUCCESS	0	The request was successful. */

/* The following error codes may be generated with the ERRDOS error class.*/

#define ERRbadfunc		1	/* Invalid function. The server did not
					   recognize or could not perform a
					   system call generated by the server,
					   e.g., set the DIRECTORY attribute on
					   a data file, invalid seek mode. */
#define ERRbadfile		2	/* File not found. The last component
					   of a file's pathname could not be
					   found. */
#define ERRbadpath		3	/* Directory invalid. A directory
					   component in a pathname could not be
					   found. */
#define ERRnofids		4	/* Too many open files. The server has
					   no file handles available. */
#define ERRnoaccess		5	/* Access denied, the client's context
					   does not permit the requested
					   function. This includes the
					   following conditions: invalid rename
					   command, write to Fid open for read
					   only, read on Fid open for write
					   only, attempt to delete a non-empty
					   directory */
#define ERRbadfid		6	/* Invalid file handle. The file handle
					   specified was not recognized by the
					   server. */
#define ERRbadmcb		7	/* Memory control blocks destroyed. */
#define ERRnomem		8	/* Insufficient server memory to
					   perform the requested function. */
#define ERRbadmem		9	/* Invalid memory block address. */
#define ERRbadenv		10	/* Invalid environment. */
#define ERRbadformat		11	/* Invalid format. */
#define ERRbadaccess		12	/* Invalid open mode. */
#define ERRbaddata		13	/* Invalid data (generated only by
					   IOCTL calls within the server). */
#define ERRbaddrive		15	/* Invalid drive specified. */
#define ERRremcd		16	/* A Delete Directory request attempted
					   to remove the server's current
					   directory. */
#define ERRdiffdevice		17	/* Not same device (e.g., a cross
					   volume rename was attempted */
#define ERRnofiles		18	/* A File Search command can find no
					   more files matching the specified
					   criteria. */
#define ERRwriteprot		19	/* media is write protected */
#define ERRgeneral		31
#define ERRbadshare		32	/* The sharing mode specified for an
					   Open conflicts with existing FIDs on
					   the file. */
#define ERRlock			33	/* A Lock request conflicted with an
					   existing lock or specified an
					   invalid mode, or an Unlock requested
					   attempted to remove a lock held by
					   another process. */
#define ERRunsup		50
#define ERRnosuchshare		67
#define ERRfilexists		80	/* The file named in the request
					   already exists. */
#define ERRinvparm		87
#define ERRdiskfull		112
#define ERRinvname		123
#define ERRinvlevel		124
#define ERRdirnotempty		145
#define ERRnotlocked		158
#define ERRcancelviolation	173
#define ERRalreadyexists	183
#define ERRbadpipe		230
#define ERRpipebusy		231
#define ERRpipeclosing		232
#define ERRnotconnected		233
#define ERRmoredata		234
#define ERReasnotsupported	282
#define ErrQuota		0x200	/* The operation would cause a quota
					   limit to be exceeded. */
#define ErrNotALink		0x201	/* A link operation was performed on a
					   pathname that was not a link. */

/* Below errors are used internally (do not come over the wire) for passthrough
   from STATUS codes to POSIX only  */
#define ERRsymlink              0xFFFD
#define ErrTooManyLinks         0xFFFE

/* Following error codes may be generated with the ERRSRV error class.*/

#define ERRerror		1	/* Non-specific error code. It is
					   returned under the following
					   conditions: resource other than disk
					   space exhausted (e.g. TIDs), first
					   SMB command was not negotiate,
					   multiple negotiates attempted, and
					   internal server error. */
#define ERRbadpw		2	/* Bad password - name/password pair in
					   a TreeConnect or Session Setup are
					   invalid. */
#define ERRbadtype		3	/* used for indicating DFS referral
					   needed */
#define ERRaccess		4	/* The client does not have the
					   necessary access rights within the
					   specified context for requested
					   function. */
#define ERRinvtid		5	/* The Tid specified in a command was
					   invalid. */
#define ERRinvnetname		6	/* Invalid network name in tree
					   connect. */
#define ERRinvdevice		7	/* Invalid device - printer request
					   made to non-printer connection or
					   non-printer request made to printer
					   connection. */
#define ERRqfull		49	/* Print queue full (files) -- returned
					   by open print file. */
#define ERRqtoobig		50	/* Print queue full -- no space. */
#define ERRqeof			51	/* EOF on print queue dump */
#define ERRinvpfid		52	/* Invalid print file FID. */
#define ERRsmbcmd		64	/* The server did not recognize the
					   command received. */
#define ERRsrverror		65	/* The server encountered an internal
					   error, e.g., system file
					   unavailable. */
#define ERRbadBID		66	/* (obsolete) */
#define ERRfilespecs		67	/* The Fid and pathname parameters
					   contained an invalid combination of
					   values. */
#define ERRbadLink		68	/* (obsolete) */
#define ERRbadpermits		69	/* The access permissions specified for
					   a file or directory are not a valid
					   combination. */
#define ERRbadPID		70
#define ERRsetattrmode		71	/* attribute (mode) is invalid */
#define ERRpaused		81	/* Server is paused */
#define ERRmsgoff		82	/* reserved - messaging off */
#define ERRnoroom		83	/* reserved - no room for message */
#define ERRrmuns		87	/* reserved - too many remote names */
#define ERRtimeout		88	/* operation timed out */
#define ERRnoresource		89	/* No resources available for request
					   */
#define ERRtoomanyuids		90	/* Too many UIDs active on this session
					   */
#define ERRbaduid		91	/* The UID is not known as a valid user
					   */
#define ERRusempx		250	/* temporarily unable to use raw */
#define ERRusestd		251	/* temporarily unable to use either raw
					   or mpx */
#define ERR_NOTIFY_ENUM_DIR	1024
#define ERRnoSuchUser		2238	/* user account does not exist */
#define ERRaccountexpired	2239
#define ERRbadclient		2240	/* can not logon from this client */
#define ERRbadLogonTime		2241	/* logon hours do not allow this */
#define ERRpasswordExpired	2242
#define ERRnetlogonNotStarted	2455
#define ERRnosupport		0xFFFF
