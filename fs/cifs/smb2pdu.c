/*
 *   fs/cifs/smb2pdu.c
 *
 *   Copyright (C) International Business Machines  Corp., 2009, 2013
 *                 Etersoft, 2012
 *   Author(s): Steve French (sfrench@us.ibm.com)
 *              Pavel Shilovsky (pshilovsky@samba.org) 2012
 *
 *   Contains the routines for constructing the SMB2 PDUs themselves
 *
 *   This library is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU Lesser General Public License as published
 *   by the Free Software Foundation; either version 2.1 of the License, or
 *   (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public License
 *   along with this library; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

 /* SMB2 PDU handling routines here - except for leftovers (eg session setup) */
 /* Note that there are handle based routines which must be		      */
 /* treated slightly differently for reconnection purposes since we never     */
 /* want to reuse a stale file handle and only the caller knows the file info */

#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/vfs.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/uaccess.h>
#include <linux/uuid.h>
#include <linux/pagemap.h>
#include <linux/xattr.h>
#include "smb2pdu.h"
#include "cifsglob.h"
#include "cifsacl.h"
#include "cifsproto.h"
#include "smb2proto.h"
#include "cifs_unicode.h"
#include "cifs_debug.h"
#include "ntlmssp.h"
#include "smb2status.h"
#include "smb2glob.h"
#include "cifspdu.h"
#include "cifs_spnego.h"

/*
 *  The following table defines the expected "StructureSize" of SMB2 requests
 *  in order by SMB2 command.  This is similar to "wct" in SMB/CIFS requests.
 *
 *  Note that commands are defined in smb2pdu.h in le16 but the array below is
 *  indexed by command in host byte order.
 */
static const int smb2_req_struct_sizes[NUMBER_OF_SMB2_COMMANDS] = {
	/* SMB2_NEGOTIATE */ 36,
	/* SMB2_SESSION_SETUP */ 25,
	/* SMB2_LOGOFF */ 4,
	/* SMB2_TREE_CONNECT */	9,
	/* SMB2_TREE_DISCONNECT */ 4,
	/* SMB2_CREATE */ 57,
	/* SMB2_CLOSE */ 24,
	/* SMB2_FLUSH */ 24,
	/* SMB2_READ */	49,
	/* SMB2_WRITE */ 49,
	/* SMB2_LOCK */	48,
	/* SMB2_IOCTL */ 57,
	/* SMB2_CANCEL */ 4,
	/* SMB2_ECHO */ 4,
	/* SMB2_QUERY_DIRECTORY */ 33,
	/* SMB2_CHANGE_NOTIFY */ 32,
	/* SMB2_QUERY_INFO */ 41,
	/* SMB2_SET_INFO */ 33,
	/* SMB2_OPLOCK_BREAK */ 24 /* BB this is 36 for LEASE_BREAK variant */
};

static int encryption_required(const struct cifs_tcon *tcon)
{
	if (!tcon)
		return 0;
	if ((tcon->ses->session_flags & SMB2_SESSION_FLAG_ENCRYPT_DATA) ||
	    (tcon->share_flags & SHI1005_FLAGS_ENCRYPT_DATA))
		return 1;
	if (tcon->seal &&
	    (tcon->ses->server->capabilities & SMB2_GLOBAL_CAP_ENCRYPTION))
		return 1;
	return 0;
}

static void
smb2_hdr_assemble(struct smb2_sync_hdr *shdr, __le16 smb2_cmd,
		  const struct cifs_tcon *tcon)
{
	shdr->ProtocolId = SMB2_PROTO_NUMBER;
	shdr->StructureSize = cpu_to_le16(64);
	shdr->Command = smb2_cmd;
	if (tcon && tcon->ses && tcon->ses->server) {
		struct TCP_Server_Info *server = tcon->ses->server;

		spin_lock(&server->req_lock);
		/* Request up to 2 credits but don't go over the limit. */
		if (server->credits >= server->max_credits)
			shdr->CreditRequest = cpu_to_le16(0);
		else
			shdr->CreditRequest = cpu_to_le16(
				min_t(int, server->max_credits -
						server->credits, 2));
		spin_unlock(&server->req_lock);
	} else {
		shdr->CreditRequest = cpu_to_le16(2);
	}
	shdr->ProcessId = cpu_to_le32((__u16)current->tgid);

	if (!tcon)
		goto out;

	/* GLOBAL_CAP_LARGE_MTU will only be set if dialect > SMB2.02 */
	/* See sections 2.2.4 and 3.2.4.1.5 of MS-SMB2 */
	if ((tcon->ses) && (tcon->ses->server) &&
	    (tcon->ses->server->capabilities & SMB2_GLOBAL_CAP_LARGE_MTU))
		shdr->CreditCharge = cpu_to_le16(1);
	/* else CreditCharge MBZ */

	shdr->TreeId = tcon->tid;
	/* Uid is not converted */
	if (tcon->ses)
		shdr->SessionId = tcon->ses->Suid;

	/*
	 * If we would set SMB2_FLAGS_DFS_OPERATIONS on open we also would have
	 * to pass the path on the Open SMB prefixed by \\server\share.
	 * Not sure when we would need to do the augmented path (if ever) and
	 * setting this flag breaks the SMB2 open operation since it is
	 * illegal to send an empty path name (without \\server\share prefix)
	 * when the DFS flag is set in the SMB open header. We could
	 * consider setting the flag on all operations other than open
	 * but it is safer to net set it for now.
	 */
/*	if (tcon->share_flags & SHI1005_FLAGS_DFS)
		shdr->Flags |= SMB2_FLAGS_DFS_OPERATIONS; */

	if (tcon->ses && tcon->ses->server && tcon->ses->server->sign &&
	    !encryption_required(tcon))
		shdr->Flags |= SMB2_FLAGS_SIGNED;
out:
	return;
}

static int
smb2_reconnect(__le16 smb2_command, struct cifs_tcon *tcon)
{
	int rc = 0;
	struct nls_table *nls_codepage;
	struct cifs_ses *ses;
	struct TCP_Server_Info *server;

	/*
	 * SMB2s NegProt, SessSetup, Logoff do not have tcon yet so
	 * check for tcp and smb session status done differently
	 * for those three - in the calling routine.
	 */
	if (tcon == NULL)
		return rc;

	if (smb2_command == SMB2_TREE_CONNECT)
		return rc;

	if (tcon->tidStatus == CifsExiting) {
		/*
		 * only tree disconnect, open, and write,
		 * (and ulogoff which does not have tcon)
		 * are allowed as we start force umount.
		 */
		if ((smb2_command != SMB2_WRITE) &&
		   (smb2_command != SMB2_CREATE) &&
		   (smb2_command != SMB2_TREE_DISCONNECT)) {
			cifs_dbg(FYI, "can not send cmd %d while umounting\n",
				 smb2_command);
			return -ENODEV;
		}
	}
	if ((!tcon->ses) || (tcon->ses->status == CifsExiting) ||
	    (!tcon->ses->server))
		return -EIO;

	ses = tcon->ses;
	server = ses->server;

	/*
	 * Give demultiplex thread up to 10 seconds to reconnect, should be
	 * greater than cifs socket timeout which is 7 seconds
	 */
	while (server->tcpStatus == CifsNeedReconnect) {
		/*
		 * Return to caller for TREE_DISCONNECT and LOGOFF and CLOSE
		 * here since they are implicitly done when session drops.
		 */
		switch (smb2_command) {
		/*
		 * BB Should we keep oplock break and add flush to exceptions?
		 */
		case SMB2_TREE_DISCONNECT:
		case SMB2_CANCEL:
		case SMB2_CLOSE:
		case SMB2_OPLOCK_BREAK:
			return -EAGAIN;
		}

		wait_event_interruptible_timeout(server->response_q,
			(server->tcpStatus != CifsNeedReconnect), 10 * HZ);

		/* are we still trying to reconnect? */
		if (server->tcpStatus != CifsNeedReconnect)
			break;

		/*
		 * on "soft" mounts we wait once. Hard mounts keep
		 * retrying until process is killed or server comes
		 * back on-line
		 */
		if (!tcon->retry) {
			cifs_dbg(FYI, "gave up waiting on reconnect in smb_init\n");
			return -EHOSTDOWN;
		}
	}

	if (!tcon->ses->need_reconnect && !tcon->need_reconnect)
		return rc;

	nls_codepage = load_nls_default();

	/*
	 * need to prevent multiple threads trying to simultaneously reconnect
	 * the same SMB session
	 */
	mutex_lock(&tcon->ses->session_mutex);
	rc = cifs_negotiate_protocol(0, tcon->ses);
	if (!rc && tcon->ses->need_reconnect)
		rc = cifs_setup_session(0, tcon->ses, nls_codepage);

	if (rc || !tcon->need_reconnect) {
		mutex_unlock(&tcon->ses->session_mutex);
		goto out;
	}

	cifs_mark_open_files_invalid(tcon);
	if (tcon->use_persistent)
		tcon->need_reopen_files = true;

	rc = SMB2_tcon(0, tcon->ses, tcon->treeName, tcon, nls_codepage);
	mutex_unlock(&tcon->ses->session_mutex);

	cifs_dbg(FYI, "reconnect tcon rc = %d\n", rc);
	if (rc)
		goto out;

	if (smb2_command != SMB2_INTERNAL_CMD)
		queue_delayed_work(cifsiod_wq, &server->reconnect, 0);

	atomic_inc(&tconInfoReconnectCount);
out:
	/*
	 * Check if handle based operation so we know whether we can continue
	 * or not without returning to caller to reset file handle.
	 */
	/*
	 * BB Is flush done by server on drop of tcp session? Should we special
	 * case it and skip above?
	 */
	switch (smb2_command) {
	case SMB2_FLUSH:
	case SMB2_READ:
	case SMB2_WRITE:
	case SMB2_LOCK:
	case SMB2_IOCTL:
	case SMB2_QUERY_DIRECTORY:
	case SMB2_CHANGE_NOTIFY:
	case SMB2_QUERY_INFO:
	case SMB2_SET_INFO:
		rc = -EAGAIN;
	}
	unload_nls(nls_codepage);
	return rc;
}

static void
fill_small_buf(__le16 smb2_command, struct cifs_tcon *tcon, void *buf,
	       unsigned int *total_len)
{
	struct smb2_sync_pdu *spdu = (struct smb2_sync_pdu *)buf;
	/* lookup word count ie StructureSize from table */
	__u16 parmsize = smb2_req_struct_sizes[le16_to_cpu(smb2_command)];

	/*
	 * smaller than SMALL_BUFFER_SIZE but bigger than fixed area of
	 * largest operations (Create)
	 */
	memset(buf, 0, 256);

	smb2_hdr_assemble(&spdu->sync_hdr, smb2_command, tcon);
	spdu->StructureSize2 = cpu_to_le16(parmsize);

	*total_len = parmsize + sizeof(struct smb2_sync_hdr);
}

/* init request without RFC1001 length at the beginning */
static int
smb2_plain_req_init(__le16 smb2_command, struct cifs_tcon *tcon,
		    void **request_buf, unsigned int *total_len)
{
	int rc;
	struct smb2_sync_hdr *shdr;

	rc = smb2_reconnect(smb2_command, tcon);
	if (rc)
		return rc;

	/* BB eventually switch this to SMB2 specific small buf size */
	*request_buf = cifs_small_buf_get();
	if (*request_buf == NULL) {
		/* BB should we add a retry in here if not a writepage? */
		return -ENOMEM;
	}

	shdr = (struct smb2_sync_hdr *)(*request_buf);

	fill_small_buf(smb2_command, tcon, shdr, total_len);

	if (tcon != NULL) {
#ifdef CONFIG_CIFS_STATS2
		uint16_t com_code = le16_to_cpu(smb2_command);

		cifs_stats_inc(&tcon->stats.smb2_stats.smb2_com_sent[com_code]);
#endif
		cifs_stats_inc(&tcon->num_smbs_sent);
	}

	return rc;
}

/*
 * Allocate and return pointer to an SMB request hdr, and set basic
 * SMB information in the SMB header. If the return code is zero, this
 * function must have filled in request_buf pointer. The returned buffer
 * has RFC1001 length at the beginning.
 */
static int
small_smb2_init(__le16 smb2_command, struct cifs_tcon *tcon,
		void **request_buf)
{
	int rc;
	unsigned int total_len;
	struct smb2_pdu *pdu;

	rc = smb2_reconnect(smb2_command, tcon);
	if (rc)
		return rc;

	/* BB eventually switch this to SMB2 specific small buf size */
	*request_buf = cifs_small_buf_get();
	if (*request_buf == NULL) {
		/* BB should we add a retry in here if not a writepage? */
		return -ENOMEM;
	}

	pdu = (struct smb2_pdu *)(*request_buf);

	fill_small_buf(smb2_command, tcon, get_sync_hdr(pdu), &total_len);

	/* Note this is only network field converted to big endian */
	pdu->hdr.smb2_buf_length = cpu_to_be32(total_len);

	if (tcon != NULL) {
#ifdef CONFIG_CIFS_STATS2
		uint16_t com_code = le16_to_cpu(smb2_command);
		cifs_stats_inc(&tcon->stats.smb2_stats.smb2_com_sent[com_code]);
#endif
		cifs_stats_inc(&tcon->num_smbs_sent);
	}

	return rc;
}

#ifdef CONFIG_CIFS_SMB311
/* offset is sizeof smb2_negotiate_req - 4 but rounded up to 8 bytes */
#define OFFSET_OF_NEG_CONTEXT 0x68  /* sizeof(struct smb2_negotiate_req) - 4 */


#define SMB2_PREAUTH_INTEGRITY_CAPABILITIES	cpu_to_le16(1)
#define SMB2_ENCRYPTION_CAPABILITIES		cpu_to_le16(2)

static void
build_preauth_ctxt(struct smb2_preauth_neg_context *pneg_ctxt)
{
	pneg_ctxt->ContextType = SMB2_PREAUTH_INTEGRITY_CAPABILITIES;
	pneg_ctxt->DataLength = cpu_to_le16(38);
	pneg_ctxt->HashAlgorithmCount = cpu_to_le16(1);
	pneg_ctxt->SaltLength = cpu_to_le16(SMB311_SALT_SIZE);
	get_random_bytes(pneg_ctxt->Salt, SMB311_SALT_SIZE);
	pneg_ctxt->HashAlgorithms = SMB2_PREAUTH_INTEGRITY_SHA512;
}

static void
build_encrypt_ctxt(struct smb2_encryption_neg_context *pneg_ctxt)
{
	pneg_ctxt->ContextType = SMB2_ENCRYPTION_CAPABILITIES;
	pneg_ctxt->DataLength = cpu_to_le16(6);
	pneg_ctxt->CipherCount = cpu_to_le16(2);
	pneg_ctxt->Ciphers[0] = SMB2_ENCRYPTION_AES128_GCM;
	pneg_ctxt->Ciphers[1] = SMB2_ENCRYPTION_AES128_CCM;
}

static void
assemble_neg_contexts(struct smb2_negotiate_req *req)
{

	/* +4 is to account for the RFC1001 len field */
	char *pneg_ctxt = (char *)req + OFFSET_OF_NEG_CONTEXT + 4;

	build_preauth_ctxt((struct smb2_preauth_neg_context *)pneg_ctxt);
	/* Add 2 to size to round to 8 byte boundary */
	pneg_ctxt += 2 + sizeof(struct smb2_preauth_neg_context);
	build_encrypt_ctxt((struct smb2_encryption_neg_context *)pneg_ctxt);
	req->NegotiateContextOffset = cpu_to_le32(OFFSET_OF_NEG_CONTEXT);
	req->NegotiateContextCount = cpu_to_le16(2);
	inc_rfc1001_len(req, 4 + sizeof(struct smb2_preauth_neg_context) + 2
			+ sizeof(struct smb2_encryption_neg_context)); /* calculate hash */
}
#else
static void assemble_neg_contexts(struct smb2_negotiate_req *req)
{
	return;
}
#endif /* SMB311 */

/*
 *
 *	SMB2 Worker functions follow:
 *
 *	The general structure of the worker functions is:
 *	1) Call smb2_init (assembles SMB2 header)
 *	2) Initialize SMB2 command specific fields in fixed length area of SMB
 *	3) Call smb_sendrcv2 (sends request on socket and waits for response)
 *	4) Decode SMB2 command specific fields in the fixed length area
 *	5) Decode variable length data area (if any for this SMB2 command type)
 *	6) Call free smb buffer
 *	7) return
 *
 */

int
SMB2_negotiate(const unsigned int xid, struct cifs_ses *ses)
{
	struct smb2_negotiate_req *req;
	struct smb2_negotiate_rsp *rsp;
	struct kvec iov[1];
	struct kvec rsp_iov;
	int rc = 0;
	int resp_buftype;
	struct TCP_Server_Info *server = ses->server;
	int blob_offset, blob_length;
	char *security_blob;
	int flags = CIFS_NEG_OP;

	cifs_dbg(FYI, "Negotiate protocol\n");

	if (!server) {
		WARN(1, "%s: server is NULL!\n", __func__);
		return -EIO;
	}

	rc = small_smb2_init(SMB2_NEGOTIATE, NULL, (void **) &req);
	if (rc)
		return rc;

	req->hdr.sync_hdr.SessionId = 0;

	req->Dialects[0] = cpu_to_le16(ses->server->vals->protocol_id);

	req->DialectCount = cpu_to_le16(1); /* One vers= at a time for now */
	inc_rfc1001_len(req, 2);

	/* only one of SMB2 signing flags may be set in SMB2 request */
	if (ses->sign)
		req->SecurityMode = cpu_to_le16(SMB2_NEGOTIATE_SIGNING_REQUIRED);
	else if (global_secflags & CIFSSEC_MAY_SIGN)
		req->SecurityMode = cpu_to_le16(SMB2_NEGOTIATE_SIGNING_ENABLED);
	else
		req->SecurityMode = 0;

	req->Capabilities = cpu_to_le32(ses->server->vals->req_capabilities);

	/* ClientGUID must be zero for SMB2.02 dialect */
	if (ses->server->vals->protocol_id == SMB20_PROT_ID)
		memset(req->ClientGUID, 0, SMB2_CLIENT_GUID_SIZE);
	else {
		memcpy(req->ClientGUID, server->client_guid,
			SMB2_CLIENT_GUID_SIZE);
		if (ses->server->vals->protocol_id == SMB311_PROT_ID)
			assemble_neg_contexts(req);
	}
	iov[0].iov_base = (char *)req;
	/* 4 for rfc1002 length field */
	iov[0].iov_len = get_rfc1002_length(req) + 4;

	rc = SendReceive2(xid, ses, iov, 1, &resp_buftype, flags, &rsp_iov);
	cifs_small_buf_release(req);
	rsp = (struct smb2_negotiate_rsp *)rsp_iov.iov_base;
	/*
	 * No tcon so can't do
	 * cifs_stats_inc(&tcon->stats.smb2_stats.smb2_com_fail[SMB2...]);
	 */
	if (rc != 0)
		goto neg_exit;

	cifs_dbg(FYI, "mode 0x%x\n", rsp->SecurityMode);

	/* BB we may eventually want to match the negotiated vs. requested
	   dialect, even though we are only requesting one at a time */
	if (rsp->DialectRevision == cpu_to_le16(SMB20_PROT_ID))
		cifs_dbg(FYI, "negotiated smb2.0 dialect\n");
	else if (rsp->DialectRevision == cpu_to_le16(SMB21_PROT_ID))
		cifs_dbg(FYI, "negotiated smb2.1 dialect\n");
	else if (rsp->DialectRevision == cpu_to_le16(SMB30_PROT_ID))
		cifs_dbg(FYI, "negotiated smb3.0 dialect\n");
	else if (rsp->DialectRevision == cpu_to_le16(SMB302_PROT_ID))
		cifs_dbg(FYI, "negotiated smb3.02 dialect\n");
#ifdef CONFIG_CIFS_SMB311
	else if (rsp->DialectRevision == cpu_to_le16(SMB311_PROT_ID))
		cifs_dbg(FYI, "negotiated smb3.1.1 dialect\n");
#endif /* SMB311 */
	else {
		cifs_dbg(VFS, "Illegal dialect returned by server 0x%x\n",
			 le16_to_cpu(rsp->DialectRevision));
		rc = -EIO;
		goto neg_exit;
	}
	server->dialect = le16_to_cpu(rsp->DialectRevision);

	/* SMB2 only has an extended negflavor */
	server->negflavor = CIFS_NEGFLAVOR_EXTENDED;
	/* set it to the maximum buffer size value we can send with 1 credit */
	server->maxBuf = min_t(unsigned int, le32_to_cpu(rsp->MaxTransactSize),
			       SMB2_MAX_BUFFER_SIZE);
	server->max_read = le32_to_cpu(rsp->MaxReadSize);
	server->max_write = le32_to_cpu(rsp->MaxWriteSize);
	/* BB Do we need to validate the SecurityMode? */
	server->sec_mode = le16_to_cpu(rsp->SecurityMode);
	server->capabilities = le32_to_cpu(rsp->Capabilities);
	/* Internal types */
	server->capabilities |= SMB2_NT_FIND | SMB2_LARGE_FILES;

	security_blob = smb2_get_data_area_len(&blob_offset, &blob_length,
					       &rsp->hdr);
	/*
	 * See MS-SMB2 section 2.2.4: if no blob, client picks default which
	 * for us will be
	 *	ses->sectype = RawNTLMSSP;
	 * but for time being this is our only auth choice so doesn't matter.
	 * We just found a server which sets blob length to zero expecting raw.
	 */
	if (blob_length == 0) {
		cifs_dbg(FYI, "missing security blob on negprot\n");
		server->sec_ntlmssp = true;
	}

	rc = cifs_enable_signing(server, ses->sign);
	if (rc)
		goto neg_exit;
	if (blob_length) {
		rc = decode_negTokenInit(security_blob, blob_length, server);
		if (rc == 1)
			rc = 0;
		else if (rc == 0)
			rc = -EIO;
	}
neg_exit:
	free_rsp_buf(resp_buftype, rsp);
	return rc;
}

int smb3_validate_negotiate(const unsigned int xid, struct cifs_tcon *tcon)
{
	int rc = 0;
	struct validate_negotiate_info_req vneg_inbuf;
	struct validate_negotiate_info_rsp *pneg_rsp;
	u32 rsplen;

	cifs_dbg(FYI, "validate negotiate\n");

	/*
	 * validation ioctl must be signed, so no point sending this if we
	 * can not sign it.  We could eventually change this to selectively
	 * sign just this, the first and only signed request on a connection.
	 * This is good enough for now since a user who wants better security
	 * would also enable signing on the mount. Having validation of
	 * negotiate info for signed connections helps reduce attack vectors
	 */
	if (tcon->ses->server->sign == false)
		return 0; /* validation requires signing */

	vneg_inbuf.Capabilities =
			cpu_to_le32(tcon->ses->server->vals->req_capabilities);
	memcpy(vneg_inbuf.Guid, tcon->ses->server->client_guid,
					SMB2_CLIENT_GUID_SIZE);

	if (tcon->ses->sign)
		vneg_inbuf.SecurityMode =
			cpu_to_le16(SMB2_NEGOTIATE_SIGNING_REQUIRED);
	else if (global_secflags & CIFSSEC_MAY_SIGN)
		vneg_inbuf.SecurityMode =
			cpu_to_le16(SMB2_NEGOTIATE_SIGNING_ENABLED);
	else
		vneg_inbuf.SecurityMode = 0;

	vneg_inbuf.DialectCount = cpu_to_le16(1);
	vneg_inbuf.Dialects[0] =
		cpu_to_le16(tcon->ses->server->vals->protocol_id);

	rc = SMB2_ioctl(xid, tcon, NO_FILE_ID, NO_FILE_ID,
		FSCTL_VALIDATE_NEGOTIATE_INFO, true /* is_fsctl */,
		false /* use_ipc */,
		(char *)&vneg_inbuf, sizeof(struct validate_negotiate_info_req),
		(char **)&pneg_rsp, &rsplen);

	if (rc != 0) {
		cifs_dbg(VFS, "validate protocol negotiate failed: %d\n", rc);
		return -EIO;
	}

	if (rsplen != sizeof(struct validate_negotiate_info_rsp)) {
		cifs_dbg(VFS, "invalid protocol negotiate response size: %d\n",
			 rsplen);

		/* relax check since Mac returns max bufsize allowed on ioctl */
		if (rsplen > CIFSMaxBufSize)
			return -EIO;
	}

	/* check validate negotiate info response matches what we got earlier */
	if (pneg_rsp->Dialect !=
			cpu_to_le16(tcon->ses->server->vals->protocol_id))
		goto vneg_out;

	if (pneg_rsp->SecurityMode != cpu_to_le16(tcon->ses->server->sec_mode))
		goto vneg_out;

	/* do not validate server guid because not saved at negprot time yet */

	if ((le32_to_cpu(pneg_rsp->Capabilities) | SMB2_NT_FIND |
	      SMB2_LARGE_FILES) != tcon->ses->server->capabilities)
		goto vneg_out;

	/* validate negotiate successful */
	cifs_dbg(FYI, "validate negotiate info successful\n");
	return 0;

vneg_out:
	cifs_dbg(VFS, "protocol revalidation - security settings mismatch\n");
	return -EIO;
}

enum securityEnum
smb2_select_sectype(struct TCP_Server_Info *server, enum securityEnum requested)
{
	switch (requested) {
	case Kerberos:
	case RawNTLMSSP:
		return requested;
	case NTLMv2:
		return RawNTLMSSP;
	case Unspecified:
		if (server->sec_ntlmssp &&
			(global_secflags & CIFSSEC_MAY_NTLMSSP))
			return RawNTLMSSP;
		if ((server->sec_kerberos || server->sec_mskerberos) &&
			(global_secflags & CIFSSEC_MAY_KRB5))
			return Kerberos;
		/* Fallthrough */
	default:
		return Unspecified;
	}
}

struct SMB2_sess_data {
	unsigned int xid;
	struct cifs_ses *ses;
	struct nls_table *nls_cp;
	void (*func)(struct SMB2_sess_data *);
	int result;
	u64 previous_session;

	/* we will send the SMB in three pieces:
	 * a fixed length beginning part, an optional
	 * SPNEGO blob (which can be zero length), and a
	 * last part which will include the strings
	 * and rest of bcc area. This allows us to avoid
	 * a large buffer 17K allocation
	 */
	int buf0_type;
	struct kvec iov[2];
};

static int
SMB2_sess_alloc_buffer(struct SMB2_sess_data *sess_data)
{
	int rc;
	struct cifs_ses *ses = sess_data->ses;
	struct smb2_sess_setup_req *req;
	struct TCP_Server_Info *server = ses->server;

	rc = small_smb2_init(SMB2_SESSION_SETUP, NULL, (void **) &req);
	if (rc)
		return rc;

	/* First session, not a reauthenticate */
	req->hdr.sync_hdr.SessionId = 0;

	/* if reconnect, we need to send previous sess id, otherwise it is 0 */
	req->PreviousSessionId = sess_data->previous_session;

	req->Flags = 0; /* MBZ */
	/* to enable echos and oplocks */
	req->hdr.sync_hdr.CreditRequest = cpu_to_le16(3);

	/* only one of SMB2 signing flags may be set in SMB2 request */
	if (server->sign)
		req->SecurityMode = SMB2_NEGOTIATE_SIGNING_REQUIRED;
	else if (global_secflags & CIFSSEC_MAY_SIGN) /* one flag unlike MUST_ */
		req->SecurityMode = SMB2_NEGOTIATE_SIGNING_ENABLED;
	else
		req->SecurityMode = 0;

	req->Capabilities = 0;
	req->Channel = 0; /* MBZ */

	sess_data->iov[0].iov_base = (char *)req;
	/* 4 for rfc1002 length field and 1 for pad */
	sess_data->iov[0].iov_len = get_rfc1002_length(req) + 4 - 1;
	/*
	 * This variable will be used to clear the buffer
	 * allocated above in case of any error in the calling function.
	 */
	sess_data->buf0_type = CIFS_SMALL_BUFFER;

	return 0;
}

static void
SMB2_sess_free_buffer(struct SMB2_sess_data *sess_data)
{
	free_rsp_buf(sess_data->buf0_type, sess_data->iov[0].iov_base);
	sess_data->buf0_type = CIFS_NO_BUFFER;
}

static int
SMB2_sess_sendreceive(struct SMB2_sess_data *sess_data)
{
	int rc;
	struct smb2_sess_setup_req *req = sess_data->iov[0].iov_base;
	struct kvec rsp_iov = { NULL, 0 };

	/* Testing shows that buffer offset must be at location of Buffer[0] */
	req->SecurityBufferOffset =
		cpu_to_le16(sizeof(struct smb2_sess_setup_req) -
			1 /* pad */ - 4 /* rfc1001 len */);
	req->SecurityBufferLength = cpu_to_le16(sess_data->iov[1].iov_len);

	inc_rfc1001_len(req, sess_data->iov[1].iov_len - 1 /* pad */);

	/* BB add code to build os and lm fields */

	rc = SendReceive2(sess_data->xid, sess_data->ses,
				sess_data->iov, 2,
				&sess_data->buf0_type,
				CIFS_LOG_ERROR | CIFS_NEG_OP, &rsp_iov);
	cifs_small_buf_release(sess_data->iov[0].iov_base);
	memcpy(&sess_data->iov[0], &rsp_iov, sizeof(struct kvec));

	return rc;
}

static int
SMB2_sess_establish_session(struct SMB2_sess_data *sess_data)
{
	int rc = 0;
	struct cifs_ses *ses = sess_data->ses;

	mutex_lock(&ses->server->srv_mutex);
	if (ses->server->ops->generate_signingkey) {
		rc = ses->server->ops->generate_signingkey(ses);
		if (rc) {
			cifs_dbg(FYI,
				"SMB3 session key generation failed\n");
			mutex_unlock(&ses->server->srv_mutex);
			return rc;
		}
	}
	if (!ses->server->session_estab) {
		ses->server->sequence_number = 0x2;
		ses->server->session_estab = true;
	}
	mutex_unlock(&ses->server->srv_mutex);

	cifs_dbg(FYI, "SMB2/3 session established successfully\n");
	spin_lock(&GlobalMid_Lock);
	ses->status = CifsGood;
	ses->need_reconnect = false;
	spin_unlock(&GlobalMid_Lock);
	return rc;
}

#ifdef CONFIG_CIFS_UPCALL
static void
SMB2_auth_kerberos(struct SMB2_sess_data *sess_data)
{
	int rc;
	struct cifs_ses *ses = sess_data->ses;
	struct cifs_spnego_msg *msg;
	struct key *spnego_key = NULL;
	struct smb2_sess_setup_rsp *rsp = NULL;

	rc = SMB2_sess_alloc_buffer(sess_data);
	if (rc)
		goto out;

	spnego_key = cifs_get_spnego_key(ses);
	if (IS_ERR(spnego_key)) {
		rc = PTR_ERR(spnego_key);
		spnego_key = NULL;
		goto out;
	}

	msg = spnego_key->payload.data[0];
	/*
	 * check version field to make sure that cifs.upcall is
	 * sending us a response in an expected form
	 */
	if (msg->version != CIFS_SPNEGO_UPCALL_VERSION) {
		cifs_dbg(VFS,
			  "bad cifs.upcall version. Expected %d got %d",
			  CIFS_SPNEGO_UPCALL_VERSION, msg->version);
		rc = -EKEYREJECTED;
		goto out_put_spnego_key;
	}

	ses->auth_key.response = kmemdup(msg->data, msg->sesskey_len,
					 GFP_KERNEL);
	if (!ses->auth_key.response) {
		cifs_dbg(VFS,
			"Kerberos can't allocate (%u bytes) memory",
			msg->sesskey_len);
		rc = -ENOMEM;
		goto out_put_spnego_key;
	}
	ses->auth_key.len = msg->sesskey_len;

	sess_data->iov[1].iov_base = msg->data + msg->sesskey_len;
	sess_data->iov[1].iov_len = msg->secblob_len;

	rc = SMB2_sess_sendreceive(sess_data);
	if (rc)
		goto out_put_spnego_key;

	rsp = (struct smb2_sess_setup_rsp *)sess_data->iov[0].iov_base;
	ses->Suid = rsp->hdr.sync_hdr.SessionId;

	ses->session_flags = le16_to_cpu(rsp->SessionFlags);

	rc = SMB2_sess_establish_session(sess_data);
out_put_spnego_key:
	key_invalidate(spnego_key);
	key_put(spnego_key);
out:
	sess_data->result = rc;
	sess_data->func = NULL;
	SMB2_sess_free_buffer(sess_data);
}
#else
static void
SMB2_auth_kerberos(struct SMB2_sess_data *sess_data)
{
	cifs_dbg(VFS, "Kerberos negotiated but upcall support disabled!\n");
	sess_data->result = -EOPNOTSUPP;
	sess_data->func = NULL;
}
#endif

static void
SMB2_sess_auth_rawntlmssp_authenticate(struct SMB2_sess_data *sess_data);

static void
SMB2_sess_auth_rawntlmssp_negotiate(struct SMB2_sess_data *sess_data)
{
	int rc;
	struct cifs_ses *ses = sess_data->ses;
	struct smb2_sess_setup_rsp *rsp = NULL;
	char *ntlmssp_blob = NULL;
	bool use_spnego = false; /* else use raw ntlmssp */
	u16 blob_length = 0;

	/*
	 * If memory allocation is successful, caller of this function
	 * frees it.
	 */
	ses->ntlmssp = kmalloc(sizeof(struct ntlmssp_auth), GFP_KERNEL);
	if (!ses->ntlmssp) {
		rc = -ENOMEM;
		goto out_err;
	}
	ses->ntlmssp->sesskey_per_smbsess = true;

	rc = SMB2_sess_alloc_buffer(sess_data);
	if (rc)
		goto out_err;

	ntlmssp_blob = kmalloc(sizeof(struct _NEGOTIATE_MESSAGE),
			       GFP_KERNEL);
	if (ntlmssp_blob == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	build_ntlmssp_negotiate_blob(ntlmssp_blob, ses);
	if (use_spnego) {
		/* BB eventually need to add this */
		cifs_dbg(VFS, "spnego not supported for SMB2 yet\n");
		rc = -EOPNOTSUPP;
		goto out;
	} else {
		blob_length = sizeof(struct _NEGOTIATE_MESSAGE);
		/* with raw NTLMSSP we don't encapsulate in SPNEGO */
	}
	sess_data->iov[1].iov_base = ntlmssp_blob;
	sess_data->iov[1].iov_len = blob_length;

	rc = SMB2_sess_sendreceive(sess_data);
	rsp = (struct smb2_sess_setup_rsp *)sess_data->iov[0].iov_base;

	/* If true, rc here is expected and not an error */
	if (sess_data->buf0_type != CIFS_NO_BUFFER &&
		rsp->hdr.sync_hdr.Status == STATUS_MORE_PROCESSING_REQUIRED)
		rc = 0;

	if (rc)
		goto out;

	if (offsetof(struct smb2_sess_setup_rsp, Buffer) - 4 !=
			le16_to_cpu(rsp->SecurityBufferOffset)) {
		cifs_dbg(VFS, "Invalid security buffer offset %d\n",
			le16_to_cpu(rsp->SecurityBufferOffset));
		rc = -EIO;
		goto out;
	}
	rc = decode_ntlmssp_challenge(rsp->Buffer,
			le16_to_cpu(rsp->SecurityBufferLength), ses);
	if (rc)
		goto out;

	cifs_dbg(FYI, "rawntlmssp session setup challenge phase\n");


	ses->Suid = rsp->hdr.sync_hdr.SessionId;
	ses->session_flags = le16_to_cpu(rsp->SessionFlags);

out:
	kfree(ntlmssp_blob);
	SMB2_sess_free_buffer(sess_data);
	if (!rc) {
		sess_data->result = 0;
		sess_data->func = SMB2_sess_auth_rawntlmssp_authenticate;
		return;
	}
out_err:
	kfree(ses->ntlmssp);
	ses->ntlmssp = NULL;
	sess_data->result = rc;
	sess_data->func = NULL;
}

static void
SMB2_sess_auth_rawntlmssp_authenticate(struct SMB2_sess_data *sess_data)
{
	int rc;
	struct cifs_ses *ses = sess_data->ses;
	struct smb2_sess_setup_req *req;
	struct smb2_sess_setup_rsp *rsp = NULL;
	unsigned char *ntlmssp_blob = NULL;
	bool use_spnego = false; /* else use raw ntlmssp */
	u16 blob_length = 0;

	rc = SMB2_sess_alloc_buffer(sess_data);
	if (rc)
		goto out;

	req = (struct smb2_sess_setup_req *) sess_data->iov[0].iov_base;
	req->hdr.sync_hdr.SessionId = ses->Suid;

	rc = build_ntlmssp_auth_blob(&ntlmssp_blob, &blob_length, ses,
					sess_data->nls_cp);
	if (rc) {
		cifs_dbg(FYI, "build_ntlmssp_auth_blob failed %d\n", rc);
		goto out;
	}

	if (use_spnego) {
		/* BB eventually need to add this */
		cifs_dbg(VFS, "spnego not supported for SMB2 yet\n");
		rc = -EOPNOTSUPP;
		goto out;
	}
	sess_data->iov[1].iov_base = ntlmssp_blob;
	sess_data->iov[1].iov_len = blob_length;

	rc = SMB2_sess_sendreceive(sess_data);
	if (rc)
		goto out;

	rsp = (struct smb2_sess_setup_rsp *)sess_data->iov[0].iov_base;

	ses->Suid = rsp->hdr.sync_hdr.SessionId;
	ses->session_flags = le16_to_cpu(rsp->SessionFlags);

	rc = SMB2_sess_establish_session(sess_data);
out:
	kfree(ntlmssp_blob);
	SMB2_sess_free_buffer(sess_data);
	kfree(ses->ntlmssp);
	ses->ntlmssp = NULL;
	sess_data->result = rc;
	sess_data->func = NULL;
}

static int
SMB2_select_sec(struct cifs_ses *ses, struct SMB2_sess_data *sess_data)
{
	int type;

	type = smb2_select_sectype(ses->server, ses->sectype);
	cifs_dbg(FYI, "sess setup type %d\n", type);
	if (type == Unspecified) {
		cifs_dbg(VFS,
			"Unable to select appropriate authentication method!");
		return -EINVAL;
	}

	switch (type) {
	case Kerberos:
		sess_data->func = SMB2_auth_kerberos;
		break;
	case RawNTLMSSP:
		sess_data->func = SMB2_sess_auth_rawntlmssp_negotiate;
		break;
	default:
		cifs_dbg(VFS, "secType %d not supported!\n", type);
		return -EOPNOTSUPP;
	}

	return 0;
}

int
SMB2_sess_setup(const unsigned int xid, struct cifs_ses *ses,
		const struct nls_table *nls_cp)
{
	int rc = 0;
	struct TCP_Server_Info *server = ses->server;
	struct SMB2_sess_data *sess_data;

	cifs_dbg(FYI, "Session Setup\n");

	if (!server) {
		WARN(1, "%s: server is NULL!\n", __func__);
		return -EIO;
	}

	sess_data = kzalloc(sizeof(struct SMB2_sess_data), GFP_KERNEL);
	if (!sess_data)
		return -ENOMEM;

	rc = SMB2_select_sec(ses, sess_data);
	if (rc)
		goto out;
	sess_data->xid = xid;
	sess_data->ses = ses;
	sess_data->buf0_type = CIFS_NO_BUFFER;
	sess_data->nls_cp = (struct nls_table *) nls_cp;

	while (sess_data->func)
		sess_data->func(sess_data);

	rc = sess_data->result;
out:
	kfree(sess_data);
	return rc;
}

int
SMB2_logoff(const unsigned int xid, struct cifs_ses *ses)
{
	struct smb2_logoff_req *req; /* response is also trivial struct */
	int rc = 0;
	struct TCP_Server_Info *server;
	int flags = 0;

	cifs_dbg(FYI, "disconnect session %p\n", ses);

	if (ses && (ses->server))
		server = ses->server;
	else
		return -EIO;

	/* no need to send SMB logoff if uid already closed due to reconnect */
	if (ses->need_reconnect)
		goto smb2_session_already_dead;

	rc = small_smb2_init(SMB2_LOGOFF, NULL, (void **) &req);
	if (rc)
		return rc;

	 /* since no tcon, smb2_init can not do this, so do here */
	req->hdr.sync_hdr.SessionId = ses->Suid;

	if (ses->session_flags & SMB2_SESSION_FLAG_ENCRYPT_DATA)
		flags |= CIFS_TRANSFORM_REQ;
	else if (server->sign)
		req->hdr.sync_hdr.Flags |= SMB2_FLAGS_SIGNED;

	rc = SendReceiveNoRsp(xid, ses, (char *) req, flags);
	cifs_small_buf_release(req);
	/*
	 * No tcon so can't do
	 * cifs_stats_inc(&tcon->stats.smb2_stats.smb2_com_fail[SMB2...]);
	 */

smb2_session_already_dead:
	return rc;
}

static inline void cifs_stats_fail_inc(struct cifs_tcon *tcon, uint16_t code)
{
	cifs_stats_inc(&tcon->stats.smb2_stats.smb2_com_failed[code]);
}

#define MAX_SHARENAME_LENGTH (255 /* server */ + 80 /* share */ + 1 /* NULL */)

/* These are similar values to what Windows uses */
static inline void init_copy_chunk_defaults(struct cifs_tcon *tcon)
{
	tcon->max_chunks = 256;
	tcon->max_bytes_chunk = 1048576;
	tcon->max_bytes_copy = 16777216;
}

int
SMB2_tcon(const unsigned int xid, struct cifs_ses *ses, const char *tree,
	  struct cifs_tcon *tcon, const struct nls_table *cp)
{
	struct smb2_tree_connect_req *req;
	struct smb2_tree_connect_rsp *rsp = NULL;
	struct kvec iov[2];
	struct kvec rsp_iov;
	int rc = 0;
	int resp_buftype;
	int unc_path_len;
	struct TCP_Server_Info *server;
	__le16 *unc_path = NULL;
	int flags = 0;

	cifs_dbg(FYI, "TCON\n");

	if ((ses->server) && tree)
		server = ses->server;
	else
		return -EIO;

	unc_path = kmalloc(MAX_SHARENAME_LENGTH * 2, GFP_KERNEL);
	if (unc_path == NULL)
		return -ENOMEM;

	unc_path_len = cifs_strtoUTF16(unc_path, tree, strlen(tree), cp) + 1;
	unc_path_len *= 2;
	if (unc_path_len < 2) {
		kfree(unc_path);
		return -EINVAL;
	}

	/* SMB2 TREE_CONNECT request must be called with TreeId == 0 */
	if (tcon)
		tcon->tid = 0;

	rc = small_smb2_init(SMB2_TREE_CONNECT, tcon, (void **) &req);
	if (rc) {
		kfree(unc_path);
		return rc;
	}

	if (tcon == NULL) {
		if ((ses->session_flags & SMB2_SESSION_FLAG_ENCRYPT_DATA))
			flags |= CIFS_TRANSFORM_REQ;

		/* since no tcon, smb2_init can not do this, so do here */
		req->hdr.sync_hdr.SessionId = ses->Suid;
		if (ses->server->sign)
			req->hdr.sync_hdr.Flags |= SMB2_FLAGS_SIGNED;
	} else if (encryption_required(tcon))
		flags |= CIFS_TRANSFORM_REQ;

	iov[0].iov_base = (char *)req;
	/* 4 for rfc1002 length field and 1 for pad */
	iov[0].iov_len = get_rfc1002_length(req) + 4 - 1;

	/* Testing shows that buffer offset must be at location of Buffer[0] */
	req->PathOffset = cpu_to_le16(sizeof(struct smb2_tree_connect_req)
			- 1 /* pad */ - 4 /* do not count rfc1001 len field */);
	req->PathLength = cpu_to_le16(unc_path_len - 2);
	iov[1].iov_base = unc_path;
	iov[1].iov_len = unc_path_len;

	inc_rfc1001_len(req, unc_path_len - 1 /* pad */);

	rc = SendReceive2(xid, ses, iov, 2, &resp_buftype, flags, &rsp_iov);
	cifs_small_buf_release(req);
	rsp = (struct smb2_tree_connect_rsp *)rsp_iov.iov_base;

	if (rc != 0) {
		if (tcon) {
			cifs_stats_fail_inc(tcon, SMB2_TREE_CONNECT_HE);
			tcon->need_reconnect = true;
		}
		goto tcon_error_exit;
	}

	if (tcon == NULL) {
		ses->ipc_tid = rsp->hdr.sync_hdr.TreeId;
		goto tcon_exit;
	}

	switch (rsp->ShareType) {
	case SMB2_SHARE_TYPE_DISK:
		cifs_dbg(FYI, "connection to disk share\n");
		break;
	case SMB2_SHARE_TYPE_PIPE:
		tcon->ipc = true;
		cifs_dbg(FYI, "connection to pipe share\n");
		break;
	case SMB2_SHARE_TYPE_PRINT:
		tcon->ipc = true;
		cifs_dbg(FYI, "connection to printer\n");
		break;
	default:
		cifs_dbg(VFS, "unknown share type %d\n", rsp->ShareType);
		rc = -EOPNOTSUPP;
		goto tcon_error_exit;
	}

	tcon->share_flags = le32_to_cpu(rsp->ShareFlags);
	tcon->capabilities = rsp->Capabilities; /* we keep caps little endian */
	tcon->maximal_access = le32_to_cpu(rsp->MaximalAccess);
	tcon->tidStatus = CifsGood;
	tcon->need_reconnect = false;
	tcon->tid = rsp->hdr.sync_hdr.TreeId;
	strlcpy(tcon->treeName, tree, sizeof(tcon->treeName));

	if ((rsp->Capabilities & SMB2_SHARE_CAP_DFS) &&
	    ((tcon->share_flags & SHI1005_FLAGS_DFS) == 0))
		cifs_dbg(VFS, "DFS capability contradicts DFS flag\n");

	if (tcon->seal &&
	    !(tcon->ses->server->capabilities & SMB2_GLOBAL_CAP_ENCRYPTION))
		cifs_dbg(VFS, "Encryption is requested but not supported\n");

	init_copy_chunk_defaults(tcon);
	if (tcon->ses->server->ops->validate_negotiate)
		rc = tcon->ses->server->ops->validate_negotiate(xid, tcon);
tcon_exit:
	free_rsp_buf(resp_buftype, rsp);
	kfree(unc_path);
	return rc;

tcon_error_exit:
	if (rsp->hdr.sync_hdr.Status == STATUS_BAD_NETWORK_NAME) {
		cifs_dbg(VFS, "BAD_NETWORK_NAME: %s\n", tree);
	}
	goto tcon_exit;
}

int
SMB2_tdis(const unsigned int xid, struct cifs_tcon *tcon)
{
	struct smb2_tree_disconnect_req *req; /* response is trivial */
	int rc = 0;
	struct TCP_Server_Info *server;
	struct cifs_ses *ses = tcon->ses;
	int flags = 0;

	cifs_dbg(FYI, "Tree Disconnect\n");

	if (ses && (ses->server))
		server = ses->server;
	else
		return -EIO;

	if ((tcon->need_reconnect) || (tcon->ses->need_reconnect))
		return 0;

	rc = small_smb2_init(SMB2_TREE_DISCONNECT, tcon, (void **) &req);
	if (rc)
		return rc;

	if (encryption_required(tcon))
		flags |= CIFS_TRANSFORM_REQ;

	rc = SendReceiveNoRsp(xid, ses, (char *)req, flags);
	cifs_small_buf_release(req);
	if (rc)
		cifs_stats_fail_inc(tcon, SMB2_TREE_DISCONNECT_HE);

	return rc;
}


static struct create_durable *
create_durable_buf(void)
{
	struct create_durable *buf;

	buf = kzalloc(sizeof(struct create_durable), GFP_KERNEL);
	if (!buf)
		return NULL;

	buf->ccontext.DataOffset = cpu_to_le16(offsetof
					(struct create_durable, Data));
	buf->ccontext.DataLength = cpu_to_le32(16);
	buf->ccontext.NameOffset = cpu_to_le16(offsetof
				(struct create_durable, Name));
	buf->ccontext.NameLength = cpu_to_le16(4);
	/* SMB2_CREATE_DURABLE_HANDLE_REQUEST is "DHnQ" */
	buf->Name[0] = 'D';
	buf->Name[1] = 'H';
	buf->Name[2] = 'n';
	buf->Name[3] = 'Q';
	return buf;
}

static struct create_durable *
create_reconnect_durable_buf(struct cifs_fid *fid)
{
	struct create_durable *buf;

	buf = kzalloc(sizeof(struct create_durable), GFP_KERNEL);
	if (!buf)
		return NULL;

	buf->ccontext.DataOffset = cpu_to_le16(offsetof
					(struct create_durable, Data));
	buf->ccontext.DataLength = cpu_to_le32(16);
	buf->ccontext.NameOffset = cpu_to_le16(offsetof
				(struct create_durable, Name));
	buf->ccontext.NameLength = cpu_to_le16(4);
	buf->Data.Fid.PersistentFileId = fid->persistent_fid;
	buf->Data.Fid.VolatileFileId = fid->volatile_fid;
	/* SMB2_CREATE_DURABLE_HANDLE_RECONNECT is "DHnC" */
	buf->Name[0] = 'D';
	buf->Name[1] = 'H';
	buf->Name[2] = 'n';
	buf->Name[3] = 'C';
	return buf;
}

static __u8
parse_lease_state(struct TCP_Server_Info *server, struct smb2_create_rsp *rsp,
		  unsigned int *epoch)
{
	char *data_offset;
	struct create_context *cc;
	unsigned int next;
	unsigned int remaining;
	char *name;

	data_offset = (char *)rsp + 4 + le32_to_cpu(rsp->CreateContextsOffset);
	remaining = le32_to_cpu(rsp->CreateContextsLength);
	cc = (struct create_context *)data_offset;
	while (remaining >= sizeof(struct create_context)) {
		name = le16_to_cpu(cc->NameOffset) + (char *)cc;
		if (le16_to_cpu(cc->NameLength) == 4 &&
		    strncmp(name, "RqLs", 4) == 0)
			return server->ops->parse_lease_buf(cc, epoch);

		next = le32_to_cpu(cc->Next);
		if (!next)
			break;
		remaining -= next;
		cc = (struct create_context *)((char *)cc + next);
	}

	return 0;
}

static int
add_lease_context(struct TCP_Server_Info *server, struct kvec *iov,
		  unsigned int *num_iovec, __u8 *oplock)
{
	struct smb2_create_req *req = iov[0].iov_base;
	unsigned int num = *num_iovec;

	iov[num].iov_base = server->ops->create_lease_buf(oplock+1, *oplock);
	if (iov[num].iov_base == NULL)
		return -ENOMEM;
	iov[num].iov_len = server->vals->create_lease_size;
	req->RequestedOplockLevel = SMB2_OPLOCK_LEVEL_LEASE;
	if (!req->CreateContextsOffset)
		req->CreateContextsOffset = cpu_to_le32(
				sizeof(struct smb2_create_req) - 4 +
				iov[num - 1].iov_len);
	le32_add_cpu(&req->CreateContextsLength,
		     server->vals->create_lease_size);
	inc_rfc1001_len(&req->hdr, server->vals->create_lease_size);
	*num_iovec = num + 1;
	return 0;
}

static struct create_durable_v2 *
create_durable_v2_buf(struct cifs_fid *pfid)
{
	struct create_durable_v2 *buf;

	buf = kzalloc(sizeof(struct create_durable_v2), GFP_KERNEL);
	if (!buf)
		return NULL;

	buf->ccontext.DataOffset = cpu_to_le16(offsetof
					(struct create_durable_v2, dcontext));
	buf->ccontext.DataLength = cpu_to_le32(sizeof(struct durable_context_v2));
	buf->ccontext.NameOffset = cpu_to_le16(offsetof
				(struct create_durable_v2, Name));
	buf->ccontext.NameLength = cpu_to_le16(4);

	buf->dcontext.Timeout = 0; /* Should this be configurable by workload */
	buf->dcontext.Flags = cpu_to_le32(SMB2_DHANDLE_FLAG_PERSISTENT);
	generate_random_uuid(buf->dcontext.CreateGuid);
	memcpy(pfid->create_guid, buf->dcontext.CreateGuid, 16);

	/* SMB2_CREATE_DURABLE_HANDLE_REQUEST is "DH2Q" */
	buf->Name[0] = 'D';
	buf->Name[1] = 'H';
	buf->Name[2] = '2';
	buf->Name[3] = 'Q';
	return buf;
}

static struct create_durable_handle_reconnect_v2 *
create_reconnect_durable_v2_buf(struct cifs_fid *fid)
{
	struct create_durable_handle_reconnect_v2 *buf;

	buf = kzalloc(sizeof(struct create_durable_handle_reconnect_v2),
			GFP_KERNEL);
	if (!buf)
		return NULL;

	buf->ccontext.DataOffset =
		cpu_to_le16(offsetof(struct create_durable_handle_reconnect_v2,
				     dcontext));
	buf->ccontext.DataLength =
		cpu_to_le32(sizeof(struct durable_reconnect_context_v2));
	buf->ccontext.NameOffset =
		cpu_to_le16(offsetof(struct create_durable_handle_reconnect_v2,
			    Name));
	buf->ccontext.NameLength = cpu_to_le16(4);

	buf->dcontext.Fid.PersistentFileId = fid->persistent_fid;
	buf->dcontext.Fid.VolatileFileId = fid->volatile_fid;
	buf->dcontext.Flags = cpu_to_le32(SMB2_DHANDLE_FLAG_PERSISTENT);
	memcpy(buf->dcontext.CreateGuid, fid->create_guid, 16);

	/* SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2 is "DH2C" */
	buf->Name[0] = 'D';
	buf->Name[1] = 'H';
	buf->Name[2] = '2';
	buf->Name[3] = 'C';
	return buf;
}

static int
add_durable_v2_context(struct kvec *iov, unsigned int *num_iovec,
		    struct cifs_open_parms *oparms)
{
	struct smb2_create_req *req = iov[0].iov_base;
	unsigned int num = *num_iovec;

	iov[num].iov_base = create_durable_v2_buf(oparms->fid);
	if (iov[num].iov_base == NULL)
		return -ENOMEM;
	iov[num].iov_len = sizeof(struct create_durable_v2);
	if (!req->CreateContextsOffset)
		req->CreateContextsOffset =
			cpu_to_le32(sizeof(struct smb2_create_req) - 4 +
								iov[1].iov_len);
	le32_add_cpu(&req->CreateContextsLength, sizeof(struct create_durable_v2));
	inc_rfc1001_len(&req->hdr, sizeof(struct create_durable_v2));
	*num_iovec = num + 1;
	return 0;
}

static int
add_durable_reconnect_v2_context(struct kvec *iov, unsigned int *num_iovec,
		    struct cifs_open_parms *oparms)
{
	struct smb2_create_req *req = iov[0].iov_base;
	unsigned int num = *num_iovec;

	/* indicate that we don't need to relock the file */
	oparms->reconnect = false;

	iov[num].iov_base = create_reconnect_durable_v2_buf(oparms->fid);
	if (iov[num].iov_base == NULL)
		return -ENOMEM;
	iov[num].iov_len = sizeof(struct create_durable_handle_reconnect_v2);
	if (!req->CreateContextsOffset)
		req->CreateContextsOffset =
			cpu_to_le32(sizeof(struct smb2_create_req) - 4 +
								iov[1].iov_len);
	le32_add_cpu(&req->CreateContextsLength,
			sizeof(struct create_durable_handle_reconnect_v2));
	inc_rfc1001_len(&req->hdr,
			sizeof(struct create_durable_handle_reconnect_v2));
	*num_iovec = num + 1;
	return 0;
}

static int
add_durable_context(struct kvec *iov, unsigned int *num_iovec,
		    struct cifs_open_parms *oparms, bool use_persistent)
{
	struct smb2_create_req *req = iov[0].iov_base;
	unsigned int num = *num_iovec;

	if (use_persistent) {
		if (oparms->reconnect)
			return add_durable_reconnect_v2_context(iov, num_iovec,
								oparms);
		else
			return add_durable_v2_context(iov, num_iovec, oparms);
	}

	if (oparms->reconnect) {
		iov[num].iov_base = create_reconnect_durable_buf(oparms->fid);
		/* indicate that we don't need to relock the file */
		oparms->reconnect = false;
	} else
		iov[num].iov_base = create_durable_buf();
	if (iov[num].iov_base == NULL)
		return -ENOMEM;
	iov[num].iov_len = sizeof(struct create_durable);
	if (!req->CreateContextsOffset)
		req->CreateContextsOffset =
			cpu_to_le32(sizeof(struct smb2_create_req) - 4 +
								iov[1].iov_len);
	le32_add_cpu(&req->CreateContextsLength, sizeof(struct create_durable));
	inc_rfc1001_len(&req->hdr, sizeof(struct create_durable));
	*num_iovec = num + 1;
	return 0;
}

static int
alloc_path_with_tree_prefix(__le16 **out_path, int *out_size, int *out_len,
			    const char *treename, const __le16 *path)
{
	int treename_len, path_len;
	struct nls_table *cp;
	const __le16 sep[] = {cpu_to_le16('\\'), cpu_to_le16(0x0000)};

	/*
	 * skip leading "\\"
	 */
	treename_len = strlen(treename);
	if (treename_len < 2 || !(treename[0] == '\\' && treename[1] == '\\'))
		return -EINVAL;

	treename += 2;
	treename_len -= 2;

	path_len = UniStrnlen((wchar_t *)path, PATH_MAX);

	/*
	 * make room for one path separator between the treename and
	 * path
	 */
	*out_len = treename_len + 1 + path_len;

	/*
	 * final path needs to be null-terminated UTF16 with a
	 * size aligned to 8
	 */

	*out_size = roundup((*out_len+1)*2, 8);
	*out_path = kzalloc(*out_size, GFP_KERNEL);
	if (!*out_path)
		return -ENOMEM;

	cp = load_nls_default();
	cifs_strtoUTF16(*out_path, treename, treename_len, cp);
	UniStrcat(*out_path, sep);
	UniStrcat(*out_path, path);
	unload_nls(cp);

	return 0;
}

int
SMB2_open(const unsigned int xid, struct cifs_open_parms *oparms, __le16 *path,
	  __u8 *oplock, struct smb2_file_all_info *buf,
	  struct smb2_err_rsp **err_buf)
{
	struct smb2_create_req *req;
	struct smb2_create_rsp *rsp;
	struct TCP_Server_Info *server;
	struct cifs_tcon *tcon = oparms->tcon;
	struct cifs_ses *ses = tcon->ses;
	struct kvec iov[4];
	struct kvec rsp_iov;
	int resp_buftype;
	int uni_path_len;
	__le16 *copy_path = NULL;
	int copy_size;
	int rc = 0;
	unsigned int n_iov = 2;
	__u32 file_attributes = 0;
	char *dhc_buf = NULL, *lc_buf = NULL;
	int flags = 0;

	cifs_dbg(FYI, "create/open\n");

	if (ses && (ses->server))
		server = ses->server;
	else
		return -EIO;

	rc = small_smb2_init(SMB2_CREATE, tcon, (void **) &req);
	if (rc)
		return rc;

	if (encryption_required(tcon))
		flags |= CIFS_TRANSFORM_REQ;

	if (oparms->create_options & CREATE_OPTION_READONLY)
		file_attributes |= ATTR_READONLY;
	if (oparms->create_options & CREATE_OPTION_SPECIAL)
		file_attributes |= ATTR_SYSTEM;

	req->ImpersonationLevel = IL_IMPERSONATION;
	req->DesiredAccess = cpu_to_le32(oparms->desired_access);
	/* File attributes ignored on open (used in create though) */
	req->FileAttributes = cpu_to_le32(file_attributes);
	req->ShareAccess = FILE_SHARE_ALL_LE;
	req->CreateDisposition = cpu_to_le32(oparms->disposition);
	req->CreateOptions = cpu_to_le32(oparms->create_options & CREATE_OPTIONS_MASK);

	iov[0].iov_base = (char *)req;
	/* 4 for rfc1002 length field */
	iov[0].iov_len = get_rfc1002_length(req) + 4;
	/* -1 since last byte is buf[0] which is sent below (path) */
	iov[0].iov_len--;

	req->NameOffset = cpu_to_le16(sizeof(struct smb2_create_req) - 4);

	/* [MS-SMB2] 2.2.13 NameOffset:
	 * If SMB2_FLAGS_DFS_OPERATIONS is set in the Flags field of
	 * the SMB2 header, the file name includes a prefix that will
	 * be processed during DFS name normalization as specified in
	 * section 3.3.5.9. Otherwise, the file name is relative to
	 * the share that is identified by the TreeId in the SMB2
	 * header.
	 */
	if (tcon->share_flags & SHI1005_FLAGS_DFS) {
		int name_len;

		req->hdr.sync_hdr.Flags |= SMB2_FLAGS_DFS_OPERATIONS;
		rc = alloc_path_with_tree_prefix(&copy_path, &copy_size,
						 &name_len,
						 tcon->treeName, path);
		if (rc)
			return rc;
		req->NameLength = cpu_to_le16(name_len * 2);
		uni_path_len = copy_size;
		path = copy_path;
	} else {
		uni_path_len = (2 * UniStrnlen((wchar_t *)path, PATH_MAX)) + 2;
		/* MUST set path len (NameLength) to 0 opening root of share */
		req->NameLength = cpu_to_le16(uni_path_len - 2);
		if (uni_path_len % 8 != 0) {
			copy_size = roundup(uni_path_len, 8);
			copy_path = kzalloc(copy_size, GFP_KERNEL);
			if (!copy_path)
				return -ENOMEM;
			memcpy((char *)copy_path, (const char *)path,
			       uni_path_len);
			uni_path_len = copy_size;
			path = copy_path;
		}
	}

	iov[1].iov_len = uni_path_len;
	iov[1].iov_base = path;
	/* -1 since last byte is buf[0] which was counted in smb2_buf_len */
	inc_rfc1001_len(req, uni_path_len - 1);

	if (!server->oplocks)
		*oplock = SMB2_OPLOCK_LEVEL_NONE;

	if (!(server->capabilities & SMB2_GLOBAL_CAP_LEASING) ||
	    *oplock == SMB2_OPLOCK_LEVEL_NONE)
		req->RequestedOplockLevel = *oplock;
	else {
		rc = add_lease_context(server, iov, &n_iov, oplock);
		if (rc) {
			cifs_small_buf_release(req);
			kfree(copy_path);
			return rc;
		}
		lc_buf = iov[n_iov-1].iov_base;
	}

	if (*oplock == SMB2_OPLOCK_LEVEL_BATCH) {
		/* need to set Next field of lease context if we request it */
		if (server->capabilities & SMB2_GLOBAL_CAP_LEASING) {
			struct create_context *ccontext =
			    (struct create_context *)iov[n_iov-1].iov_base;
			ccontext->Next =
				cpu_to_le32(server->vals->create_lease_size);
		}

		rc = add_durable_context(iov, &n_iov, oparms,
					tcon->use_persistent);
		if (rc) {
			cifs_small_buf_release(req);
			kfree(copy_path);
			kfree(lc_buf);
			return rc;
		}
		dhc_buf = iov[n_iov-1].iov_base;
	}

	rc = SendReceive2(xid, ses, iov, n_iov, &resp_buftype, flags, &rsp_iov);
	cifs_small_buf_release(req);
	rsp = (struct smb2_create_rsp *)rsp_iov.iov_base;

	if (rc != 0) {
		cifs_stats_fail_inc(tcon, SMB2_CREATE_HE);
		if (err_buf)
			*err_buf = kmemdup(rsp, get_rfc1002_length(rsp) + 4,
					   GFP_KERNEL);
		goto creat_exit;
	}

	oparms->fid->persistent_fid = rsp->PersistentFileId;
	oparms->fid->volatile_fid = rsp->VolatileFileId;

	if (buf) {
		memcpy(buf, &rsp->CreationTime, 32);
		buf->AllocationSize = rsp->AllocationSize;
		buf->EndOfFile = rsp->EndofFile;
		buf->Attributes = rsp->FileAttributes;
		buf->NumberOfLinks = cpu_to_le32(1);
		buf->DeletePending = 0;
	}

	if (rsp->OplockLevel == SMB2_OPLOCK_LEVEL_LEASE)
		*oplock = parse_lease_state(server, rsp, &oparms->fid->epoch);
	else
		*oplock = rsp->OplockLevel;
creat_exit:
	kfree(copy_path);
	kfree(lc_buf);
	kfree(dhc_buf);
	free_rsp_buf(resp_buftype, rsp);
	return rc;
}

/*
 *	SMB2 IOCTL is used for both IOCTLs and FSCTLs
 */
int
SMB2_ioctl(const unsigned int xid, struct cifs_tcon *tcon, u64 persistent_fid,
	   u64 volatile_fid, u32 opcode, bool is_fsctl, bool use_ipc,
	   char *in_data, u32 indatalen,
	   char **out_data, u32 *plen /* returned data len */)
{
	struct smb2_ioctl_req *req;
	struct smb2_ioctl_rsp *rsp;
	struct smb2_sync_hdr *shdr;
	struct TCP_Server_Info *server;
	struct cifs_ses *ses;
	struct kvec iov[2];
	struct kvec rsp_iov;
	int resp_buftype;
	int n_iov;
	int rc = 0;
	int flags = 0;

	cifs_dbg(FYI, "SMB2 IOCTL\n");

	if (out_data != NULL)
		*out_data = NULL;

	/* zero out returned data len, in case of error */
	if (plen)
		*plen = 0;

	if (tcon)
		ses = tcon->ses;
	else
		return -EIO;

	if (ses && (ses->server))
		server = ses->server;
	else
		return -EIO;

	rc = small_smb2_init(SMB2_IOCTL, tcon, (void **) &req);
	if (rc)
		return rc;

	if (use_ipc) {
		if (ses->ipc_tid == 0) {
			cifs_small_buf_release(req);
			return -ENOTCONN;
		}

		cifs_dbg(FYI, "replacing tid 0x%x with IPC tid 0x%x\n",
			 req->hdr.sync_hdr.TreeId, ses->ipc_tid);
		req->hdr.sync_hdr.TreeId = ses->ipc_tid;
	}
	if (encryption_required(tcon))
		flags |= CIFS_TRANSFORM_REQ;

	req->CtlCode = cpu_to_le32(opcode);
	req->PersistentFileId = persistent_fid;
	req->VolatileFileId = volatile_fid;

	if (indatalen) {
		req->InputCount = cpu_to_le32(indatalen);
		/* do not set InputOffset if no input data */
		req->InputOffset =
		       cpu_to_le32(offsetof(struct smb2_ioctl_req, Buffer) - 4);
		iov[1].iov_base = in_data;
		iov[1].iov_len = indatalen;
		n_iov = 2;
	} else
		n_iov = 1;

	req->OutputOffset = 0;
	req->OutputCount = 0; /* MBZ */

	/*
	 * Could increase MaxOutputResponse, but that would require more
	 * than one credit. Windows typically sets this smaller, but for some
	 * ioctls it may be useful to allow server to send more. No point
	 * limiting what the server can send as long as fits in one credit
	 * Unfortunately - we can not handle more than CIFS_MAX_MSG_SIZE
	 * (by default, note that it can be overridden to make max larger)
	 * in responses (except for read responses which can be bigger.
	 * We may want to bump this limit up
	 */
	req->MaxOutputResponse = cpu_to_le32(CIFSMaxBufSize);

	if (is_fsctl)
		req->Flags = cpu_to_le32(SMB2_0_IOCTL_IS_FSCTL);
	else
		req->Flags = 0;

	iov[0].iov_base = (char *)req;

	/*
	 * If no input data, the size of ioctl struct in
	 * protocol spec still includes a 1 byte data buffer,
	 * but if input data passed to ioctl, we do not
	 * want to double count this, so we do not send
	 * the dummy one byte of data in iovec[0] if sending
	 * input data (in iovec[1]). We also must add 4 bytes
	 * in first iovec to allow for rfc1002 length field.
	 */

	if (indatalen) {
		iov[0].iov_len = get_rfc1002_length(req) + 4 - 1;
		inc_rfc1001_len(req, indatalen - 1);
	} else
		iov[0].iov_len = get_rfc1002_length(req) + 4;


	rc = SendReceive2(xid, ses, iov, n_iov, &resp_buftype, flags, &rsp_iov);
	cifs_small_buf_release(req);
	rsp = (struct smb2_ioctl_rsp *)rsp_iov.iov_base;

	if ((rc != 0) && (rc != -EINVAL)) {
		cifs_stats_fail_inc(tcon, SMB2_IOCTL_HE);
		goto ioctl_exit;
	} else if (rc == -EINVAL) {
		if ((opcode != FSCTL_SRV_COPYCHUNK_WRITE) &&
		    (opcode != FSCTL_SRV_COPYCHUNK)) {
			cifs_stats_fail_inc(tcon, SMB2_IOCTL_HE);
			goto ioctl_exit;
		}
	}

	/* check if caller wants to look at return data or just return rc */
	if ((plen == NULL) || (out_data == NULL))
		goto ioctl_exit;

	*plen = le32_to_cpu(rsp->OutputCount);

	/* We check for obvious errors in the output buffer length and offset */
	if (*plen == 0)
		goto ioctl_exit; /* server returned no data */
	else if (*plen > 0xFF00) {
		cifs_dbg(VFS, "srv returned invalid ioctl length: %d\n", *plen);
		*plen = 0;
		rc = -EIO;
		goto ioctl_exit;
	}

	if (get_rfc1002_length(rsp) < le32_to_cpu(rsp->OutputOffset) + *plen) {
		cifs_dbg(VFS, "Malformed ioctl resp: len %d offset %d\n", *plen,
			le32_to_cpu(rsp->OutputOffset));
		*plen = 0;
		rc = -EIO;
		goto ioctl_exit;
	}

	*out_data = kmalloc(*plen, GFP_KERNEL);
	if (*out_data == NULL) {
		rc = -ENOMEM;
		goto ioctl_exit;
	}

	shdr = get_sync_hdr(rsp);
	memcpy(*out_data, (char *)shdr + le32_to_cpu(rsp->OutputOffset), *plen);
ioctl_exit:
	free_rsp_buf(resp_buftype, rsp);
	return rc;
}

/*
 *   Individual callers to ioctl worker function follow
 */

int
SMB2_set_compression(const unsigned int xid, struct cifs_tcon *tcon,
		     u64 persistent_fid, u64 volatile_fid)
{
	int rc;
	struct  compress_ioctl fsctl_input;
	char *ret_data = NULL;

	fsctl_input.CompressionState =
			cpu_to_le16(COMPRESSION_FORMAT_DEFAULT);

	rc = SMB2_ioctl(xid, tcon, persistent_fid, volatile_fid,
			FSCTL_SET_COMPRESSION, true /* is_fsctl */,
			false /* use_ipc */,
			(char *)&fsctl_input /* data input */,
			2 /* in data len */, &ret_data /* out data */, NULL);

	cifs_dbg(FYI, "set compression rc %d\n", rc);

	return rc;
}

int
SMB2_close(const unsigned int xid, struct cifs_tcon *tcon,
	   u64 persistent_fid, u64 volatile_fid)
{
	struct smb2_close_req *req;
	struct smb2_close_rsp *rsp;
	struct TCP_Server_Info *server;
	struct cifs_ses *ses = tcon->ses;
	struct kvec iov[1];
	struct kvec rsp_iov;
	int resp_buftype;
	int rc = 0;
	int flags = 0;

	cifs_dbg(FYI, "Close\n");

	if (ses && (ses->server))
		server = ses->server;
	else
		return -EIO;

	rc = small_smb2_init(SMB2_CLOSE, tcon, (void **) &req);
	if (rc)
		return rc;

	if (encryption_required(tcon))
		flags |= CIFS_TRANSFORM_REQ;

	req->PersistentFileId = persistent_fid;
	req->VolatileFileId = volatile_fid;

	iov[0].iov_base = (char *)req;
	/* 4 for rfc1002 length field */
	iov[0].iov_len = get_rfc1002_length(req) + 4;

	rc = SendReceive2(xid, ses, iov, 1, &resp_buftype, flags, &rsp_iov);
	cifs_small_buf_release(req);
	rsp = (struct smb2_close_rsp *)rsp_iov.iov_base;

	if (rc != 0) {
		cifs_stats_fail_inc(tcon, SMB2_CLOSE_HE);
		goto close_exit;
	}

	/* BB FIXME - decode close response, update inode for caching */

close_exit:
	free_rsp_buf(resp_buftype, rsp);
	return rc;
}

static int
validate_buf(unsigned int offset, unsigned int buffer_length,
	     struct smb2_hdr *hdr, unsigned int min_buf_size)

{
	unsigned int smb_len = be32_to_cpu(hdr->smb2_buf_length);
	char *end_of_smb = smb_len + 4 /* RFC1001 length field */ + (char *)hdr;
	char *begin_of_buf = 4 /* RFC1001 len field */ + offset + (char *)hdr;
	char *end_of_buf = begin_of_buf + buffer_length;


	if (buffer_length < min_buf_size) {
		cifs_dbg(VFS, "buffer length %d smaller than minimum size %d\n",
			 buffer_length, min_buf_size);
		return -EINVAL;
	}

	/* check if beyond RFC1001 maximum length */
	if ((smb_len > 0x7FFFFF) || (buffer_length > 0x7FFFFF)) {
		cifs_dbg(VFS, "buffer length %d or smb length %d too large\n",
			 buffer_length, smb_len);
		return -EINVAL;
	}

	if ((begin_of_buf > end_of_smb) || (end_of_buf > end_of_smb)) {
		cifs_dbg(VFS, "illegal server response, bad offset to data\n");
		return -EINVAL;
	}

	return 0;
}

/*
 * If SMB buffer fields are valid, copy into temporary buffer to hold result.
 * Caller must free buffer.
 */
static int
validate_and_copy_buf(unsigned int offset, unsigned int buffer_length,
		      struct smb2_hdr *hdr, unsigned int minbufsize,
		      char *data)

{
	char *begin_of_buf = 4 /* RFC1001 len field */ + offset + (char *)hdr;
	int rc;

	if (!data)
		return -EINVAL;

	rc = validate_buf(offset, buffer_length, hdr, minbufsize);
	if (rc)
		return rc;

	memcpy(data, begin_of_buf, buffer_length);

	return 0;
}

static int
query_info(const unsigned int xid, struct cifs_tcon *tcon,
	   u64 persistent_fid, u64 volatile_fid, u8 info_class,
	   size_t output_len, size_t min_len, void *data)
{
	struct smb2_query_info_req *req;
	struct smb2_query_info_rsp *rsp = NULL;
	struct kvec iov[2];
	struct kvec rsp_iov;
	int rc = 0;
	int resp_buftype;
	struct TCP_Server_Info *server;
	struct cifs_ses *ses = tcon->ses;
	int flags = 0;

	cifs_dbg(FYI, "Query Info\n");

	if (ses && (ses->server))
		server = ses->server;
	else
		return -EIO;

	rc = small_smb2_init(SMB2_QUERY_INFO, tcon, (void **) &req);
	if (rc)
		return rc;

	if (encryption_required(tcon))
		flags |= CIFS_TRANSFORM_REQ;

	req->InfoType = SMB2_O_INFO_FILE;
	req->FileInfoClass = info_class;
	req->PersistentFileId = persistent_fid;
	req->VolatileFileId = volatile_fid;
	/* 4 for rfc1002 length field and 1 for Buffer */
	req->InputBufferOffset =
		cpu_to_le16(sizeof(struct smb2_query_info_req) - 1 - 4);
	req->OutputBufferLength = cpu_to_le32(output_len);

	iov[0].iov_base = (char *)req;
	/* 4 for rfc1002 length field */
	iov[0].iov_len = get_rfc1002_length(req) + 4;

	rc = SendReceive2(xid, ses, iov, 1, &resp_buftype, flags, &rsp_iov);
	cifs_small_buf_release(req);
	rsp = (struct smb2_query_info_rsp *)rsp_iov.iov_base;

	if (rc) {
		cifs_stats_fail_inc(tcon, SMB2_QUERY_INFO_HE);
		goto qinf_exit;
	}

	rc = validate_and_copy_buf(le16_to_cpu(rsp->OutputBufferOffset),
				   le32_to_cpu(rsp->OutputBufferLength),
				   &rsp->hdr, min_len, data);

qinf_exit:
	free_rsp_buf(resp_buftype, rsp);
	return rc;
}

int
SMB2_query_info(const unsigned int xid, struct cifs_tcon *tcon,
		u64 persistent_fid, u64 volatile_fid,
		struct smb2_file_all_info *data)
{
	return query_info(xid, tcon, persistent_fid, volatile_fid,
			  FILE_ALL_INFORMATION,
			  sizeof(struct smb2_file_all_info) + PATH_MAX * 2,
			  sizeof(struct smb2_file_all_info), data);
}

int
SMB2_get_srv_num(const unsigned int xid, struct cifs_tcon *tcon,
		 u64 persistent_fid, u64 volatile_fid, __le64 *uniqueid)
{
	return query_info(xid, tcon, persistent_fid, volatile_fid,
			  FILE_INTERNAL_INFORMATION,
			  sizeof(struct smb2_file_internal_info),
			  sizeof(struct smb2_file_internal_info), uniqueid);
}

/*
 * This is a no-op for now. We're not really interested in the reply, but
 * rather in the fact that the server sent one and that server->lstrp
 * gets updated.
 *
 * FIXME: maybe we should consider checking that the reply matches request?
 */
static void
smb2_echo_callback(struct mid_q_entry *mid)
{
	struct TCP_Server_Info *server = mid->callback_data;
	struct smb2_echo_rsp *rsp = (struct smb2_echo_rsp *)mid->resp_buf;
	unsigned int credits_received = 1;

	if (mid->mid_state == MID_RESPONSE_RECEIVED)
		credits_received = le16_to_cpu(rsp->hdr.sync_hdr.CreditRequest);

	DeleteMidQEntry(mid);
	add_credits(server, credits_received, CIFS_ECHO_OP);
}

void smb2_reconnect_server(struct work_struct *work)
{
	struct TCP_Server_Info *server = container_of(work,
					struct TCP_Server_Info, reconnect.work);
	struct cifs_ses *ses;
	struct cifs_tcon *tcon, *tcon2;
	struct list_head tmp_list;
	int tcon_exist = false;
	int rc;
	int resched = false;


	/* Prevent simultaneous reconnects that can corrupt tcon->rlist list */
	mutex_lock(&server->reconnect_mutex);

	INIT_LIST_HEAD(&tmp_list);
	cifs_dbg(FYI, "Need negotiate, reconnecting tcons\n");

	spin_lock(&cifs_tcp_ses_lock);
	list_for_each_entry(ses, &server->smb_ses_list, smb_ses_list) {
		list_for_each_entry(tcon, &ses->tcon_list, tcon_list) {
			if (tcon->need_reconnect || tcon->need_reopen_files) {
				tcon->tc_count++;
				list_add_tail(&tcon->rlist, &tmp_list);
				tcon_exist = true;
			}
		}
	}
	/*
	 * Get the reference to server struct to be sure that the last call of
	 * cifs_put_tcon() in the loop below won't release the server pointer.
	 */
	if (tcon_exist)
		server->srv_count++;

	spin_unlock(&cifs_tcp_ses_lock);

	list_for_each_entry_safe(tcon, tcon2, &tmp_list, rlist) {
		rc = smb2_reconnect(SMB2_INTERNAL_CMD, tcon);
		if (!rc)
			cifs_reopen_persistent_handles(tcon);
		else
			resched = true;
		list_del_init(&tcon->rlist);
		cifs_put_tcon(tcon);
	}

	cifs_dbg(FYI, "Reconnecting tcons finished\n");
	if (resched)
		queue_delayed_work(cifsiod_wq, &server->reconnect, 2 * HZ);
	mutex_unlock(&server->reconnect_mutex);

	/* now we can safely release srv struct */
	if (tcon_exist)
		cifs_put_tcp_session(server, 1);
}

int
SMB2_echo(struct TCP_Server_Info *server)
{
	struct smb2_echo_req *req;
	int rc = 0;
	struct kvec iov[2];
	struct smb_rqst rqst = { .rq_iov = iov,
				 .rq_nvec = 2 };

	cifs_dbg(FYI, "In echo request\n");

	if (server->tcpStatus == CifsNeedNegotiate) {
		/* No need to send echo on newly established connections */
		queue_delayed_work(cifsiod_wq, &server->reconnect, 0);
		return rc;
	}

	rc = small_smb2_init(SMB2_ECHO, NULL, (void **)&req);
	if (rc)
		return rc;

	req->hdr.sync_hdr.CreditRequest = cpu_to_le16(1);

	/* 4 for rfc1002 length field */
	iov[0].iov_len = 4;
	iov[0].iov_base = (char *)req;
	iov[1].iov_len = get_rfc1002_length(req);
	iov[1].iov_base = (char *)req + 4;

	rc = cifs_call_async(server, &rqst, NULL, smb2_echo_callback, NULL,
			     server, CIFS_ECHO_OP);
	if (rc)
		cifs_dbg(FYI, "Echo request failed: %d\n", rc);

	cifs_small_buf_release(req);
	return rc;
}

int
SMB2_flush(const unsigned int xid, struct cifs_tcon *tcon, u64 persistent_fid,
	   u64 volatile_fid)
{
	struct smb2_flush_req *req;
	struct TCP_Server_Info *server;
	struct cifs_ses *ses = tcon->ses;
	struct kvec iov[1];
	struct kvec rsp_iov;
	int resp_buftype;
	int rc = 0;
	int flags = 0;

	cifs_dbg(FYI, "Flush\n");

	if (ses && (ses->server))
		server = ses->server;
	else
		return -EIO;

	rc = small_smb2_init(SMB2_FLUSH, tcon, (void **) &req);
	if (rc)
		return rc;

	if (encryption_required(tcon))
		flags |= CIFS_TRANSFORM_REQ;

	req->PersistentFileId = persistent_fid;
	req->VolatileFileId = volatile_fid;

	iov[0].iov_base = (char *)req;
	/* 4 for rfc1002 length field */
	iov[0].iov_len = get_rfc1002_length(req) + 4;

	rc = SendReceive2(xid, ses, iov, 1, &resp_buftype, flags, &rsp_iov);
	cifs_small_buf_release(req);

	if (rc != 0)
		cifs_stats_fail_inc(tcon, SMB2_FLUSH_HE);

	free_rsp_buf(resp_buftype, rsp_iov.iov_base);
	return rc;
}

/*
 * To form a chain of read requests, any read requests after the first should
 * have the end_of_chain boolean set to true.
 */
static int
smb2_new_read_req(void **buf, unsigned int *total_len,
		  struct cifs_io_parms *io_parms, unsigned int remaining_bytes,
		  int request_type)
{
	int rc = -EACCES;
	struct smb2_read_plain_req *req = NULL;
	struct smb2_sync_hdr *shdr;

	rc = smb2_plain_req_init(SMB2_READ, io_parms->tcon, (void **) &req,
				 total_len);
	if (rc)
		return rc;
	if (io_parms->tcon->ses->server == NULL)
		return -ECONNABORTED;

	shdr = &req->sync_hdr;
	shdr->ProcessId = cpu_to_le32(io_parms->pid);

	req->PersistentFileId = io_parms->persistent_fid;
	req->VolatileFileId = io_parms->volatile_fid;
	req->ReadChannelInfoOffset = 0; /* reserved */
	req->ReadChannelInfoLength = 0; /* reserved */
	req->Channel = 0; /* reserved */
	req->MinimumCount = 0;
	req->Length = cpu_to_le32(io_parms->length);
	req->Offset = cpu_to_le64(io_parms->offset);

	if (request_type & CHAINED_REQUEST) {
		if (!(request_type & END_OF_CHAIN)) {
			/* next 8-byte aligned request */
			*total_len = DIV_ROUND_UP(*total_len, 8) * 8;
			shdr->NextCommand = cpu_to_le32(*total_len);
		} else /* END_OF_CHAIN */
			shdr->NextCommand = 0;
		if (request_type & RELATED_REQUEST) {
			shdr->Flags |= SMB2_FLAGS_RELATED_OPERATIONS;
			/*
			 * Related requests use info from previous read request
			 * in chain.
			 */
			shdr->SessionId = 0xFFFFFFFF;
			shdr->TreeId = 0xFFFFFFFF;
			req->PersistentFileId = 0xFFFFFFFF;
			req->VolatileFileId = 0xFFFFFFFF;
		}
	}
	if (remaining_bytes > io_parms->length)
		req->RemainingBytes = cpu_to_le32(remaining_bytes);
	else
		req->RemainingBytes = 0;

	*buf = req;
	return rc;
}

static void
smb2_readv_callback(struct mid_q_entry *mid)
{
	struct cifs_readdata *rdata = mid->callback_data;
	struct cifs_tcon *tcon = tlink_tcon(rdata->cfile->tlink);
	struct TCP_Server_Info *server = tcon->ses->server;
	struct smb2_sync_hdr *shdr =
				(struct smb2_sync_hdr *)rdata->iov[1].iov_base;
	unsigned int credits_received = 1;
	struct smb_rqst rqst = { .rq_iov = rdata->iov,
				 .rq_nvec = 2,
				 .rq_pages = rdata->pages,
				 .rq_npages = rdata->nr_pages,
				 .rq_pagesz = rdata->pagesz,
				 .rq_tailsz = rdata->tailsz };

	cifs_dbg(FYI, "%s: mid=%llu state=%d result=%d bytes=%u\n",
		 __func__, mid->mid, mid->mid_state, rdata->result,
		 rdata->bytes);

	switch (mid->mid_state) {
	case MID_RESPONSE_RECEIVED:
		credits_received = le16_to_cpu(shdr->CreditRequest);
		/* result already set, check signature */
		if (server->sign && !mid->decrypted) {
			int rc;

			rc = smb2_verify_signature(&rqst, server);
			if (rc)
				cifs_dbg(VFS, "SMB signature verification returned error = %d\n",
					 rc);
		}
		/* FIXME: should this be counted toward the initiating task? */
		task_io_account_read(rdata->got_bytes);
		cifs_stats_bytes_read(tcon, rdata->got_bytes);
		break;
	case MID_REQUEST_SUBMITTED:
	case MID_RETRY_NEEDED:
		rdata->result = -EAGAIN;
		if (server->sign && rdata->got_bytes)
			/* reset bytes number since we can not check a sign */
			rdata->got_bytes = 0;
		/* FIXME: should this be counted toward the initiating task? */
		task_io_account_read(rdata->got_bytes);
		cifs_stats_bytes_read(tcon, rdata->got_bytes);
		break;
	default:
		if (rdata->result != -ENODATA)
			rdata->result = -EIO;
	}

	if (rdata->result)
		cifs_stats_fail_inc(tcon, SMB2_READ_HE);

	queue_work(cifsiod_wq, &rdata->work);
	DeleteMidQEntry(mid);
	add_credits(server, credits_received, 0);
}

/* smb2_async_readv - send an async read, and set up mid to handle result */
int
smb2_async_readv(struct cifs_readdata *rdata)
{
	int rc, flags = 0;
	char *buf;
	struct smb2_sync_hdr *shdr;
	struct cifs_io_parms io_parms;
	struct smb_rqst rqst = { .rq_iov = rdata->iov,
				 .rq_nvec = 2 };
	struct TCP_Server_Info *server;
	unsigned int total_len;
	__be32 req_len;

	cifs_dbg(FYI, "%s: offset=%llu bytes=%u\n",
		 __func__, rdata->offset, rdata->bytes);

	io_parms.tcon = tlink_tcon(rdata->cfile->tlink);
	io_parms.offset = rdata->offset;
	io_parms.length = rdata->bytes;
	io_parms.persistent_fid = rdata->cfile->fid.persistent_fid;
	io_parms.volatile_fid = rdata->cfile->fid.volatile_fid;
	io_parms.pid = rdata->pid;

	server = io_parms.tcon->ses->server;

	rc = smb2_new_read_req((void **) &buf, &total_len, &io_parms, 0, 0);
	if (rc) {
		if (rc == -EAGAIN && rdata->credits) {
			/* credits was reset by reconnect */
			rdata->credits = 0;
			/* reduce in_flight value since we won't send the req */
			spin_lock(&server->req_lock);
			server->in_flight--;
			spin_unlock(&server->req_lock);
		}
		return rc;
	}

	if (encryption_required(io_parms.tcon))
		flags |= CIFS_TRANSFORM_REQ;

	req_len = cpu_to_be32(total_len);

	rdata->iov[0].iov_base = &req_len;
	rdata->iov[0].iov_len = sizeof(__be32);
	rdata->iov[1].iov_base = buf;
	rdata->iov[1].iov_len = total_len;

	shdr = (struct smb2_sync_hdr *)buf;

	if (rdata->credits) {
		shdr->CreditCharge = cpu_to_le16(DIV_ROUND_UP(rdata->bytes,
						SMB2_MAX_BUFFER_SIZE));
		shdr->CreditRequest = shdr->CreditCharge;
		spin_lock(&server->req_lock);
		server->credits += rdata->credits -
						le16_to_cpu(shdr->CreditCharge);
		spin_unlock(&server->req_lock);
		wake_up(&server->request_q);
		flags |= CIFS_HAS_CREDITS;
	}

	kref_get(&rdata->refcount);
	rc = cifs_call_async(io_parms.tcon->ses->server, &rqst,
			     cifs_readv_receive, smb2_readv_callback,
			     smb3_handle_read_data, rdata, flags);
	if (rc) {
		kref_put(&rdata->refcount, cifs_readdata_release);
		cifs_stats_fail_inc(io_parms.tcon, SMB2_READ_HE);
	}

	cifs_small_buf_release(buf);
	return rc;
}

int
SMB2_read(const unsigned int xid, struct cifs_io_parms *io_parms,
	  unsigned int *nbytes, char **buf, int *buf_type)
{
	int resp_buftype, rc = -EACCES;
	struct smb2_read_plain_req *req = NULL;
	struct smb2_read_rsp *rsp = NULL;
	struct smb2_sync_hdr *shdr;
	struct kvec iov[2];
	struct kvec rsp_iov;
	unsigned int total_len;
	__be32 req_len;
	struct smb_rqst rqst = { .rq_iov = iov,
				 .rq_nvec = 2 };
	int flags = CIFS_LOG_ERROR;
	struct cifs_ses *ses = io_parms->tcon->ses;

	*nbytes = 0;
	rc = smb2_new_read_req((void **)&req, &total_len, io_parms, 0, 0);
	if (rc)
		return rc;

	if (encryption_required(io_parms->tcon))
		flags |= CIFS_TRANSFORM_REQ;

	req_len = cpu_to_be32(total_len);

	iov[0].iov_base = &req_len;
	iov[0].iov_len = sizeof(__be32);
	iov[1].iov_base = req;
	iov[1].iov_len = total_len;

	rc = cifs_send_recv(xid, ses, &rqst, &resp_buftype, flags, &rsp_iov);
	cifs_small_buf_release(req);

	rsp = (struct smb2_read_rsp *)rsp_iov.iov_base;
	shdr = get_sync_hdr(rsp);

	if (shdr->Status == STATUS_END_OF_FILE) {
		free_rsp_buf(resp_buftype, rsp_iov.iov_base);
		return 0;
	}

	if (rc) {
		cifs_stats_fail_inc(io_parms->tcon, SMB2_READ_HE);
		cifs_dbg(VFS, "Send error in read = %d\n", rc);
	} else {
		*nbytes = le32_to_cpu(rsp->DataLength);
		if ((*nbytes > CIFS_MAX_MSGSIZE) ||
		    (*nbytes > io_parms->length)) {
			cifs_dbg(FYI, "bad length %d for count %d\n",
				 *nbytes, io_parms->length);
			rc = -EIO;
			*nbytes = 0;
		}
	}

	if (*buf) {
		memcpy(*buf, (char *)shdr + rsp->DataOffset, *nbytes);
		free_rsp_buf(resp_buftype, rsp_iov.iov_base);
	} else if (resp_buftype != CIFS_NO_BUFFER) {
		*buf = rsp_iov.iov_base;
		if (resp_buftype == CIFS_SMALL_BUFFER)
			*buf_type = CIFS_SMALL_BUFFER;
		else if (resp_buftype == CIFS_LARGE_BUFFER)
			*buf_type = CIFS_LARGE_BUFFER;
	}
	return rc;
}

/*
 * Check the mid_state and signature on received buffer (if any), and queue the
 * workqueue completion task.
 */
static void
smb2_writev_callback(struct mid_q_entry *mid)
{
	struct cifs_writedata *wdata = mid->callback_data;
	struct cifs_tcon *tcon = tlink_tcon(wdata->cfile->tlink);
	unsigned int written;
	struct smb2_write_rsp *rsp = (struct smb2_write_rsp *)mid->resp_buf;
	unsigned int credits_received = 1;

	switch (mid->mid_state) {
	case MID_RESPONSE_RECEIVED:
		credits_received = le16_to_cpu(rsp->hdr.sync_hdr.CreditRequest);
		wdata->result = smb2_check_receive(mid, tcon->ses->server, 0);
		if (wdata->result != 0)
			break;

		written = le32_to_cpu(rsp->DataLength);
		/*
		 * Mask off high 16 bits when bytes written as returned
		 * by the server is greater than bytes requested by the
		 * client. OS/2 servers are known to set incorrect
		 * CountHigh values.
		 */
		if (written > wdata->bytes)
			written &= 0xFFFF;

		if (written < wdata->bytes)
			wdata->result = -ENOSPC;
		else
			wdata->bytes = written;
		break;
	case MID_REQUEST_SUBMITTED:
	case MID_RETRY_NEEDED:
		wdata->result = -EAGAIN;
		break;
	default:
		wdata->result = -EIO;
		break;
	}

	if (wdata->result)
		cifs_stats_fail_inc(tcon, SMB2_WRITE_HE);

	queue_work(cifsiod_wq, &wdata->work);
	DeleteMidQEntry(mid);
	add_credits(tcon->ses->server, credits_received, 0);
}

/* smb2_async_writev - send an async write, and set up mid to handle result */
int
smb2_async_writev(struct cifs_writedata *wdata,
		  void (*release)(struct kref *kref))
{
	int rc = -EACCES, flags = 0;
	struct smb2_write_req *req = NULL;
	struct smb2_sync_hdr *shdr;
	struct cifs_tcon *tcon = tlink_tcon(wdata->cfile->tlink);
	struct TCP_Server_Info *server = tcon->ses->server;
	struct kvec iov[2];
	struct smb_rqst rqst = { };

	rc = small_smb2_init(SMB2_WRITE, tcon, (void **) &req);
	if (rc) {
		if (rc == -EAGAIN && wdata->credits) {
			/* credits was reset by reconnect */
			wdata->credits = 0;
			/* reduce in_flight value since we won't send the req */
			spin_lock(&server->req_lock);
			server->in_flight--;
			spin_unlock(&server->req_lock);
		}
		goto async_writev_out;
	}

	if (encryption_required(tcon))
		flags |= CIFS_TRANSFORM_REQ;

	shdr = get_sync_hdr(req);
	shdr->ProcessId = cpu_to_le32(wdata->cfile->pid);

	req->PersistentFileId = wdata->cfile->fid.persistent_fid;
	req->VolatileFileId = wdata->cfile->fid.volatile_fid;
	req->WriteChannelInfoOffset = 0;
	req->WriteChannelInfoLength = 0;
	req->Channel = 0;
	req->Offset = cpu_to_le64(wdata->offset);
	/* 4 for rfc1002 length field */
	req->DataOffset = cpu_to_le16(
				offsetof(struct smb2_write_req, Buffer) - 4);
	req->RemainingBytes = 0;

	/* 4 for rfc1002 length field and 1 for Buffer */
	iov[0].iov_len = 4;
	iov[0].iov_base = req;
	iov[1].iov_len = get_rfc1002_length(req) - 1;
	iov[1].iov_base = (char *)req + 4;

	rqst.rq_iov = iov;
	rqst.rq_nvec = 2;
	rqst.rq_pages = wdata->pages;
	rqst.rq_npages = wdata->nr_pages;
	rqst.rq_pagesz = wdata->pagesz;
	rqst.rq_tailsz = wdata->tailsz;

	cifs_dbg(FYI, "async write at %llu %u bytes\n",
		 wdata->offset, wdata->bytes);

	req->Length = cpu_to_le32(wdata->bytes);

	inc_rfc1001_len(&req->hdr, wdata->bytes - 1 /* Buffer */);

	if (wdata->credits) {
		shdr->CreditCharge = cpu_to_le16(DIV_ROUND_UP(wdata->bytes,
						    SMB2_MAX_BUFFER_SIZE));
		shdr->CreditRequest = shdr->CreditCharge;
		spin_lock(&server->req_lock);
		server->credits += wdata->credits -
						le16_to_cpu(shdr->CreditCharge);
		spin_unlock(&server->req_lock);
		wake_up(&server->request_q);
		flags |= CIFS_HAS_CREDITS;
	}

	kref_get(&wdata->refcount);
	rc = cifs_call_async(server, &rqst, NULL, smb2_writev_callback, NULL,
			     wdata, flags);

	if (rc) {
		kref_put(&wdata->refcount, release);
		cifs_stats_fail_inc(tcon, SMB2_WRITE_HE);
	}

async_writev_out:
	cifs_small_buf_release(req);
	return rc;
}

/*
 * SMB2_write function gets iov pointer to kvec array with n_vec as a length.
 * The length field from io_parms must be at least 1 and indicates a number of
 * elements with data to write that begins with position 1 in iov array. All
 * data length is specified by count.
 */
int
SMB2_write(const unsigned int xid, struct cifs_io_parms *io_parms,
	   unsigned int *nbytes, struct kvec *iov, int n_vec)
{
	int rc = 0;
	struct smb2_write_req *req = NULL;
	struct smb2_write_rsp *rsp = NULL;
	int resp_buftype;
	struct kvec rsp_iov;
	int flags = 0;

	*nbytes = 0;

	if (n_vec < 1)
		return rc;

	rc = small_smb2_init(SMB2_WRITE, io_parms->tcon, (void **) &req);
	if (rc)
		return rc;

	if (io_parms->tcon->ses->server == NULL)
		return -ECONNABORTED;

	if (encryption_required(io_parms->tcon))
		flags |= CIFS_TRANSFORM_REQ;

	req->hdr.sync_hdr.ProcessId = cpu_to_le32(io_parms->pid);

	req->PersistentFileId = io_parms->persistent_fid;
	req->VolatileFileId = io_parms->volatile_fid;
	req->WriteChannelInfoOffset = 0;
	req->WriteChannelInfoLength = 0;
	req->Channel = 0;
	req->Length = cpu_to_le32(io_parms->length);
	req->Offset = cpu_to_le64(io_parms->offset);
	/* 4 for rfc1002 length field */
	req->DataOffset = cpu_to_le16(
				offsetof(struct smb2_write_req, Buffer) - 4);
	req->RemainingBytes = 0;

	iov[0].iov_base = (char *)req;
	/* 4 for rfc1002 length field and 1 for Buffer */
	iov[0].iov_len = get_rfc1002_length(req) + 4 - 1;

	/* length of entire message including data to be written */
	inc_rfc1001_len(req, io_parms->length - 1 /* Buffer */);

	rc = SendReceive2(xid, io_parms->tcon->ses, iov, n_vec + 1,
			  &resp_buftype, flags, &rsp_iov);
	cifs_small_buf_release(req);
	rsp = (struct smb2_write_rsp *)rsp_iov.iov_base;

	if (rc) {
		cifs_stats_fail_inc(io_parms->tcon, SMB2_WRITE_HE);
		cifs_dbg(VFS, "Send error in write = %d\n", rc);
	} else
		*nbytes = le32_to_cpu(rsp->DataLength);

	free_rsp_buf(resp_buftype, rsp);
	return rc;
}

static unsigned int
num_entries(char *bufstart, char *end_of_buf, char **lastentry, size_t size)
{
	int len;
	unsigned int entrycount = 0;
	unsigned int next_offset = 0;
	FILE_DIRECTORY_INFO *entryptr;

	if (bufstart == NULL)
		return 0;

	entryptr = (FILE_DIRECTORY_INFO *)bufstart;

	while (1) {
		entryptr = (FILE_DIRECTORY_INFO *)
					((char *)entryptr + next_offset);

		if ((char *)entryptr + size > end_of_buf) {
			cifs_dbg(VFS, "malformed search entry would overflow\n");
			break;
		}

		len = le32_to_cpu(entryptr->FileNameLength);
		if ((char *)entryptr + len + size > end_of_buf) {
			cifs_dbg(VFS, "directory entry name would overflow frame end of buf %p\n",
				 end_of_buf);
			break;
		}

		*lastentry = (char *)entryptr;
		entrycount++;

		next_offset = le32_to_cpu(entryptr->NextEntryOffset);
		if (!next_offset)
			break;
	}

	return entrycount;
}

/*
 * Readdir/FindFirst
 */
int
SMB2_query_directory(const unsigned int xid, struct cifs_tcon *tcon,
		     u64 persistent_fid, u64 volatile_fid, int index,
		     struct cifs_search_info *srch_inf)
{
	struct smb2_query_directory_req *req;
	struct smb2_query_directory_rsp *rsp = NULL;
	struct kvec iov[2];
	struct kvec rsp_iov;
	int rc = 0;
	int len;
	int resp_buftype = CIFS_NO_BUFFER;
	unsigned char *bufptr;
	struct TCP_Server_Info *server;
	struct cifs_ses *ses = tcon->ses;
	__le16 asteriks = cpu_to_le16('*');
	char *end_of_smb;
	unsigned int output_size = CIFSMaxBufSize;
	size_t info_buf_size;
	int flags = 0;

	if (ses && (ses->server))
		server = ses->server;
	else
		return -EIO;

	rc = small_smb2_init(SMB2_QUERY_DIRECTORY, tcon, (void **) &req);
	if (rc)
		return rc;

	if (encryption_required(tcon))
		flags |= CIFS_TRANSFORM_REQ;

	switch (srch_inf->info_level) {
	case SMB_FIND_FILE_DIRECTORY_INFO:
		req->FileInformationClass = FILE_DIRECTORY_INFORMATION;
		info_buf_size = sizeof(FILE_DIRECTORY_INFO) - 1;
		break;
	case SMB_FIND_FILE_ID_FULL_DIR_INFO:
		req->FileInformationClass = FILEID_FULL_DIRECTORY_INFORMATION;
		info_buf_size = sizeof(SEARCH_ID_FULL_DIR_INFO) - 1;
		break;
	default:
		cifs_dbg(VFS, "info level %u isn't supported\n",
			 srch_inf->info_level);
		rc = -EINVAL;
		goto qdir_exit;
	}

	req->FileIndex = cpu_to_le32(index);
	req->PersistentFileId = persistent_fid;
	req->VolatileFileId = volatile_fid;

	len = 0x2;
	bufptr = req->Buffer;
	memcpy(bufptr, &asteriks, len);

	req->FileNameOffset =
		cpu_to_le16(sizeof(struct smb2_query_directory_req) - 1 - 4);
	req->FileNameLength = cpu_to_le16(len);
	/*
	 * BB could be 30 bytes or so longer if we used SMB2 specific
	 * buffer lengths, but this is safe and close enough.
	 */
	output_size = min_t(unsigned int, output_size, server->maxBuf);
	output_size = min_t(unsigned int, output_size, 2 << 15);
	req->OutputBufferLength = cpu_to_le32(output_size);

	iov[0].iov_base = (char *)req;
	/* 4 for RFC1001 length and 1 for Buffer */
	iov[0].iov_len = get_rfc1002_length(req) + 4 - 1;

	iov[1].iov_base = (char *)(req->Buffer);
	iov[1].iov_len = len;

	inc_rfc1001_len(req, len - 1 /* Buffer */);

	rc = SendReceive2(xid, ses, iov, 2, &resp_buftype, flags, &rsp_iov);
	cifs_small_buf_release(req);
	rsp = (struct smb2_query_directory_rsp *)rsp_iov.iov_base;

	if (rc) {
		if (rc == -ENODATA &&
		    rsp->hdr.sync_hdr.Status == STATUS_NO_MORE_FILES) {
			srch_inf->endOfSearch = true;
			rc = 0;
		}
		cifs_stats_fail_inc(tcon, SMB2_QUERY_DIRECTORY_HE);
		goto qdir_exit;
	}

	rc = validate_buf(le16_to_cpu(rsp->OutputBufferOffset),
			  le32_to_cpu(rsp->OutputBufferLength), &rsp->hdr,
			  info_buf_size);
	if (rc)
		goto qdir_exit;

	srch_inf->unicode = true;

	if (srch_inf->ntwrk_buf_start) {
		if (srch_inf->smallBuf)
			cifs_small_buf_release(srch_inf->ntwrk_buf_start);
		else
			cifs_buf_release(srch_inf->ntwrk_buf_start);
	}
	srch_inf->ntwrk_buf_start = (char *)rsp;
	srch_inf->srch_entries_start = srch_inf->last_entry = 4 /* rfclen */ +
		(char *)&rsp->hdr + le16_to_cpu(rsp->OutputBufferOffset);
	/* 4 for rfc1002 length field */
	end_of_smb = get_rfc1002_length(rsp) + 4 + (char *)&rsp->hdr;
	srch_inf->entries_in_buffer =
			num_entries(srch_inf->srch_entries_start, end_of_smb,
				    &srch_inf->last_entry, info_buf_size);
	srch_inf->index_of_last_entry += srch_inf->entries_in_buffer;
	cifs_dbg(FYI, "num entries %d last_index %lld srch start %p srch end %p\n",
		 srch_inf->entries_in_buffer, srch_inf->index_of_last_entry,
		 srch_inf->srch_entries_start, srch_inf->last_entry);
	if (resp_buftype == CIFS_LARGE_BUFFER)
		srch_inf->smallBuf = false;
	else if (resp_buftype == CIFS_SMALL_BUFFER)
		srch_inf->smallBuf = true;
	else
		cifs_dbg(VFS, "illegal search buffer type\n");

	return rc;

qdir_exit:
	free_rsp_buf(resp_buftype, rsp);
	return rc;
}

static int
send_set_info(const unsigned int xid, struct cifs_tcon *tcon,
	       u64 persistent_fid, u64 volatile_fid, u32 pid, int info_class,
	       unsigned int num, void **data, unsigned int *size)
{
	struct smb2_set_info_req *req;
	struct smb2_set_info_rsp *rsp = NULL;
	struct kvec *iov;
	struct kvec rsp_iov;
	int rc = 0;
	int resp_buftype;
	unsigned int i;
	struct TCP_Server_Info *server;
	struct cifs_ses *ses = tcon->ses;
	int flags = 0;

	if (ses && (ses->server))
		server = ses->server;
	else
		return -EIO;

	if (!num)
		return -EINVAL;

	iov = kmalloc(sizeof(struct kvec) * num, GFP_KERNEL);
	if (!iov)
		return -ENOMEM;

	rc = small_smb2_init(SMB2_SET_INFO, tcon, (void **) &req);
	if (rc) {
		kfree(iov);
		return rc;
	}

	if (encryption_required(tcon))
		flags |= CIFS_TRANSFORM_REQ;

	req->hdr.sync_hdr.ProcessId = cpu_to_le32(pid);

	req->InfoType = SMB2_O_INFO_FILE;
	req->FileInfoClass = info_class;
	req->PersistentFileId = persistent_fid;
	req->VolatileFileId = volatile_fid;

	/* 4 for RFC1001 length and 1 for Buffer */
	req->BufferOffset =
			cpu_to_le16(sizeof(struct smb2_set_info_req) - 1 - 4);
	req->BufferLength = cpu_to_le32(*size);

	inc_rfc1001_len(req, *size - 1 /* Buffer */);

	memcpy(req->Buffer, *data, *size);

	iov[0].iov_base = (char *)req;
	/* 4 for RFC1001 length */
	iov[0].iov_len = get_rfc1002_length(req) + 4;

	for (i = 1; i < num; i++) {
		inc_rfc1001_len(req, size[i]);
		le32_add_cpu(&req->BufferLength, size[i]);
		iov[i].iov_base = (char *)data[i];
		iov[i].iov_len = size[i];
	}

	rc = SendReceive2(xid, ses, iov, num, &resp_buftype, flags, &rsp_iov);
	cifs_small_buf_release(req);
	rsp = (struct smb2_set_info_rsp *)rsp_iov.iov_base;

	if (rc != 0)
		cifs_stats_fail_inc(tcon, SMB2_SET_INFO_HE);

	free_rsp_buf(resp_buftype, rsp);
	kfree(iov);
	return rc;
}

int
SMB2_rename(const unsigned int xid, struct cifs_tcon *tcon,
	    u64 persistent_fid, u64 volatile_fid, __le16 *target_file)
{
	struct smb2_file_rename_info info;
	void **data;
	unsigned int size[2];
	int rc;
	int len = (2 * UniStrnlen((wchar_t *)target_file, PATH_MAX));

	data = kmalloc(sizeof(void *) * 2, GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	info.ReplaceIfExists = 1; /* 1 = replace existing target with new */
			      /* 0 = fail if target already exists */
	info.RootDirectory = 0;  /* MBZ for network ops (why does spec say?) */
	info.FileNameLength = cpu_to_le32(len);

	data[0] = &info;
	size[0] = sizeof(struct smb2_file_rename_info);

	data[1] = target_file;
	size[1] = len + 2 /* null */;

	rc = send_set_info(xid, tcon, persistent_fid, volatile_fid,
			   current->tgid, FILE_RENAME_INFORMATION, 2, data,
			   size);
	kfree(data);
	return rc;
}

int
SMB2_rmdir(const unsigned int xid, struct cifs_tcon *tcon,
		  u64 persistent_fid, u64 volatile_fid)
{
	__u8 delete_pending = 1;
	void *data;
	unsigned int size;

	data = &delete_pending;
	size = 1; /* sizeof __u8 */

	return send_set_info(xid, tcon, persistent_fid, volatile_fid,
			current->tgid, FILE_DISPOSITION_INFORMATION, 1, &data,
			&size);
}

int
SMB2_set_hardlink(const unsigned int xid, struct cifs_tcon *tcon,
		  u64 persistent_fid, u64 volatile_fid, __le16 *target_file)
{
	struct smb2_file_link_info info;
	void **data;
	unsigned int size[2];
	int rc;
	int len = (2 * UniStrnlen((wchar_t *)target_file, PATH_MAX));

	data = kmalloc(sizeof(void *) * 2, GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	info.ReplaceIfExists = 0; /* 1 = replace existing link with new */
			      /* 0 = fail if link already exists */
	info.RootDirectory = 0;  /* MBZ for network ops (why does spec say?) */
	info.FileNameLength = cpu_to_le32(len);

	data[0] = &info;
	size[0] = sizeof(struct smb2_file_link_info);

	data[1] = target_file;
	size[1] = len + 2 /* null */;

	rc = send_set_info(xid, tcon, persistent_fid, volatile_fid,
			   current->tgid, FILE_LINK_INFORMATION, 2, data, size);
	kfree(data);
	return rc;
}

int
SMB2_set_eof(const unsigned int xid, struct cifs_tcon *tcon, u64 persistent_fid,
	     u64 volatile_fid, u32 pid, __le64 *eof, bool is_falloc)
{
	struct smb2_file_eof_info info;
	void *data;
	unsigned int size;

	info.EndOfFile = *eof;

	data = &info;
	size = sizeof(struct smb2_file_eof_info);

	if (is_falloc)
		return send_set_info(xid, tcon, persistent_fid, volatile_fid,
			pid, FILE_ALLOCATION_INFORMATION, 1, &data, &size);
	else
		return send_set_info(xid, tcon, persistent_fid, volatile_fid,
			pid, FILE_END_OF_FILE_INFORMATION, 1, &data, &size);
}

int
SMB2_set_info(const unsigned int xid, struct cifs_tcon *tcon,
	      u64 persistent_fid, u64 volatile_fid, FILE_BASIC_INFO *buf)
{
	unsigned int size;
	size = sizeof(FILE_BASIC_INFO);
	return send_set_info(xid, tcon, persistent_fid, volatile_fid,
			     current->tgid, FILE_BASIC_INFORMATION, 1,
			     (void **)&buf, &size);
}

int
SMB2_oplock_break(const unsigned int xid, struct cifs_tcon *tcon,
		  const u64 persistent_fid, const u64 volatile_fid,
		  __u8 oplock_level)
{
	int rc;
	struct smb2_oplock_break *req = NULL;
	int flags = CIFS_OBREAK_OP;

	cifs_dbg(FYI, "SMB2_oplock_break\n");
	rc = small_smb2_init(SMB2_OPLOCK_BREAK, tcon, (void **) &req);
	if (rc)
		return rc;

	if (encryption_required(tcon))
		flags |= CIFS_TRANSFORM_REQ;

	req->VolatileFid = volatile_fid;
	req->PersistentFid = persistent_fid;
	req->OplockLevel = oplock_level;
	req->hdr.sync_hdr.CreditRequest = cpu_to_le16(1);

	rc = SendReceiveNoRsp(xid, tcon->ses, (char *) req, flags);
	cifs_small_buf_release(req);

	if (rc) {
		cifs_stats_fail_inc(tcon, SMB2_OPLOCK_BREAK_HE);
		cifs_dbg(FYI, "Send error in Oplock Break = %d\n", rc);
	}

	return rc;
}

static void
copy_fs_info_to_kstatfs(struct smb2_fs_full_size_info *pfs_inf,
			struct kstatfs *kst)
{
	kst->f_bsize = le32_to_cpu(pfs_inf->BytesPerSector) *
			  le32_to_cpu(pfs_inf->SectorsPerAllocationUnit);
	kst->f_blocks = le64_to_cpu(pfs_inf->TotalAllocationUnits);
	kst->f_bfree  = kst->f_bavail =
			le64_to_cpu(pfs_inf->CallerAvailableAllocationUnits);
	return;
}

static int
build_qfs_info_req(struct kvec *iov, struct cifs_tcon *tcon, int level,
		   int outbuf_len, u64 persistent_fid, u64 volatile_fid)
{
	int rc;
	struct smb2_query_info_req *req;

	cifs_dbg(FYI, "Query FSInfo level %d\n", level);

	if ((tcon->ses == NULL) || (tcon->ses->server == NULL))
		return -EIO;

	rc = small_smb2_init(SMB2_QUERY_INFO, tcon, (void **) &req);
	if (rc)
		return rc;

	req->InfoType = SMB2_O_INFO_FILESYSTEM;
	req->FileInfoClass = level;
	req->PersistentFileId = persistent_fid;
	req->VolatileFileId = volatile_fid;
	/* 4 for rfc1002 length field and 1 for pad */
	req->InputBufferOffset =
			cpu_to_le16(sizeof(struct smb2_query_info_req) - 1 - 4);
	req->OutputBufferLength = cpu_to_le32(
		outbuf_len + sizeof(struct smb2_query_info_rsp) - 1 - 4);

	iov->iov_base = (char *)req;
	/* 4 for rfc1002 length field */
	iov->iov_len = get_rfc1002_length(req) + 4;
	return 0;
}

int
SMB2_QFS_info(const unsigned int xid, struct cifs_tcon *tcon,
	      u64 persistent_fid, u64 volatile_fid, struct kstatfs *fsdata)
{
	struct smb2_query_info_rsp *rsp = NULL;
	struct kvec iov;
	struct kvec rsp_iov;
	int rc = 0;
	int resp_buftype;
	struct cifs_ses *ses = tcon->ses;
	struct smb2_fs_full_size_info *info = NULL;
	int flags = 0;

	rc = build_qfs_info_req(&iov, tcon, FS_FULL_SIZE_INFORMATION,
				sizeof(struct smb2_fs_full_size_info),
				persistent_fid, volatile_fid);
	if (rc)
		return rc;

	if (encryption_required(tcon))
		flags |= CIFS_TRANSFORM_REQ;

	rc = SendReceive2(xid, ses, &iov, 1, &resp_buftype, flags, &rsp_iov);
	cifs_small_buf_release(iov.iov_base);
	if (rc) {
		cifs_stats_fail_inc(tcon, SMB2_QUERY_INFO_HE);
		goto qfsinf_exit;
	}
	rsp = (struct smb2_query_info_rsp *)rsp_iov.iov_base;

	info = (struct smb2_fs_full_size_info *)(4 /* RFC1001 len */ +
		le16_to_cpu(rsp->OutputBufferOffset) + (char *)&rsp->hdr);
	rc = validate_buf(le16_to_cpu(rsp->OutputBufferOffset),
			  le32_to_cpu(rsp->OutputBufferLength), &rsp->hdr,
			  sizeof(struct smb2_fs_full_size_info));
	if (!rc)
		copy_fs_info_to_kstatfs(info, fsdata);

qfsinf_exit:
	free_rsp_buf(resp_buftype, rsp_iov.iov_base);
	return rc;
}

int
SMB2_QFS_attr(const unsigned int xid, struct cifs_tcon *tcon,
	      u64 persistent_fid, u64 volatile_fid, int level)
{
	struct smb2_query_info_rsp *rsp = NULL;
	struct kvec iov;
	struct kvec rsp_iov;
	int rc = 0;
	int resp_buftype, max_len, min_len;
	struct cifs_ses *ses = tcon->ses;
	unsigned int rsp_len, offset;
	int flags = 0;

	if (level == FS_DEVICE_INFORMATION) {
		max_len = sizeof(FILE_SYSTEM_DEVICE_INFO);
		min_len = sizeof(FILE_SYSTEM_DEVICE_INFO);
	} else if (level == FS_ATTRIBUTE_INFORMATION) {
		max_len = sizeof(FILE_SYSTEM_ATTRIBUTE_INFO);
		min_len = MIN_FS_ATTR_INFO_SIZE;
	} else if (level == FS_SECTOR_SIZE_INFORMATION) {
		max_len = sizeof(struct smb3_fs_ss_info);
		min_len = sizeof(struct smb3_fs_ss_info);
	} else {
		cifs_dbg(FYI, "Invalid qfsinfo level %d\n", level);
		return -EINVAL;
	}

	rc = build_qfs_info_req(&iov, tcon, level, max_len,
				persistent_fid, volatile_fid);
	if (rc)
		return rc;

	if (encryption_required(tcon))
		flags |= CIFS_TRANSFORM_REQ;

	rc = SendReceive2(xid, ses, &iov, 1, &resp_buftype, flags, &rsp_iov);
	cifs_small_buf_release(iov.iov_base);
	if (rc) {
		cifs_stats_fail_inc(tcon, SMB2_QUERY_INFO_HE);
		goto qfsattr_exit;
	}
	rsp = (struct smb2_query_info_rsp *)rsp_iov.iov_base;

	rsp_len = le32_to_cpu(rsp->OutputBufferLength);
	offset = le16_to_cpu(rsp->OutputBufferOffset);
	rc = validate_buf(offset, rsp_len, &rsp->hdr, min_len);
	if (rc)
		goto qfsattr_exit;

	if (level == FS_ATTRIBUTE_INFORMATION)
		memcpy(&tcon->fsAttrInfo, 4 /* RFC1001 len */ + offset
			+ (char *)&rsp->hdr, min_t(unsigned int,
			rsp_len, max_len));
	else if (level == FS_DEVICE_INFORMATION)
		memcpy(&tcon->fsDevInfo, 4 /* RFC1001 len */ + offset
			+ (char *)&rsp->hdr, sizeof(FILE_SYSTEM_DEVICE_INFO));
	else if (level == FS_SECTOR_SIZE_INFORMATION) {
		struct smb3_fs_ss_info *ss_info = (struct smb3_fs_ss_info *)
			(4 /* RFC1001 len */ + offset + (char *)&rsp->hdr);
		tcon->ss_flags = le32_to_cpu(ss_info->Flags);
		tcon->perf_sector_size =
			le32_to_cpu(ss_info->PhysicalBytesPerSectorForPerf);
	}

qfsattr_exit:
	free_rsp_buf(resp_buftype, rsp_iov.iov_base);
	return rc;
}

int
smb2_lockv(const unsigned int xid, struct cifs_tcon *tcon,
	   const __u64 persist_fid, const __u64 volatile_fid, const __u32 pid,
	   const __u32 num_lock, struct smb2_lock_element *buf)
{
	int rc = 0;
	struct smb2_lock_req *req = NULL;
	struct kvec iov[2];
	struct kvec rsp_iov;
	int resp_buf_type;
	unsigned int count;
	int flags = CIFS_NO_RESP;

	cifs_dbg(FYI, "smb2_lockv num lock %d\n", num_lock);

	rc = small_smb2_init(SMB2_LOCK, tcon, (void **) &req);
	if (rc)
		return rc;

	if (encryption_required(tcon))
		flags |= CIFS_TRANSFORM_REQ;

	req->hdr.sync_hdr.ProcessId = cpu_to_le32(pid);
	req->LockCount = cpu_to_le16(num_lock);

	req->PersistentFileId = persist_fid;
	req->VolatileFileId = volatile_fid;

	count = num_lock * sizeof(struct smb2_lock_element);
	inc_rfc1001_len(req, count - sizeof(struct smb2_lock_element));

	iov[0].iov_base = (char *)req;
	/* 4 for rfc1002 length field and count for all locks */
	iov[0].iov_len = get_rfc1002_length(req) + 4 - count;
	iov[1].iov_base = (char *)buf;
	iov[1].iov_len = count;

	cifs_stats_inc(&tcon->stats.cifs_stats.num_locks);
	rc = SendReceive2(xid, tcon->ses, iov, 2, &resp_buf_type, flags,
			  &rsp_iov);
	cifs_small_buf_release(req);
	if (rc) {
		cifs_dbg(FYI, "Send error in smb2_lockv = %d\n", rc);
		cifs_stats_fail_inc(tcon, SMB2_LOCK_HE);
	}

	return rc;
}

int
SMB2_lock(const unsigned int xid, struct cifs_tcon *tcon,
	  const __u64 persist_fid, const __u64 volatile_fid, const __u32 pid,
	  const __u64 length, const __u64 offset, const __u32 lock_flags,
	  const bool wait)
{
	struct smb2_lock_element lock;

	lock.Offset = cpu_to_le64(offset);
	lock.Length = cpu_to_le64(length);
	lock.Flags = cpu_to_le32(lock_flags);
	if (!wait && lock_flags != SMB2_LOCKFLAG_UNLOCK)
		lock.Flags |= cpu_to_le32(SMB2_LOCKFLAG_FAIL_IMMEDIATELY);

	return smb2_lockv(xid, tcon, persist_fid, volatile_fid, pid, 1, &lock);
}

int
SMB2_lease_break(const unsigned int xid, struct cifs_tcon *tcon,
		 __u8 *lease_key, const __le32 lease_state)
{
	int rc;
	struct smb2_lease_ack *req = NULL;
	int flags = CIFS_OBREAK_OP;

	cifs_dbg(FYI, "SMB2_lease_break\n");
	rc = small_smb2_init(SMB2_OPLOCK_BREAK, tcon, (void **) &req);
	if (rc)
		return rc;

	if (encryption_required(tcon))
		flags |= CIFS_TRANSFORM_REQ;

	req->hdr.sync_hdr.CreditRequest = cpu_to_le16(1);
	req->StructureSize = cpu_to_le16(36);
	inc_rfc1001_len(req, 12);

	memcpy(req->LeaseKey, lease_key, 16);
	req->LeaseState = lease_state;

	rc = SendReceiveNoRsp(xid, tcon->ses, (char *) req, flags);
	cifs_small_buf_release(req);

	if (rc) {
		cifs_stats_fail_inc(tcon, SMB2_OPLOCK_BREAK_HE);
		cifs_dbg(FYI, "Send error in Lease Break = %d\n", rc);
	}

	return rc;
}
