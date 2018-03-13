// SPDX-License-Identifier: GPL-2.0

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/efi.h>
#include <linux/slab.h>
#include <keys/asymmetric-type.h>
#include <keys/system_keyring.h>
#include "../integrity.h"
#include "keyring_handler.h"

/*
 * Look to see if a UEFI variable called MokIgnoreDB exists and return true if
 * it does.
 *
 * This UEFI variable is set by the shim if a user tells the shim to not use
 * the certs/hashes in the UEFI db variable for verification purposes.  If it
 * is set, we should ignore the db variable also and the true return indicates
 * this.
 */
static __init bool uefi_check_ignore_db(void)
{
	efi_status_t status;
	unsigned int db = 0;
	unsigned long size = sizeof(db);
	efi_guid_t guid = EFI_SHIM_LOCK_GUID;

	status = efi.get_variable(L"MokIgnoreDB", &guid, NULL, &size, &db);
	return status == EFI_SUCCESS;
}

/*
 * Get a certificate list blob from the named EFI variable.
 */
static __init void *get_cert_list(efi_char16_t *name, efi_guid_t *guid,
				  unsigned long *size, efi_status_t *status,
				  u32 pos_attr, u32 neg_attr)
{
	unsigned long lsize = 4;
	unsigned long tmpdb[4];
	void *db;
	u32 attr = 0;

	*status = efi.get_variable(name, guid, NULL, &lsize, &tmpdb);
	if (*status == EFI_NOT_FOUND)
		return NULL;

	if (*status != EFI_BUFFER_TOO_SMALL) {
		pr_err("Couldn't get size: 0x%lx\n", *status);
		return NULL;
	}

	db = kmalloc(lsize, GFP_KERNEL);
	if (!db)
		return NULL;

	*status = efi.get_variable(name, guid, &attr, &lsize, db);
	if (*status != EFI_SUCCESS) {
		kfree(db);
		pr_err("Error reading db var: 0x%lx\n", *status);
		return NULL;
	}
	/* must have positive attributes and no negative attributes */
	if ((pos_attr && !(attr & pos_attr)) ||
	    (neg_attr && (attr & neg_attr))) {
		kfree(db);
		pr_err("Error reading db var attributes: 0x%016x\n", attr);
		*status = EFI_SECURITY_VIOLATION;
		return NULL;
	}

	*size = lsize;
	return db;
}

/*
 * Load the certs contained in the UEFI databases into the platform trusted
 * keyring and the UEFI blacklisted X.509 cert SHA256 hashes into the blacklist
 * keyring.
 */
static int __init load_uefi_certs(void)
{
	efi_guid_t secure_var = EFI_IMAGE_SECURITY_DATABASE_GUID;
	efi_guid_t mok_var = EFI_SHIM_LOCK_GUID;
	void *db = NULL, *dbx = NULL, *mok = NULL, *mokx = NULL;
	unsigned long dbsize = 0, dbxsize = 0, moksize = 0, mokxsize = 0;
	efi_status_t status;
	int rc = 0;

	if (!efi_rt_services_supported(EFI_RT_SUPPORTED_GET_VARIABLE))
		return false;

	/* Get db, MokListRT, and dbx.  They might not exist, so it isn't
	 * an error if we can't get them.
	 */
	if (!uefi_check_ignore_db()) {
		db = get_cert_list(L"db", &secure_var, &dbsize, &status,
			EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS, 0);
		if (!db) {
			if (status == EFI_NOT_FOUND)
				pr_debug("MODSIGN: db variable wasn't found\n");
			else
				pr_err("MODSIGN: Couldn't get UEFI db list\n");
		} else {
			rc = parse_efi_signature_list("UEFI:db",
					db, dbsize, get_handler_for_db);
			if (rc)
				pr_err("Couldn't parse db signatures: %d\n",
				       rc);
			kfree(db);
		}
	}

	dbx = get_cert_list(L"dbx", &secure_var, &dbxsize, &status,
		EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS, 0);
	if (!dbx) {
		if (status == EFI_NOT_FOUND)
			pr_debug("dbx variable wasn't found\n");
		else
			pr_info("Couldn't get UEFI dbx list\n");
	} else {
		rc = parse_efi_signature_list("UEFI:dbx",
					      dbx, dbxsize,
					      get_handler_for_dbx);
		if (rc)
			pr_err("Couldn't parse dbx signatures: %d\n", rc);
		kfree(dbx);
	}

	/* the MOK and MOKx can not be trusted when secure boot is disabled */
	if (!efi_enabled(EFI_SECURE_BOOT))
		return 0;

	mok = get_cert_list(L"MokListRT", &mok_var, &moksize, &status,
				0, EFI_VARIABLE_NON_VOLATILE);
	if (!mok) {
		if (status == EFI_NOT_FOUND)
			pr_debug("MokListRT variable wasn't found\n");
		else
			pr_info("Couldn't get UEFI MokListRT\n");
	} else {
		rc = parse_efi_signature_list("UEFI:MokListRT",
					      mok, moksize, get_handler_for_db);
		if (rc)
			pr_err("Couldn't parse MokListRT signatures: %d\n", rc);
		kfree(mok);
	}

	mokx = get_cert_list(L"MokListXRT", &mok_var, &mokxsize, &status,
				0, EFI_VARIABLE_NON_VOLATILE);
	if (!mokx) {
		if (status == EFI_NOT_FOUND)
			pr_debug("MokListXRT variable wasn't found\n");
		else
			pr_info("Couldn't get UEFI MokListXRT\n");
	} else {
		rc = parse_efi_signature_list("UEFI:mokx",
					      mokx, mokxsize,
					      get_handler_for_dbx);
		if (rc)
			pr_err("Couldn't parse MokListXRT signatures: %d\n", rc);
		kfree(mokx);
	}

	return rc;
}
late_initcall(load_uefi_certs);
