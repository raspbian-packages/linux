// SPDX-License-Identifier: GPL-2.0-or-later
/* Instantiate a public key crypto key from an X.509 Certificate
 *
 * Copyright (C) 2012, 2016 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) "ASYM: "fmt
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <crypto/public_key.h>
#include "asymmetric_keys.h"

static bool use_builtin_keys;
static struct asymmetric_key_id *ca_keyid;

#ifndef MODULE
static struct {
	struct asymmetric_key_id id;
	unsigned char data[10];
} cakey;

static int __init ca_keys_setup(char *str)
{
	if (!str)		/* default system keyring */
		return 1;

	if (strncmp(str, "id:", 3) == 0) {
		struct asymmetric_key_id *p = &cakey.id;
		size_t hexlen = (strlen(str) - 3) / 2;
		int ret;

		if (hexlen == 0 || hexlen > sizeof(cakey.data)) {
			pr_err("Missing or invalid ca_keys id\n");
			return 1;
		}

		ret = __asymmetric_key_hex_to_key_id(str + 3, p, hexlen);
		if (ret < 0)
			pr_err("Unparsable ca_keys id hex string\n");
		else
			ca_keyid = p;	/* owner key 'id:xxxxxx' */
	} else if (strcmp(str, "builtin") == 0) {
		use_builtin_keys = true;
	}

	return 1;
}
__setup("ca_keys=", ca_keys_setup);
#endif

/**
 * restrict_link_by_signature - Restrict additions to a ring of public keys
 * @dest_keyring: Keyring being linked to.
 * @type: The type of key being added.
 * @payload: The payload of the new key.
 * @trust_keyring: A ring of keys that can be used to vouch for the new cert.
 *
 * Check the new certificate against the ones in the trust keyring.  If one of
 * those is the signing key and validates the new certificate, then mark the
 * new certificate as being trusted.
 *
 * Returns 0 if the new certificate was accepted, -ENOKEY if we couldn't find a
 * matching parent certificate in the trusted list, -EKEYREJECTED if the
 * signature check fails or the key is blacklisted, -ENOPKG if the signature
 * uses unsupported crypto, or some other error if there is a matching
 * certificate but the signature check cannot be performed.
 */
int restrict_link_by_signature(struct key *dest_keyring,
			       const struct key_type *type,
			       const union key_payload *payload,
			       struct key *trust_keyring)
{
	const struct public_key_signature *sig;
	struct key *key;
	int ret;

	pr_devel("==>%s()\n", __func__);

	if (!trust_keyring)
		return -ENOKEY;

	if (type != &key_type_asymmetric)
		return -EOPNOTSUPP;

	sig = payload->data[asym_auth];
	if (!sig)
		return -ENOPKG;
	if (!sig->auth_ids[0] && !sig->auth_ids[1] && !sig->auth_ids[2])
		return -ENOKEY;

	if (ca_keyid && !asymmetric_key_id_partial(sig->auth_ids[1], ca_keyid))
		return -EPERM;

	/* See if we have a key that signed this one. */
	key = find_asymmetric_key(trust_keyring,
				  sig->auth_ids[0], sig->auth_ids[1],
				  sig->auth_ids[2], false);
	if (IS_ERR(key))
		return -ENOKEY;

	if (use_builtin_keys && !test_bit(KEY_FLAG_BUILTIN, &key->flags))
		ret = -ENOKEY;
	else
		ret = verify_signature(key, sig);
	key_put(key);
	return ret;
}

/**
 * restrict_link_by_ca - Restrict additions to a ring of CA keys
 * @dest_keyring: Keyring being linked to.
 * @type: The type of key being added.
 * @payload: The payload of the new key.
 * @trust_keyring: Unused.
 *
 * Check if the new certificate is a CA. If it is a CA, then mark the new
 * certificate as being ok to link.
 *
 * Returns 0 if the new certificate was accepted, -ENOKEY if the
 * certificate is not a CA. -ENOPKG if the signature uses unsupported
 * crypto, or some other error if there is a matching certificate but
 * the signature check cannot be performed.
 */
int restrict_link_by_ca(struct key *dest_keyring,
			const struct key_type *type,
			const union key_payload *payload,
			struct key *trust_keyring)
{
	const struct public_key *pkey;

	if (type != &key_type_asymmetric)
		return -EOPNOTSUPP;

	pkey = payload->data[asym_crypto];
	if (!pkey)
		return -ENOPKG;
	if (!test_bit(KEY_EFLAG_CA, &pkey->key_eflags))
		return -ENOKEY;
	if (!test_bit(KEY_EFLAG_KEYCERTSIGN, &pkey->key_eflags))
		return -ENOKEY;
	if (!IS_ENABLED(CONFIG_INTEGRITY_CA_MACHINE_KEYRING_MAX))
		return 0;
	if (test_bit(KEY_EFLAG_DIGITALSIG, &pkey->key_eflags))
		return -ENOKEY;

	return 0;
}

static bool match_either_id(const struct asymmetric_key_id **pair,
			    const struct asymmetric_key_id *single)
{
	return (asymmetric_key_id_same(pair[0], single) ||
		asymmetric_key_id_same(pair[1], single));
}

static int key_or_keyring_common(struct key *dest_keyring,
				 const struct key_type *type,
				 const union key_payload *payload,
				 struct key *trusted, bool check_dest)
{
	const struct public_key_signature *sig;
	struct key *key = NULL;
	int ret;

	pr_devel("==>%s()\n", __func__);

	if (!dest_keyring)
		return -ENOKEY;
	else if (dest_keyring->type != &key_type_keyring)
		return -EOPNOTSUPP;

	if (!trusted && !check_dest)
		return -ENOKEY;

	if (type != &key_type_asymmetric)
		return -EOPNOTSUPP;

	sig = payload->data[asym_auth];
	if (!sig)
		return -ENOPKG;
	if (!sig->auth_ids[0] && !sig->auth_ids[1] && !sig->auth_ids[2])
		return -ENOKEY;

	if (trusted) {
		if (trusted->type == &key_type_keyring) {
			/* See if we have a key that signed this one. */
			key = find_asymmetric_key(trusted, sig->auth_ids[0],
						  sig->auth_ids[1],
						  sig->auth_ids[2], false);
			if (IS_ERR(key))
				key = NULL;
		} else if (trusted->type == &key_type_asymmetric) {
			const struct asymmetric_key_id **signer_ids;

			signer_ids = (const struct asymmetric_key_id **)
				asymmetric_key_ids(trusted)->id;

			/*
			 * The auth_ids come from the candidate key (the
			 * one that is being considered for addition to
			 * dest_keyring) and identify the key that was
			 * used to sign.
			 *
			 * The signer_ids are identifiers for the
			 * signing key specified for dest_keyring.
			 *
			 * The first auth_id is the preferred id, 2nd and
			 * 3rd are the fallbacks. If exactly one of
			 * auth_ids[0] and auth_ids[1] is present, it may
			 * match either signer_ids[0] or signed_ids[1].
			 * If both are present the first one may match
			 * either signed_id but the second one must match
			 * the second signer_id. If neither of them is
			 * available, auth_ids[2] is matched against
			 * signer_ids[2] as a fallback.
			 */
			if (!sig->auth_ids[0] && !sig->auth_ids[1]) {
				if (asymmetric_key_id_same(signer_ids[2],
							   sig->auth_ids[2]))
					key = __key_get(trusted);

			} else if (!sig->auth_ids[0] || !sig->auth_ids[1]) {
				const struct asymmetric_key_id *auth_id;

				auth_id = sig->auth_ids[0] ?: sig->auth_ids[1];
				if (match_either_id(signer_ids, auth_id))
					key = __key_get(trusted);

			} else if (asymmetric_key_id_same(signer_ids[1],
							  sig->auth_ids[1]) &&
				   match_either_id(signer_ids,
						   sig->auth_ids[0])) {
				key = __key_get(trusted);
			}
		} else {
			return -EOPNOTSUPP;
		}
	}

	if (check_dest && !key) {
		/* See if the destination has a key that signed this one. */
		key = find_asymmetric_key(dest_keyring, sig->auth_ids[0],
					  sig->auth_ids[1], sig->auth_ids[2],
					  false);
		if (IS_ERR(key))
			key = NULL;
	}

	if (!key)
		return -ENOKEY;

	ret = key_validate(key);
	if (ret == 0)
		ret = verify_signature(key, sig);

	key_put(key);
	return ret;
}

/**
 * restrict_link_by_key_or_keyring - Restrict additions to a ring of public
 * keys using the restrict_key information stored in the ring.
 * @dest_keyring: Keyring being linked to.
 * @type: The type of key being added.
 * @payload: The payload of the new key.
 * @trusted: A key or ring of keys that can be used to vouch for the new cert.
 *
 * Check the new certificate only against the key or keys passed in the data
 * parameter. If one of those is the signing key and validates the new
 * certificate, then mark the new certificate as being ok to link.
 *
 * Returns 0 if the new certificate was accepted, -ENOKEY if we
 * couldn't find a matching parent certificate in the trusted list,
 * -EKEYREJECTED if the signature check fails, -ENOPKG if the signature uses
 * unsupported crypto, or some other error if there is a matching certificate
 * but the signature check cannot be performed.
 */
int restrict_link_by_key_or_keyring(struct key *dest_keyring,
				    const struct key_type *type,
				    const union key_payload *payload,
				    struct key *trusted)
{
	return key_or_keyring_common(dest_keyring, type, payload, trusted,
				     false);
}

/**
 * restrict_link_by_key_or_keyring_chain - Restrict additions to a ring of
 * public keys using the restrict_key information stored in the ring.
 * @dest_keyring: Keyring being linked to.
 * @type: The type of key being added.
 * @payload: The payload of the new key.
 * @trusted: A key or ring of keys that can be used to vouch for the new cert.
 *
 * Check the new certificate against the key or keys passed in the data
 * parameter and against the keys already linked to the destination keyring. If
 * one of those is the signing key and validates the new certificate, then mark
 * the new certificate as being ok to link.
 *
 * Returns 0 if the new certificate was accepted, -ENOKEY if we
 * couldn't find a matching parent certificate in the trusted list,
 * -EKEYREJECTED if the signature check fails, -ENOPKG if the signature uses
 * unsupported crypto, or some other error if there is a matching certificate
 * but the signature check cannot be performed.
 */
int restrict_link_by_key_or_keyring_chain(struct key *dest_keyring,
					  const struct key_type *type,
					  const union key_payload *payload,
					  struct key *trusted)
{
	return key_or_keyring_common(dest_keyring, type, payload, trusted,
				     true);
}
