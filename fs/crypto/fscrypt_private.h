/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fscrypt_private.h
 *
 * Copyright (C) 2015, Google, Inc.
 *
 * Originally written by Michael Halcrow, Ildar Muslukhov, and Uday Savagaonkar.
 * Heavily modified since then.
 */

#ifndef _FSCRYPT_PRIVATE_H
#define _FSCRYPT_PRIVATE_H

#include <linux/fscrypt.h>
#include <linux/siphash.h>
#include <crypto/hash.h>
#include <linux/blk-crypto.h>

#define CONST_STRLEN(str)	(sizeof(str) - 1)

#define FSCRYPT_FILE_NONCE_SIZE	16

/*
 * Minimum size of an fscrypt master key.  Note: a longer key will be required
 * if ciphers with a 256-bit security strength are used.  This is just the
 * absolute minimum, which applies when only 128-bit encryption is used.
 */
#define FSCRYPT_MIN_KEY_SIZE	16

#define FSCRYPT_CONTEXT_V1	1
#define FSCRYPT_CONTEXT_V2	2

/* Keep this in sync with include/uapi/linux/fscrypt.h */
#define FSCRYPT_MODE_MAX	FSCRYPT_MODE_ADIANTUM

struct fscrypt_context_v1 {
	u8 version; /* FSCRYPT_CONTEXT_V1 */
	u8 contents_encryption_mode;
	u8 filenames_encryption_mode;
	u8 flags;
	u8 master_key_descriptor[FSCRYPT_KEY_DESCRIPTOR_SIZE];
	u8 nonce[FSCRYPT_FILE_NONCE_SIZE];
};

struct fscrypt_context_v2 {
	u8 version; /* FSCRYPT_CONTEXT_V2 */
	u8 contents_encryption_mode;
	u8 filenames_encryption_mode;
	u8 flags;
	u8 __reserved[4];
	u8 master_key_identifier[FSCRYPT_KEY_IDENTIFIER_SIZE];
	u8 nonce[FSCRYPT_FILE_NONCE_SIZE];
};

/*
 * fscrypt_context - the encryption context of an inode
 *
 * This is the on-disk equivalent of an fscrypt_policy, stored alongside each
 * encrypted file usually in a hidden extended attribute.  It contains the
 * fields from the fscrypt_policy, in order to identify the encryption algorithm
 * and key with which the file is encrypted.  It also contains a nonce that was
 * randomly generated by fscrypt itself; this is used as KDF input or as a tweak
 * to cause different files to be encrypted differently.
 */
union fscrypt_context {
	u8 version;
	struct fscrypt_context_v1 v1;
	struct fscrypt_context_v2 v2;
};

/*
 * Return the size expected for the given fscrypt_context based on its version
 * number, or 0 if the context version is unrecognized.
 */
static inline int fscrypt_context_size(const union fscrypt_context *ctx)
{
	switch (ctx->version) {
	case FSCRYPT_CONTEXT_V1:
		BUILD_BUG_ON(sizeof(ctx->v1) != 28);
		return sizeof(ctx->v1);
	case FSCRYPT_CONTEXT_V2:
		BUILD_BUG_ON(sizeof(ctx->v2) != 40);
		return sizeof(ctx->v2);
	}
	return 0;
}

/* Check whether an fscrypt_context has a recognized version number and size */
static inline bool fscrypt_context_is_valid(const union fscrypt_context *ctx,
					    int ctx_size)
{
	return ctx_size >= 1 && ctx_size == fscrypt_context_size(ctx);
}

/* Retrieve the context's nonce, assuming the context was already validated */
static inline const u8 *fscrypt_context_nonce(const union fscrypt_context *ctx)
{
	switch (ctx->version) {
	case FSCRYPT_CONTEXT_V1:
		return ctx->v1.nonce;
	case FSCRYPT_CONTEXT_V2:
		return ctx->v2.nonce;
	}
	WARN_ON(1);
	return NULL;
}

union fscrypt_policy {
	u8 version;
	struct fscrypt_policy_v1 v1;
	struct fscrypt_policy_v2 v2;
};

/*
 * Return the size expected for the given fscrypt_policy based on its version
 * number, or 0 if the policy version is unrecognized.
 */
static inline int fscrypt_policy_size(const union fscrypt_policy *policy)
{
	switch (policy->version) {
	case FSCRYPT_POLICY_V1:
		return sizeof(policy->v1);
	case FSCRYPT_POLICY_V2:
		return sizeof(policy->v2);
	}
	return 0;
}

/* Return the contents encryption mode of a valid encryption policy */
static inline u8
fscrypt_policy_contents_mode(const union fscrypt_policy *policy)
{
	switch (policy->version) {
	case FSCRYPT_POLICY_V1:
		return policy->v1.contents_encryption_mode;
	case FSCRYPT_POLICY_V2:
		return policy->v2.contents_encryption_mode;
	}
	BUG();
}

/* Return the filenames encryption mode of a valid encryption policy */
static inline u8
fscrypt_policy_fnames_mode(const union fscrypt_policy *policy)
{
	switch (policy->version) {
	case FSCRYPT_POLICY_V1:
		return policy->v1.filenames_encryption_mode;
	case FSCRYPT_POLICY_V2:
		return policy->v2.filenames_encryption_mode;
	}
	BUG();
}

/* Return the flags (FSCRYPT_POLICY_FLAG*) of a valid encryption policy */
static inline u8
fscrypt_policy_flags(const union fscrypt_policy *policy)
{
	switch (policy->version) {
	case FSCRYPT_POLICY_V1:
		return policy->v1.flags;
	case FSCRYPT_POLICY_V2:
		return policy->v2.flags;
	}
	BUG();
}

/*
 * For encrypted symlinks, the ciphertext length is stored at the beginning
 * of the string in little-endian format.
 */
struct fscrypt_symlink_data {
	__le16 len;
	char encrypted_path[1];
} __packed;

/**
 * struct fscrypt_prepared_key - a key prepared for actual encryption/decryption
 * @tfm: crypto API transform object
 * @blk_key: key for blk-crypto
 *
 * Normally only one of the fields will be non-NULL.
 */
struct fscrypt_prepared_key {
	struct crypto_skcipher *tfm;
#ifdef CONFIG_FS_ENCRYPTION_INLINE_CRYPT
	struct fscrypt_blk_crypto_key *blk_key;
#endif
};

/*
 * fscrypt_info - the "encryption key" for an inode
 *
 * When an encrypted file's key is made available, an instance of this struct is
 * allocated and stored in ->i_crypt_info.  Once created, it remains until the
 * inode is evicted.
 */
struct fscrypt_info {

	/* The key in a form prepared for actual encryption/decryption */
	struct fscrypt_prepared_key ci_enc_key;

	/* True if ci_enc_key should be freed when this fscrypt_info is freed */
	bool ci_owns_key;

#ifdef CONFIG_FS_ENCRYPTION_INLINE_CRYPT
	/*
	 * True if this inode will use inline encryption (blk-crypto) instead of
	 * the traditional filesystem-layer encryption.
	 */
	bool ci_inlinecrypt;
#endif

	/*
	 * Encryption mode used for this inode.  It corresponds to either the
	 * contents or filenames encryption mode, depending on the inode type.
	 */
	struct fscrypt_mode *ci_mode;

	/* Back-pointer to the inode */
	struct inode *ci_inode;

	/*
	 * The master key with which this inode was unlocked (decrypted).  This
	 * will be NULL if the master key was found in a process-subscribed
	 * keyring rather than in the filesystem-level keyring.
	 */
	struct key *ci_master_key;

	/*
	 * Link in list of inodes that were unlocked with the master key.
	 * Only used when ->ci_master_key is set.
	 */
	struct list_head ci_master_key_link;

	/*
	 * If non-NULL, then encryption is done using the master key directly
	 * and ci_enc_key will equal ci_direct_key->dk_key.
	 */
	struct fscrypt_direct_key *ci_direct_key;

	/*
	 * This inode's hash key for filenames.  This is a 128-bit SipHash-2-4
	 * key.  This is only set for directories that use a keyed dirhash over
	 * the plaintext filenames -- currently just casefolded directories.
	 */
	siphash_key_t ci_dirhash_key;
	bool ci_dirhash_key_initialized;

	/* The encryption policy used by this inode */
	union fscrypt_policy ci_policy;

	/* This inode's nonce, copied from the fscrypt_context */
	u8 ci_nonce[FSCRYPT_FILE_NONCE_SIZE];

	/* Hashed inode number.  Only set for IV_INO_LBLK_32 */
	u32 ci_hashed_ino;
};

typedef enum {
	FS_DECRYPT = 0,
	FS_ENCRYPT,
} fscrypt_direction_t;

/* crypto.c */
extern struct kmem_cache *fscrypt_info_cachep;
int fscrypt_initialize(unsigned int cop_flags);
int fscrypt_crypt_block(const struct inode *inode, fscrypt_direction_t rw,
			u64 lblk_num, struct page *src_page,
			struct page *dest_page, unsigned int len,
			unsigned int offs, gfp_t gfp_flags);
struct page *fscrypt_alloc_bounce_page(gfp_t gfp_flags);

void __printf(3, 4) __cold
fscrypt_msg(const struct inode *inode, const char *level, const char *fmt, ...);

#define fscrypt_warn(inode, fmt, ...)		\
	fscrypt_msg((inode), KERN_WARNING, fmt, ##__VA_ARGS__)
#define fscrypt_err(inode, fmt, ...)		\
	fscrypt_msg((inode), KERN_ERR, fmt, ##__VA_ARGS__)

#define FSCRYPT_MAX_IV_SIZE	32

union fscrypt_iv {
	struct {
		/* logical block number within the file */
		__le64 lblk_num;

		/* per-file nonce; only set in DIRECT_KEY mode */
		u8 nonce[FSCRYPT_FILE_NONCE_SIZE];
	};
	u8 raw[FSCRYPT_MAX_IV_SIZE];
	__le64 dun[FSCRYPT_MAX_IV_SIZE / sizeof(__le64)];
};

void fscrypt_generate_iv(union fscrypt_iv *iv, u64 lblk_num,
			 const struct fscrypt_info *ci);

/* fname.c */
int fscrypt_fname_encrypt(const struct inode *inode, const struct qstr *iname,
			  u8 *out, unsigned int olen);
bool fscrypt_fname_encrypted_size(const union fscrypt_policy *policy,
				  u32 orig_len, u32 max_len,
				  u32 *encrypted_len_ret);

/* hkdf.c */

struct fscrypt_hkdf {
	struct crypto_shash *hmac_tfm;
};

int fscrypt_init_hkdf(struct fscrypt_hkdf *hkdf, const u8 *master_key,
		      unsigned int master_key_size);

/*
 * The list of contexts in which fscrypt uses HKDF.  These values are used as
 * the first byte of the HKDF application-specific info string to guarantee that
 * info strings are never repeated between contexts.  This ensures that all HKDF
 * outputs are unique and cryptographically isolated, i.e. knowledge of one
 * output doesn't reveal another.
 */
#define HKDF_CONTEXT_KEY_IDENTIFIER	1 /* info=<empty>		*/
#define HKDF_CONTEXT_PER_FILE_ENC_KEY	2 /* info=file_nonce		*/
#define HKDF_CONTEXT_DIRECT_KEY		3 /* info=mode_num		*/
#define HKDF_CONTEXT_IV_INO_LBLK_64_KEY	4 /* info=mode_num||fs_uuid	*/
#define HKDF_CONTEXT_DIRHASH_KEY	5 /* info=file_nonce		*/
#define HKDF_CONTEXT_IV_INO_LBLK_32_KEY	6 /* info=mode_num||fs_uuid	*/
#define HKDF_CONTEXT_INODE_HASH_KEY	7 /* info=<empty>		*/

int fscrypt_hkdf_expand(const struct fscrypt_hkdf *hkdf, u8 context,
			const u8 *info, unsigned int infolen,
			u8 *okm, unsigned int okmlen);

void fscrypt_destroy_hkdf(struct fscrypt_hkdf *hkdf);

/* inline_crypt.c */
#ifdef CONFIG_FS_ENCRYPTION_INLINE_CRYPT
int fscrypt_select_encryption_impl(struct fscrypt_info *ci);

static inline bool
fscrypt_using_inline_encryption(const struct fscrypt_info *ci)
{
	return ci->ci_inlinecrypt;
}

int fscrypt_prepare_inline_crypt_key(struct fscrypt_prepared_key *prep_key,
				     const u8 *raw_key,
				     const struct fscrypt_info *ci);

void fscrypt_destroy_inline_crypt_key(struct fscrypt_prepared_key *prep_key);

/*
 * Check whether the crypto transform or blk-crypto key has been allocated in
 * @prep_key, depending on which encryption implementation the file will use.
 */
static inline bool
fscrypt_is_key_prepared(struct fscrypt_prepared_key *prep_key,
			const struct fscrypt_info *ci)
{
	/*
	 * The two smp_load_acquire()'s here pair with the smp_store_release()'s
	 * in fscrypt_prepare_inline_crypt_key() and fscrypt_prepare_key().
	 * I.e., in some cases (namely, if this prep_key is a per-mode
	 * encryption key) another task can publish blk_key or tfm concurrently,
	 * executing a RELEASE barrier.  We need to use smp_load_acquire() here
	 * to safely ACQUIRE the memory the other task published.
	 */
	if (fscrypt_using_inline_encryption(ci))
		return smp_load_acquire(&prep_key->blk_key) != NULL;
	return smp_load_acquire(&prep_key->tfm) != NULL;
}

#else /* CONFIG_FS_ENCRYPTION_INLINE_CRYPT */

static inline int fscrypt_select_encryption_impl(struct fscrypt_info *ci)
{
	return 0;
}

static inline bool
fscrypt_using_inline_encryption(const struct fscrypt_info *ci)
{
	return false;
}

static inline int
fscrypt_prepare_inline_crypt_key(struct fscrypt_prepared_key *prep_key,
				 const u8 *raw_key,
				 const struct fscrypt_info *ci)
{
	WARN_ON(1);
	return -EOPNOTSUPP;
}

static inline void
fscrypt_destroy_inline_crypt_key(struct fscrypt_prepared_key *prep_key)
{
}

static inline bool
fscrypt_is_key_prepared(struct fscrypt_prepared_key *prep_key,
			const struct fscrypt_info *ci)
{
	return smp_load_acquire(&prep_key->tfm) != NULL;
}
#endif /* !CONFIG_FS_ENCRYPTION_INLINE_CRYPT */

/* keyring.c */

/*
 * fscrypt_master_key_secret - secret key material of an in-use master key
 */
struct fscrypt_master_key_secret {

	/*
	 * For v2 policy keys: HKDF context keyed by this master key.
	 * For v1 policy keys: not set (hkdf.hmac_tfm == NULL).
	 */
	struct fscrypt_hkdf	hkdf;

	/*
	 * Size of the raw key in bytes.  This remains set even if ->raw was
	 * zeroized due to no longer being needed.  I.e. we still remember the
	 * size of the key even if we don't need to remember the key itself.
	 */
	u32			size;

	/* For v1 policy keys: the raw key.  Wiped for v2 policy keys. */
	u8			raw[FSCRYPT_MAX_KEY_SIZE];

} __randomize_layout;

/*
 * fscrypt_master_key - an in-use master key
 *
 * This represents a master encryption key which has been added to the
 * filesystem and can be used to "unlock" the encrypted files which were
 * encrypted with it.
 */
struct fscrypt_master_key {

	/*
	 * The secret key material.  After FS_IOC_REMOVE_ENCRYPTION_KEY is
	 * executed, this is wiped and no new inodes can be unlocked with this
	 * key; however, there may still be inodes in ->mk_decrypted_inodes
	 * which could not be evicted.  As long as some inodes still remain,
	 * FS_IOC_REMOVE_ENCRYPTION_KEY can be retried, or
	 * FS_IOC_ADD_ENCRYPTION_KEY can add the secret again.
	 *
	 * Locking: protected by this master key's key->sem.
	 */
	struct fscrypt_master_key_secret	mk_secret;

	/*
	 * For v1 policy keys: an arbitrary key descriptor which was assigned by
	 * userspace (->descriptor).
	 *
	 * For v2 policy keys: a cryptographic hash of this key (->identifier).
	 */
	struct fscrypt_key_specifier		mk_spec;

	/*
	 * Keyring which contains a key of type 'key_type_fscrypt_user' for each
	 * user who has added this key.  Normally each key will be added by just
	 * one user, but it's possible that multiple users share a key, and in
	 * that case we need to keep track of those users so that one user can't
	 * remove the key before the others want it removed too.
	 *
	 * This is NULL for v1 policy keys; those can only be added by root.
	 *
	 * Locking: in addition to this keyring's own semaphore, this is
	 * protected by this master key's key->sem, so we can do atomic
	 * search+insert.  It can also be searched without taking any locks, but
	 * in that case the returned key may have already been removed.
	 */
	struct key		*mk_users;

	/*
	 * Length of ->mk_decrypted_inodes, plus one if mk_secret is present.
	 * Once this goes to 0, the master key is removed from ->s_master_keys.
	 * The 'struct fscrypt_master_key' will continue to live as long as the
	 * 'struct key' whose payload it is, but we won't let this reference
	 * count rise again.
	 */
	refcount_t		mk_refcount;

	/*
	 * List of inodes that were unlocked using this key.  This allows the
	 * inodes to be evicted efficiently if the key is removed.
	 */
	struct list_head	mk_decrypted_inodes;
	spinlock_t		mk_decrypted_inodes_lock;

	/*
	 * Per-mode encryption keys for the various types of encryption policies
	 * that use them.  Allocated and derived on-demand.
	 */
	struct fscrypt_prepared_key mk_direct_keys[FSCRYPT_MODE_MAX + 1];
	struct fscrypt_prepared_key mk_iv_ino_lblk_64_keys[FSCRYPT_MODE_MAX + 1];
	struct fscrypt_prepared_key mk_iv_ino_lblk_32_keys[FSCRYPT_MODE_MAX + 1];

	/* Hash key for inode numbers.  Initialized only when needed. */
	siphash_key_t		mk_ino_hash_key;
	bool			mk_ino_hash_key_initialized;

} __randomize_layout;

static inline bool
is_master_key_secret_present(const struct fscrypt_master_key_secret *secret)
{
	/*
	 * The READ_ONCE() is only necessary for fscrypt_drop_inode() and
	 * fscrypt_key_describe().  These run in atomic context, so they can't
	 * take the key semaphore and thus 'secret' can change concurrently
	 * which would be a data race.  But they only need to know whether the
	 * secret *was* present at the time of check, so READ_ONCE() suffices.
	 */
	return READ_ONCE(secret->size) != 0;
}

static inline const char *master_key_spec_type(
				const struct fscrypt_key_specifier *spec)
{
	switch (spec->type) {
	case FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR:
		return "descriptor";
	case FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER:
		return "identifier";
	}
	return "[unknown]";
}

static inline int master_key_spec_len(const struct fscrypt_key_specifier *spec)
{
	switch (spec->type) {
	case FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR:
		return FSCRYPT_KEY_DESCRIPTOR_SIZE;
	case FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER:
		return FSCRYPT_KEY_IDENTIFIER_SIZE;
	}
	return 0;
}

struct key *
fscrypt_find_master_key(struct super_block *sb,
			const struct fscrypt_key_specifier *mk_spec);

int fscrypt_add_test_dummy_key(struct super_block *sb,
			       struct fscrypt_key_specifier *key_spec);

int fscrypt_verify_key_added(struct super_block *sb,
			     const u8 identifier[FSCRYPT_KEY_IDENTIFIER_SIZE]);

int __init fscrypt_init_keyring(void);

/* keysetup.c */

struct fscrypt_mode {
	const char *friendly_name;
	const char *cipher_str;
	int keysize;		/* key size in bytes */
	int security_strength;	/* security strength in bytes */
	int ivsize;		/* IV size in bytes */
	int logged_impl_name;
	enum blk_crypto_mode_num blk_crypto_mode;
};

extern struct fscrypt_mode fscrypt_modes[];

int fscrypt_prepare_key(struct fscrypt_prepared_key *prep_key,
			const u8 *raw_key, const struct fscrypt_info *ci);

void fscrypt_destroy_prepared_key(struct fscrypt_prepared_key *prep_key);

int fscrypt_set_per_file_enc_key(struct fscrypt_info *ci, const u8 *raw_key);

int fscrypt_derive_dirhash_key(struct fscrypt_info *ci,
			       const struct fscrypt_master_key *mk);

void fscrypt_hash_inode_number(struct fscrypt_info *ci,
			       const struct fscrypt_master_key *mk);

int fscrypt_get_encryption_info(struct inode *inode, bool allow_unsupported);

/**
 * fscrypt_require_key() - require an inode's encryption key
 * @inode: the inode we need the key for
 *
 * If the inode is encrypted, set up its encryption key if not already done.
 * Then require that the key be present and return -ENOKEY otherwise.
 *
 * No locks are needed, and the key will live as long as the struct inode --- so
 * it won't go away from under you.
 *
 * Return: 0 on success, -ENOKEY if the key is missing, or another -errno code
 * if a problem occurred while setting up the encryption key.
 */
static inline int fscrypt_require_key(struct inode *inode)
{
	if (IS_ENCRYPTED(inode)) {
		int err = fscrypt_get_encryption_info(inode, false);

		if (err)
			return err;
		if (!fscrypt_has_encryption_key(inode))
			return -ENOKEY;
	}
	return 0;
}

/* keysetup_v1.c */

void fscrypt_put_direct_key(struct fscrypt_direct_key *dk);

int fscrypt_setup_v1_file_key(struct fscrypt_info *ci,
			      const u8 *raw_master_key);

int fscrypt_setup_v1_file_key_via_subscribed_keyrings(struct fscrypt_info *ci);

/* policy.c */

bool fscrypt_policies_equal(const union fscrypt_policy *policy1,
			    const union fscrypt_policy *policy2);
bool fscrypt_supported_policy(const union fscrypt_policy *policy_u,
			      const struct inode *inode);
int fscrypt_policy_from_context(union fscrypt_policy *policy_u,
				const union fscrypt_context *ctx_u,
				int ctx_size);
const union fscrypt_policy *fscrypt_policy_to_inherit(struct inode *dir);

#endif /* _FSCRYPT_PRIVATE_H */
