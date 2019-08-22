/* Large capacity key type
 *
 * Copyright (C) 2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright (C) 2013 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define pr_fmt(fmt) "big_key: "fmt
#include <linux/init.h>
#include <linux/seq_file.h>
#include <linux/file.h>
#include <linux/shmem_fs.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <linux/random.h>
#include <keys/user-type.h>
#include <keys/big_key-type.h>
#include <crypto/aead.h>

/*
 * Layout of key payload words.
 */
enum {
	big_key_data,
	big_key_path,
	big_key_path_2nd_part,
	big_key_len,
};

/*
 * Crypto operation with big_key data
 */
enum big_key_op {
	BIG_KEY_ENC,
	BIG_KEY_DEC,
};

/*
 * If the data is under this limit, there's no point creating a shm file to
 * hold it as the permanently resident metadata for the shmem fs will be at
 * least as large as the data.
 */
#define BIG_KEY_FILE_THRESHOLD (sizeof(struct inode) + sizeof(struct dentry))

/*
 * Key size for big_key data encryption
 */
#define ENC_KEY_SIZE 32

/*
 * Authentication tag length
 */
#define ENC_AUTHTAG_SIZE 16

/*
 * big_key defined keys take an arbitrary string as the description and an
 * arbitrary blob of data as the payload
 */
struct key_type key_type_big_key = {
	.name			= "big_key",
	.preparse		= big_key_preparse,
	.free_preparse		= big_key_free_preparse,
	.instantiate		= generic_key_instantiate,
	.revoke			= big_key_revoke,
	.destroy		= big_key_destroy,
	.describe		= big_key_describe,
	.read			= big_key_read,
	/* no ->update(); don't add it without changing big_key_crypt() nonce */
};

/*
 * Crypto names for big_key data authenticated encryption
 */
static const char big_key_alg_name[] = "gcm(aes)";

/*
 * Crypto algorithms for big_key data authenticated encryption
 */
static struct crypto_aead *big_key_aead;

/*
 * Since changing the key affects the entire object, we need a mutex.
 */
static DEFINE_MUTEX(big_key_aead_lock);

/*
 * Encrypt/decrypt big_key data
 */
static int big_key_crypt(enum big_key_op op, u8 *data, size_t datalen, u8 *key)
{
	int ret;
	struct scatterlist sgio;
	struct aead_request *aead_req;
	/* We always use a zero nonce. The reason we can get away with this is
	 * because we're using a different randomly generated key for every
	 * different encryption. Notably, too, key_type_big_key doesn't define
	 * an .update function, so there's no chance we'll wind up reusing the
	 * key to encrypt updated data. Simply put: one key, one encryption.
	 */
	u8 zero_nonce[crypto_aead_ivsize(big_key_aead)];

	aead_req = aead_request_alloc(big_key_aead, GFP_KERNEL);
	if (!aead_req)
		return -ENOMEM;

	memset(zero_nonce, 0, sizeof(zero_nonce));
	sg_init_one(&sgio, data, datalen + (op == BIG_KEY_ENC ? ENC_AUTHTAG_SIZE : 0));
	aead_request_set_crypt(aead_req, &sgio, &sgio, datalen, zero_nonce);
	aead_request_set_callback(aead_req, CRYPTO_TFM_REQ_MAY_SLEEP, NULL, NULL);
	aead_request_set_ad(aead_req, 0);

	mutex_lock(&big_key_aead_lock);
	if (crypto_aead_setkey(big_key_aead, key, ENC_KEY_SIZE)) {
		ret = -EAGAIN;
		goto error;
	}
	if (op == BIG_KEY_ENC)
		ret = crypto_aead_encrypt(aead_req);
	else
		ret = crypto_aead_decrypt(aead_req);
error:
	mutex_unlock(&big_key_aead_lock);
	aead_request_free(aead_req);
	return ret;
}

/*
 * Preparse a big key
 */
int big_key_preparse(struct key_preparsed_payload *prep)
{
	struct path *path = (struct path *)&prep->payload.data[big_key_path];
	struct file *file;
	u8 *enckey;
	u8 *data = NULL;
	ssize_t written;
	size_t datalen = prep->datalen;
	int ret;

	ret = -EINVAL;
	if (datalen <= 0 || datalen > 1024 * 1024 || !prep->data)
		goto error;

	/* Set an arbitrary quota */
	prep->quotalen = 16;

	prep->payload.data[big_key_len] = (void *)(unsigned long)datalen;

	if (datalen > BIG_KEY_FILE_THRESHOLD) {
		/* Create a shmem file to store the data in.  This will permit the data
		 * to be swapped out if needed.
		 *
		 * File content is stored encrypted with randomly generated key.
		 */
		size_t enclen = datalen + ENC_AUTHTAG_SIZE;

		data = kmalloc(enclen, GFP_KERNEL);
		if (!data)
			return -ENOMEM;

		memcpy(data, prep->data, datalen);

		/* generate random key */
		enckey = kmalloc(ENC_KEY_SIZE, GFP_KERNEL);
		if (!enckey) {
			ret = -ENOMEM;
			goto error;
		}
		get_random_bytes(enckey, ENC_KEY_SIZE);

		/* encrypt aligned data */
		ret = big_key_crypt(BIG_KEY_ENC, data, datalen, enckey);
		if (ret)
			goto err_enckey;

		/* save aligned data to file */
		file = shmem_kernel_file_setup("", enclen, 0);
		if (IS_ERR(file)) {
			ret = PTR_ERR(file);
			goto err_enckey;
		}

		written = kernel_write(file, data, enclen, 0);
		if (written != enclen) {
			ret = written;
			if (written >= 0)
				ret = -ENOMEM;
			goto err_fput;
		}

		/* Pin the mount and dentry to the key so that we can open it again
		 * later
		 */
		prep->payload.data[big_key_data] = enckey;
		*path = file->f_path;
		path_get(path);
		fput(file);
		kzfree(data);
	} else {
		/* Just store the data in a buffer */
		void *data = kmalloc(datalen, GFP_KERNEL);

		if (!data)
			return -ENOMEM;

		prep->payload.data[big_key_data] = data;
		memcpy(data, prep->data, prep->datalen);
	}
	return 0;

err_fput:
	fput(file);
err_enckey:
	kzfree(enckey);
error:
	kzfree(data);
	return ret;
}

/*
 * Clear preparsement.
 */
void big_key_free_preparse(struct key_preparsed_payload *prep)
{
	if (prep->datalen > BIG_KEY_FILE_THRESHOLD) {
		struct path *path = (struct path *)&prep->payload.data[big_key_path];

		path_put(path);
	}
	kzfree(prep->payload.data[big_key_data]);
}

/*
 * dispose of the links from a revoked keyring
 * - called with the key sem write-locked
 */
void big_key_revoke(struct key *key)
{
	struct path *path = (struct path *)&key->payload.data[big_key_path];

	/* clear the quota */
	key_payload_reserve(key, 0);
	if (key_is_positive(key) &&
	    (size_t)key->payload.data[big_key_len] > BIG_KEY_FILE_THRESHOLD)
		vfs_truncate(path, 0);
}

/*
 * dispose of the data dangling from the corpse of a big_key key
 */
void big_key_destroy(struct key *key)
{
	size_t datalen = (size_t)key->payload.data[big_key_len];

	if (datalen > BIG_KEY_FILE_THRESHOLD) {
		struct path *path = (struct path *)&key->payload.data[big_key_path];

		path_put(path);
		path->mnt = NULL;
		path->dentry = NULL;
	}
	kzfree(key->payload.data[big_key_data]);
	key->payload.data[big_key_data] = NULL;
}

/*
 * describe the big_key key
 */
void big_key_describe(const struct key *key, struct seq_file *m)
{
	size_t datalen = (size_t)key->payload.data[big_key_len];

	seq_puts(m, key->description);

	if (key_is_positive(key))
		seq_printf(m, ": %zu [%s]",
			   datalen,
			   datalen > BIG_KEY_FILE_THRESHOLD ? "file" : "buff");
}

/*
 * read the key data
 * - the key's semaphore is read-locked
 */
long big_key_read(const struct key *key, char __user *buffer, size_t buflen)
{
	size_t datalen = (size_t)key->payload.data[big_key_len];
	long ret;

	if (!buffer || buflen < datalen)
		return datalen;

	if (datalen > BIG_KEY_FILE_THRESHOLD) {
		struct path *path = (struct path *)&key->payload.data[big_key_path];
		struct file *file;
		u8 *data;
		u8 *enckey = (u8 *)key->payload.data[big_key_data];
		size_t enclen = datalen + ENC_AUTHTAG_SIZE;

		data = kmalloc(enclen, GFP_KERNEL);
		if (!data)
			return -ENOMEM;

		file = dentry_open(path, O_RDONLY, current_cred());
		if (IS_ERR(file)) {
			ret = PTR_ERR(file);
			goto error;
		}

		/* read file to kernel and decrypt */
		ret = kernel_read(file, 0, data, enclen);
		if (ret >= 0 && ret != enclen) {
			ret = -EIO;
			goto err_fput;
		}

		ret = big_key_crypt(BIG_KEY_DEC, data, enclen, enckey);
		if (ret)
			goto err_fput;

		ret = datalen;

		/* copy decrypted data to user */
		if (copy_to_user(buffer, data, datalen) != 0)
			ret = -EFAULT;

err_fput:
		fput(file);
error:
		kzfree(data);
	} else {
		ret = datalen;
		if (copy_to_user(buffer, key->payload.data[big_key_data],
				 datalen) != 0)
			ret = -EFAULT;
	}

	return ret;
}

/*
 * Register key type
 */
static int __init big_key_init(void)
{
	int ret;

	/* init block cipher */
	big_key_aead = crypto_alloc_aead(big_key_alg_name, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(big_key_aead)) {
		ret = PTR_ERR(big_key_aead);
		pr_err("Can't alloc crypto: %d\n", ret);
		return ret;
	}
	ret = crypto_aead_setauthsize(big_key_aead, ENC_AUTHTAG_SIZE);
	if (ret < 0) {
		pr_err("Can't set crypto auth tag len: %d\n", ret);
		goto free_aead;
	}

	ret = register_key_type(&key_type_big_key);
	if (ret < 0) {
		pr_err("Can't register type: %d\n", ret);
		goto free_aead;
	}

	return 0;

free_aead:
	crypto_free_aead(big_key_aead);
	return ret;
}

late_initcall(big_key_init);
