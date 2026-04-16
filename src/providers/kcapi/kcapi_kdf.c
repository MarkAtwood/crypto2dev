// SPDX-License-Identifier: GPL-2.0-only
/*
 * kcapi_kdf.c — crypto2dev kcapi provider: HKDF and PBKDF2
 *
 * Provides:
 *   HKDF-SHA256, HKDF-SHA384, HKDF-SHA512 (RFC 5869)
 *   PBKDF2-SHA256, PBKDF2-SHA384, PBKDF2-SHA512 (RFC 8018 §5.2)
 *
 * Uses the standard kernel HMAC shash API (crypto_alloc_shash,
 * crypto_shash_setkey, shash_desc) rather than <crypto/hkdf.h>, which is
 * an internal fscrypt header not exposed in out-of-tree kernel header
 * packages (e.g. linux-headers-*-aws on Ubuntu 22.04).
 *
 * The kernel crypto API has no native PBKDF2 implementation, so both HKDF
 * and PBKDF2 are built manually using the HMAC shash primitives.
 */

#define pr_fmt(fmt) "crypto2dev_kcapi: " fmt

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <crypto/hash.h>

#include "../../../include/uapi/crypto2dev_ioctl.h"
#include "../../../include/crypto2dev_provider.h"
#include "kcapi_provider.h"

/*
 * hkdf_extract_impl — RFC 5869 §2.2
 *
 * PRK = HMAC-Hash(salt, IKM)
 *
 * @tfm:      allocated HMAC shash (already alloc'd by caller)
 * @ikm:      input keying material
 * @ikm_len:  length of ikm
 * @salt:     optional salt (NULL → use HashLen zero bytes)
 * @salt_len: length of salt (0 when salt is NULL)
 * @prk:      output buffer, must be at least digestsize bytes
 *
 * On return, tfm is re-keyed to PRK so hkdf_expand_impl() can be called
 * next without re-allocating the transform.
 */
static int hkdf_extract_impl(struct crypto_shash *tfm,
			     const u8 *ikm, u32 ikm_len,
			     const u8 *salt, u32 salt_len,
			     u8 *prk)
{
	u32 digestsize = crypto_shash_digestsize(tfm);
	u8 *zero_salt = NULL;
	struct shash_desc *desc;
	int ret;

	/* RFC 5869 §2.2: if salt is not provided, set it to HashLen zeros. */
	if (!salt || salt_len == 0) {
		zero_salt = kzalloc(digestsize, GFP_KERNEL);
		if (!zero_salt)
			return -ENOMEM;
		salt     = zero_salt;
		salt_len = digestsize;
	}

	ret = crypto_shash_setkey(tfm, salt, salt_len);
	if (ret) {
		pr_err_ratelimited("hkdf_extract: setkey(salt) failed: %d\n",
				   ret);
		goto out_free_salt;
	}

	desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc) {
		ret = -ENOMEM;
		goto out_free_salt;
	}
	desc->tfm = tfm;

	ret = crypto_shash_digest(desc, ikm, ikm_len, prk);
	if (ret) {
		pr_err_ratelimited("hkdf_extract: digest(IKM) failed: %d\n",
				   ret);
		goto out_free_desc;
	}

	/*
	 * Re-key tfm with PRK so hkdf_expand_impl() can call
	 * crypto_shash_init/update/final without a separate setkey.
	 */
	ret = crypto_shash_setkey(tfm, prk, digestsize);
	if (ret)
		pr_err_ratelimited("hkdf_extract: setkey(PRK) failed: %d\n",
				   ret);

out_free_desc:
	kfree_sensitive(desc);
out_free_salt:
	kfree_sensitive(zero_salt);
	return ret;
}

/*
 * hkdf_expand_impl — RFC 5869 §2.3
 *
 * OKM = T(1) || T(2) || ... where T(i) = HMAC(PRK, T(i-1) || info || i)
 *
 * @tfm:      HMAC shash already keyed to PRK (by hkdf_extract_impl)
 * @info:     optional context/application-specific info (may be NULL)
 * @info_len: length of info
 * @okm:      output buffer
 * @okm_len:  requested output length (must be <= 255 * digestsize)
 */
static int hkdf_expand_impl(struct crypto_shash *tfm,
			    const u8 *info, u32 info_len,
			    u8 *okm, u32 okm_len)
{
	u32 digestsize = crypto_shash_digestsize(tfm);
	struct shash_desc *desc;
	u8 *t;           /* T(i) scratch, digestsize bytes */
	u8 counter;
	u32 t_len = 0;   /* 0 for T(0) = empty */
	u32 done  = 0;
	int ret   = 0;

	if (okm_len > 255 * digestsize) {
		pr_err("hkdf_expand: okm_len %u exceeds 255 * digestsize (%u)\n",
		       okm_len, 255 * digestsize);
		return -EINVAL;
	}

	desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc)
		return -ENOMEM;
	desc->tfm = tfm;

	t = kzalloc(digestsize, GFP_KERNEL);
	if (!t) {
		ret = -ENOMEM;
		goto out_free_desc;
	}

	for (counter = 1; done < okm_len; counter++) {
		u32 copy_len;

		ret = crypto_shash_init(desc);
		if (ret)
			goto out;

		/* T(i-1): empty for the first iteration */
		if (t_len > 0) {
			ret = crypto_shash_update(desc, t, t_len);
			if (ret)
				goto out;
		}

		/* info */
		if (info && info_len > 0) {
			ret = crypto_shash_update(desc, info, info_len);
			if (ret)
				goto out;
		}

		/* counter byte */
		ret = crypto_shash_update(desc, &counter, 1);
		if (ret)
			goto out;

		ret = crypto_shash_final(desc, t);
		if (ret)
			goto out;

		t_len = digestsize;

		copy_len = min_t(u32, digestsize, okm_len - done);
		memcpy(okm + done, t, copy_len);
		done += copy_len;
	}

out:
	if (ret)
		pr_err_ratelimited("hkdf_expand: failed at counter %u: %d\n",
				   (unsigned int)counter, ret);
	memzero_explicit(t, digestsize);
	kfree(t);
out_free_desc:
	memzero_explicit(desc, sizeof(*desc) + crypto_shash_descsize(tfm));
	kfree(desc);
	return ret;
}

/*
 * kcapi_do_hkdf — HKDF-RFC5869 using kernel HMAC shash.
 *
 * @hmac_algoname: e.g. "hmac(sha256)", "hmac(sha384)", "hmac(sha512)"
 */
static int kcapi_do_hkdf(const char *hmac_algoname,
			 const u8 *ikm, u32 ikm_len,
			 const u8 *salt, u32 salt_len,
			 const u8 *info, u32 info_len,
			 u8 *out, u32 out_len)
{
	struct crypto_shash *tfm;
	u32 digestsize;
	u8 *prk;
	int ret;

	tfm = crypto_alloc_shash(hmac_algoname, 0, 0);
	if (IS_ERR(tfm)) {
		ret = PTR_ERR(tfm);
		pr_err_ratelimited("hkdf: failed to allocate %s: %d\n",
				   hmac_algoname, ret);
		return ret;
	}

	digestsize = crypto_shash_digestsize(tfm);
	prk = kzalloc(digestsize, GFP_KERNEL);
	if (!prk) {
		ret = -ENOMEM;
		goto out_free_tfm;
	}

	ret = hkdf_extract_impl(tfm, ikm, ikm_len, salt, salt_len, prk);
	if (ret)
		goto out_free_prk;

	/* hkdf_extract_impl left tfm keyed to PRK */
	ret = hkdf_expand_impl(tfm, info, info_len, out, out_len);

out_free_prk:
	memzero_explicit(prk, digestsize);
	kfree(prk);
out_free_tfm:
	crypto_free_shash(tfm);
	return ret;
}

/* ── kdf callbacks ──────────────────────────────────────────────────────── */

static int kcapi_hkdf_sha256_kdf(const u8 *ikm, u32 ikm_len,
				 const u8 *salt, u32 salt_len,
				 const u8 *info, u32 info_len,
				 u32 iterations,
				 u8 *out, u32 out_len)
{
	(void)iterations;
	return kcapi_do_hkdf("hmac(sha256)",
			     ikm, ikm_len, salt, salt_len,
			     info, info_len, out, out_len);
}

static int kcapi_hkdf_sha384_kdf(const u8 *ikm, u32 ikm_len,
				 const u8 *salt, u32 salt_len,
				 const u8 *info, u32 info_len,
				 u32 iterations,
				 u8 *out, u32 out_len)
{
	(void)iterations;
	return kcapi_do_hkdf("hmac(sha384)",
			     ikm, ikm_len, salt, salt_len,
			     info, info_len, out, out_len);
}

static int kcapi_hkdf_sha512_kdf(const u8 *ikm, u32 ikm_len,
				 const u8 *salt, u32 salt_len,
				 const u8 *info, u32 info_len,
				 u32 iterations,
				 u8 *out, u32 out_len)
{
	(void)iterations;
	return kcapi_do_hkdf("hmac(sha512)",
			     ikm, ikm_len, salt, salt_len,
			     info, info_len, out, out_len);
}

/* ── PBKDF2 ──────────────────────────────────────────────────────────────── */

/*
 * pbkdf2_block — RFC 8018 §5.2: compute one block T_i.
 *
 * T_i = U_1 XOR U_2 XOR ... XOR U_c
 *
 * U_1 = HMAC(Password, Salt || INT(i))
 * U_j = HMAC(Password, U_{j-1})  for j > 1
 *
 * @tfm:        HMAC shash already keyed with the password
 * @desc:       pre-allocated shash_desc pointing at tfm
 * @salt:       the PBKDF2 salt S
 * @salt_len:   length of salt
 * @block_idx:  1-based block counter i (big-endian INT(i) appended to salt)
 * @iterations: iteration count c (>= 1)
 * @block:      output buffer, digestsize bytes
 */
static int pbkdf2_block(struct crypto_shash *tfm, struct shash_desc *desc,
			const u8 *salt, u32 salt_len,
			u32 block_idx, u32 iterations,
			u8 *block)
{
	u32 digestsize = crypto_shash_digestsize(tfm);
	u8 be_idx[4];     /* big-endian INT(i) */
	u8 *u;            /* U_j scratch buffer */
	u32 j;
	int ret;

	be_idx[0] = (block_idx >> 24) & 0xff;
	be_idx[1] = (block_idx >> 16) & 0xff;
	be_idx[2] = (block_idx >>  8) & 0xff;
	be_idx[3] =  block_idx        & 0xff;

	u = kzalloc(digestsize, GFP_KERNEL);
	if (!u)
		return -ENOMEM;

	/* U_1 = HMAC(Password, Salt || INT(i)) */
	ret = crypto_shash_init(desc);
	if (ret)
		goto out;
	ret = crypto_shash_update(desc, salt, salt_len);
	if (ret)
		goto out;
	ret = crypto_shash_update(desc, be_idx, sizeof(be_idx));
	if (ret)
		goto out;
	ret = crypto_shash_final(desc, u);
	if (ret)
		goto out;

	memcpy(block, u, digestsize);

	/* U_j = HMAC(Password, U_{j-1}), XOR into block */
	for (j = 2; j <= iterations; j++) {
		u32 k;

		ret = crypto_shash_digest(desc, u, digestsize, u);
		if (ret)
			goto out;

		for (k = 0; k < digestsize; k++)
			block[k] ^= u[k];
	}

out:
	memzero_explicit(u, digestsize);
	kfree(u);
	return ret;
}

/*
 * kcapi_do_pbkdf2 — PBKDF2-RFC8018 using kernel HMAC shash.
 *
 * The password (IKM) is used as the HMAC key; info is unused.
 *
 * @hmac_algoname: e.g. "hmac(sha256)", "hmac(sha384)", "hmac(sha512)"
 */
static int kcapi_do_pbkdf2(const char *hmac_algoname,
			   const u8 *password, u32 password_len,
			   const u8 *salt, u32 salt_len,
			   u32 iterations,
			   u8 *out, u32 out_len)
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	u32 digestsize;
	u8 *block;
	u32 done = 0;
	u32 block_idx = 1;
	int ret;

	tfm = crypto_alloc_shash(hmac_algoname, 0, 0);
	if (IS_ERR(tfm)) {
		ret = PTR_ERR(tfm);
		pr_err_ratelimited("pbkdf2: failed to allocate %s: %d\n",
				   hmac_algoname, ret);
		return ret;
	}

	ret = crypto_shash_setkey(tfm, password, password_len);
	if (ret) {
		pr_err_ratelimited("pbkdf2: setkey(password) failed: %d\n",
				   ret);
		goto out_free_tfm;
	}

	digestsize = crypto_shash_digestsize(tfm);

	desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc) {
		ret = -ENOMEM;
		goto out_free_tfm;
	}
	desc->tfm = tfm;

	block = kzalloc(digestsize, GFP_KERNEL);
	if (!block) {
		ret = -ENOMEM;
		goto out_free_desc;
	}

	while (done < out_len) {
		u32 copy_len;

		ret = pbkdf2_block(tfm, desc, salt, salt_len,
				   block_idx, iterations, block);
		if (ret) {
			pr_err_ratelimited("pbkdf2: block %u failed: %d\n",
					   block_idx, ret);
			goto out_free_block;
		}

		copy_len = min_t(u32, digestsize, out_len - done);
		memcpy(out + done, block, copy_len);
		done += copy_len;
		block_idx++;
	}

out_free_block:
	memzero_explicit(block, digestsize);
	kfree(block);
out_free_desc:
	memzero_explicit(desc, sizeof(*desc) + crypto_shash_descsize(tfm));
	kfree(desc);
out_free_tfm:
	crypto_free_shash(tfm);
	return ret;
}

/* ── PBKDF2 kdf callbacks ────────────────────────────────────────────────── */

static int kcapi_pbkdf2_sha256_kdf(const u8 *ikm, u32 ikm_len,
				   const u8 *salt, u32 salt_len,
				   const u8 *info, u32 info_len,
				   u32 iterations,
				   u8 *out, u32 out_len)
{
	(void)info; (void)info_len;
	return kcapi_do_pbkdf2("hmac(sha256)",
			       ikm, ikm_len, salt, salt_len,
			       iterations, out, out_len);
}

static int kcapi_pbkdf2_sha384_kdf(const u8 *ikm, u32 ikm_len,
				   const u8 *salt, u32 salt_len,
				   const u8 *info, u32 info_len,
				   u32 iterations,
				   u8 *out, u32 out_len)
{
	(void)info; (void)info_len;
	return kcapi_do_pbkdf2("hmac(sha384)",
			       ikm, ikm_len, salt, salt_len,
			       iterations, out, out_len);
}

static int kcapi_pbkdf2_sha512_kdf(const u8 *ikm, u32 ikm_len,
				   const u8 *salt, u32 salt_len,
				   const u8 *info, u32 info_len,
				   u32 iterations,
				   u8 *out, u32 out_len)
{
	(void)info; (void)info_len;
	return kcapi_do_pbkdf2("hmac(sha512)",
			       ikm, ikm_len, salt, salt_len,
			       iterations, out, out_len);
}

/* ── ops structs ─────────────────────────────────────────────────────────── */

const struct crypto2dev_algo_ops kcapi_hkdf_sha256_ops = {
	.algo      = "hkdf(sha256)",
	.fips_gate = NULL,
	.kdf       = kcapi_hkdf_sha256_kdf,
};

const struct crypto2dev_algo_ops kcapi_hkdf_sha384_ops = {
	.algo      = "hkdf(sha384)",
	.fips_gate = NULL,
	.kdf       = kcapi_hkdf_sha384_kdf,
};

const struct crypto2dev_algo_ops kcapi_hkdf_sha512_ops = {
	.algo      = "hkdf(sha512)",
	.fips_gate = NULL,
	.kdf       = kcapi_hkdf_sha512_kdf,
};

const struct crypto2dev_algo_ops kcapi_pbkdf2_sha256_ops = {
	.algo           = "pbkdf2(sha256)",
	.fips_gate      = NULL,
	.kdf            = kcapi_pbkdf2_sha256_kdf,
	.min_iterations = 1000,  /* SP 800-132 §5.2 */
	.min_salt_len   = 16,    /* SP 800-132 §5.1 */
};

const struct crypto2dev_algo_ops kcapi_pbkdf2_sha384_ops = {
	.algo           = "pbkdf2(sha384)",
	.fips_gate      = NULL,
	.kdf            = kcapi_pbkdf2_sha384_kdf,
	.min_iterations = 1000,  /* SP 800-132 §5.2 */
	.min_salt_len   = 16,    /* SP 800-132 §5.1 */
};

const struct crypto2dev_algo_ops kcapi_pbkdf2_sha512_ops = {
	.algo           = "pbkdf2(sha512)",
	.fips_gate      = NULL,
	.kdf            = kcapi_pbkdf2_sha512_kdf,
	.min_iterations = 1000,  /* SP 800-132 §5.2 */
	.min_salt_len   = 16,    /* SP 800-132 §5.1 */
};
