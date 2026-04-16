// SPDX-License-Identifier: GPL-2.0-only
/*
 * wolfssl_kdf.c — crypto2dev wolfSSL provider: HKDF and PBKDF2
 *
 * Provides:
 *   HKDF-SHA256, HKDF-SHA384, HKDF-SHA512 (RFC 5869 / SP 800-56C rev2)
 *   PBKDF2-SHA256, PBKDF2-SHA384, PBKDF2-SHA512 (RFC 8018 / SP 800-132)
 *
 * All KDF operations are one-shot (no per-session state).
 *
 * FIPS 140-3 status:
 *   PBKDF2: wolfCrypt FIPS CAST-tested (FIPS_CAST_PBKDF2 = 18); approved.
 *   HKDF:   SP 800-56C rev2 approved KDF; not a standalone FIPS CAST but
 *           uses FIPS-approved HMAC internally.
 */

#define pr_fmt(fmt) "crypto2dev_wolfssl: " fmt

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/string.h>

#include "../../../include/uapi/crypto2dev_ioctl.h"
#include "../../../include/crypto2dev_provider.h"
#include "wolfssl_provider.h"

#include <wolfssl/wolfcrypt/hmac.h>      /* wc_HKDF, WC_SHA256/384/512, HAVE_HKDF */
#include <wolfssl/wolfcrypt/pwdbased.h>  /* wc_PBKDF2, NO_PWDBASED */
#include <wolfssl/wolfcrypt/error-crypt.h>

/* ── wolfCrypt error → kernel errno ───────────────────────────────────────── */

static int wolfkdf_errno(int wc_ret)
{
	switch (wc_ret) {
	case 0:             return 0;
	case BAD_FUNC_ARG:  return -EINVAL;
	case MEMORY_E:      return -ENOMEM;
	case BUFFER_E:      return -EMSGSIZE;
	default:
		pr_err_ratelimited("wolfCrypt KDF error %d\n", wc_ret);
		return -EIO;
	}
}

/* ── HKDF ─────────────────────────────────────────────────────────────────── */

/*
 * wolfssl_do_hkdf — shared HKDF implementation for all hash variants.
 *
 * hash_type: WC_SHA256, WC_SHA384, or WC_SHA512 (wolfCrypt hash type constant).
 *
 * FIPS gating is performed by each public _kdf callback before reaching here.
 */
static int wolfssl_do_hkdf(int hash_type,
			   const u8 *ikm, u32 ikm_len,
			   const u8 *salt, u32 salt_len,
			   const u8 *info, u32 info_len,
			   u8 *out, u32 out_len)
{
#ifdef HAVE_HKDF
	int ret;

	/* wc_HKDF: ikm/ikm_len are the IKM, salt/salt_len and info/info_len
	 * are optional (may be NULL with length 0). Derives out_len bytes. */
	ret = wc_HKDF(hash_type,
		      ikm, ikm_len,
		      salt_len ? salt : NULL, salt_len,
		      info_len ? info : NULL, info_len,
		      out, out_len);
	return wolfkdf_errno(ret);
#else
	(void)hash_type;
	(void)ikm; (void)ikm_len;
	(void)salt; (void)salt_len;
	(void)info; (void)info_len;
	(void)out; (void)out_len;
	return -ENOSYS;
#endif
}

static int hkdf_sha256_kdf(const u8 *ikm, u32 ikm_len,
			   const u8 *salt, u32 salt_len,
			   const u8 *info, u32 info_len,
			   u32 iterations,
			   u8 *out, u32 out_len)
{
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	(void)iterations;
	return wolfssl_do_hkdf(WC_SHA256, ikm, ikm_len,
			       salt, salt_len, info, info_len,
			       out, out_len);
}

static int hkdf_sha384_kdf(const u8 *ikm, u32 ikm_len,
			   const u8 *salt, u32 salt_len,
			   const u8 *info, u32 info_len,
			   u32 iterations,
			   u8 *out, u32 out_len)
{
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	(void)iterations;
	return wolfssl_do_hkdf(WC_SHA384, ikm, ikm_len,
			       salt, salt_len, info, info_len,
			       out, out_len);
}

static int hkdf_sha512_kdf(const u8 *ikm, u32 ikm_len,
			   const u8 *salt, u32 salt_len,
			   const u8 *info, u32 info_len,
			   u32 iterations,
			   u8 *out, u32 out_len)
{
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	(void)iterations;
	return wolfssl_do_hkdf(WC_SHA512, ikm, ikm_len,
			       salt, salt_len, info, info_len,
			       out, out_len);
}

/* ── PBKDF2 ───────────────────────────────────────────────────────────────── */

/*
 * wolfssl_do_pbkdf2 — shared PBKDF2 implementation for all hash variants.
 *
 * hash_type: WC_SHA256, WC_SHA384, or WC_SHA512.
 * iterations: >= 1000 (enforced by the framework in ioctl_do_kdf).
 *
 * FIPS 140-3 / SP 800-132: PBKDF2 with >= 1000 iterations using HMAC-SHA*.
 */
static int wolfssl_do_pbkdf2(int hash_type,
			     const u8 *passwd, u32 passwd_len,
			     const u8 *salt, u32 salt_len,
			     u32 iterations,
			     u8 *out, u32 out_len)
{
#ifndef NO_PWDBASED
	int ret;

	/* wc_PBKDF2: passwd/pLen, salt/sLen, iterations, kLen, hashType.
	 * Returns 0 on success, negative on failure. */
	ret = wc_PBKDF2(out,
			passwd, (int)passwd_len,
			salt, (int)salt_len,
			(int)iterations,
			(int)out_len,
			hash_type);
	return wolfkdf_errno(ret);
#else
	(void)hash_type;
	(void)passwd; (void)passwd_len;
	(void)salt; (void)salt_len;
	(void)iterations;
	(void)out; (void)out_len;
	return -ENOSYS;
#endif
}

static int pbkdf2_sha256_kdf(const u8 *ikm, u32 ikm_len,
			     const u8 *salt, u32 salt_len,
			     const u8 *info, u32 info_len,
			     u32 iterations,
			     u8 *out, u32 out_len)
{
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	(void)info; (void)info_len;
	return wolfssl_do_pbkdf2(WC_SHA256, ikm, ikm_len,
				 salt, salt_len, iterations,
				 out, out_len);
}

static int pbkdf2_sha384_kdf(const u8 *ikm, u32 ikm_len,
			     const u8 *salt, u32 salt_len,
			     const u8 *info, u32 info_len,
			     u32 iterations,
			     u8 *out, u32 out_len)
{
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	(void)info; (void)info_len;
	return wolfssl_do_pbkdf2(WC_SHA384, ikm, ikm_len,
				 salt, salt_len, iterations,
				 out, out_len);
}

static int pbkdf2_sha512_kdf(const u8 *ikm, u32 ikm_len,
			     const u8 *salt, u32 salt_len,
			     const u8 *info, u32 info_len,
			     u32 iterations,
			     u8 *out, u32 out_len)
{
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	(void)info; (void)info_len;
	return wolfssl_do_pbkdf2(WC_SHA512, ikm, ikm_len,
				 salt, salt_len, iterations,
				 out, out_len);
}

/* ── ops structs ─────────────────────────────────────────────────────────── */

const struct crypto2dev_algo_ops wolfssl_hkdf_sha256_ops = {
	.algo      = "hkdf(sha256)",
	.fips_gate = wolfssl_fips_gate,
	.kdf       = hkdf_sha256_kdf,
};

const struct crypto2dev_algo_ops wolfssl_hkdf_sha384_ops = {
	.algo      = "hkdf(sha384)",
	.fips_gate = wolfssl_fips_gate,
	.kdf       = hkdf_sha384_kdf,
};

const struct crypto2dev_algo_ops wolfssl_hkdf_sha512_ops = {
	.algo      = "hkdf(sha512)",
	.fips_gate = wolfssl_fips_gate,
	.kdf       = hkdf_sha512_kdf,
};

const struct crypto2dev_algo_ops wolfssl_pbkdf2_sha256_ops = {
	.algo           = "pbkdf2(sha256)",
	.fips_gate      = wolfssl_fips_gate,
	.kdf            = pbkdf2_sha256_kdf,
	.min_iterations = 1000,   /* SP 800-132 §5.2 */
	.min_salt_len   = 16,     /* SP 800-132 §5.1: >= 128 bits */
};

const struct crypto2dev_algo_ops wolfssl_pbkdf2_sha384_ops = {
	.algo           = "pbkdf2(sha384)",
	.fips_gate      = wolfssl_fips_gate,
	.kdf            = pbkdf2_sha384_kdf,
	.min_iterations = 1000,   /* SP 800-132 §5.2 */
	.min_salt_len   = 16,     /* SP 800-132 §5.1: >= 128 bits */
};

const struct crypto2dev_algo_ops wolfssl_pbkdf2_sha512_ops = {
	.algo           = "pbkdf2(sha512)",
	.fips_gate      = wolfssl_fips_gate,
	.kdf            = pbkdf2_sha512_kdf,
	.min_iterations = 1000,   /* SP 800-132 §5.2 */
	.min_salt_len   = 16,     /* SP 800-132 §5.1: >= 128 bits */
};
