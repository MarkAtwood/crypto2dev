// SPDX-License-Identifier: GPL-2.0-only
/*
 * wolfssl_ecdsa.c — ECDSA sign/verify for crypto2dev
 *
 * Implements crypto2dev_algo_ops for "ecdsa-p256" and "ecdsa-p384"
 * using wolfCrypt wc_ecc_sign_hash / wc_ecc_verify_hash.
 *
 * Key management (import, generate, export, free) is shared with
 * wolfssl_ecdh.c via wolfssl_ec_key.h static inline helpers.
 *
 * FIPS 140-3: ECDSA is approved for P-256 and P-384.
 * The sign() callback receives a pre-computed digest — the provider
 * never hashes the message.
 */

#define pr_fmt(fmt) "crypto2dev_wolfssl: " fmt

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>

#include "../../../include/crypto2dev_provider.h"
#include "../../../include/uapi/crypto2dev_ioctl.h"
#include "wolfssl_provider.h"
#include "wolfssl_ec_key.h"

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* -----------------------------------------------------------------------
 * ECDSA sign
 * ----------------------------------------------------------------------- */

static int wolfssl_ecdsa_sign(void *key_ctx, const char *hash_algo,
			      const u8 *digest, u32 digest_len,
			      u8 *sig, u32 sig_bufsz, u32 *sig_len)
{
	struct wolfssl_ec_ctx *ctx = key_ctx;
	int ret;

	/* FIPS 140-3: gate must be first */
	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!ctx || !digest || digest_len == 0 || !sig || !sig_len)
		return -EINVAL;

	/* ECDSA sign requires a private key */
	if (ctx->key_type != CRYPTO2DEV_KEY_PRIVATE &&
	    ctx->key_type != CRYPTO2DEV_KEY_PAIR)
		return -ENOKEY;

	{
		word32 out_len;

		/* FIPS 140-3 / SP 800-186 Table 2: minimum approved digest length
		 * for ECDSA is 32 bytes (SHA-256).  SHA-1 (20 bytes) is not
		 * approved for new signatures.
		 */
		if (digest_len < 32)
			return -EINVAL;

		/* Ensure output buffer is large enough for DER-encoded sig */
		out_len = (word32)wc_ecc_sig_size(&ctx->key);
		if (sig_bufsz < out_len)
			return -ENOSPC;

		out_len = sig_bufsz;
		ret = wc_ecc_sign_hash(digest, (word32)digest_len,
				       sig, &out_len,
				       &ctx->rng, &ctx->key);
		if (ret != 0) {
			pr_err_ratelimited("wc_ecc_sign_hash returned %d\n",
					   ret);
			return wolfssl_ec_xlat_err(ret);
		}
		*sig_len = (u32)out_len;
	}
	return 0;
}

/* -----------------------------------------------------------------------
 * ECDSA verify
 * ----------------------------------------------------------------------- */

static int wolfssl_ecdsa_verify(void *key_ctx, const char *hash_algo,
				const u8 *digest, u32 digest_len,
				const u8 *sig, u32 sig_len)
{
	struct wolfssl_ec_ctx *ctx = key_ctx;
	int ret;

	/* FIPS 140-3: gate must be first */
	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!ctx || !digest || digest_len == 0 || !sig || sig_len == 0)
		return -EINVAL;

	/* ECDSA verify requires a public key or key pair */
	if (ctx->key_type != CRYPTO2DEV_KEY_PUBLIC &&
	    ctx->key_type != CRYPTO2DEV_KEY_PAIR)
		return -ENOKEY;

	{
		int res = 0;

		/* FIPS 140-3 / SP 800-186 Table 2: minimum 32 bytes (SHA-256) */
		if (digest_len < 32)
			return -EINVAL;

		ret = wc_ecc_verify_hash(sig, (word32)sig_len,
					 digest, (word32)digest_len,
					 &res, &ctx->key);
		if (ret != 0) {
			pr_err_ratelimited("wc_ecc_verify_hash returned %d\n",
					   ret);
			return wolfssl_ec_xlat_err(ret);
		}
		/* res==1: valid; res==0: invalid — distinguish clearly */
		if (res != 1)
			return -EBADMSG;
	}
	return 0;
}

/* -----------------------------------------------------------------------
 * Per-curve key_import and key_generate wrappers
 * ----------------------------------------------------------------------- */

static int wolfssl_ecdsa_p256_key_import(void **key_ctx, u32 key_type,
					 const u8 *raw, u32 rawlen)
{
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;
	return wolfssl_ec_key_import(key_ctx, key_type, raw, rawlen,
				     WOLFKM_ECC_P256,
				     EC_P256_SCALAR_LEN,
				     EC_P256_PUBKEY_LEN);
}

static int wolfssl_ecdsa_p384_key_import(void **key_ctx, u32 key_type,
					 const u8 *raw, u32 rawlen)
{
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;
	return wolfssl_ec_key_import(key_ctx, key_type, raw, rawlen,
				     WOLFKM_ECC_P384,
				     EC_P384_SCALAR_LEN,
				     EC_P384_PUBKEY_LEN);
}

static int wolfssl_ecdsa_p256_key_generate(void **key_ctx)
{
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;
	return wolfssl_ec_key_generate(key_ctx, WOLFKM_ECC_P256,
				       EC_P256_SCALAR_LEN,
				       EC_P256_PUBKEY_LEN);
}

static int wolfssl_ecdsa_p384_key_generate(void **key_ctx)
{
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;
	return wolfssl_ec_key_generate(key_ctx, WOLFKM_ECC_P384,
				       EC_P384_SCALAR_LEN,
				       EC_P384_PUBKEY_LEN);
}

/* -----------------------------------------------------------------------
 * key_export_public / key_export_private wrappers with FIPS gate
 * ----------------------------------------------------------------------- */

static int wolfssl_ecdsa_key_export_public(void *key_ctx,
					   u8 *out, u32 bufsz, u32 *outlen)
{
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	return wolfssl_ec_key_export_public(key_ctx, out, bufsz, outlen);
}

static int wolfssl_ecdsa_key_export_private(void *key_ctx,
					    u8 *out, u32 bufsz, u32 *outlen)
{
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	return wolfssl_ec_key_export_private(key_ctx, out, bufsz, outlen);
}

/* -----------------------------------------------------------------------
 * key_size wrapper
 * ----------------------------------------------------------------------- */

static int wolfssl_ecdsa_key_size(void *key_ctx, u32 key_type)
{
	return wolfssl_ec_key_size(key_ctx, key_type);
}

/* -----------------------------------------------------------------------
 * algo_ops structs
 * ----------------------------------------------------------------------- */

const struct crypto2dev_algo_ops wolfssl_ecdsa_p256_ops = {
	.algo               = "ecdsa-p256",
	.fips_gate          = wolfssl_fips_gate,
	.sess_init          = NULL,
	.sess_free          = NULL,
	.set_iv             = NULL,
	.gen_iv             = NULL,
	.set_aad            = NULL,
	.set_tag            = NULL,
	.get_tag            = NULL,
	.sign               = wolfssl_ecdsa_sign,
	.verify             = wolfssl_ecdsa_verify,
	.agree              = NULL,
	.kdf                = NULL,
	.min_iterations     = 0,
	.min_salt_len       = 0,
	.sess_reset         = NULL,
	.update             = NULL,
	.finalize           = NULL,
	.key_import         = wolfssl_ecdsa_p256_key_import,
	.key_generate       = wolfssl_ecdsa_p256_key_generate,
	.key_export_public  = wolfssl_ecdsa_key_export_public,
	.key_export_private = wolfssl_ecdsa_key_export_private,
	.key_size           = wolfssl_ecdsa_key_size,
	.key_free           = wolfssl_ec_key_free,
};

const struct crypto2dev_algo_ops wolfssl_ecdsa_p384_ops = {
	.algo               = "ecdsa-p384",
	.fips_gate          = wolfssl_fips_gate,
	.sess_init          = NULL,
	.sess_free          = NULL,
	.set_iv             = NULL,
	.gen_iv             = NULL,
	.set_aad            = NULL,
	.set_tag            = NULL,
	.get_tag            = NULL,
	.sign               = wolfssl_ecdsa_sign,
	.verify             = wolfssl_ecdsa_verify,
	.agree              = NULL,
	.kdf                = NULL,
	.min_iterations     = 0,
	.min_salt_len       = 0,
	.sess_reset         = NULL,
	.update             = NULL,
	.finalize           = NULL,
	.key_import         = wolfssl_ecdsa_p384_key_import,
	.key_generate       = wolfssl_ecdsa_p384_key_generate,
	.key_export_public  = wolfssl_ecdsa_key_export_public,
	.key_export_private = wolfssl_ecdsa_key_export_private,
	.key_size           = wolfssl_ecdsa_key_size,
	.key_free           = wolfssl_ec_key_free,
};
