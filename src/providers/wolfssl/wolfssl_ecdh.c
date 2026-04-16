// SPDX-License-Identifier: GPL-2.0-only
/*
 * wolfssl_ecdh.c — ECDH key agreement with embedded HKDF
 * for the crypto2dev wolfSSL provider.
 *
 * Algorithms: "ecdh-p256", "ecdh-p384"
 * Operations: agree (ECDH+HKDF), key_import, key_generate,
 *             key_export_public, key_export_private
 *
 * FIPS SP 800-56A: ECDH shared secret Z is computed and immediately
 * consumed by HKDF (RFC 5869 / SP 800-56C).  Z never leaves this
 * provider.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>

#include <wolfssl/wolfcrypt/hmac.h>   /* wc_HKDF, WC_SHA256 */
#include "wolfssl_ec_key.h"

/* Maximum scalar size across supported curves */
#define EC_MAX_SCALAR_LEN  48u   /* P-384 */

/* ── key_import wrappers ──────────────────────────────────────────── */

static int wolfssl_ecdh_p256_key_import(void **key_ctx, u32 key_type,
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

static int wolfssl_ecdh_p384_key_import(void **key_ctx, u32 key_type,
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

/* ── key_generate wrappers ────────────────────────────────────────── */

static int wolfssl_ecdh_p256_key_generate(void **key_ctx)
{
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	return wolfssl_ec_key_generate(key_ctx, WOLFKM_ECC_P256,
				       EC_P256_SCALAR_LEN,
				       EC_P256_PUBKEY_LEN);
}

static int wolfssl_ecdh_p384_key_generate(void **key_ctx)
{
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	return wolfssl_ec_key_generate(key_ctx, WOLFKM_ECC_P384,
				       EC_P384_SCALAR_LEN,
				       EC_P384_PUBKEY_LEN);
}

/* ── key_export wrappers ──────────────────────────────────────────── */

static int wolfssl_ecdh_key_export_public(void *key_ctx,
					  u8 *out, u32 bufsz, u32 *outlen)
{
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	return wolfssl_ec_key_export_public(key_ctx, out, bufsz, outlen);
}

static int wolfssl_ecdh_key_export_private(void *key_ctx,
					   u8 *out, u32 bufsz, u32 *outlen)
{
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	return wolfssl_ec_key_export_private(key_ctx, out, bufsz, outlen);
}

/* ── agree: ECDH + HKDF ──────────────────────────────────────────── */
/*
 * wolfssl_ecdh_agree — compute ECDH shared secret Z, run HKDF, zero Z.
 *
 * Z (raw X coordinate of the ECDH result) never leaves this function.
 * HKDF hash is selected by curve: SHA-256 for P-256, SHA-384 for P-384
 * (SP 800-56C Rev 2 Table 2 — hash must match curve security level).
 * Peer public key must be in raw uncompressed form: 04||x||y.
 */
static int wolfssl_ecdh_agree(void *key_ctx,
			      const u8 *peer_pubkey, u32 peer_pubkey_len,
			      const u8 *salt,       u32 salt_len,
			      const u8 *info,       u32 info_len,
			      u8 *okm,              u32 okm_len)
{
	struct wolfssl_ec_ctx *ctx = key_ctx;
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!ctx || !peer_pubkey || !okm)
		return -EINVAL;

	/* agree requires a private key */
	if (ctx->key_type == CRYPTO2DEV_KEY_PUBLIC)
		return -ENOKEY;

	/* peer public key must be the full uncompressed point for this curve */
	if (peer_pubkey_len != ctx->pubkey_len)
		return -EINVAL;

	if (okm_len == 0 || okm_len > CRYPTO2DEV_PUBKEY_MAXLEN)
		return -EINVAL;

	{
		ecc_key *peer_key;
		u8      z[EC_MAX_SCALAR_LEN];
		word32  z_len = ctx->scalar_len;
		/* SP 800-56C Rev 2 Table 2: hash must match curve security level.
		 * P-256 (128-bit) uses SHA-256; P-384 (192-bit) uses SHA-384. */
		int     hkdf_hash = (ctx->curve_id == WOLFKM_ECC_P384)
					? WC_SHA384 : WC_SHA256;

		peer_key = kzalloc(sizeof(*peer_key), GFP_KERNEL);
		if (!peer_key)
			return -ENOMEM;

		ret = wc_ecc_init_ex(peer_key, NULL, INVALID_DEVID);
		if (ret != 0) {
			pr_err_ratelimited("%s: wc_ecc_init_ex(peer) returned %d\n",
					   __func__, ret);
			kfree(peer_key);
			return wolfssl_ec_xlat_err(ret);
		}

		/* Peer public key: raw uncompressed 04||x||y */
		ret = wc_ecc_import_x963_ex(peer_pubkey, peer_pubkey_len,
					    peer_key, ctx->curve_id);
		if (ret != 0) {
			pr_err_ratelimited("%s: wc_ecc_import_x963_ex returned %d\n",
					   __func__, ret);
			wc_ecc_free(peer_key);
			kfree(peer_key);
			return wolfssl_ec_xlat_err(ret);
		}

		/*
		 * SP 800-56A Rev 3 §5.6.2.3.3: full public key validation.
		 *
		 * wc_ecc_import_x963_ex() hardcodes untrusted=0 and
		 * WOLFSSL_VALIDATE_ECC_IMPORT defaults off, so import performs
		 * only format parsing — zero SP 800-56A validation in the
		 * default build.  All four checks (not-at-infinity, Qx/Qy in
		 * range, on-curve y²=x³+ax+b, order n×Q=∞) are performed only
		 * by _ecc_validate_public_key(), which is reachable solely via
		 * wc_ecc_check_key().  Must be called explicitly.
		 */
		ret = wc_ecc_check_key(peer_key);
		if (ret != 0) {
			pr_err_ratelimited("%s: peer key validation failed "
					   "(SP 800-56A §5.6.2.3.3): %d\n",
					   __func__, ret);
			wc_ecc_free(peer_key);
			kfree(peer_key);
			return wolfssl_ec_xlat_err(ret);
		}

		/* Compute ECDH shared secret Z (raw X coordinate) */
		memset(z, 0, sizeof(z));
		ret = wc_ecc_shared_secret(&ctx->key, peer_key, z, &z_len);
		wc_ecc_free(peer_key);
		kfree(peer_key);

		if (ret != 0) {
			pr_err_ratelimited("%s: wc_ecc_shared_secret returned %d\n",
					   __func__, ret);
			memzero_explicit(z, sizeof(z));
			return wolfssl_ec_xlat_err(ret);
		}

		/*
		 * HKDF (RFC 5869 / SP 800-56C): Extract(salt, Z) + Expand(PRK, info)
		 * → OKM.  Z is the IKM.  wc_HKDF handles NULL salt per RFC 5869 §2.2.
		 * FIPS 140-3: Z must be zeroized before any exit path.
		 */
		ret = wc_HKDF(hkdf_hash,
			      z, z_len,
			      salt, salt_len,
			      info, info_len,
			      okm,  okm_len);

		/* FIPS 140-3: zeroize Z before returning regardless of HKDF result */
		memzero_explicit(z, sizeof(z));

		if (ret != 0) {
			pr_err_ratelimited("%s: wc_HKDF returned %d\n",
					   __func__, ret);
			/* FIPS 140-3: zero any partial OKM — caller must not
			 * use partially-derived key material. */
			memzero_explicit(okm, okm_len);
			return wolfssl_ec_xlat_err(ret);
		}
	}

	return 0;
}

/* ── key_size wrapper ─────────────────────────────────────────────── */

static int wolfssl_ecdh_key_size(void *key_ctx, u32 key_type)
{
	return wolfssl_ec_key_size(key_ctx, key_type);
}

/* ── algo_ops structs ──────────────────────────────────────────────── */

const struct crypto2dev_algo_ops wolfssl_ecdh_p256_ops = {
	.algo               = "ecdh-p256",
	.fips_gate          = wolfssl_fips_gate,
	.sess_init          = NULL,
	.sess_free          = NULL,
	.set_iv             = NULL,
	.gen_iv             = NULL,
	.set_aad            = NULL,
	.set_tag            = NULL,
	.get_tag            = NULL,
	.sign               = NULL,
	.verify             = NULL,
	.agree              = wolfssl_ecdh_agree,
	.kdf                = NULL,
	.min_iterations     = 0,
	.min_salt_len       = 0,
	.sess_reset         = NULL,
	.update             = NULL,
	.finalize           = NULL,
	.key_import         = wolfssl_ecdh_p256_key_import,
	.key_generate       = wolfssl_ecdh_p256_key_generate,
	.key_export_public  = wolfssl_ecdh_key_export_public,
	.key_export_private = wolfssl_ecdh_key_export_private,
	.key_size           = wolfssl_ecdh_key_size,
	.key_free           = wolfssl_ec_key_free,
};

const struct crypto2dev_algo_ops wolfssl_ecdh_p384_ops = {
	.algo               = "ecdh-p384",
	.fips_gate          = wolfssl_fips_gate,
	.sess_init          = NULL,
	.sess_free          = NULL,
	.set_iv             = NULL,
	.gen_iv             = NULL,
	.set_aad            = NULL,
	.set_tag            = NULL,
	.get_tag            = NULL,
	.sign               = NULL,
	.verify             = NULL,
	.agree              = wolfssl_ecdh_agree,
	.kdf                = NULL,
	.min_iterations     = 0,
	.min_salt_len       = 0,
	.sess_reset         = NULL,
	.update             = NULL,
	.finalize           = NULL,
	.key_import         = wolfssl_ecdh_p384_key_import,
	.key_generate       = wolfssl_ecdh_p384_key_generate,
	.key_export_public  = wolfssl_ecdh_key_export_public,
	.key_export_private = wolfssl_ecdh_key_export_private,
	.key_size           = wolfssl_ecdh_key_size,
	.key_free           = wolfssl_ec_key_free,
};
