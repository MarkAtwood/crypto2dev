// SPDX-License-Identifier: GPL-2.0-only
/*
 * wolfssl_ec_key.c — shared ECC key management implementation
 *
 * Compiled once; shared by wolfssl_ecdh.c and wolfssl_ecdsa.c via
 * extern declarations in wolfssl_ec_key.h.
 *
 * Per-algo wrappers in each .c file call wolfssl_fips_gate() before
 * delegating to these functions.
 */

#define pr_fmt(fmt) "crypto2dev_wolfssl: " fmt

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>

#include "../../../include/uapi/crypto2dev_ioctl.h"
#include "wolfssl_provider.h"
#include "wolfssl_ec_key.h"

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

int wolfssl_ec_xlat_err(int wc_err)
{
	switch (wc_err) {
	case BAD_FUNC_ARG:
		return -EINVAL;
	case MEMORY_E:
		return -ENOMEM;
	case FIPS_NOT_ALLOWED_E:
		return -EACCES;
	case FIPS_DEGRADED_E:
		return -EACCES;
	case ECC_BAD_ARG_E:
		return -EINVAL;
	case SIG_VERIFY_E:
		return -EBADMSG;
	default:
		pr_err_ratelimited("wolfssl_ec: unhandled wc_err=%d\n", wc_err);
		return -EIO;
	}
}

/*
 * wolfssl_ec_key_import - decode a key from DER/raw bytes into wolfssl_ec_ctx.
 * Caller must call wolfssl_fips_gate() before invoking this function.
 *
 * @key_ctx:    [out] allocated context on success
 * @key_type:   CRYPTO2DEV_KEY_PRIVATE, _PUBLIC, or _PAIR
 * @raw:        key bytes (PKCS#8 DER for private; SPKI DER or raw 04||x||y for public)
 * @rawlen:     length of raw bytes
 * @curve_id:   WOLFKM_ECC_P256 or WOLFKM_ECC_P384
 * @scalar_len: curve scalar length in bytes (32 or 48)
 * @pubkey_len: uncompressed public key length in bytes (65 or 97)
 */
int wolfssl_ec_key_import(void **key_ctx, u32 key_type,
			  const u8 *raw, u32 rawlen,
			  int curve_id, u32 scalar_len,
			  u32 pubkey_len)
{
	struct wolfssl_ec_ctx *ctx;
	int ret = 0;

	if (!key_ctx || !raw || rawlen == 0)
		return -EINVAL;

	if (key_type != CRYPTO2DEV_KEY_PRIVATE &&
	    key_type != CRYPTO2DEV_KEY_PUBLIC   &&
	    key_type != CRYPTO2DEV_KEY_PAIR)
		return -EINVAL;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->key_type   = key_type;
	ctx->curve_id   = curve_id;
	ctx->scalar_len = scalar_len;
	ctx->pubkey_len = pubkey_len;

	ret = wc_ecc_init_ex(&ctx->key, NULL, INVALID_DEVID);
	if (ret != 0) {
		pr_err_ratelimited("%s: wc_ecc_init_ex returned %d\n",
				   __func__, ret);
		goto err_free_ctx;
	}
	ctx->key_inited = true;

	if (key_type == CRYPTO2DEV_KEY_PRIVATE || key_type == CRYPTO2DEV_KEY_PAIR) {
		word32 idx = 0;
		word32 inner_idx = 0;

		/* Skip PKCS#8 wrapper to reach inner ECPrivateKey DER */
		ret = wc_GetPkcs8TraditionalOffset((byte *)raw, &idx, rawlen);
		if (ret < 0) {
			pr_err_ratelimited("%s: wc_GetPkcs8TraditionalOffset returned %d\n",
					   __func__, ret);
			goto err_free_key;
		}
		ret = wc_EccPrivateKeyDecode(raw + idx, &inner_idx,
					     &ctx->key, rawlen - idx);
		if (ret != 0) {
			pr_err_ratelimited("%s: wc_EccPrivateKeyDecode returned %d\n",
					   __func__, ret);
			goto err_free_key;
		}
	} else {
		/*
		 * Public key: detect format by first byte.
		 * 0x04 = raw uncompressed point (04||x||y).
		 * 0x30 = SubjectPublicKeyInfo DER SEQUENCE.
		 */
		if (raw[0] == 0x04) {
			/* wc_ecc_import_x963_ex enforces curve_id itself */
			ret = wc_ecc_import_x963_ex(raw, rawlen,
						    &ctx->key, curve_id);
		} else {
			word32 idx = 0;

			ret = wc_EccPublicKeyDecode(raw, &idx,
						    &ctx->key, rawlen);
			/*
			 * SPKI DER decode does not check curve_id — the curve
			 * is encoded inside the DER.  Verify that the decoded
			 * key is on the expected curve so a P-384 SPKI cannot
			 * be silently imported into a P-256 context.
			 */
			if (ret == 0) {
				int got_curve = wc_ecc_get_curve_id(ctx->key.idx);

				if (got_curve != curve_id) {
					pr_err_ratelimited(
						"%s: SPKI curve id %d != expected %d\n",
						__func__, got_curve, curve_id);
					ret = ECC_BAD_ARG_E;
				}
			}
		}
		if (ret != 0) {
			pr_err_ratelimited("%s: public key import returned %d\n",
					   __func__, ret);
			goto err_free_key;
		}
	}

	ret = wc_InitRng_ex(&ctx->rng, NULL, INVALID_DEVID);
	if (ret != 0) {
		pr_err_ratelimited("%s: wc_InitRng_ex returned %d\n",
				   __func__, ret);
		goto err_free_key;
	}
	ctx->rng_inited = true;

	ret = wc_ecc_set_rng(&ctx->key, &ctx->rng);
	if (ret != 0) {
		pr_err_ratelimited("%s: wc_ecc_set_rng returned %d\n",
				   __func__, ret);
		goto err_free_rng;
	}

	*key_ctx = ctx;
	return 0;

err_free_rng:
	wc_FreeRng(&ctx->rng);
	ctx->rng_inited = false;
err_free_key:
	wc_ecc_free(&ctx->key);
	ctx->key_inited = false;
err_free_ctx:
	memzero_explicit(ctx, sizeof(*ctx));
	kfree(ctx);
	return wolfssl_ec_xlat_err(ret);
}

/*
 * wolfssl_ec_key_generate - generate a new ECC key pair.
 * Caller must call wolfssl_fips_gate() before invoking this function.
 */
int wolfssl_ec_key_generate(void **key_ctx, int curve_id,
			    u32 scalar_len, u32 pubkey_len)
{
	struct wolfssl_ec_ctx *ctx;
	int ret = 0;

	if (!key_ctx)
		return -EINVAL;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->key_type   = CRYPTO2DEV_KEY_PAIR;
	ctx->curve_id   = curve_id;
	ctx->scalar_len = scalar_len;
	ctx->pubkey_len = pubkey_len;

	ret = wc_ecc_init_ex(&ctx->key, NULL, INVALID_DEVID);
	if (ret != 0) {
		pr_err_ratelimited("%s: wc_ecc_init_ex returned %d\n",
				   __func__, ret);
		goto err_free_ctx;
	}
	ctx->key_inited = true;

	ret = wc_InitRng_ex(&ctx->rng, NULL, INVALID_DEVID);
	if (ret != 0) {
		pr_err_ratelimited("%s: wc_InitRng_ex returned %d\n",
				   __func__, ret);
		goto err_free_key;
	}
	ctx->rng_inited = true;

	ret = wc_ecc_make_key_ex(&ctx->rng, (int)scalar_len,
				 &ctx->key, curve_id);
	if (ret != 0) {
		pr_err_ratelimited("%s: wc_ecc_make_key_ex returned %d\n",
				   __func__, ret);
		goto err_free_rng;
	}

	ret = wc_ecc_set_rng(&ctx->key, &ctx->rng);
	if (ret != 0) {
		pr_err_ratelimited("%s: wc_ecc_set_rng returned %d\n",
				   __func__, ret);
		goto err_free_rng;
	}

	*key_ctx = ctx;
	return 0;

err_free_rng:
	wc_FreeRng(&ctx->rng);
	ctx->rng_inited = false;
err_free_key:
	wc_ecc_free(&ctx->key);
	ctx->key_inited = false;
err_free_ctx:
	memzero_explicit(ctx, sizeof(*ctx));
	kfree(ctx);
	return wolfssl_ec_xlat_err(ret);
}

/* Export uncompressed public point (04||x||y). */
int wolfssl_ec_key_export_public(void *key_ctx,
				 u8 *out, u32 bufsz, u32 *outlen)
{
	struct wolfssl_ec_ctx *ctx = key_ctx;
	int ret;

	/* FIPS 140-3: gate before any cryptographic state access.
	 * The helpers are called from gated per-algo wrappers today, but the
	 * gate lives here so no future caller can bypass it by accident. */
	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!ctx || !out || !outlen)
		return -EINVAL;

	{
		word32 len = bufsz;

		ret = wc_ecc_export_x963(&ctx->key, out, &len);
		if (ret != 0) {
			pr_err_ratelimited("%s: wc_ecc_export_x963 returned %d\n",
					   __func__, ret);
			return wolfssl_ec_xlat_err(ret);
		}
		*outlen = (u32)len;
	}
	return 0;
}

/* Export raw private scalar. */
int wolfssl_ec_key_export_private(void *key_ctx,
				  u8 *out, u32 bufsz, u32 *outlen)
{
	struct wolfssl_ec_ctx *ctx = key_ctx;
	int ret;

	/* FIPS 140-3: gate before any cryptographic state access. See above. */
	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!ctx || !out || !outlen)
		return -EINVAL;

	if (ctx->key_type == CRYPTO2DEV_KEY_PUBLIC)
		return -ENOKEY;

	{
		word32 len = bufsz;

		ret = wc_ecc_export_private_only(&ctx->key, out, &len);
		if (ret != 0) {
			pr_err_ratelimited("%s: wc_ecc_export_private_only returned %d\n",
					   __func__, ret);
			return wolfssl_ec_xlat_err(ret);
		}
		*outlen = (u32)len;
	}
	return 0;
}

/*
 * wolfssl_ec_key_size - return encoded key size without allocating.
 *
 * Returns the byte length of the encoded key for the requested key_type:
 *   PUBLIC:  uncompressed EC point length (pubkey_len from ctx)
 *   PRIVATE: raw scalar length (scalar_len from ctx)
 * Returns 0 if key_ctx is NULL or the key_type is unsupported.
 *
 * Must not allocate memory or call wolfCrypt export functions.
 * No FIPS gate required — reads only size metadata, not key material.
 */
int wolfssl_ec_key_size(void *key_ctx, u32 key_type)
{
	const struct wolfssl_ec_ctx *ctx = key_ctx;

	if (!ctx)
		return 0;

	if (key_type == CRYPTO2DEV_KEY_PUBLIC)
		return (int)ctx->pubkey_len;

	if (key_type == CRYPTO2DEV_KEY_PRIVATE)
		return (int)ctx->scalar_len;

	return 0;
}

/*
 * wolfssl_ec_key_free - zeroize and free a wolfssl_ec_ctx.
 * FIPS gate is NOT called here — cleanup must always proceed.
 */
void wolfssl_ec_key_free(void *key_ctx)
{
	struct wolfssl_ec_ctx *ctx = key_ctx;

	if (!ctx)
		return;

	if (ctx->rng_inited)
		wc_FreeRng(&ctx->rng);
	if (ctx->key_inited)
		wc_ecc_free(&ctx->key);
	/* FIPS 140-3: zeroize all key material before releasing memory */
	memzero_explicit(ctx, sizeof(*ctx));
	kfree(ctx);
}
