// SPDX-License-Identifier: GPL-2.0-only
/*
 * wolfssl_hmac.c — HMAC-SHA-256/384/512 provider for crypto2dev
 *
 * Implements three algo_ops structs backed by wolfCrypt.
 * HMAC requires a key.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "../../../include/crypto2dev_provider.h"
#include "../../../include/uapi/crypto2dev_ioctl.h"
#include "wolfssl_provider.h"

#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* ------------------------------------------------------------------
 * Error translation
 * ------------------------------------------------------------------ */

/* Translate wolfCrypt error codes to kernel errno */
static int wolfssl_hmac_xlat_err(int wc_err)
{
	switch (wc_err) {
	case -173: /* BAD_FUNC_ARG */
		return -EINVAL;
	case -125: /* MEMORY_E */
		return -ENOMEM;
	case FIPS_NOT_ALLOWED_E:	/* operation not allowed in FIPS mode */
		return -EACCES;
	case FIPS_DEGRADED_E:		/* FIPS module in degraded state */
		return -EACCES;
	default:
		pr_err_ratelimited("wolfssl: unhandled wc_err=%d\n", wc_err);
		return -EIO;
	}
}

/* ------------------------------------------------------------------
 * Internal context
 * ------------------------------------------------------------------ */

/* Maximum HMAC key length supported (matches wolfCrypt WC_HMAC_BLOCK_SIZE) */
#define WOLFSSL_HMAC_MAX_KEY_LEN  128

struct wolfssl_hmac_ctx {
	int  hash_type; /* WC_SHA256 / WC_SHA384 / WC_SHA512 */
	bool inited;
	u8   key_bytes[WOLFSSL_HMAC_MAX_KEY_LEN];
	u32  key_len;
	Hmac hmac;
};

/* ------------------------------------------------------------------
 * Algorithm name and digest size helpers
 * ------------------------------------------------------------------ */

/* Maps wolfssl_hmac_ctx.hash_type to a human-readable algo name for logs. */
static const char *hmac_algo_name(int hash_type)
{
	if (hash_type == WC_SHA256) return "hmac(sha256)";
	if (hash_type == WC_SHA384) return "hmac(sha384)";
	if (hash_type == WC_SHA512) return "hmac(sha512)";
	return "hmac(unknown)";
}

static size_t hmac_digest_size(int hash_type)
{
	if (hash_type == WC_SHA256)
		return WC_SHA256_DIGEST_SIZE;
	if (hash_type == WC_SHA384)
		return WC_SHA384_DIGEST_SIZE;
	if (hash_type == WC_SHA512)
		return WC_SHA512_DIGEST_SIZE;
	return 32;
}

/* ------------------------------------------------------------------
 * sess_init — shared across all three HMAC variants
 * ------------------------------------------------------------------ */

static int hmac_sess_init(void **out_ctx, int hash_type,
			  u32 op, const u8 *key, u32 keylen)
{
	struct wolfssl_hmac_ctx *ctx;
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (op != CRYPTO2DEV_OP_HASH)
		return -EINVAL;

	/* HMAC requires a key */
	if (!key || keylen == 0)
		return -EINVAL;

	/* FIPS 140-3 (SP 800-107 Rev 1 §5.3.4): minimum HMAC key length must
	 * equal the hash output size to achieve the claimed security strength.
	 * wolfCrypt does not enforce this; the module must. */
	if ((hash_type == WC_SHA256 && keylen < WC_SHA256_DIGEST_SIZE) ||
	    (hash_type == WC_SHA384 && keylen < WC_SHA384_DIGEST_SIZE) ||
	    (hash_type == WC_SHA512 && keylen < WC_SHA512_DIGEST_SIZE))
		return -EINVAL;

	if (keylen > WOLFSSL_HMAC_MAX_KEY_LEN)
		return -EINVAL;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->hash_type = hash_type;
	memcpy(ctx->key_bytes, key, keylen);
	ctx->key_len = keylen;

	ret = wc_HmacInit(&ctx->hmac, NULL, INVALID_DEVID);
	if (ret != 0) {
		pr_err_ratelimited("%s: wc_HmacInit returned %d\n",
				   __func__, ret);
		memzero_explicit(ctx, sizeof(*ctx));
		kfree(ctx);
		return wolfssl_hmac_xlat_err(ret);
	}

	ret = wc_HmacSetKey(&ctx->hmac, hash_type, key, keylen);
	if (ret != 0) {
		pr_err_ratelimited("%s: wc_HmacSetKey returned %d\n",
				   __func__, ret);
		wc_HmacFree(&ctx->hmac);
		memzero_explicit(ctx, sizeof(*ctx));
		kfree(ctx);
		return wolfssl_hmac_xlat_err(ret);
	}

	ctx->inited = true;
	*out_ctx = ctx;
	return 0;
}

static int wolfssl_hmac_sha256_sess_init(void **ctx, u32 op,
					 const u8 *key, u32 keylen)
{
	return hmac_sess_init(ctx, WC_SHA256, op, key, keylen);
}

static int wolfssl_hmac_sha384_sess_init(void **ctx, u32 op,
					 const u8 *key, u32 keylen)
{
	return hmac_sess_init(ctx, WC_SHA384, op, key, keylen);
}

static int wolfssl_hmac_sha512_sess_init(void **ctx, u32 op,
					 const u8 *key, u32 keylen)
{
	return hmac_sess_init(ctx, WC_SHA512, op, key, keylen);
}

/* ------------------------------------------------------------------
 * sess_reset
 * ------------------------------------------------------------------ */

static int wolfssl_hmac_sess_reset(void *arg)
{
	struct wolfssl_hmac_ctx *ctx = arg;
	int ret;

	/* FIPS 140-3: gate before any crypto state is touched. */
	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!ctx || !ctx->inited)
		return -EINVAL;

	/* Mark as not initialized before freeing — protects sess_free
	 * from double-freeing the Hmac struct if re-init fails below. */
	ctx->inited = false;
	wc_HmacFree(&ctx->hmac);

	ret = wc_HmacInit(&ctx->hmac, NULL, INVALID_DEVID);
	if (ret != 0) {
		pr_err_ratelimited("%s(%s): wc_HmacInit returned %d\n",
				   __func__, hmac_algo_name(ctx->hash_type), ret);
		/* FIPS 140-3: zeroize key material before returning error. */
		memzero_explicit(ctx->key_bytes, sizeof(ctx->key_bytes));
		ctx->key_len = 0;
		return wolfssl_hmac_xlat_err(ret);
	}

	ret = wc_HmacSetKey(&ctx->hmac, ctx->hash_type,
			    ctx->key_bytes, ctx->key_len);
	if (ret != 0) {
		pr_err_ratelimited("%s(%s): wc_HmacSetKey returned %d\n",
				   __func__, hmac_algo_name(ctx->hash_type), ret);
		wc_HmacFree(&ctx->hmac);
		/* FIPS 140-3: zeroize key material before returning error. */
		memzero_explicit(ctx->key_bytes, sizeof(ctx->key_bytes));
		ctx->key_len = 0;
		return wolfssl_hmac_xlat_err(ret);
	}
	ctx->inited = true;

	return 0;
}

/* ------------------------------------------------------------------
 * sess_free
 * ------------------------------------------------------------------ */

static void wolfssl_hmac_sess_free(void *arg)
{
	struct wolfssl_hmac_ctx *ctx = arg;

	if (!ctx)
		return;

	if (ctx->inited)
		wc_HmacFree(&ctx->hmac);

	memzero_explicit(ctx, sizeof(*ctx));
	kfree(ctx);
}

/* ------------------------------------------------------------------
 * update
 * ------------------------------------------------------------------ */

static int wolfssl_hmac_update(void *arg,
			       const u8 *in, size_t inlen,
			       u8 *out, size_t outbuf_size, size_t *outlen)
{
	struct wolfssl_hmac_ctx *ctx = arg;
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!ctx || !ctx->inited)
		return -EINVAL;

	if (!in)
		return -EINVAL;

	(void)out;
	(void)outbuf_size;

	ret = wc_HmacUpdate(&ctx->hmac, in, (word32)inlen);
	if (ret != 0) {
		pr_err_ratelimited("%s(%s): wc_HmacUpdate returned %d\n",
				   __func__, hmac_algo_name(ctx->hash_type), ret);
		return wolfssl_hmac_xlat_err(ret);
	}

	*outlen = 0;
	return 0;
}

/* ------------------------------------------------------------------
 * finalize
 * ------------------------------------------------------------------ */

static int wolfssl_hmac_finalize(void *arg,
				 u8 *out, size_t outbuf_size, size_t *outlen)
{
	struct wolfssl_hmac_ctx *ctx = arg;
	size_t digest_size;
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!ctx || !ctx->inited)
		return -EINVAL;

	if (!out || !outlen)
		return -EINVAL;

	digest_size = hmac_digest_size(ctx->hash_type);

	if (outbuf_size < digest_size)
		return -EMSGSIZE;

	ret = wc_HmacFinal(&ctx->hmac, out);
	if (ret != 0) {
		pr_err_ratelimited("%s(%s): wc_HmacFinal returned %d\n",
				   __func__, hmac_algo_name(ctx->hash_type), ret);
		return wolfssl_hmac_xlat_err(ret);
	}

	*outlen = digest_size;
	return 0;
}

/* ------------------------------------------------------------------
 * algo_ops tables
 * ------------------------------------------------------------------ */

const struct crypto2dev_algo_ops wolfssl_hmac_sha256_ops = {
	.algo       = "hmac(sha256)",
	.fips_gate  = wolfssl_fips_gate,
	.sess_init  = wolfssl_hmac_sha256_sess_init,
	.sess_free  = wolfssl_hmac_sess_free,
	.set_iv     = NULL,
	.set_aad    = NULL,
	.set_tag    = NULL,
	.get_tag    = NULL,
	.sign               = NULL,
	.verify             = NULL,
	.agree              = NULL,
	.sess_reset         = wolfssl_hmac_sess_reset,
	.update             = wolfssl_hmac_update,
	.finalize           = wolfssl_hmac_finalize,
	.key_import         = NULL,
	.key_generate       = NULL,
	.key_export_public  = NULL,
	.key_export_private = NULL,
	.key_free           = NULL,
};

const struct crypto2dev_algo_ops wolfssl_hmac_sha384_ops = {
	.algo       = "hmac(sha384)",
	.fips_gate  = wolfssl_fips_gate,
	.sess_init  = wolfssl_hmac_sha384_sess_init,
	.sess_free  = wolfssl_hmac_sess_free,
	.set_iv     = NULL,
	.set_aad    = NULL,
	.set_tag    = NULL,
	.get_tag    = NULL,
	.sign               = NULL,
	.verify             = NULL,
	.agree              = NULL,
	.sess_reset         = wolfssl_hmac_sess_reset,
	.update             = wolfssl_hmac_update,
	.finalize           = wolfssl_hmac_finalize,
	.key_import         = NULL,
	.key_generate       = NULL,
	.key_export_public  = NULL,
	.key_export_private = NULL,
	.key_free           = NULL,
};

const struct crypto2dev_algo_ops wolfssl_hmac_sha512_ops = {
	.algo       = "hmac(sha512)",
	.fips_gate  = wolfssl_fips_gate,
	.sess_init  = wolfssl_hmac_sha512_sess_init,
	.sess_free  = wolfssl_hmac_sess_free,
	.set_iv     = NULL,
	.set_aad    = NULL,
	.set_tag    = NULL,
	.get_tag    = NULL,
	.sign               = NULL,
	.verify             = NULL,
	.agree              = NULL,
	.sess_reset         = wolfssl_hmac_sess_reset,
	.update             = wolfssl_hmac_update,
	.finalize           = wolfssl_hmac_finalize,
	.key_import         = NULL,
	.key_generate       = NULL,
	.key_export_public  = NULL,
	.key_export_private = NULL,
	.key_free           = NULL,
};
