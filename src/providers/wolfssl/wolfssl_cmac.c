// SPDX-License-Identifier: GPL-2.0-only
/*
 * wolfssl_cmac.c — crypto2dev wolfSSL provider: CMAC-AES
 *
 * Implements cmac(aes) via wolfCrypt wc_Cmac* API.
 * FIPS 140-3: CMAC-AES is approved for 128-, 192-, and 256-bit keys.
 */

#define pr_fmt(fmt) "crypto2dev_wolfssl: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>

#include "../../../include/crypto2dev_provider.h"
#include "../../../include/uapi/crypto2dev_ioctl.h"
#include "wolfssl_provider.h"

#include <wolfssl/wolfcrypt/cmac.h>
#include <wolfssl/wolfcrypt/aes.h>	/* for WC_AES_BLOCK_SIZE */
#include <wolfssl/wolfcrypt/error-crypt.h>

/* Translate wolfCrypt error codes to kernel errno */
static int wolfssl_cmac_xlat_err(int wc_err)
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

/* Maximum AES key length in bytes (AES-256) */
#define WOLFSSL_CMAC_MAX_KEY_LEN  32

struct wolfssl_cmac_ctx {
	bool inited;
	u8   key_bytes[WOLFSSL_CMAC_MAX_KEY_LEN];
	u32  key_len;
	Cmac cmac;
};

static int wolfssl_cmac_aes_sess_init(void **out_ctx, u32 op,
				      const u8 *key, u32 keylen)
{
	struct wolfssl_cmac_ctx *ctx;
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (op != CRYPTO2DEV_OP_HASH)
		return -EINVAL;

	/* FIPS 140-3: AES key sizes only */
	if (keylen != 16 && keylen != 24 && keylen != 32)
		return -EINVAL;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	memcpy(ctx->key_bytes, key, keylen);
	ctx->key_len = keylen;

	/* wc_InitCmac performs both init and key loading in one call */
	ret = wc_InitCmac(&ctx->cmac, key, keylen, WC_CMAC_AES, NULL);
	if (ret != 0) {
		pr_err_ratelimited("%s: wc_InitCmac returned %d\n",
				   __func__, ret);
		/* wc_InitCmac failed before any resource was acquired */
		memzero_explicit(ctx, sizeof(*ctx));
		kfree(ctx);
		return wolfssl_cmac_xlat_err(ret);
	}

	ctx->inited = true;
	*out_ctx = ctx;
	return 0;
}

static int wolfssl_cmac_aes_sess_reset(void *vctx)
{
	struct wolfssl_cmac_ctx *ctx = vctx;
	int ret;

	/* FIPS 140-3: gate before any crypto state is touched. */
	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!ctx || !ctx->inited)
		return -EINVAL;

	/* Mark as not initialized before freeing — protects sess_free
	 * from double-freeing the Cmac struct if re-init fails below. */
	ctx->inited = false;

#ifdef HAVE_CMAC_FREE
	wc_CmacFree(&ctx->cmac);
#endif

	/* wc_InitCmac performs both init and key loading in one call */
	ret = wc_InitCmac(&ctx->cmac, ctx->key_bytes, ctx->key_len,
			  WC_CMAC_AES, NULL);
	if (ret != 0) {
		pr_err_ratelimited("%s: wc_InitCmac returned %d\n",
				   __func__, ret);
		/* FIPS 140-3: zeroize key material before abandoning context */
		memzero_explicit(ctx->key_bytes, sizeof(ctx->key_bytes));
		ctx->key_len = 0;
		return wolfssl_cmac_xlat_err(ret);
	}

	ctx->inited = true;

	return 0;
}

static void wolfssl_cmac_aes_sess_free(void *vctx)
{
	struct wolfssl_cmac_ctx *ctx = vctx;

	if (!ctx)
		return;

	if (ctx->inited) {
#ifdef HAVE_CMAC_FREE
		wc_CmacFree(&ctx->cmac);
#endif
	}

	memzero_explicit(ctx, sizeof(*ctx));
	kfree(ctx);
}

/* ------------------------------------------------------------------
 * update
 * ------------------------------------------------------------------ */

static int wolfssl_cmac_aes_update(void *vctx,
				   const u8 *in, size_t inlen,
				   u8 *out, size_t outbuf_size, size_t *outlen)
{
	struct wolfssl_cmac_ctx *ctx = vctx;
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!ctx || !ctx->inited)
		return -EINVAL;

	/* Allow inlen == 0: empty message is valid for CMAC */
	if (inlen > 0 && !in)
		return -EINVAL;

	(void)out;
	(void)outbuf_size;

	ret = wc_CmacUpdate(&ctx->cmac, in, (word32)inlen);
	if (ret != 0) {
		pr_err_ratelimited("%s: wc_CmacUpdate returned %d\n",
				   __func__, ret);
		return wolfssl_cmac_xlat_err(ret);
	}

	*outlen = 0;
	return 0;
}

/* ------------------------------------------------------------------
 * finalize
 * ------------------------------------------------------------------ */

static int wolfssl_cmac_aes_finalize(void *vctx,
				     u8 *out, size_t outbuf_size, size_t *outlen)
{
	struct wolfssl_cmac_ctx *ctx = vctx;
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!ctx || !ctx->inited)
		return -EINVAL;

	if (!out || !outlen)
		return -EINVAL;

	if (outbuf_size < WC_AES_BLOCK_SIZE)
		return -EMSGSIZE;

	{
		word32 outlen32 = WC_AES_BLOCK_SIZE;

		ret = wc_CmacFinal(&ctx->cmac, out, &outlen32);
		if (ret != 0) {
			pr_err_ratelimited("%s: wc_CmacFinal returned %d\n",
					   __func__, ret);
			return wolfssl_cmac_xlat_err(ret);
		}

		*outlen = (size_t)outlen32;
	}

	return 0;
}

const struct crypto2dev_algo_ops wolfssl_cmac_aes_ops = {
	.algo       = "cmac(aes)",
	.fips_gate  = wolfssl_fips_gate,
	.sess_init  = wolfssl_cmac_aes_sess_init,
	.sess_free  = wolfssl_cmac_aes_sess_free,
	.set_iv     = NULL,
	.set_aad    = NULL,
	.set_tag    = NULL,
	.get_tag    = NULL,
	.sign               = NULL,
	.verify             = NULL,
	.agree              = NULL,
	.sess_reset         = wolfssl_cmac_aes_sess_reset,
	.update             = wolfssl_cmac_aes_update,
	.finalize           = wolfssl_cmac_aes_finalize,
	.key_import         = NULL,
	.key_generate       = NULL,
	.key_export_public  = NULL,
	.key_export_private = NULL,
	.key_free           = NULL,
};
EXPORT_SYMBOL_GPL(wolfssl_cmac_aes_ops);
