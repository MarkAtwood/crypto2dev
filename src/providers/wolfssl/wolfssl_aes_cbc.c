// SPDX-License-Identifier: GPL-2.0-only
/*
 * crypto2dev wolfSSL provider — AES-CBC
 *
 * Implements the crypto2dev_algo_ops vtable for "cbc(aes)" using wolfCrypt.
 */

#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>

#include "../../../include/uapi/crypto2dev_ioctl.h"
#include "wolfssl_provider.h"

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* Session context */
struct wolfssl_aes_cbc_ctx {
	Aes    aes;
	WC_RNG rng;    /* DRBG for GEN_IV — stays within FIPS boundary */
	bool inited;
	u32  op;
	/*
	 * Streaming tail: bytes not yet processed because they did not fill a
	 * complete AES block (16 bytes).  update() processes complete blocks
	 * immediately; any remainder (0-15 bytes) is held here until the next
	 * update() or finalize().  wolfCrypt maintains CBC chaining state
	 * (last ciphertext block) inside ctx->aes across calls.
	 */
	u8   tail[WC_AES_BLOCK_SIZE];
	u32  tail_len;
	/*
	 * IV tracking: non-zero once SET_IV or GEN_IV has succeeded.
	 * update() rejects calls when ivlen == 0 to prevent zero-IV
	 * encryption.  Cleared on sess_reset() so a new IV is required
	 * before the next UPDATE.
	 */
	u32  ivlen;
};

/* Translate wolfCrypt error codes to kernel errno */
static int wolfssl_cbc_xlat_err(int wc_err)
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

static int wolfssl_aes_cbc_sess_init(void **out_ctx, u32 op,
				     const u8 *key, u32 keylen)
{
	struct wolfssl_aes_cbc_ctx *ctx;
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!out_ctx || !key)
		return -EINVAL;

	if (op != CRYPTO2DEV_OP_ENCRYPT && op != CRYPTO2DEV_OP_DECRYPT)
		return -EINVAL;

	if (keylen != AES_128_KEY_SIZE &&
	    keylen != AES_192_KEY_SIZE &&
	    keylen != AES_256_KEY_SIZE)
		return -EINVAL;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->op = op;

	ret = wc_AesInit(&ctx->aes, NULL, INVALID_DEVID);
	if (ret != 0) {
		pr_err_ratelimited("%s: wc_AesInit returned %d\n", __func__, ret);
		memzero_explicit(ctx, sizeof(*ctx));
		kfree(ctx);
		return wolfssl_cbc_xlat_err(ret);
	}

	{
		int dir = (op == CRYPTO2DEV_OP_ENCRYPT) ?
			  AES_ENCRYPTION : AES_DECRYPTION;

		ret = wc_AesSetKey(&ctx->aes, key, keylen, NULL, dir);
		if (ret != 0) {
			pr_err_ratelimited("%s: wc_AesSetKey returned %d\n",
					   __func__, ret);
			wc_AesFree(&ctx->aes);
			memzero_explicit(ctx, sizeof(*ctx));
			kfree(ctx);
			return wolfssl_cbc_xlat_err(ret);
		}
	}

	ret = wc_InitRng_ex(&ctx->rng, NULL, INVALID_DEVID);
	if (ret != 0) {
		pr_err_ratelimited("%s: wc_InitRng_ex returned %d\n", __func__, ret);
		wc_AesFree(&ctx->aes);
		memzero_explicit(ctx, sizeof(*ctx));
		kfree(ctx);
		return wolfssl_cbc_xlat_err(ret);
	}

	ctx->inited = true;
	*out_ctx = ctx;
	return 0;
}

static int wolfssl_aes_cbc_sess_reset(void *ctx_)
{
	struct wolfssl_aes_cbc_ctx *ctx = ctx_;
	int ret;

	/* FIPS 140-3: gate before any crypto state is touched. */
	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!ctx || !ctx->inited)
		return -EINVAL;

	/* Clear streaming tail and IV state */
	memzero_explicit(ctx->tail, sizeof(ctx->tail));
	ctx->tail_len = 0;
	ctx->ivlen = 0;	/* SET_IV/GEN_IV required before next UPDATE */

	/*
	 * Reset the CBC chaining register to zero.  The key schedule in
	 * ctx->aes is unchanged — wc_AesSetKey was called once in sess_init
	 * and is valid for the session lifetime.  Only aes->reg (the IV /
	 * last-ciphertext-block chaining value) needs to be zeroed so that the
	 * next SET_IV / GEN_IV call starts from a clean state.
	 *
	 * Storing a plaintext copy of the raw key bytes purely for re-keying
	 * would create an additional heap-disclosable copy of the key material.
	 * wc_AesSetIV(NULL) avoids that by resetting only the IV register.
	 */
	ret = wc_AesSetIV(&ctx->aes, NULL);
	if (ret != 0) {
		pr_err_ratelimited("%s: wc_AesSetIV returned %d\n",
				   __func__, ret);
		return wolfssl_cbc_xlat_err(ret);
	}

	return 0;
}

static void wolfssl_aes_cbc_sess_free(void *ctx_)
{
	struct wolfssl_aes_cbc_ctx *ctx = ctx_;

	if (!ctx)
		return;

	if (ctx->inited) {
		wc_FreeRng(&ctx->rng);
		wc_AesFree(&ctx->aes);
	}

	memzero_explicit(ctx, sizeof(*ctx));
	kfree(ctx);
}

static int wolfssl_aes_cbc_gen_iv(void *ctx_, u8 *iv, u32 ivlen)
{
	struct wolfssl_aes_cbc_ctx *ctx = ctx_;
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!ctx || !iv || ivlen != WC_AES_BLOCK_SIZE)
		return -EINVAL;

	/* FIPS 140-3: generate IV from the wolfCrypt approved DRBG. */
	ret = wc_RNG_GenerateBlock(&ctx->rng, iv, ivlen);
	if (ret != 0) {
		pr_err_ratelimited("%s: wc_RNG_GenerateBlock returned %d\n",
				   __func__, ret);
		return wolfssl_cbc_xlat_err(ret);
	}
	ctx->ivlen = ivlen;	/* IV successfully generated */
	return 0;
}

static int wolfssl_aes_cbc_set_iv(void *ctx_, const u8 *iv, u32 ivlen)
{
	struct wolfssl_aes_cbc_ctx *ctx = ctx_;
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!ctx || !iv)
		return -EINVAL;

	if (ivlen != WC_AES_BLOCK_SIZE)
		return -EINVAL;

	ret = wc_AesSetIV(&ctx->aes, iv);
	if (ret != 0) {
		pr_err_ratelimited("%s: wc_AesSetIV returned %d\n",
				   __func__, ret);
		return wolfssl_cbc_xlat_err(ret);
	}
	ctx->ivlen = ivlen;	/* IV successfully committed to wc state */
	return 0;
}

static int wolfssl_aes_cbc_update(void *ctx_, const u8 *in, size_t inlen,
				   u8 *out, size_t outbuf_size, size_t *outlen)
{
	struct wolfssl_aes_cbc_ctx *ctx = ctx_;
	size_t combined, to_process, full_blocks;
	size_t out_prod = 0;
	int ret;

	/* FIPS 140-3: gate before any crypto state is touched. */
	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!ctx || !in || inlen == 0)
		return -EINVAL;

	/* FIPS 140-3: CBC encryption with a zero IV is cryptographically weak
	 * (deterministic IV = same key+IV pair for every session).  Require
	 * SET_IV or GEN_IV before the first UPDATE.  Mirrors the check in the
	 * GCM and kcapi CBC providers. */
	if (ctx->ivlen == 0)
		return -EINVAL;

	*outlen = 0;

	combined   = ctx->tail_len + inlen;
	to_process = (combined / WC_AES_BLOCK_SIZE) * WC_AES_BLOCK_SIZE;

	if (to_process == 0) {
		/* Not enough for a full block yet — append to tail */
		memcpy(ctx->tail + ctx->tail_len, in, inlen);
		ctx->tail_len += (u32)inlen;
		return 0;
	}

	if (outbuf_size < to_process)
		return -EMSGSIZE;

	/*
	 * Phase 1: if there are leftover bytes from a previous update(),
	 * complete the first block by drawing bytes from 'in'.
	 */
	if (ctx->tail_len > 0) {
		u32 need = WC_AES_BLOCK_SIZE - ctx->tail_len;

		memcpy(ctx->tail + ctx->tail_len, in, need);
		in    += need;
		inlen -= need;

		if (ctx->op == CRYPTO2DEV_OP_ENCRYPT)
			ret = wc_AesCbcEncrypt(&ctx->aes, out, ctx->tail,
					       WC_AES_BLOCK_SIZE);
		else
			ret = wc_AesCbcDecrypt(&ctx->aes, out, ctx->tail,
					       WC_AES_BLOCK_SIZE);
		if (ret != 0) {
			pr_err_ratelimited("%s: wc_AesCbc%s returned %d\n",
					   __func__,
					   ctx->op == CRYPTO2DEV_OP_ENCRYPT ?
					   "Encrypt" : "Decrypt", ret);
			return wolfssl_cbc_xlat_err(ret);
		}
		out      += WC_AES_BLOCK_SIZE;
		out_prod += WC_AES_BLOCK_SIZE;
		memzero_explicit(ctx->tail, WC_AES_BLOCK_SIZE);
		ctx->tail_len = 0;
	}

	/*
	 * Phase 2: process remaining full blocks directly from 'in'.
	 * wolfCrypt maintains CBC chaining state (last ciphertext block)
	 * inside ctx->aes across calls — no IV copy-back needed.
	 */
	full_blocks = (inlen / WC_AES_BLOCK_SIZE) * WC_AES_BLOCK_SIZE;
	if (full_blocks > 0) {
		if (ctx->op == CRYPTO2DEV_OP_ENCRYPT)
			ret = wc_AesCbcEncrypt(&ctx->aes, out, in,
					       full_blocks);
		else
			ret = wc_AesCbcDecrypt(&ctx->aes, out, in,
					       full_blocks);
		if (ret != 0) {
			pr_err_ratelimited("%s: wc_AesCbc%s returned %d\n",
					   __func__,
					   ctx->op == CRYPTO2DEV_OP_ENCRYPT ?
					   "Encrypt" : "Decrypt", ret);
			return wolfssl_cbc_xlat_err(ret);
		}
		out_prod += full_blocks;
		in       += full_blocks;
		inlen    -= full_blocks;
	}

	/* Phase 3: save any remaining bytes into the tail */
	if (inlen > 0) {
		memcpy(ctx->tail, in, inlen);
		ctx->tail_len = (u32)inlen;
	}

	*outlen = out_prod;
	return 0;
}

static int wolfssl_aes_cbc_finalize(void *ctx_, u8 *out, size_t outbuf_size,
				     size_t *outlen)
{
	struct wolfssl_aes_cbc_ctx *ctx = ctx_;
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!ctx || !out || !outlen)
		return -EINVAL;

	(void)outbuf_size;

	/*
	 * CBC requires block-aligned input.  A non-zero tail means the total
	 * input was not a multiple of WC_AES_BLOCK_SIZE — reject.
	 */
	if (ctx->tail_len != 0) {
		pr_err("wolfssl_cbc finalize: non-block-aligned input (%u tail bytes)\n",
		       ctx->tail_len);
		return -EINVAL;
	}

	*outlen = 0;
	return 0;
}

const struct crypto2dev_algo_ops wolfssl_aes_cbc_ops = {
	.algo       = "cbc(aes)",
	.fips_gate  = wolfssl_fips_gate,
	.sess_init  = wolfssl_aes_cbc_sess_init,
	.sess_free  = wolfssl_aes_cbc_sess_free,
	.set_iv     = wolfssl_aes_cbc_set_iv,
	.gen_iv     = wolfssl_aes_cbc_gen_iv,
	.set_aad    = NULL,
	.set_tag    = NULL,
	.get_tag    = NULL,
	.sign               = NULL,
	.verify             = NULL,
	.agree              = NULL,
	.sess_reset         = wolfssl_aes_cbc_sess_reset,
	.update     = wolfssl_aes_cbc_update,
	.finalize   = wolfssl_aes_cbc_finalize,
	.key_import         = NULL,
	.key_generate       = NULL,
	.key_export_public  = NULL,
	.key_export_private = NULL,
	.key_free           = NULL,
};
