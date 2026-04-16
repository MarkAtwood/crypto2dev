// SPDX-License-Identifier: GPL-2.0-only
/*
 * crypto2dev wolfSSL provider — AES-GCM
 *
 * Implements the crypto2dev_algo_ops vtable for "gcm(aes)" using wolfCrypt.
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

#define WOLFSSL_GCM_IV_SIZE   12
#define WOLFSSL_GCM_TAG_SIZE  16

/* Session context */
struct wolfssl_aes_gcm_ctx {
	Aes    aes;
	WC_RNG rng;    /* DRBG for GEN_IV — stays within FIPS boundary */
	bool inited;
	u32  op;
	u8   iv[WOLFSSL_GCM_IV_SIZE];
	u32  ivlen;
	u8  *aad;
	u32  aadlen;
	u8   tag[WOLFSSL_GCM_TAG_SIZE];
	u32  taglen;
	bool processed;
	/*
	 * Unified inbuf for both encrypt and decrypt paths.
	 *
	 * Encrypt: plaintext is buffered here and encrypted atomically at
	 * FINALIZE via wc_AesGcmEncrypt().  Ciphertext and tag are produced
	 * together — no unauthenticated ciphertext is released before the
	 * tag is computed.  This matches the kcapi AEAD provider's batch
	 * model so both providers present the same UAPI contract: callers
	 * read all ciphertext only after FINALIZE.
	 *
	 * Decrypt: batch accumulation is architecturally required —
	 * unauthenticated plaintext must not be released before the tag is
	 * verified.  inbuf holds the full ciphertext; finalize() verifies
	 * the tag and then decrypts into the caller-supplied output buffer.
	 *
	 * Growth: doubling strategy — O(n) total allocations across n
	 * update() calls, not O(n^2).
	 */
	u8  *inbuf;
	size_t inbuf_len;
	size_t inbuf_cap;
};

/* Translate wolfCrypt error codes to kernel errno */
static int wolfssl_gcm_xlat_err(int wc_err)
{
	switch (wc_err) {
	case -173: /* BAD_FUNC_ARG */
		return -EINVAL;
	case -125: /* MEMORY_E */
		return -ENOMEM;
	case AES_GCM_AUTH_E:		/* GCM authentication tag mismatch */
		return -EBADMSG;
	case FIPS_NOT_ALLOWED_E:	/* operation not allowed in FIPS mode */
		return -EACCES;
	case FIPS_DEGRADED_E:		/* FIPS module in degraded state */
		return -EACCES;
	default:
		pr_err_ratelimited("wolfssl: unhandled wc_err=%d\n", wc_err);
		return -EIO;
	}
}

static int wolfssl_aes_gcm_sess_init(void **out_ctx, u32 op,
				     const u8 *key, u32 keylen)
{
	struct wolfssl_aes_gcm_ctx *ctx;
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
		pr_err_ratelimited("%s: wc_AesInit returned %d\n",
				   __func__, ret);
		goto err_free_ctx;
	}

	ret = wc_AesGcmSetKey(&ctx->aes, key, keylen);
	if (ret != 0) {
		pr_err_ratelimited("%s: wc_AesGcmSetKey returned %d\n",
				   __func__, ret);
		wc_AesFree(&ctx->aes);
		goto err_free_ctx;
	}

	ret = wc_InitRng_ex(&ctx->rng, NULL, INVALID_DEVID);
	if (ret != 0) {
		pr_err_ratelimited("%s: wc_InitRng_ex returned %d\n",
				   __func__, ret);
		wc_AesFree(&ctx->aes);
		goto err_free_ctx;
	}

	ctx->inited = true;
	*out_ctx = ctx;
	return 0;

err_free_ctx:
	memzero_explicit(ctx, sizeof(*ctx));	/* FIPS 140-3: zero key schedule before free */
	kfree(ctx);
	return wolfssl_gcm_xlat_err(ret);
}

static int wolfssl_aes_gcm_sess_reset(void *ctx_)
{
	struct wolfssl_aes_gcm_ctx *ctx = ctx_;
	int ret;

	/* FIPS 140-3: gate before any crypto state is touched. */
	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!ctx || !ctx->inited)
		return -EINVAL;

	/* Clear IV — caller must re-supply via SET_IV / GEN_IV */
	memzero_explicit(ctx->iv, sizeof(ctx->iv));
	ctx->ivlen = 0;

	/* Clear AAD */
	if (ctx->aad) {
		memzero_explicit(ctx->aad, ctx->aadlen);
		kfree(ctx->aad);
		ctx->aad    = NULL;
		ctx->aadlen = 0;
	}

	/* Clear tag */
	memzero_explicit(ctx->tag, sizeof(ctx->tag));
	ctx->taglen = 0;

	ctx->processed = false;

	/* Clear accumulated input; keep buffer allocated for reuse */
	if (ctx->inbuf)
		memzero_explicit(ctx->inbuf, ctx->inbuf_cap);
	ctx->inbuf_len = 0;

	/*
	 * The AES key remains programmed in ctx->aes (set via
	 * wc_AesGcmSetKey during sess_init).  No re-keying is needed.
	 */

	return 0;
}

static void wolfssl_aes_gcm_sess_free(void *ctx_)
{
	struct wolfssl_aes_gcm_ctx *ctx = ctx_;

	if (!ctx)
		return;

	if (ctx->inited) {
		wc_FreeRng(&ctx->rng);
		wc_AesFree(&ctx->aes);
	}

	if (ctx->aad) {
		memzero_explicit(ctx->aad, ctx->aadlen);
		kfree(ctx->aad);
	}

	if (ctx->inbuf) {
		memzero_explicit(ctx->inbuf, ctx->inbuf_cap);
		kfree(ctx->inbuf);
	}

	memzero_explicit(ctx, sizeof(*ctx));
	kfree(ctx);
}

static int wolfssl_aes_gcm_gen_iv(void *ctx_, u8 *iv, u32 ivlen)
{
	struct wolfssl_aes_gcm_ctx *ctx = ctx_;
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!ctx || !iv || ivlen != WOLFSSL_GCM_IV_SIZE)
		return -EINVAL;

	/* FIPS 140-3: generate IV from the wolfCrypt approved DRBG. */
	ret = wc_RNG_GenerateBlock(&ctx->rng, iv, ivlen);
	if (ret != 0) {
		pr_err_ratelimited("%s: wc_RNG_GenerateBlock returned %d\n",
				   __func__, ret);
		return wolfssl_gcm_xlat_err(ret);
	}
	return 0;
}

static int wolfssl_aes_gcm_set_iv(void *ctx_, const u8 *iv, u32 ivlen)
{
	struct wolfssl_aes_gcm_ctx *ctx = ctx_;
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!ctx || !iv)
		return -EINVAL;

	/*
	 * GCM nonce must be exactly 12 bytes for the standard 96-bit IV
	 * construction.  Shorter or longer values require a different GHASH
	 * derivation path not supported here.
	 */
	if (ivlen != WOLFSSL_GCM_IV_SIZE)
		return -EINVAL;

	memcpy(ctx->iv, iv, ivlen);
	ctx->ivlen = ivlen;
	return 0;
}

static int wolfssl_aes_gcm_set_aad(void *ctx_, const u8 *aad, u32 aadlen)
{
	struct wolfssl_aes_gcm_ctx *ctx = ctx_;
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!ctx)
		return -EINVAL;

	/* Replace any previously stored AAD */
	if (ctx->aad) {
		memzero_explicit(ctx->aad, ctx->aadlen);
		kfree(ctx->aad);
		ctx->aad    = NULL;
		ctx->aadlen = 0;
	}

	if (!aad || aadlen == 0)
		return 0;

	ctx->aad = kmalloc(aadlen, GFP_KERNEL);
	if (!ctx->aad)
		return -ENOMEM;

	memcpy(ctx->aad, aad, aadlen);
	ctx->aadlen = aadlen;
	return 0;
}

static int wolfssl_aes_gcm_set_tag(void *ctx_, const u8 *tag, u32 taglen)
{
	struct wolfssl_aes_gcm_ctx *ctx = ctx_;
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!ctx || !tag)
		return -EINVAL;

	/* FIPS 140-3 SP 800-38D: authentication tag must be at least 96 bits (12 bytes). */
	if (taglen < 12 || taglen > WOLFSSL_GCM_TAG_SIZE)
		return -EINVAL;

	memcpy(ctx->tag, tag, taglen);
	ctx->taglen = taglen;
	return 0;
}

static int wolfssl_aes_gcm_get_tag(void *ctx_, u8 *tag, u32 *taglen)
{
	struct wolfssl_aes_gcm_ctx *ctx = ctx_;
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!ctx || !tag || !taglen)
		return -EINVAL;

	if (ctx->op != CRYPTO2DEV_OP_ENCRYPT)
		return -EINVAL;

	if (!ctx->processed || ctx->taglen == 0)
		return -EINVAL;

	memcpy(tag, ctx->tag, ctx->taglen);
	*taglen = ctx->taglen;
	return 0;
}

/*
 * gcm_inbuf_append — append @inlen bytes from @in to ctx->inbuf.
 *
 * Uses a doubling growth strategy: O(n) total allocations for n calls,
 * not O(n^2).  Each superseded buffer is zeroized before freeing per
 * FIPS 140-3 (the data held is plaintext or ciphertext under active use).
 */
static int gcm_inbuf_append(struct wolfssl_aes_gcm_ctx *ctx,
			    const u8 *in, size_t inlen)
{
	size_t new_len = ctx->inbuf_len + inlen;

	if (new_len > CRYPTO2DEV_MAX_PAYLOAD)
		return -EMSGSIZE;

	if (new_len > ctx->inbuf_cap) {
		size_t new_cap = ctx->inbuf_cap ? ctx->inbuf_cap * 2 : 4096;
		u8    *new_buf;

		while (new_cap < new_len)
			new_cap *= 2;
		if (new_cap > CRYPTO2DEV_MAX_PAYLOAD)
			new_cap = CRYPTO2DEV_MAX_PAYLOAD;

		new_buf = kmalloc(new_cap, GFP_KERNEL);
		if (!new_buf)
			return -ENOMEM;
		if (ctx->inbuf) {
			memcpy(new_buf, ctx->inbuf, ctx->inbuf_len);
			/* FIPS 140-3: zero old buffer before freeing. */
			memzero_explicit(ctx->inbuf, ctx->inbuf_cap);
			kfree(ctx->inbuf);
		}
		ctx->inbuf     = new_buf;
		ctx->inbuf_cap = new_cap;
	}

	memcpy(ctx->inbuf + ctx->inbuf_len, in, inlen);
	ctx->inbuf_len += inlen;
	return 0;
}

static int wolfssl_aes_gcm_update(void *ctx_, const u8 *in, size_t inlen,
				   u8 *out, size_t outbuf_size, size_t *outlen)
{
	struct wolfssl_aes_gcm_ctx *ctx = ctx_;
	int ret;

	/* FIPS 140-3: gate before any crypto state is touched. */
	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!ctx || !in || inlen == 0)
		return -EINVAL;

	/*
	 * Both encrypt and decrypt buffer all input until FINALIZE.
	 *
	 * Encrypt: plaintext is buffered here; finalize() encrypts everything
	 * and produces ciphertext + tag atomically via wc_AesGcmEncrypt().
	 * No ciphertext is released before the tag is computed — consistent
	 * with the kcapi AEAD provider and safe against plaintext oracle if
	 * a caller abandons the session before FINALIZE.
	 *
	 * Decrypt: ciphertext is buffered here; finalize() verifies the tag
	 * and decrypts only on success — no unauthenticated plaintext leaks.
	 *
	 * IV must be set before the first update().
	 */
	if (ctx->ivlen == 0)
		return -EINVAL;

	ret = gcm_inbuf_append(ctx, in, inlen);
	if (ret)
		return ret;

	(void)out;
	(void)outbuf_size;
	*outlen = 0;   /* output is deferred to finalize() */
	return 0;
}

static int wolfssl_aes_gcm_finalize(void *ctx_, u8 *out, size_t outbuf_size,
				     size_t *outlen)
{
	struct wolfssl_aes_gcm_ctx *ctx = ctx_;
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!ctx || !out || !outlen)
		return -EINVAL;

	if (ctx->op == CRYPTO2DEV_OP_ENCRYPT) {
		/*
		 * Batch encrypt: all plaintext was buffered by update().
		 * Encrypt and authenticate in one shot — ciphertext and tag
		 * are produced together so the caller never receives
		 * unauthenticated ciphertext.
		 */
		size_t inlen = ctx->inbuf_len;

		if (ctx->ivlen == 0)
			return -EINVAL;

		if (outbuf_size < inlen)
			return -EMSGSIZE;

		/*
		 * wc_AesGcmEncrypt: one-shot encrypt + GHASH.
		 * Key was set in sess_init via wc_AesGcmSetKey.
		 * Ciphertext written to out; tag stored in ctx->tag for
		 * retrieval via GET_TAG.  Zero ciphertext on error per
		 * FIPS 140-3 — caller must not use partial output.
		 */
		ret = wc_AesGcmEncrypt(&ctx->aes,
				       inlen ? out : NULL,
				       inlen ? ctx->inbuf : NULL,
				       (word32)inlen,
				       ctx->iv, ctx->ivlen,
				       ctx->tag, WOLFSSL_GCM_TAG_SIZE,
				       ctx->aad, ctx->aadlen);
		if (ret != 0) {
			pr_err_ratelimited("%s: wc_AesGcmEncrypt returned %d\n",
					   __func__, ret);
			if (inlen)
				memzero_explicit(out, inlen);
			return wolfssl_gcm_xlat_err(ret);
		}
		ctx->taglen    = WOLFSSL_GCM_TAG_SIZE;
		ctx->processed = true;
		*outlen        = inlen;

	} else {
		/*
		 * Batch decrypt: verify the tag over the full ciphertext and
		 * AAD, then decrypt into caller's buffer.  No plaintext is
		 * released until the tag check passes.
		 */
		size_t inlen = ctx->inbuf_len;

		if (inlen == 0)
			return -EINVAL;

		if (ctx->ivlen == 0)
			return -EINVAL;

		if (ctx->taglen == 0)
			return -EINVAL;

		if (outbuf_size < inlen)
			return -EMSGSIZE;

		ret = wc_AesGcmDecrypt(&ctx->aes,
				       out, ctx->inbuf, (word32)inlen,
				       ctx->iv, ctx->ivlen,
				       ctx->tag, ctx->taglen,
				       ctx->aad, ctx->aadlen);
		if (ret != 0) {
			pr_err_ratelimited("%s: wc_AesGcmDecrypt returned %d\n",
					   __func__, ret);
			return wolfssl_gcm_xlat_err(ret);
		}
		ctx->processed = true;
		*outlen = inlen;
	}

	return 0;
}

static size_t wolfssl_aes_gcm_get_finalize_output_size(void *ctx_)
{
	struct wolfssl_aes_gcm_ctx *ctx = ctx_;

	if (!ctx)
		return 0;
	/*
	 * For both encrypt and decrypt, finalize() outputs exactly
	 * inbuf_len bytes (ciphertext == plaintext length for GCM).
	 * The tag is stored separately in ctx->tag; it is not written
	 * to the outbuf — callers retrieve it via GET_TAG.
	 */
	return ctx->inbuf_len;
}

const struct crypto2dev_algo_ops wolfssl_aes_gcm_ops = {
	.algo       = "gcm(aes)",
	.fips_gate  = wolfssl_fips_gate,
	.sess_init  = wolfssl_aes_gcm_sess_init,
	.sess_free  = wolfssl_aes_gcm_sess_free,
	.set_iv     = wolfssl_aes_gcm_set_iv,
	.gen_iv     = wolfssl_aes_gcm_gen_iv,
	.set_aad    = wolfssl_aes_gcm_set_aad,
	.set_tag    = wolfssl_aes_gcm_set_tag,
	.get_tag    = wolfssl_aes_gcm_get_tag,
	.sign               = NULL,
	.verify             = NULL,
	.agree              = NULL,
	.sess_reset         = wolfssl_aes_gcm_sess_reset,
	.update                   = wolfssl_aes_gcm_update,
	.finalize                 = wolfssl_aes_gcm_finalize,
	.get_finalize_output_size = wolfssl_aes_gcm_get_finalize_output_size,
	.key_import               = NULL,
	.key_generate       = NULL,
	.key_export_public  = NULL,
	.key_export_private = NULL,
	.key_free           = NULL,
};
