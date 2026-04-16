// SPDX-License-Identifier: GPL-2.0-only
/*
 * crypto2dev — kernel crypto API skcipher provider
 *
 * Implements crypto2dev_algo_ops for cbc(aes), ctr(aes), and xts(aes)
 * using the Linux kernel's crypto_alloc_skcipher interface.
 */

#define pr_fmt(fmt) "crypto2dev_kcapi: " fmt

#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/scatterlist.h>
#include <crypto/skcipher.h>

#include "../../../include/uapi/crypto2dev_ioctl.h"
#include "kcapi_provider.h"

/*
 * Maximum cipher block size we accommodate.  All three supported algorithms
 * (cbc(aes), ctr(aes), xts(aes)) use AES which has a 16-byte block.
 */
#define KCAPI_SKCIPHER_BLOCK_MAX  16U

struct kcapi_skcipher_ctx {
	struct crypto_skcipher *tfm;
	const char             *algo;   /* pointer to static string, e.g. "cbc(aes)" */
	u32                     op;     /* CRYPTO2DEV_OP_ENCRYPT or DECRYPT */
	u8                      iv[CRYPTO2DEV_IV_MAXLEN];
	u32                     ivlen;
	/*
	 * Streaming tail: bytes not yet processed because they did not fill a
	 * complete cipher block.  For CTR mode (block_size == 1) this is always
	 * empty.  For CBC/XTS (block_size == 16) we hold up to 15 bytes here
	 * until update() or finalize() can complete the block.
	 *
	 * IV chaining: ctx->iv is passed directly to skcipher_request_set_crypt().
	 * The kernel updates it in-place after each encrypt/decrypt call (CBC: last
	 * ciphertext block; CTR: incremented counter), so chained streaming calls
	 * automatically see the correct IV.
	 */
	u8                      tail[KCAPI_SKCIPHER_BLOCK_MAX];
	u32                     tail_len;
	u32                     block_size;
};

/*
 * Shared initializer — called by the three thin wrappers below.
 */
static int kcapi_skcipher_sess_init(void **ctx_out, u32 op,
				    const u8 *key, u32 keylen,
				    const char *algo)
{
	struct kcapi_skcipher_ctx *ctx;
	struct crypto_skcipher    *tfm;
	int ret;

	if (op != CRYPTO2DEV_OP_ENCRYPT && op != CRYPTO2DEV_OP_DECRYPT)
		return -EINVAL;

	if (!key || keylen == 0)
		return -EINVAL;

	/* FIPS 140-3: AES minimum key size is 128 bits (16 bytes).
	 * Only standard AES key sizes are permitted.
	 */
	if (keylen != 16 && keylen != 24 && keylen != 32)
		return -EINVAL;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	tfm = crypto_alloc_skcipher(algo, 0, 0);
	if (IS_ERR(tfm)) {
		ret = PTR_ERR(tfm);
		pr_err("crypto_alloc_skcipher(%s) failed: %d\n", algo, ret);
		goto err_free_ctx;
	}

	ret = crypto_skcipher_setkey(tfm, key, keylen);
	if (ret < 0) {
		pr_err("crypto_skcipher_setkey(%s) failed: %d\n", algo, ret);
		goto err_free_tfm;
	}

	ctx->tfm        = tfm;
	ctx->algo       = algo;
	ctx->op         = op;
	ctx->block_size = crypto_skcipher_blocksize(tfm);

	*ctx_out = ctx;
	return 0;

err_free_tfm:
	crypto_free_skcipher(tfm);
err_free_ctx:
	kfree(ctx);
	return ret;
}

static int kcapi_skcipher_sess_reset(void *ctx_in)
{
	struct kcapi_skcipher_ctx *ctx = ctx_in;

	if (!ctx || !ctx->tfm)
		return -EINVAL;

	/* Clear IV — caller must re-supply via SET_IV / GEN_IV */
	memzero_explicit(ctx->iv, sizeof(ctx->iv));
	ctx->ivlen = 0;

	/* Clear streaming tail */
	memzero_explicit(ctx->tail, sizeof(ctx->tail));
	ctx->tail_len = 0;

	return 0;
}

static void kcapi_skcipher_sess_free(void *ctx_in)
{
	struct kcapi_skcipher_ctx *ctx = ctx_in;

	if (!ctx)
		return;

	if (ctx->tfm)
		crypto_free_skcipher(ctx->tfm);

	memzero_explicit(ctx, sizeof(*ctx));
	kfree(ctx);
}

static int kcapi_skcipher_set_iv(void *ctx_in, const u8 *iv, u32 ivlen)
{
	struct kcapi_skcipher_ctx *ctx = ctx_in;
	unsigned int expected;

	if (!iv || ivlen == 0 || ivlen > CRYPTO2DEV_IV_MAXLEN)
		return -EINVAL;

	expected = crypto_skcipher_ivsize(ctx->tfm);
	if (ivlen != expected) {
		pr_err("set_iv: expected %u bytes for %s, got %u\n",
		       expected, ctx->algo, ivlen);
		return -EINVAL;
	}

	memcpy(ctx->iv, iv, ivlen);
	ctx->ivlen = ivlen;
	return 0;
}

static int kcapi_skcipher_gen_iv(void *ctx_in, u8 *iv, u32 ivlen)
{
	struct kcapi_skcipher_ctx *ctx = ctx_in;
	unsigned int expected;

	if (!ctx || !iv || ivlen == 0 || ivlen > CRYPTO2DEV_IV_MAXLEN)
		return -EINVAL;

	expected = crypto_skcipher_ivsize(ctx->tfm);
	if (ivlen != expected)
		return -EINVAL;

	get_random_bytes(iv, ivlen);
	return 0;
}

static int kcapi_skcipher_update(void *ctx_in, const u8 *in, size_t inlen,
				  u8 *out, size_t outbuf_size, size_t *outlen)
{
	struct kcapi_skcipher_ctx *ctx = ctx_in;
	struct skcipher_request   *req;
	struct scatterlist         src_sg, dst_sg;
	DECLARE_CRYPTO_WAIT(wait);
	size_t combined, to_process, consumed;
	u8    *tmp = NULL;
	int    ret = 0;

	if (!ctx || !in || inlen == 0)
		return -EINVAL;
	if (ctx->ivlen == 0)
		return -EINVAL;

	*outlen = 0;

	combined   = ctx->tail_len + inlen;
	to_process = (combined / ctx->block_size) * ctx->block_size;

	if (to_process == 0) {
		/* Not a full block yet — append to tail */
		if (ctx->tail_len + inlen > sizeof(ctx->tail))
			return -EMSGSIZE;
		memcpy(ctx->tail + ctx->tail_len, in, inlen);
		ctx->tail_len += inlen;
		return 0;
	}

	if (outbuf_size < to_process)
		return -EMSGSIZE;

	consumed = to_process - ctx->tail_len;   /* bytes consumed from 'in' */

	req = skcipher_request_alloc(ctx->tfm, GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	skcipher_request_set_callback(req,
				      CRYPTO_TFM_REQ_MAY_BACKLOG |
				      CRYPTO_TFM_REQ_MAY_SLEEP,
				      crypto_req_done, &wait);

	if (ctx->tail_len > 0) {
		/*
		 * Must prepend tail bytes to form a complete block —
		 * allocate a contiguous combined input buffer.
		 */
		tmp = kmalloc(to_process, GFP_KERNEL);
		if (!tmp) {
			ret = -ENOMEM;
			goto out;
		}
		memcpy(tmp, ctx->tail, ctx->tail_len);
		memcpy(tmp + ctx->tail_len, in, consumed);
		sg_init_one(&src_sg, tmp, to_process);
	} else {
		sg_init_one(&src_sg, in, to_process);
	}

	sg_init_one(&dst_sg, out, to_process);
	/*
	 * Pass ctx->iv directly.  The kernel updates this buffer in-place
	 * after each encrypt/decrypt: for CBC it holds the last ciphertext
	 * block (the IV for the next call); for CTR it holds the incremented
	 * counter.  No explicit IV copy-back is required.
	 */
	skcipher_request_set_crypt(req, &src_sg, &dst_sg, to_process, ctx->iv);

	if (ctx->op == CRYPTO2DEV_OP_ENCRYPT)
		ret = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
	else
		ret = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);

out:
	skcipher_request_free(req);
	kfree(tmp);

	if (ret < 0) {
		pr_err_ratelimited("update: %s %s failed: %d\n",
				   ctx->algo,
				   ctx->op == CRYPTO2DEV_OP_ENCRYPT ?
					"encrypt" : "decrypt",
				   ret);
		return ret;
	}

	*outlen = to_process;

	/* Save bytes from 'in' not yet processed into the tail */
	ctx->tail_len = inlen - consumed;
	if (ctx->tail_len > 0)
		memcpy(ctx->tail, in + consumed, ctx->tail_len);
	else
		memzero_explicit(ctx->tail, sizeof(ctx->tail));

	return 0;
}

static int kcapi_skcipher_finalize(void *ctx_in, u8 *out, size_t outbuf_size,
				    size_t *outlen)
{
	struct kcapi_skcipher_ctx *ctx = ctx_in;
	struct skcipher_request   *req;
	struct scatterlist         src_sg, dst_sg;
	DECLARE_CRYPTO_WAIT(wait);
	int ret;

	if (!ctx || !out || !outlen)
		return -EINVAL;

	if (ctx->tail_len == 0) {
		*outlen = 0;
		return 0;
	}

	/*
	 * A non-zero tail means total input was not block-aligned.
	 * CBC and XTS require block-aligned input; reject with -EINVAL.
	 * CTR (block_size == 1) never accumulates a tail.
	 */
	if (ctx->block_size > 1) {
		pr_err("finalize: %s: non-block-aligned input (%u tail bytes)\n",
		       ctx->algo, ctx->tail_len);
		return -EINVAL;
	}

	/* CTR/stream: encrypt/decrypt the partial tail */
	if (outbuf_size < ctx->tail_len)
		return -EMSGSIZE;

	req = skcipher_request_alloc(ctx->tfm, GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	skcipher_request_set_callback(req,
				      CRYPTO_TFM_REQ_MAY_BACKLOG |
				      CRYPTO_TFM_REQ_MAY_SLEEP,
				      crypto_req_done, &wait);

	sg_init_one(&src_sg, ctx->tail, ctx->tail_len);
	sg_init_one(&dst_sg, out, ctx->tail_len);
	skcipher_request_set_crypt(req, &src_sg, &dst_sg, ctx->tail_len,
				   ctx->iv);

	if (ctx->op == CRYPTO2DEV_OP_ENCRYPT)
		ret = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
	else
		ret = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);

	skcipher_request_free(req);

	if (ret < 0) {
		pr_err("finalize: %s %s tail failed: %d\n",
		       ctx->algo,
		       ctx->op == CRYPTO2DEV_OP_ENCRYPT ? "encrypt" : "decrypt",
		       ret);
		return ret;
	}

	*outlen = ctx->tail_len;
	memzero_explicit(ctx->tail, sizeof(ctx->tail));
	ctx->tail_len = 0;
	return 0;
}

/* Thin wrappers — one per algorithm */

static int cbc_sess_init(void **ctx, u32 op, const u8 *key, u32 keylen)
{
	return kcapi_skcipher_sess_init(ctx, op, key, keylen, "cbc(aes)");
}

static int ctr_sess_init(void **ctx, u32 op, const u8 *key, u32 keylen)
{
	return kcapi_skcipher_sess_init(ctx, op, key, keylen, "ctr(aes)");
}

static int xts_sess_init(void **ctx, u32 op, const u8 *key, u32 keylen)
{
	return kcapi_skcipher_sess_init(ctx, op, key, keylen, "xts(aes)");
}

/* Public ops tables */

const struct crypto2dev_algo_ops kcapi_cbc_aes_ops = {
	.algo               = "cbc(aes)",
	.fips_gate          = NULL,
	.sess_init          = cbc_sess_init,
	.sess_free          = kcapi_skcipher_sess_free,
	.set_iv             = kcapi_skcipher_set_iv,
	.gen_iv             = kcapi_skcipher_gen_iv,
	.set_aad            = NULL,
	.set_tag            = NULL,
	.get_tag            = NULL,
	.sign               = NULL,
	.verify             = NULL,
	.agree              = NULL,
	.sess_reset         = kcapi_skcipher_sess_reset,
	.update             = kcapi_skcipher_update,
	.finalize           = kcapi_skcipher_finalize,
	.key_import         = NULL,
	.key_generate       = NULL,
	.key_export_public  = NULL,
	.key_export_private = NULL,
	.key_free           = NULL,
};

const struct crypto2dev_algo_ops kcapi_ctr_aes_ops = {
	.algo               = "ctr(aes)",
	.fips_gate          = NULL,
	.sess_init          = ctr_sess_init,
	.sess_free          = kcapi_skcipher_sess_free,
	.set_iv             = kcapi_skcipher_set_iv,
	.gen_iv             = kcapi_skcipher_gen_iv,
	.set_aad            = NULL,
	.set_tag            = NULL,
	.get_tag            = NULL,
	.sign               = NULL,
	.verify             = NULL,
	.agree              = NULL,
	.sess_reset         = kcapi_skcipher_sess_reset,
	.update             = kcapi_skcipher_update,
	.finalize           = kcapi_skcipher_finalize,
	.key_import         = NULL,
	.key_generate       = NULL,
	.key_export_public  = NULL,
	.key_export_private = NULL,
	.key_free           = NULL,
};

const struct crypto2dev_algo_ops kcapi_xts_aes_ops = {
	.algo               = "xts(aes)",
	.fips_gate          = NULL,
	.sess_init          = xts_sess_init,
	.sess_free          = kcapi_skcipher_sess_free,
	.set_iv             = kcapi_skcipher_set_iv,
	.gen_iv             = kcapi_skcipher_gen_iv,
	.set_aad            = NULL,
	.set_tag            = NULL,
	.get_tag            = NULL,
	.sign               = NULL,
	.verify             = NULL,
	.agree              = NULL,
	.sess_reset         = kcapi_skcipher_sess_reset,
	.update             = kcapi_skcipher_update,
	.finalize           = kcapi_skcipher_finalize,
	.key_import         = NULL,
	.key_generate       = NULL,
	.key_export_public  = NULL,
	.key_export_private = NULL,
	.key_free           = NULL,
};
