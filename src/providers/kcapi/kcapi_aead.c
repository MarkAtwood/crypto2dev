// SPDX-License-Identifier: GPL-2.0-only
#define pr_fmt(fmt) "crypto2dev_kcapi: " fmt

#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/scatterlist.h>
#include <crypto/aead.h>

#include "../../../include/uapi/crypto2dev_ioctl.h"
#include "kcapi_provider.h"

#define GCM_IV_SIZE    12
#define GCM_TAG_SIZE   16

struct kcapi_aead_ctx {
	struct crypto_aead *tfm;
	u32  op;
	u8   iv[16];
	u32  ivlen;
	u8  *aad;
	u32  aadlen;
	u8   tag[16];
	u32  taglen;
	u32  authsize;
	bool processed;
	u8  *inbuf;
	size_t inbuf_len;
	size_t inbuf_cap;
};

static int kcapi_aead_sess_init(void **ctx_out, u32 op,
				const u8 *key, u32 keylen)
{
	struct kcapi_aead_ctx *ctx;
	struct crypto_aead *tfm;
	int ret;

	if (op != CRYPTO2DEV_OP_ENCRYPT && op != CRYPTO2DEV_OP_DECRYPT)
		return -EINVAL;

	if (keylen != 16 && keylen != 24 && keylen != 32)
		return -EINVAL;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(tfm)) {
		ret = PTR_ERR(tfm);
		goto err_free_ctx;
	}

	ret = crypto_aead_setkey(tfm, key, keylen);
	if (ret < 0)
		goto err_free_tfm;

	ret = crypto_aead_setauthsize(tfm, GCM_TAG_SIZE);
	if (ret < 0)
		goto err_free_tfm;

	ctx->tfm      = tfm;
	ctx->op       = op;
	ctx->authsize = GCM_TAG_SIZE;
	*ctx_out      = ctx;
	return 0;

err_free_tfm:
	crypto_free_aead(tfm);
err_free_ctx:
	memzero_explicit(ctx, sizeof(*ctx));
	kfree(ctx);
	return ret;
}

static int kcapi_aead_sess_reset(void *ctx_in)
{
	struct kcapi_aead_ctx *ctx = ctx_in;

	if (!ctx || !ctx->tfm)
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

	/* Clear tag and restore default authsize.
	 * Both ctx->taglen and ctx->authsize must be in sync with the kernel
	 * tfm's authsize. Reset all three to GCM_TAG_SIZE (16) so that a
	 * reused session begins from a known state; set_tag will update if
	 * the caller supplies a shorter tag. crypto_aead_setauthsize cannot
	 * fail for GCM_TAG_SIZE (16 bytes is always valid). */
	memzero_explicit(ctx->tag, sizeof(ctx->tag));
	ctx->taglen  = 0;
	ctx->authsize = GCM_TAG_SIZE;
	/* Restore default authsize — cannot fail for GCM_TAG_SIZE=16 */
	WARN_ON(crypto_aead_setauthsize(ctx->tfm, GCM_TAG_SIZE));

	/* Clear processed flag */
	ctx->processed = false;

	/* Clear accumulated input; keep buffer allocated for reuse */
	if (ctx->inbuf)
		memzero_explicit(ctx->inbuf, ctx->inbuf_cap);
	ctx->inbuf_len = 0;

	return 0;
}

static void kcapi_aead_sess_free(void *ctx_in)
{
	struct kcapi_aead_ctx *ctx = ctx_in;

	if (!ctx)
		return;

	if (ctx->aad) {
		memzero_explicit(ctx->aad, ctx->aadlen);
		kfree(ctx->aad);
	}

	if (ctx->inbuf) {
		memzero_explicit(ctx->inbuf, ctx->inbuf_cap);
		kfree(ctx->inbuf);
	}

	if (ctx->tfm)
		crypto_free_aead(ctx->tfm);

	memzero_explicit(ctx, sizeof(*ctx));
	kfree(ctx);
}

static int kcapi_aead_set_iv(void *ctx_in, const u8 *iv, u32 ivlen)
{
	struct kcapi_aead_ctx *ctx = ctx_in;

	if (ivlen != GCM_IV_SIZE)
		return -EINVAL;

	memcpy(ctx->iv, iv, ivlen);
	ctx->ivlen = ivlen;
	return 0;
}

static int kcapi_aead_gen_iv(void *ctx_in, u8 *iv, u32 ivlen)
{
	(void)ctx_in;

	if (!iv || ivlen != GCM_IV_SIZE)
		return -EINVAL;

	get_random_bytes(iv, ivlen);
	return 0;
}

static int kcapi_aead_set_aad(void *ctx_in, const u8 *aad, u32 aadlen)
{
	struct kcapi_aead_ctx *ctx = ctx_in;

	if (ctx->aad) {
		memzero_explicit(ctx->aad, ctx->aadlen);
		kfree(ctx->aad);
		ctx->aad    = NULL;
		ctx->aadlen = 0;
	}

	if (aadlen == 0) {
		ctx->aad    = NULL;
		ctx->aadlen = 0;
		return 0;
	}

	ctx->aad = kmalloc(aadlen, GFP_KERNEL);
	if (!ctx->aad)
		return -ENOMEM;

	memcpy(ctx->aad, aad, aadlen);
	ctx->aadlen = aadlen;
	return 0;
}

static int kcapi_aead_set_tag(void *ctx_in, const u8 *tag, u32 taglen)
{
	struct kcapi_aead_ctx *ctx = ctx_in;
	int ret;

	/* FIPS 140-3 SP 800-38D: authentication tag must be at least 96 bits (12 bytes). */
	if (taglen < 12 || taglen > GCM_TAG_SIZE)
		return -EINVAL;

	/* Update the kernel transform's authsize to match the caller-supplied
	 * tag length. This is a transform property (not per-request), so it
	 * must be set here, not inside encrypt/decrypt. */
	ret = crypto_aead_setauthsize(ctx->tfm, taglen);
	if (ret)
		return ret;
	ctx->authsize = taglen;

	memcpy(ctx->tag, tag, taglen);
	ctx->taglen = taglen;
	return 0;
}

static int kcapi_aead_encrypt(struct kcapi_aead_ctx *ctx,
			      const u8 *in, size_t inlen,
			      u8 *out, size_t *outlen)
{
	struct aead_request *req = NULL;
	struct scatterlist src_sg, dst_sg;
	DECLARE_CRYPTO_WAIT(wait);
	u8 *src_buf = NULL;
	u8 *dst_buf = NULL;
	u32 aadlen  = ctx->aadlen;
	u32 taglen  = ctx->authsize;
	int ret;

	if (ctx->ivlen != GCM_IV_SIZE)
		return -EINVAL;

	src_buf = kmalloc(aadlen + inlen, GFP_KERNEL);
	if (!src_buf)
		return -ENOMEM;

	dst_buf = kzalloc(aadlen + inlen + taglen, GFP_KERNEL);
	if (!dst_buf) {
		ret = -ENOMEM;
		goto out_free_src;
	}

	if (aadlen && ctx->aad)
		memcpy(src_buf, ctx->aad, aadlen);
	memcpy(src_buf + aadlen, in, inlen);

	sg_init_one(&src_sg, src_buf, aadlen + inlen);
	sg_init_one(&dst_sg, dst_buf, aadlen + inlen + taglen);

	req = aead_request_alloc(ctx->tfm, GFP_KERNEL);
	if (!req) {
		ret = -ENOMEM;
		goto out_free_dst;
	}

	aead_request_set_callback(req,
		CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
		crypto_req_done, &wait);

	aead_request_set_crypt(req, &src_sg, &dst_sg, inlen, ctx->iv);
	aead_request_set_ad(req, aadlen);

	ret = crypto_wait_req(crypto_aead_encrypt(req), &wait);
	if (ret) {
		pr_err_ratelimited("%s: crypto_aead_encrypt returned %d\n",
				   __func__, ret);
		goto out_free_req;
	}

	memcpy(out, dst_buf + aadlen, inlen);
	memcpy(ctx->tag, dst_buf + aadlen + inlen, taglen);
	ctx->taglen    = taglen;
	ctx->processed = true;
	*outlen        = inlen;

out_free_req:
	aead_request_free(req);
out_free_dst:
	memzero_explicit(dst_buf, aadlen + inlen + taglen);
	kfree(dst_buf);
out_free_src:
	memzero_explicit(src_buf, aadlen + inlen);
	kfree(src_buf);
	return ret;
}

static int kcapi_aead_decrypt(struct kcapi_aead_ctx *ctx,
			      const u8 *in, size_t inlen,
			      u8 *out, size_t *outlen)
{
	struct aead_request *req = NULL;
	struct scatterlist src_sg, dst_sg;
	DECLARE_CRYPTO_WAIT(wait);
	u8 *src_buf = NULL;
	u8 *dst_buf = NULL;
	u32 aadlen  = ctx->aadlen;
	u32 taglen  = ctx->taglen;
	int ret;

	if (ctx->ivlen != GCM_IV_SIZE)
		return -EINVAL;

	if (taglen == 0)
		return -EINVAL;

	src_buf = kmalloc(aadlen + inlen + taglen, GFP_KERNEL);
	if (!src_buf)
		return -ENOMEM;

	dst_buf = kzalloc(aadlen + inlen, GFP_KERNEL);
	if (!dst_buf) {
		ret = -ENOMEM;
		goto out_free_src;
	}

	if (aadlen && ctx->aad)
		memcpy(src_buf, ctx->aad, aadlen);
	memcpy(src_buf + aadlen, in, inlen);
	memcpy(src_buf + aadlen + inlen, ctx->tag, taglen);

	sg_init_one(&src_sg, src_buf, aadlen + inlen + taglen);
	sg_init_one(&dst_sg, dst_buf, aadlen + inlen);

	req = aead_request_alloc(ctx->tfm, GFP_KERNEL);
	if (!req) {
		ret = -ENOMEM;
		goto out_free_dst;
	}

	aead_request_set_callback(req,
		CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
		crypto_req_done, &wait);

	aead_request_set_crypt(req, &src_sg, &dst_sg,
			       inlen + taglen, ctx->iv);
	aead_request_set_ad(req, aadlen);

	ret = crypto_wait_req(crypto_aead_decrypt(req), &wait);
	if (ret == -EBADMSG) {
		/* Authentication tag mismatch — normal security event, not a
		 * kernel error. Do not log: callers expect this under replay
		 * attacks or corrupt ciphertext and will handle it themselves. */
		goto out_free_req;
	}
	if (ret) {
		pr_err_ratelimited("%s: crypto_aead_decrypt returned %d\n",
				   __func__, ret);
		goto out_free_req;
	}

	memcpy(out, dst_buf + aadlen, inlen);
	ctx->processed = true;
	*outlen        = inlen;

out_free_req:
	aead_request_free(req);
out_free_dst:
	memzero_explicit(dst_buf, aadlen + inlen);
	kfree(dst_buf);
out_free_src:
	memzero_explicit(src_buf, aadlen + inlen + taglen);
	kfree(src_buf);
	return ret;
}

static int kcapi_aead_get_tag(void *ctx_in, u8 *tag, u32 *taglen)
{
	struct kcapi_aead_ctx *ctx = ctx_in;

	if (ctx->op != CRYPTO2DEV_OP_ENCRYPT)
		return -EINVAL;

	if (!ctx->processed)
		return -EINVAL;

	memcpy(tag, ctx->tag, ctx->taglen);
	*taglen = ctx->taglen;
	return 0;
}

static int kcapi_aead_update(void *ctx_in, const u8 *in, size_t inlen,
			      u8 *out, size_t outbuf_size, size_t *outlen)
{
	struct kcapi_aead_ctx *ctx = ctx_in;
	size_t new_len;

	(void)out;
	(void)outbuf_size;

	if (!ctx || !in || inlen == 0)
		return -EINVAL;

	new_len = ctx->inbuf_len + inlen;
	if (new_len > CRYPTO2DEV_MAX_PAYLOAD)
		return -EMSGSIZE;

	if (new_len > ctx->inbuf_cap) {
		u8 *new_buf = kmalloc(new_len, GFP_KERNEL);

		if (!new_buf)
			return -ENOMEM;
		if (ctx->inbuf) {
			memcpy(new_buf, ctx->inbuf, ctx->inbuf_len);
			/* FIPS 140-3: zero old buffer before freeing. */
			memzero_explicit(ctx->inbuf, ctx->inbuf_cap);
			kfree(ctx->inbuf);
		}
		ctx->inbuf     = new_buf;
		ctx->inbuf_cap = new_len;
	}

	memcpy(ctx->inbuf + ctx->inbuf_len, in, inlen);
	ctx->inbuf_len += inlen;
	*outlen = 0;
	return 0;
}

static size_t kcapi_aead_get_finalize_output_size(void *ctx_in)
{
	struct kcapi_aead_ctx *ctx = ctx_in;

	/* For encrypt: output is ciphertext (inbuf_len bytes); tag goes to
	 * ctx->tag separately.  For decrypt: output is plaintext (inbuf_len
	 * bytes).  Add authsize as headroom so the framework buffer is always
	 * large enough regardless of which path is taken. */
	return ctx->inbuf_len + ctx->authsize;
}

static int kcapi_aead_finalize(void *ctx_in, u8 *out, size_t outbuf_size,
				size_t *outlen)
{
	struct kcapi_aead_ctx *ctx = ctx_in;

	if (!ctx || !out || !outlen)
		return -EINVAL;

	if (ctx->inbuf_len == 0)
		return -EINVAL;

	if (outbuf_size < ctx->inbuf_len)
		return -EMSGSIZE;

	if (ctx->op == CRYPTO2DEV_OP_ENCRYPT)
		return kcapi_aead_encrypt(ctx, ctx->inbuf, ctx->inbuf_len,
					  out, outlen);
	else
		return kcapi_aead_decrypt(ctx, ctx->inbuf, ctx->inbuf_len,
					  out, outlen);
}

const struct crypto2dev_algo_ops kcapi_gcm_aes_ops = {
	.algo               = "gcm(aes)",
	.fips_gate          = NULL,
	.sess_init          = kcapi_aead_sess_init,
	.sess_free          = kcapi_aead_sess_free,
	.set_iv             = kcapi_aead_set_iv,
	.gen_iv             = kcapi_aead_gen_iv,
	.set_aad            = kcapi_aead_set_aad,
	.set_tag            = kcapi_aead_set_tag,
	.get_tag            = kcapi_aead_get_tag,
	.sign               = NULL,
	.verify             = NULL,
	.agree              = NULL,
	.sess_reset         = kcapi_aead_sess_reset,
	.update                   = kcapi_aead_update,
	.finalize                 = kcapi_aead_finalize,
	.get_finalize_output_size = kcapi_aead_get_finalize_output_size,
	.key_import         = NULL,
	.key_generate       = NULL,
	.key_export_public  = NULL,
	.key_export_private = NULL,
	.key_free           = NULL,
};
