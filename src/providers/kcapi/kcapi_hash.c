// SPDX-License-Identifier: GPL-2.0-only
/*
 * crypto2dev kcapi hash/MAC provider
 *
 * Implements crypto2dev_algo_ops for 8 hash and MAC algorithms using the
 * Linux kernel ahash API:
 *
 *   Plain hash (no key): sha256, sha384, sha512, sha3-256
 *   Keyed MAC (setkey):  hmac(sha256), hmac(sha384), hmac(sha512), cmac(aes)
 *
 * Streaming model: a persistent ahash_request is allocated at sess_init and
 * crypto_ahash_init() is called immediately.  Each update() call feeds one
 * chunk via crypto_ahash_update(); finalize() calls crypto_ahash_final().
 * sess_reset() calls crypto_ahash_init() again to re-arm the request.
 *
 * Each async operation is made synchronous via DECLARE_CRYPTO_WAIT /
 * crypto_wait_req with CRYPTO_TFM_REQ_MAY_SLEEP.  The scatterlist for
 * update() lives on the caller's stack — safe because crypto_wait_req
 * returns only after the hardware (or software) driver has consumed it.
 */

#define pr_fmt(fmt) "crypto2dev_kcapi: " fmt

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <crypto/hash.h>

#include "../../../include/uapi/crypto2dev_ioctl.h"
#include "kcapi_provider.h"

/* -------------------------------------------------------------------------
 * Session context
 * ------------------------------------------------------------------------- */

struct kcapi_hash_ctx {
	struct crypto_ahash  *tfm;
	struct ahash_request *req;         /* persistent; carries incremental state */
	u32                   digestsize;  /* cached from crypto_ahash_digestsize() */
	bool                  keyed;       /* true for HMAC/CMAC */
};

/* -------------------------------------------------------------------------
 * Shared implementation
 * ------------------------------------------------------------------------- */

static int kcapi_hash_sess_init_impl(void **out_ctx, u32 op,
				     const u8 *key, u32 keylen,
				     const char *algo, bool keyed)
{
	struct kcapi_hash_ctx *ctx;
	struct crypto_ahash   *tfm;
	struct ahash_request  *req;
	DECLARE_CRYPTO_WAIT(wait);
	int ret;

	if (!out_ctx || !algo)
		return -EINVAL;

	if (op != CRYPTO2DEV_OP_HASH)
		return -EINVAL;

	if (keyed) {
		if (!key || keylen == 0)
			return -EINVAL;
	} else {
		if (keylen != 0)
			return -EINVAL;
	}

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	tfm = crypto_alloc_ahash(algo, 0, 0);
	if (IS_ERR(tfm)) {
		ret = PTR_ERR(tfm);
		kfree(ctx);
		return ret;
	}

	if (keyed) {
		ret = crypto_ahash_setkey(tfm, key, keylen);
		if (ret < 0) {
			crypto_free_ahash(tfm);
			kfree(ctx);
			return ret;
		}
	}

	req = ahash_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		crypto_free_ahash(tfm);
		kfree(ctx);
		return -ENOMEM;
	}

	ahash_request_set_callback(req,
		CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
		crypto_req_done, &wait);

	ret = crypto_wait_req(crypto_ahash_init(req), &wait);
	if (ret < 0) {
		ahash_request_free(req);
		crypto_free_ahash(tfm);
		kfree(ctx);
		return ret;
	}

	ctx->tfm        = tfm;
	ctx->req        = req;
	ctx->digestsize = crypto_ahash_digestsize(tfm);
	ctx->keyed      = keyed;

	*out_ctx = ctx;
	return 0;
}

static int kcapi_hash_sess_reset(void *vctx)
{
	struct kcapi_hash_ctx *ctx = vctx;
	DECLARE_CRYPTO_WAIT(wait);

	if (!ctx || !ctx->req)
		return -EINVAL;

	/*
	 * Re-arm the streaming state.  The tfm retains any setkey state so
	 * the session is immediately ready for new update() calls.
	 */
	ahash_request_set_callback(ctx->req,
		CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
		crypto_req_done, &wait);

	return crypto_wait_req(crypto_ahash_init(ctx->req), &wait);
}

static void kcapi_hash_sess_free(void *vctx)
{
	struct kcapi_hash_ctx *ctx = vctx;

	if (!ctx)
		return;

	if (ctx->req)
		ahash_request_free(ctx->req);

	if (ctx->tfm)
		crypto_free_ahash(ctx->tfm);

	memzero_explicit(ctx, sizeof(*ctx));
	kfree(ctx);
}

static int kcapi_hash_update(void *vctx, const u8 *in, size_t inlen,
			      u8 *out, size_t outbuf_size, size_t *outlen)
{
	struct kcapi_hash_ctx *ctx = vctx;
	struct scatterlist     sg;
	DECLARE_CRYPTO_WAIT(wait);
	int ret;

	(void)out;
	(void)outbuf_size;

	if (!ctx || !in || inlen == 0)
		return -EINVAL;

	if (inlen > CRYPTO2DEV_MAX_PAYLOAD)
		return -EMSGSIZE;

	sg_init_one(&sg, in, inlen);
	ahash_request_set_callback(ctx->req,
		CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
		crypto_req_done, &wait);
	ahash_request_set_crypt(ctx->req, &sg, NULL, inlen);

	ret = crypto_wait_req(crypto_ahash_update(ctx->req), &wait);
	if (ret == 0)
		*outlen = 0;
	return ret;
}

static int kcapi_hash_finalize(void *vctx, u8 *out, size_t outbuf_size,
				size_t *outlen)
{
	struct kcapi_hash_ctx *ctx = vctx;
	DECLARE_CRYPTO_WAIT(wait);
	u8  *result;
	int  ret;

	if (!ctx || !out || !outlen)
		return -EINVAL;

	if (outbuf_size < ctx->digestsize)
		return -EMSGSIZE;

	result = kzalloc(ctx->digestsize, GFP_KERNEL);
	if (!result)
		return -ENOMEM;

	ahash_request_set_callback(ctx->req,
		CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
		crypto_req_done, &wait);
	ahash_request_set_crypt(ctx->req, NULL, result, 0);

	ret = crypto_wait_req(crypto_ahash_final(ctx->req), &wait);
	if (ret == 0) {
		memcpy(out, result, ctx->digestsize);
		*outlen = ctx->digestsize;
	}

	memzero_explicit(result, ctx->digestsize);
	kfree(result);
	return ret;
}

/* -------------------------------------------------------------------------
 * Per-algorithm sess_init wrappers
 * ------------------------------------------------------------------------- */

static int sha256_sess_init(void **ctx, u32 op, const u8 *key, u32 keylen)
{
	return kcapi_hash_sess_init_impl(ctx, op, key, keylen,
					 "sha256", false);
}

static int sha384_sess_init(void **ctx, u32 op, const u8 *key, u32 keylen)
{
	return kcapi_hash_sess_init_impl(ctx, op, key, keylen,
					 "sha384", false);
}

static int sha512_sess_init(void **ctx, u32 op, const u8 *key, u32 keylen)
{
	return kcapi_hash_sess_init_impl(ctx, op, key, keylen,
					 "sha512", false);
}

static int sha3_256_sess_init(void **ctx, u32 op, const u8 *key, u32 keylen)
{
	return kcapi_hash_sess_init_impl(ctx, op, key, keylen,
					 "sha3-256", false);
}

static int sha3_384_sess_init(void **ctx, u32 op, const u8 *key, u32 keylen)
{
	return kcapi_hash_sess_init_impl(ctx, op, key, keylen,
					 "sha3-384", false);
}

static int sha3_512_sess_init(void **ctx, u32 op, const u8 *key, u32 keylen)
{
	return kcapi_hash_sess_init_impl(ctx, op, key, keylen,
					 "sha3-512", false);
}

static int hmac_sha256_sess_init(void **ctx, u32 op, const u8 *key,
				 u32 keylen)
{
	return kcapi_hash_sess_init_impl(ctx, op, key, keylen,
					 "hmac(sha256)", true);
}

static int hmac_sha384_sess_init(void **ctx, u32 op, const u8 *key,
				 u32 keylen)
{
	return kcapi_hash_sess_init_impl(ctx, op, key, keylen,
					 "hmac(sha384)", true);
}

static int hmac_sha512_sess_init(void **ctx, u32 op, const u8 *key,
				 u32 keylen)
{
	return kcapi_hash_sess_init_impl(ctx, op, key, keylen,
					 "hmac(sha512)", true);
}

static int cmac_aes_sess_init(void **ctx, u32 op, const u8 *key, u32 keylen)
{
	return kcapi_hash_sess_init_impl(ctx, op, key, keylen,
					 "cmac(aes)", true);
}

/* -------------------------------------------------------------------------
 * Public ops structs
 * ------------------------------------------------------------------------- */

const struct crypto2dev_algo_ops kcapi_sha256_ops = {
	.algo               = "sha256",
	.fips_gate          = NULL,
	.sess_init          = sha256_sess_init,
	.sess_free          = kcapi_hash_sess_free,
	.set_iv             = NULL,
	.set_aad            = NULL,
	.set_tag            = NULL,
	.get_tag            = NULL,
	.sign               = NULL,
	.verify             = NULL,
	.agree              = NULL,
	.sess_reset         = kcapi_hash_sess_reset,
	.update             = kcapi_hash_update,
	.finalize           = kcapi_hash_finalize,
	.key_import         = NULL,
	.key_generate       = NULL,
	.key_export_public  = NULL,
	.key_export_private = NULL,
	.key_free           = NULL,
};

const struct crypto2dev_algo_ops kcapi_sha384_ops = {
	.algo               = "sha384",
	.fips_gate          = NULL,
	.sess_init          = sha384_sess_init,
	.sess_free          = kcapi_hash_sess_free,
	.set_iv             = NULL,
	.set_aad            = NULL,
	.set_tag            = NULL,
	.get_tag            = NULL,
	.sign               = NULL,
	.verify             = NULL,
	.agree              = NULL,
	.sess_reset         = kcapi_hash_sess_reset,
	.update             = kcapi_hash_update,
	.finalize           = kcapi_hash_finalize,
	.key_import         = NULL,
	.key_generate       = NULL,
	.key_export_public  = NULL,
	.key_export_private = NULL,
	.key_free           = NULL,
};

const struct crypto2dev_algo_ops kcapi_sha512_ops = {
	.algo               = "sha512",
	.fips_gate          = NULL,
	.sess_init          = sha512_sess_init,
	.sess_free          = kcapi_hash_sess_free,
	.set_iv             = NULL,
	.set_aad            = NULL,
	.set_tag            = NULL,
	.get_tag            = NULL,
	.sign               = NULL,
	.verify             = NULL,
	.agree              = NULL,
	.sess_reset         = kcapi_hash_sess_reset,
	.update             = kcapi_hash_update,
	.finalize           = kcapi_hash_finalize,
	.key_import         = NULL,
	.key_generate       = NULL,
	.key_export_public  = NULL,
	.key_export_private = NULL,
	.key_free           = NULL,
};

const struct crypto2dev_algo_ops kcapi_sha3_256_ops = {
	.algo               = "sha3-256",
	.fips_gate          = NULL,
	.sess_init          = sha3_256_sess_init,
	.sess_free          = kcapi_hash_sess_free,
	.set_iv             = NULL,
	.set_aad            = NULL,
	.set_tag            = NULL,
	.get_tag            = NULL,
	.sign               = NULL,
	.verify             = NULL,
	.agree              = NULL,
	.sess_reset         = kcapi_hash_sess_reset,
	.update             = kcapi_hash_update,
	.finalize           = kcapi_hash_finalize,
	.key_import         = NULL,
	.key_generate       = NULL,
	.key_export_public  = NULL,
	.key_export_private = NULL,
	.key_free           = NULL,
};

const struct crypto2dev_algo_ops kcapi_sha3_384_ops = {
	.algo               = "sha3-384",
	.fips_gate          = NULL,
	.sess_init          = sha3_384_sess_init,
	.sess_free          = kcapi_hash_sess_free,
	.set_iv             = NULL,
	.set_aad            = NULL,
	.set_tag            = NULL,
	.get_tag            = NULL,
	.sign               = NULL,
	.verify             = NULL,
	.agree              = NULL,
	.sess_reset         = kcapi_hash_sess_reset,
	.update             = kcapi_hash_update,
	.finalize           = kcapi_hash_finalize,
	.key_import         = NULL,
	.key_generate       = NULL,
	.key_export_public  = NULL,
	.key_export_private = NULL,
	.key_free           = NULL,
};

const struct crypto2dev_algo_ops kcapi_sha3_512_ops = {
	.algo               = "sha3-512",
	.fips_gate          = NULL,
	.sess_init          = sha3_512_sess_init,
	.sess_free          = kcapi_hash_sess_free,
	.set_iv             = NULL,
	.set_aad            = NULL,
	.set_tag            = NULL,
	.get_tag            = NULL,
	.sign               = NULL,
	.verify             = NULL,
	.agree              = NULL,
	.sess_reset         = kcapi_hash_sess_reset,
	.update             = kcapi_hash_update,
	.finalize           = kcapi_hash_finalize,
	.key_import         = NULL,
	.key_generate       = NULL,
	.key_export_public  = NULL,
	.key_export_private = NULL,
	.key_free           = NULL,
};

const struct crypto2dev_algo_ops kcapi_hmac_sha256_ops = {
	.algo               = "hmac(sha256)",
	.fips_gate          = NULL,
	.sess_init          = hmac_sha256_sess_init,
	.sess_free          = kcapi_hash_sess_free,
	.set_iv             = NULL,
	.set_aad            = NULL,
	.set_tag            = NULL,
	.get_tag            = NULL,
	.sign               = NULL,
	.verify             = NULL,
	.agree              = NULL,
	.sess_reset         = kcapi_hash_sess_reset,
	.update             = kcapi_hash_update,
	.finalize           = kcapi_hash_finalize,
	.key_import         = NULL,
	.key_generate       = NULL,
	.key_export_public  = NULL,
	.key_export_private = NULL,
	.key_free           = NULL,
};

const struct crypto2dev_algo_ops kcapi_hmac_sha384_ops = {
	.algo               = "hmac(sha384)",
	.fips_gate          = NULL,
	.sess_init          = hmac_sha384_sess_init,
	.sess_free          = kcapi_hash_sess_free,
	.set_iv             = NULL,
	.set_aad            = NULL,
	.set_tag            = NULL,
	.get_tag            = NULL,
	.sign               = NULL,
	.verify             = NULL,
	.agree              = NULL,
	.sess_reset         = kcapi_hash_sess_reset,
	.update             = kcapi_hash_update,
	.finalize           = kcapi_hash_finalize,
	.key_import         = NULL,
	.key_generate       = NULL,
	.key_export_public  = NULL,
	.key_export_private = NULL,
	.key_free           = NULL,
};

const struct crypto2dev_algo_ops kcapi_hmac_sha512_ops = {
	.algo               = "hmac(sha512)",
	.fips_gate          = NULL,
	.sess_init          = hmac_sha512_sess_init,
	.sess_free          = kcapi_hash_sess_free,
	.set_iv             = NULL,
	.set_aad            = NULL,
	.set_tag            = NULL,
	.get_tag            = NULL,
	.sign               = NULL,
	.verify             = NULL,
	.agree              = NULL,
	.sess_reset         = kcapi_hash_sess_reset,
	.update             = kcapi_hash_update,
	.finalize           = kcapi_hash_finalize,
	.key_import         = NULL,
	.key_generate       = NULL,
	.key_export_public  = NULL,
	.key_export_private = NULL,
	.key_free           = NULL,
};

const struct crypto2dev_algo_ops kcapi_cmac_aes_ops = {
	.algo               = "cmac(aes)",
	.fips_gate          = NULL,
	.sess_init          = cmac_aes_sess_init,
	.sess_free          = kcapi_hash_sess_free,
	.set_iv             = NULL,
	.set_aad            = NULL,
	.set_tag            = NULL,
	.get_tag            = NULL,
	.sign               = NULL,
	.verify             = NULL,
	.agree              = NULL,
	.sess_reset         = kcapi_hash_sess_reset,
	.update             = kcapi_hash_update,
	.finalize           = kcapi_hash_finalize,
	.key_import         = NULL,
	.key_generate       = NULL,
	.key_export_public  = NULL,
	.key_export_private = NULL,
	.key_free           = NULL,
};
