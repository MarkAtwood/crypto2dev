// SPDX-License-Identifier: GPL-2.0-only
/*
 * wolfssl_sha.c — SHA-256, SHA-384, SHA-512, SHA3-256 provider for crypto2dev
 *
 * Implements four algo_ops structs backed by wolfCrypt.
 * Plain hash; no key, no IV.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "../../../include/crypto2dev_provider.h"
#include "../../../include/uapi/crypto2dev_ioctl.h"
#include "wolfssl_provider.h"

#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* ------------------------------------------------------------------
 * Internal context
 * ------------------------------------------------------------------ */

/* Enum is banned per CLAUDE.md §4 — use #define integer constants instead. */
#define C2D_SHA256   0
#define C2D_SHA384   1
#define C2D_SHA512   2
#define C2D_SHA3_256 3
#define C2D_SHA3_384 4
#define C2D_SHA3_512 5

struct wolfssl_sha_ctx {
	int type;
	bool inited;
	union {
		wc_Sha256 sha256;
		wc_Sha384 sha384;
		wc_Sha512 sha512;
		wc_Sha3   sha3;
	} wc;
};

/* ------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------ */

/* Translate wolfCrypt error codes to kernel errno */
static int wolfssl_sha_xlat_err(int wc_err)
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

/* Maps wolfssl_sha_ctx.type to a human-readable algo name for log messages. */
static const char *sha_algo_name(int type)
{
	switch (type) {
	case C2D_SHA256:   return "sha256";
	case C2D_SHA384:   return "sha384";
	case C2D_SHA512:   return "sha512";
	case C2D_SHA3_256: return "sha3-256";
	case C2D_SHA3_384: return "sha3-384";
	case C2D_SHA3_512: return "sha3-512";
	default:               return "sha(unknown)";
	}
}

static size_t sha_digest_size(int type)
{
	switch (type) {
	case C2D_SHA256:   return WC_SHA256_DIGEST_SIZE;
	case C2D_SHA384:   return WC_SHA384_DIGEST_SIZE;
	case C2D_SHA512:   return WC_SHA512_DIGEST_SIZE;
	case C2D_SHA3_256: return WC_SHA3_256_DIGEST_SIZE;
	case C2D_SHA3_384: return WC_SHA3_384_DIGEST_SIZE;
	case C2D_SHA3_512: return WC_SHA3_512_DIGEST_SIZE;
	default:
		return 32;
	}
}

/* ------------------------------------------------------------------
 * sess_init — shared across all four SHA variants
 * ------------------------------------------------------------------ */

static int sha_sess_init(void **out_ctx, int type,
			 u32 op, const u8 *key, u32 keylen)
{
	struct wolfssl_sha_ctx *ctx;
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (op != CRYPTO2DEV_OP_HASH)
		return -EINVAL;

	if (keylen != 0)
		return -EINVAL;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->type = type;

	switch (type) {
	case C2D_SHA256:
		ret = wc_InitSha256(&ctx->wc.sha256);
		break;
	case C2D_SHA384:
		ret = wc_InitSha384(&ctx->wc.sha384);
		break;
	case C2D_SHA512:
		ret = wc_InitSha512(&ctx->wc.sha512);
		break;
	case C2D_SHA3_256:
		ret = wc_InitSha3_256(&ctx->wc.sha3, NULL, INVALID_DEVID);
		break;
	case C2D_SHA3_384:
		ret = wc_InitSha3_384(&ctx->wc.sha3, NULL, INVALID_DEVID);
		break;
	case C2D_SHA3_512:
		ret = wc_InitSha3_512(&ctx->wc.sha3, NULL, INVALID_DEVID);
		break;
	default:
		memzero_explicit(ctx, sizeof(*ctx));
		kfree(ctx);
		return -EINVAL;
	}

	if (ret != 0) {
		pr_err_ratelimited("%s: wc hash init returned %d\n",
				   __func__, ret);
		/*
		 * wc_InitSha*() may have partially constructed internal state
		 * before failing.  Free the wc struct before zeroizing to avoid
		 * leaking wolfCrypt internal hash state.  FIPS 140-3: zeroize
		 * before kfree even though SHA ctx holds no key material —
		 * internal hash schedule data still deserves protection.
		 */
		switch (type) {
		case C2D_SHA256:   wc_Sha256Free(&ctx->wc.sha256);  break;
		case C2D_SHA384:   wc_Sha384Free(&ctx->wc.sha384);  break;
		case C2D_SHA512:   wc_Sha512Free(&ctx->wc.sha512);  break;
		case C2D_SHA3_256: wc_Sha3_256_Free(&ctx->wc.sha3); break;
		case C2D_SHA3_384: wc_Sha3_384_Free(&ctx->wc.sha3); break;
		case C2D_SHA3_512: wc_Sha3_512_Free(&ctx->wc.sha3); break;
		default:                                             break;
		}
		memzero_explicit(ctx, sizeof(*ctx));
		kfree(ctx);
		return wolfssl_sha_xlat_err(ret);
	}

	ctx->inited = true;
	*out_ctx = ctx;
	return 0;
}

static int wolfssl_sha256_sess_init(void **ctx, u32 op,
				    const u8 *key, u32 keylen)
{
	return sha_sess_init(ctx, C2D_SHA256, op, key, keylen);
}

static int wolfssl_sha384_sess_init(void **ctx, u32 op,
				    const u8 *key, u32 keylen)
{
	return sha_sess_init(ctx, C2D_SHA384, op, key, keylen);
}

static int wolfssl_sha512_sess_init(void **ctx, u32 op,
				    const u8 *key, u32 keylen)
{
	return sha_sess_init(ctx, C2D_SHA512, op, key, keylen);
}

static int wolfssl_sha3_256_sess_init(void **ctx, u32 op,
				      const u8 *key, u32 keylen)
{
	return sha_sess_init(ctx, C2D_SHA3_256, op, key, keylen);
}

static int wolfssl_sha3_384_sess_init(void **ctx, u32 op,
				      const u8 *key, u32 keylen)
{
	return sha_sess_init(ctx, C2D_SHA3_384, op, key, keylen);
}

static int wolfssl_sha3_512_sess_init(void **ctx, u32 op,
				      const u8 *key, u32 keylen)
{
	return sha_sess_init(ctx, C2D_SHA3_512, op, key, keylen);
}

/* ------------------------------------------------------------------
 * sess_reset
 * ------------------------------------------------------------------ */

static int wolfssl_sha_sess_reset(void *arg)
{
	struct wolfssl_sha_ctx *ctx = arg;
	int ret;

	/* FIPS 140-3: gate before any crypto state is touched. */
	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!ctx || !ctx->inited)
		return -EINVAL;

	/* Mark as not initialized before freeing — protects sess_free
	 * from double-freeing the hash struct if re-init fails below. */
	ctx->inited = false;

	switch (ctx->type) {
	case C2D_SHA256:
		wc_Sha256Free(&ctx->wc.sha256);
		ret = wc_InitSha256(&ctx->wc.sha256);
		break;
	case C2D_SHA384:
		wc_Sha384Free(&ctx->wc.sha384);
		ret = wc_InitSha384(&ctx->wc.sha384);
		break;
	case C2D_SHA512:
		wc_Sha512Free(&ctx->wc.sha512);
		ret = wc_InitSha512(&ctx->wc.sha512);
		break;
	case C2D_SHA3_256:
		wc_Sha3_256_Free(&ctx->wc.sha3);
		ret = wc_InitSha3_256(&ctx->wc.sha3, NULL, INVALID_DEVID);
		break;
	case C2D_SHA3_384:
		wc_Sha3_384_Free(&ctx->wc.sha3);
		ret = wc_InitSha3_384(&ctx->wc.sha3, NULL, INVALID_DEVID);
		break;
	case C2D_SHA3_512:
		wc_Sha3_512_Free(&ctx->wc.sha3);
		ret = wc_InitSha3_512(&ctx->wc.sha3, NULL, INVALID_DEVID);
		break;
	default:
		return -EINVAL;
	}

	if (ret != 0) {
		pr_err_ratelimited("%s(%s): wc hash init returned %d\n",
				   __func__, sha_algo_name(ctx->type), ret);
		return wolfssl_sha_xlat_err(ret);
	}

	ctx->inited = true;

	return 0;
}

/* ------------------------------------------------------------------
 * sess_free
 * ------------------------------------------------------------------ */

static void wolfssl_sha_sess_free(void *arg)
{
	struct wolfssl_sha_ctx *ctx = arg;

	if (!ctx)
		return;

	if (ctx->inited) {
		switch (ctx->type) {
		case C2D_SHA256:
			wc_Sha256Free(&ctx->wc.sha256);
			break;
		case C2D_SHA384:
			wc_Sha384Free(&ctx->wc.sha384);
			break;
		case C2D_SHA512:
			wc_Sha512Free(&ctx->wc.sha512);
			break;
		case C2D_SHA3_256:
			wc_Sha3_256_Free(&ctx->wc.sha3);
			break;
		case C2D_SHA3_384:
			wc_Sha3_384_Free(&ctx->wc.sha3);
			break;
		case C2D_SHA3_512:
			wc_Sha3_512_Free(&ctx->wc.sha3);
			break;
		default:
			break;
		}
	}

	memzero_explicit(ctx, sizeof(*ctx));
	kfree(ctx);
}

/* ------------------------------------------------------------------
 * update
 * ------------------------------------------------------------------ */

static int wolfssl_sha_update(void *arg,
			      const u8 *in, size_t inlen,
			      u8 *out, size_t outbuf_size, size_t *outlen)
{
	struct wolfssl_sha_ctx *ctx = arg;
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

	switch (ctx->type) {
	case C2D_SHA256:
		ret = wc_Sha256Update(&ctx->wc.sha256, in, (word32)inlen);
		break;
	case C2D_SHA384:
		ret = wc_Sha384Update(&ctx->wc.sha384, in, (word32)inlen);
		break;
	case C2D_SHA512:
		ret = wc_Sha512Update(&ctx->wc.sha512, in, (word32)inlen);
		break;
	case C2D_SHA3_256:
		ret = wc_Sha3_256_Update(&ctx->wc.sha3, in, (word32)inlen);
		break;
	case C2D_SHA3_384:
		ret = wc_Sha3_384_Update(&ctx->wc.sha3, in, (word32)inlen);
		break;
	case C2D_SHA3_512:
		ret = wc_Sha3_512_Update(&ctx->wc.sha3, in, (word32)inlen);
		break;
	default:
		return -EINVAL;
	}

	if (ret != 0) {
		pr_err_ratelimited("%s(%s): wc hash update returned %d\n",
				   __func__, sha_algo_name(ctx->type), ret);
		return wolfssl_sha_xlat_err(ret);
	}

	*outlen = 0;
	return 0;
}

/* ------------------------------------------------------------------
 * finalize
 * ------------------------------------------------------------------ */

static int wolfssl_sha_finalize(void *arg,
				u8 *out, size_t outbuf_size, size_t *outlen)
{
	struct wolfssl_sha_ctx *ctx = arg;
	size_t digest_size;
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!ctx || !ctx->inited)
		return -EINVAL;

	if (!out || !outlen)
		return -EINVAL;

	digest_size = sha_digest_size(ctx->type);

	if (outbuf_size < digest_size)
		return -EMSGSIZE;

	switch (ctx->type) {
	case C2D_SHA256:
		ret = wc_Sha256Final(&ctx->wc.sha256, out);
		break;
	case C2D_SHA384:
		ret = wc_Sha384Final(&ctx->wc.sha384, out);
		break;
	case C2D_SHA512:
		ret = wc_Sha512Final(&ctx->wc.sha512, out);
		break;
	case C2D_SHA3_256:
		ret = wc_Sha3_256_Final(&ctx->wc.sha3, out);
		break;
	case C2D_SHA3_384:
		ret = wc_Sha3_384_Final(&ctx->wc.sha3, out);
		break;
	case C2D_SHA3_512:
		ret = wc_Sha3_512_Final(&ctx->wc.sha3, out);
		break;
	default:
		return -EINVAL;
	}

	if (ret != 0) {
		pr_err_ratelimited("%s(%s): wc hash final returned %d\n",
				   __func__, sha_algo_name(ctx->type), ret);
		return wolfssl_sha_xlat_err(ret);
	}

	*outlen = digest_size;
	return 0;
}

/* ------------------------------------------------------------------
 * algo_ops tables
 * ------------------------------------------------------------------ */

const struct crypto2dev_algo_ops wolfssl_sha256_ops = {
	.algo       = "sha256",
	.fips_gate  = wolfssl_fips_gate,
	.sess_init  = wolfssl_sha256_sess_init,
	.sess_free  = wolfssl_sha_sess_free,
	.set_iv     = NULL,
	.set_aad    = NULL,
	.set_tag    = NULL,
	.get_tag    = NULL,
	.sign               = NULL,
	.verify             = NULL,
	.agree              = NULL,
	.sess_reset         = wolfssl_sha_sess_reset,
	.update             = wolfssl_sha_update,
	.finalize           = wolfssl_sha_finalize,
	.key_import         = NULL,
	.key_generate       = NULL,
	.key_export_public  = NULL,
	.key_export_private = NULL,
	.key_free           = NULL,
};

const struct crypto2dev_algo_ops wolfssl_sha384_ops = {
	.algo       = "sha384",
	.fips_gate  = wolfssl_fips_gate,
	.sess_init  = wolfssl_sha384_sess_init,
	.sess_free  = wolfssl_sha_sess_free,
	.set_iv     = NULL,
	.set_aad    = NULL,
	.set_tag    = NULL,
	.get_tag    = NULL,
	.sign               = NULL,
	.verify             = NULL,
	.agree              = NULL,
	.sess_reset         = wolfssl_sha_sess_reset,
	.update             = wolfssl_sha_update,
	.finalize           = wolfssl_sha_finalize,
	.key_import         = NULL,
	.key_generate       = NULL,
	.key_export_public  = NULL,
	.key_export_private = NULL,
	.key_free           = NULL,
};

const struct crypto2dev_algo_ops wolfssl_sha512_ops = {
	.algo       = "sha512",
	.fips_gate  = wolfssl_fips_gate,
	.sess_init  = wolfssl_sha512_sess_init,
	.sess_free  = wolfssl_sha_sess_free,
	.set_iv     = NULL,
	.set_aad    = NULL,
	.set_tag    = NULL,
	.get_tag    = NULL,
	.sign               = NULL,
	.verify             = NULL,
	.agree              = NULL,
	.sess_reset         = wolfssl_sha_sess_reset,
	.update             = wolfssl_sha_update,
	.finalize           = wolfssl_sha_finalize,
	.key_import         = NULL,
	.key_generate       = NULL,
	.key_export_public  = NULL,
	.key_export_private = NULL,
	.key_free           = NULL,
};

const struct crypto2dev_algo_ops wolfssl_sha3_256_ops = {
	.algo       = "sha3-256",
	.fips_gate  = wolfssl_fips_gate,
	.sess_init  = wolfssl_sha3_256_sess_init,
	.sess_free  = wolfssl_sha_sess_free,
	.set_iv     = NULL,
	.set_aad    = NULL,
	.set_tag    = NULL,
	.get_tag    = NULL,
	.sign               = NULL,
	.verify             = NULL,
	.agree              = NULL,
	.sess_reset         = wolfssl_sha_sess_reset,
	.update             = wolfssl_sha_update,
	.finalize           = wolfssl_sha_finalize,
	.key_import         = NULL,
	.key_generate       = NULL,
	.key_export_public  = NULL,
	.key_export_private = NULL,
	.key_free           = NULL,
};

const struct crypto2dev_algo_ops wolfssl_sha3_384_ops = {
	.algo       = "sha3-384",
	.fips_gate  = wolfssl_fips_gate,
	.sess_init  = wolfssl_sha3_384_sess_init,
	.sess_free  = wolfssl_sha_sess_free,
	.set_iv     = NULL,
	.set_aad    = NULL,
	.set_tag    = NULL,
	.get_tag    = NULL,
	.sign               = NULL,
	.verify             = NULL,
	.agree              = NULL,
	.sess_reset         = wolfssl_sha_sess_reset,
	.update             = wolfssl_sha_update,
	.finalize           = wolfssl_sha_finalize,
	.key_import         = NULL,
	.key_generate       = NULL,
	.key_export_public  = NULL,
	.key_export_private = NULL,
	.key_free           = NULL,
};

const struct crypto2dev_algo_ops wolfssl_sha3_512_ops = {
	.algo       = "sha3-512",
	.fips_gate  = wolfssl_fips_gate,
	.sess_init  = wolfssl_sha3_512_sess_init,
	.sess_free  = wolfssl_sha_sess_free,
	.set_iv     = NULL,
	.set_aad    = NULL,
	.set_tag    = NULL,
	.get_tag    = NULL,
	.sign               = NULL,
	.verify             = NULL,
	.agree              = NULL,
	.sess_reset         = wolfssl_sha_sess_reset,
	.update             = wolfssl_sha_update,
	.finalize           = wolfssl_sha_finalize,
	.key_import         = NULL,
	.key_generate       = NULL,
	.key_export_public  = NULL,
	.key_export_private = NULL,
	.key_free           = NULL,
};
