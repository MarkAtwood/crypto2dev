// SPDX-License-Identifier: GPL-2.0-only
/*
 * wolfssl_rsa.c — RSA-2048 and RSA-4096 PKCS#1 v1.5 sign/verify
 * for the crypto2dev wolfSSL provider.
 *
 * Algorithms: "rsa-2048", "rsa-4096"
 * Operations: key_import, sign, verify, key_generate,
 *             key_export_public, key_export_private
 *
 * Key formats (write-before-ioctl pattern):
 *   PRIVATE or PAIR: PKCS#8 unencrypted DER (wc_GetPkcs8TraditionalOffset
 *                    unwraps to inner PKCS#1 RSAPrivateKey)
 *   PUBLIC:          SubjectPublicKeyInfo DER
 *
 * PKCS#1 v1.5 sign: provider constructs the DigestInfo DER prefix and
 * appends the caller-supplied pre-computed digest before calling
 * wc_RsaSSL_Sign.  The provider MUST NOT hash the digest — it is always
 * pre-computed by the caller.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/version.h>
/* crypto_memneq: moved to crypto/utils.h in kernel 6.2; algapi.h works everywhere */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
#include <crypto/utils.h>
#else
#include <crypto/algapi.h>
#endif

#include "../../../include/uapi/crypto2dev_ioctl.h"
#include "wolfssl_provider.h"

#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/*
 * DigestInfo DER prefixes for PKCS#1 v1.5 (RFC 8017 §9.2).
 *
 * DigestInfo ::= SEQUENCE {
 *   digestAlgorithm  AlgorithmIdentifier,
 *   digest           OCTET STRING
 * }
 *
 * Each prefix is 19 bytes: SEQUENCE header, nested SEQUENCE with OID + NULL,
 * and OCTET STRING tag+length.  The digest bytes follow immediately.
 */
static const u8 digestinfo_sha256_prefix[19] = {
	/* SEQUENCE(49) { SEQUENCE(13) { OID sha256, NULL } OCTET_STRING(32) } */
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09,
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
	0x05, 0x00, 0x04, 0x20,
};
static const u8 digestinfo_sha384_prefix[19] = {
	/* SEQUENCE(65) { SEQUENCE(13) { OID sha384, NULL } OCTET_STRING(48) } */
	0x30, 0x41, 0x30, 0x0d, 0x06, 0x09,
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
	0x05, 0x00, 0x04, 0x30,
};
static const u8 digestinfo_sha512_prefix[19] = {
	/* SEQUENCE(81) { SEQUENCE(13) { OID sha512, NULL } OCTET_STRING(64) } */
	0x30, 0x51, 0x30, 0x0d, 0x06, 0x09,
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
	0x05, 0x00, 0x04, 0x40,
};

#define DIGESTINFO_PREFIX_LEN   19u
#define SHA256_DIGEST_LEN       32u
#define SHA384_DIGEST_LEN       48u
#define SHA512_DIGEST_LEN       64u
/* Largest DigestInfo: 19 prefix + 64 digest bytes = 83 bytes */
#define DIGESTINFO_MAX_LEN      83u

/* FIPS 140-3: minimum RSA key size is 2048 bits */
#define RSA_MIN_KEY_BYTES       256u
#define RSA_2048_KEY_BYTES      256u
#define RSA_4096_KEY_BYTES      512u

struct wolfssl_rsa_ctx {
	RsaKey  key;
	WC_RNG  rng;
	u32     key_size_bytes;  /* 256 for rsa-2048, 512 for rsa-4096 */
	u32     key_type;        /* CRYPTO2DEV_KEY_PRIVATE/PUBLIC/PAIR */
	bool    rng_inited;
	bool    key_inited;
};

static int wolfssl_rsa_xlat_err(int wc_err)
{
	switch (wc_err) {
	case BAD_FUNC_ARG:
		return -EINVAL;
	case MEMORY_E:
		return -ENOMEM;
	case RSA_BUFFER_E:
		return -ENOBUFS;
	case BAD_PADDING_E:
		return -EBADMSG;
	case RSA_WRONG_TYPE_E:
		return -EINVAL;
	case FIPS_NOT_ALLOWED_E:
		return -EACCES;
	case FIPS_DEGRADED_E:
		return -EACCES;
	default:
		pr_err_ratelimited("wolfssl_rsa: unhandled wc_err=%d\n", wc_err);
		return -EIO;
	}
}

/*
 * build_digestinfo - construct a PKCS#1 v1.5 DigestInfo DER structure.
 * Returns the total length (prefix + digest), or negative errno on error.
 * buf must be at least DIGESTINFO_MAX_LEN bytes.
 */
static int build_digestinfo(const char *hash_algo,
			     const u8 *digest, u32 digest_len,
			     u8 *buf, u32 bufsz)
{
	const u8 *prefix;
	u32       expected_digest_len;

	if (!hash_algo || !digest || !buf)
		return -EINVAL;

	if (!strcmp(hash_algo, "sha256")) {
		prefix               = digestinfo_sha256_prefix;
		expected_digest_len  = SHA256_DIGEST_LEN;
	} else if (!strcmp(hash_algo, "sha384")) {
		prefix               = digestinfo_sha384_prefix;
		expected_digest_len  = SHA384_DIGEST_LEN;
	} else if (!strcmp(hash_algo, "sha512")) {
		prefix               = digestinfo_sha512_prefix;
		expected_digest_len  = SHA512_DIGEST_LEN;
	} else {
		pr_err_ratelimited("wolfssl_rsa: unsupported hash_algo %s\n",
				   hash_algo);
		return -EINVAL;
	}

	if (digest_len != expected_digest_len)
		return -EINVAL;

	if (bufsz < DIGESTINFO_PREFIX_LEN + digest_len)
		return -ENOBUFS;

	memcpy(buf, prefix, DIGESTINFO_PREFIX_LEN);
	memcpy(buf + DIGESTINFO_PREFIX_LEN, digest, digest_len);
	return (int)(DIGESTINFO_PREFIX_LEN + digest_len);
}

/*
 * wolfssl_rsa_key_import_size — decode and import an RSA key, enforcing that
 * the actual key size matches @expected_key_bytes.
 *
 * FIPS 140-3: an rsa-2048 handle must not accept a 4096-bit key and vice
 * versa.  The algo boundary is part of the FIPS module boundary.
 */
static int wolfssl_rsa_key_import_size(void **key_ctx, u32 key_type,
				       const u8 *raw, u32 rawlen,
				       u32 expected_key_bytes)
{
	struct wolfssl_rsa_ctx *ctx;
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!key_ctx || !raw || rawlen == 0)
		return -EINVAL;

	if (key_type != CRYPTO2DEV_KEY_PRIVATE &&
	    key_type != CRYPTO2DEV_KEY_PUBLIC   &&
	    key_type != CRYPTO2DEV_KEY_PAIR)
		return -EINVAL;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->key_type = key_type;

	ret = wc_InitRsaKey_ex(&ctx->key, NULL, INVALID_DEVID);
	if (ret != 0) {
		pr_err_ratelimited("%s: wc_InitRsaKey_ex returned %d\n",
				   __func__, ret);
		goto err_free_ctx;
	}
	ctx->key_inited = true;

	if (key_type == CRYPTO2DEV_KEY_PRIVATE || key_type == CRYPTO2DEV_KEY_PAIR) {
		word32 idx = 0;
		word32 inner_idx = 0;

		/* Skip PKCS#8 wrapper to reach inner PKCS#1 RSAPrivateKey */
		ret = wc_GetPkcs8TraditionalOffset((byte *)raw, &idx, rawlen);
		if (ret < 0) {
			pr_err_ratelimited("%s: wc_GetPkcs8TraditionalOffset returned %d\n",
					   __func__, ret);
			goto err_free_key;
		}
		ret = wc_RsaPrivateKeyDecode(raw + idx, &inner_idx,
					     &ctx->key, rawlen - idx);
		if (ret != 0) {
			pr_err_ratelimited("%s: wc_RsaPrivateKeyDecode returned %d\n",
					   __func__, ret);
			goto err_free_key;
		}
	} else {
		word32 idx = 0;

		/* SubjectPublicKeyInfo DER */
		ret = wc_RsaPublicKeyDecode(raw, &idx, &ctx->key, rawlen);
		if (ret != 0) {
			pr_err_ratelimited("%s: wc_RsaPublicKeyDecode returned %d\n",
					   __func__, ret);
			goto err_free_key;
		}
	}

	{
		int keybytes = wc_RsaEncryptSize(&ctx->key);

		if (keybytes < 0) {
			pr_err_ratelimited("%s: wc_RsaEncryptSize returned %d\n",
					   __func__, keybytes);
			ret = keybytes;
			goto err_free_key;
		}
		/* FIPS 140-3: minimum RSA key size is 2048 bits */
		if ((u32)keybytes < RSA_MIN_KEY_BYTES) {
			pr_err_ratelimited("%s: RSA key too small (%d bits); FIPS 140-3 requires >= 2048\n",
					   __func__, keybytes * 8);
			ret = BAD_FUNC_ARG;	/* xlat → -EINVAL */
			goto err_free_key;
		}
		/*
		 * FIPS 140-3: enforce algo-name boundary.  An rsa-2048 handle
		 * must not accept a 4096-bit key.  expected_key_bytes==0 skips
		 * the check (internal callers that don't care about the boundary).
		 */
		if (expected_key_bytes != 0 &&
		    (u32)keybytes != expected_key_bytes) {
			pr_err_ratelimited(
				"%s: key size %d B does not match expected %u B\n",
				__func__, keybytes, expected_key_bytes);
			ret = BAD_FUNC_ARG;	/* xlat → -EINVAL */
			goto err_free_key;
		}
		ctx->key_size_bytes = (u32)keybytes;
	}

	ret = wc_InitRng_ex(&ctx->rng, NULL, INVALID_DEVID);
	if (ret != 0) {
		pr_err_ratelimited("%s: wc_InitRng_ex returned %d\n",
				   __func__, ret);
		goto err_free_key;
	}
	ctx->rng_inited = true;

	if (key_type != CRYPTO2DEV_KEY_PUBLIC) {
		ret = wc_RsaSetRNG(&ctx->key, &ctx->rng);
		if (ret != 0) {
			pr_err_ratelimited("%s: wc_RsaSetRNG returned %d\n",
					   __func__, ret);
			goto err_free_rng;
		}
	}

	*key_ctx = ctx;
	return 0;

err_free_rng:
	wc_FreeRng(&ctx->rng);
	ctx->rng_inited = false;
err_free_key:
	wc_FreeRsaKey(&ctx->key);
	ctx->key_inited = false;
err_free_ctx:
	memzero_explicit(ctx, sizeof(*ctx));
	kfree(ctx);
	return wolfssl_rsa_xlat_err(ret);
}

static void wolfssl_rsa_key_free(void *key_ctx)
{
	struct wolfssl_rsa_ctx *ctx = key_ctx;

	if (!ctx)
		return;

	if (ctx->rng_inited)
		wc_FreeRng(&ctx->rng);
	if (ctx->key_inited)
		wc_FreeRsaKey(&ctx->key);
	/* FIPS 140-3: zeroize all key material before releasing memory */
	memzero_explicit(ctx, sizeof(*ctx));
	kfree(ctx);
}

/* Per-algo key_import wrappers — enforce exact key size for FIPS boundary */

static int wolfssl_rsa_2048_key_import(void **key_ctx, u32 key_type,
				       const u8 *raw, u32 rawlen)
{
	return wolfssl_rsa_key_import_size(key_ctx, key_type, raw, rawlen,
					   RSA_2048_KEY_BYTES);
}

static int wolfssl_rsa_4096_key_import(void **key_ctx, u32 key_type,
				       const u8 *raw, u32 rawlen)
{
	return wolfssl_rsa_key_import_size(key_ctx, key_type, raw, rawlen,
					   RSA_4096_KEY_BYTES);
}

static int wolfssl_rsa_sign(void *key_ctx, const char *hash_algo,
			    const u8 *digest, u32 digest_len,
			    u8 *sig, u32 sig_bufsz, u32 *sig_len)
{
	struct wolfssl_rsa_ctx *ctx = key_ctx;
	u8  digestinfo[DIGESTINFO_MAX_LEN];
	int digestinfo_len;
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!ctx || !digest || !sig || !sig_len)
		return -EINVAL;

	if (ctx->key_type == CRYPTO2DEV_KEY_PUBLIC)
		return -ENOKEY; /* sign requires private key */

	if (sig_bufsz < ctx->key_size_bytes)
		return -ENOBUFS;

	digestinfo_len = build_digestinfo(hash_algo, digest, digest_len,
					  digestinfo, sizeof(digestinfo));
	if (digestinfo_len < 0)
		return digestinfo_len;

	ret = wc_RsaSSL_Sign(digestinfo, (word32)digestinfo_len,
			     sig, sig_bufsz,
			     &ctx->key, &ctx->rng);
	if (ret <= 0) {
		pr_err_ratelimited("%s: wc_RsaSSL_Sign returned %d\n",
				   __func__, ret);
		memzero_explicit(digestinfo, sizeof(digestinfo));
		return wolfssl_rsa_xlat_err(ret);
	}
	*sig_len = (u32)ret;
	ret = 0;

	memzero_explicit(digestinfo, sizeof(digestinfo));
	return ret;
}

static int wolfssl_rsa_verify(void *key_ctx, const char *hash_algo,
			      const u8 *digest, u32 digest_len,
			      const u8 *sig, u32 sig_len)
{
	struct wolfssl_rsa_ctx *ctx = key_ctx;
	u8  expected[DIGESTINFO_MAX_LEN];
	int expected_len;
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!ctx || !digest || !sig)
		return -EINVAL;

	if (sig_len != ctx->key_size_bytes)
		return -EINVAL;

	expected_len = build_digestinfo(hash_algo, digest, digest_len,
					expected, sizeof(expected));
	if (expected_len < 0)
		return expected_len;

	{
		u8 *out;

		out = kmalloc(ctx->key_size_bytes, GFP_KERNEL);
		if (!out) {
			memzero_explicit(expected, sizeof(expected));
			return -ENOMEM;
		}

		/*
		 * wc_RsaSSL_Verify uses a non-standard return convention:
		 * positive = recovered DigestInfo byte count (success),
		 * negative = wolfCrypt error code.
		 * Zero is theoretically impossible for PKCS#1 v1.5 (minimum
		 * DigestInfo is non-empty) but guarded explicitly — xlat_err(0)
		 * has no switch case and falls through to -EIO, not -EBADMSG.
		 */
		ret = wc_RsaSSL_Verify(sig, sig_len, out,
					ctx->key_size_bytes, &ctx->key);
		if (ret > 0) {
			/*
			 * crypto_memneq: constant-time compare to avoid timing
			 * side-channel on PKCS#1 v1.5 DigestInfo comparison.
			 */
			if ((u32)ret == (u32)expected_len &&
			    crypto_memneq(out, expected, (size_t)expected_len) == 0)
				ret = 0;
			else
				ret = -EBADMSG;
		} else if (ret == 0) {
			/* Zero-length recovery: impossible for PKCS#1 but guard. */
			pr_err_ratelimited("%s: wc_RsaSSL_Verify returned 0 (unexpected)\n",
					   __func__);
			ret = -EBADMSG;
		} else {
			/* ret < 0: wolfCrypt error code */
			pr_err_ratelimited("%s: wc_RsaSSL_Verify returned %d\n",
					   __func__, ret);
			ret = wolfssl_rsa_xlat_err(ret);
		}

		memzero_explicit(out, ctx->key_size_bytes);
		kfree(out);
	}

	memzero_explicit(expected, sizeof(expected));
	return ret;
}

/* Internal helper: allocate ctx and generate an RSA key of key_bits size. */
static int wolfssl_rsa_key_generate_size(void **key_ctx, int key_bits)
{
	struct wolfssl_rsa_ctx *ctx;
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!key_ctx)
		return -EINVAL;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->key_type       = CRYPTO2DEV_KEY_PAIR;
	ctx->key_size_bytes = (u32)(key_bits / 8);

	ret = wc_InitRsaKey_ex(&ctx->key, NULL, INVALID_DEVID);
	if (ret != 0) {
		pr_err_ratelimited("%s: wc_InitRsaKey_ex returned %d\n",
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

	/* Generate RSA key: public exponent 65537 (FIPS 186-5 compliant) */
	ret = wc_MakeRsaKey(&ctx->key, key_bits, 65537, &ctx->rng);
	if (ret != 0) {
		pr_err_ratelimited("%s: wc_MakeRsaKey(%d) returned %d\n",
				   __func__, key_bits, ret);
		goto err_free_rng;
	}

	ret = wc_RsaSetRNG(&ctx->key, &ctx->rng);
	if (ret != 0) {
		pr_err_ratelimited("%s: wc_RsaSetRNG returned %d\n",
				   __func__, ret);
		goto err_free_rng;
	}

	*key_ctx = ctx;
	return 0;

err_free_rng:
	wc_FreeRng(&ctx->rng);
	ctx->rng_inited = false;
err_free_key:
	wc_FreeRsaKey(&ctx->key);
	ctx->key_inited = false;
err_free_ctx:
	memzero_explicit(ctx, sizeof(*ctx));
	kfree(ctx);
	return wolfssl_rsa_xlat_err(ret);
}

static int wolfssl_rsa_2048_key_generate(void **key_ctx)
{
	return wolfssl_rsa_key_generate_size(key_ctx, 2048);
}

static int wolfssl_rsa_4096_key_generate(void **key_ctx)
{
	return wolfssl_rsa_key_generate_size(key_ctx, 4096);
}

static int wolfssl_rsa_key_export_public(void *key_ctx,
					 u8 *out, u32 bufsz, u32 *outlen)
{
	struct wolfssl_rsa_ctx *ctx = key_ctx;
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!ctx || !out || !outlen)
		return -EINVAL;

	ret = wc_RsaKeyToPublicDer(&ctx->key, out, bufsz);
	if (ret <= 0) {
		pr_err_ratelimited("%s: wc_RsaKeyToPublicDer returned %d\n",
				   __func__, ret);
		return wolfssl_rsa_xlat_err(ret);
	}
	*outlen = (u32)ret;
	return 0;
}

static int wolfssl_rsa_key_export_private(void *key_ctx,
					  u8 *out, u32 bufsz, u32 *outlen)
{
	struct wolfssl_rsa_ctx *ctx = key_ctx;
	int ret;

	ret = wolfssl_fips_gate();
	if (ret)
		return ret;

	if (!ctx || !out || !outlen)
		return -EINVAL;

	if (ctx->key_type == CRYPTO2DEV_KEY_PUBLIC)
		return -ENOKEY;

	ret = wc_RsaKeyToDer(&ctx->key, out, bufsz);
	if (ret <= 0) {
		pr_err_ratelimited("%s: wc_RsaKeyToDer returned %d\n",
				   __func__, ret);
		return wolfssl_rsa_xlat_err(ret);
	}
	*outlen = (u32)ret;
	return 0;
}

/* ── algo_ops structs ──────────────────────────────────────────────── */

const struct crypto2dev_algo_ops wolfssl_rsa_2048_ops = {
	.algo               = "rsa-2048",
	.fips_gate          = wolfssl_fips_gate,
	.sess_init          = NULL,
	.sess_free          = NULL,
	.set_iv             = NULL,
	.gen_iv             = NULL,
	.set_aad            = NULL,
	.set_tag            = NULL,
	.get_tag            = NULL,
	.sign               = wolfssl_rsa_sign,
	.verify             = wolfssl_rsa_verify,
	.agree              = NULL,
	.kdf                = NULL,
	.min_iterations     = 0,
	.min_salt_len       = 0,
	.sess_reset         = NULL,
	.update             = NULL,
	.finalize           = NULL,
	.key_import         = wolfssl_rsa_2048_key_import,
	.key_generate       = wolfssl_rsa_2048_key_generate,
	.key_export_public  = wolfssl_rsa_key_export_public,
	.key_export_private = wolfssl_rsa_key_export_private,
	.key_free           = wolfssl_rsa_key_free,
};

const struct crypto2dev_algo_ops wolfssl_rsa_4096_ops = {
	.algo               = "rsa-4096",
	.fips_gate          = wolfssl_fips_gate,
	.sess_init          = NULL,
	.sess_free          = NULL,
	.set_iv             = NULL,
	.gen_iv             = NULL,
	.set_aad            = NULL,
	.set_tag            = NULL,
	.get_tag            = NULL,
	.sign               = wolfssl_rsa_sign,
	.verify             = wolfssl_rsa_verify,
	.agree              = NULL,
	.kdf                = NULL,
	.min_iterations     = 0,
	.min_salt_len       = 0,
	.sess_reset         = NULL,
	.update             = NULL,
	.finalize           = NULL,
	.key_import         = wolfssl_rsa_4096_key_import,
	.key_generate       = wolfssl_rsa_4096_key_generate,
	.key_export_public  = wolfssl_rsa_key_export_public,
	.key_export_private = wolfssl_rsa_key_export_private,
	.key_free           = wolfssl_rsa_key_free,
};
