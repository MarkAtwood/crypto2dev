// SPDX-License-Identifier: GPL-2.0-only
/*
 * test_shash.c — kernel module: SHA-256, HMAC-SHA-2, CMAC-AES-128 KAT
 *
 * Verifies wolfcrypt.ko's shash registrations via the kernel crypto API using
 * known-answer tests from NIST FIPS 180-4 (SHA-256), RFC 4231 (HMAC), and
 * NIST SP 800-38B (CMAC). Results emitted to dmesg at load time.
 *
 * Tests:
 *   SHA-256:       NIST FIPS 180-4 §B.1 — 4 vectors
 *   HMAC-SHA-256:  RFC 4231 §4.2–4.3   — 2 vectors
 *   HMAC-SHA-384:  RFC 4231 §4.2–4.4   — 3 vectors
 *   HMAC-SHA-512:  RFC 4231 §4.2–4.3   — 2 vectors
 *   CMAC-AES-128:  NIST SP 800-38B §D.1 — 4 vectors
 *
 * Load:
 *   insmod test_shash.ko
 *   dmesg | grep test_shash
 *
 * Expected dmesg (wolfcrypt.ko loaded):
 *   test_shash: PASS <source> ...
 *   test_shash: ALL TESTS PASSED (N/N)
 *
 * Requires wolfcrypt.ko to be loaded before insmod.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/fips.h>
#include <crypto/hash.h>

#include "../vectors/sha256.h"
#include "../vectors/hmac.h"
#include "../vectors/cmac.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("crypto2dev shash known-answer tests");
MODULE_AUTHOR("wolfSSL Inc.");

static int test_pass;
static int test_fail;

#define T_PASS(fmt, ...) do {                                              \
	pr_info("test_shash: PASS " fmt "\n", ##__VA_ARGS__);             \
	test_pass++;                                                       \
} while (0)

#define T_FAIL(fmt, ...) do {                                              \
	pr_err("test_shash: FAIL " fmt "\n", ##__VA_ARGS__);              \
	test_fail++;                                                       \
} while (0)

#define T_NOTE(fmt, ...) \
	pr_info("test_shash: NOTE " fmt "\n", ##__VA_ARGS__)

/*
 * run_shash_kat - allocate @algo, optionally set @key/@key_len, run a
 *                single-shot digest over @msg/@msg_len, compare the output
 *                against @expected[@digest_len].
 *
 * Returns 0 on pass, -1 on failure (counters updated via T_PASS/T_FAIL).
 */
static int run_shash_kat(const char *algo,
			 const u8 *key, unsigned int key_len,
			 const u8 *msg, unsigned int msg_len,
			 const u8 *expected, unsigned int digest_len,
			 const char *source)
{
	struct crypto_shash *tfm;
	SHASH_DESC_ON_STACK(desc, tfm);
	u8 out[64];   /* large enough for SHA-512 (64 bytes) */
	int ret = -1;

	if (digest_len > sizeof(out)) {
		T_FAIL("digest_len %u > buffer for %s", digest_len, source);
		return -1;
	}

	tfm = crypto_alloc_shash(algo, 0, 0);
	if (IS_ERR(tfm)) {
		T_FAIL("crypto_alloc_shash(\"%s\") failed: %ld [%s]",
		       algo, PTR_ERR(tfm), source);
		return -1;
	}

	if (key && key_len) {
		ret = crypto_shash_setkey(tfm, key, key_len);
		if (ret) {
			T_FAIL("setkey failed: %d [%s]", ret, source);
			goto out_free;
		}
	}

	desc->tfm = tfm;
	ret = crypto_shash_digest(desc, msg, msg_len, out);
	if (ret) {
		T_FAIL("digest failed: %d [%s]", ret, source);
		goto out_free;
	}

	if (memcmp(out, expected, digest_len) != 0) {
		T_FAIL("digest mismatch for %s", source);
		ret = -1;
		goto out_free;
	}

	T_PASS("%s", source);
	ret = 0;

out_free:
	memzero_explicit(out, sizeof(out));
	crypto_free_shash(tfm);
	return ret;
}

/* ── SHA-256 ────────────────────────────────────────────────────────────── */

static void test_sha256_kat(void)
{
	int i;

	for (i = 0; i < SHA256_VECTOR_COUNT; i++) {
		const struct sha256_vector *v = &sha256_vectors[i];

		run_shash_kat("sha256",
			      NULL, 0,
			      v->input, v->input_len,
			      v->digest, 32,
			      v->source);
	}
}

/* ── HMAC-SHA-256 ───────────────────────────────────────────────────────── */

static void test_hmac_sha256_kat(void)
{
	int i;

	for (i = 0; i < HMAC_SHA256_VECTOR_COUNT; i++) {
		const struct hmac_vector *v = &hmac_sha256_vectors[i];

		if (v->fips_skip && fips_enabled) {
			T_NOTE("SKIP (fips_enabled, key too short): %s", v->source);
			continue;
		}
		run_shash_kat("hmac(sha256)",
			      v->key, v->key_len,
			      v->input, v->input_len,
			      v->tag, v->tag_len,
			      v->source);
	}
}

/* ── HMAC-SHA-384 ───────────────────────────────────────────────────────── */

static void test_hmac_sha384_kat(void)
{
	int i;

	for (i = 0; i < HMAC_SHA384_VECTOR_COUNT; i++) {
		const struct hmac_vector *v = &hmac_sha384_vectors[i];

		if (v->fips_skip && fips_enabled) {
			T_NOTE("SKIP (fips_enabled, key too short): %s", v->source);
			continue;
		}
		run_shash_kat("hmac(sha384)",
			      v->key, v->key_len,
			      v->input, v->input_len,
			      v->tag, v->tag_len,
			      v->source);
	}
}

/* ── HMAC-SHA-512 ───────────────────────────────────────────────────────── */

static void test_hmac_sha512_kat(void)
{
	int i;

	for (i = 0; i < HMAC_SHA512_VECTOR_COUNT; i++) {
		const struct hmac_vector *v = &hmac_sha512_vectors[i];

		if (v->fips_skip && fips_enabled) {
			T_NOTE("SKIP (fips_enabled, key too short): %s", v->source);
			continue;
		}
		run_shash_kat("hmac(sha512)",
			      v->key, v->key_len,
			      v->input, v->input_len,
			      v->tag, v->tag_len,
			      v->source);
	}
}

/* ── CMAC-AES-128 ───────────────────────────────────────────────────────── */

static void test_cmac_aes128_kat(void)
{
	int i;

	for (i = 0; i < CMAC_VECTOR_COUNT; i++) {
		const struct cmac_vector *v = &cmac_vectors[i];

		run_shash_kat("cmac(aes)",
			      v->key, v->key_len,
			      v->msg, v->msg_len,
			      v->tag, 16,
			      v->source);
	}
}

/* ── Module init/exit ───────────────────────────────────────────────────── */

static int __init test_shash_init(void)
{
	test_sha256_kat();
	test_hmac_sha256_kat();
	test_hmac_sha384_kat();
	test_hmac_sha512_kat();
	test_cmac_aes128_kat();

	if (test_fail == 0)
		pr_info("test_shash: ALL TESTS PASSED (%d/%d)\n",
			test_pass, test_pass + test_fail);
	else
		pr_err("test_shash: TESTS FAILED (%d failed, %d passed)\n",
		       test_fail, test_pass);

	/* Return 0 even on test failure so dmesg can be inspected.
	 * CI scripts check for "FAIL" in dmesg rather than insmod exit code. */
	return 0;
}

static void __exit test_shash_exit(void)
{
}

module_init(test_shash_init);
module_exit(test_shash_exit);
