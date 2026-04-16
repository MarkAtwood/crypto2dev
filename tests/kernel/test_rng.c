// SPDX-License-Identifier: GPL-2.0-only
/*
 * test_rng.c — kernel module: DRBG behavioral tests
 *
 * Exercises wolfcrypt.ko's DRBG registration via the kernel crypto API.
 * These are behavioral tests (not KATs): a properly seeded DRBG produces
 * unpredictable output, so the tests verify non-trivial, non-repeating
 * output and sustained generation under load.
 *
 * Tests:
 *   1. non-trivial:   32 bytes generated are not all-zero.
 *   2. non-repeating: two consecutive 32-byte generations differ.
 *   3. stress:        10240 bytes generated without error.
 *
 * Load:
 *   insmod test_rng.ko
 *   dmesg | grep test_rng
 *
 * Requires wolfcrypt.ko to be loaded before insmod.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <crypto/rng.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("crypto2dev DRBG behavioral tests");
MODULE_AUTHOR("wolfSSL Inc.");

/* Use the kernel's default PRNG, which wolfcrypt.ko registers at high priority
 * when loaded.  "stdrng" resolves to the highest-priority rng implementation. */
#define RNG_ALGO  "stdrng"

static int test_pass;
static int test_fail;

#define T_PASS(fmt, ...) do {                                              \
	pr_info("test_rng: PASS " fmt "\n", ##__VA_ARGS__);               \
	test_pass++;                                                       \
} while (0)

#define T_FAIL(fmt, ...) do {                                              \
	pr_err("test_rng: FAIL " fmt "\n", ##__VA_ARGS__);                \
	test_fail++;                                                       \
} while (0)

#define T_NOTE(fmt, ...) \
	pr_info("test_rng: NOTE " fmt "\n", ##__VA_ARGS__)

/* ── Test 1: non-trivial output ─────────────────────────────────────────── */
/*
 * A properly functioning DRBG should not produce all-zero output.  This
 * catches initialization failures and stub implementations that always return
 * zeros.
 */
static void test_rng_non_trivial(void)
{
	struct crypto_rng *rng;
	u8 buf[32];
	unsigned int i;
	int ret;

	rng = crypto_alloc_rng(RNG_ALGO, 0, 0);
	if (IS_ERR(rng)) {
		T_FAIL("crypto_alloc_rng(\"%s\") failed: %ld", RNG_ALGO, PTR_ERR(rng));
		return;
	}

	memset(buf, 0, sizeof(buf));
	ret = crypto_rng_get_bytes(rng, buf, sizeof(buf));
	if (ret) {
		T_FAIL("get_bytes(32) failed: %d", ret);
		goto out;
	}

	for (i = 0; i < sizeof(buf); i++) {
		if (buf[i] != 0)
			break;
	}
	if (i == sizeof(buf)) {
		T_FAIL("32 bytes are all-zero — DRBG not functioning");
		goto out;
	}

	T_PASS("DRBG produced non-zero output");

out:
	memzero_explicit(buf, sizeof(buf));
	crypto_free_rng(rng);
}

/* ── Test 2: successive outputs differ ──────────────────────────────────── */
/*
 * Two consecutive 32-byte generations must differ.  A DRBG that repeats
 * output is broken or not advancing its internal state.
 */
static void test_rng_non_repeating(void)
{
	struct crypto_rng *rng;
	u8 buf1[32], buf2[32];
	int ret;

	rng = crypto_alloc_rng(RNG_ALGO, 0, 0);
	if (IS_ERR(rng)) {
		T_FAIL("crypto_alloc_rng(\"%s\") failed: %ld", RNG_ALGO, PTR_ERR(rng));
		return;
	}

	ret = crypto_rng_get_bytes(rng, buf1, sizeof(buf1));
	if (ret) {
		T_FAIL("get_bytes(32) #1 failed: %d", ret);
		goto out;
	}

	ret = crypto_rng_get_bytes(rng, buf2, sizeof(buf2));
	if (ret) {
		T_FAIL("get_bytes(32) #2 failed: %d", ret);
		goto out;
	}

	if (memcmp(buf1, buf2, sizeof(buf1)) == 0) {
		T_FAIL("two consecutive 32-byte outputs are identical");
		goto out;
	}

	T_PASS("consecutive DRBG outputs differ");

out:
	memzero_explicit(buf1, sizeof(buf1));
	memzero_explicit(buf2, sizeof(buf2));
	crypto_free_rng(rng);
}

/* ── Test 3: stress — 10240 bytes without error ─────────────────────────── */

static void test_rng_stress(void)
{
	struct crypto_rng *rng;
	u8 *buf;
	int ret;

	rng = crypto_alloc_rng(RNG_ALGO, 0, 0);
	if (IS_ERR(rng)) {
		T_FAIL("crypto_alloc_rng(\"%s\") failed: %ld", RNG_ALGO, PTR_ERR(rng));
		return;
	}

	buf = kmalloc(10240, GFP_KERNEL);
	if (!buf) {
		T_FAIL("kmalloc(10240) failed");
		crypto_free_rng(rng);
		return;
	}

	ret = crypto_rng_get_bytes(rng, buf, 10240);
	if (ret) {
		T_FAIL("get_bytes(10240) failed: %d", ret);
		goto out;
	}

	T_PASS("DRBG generated 10240 bytes without error");

out:
	memzero_explicit(buf, 10240);
	kfree(buf);
	crypto_free_rng(rng);
}

/* ── Module init/exit ───────────────────────────────────────────────────── */

static int __init test_rng_init(void)
{
	struct crypto_rng *probe;

	/* Log which driver was selected for "stdrng". */
	probe = crypto_alloc_rng(RNG_ALGO, 0, 0);
	if (!IS_ERR(probe)) {
		T_NOTE("stdrng driver: %s",
		       crypto_tfm_alg_driver_name(crypto_rng_tfm(probe)));
		crypto_free_rng(probe);
	}

	test_rng_non_trivial();
	test_rng_non_repeating();
	test_rng_stress();

	if (test_fail == 0)
		pr_info("test_rng: ALL TESTS PASSED (%d/%d)\n",
			test_pass, test_pass + test_fail);
	else
		pr_err("test_rng: TESTS FAILED (%d failed, %d passed)\n",
		       test_fail, test_pass);

	/* Return 0 even on test failure so dmesg can be inspected.
	 * CI scripts check for "FAIL" in dmesg rather than insmod exit code. */
	return 0;
}

static void __exit test_rng_exit(void)
{
}

module_init(test_rng_init);
module_exit(test_rng_exit);
