// SPDX-License-Identifier: GPL-2.0-only
/*
 * test_skcipher.c — kernel module: AES-CBC known-answer tests
 *
 * Verifies wolfcrypt.ko's skcipher registrations via the kernel crypto API.
 * Vectors from NIST SP 800-38A Appendix F.2. Results emitted to dmesg at
 * load time.
 *
 * For each vector, the test:
 *   1. Encrypts the plaintext and verifies the ciphertext.
 *   2. Decrypts the ciphertext and verifies the recovered plaintext.
 *
 * Load:
 *   insmod test_skcipher.ko
 *   dmesg | grep test_skcipher
 *
 * Requires wolfcrypt.ko to be loaded before insmod.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/scatterlist.h>
#include <crypto/skcipher.h>

#include "../vectors/aes_cbc.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("crypto2dev skcipher known-answer tests");
MODULE_AUTHOR("wolfSSL Inc.");

#define IV_LEN  16   /* AES block size */

static int test_pass;
static int test_fail;

#define T_PASS(fmt, ...) do {                                              \
	pr_info("test_skcipher: PASS " fmt "\n", ##__VA_ARGS__);          \
	test_pass++;                                                       \
} while (0)

#define T_FAIL(fmt, ...) do {                                              \
	pr_err("test_skcipher: FAIL " fmt "\n", ##__VA_ARGS__);           \
	test_fail++;                                                       \
} while (0)

/*
 * run_cbc_vector - encrypt then decrypt one AES-CBC vector.
 *
 * Encryption: verifies the produced ciphertext matches the vector.
 * Decryption: verifies the recovered plaintext matches the vector.
 *
 * Returns 0 if both sub-tests pass, -1 if either fails.
 */
static int run_cbc_vector(const struct aes_cbc_vector *v)
{
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
	struct scatterlist sg;
	u8 *buf;
	u8 iv[IV_LEN];
	int ret = -1;

	buf = kmalloc(v->len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	tfm = crypto_alloc_skcipher("cbc(aes)", 0, 0);
	if (IS_ERR(tfm)) {
		T_FAIL("crypto_alloc_skcipher(\"cbc(aes)\") failed: %ld [%s]",
		       PTR_ERR(tfm), v->source);
		kfree(buf);
		return -1;
	}

	ret = crypto_skcipher_setkey(tfm, v->key, v->key_len);
	if (ret) {
		T_FAIL("setkey failed: %d [%s]", ret, v->source);
		goto out_free_tfm;
	}

	req = skcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		T_FAIL("skcipher_request_alloc failed [%s]", v->source);
		ret = -ENOMEM;
		goto out_free_tfm;
	}

	/* ── Encrypt ──────────────────────────────────────────────────── */

	memcpy(buf, v->plaintext, v->len);
	memcpy(iv,  v->iv,        IV_LEN);
	sg_init_one(&sg, buf, v->len);
	skcipher_request_set_crypt(req, &sg, &sg, v->len, iv);

	ret = crypto_skcipher_encrypt(req);
	if (ret) {
		T_FAIL("encrypt failed: %d [%s]", ret, v->source);
		goto out_free_req;
	}

	if (memcmp(buf, v->ciphertext, v->len) != 0) {
		T_FAIL("ciphertext mismatch [%s]", v->source);
		ret = -1;
		goto out_free_req;
	}

	T_PASS("cbc(aes) encrypt %s", v->source);

	/* ── Decrypt ──────────────────────────────────────────────────── */

	memcpy(buf, v->ciphertext, v->len);
	memcpy(iv,  v->iv,         IV_LEN);
	sg_init_one(&sg, buf, v->len);
	skcipher_request_set_crypt(req, &sg, &sg, v->len, iv);

	ret = crypto_skcipher_decrypt(req);
	if (ret) {
		T_FAIL("decrypt failed: %d [%s]", ret, v->source);
		goto out_free_req;
	}

	if (memcmp(buf, v->plaintext, v->len) != 0) {
		T_FAIL("decrypted plaintext mismatch [%s]", v->source);
		ret = -1;
		goto out_free_req;
	}

	T_PASS("cbc(aes) decrypt %s", v->source);
	ret = 0;

out_free_req:
	skcipher_request_free(req);
out_free_tfm:
	crypto_free_skcipher(tfm);
	memzero_explicit(buf, v->len);
	memzero_explicit(iv, sizeof(iv));
	kfree(buf);
	return ret;
}

/* ── AES-CBC KAT ────────────────────────────────────────────────────────── */

static void test_cbc_kat(void)
{
	int i;

	for (i = 0; i < AES_CBC_VECTOR_COUNT; i++)
		run_cbc_vector(&aes_cbc_vectors[i]);
}

/* ── Module init/exit ───────────────────────────────────────────────────── */

static int __init test_skcipher_init(void)
{
	test_cbc_kat();

	if (test_fail == 0)
		pr_info("test_skcipher: ALL TESTS PASSED (%d/%d)\n",
			test_pass, test_pass + test_fail);
	else
		pr_err("test_skcipher: TESTS FAILED (%d failed, %d passed)\n",
		       test_fail, test_pass);

	/* Return 0 even on test failure so dmesg can be inspected.
	 * CI scripts check for "FAIL" in dmesg rather than insmod exit code. */
	return 0;
}

static void __exit test_skcipher_exit(void)
{
}

module_init(test_skcipher_init);
module_exit(test_skcipher_exit);
