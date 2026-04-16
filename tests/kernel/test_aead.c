// SPDX-License-Identifier: GPL-2.0-only
/*
 * test_aead.c — kernel module: AES-GCM known-answer tests
 *
 * Verifies wolfcrypt.ko's AEAD registrations via the kernel crypto API.
 * Vectors from NIST SP 800-38D, McGrew-Viega, and wolfSSL's own test suite.
 * Results emitted to dmesg at load time.
 *
 * For each vector, the test:
 *   1. Encrypts the plaintext and verifies ciphertext + authentication tag.
 *   2. Decrypts the ciphertext+tag and verifies the recovered plaintext.
 *
 * Load:
 *   insmod test_aead.ko
 *   dmesg | grep test_aead
 *
 * Requires wolfcrypt.ko to be loaded before insmod.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/scatterlist.h>
#include <crypto/aead.h>

#include "../vectors/aes_gcm.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("crypto2dev AEAD known-answer tests");
MODULE_AUTHOR("wolfSSL Inc.");

static int test_pass;
static int test_fail;

#define T_PASS(fmt, ...) do {                                              \
	pr_info("test_aead: PASS " fmt "\n", ##__VA_ARGS__);              \
	test_pass++;                                                       \
} while (0)

#define T_FAIL(fmt, ...) do {                                              \
	pr_err("test_aead: FAIL " fmt "\n", ##__VA_ARGS__);               \
	test_fail++;                                                       \
} while (0)

/*
 * run_gcm_vector - encrypt then decrypt one AES-GCM vector.
 *
 * Encryption: verifies that the produced ciphertext and tag match the vector.
 * Decryption: verifies that decrypting CT+tag recovers the original plaintext
 *             and that authentication passes (no -EBADMSG).
 *
 * Returns 0 if both sub-tests pass, -1 if either fails.
 */
static int run_gcm_vector(const struct aes_gcm_vector *v)
{
	struct crypto_aead *tfm;
	struct aead_request *req;
	struct scatterlist sg;
	u8 *buf;
	u8 nonce[12];
	unsigned int buf_len;
	int ret = -1;

	/* catch a future vector with an uninitialised tag_len field */
	if (WARN_ON_ONCE(v->tag_len == 0 || v->tag_len > 16))
		return -EINVAL;

	buf_len = v->aad_len + v->pt_len + v->tag_len;
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(tfm)) {
		T_FAIL("crypto_alloc_aead(\"gcm(aes)\") failed: %ld [%s]",
		       PTR_ERR(tfm), v->source);
		kfree(buf);
		return -1;
	}

	ret = crypto_aead_setkey(tfm, v->key, v->key_len);
	if (ret) {
		T_FAIL("setkey failed: %d [%s]", ret, v->source);
		goto out_free_tfm;
	}

	ret = crypto_aead_setauthsize(tfm, v->tag_len);
	if (ret) {
		T_FAIL("setauthsize failed: %d [%s]", ret, v->source);
		goto out_free_tfm;
	}

	req = aead_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		T_FAIL("aead_request_alloc failed [%s]", v->source);
		ret = -ENOMEM;
		goto out_free_tfm;
	}

	/* ── Encrypt ──────────────────────────────────────────────────── */

	memset(buf, 0, buf_len);
	if (v->aad_len && v->aad)
		memcpy(buf, v->aad, v->aad_len);
	memcpy(buf + v->aad_len, v->plaintext, v->pt_len);
	/* tag space buf[aad_len+pt_len .. buf_len] is already zero */

	sg_init_one(&sg, buf, buf_len);
	memcpy(nonce, v->nonce, 12);

	aead_request_set_crypt(req, &sg, &sg, v->pt_len, nonce);
	aead_request_set_ad(req, v->aad_len);

	ret = crypto_aead_encrypt(req);
	if (ret) {
		T_FAIL("encrypt failed: %d [%s]", ret, v->source);
		goto out_free_req;
	}

	if (memcmp(buf + v->aad_len, v->ciphertext, v->pt_len) != 0) {
		T_FAIL("ciphertext mismatch [%s]", v->source);
		ret = -1;
		goto out_free_req;
	}

	if (memcmp(buf + v->aad_len + v->pt_len, v->tag, v->tag_len) != 0) {
		T_FAIL("tag mismatch [%s]", v->source);
		ret = -1;
		goto out_free_req;
	}

	T_PASS("gcm(aes) encrypt %s", v->source);

	/* ── Decrypt ──────────────────────────────────────────────────── */

	memset(buf, 0, buf_len);
	if (v->aad_len && v->aad)
		memcpy(buf, v->aad, v->aad_len);
	memcpy(buf + v->aad_len,          v->ciphertext, v->pt_len);
	memcpy(buf + v->aad_len + v->pt_len, v->tag,     v->tag_len);

	sg_init_one(&sg, buf, buf_len);
	memcpy(nonce, v->nonce, 12);

	aead_request_set_crypt(req, &sg, &sg, v->pt_len + v->tag_len, nonce);
	aead_request_set_ad(req, v->aad_len);

	ret = crypto_aead_decrypt(req);
	if (ret == -EBADMSG) {
		T_FAIL("decrypt: authentication failure [%s]", v->source);
		ret = -1;
		goto out_free_req;
	}
	if (ret) {
		T_FAIL("decrypt failed: %d [%s]", ret, v->source);
		goto out_free_req;
	}

	if (memcmp(buf + v->aad_len, v->plaintext, v->pt_len) != 0) {
		T_FAIL("decrypted plaintext mismatch [%s]", v->source);
		ret = -1;
		goto out_free_req;
	}

	T_PASS("gcm(aes) decrypt %s", v->source);
	ret = 0;

out_free_req:
	aead_request_free(req);
out_free_tfm:
	crypto_free_aead(tfm);
	memzero_explicit(buf, buf_len);
	kfree(buf);
	return ret;
}

/* ── AES-GCM KAT ────────────────────────────────────────────────────────── */

static void test_gcm_kat(void)
{
	int i;

	for (i = 0; i < AES_GCM_VECTOR_COUNT; i++)
		run_gcm_vector(&aes_gcm_vectors[i]);
}

/* ── Module init/exit ───────────────────────────────────────────────────── */

static int __init test_aead_init(void)
{
	test_gcm_kat();

	if (test_fail == 0)
		pr_info("test_aead: ALL TESTS PASSED (%d/%d)\n",
			test_pass, test_pass + test_fail);
	else
		pr_err("test_aead: TESTS FAILED (%d failed, %d passed)\n",
		       test_fail, test_pass);

	/* Return 0 even on test failure so dmesg can be inspected.
	 * CI scripts check for "FAIL" in dmesg rather than insmod exit code. */
	return 0;
}

static void __exit test_aead_exit(void)
{
}

module_init(test_aead_init);
module_exit(test_aead_exit);
