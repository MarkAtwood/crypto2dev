// SPDX-License-Identifier: GPL-2.0-only
/*
 * test_chardev.c — /dev/crypto2dev session lifecycle and streaming tests
 *
 * Tests NIST CAVP vectors for AES-CBC and AES-GCM, SHA-256 hash, and the
 * FINALIZE ioctl for the streaming I/O model.
 *
 * Compile:
 *   gcc -Wall -o test_chardev test_chardev.c \
 *       -I../../include -I../vectors
 *
 * Run as root with crypto2dev.ko loaded:
 *   sudo ./test_chardev
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>

#include "uapi/crypto2dev_ioctl.h"

#include "../vectors/aes_cbc.h"
#include "../vectors/aes_gcm.h"
#include "../vectors/sha256.h"
#include "../vectors/sha3.h"
#include "../vectors/hmac.h"

#define DEVICE_PATH  "/dev/crypto2dev"
#define MAX_OUT_BUF  4096

/* ── Test result tracking ─────────────────────────────────────────────────── */

static int g_pass;
static int g_fail;

#define FAIL(fmt, ...) do {                                                 \
	fprintf(stderr, "FAIL [%s:%d]: " fmt "\n",                          \
		__func__, __LINE__, ##__VA_ARGS__);                         \
	g_fail++;                                                           \
	return -1;                                                          \
} while (0)

#define PASS() do { g_pass++; return 0; } while (0)

/* ── Helpers ──────────────────────────────────────────────────────────────── */

static int open_dev(void)
{
	int fd = open(DEVICE_PATH, O_RDWR);

	if (fd < 0) {
		if (errno == ENOENT)
			fprintf(stderr,
				"SKIP: %s not found — module not loaded?\n",
				DEVICE_PATH);
		else
			fprintf(stderr, "open %s: %s\n",
				DEVICE_PATH, strerror(errno));
	}
	return fd;
}

static int do_init(int fd, const char *algo, __u32 op,
		   const unsigned char *key, unsigned int keylen)
{
	struct crypto2dev_init_op init;

	memset(&init, 0, sizeof(init));
	strncpy(init.algo, algo, sizeof(init.algo) - 1);
	init.op     = op;
	init.keylen = (__u32)keylen;
	if (key && keylen)
		memcpy(init.key, key, keylen);
	init.key_fd = -1;

	return ioctl(fd, CRYPTO2DEV_IOC_INIT, &init);
}

static int do_set_iv(int fd, const unsigned char *iv, unsigned int ivlen)
{
	struct crypto2dev_iv_op iv_op;

	memset(&iv_op, 0, sizeof(iv_op));
	memcpy(iv_op.iv, iv, ivlen);
	iv_op.ivlen = (__u32)ivlen;
	return ioctl(fd, CRYPTO2DEV_IOC_SET_IV, &iv_op);
}

static int do_set_aad(int fd, const unsigned char *aad, unsigned int aadlen)
{
	struct crypto2dev_aad_op aad_op;

	memset(&aad_op, 0, sizeof(aad_op));
	if (aad && aadlen)
		memcpy(aad_op.aad, aad, aadlen);
	aad_op.aadlen = (__u32)aadlen;
	return ioctl(fd, CRYPTO2DEV_IOC_SET_AAD, &aad_op);
}

static int do_set_tag(int fd, const unsigned char *tag, unsigned int taglen)
{
	struct crypto2dev_tag_op tag_op;

	memset(&tag_op, 0, sizeof(tag_op));
	memcpy(tag_op.tag, tag, taglen);
	tag_op.taglen = (__u32)taglen;
	return ioctl(fd, CRYPTO2DEV_IOC_SET_TAG, &tag_op);
}

static int do_get_state(int fd, struct crypto2dev_fd_state_info *out)
{
	memset(out, 0, sizeof(*out));
	return ioctl(fd, CRYPTO2DEV_IOC_GET_STATE, out);
}

static int do_get_tag(int fd, unsigned char *tag_out, unsigned int *taglen_out)
{
	struct crypto2dev_tag_op tag_op;
	int ret;

	memset(&tag_op, 0, sizeof(tag_op));
	ret = ioctl(fd, CRYPTO2DEV_IOC_GET_TAG, &tag_op);
	if (ret == 0) {
		memcpy(tag_out, tag_op.tag, tag_op.taglen);
		*taglen_out = tag_op.taglen;
	}
	return ret;
}

/* ── CBC tests ────────────────────────────────────────────────────────────── */

/*
 * One-shot CBC encrypt or decrypt:
 *   INIT → SET_IV → write(all input) → FINALIZE → read(output)
 *
 * For CBC streaming providers, update() processes complete blocks immediately;
 * the output is in the outbuf before FINALIZE is called.  FINALIZE returns
 * *outlen=0 (no tail, block-aligned input) and sets finalized=true.
 */
static int run_cbc_oneshot(const struct aes_cbc_vector *v, int direction)
{
	unsigned char outbuf[64];
	const unsigned char *input;
	const unsigned char *expected;
	ssize_t n;
	int fd, ret = -1;

	fd = open_dev();
	if (fd < 0)
		return -1;

	if (do_init(fd, "cbc(aes)", (__u32)direction, v->key, v->key_len) != 0) {
		fprintf(stderr, "INIT failed: %s\n", strerror(errno));
		goto out;
	}

	if (do_set_iv(fd, v->iv, 16) != 0) {
		fprintf(stderr, "SET_IV failed: %s\n", strerror(errno));
		goto out;
	}

	input    = (direction == CRYPTO2DEV_OP_ENCRYPT) ?
		   v->plaintext : v->ciphertext;
	expected = (direction == CRYPTO2DEV_OP_ENCRYPT) ?
		   v->ciphertext : v->plaintext;

	n = write(fd, input, v->len);
	if (n < 0 || (unsigned)n != v->len) {
		fprintf(stderr, "write returned %zd, expected %u: %s\n",
			n, v->len, strerror(errno));
		goto out;
	}

	if (ioctl(fd, CRYPTO2DEV_IOC_FINALIZE) != 0) {
		fprintf(stderr, "FINALIZE failed: %s\n", strerror(errno));
		goto out;
	}

	n = read(fd, outbuf, sizeof(outbuf));
	if (n < 0 || (unsigned)n != v->len) {
		fprintf(stderr, "read returned %zd, expected %u: %s\n",
			n, v->len, strerror(errno));
		goto out;
	}

	if (memcmp(outbuf, expected, v->len) != 0) {
		fprintf(stderr, "output mismatch for %s\n", v->source);
		goto out;
	}
	ret = 0;

out:
	close(fd);
	return ret;
}

static int test_cbc_nist_vectors(void)
{
	int i, r = 0;

	for (i = 0; i < AES_CBC_VECTOR_COUNT; i++) {
		if (run_cbc_oneshot(&aes_cbc_vectors[i], CRYPTO2DEV_OP_ENCRYPT)) {
			fprintf(stderr, "CBC encrypt vector %d failed: %s\n",
				i, aes_cbc_vectors[i].source);
			r = -1;
		}
		if (run_cbc_oneshot(&aes_cbc_vectors[i], CRYPTO2DEV_OP_DECRYPT)) {
			fprintf(stderr, "CBC decrypt vector %d failed: %s\n",
				i, aes_cbc_vectors[i].source);
			r = -1;
		}
	}
	if (r == 0)
		g_pass++;
	else
		g_fail++;
	return r;
}

/*
 * Streaming CBC: write one block at a time, read after each write.
 *
 * Uses vector 0 (AES-128-CBC, 32-byte plaintext):
 *   write(block0) → read(block0 CT)
 *   write(block1) → read(block1 CT)
 *   FINALIZE → read(0, EOF)
 */
static int test_cbc_streaming_encrypt(void)
{
	const struct aes_cbc_vector *v = &aes_cbc_vectors[0]; /* AES-128, 32B */
	unsigned char outbuf[16];
	unsigned char all_ct[32];
	ssize_t n;
	int i, fd;

	fd = open_dev();
	if (fd < 0)
		return -1;

	if (do_init(fd, "cbc(aes)", CRYPTO2DEV_OP_ENCRYPT, v->key, v->key_len)
	    || do_set_iv(fd, v->iv, 16)) {
		fprintf(stderr, "INIT/SET_IV failed: %s\n", strerror(errno));
		close(fd);
		g_fail++;
		return -1;
	}

	for (i = 0; i < 2; i++) {
		n = write(fd, v->plaintext + i * 16, 16);
		if (n != 16) {
			fprintf(stderr, "streaming write %d returned %zd: %s\n",
				i, n, strerror(errno));
			close(fd);
			g_fail++;
			return -1;
		}
		n = read(fd, outbuf, sizeof(outbuf));
		if (n != 16) {
			fprintf(stderr, "streaming read %d returned %zd: %s\n",
				i, n, strerror(errno));
			close(fd);
			g_fail++;
			return -1;
		}
		memcpy(all_ct + i * 16, outbuf, 16);
	}

	if (ioctl(fd, CRYPTO2DEV_IOC_FINALIZE) != 0) {
		fprintf(stderr, "FINALIZE failed: %s\n", strerror(errno));
		close(fd);
		g_fail++;
		return -1;
	}

	/* After FINALIZE, outbuf is empty for block-aligned CBC — EOF */
	n = read(fd, outbuf, sizeof(outbuf));
	if (n != 0) {
		fprintf(stderr, "post-FINALIZE read returned %zd, expected 0\n",
			n);
		close(fd);
		g_fail++;
		return -1;
	}

	close(fd);

	if (memcmp(all_ct, v->ciphertext, 32) != 0) {
		fprintf(stderr, "CBC streaming: ciphertext mismatch (%s)\n",
			v->source);
		g_fail++;
		return -1;
	}

	g_pass++;
	return 0;
}

/* ── GCM tests ────────────────────────────────────────────────────────────── */

/*
 * GCM encrypt oneshot:
 *   INIT → SET_IV → SET_AAD → write(PT) → FINALIZE → read(CT) → GET_TAG
 *
 * GCM encrypt uses the streaming API (wc_AesGcmEncryptInit/Update/Final).
 * write() outputs ciphertext immediately; FINALIZE produces the auth tag,
 * stored in the provider context and retrieved via GET_TAG.
 */
static int run_gcm_encrypt(const struct aes_gcm_vector *v)
{
	unsigned char ctbuf[256];
	unsigned char tagbuf[16];
	unsigned int taglen = 0;
	ssize_t n;
	int fd, ret = -1;

	fd = open_dev();
	if (fd < 0)
		return -1;

	if (do_init(fd, "gcm(aes)", CRYPTO2DEV_OP_ENCRYPT,
		    v->key, v->key_len) != 0) {
		fprintf(stderr, "GCM INIT failed: %s\n", strerror(errno));
		goto out;
	}

	if (do_set_iv(fd, v->nonce, 12) != 0) {
		fprintf(stderr, "GCM SET_IV failed: %s\n", strerror(errno));
		goto out;
	}

	if (v->aad_len > 0 && do_set_aad(fd, v->aad, v->aad_len) != 0) {
		fprintf(stderr, "GCM SET_AAD failed: %s\n", strerror(errno));
		goto out;
	}

	if (v->pt_len > 0) {
		n = write(fd, v->plaintext, v->pt_len);
		if (n < 0 || (unsigned)n != v->pt_len) {
			fprintf(stderr, "GCM write returned %zd, expected %u: %s\n",
				n, v->pt_len, strerror(errno));
			goto out;
		}
	}

	if (ioctl(fd, CRYPTO2DEV_IOC_FINALIZE) != 0) {
		fprintf(stderr, "GCM FINALIZE failed: %s\n", strerror(errno));
		goto out;
	}

	if (v->pt_len > 0) {
		n = read(fd, ctbuf, sizeof(ctbuf));
		if (n < 0 || (unsigned)n != v->pt_len) {
			fprintf(stderr, "GCM CT read returned %zd, expected %u: %s\n",
				n, v->pt_len, strerror(errno));
			goto out;
		}
		if (memcmp(ctbuf, v->ciphertext, v->pt_len) != 0) {
			fprintf(stderr, "GCM ciphertext mismatch: %s\n",
				v->source);
			goto out;
		}
	}

	if (do_get_tag(fd, tagbuf, &taglen) != 0) {
		fprintf(stderr, "GCM GET_TAG failed: %s\n", strerror(errno));
		goto out;
	}

	/* Per NIST SP 800-38D §7.2, a shorter tag is the leftmost bytes of
	 * the full tag.  Accept a returned tag that is at least v->tag_len
	 * bytes and whose first v->tag_len bytes match the vector. */
	if (taglen < v->tag_len || memcmp(tagbuf, v->tag, v->tag_len) != 0) {
		fprintf(stderr, "GCM tag mismatch: %s\n", v->source);
		goto out;
	}

	ret = 0;
out:
	close(fd);
	return ret;
}

/*
 * GCM decrypt oneshot:
 *   INIT → SET_IV → SET_AAD → SET_TAG → write(CT) → FINALIZE → read(PT)
 *
 * GCM decrypt uses batch accumulation: write() buffers all ciphertext;
 * FINALIZE verifies the auth tag and decrypts into the outbuf.
 * No plaintext is released before tag verification.
 */
static int run_gcm_decrypt(const struct aes_gcm_vector *v)
{
	unsigned char ptbuf[256];
	ssize_t n;
	int fd, ret = -1;

	fd = open_dev();
	if (fd < 0)
		return -1;

	if (do_init(fd, "gcm(aes)", CRYPTO2DEV_OP_DECRYPT,
		    v->key, v->key_len) != 0) {
		fprintf(stderr, "GCM decrypt INIT failed: %s\n",
			strerror(errno));
		goto out;
	}

	if (do_set_iv(fd, v->nonce, 12) != 0) {
		fprintf(stderr, "GCM decrypt SET_IV failed: %s\n",
			strerror(errno));
		goto out;
	}

	if (v->aad_len > 0 && do_set_aad(fd, v->aad, v->aad_len) != 0) {
		fprintf(stderr, "GCM decrypt SET_AAD failed: %s\n",
			strerror(errno));
		goto out;
	}

	if (do_set_tag(fd, v->tag, v->tag_len) != 0) {
		fprintf(stderr, "GCM decrypt SET_TAG failed: %s\n",
			strerror(errno));
		goto out;
	}

	if (v->pt_len > 0) {
		/* write() buffers CT; no plaintext until tag is verified */
		n = write(fd, v->ciphertext, v->pt_len);
		if (n < 0 || (unsigned)n != v->pt_len) {
			fprintf(stderr, "GCM decrypt write returned %zd: %s\n",
				n, strerror(errno));
			goto out;
		}

		/* read() before FINALIZE returns 0 — no plaintext available */
		n = read(fd, ptbuf, sizeof(ptbuf));
		if (n != 0) {
			fprintf(stderr,
				"GCM decrypt: pre-FINALIZE read returned %zd, expected 0\n",
				n);
			goto out;
		}
	}

	/* FINALIZE: verify tag + decrypt; plaintext goes into outbuf */
	if (ioctl(fd, CRYPTO2DEV_IOC_FINALIZE) != 0) {
		fprintf(stderr, "GCM decrypt FINALIZE failed: %s\n",
			strerror(errno));
		goto out;
	}

	if (v->pt_len > 0) {
		n = read(fd, ptbuf, sizeof(ptbuf));
		if (n < 0 || (unsigned)n != v->pt_len) {
			fprintf(stderr,
				"GCM decrypt PT read returned %zd, expected %u: %s\n",
				n, v->pt_len, strerror(errno));
			goto out;
		}
		if (memcmp(ptbuf, v->plaintext, v->pt_len) != 0) {
			fprintf(stderr, "GCM decrypt plaintext mismatch: %s\n",
				v->source);
			goto out;
		}
	}

	ret = 0;
out:
	close(fd);
	return ret;
}

static int test_gcm_nist_vectors(void)
{
	int i, r = 0;

	for (i = 0; i < AES_GCM_VECTOR_COUNT; i++) {
		if (aes_gcm_vectors[i].tag_len == 0 ||
		    aes_gcm_vectors[i].tag_len > sizeof(aes_gcm_vectors[i].tag)) {
			fprintf(stderr,
				"GCM vector %d has invalid tag_len %u\n",
				i, aes_gcm_vectors[i].tag_len);
			r = -1;
			continue;
		}
		if (run_gcm_encrypt(&aes_gcm_vectors[i])) {
			fprintf(stderr, "GCM encrypt vector %d failed: %s\n",
				i, aes_gcm_vectors[i].source);
			r = -1;
		}
		if (run_gcm_decrypt(&aes_gcm_vectors[i])) {
			fprintf(stderr, "GCM decrypt vector %d failed: %s\n",
				i, aes_gcm_vectors[i].source);
			r = -1;
		}
	}
	if (r == 0)
		g_pass++;
	else
		g_fail++;
	return r;
}

/* ── SHA-256 tests ────────────────────────────────────────────────────────── */

/*
 * SHA-256 oneshot:
 *   INIT(sha256, OP_HASH, no key) → [write(input)] → FINALIZE → read(32B)
 *
 * Hash providers buffer all input internally; update() returns *outlen=0.
 * read() before FINALIZE returns 0. After FINALIZE, read() returns the digest.
 */
static int run_sha256_oneshot(const struct sha256_vector *v)
{
	unsigned char digest[32];
	ssize_t n;
	int fd, ret = -1;

	fd = open_dev();
	if (fd < 0)
		return -1;

	if (do_init(fd, "sha256", CRYPTO2DEV_OP_HASH, NULL, 0) != 0) {
		fprintf(stderr, "SHA-256 INIT failed: %s\n", strerror(errno));
		goto out;
	}

	if (v->input_len > 0) {
		n = write(fd, v->input, v->input_len);
		if (n < 0 || (unsigned)n != v->input_len) {
			fprintf(stderr, "SHA-256 write returned %zd: %s\n",
				n, strerror(errno));
			goto out;
		}

		/* read() before FINALIZE returns 0 for hash operations */
		n = read(fd, digest, sizeof(digest));
		if (n != 0) {
			fprintf(stderr,
				"SHA-256: pre-FINALIZE read returned %zd, expected 0\n",
				n);
			goto out;
		}
	}

	if (ioctl(fd, CRYPTO2DEV_IOC_FINALIZE) != 0) {
		fprintf(stderr, "SHA-256 FINALIZE failed: %s\n",
			strerror(errno));
		goto out;
	}

	n = read(fd, digest, sizeof(digest));
	if (n != 32) {
		fprintf(stderr, "SHA-256 read returned %zd, expected 32: %s\n",
			n, strerror(errno));
		goto out;
	}

	if (memcmp(digest, v->digest, 32) != 0) {
		fprintf(stderr, "SHA-256 digest mismatch: %s\n", v->source);
		goto out;
	}

	ret = 0;
out:
	close(fd);
	return ret;
}

static int test_sha256_vectors(void)
{
	int i, r = 0;

	for (i = 0; i < SHA256_VECTOR_COUNT; i++) {
		if (run_sha256_oneshot(&sha256_vectors[i])) {
			fprintf(stderr, "SHA-256 vector %d failed: %s\n",
				i, sha256_vectors[i].source);
			r = -1;
		}
	}
	if (r == 0)
		g_pass++;
	else
		g_fail++;
	return r;
}

/* ── SHA3-256 tests ───────────────────────────────────────────────────────── */

/*
 * SHA3-256 oneshot:
 *   INIT(sha3-256, OP_HASH, no key) → [write(input)] → FINALIZE → read(32B)
 */
static int run_sha3_256_oneshot(const struct sha3_256_vector *v)
{
	unsigned char digest[32];
	ssize_t n;
	int fd, ret = -1;

	fd = open_dev();
	if (fd < 0)
		return -1;

	if (do_init(fd, "sha3-256", CRYPTO2DEV_OP_HASH, NULL, 0) != 0) {
		fprintf(stderr, "SHA3-256 INIT failed: %s\n", strerror(errno));
		goto out;
	}

	if (v->input_len > 0) {
		n = write(fd, v->input, v->input_len);
		if (n < 0 || (unsigned)n != v->input_len) {
			fprintf(stderr, "SHA3-256 write returned %zd: %s\n",
				n, strerror(errno));
			goto out;
		}

		/* read() before FINALIZE returns 0 for hash operations */
		n = read(fd, digest, sizeof(digest));
		if (n != 0) {
			fprintf(stderr,
				"SHA3-256: pre-FINALIZE read returned %zd, expected 0\n",
				n);
			goto out;
		}
	}

	if (ioctl(fd, CRYPTO2DEV_IOC_FINALIZE) != 0) {
		fprintf(stderr, "SHA3-256 FINALIZE failed: %s\n",
			strerror(errno));
		goto out;
	}

	n = read(fd, digest, sizeof(digest));
	if (n != 32) {
		fprintf(stderr, "SHA3-256 read returned %zd, expected 32: %s\n",
			n, strerror(errno));
		goto out;
	}

	if (memcmp(digest, v->digest, 32) != 0) {
		fprintf(stderr, "SHA3-256 digest mismatch: %s\n", v->source);
		goto out;
	}

	ret = 0;
out:
	close(fd);
	return ret;
}

static int test_sha3_256_vectors(void)
{
	int i, r = 0;

	for (i = 0; i < SHA3_256_VECTOR_COUNT; i++) {
		if (run_sha3_256_oneshot(&sha3_256_vectors[i])) {
			fprintf(stderr, "SHA3-256 vector %d failed: %s\n",
				i, sha3_256_vectors[i].source);
			r = -1;
		}
	}
	if (r == 0)
		g_pass++;
	else
		g_fail++;
	return r;
}

/* ── SHA3-384 tests ───────────────────────────────────────────────────────── */

/*
 * SHA3-384 oneshot:
 *   INIT(sha3-384, OP_HASH, no key) → [write(input)] → FINALIZE → read(48B)
 */
static int run_sha3_384_oneshot(const struct sha3_384_vector *v)
{
	unsigned char digest[48];
	ssize_t n;
	int fd, ret = -1;

	fd = open_dev();
	if (fd < 0)
		return -1;

	if (do_init(fd, "sha3-384", CRYPTO2DEV_OP_HASH, NULL, 0) != 0) {
		fprintf(stderr, "SHA3-384 INIT failed: %s\n", strerror(errno));
		goto out;
	}

	if (v->input_len > 0) {
		n = write(fd, v->input, v->input_len);
		if (n < 0 || (unsigned)n != v->input_len) {
			fprintf(stderr, "SHA3-384 write returned %zd: %s\n",
				n, strerror(errno));
			goto out;
		}

		/* read() before FINALIZE returns 0 for hash operations */
		n = read(fd, digest, sizeof(digest));
		if (n != 0) {
			fprintf(stderr,
				"SHA3-384: pre-FINALIZE read returned %zd, expected 0\n",
				n);
			goto out;
		}
	}

	if (ioctl(fd, CRYPTO2DEV_IOC_FINALIZE) != 0) {
		fprintf(stderr, "SHA3-384 FINALIZE failed: %s\n",
			strerror(errno));
		goto out;
	}

	n = read(fd, digest, sizeof(digest));
	if (n != 48) {
		fprintf(stderr, "SHA3-384 read returned %zd, expected 48: %s\n",
			n, strerror(errno));
		goto out;
	}

	if (memcmp(digest, v->digest, 48) != 0) {
		fprintf(stderr, "SHA3-384 digest mismatch: %s\n", v->source);
		goto out;
	}

	ret = 0;
out:
	close(fd);
	return ret;
}

static int test_sha3_384_vectors(void)
{
	int i, r = 0;

	for (i = 0; i < SHA3_384_VECTOR_COUNT; i++) {
		if (run_sha3_384_oneshot(&sha3_384_vectors[i])) {
			fprintf(stderr, "SHA3-384 vector %d failed: %s\n",
				i, sha3_384_vectors[i].source);
			r = -1;
		}
	}
	if (r == 0)
		g_pass++;
	else
		g_fail++;
	return r;
}

/* ── SHA3-512 tests ───────────────────────────────────────────────────────── */

/*
 * SHA3-512 oneshot:
 *   INIT(sha3-512, OP_HASH, no key) → [write(input)] → FINALIZE → read(64B)
 */
static int run_sha3_512_oneshot(const struct sha3_512_vector *v)
{
	unsigned char digest[64];
	ssize_t n;
	int fd, ret = -1;

	fd = open_dev();
	if (fd < 0)
		return -1;

	if (do_init(fd, "sha3-512", CRYPTO2DEV_OP_HASH, NULL, 0) != 0) {
		fprintf(stderr, "SHA3-512 INIT failed: %s\n", strerror(errno));
		goto out;
	}

	if (v->input_len > 0) {
		n = write(fd, v->input, v->input_len);
		if (n < 0 || (unsigned)n != v->input_len) {
			fprintf(stderr, "SHA3-512 write returned %zd: %s\n",
				n, strerror(errno));
			goto out;
		}

		/* read() before FINALIZE returns 0 for hash operations */
		n = read(fd, digest, sizeof(digest));
		if (n != 0) {
			fprintf(stderr,
				"SHA3-512: pre-FINALIZE read returned %zd, expected 0\n",
				n);
			goto out;
		}
	}

	if (ioctl(fd, CRYPTO2DEV_IOC_FINALIZE) != 0) {
		fprintf(stderr, "SHA3-512 FINALIZE failed: %s\n",
			strerror(errno));
		goto out;
	}

	n = read(fd, digest, sizeof(digest));
	if (n != 64) {
		fprintf(stderr, "SHA3-512 read returned %zd, expected 64: %s\n",
			n, strerror(errno));
		goto out;
	}

	if (memcmp(digest, v->digest, 64) != 0) {
		fprintf(stderr, "SHA3-512 digest mismatch: %s\n", v->source);
		goto out;
	}

	ret = 0;
out:
	close(fd);
	return ret;
}

static int test_sha3_512_vectors(void)
{
	int i, r = 0;

	for (i = 0; i < SHA3_512_VECTOR_COUNT; i++) {
		if (run_sha3_512_oneshot(&sha3_512_vectors[i])) {
			fprintf(stderr, "SHA3-512 vector %d failed: %s\n",
				i, sha3_512_vectors[i].source);
			r = -1;
		}
	}
	if (r == 0)
		g_pass++;
	else
		g_fail++;
	return r;
}

/* ── FINALIZE error cases ─────────────────────────────────────────────────── */

/*
 * Double FINALIZE: second FINALIZE returns -EINVAL.
 * write() after FINALIZE returns -EINVAL.
 */
static int test_finalize_error_cases(void)
{
	const struct aes_cbc_vector *v = &aes_cbc_vectors[0];
	unsigned char dummy[16] = {0};
	int fd, ret = -1;
	ssize_t n;

	fd = open_dev();
	if (fd < 0)
		return -1;

	if (do_init(fd, "cbc(aes)", CRYPTO2DEV_OP_ENCRYPT, v->key, v->key_len)
	    || do_set_iv(fd, v->iv, 16)) {
		fprintf(stderr, "INIT/SET_IV failed: %s\n", strerror(errno));
		goto out;
	}

	n = write(fd, v->plaintext, v->len);
	if (n != (ssize_t)v->len) {
		fprintf(stderr, "write failed: %s\n", strerror(errno));
		goto out;
	}

	/* First FINALIZE — must succeed */
	if (ioctl(fd, CRYPTO2DEV_IOC_FINALIZE) != 0) {
		fprintf(stderr, "first FINALIZE failed: %s\n", strerror(errno));
		goto out;
	}

	/* Second FINALIZE — must return -EINVAL */
	if (ioctl(fd, CRYPTO2DEV_IOC_FINALIZE) == 0) {
		fprintf(stderr, "second FINALIZE succeeded (expected -EINVAL)\n");
		goto out;
	}
	if (errno != EINVAL) {
		fprintf(stderr, "second FINALIZE: errno=%d, expected EINVAL\n",
			errno);
		goto out;
	}

	/* write() after FINALIZE — must return -EINVAL */
	n = write(fd, dummy, sizeof(dummy));
	if (n >= 0) {
		fprintf(stderr,
			"write after FINALIZE succeeded (expected -EINVAL)\n");
		goto out;
	}
	if (errno != EINVAL) {
		fprintf(stderr,
			"write after FINALIZE: errno=%d, expected EINVAL\n",
			errno);
		goto out;
	}

	ret = 0;
out:
	close(fd);
	if (ret == 0)
		g_pass++;
	else
		g_fail++;
	return ret;
}

/* ── GCM tag tamper test ──────────────────────────────────────────────────── */

/*
 * Flip one bit in the auth tag and verify that FINALIZE returns -EBADMSG.
 * Uses vector 0 (AES-128-GCM, 32-byte PT, 16-byte AAD).
 */
static int test_gcm_tag_tamper(void)
{
	const struct aes_gcm_vector *v = &aes_gcm_vectors[0];
	unsigned char tampered_tag[16];
	int fd, ret = -1;
	ssize_t n;

	fd = open_dev();
	if (fd < 0)
		return -1;

	memcpy(tampered_tag, v->tag, v->tag_len);
	tampered_tag[0] ^= 0x01;            /* 1-bit flip */

	if (do_init(fd, "gcm(aes)", CRYPTO2DEV_OP_DECRYPT,
		    v->key, v->key_len) != 0) {
		fprintf(stderr, "GCM tamper INIT failed: %s\n", strerror(errno));
		goto out;
	}
	if (do_set_iv(fd, v->nonce, 12) != 0) {
		fprintf(stderr, "GCM tamper SET_IV failed: %s\n",
			strerror(errno));
		goto out;
	}
	if (v->aad_len > 0 &&
	    do_set_aad(fd, v->aad, v->aad_len) != 0) {
		fprintf(stderr, "GCM tamper SET_AAD failed: %s\n",
			strerror(errno));
		goto out;
	}
	if (do_set_tag(fd, tampered_tag, v->tag_len) != 0) {
		fprintf(stderr, "GCM tamper SET_TAG failed: %s\n",
			strerror(errno));
		goto out;
	}

	n = write(fd, v->ciphertext, v->pt_len);
	if (n < 0 || (unsigned)n != v->pt_len) {
		fprintf(stderr, "GCM tamper write failed: %s\n", strerror(errno));
		goto out;
	}

	/* FINALIZE must fail with EBADMSG due to tag mismatch */
	if (ioctl(fd, CRYPTO2DEV_IOC_FINALIZE) == 0) {
		fprintf(stderr,
			"GCM tamper: FINALIZE succeeded (expected -EBADMSG)\n");
		goto out;
	}
	if (errno != EBADMSG) {
		fprintf(stderr,
			"GCM tamper: FINALIZE errno=%d, expected EBADMSG\n",
			errno);
		goto out;
	}

	ret = 0;
out:
	close(fd);
	if (ret == 0)
		g_pass++;
	else
		g_fail++;
	return ret;
}

/* ── Chunked SHA-256 ──────────────────────────────────────────────────────── */

/*
 * Feed SHA-256 input in 8-byte chunks.
 * Vector 3: 64 × 'a' — chosen because 64 is cleanly divisible by 8 and
 * tests multi-block accumulation across the SHA-256 block boundary (64 B).
 */
static int test_sha256_chunked(void)
{
	const struct sha256_vector *v = &sha256_vectors[3]; /* 64 × 'a' */
	unsigned char digest[32];
	int fd, i, ret = -1;
	ssize_t n;

	fd = open_dev();
	if (fd < 0)
		return -1;

	if (do_init(fd, "sha256", CRYPTO2DEV_OP_HASH, NULL, 0) != 0) {
		fprintf(stderr, "SHA-256 chunked INIT failed: %s\n",
			strerror(errno));
		goto out;
	}

	for (i = 0; i < 8; i++) {            /* 8 chunks × 8 bytes = 64 bytes */
		n = write(fd, v->input + i * 8, 8);
		if (n != 8) {
			fprintf(stderr, "SHA-256 chunked write %d: %s\n",
				i, strerror(errno));
			goto out;
		}
	}

	if (ioctl(fd, CRYPTO2DEV_IOC_FINALIZE) != 0) {
		fprintf(stderr, "SHA-256 chunked FINALIZE failed: %s\n",
			strerror(errno));
		goto out;
	}

	n = read(fd, digest, sizeof(digest));
	if (n != 32) {
		fprintf(stderr,
			"SHA-256 chunked read returned %zd: %s\n",
			n, strerror(errno));
		goto out;
	}

	if (memcmp(digest, v->digest, 32) != 0) {
		fprintf(stderr, "SHA-256 chunked: digest mismatch (%s)\n",
			v->source);
		goto out;
	}

	ret = 0;
out:
	close(fd);
	if (ret == 0)
		g_pass++;
	else
		g_fail++;
	return ret;
}

/* ── HMAC-SHA-256 ─────────────────────────────────────────────────────────── */

/*
 * HMAC-SHA-256 oneshot:
 *   INIT(hmac(sha256), OP_HASH, key) → write(input) → FINALIZE → read(32B)
 *
 * The key is passed inline in INIT (HMAC is a keyed hash, not a cipher).
 * Output is the 32-byte MAC, produced by FINALIZE and returned by read().
 */
static int run_hmac_sha256(const struct hmac_vector *v)
{
	unsigned char tag[32];
	int fd, ret = -1;
	ssize_t n;

	fd = open_dev();
	if (fd < 0)
		return -1;

	if (do_init(fd, "hmac(sha256)", CRYPTO2DEV_OP_HASH,
		    v->key, v->key_len) != 0) {
		fprintf(stderr, "HMAC-SHA256 INIT failed: %s\n",
			strerror(errno));
		goto out;
	}

	if (v->input_len > 0) {
		n = write(fd, v->input, v->input_len);
		if (n < 0 || (unsigned)n != v->input_len) {
			fprintf(stderr, "HMAC-SHA256 write failed: %s\n",
				strerror(errno));
			goto out;
		}
	}

	if (ioctl(fd, CRYPTO2DEV_IOC_FINALIZE) != 0) {
		fprintf(stderr, "HMAC-SHA256 FINALIZE failed: %s\n",
			strerror(errno));
		goto out;
	}

	n = read(fd, tag, v->tag_len);
	if (n != (ssize_t)v->tag_len) {
		fprintf(stderr,
			"HMAC-SHA256 read returned %zd, expected %u: %s\n",
			n, v->tag_len, strerror(errno));
		goto out;
	}

	if (memcmp(tag, v->tag, v->tag_len) != 0) {
		fprintf(stderr, "HMAC-SHA256 tag mismatch: %s\n", v->source);
		goto out;
	}

	ret = 0;
out:
	close(fd);
	return ret;
}

static int test_hmac_sha256(void)
{
	int i, r = 0;

	for (i = 0; i < HMAC_SHA256_VECTOR_COUNT; i++) {
		if (run_hmac_sha256(&hmac_sha256_vectors[i]) != 0) {
			fprintf(stderr, "HMAC-SHA256 vector %d failed: %s\n",
				i, hmac_sha256_vectors[i].source);
			r = -1;
		}
	}
	if (r == 0)
		g_pass++;
	else
		g_fail++;
	return r;
}

/* ── GET_STATE ioctl ──────────────────────────────────────────────────────── */

/*
 * Verify GET_STATE reports correct fd metadata at each lifecycle stage:
 *   (a) before INIT: fd_type=UNSET, initialized=0, algo empty
 *   (b) after INIT:  fd_type=OPERATION, initialized=1, algo matches
 *   (c) after write: bytes_written reflects actual bytes written
 */
static int test_get_state(void)
{
	const struct aes_cbc_vector *v = &aes_cbc_vectors[0];
	struct crypto2dev_fd_state_info info;
	int fd, ret = -1;
	ssize_t n;

	fd = open_dev();
	if (fd < 0)
		return -1;

	/* (a) Before INIT */
	if (do_get_state(fd, &info) != 0) {
		fprintf(stderr, "GET_STATE before INIT failed: %s\n",
			strerror(errno));
		goto out;
	}
	if (info.fd_type != CRYPTO2DEV_FDTYPE_UNSET) {
		fprintf(stderr,
			"GET_STATE: fd_type=%u, expected UNSET (%d)\n",
			info.fd_type, CRYPTO2DEV_FDTYPE_UNSET);
		goto out;
	}
	if (info.initialized != 0) {
		fprintf(stderr,
			"GET_STATE: initialized=%u before INIT (expected 0)\n",
			info.initialized);
		goto out;
	}
	if (info.algo[0] != '\0') {
		fprintf(stderr,
			"GET_STATE: algo=\"%s\" before INIT (expected empty)\n",
			info.algo);
		goto out;
	}
	if (info.bytes_written != 0 || info.bytes_read != 0) {
		fprintf(stderr,
			"GET_STATE: non-zero counters before INIT "
			"(bytes_written=%llu bytes_read=%llu)\n",
			(unsigned long long)info.bytes_written,
			(unsigned long long)info.bytes_read);
		goto out;
	}

	/* (b) After INIT */
	if (do_init(fd, "cbc(aes)", CRYPTO2DEV_OP_ENCRYPT,
		    v->key, v->key_len) != 0) {
		fprintf(stderr, "GET_STATE test INIT failed: %s\n",
			strerror(errno));
		goto out;
	}
	if (do_get_state(fd, &info) != 0) {
		fprintf(stderr, "GET_STATE after INIT failed: %s\n",
			strerror(errno));
		goto out;
	}
	if (info.fd_type != CRYPTO2DEV_FDTYPE_OPERATION) {
		fprintf(stderr,
			"GET_STATE: fd_type=%u after INIT, expected OPERATION (%d)\n",
			info.fd_type, CRYPTO2DEV_FDTYPE_OPERATION);
		goto out;
	}
	if (!info.initialized) {
		fprintf(stderr,
			"GET_STATE: initialized=0 after INIT (expected 1)\n");
		goto out;
	}
	if (strcmp(info.algo, "cbc(aes)") != 0) {
		fprintf(stderr,
			"GET_STATE: algo=\"%s\" after INIT, expected \"cbc(aes)\"\n",
			info.algo);
		goto out;
	}

	/* (c) After write: bytes_written reflects actual count */
	if (do_set_iv(fd, v->iv, 16) != 0) {
		fprintf(stderr, "GET_STATE test SET_IV failed: %s\n",
			strerror(errno));
		goto out;
	}
	n = write(fd, v->plaintext, v->len);
	if (n != (ssize_t)v->len) {
		fprintf(stderr, "GET_STATE test write returned %zd: %s\n",
			n, strerror(errno));
		goto out;
	}
	if (do_get_state(fd, &info) != 0) {
		fprintf(stderr, "GET_STATE after write failed: %s\n",
			strerror(errno));
		goto out;
	}
	if (info.bytes_written != v->len) {
		fprintf(stderr,
			"GET_STATE: bytes_written=%llu after write, expected %u\n",
			(unsigned long long)info.bytes_written, v->len);
		goto out;
	}

	ret = 0;
out:
	close(fd);
	if (ret == 0)
		g_pass++;
	else
		g_fail++;
	return ret;
}

/* ── GCM tag length variant tests ────────────────────────────────────────── */

/*
 * Three negative / boundary tests for GCM authentication-tag length handling:
 *
 * Test 1: 12-byte tag corruption → EBADMSG
 *   Encrypt with the v4 vector (12-byte tag), then decrypt using the correct
 *   ciphertext but with one bit flipped in the 12-byte tag.  FINALIZE must
 *   return -EBADMSG, proving the short tag is actually verified.
 *   Oracle: NIST SP 800-38D §7.2 — tag mismatch must cause authentication
 *   failure regardless of tag length.
 *
 * Test 2: set_tag rejection for taglen < 12
 *   Open a fresh fd, init GCM, call SET_TAG with an 11-byte tag.
 *   The ioctl must return -EINVAL.
 *   Oracle: FIPS 140-3 SP 800-38D §5.2.1.2 — minimum tag length is 96 bits.
 *
 * Test 3: sess_reset restores default authsize
 *   Open a fd, init GCM encrypt, set_tag with a 12-byte tag, write data,
 *   then RESET.  After reset, run a full encrypt+decrypt cycle with a 16-byte
 *   tag (v1 vector) to confirm the session is cleanly re-armed.
 *   Oracle: v1 NIST vector (16-byte tag) must decrypt correctly after reset.
 */
static int test_gcm_tag_length_variants(void)
{
	/* v4: AES-128-GCM, 32-byte PT, 16-byte AAD, 12-byte tag */
	const struct aes_gcm_vector *v4 = &aes_gcm_vectors[3];
	/* v1: AES-128-GCM, 32-byte PT, 16-byte AAD, 16-byte tag */
	const struct aes_gcm_vector *v1 = &aes_gcm_vectors[0];
	unsigned char tampered_tag[12];
	unsigned char ctbuf[256];
	unsigned char ptbuf[256];
	unsigned char tagbuf[16];
	unsigned int taglen = 0;
	unsigned char short_tag[11];
	int fd, ret = -1;
	ssize_t n;

	/* ── Test 1: 12-byte tag corruption → EBADMSG ─────────────────────── */

	/* Step 1a: encrypt with v4 (12-byte tag) and collect ciphertext */
	fd = open_dev();
	if (fd < 0)
		goto out_fail;

	if (do_init(fd, "gcm(aes)", CRYPTO2DEV_OP_ENCRYPT,
		    v4->key, v4->key_len) != 0) {
		fprintf(stderr, "tag-variants: v4 encrypt INIT failed: %s\n",
			strerror(errno));
		goto out_close;
	}
	if (do_set_iv(fd, v4->nonce, 12) != 0 ||
	    do_set_aad(fd, v4->aad, v4->aad_len) != 0) {
		fprintf(stderr, "tag-variants: v4 encrypt IV/AAD failed: %s\n",
			strerror(errno));
		goto out_close;
	}
	n = write(fd, v4->plaintext, v4->pt_len);
	if (n < 0 || (unsigned)n != v4->pt_len) {
		fprintf(stderr, "tag-variants: v4 encrypt write failed: %s\n",
			strerror(errno));
		goto out_close;
	}
	if (ioctl(fd, CRYPTO2DEV_IOC_FINALIZE) != 0) {
		fprintf(stderr, "tag-variants: v4 encrypt FINALIZE failed: %s\n",
			strerror(errno));
		goto out_close;
	}
	n = read(fd, ctbuf, sizeof(ctbuf));
	if (n < 0 || (unsigned)n != v4->pt_len) {
		fprintf(stderr, "tag-variants: v4 encrypt CT read failed: %s\n",
			strerror(errno));
		goto out_close;
	}
	if (do_get_tag(fd, tagbuf, &taglen) != 0 || taglen != v4->tag_len) {
		fprintf(stderr, "tag-variants: v4 GET_TAG failed or wrong len\n");
		goto out_close;
	}
	/* Sanity-check ciphertext and tag match the known-good vector */
	if (memcmp(ctbuf, v4->ciphertext, v4->pt_len) != 0 ||
	    memcmp(tagbuf, v4->tag, v4->tag_len) != 0) {
		fprintf(stderr, "tag-variants: v4 encrypt output mismatch\n");
		goto out_close;
	}
	close(fd);

	/* Step 1b: decrypt with a 1-bit-flipped 12-byte tag → must get EBADMSG */
	memcpy(tampered_tag, v4->tag, v4->tag_len);
	tampered_tag[0] ^= 0x01;

	fd = open_dev();
	if (fd < 0)
		goto out_fail;

	if (do_init(fd, "gcm(aes)", CRYPTO2DEV_OP_DECRYPT,
		    v4->key, v4->key_len) != 0) {
		fprintf(stderr, "tag-variants: v4 tamper INIT failed: %s\n",
			strerror(errno));
		goto out_close;
	}
	if (do_set_iv(fd, v4->nonce, 12) != 0 ||
	    do_set_aad(fd, v4->aad, v4->aad_len) != 0) {
		fprintf(stderr, "tag-variants: v4 tamper IV/AAD failed: %s\n",
			strerror(errno));
		goto out_close;
	}
	if (do_set_tag(fd, tampered_tag, v4->tag_len) != 0) {
		fprintf(stderr, "tag-variants: v4 tamper SET_TAG failed: %s\n",
			strerror(errno));
		goto out_close;
	}
	n = write(fd, v4->ciphertext, v4->pt_len);
	if (n < 0 || (unsigned)n != v4->pt_len) {
		fprintf(stderr, "tag-variants: v4 tamper write failed: %s\n",
			strerror(errno));
		goto out_close;
	}
	/* FINALIZE must fail with EBADMSG — 12-byte tag is verified */
	if (ioctl(fd, CRYPTO2DEV_IOC_FINALIZE) == 0) {
		fprintf(stderr,
			"tag-variants: 12-byte tamper FINALIZE succeeded (expected EBADMSG)\n");
		goto out_close;
	}
	if (errno != EBADMSG) {
		fprintf(stderr,
			"tag-variants: 12-byte tamper FINALIZE errno=%d, expected EBADMSG\n",
			errno);
		goto out_close;
	}
	close(fd);

	/* ── Test 2: SET_TAG with taglen=11 → -EINVAL ──────────────────────── */

	fd = open_dev();
	if (fd < 0)
		goto out_fail;

	if (do_init(fd, "gcm(aes)", CRYPTO2DEV_OP_DECRYPT,
		    v1->key, v1->key_len) != 0) {
		fprintf(stderr, "tag-variants: short-tag INIT failed: %s\n",
			strerror(errno));
		goto out_close;
	}
	memset(short_tag, 0xAA, sizeof(short_tag));
	if (do_set_tag(fd, short_tag, 11) == 0) {
		fprintf(stderr,
			"tag-variants: SET_TAG(11) succeeded (expected EINVAL)\n");
		goto out_close;
	}
	if (errno != EINVAL) {
		fprintf(stderr,
			"tag-variants: SET_TAG(11) errno=%d, expected EINVAL\n",
			errno);
		goto out_close;
	}
	close(fd);

	/* ── Test 3: sess_reset restores default authsize ───────────────────── */
	/*
	 * Use v4 (key/nonce/aad/pt) throughout.  The fd is inited with the
	 * v4 key once; before-reset uses a 12-byte tag, after-reset uses the
	 * default 16-byte tag without an explicit set_tag call.
	 *
	 * Per NIST SP 800-38D §7.2, a t-byte tag is the leftmost t bytes of
	 * the full GHASH output, so the post-reset 16-byte tag must begin with
	 * the 12 bytes in aes_gcm_v4_tag.  The ciphertext is tag-length
	 * independent and must equal aes_gcm_v4_ct in both cases.
	 */

	fd = open_dev();
	if (fd < 0)
		goto out_fail;

	/* Init encrypt with v4 key (12-byte tag path first) */
	if (do_init(fd, "gcm(aes)", CRYPTO2DEV_OP_ENCRYPT,
		    v4->key, v4->key_len) != 0) {
		fprintf(stderr, "tag-variants: reset test INIT failed: %s\n",
			strerror(errno));
		goto out_close;
	}
	if (do_set_iv(fd, v4->nonce, 12) != 0 ||
	    do_set_aad(fd, v4->aad, v4->aad_len) != 0 ||
	    do_set_tag(fd, v4->tag, v4->tag_len) != 0) {
		fprintf(stderr,
			"tag-variants: reset test IV/AAD/TAG setup failed: %s\n",
			strerror(errno));
		goto out_close;
	}
	n = write(fd, v4->plaintext, v4->pt_len);
	if (n < 0 || (unsigned)n != v4->pt_len) {
		fprintf(stderr, "tag-variants: reset test write failed: %s\n",
			strerror(errno));
		goto out_close;
	}

	/* RESET — clears streaming state, restores default 16-byte authsize */
	if (ioctl(fd, CRYPTO2DEV_IOC_RESET) != 0) {
		fprintf(stderr, "tag-variants: RESET failed: %s\n",
			strerror(errno));
		goto out_close;
	}

	/* After reset: re-encrypt same v4 data without set_tag (authsize=16) */
	if (do_set_iv(fd, v4->nonce, 12) != 0 ||
	    do_set_aad(fd, v4->aad, v4->aad_len) != 0) {
		fprintf(stderr,
			"tag-variants: post-reset IV/AAD failed: %s\n",
			strerror(errno));
		goto out_close;
	}
	n = write(fd, v4->plaintext, v4->pt_len);
	if (n < 0 || (unsigned)n != v4->pt_len) {
		fprintf(stderr, "tag-variants: post-reset write failed: %s\n",
			strerror(errno));
		goto out_close;
	}
	if (ioctl(fd, CRYPTO2DEV_IOC_FINALIZE) != 0) {
		fprintf(stderr,
			"tag-variants: post-reset FINALIZE failed: %s\n",
			strerror(errno));
		goto out_close;
	}
	n = read(fd, ctbuf, sizeof(ctbuf));
	if (n < 0 || (unsigned)n != v4->pt_len) {
		fprintf(stderr,
			"tag-variants: post-reset CT read returned %zd: %s\n",
			n, strerror(errno));
		goto out_close;
	}
	/* Ciphertext is tag-length independent — must match v4's vector */
	if (memcmp(ctbuf, v4->ciphertext, v4->pt_len) != 0) {
		fprintf(stderr,
			"tag-variants: post-reset ciphertext mismatch\n");
		goto out_close;
	}
	/* Tag must be 16 bytes (default restored by reset) and its first
	 * 12 bytes must match the v4 12-byte tag (NIST SP 800-38D §7.2) */
	if (do_get_tag(fd, tagbuf, &taglen) != 0 || taglen != 16) {
		fprintf(stderr,
			"tag-variants: post-reset GET_TAG failed or taglen=%u (expected 16)\n",
			taglen);
		goto out_close;
	}
	if (memcmp(tagbuf, v4->tag, v4->tag_len) != 0) {
		fprintf(stderr,
			"tag-variants: post-reset tag prefix mismatch\n");
		goto out_close;
	}
	close(fd);

	/* Decrypt the post-reset ciphertext+tag to confirm round-trip */
	fd = open_dev();
	if (fd < 0)
		goto out_fail;

	if (do_init(fd, "gcm(aes)", CRYPTO2DEV_OP_DECRYPT,
		    v4->key, v4->key_len) != 0) {
		fprintf(stderr,
			"tag-variants: post-reset decrypt INIT failed: %s\n",
			strerror(errno));
		goto out_close;
	}
	if (do_set_iv(fd, v4->nonce, 12) != 0 ||
	    do_set_aad(fd, v4->aad, v4->aad_len) != 0 ||
	    do_set_tag(fd, tagbuf, 16) != 0) {
		fprintf(stderr,
			"tag-variants: post-reset decrypt setup failed: %s\n",
			strerror(errno));
		goto out_close;
	}
	n = write(fd, v4->ciphertext, v4->pt_len);
	if (n < 0 || (unsigned)n != v4->pt_len) {
		fprintf(stderr,
			"tag-variants: post-reset decrypt write failed: %s\n",
			strerror(errno));
		goto out_close;
	}
	if (ioctl(fd, CRYPTO2DEV_IOC_FINALIZE) != 0) {
		fprintf(stderr,
			"tag-variants: post-reset decrypt FINALIZE failed: %s\n",
			strerror(errno));
		goto out_close;
	}
	n = read(fd, ptbuf, sizeof(ptbuf));
	if (n < 0 || (unsigned)n != v4->pt_len) {
		fprintf(stderr,
			"tag-variants: post-reset decrypt PT read returned %zd: %s\n",
			n, strerror(errno));
		goto out_close;
	}
	if (memcmp(ptbuf, v4->plaintext, v4->pt_len) != 0) {
		fprintf(stderr,
			"tag-variants: post-reset decrypt plaintext mismatch\n");
		goto out_close;
	}

	ret = 0;
out_close:
	close(fd);
out_fail:
	if (ret == 0)
		g_pass++;
	else
		g_fail++;
	return ret;
}

/* ── Main ─────────────────────────────────────────────────────────────────── */

struct test_case {
	const char *name;
	int (*fn)(void);
};

static const struct test_case tests[] = {
	{ "CBC NIST CAVP vectors (oneshot encrypt + decrypt)", test_cbc_nist_vectors       },
	{ "CBC streaming encrypt (interleaved write/read)",    test_cbc_streaming_encrypt  },
	{ "GCM NIST vectors (encrypt + decrypt)",             test_gcm_nist_vectors        },
	{ "SHA-256 NIST FIPS 180-4 vectors",                  test_sha256_vectors          },
	{ "SHA3-256 known-answer vectors",                    test_sha3_256_vectors        },
	{ "SHA3-384 known-answer vectors",                    test_sha3_384_vectors        },
	{ "SHA3-512 known-answer vectors",                    test_sha3_512_vectors        },
	{ "FINALIZE error cases (double/post-write)",          test_finalize_error_cases   },
	{ "GCM tag tamper (1-bit flip → EBADMSG)",            test_gcm_tag_tamper         },
	{ "SHA-256 chunked input (8-byte writes, 64-byte msg)", test_sha256_chunked        },
	{ "HMAC-SHA256 RFC 4231 vectors",                     test_hmac_sha256            },
	{ "GET_STATE lifecycle (before/after INIT/write)",    test_get_state              },
	{ "GCM tag length variants (tamper/short/reset)",     test_gcm_tag_length_variants },
};

int main(void)
{
	unsigned int i;

	printf("crypto2dev chardev tests\n");
	printf("device: %s\n\n", DEVICE_PATH);

	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		int res = tests[i].fn();

		printf("  [%s] %s\n", res == 0 ? "PASS" : "FAIL", tests[i].name);
	}

	printf("\n%d passed, %d failed\n", g_pass, g_fail);
	return (g_fail == 0) ? 0 : 1;
}
