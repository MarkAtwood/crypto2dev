// SPDX-License-Identifier: GPL-2.0-only
/*
 * test_kdf.c — CRYPTO2DEV_IOC_DO_KDF known-answer tests
 *
 * Tests HKDF-SHA256 against RFC 5869 Appendix A vectors (TC1 and TC3) and
 * PBKDF2-SHA256/SHA384/SHA512 against independently computed vectors
 * verified with both Python 3 hashlib and OpenSSL 3.
 *
 * Flow for each test:
 *   open /dev/crypto2dev
 *   write() IKM / password
 *   DO_KDF ioctl with exportable=1
 *   KEY_EXPORT_PRIVATE ioctl → keylen
 *   read(fd, buf, keylen) → OKM bytes
 *   memcmp against expected vector
 *   close fd
 *
 * Compile:
 *   gcc -Wall -Wextra -o test_kdf test_kdf.c -I../../include -I../vectors
 *
 * Run as root with crypto2dev.ko loaded:
 *   sudo ./test_kdf
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>

#include "uapi/crypto2dev_ioctl.h"

#include "../vectors/hkdf.h"
#include "../vectors/pbkdf2_sha256.h"
#include "../vectors/pbkdf2_sha384.h"
#include "../vectors/pbkdf2_sha512.h"

/*
 * Two-stage HKDF-SHA256 chain vectors for ikm_fd feature.
 * Oracle: OpenSSL 3.0.13 on this machine.
 *
 * Stage 1: IKM = "test input key material for ikm_fd stage 1"
 *   $ openssl kdf -keylen 32 -kdfopt digest:SHA256 \
 *     -kdfopt hexkey:7465737420696e707574206b6579206d6174657269616c20666f7220696b6d5f66642073746167652031 \
 *     -kdfopt hexsalt:0000000000000000000000000000000000000000000000000000000000000000 \
 *     -kdfopt hexinfo:737461676531 HKDF
 */
static const unsigned char ikm_fd_stage1_ikm[] = {
	0x74, 0x65, 0x73, 0x74, 0x20, 0x69, 0x6e, 0x70,
	0x75, 0x74, 0x20, 0x6b, 0x65, 0x79, 0x20, 0x6d,
	0x61, 0x74, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x20,
	0x66, 0x6f, 0x72, 0x20, 0x69, 0x6b, 0x6d, 0x5f,
	0x66, 0x64, 0x20, 0x73, 0x74, 0x61, 0x67, 0x65,
	0x20, 0x31
};

static const unsigned char ikm_fd_stage1_info[] = {
	0x73, 0x74, 0x61, 0x67, 0x65, 0x31  /* "stage1" */
};

/*
 * Stage 2: IKM = OKM1 (stage 1 output used as IKM via ikm_fd)
 *   $ openssl kdf -keylen 32 -kdfopt digest:SHA256 \
 *     -kdfopt hexkey:e61e4d83e1b370395049984f819c98e8717e158ceb68a9164a52bd952e09b0d8 \
 *     -kdfopt hexsalt:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 \
 *     -kdfopt hexinfo:737461676532 HKDF
 */
static const unsigned char ikm_fd_stage2_salt[] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
};

static const unsigned char ikm_fd_stage2_info[] = {
	0x73, 0x74, 0x61, 0x67, 0x65, 0x32  /* "stage2" */
};

/* Expected OKM2 — final output of two-stage chain */
static const unsigned char ikm_fd_stage2_okm[] = {
	0xb3, 0x74, 0xdc, 0x3a, 0x77, 0xab, 0xb3, 0x44,
	0x9e, 0x64, 0x7a, 0xb1, 0xe4, 0x69, 0xb6, 0xa7,
	0xd8, 0xc5, 0x68, 0x2b, 0xa6, 0x3b, 0x4f, 0x02,
	0x9a, 0x9e, 0x4a, 0xa5, 0x12, 0x81, 0x6a, 0xe0
};

#define DEVICE_PATH  "/dev/crypto2dev"

static int g_pass;
static int g_fail;

#define FAIL(fmt, ...) do {                                                \
	fprintf(stderr, "FAIL [%s:%d]: " fmt "\n",                         \
		__func__, __LINE__, ##__VA_ARGS__);                        \
	g_fail++;                                                          \
	return -1;                                                         \
} while (0)

#define PASS() do { g_pass++; return 0; } while (0)

/* ── Device helper ─────────────────────────────────────────────────────── */

static int open_dev(void)
{
	int fd = open(DEVICE_PATH, O_RDWR);

	if (fd < 0) {
		if (errno == ENOENT)
			fprintf(stderr, "SKIP: %s not found — module not loaded?\n",
				DEVICE_PATH);
		else
			fprintf(stderr, "open %s: %s\n", DEVICE_PATH, strerror(errno));
	}
	return fd;
}

/* ── KDF helper ─────────────────────────────────────────────────────────── */

/*
 * run_kdf_vector — derive and export a key, compare against expected bytes.
 *
 * @algo:       KDF algorithm: "hkdf(sha256)", "pbkdf2(sha256)", ...
 * @ikm:        IKM or password bytes
 * @ikm_len:    length of IKM / password
 * @salt:       salt bytes (may be NULL if salt_len==0)
 * @salt_len:   salt length
 * @info:       HKDF info bytes (may be NULL if info_len==0)
 * @info_len:   info length
 * @iterations: iteration count (0 for HKDF)
 * @okm_len:    requested OKM length
 * @expected:   expected OKM bytes
 * @source:     vector description for error messages
 *
 * Returns 0 on pass, -1 on failure.
 */
static int run_kdf_vector(const char *algo,
			  const unsigned char *ikm, unsigned int ikm_len,
			  const unsigned char *salt, unsigned int salt_len,
			  const unsigned char *info, unsigned int info_len,
			  unsigned int iterations,
			  unsigned int okm_len,
			  const unsigned char *expected,
			  const char *source)
{
	struct crypto2dev_kdf_op kdf;
	struct crypto2dev_key_export_op exp_op;
	unsigned char okm[CRYPTO2DEV_KDF_OKM_MAXLEN];
	ssize_t n;
	int fd, ret = -1;

	if (okm_len > sizeof(okm)) {
		fprintf(stderr, "SKIP: okm_len %u > buffer %zu for %s\n",
			okm_len, sizeof(okm), source);
		return 0;
	}

	fd = open_dev();
	if (fd < 0)
		return -1;

	/* Write IKM / password before calling DO_KDF */
	n = write(fd, ikm, ikm_len);
	if (n < 0 || (unsigned)n != ikm_len) {
		fprintf(stderr, "write IKM failed (%zd): %s [%s]\n",
			n, strerror(errno), source);
		goto out;
	}

	/* Build the DO_KDF request */
	memset(&kdf, 0, sizeof(kdf));
	strncpy(kdf.algo, algo, sizeof(kdf.algo) - 1);
	/* out_algo: use "hmac(sha256)" as the label — tests only export the key,
	 * they do not pass it to INIT, so the binding constraint is not exercised. */
	strncpy(kdf.out_algo, "hmac(sha256)", sizeof(kdf.out_algo) - 1);

	if (salt && salt_len) {
		if (salt_len > sizeof(kdf.salt)) {
			fprintf(stderr, "salt_len %u too large for %s\n",
				salt_len, source);
			goto out;
		}
		memcpy(kdf.salt, salt, salt_len);
	}
	kdf.salt_len = salt_len;

	if (info && info_len) {
		if (info_len > sizeof(kdf.info)) {
			fprintf(stderr, "info_len %u too large for %s\n",
				info_len, source);
			goto out;
		}
		memcpy(kdf.info, info, info_len);
	}
	kdf.info_len   = info_len;
	kdf.okm_len    = okm_len;
	kdf.iterations = iterations;
	kdf.ikm_fd     = -1;
	kdf.exportable = 1;  /* allow KEY_EXPORT_PRIVATE so we can compare OKM */

	if (ioctl(fd, CRYPTO2DEV_IOC_DO_KDF, &kdf) != 0) {
		fprintf(stderr, "DO_KDF failed: %s [%s]\n", strerror(errno), source);
		goto out;
	}

	/* Export the derived key bytes via KEY_EXPORT_PRIVATE + read() */
	memset(&exp_op, 0, sizeof(exp_op));
	if (ioctl(fd, CRYPTO2DEV_IOC_KEY_EXPORT_PRIVATE, &exp_op) != 0) {
		fprintf(stderr, "KEY_EXPORT_PRIVATE failed: %s [%s]\n",
			strerror(errno), source);
		goto out;
	}

	if (exp_op.keylen != okm_len) {
		fprintf(stderr, "KEY_EXPORT_PRIVATE keylen %u != okm_len %u [%s]\n",
			exp_op.keylen, okm_len, source);
		goto out;
	}

	n = read(fd, okm, exp_op.keylen);
	if (n < 0 || (unsigned)n != exp_op.keylen) {
		fprintf(stderr, "read OKM failed (%zd, expected %u): %s [%s]\n",
			n, exp_op.keylen, strerror(errno), source);
		goto out;
	}

	if (memcmp(okm, expected, okm_len) != 0) {
		unsigned int i;

		fprintf(stderr, "OKM mismatch for %s\n", source);
		fprintf(stderr, "  expected: ");
		for (i = 0; i < okm_len; i++)
			fprintf(stderr, "%02x", expected[i]);
		fprintf(stderr, "\n  got:      ");
		for (i = 0; i < okm_len; i++)
			fprintf(stderr, "%02x", okm[i]);
		fprintf(stderr, "\n");
		goto out;
	}
	ret = 0;

out:
	/* Zeroize local OKM copy before returning */
	memset(okm, 0, sizeof(okm));
	close(fd);
	return ret;
}

/* ── HKDF-SHA256 tests ──────────────────────────────────────────────────── */

static int test_hkdf_sha256_rfc5869(void)
{
	unsigned int i;
	int r = 0;

	for (i = 0; i < HKDF_SHA256_VECTOR_COUNT; i++) {
		const struct hkdf_vector *v = &hkdf_sha256_vectors[i];

		if (run_kdf_vector("hkdf(sha256)",
				   v->ikm, v->ikm_len,
				   v->salt, v->salt_len,
				   v->info, v->info_len,
				   0,  /* iterations must be 0 for HKDF */
				   v->okm_len,
				   v->okm,
				   v->source) != 0) {
			fprintf(stderr, "  HKDF vector %u failed: %s\n", i, v->source);
			r = -1;
		}
	}
	if (r == 0)
		PASS();
	g_fail++;
	return -1;
}

/* ── HKDF-SHA256: validation rejection tests ─────────────────────────────── */

/*
 * iterations != 0 for HKDF must return -EINVAL.
 * SP 800-56C / CLAUDE.md: HKDF has no iteration count; non-zero is rejected
 * to prevent users from mistaking HKDF for PBKDF2.
 */
static int test_hkdf_iterations_rejected(void)
{
	struct crypto2dev_kdf_op kdf;
	int fd;

	fd = open_dev();
	if (fd < 0)
		return -1;

	/* iterations check is pre-lock; no write() needed to reach it */
	memset(&kdf, 0, sizeof(kdf));
	strncpy(kdf.algo,     "hkdf(sha256)", sizeof(kdf.algo) - 1);
	strncpy(kdf.out_algo, "hmac(sha256)", sizeof(kdf.out_algo) - 1);
	kdf.okm_len    = 32;
	kdf.iterations = 500;  /* non-zero: must be rejected */
	kdf.ikm_fd     = -1;

	if (ioctl(fd, CRYPTO2DEV_IOC_DO_KDF, &kdf) == 0) {
		close(fd);
		FAIL("DO_KDF with iterations=500 for HKDF should have failed");
	}
	if (errno != EINVAL) {
		close(fd);
		FAIL("expected EINVAL, got %s", strerror(errno));
	}

	close(fd);
	PASS();
}

/*
 * okm_len > CRYPTO2DEV_KDF_OKM_MAXLEN must return -EMSGSIZE (not -EINVAL).
 */
static int test_hkdf_okm_too_large(void)
{
	struct crypto2dev_kdf_op kdf;
	unsigned char ikm[22];
	int fd;

	fd = open_dev();
	if (fd < 0)
		return -1;

	memset(ikm, 0x0b, sizeof(ikm));
	/* okm_len is validated before the lock, before inbuf is checked */
	memset(&kdf, 0, sizeof(kdf));
	strncpy(kdf.algo,     "hkdf(sha256)", sizeof(kdf.algo) - 1);
	strncpy(kdf.out_algo, "hmac(sha256)", sizeof(kdf.out_algo) - 1);
	kdf.okm_len    = CRYPTO2DEV_KDF_OKM_MAXLEN + 1;
	kdf.iterations = 0;
	kdf.ikm_fd     = -1;

	if (ioctl(fd, CRYPTO2DEV_IOC_DO_KDF, &kdf) == 0) {
		close(fd);
		FAIL("DO_KDF with oversized okm_len should have failed");
	}
	if (errno != EMSGSIZE) {
		close(fd);
		FAIL("expected EMSGSIZE for okm_len=%u, got %s",
		     CRYPTO2DEV_KDF_OKM_MAXLEN + 1, strerror(errno));
	}

	close(fd);
	PASS();
}

/* ── PBKDF2-SHA256 tests ─────────────────────────────────────────────────── */

static int test_pbkdf2_sha256_vectors(void)
{
	unsigned int i;
	int r = 0;

	for (i = 0; i < PBKDF2_SHA256_VECTOR_COUNT; i++) {
		const struct pbkdf2_sha256_vector *v = &pbkdf2_sha256_vectors[i];

		if (run_kdf_vector("pbkdf2(sha256)",
				   v->password, v->password_len,
				   v->salt, v->salt_len,
				   NULL, 0,         /* PBKDF2 has no info field */
				   v->iterations,
				   v->dk_len,
				   v->dk,
				   v->source) != 0) {
			fprintf(stderr, "  PBKDF2 vector %u failed: %s\n", i, v->source);
			r = -1;
		}
	}
	if (r == 0)
		PASS();
	g_fail++;
	return -1;
}

/* ── PBKDF2-SHA256: validation rejection tests ───────────────────────────── */

/*
 * iterations < 1000 for PBKDF2 must return -EINVAL (SP 800-132 §5.2).
 */
static int test_pbkdf2_iterations_floor(void)
{
	struct crypto2dev_kdf_op kdf;
	int fd;

	fd = open_dev();
	if (fd < 0)
		return -1;

	/* iterations check happens after ops lookup; write IKM to pass
	 * the inbuf_len guard and reach the provider-policy validation. */
	{
		ssize_t n = write(fd, "password", 8);

		if (n < 0 || (unsigned)n != 8) {
			fprintf(stderr, "write IKM failed: %s\n", strerror(errno));
			close(fd);
			return -1;
		}
	}

	memset(&kdf, 0, sizeof(kdf));
	strncpy(kdf.algo,     "pbkdf2(sha256)", sizeof(kdf.algo) - 1);
	strncpy(kdf.out_algo, "cbc(aes)",       sizeof(kdf.out_algo) - 1);
	memcpy(kdf.salt, "saltsaltsaltsalt", 16);
	kdf.salt_len   = 16;
	kdf.okm_len    = 32;
	kdf.iterations = 999;  /* below minimum; must be rejected */
	kdf.ikm_fd     = -1;

	if (ioctl(fd, CRYPTO2DEV_IOC_DO_KDF, &kdf) == 0) {
		close(fd);
		FAIL("DO_KDF pbkdf2 iterations=999 should have failed");
	}
	if (errno != EINVAL) {
		close(fd);
		FAIL("expected EINVAL, got %s", strerror(errno));
	}

	close(fd);
	PASS();
}

/*
 * PBKDF2 with salt_len < 16 must return -EINVAL (SP 800-132 §5.1).
 */
static int test_pbkdf2_salt_too_short(void)
{
	struct crypto2dev_kdf_op kdf;
	int fd;

	fd = open_dev();
	if (fd < 0)
		return -1;

	/* salt_len check happens after ops lookup; write IKM to pass
	 * the inbuf_len guard and reach the provider-policy validation. */
	{
		ssize_t n = write(fd, "password", 8);

		if (n < 0 || (unsigned)n != 8) {
			fprintf(stderr, "write IKM failed: %s\n", strerror(errno));
			close(fd);
			return -1;
		}
	}

	memset(&kdf, 0, sizeof(kdf));
	strncpy(kdf.algo,     "pbkdf2(sha256)", sizeof(kdf.algo) - 1);
	strncpy(kdf.out_algo, "cbc(aes)",       sizeof(kdf.out_algo) - 1);
	memcpy(kdf.salt, "shortsal", 8);  /* 8 bytes < 16 minimum */
	kdf.salt_len   = 8;
	kdf.okm_len    = 32;
	kdf.iterations = 1000;
	kdf.ikm_fd     = -1;

	if (ioctl(fd, CRYPTO2DEV_IOC_DO_KDF, &kdf) == 0) {
		close(fd);
		FAIL("DO_KDF pbkdf2 salt_len=8 should have failed");
	}
	if (errno != EINVAL) {
		close(fd);
		FAIL("expected EINVAL for short salt, got %s", strerror(errno));
	}

	close(fd);
	PASS();
}

/* ── PBKDF2-SHA384 tests ─────────────────────────────────────────────────── */

static int test_pbkdf2_sha384_vectors(void)
{
	unsigned int i;
	int r = 0;

	for (i = 0; i < PBKDF2_SHA384_VECTOR_COUNT; i++) {
		const struct pbkdf2_sha384_vector *v = &pbkdf2_sha384_vectors[i];

		if (run_kdf_vector("pbkdf2(sha384)",
				   v->password, v->password_len,
				   v->salt, v->salt_len,
				   NULL, 0,
				   v->iterations,
				   v->dk_len,
				   v->dk,
				   v->source) != 0) {
			fprintf(stderr, "  PBKDF2-SHA384 vector %u failed: %s\n",
				i, v->source);
			r = -1;
		}
	}
	if (r == 0)
		PASS();
	g_fail++;
	return -1;
}

static int test_pbkdf2_sha384_iterations_floor(void)
{
	struct crypto2dev_kdf_op kdf;
	int fd;

	fd = open_dev();
	if (fd < 0)
		return -1;

	{
		ssize_t n = write(fd, "password", 8);

		if (n < 0 || (unsigned)n != 8) {
			fprintf(stderr, "write IKM failed: %s\n", strerror(errno));
			close(fd);
			return -1;
		}
	}

	memset(&kdf, 0, sizeof(kdf));
	strncpy(kdf.algo,     "pbkdf2(sha384)", sizeof(kdf.algo) - 1);
	strncpy(kdf.out_algo, "cbc(aes)",       sizeof(kdf.out_algo) - 1);
	memcpy(kdf.salt, "saltsaltsaltsalt", 16);
	kdf.salt_len   = 16;
	kdf.okm_len    = 48;
	kdf.iterations = 999;
	kdf.ikm_fd     = -1;

	if (ioctl(fd, CRYPTO2DEV_IOC_DO_KDF, &kdf) == 0) {
		close(fd);
		FAIL("pbkdf2(sha384) iterations=999 should have failed");
	}
	if (errno != EINVAL) {
		close(fd);
		FAIL("expected EINVAL, got %s", strerror(errno));
	}

	close(fd);
	PASS();
}

static int test_pbkdf2_sha384_salt_too_short(void)
{
	struct crypto2dev_kdf_op kdf;
	int fd;

	fd = open_dev();
	if (fd < 0)
		return -1;

	{
		ssize_t n = write(fd, "password", 8);

		if (n < 0 || (unsigned)n != 8) {
			fprintf(stderr, "write IKM failed: %s\n", strerror(errno));
			close(fd);
			return -1;
		}
	}

	memset(&kdf, 0, sizeof(kdf));
	strncpy(kdf.algo,     "pbkdf2(sha384)", sizeof(kdf.algo) - 1);
	strncpy(kdf.out_algo, "cbc(aes)",       sizeof(kdf.out_algo) - 1);
	memcpy(kdf.salt, "shortsal", 8);
	kdf.salt_len   = 8;
	kdf.okm_len    = 48;
	kdf.iterations = 1000;
	kdf.ikm_fd     = -1;

	if (ioctl(fd, CRYPTO2DEV_IOC_DO_KDF, &kdf) == 0) {
		close(fd);
		FAIL("pbkdf2(sha384) salt_len=8 should have failed");
	}
	if (errno != EINVAL) {
		close(fd);
		FAIL("expected EINVAL for short salt, got %s", strerror(errno));
	}

	close(fd);
	PASS();
}

/* ── PBKDF2-SHA512 tests ─────────────────────────────────────────────────── */

static int test_pbkdf2_sha512_vectors(void)
{
	unsigned int i;
	int r = 0;

	for (i = 0; i < PBKDF2_SHA512_VECTOR_COUNT; i++) {
		const struct pbkdf2_sha512_vector *v = &pbkdf2_sha512_vectors[i];

		if (run_kdf_vector("pbkdf2(sha512)",
				   v->password, v->password_len,
				   v->salt, v->salt_len,
				   NULL, 0,
				   v->iterations,
				   v->dk_len,
				   v->dk,
				   v->source) != 0) {
			fprintf(stderr, "  PBKDF2-SHA512 vector %u failed: %s\n",
				i, v->source);
			r = -1;
		}
	}
	if (r == 0)
		PASS();
	g_fail++;
	return -1;
}

static int test_pbkdf2_sha512_iterations_floor(void)
{
	struct crypto2dev_kdf_op kdf;
	int fd;

	fd = open_dev();
	if (fd < 0)
		return -1;

	{
		ssize_t n = write(fd, "password", 8);

		if (n < 0 || (unsigned)n != 8) {
			fprintf(stderr, "write IKM failed: %s\n", strerror(errno));
			close(fd);
			return -1;
		}
	}

	memset(&kdf, 0, sizeof(kdf));
	strncpy(kdf.algo,     "pbkdf2(sha512)", sizeof(kdf.algo) - 1);
	strncpy(kdf.out_algo, "cbc(aes)",       sizeof(kdf.out_algo) - 1);
	memcpy(kdf.salt, "saltsaltsaltsalt", 16);
	kdf.salt_len   = 16;
	kdf.okm_len    = 64;
	kdf.iterations = 999;
	kdf.ikm_fd     = -1;

	if (ioctl(fd, CRYPTO2DEV_IOC_DO_KDF, &kdf) == 0) {
		close(fd);
		FAIL("pbkdf2(sha512) iterations=999 should have failed");
	}
	if (errno != EINVAL) {
		close(fd);
		FAIL("expected EINVAL, got %s", strerror(errno));
	}

	close(fd);
	PASS();
}

static int test_pbkdf2_sha512_salt_too_short(void)
{
	struct crypto2dev_kdf_op kdf;
	int fd;

	fd = open_dev();
	if (fd < 0)
		return -1;

	{
		ssize_t n = write(fd, "password", 8);

		if (n < 0 || (unsigned)n != 8) {
			fprintf(stderr, "write IKM failed: %s\n", strerror(errno));
			close(fd);
			return -1;
		}
	}

	memset(&kdf, 0, sizeof(kdf));
	strncpy(kdf.algo,     "pbkdf2(sha512)", sizeof(kdf.algo) - 1);
	strncpy(kdf.out_algo, "cbc(aes)",       sizeof(kdf.out_algo) - 1);
	memcpy(kdf.salt, "shortsal", 8);
	kdf.salt_len   = 8;
	kdf.okm_len    = 64;
	kdf.iterations = 1000;
	kdf.ikm_fd     = -1;

	if (ioctl(fd, CRYPTO2DEV_IOC_DO_KDF, &kdf) == 0) {
		close(fd);
		FAIL("pbkdf2(sha512) salt_len=8 should have failed");
	}
	if (errno != EINVAL) {
		close(fd);
		FAIL("expected EINVAL for short salt, got %s", strerror(errno));
	}

	close(fd);
	PASS();
}

/* ── ikm_fd tests ───────────────────────────────────────────────────────── */

/*
 * test_ikm_fd_chain — two-stage HKDF-SHA256 chain via ikm_fd.
 *
 * Stage 1: write IKM1, DO_KDF hkdf(sha256) → KEY fd (fd1).
 * Stage 2: open fd2 (no write()), DO_KDF hkdf(sha256) with ikm_fd=fd1 → KEY fd (fd2).
 * Export fd2 OKM and compare to expected vector (OpenSSL 3.0.13 oracle).
 */
static int test_ikm_fd_chain(void)
{
	static const unsigned char stage1_salt[32]; /* zero-initialised */

	struct crypto2dev_kdf_op kdf;
	struct crypto2dev_key_export_op exp_op;
	unsigned char okm[32];
	ssize_t n;
	int fd1 = -1, fd2 = -1, ret = -1;

	fd1 = open_dev();
	if (fd1 < 0)
		return -1;

	n = write(fd1, ikm_fd_stage1_ikm, sizeof(ikm_fd_stage1_ikm));
	if (n < 0 || (size_t)n != sizeof(ikm_fd_stage1_ikm)) {
		fprintf(stderr, "ikm_fd_chain: stage1 write failed: %s\n",
			strerror(errno));
		goto out;
	}

	memset(&kdf, 0, sizeof(kdf));
	strncpy(kdf.algo,     "hkdf(sha256)", sizeof(kdf.algo) - 1);
	strncpy(kdf.out_algo, "hkdf(sha256)", sizeof(kdf.out_algo) - 1);
	memcpy(kdf.salt, stage1_salt, sizeof(stage1_salt));
	kdf.salt_len = sizeof(stage1_salt);
	memcpy(kdf.info, ikm_fd_stage1_info, sizeof(ikm_fd_stage1_info));
	kdf.info_len = sizeof(ikm_fd_stage1_info);
	kdf.okm_len  = 32;
	kdf.ikm_fd   = -1;

	if (ioctl(fd1, CRYPTO2DEV_IOC_DO_KDF, &kdf) != 0) {
		fprintf(stderr, "ikm_fd_chain: stage1 DO_KDF failed: %s\n",
			strerror(errno));
		goto out;
	}

	fd2 = open_dev();
	if (fd2 < 0)
		goto out;

	memset(&kdf, 0, sizeof(kdf));
	strncpy(kdf.algo,     "hkdf(sha256)", sizeof(kdf.algo) - 1);
	strncpy(kdf.out_algo, "cbc(aes)",     sizeof(kdf.out_algo) - 1);
	memcpy(kdf.salt, ikm_fd_stage2_salt, sizeof(ikm_fd_stage2_salt));
	kdf.salt_len  = sizeof(ikm_fd_stage2_salt);
	memcpy(kdf.info, ikm_fd_stage2_info, sizeof(ikm_fd_stage2_info));
	kdf.info_len  = sizeof(ikm_fd_stage2_info);
	kdf.okm_len   = 32;
	kdf.ikm_fd    = fd1;
	kdf.exportable = 1;

	if (ioctl(fd2, CRYPTO2DEV_IOC_DO_KDF, &kdf) != 0) {
		fprintf(stderr, "ikm_fd_chain: stage2 DO_KDF with ikm_fd failed: %s\n",
			strerror(errno));
		goto out;
	}

	memset(&exp_op, 0, sizeof(exp_op));
	if (ioctl(fd2, CRYPTO2DEV_IOC_KEY_EXPORT_PRIVATE, &exp_op) != 0) {
		fprintf(stderr, "ikm_fd_chain: KEY_EXPORT_PRIVATE failed: %s\n",
			strerror(errno));
		goto out;
	}
	if (exp_op.keylen != 32) {
		fprintf(stderr, "ikm_fd_chain: keylen %u != 32\n", exp_op.keylen);
		goto out;
	}

	n = read(fd2, okm, exp_op.keylen);
	if (n < 0 || (size_t)n != exp_op.keylen) {
		fprintf(stderr, "ikm_fd_chain: read OKM failed: %s\n",
			strerror(errno));
		goto out;
	}

	if (memcmp(okm, ikm_fd_stage2_okm, 32) != 0) {
		unsigned int i;

		fprintf(stderr, "ikm_fd_chain: OKM mismatch\n  expected: ");
		for (i = 0; i < 32; i++)
			fprintf(stderr, "%02x", ikm_fd_stage2_okm[i]);
		fprintf(stderr, "\n  got:      ");
		for (i = 0; i < 32; i++)
			fprintf(stderr, "%02x", okm[i]);
		fprintf(stderr, "\n");
		goto out;
	}
	ret = 0;

out:
	memset(okm, 0, sizeof(okm));
	if (fd2 >= 0)
		close(fd2);
	if (fd1 >= 0)
		close(fd1);
	if (ret == 0)
		PASS();
	g_fail++;
	return -1;
}

/*
 * test_ikm_fd_operation_fd_rejected — OPERATION fd (after INIT) passed as
 * ikm_fd must return -EBADF. Only symmetric KEY fds are valid ikm_fd sources.
 */
static int test_ikm_fd_operation_fd_rejected(void)
{
	struct crypto2dev_init_op init;
	struct crypto2dev_kdf_op kdf;
	int fd = -1, fd_op = -1, ret = -1;

	fd_op = open_dev();
	if (fd_op < 0)
		return -1;

	memset(&init, 0, sizeof(init));
	strncpy(init.algo, "sha256", sizeof(init.algo) - 1);
	init.op     = CRYPTO2DEV_OP_HASH;
	init.key_fd = -1;
	if (ioctl(fd_op, CRYPTO2DEV_IOC_INIT, &init) != 0) {
		fprintf(stderr, "ikm_fd_op_rejected: INIT failed: %s\n",
			strerror(errno));
		goto out;
	}

	fd = open_dev();
	if (fd < 0)
		goto out;

	memset(&kdf, 0, sizeof(kdf));
	strncpy(kdf.algo,     "hkdf(sha256)", sizeof(kdf.algo) - 1);
	strncpy(kdf.out_algo, "cbc(aes)",     sizeof(kdf.out_algo) - 1);
	kdf.okm_len = 32;
	kdf.ikm_fd  = fd_op;

	if (ioctl(fd, CRYPTO2DEV_IOC_DO_KDF, &kdf) == 0) {
		fprintf(stderr, "ikm_fd_op_rejected: should have failed\n");
		goto out;
	}
	if (errno != EBADF) {
		fprintf(stderr, "ikm_fd_op_rejected: expected EBADF, got %s\n",
			strerror(errno));
		goto out;
	}
	ret = 0;

out:
	if (fd >= 0)
		close(fd);
	if (fd_op >= 0)
		close(fd_op);
	if (ret == 0)
		PASS();
	g_fail++;
	return -1;
}

/*
 * test_ikm_fd_pbkdf2_rejected — ikm_fd is not valid for PBKDF2.
 * PBKDF2 passwords must arrive via write(); using a KEY fd must return -EINVAL.
 */
static int test_ikm_fd_pbkdf2_rejected(void)
{
	struct crypto2dev_kdf_op kdf;
	ssize_t n;
	int fd = -1, fd_key = -1, ret = -1;

	fd_key = open_dev();
	if (fd_key < 0)
		return -1;

	n = write(fd_key, "keydata", 7);
	if (n != 7) {
		fprintf(stderr, "ikm_fd_pbkdf2: write failed: %s\n",
			strerror(errno));
		goto out;
	}

	memset(&kdf, 0, sizeof(kdf));
	strncpy(kdf.algo,     "hkdf(sha256)", sizeof(kdf.algo) - 1);
	strncpy(kdf.out_algo, "hmac(sha256)", sizeof(kdf.out_algo) - 1);
	kdf.okm_len = 32;
	kdf.ikm_fd  = -1;
	if (ioctl(fd_key, CRYPTO2DEV_IOC_DO_KDF, &kdf) != 0) {
		fprintf(stderr, "ikm_fd_pbkdf2: setup DO_KDF failed: %s\n",
			strerror(errno));
		goto out;
	}

	fd = open_dev();
	if (fd < 0)
		goto out;

	memset(&kdf, 0, sizeof(kdf));
	strncpy(kdf.algo,     "pbkdf2(sha256)", sizeof(kdf.algo) - 1);
	strncpy(kdf.out_algo, "cbc(aes)",       sizeof(kdf.out_algo) - 1);
	memcpy(kdf.salt, "saltsaltsaltsalt", 16);
	kdf.salt_len   = 16;
	kdf.okm_len    = 32;
	kdf.iterations = 1000;
	kdf.ikm_fd     = fd_key;

	if (ioctl(fd, CRYPTO2DEV_IOC_DO_KDF, &kdf) == 0) {
		fprintf(stderr, "ikm_fd_pbkdf2: should have failed\n");
		goto out;
	}
	if (errno != EINVAL) {
		fprintf(stderr, "ikm_fd_pbkdf2: expected EINVAL, got %s\n",
			strerror(errno));
		goto out;
	}
	ret = 0;

out:
	if (fd >= 0)
		close(fd);
	if (fd_key >= 0)
		close(fd_key);
	if (ret == 0)
		PASS();
	g_fail++;
	return -1;
}

/*
 * test_ikm_fd_dual_source_rejected — providing both write() IKM and ikm_fd
 * simultaneously must return -EINVAL (dual-source is ambiguous and rejected).
 */
static int test_ikm_fd_dual_source_rejected(void)
{
	struct crypto2dev_kdf_op kdf;
	ssize_t n;
	int fd = -1, fd_key = -1, ret = -1;

	fd_key = open_dev();
	if (fd_key < 0)
		return -1;

	n = write(fd_key, "keydata", 7);
	if (n != 7) {
		fprintf(stderr, "ikm_fd_dual: write for key fd failed: %s\n",
			strerror(errno));
		goto out;
	}

	memset(&kdf, 0, sizeof(kdf));
	strncpy(kdf.algo,     "hkdf(sha256)", sizeof(kdf.algo) - 1);
	strncpy(kdf.out_algo, "hmac(sha256)", sizeof(kdf.out_algo) - 1);
	kdf.okm_len = 32;
	kdf.ikm_fd  = -1;
	if (ioctl(fd_key, CRYPTO2DEV_IOC_DO_KDF, &kdf) != 0) {
		fprintf(stderr, "ikm_fd_dual: setup DO_KDF failed: %s\n",
			strerror(errno));
		goto out;
	}

	fd = open_dev();
	if (fd < 0)
		goto out;

	/* Write IKM bytes to fd (method A) */
	n = write(fd, "conflicting ikm", 15);
	if (n != 15) {
		fprintf(stderr, "ikm_fd_dual: write to fd2 failed: %s\n",
			strerror(errno));
		goto out;
	}

	/* Also set ikm_fd (method B) — dual source must be rejected */
	memset(&kdf, 0, sizeof(kdf));
	strncpy(kdf.algo,     "hkdf(sha256)", sizeof(kdf.algo) - 1);
	strncpy(kdf.out_algo, "cbc(aes)",     sizeof(kdf.out_algo) - 1);
	kdf.okm_len = 32;
	kdf.ikm_fd  = fd_key;

	if (ioctl(fd, CRYPTO2DEV_IOC_DO_KDF, &kdf) == 0) {
		fprintf(stderr, "ikm_fd_dual: should have failed\n");
		goto out;
	}
	if (errno != EINVAL) {
		fprintf(stderr, "ikm_fd_dual: expected EINVAL, got %s\n",
			strerror(errno));
		goto out;
	}
	ret = 0;

out:
	if (fd >= 0)
		close(fd);
	if (fd_key >= 0)
		close(fd_key);
	if (ret == 0)
		PASS();
	g_fail++;
	return -1;
}

/*
 * test_ikm_fd_invalid_fd_rejected — ikm_fd=-2 (not the -1 sentinel, not a
 * valid open fd) must return -EBADF.
 */
static int test_ikm_fd_invalid_fd_rejected(void)
{
	struct crypto2dev_kdf_op kdf;
	int fd;

	fd = open_dev();
	if (fd < 0)
		return -1;

	memset(&kdf, 0, sizeof(kdf));
	strncpy(kdf.algo,     "hkdf(sha256)", sizeof(kdf.algo) - 1);
	strncpy(kdf.out_algo, "cbc(aes)",     sizeof(kdf.out_algo) - 1);
	kdf.okm_len = 32;
	kdf.ikm_fd  = -2;

	if (ioctl(fd, CRYPTO2DEV_IOC_DO_KDF, &kdf) == 0) {
		close(fd);
		FAIL("DO_KDF with ikm_fd=-2 should fail");
	}
	if (errno != EBADF) {
		close(fd);
		FAIL("expected EBADF for ikm_fd=-2, got %s", strerror(errno));
	}

	close(fd);
	PASS();
}

/* ── Test dispatch ──────────────────────────────────────────────────────── */

struct test_case {
	const char *name;
	int (*fn)(void);
};

static const struct test_case tests[] = {
	{ "HKDF-SHA256 RFC 5869 Appendix A vectors",              test_hkdf_sha256_rfc5869        },
	{ "HKDF iterations!=0 rejected with -EINVAL",             test_hkdf_iterations_rejected   },
	{ "HKDF okm_len>max rejected with -EMSGSIZE",             test_hkdf_okm_too_large         },
	{ "PBKDF2-SHA256 known-answer vectors",                   test_pbkdf2_sha256_vectors         },
	{ "PBKDF2 iterations<1000 rejected (SP 800-132 §5.2)",    test_pbkdf2_iterations_floor       },
	{ "PBKDF2 salt_len<16 rejected (SP 800-132 §5.1)",        test_pbkdf2_salt_too_short         },
	{ "PBKDF2-SHA384 known-answer vectors",                   test_pbkdf2_sha384_vectors         },
	{ "PBKDF2-SHA384 iterations<1000 rejected",               test_pbkdf2_sha384_iterations_floor},
	{ "PBKDF2-SHA384 salt_len<16 rejected",                   test_pbkdf2_sha384_salt_too_short  },
	{ "PBKDF2-SHA512 known-answer vectors",                   test_pbkdf2_sha512_vectors         },
	{ "PBKDF2-SHA512 iterations<1000 rejected",               test_pbkdf2_sha512_iterations_floor},
	{ "PBKDF2-SHA512 salt_len<16 rejected",                   test_pbkdf2_sha512_salt_too_short  },
	{ "HKDF ikm_fd two-stage chain (OpenSSL 3 vector)",       test_ikm_fd_chain                  },
	{ "HKDF ikm_fd=OPERATION fd rejected with -EBADF",        test_ikm_fd_operation_fd_rejected  },
	{ "HKDF ikm_fd with PBKDF2 rejected with -EINVAL",        test_ikm_fd_pbkdf2_rejected        },
	{ "HKDF ikm_fd + write() dual source rejected with -EINVAL", test_ikm_fd_dual_source_rejected },
	{ "HKDF ikm_fd=-2 (invalid fd) rejected with -EBADF",    test_ikm_fd_invalid_fd_rejected    },
};

int main(void)
{
	unsigned int i;

	printf("crypto2dev KDF tests\n");
	printf("device: %s\n\n", DEVICE_PATH);

	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		int res = tests[i].fn();

		printf("  [%s] %s\n", res == 0 ? "PASS" : "FAIL", tests[i].name);
	}

	printf("\n%d passed, %d failed\n", g_pass, g_fail);
	return (g_fail == 0) ? 0 : 1;
}
