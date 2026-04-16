// SPDX-License-Identifier: GPL-2.0-only
/*
 * test_asym.c — asymmetric key operations for /dev/crypto2dev
 *
 * Tests KEY_IMPORT, DO_SIGN, DO_VERIFY, and DO_AGREE ioctls for:
 *   - RSA-2048 PKCS#1 v1.5 sign/verify
 *   - ECDH P-256 key agreement with HKDF-SHA256
 *   - ECDH P-384 key agreement with HKDF-SHA384
 *   - ECDSA P-256 sign/verify
 *
 * All vectors are from tests/vectors/{rsa,ecdh,ecdsa}.h, computed with
 * OpenSSL as the independent oracle.
 *
 * Compile:
 *   gcc -Wall -Wextra -o test_asym test_asym.c \
 *       -I../../include -I../vectors
 *
 * Run as root with crypto2dev.ko and crypto2dev_wolfssl.ko loaded:
 *   sudo ./test_asym
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>

#include "uapi/crypto2dev_ioctl.h"

#include "../vectors/rsa.h"
#include "../vectors/ecdh.h"
#include "../vectors/ecdh_p384.h"
#include "../vectors/ecdsa.h"

#define DEVICE_PATH  "/dev/crypto2dev"

static int g_pass;
static int g_fail;

#define FAIL(fmt, ...) do {                                                 \
	fprintf(stderr, "FAIL [%s:%d]: " fmt "\n",                          \
		__func__, __LINE__, ##__VA_ARGS__);                         \
	g_fail++;                                                           \
	return -1;                                                          \
} while (0)

#define PASS() do { g_pass++; return 0; } while (0)

/* ── Helpers ───────────────────────────────────────────────────────────── */

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

/*
 * import_key — write key bytes and call KEY_IMPORT.
 *
 * Returns an open KEY fd on success, or -1 with error printed.
 */
static int import_key(const char *algo, unsigned int key_type,
		      const unsigned char *key_bytes, unsigned int key_len)
{
	struct crypto2dev_key_import_op imp;
	int fd;
	ssize_t n;

	fd = open_dev();
	if (fd < 0)
		return -1;

	n = write(fd, key_bytes, key_len);
	if (n < 0 || (unsigned int)n != key_len) {
		fprintf(stderr, "import_key write: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	memset(&imp, 0, sizeof(imp));
	strncpy(imp.algo, algo, sizeof(imp.algo) - 1);
	imp.key_type   = (__u32)key_type;
	imp.exportable = 0;
	imp.keylen     = (__u32)key_len;

	if (ioctl(fd, CRYPTO2DEV_IOC_KEY_IMPORT, &imp) != 0) {
		fprintf(stderr, "KEY_IMPORT [%s, type=%u]: %s\n",
			algo, key_type, strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

/* ── RSA tests ─────────────────────────────────────────────────────────── */

/*
 * test_rsa_sign_verify — import private key, sign, import public key, verify.
 *
 * Uses the fixed PKCS#1 v1.5 test vector from rsa.h. The sign operation
 * uses the private key; verify uses the public key and the signature from
 * rsa.h (known-answer test).
 */
static int test_rsa_sign_verify(void)
{
	struct crypto2dev_sign_op   sign_op;
	struct crypto2dev_verify_op verify_op;
	int priv_fd, pub_fd;
	int ret;

	/* Import private key */
	priv_fd = import_key("rsa-2048", CRYPTO2DEV_KEY_PRIVATE,
			     rsa2048_priv_der, rsa2048_priv_der_len);
	if (priv_fd < 0)
		FAIL("failed to import RSA-2048 private key");

	/* DO_SIGN */
	memset(&sign_op, 0, sizeof(sign_op));
	sign_op.key_fd     = priv_fd;
	strncpy(sign_op.hash_algo, "sha256", sizeof(sign_op.hash_algo) - 1);
	sign_op.digest_len = 32;
	memcpy(sign_op.digest, rsa2048_test_digest, 32);

	ret = ioctl(priv_fd, CRYPTO2DEV_IOC_DO_SIGN, &sign_op);
	close(priv_fd);
	if (ret != 0)
		FAIL("DO_SIGN failed: %s", strerror(errno));
	if (sign_op.sig_len != 256)
		FAIL("DO_SIGN: expected 256-byte sig, got %u", sign_op.sig_len);

	/* Import public key for verify */
	pub_fd = import_key("rsa-2048", CRYPTO2DEV_KEY_PUBLIC,
			    rsa2048_pub_der, rsa2048_pub_der_len);
	if (pub_fd < 0)
		FAIL("failed to import RSA-2048 public key");

	/* DO_VERIFY with the just-generated signature (round-trip) */
	memset(&verify_op, 0, sizeof(verify_op));
	verify_op.key_fd     = pub_fd;
	strncpy(verify_op.hash_algo, "sha256", sizeof(verify_op.hash_algo) - 1);
	verify_op.digest_len = 32;
	memcpy(verify_op.digest, rsa2048_test_digest, 32);
	verify_op.sig_len    = sign_op.sig_len;
	memcpy(verify_op.sig, sign_op.sig, sign_op.sig_len);

	ret = ioctl(pub_fd, CRYPTO2DEV_IOC_DO_VERIFY, &verify_op);
	if (ret != 0) {
		close(pub_fd);
		FAIL("DO_VERIFY (round-trip) failed: %s", strerror(errno));
	}

	/* DO_VERIFY with known-answer signature from rsa.h */
	memset(&verify_op, 0, sizeof(verify_op));
	verify_op.key_fd     = pub_fd;
	strncpy(verify_op.hash_algo, "sha256", sizeof(verify_op.hash_algo) - 1);
	verify_op.digest_len = 32;
	memcpy(verify_op.digest, rsa2048_test_digest, 32);
	verify_op.sig_len    = 256;
	memcpy(verify_op.sig, rsa2048_test_sig, 256);

	ret = ioctl(pub_fd, CRYPTO2DEV_IOC_DO_VERIFY, &verify_op);
	if (ret != 0) {
		close(pub_fd);
		FAIL("DO_VERIFY (known-answer) failed: %s", strerror(errno));
	}

	/* DO_VERIFY with tampered signature — must return -EBADMSG */
	verify_op.sig[0] ^= 0xff;
	ret = ioctl(pub_fd, CRYPTO2DEV_IOC_DO_VERIFY, &verify_op);
	close(pub_fd);
	if (ret == 0)
		FAIL("DO_VERIFY tampered: expected failure, got 0");
	if (errno != EBADMSG)
		FAIL("DO_VERIFY tampered: expected EBADMSG, got %s",
		     strerror(errno));

	PASS();
}

/* ── ECDH tests ────────────────────────────────────────────────────────── */

/*
 * test_ecdh_agree — import ECDH P-256 private key, DO_AGREE with B_pub,
 * compare OKM against HKDF-SHA256 known-answer.
 *
 * DO_AGREE performs ECDH(A_priv, B_pub) then HKDF-SHA256 internally.
 * With no salt and no info, the OKM is deterministic for fixed inputs.
 */
static int test_ecdh_agree(void)
{
	struct crypto2dev_agree_op agree;
	int priv_fd;
	int ret;

	priv_fd = import_key("ecdh-p256", CRYPTO2DEV_KEY_PRIVATE,
			     ecdh_a_priv_der, ecdh_a_priv_der_len);
	if (priv_fd < 0)
		FAIL("failed to import ECDH P-256 private key");

	memset(&agree, 0, sizeof(agree));
	agree.key_fd          = priv_fd;
	agree.peer_pubkey_len = 65;
	memcpy(agree.peer_pubkey, ecdh_b_raw_pub, 65);
	agree.salt_len = 0;
	agree.info_len = 0;
	agree.okm_len  = 32;

	ret = ioctl(priv_fd, CRYPTO2DEV_IOC_DO_AGREE, &agree);
	close(priv_fd);
	if (ret != 0)
		FAIL("DO_AGREE failed: %s", strerror(errno));

	if (memcmp(agree.okm, ecdh_p256_hkdf_sha256_okm, 32) != 0) {
		fprintf(stderr, "FAIL [%s:%d]: DO_AGREE OKM mismatch\n"
			"  got: ", __func__, __LINE__);
		for (int i = 0; i < 32; i++)
			fprintf(stderr, "%02x", agree.okm[i]);
		fprintf(stderr, "\n  exp: ");
		for (int i = 0; i < 32; i++)
			fprintf(stderr, "%02x", ecdh_p256_hkdf_sha256_okm[i]);
		fprintf(stderr, "\n");
		g_fail++;
		return -1;
	}

	PASS();
}

/*
 * test_ecdh_p384_agree — import ECDH P-384 private key, DO_AGREE with B_pub,
 * compare OKM against HKDF-SHA384 known-answer.
 *
 * DO_AGREE performs ECDH(A_priv, B_pub) then HKDF-SHA384 internally.
 * With no salt and no info, the OKM is deterministic for fixed inputs.
 */
static int test_ecdh_p384_agree(void)
{
	struct crypto2dev_agree_op agree;
	int priv_fd;
	int ret;

	priv_fd = import_key("ecdh-p384", CRYPTO2DEV_KEY_PRIVATE,
			     ecdh_p384_a_priv_der, ecdh_p384_a_priv_der_len);
	if (priv_fd < 0)
		FAIL("failed to import ECDH P-384 private key");

	memset(&agree, 0, sizeof(agree));
	agree.key_fd          = priv_fd;
	agree.peer_pubkey_len = 97;
	memcpy(agree.peer_pubkey, ecdh_p384_b_raw_pub, 97);
	agree.salt_len = 0;
	agree.info_len = 0;
	agree.okm_len  = 48;

	ret = ioctl(priv_fd, CRYPTO2DEV_IOC_DO_AGREE, &agree);
	close(priv_fd);
	if (ret != 0)
		FAIL("DO_AGREE P-384 failed: %s", strerror(errno));

	if (memcmp(agree.okm, ecdh_p384_hkdf_sha384_okm, 48) != 0) {
		fprintf(stderr, "FAIL [%s:%d]: DO_AGREE P-384 OKM mismatch\n"
			"  got: ", __func__, __LINE__);
		for (int i = 0; i < 48; i++)
			fprintf(stderr, "%02x", agree.okm[i]);
		fprintf(stderr, "\n  exp: ");
		for (int i = 0; i < 48; i++)
			fprintf(stderr, "%02x", ecdh_p384_hkdf_sha384_okm[i]);
		fprintf(stderr, "\n");
		g_fail++;
		return -1;
	}

	PASS();
}

/* ── ECDSA tests ───────────────────────────────────────────────────────── */

/*
 * test_ecdsa_sign_verify — import ECDSA P-256 private key, sign, import
 * public key, verify round-trip and known-answer, tamper check.
 */
static int test_ecdsa_sign_verify(void)
{
	struct crypto2dev_sign_op   sign_op;
	struct crypto2dev_verify_op verify_op;
	int priv_fd, pub_fd;
	int ret;

	/* Import private key */
	priv_fd = import_key("ecdsa-p256", CRYPTO2DEV_KEY_PRIVATE,
			     ecdsa_p256_priv_der, ECDSA_P256_PRIV_DER_LEN);
	if (priv_fd < 0)
		FAIL("failed to import ECDSA P-256 private key");

	/* DO_SIGN — ECDSA does not require hash_algo to be set */
	memset(&sign_op, 0, sizeof(sign_op));
	sign_op.key_fd     = priv_fd;
	sign_op.digest_len = ECDSA_P256_DIGEST_LEN;
	memcpy(sign_op.digest, ecdsa_p256_digest_sha256, ECDSA_P256_DIGEST_LEN);

	ret = ioctl(priv_fd, CRYPTO2DEV_IOC_DO_SIGN, &sign_op);
	close(priv_fd);
	if (ret != 0)
		FAIL("DO_SIGN ECDSA failed: %s", strerror(errno));
	if (sign_op.sig_len == 0 || sign_op.sig_len > CRYPTO2DEV_SIG_MAXLEN)
		FAIL("DO_SIGN ECDSA: invalid sig_len=%u", sign_op.sig_len);

	/* Import public key for verify */
	pub_fd = import_key("ecdsa-p256", CRYPTO2DEV_KEY_PUBLIC,
			    ecdsa_p256_pub_der, ECDSA_P256_PUB_DER_LEN);
	if (pub_fd < 0)
		FAIL("failed to import ECDSA P-256 public key");

	/* DO_VERIFY with the just-generated signature (round-trip) */
	memset(&verify_op, 0, sizeof(verify_op));
	verify_op.key_fd     = pub_fd;
	verify_op.digest_len = ECDSA_P256_DIGEST_LEN;
	memcpy(verify_op.digest, ecdsa_p256_digest_sha256, ECDSA_P256_DIGEST_LEN);
	verify_op.sig_len    = sign_op.sig_len;
	memcpy(verify_op.sig, sign_op.sig, sign_op.sig_len);

	ret = ioctl(pub_fd, CRYPTO2DEV_IOC_DO_VERIFY, &verify_op);
	if (ret != 0) {
		close(pub_fd);
		FAIL("DO_VERIFY ECDSA (round-trip) failed: %s", strerror(errno));
	}

	/* DO_VERIFY with known-answer signature from ecdsa.h */
	memset(&verify_op, 0, sizeof(verify_op));
	verify_op.key_fd     = pub_fd;
	verify_op.digest_len = ECDSA_P256_DIGEST_LEN;
	memcpy(verify_op.digest, ecdsa_p256_digest_sha256, ECDSA_P256_DIGEST_LEN);
	verify_op.sig_len    = ECDSA_P256_SIG_DER_LEN;
	memcpy(verify_op.sig, ecdsa_p256_sig_der, ECDSA_P256_SIG_DER_LEN);

	ret = ioctl(pub_fd, CRYPTO2DEV_IOC_DO_VERIFY, &verify_op);
	if (ret != 0) {
		close(pub_fd);
		FAIL("DO_VERIFY ECDSA (known-answer) failed: %s", strerror(errno));
	}

	/* DO_VERIFY with tampered signature — must return -EBADMSG */
	verify_op.sig[4] ^= 0xff;
	ret = ioctl(pub_fd, CRYPTO2DEV_IOC_DO_VERIFY, &verify_op);
	close(pub_fd);
	if (ret == 0)
		FAIL("DO_VERIFY ECDSA tampered: expected failure, got 0");
	if (errno != EBADMSG)
		FAIL("DO_VERIFY ECDSA tampered: expected EBADMSG, got %s",
		     strerror(errno));

	PASS();
}

/* ── main ──────────────────────────────────────────────────────────────── */

int main(void)
{
	printf("crypto2dev asymmetric test\n");

	test_rsa_sign_verify();
	test_ecdh_agree();
	test_ecdh_p384_agree();
	test_ecdsa_sign_verify();

	printf("\n%s: %d passed, %d failed\n",
	       g_fail ? "FAIL" : "PASS", g_pass, g_fail);

	return g_fail ? 1 : 0;
}
