// SPDX-License-Identifier: GPL-2.0-only
/*
 * test_af_alg.c — wolfkm kernel crypto API tests via AF_ALG sockets
 *
 * Verifies that wolfkm (wolfcrypt.ko) implementations are selected by the
 * kernel crypto API and produce NIST-correct outputs. Uses Linux AF_ALG
 * sockets to exercise cbc(aes), sha256, and gcm(aes).
 *
 * Each algorithm test:
 *   1. Checks /proc/crypto to confirm wolfkm is the selected driver.
 *   2. Exercises the AF_ALG socket API with NIST known-answer vectors.
 *   3. Compares output byte-for-byte against expected values.
 *
 * Compile:
 *   gcc -Wall -Wextra -o test_af_alg test_af_alg.c -I../vectors
 *
 * Run as root with wolfcrypt.ko loaded:
 *   sudo ./test_af_alg
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

#include "../vectors/aes_cbc.h"
#include "../vectors/aes_gcm.h"
#include "../vectors/sha256.h"

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#ifndef AF_ALG
#define AF_ALG 38
#endif

/* ------------------------------------------------------------------
 * Test result tracking
 * ------------------------------------------------------------------ */

static int g_pass;
static int g_fail;

/* Used only in top-level test functions — never in inner helpers. */
#define TEST_FAIL(fmt, ...) do {                                            \
	fprintf(stderr, "FAIL [%s]: " fmt "\n", __func__, ##__VA_ARGS__);  \
	g_fail++;                                                           \
	return -1;                                                          \
} while (0)

#define TEST_SKIP(fmt, ...) do {                                            \
	printf("SKIP (" fmt ")\n", ##__VA_ARGS__);                         \
	return 0;                                                           \
} while (0)

#define TEST_PASS() do { printf("PASS\n"); g_pass++; return 0; } while (0)

/* ------------------------------------------------------------------
 * /proc/crypto driver check
 * ------------------------------------------------------------------ */

/*
 * proc_crypto_driver_is_wolfkm — verify wolfkm is the selected driver for
 * @algo in the kernel crypto API.
 *
 * Returns:
 *   1   wolfkm driver selected
 *   0   algo found but non-wolfkm driver selected
 *  -1   algo not found or /proc/crypto unreadable
 */
static int proc_crypto_driver_is_wolfkm(const char *algo)
{
	FILE *f;
	char line[256];
	int in_target = 0;

	f = fopen("/proc/crypto", "r");
	if (!f)
		return -1;

	while (fgets(line, sizeof(line), f)) {
		char *colon, *key, *val, *trim;

		if (line[0] == '\n' || line[0] == '\r') {
			in_target = 0;
			continue;
		}

		colon = strchr(line, ':');
		if (!colon)
			continue;
		*colon = '\0';

		/* Trim trailing whitespace from key. */
		key = line;
		trim = colon - 1;
		while (trim > key && (*trim == ' ' || *trim == '\t'))
			*trim-- = '\0';

		/* Trim leading and trailing whitespace from value. */
		val = colon + 1;
		while (*val == ' ' || *val == '\t')
			val++;
		trim = val + strlen(val) - 1;
		while (trim >= val &&
		       (*trim == '\n' || *trim == '\r' || *trim == ' '))
			*trim-- = '\0';

		if (strcmp(key, "name") == 0) {
			in_target = (strcmp(val, algo) == 0);
		} else if (in_target && strcmp(key, "driver") == 0) {
			int ret = (strstr(val, "wolfkm") != NULL) ? 1 : 0;
			fclose(f);
			return ret;
		}
	}

	fclose(f);
	return -1;
}

/* ------------------------------------------------------------------
 * AF_ALG socket helpers
 * ------------------------------------------------------------------ */

/*
 * alg_bind — create and bind an AF_ALG socket.
 * Returns the bound socket fd on success, -1 on error (errno set).
 */
static int alg_bind(const char *salg_type, const char *salg_name)
{
	struct sockaddr_alg sa;
	int fd;

	fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (fd < 0)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.salg_family = AF_ALG;
	strncpy((char *)sa.salg_type, salg_type, sizeof(sa.salg_type) - 1);
	strncpy((char *)sa.salg_name, salg_name, sizeof(sa.salg_name) - 1);

	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

/* ------------------------------------------------------------------
 * Skcipher (cbc(aes)) test
 * ------------------------------------------------------------------ */

/*
 * run_skcipher_encrypt — encrypt one AES-CBC vector via AF_ALG.
 * Returns 0 on success; prints reason and returns -1 on failure.
 * Does NOT touch g_pass/g_fail.
 */
static int run_skcipher_encrypt(const struct aes_cbc_vector *v)
{
	int alg_fd = -1, op_fd = -1;
	unsigned char out[64];
	ssize_t n;
	int ret = -1;

	/* cmsg: ALG_SET_OP (__u32) + ALG_SET_IV (af_alg_iv header + 16 bytes) */
	char cmsgbuf[CMSG_SPACE(sizeof(__u32)) +
		     CMSG_SPACE(sizeof(struct af_alg_iv) + 16)];
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct af_alg_iv *aiv;

	alg_fd = alg_bind("skcipher", "cbc(aes)");
	if (alg_fd < 0) {
		fprintf(stderr, "    bind cbc(aes): %s\n", strerror(errno));
		return -1;
	}

	if (setsockopt(alg_fd, SOL_ALG, ALG_SET_KEY,
		       v->key, (socklen_t)v->key_len) < 0) {
		fprintf(stderr, "    ALG_SET_KEY: %s\n", strerror(errno));
		goto out;
	}

	op_fd = accept(alg_fd, NULL, 0);
	if (op_fd < 0) {
		fprintf(stderr, "    accept: %s\n", strerror(errno));
		goto out;
	}

	memset(cmsgbuf, 0, sizeof(cmsgbuf));
	memset(&msg, 0, sizeof(msg));

	iov.iov_base = (void *)v->plaintext;
	iov.iov_len  = v->len;
	msg.msg_iov        = &iov;
	msg.msg_iovlen     = 1;
	msg.msg_control    = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type  = ALG_SET_OP;
	cmsg->cmsg_len   = CMSG_LEN(sizeof(__u32));
	*((__u32 *)CMSG_DATA(cmsg)) = ALG_OP_ENCRYPT;

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type  = ALG_SET_IV;
	cmsg->cmsg_len   = CMSG_LEN(sizeof(struct af_alg_iv) + 16);
	aiv = (struct af_alg_iv *)CMSG_DATA(cmsg);
	aiv->ivlen = 16;
	memcpy(aiv->iv, v->iv, 16);

	if (sendmsg(op_fd, &msg, 0) < 0) {
		fprintf(stderr, "    sendmsg: %s\n", strerror(errno));
		goto out;
	}

	n = read(op_fd, out, v->len);
	if (n < 0 || (size_t)n != v->len) {
		fprintf(stderr, "    read: got %zd, want %u: %s\n",
			n, v->len, strerror(errno));
		goto out;
	}

	if (memcmp(out, v->ciphertext, v->len) != 0) {
		fprintf(stderr, "    ciphertext mismatch: %s\n", v->source);
		goto out;
	}

	ret = 0;

out:
	if (op_fd >= 0)
		close(op_fd);
	close(alg_fd);
	return ret;
}

static int test_skcipher_cbc_aes(void)
{
	int driver_check, i;

	printf("  skcipher cbc(aes): ");

	driver_check = proc_crypto_driver_is_wolfkm("cbc(aes)");
	if (driver_check < 0)
		TEST_SKIP("wolfkm not in /proc/crypto — wolfcrypt.ko not loaded?");
	if (!driver_check)
		TEST_FAIL("wolfkm not selected as cbc(aes) driver");

	for (i = 0; i < AES_CBC_VECTOR_COUNT; i++) {
		if (run_skcipher_encrypt(&aes_cbc_vectors[i]) != 0)
			TEST_FAIL("vector %d failed: %s",
				  i, aes_cbc_vectors[i].source);
	}

	TEST_PASS();
}

/* ------------------------------------------------------------------
 * Hash (sha256) test
 * ------------------------------------------------------------------ */

/*
 * run_hash_sha256 — hash one SHA-256 vector via AF_ALG.
 * Returns 0 on success; prints reason and returns -1 on failure.
 * Does NOT touch g_pass/g_fail.
 */
static int run_hash_sha256(int op_fd, const struct sha256_vector *v)
{
	unsigned char digest[32];
	ssize_t n;

	if (v->input_len > 0 &&
	    write(op_fd, v->input, v->input_len) != (ssize_t)v->input_len) {
		fprintf(stderr, "    write: %s\n", strerror(errno));
		return -1;
	}

	/*
	 * read() finalizes the hash. For empty input (input_len == 0) the
	 * hash state is already at init, and read triggers the final without
	 * any data — giving SHA-256 of the empty string.
	 * After read(), the AF_ALG subsystem resets the state for reuse.
	 */
	n = read(op_fd, digest, sizeof(digest));
	if (n != (ssize_t)sizeof(digest)) {
		fprintf(stderr, "    read digest: got %zd, want 32: %s\n",
			n, strerror(errno));
		return -1;
	}

	if (memcmp(digest, v->digest, sizeof(digest)) != 0) {
		fprintf(stderr, "    digest mismatch: %s\n", v->source);
		return -1;
	}

	return 0;
}

static int test_hash_sha256(void)
{
	int driver_check, alg_fd, op_fd, i;

	printf("  hash sha256: ");

	driver_check = proc_crypto_driver_is_wolfkm("sha256");
	if (driver_check < 0)
		TEST_SKIP("wolfkm not in /proc/crypto — wolfcrypt.ko not loaded?");
	if (!driver_check)
		TEST_FAIL("wolfkm not selected as sha256 driver");

	alg_fd = alg_bind("hash", "sha256");
	if (alg_fd < 0)
		TEST_FAIL("bind hash/sha256: %s", strerror(errno));

	op_fd = accept(alg_fd, NULL, 0);
	if (op_fd < 0) {
		close(alg_fd);
		TEST_FAIL("accept: %s", strerror(errno));
	}

	for (i = 0; i < SHA256_VECTOR_COUNT; i++) {
		if (run_hash_sha256(op_fd, &sha256_vectors[i]) != 0) {
			close(op_fd);
			close(alg_fd);
			TEST_FAIL("vector %d failed: %s",
				  i, sha256_vectors[i].source);
		}
	}

	close(op_fd);
	close(alg_fd);
	TEST_PASS();
}

/* ------------------------------------------------------------------
 * AEAD (gcm(aes)) test
 * ------------------------------------------------------------------ */

static int test_aead_gcm_aes(void)
{
	/*
	 * Vector: AES-128-GCM, 32-byte PT, 16-byte AAD — NIST SP 800-38D.
	 * Source: aes_gcm_vectors[0] from tests/vectors/aes_gcm.h.
	 */
	const unsigned char *key    = aes_gcm_v1_key;    /* 16 bytes (AES-128) */
	const unsigned char *nonce  = aes_gcm_v1_nonce;  /* 12 bytes (96-bit)  */
	const unsigned char *pt     = aes_gcm_v1_pt;     /* 32 bytes           */
	const unsigned char *aad    = aes_gcm_v1_aad;    /* 16 bytes           */
	const unsigned char *exp_ct = aes_gcm_v1_ct;     /* 32 bytes           */
	const unsigned char *exp_tag = aes_gcm_v1_tag;   /* 16 bytes           */
	unsigned int pt_len  = 32;
	unsigned int aad_len = 16;
	unsigned int tag_len = 16;
	unsigned int ct_out_len = pt_len + tag_len; /* 48 bytes total */

	int driver_check, alg_fd, op_fd;
	unsigned char out[48];

	/* cmsg: ALG_SET_OP + ALG_SET_IV (12-byte nonce) + ALG_SET_AEAD_ASSOCLEN */
	char cmsgbuf[CMSG_SPACE(sizeof(__u32)) +
		     CMSG_SPACE(sizeof(struct af_alg_iv) + 12) +
		     CMSG_SPACE(sizeof(__u32))];
	struct iovec iov[2];
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct af_alg_iv *aiv;
	ssize_t n;
	int ret = -1;

	printf("  aead gcm(aes): ");

	driver_check = proc_crypto_driver_is_wolfkm("gcm(aes)");
	if (driver_check < 0)
		TEST_SKIP("wolfkm not in /proc/crypto — wolfcrypt.ko not loaded?");
	if (!driver_check)
		TEST_FAIL("wolfkm not selected as gcm(aes) driver");

	alg_fd = alg_bind("aead", "gcm(aes)");
	if (alg_fd < 0)
		TEST_FAIL("bind aead/gcm(aes): %s", strerror(errno));

	if (setsockopt(alg_fd, SOL_ALG, ALG_SET_KEY,
		       key, (socklen_t)16) < 0) {
		fprintf(stderr, "ALG_SET_KEY: %s\n", strerror(errno));
		close(alg_fd);
		g_fail++;
		return -1;
	}

	/*
	 * ALG_SET_AEAD_AUTHSIZE: option value is in optlen, not optval.
	 * Kernel reads the tag size from the socklen_t parameter.
	 */
	if (setsockopt(alg_fd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE,
		       NULL, (socklen_t)tag_len) < 0) {
		fprintf(stderr, "ALG_SET_AEAD_AUTHSIZE: %s\n", strerror(errno));
		close(alg_fd);
		g_fail++;
		return -1;
	}

	op_fd = accept(alg_fd, NULL, 0);
	if (op_fd < 0) {
		close(alg_fd);
		TEST_FAIL("accept: %s", strerror(errno));
	}

	/*
	 * AEAD encrypt via AF_ALG:
	 *   iov[0] = AAD, iov[1] = plaintext
	 *   cmsg:  ALG_SET_OP=ENCRYPT, ALG_SET_IV=nonce, ALG_SET_AEAD_ASSOCLEN=aad_len
	 *   output: [ciphertext (pt_len bytes) | auth tag (tag_len bytes)]
	 */
	memset(cmsgbuf, 0, sizeof(cmsgbuf));
	memset(&msg, 0, sizeof(msg));

	iov[0].iov_base = (void *)aad;
	iov[0].iov_len  = aad_len;
	iov[1].iov_base = (void *)pt;
	iov[1].iov_len  = pt_len;
	msg.msg_iov        = iov;
	msg.msg_iovlen     = 2;
	msg.msg_control    = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type  = ALG_SET_OP;
	cmsg->cmsg_len   = CMSG_LEN(sizeof(__u32));
	*((__u32 *)CMSG_DATA(cmsg)) = ALG_OP_ENCRYPT;

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type  = ALG_SET_IV;
	cmsg->cmsg_len   = CMSG_LEN(sizeof(struct af_alg_iv) + 12);
	aiv = (struct af_alg_iv *)CMSG_DATA(cmsg);
	aiv->ivlen = 12;
	memcpy(aiv->iv, nonce, 12);

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type  = ALG_SET_AEAD_ASSOCLEN;
	cmsg->cmsg_len   = CMSG_LEN(sizeof(__u32));
	*((__u32 *)CMSG_DATA(cmsg)) = aad_len;

	if (sendmsg(op_fd, &msg, 0) < 0) {
		fprintf(stderr, "  sendmsg: %s\n", strerror(errno));
		goto out;
	}

	n = read(op_fd, out, ct_out_len);
	if (n < 0 || (size_t)n != ct_out_len) {
		fprintf(stderr, "  read: got %zd, want %u: %s\n",
			n, ct_out_len, strerror(errno));
		goto out;
	}

	if (memcmp(out, exp_ct, pt_len) != 0) {
		fprintf(stderr, "  ciphertext mismatch\n");
		goto out;
	}

	if (memcmp(out + pt_len, exp_tag, tag_len) != 0) {
		fprintf(stderr, "  auth tag mismatch\n");
		goto out;
	}

	printf("PASS\n");
	g_pass++;
	ret = 0;

out:
	if (ret != 0) {
		fprintf(stderr, "FAIL [%s]\n", __func__);
		g_fail++;
	}
	close(op_fd);
	close(alg_fd);
	return ret;
}

/* ------------------------------------------------------------------
 * Main
 * ------------------------------------------------------------------ */

int main(void)
{
	printf("crypto2dev/wolfkm AF_ALG kernel crypto API test\n\n");

	test_skcipher_cbc_aes();
	test_hash_sha256();
	test_aead_gcm_aes();

	printf("\n%d passed, %d failed\n", g_pass, g_fail);

	if (g_fail > 0) {
		printf("FAIL\n");
		return 1;
	}
	printf("PASS\n");
	return 0;
}
