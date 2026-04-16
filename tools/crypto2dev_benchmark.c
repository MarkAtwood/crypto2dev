// SPDX-License-Identifier: GPL-2.0-only
/*
 * crypto2dev_benchmark.c — throughput benchmark: /dev/crypto2dev vs AF_ALG
 *
 * Measures AES-CBC-256 encrypt and SHA-256 hash throughput for both
 * /dev/crypto2dev and the kernel built-in crypto via AF_ALG sockets.
 * Reports mean MB/s ± stddev and a speedup ratio.
 *
 * Usage:
 *   crypto2dev_benchmark [--iterations N]   (default: 20)
 *
 * Output: TSV rows, one per algorithm/backend combination, plus a summary
 * table.  TSV is parseable by awk/python.  Each row:
 *   algo <TAB> backend <TAB> mean_mbs <TAB> stddev_mbs
 *
 * Compile:
 *   gcc -O2 -Wall -Wextra -I../include \
 *       -o crypto2dev_benchmark crypto2dev_benchmark.c -lm
 *
 * Run as root with wolfcrypt.ko and crypto2dev.ko loaded:
 *   sudo ./crypto2dev_benchmark
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <math.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <linux/types.h>

#include "uapi/crypto2dev_ioctl.h"

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#ifndef AF_ALG
#define AF_ALG 38
#endif

/* ── Benchmark parameters ─────────────────────────────────────────────────── */

#define BENCH_DATA_LEN    (1U << 20)   /* 1 MB per iteration */
#define BENCH_CHUNK_LEN   (64U << 10)  /* 64 KB write chunks */
#define DEFAULT_ITERS     20
#define AES256_KEYLEN     32           /* AES-256: 32-byte key */
#define AES_IVLEN         16           /* CBC IV: 16 bytes */
#define SHA256_DIGESTLEN  32

/* ── Result sentinel ──────────────────────────────────────────────────────── */

#define UNAVAIL_MARKER    (-1.0)       /* backend not available */

/* ── Shared test material (generated once from /dev/urandom) ─────────────── */

static unsigned char g_aes_key[AES256_KEYLEN];
static unsigned char g_aes_iv[AES_IVLEN];
static unsigned char *g_plaintext;    /* BENCH_DATA_LEN bytes */
static unsigned char *g_ciphertext;   /* BENCH_DATA_LEN bytes (drain buffer) */

/* ── Timing helpers ───────────────────────────────────────────────────────── */

static double now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

static double ns_to_mbs(double ns, size_t bytes)
{
	if (ns <= 0.0)
		return 0.0;
	return ((double)bytes / (1024.0 * 1024.0)) / (ns / 1e9);
}

/* ── Statistics ───────────────────────────────────────────────────────────── */

static void compute_stats(const double *samples, int n,
			  double *out_mean, double *out_stddev)
{
	double sum = 0.0, sq = 0.0;
	int i;

	for (i = 0; i < n; i++)
		sum += samples[i];
	*out_mean = sum / n;

	for (i = 0; i < n; i++) {
		double d = samples[i] - *out_mean;

		sq += d * d;
	}
	*out_stddev = (n > 1) ? sqrt(sq / (n - 1)) : 0.0;
}

/* ── Random material ──────────────────────────────────────────────────────── */

static int fill_random(void *buf, size_t len)
{
	int fd;
	ssize_t n;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		perror("open /dev/urandom");
		return -1;
	}
	n = read(fd, buf, len);
	close(fd);
	if (n < 0 || (size_t)n != len) {
		fprintf(stderr, "read /dev/urandom: short read\n");
		return -1;
	}
	return 0;
}

/* ── crypto2dev helpers ───────────────────────────────────────────────────── */

/*
 * c2d_open_cbc — open /dev/crypto2dev and initialize for AES-256-CBC encrypt.
 * Returns fd >= 0 on success, -1 if device unavailable or init fails.
 * Sets errno on failure.
 */
static int c2d_open_cbc(void)
{
	struct crypto2dev_init_op init;
	struct crypto2dev_iv_op iv_op;
	int fd;

	fd = open("/dev/crypto2dev", O_RDWR);
	if (fd < 0)
		return -1;

	memset(&init, 0, sizeof(init));
	strncpy(init.algo, "cbc(aes)", sizeof(init.algo) - 1);
	init.op     = CRYPTO2DEV_OP_ENCRYPT;
	init.keylen = AES256_KEYLEN;
	memcpy(init.key, g_aes_key, AES256_KEYLEN);
	init.key_fd = -1;

	if (ioctl(fd, CRYPTO2DEV_IOC_INIT, &init) != 0) {
		close(fd);
		return -1;
	}

	memset(&iv_op, 0, sizeof(iv_op));
	memcpy(iv_op.iv, g_aes_iv, AES_IVLEN);
	iv_op.ivlen = AES_IVLEN;

	if (ioctl(fd, CRYPTO2DEV_IOC_SET_IV, &iv_op) != 0) {
		close(fd);
		return -1;
	}

	return fd;
}

/*
 * c2d_open_sha256 — open /dev/crypto2dev and initialize for SHA-256.
 * Returns fd >= 0 on success, -1 if device unavailable or init fails.
 */
static int c2d_open_sha256(void)
{
	struct crypto2dev_init_op init;
	int fd;

	fd = open("/dev/crypto2dev", O_RDWR);
	if (fd < 0)
		return -1;

	memset(&init, 0, sizeof(init));
	strncpy(init.algo, "sha256", sizeof(init.algo) - 1);
	init.op     = CRYPTO2DEV_OP_HASH;
	init.keylen = 0;
	init.key_fd = -1;

	if (ioctl(fd, CRYPTO2DEV_IOC_INIT, &init) != 0) {
		close(fd);
		return -1;
	}

	return fd;
}

/*
 * c2d_reset_cbc — reset fd for a new CBC iteration (same key; new IV).
 * Returns 0 on success, -1 on failure.
 */
static int c2d_reset_cbc(int fd)
{
	struct crypto2dev_iv_op iv_op;

	if (ioctl(fd, CRYPTO2DEV_IOC_RESET) != 0)
		return -1;

	memset(&iv_op, 0, sizeof(iv_op));
	memcpy(iv_op.iv, g_aes_iv, AES_IVLEN);
	iv_op.ivlen = AES_IVLEN;

	return ioctl(fd, CRYPTO2DEV_IOC_SET_IV, &iv_op);
}

/*
 * c2d_reset_sha256 — reset fd for a new SHA-256 iteration.
 * Returns 0 on success, -1 on failure.
 */
static int c2d_reset_sha256(int fd)
{
	return ioctl(fd, CRYPTO2DEV_IOC_RESET);
}

/*
 * c2d_run_one — run one iteration of a crypto2dev benchmark pass.
 *
 * For CBC:  write all chunks → FINALIZE → read all output (discard)
 * For SHA:  write all chunks → FINALIZE → read digest (discard)
 *
 * Returns elapsed nanoseconds on success, -1.0 on I/O error.
 */
static double c2d_run_one(int fd, int is_hash)
{
	unsigned char digest[SHA256_DIGESTLEN];
	unsigned char *drain;
	size_t sent, to_send, drained, to_drain;
	ssize_t n;
	double t0, t1;

	t0 = now_ns();

	/* --- write phase (chunked) --- */
	sent = 0;
	while (sent < BENCH_DATA_LEN) {
		to_send = BENCH_DATA_LEN - sent;
		if (to_send > BENCH_CHUNK_LEN)
			to_send = BENCH_CHUNK_LEN;

		n = write(fd, g_plaintext + sent, to_send);
		if (n < 0) {
			fprintf(stderr, "c2d write: %s\n", strerror(errno));
			return -1.0;
		}
		sent += (size_t)n;
	}

	/* --- finalize --- */
	if (ioctl(fd, CRYPTO2DEV_IOC_FINALIZE) != 0) {
		fprintf(stderr, "c2d FINALIZE: %s\n", strerror(errno));
		return -1.0;
	}

	/* --- drain output --- */
	if (is_hash) {
		/* Hash: exactly SHA256_DIGESTLEN bytes */
		n = read(fd, digest, sizeof(digest));
		if (n < 0) {
			fprintf(stderr, "c2d hash read: %s\n", strerror(errno));
			return -1.0;
		}
	} else {
		/* CBC: drain BENCH_DATA_LEN bytes of ciphertext */
		drain   = g_ciphertext;
		drained = 0;
		while (drained < BENCH_DATA_LEN) {
			to_drain = BENCH_DATA_LEN - drained;
			if (to_drain > BENCH_CHUNK_LEN)
				to_drain = BENCH_CHUNK_LEN;

			n = read(fd, drain + drained, to_drain);
			if (n <= 0) {
				if (n == 0)
					break;  /* EOF — done */
				fprintf(stderr, "c2d cbc read: %s\n",
					strerror(errno));
				return -1.0;
			}
			drained += (size_t)n;
		}
	}

	t1 = now_ns();
	return t1 - t0;
}

/* ── crypto2dev benchmark runners ────────────────────────────────────────── */

static double bench_c2d_cbc(int iters, double *samples)
{
	int fd, i;

	fd = c2d_open_cbc();
	if (fd < 0) {
		if (errno == ENOENT || errno == ENODEV)
			fprintf(stderr,
				"  crypto2dev: %s not found — module loaded?\n",
				"/dev/crypto2dev");
		else
			fprintf(stderr, "  crypto2dev cbc open: %s\n",
				strerror(errno));
		return UNAVAIL_MARKER;
	}

	for (i = 0; i < iters; i++) {
		double elapsed;

		if (i > 0 && c2d_reset_cbc(fd) != 0) {
			fprintf(stderr, "  c2d RESET (cbc): %s\n",
				strerror(errno));
			close(fd);
			return UNAVAIL_MARKER;
		}

		elapsed = c2d_run_one(fd, 0);
		if (elapsed < 0.0) {
			close(fd);
			return UNAVAIL_MARKER;
		}
		samples[i] = ns_to_mbs(elapsed, BENCH_DATA_LEN);
	}

	close(fd);
	return 0.0;
}

static double bench_c2d_sha256(int iters, double *samples)
{
	int fd, i;

	fd = c2d_open_sha256();
	if (fd < 0) {
		if (errno == ENOENT || errno == ENODEV)
			fprintf(stderr,
				"  crypto2dev: %s not found — module loaded?\n",
				"/dev/crypto2dev");
		else
			fprintf(stderr, "  crypto2dev sha256 open: %s\n",
				strerror(errno));
		return UNAVAIL_MARKER;
	}

	for (i = 0; i < iters; i++) {
		double elapsed;

		if (i > 0 && c2d_reset_sha256(fd) != 0) {
			fprintf(stderr, "  c2d RESET (sha256): %s\n",
				strerror(errno));
			close(fd);
			return UNAVAIL_MARKER;
		}

		elapsed = c2d_run_one(fd, 1);
		if (elapsed < 0.0) {
			close(fd);
			return UNAVAIL_MARKER;
		}
		samples[i] = ns_to_mbs(elapsed, BENCH_DATA_LEN);
	}

	close(fd);
	return 0.0;
}

/* ── AF_ALG helpers ───────────────────────────────────────────────────────── */

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

/*
 * afalg_run_cbc_one — one AF_ALG CBC encrypt iteration.
 *
 * AF_ALG skcipher workflow per iteration:
 *   accept(alg_fd) → sendmsg(with OP+IV cmsg, first chunk)
 *   → send remaining chunks → recv all output
 *
 * A new op_fd is opened per iteration so the IV is fresh each time.
 * Returns elapsed nanoseconds on success, -1.0 on error.
 */
static double afalg_run_cbc_one(int alg_fd)
{
	/* cmsg buffer: ALG_SET_OP (__u32) + ALG_SET_IV (af_alg_iv + 16 bytes) */
	char cmsgbuf[CMSG_SPACE(sizeof(__u32)) +
		     CMSG_SPACE(sizeof(struct af_alg_iv) + AES_IVLEN)];
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct af_alg_iv *aiv;
	int op_fd;
	size_t sent, drained, to_send, to_drain;
	ssize_t n;
	double t0, t1;

	op_fd = accept(alg_fd, NULL, 0);
	if (op_fd < 0) {
		fprintf(stderr, "  afalg accept (cbc): %s\n", strerror(errno));
		return -1.0;
	}

	t0 = now_ns();

	/*
	 * First chunk: carry OP + IV in cmsg.
	 * Subsequent chunks: plain send() with no cmsg (IV is sticky).
	 */
	memset(cmsgbuf, 0, sizeof(cmsgbuf));
	memset(&msg, 0, sizeof(msg));

	iov.iov_base = g_plaintext;
	iov.iov_len  = BENCH_CHUNK_LEN;
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
	cmsg->cmsg_len   = CMSG_LEN(sizeof(struct af_alg_iv) + AES_IVLEN);
	aiv = (struct af_alg_iv *)CMSG_DATA(cmsg);
	aiv->ivlen = AES_IVLEN;
	memcpy(aiv->iv, g_aes_iv, AES_IVLEN);

	if (sendmsg(op_fd, &msg, 0) < 0) {
		fprintf(stderr, "  afalg sendmsg (cbc): %s\n", strerror(errno));
		close(op_fd);
		return -1.0;
	}

	/* Remaining chunks: plain send, IV already set */
	sent = BENCH_CHUNK_LEN;
	while (sent < BENCH_DATA_LEN) {
		to_send = BENCH_DATA_LEN - sent;
		if (to_send > BENCH_CHUNK_LEN)
			to_send = BENCH_CHUNK_LEN;

		n = send(op_fd, g_plaintext + sent, to_send, MSG_MORE);
		if (n < 0) {
			fprintf(stderr, "  afalg send (cbc): %s\n",
				strerror(errno));
			close(op_fd);
			return -1.0;
		}
		sent += (size_t)n;
	}

	/* Drain all ciphertext output */
	drained = 0;
	while (drained < BENCH_DATA_LEN) {
		to_drain = BENCH_DATA_LEN - drained;
		if (to_drain > BENCH_CHUNK_LEN)
			to_drain = BENCH_CHUNK_LEN;

		n = recv(op_fd, g_ciphertext + drained, to_drain, 0);
		if (n <= 0) {
			if (n == 0)
				break;
			fprintf(stderr, "  afalg recv (cbc): %s\n",
				strerror(errno));
			close(op_fd);
			return -1.0;
		}
		drained += (size_t)n;
	}

	t1 = now_ns();
	close(op_fd);
	return t1 - t0;
}

/*
 * afalg_run_sha256_one — one AF_ALG SHA-256 hash iteration.
 *
 * AF_ALG hash workflow: op_fd reused across iterations (read() resets state).
 *   send(all data) → read(32-byte digest)
 *
 * Returns elapsed nanoseconds on success, -1.0 on error.
 */
static double afalg_run_sha256_one(int op_fd)
{
	unsigned char digest[SHA256_DIGESTLEN];
	size_t sent, to_send;
	ssize_t n;
	double t0, t1;

	t0 = now_ns();

	sent = 0;
	while (sent < BENCH_DATA_LEN) {
		to_send = BENCH_DATA_LEN - sent;
		if (to_send > BENCH_CHUNK_LEN)
			to_send = BENCH_CHUNK_LEN;

		n = send(op_fd, g_plaintext + sent, to_send, MSG_MORE);
		if (n < 0) {
			fprintf(stderr, "  afalg send (sha256): %s\n",
				strerror(errno));
			return -1.0;
		}
		sent += (size_t)n;
	}

	n = read(op_fd, digest, sizeof(digest));
	if (n != SHA256_DIGESTLEN) {
		fprintf(stderr, "  afalg read digest: got %zd, want %d: %s\n",
			n, SHA256_DIGESTLEN, strerror(errno));
		return -1.0;
	}

	t1 = now_ns();
	return t1 - t0;
}

/* ── AF_ALG benchmark runners ─────────────────────────────────────────────── */

static double bench_afalg_cbc(int iters, double *samples)
{
	int alg_fd, i;

	alg_fd = alg_bind("skcipher", "cbc(aes)");
	if (alg_fd < 0) {
		fprintf(stderr, "  AF_ALG bind skcipher/cbc(aes): %s\n",
			strerror(errno));
		return UNAVAIL_MARKER;
	}

	if (setsockopt(alg_fd, SOL_ALG, ALG_SET_KEY,
		       g_aes_key, (socklen_t)AES256_KEYLEN) < 0) {
		fprintf(stderr, "  AF_ALG ALG_SET_KEY (cbc): %s\n",
			strerror(errno));
		close(alg_fd);
		return UNAVAIL_MARKER;
	}

	for (i = 0; i < iters; i++) {
		double elapsed = afalg_run_cbc_one(alg_fd);

		if (elapsed < 0.0) {
			close(alg_fd);
			return UNAVAIL_MARKER;
		}
		samples[i] = ns_to_mbs(elapsed, BENCH_DATA_LEN);
	}

	close(alg_fd);
	return 0.0;
}

static double bench_afalg_sha256(int iters, double *samples)
{
	int alg_fd, op_fd, i;

	alg_fd = alg_bind("hash", "sha256");
	if (alg_fd < 0) {
		fprintf(stderr, "  AF_ALG bind hash/sha256: %s\n",
			strerror(errno));
		return UNAVAIL_MARKER;
	}

	op_fd = accept(alg_fd, NULL, 0);
	if (op_fd < 0) {
		fprintf(stderr, "  AF_ALG accept (sha256): %s\n",
			strerror(errno));
		close(alg_fd);
		return UNAVAIL_MARKER;
	}

	for (i = 0; i < iters; i++) {
		double elapsed = afalg_run_sha256_one(op_fd);

		if (elapsed < 0.0) {
			close(op_fd);
			close(alg_fd);
			return UNAVAIL_MARKER;
		}
		samples[i] = ns_to_mbs(elapsed, BENCH_DATA_LEN);
	}

	close(op_fd);
	close(alg_fd);
	return 0.0;
}

/* ── Output ───────────────────────────────────────────────────────────────── */

static void print_row_tsv(const char *algo, const char *backend,
			  double mean, double stddev)
{
	if (mean < 0.0)
		printf("%s\t%s\tUNAVAIL\tUNAVAIL\n", algo, backend);
	else
		printf("%s\t%s\t%.1f\t%.1f\n", algo, backend, mean, stddev);
}

static void print_summary_row(const char *algo,
			      double c2d_mean, double c2d_sd,
			      double afalg_mean, double afalg_sd)
{
	char c2d_buf[32], afalg_buf[32], ratio_buf[16];

	if (c2d_mean < 0.0)
		snprintf(c2d_buf, sizeof(c2d_buf), "%-20s", "UNAVAIL");
	else
		snprintf(c2d_buf, sizeof(c2d_buf), "%7.1f ± %5.1f",
			 c2d_mean, c2d_sd);

	if (afalg_mean < 0.0)
		snprintf(afalg_buf, sizeof(afalg_buf), "%-20s", "UNAVAIL");
	else
		snprintf(afalg_buf, sizeof(afalg_buf), "%7.1f ± %5.1f",
			 afalg_mean, afalg_sd);

	if (c2d_mean > 0.0 && afalg_mean > 0.0)
		snprintf(ratio_buf, sizeof(ratio_buf), "%.2fx",
			 c2d_mean / afalg_mean);
	else
		snprintf(ratio_buf, sizeof(ratio_buf), "N/A");

	printf("%-28s %-20s %-20s %s\n",
	       algo, c2d_buf, afalg_buf, ratio_buf);
}

/* ── Main ─────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
	int iters = DEFAULT_ITERS;
	double *c2d_cbc_s, *c2d_sha_s, *afalg_cbc_s, *afalg_sha_s;
	double c2d_cbc_mean, c2d_cbc_sd;
	double c2d_sha_mean, c2d_sha_sd;
	double afalg_cbc_mean, afalg_cbc_sd;
	double afalg_sha_mean, afalg_sha_sd;
	int c2d_cbc_ok, c2d_sha_ok, afalg_cbc_ok, afalg_sha_ok;

	/* Parse --iterations N */
	if (argc == 3 && strcmp(argv[1], "--iterations") == 0) {
		iters = atoi(argv[2]);
		if (iters < 1) {
			fprintf(stderr, "error: iterations must be >= 1\n");
			return 1;
		}
	} else if (argc > 1) {
		fprintf(stderr,
			"Usage: %s [--iterations N]\n", argv[0]);
		return 1;
	}

	/* Allocate sample arrays */
	c2d_cbc_s   = malloc(iters * sizeof(double));
	c2d_sha_s   = malloc(iters * sizeof(double));
	afalg_cbc_s = malloc(iters * sizeof(double));
	afalg_sha_s = malloc(iters * sizeof(double));
	g_plaintext  = malloc(BENCH_DATA_LEN);
	g_ciphertext = malloc(BENCH_DATA_LEN);

	if (!c2d_cbc_s || !c2d_sha_s || !afalg_cbc_s || !afalg_sha_s ||
	    !g_plaintext || !g_ciphertext) {
		fprintf(stderr, "error: malloc failed\n");
		return 1;
	}

	/* Generate random key, IV, and plaintext from /dev/urandom */
	if (fill_random(g_aes_key, sizeof(g_aes_key)) != 0 ||
	    fill_random(g_aes_iv, sizeof(g_aes_iv)) != 0 ||
	    fill_random(g_plaintext, BENCH_DATA_LEN) != 0) {
		return 1;
	}

	fprintf(stderr,
		"crypto2dev_benchmark: %d iterations, %u KB payload, "
		"%u KB chunks\n",
		iters, BENCH_DATA_LEN / 1024, BENCH_CHUNK_LEN / 1024);

	/* ── Run benchmarks ─────────────────────────────────────────────────── */

	fprintf(stderr, "  Benchmarking crypto2dev cbc(aes)-256-encrypt ...\n");
	c2d_cbc_ok = (bench_c2d_cbc(iters, c2d_cbc_s) == 0.0);

	fprintf(stderr, "  Benchmarking crypto2dev sha256 ...\n");
	c2d_sha_ok = (bench_c2d_sha256(iters, c2d_sha_s) == 0.0);

	fprintf(stderr, "  Benchmarking AF_ALG cbc(aes)-256-encrypt ...\n");
	afalg_cbc_ok = (bench_afalg_cbc(iters, afalg_cbc_s) == 0.0);

	fprintf(stderr, "  Benchmarking AF_ALG sha256 ...\n");
	afalg_sha_ok = (bench_afalg_sha256(iters, afalg_sha_s) == 0.0);

	/* ── Compute stats ──────────────────────────────────────────────────── */

	if (c2d_cbc_ok)
		compute_stats(c2d_cbc_s, iters, &c2d_cbc_mean, &c2d_cbc_sd);
	else
		c2d_cbc_mean = c2d_cbc_sd = UNAVAIL_MARKER;

	if (c2d_sha_ok)
		compute_stats(c2d_sha_s, iters, &c2d_sha_mean, &c2d_sha_sd);
	else
		c2d_sha_mean = c2d_sha_sd = UNAVAIL_MARKER;

	if (afalg_cbc_ok)
		compute_stats(afalg_cbc_s, iters,
			      &afalg_cbc_mean, &afalg_cbc_sd);
	else
		afalg_cbc_mean = afalg_cbc_sd = UNAVAIL_MARKER;

	if (afalg_sha_ok)
		compute_stats(afalg_sha_s, iters,
			      &afalg_sha_mean, &afalg_sha_sd);
	else
		afalg_sha_mean = afalg_sha_sd = UNAVAIL_MARKER;

	/* ── TSV output (algo, backend, mean_mbs, stddev_mbs) ──────────────── */

	printf("# TSV: algo\tbackend\tmean_mbs\tstddev_mbs\n");
	print_row_tsv("cbc(aes)-256-encrypt", "crypto2dev",
		      c2d_cbc_mean, c2d_cbc_sd);
	print_row_tsv("cbc(aes)-256-encrypt", "afalg",
		      afalg_cbc_mean, afalg_cbc_sd);
	print_row_tsv("sha256", "crypto2dev",
		      c2d_sha_mean, c2d_sha_sd);
	print_row_tsv("sha256", "afalg",
		      afalg_sha_mean, afalg_sha_sd);

	/* ── Human-readable summary ─────────────────────────────────────────── */

	printf("\n");
	printf("%-28s %-20s %-20s %s\n",
	       "Algorithm",
	       "crypto2dev (MB/s)",
	       "AF_ALG (MB/s)",
	       "ratio");
	printf("%-28s %-20s %-20s %s\n",
	       "----------------------------",
	       "--------------------",
	       "--------------------",
	       "-----");
	print_summary_row("cbc(aes)-256-encrypt",
			  c2d_cbc_mean, c2d_cbc_sd,
			  afalg_cbc_mean, afalg_cbc_sd);
	print_summary_row("sha256",
			  c2d_sha_mean, c2d_sha_sd,
			  afalg_sha_mean, afalg_sha_sd);

	free(c2d_cbc_s);
	free(c2d_sha_s);
	free(afalg_cbc_s);
	free(afalg_sha_s);
	free(g_plaintext);
	free(g_ciphertext);

	return 0;
}
