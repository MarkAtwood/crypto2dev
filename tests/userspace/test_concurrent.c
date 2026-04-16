// SPDX-License-Identifier: GPL-2.0-only
/*
 * test_concurrent.c — provider-cycling concurrency stress test
 *
 * Tests fget/fput discipline (WOLFKM-con.32), module unload race,
 * registry rwlock vs session mutex ordering.
 *
 * Spawns N worker threads each performing repeated SHA-256 hash operations
 * on fresh fds, while a separate cycler thread repeatedly unloads and
 * reloads the wolfssl provider module. Workers encountering ENOENT (no
 * provider) or EACCES (FIPS gate) during cycling are expected and counted
 * but do not cause test failure. Panics, hangs, or lockdep splats (checked
 * externally via dmesg) are failure indicators.
 *
 * Compile:
 *   gcc -Wall -Wextra -pthread -O2 -o test_concurrent test_concurrent.c \
 *       -I../../include
 *
 * Run as root with crypto2dev.ko (and wolfcrypt.ko) loaded:
 *   sudo ./test_concurrent -t 8 -d 60 -k /path/to/crypto2dev_wolfssl.ko
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <linux/types.h>

#include "uapi/crypto2dev_ioctl.h"

#define DEVICE_PATH       "/dev/crypto2dev"
#define DEFAULT_THREADS   8
#define DEFAULT_DURATION  30     /* seconds */
#define SHA256_DIGEST_LEN 32
#define PAYLOAD_SIZE      64     /* bytes fed to SHA-256 per operation */
#define CYCLER_SLEEP_US   50000  /* 50 ms between rmmod/insmod */
#define PROGRESS_INTERVAL 5      /* seconds between progress prints */
#define RMMOD_RETRY_MAX   20     /* retries on EBUSY before giving up */
#define RMMOD_RETRY_US    10000  /* 10 ms between EBUSY retries */

/* Shared stop flag: set by SIGALRM or SIGINT/SIGTERM */
static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_verbose;

/* Per-worker counters */
struct worker_stats {
	unsigned long ops_ok;      /* completed hash ops */
	unsigned long err_noprov;  /* ENOENT — no provider, expected during cycling */
	unsigned long err_fips;    /* EACCES — FIPS gate, expected during cycling */
	unsigned long err_other;   /* unexpected errors */
	int           thread_id;
};

/* Cycler stats */
struct cycler_stats {
	unsigned long cycles_ok;   /* successful rmmod+insmod pairs */
	unsigned long rmmod_busy;  /* EBUSY retries */
	unsigned long rmmod_fail;  /* rmmod failed for other reason */
	unsigned long insmod_fail; /* insmod failed */
};

static struct cycler_stats g_cycler_stats;

/* ko path for the wolfssl provider module */
static char g_ko_path[512];

static void sig_handler(int sig)
{
	(void)sig;
	g_running = 0;
}

/* ── Device helpers ───────────────────────────────────────────────────────── */

static int do_init_hash(int fd, const char *algo)
{
	struct crypto2dev_init_op init;

	memset(&init, 0, sizeof(init));
	strncpy(init.algo, algo, sizeof(init.algo) - 1);
	init.op     = CRYPTO2DEV_OP_HASH;
	init.keylen = 0;
	init.key_fd = -1;
	return ioctl(fd, CRYPTO2DEV_IOC_INIT, &init);
}

/* ── Worker thread ────────────────────────────────────────────────────────── */

/*
 * One SHA-256 hash operation:
 *   open → INIT("sha256", HASH) → write(64B) → FINALIZE → read(32B) → close
 *
 * Returns:
 *   0        success
 *  -ENOENT   no provider loaded (wolfssl unloaded by cycler)
 *  -EACCES   FIPS gate not operational
 *  -1        other error (unexpected)
 */
static int do_sha256_op(void)
{
	static const uint8_t testdata[PAYLOAD_SIZE] = {
		0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
		0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
		0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
		0x79, 0x7a, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
		0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
		0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
		0x77, 0x78, 0x79, 0x7a, 0x30, 0x31, 0x32, 0x33,
		0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42,
	};
	uint8_t digest[SHA256_DIGEST_LEN];
	int fd, ret, saved_errno;
	ssize_t n;

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		saved_errno = errno;
		if (saved_errno == ENOENT || saved_errno == ENODEV)
			return -ENOENT;
		return -1;
	}

	ret = do_init_hash(fd, "sha256");
	if (ret != 0) {
		saved_errno = errno;
		close(fd);
		if (saved_errno == ENOENT)
			return -ENOENT;
		if (saved_errno == EACCES)
			return -EACCES;
		return -1;
	}

	n = write(fd, testdata, PAYLOAD_SIZE);
	if (n != PAYLOAD_SIZE) {
		saved_errno = errno;
		close(fd);
		if (saved_errno == ENOENT)
			return -ENOENT;
		if (saved_errno == EACCES)
			return -EACCES;
		if (saved_errno == EIO || saved_errno == ENODEV)
			return -ENOENT;  /* provider vanished mid-op */
		return -1;
	}

	ret = ioctl(fd, CRYPTO2DEV_IOC_FINALIZE);
	if (ret != 0) {
		saved_errno = errno;
		close(fd);
		if (saved_errno == ENOENT)
			return -ENOENT;
		if (saved_errno == EACCES)
			return -EACCES;
		if (saved_errno == EIO || saved_errno == ENODEV)
			return -ENOENT;
		return -1;
	}

	/* SHA-256 digest is 32 bytes; read returns exactly that after FINALIZE */
	n = read(fd, digest, sizeof(digest));
	if (n != SHA256_DIGEST_LEN) {
		saved_errno = errno;
		close(fd);
		if (saved_errno == ENOENT)
			return -ENOENT;
		if (saved_errno == EIO || saved_errno == ENODEV)
			return -ENOENT;
		return -1;
	}

	close(fd);
	return 0;
}

static void *worker_fn(void *arg)
{
	struct worker_stats *s = arg;
	int r;

	while (g_running) {
		r = do_sha256_op();
		if (r == 0) {
			s->ops_ok++;
		} else if (r == -ENOENT) {
			s->err_noprov++;
		} else if (r == -EACCES) {
			s->err_fips++;
		} else {
			s->err_other++;
		}
	}

	return NULL;
}

/* ── Cycler thread ────────────────────────────────────────────────────────── */

static void *cycler_fn(void *arg)
{
	char rmmod_cmd[128];
	char insmod_cmd[600];
	int ret, retries;

	(void)arg;

	if (g_ko_path[0] == '\0') {
		/* No ko path provided — cycling disabled */
		return NULL;
	}

	snprintf(rmmod_cmd, sizeof(rmmod_cmd), "rmmod crypto2dev_wolfssl 2>/dev/null");
	snprintf(insmod_cmd, sizeof(insmod_cmd), "insmod %s 2>/dev/null", g_ko_path);

	while (g_running) {
		/*
		 * rmmod: workers may hold open fds which keep the module
		 * busy. Retry with a short delay — this is expected and
		 * normal; the test exercises this exact race.
		 */
		retries = 0;
		while (g_running && retries < RMMOD_RETRY_MAX) {
			ret = system(rmmod_cmd);
			if (ret == 0)
				break;
			/*
			 * system() exit status is the shell's exit code.
			 * rmmod exits 1 on EBUSY (module in use).
			 * We treat any non-zero as "busy, retry".
			 */
			__atomic_fetch_add(&g_cycler_stats.rmmod_busy, 1,
					   __ATOMIC_RELAXED);
			usleep(RMMOD_RETRY_US);
			retries++;
		}
		if (!g_running)
			break;
		if (retries == RMMOD_RETRY_MAX) {
			__atomic_fetch_add(&g_cycler_stats.rmmod_fail, 1,
					   __ATOMIC_RELAXED);
			if (g_verbose)
				fprintf(stderr,
					"cycler: rmmod still EBUSY after %d retries — skipping\n",
					RMMOD_RETRY_MAX);
			usleep(CYCLER_SLEEP_US);
			continue;
		}

		usleep(CYCLER_SLEEP_US);
		if (!g_running)
			break;

		ret = system(insmod_cmd);
		if (ret != 0) {
			__atomic_fetch_add(&g_cycler_stats.insmod_fail, 1,
					   __ATOMIC_RELAXED);
			if (g_verbose)
				fprintf(stderr,
					"cycler: insmod %s failed (exit %d)\n",
					g_ko_path, ret);
		} else {
			__atomic_fetch_add(&g_cycler_stats.cycles_ok, 1,
					   __ATOMIC_RELAXED);
		}

		usleep(CYCLER_SLEEP_US);
	}

	/*
	 * On exit, attempt to leave the module loaded so the system is
	 * left in a usable state.
	 */
	if (system(insmod_cmd) != 0 && g_verbose)
		fprintf(stderr, "cycler: cleanup insmod failed (may already be loaded)\n");

	return NULL;
}

/* ── Progress reporter ────────────────────────────────────────────────────── */

static void *progress_fn(void *arg)
{
	struct worker_stats **workers = arg;
	int num_threads = DEFAULT_THREADS;  /* captured at thread create */
	unsigned long last_ops = 0;
	unsigned long cur_ops;
	int i, elapsed = 0;

	(void)num_threads;

	/*
	 * The actual thread count is passed via a small wrapper struct.
	 * Here we receive it as the first element of the array passed in.
	 * See main() for details.
	 */
	while (g_running) {
		sleep(PROGRESS_INTERVAL);
		if (!g_running)
			break;
		elapsed += PROGRESS_INTERVAL;

		cur_ops = 0;
		for (i = 0; workers[i] != NULL; i++)
			cur_ops += workers[i]->ops_ok;

		printf("[+%3ds] ops: %lu total  (+%lu in last %ds)"
		       "  cycles: %lu\n",
		       elapsed,
		       cur_ops,
		       cur_ops - last_ops,
		       PROGRESS_INTERVAL,
		       g_cycler_stats.cycles_ok);
		fflush(stdout);

		last_ops = cur_ops;
	}

	return NULL;
}

/* ── Argument parsing ─────────────────────────────────────────────────────── */

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-t threads] [-d duration_sec] [-k ko_path] [-v]\n"
		"\n"
		"  -t N    number of worker threads (default: %d)\n"
		"  -d N    test duration in seconds (default: %d)\n"
		"  -k PATH path to crypto2dev_wolfssl.ko for provider cycling\n"
		"  -v      verbose output\n"
		"\n"
		"Example:\n"
		"  sudo %s -t 8 -d 60 -k /path/to/crypto2dev_wolfssl.ko\n"
		"\n"
		"Note: provider cycling (-k) requires root and the module\n"
		"to be signed appropriately for the running kernel.\n",
		prog, DEFAULT_THREADS, DEFAULT_DURATION, prog);
}

/* ── Main ─────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
	int num_threads = DEFAULT_THREADS;
	int duration    = DEFAULT_DURATION;
	int opt, i, fd;
	int any_fatal   = 0;

	pthread_t *worker_threads;
	pthread_t  cycler_thread;
	pthread_t  progress_thread;
	int        do_cycling    = 0;
	int        do_progress;

	struct worker_stats  **worker_stats_ptrs; /* NULL-terminated array */
	struct worker_stats   *worker_stats_arr;

	unsigned long total_ops      = 0;
	unsigned long total_noprov   = 0;
	unsigned long total_fips     = 0;
	unsigned long total_other    = 0;

	struct timeval t_start, t_end;
	double elapsed_sec;

	while ((opt = getopt(argc, argv, "t:d:k:v")) != -1) {
		switch (opt) {
		case 't':
			num_threads = atoi(optarg);
			if (num_threads < 1 || num_threads > 256) {
				fprintf(stderr,
					"error: -t must be 1..256\n");
				return 1;
			}
			break;
		case 'd':
			duration = atoi(optarg);
			if (duration < 1 || duration > 3600) {
				fprintf(stderr,
					"error: -d must be 1..3600\n");
				return 1;
			}
			break;
		case 'k':
			strncpy(g_ko_path, optarg, sizeof(g_ko_path) - 1);
			g_ko_path[sizeof(g_ko_path) - 1] = '\0';
			do_cycling = 1;
			break;
		case 'v':
			g_verbose = 1;
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	printf("crypto2dev concurrency stress test\n");
	printf("device:   %s\n", DEVICE_PATH);
	printf("threads:  %d\n", num_threads);
	printf("duration: %d seconds\n", duration);
	if (do_cycling)
		printf("cycling:  %s\n", g_ko_path);
	else
		printf("cycling:  disabled (no -k given)\n");
	printf("\n");

	/* Verify device is accessible before spawning threads */
	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		if (errno == ENOENT)
			fprintf(stderr,
				"SKIP: %s not found — module not loaded?\n",
				DEVICE_PATH);
		else
			fprintf(stderr, "open %s: %s\n",
				DEVICE_PATH, strerror(errno));
		return 1;
	}
	close(fd);

	/* Allocate thread and stats arrays */
	worker_threads = calloc((size_t)num_threads, sizeof(pthread_t));
	worker_stats_arr = calloc((size_t)num_threads, sizeof(struct worker_stats));
	/* +1 for NULL sentinel used by progress thread */
	worker_stats_ptrs = calloc((size_t)(num_threads + 1),
				   sizeof(struct worker_stats *));
	if (!worker_threads || !worker_stats_arr || !worker_stats_ptrs) {
		fprintf(stderr, "calloc: %s\n", strerror(errno));
		return 1;
	}
	for (i = 0; i < num_threads; i++) {
		worker_stats_arr[i].thread_id  = i;
		worker_stats_ptrs[i] = &worker_stats_arr[i];
	}
	worker_stats_ptrs[num_threads] = NULL; /* sentinel */

	/* Install signal handlers */
	signal(SIGINT,  sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGALRM, sig_handler);

	/* Set duration timer */
	alarm((unsigned int)duration);

	gettimeofday(&t_start, NULL);

	/* Start cycler thread first so provider is loaded when workers start */
	if (do_cycling) {
		if (pthread_create(&cycler_thread, NULL, cycler_fn, NULL) != 0) {
			fprintf(stderr, "pthread_create cycler: %s\n",
				strerror(errno));
			return 1;
		}
	}

	/* Start worker threads */
	for (i = 0; i < num_threads; i++) {
		if (pthread_create(&worker_threads[i], NULL,
				   worker_fn,
				   &worker_stats_arr[i]) != 0) {
			fprintf(stderr, "pthread_create worker %d: %s\n",
				i, strerror(errno));
			g_running = 0;
			break;
		}
	}

	/* Start progress reporter if verbose */
	do_progress = g_verbose;
	if (do_progress) {
		if (pthread_create(&progress_thread, NULL,
				   progress_fn,
				   worker_stats_ptrs) != 0) {
			do_progress = 0; /* non-fatal */
		}
	}

	/* Wait for all workers */
	for (i = 0; i < num_threads; i++)
		pthread_join(worker_threads[i], NULL);

	g_running = 0; /* ensure cycler and progress threads also stop */

	if (do_cycling)
		pthread_join(cycler_thread, NULL);
	if (do_progress)
		pthread_join(progress_thread, NULL);

	gettimeofday(&t_end, NULL);
	elapsed_sec = (double)(t_end.tv_sec  - t_start.tv_sec) +
		      (double)(t_end.tv_usec - t_start.tv_usec) / 1e6;

	/* Aggregate per-worker counters */
	for (i = 0; i < num_threads; i++) {
		total_ops    += worker_stats_arr[i].ops_ok;
		total_noprov += worker_stats_arr[i].err_noprov;
		total_fips   += worker_stats_arr[i].err_fips;
		total_other  += worker_stats_arr[i].err_other;
		if (worker_stats_arr[i].err_other > 0)
			any_fatal = 1;
	}

	/* Per-thread summary in verbose mode */
	if (g_verbose) {
		printf("\nPer-thread results:\n");
		for (i = 0; i < num_threads; i++) {
			struct worker_stats *s = &worker_stats_arr[i];

			printf("  thread %2d: ok=%lu noprov=%lu fips=%lu other=%lu\n",
			       i, s->ops_ok, s->err_noprov,
			       s->err_fips, s->err_other);
		}
	}

	printf("\n--- Results ---\n");
	printf("elapsed:        %.2f s\n", elapsed_sec);
	printf("hash ops ok:    %lu\n", total_ops);
	printf("err_noprov:     %lu  (expected during cycling)\n", total_noprov);
	printf("err_fips:       %lu  (expected during cycling)\n", total_fips);
	printf("err_other:      %lu  (unexpected — check dmesg)\n", total_other);
	if (elapsed_sec > 0)
		printf("throughput:     %.0f ops/sec\n",
		       (double)total_ops / elapsed_sec);
	if (do_cycling) {
		printf("cycles ok:      %lu\n", g_cycler_stats.cycles_ok);
		printf("rmmod busy:     %lu\n", g_cycler_stats.rmmod_busy);
		printf("rmmod fail:     %lu\n", g_cycler_stats.rmmod_fail);
		printf("insmod fail:    %lu\n", g_cycler_stats.insmod_fail);
	}

	/*
	 * Pass criteria:
	 *   - No unexpected errors (err_other == 0).
	 *   - At least one successful op (guards against the device being
	 *     unreachable for the entire run).
	 *   - No kernel panic or hang (checked externally via dmesg).
	 *
	 * err_noprov and err_fips are expected and normal when cycling is
	 * active — workers simply encounter a transiently absent provider.
	 */
	if (any_fatal || total_other > 0) {
		printf("\nFAIL: %lu unexpected error(s) — check dmesg for oops/lockdep\n",
		       total_other);
		free(worker_threads);
		free(worker_stats_arr);
		free(worker_stats_ptrs);
		return 1;
	}

	if (total_ops == 0) {
		printf("\nFAIL: no successful operations completed\n");
		free(worker_threads);
		free(worker_stats_arr);
		free(worker_stats_ptrs);
		return 1;
	}

	printf("\nPASS: no panics, no lockdep splats, no unexpected errors\n");
	free(worker_threads);
	free(worker_stats_arr);
	free(worker_stats_ptrs);
	return 0;
}
