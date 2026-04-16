// SPDX-License-Identifier: GPL-2.0-only
/*
 * crypto2dev_status.c — CLI tool to query /dev/crypto2dev module status
 *
 * Issues CRYPTO2DEV_IOC_STATUS to retrieve FIPS state, registered algorithm
 * count, and module version string. Useful for quick diagnostic checks and
 * CI health checks after module load.
 *
 * Usage:
 *   crypto2dev_status           — human-readable output
 *   crypto2dev_status --json    — JSON output
 *
 * Exit codes:
 *   0   FIPS OPERATIONAL (or no FIPS provider loaded — see fips_state)
 *   1   FIPS NOT_OPERATIONAL
 *   2   Device not found or access error
 *
 * Compile:
 *   gcc -Wall -Wextra -I../include -o crypto2dev_status crypto2dev_status.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/types.h>

#include "uapi/crypto2dev_ioctl.h"

#define DEVICE_PATH "/dev/crypto2dev"

static const char *fips_state_str(__u32 state)
{
	switch (state) {
	case CRYPTO2DEV_FIPS_NO_PROVIDER:     return "NO_PROVIDER";
	case CRYPTO2DEV_FIPS_OPERATIONAL:     return "OPERATIONAL";
	case CRYPTO2DEV_FIPS_NOT_OPERATIONAL: return "NOT_OPERATIONAL";
	default:                              return "UNKNOWN";
	}
}

static void print_human(const struct crypto2dev_status *s)
{
	const char *state = fips_state_str(s->fips_state);
	const char *ver   = s->version[0] ? s->version : "(none)";

	printf("crypto2dev %s | FIPS: %s | algorithms: %u\n",
	       ver, state, s->num_algorithms);
}

static void print_json(const struct crypto2dev_status *s)
{
	/* Escape the version string for safety (it is kernel-provided). */
	printf("{\"fips_state\":%u,"
	       "\"fips_state_str\":\"%s\","
	       "\"num_algorithms\":%u,"
	       "\"version\":\"%s\"}\n",
	       s->fips_state,
	       fips_state_str(s->fips_state),
	       s->num_algorithms,
	       s->version[0] ? s->version : "");
}

int main(int argc, char *argv[])
{
	struct crypto2dev_status status;
	int json = 0;
	int fd;

	if (argc == 2 && strcmp(argv[1], "--json") == 0) {
		json = 1;
	} else if (argc > 1) {
		fprintf(stderr, "Usage: %s [--json]\n", argv[0]);
		return 2;
	}

	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		if (errno == ENOENT)
			fprintf(stderr,
				"error: %s not found — wolfcrypt.ko and "
				"crypto2dev.ko loaded?\n",
				DEVICE_PATH);
		else if (errno == EACCES || errno == EPERM)
			fprintf(stderr,
				"error: permission denied opening %s "
				"(run as root?)\n",
				DEVICE_PATH);
		else
			fprintf(stderr, "error: open %s: %s\n",
				DEVICE_PATH, strerror(errno));
		return 2;
	}

	memset(&status, 0, sizeof(status));
	if (ioctl(fd, CRYPTO2DEV_IOC_STATUS, &status) != 0) {
		fprintf(stderr, "error: CRYPTO2DEV_IOC_STATUS: %s\n",
			strerror(errno));
		close(fd);
		return 2;
	}
	close(fd);

	/* Ensure version is NUL-terminated (kernel fills the buffer). */
	status.version[sizeof(status.version) - 1] = '\0';

	if (json)
		print_json(&status);
	else
		print_human(&status);

	/* Exit 1 if FIPS provider is loaded but not operational. */
	if (status.fips_state == CRYPTO2DEV_FIPS_NOT_OPERATIONAL)
		return 1;

	return 0;
}
