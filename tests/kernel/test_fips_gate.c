// SPDX-License-Identifier: GPL-2.0-only
/*
 * test_fips_gate.c — kernel module: FIPS gate and aggregate state checks
 *
 * Verifies that crypto2dev's FIPS enforcement mechanisms report a consistent,
 * valid state. Results are emitted to dmesg at load time and can be checked by
 * automated test scripts.
 *
 * Tests:
 *   1. crypto2dev_fips_aggregate() returns a recognized FIPS state code.
 *   2. crypto2dev_fips_provider_loaded() is consistent with aggregate state.
 *   3. If a FIPS provider is loaded: algo lookup returns ops with a fips_gate.
 *   4. If a FIPS provider is loaded: fips_gate() returns 0 (OPERATIONAL).
 *
 * Non-OPERATIONAL path (requires wolfcrypt.ko not loaded):
 *   The following cannot be injected from a kernel module without wolfCrypt's
 *   internal FIPS state API. A shell-level equivalent is:
 *     modprobe -r crypto2dev ; modprobe -r wolfcrypt
 *     insmod wolfcrypt.ko corrupt_fips_hash=1   # if parameter available
 *     insmod crypto2dev.ko
 *     [verify /dev/crypto2dev INIT returns -EACCES]
 *   See tests/ci/test-on-aws.sh for the integration harness.
 *
 * Load:
 *   insmod test_fips_gate.ko
 *   dmesg | grep "test_fips_gate"
 *
 * Expected dmesg (FIPS provider loaded):
 *   test_fips_gate: PASS fips_aggregate=OPERATIONAL
 *   test_fips_gate: PASS fips_provider_loaded=1 consistent with aggregate
 *   test_fips_gate: PASS fips_gate() returned 0 (OPERATIONAL) for "cbc(aes)"
 *   test_fips_gate: ALL TESTS PASSED
 *
 * Expected dmesg (no FIPS provider, stub mode):
 *   test_fips_gate: PASS fips_aggregate=NO_PROVIDER
 *   test_fips_gate: PASS fips_provider_loaded=0 consistent with aggregate
 *   test_fips_gate: NOTE fips_gate test skipped — no FIPS provider loaded
 *   test_fips_gate: ALL TESTS PASSED
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include "../../include/crypto2dev_provider.h"
#include "../../include/uapi/crypto2dev_ioctl.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("crypto2dev FIPS gate correctness test");
MODULE_AUTHOR("wolfSSL Inc.");

static int test_pass;
static int test_fail;

#define T_PASS(fmt, ...) do {                                        \
	pr_info("test_fips_gate: PASS " fmt "\n", ##__VA_ARGS__);   \
	test_pass++;                                                 \
} while (0)

#define T_FAIL(fmt, ...) do {                                        \
	pr_err("test_fips_gate: FAIL " fmt "\n", ##__VA_ARGS__);    \
	test_fail++;                                                 \
} while (0)

#define T_NOTE(fmt, ...) \
	pr_info("test_fips_gate: NOTE " fmt "\n", ##__VA_ARGS__)

static const char *fips_state_name(u32 state)
{
	switch (state) {
	case CRYPTO2DEV_FIPS_NO_PROVIDER:     return "NO_PROVIDER";
	case CRYPTO2DEV_FIPS_OPERATIONAL:     return "OPERATIONAL";
	case CRYPTO2DEV_FIPS_NOT_OPERATIONAL: return "NOT_OPERATIONAL";
	default:                              return "INVALID";
	}
}

static int __init test_fips_gate_init(void)
{
	u32 agg_state;
	bool fips_loaded;
	const struct crypto2dev_algo_ops *ops;
	struct module *owner = NULL;

	/* Test 1: crypto2dev_fips_aggregate() returns a valid state code. */
	agg_state = crypto2dev_fips_aggregate();
	if (agg_state != CRYPTO2DEV_FIPS_NO_PROVIDER &&
	    agg_state != CRYPTO2DEV_FIPS_OPERATIONAL &&
	    agg_state != CRYPTO2DEV_FIPS_NOT_OPERATIONAL) {
		T_FAIL("fips_aggregate returned unrecognized value %u", agg_state);
	} else {
		T_PASS("fips_aggregate=%s", fips_state_name(agg_state));
	}

	/* Test 2: fips_provider_loaded() is consistent with aggregate state. */
	fips_loaded = crypto2dev_fips_provider_loaded();
	if (fips_loaded && agg_state == CRYPTO2DEV_FIPS_NO_PROVIDER) {
		T_FAIL("fips_provider_loaded=true but aggregate=NO_PROVIDER");
	} else if (!fips_loaded && agg_state != CRYPTO2DEV_FIPS_NO_PROVIDER) {
		T_FAIL("fips_provider_loaded=false but aggregate=%s",
		       fips_state_name(agg_state));
	} else {
		T_PASS("fips_provider_loaded=%d consistent with aggregate",
		       (int)fips_loaded);
	}

	/* Tests 3+4 only meaningful when a FIPS provider is loaded. */
	if (!fips_loaded) {
		T_NOTE("fips_gate test skipped — no FIPS provider loaded");
		goto done;
	}

	/* Test 3: lookup a well-known FIPS algorithm and verify it has a gate. */
	ops = crypto2dev_lookup_algo("cbc(aes)", NULL, &owner, NULL);
	if (!ops) {
		T_FAIL("lookup_algo(\"cbc(aes)\") returned NULL — FIPS provider "
		       "not serving cbc(aes)?");
		goto done;
	}
	if (!ops->fips_gate) {
		T_FAIL("cbc(aes) ops has no fips_gate — FIPS gate not enforced");
		module_put(owner);
		goto done;
	}
	T_PASS("lookup_algo(\"cbc(aes)\") returned ops with fips_gate");

	/* Test 4: fips_gate() must return 0 (OPERATIONAL) when aggregate says so. */
	if (agg_state == CRYPTO2DEV_FIPS_OPERATIONAL) {
		int gate_ret = ops->fips_gate();

		if (gate_ret != 0) {
			T_FAIL("fips_gate() returned %d for \"cbc(aes)\" "
			       "(expected 0, aggregate=OPERATIONAL)", gate_ret);
		} else {
			T_PASS("fips_gate() returned 0 (OPERATIONAL) for "
			       "\"cbc(aes)\"");
		}
	} else {
		T_NOTE("fips_gate() call skipped — aggregate=%s",
		       fips_state_name(agg_state));
	}

	module_put(owner);

done:
	if (test_fail == 0)
		pr_info("test_fips_gate: ALL TESTS PASSED (%d/%d)\n",
			test_pass, test_pass + test_fail);
	else
		pr_err("test_fips_gate: TESTS FAILED (%d failed, %d passed)\n",
		       test_fail, test_pass);

	/* Return 0 even on test failure so dmesg can be inspected.
	 * CI scripts check for "FAIL" in dmesg rather than insmod exit code. */
	return 0;
}

static void __exit test_fips_gate_exit(void)
{
	/* Nothing to clean up — all work done in init. */
}

module_init(test_fips_gate_init);
module_exit(test_fips_gate_exit);
