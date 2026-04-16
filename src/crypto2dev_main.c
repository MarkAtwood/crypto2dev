// SPDX-License-Identifier: GPL-2.0-only
/*
 * crypto2dev_main.c — module_init / module_exit for crypto2dev.ko
 *
 * crypto2dev.ko is the framework module. It provides:
 *   - /dev/crypto2dev character device
 *   - Provider registration API (crypto2dev_register_provider, etc.)
 *
 * crypto2dev.ko contains NO cryptographic implementation. All crypto is
 * delegated to provider modules (e.g. crypto2dev_wolfssl.ko) that register
 * algorithms via crypto2dev_register_provider() from their own module_init.
 *
 * Load order:
 *   wolfcrypt.ko  ->  crypto2dev.ko  ->  crypto2dev_wolfssl.ko
 *
 * Note: crypto2dev.ko itself has NO dependency on wolfcrypt.ko.
 * That dependency belongs to crypto2dev_wolfssl.ko.
 */

#define pr_fmt(fmt) "crypto2dev: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

/* Forward declarations from cdev layer */
int  crypto2dev_cdev_init(void);
void crypto2dev_cdev_exit(void);

static int __init crypto2dev_init(void)
{
	int ret;

	pr_info("loading (provider framework v1.0)\n");

	ret = crypto2dev_cdev_init();
	if (ret) {
		pr_err("chardev init failed: %d\n", ret);
		return ret;
	}

	pr_info("ready — load a provider module to enable algorithms\n");
	return 0;
}

static void __exit crypto2dev_exit(void)
{
	crypto2dev_cdev_exit();
	pr_info("unloaded\n");
}

module_init(crypto2dev_init);
module_exit(crypto2dev_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("wolfSSL Inc.");
MODULE_DESCRIPTION("crypto2dev: FIPS-gated userspace crypto via /dev/crypto2dev");
MODULE_VERSION("1.0");
MODULE_SOFTDEP("post: crypto2dev_wolfssl");
