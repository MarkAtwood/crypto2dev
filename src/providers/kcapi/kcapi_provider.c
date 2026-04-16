// SPDX-License-Identifier: GPL-2.0-only
/*
 * kcapi_provider.c — crypto2dev provider module wrapping the kernel crypto API
 *
 * Registers algorithm implementations backed by the Linux kernel's own crypto
 * subsystem (software fallbacks, hardware-accelerated transforms, etc.).
 *
 * No dependency on wolfcrypt.ko. Builds unconditionally alongside crypto2dev.ko.
 * Load order: crypto2dev.ko → crypto2dev_kcapi.ko
 *
 * FIPS: no explicit FIPS gate. If CONFIG_CRYPTO_FIPS is enabled, the kernel
 * crypto subsystem enforces FIPS constraints internally. ops->fips_gate = NULL.
 */

#define pr_fmt(fmt) "crypto2dev_kcapi: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/utsname.h>

#include "../../../include/crypto2dev_provider.h"
#include "kcapi_provider.h"

static const struct crypto2dev_algo_ops *kcapi_algo_list[] = {
	&kcapi_cbc_aes_ops,
	&kcapi_ctr_aes_ops,
	&kcapi_xts_aes_ops,
	&kcapi_sha256_ops,
	&kcapi_sha384_ops,
	&kcapi_sha512_ops,
	&kcapi_sha3_256_ops,
	&kcapi_sha3_384_ops,
	&kcapi_sha3_512_ops,
	&kcapi_hmac_sha256_ops,
	&kcapi_hmac_sha384_ops,
	&kcapi_hmac_sha512_ops,
	&kcapi_cmac_aes_ops,
	&kcapi_gcm_aes_ops,
	&kcapi_hkdf_sha256_ops,
	&kcapi_hkdf_sha384_ops,
	&kcapi_hkdf_sha512_ops,
	&kcapi_pbkdf2_sha256_ops,
	&kcapi_pbkdf2_sha384_ops,
	&kcapi_pbkdf2_sha512_ops,
	NULL,
};

static struct crypto2dev_provider kcapi_provider = {
	.name      = "kcapi",
	.version   = "Linux kernel crypto API " UTS_RELEASE,
	.algos     = kcapi_algo_list,
	.num_algos = ARRAY_SIZE(kcapi_algo_list) - 1,
	.owner     = THIS_MODULE,
};

static int __init kcapi_provider_init(void)
{
	int ret;

	ret = crypto2dev_register_provider(&kcapi_provider);
	if (ret) {
		pr_err("provider registration failed: %d\n", ret);
		return ret;
	}

	pr_info("registered %u algorithm(s) via kernel crypto API\n",
		kcapi_provider.num_algos);
	return 0;
}

static void __exit kcapi_provider_exit(void)
{
	crypto2dev_unregister_provider(&kcapi_provider);
	pr_info("unregistered\n");
}

module_init(kcapi_provider_init);
module_exit(kcapi_provider_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("wolfSSL Inc.");
MODULE_DESCRIPTION("crypto2dev kernel crypto API provider");
MODULE_VERSION("1.0");
MODULE_SOFTDEP("pre: crypto2dev");
