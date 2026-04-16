// SPDX-License-Identifier: GPL-2.0-only
/*
 * wolfssl_provider.c — crypto2dev provider module for wolfSSL/wolfCrypt
 *
 * Registers all wolfCrypt-backed algorithm implementations with the
 * crypto2dev framework. Depends on wolfcrypt.ko and crypto2dev.ko.
 *
 * Load order: wolfcrypt.ko → crypto2dev.ko → crypto2dev_wolfssl.ko
 */

#define pr_fmt(fmt) "crypto2dev_wolfssl: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/errno.h>

#include "../../../include/crypto2dev_provider.h"
#include "wolfssl_provider.h"

#include <wolfssl/wolfcrypt/fips.h>
#include <wolfssl/version.h>

int wolfssl_fips_gate(void)
{
#ifdef HAVE_FIPS
	int status = wolfCrypt_GetStatus_fips();

	if (status != 0) {
		/* Rate-limited: prevents log flooding when module is degraded
		 * but still emits a visible message for support diagnosis.
		 * Use '!= 0' to match wolfCrypt's own convention — wolfCrypt_GetStatus_fips()
		 * returns 0 for OPERATIONAL and a negative error code otherwise.
		 * FIPS_OPERATIONAL is the symbolic name for 0; using '!= 0' avoids any
		 * future hazard if the constant were redefined.
		 */
		pr_err_ratelimited("FIPS boundary not operational (wolfCrypt status %d) — all crypto rejected\n",
				   status);
		return -EACCES;
	}
	return 0;
#else
	return 0;	/* non-FIPS build: no FIPS gating */
#endif
}

static const struct crypto2dev_algo_ops *wolfssl_algo_list[] = {
	&wolfssl_aes_cbc_ops,
	&wolfssl_aes_gcm_ops,
	&wolfssl_sha256_ops,
	&wolfssl_sha384_ops,
	&wolfssl_sha512_ops,
	&wolfssl_sha3_256_ops,
	&wolfssl_sha3_384_ops,
	&wolfssl_sha3_512_ops,
	&wolfssl_hmac_sha256_ops,
	&wolfssl_hmac_sha384_ops,
	&wolfssl_hmac_sha512_ops,
	&wolfssl_cmac_aes_ops,
	&wolfssl_hkdf_sha256_ops,
	&wolfssl_hkdf_sha384_ops,
	&wolfssl_hkdf_sha512_ops,
	&wolfssl_pbkdf2_sha256_ops,
	&wolfssl_pbkdf2_sha384_ops,
	&wolfssl_pbkdf2_sha512_ops,
	&wolfssl_rsa_2048_ops,
	&wolfssl_rsa_4096_ops,
	&wolfssl_ecdh_p256_ops,
	&wolfssl_ecdh_p384_ops,
	&wolfssl_ecdsa_p256_ops,
	&wolfssl_ecdsa_p384_ops,
	NULL,
};

static struct crypto2dev_provider wolfssl_provider = {
	.name      = "wolfssl",
	/* is_fips=1 only when wolfCrypt was built with FIPS (HAVE_FIPS defined). */
#ifdef HAVE_FIPS
	.is_fips   = 1,
	.version   = "wolfCrypt FIPS " LIBWOLFSSL_VERSION_STRING,
#else
	.is_fips   = 0,
	.version   = "wolfCrypt " LIBWOLFSSL_VERSION_STRING,
#endif
	.algos     = wolfssl_algo_list,
	.num_algos = ARRAY_SIZE(wolfssl_algo_list) - 1,
	.owner     = THIS_MODULE,
};

static int __init wolfssl_provider_init(void)
{
	int ret;

	ret = crypto2dev_register_provider(&wolfssl_provider);
	if (ret) {
		pr_err("provider registration failed: %d\n", ret);
		return ret;
	}

	pr_info("registered %u algorithm(s)\n", wolfssl_provider.num_algos);
	return 0;
}

static void __exit wolfssl_provider_exit(void)
{
	crypto2dev_unregister_provider(&wolfssl_provider);
	pr_info("unregistered\n");
}

module_init(wolfssl_provider_init);
module_exit(wolfssl_provider_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("wolfSSL Inc.");
MODULE_DESCRIPTION("crypto2dev wolfSSL provider");
MODULE_VERSION("1.0");
MODULE_SOFTDEP("pre: wolfcrypt crypto2dev");
/* Kernel 6.13 changed MODULE_IMPORT_NS to require a string literal. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("WOLFSSL");
#else
MODULE_IMPORT_NS(WOLFSSL);
#endif
