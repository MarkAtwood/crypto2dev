// SPDX-License-Identifier: GPL-2.0-only
/*
 * crypto2dev_cdev.c — misc chardev and sysfs registration for /dev/crypto2dev
 *
 * Registers and unregisters the character device via misc_register().
 * Exposes a sysfs attribute for algorithm enumeration.
 * All file operations delegate to crypto2dev_fd.c.
 */

#define pr_fmt(fmt) "crypto2dev: " fmt

#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/device.h>

#include "../crypto2dev_compat.h"
#include "../../include/uapi/crypto2dev_ioctl.h"
#include "../../include/crypto2dev_provider.h"
#include "crypto2dev_fd.h"

static const struct file_operations crypto2dev_fops = {
	.owner          = THIS_MODULE,
	.open           = crypto2dev_fd_open,
	.release        = crypto2dev_fd_release,
	.write          = crypto2dev_fd_write,
	.read           = crypto2dev_fd_read,
	.poll           = crypto2dev_fd_poll,
	.unlocked_ioctl = crypto2dev_fd_ioctl,
	.llseek         = CRYPTO2DEV_NO_LLSEEK,
};

static struct miscdevice crypto2dev_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "crypto2dev",
	.fops  = &crypto2dev_fops,
	.mode  = 0600,
};

/* ── sysfs: /sys/class/misc/crypto2dev/algorithms ───────────────────────── */

/*
 * algorithms — enumerate all registered algorithms.
 *
 * Each line is: algo:provider:has_fips_gate:has_key_ops
 *
 * Example:
 *   cbc(aes):wolfssl:1:0
 *   sha256:wolfssl:1:0
 *   hmac(sha256):wolfssl:1:0
 *
 * Output is truncated at PAGE_SIZE if an unusually large number of
 * algorithms are registered.
 */
static ssize_t algorithms_show(struct device *dev,
				struct device_attribute *attr,
				char *buf)
{
	struct crypto2dev_algo_info *info;
	u32 count, n, i;
	ssize_t len = 0;

	count = crypto2dev_algo_count();
	if (count == 0)
		return 0;

	info = kmalloc_array(count, sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	n = crypto2dev_enumerate_algos(info, count);
	/* Cap to allocated entries — concurrent registration between count()
	 * and enumerate() can return n > count, causing OOB access. */
	if (n > count)
		n = count;

	for (i = 0; i < n; i++)
		len += sysfs_emit_at(buf, len, "%s:%s:%u:%u\n",
				     info[i].algo,
				     info[i].provider,
				     info[i].has_fips_gate,
				     info[i].has_key_ops);

	kfree(info);
	return len;
}

static DEVICE_ATTR_RO(algorithms);

/* ── sysfs: /sys/class/misc/crypto2dev/providers ────────────────────────── */

/*
 * providers — one line per registered provider:
 *   name:is_fips:version_string
 *
 * Example:
 *   wolfssl:1:wolfCrypt FIPS v5.7.0 (CMVP #4718)
 *   kcapi:0:Linux kernel crypto API 6.8.0-51-generic
 *
 * Fields 1 and 2 are fixed-position colon-delimited tokens. Field 3 is the
 * remainder of the line (the version string, which may contain colons).
 */
static ssize_t providers_show(struct device *dev,
			      struct device_attribute *attr,
			      char *buf)
{
	struct crypto2dev_provider_info *info;
	u32 count, n, i;
	ssize_t len = 0;

	count = crypto2dev_enumerate_providers(NULL, 0);
	if (count == 0)
		return 0;

	info = kmalloc_array(count, sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	n = crypto2dev_enumerate_providers(info, count);
	if (n > count)
		n = count;

	for (i = 0; i < n; i++)
		len += sysfs_emit_at(buf, len, "%s:%u:%s\n",
				     info[i].name,
				     info[i].is_fips,
				     info[i].version);

	kfree(info);
	return len;
}

static DEVICE_ATTR_RO(providers);

/* ── sysfs: /sys/class/misc/crypto2dev/fips_state ───────────────────────── */

/*
 * fips_state — single integer indicating aggregate FIPS operational status.
 *
 *   0  CRYPTO2DEV_FIPS_NO_PROVIDER      no FIPS-gated provider loaded
 *   1  CRYPTO2DEV_FIPS_OPERATIONAL      FIPS provider loaded, all self-tests pass
 *   2  CRYPTO2DEV_FIPS_NOT_OPERATIONAL  FIPS provider loaded but degraded
 *
 * Intended for monitoring scripts and systemd conditions that need a simple
 * machine-readable health signal without parsing ioctl output.
 */
static ssize_t fips_state_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	return sysfs_emit(buf, "%u\n", crypto2dev_fips_aggregate());
}

static DEVICE_ATTR_RO(fips_state);

/* ── init / exit ─────────────────────────────────────────────────────────── */

int  crypto2dev_cdev_init(void);
void crypto2dev_cdev_exit(void);

int crypto2dev_cdev_init(void)
{
	int ret;

	ret = misc_register(&crypto2dev_miscdev);
	if (ret) {
		pr_err("misc_register failed: %d\n", ret);
		return ret;
	}

	ret = device_create_file(crypto2dev_miscdev.this_device,
				 &dev_attr_algorithms);
	if (ret) {
		pr_err("sysfs algorithms attribute failed: %d\n", ret);
		misc_deregister(&crypto2dev_miscdev);
		return ret;
	}

	ret = device_create_file(crypto2dev_miscdev.this_device,
				 &dev_attr_providers);
	if (ret) {
		pr_err("sysfs providers attribute failed: %d\n", ret);
		device_remove_file(crypto2dev_miscdev.this_device,
				   &dev_attr_algorithms);
		misc_deregister(&crypto2dev_miscdev);
		return ret;
	}

	ret = device_create_file(crypto2dev_miscdev.this_device,
				 &dev_attr_fips_state);
	if (ret) {
		pr_err("sysfs fips_state attribute failed: %d\n", ret);
		device_remove_file(crypto2dev_miscdev.this_device,
				   &dev_attr_providers);
		device_remove_file(crypto2dev_miscdev.this_device,
				   &dev_attr_algorithms);
		misc_deregister(&crypto2dev_miscdev);
		return ret;
	}

	pr_info("/dev/crypto2dev registered (minor %d)\n",
		crypto2dev_miscdev.minor);
	return 0;
}

void crypto2dev_cdev_exit(void)
{
	device_remove_file(crypto2dev_miscdev.this_device,
			   &dev_attr_fips_state);
	device_remove_file(crypto2dev_miscdev.this_device,
			   &dev_attr_providers);
	device_remove_file(crypto2dev_miscdev.this_device,
			   &dev_attr_algorithms);
	misc_deregister(&crypto2dev_miscdev);
	pr_info("/dev/crypto2dev unregistered\n");
}
