/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * crypto2dev_compat.h — kernel version compatibility shims (5.10 – 6.x)
 *
 * Include this from every .c file that needs version-dependent API.
 * Add shims here; never scatter #if LINUX_VERSION_CODE checks through
 * algorithm files.
 */

#ifndef _CRYPTO2DEV_COMPAT_H
#define _CRYPTO2DEV_COMPAT_H

#include <linux/version.h>
#include <linux/types.h>

/*
 * no_llseek was removed in 6.8. On older kernels it is declared in
 * <linux/fs.h>; provide a stub for newer kernels.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
#include <linux/fs.h>
static inline loff_t crypto2dev_no_llseek(struct file *f, loff_t o, int w)
{
	return -ESPIPE;
}
#define CRYPTO2DEV_NO_LLSEEK crypto2dev_no_llseek
#else
#include <linux/fs.h>
#define CRYPTO2DEV_NO_LLSEEK no_llseek
#endif

/*
 * copy_from_user / copy_to_user: no change needed across our target range.
 * Defined here as documentation of the checked-return contract.
 *
 * Both functions return the number of bytes NOT copied.
 * Zero means success. Any non-zero return must be treated as -EFAULT.
 */

#endif /* _CRYPTO2DEV_COMPAT_H */
