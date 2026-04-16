/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * crypto2dev_fd.h — per-fd session state (kernel-internal)
 *
 * Not part of the UAPI. Include only from crypto2dev_fd.c and
 * crypto2dev_cdev.c.
 */

#ifndef _CRYPTO2DEV_FD_H
#define _CRYPTO2DEV_FD_H

#include <linux/fs.h>
#include <linux/poll.h>

int       crypto2dev_fd_open(struct inode *inode, struct file *file);
int       crypto2dev_fd_release(struct inode *inode, struct file *file);
ssize_t   crypto2dev_fd_write(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos);
ssize_t   crypto2dev_fd_read(struct file *file, char __user *buf,
			     size_t count, loff_t *ppos);
__poll_t  crypto2dev_fd_poll(struct file *file, poll_table *wait);
long      crypto2dev_fd_ioctl(struct file *file, unsigned int cmd,
			      unsigned long arg);

#endif /* _CRYPTO2DEV_FD_H */
