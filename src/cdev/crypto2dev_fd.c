// SPDX-License-Identifier: GPL-2.0-only
/*
 * crypto2dev_fd.c — per-fd session state and chardev file operations
 *
 * Each open() on /dev/crypto2dev allocates a crypto2dev_fd_state. An fd starts
 * UNSET and is promoted to either OPERATION or KEY:
 *
 *   OPERATION fd (via CRYPTO2DEV_IOC_INIT):
 *     INIT → [SET_IV] → [SET_AAD / SET_TAG] → write()* → FINALIZE → read()* → RESET
 *     write() calls ops->update() and appends any output to the outbuf.
 *     CRYPTO2DEV_IOC_FINALIZE calls ops->finalize() and sets finalized=true.
 *     read() drains outbuf; returns 0 (EOF) after FINALIZE when outbuf is empty.
 *     write() after FINALIZE returns -EINVAL.
 *
 *   KEY fd (via CRYPTO2DEV_IOC_KEY_IMPORT or KEY_GENERATE):
 *     Holds a single key object. read() returns the public key bytes. The key
 *     fd may be passed to CRYPTO2DEV_IOC_INIT.key_fd on an OPERATION fd to
 *     supply the key from the KEY fd.
 *
 * Thread safety: all state is protected by state->lock. Multiple threads
 * sharing a single fd are serialized by the mutex.
 *
 * Output buffer: the framework maintains a per-session output buffer
 * (outbuf). update() appends to it; finalize() appends the final output.
 * read() drains outbuf.
 */

#define pr_fmt(fmt) "crypto2dev: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/random.h>

#include "../../include/uapi/crypto2dev_ioctl.h"
#include "../../include/crypto2dev_provider.h"
#include "crypto2dev_fd.h"

/*
 * Maximum size of the per-session output buffer (1 MiB hard ceiling).
 * The buffer starts at CRYPTO2DEV_OUTBUF_INIT bytes and grows with krealloc
 * as update()/finalize() produce output. Asymmetric sign/verify/agree use
 * one-shot ioctls and do not use outbuf.
 */
#define CRYPTO2DEV_OUTBUF_MAX   CRYPTO2DEV_MAX_PAYLOAD
#define CRYPTO2DEV_OUTBUF_INIT  4096u

/* outbuf is allocated on first write()/finalize(), not at open() or init().
 * Rationale: pre-allocating at open() would reserve CRYPTO2DEV_OUTBUF_INIT
 * per fd regardless of whether crypto is ever performed — 1000 concurrent
 * sessions would waste gigabytes of memory. Sessions that only hash allocate
 * at most CRYPTO2DEV_OUTBUF_INIT bytes total. Sessions opened but never
 * initialized allocate nothing. Do not pre-allocate at open(). */

/*
 * crypto2dev_sym_key — raw symmetric key bytes derived via DO_KDF.
 * Stored as key_ctx in a KEY fd with key_type == CRYPTO2DEV_KEY_SYMMETRIC.
 */
struct crypto2dev_sym_key {
	u8  bytes[CRYPTO2DEV_KDF_OKM_MAXLEN];
	u32 len;
};


/*
 * crypto2dev_fd_state — per-open-fd state.
 *
 * fd_type determines which fields are active:
 *   UNSET:     only lock and fd_type are valid.
 *   OPERATION: the OPERATION fd fields and statistics are valid.
 *   KEY:       the KEY fd fields are valid.
 *
 * All fields are protected by lock.
 */
struct crypto2dev_fd_state {
	struct mutex       lock;
	wait_queue_head_t  poll_wq;   /* woken on outbuf change and RESET */
	u32 fd_type;   /* CRYPTO2DEV_FDTYPE_* */

	/* ── OPERATION fd ──────────────────────────────────────────────────── */

	char algo         [CRYPTO2DEV_ALGO_MAXLEN];
	char provider_name[CRYPTO2DEV_PROVIDER_MAXLEN];
	u32  op;
	bool finalized;   /* true after ops->finalize() has been called */
	bool error;       /* true after update()/finalize() error — session dead until RESET */
	bool iv_set;      /* true after SET_IV / GEN_IV — cleared by RESET */
	bool require_fips; /* true after REQUIRE_FIPS ioctl — INIT rejects non-FIPS providers */

	const struct crypto2dev_algo_ops *ops;
	struct module                    *owner_module;
	void                             *ctx;

	/* Output buffer (from ops->update() and ops->finalize()) */
	u8    *outbuf;
	size_t outbuf_len;      /* bytes accumulated so far */
	size_t outbuf_cap;      /* allocated capacity */
	size_t outbuf_drained;  /* bytes already returned to userspace */

	/* Statistics */
	u64 bytes_written;
	u64 bytes_read;

	/* ── UNSET fd — pending write data (consumed by KEY_IMPORT or DO_KDF) ── */

	u8    *inbuf;
	size_t inbuf_len;
	size_t inbuf_cap;

	/* ── KEY fd ────────────────────────────────────────────────────────── */

	char key_algo         [CRYPTO2DEV_ALGO_MAXLEN];
	char key_provider_name[CRYPTO2DEV_PROVIDER_MAXLEN];
	u32  key_type;
	u32  key_exportable;
	void *key_ctx;
	const struct crypto2dev_algo_ops *key_ops;
	struct module                    *key_owner_module;
};

/* ── Internal helpers ─────────────────────────────────────────────────────── */

/*
 * outbuf_grow — ensure at least 'extra' bytes of free space in outbuf.
 *
 * Compacts already-drained bytes first (O(remaining) memmove, not O(cap)).
 * If still insufficient, krealloc doubles the buffer up to CRYPTO2DEV_OUTBUF_MAX.
 * Called with state->lock held.
 */
static int outbuf_grow(struct crypto2dev_fd_state *state, size_t extra)
{
	size_t remaining, needed, newcap;
	u8 *newbuf;

	/* Compact: slide unread data to the front, reclaiming drained space. */
	if (state->outbuf_drained > 0) {
		remaining = state->outbuf_len - state->outbuf_drained;
		if (remaining > 0)
			memmove(state->outbuf, state->outbuf + state->outbuf_drained,
				remaining);
		state->outbuf_len     = remaining;
		state->outbuf_drained = 0;
	}

	/* Check if current capacity is already sufficient. */
	if (state->outbuf && state->outbuf_cap - state->outbuf_len >= extra)
		return 0;

	needed = state->outbuf_len + extra;
	if (needed > CRYPTO2DEV_OUTBUF_MAX)
		return -EMSGSIZE;

	/* Double from initial size until we have enough, capped at the maximum. */
	newcap = state->outbuf_cap ? state->outbuf_cap : CRYPTO2DEV_OUTBUF_INIT;
	while (newcap < needed)
		newcap = min(newcap * 2, (size_t)CRYPTO2DEV_OUTBUF_MAX);

	newbuf = krealloc(state->outbuf, newcap, GFP_KERNEL);
	if (!newbuf)
		return -ENOMEM;

	state->outbuf     = newbuf;
	state->outbuf_cap = newcap;
	return 0;
}

/*
 * inbuf_clear — zeroize and free the pending write buffer.
 * Must be called with state->lock held.
 */
static void inbuf_clear(struct crypto2dev_fd_state *state)
{
	if (state->inbuf) {
		/* memzero_explicit, not memset: the C compiler is permitted to elide a
		 * plain memset() when it can prove the memory is never read again before
		 * reuse or free. memzero_explicit() is a compiler barrier that prevents
		 * this. FIPS 140-3 requires CSPs to be zeroized before memory is released;
		 * an elided memset() is a compliance failure. Do not change to memset(). */
		memzero_explicit(state->inbuf, state->inbuf_cap);
		kfree(state->inbuf);
		state->inbuf = NULL;
	}
	state->inbuf_len = 0;
	state->inbuf_cap = 0;
}

/*
 * inbuf_append — append data to the pending write buffer.
 * Must be called with state->lock held.
 * Returns 0 on success, negative errno on failure.
 */
static int inbuf_append(struct crypto2dev_fd_state *state,
			const u8 *data, size_t len)
{
	size_t new_len = state->inbuf_len + len;

	if (new_len > CRYPTO2DEV_KEY_IMPORT_MAXLEN)
		return -EMSGSIZE;

	if (new_len > state->inbuf_cap) {
		size_t new_cap = state->inbuf_cap ? state->inbuf_cap * 2 : 256;
		u8 *newbuf;

		if (new_cap < new_len)
			new_cap = new_len;
		if (new_cap > CRYPTO2DEV_KEY_IMPORT_MAXLEN)
			new_cap = CRYPTO2DEV_KEY_IMPORT_MAXLEN;

		newbuf = kmalloc(new_cap, GFP_KERNEL);
		if (!newbuf)
			return -ENOMEM;
		if (state->inbuf) {
			memcpy(newbuf, state->inbuf, state->inbuf_len);
			memzero_explicit(state->inbuf, state->inbuf_cap);  /* FIPS 140-3 */
			kfree(state->inbuf);
		}
		state->inbuf     = newbuf;
		state->inbuf_cap = new_cap;
	}

	memcpy(state->inbuf + state->inbuf_len, data, len);
	state->inbuf_len += len;
	return 0;
}

/* ── poll ─────────────────────────────────────────────────────────────────── */

/*
 * crypto2dev_fd_poll — report I/O readiness for select(2)/poll(2)/epoll(2).
 *
 * OPERATION fd:
 *   EPOLLOUT | EPOLLWRNORM: set when the session is initialized and not yet
 *     finalized — i.e., write(2) will be accepted.
 *   EPOLLIN | EPOLLRDNORM: set when the output buffer contains unread bytes
 *     (produced by update() calls or by the FINALIZE ioctl).
 *
 * KEY fd:
 *   EPOLLIN | EPOLLRDNORM: set once the key is ready (always true after a
 *     successful KEY_IMPORT or KEY_GENERATE, since those are synchronous).
 *
 * UNSET fd: no bits set (neither readable nor writable via file I/O).
 *
 * Note: write(2) and read(2) are synchronous; they never block waiting for
 * an async crypto operation.  O_NONBLOCK has no effect — a slow provider
 * will block the caller.  Edge-triggered epoll (EPOLLET) is supported: the
 * wait queue is woken whenever the output buffer gains new bytes (in write)
 * and whenever RESET transitions the fd back to writable.
 */
__poll_t crypto2dev_fd_poll(struct file *file, poll_table *wait)
{
	struct crypto2dev_fd_state *state = file->private_data;
	__poll_t mask = 0;

	poll_wait(file, &state->poll_wq, wait);

	mutex_lock(&state->lock);

	switch (state->fd_type) {
	case CRYPTO2DEV_FDTYPE_OPERATION:
		if (!state->finalized)
			mask |= EPOLLOUT | EPOLLWRNORM;
		if (state->outbuf && state->outbuf_len > state->outbuf_drained)
			mask |= EPOLLIN | EPOLLRDNORM;
		break;
	case CRYPTO2DEV_FDTYPE_KEY:
		if (state->key_ctx)
			mask |= EPOLLIN | EPOLLRDNORM;
		break;
	default:
		break;
	}

	mutex_unlock(&state->lock);
	return mask;
}

/* ── open / release ───────────────────────────────────────────────────────── */

int crypto2dev_fd_open(struct inode *inode, struct file *file)
{
	struct crypto2dev_fd_state *state;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	mutex_init(&state->lock);
	init_waitqueue_head(&state->poll_wq);
	state->fd_type = CRYPTO2DEV_FDTYPE_UNSET;
	file->private_data = state;

	pr_debug("fd opened\n");
	return 0;
}

int crypto2dev_fd_release(struct inode *inode, struct file *file)
{
	struct crypto2dev_fd_state *state = file->private_data;

	if (!state)
		return 0;

	mutex_lock(&state->lock);

	switch (state->fd_type) {
	case CRYPTO2DEV_FDTYPE_OPERATION:
		/* inbuf may have been accumulated before INIT; zeroize it. */
		inbuf_clear(state);
		if (state->ops && state->ctx)
			state->ops->sess_free(state->ctx);
		if (state->owner_module)
			module_put(state->owner_module);
		if (state->outbuf) {
			memzero_explicit(state->outbuf, state->outbuf_cap);
			kfree(state->outbuf);
		}
		break;

	case CRYPTO2DEV_FDTYPE_KEY:
		/* inbuf may have been accumulated before KEY_GENERATE; zeroize it. */
		inbuf_clear(state);
		if (state->key_ops && state->key_ctx)
			state->key_ops->key_free(state->key_ctx);
		if (state->key_owner_module)
			module_put(state->key_owner_module);
		if (state->outbuf) {
			memzero_explicit(state->outbuf, state->outbuf_cap);
			kfree(state->outbuf);
		}
		break;

	default:
		inbuf_clear(state);
		break;
	}

	mutex_unlock(&state->lock);

	memzero_explicit(state, sizeof(*state));
	kfree(state);

	pr_debug("fd closed\n");
	return 0;
}

/* ── write ────────────────────────────────────────────────────────────────── */

ssize_t crypto2dev_fd_write(struct file *file, const char __user *ubuf,
			    size_t count, loff_t *ppos)
{
	struct crypto2dev_fd_state *state = file->private_data;
	u8 *kbuf = NULL;
	size_t outlen = 0;
	int ret = 0;

	if (count == 0)
		return 0;

	if (count > CRYPTO2DEV_MAX_PAYLOAD)
		return -EMSGSIZE;

	/* Copy user data to kernel before acquiring lock. */
	kbuf = kmalloc(count, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	if (copy_from_user(kbuf, ubuf, count)) {
		kfree(kbuf);
		return -EFAULT;
	}

	mutex_lock(&state->lock);

	/* FIPS 140-3: gate before any session-state inspection.
	 * state->ops is non-NULL only for OPERATION fds (set at INIT); it is
	 * NULL for UNSET and KEY fds, which accumulate write() data into inbuf
	 * and never call wolfCrypt directly. Gate is therefore skipped for
	 * non-OPERATION fds, and the fd_type checks below handle them. */
	if (state->ops && state->ops->fips_gate) {
		ret = state->ops->fips_gate();
		if (ret) {
			pr_err_ratelimited("fips_gate('%s'/%s): FIPS not operational (%d)\n",
					   state->algo, state->provider_name, ret);
			goto out;
		}
	}

	if (state->fd_type == CRYPTO2DEV_FDTYPE_UNSET) {
		/* Accumulate into inbuf for KEY_IMPORT or DO_KDF. */
		ret = inbuf_append(state, kbuf, count);
		if (ret == 0)
			ret = count;
		goto out;
	}

	if (state->fd_type != CRYPTO2DEV_FDTYPE_OPERATION) {
		pr_info_ratelimited("write: called on non-OPERATION fd (fd_type=%u) — did you call INIT first?\n",
				    state->fd_type);
		ret = -ENODEV;
		goto out;
	}

	if (state->finalized) {
		pr_info_ratelimited("write('%s'/%s): write after finalize\n",
				    state->algo, state->provider_name);
		ret = -EINVAL;
		goto out;
	}

	if (state->error) {
		pr_info_ratelimited("write('%s'/%s): write to fd in error state\n",
				    state->algo, state->provider_name);
		ret = -EIO;
		goto out;
	}

	/* Enforce IV-before-write for algorithms that require one. */
	if (state->ops->set_iv && !state->iv_set) {
		pr_info_ratelimited("write('%s'/%s): IV not set; call SET_IV or GEN_IV before write\n",
				    state->algo, state->provider_name);
		ret = -EINVAL;
		goto out;
	}

	/*
	 * Ensure outbuf has room for up to count bytes of update() output,
	 * plus CRYPTO2DEV_HASH_MAXLEN bytes of overhead for block-cipher tail
	 * accumulation (providers may output up to one extra block beyond the
	 * input size when the previous tail fills a complete block).
	 */
	ret = outbuf_grow(state, count + CRYPTO2DEV_HASH_MAXLEN);
	if (ret)
		goto out;

	if (!state->ops->update) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	ret = state->ops->update(state->ctx, kbuf, count,
				 state->outbuf + state->outbuf_len,
				 state->outbuf_cap - state->outbuf_len,
				 &outlen);
	if (ret) {
		pr_err_ratelimited("write('%s'/%s): update failed: %d\n",
				   state->algo, state->provider_name, ret);
		state->error = true;
		goto out;
	}

	if (WARN_ON(outlen > state->outbuf_cap - state->outbuf_len)) {
		ret = -EIO;
		state->error = true;
		goto out;
	}

	state->outbuf_len    += outlen;
	state->bytes_written += count;
	ret = count;

out:
	mutex_unlock(&state->lock);
	if (ret > 0 && outlen > 0)
		wake_up_interruptible(&state->poll_wq);
	memzero_explicit(kbuf, count);
	kfree(kbuf);
	return ret;
}

/* ── read ─────────────────────────────────────────────────────────────────── */

ssize_t crypto2dev_fd_read(struct file *file, char __user *ubuf,
			   size_t count, loff_t *ppos)
{
	struct crypto2dev_fd_state *state = file->private_data;
	size_t to_copy;
	int ret = 0;

	if (count == 0)
		return 0;

	mutex_lock(&state->lock);

	switch (state->fd_type) {
	case CRYPTO2DEV_FDTYPE_OPERATION:
		break;  /* handled below */

	case CRYPTO2DEV_FDTYPE_KEY: {
		u8 *kbuf;
		u32 outlen = 0;

		if (!state->key_ctx) {
			ret = -ENODEV;
			goto out;
		}

		/* Drain pending private key bytes placed by KEY_EXPORT_PRIVATE. */
		if (state->outbuf && state->outbuf_drained < state->outbuf_len) {
			to_copy = min(count,
				      state->outbuf_len - state->outbuf_drained);
			if (copy_to_user(ubuf,
					 state->outbuf + state->outbuf_drained,
					 to_copy)) {
				ret = -EFAULT;
			} else {
				state->outbuf_drained += to_copy;
				state->bytes_read     += to_copy;
				ret = to_copy;
			}
			goto out;
		}

		/* Otherwise return the public key bytes. */
		if (!state->key_ops->key_export_public) {
			ret = -EOPNOTSUPP;
			goto out;
		}

		/* FIPS 140-3: gate before any key material export. */
		if (state->key_ops->fips_gate) {
			ret = state->key_ops->fips_gate();
			if (ret) {
				pr_err_ratelimited("fips_gate('%s'/%s): FIPS not operational (%d)\n",
						   state->key_algo,
						   state->key_provider_name, ret);
				goto out;
			}
		}

		kbuf = kmalloc(CRYPTO2DEV_PUBKEY_MAXLEN, GFP_KERNEL);
		if (!kbuf) {
			ret = -ENOMEM;
			goto out;
		}

		ret = state->key_ops->key_export_public(state->key_ctx,
							 kbuf,
							 CRYPTO2DEV_PUBKEY_MAXLEN,
							 &outlen);
		if (ret) {
			pr_err_ratelimited("key_export_public('%s'/%s): callback failed: %d\n",
					   state->key_algo, state->key_provider_name, ret);
			goto out_free_keybuf;
		}

		if (outlen > CRYPTO2DEV_PUBKEY_MAXLEN) {
			pr_err("key_export_public: provider returned outlen %u > max %u\n",
			       outlen, CRYPTO2DEV_PUBKEY_MAXLEN);
			ret = -EOVERFLOW;
			goto out_free_keybuf;
		}

		if (count < outlen) {
			ret = -EMSGSIZE;
			goto out_free_keybuf;
		}

		if (copy_to_user(ubuf, kbuf, outlen)) {
			ret = -EFAULT;
			goto out_free_keybuf;
		}

		state->bytes_read += outlen;
		ret = outlen;

out_free_keybuf:
		memzero_explicit(kbuf, CRYPTO2DEV_PUBKEY_MAXLEN);
		kfree(kbuf);
		goto out;
	}

	default:
		ret = -ENODEV;
		goto out;
	}

	/* OPERATION fd path */
	/* FIPS 140-3: gate before any session-state inspection. */
	if (state->ops->fips_gate) {
		ret = state->ops->fips_gate();
		if (ret) {
			pr_err_ratelimited("fips_gate('%s'/%s): FIPS not operational (%d)\n",
					   state->algo, state->provider_name, ret);
			goto out;
		}
	}

	if (state->error) {
		ret = -EIO;
		goto out;
	}

	/*
	 * Drain the output buffer. Finalization must be requested explicitly
	 * via CRYPTO2DEV_IOC_FINALIZE — read() never calls finalize() itself.
	 *
	 * Returns 0 (EOF) when finalized=true and outbuf is fully drained.
	 * Returns 0 (empty, not EOF) when outbuf is empty but not yet finalized;
	 * the caller should write more data then call FINALIZE.
	 */
	if (!state->outbuf || state->outbuf_drained >= state->outbuf_len) {
		ret = 0;
		goto out;
	}

	to_copy = min(count, state->outbuf_len - state->outbuf_drained);

	if (copy_to_user(ubuf, state->outbuf + state->outbuf_drained, to_copy)) {
		ret = -EFAULT;
		goto out;
	}

	state->outbuf_drained += to_copy;
	state->bytes_read     += to_copy;
	ret = to_copy;

out:
	mutex_unlock(&state->lock);
	return ret;
}

/* ── ioctl handlers ───────────────────────────────────────────────────────── */

static long ioctl_require_fips(struct crypto2dev_fd_state *state)
{
	int ret;

	mutex_lock(&state->lock);
	if (state->fd_type != CRYPTO2DEV_FDTYPE_UNSET) {
		ret = -EBUSY;
	} else {
		state->require_fips = true;
		ret = 0;
	}
	mutex_unlock(&state->lock);
	return ret;
}

static long ioctl_init(struct crypto2dev_fd_state *state, struct file *file,
		       unsigned long arg)
{
	struct crypto2dev_init_op op;
	const struct crypto2dev_algo_ops *ops;
	struct module *owner;
	const char *actual_provider = NULL;
	void *ctx = NULL;
	int ret;

	if (copy_from_user(&op, (void __user *)arg, sizeof(op))) {
		ret = -EFAULT;
		goto out_zeroize;
	}

	op.algo    [CRYPTO2DEV_ALGO_MAXLEN - 1]     = '\0';
	op.provider[CRYPTO2DEV_PROVIDER_MAXLEN - 1] = '\0';

	if (op.key_fd < -1) {
		ret = -EINVAL;
		goto out_zeroize;
	}

	if (op.algo[0] == '\0') {
		ret = -EINVAL;
		goto out_zeroize;
	}

	if (op.op != CRYPTO2DEV_OP_ENCRYPT &&
	    op.op != CRYPTO2DEV_OP_DECRYPT &&
	    op.op != CRYPTO2DEV_OP_HASH) {
		ret = -EINVAL;
		goto out_zeroize;
	}

	if (op.keylen > CRYPTO2DEV_KEY_MAXLEN) {
		ret = -EINVAL;
		goto out_zeroize;
	}

	/* key_fd >= 0: extract key from a SYMMETRIC KEY fd (from a prior DO_KDF).
	 * Asymmetric KEY fds are not valid here. key_fd == -1 uses inline key. */
	if (op.key_fd >= 0) {
		struct file *kf = fget(op.key_fd);

		if (!kf) {
			ret = -EBADF;
			goto out_zeroize;
		}
		if (kf->f_op != file->f_op) {
			fput(kf);
			ret = -EBADF;
			goto out_zeroize;
		}
		{
			struct crypto2dev_fd_state *ks = kf->private_data;
			struct crypto2dev_sym_key  *sk;

			mutex_lock(&ks->lock);
			if (ks->fd_type != CRYPTO2DEV_FDTYPE_KEY ||
			    ks->key_type != CRYPTO2DEV_KEY_SYMMETRIC ||
			    !ks->key_ctx) {
				mutex_unlock(&ks->lock);
				fput(kf);
				ret = -EBADF;
				goto out_zeroize;
			}
			sk = ks->key_ctx;
			if (sk->len == 0 || sk->len > CRYPTO2DEV_KEY_MAXLEN) {
				mutex_unlock(&ks->lock);
				fput(kf);
				ret = -EINVAL;
				goto out_zeroize;
			}
			/* SP 800-57: key material must be used only for the
			 * purpose it was derived for. Enforce that the target
			 * algorithm matches the out_algo label set at DO_KDF
			 * time. Cross-algo use of derived key material violates
			 * key separation even when key lengths happen to match. */
			if (strncmp(ks->key_algo, op.algo,
				    CRYPTO2DEV_ALGO_MAXLEN) != 0) {
				mutex_unlock(&ks->lock);
				fput(kf);
				ret = -EINVAL;
				goto out_zeroize;
			}
			memcpy(op.key, sk->bytes, sk->len);
			op.keylen = sk->len;
			mutex_unlock(&ks->lock);
		}
		fput(kf);
	}

	/* Reject nonzero pad bytes — they are reserved for future ABI
	 * extension; nonzero values would have ambiguous meaning if old
	 * callers set them to garbage before the extension is defined.
	 */
	if (memchr_inv(op._pad, 0, sizeof(op._pad))) {
		ret = -EINVAL;
		goto out_zeroize;
	}

	mutex_lock(&state->lock);

	if (state->fd_type != CRYPTO2DEV_FDTYPE_UNSET) {
		pr_info_ratelimited("init('%.*s'): double-INIT rejected — fd already initialized (fd_type=%u)\n",
				    (int)CRYPTO2DEV_ALGO_MAXLEN, op.algo,
				    state->fd_type);
		ret = -EBUSY;
		goto out_unlock;
	}

	ops = crypto2dev_lookup_algo(op.algo,
				     op.provider[0] ? op.provider : NULL,
				     &owner, &actual_provider);
	if (!ops) {
		if (crypto2dev_fips_provider_loaded())
			pr_info_ratelimited("init('%.*s'): not found — FIPS mode active; ensure a FIPS provider registers this algo\n",
					    (int)CRYPTO2DEV_ALGO_MAXLEN, op.algo);
		else
			pr_info_ratelimited("init('%.*s'): no provider registered for this algo\n",
					    (int)CRYPTO2DEV_ALGO_MAXLEN, op.algo);
		ret = -ENOENT;
		goto out_unlock;
	}

	/* REQUIRE_FIPS: verify the *selected* provider is FIPS-validated.
	 * Check ops->fips_gate rather than re-reading fips_provider_loaded() —
	 * the latter is a separate atomic read that can race with a concurrent
	 * provider load between lookup and this check (TOCTOU). FIPS providers
	 * always set fips_gate; non-FIPS providers (e.g. kcapi) leave it NULL. */
	if (state->require_fips && !ops->fips_gate) {
		pr_info_ratelimited("init('%.*s'): rejected — REQUIRE_FIPS set but provider '%s' is not FIPS-validated\n",
				    (int)CRYPTO2DEV_ALGO_MAXLEN, op.algo,
				    actual_provider);
		module_put(owner);
		ret = -ENOENT;
		goto out_unlock;
	}

	if (ops->fips_gate) {
		int fips_ret = ops->fips_gate();

		if (fips_ret) {
			pr_err("init('%.*s'): FIPS gate rejected — provider '%s' not operational (%d)\n",
			       (int)CRYPTO2DEV_ALGO_MAXLEN, op.algo,
			       actual_provider ? actual_provider : op.provider, fips_ret);
			ret = -EACCES;
			module_put(owner);
			goto out_unlock;
		}
	}

	if (!ops->sess_init) {
		pr_info_ratelimited("init('%.*s'): provider '%.*s' registered but has no sess_init\n",
				    (int)CRYPTO2DEV_ALGO_MAXLEN, op.algo,
				    (int)CRYPTO2DEV_PROVIDER_MAXLEN,
				    op.provider[0] ? op.provider : "<any>");
		module_put(owner);
		ret = -EOPNOTSUPP;
		goto out_unlock;
	}

	/* FIPS 140-3: zeroize any inbuf bytes accumulated before INIT — key material
	 * written for a KEY_IMPORT that never happened must not persist into the
	 * OPERATION session. */
	inbuf_clear(state);

	ret = ops->sess_init(&ctx, op.op,
			     op.keylen ? op.key : NULL, op.keylen);
	if (ret) {
		pr_err_ratelimited("init('%.*s'/%s): sess_init failed: %d\n",
				   (int)CRYPTO2DEV_ALGO_MAXLEN, op.algo,
				   actual_provider ? actual_provider : op.provider, ret);
		module_put(owner);
		goto out_unlock;
	}

	state->fd_type = CRYPTO2DEV_FDTYPE_OPERATION;
	state->ops = ops;
	state->owner_module = owner;
	state->ctx = ctx;
	state->op = op.op;
	strscpy(state->algo,          op.algo,          CRYPTO2DEV_ALGO_MAXLEN);
	strscpy(state->provider_name,
		actual_provider ? actual_provider : op.provider,
		CRYPTO2DEV_PROVIDER_MAXLEN);
	pr_info_ratelimited("init '%.*s' dispatched to provider '%.*s'\n",
			    (int)CRYPTO2DEV_ALGO_MAXLEN,     state->algo,
			    (int)CRYPTO2DEV_PROVIDER_MAXLEN, state->provider_name);
	ret = 0;

out_unlock:
	mutex_unlock(&state->lock);

out_zeroize:
	memzero_explicit(&op, sizeof(op));
	return ret;
}

static long ioctl_set_iv(struct crypto2dev_fd_state *state, unsigned long arg)
{
	const struct crypto2dev_algo_ops *early_ops;
	struct crypto2dev_iv_op op;
	int ret;

	/* FIPS 140-3: gate must fire before any work at this crypto entry
	 * point. state->ops is written exactly once in ioctl_init (under
	 * state->lock) and is never modified afterwards — READ_ONCE prevents
	 * the compiler from reloading it. The gate is re-checked under the
	 * mutex below in case FIPS status changes between entry and lock
	 * acquisition (runtime POST failure is a real scenario). */
	early_ops = READ_ONCE(state->ops);
	if (early_ops && early_ops->fips_gate) {
		ret = early_ops->fips_gate();
		if (ret) {
			pr_err_ratelimited("set_iv('%s'/%s): FIPS not operational (%d)\n",
					   state->algo, state->provider_name, ret);
			return ret;
		}
	}

	if (copy_from_user(&op, (void __user *)arg, sizeof(op)))
		return -EFAULT;

	if (op.ivlen == 0 || op.ivlen > CRYPTO2DEV_IV_MAXLEN)
		return -EINVAL;

	mutex_lock(&state->lock);

	/* FIPS 140-3: gate before any session-state inspection. */
	if (state->ops && state->ops->fips_gate) {
		ret = state->ops->fips_gate();
		if (ret) {
			pr_err_ratelimited("fips_gate('%s'/%s): FIPS not operational (%d)\n",
					   state->algo, state->provider_name, ret);
			goto out;
		}
	}

	if (state->fd_type != CRYPTO2DEV_FDTYPE_OPERATION) {
		pr_info_ratelimited("set_iv: called on non-OPERATION fd (fd_type=%u)\n",
				    state->fd_type);
		ret = -ENODEV;
		goto out;
	}

	if (state->finalized || state->error) {
		ret = -EINVAL;
		goto out;
	}

	if (!state->ops->set_iv) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	ret = state->ops->set_iv(state->ctx, op.iv, op.ivlen);
	if (ret == 0) {
		state->iv_set = true;
	} else {
		pr_err_ratelimited("set_iv('%s'): provider '%s' returned %d\n",
				   state->algo, state->provider_name, ret);
	}

out:
	mutex_unlock(&state->lock);
	return ret;
}

static long ioctl_gen_iv(struct crypto2dev_fd_state *state, unsigned long arg)
{
	const struct crypto2dev_algo_ops *early_ops;
	struct crypto2dev_iv_op op;
	u8 iv[CRYPTO2DEV_IV_MAXLEN];
	int ret;

	/* FIPS 140-3: gate before any work. See ioctl_set_iv for rationale. */
	early_ops = READ_ONCE(state->ops);
	if (early_ops && early_ops->fips_gate) {
		ret = early_ops->fips_gate();
		if (ret) {
			pr_err_ratelimited("gen_iv('%s'/%s): FIPS not operational (%d)\n",
					   state->algo, state->provider_name, ret);
			return ret;
		}
	}

	if (copy_from_user(&op, (void __user *)arg, sizeof(op)))
		return -EFAULT;

	if (op.ivlen == 0 || op.ivlen > CRYPTO2DEV_IV_MAXLEN)
		return -EINVAL;

	mutex_lock(&state->lock);

	/* FIPS 140-3: gate before any session-state inspection. */
	if (state->ops && state->ops->fips_gate) {
		ret = state->ops->fips_gate();
		if (ret) {
			pr_err_ratelimited("fips_gate('%s'/%s): FIPS not operational (%d)\n",
					   state->algo, state->provider_name, ret);
			goto out;
		}
	}

	if (state->fd_type != CRYPTO2DEV_FDTYPE_OPERATION) {
		pr_info_ratelimited("gen_iv: called on non-OPERATION fd (fd_type=%u)\n",
				    state->fd_type);
		ret = -ENODEV;
		goto out;
	}

	if (state->finalized || state->error) {
		ret = -EINVAL;
		goto out;
	}

	if (!state->ops->set_iv) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	/* Use provider DRBG if available (FIPS boundary), else kernel CSPRNG. */
	if (state->ops->gen_iv) {
		ret = state->ops->gen_iv(state->ctx, iv, op.ivlen);
		if (ret) {
			pr_err_ratelimited("gen_iv('%s'/%s): callback failed: %d\n",
					   state->algo, state->provider_name, ret);
			goto out_zeroize;
		}
	} else {
		get_random_bytes(iv, op.ivlen);
	}

	ret = state->ops->set_iv(state->ctx, iv, op.ivlen);
	if (ret)
		goto out_zeroize;

	memcpy(op.iv, iv, op.ivlen);

	if (copy_to_user((void __user *)arg, &op, sizeof(op))) {
		ret = -EFAULT;
		goto out_zeroize;
	}

	/* iv_set only after the IV has been delivered to the caller;
	 * if copy_to_user fails the caller never received the IV. */
	state->iv_set = true;

out_zeroize:
	memzero_explicit(iv, sizeof(iv));
out:
	mutex_unlock(&state->lock);
	return ret;
}

static long ioctl_set_aad(struct crypto2dev_fd_state *state, unsigned long arg)
{
	const struct crypto2dev_algo_ops *early_ops;
	struct crypto2dev_aad_op op;
	int ret;

	/* FIPS 140-3: gate before any work. See ioctl_set_iv for rationale. */
	early_ops = READ_ONCE(state->ops);
	if (early_ops && early_ops->fips_gate) {
		ret = early_ops->fips_gate();
		if (ret) {
			pr_err_ratelimited("set_aad('%s'/%s): FIPS not operational (%d)\n",
					   state->algo, state->provider_name, ret);
			return ret;
		}
	}

	if (copy_from_user(&op, (void __user *)arg, sizeof(op)))
		return -EFAULT;

	if (op.aadlen == 0 || op.aadlen > CRYPTO2DEV_AAD_MAXLEN)
		return -EINVAL;

	mutex_lock(&state->lock);

	/* FIPS 140-3: gate before any session-state inspection. */
	if (state->ops && state->ops->fips_gate) {
		ret = state->ops->fips_gate();
		if (ret) {
			pr_err_ratelimited("fips_gate('%s'/%s): FIPS not operational (%d)\n",
					   state->algo, state->provider_name, ret);
			goto out;
		}
	}

	if (state->fd_type != CRYPTO2DEV_FDTYPE_OPERATION) {
		pr_info_ratelimited("set_aad: called on non-OPERATION fd (fd_type=%u)\n",
				    state->fd_type);
		ret = -ENODEV;
		goto out;
	}

	if (state->finalized || state->error) {
		ret = -EINVAL;
		goto out;
	}

	if (!state->ops->set_aad) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	/* AAD is inline in the ioctl struct — no extra copy needed. */
	ret = state->ops->set_aad(state->ctx, op.aad, op.aadlen);
	if (ret)
		pr_err_ratelimited("set_aad('%s'/%s): callback failed: %d\n",
				   state->algo, state->provider_name, ret);

out:
	mutex_unlock(&state->lock);
	return ret;
}

static long ioctl_get_tag(struct crypto2dev_fd_state *state, unsigned long arg)
{
	const struct crypto2dev_algo_ops *early_ops;
	struct crypto2dev_tag_op op;
	int ret;

	/* FIPS 140-3: gate before any work. See ioctl_set_iv for rationale. */
	early_ops = READ_ONCE(state->ops);
	if (early_ops && early_ops->fips_gate) {
		ret = early_ops->fips_gate();
		if (ret) {
			pr_err_ratelimited("get_tag('%s'/%s): FIPS not operational (%d)\n",
					   state->algo, state->provider_name, ret);
			return ret;
		}
	}

	if (copy_from_user(&op, (void __user *)arg, sizeof(op)))
		return -EFAULT;

	mutex_lock(&state->lock);

	/* FIPS 140-3: gate before any session-state inspection. */
	if (state->ops && state->ops->fips_gate) {
		ret = state->ops->fips_gate();
		if (ret) {
			pr_err_ratelimited("fips_gate('%s'/%s): FIPS not operational (%d)\n",
					   state->algo, state->provider_name, ret);
			goto out;
		}
	}

	if (state->fd_type != CRYPTO2DEV_FDTYPE_OPERATION) {
		pr_info_ratelimited("get_tag: called on non-OPERATION fd (fd_type=%u)\n",
				    state->fd_type);
		ret = -ENODEV;
		goto out;
	}

	if (!state->ops->get_tag) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	ret = state->ops->get_tag(state->ctx, op.tag, &op.taglen);
	if (ret) {
		pr_err_ratelimited("get_tag('%s'/%s): callback failed: %d\n",
				   state->algo, state->provider_name, ret);
		goto out;
	}

	if (copy_to_user((void __user *)arg, &op, sizeof(op)))
		ret = -EFAULT;

out:
	mutex_unlock(&state->lock);
	return ret;
}

static long ioctl_set_tag(struct crypto2dev_fd_state *state, unsigned long arg)
{
	const struct crypto2dev_algo_ops *early_ops;
	struct crypto2dev_tag_op op;
	int ret;

	/* FIPS 140-3: gate before any work. See ioctl_set_iv for rationale. */
	early_ops = READ_ONCE(state->ops);
	if (early_ops && early_ops->fips_gate) {
		ret = early_ops->fips_gate();
		if (ret) {
			pr_err_ratelimited("set_tag('%s'/%s): FIPS not operational (%d)\n",
					   state->algo, state->provider_name, ret);
			return ret;
		}
	}

	if (copy_from_user(&op, (void __user *)arg, sizeof(op)))
		return -EFAULT;

	/* FIPS SP 800-38D §5.2.1.2: GCM tag must be at least 96 bits (12 bytes) */
	if (op.taglen < 12 || op.taglen > CRYPTO2DEV_TAG_MAXLEN) {
		pr_info_ratelimited("set_tag: taglen %u rejected (FIPS SP 800-38D: min 12, max %u bytes)\n",
				    op.taglen, CRYPTO2DEV_TAG_MAXLEN);
		return -EINVAL;
	}

	mutex_lock(&state->lock);

	/* FIPS 140-3: gate before any session-state inspection. */
	if (state->ops && state->ops->fips_gate) {
		ret = state->ops->fips_gate();
		if (ret) {
			pr_err_ratelimited("fips_gate('%s'/%s): FIPS not operational (%d)\n",
					   state->algo, state->provider_name, ret);
			goto out;
		}
	}

	if (state->fd_type != CRYPTO2DEV_FDTYPE_OPERATION) {
		pr_info_ratelimited("set_tag: called on non-OPERATION fd (fd_type=%u)\n",
				    state->fd_type);
		ret = -ENODEV;
		goto out;
	}

	if (state->finalized || state->error) {
		ret = -EINVAL;
		goto out;
	}

	if (!state->ops->set_tag) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	ret = state->ops->set_tag(state->ctx, op.tag, op.taglen);
	if (ret)
		pr_err_ratelimited("set_tag('%s'/%s): callback failed: %d\n",
				   state->algo, state->provider_name, ret);

out:
	mutex_unlock(&state->lock);
	return ret;
}

/*
 * ioctl_do_sign / ioctl_do_verify / ioctl_do_agree — one-shot asymmetric ops.
 *
 * These handlers hold only the KEY fd's mutex. They do NOT lock the calling
 * fd's state because they operate entirely on the key fd's data. The fget()
 * on key_fd prevents fd teardown while the call is in flight.
 */

static long ioctl_do_sign(struct crypto2dev_fd_state *state,
			  struct file *file, unsigned long arg)
{
	struct crypto2dev_sign_op op;
	struct crypto2dev_fd_state *key_state;
	struct file *key_file = NULL;
	int ret;

	if (copy_from_user(&op, (void __user *)arg, sizeof(op))) {
		ret = -EFAULT;
		goto out_zero;
	}

	op.hash_algo[CRYPTO2DEV_ALGO_MAXLEN - 1] = '\0';

	if (op.digest_len == 0 || op.digest_len > CRYPTO2DEV_HASH_MAXLEN) {
		ret = -EINVAL;
		goto out_zero;
	}

	if (memchr_inv(op._pad, 0, sizeof(op._pad))) {
		ret = -EINVAL;
		goto out_zero;
	}

	key_file = fget(op.key_fd);
	if (!key_file) {
		ret = -EBADF;
		goto out_zero;
	}

	if (key_file->f_op != file->f_op) {
		fput(key_file);
		key_file = NULL;
		ret = -EBADF;
		goto out_zero;
	}

	key_state = key_file->private_data;
	mutex_lock(&key_state->lock);

	if (key_state->fd_type != CRYPTO2DEV_FDTYPE_KEY || !key_state->key_ctx) {
		ret = -EBADF;
		goto out_unlock;
	}

	/* PRIVATE or PAIR keys may sign; PUBLIC and SYMMETRIC are invalid. */
	if (key_state->key_type != CRYPTO2DEV_KEY_PRIVATE &&
	    key_state->key_type != CRYPTO2DEV_KEY_PAIR) {
		ret = -EBADF;
		goto out_unlock;
	}

	if (!key_state->key_ops->sign) {
		ret = -EOPNOTSUPP;
		goto out_unlock;
	}

	if (key_state->key_ops->fips_gate) {
		ret = key_state->key_ops->fips_gate();
		if (ret) {
			pr_err_ratelimited("fips_gate('%s'/%s): FIPS not operational (%d)\n",
					   key_state->key_algo,
					   key_state->key_provider_name, ret);
			goto out_unlock;
		}
	}

	op.sig_len = 0;
	ret = key_state->key_ops->sign(key_state->key_ctx,
				       op.hash_algo[0] ? op.hash_algo : NULL,
				       op.digest, op.digest_len,
				       op.sig, sizeof(op.sig), &op.sig_len);
	if (ret)
		pr_err_ratelimited("sign('%s'): provider '%s' returned %d\n",
				   key_state->key_algo,
				   key_state->key_provider_name, ret);

out_unlock:
	mutex_unlock(&key_state->lock);
	fput(key_file);

	if (ret)
		goto out_zero;

	if (copy_to_user((void __user *)arg, &op, sizeof(op))) {
		ret = -EFAULT;
		goto out_zero;
	}

out_zero:
	memzero_explicit(&op, sizeof(op));
	return ret;
}

static long ioctl_do_verify(struct crypto2dev_fd_state *state,
			    struct file *file, unsigned long arg)
{
	struct crypto2dev_verify_op op;
	struct crypto2dev_fd_state *key_state;
	struct file *key_file = NULL;
	int ret;

	if (copy_from_user(&op, (void __user *)arg, sizeof(op))) {
		ret = -EFAULT;
		goto out_zero;
	}

	op.hash_algo[CRYPTO2DEV_ALGO_MAXLEN - 1] = '\0';

	if (op.digest_len == 0 || op.digest_len > CRYPTO2DEV_HASH_MAXLEN) {
		ret = -EINVAL;
		goto out_zero;
	}

	if (op.sig_len == 0 || op.sig_len > CRYPTO2DEV_SIG_MAXLEN) {
		ret = -EINVAL;
		goto out_zero;
	}

	if (memchr_inv(op._pad, 0, sizeof(op._pad))) {
		ret = -EINVAL;
		goto out_zero;
	}

	key_file = fget(op.key_fd);
	if (!key_file) {
		ret = -EBADF;
		goto out_zero;
	}

	if (key_file->f_op != file->f_op) {
		fput(key_file);
		key_file = NULL;
		ret = -EBADF;
		goto out_zero;
	}

	key_state = key_file->private_data;
	mutex_lock(&key_state->lock);

	if (key_state->fd_type != CRYPTO2DEV_FDTYPE_KEY || !key_state->key_ctx) {
		ret = -EBADF;
		goto out_unlock;
	}

	if (!key_state->key_ops->verify) {
		ret = -EOPNOTSUPP;
		goto out_unlock;
	}

	if (key_state->key_ops->fips_gate) {
		ret = key_state->key_ops->fips_gate();
		if (ret) {
			pr_err_ratelimited("fips_gate('%s'/%s): FIPS not operational (%d)\n",
					   key_state->key_algo,
					   key_state->key_provider_name, ret);
			goto out_unlock;
		}
	}

	ret = key_state->key_ops->verify(key_state->key_ctx,
					 op.hash_algo[0] ? op.hash_algo : NULL,
					 op.digest, op.digest_len,
					 op.sig, op.sig_len);
	if (ret)
		pr_err_ratelimited("verify('%s'): provider '%s' returned %d\n",
				   key_state->key_algo,
				   key_state->key_provider_name, ret);

out_unlock:
	mutex_unlock(&key_state->lock);
	fput(key_file);
	key_file = NULL;
out_zero:
	memzero_explicit(&op, sizeof(op));
	return ret;
}

static long ioctl_do_agree(struct crypto2dev_fd_state *state,
			   struct file *file, unsigned long arg)
{
	struct crypto2dev_agree_op op;
	struct crypto2dev_fd_state *key_state;
	struct file *key_file = NULL;
	int ret;

	if (copy_from_user(&op, (void __user *)arg, sizeof(op))) {
		ret = -EFAULT;
		goto out_zero;
	}

	if (op.peer_pubkey_len == 0 ||
	    op.peer_pubkey_len > CRYPTO2DEV_PUBKEY_MAXLEN) {
		ret = -EINVAL;
		goto out_zero;
	}

	if (op.okm_len == 0 || op.okm_len > CRYPTO2DEV_PUBKEY_MAXLEN) {
		ret = -EINVAL;
		goto out_zero;
	}

	if (op.salt_len > CRYPTO2DEV_KDF_SALT_MAXLEN) {
		ret = -EINVAL;
		goto out_zero;
	}

	if (op.info_len > CRYPTO2DEV_KDF_INFO_MAXLEN) {
		ret = -EINVAL;
		goto out_zero;
	}

	if (memchr_inv(op._pad, 0, sizeof(op._pad))) {
		ret = -EINVAL;
		goto out_zero;
	}

	key_file = fget(op.key_fd);
	if (!key_file) {
		ret = -EBADF;
		goto out_zero;
	}

	if (key_file->f_op != file->f_op) {
		fput(key_file);
		key_file = NULL;
		ret = -EBADF;
		goto out_zero;
	}

	key_state = key_file->private_data;
	mutex_lock(&key_state->lock);

	if (key_state->fd_type != CRYPTO2DEV_FDTYPE_KEY || !key_state->key_ctx) {
		ret = -EBADF;
		goto out_unlock;
	}

	/* PRIVATE or PAIR keys may perform key agreement; PUBLIC and SYMMETRIC are invalid. */
	if (key_state->key_type != CRYPTO2DEV_KEY_PRIVATE &&
	    key_state->key_type != CRYPTO2DEV_KEY_PAIR) {
		ret = -EBADF;
		goto out_unlock;
	}

	if (!key_state->key_ops->agree) {
		ret = -EOPNOTSUPP;
		goto out_unlock;
	}

	if (key_state->key_ops->fips_gate) {
		ret = key_state->key_ops->fips_gate();
		if (ret) {
			pr_err_ratelimited("fips_gate('%s'/%s): FIPS not operational (%d)\n",
					   key_state->key_algo,
					   key_state->key_provider_name, ret);
			goto out_unlock;
		}
	}

	ret = key_state->key_ops->agree(key_state->key_ctx,
					op.peer_pubkey, op.peer_pubkey_len,
					op.salt_len ? op.salt : NULL,
					op.salt_len,
					op.info_len ? op.info : NULL,
					op.info_len,
					op.okm, op.okm_len);
	if (ret)
		pr_err_ratelimited("agree('%s'): provider '%s' returned %d\n",
				   key_state->key_algo,
				   key_state->key_provider_name, ret);

out_unlock:
	mutex_unlock(&key_state->lock);
	fput(key_file);

	if (ret)
		goto out_zero;

	if (copy_to_user((void __user *)arg, &op, sizeof(op))) {
		ret = -EFAULT;
		goto out_zero;
	}

out_zero:
	memzero_explicit(&op, sizeof(op));
	return ret;
}

/*
 * ioctl_finalize — CRYPTO2DEV_IOC_FINALIZE
 *
 * Signals end-of-input for an OPERATION fd. Calls ops->finalize() and appends
 * the final output (last cipher block, digest, GCM tag) to outbuf. Sets
 * finalized=true so subsequent write() calls return -EINVAL, and so read()
 * returns 0 (EOF) once outbuf is fully drained.
 */
static long ioctl_finalize(struct crypto2dev_fd_state *state)
{
	size_t produced = 0;
	int ret;

	mutex_lock(&state->lock);

	/* FIPS 140-3: gate before any session-state inspection. */
	if (state->ops && state->ops->fips_gate) {
		ret = state->ops->fips_gate();
		if (ret) {
			pr_err_ratelimited("fips_gate('%s'/%s): FIPS not operational (%d)\n",
					   state->algo, state->provider_name, ret);
			goto out;
		}
	}

	if (state->fd_type != CRYPTO2DEV_FDTYPE_OPERATION) {
		pr_info_ratelimited("finalize: called on non-OPERATION fd (fd_type=%u)\n",
				    state->fd_type);
		ret = -ENODEV;
		goto out;
	}

	if (state->finalized) {
		ret = -EINVAL;
		goto out;
	}

	if (state->error) {
		ret = -EIO;
		goto out;
	}

	/* IV must be set for algorithms that require one. */
	if (state->ops->set_iv && !state->iv_set) {
		ret = -EINVAL;
		goto out;
	}

	if (!state->ops->finalize) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	/*
	 * Reserve space for finalize output. Streaming providers (hash, HMAC,
	 * CBC) produce at most CRYPTO2DEV_HASH_MAXLEN bytes here.  Batching
	 * AEAD providers (wolfssl GCM, kcapi AEAD) must implement
	 * get_finalize_output_size() to report the actual ciphertext/plaintext
	 * length so the framework allocates a correctly-sized outbuf.
	 */
	{
		size_t need = CRYPTO2DEV_HASH_MAXLEN;
		if (state->ops->get_finalize_output_size)
			need = max_t(size_t, need,
				     state->ops->get_finalize_output_size(state->ctx));
		ret = outbuf_grow(state, need);
	}
	if (ret)
		goto out;

	ret = state->ops->finalize(state->ctx,
				   state->outbuf + state->outbuf_len,
				   state->outbuf_cap - state->outbuf_len,
				   &produced);
	if (ret) {
		pr_err_ratelimited("finalize('%s'/%s): failed: %d\n",
				   state->algo, state->provider_name, ret);
		state->error = true;
		goto out;
	}

	if (WARN_ON(produced > state->outbuf_cap - state->outbuf_len)) {
		ret = -EIO;
		state->error = true;
		goto out;
	}

	state->outbuf_len += produced;
	state->finalized   = true;

out:
	mutex_unlock(&state->lock);
	if (ret == 0)
		wake_up_interruptible(&state->poll_wq);
	return ret;
}

static long ioctl_reset(struct crypto2dev_fd_state *state)
{
	int ret;

	mutex_lock(&state->lock);

	/* FIPS 140-3: gate before any session-state inspection. */
	if (state->ops && state->ops->fips_gate) {
		ret = state->ops->fips_gate();
		if (ret) {
			pr_err_ratelimited("fips_gate('%s'/%s): FIPS not operational (%d)\n",
					   state->algo, state->provider_name, ret);
			goto out;
		}
	}

	if (state->fd_type != CRYPTO2DEV_FDTYPE_OPERATION) {
		pr_info_ratelimited("reset: called on non-OPERATION fd (fd_type=%u)\n",
				    state->fd_type);
		ret = -ENODEV;
		goto out;
	}

	if (!state->finalized && !state->error) {
		/* Only valid after a completed finalize() or after an error. */
		ret = -EINVAL;
		goto out;
	}

	if (!state->ops->sess_reset) {
		/* Provider does not support reset. The fd remains finalized;
		 * the caller should close it and open a new one. */
		ret = -EOPNOTSUPP;
		goto out;
	}

	ret = state->ops->sess_reset(state->ctx);
	if (ret == 0) {
		state->outbuf_len     = 0;
		state->outbuf_drained = 0;
		state->finalized      = false;
		state->error          = false;
		state->iv_set         = false;
	} else {
		pr_err_ratelimited("reset('%s'): provider '%s' returned %d\n",
				   state->algo, state->provider_name, ret);
		/* Provider session is in undefined state after failed reset —
		 * mark dead so write()/finalize() return -EIO rather than
		 * operating on freed/uninitialized crypto structs. */
		state->error = true;
	}

out:
	mutex_unlock(&state->lock);
	if (ret == 0)
		wake_up_interruptible(&state->poll_wq);
	return ret;
}

static long ioctl_status(unsigned long arg)
{
	struct crypto2dev_status st = {};

	st.fips_state    = crypto2dev_fips_aggregate();
	st.num_algorithms = crypto2dev_algo_count();
	strscpy(st.version, "1.1.0", sizeof(st.version));

	if (copy_to_user((void __user *)arg, &st, sizeof(st)))
		return -EFAULT;

	return 0;
}

static long ioctl_get_state(struct crypto2dev_fd_state *state,
			    unsigned long arg)
{
	struct crypto2dev_fd_state_info info = {};

	mutex_lock(&state->lock);

	info.fd_type = state->fd_type;

	switch (state->fd_type) {
	case CRYPTO2DEV_FDTYPE_OPERATION:
		strscpy(info.algo,     state->algo,          sizeof(info.algo));
		strscpy(info.provider, state->provider_name, sizeof(info.provider));
		info.op             = state->op;
		info.initialized    = 1;
		info.bytes_written  = state->bytes_written;
		info.bytes_read     = state->bytes_read;
		info.outbuf_pending = state->outbuf_len - state->outbuf_drained;
		info.inbuf_pending  = state->inbuf_len;
		info.finalized      = state->finalized     ? 1 : 0;
		info.error          = state->error         ? 1 : 0;
		info.iv_set         = state->iv_set        ? 1 : 0;
		info.require_fips   = state->require_fips  ? 1 : 0;
		info.outbuf_cap     = (u32)state->outbuf_cap;
		break;

	case CRYPTO2DEV_FDTYPE_KEY:
		strscpy(info.algo,     state->key_algo,          sizeof(info.algo));
		strscpy(info.provider, state->key_provider_name, sizeof(info.provider));
		info.key_type       = state->key_type;
		info.key_exportable = state->key_exportable;
		info.inbuf_pending  = state->inbuf_len;
		info.outbuf_pending = state->outbuf_len - state->outbuf_drained;
		info.outbuf_cap     = (u32)state->outbuf_cap;
		info.initialized    = state->key_ctx ? 1 : 0;
		break;

	default:
		/* UNSET fd: populate inbuf_pending (write() data buffered before KEY_IMPORT)
		 * and require_fips so callers can observe both pending data and FIPS state. */
		info.inbuf_pending = state->inbuf_len;
		info.require_fips  = state->require_fips ? 1 : 0;
		break;
	}

	mutex_unlock(&state->lock);

	if (copy_to_user((void __user *)arg, &info, sizeof(info)))
		return -EFAULT;

	return 0;
}

/* ── Symmetric KEY fd support (for DO_KDF) ────────────────────────────────── */

static void sym_key_free(void *key_ctx)
{
	if (!key_ctx)
		return;
	memzero_explicit(key_ctx, sizeof(struct crypto2dev_sym_key));
	kfree(key_ctx);
}

static int sym_key_export_private(void *key_ctx,
				  u8 *out, u32 bufsz, u32 *outlen)
{
	struct crypto2dev_sym_key *sk = key_ctx;

	if (!sk || sk->len == 0)
		return -ENOKEY;
	if (bufsz < sk->len)
		return -EMSGSIZE;
	memcpy(out, sk->bytes, sk->len);
	*outlen = sk->len;
	return 0;
}

/*
 * crypto2dev_sym_key_ops — minimal ops vtable for symmetric KEY fds.
 *
 * KEY_EXPORT_PRIVATE is guarded by key_exportable (set from op.exportable in
 * DO_KDF). Non-exportable fds get -EACCES before reaching this callback.
 * All asymmetric callbacks (sign, verify, agree) are absent (NULL → -EOPNOTSUPP).
 */
static const struct crypto2dev_algo_ops crypto2dev_sym_key_ops = {
	.algo               = "symmetric",
	.key_free           = sym_key_free,
	.key_export_private = sym_key_export_private,
};

/* ── KEY fd ioctls ────────────────────────────────────────────────────────── */

static long ioctl_key_import(struct crypto2dev_fd_state *state,
			     unsigned long arg)
{
	struct crypto2dev_key_import_op op;
	const struct crypto2dev_algo_ops *ops;
	struct module *owner;
	const char *actual_provider = NULL;
	void *key_ctx = NULL;
	int ret;

	if (copy_from_user(&op, (void __user *)arg, sizeof(op))) {
		/* copy_from_user failed — still must zeroize any pending inbuf */
		mutex_lock(&state->lock);
		inbuf_clear(state);
		mutex_unlock(&state->lock);
		return -EFAULT;
	}

	op.algo    [CRYPTO2DEV_ALGO_MAXLEN - 1]     = '\0';
	op.provider[CRYPTO2DEV_PROVIDER_MAXLEN - 1] = '\0';

	mutex_lock(&state->lock);

	/* Validate op fields under the lock so early exits can zeroize inbuf */
	if (op.algo[0] == '\0') {
		ret = -EINVAL;
		goto out_inbuf_clear;
	}

	if (op.keylen == 0 || op.keylen > CRYPTO2DEV_KEY_IMPORT_MAXLEN) {
		ret = -EINVAL;
		goto out_inbuf_clear;
	}

	if (op.key_type != CRYPTO2DEV_KEY_PRIVATE &&
	    op.key_type != CRYPTO2DEV_KEY_PUBLIC &&
	    op.key_type != CRYPTO2DEV_KEY_PAIR) {
		ret = -EINVAL;
		goto out_inbuf_clear;
	}

	if (memchr_inv(op._pad, 0, sizeof(op._pad))) {
		pr_err("key_import: nonzero _pad field\n");
		ret = -EINVAL;
		goto out_inbuf_clear;
	}

	if (state->fd_type != CRYPTO2DEV_FDTYPE_UNSET) {
		ret = -EBUSY;
		goto out_inbuf_clear;
	}

	if (state->inbuf_len != op.keylen) {
		pr_err("key_import: inbuf_len %zu != op.keylen %u\n",
		       state->inbuf_len, op.keylen);
		ret = -EINVAL;
		goto out_inbuf_clear;
	}

	ops = crypto2dev_lookup_algo(op.algo,
				     op.provider[0] ? op.provider : NULL,
				     &owner, &actual_provider);
	if (!ops) {
		if (crypto2dev_fips_provider_loaded())
			pr_info_ratelimited("key_import('%.*s'): not found — FIPS mode active; ensure a FIPS provider registers this algo\n",
					    (int)CRYPTO2DEV_ALGO_MAXLEN, op.algo);
		else
			pr_info_ratelimited("key_import('%.*s'): no provider registered for this algo\n",
					    (int)CRYPTO2DEV_ALGO_MAXLEN, op.algo);
		ret = -ENOENT;
		goto out_inbuf_clear;
	}

	if (!ops->key_import) {
		pr_info_ratelimited("key_import('%.*s'): provider '%s' registered but has no key_import op\n",
				    (int)CRYPTO2DEV_ALGO_MAXLEN, op.algo,
				    actual_provider);
		module_put(owner);
		ret = -EOPNOTSUPP;
		goto out_inbuf_clear;
	}

	if (ops->fips_gate) {
		ret = ops->fips_gate();
		if (ret) {
			pr_err_ratelimited("KEY_IMPORT('%.*s'/%s): FIPS not operational (%d)\n",
					   (int)CRYPTO2DEV_ALGO_MAXLEN, op.algo,
					   actual_provider, ret);
			module_put(owner);
			goto out_inbuf_clear;
		}
	}

	ret = ops->key_import(&key_ctx, op.key_type, state->inbuf, op.keylen);
	inbuf_clear(state);   /* zeroize key material regardless of outcome */
	if (ret) {
		pr_err_ratelimited("key_import('%.*s'): provider '%s' returned %d\n",
				   (int)CRYPTO2DEV_ALGO_MAXLEN, op.algo,
				   actual_provider, ret);
		if (key_ctx != NULL)
			WARN(1, "provider '%s' left key_ctx non-NULL on key_import error — memory leak\n",
			     actual_provider);
		module_put(owner);
		goto out;
	}

	state->fd_type           = CRYPTO2DEV_FDTYPE_KEY;
	state->key_type          = op.key_type;
	state->key_exportable    = op.exportable;
	state->key_ctx           = key_ctx;
	state->key_ops           = ops;
	state->key_owner_module  = owner;
	strscpy(state->key_algo,          op.algo,          CRYPTO2DEV_ALGO_MAXLEN);
	strscpy(state->key_provider_name,
		actual_provider ? actual_provider : op.provider,
		CRYPTO2DEV_PROVIDER_MAXLEN);
	pr_info_ratelimited("KEY_IMPORT '%.*s' dispatched to provider '%s'\n",
			    (int)CRYPTO2DEV_ALGO_MAXLEN, op.algo,
			    actual_provider ? actual_provider : op.provider);
	ret = 0;
	goto out;

out_inbuf_clear:
	inbuf_clear(state);   /* FIPS 140-3: zeroize pending key bytes on all error paths */
out:
	mutex_unlock(&state->lock);
	return ret;
}

static long ioctl_do_kdf(struct crypto2dev_fd_state *state,
			 struct file *file,
			 unsigned long arg)
{
	struct crypto2dev_kdf_op op;
	const struct crypto2dev_algo_ops *ops;
	struct module *owner;
	const char *actual_provider = NULL;
	struct crypto2dev_sym_key *sk = NULL;
	u8 *okm_buf = NULL;
	u8  *ikm_buf = NULL;  /* IKM from KEY fd when ikm_fd != -1 */
	u32  ikm_len = 0;
	int ret;

	if (copy_from_user(&op, (void __user *)arg, sizeof(op))) {
		ret = -EFAULT;
		goto out_early;
	}

	op.algo    [CRYPTO2DEV_ALGO_MAXLEN - 1] = '\0';
	op.out_algo[CRYPTO2DEV_ALGO_MAXLEN - 1] = '\0';

	/* Basic field validation before acquiring the lock */
	if (op.algo[0] == '\0' || op.out_algo[0] == '\0') {
		ret = -EINVAL;
		goto out_early;
	}

	if (op.okm_len == 0) {
		ret = -EINVAL;
		goto out_early;
	}
	if (op.okm_len > CRYPTO2DEV_KDF_OKM_MAXLEN) {
		ret = -EMSGSIZE;
		goto out_early;
	}

	if (op.salt_len > CRYPTO2DEV_KDF_SALT_MAXLEN) {
		ret = -EINVAL;
		goto out_early;
	}

	if (op.info_len > CRYPTO2DEV_KDF_INFO_MAXLEN) {
		ret = -EINVAL;
		goto out_early;
	}

	/* HKDF has no iteration count; reject non-zero to catch user errors
	 * where the caller mistakes HKDF for PBKDF2 and passes an iteration
	 * count that is silently discarded. */
	if (strncmp(op.algo, "hkdf", 4) == 0 && op.iterations != 0) {
		ret = -EINVAL;
		goto out_early;
	}

	/* Reject garbage reserved fields before touching any fd or key state. */
	if (memchr_inv(op._pad, 0, sizeof(op._pad))) {
		pr_err("do_kdf: nonzero _pad field\n");
		ret = -EINVAL;
		goto out_early;
	}

	/* ikm_fd: extract IKM bytes from a symmetric KEY fd.
	 * Lock ordering: ks->lock acquired and released BEFORE state->lock
	 * to prevent ABBA deadlock with concurrent CRYPTO2DEV_IOC_INIT. */
	if (op.ikm_fd != -1) {
		struct file               *kf;
		struct crypto2dev_fd_state *ks;
		struct crypto2dev_sym_key  *sk_src;

		/* PBKDF2 IKM must come from write() — passwords are sensitive
		 * and are never stored in KEY fds. */
		if (strncmp(op.algo, "pbkdf2", 6) == 0) {
			ret = -EINVAL;
			goto out_early;
		}

		ikm_buf = kmalloc(CRYPTO2DEV_KDF_OKM_MAXLEN, GFP_KERNEL);
		if (!ikm_buf) {
			ret = -ENOMEM;
			goto out_early;
		}

		kf = fget(op.ikm_fd);
		if (!kf) {
			ret = -EBADF;
			goto out_early;
		}
		if (kf->f_op != file->f_op) {
			fput(kf);
			ret = -EBADF;
			goto out_early;
		}

		ks = kf->private_data;
		mutex_lock(&ks->lock);

		if (ks->fd_type != CRYPTO2DEV_FDTYPE_KEY ||
		    ks->key_type != CRYPTO2DEV_KEY_SYMMETRIC ||
		    !ks->key_ctx) {
			mutex_unlock(&ks->lock);
			fput(kf);
			ret = -EBADF;
			goto out_early;
		}

		sk_src = ks->key_ctx;
		if (sk_src->len == 0) {
			mutex_unlock(&ks->lock);
			fput(kf);
			ret = -EINVAL;
			goto out_early;
		}

		memcpy(ikm_buf, sk_src->bytes, sk_src->len);
		ikm_len = sk_src->len;

		mutex_unlock(&ks->lock);
		fput(kf);
	}

	mutex_lock(&state->lock);

	if (state->fd_type != CRYPTO2DEV_FDTYPE_UNSET) {
		ret = -ENODEV;
		goto out_inbuf_clear;
	}

	/* ikm_fd path: require no pending write() data (dual-source rejected).
	 * write() path: require at least one byte of accumulated write() data. */
	if (op.ikm_fd != -1) {
		if (state->inbuf_len > 0) {
			ret = -EINVAL;
			goto out_inbuf_clear;
		}
	} else {
		if (state->inbuf_len == 0) {
			ret = -EINVAL;
			goto out_inbuf_clear;
		}
	}

	ops = crypto2dev_lookup_algo(op.algo, NULL, &owner, &actual_provider);
	if (!ops) {
		if (crypto2dev_fips_provider_loaded())
			pr_info_ratelimited("do_kdf('%.*s'): not found — FIPS mode active\n",
					    (int)CRYPTO2DEV_ALGO_MAXLEN, op.algo);
		else
			pr_info_ratelimited("do_kdf('%.*s'): no provider registered\n",
					    (int)CRYPTO2DEV_ALGO_MAXLEN, op.algo);
		ret = -ENOENT;
		goto out_inbuf_clear;
	}

	if (!ops->kdf) {
		pr_info_ratelimited("do_kdf('%.*s'): provider '%s' has no kdf callback\n",
				    (int)CRYPTO2DEV_ALGO_MAXLEN, op.algo,
				    actual_provider);
		module_put(owner);
		ret = -EOPNOTSUPP;
		goto out_inbuf_clear;
	}

	if (ops->fips_gate) {
		ret = ops->fips_gate();
		if (ret) {
			pr_err_ratelimited("DO_KDF('%.*s'->'%.*s'/%s): FIPS not operational (%d)\n",
					   (int)CRYPTO2DEV_ALGO_MAXLEN, op.algo,
					   (int)CRYPTO2DEV_ALGO_MAXLEN, op.out_algo,
					   actual_provider ? actual_provider : "<unknown>",
					   ret);
			module_put(owner);
			goto out_inbuf_clear;
		}
	}

	/* Provider-declared minimum iteration count (SP 800-132 §5.2) */
	if (ops->min_iterations && op.iterations < ops->min_iterations) {
		pr_info_ratelimited("do_kdf('%.*s'): iterations %u < minimum %u\n",
				    (int)CRYPTO2DEV_ALGO_MAXLEN, op.algo,
				    op.iterations, ops->min_iterations);
		module_put(owner);
		ret = -EINVAL;
		goto out_inbuf_clear;
	}

	/* Provider-declared minimum salt length (SP 800-132 §5.1) */
	if (ops->min_salt_len && op.salt_len < ops->min_salt_len) {
		pr_info_ratelimited("do_kdf('%.*s'): salt_len %u < minimum %u\n",
				    (int)CRYPTO2DEV_ALGO_MAXLEN, op.algo,
				    op.salt_len, ops->min_salt_len);
		module_put(owner);
		ret = -EINVAL;
		goto out_inbuf_clear;
	}

	/* Allocate OKM scratch buffer before calling the KDF */
	okm_buf = kmalloc(op.okm_len, GFP_KERNEL);
	if (!okm_buf) {
		module_put(owner);
		ret = -ENOMEM;
		goto out_inbuf_clear;
	}

	ret = ops->kdf(op.ikm_fd != -1 ? ikm_buf       : state->inbuf,
		       op.ikm_fd != -1 ? ikm_len        : state->inbuf_len,
		       op.salt_len ? op.salt : NULL, op.salt_len,
		       op.info_len ? op.info : NULL, op.info_len,
		       op.iterations,
		       okm_buf, op.okm_len);

	/* FIPS 140-3: zeroize IKM regardless of KDF outcome */
	if (op.ikm_fd != -1) {
		memzero_explicit(ikm_buf, CRYPTO2DEV_KDF_OKM_MAXLEN);
		kfree(ikm_buf);
		ikm_buf = NULL;
	} else {
		inbuf_clear(state);
	}

	module_put(owner);

	if (ret) {
		pr_err_ratelimited("do_kdf('%.*s'): provider '%s' returned %d\n",
				   (int)CRYPTO2DEV_ALGO_MAXLEN, op.algo,
				   actual_provider, ret);
		goto out_free_okm;
	}

	pr_info_ratelimited("do_kdf('%.*s'): dispatched to provider '%s'\n",
			    (int)CRYPTO2DEV_ALGO_MAXLEN, op.algo,
			    actual_provider);

	sk = kzalloc(sizeof(*sk), GFP_KERNEL);
	if (!sk) {
		ret = -ENOMEM;
		goto out_free_okm;
	}

	memcpy(sk->bytes, okm_buf, op.okm_len);
	sk->len = op.okm_len;

	/* Promote to KEY fd with the derived symmetric key */
	state->fd_type          = CRYPTO2DEV_FDTYPE_KEY;
	state->key_type         = CRYPTO2DEV_KEY_SYMMETRIC;
	state->key_exportable   = op.exportable ? 1 : 0;
	state->key_ctx          = sk;
	state->key_ops          = &crypto2dev_sym_key_ops;
	state->key_owner_module = NULL;  /* sym_key_ops lives in this module */
	strscpy(state->key_algo, op.out_algo, CRYPTO2DEV_ALGO_MAXLEN);
	strscpy(state->key_provider_name, "crypto2dev", CRYPTO2DEV_PROVIDER_MAXLEN);
	ret = 0;
	/* fall through — out_inbuf_clear is a no-op (inbuf already cleared above) */

out_inbuf_clear:
	inbuf_clear(state);
out_free_okm:
	if (okm_buf) {
		memzero_explicit(okm_buf, op.okm_len);
		kfree(okm_buf);
	}
	if (ikm_buf) {
		memzero_explicit(ikm_buf, CRYPTO2DEV_KDF_OKM_MAXLEN);
		kfree(ikm_buf);
		ikm_buf = NULL;    /* prevent double-free via out_zero */
	}
	mutex_unlock(&state->lock);
	goto out_zero;

out_early:
	/* Pre-lock validation failure: lock was never acquired.
	 * Acquire state->lock to zeroize any IKM that was written via write()
	 * before this DO_KDF call — FIPS 140-3 requires CSPs to be zeroized
	 * when no longer operationally needed, regardless of why the call failed. */
	mutex_lock(&state->lock);
	inbuf_clear(state);
	mutex_unlock(&state->lock);
out_zero:
	if (ikm_buf) {
		memzero_explicit(ikm_buf, CRYPTO2DEV_KDF_OKM_MAXLEN);
		kfree(ikm_buf);
	}
	memzero_explicit(&op, sizeof(op));
	return ret;
}

static long ioctl_key_generate(struct crypto2dev_fd_state *state,
			       unsigned long arg)
{
	struct crypto2dev_key_generate_op op;
	const struct crypto2dev_algo_ops *ops;
	struct module *owner;
	const char *actual_provider = NULL;
	void *key_ctx = NULL;
	int ret;

	if (copy_from_user(&op, (void __user *)arg, sizeof(op))) {
		mutex_lock(&state->lock);
		inbuf_clear(state);
		mutex_unlock(&state->lock);
		return -EFAULT;
	}

	op.algo    [CRYPTO2DEV_ALGO_MAXLEN - 1]     = '\0';
	op.provider[CRYPTO2DEV_PROVIDER_MAXLEN - 1] = '\0';

	mutex_lock(&state->lock);

	if (op.algo[0] == '\0') {
		inbuf_clear(state);
		ret = -EINVAL;
		goto out;
	}

	if (memchr_inv(op._pad, 0, sizeof(op._pad))) {
		pr_err("key_generate: nonzero _pad field\n");
		inbuf_clear(state);
		ret = -EINVAL;
		goto out;
	}

	if (state->fd_type != CRYPTO2DEV_FDTYPE_UNSET) {
		inbuf_clear(state);  /* symmetric with ioctl_key_import's -EBUSY path */
		ret = -EBUSY;
		goto out;
	}

	ops = crypto2dev_lookup_algo(op.algo,
				     op.provider[0] ? op.provider : NULL,
				     &owner, &actual_provider);
	if (!ops) {
		if (crypto2dev_fips_provider_loaded())
			pr_info_ratelimited("key_generate('%.*s'): not found — FIPS mode active; ensure a FIPS provider registers this algo\n",
					    (int)CRYPTO2DEV_ALGO_MAXLEN, op.algo);
		else
			pr_info_ratelimited("key_generate('%.*s'): no provider registered for this algo\n",
					    (int)CRYPTO2DEV_ALGO_MAXLEN, op.algo);
		inbuf_clear(state);	/* FIPS 140-3: zero IKM on all error paths */
		ret = -ENOENT;
		goto out;
	}

	if (!ops->key_generate) {
		pr_info_ratelimited("key_generate('%.*s'): provider '%s' registered but has no key_generate op\n",
				    (int)CRYPTO2DEV_ALGO_MAXLEN, op.algo,
				    actual_provider);
		inbuf_clear(state);	/* FIPS 140-3: zero IKM on all error paths */
		module_put(owner);
		ret = -EOPNOTSUPP;
		goto out;
	}

	if (ops->fips_gate) {
		ret = ops->fips_gate();
		if (ret) {
			pr_err_ratelimited("KEY_GENERATE('%.*s'/%s): FIPS not operational (%d)\n",
					   (int)CRYPTO2DEV_ALGO_MAXLEN, op.algo,
					   actual_provider, ret);
			inbuf_clear(state);	/* FIPS 140-3: zero IKM on all error paths */
			module_put(owner);
			goto out;
		}
	}

	ret = ops->key_generate(&key_ctx);
	if (ret) {
		pr_err_ratelimited("key_generate('%.*s'): provider '%s' returned %d\n",
				   (int)CRYPTO2DEV_ALGO_MAXLEN, op.algo,
				   actual_provider, ret);
		if (key_ctx != NULL)
			WARN(1, "provider '%s' left key_ctx non-NULL on key_generate error — memory leak\n",
			     actual_provider);
		inbuf_clear(state);   /* FIPS 140-3: zero IKM on all error paths */
		module_put(owner);
		goto out;
	}

	inbuf_clear(state);   /* discard any abandoned write() data — FIPS 140-3 */
	state->fd_type           = CRYPTO2DEV_FDTYPE_KEY;
	state->key_type          = CRYPTO2DEV_KEY_PAIR;
	state->key_exportable    = op.exportable;
	state->key_ctx           = key_ctx;
	state->key_ops           = ops;
	state->key_owner_module  = owner;
	strscpy(state->key_algo,          op.algo,          CRYPTO2DEV_ALGO_MAXLEN);
	strscpy(state->key_provider_name,
		actual_provider ? actual_provider : op.provider,
		CRYPTO2DEV_PROVIDER_MAXLEN);
	pr_info_ratelimited("KEY_GENERATE '%.*s' dispatched to provider '%s'\n",
			    (int)CRYPTO2DEV_ALGO_MAXLEN, op.algo,
			    actual_provider ? actual_provider : op.provider);
	ret = 0;

out:
	mutex_unlock(&state->lock);
	return ret;
}

static long ioctl_key_get_info(struct crypto2dev_fd_state *state,
			       unsigned long arg)
{
	struct crypto2dev_key_info info = {};
	u8 *kbuf = NULL;
	u32 publen = 0;
	int ret = 0;

	mutex_lock(&state->lock);

	if (state->fd_type != CRYPTO2DEV_FDTYPE_KEY || !state->key_ctx) {
		mutex_unlock(&state->lock);
		return -EINVAL;
	}

	strscpy(info.algo,     state->key_algo,          sizeof(info.algo));
	strscpy(info.provider, state->key_provider_name, sizeof(info.provider));
	info.key_type   = state->key_type;
	info.exportable = state->key_exportable;

	/*
	 * Determine the public key length. Try the fast path first: if the
	 * provider implements key_size, ask it directly without allocating a
	 * temporary buffer or serialising the key. Fall back to a trial export
	 * for providers that do not implement key_size or that return 0.
	 */
	if (state->key_ops->key_size) {
		int sz = state->key_ops->key_size(state->key_ctx,
						  CRYPTO2DEV_KEY_PUBLIC);
		if (sz > 0) {
			info.public_key_len = (u32)sz;
			goto key_info_done;
		}
	}

	if (state->key_ops->key_export_public) {
		/* FIPS 140-3: gate before any key material export. */
		if (state->key_ops->fips_gate) {
			int gret = state->key_ops->fips_gate();

			if (gret) {
				pr_err_ratelimited("fips_gate('%s'/%s): FIPS not operational (%d)\n",
						   state->key_algo,
						   state->key_provider_name, gret);
				ret = -EACCES;
				goto key_info_done;
			}
		}
		kbuf = kmalloc(CRYPTO2DEV_PUBKEY_MAXLEN, GFP_KERNEL);
		if (kbuf) {
			if (state->key_ops->key_export_public(
					state->key_ctx, kbuf,
					CRYPTO2DEV_PUBKEY_MAXLEN, &publen) == 0)
				info.public_key_len = publen;
			memzero_explicit(kbuf, CRYPTO2DEV_PUBKEY_MAXLEN);
			kfree(kbuf);
		} else {
			pr_warn_ratelimited("KEY_GET_INFO('%s'/%s): kmalloc failed — public_key_len unavailable\n",
					    state->key_algo,
					    state->key_provider_name);
		}
	}

key_info_done:
	mutex_unlock(&state->lock);

	if (ret)
		return ret;

	if (copy_to_user((void __user *)arg, &info, sizeof(info)))
		return -EFAULT;

	return 0;
}

static long ioctl_key_export_private(struct crypto2dev_fd_state *state,
				     unsigned long arg)
{
	struct crypto2dev_key_export_op op = {};
	u8 *kbuf;
	u32 outlen = 0;
	int ret;

	mutex_lock(&state->lock);

	if (state->fd_type != CRYPTO2DEV_FDTYPE_KEY || !state->key_ctx) {
		ret = -EINVAL;
		goto out;
	}

	if (!state->key_exportable) {
		ret = -EACCES;
		goto out;
	}

	if (!state->key_ops->key_export_private) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	/* FIPS 140-3: gate before any key material export. */
	if (state->key_ops->fips_gate) {
		int gret = state->key_ops->fips_gate();

		if (gret) {
			pr_err_ratelimited("fips_gate('%s'/%s): FIPS not operational (%d)\n",
					   state->key_algo,
					   state->key_provider_name, gret);
			ret = -EACCES;
			goto out;
		}
	}

	/* Reject if a previous export is still partially unread — do not
	 * silently overwrite key material that the caller has not yet drained. */
	if (state->outbuf && state->outbuf_drained < state->outbuf_len) {
		ret = -EBUSY;
		goto out;
	}

	/* FIPS 140-3 Level 2+: private key export in plaintext is a compliance
	 * concern. Emit once-per-algo to make exports auditable in dmesg.
	 * Decision 3C: keep export available but require explicit opt-in
	 * (key_exportable flag) and loud warning. */
	pr_warn_ratelimited("crypto2dev: plaintext private key export (%s) — FIPS 140-3 Level 2+ requires key wrapping\n",
			    state->key_algo);

	kbuf = kmalloc(CRYPTO2DEV_KEY_IMPORT_MAXLEN, GFP_KERNEL);
	if (!kbuf) {
		ret = -ENOMEM;
		goto out;
	}

	ret = state->key_ops->key_export_private(state->key_ctx,
						  kbuf,
						  CRYPTO2DEV_KEY_IMPORT_MAXLEN,
						  &outlen);
	if (ret) {
		pr_err_ratelimited("key_export_private('%s'/%s): callback failed: %d\n",
				   state->key_algo, state->key_provider_name, ret);
		memzero_explicit(kbuf, CRYPTO2DEV_KEY_IMPORT_MAXLEN);
		kfree(kbuf);
		goto out;
	}

	if (outlen > CRYPTO2DEV_KEY_IMPORT_MAXLEN) {
		pr_err("key_export_private: provider returned outlen %u > bufsz %u\n",
		       outlen, CRYPTO2DEV_KEY_IMPORT_MAXLEN);
		memzero_explicit(kbuf, CRYPTO2DEV_KEY_IMPORT_MAXLEN);
		kfree(kbuf);
		ret = -EOVERFLOW;
		goto out;
	}

	/* Replace any stale outbuf and install the private key bytes. */
	if (state->outbuf) {
		memzero_explicit(state->outbuf, state->outbuf_cap);
		kfree(state->outbuf);
	}
	state->outbuf         = kbuf;
	state->outbuf_cap     = CRYPTO2DEV_KEY_IMPORT_MAXLEN;
	state->outbuf_len     = outlen;
	state->outbuf_drained = 0;

	op.keylen = outlen;

	if (copy_to_user((void __user *)arg, &op, sizeof(op))) {
		/* Caller never received keylen — private key bytes cannot be
		 * drained; zeroize and free the outbuf now. */
		memzero_explicit(state->outbuf, state->outbuf_cap);
		kfree(state->outbuf);
		state->outbuf         = NULL;
		state->outbuf_len     = 0;
		state->outbuf_cap     = 0;
		state->outbuf_drained = 0;
		ret = -EFAULT;
		goto out;
	}

	ret = 0;

out:
	mutex_unlock(&state->lock);
	return ret;
}

/* ── ioctl dispatcher ─────────────────────────────────────────────────────── */

long crypto2dev_fd_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct crypto2dev_fd_state *state = file->private_data;

	switch (cmd) {
	case CRYPTO2DEV_IOC_INIT:
		return ioctl_init(state, file, arg);
	case CRYPTO2DEV_IOC_SET_IV:
		return ioctl_set_iv(state, arg);
	case CRYPTO2DEV_IOC_GEN_IV:
		return ioctl_gen_iv(state, arg);
	case CRYPTO2DEV_IOC_SET_AAD:
		return ioctl_set_aad(state, arg);
	case CRYPTO2DEV_IOC_GET_TAG:
		return ioctl_get_tag(state, arg);
	case CRYPTO2DEV_IOC_SET_TAG:
		return ioctl_set_tag(state, arg);
	case CRYPTO2DEV_IOC_STATUS:
		return ioctl_status(arg);
	case CRYPTO2DEV_IOC_GET_STATE:
		return ioctl_get_state(state, arg);
	case CRYPTO2DEV_IOC_KEY_IMPORT:
		return ioctl_key_import(state, arg);
	case CRYPTO2DEV_IOC_KEY_GENERATE:
		return ioctl_key_generate(state, arg);
	case CRYPTO2DEV_IOC_KEY_GET_INFO:
		return ioctl_key_get_info(state, arg);
	case CRYPTO2DEV_IOC_KEY_EXPORT_PRIVATE:
		return ioctl_key_export_private(state, arg);
	case CRYPTO2DEV_IOC_DO_SIGN:
		return ioctl_do_sign(state, file, arg);
	case CRYPTO2DEV_IOC_DO_VERIFY:
		return ioctl_do_verify(state, file, arg);
	case CRYPTO2DEV_IOC_DO_AGREE:
		return ioctl_do_agree(state, file, arg);
	case CRYPTO2DEV_IOC_RESET:
		return ioctl_reset(state);
	case CRYPTO2DEV_IOC_REQUIRE_FIPS:
		return ioctl_require_fips(state);
	case CRYPTO2DEV_IOC_FINALIZE:
		return ioctl_finalize(state);
	case CRYPTO2DEV_IOC_DO_KDF:
		return ioctl_do_kdf(state, file, arg);
	default:
		return -ENOTTY;
	}
}

