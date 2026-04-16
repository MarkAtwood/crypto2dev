// SPDX-License-Identifier: GPL-2.0-only
/*
 * example_provider.c — skeleton crypto2dev provider for hardware accelerators
 *
 * PURPOSE
 * -------
 * This file is a starting point for writing a crypto2dev provider that wraps
 * a hardware crypto engine. Fork it, replace every TODO with real hardware
 * calls, and register it as a new kernel module.
 *
 * This file is NOT included in the Kbuild by default. To build it, add:
 *
 *   obj-m += crypto2dev_example.o
 *   crypto2dev_example-objs := src/providers/example/example_provider.c
 *
 * to Kbuild, or build it standalone:
 *
 *   make -C /lib/modules/$(uname -r)/build M=$(pwd) \
 *        EXTRA_CFLAGS="-I$(pwd)/include" modules
 *
 * LOAD ORDER
 * ----------
 *   crypto2dev.ko  ->  crypto2dev_example.ko
 *
 * Do not load alongside the wolfssl or kcapi providers if they register the
 * same algorithm names — first-registered wins and a pr_warn is emitted for
 * duplicates. Use a distinct algorithm name during development (e.g. rename
 * "cbc(aes)" to "cbc(aes-acme)") to avoid conflicts during bring-up.
 *
 * WHAT TO IMPLEMENT
 * -----------------
 * The crypto2dev provider interface is defined in include/crypto2dev_provider.h.
 * A provider implements struct crypto2dev_algo_ops for each algorithm and
 * registers them via crypto2dev_register_provider().
 *
 * The framework guarantees:
 *   - The per-fd session mutex is held across every callback.
 *     You may sleep inside callbacks (kmalloc, wait for DMA, etc.).
 *   - sess_init is called once per fd; sess_free is called on close().
 *     Symmetric key bytes are passed inline via key/keylen. KEY fds are
 *     for asymmetric operations only and are never passed to sess_init.
 *   - update() may be called zero or more times with incremental input.
 *     finalize() is called once to produce the final output.
 *   - fips_gate() (if non-NULL) is called before every crypto callback.
 *     Return -EACCES to block the operation.
 *
 * ERROR CONVENTION
 * ----------------
 * Return kernel errno (negative). If your hardware returns its own error
 * codes, translate them before returning:
 *
 *   ACME_ERR_INVALID_KEY  -> -EINVAL
 *   ACME_ERR_NO_MEM       -> -ENOMEM
 *   ACME_ERR_AUTH_FAIL    -> -EBADMSG   (AEAD authentication failure only)
 *   ACME_ERR_*            -> -EIO       (generic hardware error)
 *
 * KEY MATERIAL
 * ------------
 * Always use memzero_explicit() (not memset) to wipe sensitive data before
 * freeing. The compiler may elide a plain memset of memory that is about to
 * be freed; memzero_explicit prevents that optimization.
 */

#define pr_fmt(fmt) "crypto2dev_example: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>

#include "../../include/crypto2dev_provider.h"
#include "../../include/uapi/crypto2dev_ioctl.h"

/* ── Session context ─────────────────────────────────────────────────────── */

/*
 * example_ctx — per-fd session state for this provider.
 *
 * Allocate this in sess_init, free it in sess_free. The framework stores a
 * void * to it and passes it back to every callback. Add hardware-specific
 * fields here.
 */
struct example_ctx {
	u32  op;    /* CRYPTO2DEV_OP_ENCRYPT / DECRYPT / HASH */

	/* TODO: add hardware-specific fields, for example:
	 *
	 *   struct acme_device  *dev;      // hardware device handle
	 *   dma_addr_t           key_dma;  // DMA address of key material
	 *   u8                   key[32];  // copy of key (for re-keying the HW)
	 *   u32                  keylen;
	 *   u8                   iv[16];   // current IV/nonce
	 *   u32                  ivlen;
	 */

	u8   key[CRYPTO2DEV_KEY_MAXLEN];
	u32  keylen;
	u8   iv[CRYPTO2DEV_IV_MAXLEN];
	u32  ivlen;
};

/* ── Optional: FIPS gate ─────────────────────────────────────────────────── */

/*
 * example_fips_gate — check whether your hardware is in a valid operational state.
 *
 * If your hardware has a FIPS or self-test status register, poll it here.
 * Return 0 if ready, -EACCES if not. Set .fips_gate = NULL to skip gating.
 *
 * The framework calls this before every crypto callback (sess_init, set_iv,
 * set_aad, set_tag, process, get_tag). It is NOT called before sess_free
 * (cleanup must always proceed regardless of hardware state).
 */
static int example_fips_gate(void)
{
	/* TODO: check hardware FIPS/operational status.
	 *
	 *   if (acme_get_status() != ACME_STATUS_OPERATIONAL)
	 *       return -EACCES;
	 */
	return 0;
}

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

/*
 * example_sess_init — allocate and initialize a session.
 *
 * Called when userspace issues CRYPTO2DEV_IOC_INIT. Set up hardware resources
 * (DMA buffers, key registers, etc.) here. If init fails, free any partial
 * allocations and return a negative errno; *ctx must be NULL on failure.
 *
 * @ctx:     [out] must point to a kzalloc'd context on success, NULL on failure
 * @op:      CRYPTO2DEV_OP_ENCRYPT / DECRYPT / HASH
 * @key:     key bytes (NULL and keylen==0 for un-keyed hash algorithms)
 * @keylen:  key length in bytes
 */
static int example_sess_init(void **ctx, u32 op,
			     const u8 *key, u32 keylen)
{
	struct example_ctx *c;
	int ret;

	ret = example_fips_gate();
	if (ret)
		return ret;

	/* Validate op */
	if (op != CRYPTO2DEV_OP_ENCRYPT &&
	    op != CRYPTO2DEV_OP_DECRYPT &&
	    op != CRYPTO2DEV_OP_HASH)
		return -EINVAL;

	/* Validate key length for your algorithm.
	 * TODO: replace with your hardware's accepted key lengths.
	 *
	 *   if (keylen != 16 && keylen != 24 && keylen != 32)
	 *       return -EINVAL;
	 */
	if (key && keylen == 0)
		return -EINVAL;
	if (!key && keylen != 0)
		return -EINVAL;
	if (keylen > CRYPTO2DEV_KEY_MAXLEN)
		return -EINVAL;

	c = kzalloc(sizeof(*c), GFP_KERNEL);
	if (!c)
		return -ENOMEM;

	c->op = op;

	if (key && keylen) {
		memcpy(c->key, key, keylen);
		c->keylen = keylen;
	}

	/* TODO: program the hardware with the key.
	 *
	 *   c->dev = acme_get_device();
	 *   if (!c->dev) { kfree(c); return -ENODEV; }
	 *
	 *   ret = acme_set_key(c->dev, key, keylen, op);
	 *   if (ret) { kfree(c); return -EINVAL; }
	 */

	*ctx = c;
	return 0;
}

/*
 * example_sess_free — zeroize key material and release hardware resources.
 *
 * Always called on fd close(). Must not fail. Must not skip cleanup even if
 * hardware is in an error state — at minimum, wipe the software copy of key
 * material and free kernel allocations.
 */
static void example_sess_free(void *ctx)
{
	struct example_ctx *c = ctx;

	if (!c)
		return;

	/* TODO: release hardware resources.
	 *
	 *   acme_release_session(c->dev);
	 *   dma_free_coherent(..., c->key_dma, ...);
	 */

	/* Zeroize all key material before freeing. memzero_explicit prevents
	 * the compiler from eliding this wipe as a "dead write". */
	memzero_explicit(c, sizeof(*c));
	kfree(c);
}

/*
 * example_sess_reset — re-arm the session for a new encrypt/hash without
 * close/reopen overhead.
 *
 * Called when userspace issues CRYPTO2DEV_IOC_RESET after finalize().
 * Must restore the session to the same state it was in just after
 * sess_init(): key material and algorithm state intact, but any
 * per-operation state (IV, AAD, partial output) cleared.
 *
 * For a hash: call your hardware's "init hash" command again.
 * For a cipher: clear the IV field in ctx so set_iv() is required again
 * before the next update() — this prevents accidental IV reuse.
 *
 * TODO: replace -EOPNOTSUPP with a real implementation once the hardware
 * supports mid-session reinitialisation.
 */
static int example_sess_reset(void *ctx)
{
	int ret;

	ret = example_fips_gate();
	if (ret)
		return ret;

	(void)ctx;

	/* TODO: re-arm hardware state while preserving key material.
	 *
	 *   struct example_ctx *c = ctx;
	 *   acme_reset_session(c->dev);
	 *   c->ivlen = 0;
	 */

	return -EOPNOTSUPP;
}

/* ── IV / nonce ──────────────────────────────────────────────────────────── */

/*
 * example_set_iv — store IV or nonce for use in process().
 *
 * Called after CRYPTO2DEV_IOC_INIT and before write()/read() for algorithms
 * that use an IV (CBC, CTR, GCM, CCM, …). Set .set_iv = NULL for hash/MAC
 * algorithms that have no IV.
 *
 * Validate the IV length for your algorithm (e.g. CBC requires 16 bytes,
 * GCM requires 12). Return -EINVAL if wrong.
 */
static int example_set_iv(void *ctx, const u8 *iv, u32 ivlen)
{
	struct example_ctx *c = ctx;
	int ret;

	ret = example_fips_gate();
	if (ret)
		return ret;

	if (!iv || ivlen == 0 || ivlen > CRYPTO2DEV_IV_MAXLEN)
		return -EINVAL;

	/* TODO: validate ivlen for your specific algorithm.
	 *
	 *   if (ivlen != 16)   // CBC: 16-byte IV
	 *       return -EINVAL;
	 */

	memcpy(c->iv, iv, ivlen);
	c->ivlen = ivlen;

	/* TODO: if the hardware accepts the IV at key-setup time rather than
	 * at encryption time, program it here:
	 *
	 *   acme_set_iv(c->dev, iv, ivlen);
	 */

	return 0;
}

/*
 * example_gen_iv — generate a random IV using the kernel CSPRNG.
 *
 * For FIPS providers, replace get_random_bytes with your approved DRBG call
 * (e.g. wc_RNG_GenerateBlock for wolfCrypt). The framework calls set_iv()
 * after this to program the generated IV into the session.
 *
 * Set .gen_iv = NULL if your hardware generates IVs internally during encrypt.
 */
static int example_gen_iv(void *ctx, u8 *iv, u32 ivlen)
{
	int ret;

	ret = example_fips_gate();
	if (ret)
		return ret;

	(void)ctx;

	if (!iv || ivlen == 0 || ivlen > CRYPTO2DEV_IV_MAXLEN)
		return -EINVAL;

	/* TODO: for FIPS, call your approved DRBG instead. */
	get_random_bytes(iv, ivlen);
	return 0;
}

/* ── AEAD (optional) ─────────────────────────────────────────────────────── */

/*
 * For AEAD algorithms (GCM, CCM), also implement:
 *
 *   example_set_aad(ctx, aad, aadlen)  — store additional authenticated data
 *   example_set_tag(ctx, tag, taglen)  — store expected tag (decrypt only)
 *   example_get_tag(ctx, tag, taglen)  — retrieve produced tag (encrypt only)
 *
 * For non-AEAD algorithms, set these fields to NULL in the ops struct.
 *
 * If your hardware handles AAD natively, pass it directly to the hardware here.
 * If not, store a copy in ctx and pass it to process().
 *
 * The example below sets them to NULL — fill them in if implementing AEAD.
 */

/* ── Processing ──────────────────────────────────────────────────────────── */

/*
 * example_update — feed input data into the ongoing crypto operation.
 *
 * May be called zero or more times between sess_init and finalize(). For
 * batch-only hardware, accumulate input in ctx->inbuf here and do the real
 * work in finalize(). For streaming hardware, submit each chunk directly.
 *
 * @ctx:         session context
 * @in:          input data
 * @inlen:       input length in bytes
 * @out:         output buffer (may be NULL if hardware cannot produce partial output)
 * @outbuf_size: size of @out
 * @outlen:      [out] bytes written to @out (0 if buffering for finalize)
 */
static int example_update(void *ctx, const u8 *in, size_t inlen,
			  u8 *out, size_t outbuf_size, size_t *outlen)
{
	struct example_ctx *c = ctx;
	int ret;

	ret = example_fips_gate();
	if (ret)
		return ret;

	if (!in || !out || !outlen || inlen == 0)
		return -EINVAL;

	if (c->ivlen == 0) {
		/* IV not set — caller forgot CRYPTO2DEV_IOC_SET_IV.
		 * Return -EINVAL rather than silently using a zero IV. */
		pr_err("update called without IV\n");
		return -EINVAL;
	}

	/* TODO: Replace with incremental hardware call if hardware can stream,
	 * OR just buffer input for batch processing in finalize(). For
	 * batch-only hardware, accumulate in ctx->inbuf here.
	 */

	/* STUB: no incremental output — accumulate in finalize */
	(void)out;
	(void)outbuf_size;
	*outlen = 0;
	return 0;
}

/*
 * example_finalize — complete the crypto operation and produce final output.
 *
 * Called once after all update() calls. Produce the final ciphertext, digest,
 * or MAC in @out and set *@outlen to the number of bytes written.
 *
 * For AEAD decrypt: return -EBADMSG if the authentication tag does not match.
 * The framework will not copy @out to userspace if finalize() returns an error.
 *
 * Hardware DMA pattern:
 *   1. Map buffered input and @out for DMA
 *   2. Program the hardware descriptor
 *   3. Start the operation
 *   4. Wait for completion (interrupt + wait_event, or polling for bring-up)
 *   5. Unmap DMA
 *   6. Check hardware status register for errors
 *
 * @ctx:         session context
 * @out:         output buffer
 * @outbuf_size: size of @out
 * @outlen:      [out] bytes written to @out
 */
static int example_finalize(void *ctx, u8 *out, size_t outbuf_size,
			    size_t *outlen)
{
	struct example_ctx *c = ctx;
	int ret;

	ret = example_fips_gate();
	if (ret)
		return ret;

	if (!out || !outlen || outbuf_size == 0)
		return -EINVAL;

	if (c->ivlen == 0) {
		/* IV not set — caller forgot CRYPTO2DEV_IOC_SET_IV.
		 * Return -EINVAL rather than silently using a zero IV. */
		pr_err("finalize called without IV\n");
		return -EINVAL;
	}

	/* TODO: Replace with incremental hardware call if hardware can stream,
	 * OR just buffer input for batch processing in finalize(). For
	 * batch-only hardware, accumulate in ctx->inbuf here.
	 *
	 * Bring-up sequence:
	 *
	 *   ret = acme_encrypt(c->dev,
	 *                      c->inbuf, c->inbuf_len,
	 *                      out, outbuf_size, outlen,
	 *                      c->iv, c->ivlen);
	 *   if (ret == ACME_ERR_AUTH_FAIL)
	 *       return -EBADMSG;
	 *   if (ret)
	 *       return -EIO;
	 */

	/* STUB: not real crypto */
	memset(out, 0xAB, 16);
	*outlen = 16;

	return 0;
}

/* ── Algorithm ops table ─────────────────────────────────────────────────── */

/*
 * example_cbc_aes_ops — ops table for "cbc(aes)".
 *
 * TODO: rename the algo string to your hardware's algorithm (e.g. "cbc(aes)")
 * and add/remove callbacks as appropriate:
 *   - Set .fips_gate = NULL if your hardware has no FIPS state to check.
 *   - Set .set_iv = NULL for hash/MAC algorithms.
 *   - Set .set_aad, .set_tag, .get_tag = NULL for non-AEAD algorithms.
 *
 * Register multiple ops tables (one per algorithm) in the algo_list below.
 */
static const struct crypto2dev_algo_ops example_cbc_aes_ops = {
	.algo       = "cbc(aes)",          /* TODO: set your algo name */
	.fips_gate  = example_fips_gate,   /* set NULL if not needed */
	.sess_init  = example_sess_init,
	.sess_free  = example_sess_free,
	.set_iv     = example_set_iv,
	.gen_iv     = example_gen_iv,
	.set_aad    = NULL,                /* not an AEAD algorithm */
	.set_tag    = NULL,
	.get_tag    = NULL,
	.sign               = NULL,
	.verify             = NULL,
	.agree              = NULL,
	.sess_reset         = example_sess_reset,
	.update             = example_update,
	.finalize           = example_finalize,
	.key_import         = NULL,
	.key_generate       = NULL,
	.key_export_public  = NULL,
	.key_export_private = NULL,
	.key_free           = NULL,
};

/* ── Provider registration ───────────────────────────────────────────────── */

static const struct crypto2dev_algo_ops *example_algo_list[] = {
	&example_cbc_aes_ops,
	/* TODO: add more ops tables here for each algorithm your hardware
	 * supports, and update num_algos below. */
	NULL,
};

static struct crypto2dev_provider example_provider = {
	.name      = "example",            /* TODO: rename to your provider */
	.algos     = example_algo_list,
	.num_algos = 1,                    /* TODO: update to match list above */
	.owner     = THIS_MODULE,
};

static int __init example_provider_init(void)
{
	int ret;

	/* TODO: initialize your hardware here (power on, load firmware,
	 * run self-tests, map MMIO, allocate DMA pools, etc.). */

	ret = crypto2dev_register_provider(&example_provider);
	if (ret) {
		pr_err("provider registration failed: %d\n", ret);
		/* TODO: undo hardware initialization on failure. */
		return ret;
	}

	pr_info("registered %u algorithm(s) [EXAMPLE — not for production]\n",
		example_provider.num_algos);
	return 0;
}

static void __exit example_provider_exit(void)
{
	crypto2dev_unregister_provider(&example_provider);

	/* TODO: shut down hardware (power off, unmap MMIO, free DMA, etc.).
	 * Existing sessions hold a module reference so this runs only after
	 * all fds using this provider have been closed. */

	pr_info("unregistered\n");
}

module_init(example_provider_init);
module_exit(example_provider_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("TODO: your name");
MODULE_DESCRIPTION("crypto2dev example provider — fork and fill in for hardware");
MODULE_VERSION("0.1");
MODULE_SOFTDEP("pre: crypto2dev");
