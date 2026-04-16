// SPDX-License-Identifier: GPL-2.0-only
/*
 * crypto2dev_registry.c — provider registry for crypto2dev
 *
 * Maintains an ordered list of registered crypto providers. Algorithm lookup
 * returns the first provider whose algo_ops matches the requested name
 * (first-registered wins within a provider name filter). On lookup, the
 * matching provider's module refcount is incremented so it cannot be unloaded
 * while a session is live.
 *
 * Locking: a single rwlock protects the provider list.
 *   - Readers (lookup, count, fips_aggregate): hold read lock.
 *   - Writers (register/unregister): hold write lock.
 *
 * This file is compiled into crypto2dev.ko, not into any provider module.
 */

#include <linux/atomic.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/rwlock.h>
#include <linux/string.h>
#include <linux/slab.h>

#include "../../include/crypto2dev_provider.h"
#include "../../include/uapi/crypto2dev_ioctl.h"

static LIST_HEAD(provider_list);
static DEFINE_RWLOCK(provider_lock);

/*
 * fips_provider_count: number of currently registered FIPS providers.
 * When nonzero, crypto2dev_lookup_algo() skips all non-FIPS providers —
 * the hard filter is an operational requirement of FIPS 140-3.
 *
 * Activation: incremented when the first is_fips=1 provider registers.
 * Deactivation: decremented when a FIPS provider unregisters; FIPS
 * enforcement ends when the count returns to zero. The ONLY way to
 * deactivate FIPS enforcement is to unload all FIPS provider modules
 * (e.g., rmmod crypto2dev_wolfssl.ko). There is intentionally no runtime
 * toggle, sysctl knob, or ioctl to disable FIPS mode while a FIPS
 * provider is loaded — that would void CMVP certification.
 *
 * How to disable FIPS / turn off FIPS mode / fips toggle:
 *   rmmod crypto2dev_wolfssl   (or whichever FIPS provider is loaded)
 * There is no flag, sysctl, or ioctl. Disabling FIPS at runtime while a
 * FIPS provider is loaded would void CMVP certification. This is by design.
 */
static atomic_t fips_provider_count = ATOMIC_INIT(0);

/**
 * crypto2dev_register_provider - add a provider to the registry.
 *
 * Appends @p to the tail of the provider list. If p->is_fips, increments
 * the FIPS provider counter, enabling FIPS enforcement for all lookups.
 * Emits a diagnostic when a FIPS and non-FIPS provider share an algorithm.
 *
 * The caller MUST NOT modify any field of @p after this call returns — the
 * struct is live in the registry and its fields (is_fips, algos, num_algos,
 * name, owner) are read under the read lock by concurrent lookups. The list
 * node (p->list) is owned by the registry until crypto2dev_unregister_provider().
 * The parameter cannot be const because INIT_LIST_HEAD and list_add_tail must
 * write to p->list; all other fields are treated as read-only once registered.
 */
int crypto2dev_register_provider(struct crypto2dev_provider *p)
{
	u32 i;
	struct crypto2dev_provider *existing;

	if (!p || !p->name || !p->algos || !p->owner)
		return -EINVAL;

	for (i = 0; i < p->num_algos; i++) {
		if (!p->algos[i] || !p->algos[i]->algo) {
			pr_err("crypto2dev: provider \"%s\" algo[%u] is NULL\n",
			       p->name, i);
			return -EINVAL;
		}
		/*
		 * Backstop: PBKDF2 providers must declare SP 800-132 minimums
		 * via ops->min_iterations and ops->min_salt_len.  The framework
		 * enforces these in ioctl_do_kdf only if the provider declares
		 * them.  A provider that omits them silently bypasses the limits.
		 */
		if (strstr(p->algos[i]->algo, "pbkdf2")) {
			/* Use pr_warn, not WARN: this is a soft diagnostic.
			 * WARN() is a BUG-family macro that prints a stack
			 * trace and may halt on CONFIG_BUG_ON_WARN=y kernels,
			 * causing insmod to fail for a misconfigured provider —
			 * the opposite of what a backstop should do.
			 * The framework enforces the limits in ioctl_do_kdf;
			 * registration is defense-in-depth only.
			 */
			if (p->algos[i]->min_iterations < 1000)
				pr_warn("crypto2dev: provider \"%s\" algo \"%s\": min_iterations=%u < 1000 (SP 800-132 §5.2 violation)\n",
					p->name, p->algos[i]->algo,
					p->algos[i]->min_iterations);
			if (p->algos[i]->min_salt_len < 16)
				pr_warn("crypto2dev: provider \"%s\" algo \"%s\": min_salt_len=%u < 16 (SP 800-132 §5.1 violation)\n",
					p->name, p->algos[i]->algo,
					p->algos[i]->min_salt_len);
		}
	}

	write_lock(&provider_lock);

	list_for_each_entry(existing, &provider_list, list) {
		u32 j;

		for (i = 0; i < p->num_algos; i++) {
			for (j = 0; j < existing->num_algos; j++) {
				if (strcmp(p->algos[i]->algo,
					   existing->algos[j]->algo) != 0)
					continue;
				if (p->is_fips != existing->is_fips)
					pr_info("crypto2dev: algo \"%s\" registered by both FIPS provider \"%s\" and non-FIPS provider \"%s\"\n",
						p->algos[i]->algo,
						p->is_fips ? p->name : existing->name,
						p->is_fips ? existing->name : p->name);
				else
					pr_warn("crypto2dev: provider \"%s\" algo \"%s\" also registered by \"%s\"\n",
						p->name, p->algos[i]->algo,
						existing->name);
			}
		}
	}

	INIT_LIST_HEAD(&p->list);
	list_add_tail(&p->list, &provider_list);
	if (p->is_fips)
		atomic_inc(&fips_provider_count);

	write_unlock(&provider_lock);

	if (p->is_fips)
		pr_info("crypto2dev: registered FIPS provider \"%s\" (%u algo(s)) — FIPS enforcement active\n",
			p->name, p->num_algos);
	else
		pr_info("crypto2dev: registered provider \"%s\" (%u algo(s))\n",
			p->name, p->num_algos);

	return 0;
}
EXPORT_SYMBOL_GPL(crypto2dev_register_provider);

/**
 * crypto2dev_unregister_provider - remove a provider from the registry.
 *
 * After this call returns, no new sessions will be dispatched to @p's algos.
 * Existing sessions that already hold a module reference continue until closed.
 */
void crypto2dev_unregister_provider(struct crypto2dev_provider *p)
{
	if (!p)
		return;

	write_lock(&provider_lock);
	list_del(&p->list);
	if (p->is_fips) {
		/* atomic_dec_if_positive, not atomic_dec: if the count is already 0
		 * (double-unregister or provider bug), atomic_dec would take it to -1,
		 * causing (count > 0) to return false and silently disabling FIPS-only
		 * dispatch with no visible symptom — a CMVP compliance failure.
		 * atomic_dec_if_positive returns -1 without decrementing, and the WARN
		 * fires. Do not change to atomic_dec(). */
		if (atomic_dec_if_positive(&fips_provider_count) < 0)
			WARN(1, "crypto2dev: FIPS provider count underflow — \"%s\" unregistered multiple times?\n",
			     p->name);
	}
	write_unlock(&provider_lock);

	if (p->is_fips)
		pr_info("crypto2dev: unregistered FIPS provider \"%s\"\n",
			p->name);
	else
		pr_info("crypto2dev: unregistered provider \"%s\"\n", p->name);
}
EXPORT_SYMBOL_GPL(crypto2dev_unregister_provider);

/**
 * crypto2dev_fips_provider_loaded - test whether any FIPS provider is active.
 *
 * Returns true if at least one FIPS provider is currently registered.
 * Used by fd.c to enforce REQUIRE_FIPS semantics.
 */
bool crypto2dev_fips_provider_loaded(void)
{
	return atomic_read(&fips_provider_count) > 0;
}
EXPORT_SYMBOL_GPL(crypto2dev_fips_provider_loaded);

/**
 * crypto2dev_enumerate_providers - snapshot all registered providers.
 *
 * Fills @buf with up to @capacity entries. If @buf is NULL or @capacity is 0,
 * no data is copied; the return value indicates the total provider count.
 */
u32 crypto2dev_enumerate_providers(struct crypto2dev_provider_info *buf,
				   u32 capacity)
{
	struct crypto2dev_provider *p;
	u32 n = 0;

	read_lock(&provider_lock);

	list_for_each_entry(p, &provider_list, list) {
		if (buf && n < capacity) {
			strscpy(buf[n].name, p->name, CRYPTO2DEV_PROVIDER_MAXLEN);
			strscpy(buf[n].version, p->version ?: "(unknown)",
				CRYPTO2DEV_VERSION_MAXLEN);
			buf[n].is_fips = p->is_fips;
		}
		n++;
	}

	read_unlock(&provider_lock);
	return n;
}
EXPORT_SYMBOL_GPL(crypto2dev_enumerate_providers);

/**
 * crypto2dev_lookup_algo - find registered ops for @algo.
 *
 * If @provider is non-NULL and non-empty, only the named provider is
 * considered.
 *
 * FIPS enforcement: if any FIPS provider is currently registered
 * (fips_provider_count > 0), non-FIPS providers are invisible to this
 * function regardless of load order or explicit provider name. This prevents
 * silent FIPS bypass — once FIPS providers are present, every algo dispatch
 * goes through them or fails.
 *
 * On success, increments the matching provider's module refcount via
 * try_module_get() and stores the module pointer in *owner_module.
 * The caller must call module_put(*owner_module) when the session is freed.
 *
 * Returns the algo_ops pointer, or NULL if no matching provider is found.
 */
const struct crypto2dev_algo_ops *crypto2dev_lookup_algo(
	const char *algo, const char *provider,
	struct module **owner_module,
	const char **provider_name_out)
{
	struct crypto2dev_provider *p;
	const struct crypto2dev_algo_ops *ops = NULL;
	const char *skipped_non_fips = NULL;
	bool filter_provider;
	bool fips_mode;
	u32 i;

	if (!algo || !owner_module)
		return NULL;

	*owner_module = NULL;
	if (provider_name_out)
		*provider_name_out = NULL;
	filter_provider = provider && provider[0] != '\0';

	read_lock(&provider_lock);

	/*
	 * Read fips_provider_count under provider_lock (read side).
	 * fips_provider_count is an atomic_t updated under write_lock in
	 * register/unregister, so reads here are consistent with the provider
	 * list state — there is no TOCTOU between "is FIPS active?" and
	 * "which provider am I dispatching to?".  The atomic_t avoids the
	 * need for a separate lock: readers see a coherent value without
	 * stale observations from out-of-order stores on SMP.
	 */
	fips_mode = atomic_read(&fips_provider_count) > 0;

	list_for_each_entry(p, &provider_list, list) {
		/* Hard filter: when fips_mode is active, skip all non-FIPS providers.
		 * There is intentionally NO fallback to non-FIPS providers. A
		 * 'prefer FIPS, fall back to non-FIPS' policy would allow silent downgrade
		 * when the FIPS provider doesn't handle an algorithm — silently using
		 * unvalidated crypto. The correct failure mode is -ENOENT. Any use of a
		 * non-FIPS fallback path would void the CMVP certification for that
		 * operation. Do not add a non-FIPS fallback here. */
		if (fips_mode && !p->is_fips) {
			if (!skipped_non_fips)
				skipped_non_fips = p->name;
			continue;
		}

		if (filter_provider && strcmp(p->name, provider) != 0)
			continue;

		for (i = 0; i < p->num_algos; i++) {
			if (strcmp(p->algos[i]->algo, algo) != 0)
				continue;
			if (!try_module_get(p->owner)) {
				pr_warn_ratelimited("crypto2dev: lookup '%s': provider '%s' unloading, skipping\n",
						    algo, p->name);
				continue;
			}
			ops = p->algos[i];
			*owner_module = p->owner;
			if (provider_name_out)
				*provider_name_out = p->name;
			goto found;
		}

		/* Explicit provider requested: stop after checking it. */
		if (filter_provider)
			break;
	}

	if (fips_mode && skipped_non_fips)
		pr_info_ratelimited("crypto2dev: FIPS mode: skipped non-FIPS provider '%s' for '%s' — no FIPS provider found\n",
				    skipped_non_fips, algo);
	else if (fips_mode)
		/* No non-FIPS providers were traversed; the algo is simply
		 * absent from every registered FIPS provider. */
		pr_info_ratelimited("crypto2dev: FIPS mode: algo '%s' not found in any registered FIPS provider\n",
				    algo);

found:
	read_unlock(&provider_lock);
	return ops;
}
EXPORT_SYMBOL_GPL(crypto2dev_lookup_algo);

/**
 * crypto2dev_enumerate_algos - fill a buffer with all registered algorithm info.
 *
 * Used by the LIST_ALGOS ioctl. @buf is kernel space (caller does copy_to_user).
 * Returns total number of registered algorithms regardless of capacity.
 */
u32 crypto2dev_enumerate_algos(struct crypto2dev_algo_info *buf, u32 capacity)
{
	struct crypto2dev_provider *p;
	u32 count = 0, i;

	read_lock(&provider_lock);

	list_for_each_entry(p, &provider_list, list) {
		for (i = 0; i < p->num_algos; i++) {
			if (buf && count < capacity) {
				struct crypto2dev_algo_info *e = &buf[count];

				strscpy(e->algo, p->algos[i]->algo,
					CRYPTO2DEV_ALGO_MAXLEN);
				strscpy(e->provider, p->name,
					CRYPTO2DEV_PROVIDER_MAXLEN);
				e->has_fips_gate =
					p->algos[i]->fips_gate ? 1 : 0;
				e->has_key_ops =
					p->algos[i]->key_import ? 1 : 0;
			}
			count++;
		}
	}

	read_unlock(&provider_lock);
	return count;
}
EXPORT_SYMBOL_GPL(crypto2dev_enumerate_algos);

/**
 * crypto2dev_algo_count - return total number of registered algorithms.
 *
 * Counts the sum of num_algos across all registered providers. Duplicate
 * algo names across providers are each counted separately; the count reflects
 * the total registrations, not unique algo names.
 */
u32 crypto2dev_algo_count(void)
{
	struct crypto2dev_provider *p;
	u32 count = 0;

	read_lock(&provider_lock);
	list_for_each_entry(p, &provider_list, list)
		count += p->num_algos;
	read_unlock(&provider_lock);

	return count;
}
EXPORT_SYMBOL_GPL(crypto2dev_algo_count);

/*
 * Maximum number of distinct FIPS gate callbacks we snapshot per call.
 * In practice there will be 1–3 FIPS providers; 16 is a generous ceiling.
 */
#define CRYPTO2DEV_MAX_FIPS_GATES 16

/**
 * crypto2dev_fips_aggregate - aggregate FIPS state across all providers.
 *
 * Iterates all registered providers' fips_gate() callbacks:
 *   - If no provider has a fips_gate: CRYPTO2DEV_FIPS_NO_PROVIDER.
 *   - If all fips_gate providers return 0: CRYPTO2DEV_FIPS_OPERATIONAL.
 *   - If any fips_gate provider returns non-zero: CRYPTO2DEV_FIPS_NOT_OPERATIONAL.
 *
 * Gate callbacks are collected under the read lock and then called after
 * unlocking. This avoids calling fips_gate() under a spinlock: on PREEMPT_RT
 * the wolfssl gate emits pr_err_ratelimited() which acquires a ratelimit
 * spinlock — a lock ordering violation when provider_lock is already held.
 * A module refcount is taken for each provider before unlock so the gate
 * function cannot disappear while we call it.
 */
u32 crypto2dev_fips_aggregate(void)
{
	struct crypto2dev_provider *p;
	int (*gates[CRYPTO2DEV_MAX_FIPS_GATES])(void);
	struct module *owners[CRYPTO2DEV_MAX_FIPS_GATES];
	char  names[CRYPTO2DEV_MAX_FIPS_GATES][CRYPTO2DEV_PROVIDER_MAXLEN];
	int ngate = 0;
	bool found_fips_provider = false;
	int g;
	u32 i;

	read_lock(&provider_lock);

	list_for_each_entry(p, &provider_list, list) {
		/* Only providers with is_fips=1 are FIPS-certified providers.
		 * Non-FIPS providers may still have a fips_gate stub (returns 0),
		 * but they do not contribute to the FIPS operational state.
		 * This keeps fips_aggregate() consistent with fips_provider_loaded()
		 * which also checks is_fips. */
		if (!p->is_fips)
			continue;

		for (i = 0; i < p->num_algos; i++) {
			if (!p->algos[i]->fips_gate)
				continue;

			found_fips_provider = true;

			if (ngate < CRYPTO2DEV_MAX_FIPS_GATES &&
			    try_module_get(p->owner)) {
				gates[ngate]  = p->algos[i]->fips_gate;
				owners[ngate] = p->owner;
				strscpy(names[ngate], p->name,
					CRYPTO2DEV_PROVIDER_MAXLEN);
				ngate++;
			} else if (ngate >= CRYPTO2DEV_MAX_FIPS_GATES) {
				WARN_ONCE(1, "crypto2dev: fips_gate provider count exceeds %d — some providers not checked\n",
					  CRYPTO2DEV_MAX_FIPS_GATES);
			}

			/* One gate per provider is sufficient — they all call
			 * the same underlying module check. */
			break;
		}
	}

	read_unlock(&provider_lock);

	/*
	 * Gates are called outside provider_lock intentionally. wolfssl_fips_gate()
	 * acquires the wolfCrypt ratelimit spinlock internally (pr_err_ratelimited).
	 * Calling it under provider_lock (a rwlock) would violate lock ordering on
	 * PREEMPT_RT kernels where rwlocks are PI-aware, causing boot failures.
	 * No atomicity guarantee is needed across multiple gate calls: fips_aggregate
	 * is a snapshot query; a FIPS state change between two gate calls is safe
	 * (each subsequent operation will also check its own gate). Do not move these
	 * calls inside the lock.
	 */
	for (g = 0; g < ngate; g++) {
		int gret = gates[g]();

		module_put(owners[g]);
		if (gret != 0) {
			pr_err_ratelimited("crypto2dev: FIPS provider \"%s\" gate returned %d — NOT_OPERATIONAL\n",
					   names[g], gret);
			/* Release remaining module refs before returning. */
			for (g++; g < ngate; g++)
				module_put(owners[g]);
			return CRYPTO2DEV_FIPS_NOT_OPERATIONAL;
		}
	}

	return found_fips_provider ? CRYPTO2DEV_FIPS_OPERATIONAL
				   : CRYPTO2DEV_FIPS_NO_PROVIDER;
}
EXPORT_SYMBOL_GPL(crypto2dev_fips_aggregate);
