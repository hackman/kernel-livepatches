// SPDX-License-Identifier: GPL-2.0
/*
 * Livepatch for CVE-2026-46242: BadEpoll struct eventpoll / struct file
 * use-after-free in ep_remove().
 *
 * Upstream fix:
 *   commit a6dc643c69311677c574a0f17a3f4d66a5f3744b
 *   ("eventpoll: fix ep_remove struct eventpoll / struct file UAF")
 *   fs/eventpoll.c
 *
 * Bug
 * ---
 * Pre-fix ep_remove() acquired &file->f_lock with file = epi->ffd.file,
 * then called ep_remove_file() which clears file->f_ep under that
 * spinlock. 
 * The function kept using @file inside that critical section
 * (is_file_epoll, hlist_del_rcu via the file's hlist_head, the trailing
 * spin_unlock). 
 * A concurrent __fput() that observed the transient f_ep==NULL took 
 * the eventpoll_release() fastpath, skipped eventpoll_release_file(), 
 * and ran on to f_op->release / file_free().
 *
 * For the epoll-watches-epoll case, f_op->release is
 * ep_eventpoll_release() -> ep_clear_and_put() -> ep_free(), which
 * kfree()'s the watched struct eventpoll. Its embedded ->refs
 * hlist_head is precisely where epi->fllink.pprev points, so the
 * subsequent hlist_del_rcu()'s "*pprev = next" store scribbles into
 * freed kmalloc-192 memory.
 *
 * In addition, struct file is SLAB_TYPESAFE_BY_RCU, so the slot
 * backing @file can be recycled by alloc_empty_file() - reinitialising
 * f_lock and f_ep, while ep_remove() is still nominally inside that
 * lock, yielding an attacker-controllable kmem_cache_free() against
 * the wrong slab cache.
 *
 * Fix: pin @file via epi_fget() at the top of ep_remove() and gate the
 * critical section on the pin succeeding. The pin keeps @file (and
 * transitively the watched struct eventpoll, via its f_op->release
 * chain) alive across hlist_del_rcu() and the f_lock window, closing
 * both UAFs. The redundant epi->dying re-check under f_lock is dropped:
 * a successful pin proves we are not racing eventpoll_release_file()
 * on this epi. The cheap lockless READ_ONCE(epi->dying) fast-path
 * bailout stays.
 *
 * If epi_fget() fails, @file has already reached refcount zero and its
 * __fput() is in flight; that path takes the slow eventpoll_release()
 * route into eventpoll_release_file() and blocks on ep->mtx until the
 * waiter side's ep_clear_and_put() drops it. The bailed epi's share of
 * ep->refcount is left intact so the trailing ep_refcount_dec_and_test()
 * in ep_clear_and_put() cannot free the eventpoll out from under
 * eventpoll_release_file().
 *
 * Affected range
 * --------------
 * The bug was introduced by commit 58c9b016e128 ("epoll: use refcount
 * to reduce ep_mutex contention", v6.4) - the same commit that added
 * struct epitem::dying and the racy refcount-based teardown. Pre-v6.4
 * kernels have none of dying / epi_fget() / ep_refcount_dec_and_test()
 * and are not vulnerable. This module supports v6.4+ only and rejects
 * older trees at build time.
 *
 * Target object
 * -------------
 * ep_remove lives in fs/eventpoll.c which is built into vmlinux
 * (epoll cannot be a module), so klp_object.name is NULL.
 *
 * Static helpers
 * --------------
 * There are a lot of static defintions in eventpoll.c so we have to 
 * bring them all here in order to build the correct livepatch.
 * ep_unregister_pollwait, epi_fget, ep_remove_file, ep_remove_epi, and
 * ep_refcount_dec_and_test are all file-static in fs/eventpoll.c.
 * They are resolved by name via a kprobe on kallsyms_lookup_name
 * (kallsyms_lookup_name has not been EXPORT'd since v5.7) and called
 * through function pointers. Each address is overridable via a module
 * parameter for the case where kallsyms resolution fails.
 *
 * Compatibility
 * -------------
 *  - Linux v6.4 or newer (enforced by #error below)
 *	- Tested only on v6.10+ kernels, but should work on v6.4+
 *  - CONFIG_LIVEPATCH=y, CONFIG_KPROBES=y
 *  - All five static helpers must be present in kallsyms; verify with:
 *      for s in ep_unregister_pollwait epi_fget ep_remove_file \
 *               ep_remove_epi ep_refcount_dec_and_test; do
 *          grep " $s\$" /proc/kallsyms; done
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/livepatch.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>
#include <linux/compiler.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
# error "CVE-2026-46242 does not affect kernels prior to 6.4.0"
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marian Marinov");
MODULE_DESCRIPTION("Livepatch for CVE-2026-46242 (BadEpoll ep_remove UAF)");
MODULE_INFO(livepatch, "Y");

/*
 * Private fs/eventpoll.c types - re-declared because neither
 * struct epitem nor struct eppoll_entry are exposed in any kernel
 * header. Layout mirrors the in-kernel object on v6.4+; the dying
 * field's position (immediately after ffd) is set by 58c9b016e128
 * and unchanged since.
 */
struct eventpoll;		// opaque; only passed through
struct eppoll_entry;	// opaque; pointer-typed field only

struct epoll_filefd {
	struct file	*file;
	int		fd;
} __packed;

struct epitem {
	union {
		struct rb_node		rbn;
		struct rcu_head		rcu;
	};
	struct list_head		rdllink;
	struct epitem			*next;
	struct epoll_filefd		ffd;
	bool				dying;
	struct eppoll_entry		*pwqlist;
	struct eventpoll		*ep;
	struct hlist_node		fllink;
	struct wakeup_source __rcu	*ws;
	struct epoll_event		event;
};

typedef unsigned long (*kln_t)(const char *);

static kln_t resolve_kln(void)
{
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	kln_t fn;
	int ret;

	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("badepoll-cve-2026-46242: register_kprobe(kallsyms_lookup_name) failed: %d\n",
		       ret);
		pr_err("badepoll-cve-2026-46242: pass *_addr= module params as a fallback\n");
		return NULL;
	}
	fn = (kln_t)kp.addr;
	unregister_kprobe(&kp);
	return fn;
}

// Indirect calls into fs/eventpoll.c's file-static helpers.
static void        (*ep_unregister_pollwait_fn)(struct eventpoll *ep,
						struct epitem *epi);
static struct file *(*epi_fget_fn)(const struct epitem *epi);
static void        (*ep_remove_file_fn)(struct eventpoll *ep,
					struct epitem *epi,
					struct file *file);
static bool        (*ep_remove_epi_fn)(struct eventpoll *ep,
				       struct epitem *epi);
static bool        (*ep_refcount_dec_and_test_fn)(struct eventpoll *ep);

// Operator overrides for the case where kallsyms is stripped or denied. 
static unsigned long ep_unregister_pollwait_addr;
static unsigned long epi_fget_addr;
static unsigned long ep_remove_file_addr;
static unsigned long ep_remove_epi_addr;
static unsigned long ep_refcount_dec_and_test_addr;

module_param(ep_unregister_pollwait_addr, ulong, 0);
MODULE_PARM_DESC(ep_unregister_pollwait_addr,
	"Address of ep_unregister_pollwait (0 = auto via kallsyms)");
module_param(epi_fget_addr, ulong, 0);
MODULE_PARM_DESC(epi_fget_addr,
	"Address of epi_fget (0 = auto via kallsyms)");
module_param(ep_remove_file_addr, ulong, 0);
MODULE_PARM_DESC(ep_remove_file_addr,
	"Address of ep_remove_file (0 = auto via kallsyms)");
module_param(ep_remove_epi_addr, ulong, 0);
MODULE_PARM_DESC(ep_remove_epi_addr,
	"Address of ep_remove_epi (0 = auto via kallsyms)");
module_param(ep_refcount_dec_and_test_addr, ulong, 0);
MODULE_PARM_DESC(ep_refcount_dec_and_test_addr,
	"Address of ep_refcount_dec_and_test (0 = auto via kallsyms)");

/*
 * Patched ep_remove() - mirrors upstream
 * a6dc643c69311677c574a0f17a3f4d66a5f3744b.
 *
 * Pin @file via epi_fget() before touching &file->f_lock; bail if the
 * pin fails (the slow eventpoll_release_file() path will clean up).
 * ep_remove_file() releases &file->f_lock internally. The pinning
 * reference is released by fput() at function exit; ep_remove_file()
 * does not consume it.
 *
 * The upstream uses `struct file *file __free(fput) = NULL;` - the
 * scope-based cleanup attribute from <linux/cleanup.h>. We drop the
 * pin manually with fput() instead, which is equivalent here because
 * the function has a single successful-pin return path.
 *
 * The lockdep_assert_* calls in the upstream are debug-only and rely
 * on private struct fields (ep->mtx); we omit them.
 */
static void patched_ep_remove(struct eventpoll *ep, struct epitem *epi)
{
	struct file *file;

	ep_unregister_pollwait_fn(ep, epi);

	/* cheap sync with eventpoll_release_file() */
	if (unlikely(READ_ONCE(epi->dying)))
		return;

	/*
	 * If we manage to grab a reference it means we're not in
	 * eventpoll_release_file() and aren't going to be.
	 */
	file = epi_fget_fn(epi);
	if (!file)
		return;

	spin_lock(&file->f_lock);
	ep_remove_file_fn(ep, epi, file);	/* releases f_lock */

	if (ep_remove_epi_fn(ep, epi))
		WARN_ON_ONCE(ep_refcount_dec_and_test_fn(ep));

	fput(file);
}

static struct klp_func funcs[] = {
	{
		.old_name = "ep_remove",
		.new_func = patched_ep_remove,
	},
	{ }
};

static struct klp_object objs[] = {
	{
		// fs/eventpoll.c is built into vmlinux.
		.name  = NULL,
		.funcs = funcs,
	},
	{ }
};

static struct klp_patch patch = {
	.mod  = THIS_MODULE,
	.objs = objs,
};

struct sym_resolve {
	const char		 *name;
	unsigned long	  override;
	void			**target;
};

static int resolve_symbols(void)
{
	struct sym_resolve syms[] = {
		{ "ep_unregister_pollwait",
		  ep_unregister_pollwait_addr,
		  (void **)&ep_unregister_pollwait_fn },
		{ "epi_fget",
		  epi_fget_addr,
		  (void **)&epi_fget_fn },
		{ "ep_remove_file",
		  ep_remove_file_addr,
		  (void **)&ep_remove_file_fn },
		{ "ep_remove_epi",
		  ep_remove_epi_addr,
		  (void **)&ep_remove_epi_fn },
		{ "ep_refcount_dec_and_test",
		  ep_refcount_dec_and_test_addr,
		  (void **)&ep_refcount_dec_and_test_fn },
	};
	kln_t kln = NULL;
	int i;

	for (i = 0; i < ARRAY_SIZE(syms); i++) {
		unsigned long addr = syms[i].override;

		if (!addr) {
			if (!kln) {
				kln = resolve_kln();
				if (!kln)
					return -ENOENT;
			}
			addr = kln(syms[i].name);
			if (!addr) {
				pr_err("badepoll-cve-2026-46242: %s not in kallsyms\n",
				       syms[i].name);
				return -ENOENT;
			}
		}
		*syms[i].target = (void *)addr;
		pr_info("badepoll-cve-2026-46242: %s at %px\n",
			syms[i].name, (void *)addr);
	}
	return 0;
}

static int __init badepoll_lp_init(void)
{
	int ret;

	ret = resolve_symbols();
	if (ret)
		return ret;

	ret = klp_enable_patch(&patch);
	if (ret) {
		pr_err("badepoll-cve-2026-46242: klp_enable_patch failed: %d\n",
		       ret);
		return ret;
	}

	pr_info("badepoll-cve-2026-46242: ep_remove patched\n");
	return 0;
}

static void __exit badepoll_lp_exit(void)
{
	/*
	 * Modern livepatch: disable via sysfs *before* rmmod:
	 *   echo 0 > /sys/kernel/livepatch/badepoll_livepatch/enabled
	 * Wait for .../transition to read 0, then rmmod.
	 */
}

module_init(badepoll_lp_init);
module_exit(badepoll_lp_exit);
