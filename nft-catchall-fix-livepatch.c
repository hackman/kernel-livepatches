// SPDX-License-Identifier: GPL-2.0
/*
 * Livepatch for CVE-2026-23111: use-after-free in
 * nft_map_catchall_activate() via inverted genmask check.
 *
 * Upstream fix:
 *   commit f41c5d151078c5348271ffaf8e7410d96f2d82f8
 *   net/netfilter/nf_tables_api.c
 *
 * Bug
 * ---
 * The pre-fix nft_map_catchall_activate() walked set->catchall_list
 * with an inverted active-bit check:
 *
 *     if (!nft_set_elem_active(ext, genmask))
 *         continue;
 *
 * On the DELSET abort path this skips the catchall element that needs
 * re-activation and instead falls through on already-active (or no)
 * elements. For map elements carrying NFT_GOTO verdicts, the missed
 * call to nft_setelem_data_activate() means chain->use is never
 * restored. Repeating the create/abort cycle drives chain->use to
 * zero; a subsequent DELCHAIN then frees the chain while a catchall
 * element still references it -> UAF on struct nft_chain.
 *
 * Fix: drop the '!'.
 *
 *     if (nft_set_elem_active(ext, genmask))
 *         continue;
 *
 * Reconstruction caveat
 * ---------------------
 * The verbatim body of nft_map_catchall_activate() was not available
 * at write time (kernel.org cgit blocked, and the GitHub mirror
 * summarised rather than quoted). The non-conditional lines below
 * are reconstructed by symmetry from nft_map_catchall_deactivate(),
 * which *was* available verbatim, and from standard nf_tables
 * activate/deactivate symmetry (nft_clear + nft_setelem_data_activate
 * mirrors nft_set_elem_change_active + nft_setelem_data_deactivate).
 *
 * BEFORE DEPLOYING: diff this against your kernel's actual
 * pre-fix function body. If any non-conditional line differs,
 * update accordingly or use kpatch-build against commit
 * f41c5d151078 -- that produces a bit-exact replacement.
 *
 * Static helpers
 * --------------
 * nft_setelem_data_activate() is non-static and declared in
 * <net/netfilter/nf_tables.h>, but on many builds it is not
 * EXPORT_SYMBOL_GPL'd, so this module resolves it via
 * kallsyms-through-kprobes (same pattern as ptrace-fix-livepatch.c)
 * rather than relying on the linker.
 *
 * Target object
 * -------------
 * nf_tables_api.c builds into the nf_tables module on most distros
 * (CONFIG_NF_TABLES=m). If your kernel has CONFIG_NF_TABLES=y, change
 * klp_object.name to NULL so the patch attaches to vmlinux.
 *
 * Compatibility
 * -------------
 *  - CONFIG_LIVEPATCH=y, CONFIG_KPROBES=y
 *  - Modern (>=5.1) and legacy livepatch APIs both handled.
 *  - nft_map_catchall_activate must be present in kallsyms; verify
 *    with: grep nft_map_catchall_activate /proc/kallsyms
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/livepatch.h>
#include <linux/list.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/errno.h>
#include <net/netfilter/nf_tables.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
# include <linux/kprobes.h>
# define NEED_KPROBE_FALLBACK 1
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marian Marinov");
MODULE_DESCRIPTION("Livepatch for CVE-2026-23111 (nf_tables catchall UAF)");
MODULE_INFO(livepatch, "Y");

static void (*nft_setelem_data_activate_fn)(const struct net *net,
					    const struct nft_set *set,
					    struct nft_elem_priv *elem_priv);

typedef unsigned long (*kln_t)(const char *);

static kln_t resolve_kln(void)
{
#ifdef NEED_KPROBE_FALLBACK
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	kln_t fn;
	int ret;

	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("nft-cve-2026-23111: register_kprobe(kallsyms_lookup_name) failed: %d\n",
		       ret);
		pr_err("nft-cve-2026-23111: pass activate_addr= as a fallback\n");
		return NULL;
	}
	fn = (kln_t)kp.addr;
	unregister_kprobe(&kp);
	return fn;
#else
	return (kln_t)kallsyms_lookup_name;
#endif
}

static unsigned long activate_addr;
module_param(activate_addr, ulong, 0);
MODULE_PARM_DESC(activate_addr,
	"Address of nft_setelem_data_activate (override; 0=auto via kallsyms)");

static void patched_nft_map_catchall_activate(const struct nft_ctx *ctx,
					      struct nft_set *set)
{
	u8 genmask = nft_genmask_next(ctx->net);
	struct nft_set_elem_catchall *catchall;
	struct nft_set_ext *ext;

	list_for_each_entry(catchall, &set->catchall_list, list) {
		ext = nft_set_elem_ext(set, catchall->elem);
		/*
		 * CVE-2026-23111 fix: drop the '!'. Skip already-active
		 * elements; process the inactive catchall that the abort
		 * path needs to re-activate.
		 */
		if (nft_set_elem_active(ext, genmask))
			continue;

		nft_clear(ctx->net, ext);
		nft_setelem_data_activate_fn(ctx->net, set, catchall->elem);
		break;
	}
}

static struct klp_func funcs[] = {
	{
		.old_name = "nft_map_catchall_activate",
		.new_func = patched_nft_map_catchall_activate,
	},
	{ }
};

static struct klp_object objs[] = {
	{
		// CONFIG_NF_TABLES=y systems: set .name = NULL for vmlinux
		.name  = "nf_tables",
		.funcs = funcs,
	},
	{ }
};

static struct klp_patch patch = {
	.mod  = THIS_MODULE,
	.objs = objs,
};

static int __init nft_lp_init(void)
{
	unsigned long addr = activate_addr;
	int ret;

	if (!addr) {
		kln_t kln = resolve_kln();
		if (!kln)
			return -ENOENT;
		addr = kln("nft_setelem_data_activate");
		if (!addr) {
			pr_err("nft-cve-2026-23111: nft_setelem_data_activate not in kallsyms\n");
			return -ENOENT;
		}
	}
	nft_setelem_data_activate_fn =
		(typeof(nft_setelem_data_activate_fn))addr;
	pr_info("nft-cve-2026-23111: nft_setelem_data_activate at %px\n",
		(void *)addr);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
	ret = klp_enable_patch(&patch);
#else
	ret = klp_register_patch(&patch);
	if (ret)
		return ret;
	ret = klp_enable_patch(&patch);
	if (ret) {
		klp_unregister_patch(&patch);
		return ret;
	}
#endif

	if (ret) {
		pr_err("nft-cve-2026-23111: klp_enable_patch failed: %d\n",
		       ret);
		return ret;
	}

	pr_info("nft-cve-2026-23111: nft_map_catchall_activate patched\n");
	return 0;
}

static void __exit nft_lp_exit(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
	/*
	 * Modern livepatch: disable via sysfs *before* rmmod:
	 *   echo 0 > /sys/kernel/livepatch/nft_catchall_fix_livepatch/enabled
	 * Wait for .../transition to read 0, then rmmod.
	 */
#else
	klp_disable_patch(&patch);
	klp_unregister_patch(&patch);
#endif
}

module_init(nft_lp_init);
module_exit(nft_lp_exit);
