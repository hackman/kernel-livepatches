// License: GPL-2.0
/*
 * Livepatch mitigation for the ptrace-after-exit_mm() dumpability
 * bypass fixed upstream by:
 *
 *   commit 31e62c2ebbfd ("ptrace: slightly saner 'get_dumpable()' logic")
 *
 * See ptrace-fix-ftrace.c for the full background. Briefly: when
 * task->mm has been torn down, the original __ptrace_may_access()
 * skipped the dumpability gate entirely. Upstream caches the
 * pre-exit dumpable state in task->user_dumpable; we cannot add
 * struct fields via livepatching, so we apply a stricter mitigation:
 * when task->mm is NULL, require CAP_SYS_PTRACE in init_user_ns.
 *
 * Strategy
 * --------
 * Replace the public ptrace_may_access() with a wrapper that:
 *   1. holds task_lock(task) -- as the original does,
 *   2. denies if task->mm is NULL and the tracer lacks CAP_SYS_PTRACE,
 *   3. delegates to the original __ptrace_may_access() through a
 *      function pointer resolved at load time.
 *
 * __ptrace_may_access() is static in kernel/ptrace.c. We resolve its
 * address via the kallsyms-via-kprobes trick, which works regardless
 * of whether kallsyms_lookup_name itself is exported (the export was
 * removed in 5.7).
 *
 * Exploit PoC
 * -----------
 *  https://github.com/0xdeadbeefnetwork/ssh-keysign-pwn
 *
 * Compatibility
 * -------------
 *  - Kernels 4.11+ on x86_64. Other architectures should work but
 *    haven't been verified.
 *  - Requires CONFIG_LIVEPATCH=y and CONFIG_KPROBES=y.
 *  - The livepatch enable/unregister API changed in 5.1
 *    (commit 958ef1e39d24); both eras are handled below.
 *  - __ptrace_may_access must be present in kallsyms.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/livepatch.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>		/* task_lock on >=4.11 */
#include <linux/sched/task.h>		/* task_lock on newer trees */
#include <linux/kallsyms.h>
#include <linux/capability.h>
#include <linux/user_namespace.h>
#include <linux/errno.h>
#include <linux/version.h>

/*
 * On kernels < 5.7, kallsyms_lookup_name() is exported -- call it.
 * On >= 5.7 the export was removed; fall back to the kprobe trick.
 * Some 5.4-era kernels also reject kprobing kallsyms_lookup_name
 * (NOKPROBE_SYMBOL or KPROBES_ON_FTRACE=n -> register_kprobe returns
 * -ENOSYS), so prefer the direct call wherever possible.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
# include <linux/kprobes.h>
# define NEED_KPROBE_FALLBACK 1
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marian Marinov");
MODULE_DESCRIPTION("Livepatch for ptrace-after-exit_mm bypass");
MODULE_INFO(livepatch, "Y");

// Address of the static __ptrace_may_access(); resolved at init.
static int (*orig_inner)(struct task_struct *task, unsigned int mode);

typedef unsigned long (*kln_t)(const char *);

static kln_t resolve_kln(void)
{
#ifdef NEED_KPROBE_FALLBACK
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	kln_t fn;
	int ret;

	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("ptrace-fix-lp: register_kprobe(kallsyms_lookup_name) failed: %d\n",
		       ret);
		pr_err("ptrace-fix-lp: pass the address explicitly via the 'kln_addr' parameter as a fallback\n");
		return NULL;
	}
	fn = (kln_t)kp.addr;
	unregister_kprobe(&kp);
	return fn;
#else
	/* kallsyms_lookup_name is still exported on <5.7. */
	return (kln_t)kallsyms_lookup_name;
#endif
}

/*
 * Last-resort escape hatch: if neither kallsyms_lookup_name is exported
 * nor a kprobe on it can be registered, the user can pass the address
 * of __ptrace_may_access directly:
 *   insmod ptrace-fix-livepatch.ko ptrace_addr=0xffffffff812a0bf0
 * (read it from /proc/kallsyms; needs root and !kptr_restrict).
 */
static unsigned long ptrace_addr;
module_param(ptrace_addr, ulong, 0);
MODULE_PARM_DESC(ptrace_addr, "Address of __ptrace_may_access (override; 0=auto)");

// the replacement function
static bool patched_ptrace_may_access(struct task_struct *task,
				      unsigned int mode)
{
	int err;
	bool deny_no_mm;

	task_lock(task);

	/*
	 * Extra guard not present in pre-fix kernels: a torn-down mm
	 * is no longer trusted to imply "previously dumpable". Require
	 * the tracer to hold CAP_SYS_PTRACE globally. Same-thread-group
	 * accesses are still allowed by the original via the early
	 * same_thread_group(task, current) short-circuit, so we don't
	 * need to special-case them here.
	 */
	deny_no_mm = !task->mm &&
		     !same_thread_group(task, current) &&
		     !ns_capable(&init_user_ns, CAP_SYS_PTRACE);
	if (deny_no_mm) {
		task_unlock(task);
		return false;
	}

	err = orig_inner(task, mode);
	task_unlock(task);
	return !err;
}

static struct klp_func funcs[] = {
	{
		.old_name = "ptrace_may_access",
		.new_func = patched_ptrace_may_access,
	},
	{ }
};

static struct klp_object objs[] = {
	{ .funcs = funcs },		// .name = NULL -> vmlinux
	{ }
};

static struct klp_patch patch = {
	.mod  = THIS_MODULE,
	.objs = objs,
};

static int __init ptrace_lp_init(void)
{
	unsigned long addr = ptrace_addr;
	int ret;

	if (!addr) {
		kln_t kln = resolve_kln();
		if (!kln)
			return -ENOENT;
		addr = kln("__ptrace_may_access");
		if (!addr) {
			pr_err("ptrace-fix-lp: __ptrace_may_access not in kallsyms\n");
			return -ENOENT;
		}
	}
	orig_inner = (typeof(orig_inner))addr;
	pr_info("ptrace-fix-lp: __ptrace_may_access at %px\n", (void *)addr);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
	// Modern API: enable does everything; cannot rmmod while enabled.
	ret = klp_enable_patch(&patch);
#else
	// Pre-5.1: register-then-enable, both undoable from module_exit.
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
		pr_err("ptrace-fix-lp: klp_enable_patch failed: %d\n", ret);
		return ret;
	}

	pr_info("ptrace-fix-lp: ptrace_may_access patched; "
		"NULL-mm ptrace now requires CAP_SYS_PTRACE\n");
	return 0;
}

static void __exit ptrace_lp_exit(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
	/*
	 * Modern livepatch: disable via sysfs *before* rmmod:
	 *   echo 0 > /sys/kernel/livepatch/ptrace_fix_livepatch/enabled
	 * Wait for .../transition to read 0, then rmmod.
	 */
#else
	klp_disable_patch(&patch);
	klp_unregister_patch(&patch);
#endif
}

module_init(ptrace_lp_init);
module_exit(ptrace_lp_exit);
