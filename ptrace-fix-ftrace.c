// License: GPL-2.0
/*
 * ftrace-based mitigation for the ptrace-after-exit_mm() dumpability
 * bypass fixed upstream by:
 *
 *   commit 31e62c2ebbfd ("ptrace: slightly saner 'get_dumpable()' logic")
 *
 * Background
 * ----------
 * __ptrace_may_access() used to read task->mm and, when mm was NULL,
 * silently skipped the dumpability check. A task whose mm had been
 * torn down by exit_mm() (still ptrace-attachable for a window) could
 * therefore be inspected by an unprivileged tracer even if the task's
 * original mm was not SUID_DUMP_USER. Exploited by the Qualys
 * ssh-keysign chain.
 *
 * Upstream fix adds a `task->user_dumpable:1` bit cached in exit_mm()
 * and consulted by a new helper task_still_dumpable(). Neither ftrace
 * nor livepatch can add fields to struct task_struct, so this module
 * applies the stricter half of the fix: when task->mm is NULL, deny
 * unless the tracer has CAP_SYS_PTRACE in init_user_ns. This matches
 * upstream for kernel threads and for previously-non-dumpable tasks;
 * it is stricter than upstream only for previously-DUMP_USER tasks
 * whose mm has gone away.
 *
 * Mechanism
 * ---------
 * Install one ftrace_ops (IPMODIFY + SAVE_REGS) on __ptrace_may_access.
 * The thunk reads %rdi (the `task` argument), inspects task->mm and
 * the calling thread's caps, then either:
 *   (a) leaves regs->ip alone so the original function runs normally
 *       -- this is the common case, mm intact or caller privileged;
 *   (b) rewrites regs->ip to a -EPERM stub.
 *
 * __ptrace_may_access() is called by ptrace_may_access() under
 * task_lock(task), so the task->mm load in the thunk is stable.
 *
 * Exploit PoC
 * -----------
 *  https://github.com/0xdeadbeefnetwork/ssh-keysign-pwn
 *
 * Compatibility
 * -------------
 *  - x86_64 only (uses pt_regs->di for the first argument).
 *  - Kernels 4.11+ (uses ftrace_regs API on >= 5.11, pt_regs below).
 *  - Requires CONFIG_DYNAMIC_FTRACE=y, CONFIG_FUNCTION_TRACER=y,
 *    CONFIG_DYNAMIC_FTRACE_WITH_REGS=y.
 *  - Requires that __ptrace_may_access not be inlined: check
 *      grep ' __ptrace_may_access$' /proc/kallsyms
 *    before loading. (Standard distro kernels keep it out-of-line.)
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/ftrace.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>		// same_thread_group() on newer trees
#include <linux/capability.h>
#include <linux/user_namespace.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marian Marinov");
MODULE_DESCRIPTION("ftrace mitigation for ptrace-after-exit_mm bypass");
MODULE_VERSION("0.1");

#define TARGET_SYM "__ptrace_may_access"

/*
 * struct ftrace_regs / ftrace_get_regs() landed in 5.11. Older kernels
 * pass struct pt_regs * directly to the callback.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
# define FTRACE_REGS_T          struct ftrace_regs
# define FTRACE_TO_PT_REGS(r)   ftrace_get_regs(r)
#else
# define FTRACE_REGS_T          struct pt_regs
# define FTRACE_TO_PT_REGS(r)   (r)
#endif

/*
 * -EPERM stub. Returns `long` so %rax is fully populated with the
 * sign-extended error; __ptrace_may_access() reads only %eax (int)
 * and still sees -EPERM correctly.
 */
static long notrace eperm_stub(void)
{
	return -EPERM;
}

static struct ftrace_ops ptrace_ops __read_mostly;

static void notrace ptrace_thunk(unsigned long ip,
				 unsigned long parent_ip,
				 struct ftrace_ops *ops,
				 FTRACE_REGS_T *fregs)
{
	struct pt_regs *regs = FTRACE_TO_PT_REGS(fregs);
	struct task_struct *task;

	if (unlikely(!regs))
		return;

	// Recursion guard.
	if (within_module((unsigned long)parent_ip, THIS_MODULE))
		return;

	// x86_64 SysV: first arg in %rdi. 
	task = (struct task_struct *)regs->di;
	if (!task)
		return;	// let original handle (it WARN_ON_ONCE's). 

	/*
	 * Three "let the original run" cases:
	 *   1. mm still attached      -> original logic is sufficient
	 *   2. same thread group      -> original returns 0 immediately
	 *   3. tracer has CAP_SYS_PTRACE in init_user_ns
	 * Otherwise: redirect to -EPERM stub.
	 */
	if (task->mm)
		return;
	if (same_thread_group(task, current))
		return;
	if (ns_capable(&init_user_ns, CAP_SYS_PTRACE))
		return;

	regs->ip = (unsigned long)eperm_stub;
}

static int __init ptrace_fix_init(void)
{
	int ret;

	ptrace_ops.func  = ptrace_thunk;
	ptrace_ops.flags = FTRACE_OPS_FL_SAVE_REGS |
			   FTRACE_OPS_FL_IPMODIFY;

	ret = ftrace_set_filter(&ptrace_ops, (unsigned char *)TARGET_SYM,
				strlen(TARGET_SYM), 0);
	if (ret) {
		pr_err("ptrace-fix-ftrace: ftrace_set_filter(\"%s\") failed: %d\n",
		       TARGET_SYM, ret);
		pr_err("ptrace-fix-ftrace: is %s present in /proc/kallsyms? (may be inlined)\n",
		       TARGET_SYM);
		return ret;
	}

	ret = register_ftrace_function(&ptrace_ops);
	if (ret) {
		pr_err("ptrace-fix-ftrace: register_ftrace_function failed: %d\n",
		       ret);
		ftrace_set_filter(&ptrace_ops, NULL, 0, 1);
		return ret;
	}

	pr_info("ptrace-fix-ftrace: hooked %s; "
		"NULL-mm ptrace now requires CAP_SYS_PTRACE\n", TARGET_SYM);
	return 0;
}

static void __exit ptrace_fix_exit(void)
{
	unregister_ftrace_function(&ptrace_ops);
	ftrace_set_filter(&ptrace_ops, NULL, 0, 1);
	pr_info("ptrace-fix-ftrace: unloaded\n");
}

module_init(ptrace_fix_init);
module_exit(ptrace_fix_exit);
