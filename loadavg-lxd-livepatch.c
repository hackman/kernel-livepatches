// SPDX-License-Identifier: GPL-2.0
/*
 * Livepatch: replace sysinfo(2) so the three load values come from
 * /proc/loadavg as seen in the calling process's mount namespace.
 *
 * Rationale
 *   In containerised setups (e.g. LXC + lxcfs) /proc/loadavg is
 *   bind-mounted from a FUSE filesystem that reports container-local
 *   load averages. Programs that read /proc/loadavg directly see
 *   those values, but sysinfo(2) reads the kernel's global avenrun[]
 *   and so returns host values. This patch makes sysinfo(2) consult
 *   the same /proc/loadavg the caller would have read, so the two
 *   sources agree.
 *
 *   filp_open() resolves "/proc/loadavg" through current->fs->root,
 *   i.e. the mount namespace of the calling task, so each caller
 *   sees exactly what its own namespace exposes.
 *
 * Implementation notes
 *   - Patches __x64_sys_sysinfo (x86_64 SysV syscall entry stub).
 *     32-bit compat callers via __ia32_compat_sys_sysinfo are NOT
 *     patched here.
 *   - The non-loadavg fields are rebuilt from EXPORT_SYMBOL'd APIs:
 *     ktime_get_boottime_ts64 (uptime) and si_meminfo (RAM). Swap
 *     fields (totalswap/freeswap) are left at zero because
 *     si_swapinfo() is not exported in this kernel. The mem_unit
 *     overflow-scaling loop mirrors do_sysinfo() in kernel/sys.c.
 *   - The 'procs' field is taken from the 4th column of
 *     /proc/loadavg ("nr_running/nr_threads"), whose denominator is
 *     exactly the global nr_threads the kernel would have used.
 *     This avoids a dependency on the non-exported nr_threads symbol
 *     and is also namespace-consistent with the load fields.
 *   - Time namespaces (timens_add_boottime) are not adjusted here:
 *     uptime always reflects host boottime. Fix this only if your
 *     workload actually uses time namespaces.
 *
 * Requires CONFIG_LIVEPATCH=y.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/livepatch.h>
#include <linux/sysinfo.h>
#include <linux/mm.h>
#include <linux/timekeeping.h>
#include <linux/time.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <asm/ptrace.h>

struct lp_loadavg {
	unsigned long loads[3];	// fixed-point, scaled by 1 << SI_LOAD_SHIFT
	unsigned long procs;	// nr_threads (denominator of "R/T")
};

/*
 * Read /proc/loadavg in the current task's mount namespace and parse
 * out loadavg + nr_threads. Returns 0 on success, negative errno on
 * any failure (open, read, or parse). On failure *out is left zeroed.
 */
static int lp_read_loadavg(struct lp_loadavg *out)
{
	struct file *f;
	char buf[96];
	loff_t pos = 0;
	ssize_t n;
	unsigned long w[3], fr[3];
	unsigned long running, threads;
	int got, i;

	memset(out, 0, sizeof(*out));

	f = filp_open("/proc/loadavg", O_RDONLY, 0);
	if (IS_ERR(f))
		return PTR_ERR(f);

	n = kernel_read(f, buf, sizeof(buf) - 1, &pos);
	filp_close(f, NULL);
	if (n <= 0)
		return n < 0 ? (int)n : -EIO;
	buf[n] = '\0';

	// /proc/loadavg format: "X.XX Y.YY Z.ZZ R/T LASTPID\n" 
	got = sscanf(buf, "%lu.%lu %lu.%lu %lu.%lu %lu/%lu",
		     &w[0], &fr[0], &w[1], &fr[1], &w[2], &fr[2],
		     &running, &threads);
	if (got < 8)
		return -EINVAL;

	for (i = 0; i < 3; i++)
		out->loads[i] = (w[i] << SI_LOAD_SHIFT) +
				((fr[i] << SI_LOAD_SHIFT) / 100);
	out->procs = threads;
	return 0;
}

/*
 * Replacement for __x64_sys_sysinfo(). Mirrors do_sysinfo() in
 * kernel/sys.c except loads (and procs) come from /proc/loadavg.
 */
static long notrace lp_sys_sysinfo(const struct pt_regs *regs)
{
	struct sysinfo __user *info = (struct sysinfo __user *)regs->di;
	struct sysinfo val;
	struct timespec64 tp;
	struct lp_loadavg la;
	unsigned long mem_total, sav_total;
	unsigned int mem_unit, bitcount;

	memset(&val, 0, sizeof(val));

	/*
	 * If /proc/loadavg can't be read in the caller's mount namespace
	 * (procfs not mounted, FUSE backend dead, permission denied,
	 * malformed contents, ...), return an all-zero struct sysinfo.
	 * Do this BEFORE populating any other field so a failure leaves
	 * the entire structure zeroed.
	 */
	if (lp_read_loadavg(&la) != 0)
		goto out;

	val.loads[0] = la.loads[0];
	val.loads[1] = la.loads[1];
	val.loads[2] = la.loads[2];
	val.procs    = (__u16)la.procs;

	ktime_get_boottime_ts64(&tp);
	val.uptime = tp.tv_sec + (tp.tv_nsec ? 1 : 0);

	si_meminfo(&val);
	/* si_swapinfo() is not EXPORT_SYMBOL'd on this kernel; leave
	 * val.totalswap and val.freeswap at their memset()-zero values.
	 */

	// Same mem_unit scaling loop as kernel's do_sysinfo().
	mem_total = val.totalram + val.totalswap;
	if (mem_total < val.totalram || mem_total < val.totalswap)
		goto out;
	bitcount = 0;
	mem_unit = val.mem_unit;
	while (mem_unit > 1) {
		bitcount++;
		mem_unit >>= 1;
		sav_total = mem_total;
		mem_total <<= 1;
		if (mem_total < sav_total)
			goto out;
	}
	val.mem_unit  = 1;
	val.totalram  <<= bitcount;
	val.freeram   <<= bitcount;
	val.sharedram <<= bitcount;
	val.bufferram <<= bitcount;
	val.totalswap <<= bitcount;
	val.freeswap  <<= bitcount;
	val.totalhigh <<= bitcount;
	val.freehigh  <<= bitcount;

out:
	if (copy_to_user(info, &val, sizeof(val)))
		return -EFAULT;
	return 0;
}

static struct klp_func funcs[] = {
	{
		.old_name = "__x64_sys_sysinfo",
		.new_func = lp_sys_sysinfo,
	},
	{ }
};

static struct klp_object objs[] = {
	{
		// .name = NULL  =>  symbol lives in vmlinux
		.funcs = funcs,
	},
	{ }
};

static struct klp_patch patch = {
	.mod  = THIS_MODULE,
	.objs = objs,
};

static int __init lp_loadavg_init(void)
{
	int ret = klp_enable_patch(&patch);

	if (ret) {
		pr_err("livepatch_loadavg: klp_enable_patch failed: %d\n", ret);
		return ret;
	}
	pr_info("livepatch_loadavg: sysinfo() loadavg now sourced from /proc/loadavg in caller's mount ns\n");
	return 0;
}

static void __exit lp_loadavg_exit(void)
{
	/*
	 * Reached only after the patch has been disabled via sysfs:
	 *   echo 0 > /sys/kernel/livepatch/livepatch_loadavg/enabled
	 *   (wait for .../transition to read 0)
	 *   rmmod livepatch_loadavg
	 */
}

module_init(lp_loadavg_init);
module_exit(lp_loadavg_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marian Marinov");
MODULE_DESCRIPTION("Livepatch: sysinfo(2) loadavg fields come from /proc/loadavg in caller's mount namespace");
MODULE_INFO(livepatch, "Y");
