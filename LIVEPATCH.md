# Linux Kernel Livepatching

This is an introduction to the Linux kernel Live Patching mechanism.

In this guide we will create a fictional module [`tcp-connect-logger.c`](tcp-connect-logger.c)
which will help us illustrate the mechanics and the process of creating
a livepatch module for the linux kernel.

What this fictional module will do is wrap `tcp_v4_connect()` with a 
sysfs-toggled connection logger, without rebooting or recompiling the 
kernel.

---

## 1. What livepatching is

Livepatching lets a kernel module replace a function in the running
kernel — without rebooting, without unloading the original code, and
without stopping the workload. The original use case was applying
security CVEs to long-uptime servers; the same mechanism is equally
useful for in-place instrumentation, debugging, and back-porting fixes.

The kernel itself has a number of hardcoded values, livepatching allows
for those values to be modified without rebooting. This technique was
mainly used by hackers in the pre-livepatch kernel days.

The infrastructure lives in `kernel/livepatch/` and is enabled with
`CONFIG_LIVEPATCH=y`. On x86_64 it also implies
`CONFIG_DYNAMIC_FTRACE_WITH_REGS=y` and `CONFIG_HAVE_RELIABLE_STACKTRACE=y`.
Distros that ship with kpatch (RHEL, SUSE) all have it on.

### How it works under the hood

Three things you should know:

1. **It rides on ftrace.** Each patched function gets an
   `FTRACE_OPS_FL_IPMODIFY` hook installed at its fentry NOP. When the
   function is called, the trampoline rewrites `%rip` to point at your
   replacement. The original code is never deleted; it just stops being
   reached.

2. **Only one IPMODIFY hook per function.** Two livepatches, or a
   livepatch plus an ftrace IPMODIFY user, cannot target the same
   function simultaneously. The second one fails with `-EBUSY`.

3. **Per-task consistency model.** Switching from "old function" to
   "new function" is not instantaneous. The kernel migrates each task
   only when it's safe — when that task's stack does not contain a
   frame belonging to the patched function. Until every task has
   migrated, the patch is "in transition" and both versions of the
   function are reachable (different callers see different versions).
   This is what `/sys/kernel/livepatch/<name>/transition` reflects:
   `1` while migrating, `0` when complete.

### The data model

A livepatch module declares three nested structures:

```text
struct klp_patch
   .mod   = THIS_MODULE
   .objs  -> array of klp_object, NULL-terminated
                 .name  = "module_name" or NULL for vmlinux
                 .funcs -> array of klp_func, NULL-terminated
                              .old_name = "function_to_patch"
                              .new_func = pointer_to_replacement
```

You hand the top-level `struct klp_patch` to `klp_enable_patch()` (or
`klp_register_patch()` + `klp_enable_patch()` on kernels < 5.1). The
livepatch core resolves each `old_name` via kallsyms, arms ftrace, and
starts the per-task transition.

### Lifecycle and the sysfs interface

After a successful `klp_enable_patch()`, the patch shows up at:

```text
/sys/kernel/livepatch/<modname>/
├── enabled            # 1 = patch active, 0 = inactive
├── transition         # 1 = migration in progress, 0 = settled
├── force              # write 1 to force-finish a stuck transition (taints)
└── <object>/
    └── <function>/
        ├── patched
        └── sympos
```

To remove a livepatch module you must:

1. Write `0` to `enabled`.
2. Poll `transition` until it reads `0`.
3. `rmmod` the module.

The module's own `module_exit` cannot disable the patch — by design,
since you might still have tasks executing inside the replacement.

### Requirements at a glance

| Requirement | Reason |
|---|---|
| `CONFIG_LIVEPATCH=y` | the infrastructure itself |
| `CONFIG_KALLSYMS_ALL=y` | symbol resolution for `klp_func.old_name` |
| `CONFIG_DYNAMIC_FTRACE_WITH_REGS=y` | underlying redirect mechanism |
| `CONFIG_HAVE_RELIABLE_STACKTRACE=y` | per-task consistency model |
| `MODULE_LICENSE("GPL")` | `klp_enable_patch` is `EXPORT_SYMBOL_GPL` |
| `MODULE_INFO(livepatch, "Y")` | tells the loader this is a livepatch module |

---

## 2. Tutorial/Step-by-step guide: a TCP-connect logger

**Goal**: every time a userspace program calls `connect()` over an IPv4
TCP socket, log the destination address, port, and the calling process
to dmesg — but only when explicitly enabled.

**Target function**: `tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)`
in `net/ipv4/tcp_ipv4.c`. It runs once per outbound IPv4 TCP connection
attempt, with the destination address already copied from userspace. Low
volume, useful data, returns `int`.

**Control**: a single boolean at `/sys/kernel/tcp_connect_logger/enabled`,
default `0`.

The pieces:

```text
1. Resolve the original tcp_v4_connect address (livepatch replaces
   the function but our wrapper still needs to call it).
2. Define a replacement that conditionally logs, then calls the original.
3. Wire that replacement into klp_patch / klp_object / klp_func.
4. Expose a sysfs toggle.
5. klp_enable_patch().
```

### 2.1 Headers

```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/livepatch.h>     // klp_patch / klp_object / klp_func
#include <linux/kallsyms.h>      // kallsyms_lookup_name on <5.7
#include <linux/kobject.h>       // sysfs kobject
#include <linux/sysfs.h>         // sysfs_create_group
#include <linux/version.h>
#include <linux/in.h>            // sockaddr_in
#include <linux/sched.h>         // current
#include <net/sock.h>            // struct sock
```

### 2.2 Resolving the original function

Livepatch will install our replacement *in place of* `tcp_v4_connect` —
which means a naked call to `tcp_v4_connect` from inside our replacement
would call **us**, looping. We need to call the *original* code.
Livepatch doesn't expose an "original pointer" by design, so we resolve
it ourselves via kallsyms.

The mechanics differ by kernel version:

- **< 5.7**: `kallsyms_lookup_name()` is exported. Just call it.
- **>= 5.7**: the export was removed. Use a kprobe to obtain the function's
  address from kallsyms.

```c
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
# include <linux/kprobes.h>
# define NEED_KPROBE_FALLBACK 1
#endif

typedef unsigned long (*kln_t)(const char *);

static kln_t resolve_kln(void)
{
#ifdef NEED_KPROBE_FALLBACK
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    kln_t fn;
    int ret = register_kprobe(&kp);
    if (ret < 0) return NULL;
    fn = (kln_t)kp.addr;
    unregister_kprobe(&kp);
    return fn;
#else
    return (kln_t)kallsyms_lookup_name;
#endif
}
```

The kprobe trick works because kprobes *also* uses kallsyms internally
to resolve `symbol_name`, so registering a probe gives us the resolved
address as a side effect.

### 2.3 The original-function pointer and the toggle

```c
static int (*orig_tcp_v4_connect)(struct sock *sk,
                                  struct sockaddr *uaddr,
                                  int addr_len);

static int logging_enabled;     // default 0
```

A plain `int` with `READ_ONCE`/`WRITE_ONCE` on both sides is fine for a
single boolean. `atomic_t` would work too but adds nothing here.

### 2.4 The replacement function

The replacement must have **exactly** the original signature, including
the return type. Livepatch installs your function at the original's
fentry site and the caller jumps to it expecting that calling
convention; mismatches corrupt the stack.

```c
static int patched_tcp_v4_connect(struct sock *sk,
                                  struct sockaddr *uaddr,
                                  int addr_len)
{
    if (READ_ONCE(logging_enabled) && uaddr &&
        addr_len >= (int)sizeof(struct sockaddr_in)) {
        struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
        if (sin->sin_family == AF_INET) {
            pr_info("tcp_connect_logger: pid=%d uid=%u comm=%s -> %pI4:%u\n",
                    current->pid,
                    from_kuid(&init_user_ns, current_uid()),
                    current->comm,
                    &sin->sin_addr, ntohs(sin->sin_port));
        }
    }
    return orig_tcp_v4_connect(sk, uaddr, addr_len);
}
```

Notes:

- The `uaddr` was already copied from userspace by `__sys_connect()`
  before TCP sees it, so it's safe to dereference here.
- `%pI4` is `printk`'s IPv4 format specifier — give it the address of
  the `__be32` and it prints `1.2.3.4`.
- We always delegate to `orig_tcp_v4_connect`. Even when logging is on,
  we just observe; we don't alter behavior.

### 2.5 Livepatch wiring

```c
static struct klp_func funcs[] = {
    {
        .old_name = "tcp_v4_connect",
        .new_func = patched_tcp_v4_connect,
    },
    { }     // terminator
};

static struct klp_object objs[] = {
    { .funcs = funcs },     // .name = NULL -> vmlinux
    { }                     // terminator
};

static struct klp_patch patch = {
    .mod  = THIS_MODULE,
    .objs = objs,
};
```

These structures are not const — livepatch writes back into them
(transition state, internal bookkeeping). Keep them static at file
scope.

The `.name = NULL` in `objs[0]` means "the symbol lives in vmlinux."
If you were patching a function in a loadable module (e.g.
`nf_conntrack`), you'd set `.name = "nf_conntrack"`. Livepatch
supports patching not-yet-loaded modules: when the named module
loads later, the patch is applied to it then.

### 2.6 Sysfs control

We create a kobject under `/sys/kernel/` and expose one read/write
attribute:

```c
static ssize_t enabled_show(struct kobject *kobj,
                            struct kobj_attribute *attr, char *buf)
{
    return sysfs_emit(buf, "%d\n", READ_ONCE(logging_enabled));
}

static ssize_t enabled_store(struct kobject *kobj,
                             struct kobj_attribute *attr,
                             const char *buf, size_t count)
{
    int v, err;
    err = kstrtoint(buf, 10, &v);
    if (err) return err;
    WRITE_ONCE(logging_enabled, !!v);
    return count;
}

static struct kobj_attribute enabled_attr =
    __ATTR(enabled, 0644, enabled_show, enabled_store);

static struct attribute *tcl_attrs[] = { &enabled_attr.attr, NULL };
static const struct attribute_group tcl_group = { .attrs = tcl_attrs };
static struct kobject *tcl_kobj;
```

The mode `0644` means owner can write, others can read. If you want
only root to be able to toggle, use `0600`.

Registration at init time:

```c
tcl_kobj = kobject_create_and_add("tcp_connect_logger", kernel_kobj);
if (!tcl_kobj) return -ENOMEM;
ret = sysfs_create_group(tcl_kobj, &tcl_group);
```

The path becomes `/sys/kernel/tcp_connect_logger/enabled`. `kernel_kobj`
is the kobject backing `/sys/kernel/`; passing `NULL` as the parent
would put it directly under `/sys/`, which the kernel discourages.

### 2.7 Init and exit

```c
static int __init tcl_init(void)
{
    kln_t kln;
    unsigned long addr;
    int ret;

    // (1) Resolve the original function.
    kln = resolve_kln();
    if (!kln) return -ENOENT;
    addr = kln("tcp_v4_connect");
    if (!addr) return -ENOENT;
    orig_tcp_v4_connect = (typeof(orig_tcp_v4_connect))addr;

    // (2) Set up sysfs.
    tcl_kobj = kobject_create_and_add("tcp_connect_logger", kernel_kobj);
    if (!tcl_kobj) return -ENOMEM;
    ret = sysfs_create_group(tcl_kobj, &tcl_group);
    if (ret) {
        kobject_put(tcl_kobj);
        return ret;
    }

    // (3) Enable the patch.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
    ret = klp_enable_patch(&patch);
#else
    ret = klp_register_patch(&patch);
    if (!ret) {
        ret = klp_enable_patch(&patch);
        if (ret) klp_unregister_patch(&patch);
    }
#endif
    if (ret) {
        sysfs_remove_group(tcl_kobj, &tcl_group);
        kobject_put(tcl_kobj);
        return ret;
    }

    pr_info("tcp_connect_logger: loaded, logging disabled\n");
    return 0;
}

static void __exit tcl_exit(void)
{
    sysfs_remove_group(tcl_kobj, &tcl_group);
    kobject_put(tcl_kobj);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
    klp_disable_patch(&patch);
    klp_unregister_patch(&patch);
#endif
}
```

Two version-conditioned paths:

- **5.1+**: `klp_enable_patch()` does registration + enable atomically.
  The module cannot run `tcl_exit` until the patch has been disabled
  via sysfs (see "Unloading" below). So `tcl_exit` only needs to tear
  down the sysfs files.
- **< 5.1**: separate `klp_register_patch` + `klp_enable_patch` calls.
  The module *can* run its exit handler while the patch is active, and
  must explicitly disable + unregister.

### 2.8 Build, load, exercise

A minimal kbuild Makefile (the repo's `Makefile` already includes
`tcp-connect-logger.o`; this is the standalone equivalent):

```make
obj-m := tcp-connect-logger.o
KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
```

Build and load:

```sh
$ make
$ sudo insmod tcp-connect-logger.ko
$ dmesg | tail -2
[ 1042.117] livepatch: enabling patch 'tcp_connect_logger'
[ 1042.119] tcp_connect_logger: loaded, logging disabled
```

Verify the patch is live and the transition has finished:

```sh
$ cat /sys/kernel/livepatch/tcp_connect_logger/enabled
1
$ cat /sys/kernel/livepatch/tcp_connect_logger/transition
0
$ cat /sys/kernel/livepatch/tcp_connect_logger/vmlinux/tcp_v4_connect/patched
1
```

Turn logging on, generate a connection:

```sh
$ echo 1 | sudo tee /sys/kernel/tcp_connect_logger/enabled
$ curl -s http://example.com >/dev/null
$ dmesg | tail -1
[ 1130.045] tcp_connect_logger: pid=8421 uid=1053 comm=curl -> 93.184.216.34:80
```

Turn it back off:

```sh
$ echo 0 | sudo tee /sys/kernel/tcp_connect_logger/enabled
```

### 2.9 Unloading

This is where livepatch modules differ from ordinary ones. On 5.1+:

```sh
# Disable the patch
$ echo 0 | sudo tee /sys/kernel/livepatch/tcp_connect_logger/enabled
# Wait for every task to migrate off the old/new function
$ while [ "$(cat /sys/kernel/livepatch/tcp_connect_logger/transition)" = "1" ]; do
>   sleep 1
> done
# Now the module is unbusy and can be removed
$ sudo rmmod tcp_connect_logger
```

If a task is permanently stuck inside the patched function and the
transition never completes, you can force it (taints the kernel):

```sh
$ echo 1 | sudo tee /sys/kernel/livepatch/tcp_connect_logger/force
```

On kernels < 5.1, `rmmod` Just Works — the exit handler disables and
unregisters the patch synchronously.

---

## 3. Caveats and common pitfalls

- **Signature must match exactly.** Livepatch calls your replacement
  in place of the original. Mismatched return type or argument list
  corrupts the stack. If the function changed signature across kernel
  versions, your module needs version conditionals.

- **Static symbols may have name collisions.** If two functions named
  `foo` exist in vmlinux (different translation units), livepatch
  refuses to patch them by name alone — you must set
  `klp_func.sympos = N` to pick the Nth occurrence (1-based, as it
  appears in `/proc/kallsyms`).

- **Macros are not patchable.** Anything inlined at the call site has
  no symbol to patch. Check `grep ' tcp_v4_connect$' /proc/kallsyms`
  before relying on the function being patchable; if it's missing,
  it was inlined or removed.

- **Patching not-yet-loaded modules works.** Set
  `klp_object.name = "foo"` for a module that may load later. The
  livepatch core records the pending patch and applies it on the next
  load of `foo`. The patch is removed automatically on `rmmod foo`.

- **You can't add fields to existing kernel structs.** Livepatch only
  redirects code. If a CVE fix adds a new struct field, you have to
  approximate around the missing storage (this is why the
  `ptrace-fix-livepatch.c` in this repo applies a stricter check than
  upstream — see [`README.md`](README.md#ptrace-exit_mm-dumpability-mitigation)).

- **Shadow variables exist for the above.** `linux/livepatch.h` exposes
  `klp_shadow_alloc/get/free` — a per-(object,id) keyed hash that
  livepatches can use as out-of-band per-instance storage when they
  *need* a new field. It's clunkier than adding a struct member but
  doesn't require kernel ABI changes.

- **IPMODIFY is single-owner.** Two livepatches cannot patch the same
  function. Neither can a livepatch and an ftrace IPMODIFY hook
  (e.g. the `ptrace-fix-ftrace.c` and `ptrace-fix-livepatch.c` in this
  repo cannot both be loaded against the same target).

- **Hot-path overhead is real but small.** A patched function pays
  one trampoline (~ftrace overhead) per call. For something called
  millions of times per second, profile before deploying.

- **Reliable stacktrace requirements.** The per-task consistency model
  needs the architecture to provide reliable unwinding (frame pointers
  via `STACK_VALIDATION`, or ORC on x86_64 with objtool). On
  architectures without reliable stacktraces, the transition may stall
  longer.

---

## 4. Further reading

- `Documentation/livepatch/livepatch.rst` in the kernel tree — the
  authoritative reference.
- `Documentation/livepatch/cumulative-patches.rst` — atomic replace
  mode, used when you want a new patch to fully supersede an older
  one in one operation.
- `Documentation/livepatch/shadow-vars.rst` — adding storage without
  changing struct layout.
- `samples/livepatch/` in the kernel tree — small, runnable examples.
- `kpatch` and `klp-build` projects — toolchains that generate livepatch
  modules automatically from a source diff.
