// SPDX-License-Identifier: GPL-2.0
/*
 * artitux_kmod - Per-process lazy XCR0=7 and UMIP SGDT/SIDT fixup module.
 *
 * Design:
 * - Zero text_poke / .noinstr patching / vmlinux profiling.
 * - Uses only standard ftrace, fprobe (with kretprobe fallback), kernel
 *   tracepoints, and user_return_notifier.
 * - Leaves XCR0=7 across fast non-FPU syscalls and IRQs; restores host XCR0
 *   lazily before context switches, kernel FPU usage, or XSAVE/XRSTOR paths,
 *   and lowers back to 7 on return to userspace via switch_fpu_return /
 *   user_return_notifier.
 * - Compatible with hardware IBT and FRED, and cleanly unloadable once no
 *   tracked tasks remain.
 */

#include <linux/atomic.h>
#include <linux/binfmts.h>
#include <linux/cpumask.h>
#include <linux/fprobe.h>
#include <linux/fs.h>
#include <linux/ftrace.h>
#include <linux/hash.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#include <linux/tracepoint.h>
#include <linux/uaccess.h>
#include <linux/user-return-notifier.h>

#include <asm/cpufeature.h>
#include <asm/fpu/types.h>
#include <asm/fpu/xcr.h>
#include <asm/msr.h>
#include <asm/prctl.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/thread_info.h>

#include "artitux_kmod.h"

#define ARTITUX_XCR0_TARGET 7ULL
#define POLICY_HASH_BITS    10
#define POLICY_HASH_SIZE    (1U << POLICY_HASH_BITS)

/* Module parameters */
static bool umip_global;
module_param(umip_global, bool, 0644);
MODULE_PARM_DESC(umip_global, "Apply UMIP SGDT/SIDT dummy_limit systemwide (default: false, per-process opt-in)");

static unsigned short umip_dummy_limit = 0x007F;
module_param(umip_dummy_limit, ushort, 0644);
MODULE_PARM_DESC(umip_dummy_limit, "16-bit descriptor table limit written for SGDT/SIDT under UMIP (default: 0x007F)");

/* Runtime state */
static u64 host_xcr0;
static bool xcr0_hook_active;
static bool umip_hook_active;
static u32 host_capabilities;

static atomic_t tracked_count = ATOMIC_INIT(0);
static atomic_t active_xcr0_count = ATOMIC_INIT(0);
static atomic_t active_umip_count = ATOMIC_INIT(0);

static DEFINE_PER_CPU(unsigned long, stat_xcr0_switches);
static DEFINE_PER_CPU(unsigned long, stat_umip_fixups);

/* Per-task policy entry (RCU-read, policy_lock-write) */
struct task_policy_node {
	struct hlist_node hnode;
	struct rcu_head rcu;
	struct task_struct *task;
	u32 pending_flags;
	u32 active_flags;
};

static struct hlist_head policy_buckets[POLICY_HASH_SIZE];
static DEFINE_RAW_SPINLOCK(policy_lock);
static struct kmem_cache *policy_cache;

/* Per-CPU lazy XCR0 state */
struct cpu_xcr0_state {
	bool task_active;    /* current task on this CPU has ARTITUX_FLAG_XCR0_7 active */
	bool hw_lowered;     /* hardware XCR0 on this CPU is currently ARTITUX_XCR0_TARGET */
	bool urn_registered; /* user_return_notifier is currently registered on this CPU */
	struct user_return_notifier urn;
};

static DEFINE_PER_CPU(struct cpu_xcr0_state, cpu_xcr0);

/* Tracepoints */
static struct tracepoint *tp_sched_switch;
static struct tracepoint *tp_sched_fork;
static struct tracepoint *tp_sched_exec;
static struct tracepoint *tp_sched_free;
static bool tp_switch_reg;
static bool tp_fork_reg;
static bool tp_exec_reg;
static bool tp_free_reg;

/* Ftrace pre-call restore hook */
static struct ftrace_ops fpu_restore_ops;
static bool fpu_restore_reg;

/* Return-aware probes (fprobe on CONFIG_FPROBE, else kretprobe) */
#ifdef CONFIG_FPROBE
static struct fprobe fp_switch_fpu;
static struct fprobe fp_xstate_prctl;
static struct fprobe fp_umip;
#else
static struct kretprobe krp_switch_fpu;
static struct kretprobe krp_xstate_prctl;
static struct kretprobe krp_umip;
#endif
static bool probe_switch_fpu_reg;
static bool probe_xstate_prctl_reg;
static bool probe_umip_reg;

/* Read-only diagnostics in /sys/module/artitux_kmod/parameters/ */
static int param_get_host_xcr0(char *buf, const struct kernel_param *kp)
{
	return scnprintf(buf, PAGE_SIZE, "0x%llx\n", host_xcr0);
}
static const struct kernel_param_ops host_xcr0_ops = { .get = param_get_host_xcr0 };
module_param_cb(host_xcr0, &host_xcr0_ops, NULL, 0444);

static int param_get_tracked(char *buf, const struct kernel_param *kp)
{
	return scnprintf(buf, PAGE_SIZE, "%d\n", atomic_read(&tracked_count));
}
static const struct kernel_param_ops tracked_ops = { .get = param_get_tracked };
module_param_cb(tracked_tasks, &tracked_ops, NULL, 0444);

static int param_get_active_xcr0(char *buf, const struct kernel_param *kp)
{
	return scnprintf(buf, PAGE_SIZE, "%d\n", atomic_read(&active_xcr0_count));
}
static const struct kernel_param_ops active_xcr0_ops = { .get = param_get_active_xcr0 };
module_param_cb(active_xcr0_tasks, &active_xcr0_ops, NULL, 0444);

static int param_get_xcr0_switches(char *buf, const struct kernel_param *kp)
{
	unsigned long total = 0;
	int cpu;

	for_each_possible_cpu(cpu)
		total += per_cpu(stat_xcr0_switches, cpu);
	return scnprintf(buf, PAGE_SIZE, "%lu\n", total);
}
static const struct kernel_param_ops xcr0_switches_ops = { .get = param_get_xcr0_switches };
module_param_cb(xcr0_switches, &xcr0_switches_ops, NULL, 0444);

static int param_get_umip_fixups(char *buf, const struct kernel_param *kp)
{
	unsigned long total = 0;
	int cpu;

	for_each_possible_cpu(cpu)
		total += per_cpu(stat_umip_fixups, cpu);
	return scnprintf(buf, PAGE_SIZE, "%lu\n", total);
}
static const struct kernel_param_ops umip_fixups_ops = { .get = param_get_umip_fixups };
module_param_cb(umip_fixups, &umip_fixups_ops, NULL, 0444);

static int param_get_switch_fpu_missed(char *buf, const struct kernel_param *kp)
{
	unsigned long missed = 0;
#ifdef CONFIG_FPROBE
	missed = fp_switch_fpu.nmissed;
#else
	missed = krp_switch_fpu.nmissed;
#endif
	return scnprintf(buf, PAGE_SIZE, "%lu\n", missed);
}
static const struct kernel_param_ops switch_fpu_missed_ops = { .get = param_get_switch_fpu_missed };
module_param_cb(switch_fpu_missed, &switch_fpu_missed_ops, NULL, 0444);

/* ---- Helpers ---- */

static inline u64 artitux_rdmsr(u32 msr)
{
	u64 val;

#ifdef rdmsrq
	rdmsrq(msr, val);
#else
	rdmsrl(msr, val);
#endif
	return val;
}

static inline struct fpu *artitux_task_fpu(struct task_struct *task)
{
#if defined(ARTITUX_HAVE_X86_TASK_FPU) && ARTITUX_HAVE_X86_TASK_FPU
	return (struct fpu *)((void *)task + sizeof(*task));
#else
	return &task->thread.fpu;
#endif
}

static void restrict_task_fpu_state(struct task_struct *task)
{
	struct fpu *fpu = artitux_task_fpu(task);

	if (fpu && fpu->fpstate)
		fpu->fpstate->user_xfeatures &= ARTITUX_XCR0_TARGET;
	if (fpu)
		fpu->perm.__state_perm &= ARTITUX_XCR0_TARGET;
}

static void policy_node_free_rcu(struct rcu_head *head)
{
	struct task_policy_node *node = container_of(head, struct task_policy_node, rcu);

	kmem_cache_free(policy_cache, node);
}

/* Lockless RCU lookup of a task's flags. Safe in any normal/IRQ/sched context. */
static u32 lookup_task_active_flags(struct task_struct *task)
{
	struct hlist_head *bucket;
	struct task_policy_node *node;
	u32 flags = 0;

	if (likely(atomic_read(&tracked_count) == 0))
		return 0;

	bucket = &policy_buckets[hash_ptr(task, POLICY_HASH_BITS)];
	rcu_read_lock();
	hlist_for_each_entry_rcu(node, bucket, hnode) {
		if (node->task == task) {
			flags = READ_ONCE(node->active_flags);
			break;
		}
	}
	rcu_read_unlock();
	return flags;
}

static void lookup_task_both_flags(struct task_struct *task, u32 *active_out, u32 *pending_out)
{
	struct hlist_head *bucket;
	struct task_policy_node *node;
	u32 active = 0, pending = 0;

	if (atomic_read(&tracked_count) != 0) {
		bucket = &policy_buckets[hash_ptr(task, POLICY_HASH_BITS)];
		rcu_read_lock();
		hlist_for_each_entry_rcu(node, bucket, hnode) {
			if (node->task == task) {
				active = READ_ONCE(node->active_flags);
				pending = READ_ONCE(node->pending_flags);
				break;
			}
		}
		rcu_read_unlock();
	}
	*active_out = active;
	*pending_out = pending;
}

static struct task_policy_node *find_node_locked(struct task_struct *task)
{
	struct hlist_head *bucket = &policy_buckets[hash_ptr(task, POLICY_HASH_BITS)];
	struct task_policy_node *node;

	hlist_for_each_entry(node, bucket, hnode) {
		if (node->task == task)
			return node;
	}
	return NULL;
}

static void update_flag_counters_locked(u32 old_active, u32 new_active)
{
	bool old_xcr0 = !!(old_active & ARTITUX_FLAG_XCR0_7);
	bool new_xcr0 = !!(new_active & ARTITUX_FLAG_XCR0_7);
	bool old_umip = !!(old_active & ARTITUX_FLAG_UMIP);
	bool new_umip = !!(new_active & ARTITUX_FLAG_UMIP);

	if (!old_xcr0 && new_xcr0)
		atomic_inc(&active_xcr0_count);
	else if (old_xcr0 && !new_xcr0)
		atomic_dec(&active_xcr0_count);

	if (!old_umip && new_umip)
		atomic_inc(&active_umip_count);
	else if (old_umip && !new_umip)
		atomic_dec(&active_umip_count);
}

/*
 * Insert or update policy for @task.
 * If both @active_flags and @pending_flags are 0, removes the entry.
 */
static int set_task_policy(struct task_struct *task, u32 active_flags, u32 pending_flags)
{
	struct task_policy_node *node, *fresh = NULL;
	unsigned long irqflags;
	bool put_mod = false;

	if (active_flags || pending_flags) {
		fresh = kmem_cache_alloc(policy_cache, GFP_ATOMIC);
		if (!fresh)
			return -ENOMEM;
	}

	raw_spin_lock_irqsave(&policy_lock, irqflags);
	node = find_node_locked(task);

	if (!active_flags && !pending_flags) {
		if (node) {
			update_flag_counters_locked(node->active_flags, 0);
			hlist_del_rcu(&node->hnode);
			if (atomic_dec_and_test(&tracked_count))
				put_mod = true;
			call_rcu(&node->rcu, policy_node_free_rcu);
		}
		raw_spin_unlock_irqrestore(&policy_lock, irqflags);
		if (fresh)
			kmem_cache_free(policy_cache, fresh);
		if (put_mod)
			module_put(THIS_MODULE);
		return 0;
	}

	if (node) {
		update_flag_counters_locked(node->active_flags, active_flags);
		WRITE_ONCE(node->active_flags, active_flags);
		WRITE_ONCE(node->pending_flags, pending_flags);
		raw_spin_unlock_irqrestore(&policy_lock, irqflags);
		kmem_cache_free(policy_cache, fresh);
		return 0;
	}

	fresh->task = task;
	fresh->active_flags = active_flags;
	fresh->pending_flags = pending_flags;
	hlist_add_head_rcu(&fresh->hnode, &policy_buckets[hash_ptr(task, POLICY_HASH_BITS)]);
	if (atomic_inc_return(&tracked_count) == 1)
		__module_get(THIS_MODULE);
	update_flag_counters_locked(0, active_flags);
	raw_spin_unlock_irqrestore(&policy_lock, irqflags);
	return 0;
}

/* ---- Lazy XCR0 Engine ---- */

static void xcr0_on_user_return(struct user_return_notifier *urn)
{
	struct cpu_xcr0_state *st = container_of(urn, struct cpu_xcr0_state, urn);

	/* Always unregister ourselves on this CPU. */
	user_return_notifier_unregister(urn);
	st->urn_registered = false;

	/*
	 * If TIF_NEED_FPU_LOAD is set, switch_fpu_return() runs right after us
	 * in arch_exit_work() and needs host_xcr0 for XRSTORS; its exit probe
	 * will lower XCR0 to 7 immediately afterward.
	 */
	if (st->task_active && !test_thread_flag(TIF_NEED_FPU_LOAD) && !st->hw_lowered) {
		xsetbv(XCR_XFEATURE_ENABLED_MASK, ARTITUX_XCR0_TARGET);
		st->hw_lowered = true;
		this_cpu_inc(stat_xcr0_switches);
	}
}

static __always_inline void ensure_kernel_xcr0(bool arm_reapply)
{
	struct cpu_xcr0_state *st;
	unsigned long flags;

	/* Fast path: unrelated tasks/CPUs have both hw_lowered and task_active false. */
	if (likely(!this_cpu_read(cpu_xcr0.hw_lowered) &&
		   !(arm_reapply && this_cpu_read(cpu_xcr0.task_active))))
		return;

	local_irq_save(flags);
	st = this_cpu_ptr(&cpu_xcr0);
	if (st->hw_lowered) {
		xsetbv(XCR_XFEATURE_ENABLED_MASK, host_xcr0);
		st->hw_lowered = false;
	}
	/*
	 * Arm user_return_notifier even if hw_lowered was already false:
	 * functions like fpu__clear_user_states / fpu__restore_sig /
	 * fpregs_mark_activate load FPU state directly and clear
	 * TIF_NEED_FPU_LOAD, bypassing switch_fpu_return() on exit.
	 */
	if (arm_reapply && st->task_active && !st->urn_registered) {
		user_return_notifier_register(&st->urn);
		st->urn_registered = true;
	}
	local_irq_restore(flags);
}

/* Plain ftrace pre-call hook for all FPU/XSAVE/XRSTOR entry points. */
static void notrace fpu_restore_ftrace_cb(unsigned long ip, unsigned long parent_ip,
					  struct ftrace_ops *ops,
					  struct ftrace_regs *fregs)
{
	ensure_kernel_xcr0(!in_interrupt());
}

/* switch_fpu_return / fpregs_restore_userregs entry & exit callbacks */
static int switch_fpu_on_entry(void)
{
	struct cpu_xcr0_state *st = this_cpu_ptr(&cpu_xcr0);

	if (unlikely(st->hw_lowered)) {
		xsetbv(XCR_XFEATURE_ENABLED_MASK, host_xcr0);
		st->hw_lowered = false;
	}
	/* Return 0 to run exit handler only when current task needs XCR0=7. */
	return st->task_active ? 0 : 1;
}

static void switch_fpu_on_exit(void)
{
	struct cpu_xcr0_state *st = this_cpu_ptr(&cpu_xcr0);

	if (likely(st->task_active) && !st->hw_lowered) {
		xsetbv(XCR_XFEATURE_ENABLED_MASK, ARTITUX_XCR0_TARGET);
		st->hw_lowered = true;
		this_cpu_inc(stat_xcr0_switches);
	}
}

/* fpu_xstate_prctl entry & exit callbacks */
struct xstate_prctl_data {
	int option;
	unsigned long arg2;
};

static int xstate_prctl_on_entry(int option, unsigned long arg2,
				 struct xstate_prctl_data *data,
				 bool *force_unsupported)
{
	if (!(lookup_task_active_flags(current) & ARTITUX_FLAG_XCR0_7))
		return 1;

	if (option == ARCH_GET_XCOMP_SUPP || option == ARCH_GET_XCOMP_PERM) {
		data->option = option;
		data->arg2 = arg2;
		return 0;
	}
	if (option == ARCH_REQ_XCOMP_PERM) {
		*force_unsupported = true;
		return 1;
	}
	return 1;
}

static void xstate_prctl_on_exit(long retval, const struct xstate_prctl_data *data)
{
	if (retval == 0 &&
	    (data->option == ARCH_GET_XCOMP_SUPP || data->option == ARCH_GET_XCOMP_PERM)) {
		u64 val = ARTITUX_XCR0_TARGET;

		if (put_user(val, (u64 __user *)data->arg2))
			pr_debug("artitux_kmod: failed to write masked XCOMP to user\n");
	}
}

/* ---- UMIP SGDT/SIDT Limit Fixup ---- */

struct umip_probe_data {
	unsigned long uaddr;
	bool valid;
};

static unsigned long pt_reg_by_idx(const struct pt_regs *regs, int idx)
{
	switch (idx) {
	case 0:  return regs->ax;
	case 1:  return regs->cx;
	case 2:  return regs->dx;
	case 3:  return regs->bx;
	case 4:  return regs->sp;
	case 5:  return regs->bp;
	case 6:  return regs->si;
	case 7:  return regs->di;
	case 8:  return regs->r8;
	case 9:  return regs->r9;
	case 10: return regs->r10;
	case 11: return regs->r11;
	case 12: return regs->r12;
	case 13: return regs->r13;
	case 14: return regs->r14;
	case 15: return regs->r15;
	default: return 0;
	}
}

/* Decode 64-bit SGDT (0F 01 /0) or SIDT (0F 01 /1) effective user address. */
static bool decode_umip_dt_addr(struct pt_regs *user_regs, unsigned long *uaddr_out)
{
	unsigned char code[15];
	int i = 0;
	int seg_ovr = 0; /* 0=none, 6=FS, 7=GS */
	int rex_b = 0, rex_x = 0;
	bool addr32 = false;
	unsigned char modrm;
	int mod, reg, rm;
	unsigned long uaddr = 0;

	if (!user_regs || !user_64bit_mode(user_regs))
		return false;

	if (copy_from_user(code, (const void __user *)user_regs->ip, sizeof(code)))
		return false;

	while (i < (int)sizeof(code)) {
		unsigned char b = code[i];

		if (b == 0x66) {
			i++;
		} else if (b == 0x67) {
			if (addr32)
				return false;
			addr32 = true;
			i++;
		} else if (b == 0x64 || b == 0x65) {
			seg_ovr = (b == 0x64) ? 6 : 7;
			i++;
		} else if (b == 0x2e || b == 0x3e || b == 0x26 || b == 0x36) {
			i++;
		} else if ((b & 0xf0) == 0x40) {
			rex_b = (b & 1) ? 8 : 0;
			rex_x = (b & 2) ? 8 : 0;
			i++;
		} else {
			break;
		}
	}

	if (i + 2 >= (int)sizeof(code) || code[i] != 0x0f || code[i + 1] != 0x01)
		return false;

	modrm = code[i + 2];
	mod = (modrm >> 6) & 3;
	reg = (modrm >> 3) & 7;
	rm  = modrm & 7;

	/* Only SGDT (reg=0) and SIDT (reg=1) with memory operand (mod!=3). */
	if ((reg != 0 && reg != 1) || mod == 3)
		return false;

	i += 3;

	if (rm == 4) {
		unsigned char sib;
		int sib_base, sib_index, sib_scale;

		if (i >= (int)sizeof(code))
			return false;
		sib = code[i++];
		sib_base  = (sib & 7) | rex_b;
		sib_index = ((sib >> 3) & 7) | rex_x;
		sib_scale = 1 << ((sib >> 6) & 3);

		if ((sib & 7) == 5 && mod == 0) {
			s32 disp32;

			if (i + 4 > (int)sizeof(code))
				return false;
			memcpy(&disp32, &code[i], 4);
			i += 4;
			uaddr = (unsigned long)(long)disp32;
			if (sib_index != 4)
				uaddr += pt_reg_by_idx(user_regs, sib_index) * (unsigned long)sib_scale;
			goto have_ea;
		}

		uaddr = pt_reg_by_idx(user_regs, sib_base);
		if (sib_index != 4)
			uaddr += pt_reg_by_idx(user_regs, sib_index) * (unsigned long)sib_scale;
	} else if (mod == 0 && rm == 5) {
		s32 disp32;

		if (i + 4 > (int)sizeof(code))
			return false;
		memcpy(&disp32, &code[i], 4);
		i += 4;
		if (addr32)
			uaddr = (unsigned long)(u32)disp32;
		else
			uaddr = (user_regs->ip + i) + (unsigned long)(long)disp32;
		goto have_ea;
	} else {
		uaddr = pt_reg_by_idx(user_regs, rm | rex_b);
	}

	if (mod == 1) {
		if (i >= (int)sizeof(code))
			return false;
		uaddr += (unsigned long)(long)(s8)code[i];
	} else if (mod == 2) {
		s32 disp32;

		if (i + 4 > (int)sizeof(code))
			return false;
		memcpy(&disp32, &code[i], 4);
		uaddr += (unsigned long)(long)disp32;
	}

have_ea:
	if (addr32)
		uaddr &= 0xffffffffUL;

	if (seg_ovr == 6 || seg_ovr == 7) {
		preempt_disable();
		if (seg_ovr == 6)
			uaddr += artitux_rdmsr(MSR_FS_BASE);
		else
			uaddr += artitux_rdmsr(MSR_KERNEL_GS_BASE);
		preempt_enable();
	}

	*uaddr_out = uaddr;
	return true;
}

static int umip_on_entry(struct pt_regs *user_regs, struct umip_probe_data *data)
{
	data->valid = false;
	data->uaddr = 0;

	if (!READ_ONCE(umip_global) &&
	    !(lookup_task_active_flags(current) & ARTITUX_FLAG_UMIP))
		return 1;

	if (!decode_umip_dt_addr(user_regs, &data->uaddr))
		return 1;

	data->valid = true;
	return 0;
}

static void umip_on_exit(unsigned long retval, const struct umip_probe_data *data)
{
	if (retval && data->valid && data->uaddr) {
		u16 limit = READ_ONCE(umip_dummy_limit);

		if (put_user(limit, (u16 __user *)data->uaddr) == 0)
			this_cpu_inc(stat_umip_fixups);
	}
}

/* ---- Probe wrappers (fprobe vs kretprobe) ---- */

#ifdef CONFIG_FPROBE

#if defined(ARTITUX_FPROBE_FTRACE_REGS) && ARTITUX_FPROBE_FTRACE_REGS
#define FP_REGS_TYPE struct ftrace_regs
#define FP_GET_ARG(r, n) ftrace_regs_get_argument((r), (n))
#define FP_GET_RET(r)    ftrace_regs_get_return_value((r))
#define FP_SET_ARG1(r, v) do { arch_ftrace_regs(r)->regs.si = (v); } while (0)
#else
#define FP_REGS_TYPE struct pt_regs
#define FP_GET_ARG(r, n) regs_get_kernel_argument((r), (n))
#define FP_GET_RET(r)    regs_return_value((r))
#define FP_SET_ARG1(r, v) do { (r)->si = (v); } while (0)
#endif

static int fp_switch_fpu_entry(struct fprobe *fp, unsigned long entry_ip,
			       unsigned long ret_ip, FP_REGS_TYPE *regs,
			       void *entry_data)
{
	return switch_fpu_on_entry();
}

static void fp_switch_fpu_exit(struct fprobe *fp, unsigned long entry_ip,
			       unsigned long ret_ip, FP_REGS_TYPE *regs,
			       void *entry_data)
{
	switch_fpu_on_exit();
}

static int fp_xstate_prctl_entry(struct fprobe *fp, unsigned long entry_ip,
				 unsigned long ret_ip, FP_REGS_TYPE *regs,
				 void *entry_data)
{
	int option = (int)FP_GET_ARG(regs, 0);
	unsigned long arg2 = FP_GET_ARG(regs, 1);
	bool force_unsupp = false;
	int ret;

	ret = xstate_prctl_on_entry(option, arg2, entry_data, &force_unsupp);
	if (force_unsupp)
		FP_SET_ARG1(regs, 63UL);
	return ret;
}

static void fp_xstate_prctl_exit(struct fprobe *fp, unsigned long entry_ip,
				 unsigned long ret_ip, FP_REGS_TYPE *regs,
				 void *entry_data)
{
	xstate_prctl_on_exit((long)FP_GET_RET(regs), entry_data);
}

static int fp_umip_entry(struct fprobe *fp, unsigned long entry_ip,
			 unsigned long ret_ip, FP_REGS_TYPE *regs,
			 void *entry_data)
{
	struct pt_regs *user_regs = (struct pt_regs *)FP_GET_ARG(regs, 0);

	return umip_on_entry(user_regs, entry_data);
}

static void fp_umip_exit(struct fprobe *fp, unsigned long entry_ip,
			 unsigned long ret_ip, FP_REGS_TYPE *regs,
			 void *entry_data)
{
	umip_on_exit(FP_GET_RET(regs), entry_data);
}

#else /* !CONFIG_FPROBE: kretprobe fallback */

static int krp_switch_fpu_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return switch_fpu_on_entry();
}

static int krp_switch_fpu_exit(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	switch_fpu_on_exit();
	return 0;
}

static int krp_xstate_prctl_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	bool force_unsupp = false;
	int ret;

	ret = xstate_prctl_on_entry((int)regs->di, regs->si,
				    (struct xstate_prctl_data *)ri->data,
				    &force_unsupp);
	if (force_unsupp)
		regs->si = 63UL;
	return ret;
}

static int krp_xstate_prctl_exit(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	xstate_prctl_on_exit((long)regs_return_value(regs),
			     (const struct xstate_prctl_data *)ri->data);
	return 0;
}

static int krp_umip_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return umip_on_entry((struct pt_regs *)regs->di,
			     (struct umip_probe_data *)ri->data);
}

static int krp_umip_exit(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	umip_on_exit(regs_return_value(regs), (const struct umip_probe_data *)ri->data);
	return 0;
}

#endif /* CONFIG_FPROBE */

/* ---- Tracepoint probes ---- */

static void tp_on_sched_switch(void *data, bool preempt,
			       struct task_struct *prev,
			       struct task_struct *next,
			       unsigned int prev_state)
{
	struct cpu_xcr0_state *st = this_cpu_ptr(&cpu_xcr0);
	bool next_active;

	/* Always restore host XCR0 before switch_fpu(prev) runs XSAVES. */
	if (unlikely(st->hw_lowered)) {
		xsetbv(XCR_XFEATURE_ENABLED_MASK, host_xcr0);
		st->hw_lowered = false;
	}

	if (likely(atomic_read(&active_xcr0_count) == 0)) {
		st->task_active = false;
		return;
	}

	next_active = !!(lookup_task_active_flags(next) & ARTITUX_FLAG_XCR0_7);
	st->task_active = next_active;

	/*
	 * Normally next already has TIF_NEED_FPU_LOAD set (from switch_fpu or
	 * fpu_clone), so switch_fpu_return() will lower XCR0 on user exit.
	 * Belt-and-suspenders: if TIF_NEED_FPU_LOAD is somehow clear on next,
	 * arm user_return_notifier (propagate_user_return_notify moves it to next).
	 */
	if (unlikely(next_active && !test_tsk_thread_flag(next, TIF_NEED_FPU_LOAD))) {
		if (!st->urn_registered) {
			user_return_notifier_register(&st->urn);
			st->urn_registered = true;
		}
	}
}

static void tp_on_sched_fork(void *data, struct task_struct *parent,
			     struct task_struct *child)
{
	u32 active, pending;

	if (likely(atomic_read(&tracked_count) == 0))
		return;

	if (child->flags & (PF_KTHREAD | PF_USER_WORKER))
		return;

	lookup_task_both_flags(parent, &active, &pending);
	if (!active && !pending)
		return;

	if (set_task_policy(child, active, pending) == 0) {
		if (xcr0_hook_active && (active & ARTITUX_FLAG_XCR0_7))
			restrict_task_fpu_state(child);
	}
}

static void tp_on_sched_exec(void *data, struct task_struct *task,
			     pid_t old_pid, struct linux_binprm *bprm)
{
	u32 active, pending, merged;

	if (likely(atomic_read(&tracked_count) == 0))
		return;

	lookup_task_both_flags(task, &active, &pending);
	if (!active && !pending)
		return;

	merged = active | pending;
	if (set_task_policy(task, merged, 0) != 0)
		return;

	if (xcr0_hook_active && (merged & ARTITUX_FLAG_XCR0_7)) {
		struct cpu_xcr0_state *st;
		unsigned long irqflags;

		restrict_task_fpu_state(task);

		local_irq_save(irqflags);
		st = this_cpu_ptr(&cpu_xcr0);
		st->task_active = true;
		if (!st->hw_lowered && !st->urn_registered) {
			user_return_notifier_register(&st->urn);
			st->urn_registered = true;
		}
		local_irq_restore(irqflags);
	}
}

static void tp_on_sched_free(void *data, struct task_struct *task)
{
	if (likely(atomic_read(&tracked_count) == 0))
		return;

	set_task_policy(task, 0, 0);
}

/* ---- /dev/artitux character device ---- */

static int arm_current_exec_flags(u32 req_flags)
{
	u32 active, pending;

	if (req_flags & ~ARTITUX_FLAG_ALL)
		return -EINVAL;
	if ((req_flags & ARTITUX_FLAG_XCR0_7) &&
	    !xcr0_hook_active && host_xcr0 != ARTITUX_XCR0_TARGET)
		return -ENODEV;

	lookup_task_both_flags(current, &active, &pending);
	if ((active & ARTITUX_FLAG_XCR0_7) && !(req_flags & ARTITUX_FLAG_XCR0_7))
		return -EPERM;

	/*
	 * If host XCR0 is already 7 natively, keep the flag for status
	 * consistency without touching hardware XCR0.
	 */
	return set_task_policy(current, active, req_flags & ~active);
}

static ssize_t artitux_read(struct file *file, char __user *buf,
			    size_t count, loff_t *ppos)
{
	char out[192];
	u32 active, pending;
	int len;

	lookup_task_both_flags(current, &active, &pending);
	len = scnprintf(out, sizeof(out),
			"abi=%u host_xcr0=0x%llx caps=0x%x umip=%u xcr0_hook=%u xcr0_native=%u tracked=%d active_xcr0=%d active=0x%x pending=0x%x\n",
			ARTITUX_KMOD_ABI_VERSION,
			host_xcr0,
			host_capabilities,
			!!(host_capabilities & ARTITUX_CAP_UMIP_HOOK),
			!!(host_capabilities & ARTITUX_CAP_XCR0_HOOK),
			!!(host_capabilities & ARTITUX_CAP_XCR0_NATIVE),
			atomic_read(&tracked_count),
			atomic_read(&active_xcr0_count),
			active,
			pending);
	return simple_read_from_buffer(buf, count, ppos, out, len);
}

static ssize_t artitux_write(struct file *file, const char __user *buf,
			     size_t count, loff_t *ppos)
{
	char kbuf[64];
	char *p, *tok;
	u32 req_flags = 0;
	bool saw_token = false;
	int ret;

	if (count == 0 || count >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;
	kbuf[count] = '\0';

	p = kbuf;
	while ((tok = strsep(&p, " \t\r\n,")) != NULL) {
		if (!*tok)
			continue;
		saw_token = true;
		if (!strcmp(tok, "umip"))
			req_flags |= ARTITUX_FLAG_UMIP;
		else if (!strcmp(tok, "xcr0") || !strcmp(tok, "xcr0_7"))
			req_flags |= ARTITUX_FLAG_XCR0_7;
		else if (!strcmp(tok, "none") || !strcmp(tok, "0"))
			req_flags = 0;
		else
			return -EINVAL;
	}
	if (!saw_token)
		return -EINVAL;

	ret = arm_current_exec_flags(req_flags);
	return ret ? ret : (ssize_t)count;
}

static long artitux_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case ARTITUX_IOCTL_GET_INFO: {
		struct artitux_kmod_info info = {
			.abi_version = ARTITUX_KMOD_ABI_VERSION,
			.capabilities = host_capabilities,
			.host_xcr0 = host_xcr0,
			.tracked_tasks = (u32)atomic_read(&tracked_count),
			.active_xcr0_tasks = (u32)atomic_read(&active_xcr0_count),
		};

		lookup_task_both_flags(current, &info.active_flags, &info.pending_flags);
		if (copy_to_user((void __user *)arg, &info, sizeof(info)))
			return -EFAULT;
		return 0;
	}
	case ARTITUX_IOCTL_ARM_EXEC: {
		u32 req_flags;

		if (copy_from_user(&req_flags, (void __user *)arg, sizeof(req_flags)))
			return -EFAULT;
		return arm_current_exec_flags(req_flags);
	}
	case ARTITUX_IOCTL_GET_STATE: {
		struct artitux_task_state st;

		lookup_task_both_flags(current, &st.active_flags, &st.pending_flags);
		if (copy_to_user((void __user *)arg, &st, sizeof(st)))
			return -EFAULT;
		return 0;
	}
	default:
		return -ENOTTY;
	}
}

static const struct file_operations artitux_fops = {
	.owner          = THIS_MODULE,
	.read           = artitux_read,
	.write          = artitux_write,
	.unlocked_ioctl = artitux_ioctl,
	.compat_ioctl   = compat_ptr_ioctl,
};

static struct miscdevice artitux_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "artitux",
	.fops  = &artitux_fops,
	.mode  = 0666,
};

/* ---- Init / Exit ---- */

static void find_tracepoints_cb(struct tracepoint *tp, void *priv)
{
	if (!strcmp(tp->name, "sched_switch"))
		tp_sched_switch = tp;
	else if (!strcmp(tp->name, "sched_process_fork"))
		tp_sched_fork = tp;
	else if (!strcmp(tp->name, "sched_process_exec"))
		tp_sched_exec = tp;
	else if (!strcmp(tp->name, "sched_process_free"))
		tp_sched_free = tp;
}

/* Kernel FPU functions that require host_xcr0 before executing. */
static const char *const fpu_restore_syms[] = {
	"kernel_fpu_begin_mask",
	"save_fpregs_to_fpstate",
	"restore_fpregs_from_fpstate",
	"copy_fpstate_to_sigframe",
	"fpu__restore_sig",
	"fpregs_lock_and_load",
	"fpu_flush_thread",
	"fpu_swap_kvm_fpstate",
	"fpu__clear_user_states",
	"fpregs_mark_activate",
	"fpu_clone",
	"fpu_sync_fpstate",
};

static int register_xcr0_hooks(void)
{
	const char *switch_fpu_sym = NULL;
	unsigned int added = 0;
	unsigned int i;
	int ret;

	/* Register plain ftrace pre-call restore hooks (no IPMODIFY, no SAVE_REGS). */
	fpu_restore_ops.func = fpu_restore_ftrace_cb;
	fpu_restore_ops.flags = FTRACE_OPS_FL_RECURSION;

	for (i = 0; i < ARRAY_SIZE(fpu_restore_syms); i++) {
		ret = ftrace_set_filter(&fpu_restore_ops,
					(unsigned char *)fpu_restore_syms[i],
					strlen(fpu_restore_syms[i]), 0);
		if (ret) {
			pr_debug("artitux_kmod: skip non-traceable %s (%d)\n",
				 fpu_restore_syms[i], ret);
			continue;
		}
		added++;
	}
	if (!added) {
		pr_err("artitux_kmod: no FPU restore hook sites found\n");
		return -ENOENT;
	}

	ret = register_ftrace_function(&fpu_restore_ops);
	if (ret) {
		ftrace_free_filter(&fpu_restore_ops);
		return ret;
	}
	fpu_restore_reg = true;

#ifdef CONFIG_FPROBE
	fp_switch_fpu.entry_handler = fp_switch_fpu_entry;
	fp_switch_fpu.exit_handler = fp_switch_fpu_exit;
	switch_fpu_sym = "switch_fpu_return";
	ret = register_fprobe(&fp_switch_fpu, switch_fpu_sym, NULL);
	if (ret) {
		memset(&fp_switch_fpu, 0, sizeof(fp_switch_fpu));
		fp_switch_fpu.entry_handler = fp_switch_fpu_entry;
		fp_switch_fpu.exit_handler = fp_switch_fpu_exit;
		switch_fpu_sym = "fpregs_restore_userregs";
		ret = register_fprobe(&fp_switch_fpu, switch_fpu_sym, NULL);
	}
	if (ret) {
		pr_err("artitux_kmod: register_fprobe(switch_fpu_return/fpregs_restore_userregs) failed: %d\n",
		       ret);
		return ret;
	}
	probe_switch_fpu_reg = true;

	fp_xstate_prctl.entry_handler = fp_xstate_prctl_entry;
	fp_xstate_prctl.exit_handler = fp_xstate_prctl_exit;
	fp_xstate_prctl.entry_data_size = sizeof(struct xstate_prctl_data);
	ret = register_fprobe(&fp_xstate_prctl, "fpu_xstate_prctl", NULL);
	if (ret)
		pr_debug("artitux_kmod: fpu_xstate_prctl hook skipped (%d)\n", ret);
	else
		probe_xstate_prctl_reg = true;
#else
	switch_fpu_sym = "switch_fpu_return";
	krp_switch_fpu.kp.symbol_name = switch_fpu_sym;
	krp_switch_fpu.entry_handler = krp_switch_fpu_entry;
	krp_switch_fpu.handler = krp_switch_fpu_exit;
	krp_switch_fpu.maxactive = 256;
	ret = register_kretprobe(&krp_switch_fpu);
	if (ret) {
		memset(&krp_switch_fpu, 0, sizeof(krp_switch_fpu));
		switch_fpu_sym = "fpregs_restore_userregs";
		krp_switch_fpu.kp.symbol_name = switch_fpu_sym;
		krp_switch_fpu.entry_handler = krp_switch_fpu_entry;
		krp_switch_fpu.handler = krp_switch_fpu_exit;
		krp_switch_fpu.maxactive = 256;
		ret = register_kretprobe(&krp_switch_fpu);
	}
	if (ret) {
		pr_err("artitux_kmod: register_kretprobe(switch_fpu_return/fpregs_restore_userregs) failed: %d\n",
		       ret);
		return ret;
	}
	probe_switch_fpu_reg = true;

	krp_xstate_prctl.kp.symbol_name = "fpu_xstate_prctl";
	krp_xstate_prctl.entry_handler = krp_xstate_prctl_entry;
	krp_xstate_prctl.handler = krp_xstate_prctl_exit;
	krp_xstate_prctl.data_size = sizeof(struct xstate_prctl_data);
	krp_xstate_prctl.maxactive = 256;
	ret = register_kretprobe(&krp_xstate_prctl);
	if (ret)
		pr_debug("artitux_kmod: fpu_xstate_prctl hook skipped (%d)\n", ret);
	else
		probe_xstate_prctl_reg = true;
#endif

	ret = tracepoint_probe_register(tp_sched_switch, tp_on_sched_switch, NULL);
	if (ret)
		return ret;
	tp_switch_reg = true;

	pr_info("artitux_kmod: lazy XCR0=7 active (host_xcr0=0x%llx, exit=%s, restore_sites=%u)\n",
		host_xcr0, switch_fpu_sym, added);
	return 0;
}

static int register_umip_hook(void)
{
	int ret;

	if (!boot_cpu_has(X86_FEATURE_UMIP))
		return 0;

#ifdef CONFIG_FPROBE
	fp_umip.entry_handler = fp_umip_entry;
	fp_umip.exit_handler = fp_umip_exit;
	fp_umip.entry_data_size = sizeof(struct umip_probe_data);
	ret = register_fprobe(&fp_umip, "fixup_umip_exception", NULL);
#else
	krp_umip.kp.symbol_name = "fixup_umip_exception";
	krp_umip.entry_handler = krp_umip_entry;
	krp_umip.handler = krp_umip_exit;
	krp_umip.data_size = sizeof(struct umip_probe_data);
	krp_umip.maxactive = 256;
	ret = register_kretprobe(&krp_umip);
#endif
	if (ret) {
		pr_warn("artitux_kmod: fixup_umip_exception hook failed (%d)\n", ret);
		return 0;
	}
	probe_umip_reg = true;
	umip_hook_active = true;
	host_capabilities |= ARTITUX_CAP_UMIP_HOOK;
	pr_info("artitux_kmod: UMIP SGDT/SIDT fixup ready (dummy_limit=0x%04x, global=%d)\n",
		umip_dummy_limit, umip_global);
	return 0;
}

static void cpu_cleanup_xcr0(void *unused)
{
	struct cpu_xcr0_state *st = this_cpu_ptr(&cpu_xcr0);
	unsigned long flags;

	local_irq_save(flags);
	st->task_active = false;
	if (st->urn_registered) {
		user_return_notifier_unregister(&st->urn);
		st->urn_registered = false;
	}
	if (st->hw_lowered) {
		xsetbv(XCR_XFEATURE_ENABLED_MASK, host_xcr0);
		st->hw_lowered = false;
	}
	local_irq_restore(flags);
}

static void cleanup_all(void)
{
	int i;

	if (tp_fork_reg) {
		tracepoint_probe_unregister(tp_sched_fork, tp_on_sched_fork, NULL);
		tp_fork_reg = false;
	}
	if (tp_exec_reg) {
		tracepoint_probe_unregister(tp_sched_exec, tp_on_sched_exec, NULL);
		tp_exec_reg = false;
	}
	if (tp_free_reg) {
		tracepoint_probe_unregister(tp_sched_free, tp_on_sched_free, NULL);
		tp_free_reg = false;
	}
	if (tp_switch_reg) {
		tracepoint_probe_unregister(tp_sched_switch, tp_on_sched_switch, NULL);
		tp_switch_reg = false;
	}
	tracepoint_synchronize_unregister();

#ifdef CONFIG_FPROBE
	if (probe_umip_reg) {
		unregister_fprobe(&fp_umip);
		probe_umip_reg = false;
	}
	if (probe_xstate_prctl_reg) {
		unregister_fprobe(&fp_xstate_prctl);
		probe_xstate_prctl_reg = false;
	}
	if (probe_switch_fpu_reg) {
		unregister_fprobe(&fp_switch_fpu);
		probe_switch_fpu_reg = false;
	}
#else
	if (probe_umip_reg) {
		unregister_kretprobe(&krp_umip);
		probe_umip_reg = false;
	}
	if (probe_xstate_prctl_reg) {
		unregister_kretprobe(&krp_xstate_prctl);
		probe_xstate_prctl_reg = false;
	}
	if (probe_switch_fpu_reg) {
		unregister_kretprobe(&krp_switch_fpu);
		probe_switch_fpu_reg = false;
	}
#endif

	if (fpu_restore_reg) {
		unregister_ftrace_function(&fpu_restore_ops);
		ftrace_free_filter(&fpu_restore_ops);
		fpu_restore_reg = false;
	}

	if (xcr0_hook_active) {
		on_each_cpu(cpu_cleanup_xcr0, NULL, 1);
		xcr0_hook_active = false;
	}

	if (policy_cache) {
		unsigned long irqflags;

		raw_spin_lock_irqsave(&policy_lock, irqflags);
		for (i = 0; i < POLICY_HASH_SIZE; i++) {
			struct task_policy_node *node;
			struct hlist_node *tmp;

			hlist_for_each_entry_safe(node, tmp, &policy_buckets[i], hnode) {
				hlist_del_rcu(&node->hnode);
				call_rcu(&node->rcu, policy_node_free_rcu);
			}
		}
		raw_spin_unlock_irqrestore(&policy_lock, irqflags);
		rcu_barrier();
		kmem_cache_destroy(policy_cache);
		policy_cache = NULL;
	}
}

static int __init artitux_kmod_init(void)
{
	int cpu, i, ret;

	for (i = 0; i < POLICY_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&policy_buckets[i]);

	for_each_possible_cpu(cpu) {
		struct cpu_xcr0_state *st = per_cpu_ptr(&cpu_xcr0, cpu);

		st->task_active = false;
		st->hw_lowered = false;
		st->urn_registered = false;
		st->urn.on_user_return = xcr0_on_user_return;
	}

	policy_cache = KMEM_CACHE(task_policy_node, 0);
	if (!policy_cache)
		return -ENOMEM;

	for_each_kernel_tracepoint(find_tracepoints_cb, NULL);
	if (!tp_sched_switch || !tp_sched_fork || !tp_sched_exec || !tp_sched_free) {
		pr_err("artitux_kmod: missing required sched tracepoints\n");
		ret = -ENOENT;
		goto fail;
	}

	if (boot_cpu_has(X86_FEATURE_XSAVE) && boot_cpu_has(X86_FEATURE_OSXSAVE)) {
		host_xcr0 = xgetbv(XCR_XFEATURE_ENABLED_MASK);
		if (host_xcr0 == ARTITUX_XCR0_TARGET) {
			host_capabilities |= ARTITUX_CAP_XCR0_NATIVE;
			pr_info("artitux_kmod: host XCR0 is already 0x7 natively\n");
		} else if ((host_xcr0 & ARTITUX_XCR0_TARGET) == ARTITUX_XCR0_TARGET) {
			ret = register_xcr0_hooks();
			if (ret)
				goto fail;
			xcr0_hook_active = true;
			host_capabilities |= ARTITUX_CAP_XCR0_HOOK;
		}
	}

	register_umip_hook();

	ret = tracepoint_probe_register(tp_sched_fork, tp_on_sched_fork, NULL);
	if (ret)
		goto fail;
	tp_fork_reg = true;

	ret = tracepoint_probe_register(tp_sched_exec, tp_on_sched_exec, NULL);
	if (ret)
		goto fail;
	tp_exec_reg = true;

	ret = tracepoint_probe_register(tp_sched_free, tp_on_sched_free, NULL);
	if (ret)
		goto fail;
	tp_free_reg = true;

	ret = misc_register(&artitux_miscdev);
	if (ret)
		goto fail;

	pr_info("artitux_kmod: ready (/dev/artitux, caps=0x%x, host_xcr0=0x%llx)\n",
		host_capabilities, host_xcr0);
	return 0;

fail:
	cleanup_all();
	return ret;
}

static void __exit artitux_kmod_exit(void)
{
	misc_deregister(&artitux_miscdev);
	cleanup_all();
	pr_info("artitux_kmod: unloaded cleanly\n");
}

module_init(artitux_kmod_init);
module_exit(artitux_kmod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lumice <89531268+Lumice@users.noreply.github.com>");
MODULE_VERSION("0.1.0");
MODULE_DESCRIPTION("Per-process lazy XCR0=7 and UMIP SGDT/SIDT fixup for Artitux");
