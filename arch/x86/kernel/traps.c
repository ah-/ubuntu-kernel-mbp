/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *  Copyright (C) 2000, 2001, 2002 Andi Kleen, SuSE Labs
 *
 *  Pentium III FXSR, SSE support
 *	Gareth Hughes <gareth@valinux.com>, May 2000
 */

/*
 * Handle hardware traps and faults.
 */
#include <linux/interrupt.h>
#include <linux/kallsyms.h>
#include <linux/spinlock.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/kdebug.h>
#include <linux/kgdb.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/kexec.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/init.h>
#include <linux/bug.h>
#include <linux/nmi.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/io.h>

#ifdef CONFIG_EISA
#include <linux/ioport.h>
#include <linux/eisa.h>
#endif

#ifdef CONFIG_MCA
#include <linux/mca.h>
#endif

#if defined(CONFIG_EDAC)
#include <linux/edac.h>
#endif

#include <asm/kmemcheck.h>
#include <asm/stacktrace.h>
#include <asm/processor.h>
#include <asm/debugreg.h>
#include <linux/atomic.h>
#include <asm/system.h>
#include <asm/traps.h>
#include <asm/desc.h>
#include <asm/i387.h>
#include <asm/mce.h>

#include <asm/mach_traps.h>

#ifdef CONFIG_X86_64
#include <asm/x86_init.h>
#include <asm/pgalloc.h>
#include <asm/proto.h>
#else
#include <asm/processor-flags.h>
#include <asm/setup.h>

asmlinkage int system_call(void);

/* Do we ignore FPU interrupts ? */
char ignore_fpu_irq;

/*
 * The IDT has to be page-aligned to simplify the Pentium
 * F0 0F bug workaround.
 */
gate_desc idt_table[NR_VECTORS] __page_aligned_data = { { { { 0, 0 } } }, };
#endif

DECLARE_BITMAP(used_vectors, NR_VECTORS);
EXPORT_SYMBOL_GPL(used_vectors);

static inline void conditional_sti(struct pt_regs *regs)
{
	if (regs->flags & X86_EFLAGS_IF)
		local_irq_enable();
}

static inline void preempt_conditional_sti(struct pt_regs *regs)
{
	inc_preempt_count();
	if (regs->flags & X86_EFLAGS_IF)
		local_irq_enable();
}

static inline void conditional_cli(struct pt_regs *regs)
{
	if (regs->flags & X86_EFLAGS_IF)
		local_irq_disable();
}

static inline void preempt_conditional_cli(struct pt_regs *regs)
{
	if (regs->flags & X86_EFLAGS_IF)
		local_irq_disable();
	dec_preempt_count();
}

#ifdef CONFIG_X86_32
static inline int
__compare_user_cs_desc(const struct desc_struct *desc1,
	const struct desc_struct *desc2)
{
	return ((desc1->limit0 != desc2->limit0) ||
		(desc1->limit != desc2->limit) ||
		(desc1->base0 != desc2->base0) ||
		(desc1->base1 != desc2->base1) ||
		(desc1->base2 != desc2->base2));
}

/*
 * lazy-check for CS validity on exec-shield binaries:
 *
 * the original non-exec stack patch was written by
 * Solar Designer <solar at openwall.com>. Thanks!
 */
static int
check_lazy_exec_limit(int cpu, struct pt_regs *regs, long error_code)
{
	struct desc_struct *desc1, *desc2;
	struct vm_area_struct *vma;
	unsigned long limit;

	if (current->mm == NULL)
		return 0;

	limit = -1UL;
	if (current->mm->context.exec_limit != -1UL) {
		limit = PAGE_SIZE;
		spin_lock(&current->mm->page_table_lock);
		for (vma = current->mm->mmap; vma; vma = vma->vm_next)
			if ((vma->vm_flags & VM_EXEC) && (vma->vm_end > limit))
				limit = vma->vm_end;
		vma = get_gate_vma(current);
		if (vma && (vma->vm_flags & VM_EXEC) && (vma->vm_end > limit))
			limit = vma->vm_end;
		spin_unlock(&current->mm->page_table_lock);
		if (limit >= TASK_SIZE)
			limit = -1UL;
		current->mm->context.exec_limit = limit;
	}
	set_user_cs(&current->mm->context.user_cs, limit);

	desc1 = &current->mm->context.user_cs;
	desc2 = get_cpu_gdt_table(cpu) + GDT_ENTRY_DEFAULT_USER_CS;

	if (__compare_user_cs_desc(desc1, desc2)) {
		/*
		 * The CS was not in sync - reload it and retry the
		 * instruction. If the instruction still faults then
		 * we won't hit this branch next time around.
		 */
		if (print_fatal_signals >= 2) {
			printk(KERN_ERR "#GPF fixup (%ld[seg:%lx]) at %08lx, CPU#%d.\n",
				error_code, error_code/8, regs->ip,
				smp_processor_id());
			printk(KERN_ERR "exec_limit: %08lx, user_cs: %08x/%08x, CPU_cs: %08x/%08x.\n",
				current->mm->context.exec_limit,
				desc1->a, desc1->b, desc2->a, desc2->b);
		}

		load_user_cs_desc(cpu, current->mm);

		return 1;
	}

	return 0;
}
#endif

static void __kprobes
do_trap(int trapnr, int signr, char *str, struct pt_regs *regs,
	long error_code, siginfo_t *info)
{
	struct task_struct *tsk = current;

#ifdef CONFIG_X86_32
	if (regs->flags & X86_VM_MASK) {
		/*
		 * traps 0, 1, 3, 4, and 5 should be forwarded to vm86.
		 * On nmi (interrupt 2), do_trap should not be called.
		 */
		if (trapnr < 6)
			goto vm86_trap;
		goto trap_signal;
	}
#endif

	if (!user_mode(regs))
		goto kernel_trap;

#ifdef CONFIG_X86_32
trap_signal:
#endif
	/*
	 * We want error_code and trap_no set for userspace faults and
	 * kernelspace faults which result in die(), but not
	 * kernelspace faults which are fixed up.  die() gives the
	 * process no chance to handle the signal and notice the
	 * kernel fault information, so that won't result in polluting
	 * the information about previously queued, but not yet
	 * delivered, faults.  See also do_general_protection below.
	 */
	tsk->thread.error_code = error_code;
	tsk->thread.trap_no = trapnr;

#ifdef CONFIG_X86_64
	if (show_unhandled_signals && unhandled_signal(tsk, signr) &&
	    printk_ratelimit()) {
		printk(KERN_INFO
		       "%s[%d] trap %s ip:%lx sp:%lx error:%lx",
		       tsk->comm, tsk->pid, str,
		       regs->ip, regs->sp, error_code);
		print_vma_addr(" in ", regs->ip);
		printk("\n");
	}
#endif

	if (info)
		force_sig_info(signr, info, tsk);
	else
		force_sig(signr, tsk);
	return;

kernel_trap:
	if (!fixup_exception(regs)) {
		tsk->thread.error_code = error_code;
		tsk->thread.trap_no = trapnr;
		die(str, regs, error_code);
	}
	return;

#ifdef CONFIG_X86_32
vm86_trap:
	if (handle_vm86_trap((struct kernel_vm86_regs *) regs,
						error_code, trapnr))
		goto trap_signal;
	return;
#endif
}

#define DO_ERROR(trapnr, signr, str, name)				\
dotraplinkage void do_##name(struct pt_regs *regs, long error_code)	\
{									\
	if (notify_die(DIE_TRAP, str, regs, error_code, trapnr, signr)	\
							== NOTIFY_STOP)	\
		return;							\
	conditional_sti(regs);						\
	do_trap(trapnr, signr, str, regs, error_code, NULL);		\
}

#define DO_ERROR_INFO(trapnr, signr, str, name, sicode, siaddr)		\
dotraplinkage void do_##name(struct pt_regs *regs, long error_code)	\
{									\
	siginfo_t info;							\
	info.si_signo = signr;						\
	info.si_errno = 0;						\
	info.si_code = sicode;						\
	info.si_addr = (void __user *)siaddr;				\
	if (notify_die(DIE_TRAP, str, regs, error_code, trapnr, signr)	\
							== NOTIFY_STOP)	\
		return;							\
	conditional_sti(regs);						\
	do_trap(trapnr, signr, str, regs, error_code, &info);		\
}

DO_ERROR_INFO(0, SIGFPE, "divide error", divide_error, FPE_INTDIV, regs->ip)
DO_ERROR(4, SIGSEGV, "overflow", overflow)
DO_ERROR(5, SIGSEGV, "bounds", bounds)
DO_ERROR_INFO(6, SIGILL, "invalid opcode", invalid_op, ILL_ILLOPN, regs->ip)
DO_ERROR(9, SIGFPE, "coprocessor segment overrun", coprocessor_segment_overrun)
DO_ERROR(10, SIGSEGV, "invalid TSS", invalid_TSS)
DO_ERROR(11, SIGBUS, "segment not present", segment_not_present)
#ifdef CONFIG_X86_32
DO_ERROR(12, SIGBUS, "stack segment", stack_segment)
#endif
DO_ERROR_INFO(17, SIGBUS, "alignment check", alignment_check, BUS_ADRALN, 0)

#ifdef CONFIG_X86_64
/* Runs on IST stack */
dotraplinkage void do_stack_segment(struct pt_regs *regs, long error_code)
{
	if (notify_die(DIE_TRAP, "stack segment", regs, error_code,
			12, SIGBUS) == NOTIFY_STOP)
		return;
	preempt_conditional_sti(regs);
	do_trap(12, SIGBUS, "stack segment", regs, error_code, NULL);
	preempt_conditional_cli(regs);
}

dotraplinkage void do_double_fault(struct pt_regs *regs, long error_code)
{
	static const char str[] = "double fault";
	struct task_struct *tsk = current;

	/* Return not checked because double check cannot be ignored */
	notify_die(DIE_TRAP, str, regs, error_code, 8, SIGSEGV);

	tsk->thread.error_code = error_code;
	tsk->thread.trap_no = 8;

	/*
	 * This is always a kernel trap and never fixable (and thus must
	 * never return).
	 */
	for (;;)
		die(str, regs, error_code);
}
#endif

dotraplinkage void __kprobes
do_general_protection(struct pt_regs *regs, long error_code)
{
	struct task_struct *tsk;

	conditional_sti(regs);

#ifdef CONFIG_X86_32
	if (regs->flags & X86_VM_MASK)
		goto gp_in_vm86;
#endif

	tsk = current;
	if (!user_mode(regs))
		goto gp_in_kernel;

#ifdef CONFIG_X86_32
{
	int cpu;
	int ok;

	cpu = get_cpu();
	ok = check_lazy_exec_limit(cpu, regs, error_code);
	put_cpu();

	if (ok)
		return;

	if (print_fatal_signals) {
		printk(KERN_ERR "#GPF(%ld[seg:%lx]) at %08lx, CPU#%d.\n",
			error_code, error_code/8, regs->ip, smp_processor_id());
		printk(KERN_ERR "exec_limit: %08lx, user_cs: %08x/%08x.\n",
			current->mm->context.exec_limit,
			current->mm->context.user_cs.a,
			current->mm->context.user_cs.b);
	}
}
#endif /*CONFIG_X86_32*/

	tsk->thread.error_code = error_code;
	tsk->thread.trap_no = 13;

	if (show_unhandled_signals && unhandled_signal(tsk, SIGSEGV) &&
			printk_ratelimit()) {
		printk(KERN_INFO
			"%s[%d] general protection ip:%lx sp:%lx error:%lx",
			tsk->comm, task_pid_nr(tsk),
			regs->ip, regs->sp, error_code);
		print_vma_addr(" in ", regs->ip);
		printk("\n");
	}

	force_sig(SIGSEGV, tsk);
	return;

#ifdef CONFIG_X86_32
gp_in_vm86:
	local_irq_enable();
	handle_vm86_fault((struct kernel_vm86_regs *) regs, error_code);
	return;
#endif

gp_in_kernel:
	if (fixup_exception(regs))
		return;

	tsk->thread.error_code = error_code;
	tsk->thread.trap_no = 13;
	if (notify_die(DIE_GPF, "general protection fault", regs,
				error_code, 13, SIGSEGV) == NOTIFY_STOP)
		return;
	die("general protection fault", regs, error_code);
}

/* May run on IST stack. */
dotraplinkage void __kprobes do_int3(struct pt_regs *regs, long error_code)
{
#ifdef CONFIG_KGDB_LOW_LEVEL_TRAP
	if (kgdb_ll_trap(DIE_INT3, "int3", regs, error_code, 3, SIGTRAP)
			== NOTIFY_STOP)
		return;
#endif /* CONFIG_KGDB_LOW_LEVEL_TRAP */
#ifdef CONFIG_KPROBES
	if (notify_die(DIE_INT3, "int3", regs, error_code, 3, SIGTRAP)
			== NOTIFY_STOP)
		return;
#else
	if (notify_die(DIE_TRAP, "int3", regs, error_code, 3, SIGTRAP)
			== NOTIFY_STOP)
		return;
#endif

	preempt_conditional_sti(regs);
	do_trap(3, SIGTRAP, "int3", regs, error_code, NULL);
	preempt_conditional_cli(regs);
}

#ifdef CONFIG_X86_64
/*
 * Help handler running on IST stack to switch back to user stack
 * for scheduling or signal handling. The actual stack switch is done in
 * entry.S
 */
asmlinkage __kprobes struct pt_regs *sync_regs(struct pt_regs *eregs)
{
	struct pt_regs *regs = eregs;
	/* Did already sync */
	if (eregs == (struct pt_regs *)eregs->sp)
		;
	/* Exception from user space */
	else if (user_mode(eregs))
		regs = task_pt_regs(current);
	/*
	 * Exception from kernel and interrupts are enabled. Move to
	 * kernel process stack.
	 */
	else if (eregs->flags & X86_EFLAGS_IF)
		regs = (struct pt_regs *)(eregs->sp -= sizeof(struct pt_regs));
	if (eregs != regs)
		*regs = *eregs;
	return regs;
}
#endif

/*
 * Our handling of the processor debug registers is non-trivial.
 * We do not clear them on entry and exit from the kernel. Therefore
 * it is possible to get a watchpoint trap here from inside the kernel.
 * However, the code in ./ptrace.c has ensured that the user can
 * only set watchpoints on userspace addresses. Therefore the in-kernel
 * watchpoint trap can only occur in code which is reading/writing
 * from user space. Such code must not hold kernel locks (since it
 * can equally take a page fault), therefore it is safe to call
 * force_sig_info even though that claims and releases locks.
 *
 * Code in ./signal.c ensures that the debug control register
 * is restored before we deliver any signal, and therefore that
 * user code runs with the correct debug control register even though
 * we clear it here.
 *
 * Being careful here means that we don't have to be as careful in a
 * lot of more complicated places (task switching can be a bit lazy
 * about restoring all the debug state, and ptrace doesn't have to
 * find every occurrence of the TF bit that could be saved away even
 * by user code)
 *
 * May run on IST stack.
 */
dotraplinkage void __kprobes do_debug(struct pt_regs *regs, long error_code)
{
	struct task_struct *tsk = current;
	int user_icebp = 0;
	unsigned long dr6;
	int si_code;

	get_debugreg(dr6, 6);

	/* Filter out all the reserved bits which are preset to 1 */
	dr6 &= ~DR6_RESERVED;

	/*
	 * If dr6 has no reason to give us about the origin of this trap,
	 * then it's very likely the result of an icebp/int01 trap.
	 * User wants a sigtrap for that.
	 */
	if (!dr6 && user_mode(regs))
		user_icebp = 1;

	/* Catch kmemcheck conditions first of all! */
	if ((dr6 & DR_STEP) && kmemcheck_trap(regs))
		return;

	/* DR6 may or may not be cleared by the CPU */
	set_debugreg(0, 6);

	/*
	 * The processor cleared BTF, so don't mark that we need it set.
	 */
	clear_tsk_thread_flag(tsk, TIF_BLOCKSTEP);

	/* Store the virtualized DR6 value */
	tsk->thread.debugreg6 = dr6;

	if (notify_die(DIE_DEBUG, "debug", regs, PTR_ERR(&dr6), error_code,
							SIGTRAP) == NOTIFY_STOP)
		return;

	/* It's safe to allow irq's after DR6 has been saved */
	preempt_conditional_sti(regs);

	if (regs->flags & X86_VM_MASK) {
		handle_vm86_trap((struct kernel_vm86_regs *) regs,
				error_code, 1);
		preempt_conditional_cli(regs);
		return;
	}

	/*
	 * Single-stepping through system calls: ignore any exceptions in
	 * kernel space, but re-enable TF when returning to user mode.
	 *
	 * We already checked v86 mode above, so we can check for kernel mode
	 * by just checking the CPL of CS.
	 */
	if ((dr6 & DR_STEP) && !user_mode(regs)) {
		tsk->thread.debugreg6 &= ~DR_STEP;
		set_tsk_thread_flag(tsk, TIF_SINGLESTEP);
		regs->flags &= ~X86_EFLAGS_TF;
	}
	si_code = get_si_code(tsk->thread.debugreg6);
	if (tsk->thread.debugreg6 & (DR_STEP | DR_TRAP_BITS) || user_icebp)
		send_sigtrap(tsk, regs, error_code, si_code);
	preempt_conditional_cli(regs);

	return;
}

/*
 * Note that we play around with the 'TS' bit in an attempt to get
 * the correct behaviour even in the presence of the asynchronous
 * IRQ13 behaviour
 */
void math_error(struct pt_regs *regs, int error_code, int trapnr)
{
	struct task_struct *task = current;
	siginfo_t info;
	unsigned short err;
	char *str = (trapnr == 16) ? "fpu exception" : "simd exception";

	if (notify_die(DIE_TRAP, str, regs, error_code, trapnr, SIGFPE) == NOTIFY_STOP)
		return;
	conditional_sti(regs);

	if (!user_mode_vm(regs))
	{
		if (!fixup_exception(regs)) {
			task->thread.error_code = error_code;
			task->thread.trap_no = trapnr;
			die(str, regs, error_code);
		}
		return;
	}

	/*
	 * Save the info for the exception handler and clear the error.
	 */
	save_init_fpu(task);
	task->thread.trap_no = trapnr;
	task->thread.error_code = error_code;
	info.si_signo = SIGFPE;
	info.si_errno = 0;
	info.si_addr = (void __user *)regs->ip;
	if (trapnr == 16) {
		unsigned short cwd, swd;
		/*
		 * (~cwd & swd) will mask out exceptions that are not set to unmasked
		 * status.  0x3f is the exception bits in these regs, 0x200 is the
		 * C1 reg you need in case of a stack fault, 0x040 is the stack
		 * fault bit.  We should only be taking one exception at a time,
		 * so if this combination doesn't produce any single exception,
		 * then we have a bad program that isn't synchronizing its FPU usage
		 * and it will suffer the consequences since we won't be able to
		 * fully reproduce the context of the exception
		 */
		cwd = get_fpu_cwd(task);
		swd = get_fpu_swd(task);

		err = swd & ~cwd;
	} else {
		/*
		 * The SIMD FPU exceptions are handled a little differently, as there
		 * is only a single status/control register.  Thus, to determine which
		 * unmasked exception was caught we must mask the exception mask bits
		 * at 0x1f80, and then use these to mask the exception bits at 0x3f.
		 */
		unsigned short mxcsr = get_fpu_mxcsr(task);
		err = ~(mxcsr >> 7) & mxcsr;
	}

	if (err & 0x001) {	/* Invalid op */
		/*
		 * swd & 0x240 == 0x040: Stack Underflow
		 * swd & 0x240 == 0x240: Stack Overflow
		 * User must clear the SF bit (0x40) if set
		 */
		info.si_code = FPE_FLTINV;
	} else if (err & 0x004) { /* Divide by Zero */
		info.si_code = FPE_FLTDIV;
	} else if (err & 0x008) { /* Overflow */
		info.si_code = FPE_FLTOVF;
	} else if (err & 0x012) { /* Denormal, Underflow */
		info.si_code = FPE_FLTUND;
	} else if (err & 0x020) { /* Precision */
		info.si_code = FPE_FLTRES;
	} else {
		/*
		 * If we're using IRQ 13, or supposedly even some trap 16
		 * implementations, it's possible we get a spurious trap...
		 */
		return;		/* Spurious trap, no error */
	}
	force_sig_info(SIGFPE, &info, task);
}

dotraplinkage void do_coprocessor_error(struct pt_regs *regs, long error_code)
{
#ifdef CONFIG_X86_32
	ignore_fpu_irq = 1;
#endif

	math_error(regs, error_code, 16);
}

dotraplinkage void
do_simd_coprocessor_error(struct pt_regs *regs, long error_code)
{
	math_error(regs, error_code, 19);
}

dotraplinkage void
do_spurious_interrupt_bug(struct pt_regs *regs, long error_code)
{
	conditional_sti(regs);
#if 0
	/* No need to warn about this any longer. */
	printk(KERN_INFO "Ignoring P6 Local APIC Spurious Interrupt Bug...\n");
#endif
}

asmlinkage void __attribute__((weak)) smp_thermal_interrupt(void)
{
}

asmlinkage void __attribute__((weak)) smp_threshold_interrupt(void)
{
}

/*
 * This gets called with the process already owning the
 * FPU state, and with CR0.TS cleared. It just needs to
 * restore the FPU register state.
 */
void __math_state_restore(struct task_struct *tsk)
{
	/* We need a safe address that is cheap to find and that is already
	   in L1. We've just brought in "tsk->thread.has_fpu", so use that */
#define safe_address (tsk->thread.has_fpu)

	/* AMD K7/K8 CPUs don't save/restore FDP/FIP/FOP unless an exception
	   is pending.  Clear the x87 state here by setting it to fixed
	   values. safe_address is a random variable that should be in L1 */
	alternative_input(
		ASM_NOP8 ASM_NOP2,
		"emms\n\t"	  	/* clear stack tags */
		"fildl %P[addr]",	/* set F?P to defined value */
		X86_FEATURE_FXSAVE_LEAK,
		[addr] "m" (safe_address));

	/*
	 * Paranoid restore. send a SIGSEGV if we fail to restore the state.
	 */
	if (unlikely(restore_fpu_checking(tsk))) {
		__thread_fpu_end(tsk);
		force_sig(SIGSEGV, tsk);
		return;
	}
}

/*
 * 'math_state_restore()' saves the current math information in the
 * old math state array, and gets the new ones from the current task
 *
 * Careful.. There are problems with IBM-designed IRQ13 behaviour.
 * Don't touch unless you *really* know how it works.
 *
 * Must be called with kernel preemption disabled (eg with local
 * local interrupts as in the case of do_device_not_available).
 */
void math_state_restore(void)
{
	struct task_struct *tsk = current;

	if (!tsk_used_math(tsk)) {
		local_irq_enable();
		/*
		 * does a slab alloc which can sleep
		 */
		if (init_fpu(tsk)) {
			/*
			 * ran out of memory!
			 */
			do_group_exit(SIGKILL);
			return;
		}
		local_irq_disable();
	}

	__thread_fpu_begin(tsk);
	__math_state_restore(tsk);

	tsk->fpu_counter++;
}
EXPORT_SYMBOL_GPL(math_state_restore);

dotraplinkage void __kprobes
do_device_not_available(struct pt_regs *regs, long error_code)
{
#ifdef CONFIG_MATH_EMULATION
	if (read_cr0() & X86_CR0_EM) {
		struct math_emu_info info = { };

		conditional_sti(regs);

		info.regs = regs;
		math_emulate(&info);
		return;
	}
#endif
	math_state_restore(); /* interrupts still off */
#ifdef CONFIG_X86_32
	conditional_sti(regs);
#endif
}

#ifdef CONFIG_X86_32
/*
 * The fixup code for errors in iret jumps to here (iret_exc). It loses
 * the original trap number and erorr code. The bogus trap 32 and error
 * code 0 are what the vanilla kernel delivers via:
 * DO_ERROR_INFO(32, SIGSEGV, "iret exception", iret_error, ILL_BADSTK, 0, 1)
 *
 * NOTE: Because of the final "1" in the macro we need to enable interrupts.
 *
 * In case of a general protection fault in the iret instruction, we
 * need to check for a lazy CS update for exec-shield.
 */
dotraplinkage void do_iret_error(struct pt_regs *regs, long error_code)
{
	int ok;
	int cpu;

	local_irq_enable();

	cpu = get_cpu();
	ok = check_lazy_exec_limit(cpu, regs, error_code);
	put_cpu();

	if (!ok && notify_die(DIE_TRAP, "iret exception", regs,
		error_code, 32, SIGSEGV) != NOTIFY_STOP) {
			siginfo_t info;
			info.si_signo = SIGSEGV;
			info.si_errno = 0;
			info.si_code = ILL_BADSTK;
			info.si_addr = 0;
			do_trap(32, SIGSEGV, "iret exception", regs, error_code, &info);
	}
}
#endif

/* Set of traps needed for early debugging. */
void __init early_trap_init(void)
{
	set_intr_gate_ist(1, &debug, DEBUG_STACK);
	/* int3 can be called from all */
	set_system_intr_gate_ist(3, &int3, DEBUG_STACK);
	set_intr_gate(14, &page_fault);
	load_idt(&idt_descr);
}

void __init trap_init(void)
{
	int i;

#ifdef CONFIG_EISA
	void __iomem *p = early_ioremap(0x0FFFD9, 4);

	if (readl(p) == 'E' + ('I'<<8) + ('S'<<16) + ('A'<<24))
		EISA_bus = 1;
	early_iounmap(p, 4);
#endif

	set_intr_gate(0, &divide_error);
	set_intr_gate_ist(2, &nmi, NMI_STACK);
	/* int4 can be called from all */
	set_system_intr_gate(4, &overflow);
	set_intr_gate(5, &bounds);
	set_intr_gate(6, &invalid_op);
	set_intr_gate(7, &device_not_available);
#ifdef CONFIG_X86_32
	set_task_gate(8, GDT_ENTRY_DOUBLEFAULT_TSS);
#else
	set_intr_gate_ist(8, &double_fault, DOUBLEFAULT_STACK);
#endif
	set_intr_gate(9, &coprocessor_segment_overrun);
	set_intr_gate(10, &invalid_TSS);
	set_intr_gate(11, &segment_not_present);
	set_intr_gate_ist(12, &stack_segment, STACKFAULT_STACK);
	set_intr_gate(13, &general_protection);
	set_intr_gate(15, &spurious_interrupt_bug);
	set_intr_gate(16, &coprocessor_error);
	set_intr_gate(17, &alignment_check);
#ifdef CONFIG_X86_MCE
	set_intr_gate_ist(18, &machine_check, MCE_STACK);
#endif
	set_intr_gate(19, &simd_coprocessor_error);

	/* Reserve all the builtin and the syscall vector: */
	for (i = 0; i < FIRST_EXTERNAL_VECTOR; i++)
		set_bit(i, used_vectors);

#ifdef CONFIG_IA32_EMULATION
	set_system_intr_gate(IA32_SYSCALL_VECTOR, ia32_syscall);
	set_bit(IA32_SYSCALL_VECTOR, used_vectors);
#endif

#ifdef CONFIG_X86_32
	set_system_trap_gate(SYSCALL_VECTOR, &system_call);
	set_bit(SYSCALL_VECTOR, used_vectors);
#endif

	/*
	 * Should be a barrier for any external CPU state:
	 */
	cpu_init();

	x86_init.irqs.trap_init();
}
