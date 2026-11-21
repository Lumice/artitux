/*
 * Freestanding 32-bit (ia32) signal/sigreturn regression test for artitux_kmod.
 *
 * Exercises both legacy sigreturn (ia32_setup_frame) and rt_sigreturn
 * (ia32_setup_rt_frame) under XCR0=7 on hosts with OSPKE/PKU enabled.
 * Built with: gcc -m32 -nostdlib -static -fno-pie -no-pie -ffreestanding
 */

#define SYS_exit         1
#define SYS_getpid       20
#define SYS_kill         37
#define SYS_rt_sigaction 174

#define SIGUSR1          10
#define SA_SIGINFO       0x00000004U
#define SA_RESTORER      0x04000000U

struct k_sigaction32 {
	unsigned int sa_handler;
	unsigned int sa_flags;
	unsigned int sa_restorer;
	unsigned int sa_mask[2];
};

static volatile int sig_count;
static volatile unsigned long long sig_xcr0_bad;

static inline unsigned long long read_xcr0(void)
{
	unsigned int lo, hi;

	__asm__ volatile("xor %%ecx, %%ecx\n\txgetbv"
			 : "=a"(lo), "=d"(hi) :: "ecx");
	return ((unsigned long long)hi << 32) | lo;
}

static inline int sys1(int nr, int a1)
{
	int ret;

	__asm__ volatile("int $0x80"
			 : "=a"(ret)
			 : "a"(nr), "b"(a1)
			 : "memory");
	return ret;
}

static inline int sys2(int nr, int a1, int a2)
{
	int ret;

	__asm__ volatile("int $0x80"
			 : "=a"(ret)
			 : "a"(nr), "b"(a1), "c"(a2)
			 : "memory");
	return ret;
}

static inline int sys4(int nr, int a1, int a2, int a3, int a4)
{
	int ret;

	__asm__ volatile("int $0x80"
			 : "=a"(ret)
			 : "a"(nr), "b"(a1), "c"(a2), "d"(a3), "S"(a4)
			 : "memory");
	return ret;
}

static void __attribute__((noreturn)) exit_now(int code)
{
	sys1(SYS_exit, code);
	for (;;)
		__asm__ volatile("ud2");
}

extern void restorer_sigreturn(void);
extern void restorer_rt_sigreturn(void);

__asm__(
	".text\n"
	".globl restorer_sigreturn\n"
	"restorer_sigreturn:\n"
	"  popl %eax\n"
	"  movl $119, %eax\n"
	"  int $0x80\n"
	".globl restorer_rt_sigreturn\n"
	"restorer_rt_sigreturn:\n"
	"  movl $173, %eax\n"
	"  int $0x80\n"
);

static void sig_handler(int sig)
{
	unsigned long long x = read_xcr0();

	(void)sig;
	if (x != 7ULL)
		sig_xcr0_bad = x;
	sig_count++;
}

void __attribute__((noreturn)) _start(void)
{
	struct k_sigaction32 act;
	int pid, i;

	if (read_xcr0() != 7ULL)
		exit_now(10);

	pid = sys1(SYS_getpid, 0);
	if (pid <= 0)
		exit_now(11);

	/* 1. Legacy ia32_setup_frame + sigreturn (syscall 119) */
	act.sa_handler = (unsigned int)(unsigned long)&sig_handler;
	act.sa_flags = SA_RESTORER;
	act.sa_restorer = (unsigned int)(unsigned long)&restorer_sigreturn;
	act.sa_mask[0] = 0;
	act.sa_mask[1] = 0;
	if (sys4(SYS_rt_sigaction, SIGUSR1, (int)(unsigned long)&act, 0, 8) != 0)
		exit_now(12);

	for (i = 0; i < 10; i++) {
		if (sys2(SYS_kill, pid, SIGUSR1) != 0)
			exit_now(13);
		if (read_xcr0() != 7ULL)
			exit_now(14);
	}

	/* 2. RT ia32_setup_rt_frame + rt_sigreturn (syscall 173) */
	act.sa_flags = SA_RESTORER | SA_SIGINFO;
	act.sa_restorer = (unsigned int)(unsigned long)&restorer_rt_sigreturn;
	if (sys4(SYS_rt_sigaction, SIGUSR1, (int)(unsigned long)&act, 0, 8) != 0)
		exit_now(15);

	for (i = 0; i < 10; i++) {
		if (sys2(SYS_kill, pid, SIGUSR1) != 0)
			exit_now(16);
		if (read_xcr0() != 7ULL)
			exit_now(17);
	}

	if (sig_xcr0_bad != 0ULL)
		exit_now(18);
	if (sig_count != 20)
		exit_now(19);

	exit_now(0);
}
