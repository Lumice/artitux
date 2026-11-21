#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/random.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../artitux_kmod.h"

#ifndef ARCH_GET_XCOMP_SUPP
#define ARCH_GET_XCOMP_SUPP 0x1021
#define ARCH_GET_XCOMP_PERM 0x1022
#define ARCH_REQ_XCOMP_PERM 0x1023
#endif
#ifndef NT_X86_XSTATE
#define NT_X86_XSTATE 0x202
#endif

static int failures = 0;

#define CHECK(cond, fmt, ...) do { \
	if (!(cond)) { \
		fprintf(stderr, "FAIL: " fmt "\n", ##__VA_ARGS__); \
		failures++; \
	} \
} while (0)

static inline uint64_t read_xcr0(void)
{
	uint32_t lo, hi;
	__asm__ volatile("xor %%ecx, %%ecx\n\txgetbv" : "=a"(lo), "=d"(hi) :: "ecx");
	return ((uint64_t)hi << 32) | lo;
}

static inline uint32_t read_pkru(void)
{
	uint32_t eax, edx;
	__asm__ volatile("xor %%ecx, %%ecx\n\t.byte 0x0f, 0x01, 0xee"
			 : "=a"(eax), "=d"(edx) :: "ecx");
	return eax;
}

static inline void write_pkru(uint32_t val)
{
	__asm__ volatile("xor %%ecx, %%ecx\n\txor %%edx, %%edx\n\t.byte 0x0f, 0x01, 0xef"
			 :: "a"(val) : "ecx", "edx");
}

static sigjmp_buf sigill_jmp;
static volatile sig_atomic_t got_sigill = 0;

static void sigill_handler(int sig)
{
	(void)sig;
	got_sigill = 1;
	siglongjmp(sigill_jmp, 1);
}

/* Executes vpxord zmm0, zmm0, zmm0 (EVEX AVX-512F). Returns true if executed, false if SIGILL. */
static bool try_avx512_insn(void)
{
	struct sigaction sa = {0}, old;

	sa.sa_handler = sigill_handler;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGILL, &sa, &old);
	got_sigill = 0;

	if (sigsetjmp(sigill_jmp, 1) == 0) {
		__asm__ volatile(".byte 0x62, 0xf1, 0x7d, 0x48, 0xef, 0xc0" ::: "xmm0");
	}
	sigaction(SIGILL, &old, NULL);
	return !got_sigill;
}

struct __attribute__((packed)) desc_ptr_u {
	uint16_t limit;
	uint64_t base;
};

static struct desc_ptr_u global_gdt_desc;

static uint16_t read_sgdt_stack(void)
{
	struct desc_ptr_u d = { 0xdead, 0 };
	__asm__ volatile("sgdt %0" : "=m"(d) :: "memory");
	return d.limit;
}

static uint16_t read_sgdt_rip(void)
{
	global_gdt_desc.limit = 0xbeef;
	__asm__ volatile("sgdt %0" : "=m"(global_gdt_desc) :: "memory");
	return global_gdt_desc.limit;
}

static uint16_t read_sidt_stack(void)
{
	struct desc_ptr_u d = { 0xdead, 0 };
	__asm__ volatile("sidt %0" : "=m"(d) :: "memory");
	return d.limit;
}

static long read_sysfs_long(const char *path)
{
	char buf[64] = {0};
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	ssize_t n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	return strtol(buf, NULL, 0);
}

static volatile sig_atomic_t sig_count = 0;
static volatile uint64_t sig_xcr0_seen = 0;
static volatile sig_atomic_t alrm_count = 0;
static volatile sig_atomic_t alrm_bad_xcr0 = 0;

static void usr1_handler(int sig)
{
	(void)sig;
	sig_xcr0_seen = read_xcr0();
	sig_count++;
}

static void alrm_handler(int sig)
{
	(void)sig;
	if (read_xcr0() != 7)
		alrm_bad_xcr0++;
	alrm_count++;
}

static void pin_cpu(int cpu)
{
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	sched_setaffinity(0, sizeof(set), &set);
}

static void *xcr0_thread_fn(void *arg)
{
	int id = (int)(intptr_t)arg;
	int ncpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
	uint8_t rnd[128];

	for (int iter = 0; iter < 50; iter++) {
		pin_cpu((id + iter) % ncpus);
		uint64_t x = read_xcr0();
		if (x != 7) {
			fprintf(stderr, "FAIL: thread %d iter %d saw xcr0=0x%llx\n",
				id, iter, (unsigned long long)x);
			return (void *)1;
		}
		(void)getrandom(rnd, sizeof(rnd), 0);
		if (read_xcr0() != 7) {
			fprintf(stderr, "FAIL: thread %d after getrandom saw xcr0=0x%llx\n",
				id, (unsigned long long)read_xcr0());
			return (void *)1;
		}
		if (iter % 10 == 0)
			sched_yield();
	}
	return NULL;
}

static int run_umip_only_worker(uint64_t host_xcr0)
{
	uint64_t x = read_xcr0();
	CHECK(x == host_xcr0, "umip-only worker XCR0 changed: got 0x%llx expected 0x%llx",
	      (unsigned long long)x, (unsigned long long)host_xcr0);

	if ((host_xcr0 & 0xe0) == 0xe0)
		CHECK(try_avx512_insn(), "umip-only worker lost AVX-512");

	uint16_t lim1 = read_sgdt_stack();
	uint16_t lim2 = read_sgdt_rip();
	uint16_t lim3 = read_sidt_stack();
	CHECK(lim1 == 0x007f, "umip-only sgdt(stack) limit=0x%04x expected 0x007f", lim1);
	CHECK(lim2 == 0x007f, "umip-only sgdt(rip) limit=0x%04x expected 0x007f", lim2);
	CHECK(lim3 == 0x007f, "umip-only sidt(stack) limit=0x%04x expected 0x007f", lim3);

	printf("PASS: umip-only worker (xcr0=0x%llx, sgdt=0x%04x/0x%04x, sidt=0x%04x)\n",
	       (unsigned long long)x, lim1, lim2, lim3);
	return failures ? 1 : 0;
}

static int run_xcr0_worker(uint64_t host_xcr0)
{
	int fd;
	uint64_t x = read_xcr0();
	CHECK(x == 7, "xcr0 worker initial XCR0=0x%llx expected 0x7", (unsigned long long)x);

	/* arch_prctl XCOMP checks */
	uint64_t supp = 0, perm = 0;
	if (syscall(SYS_arch_prctl, ARCH_GET_XCOMP_SUPP, &supp) == 0)
		CHECK(supp == 7, "ARCH_GET_XCOMP_SUPP=0x%llx expected 7", (unsigned long long)supp);
	if (syscall(SYS_arch_prctl, ARCH_GET_XCOMP_PERM, &perm) == 0)
		CHECK(perm == 7, "ARCH_GET_XCOMP_PERM=0x%llx expected 7", (unsigned long long)perm);
	long req = syscall(SYS_arch_prctl, ARCH_REQ_XCOMP_PERM, 18);
	CHECK(req != 0, "ARCH_REQ_XCOMP_PERM unexpectedly succeeded");

	/* Cannot drop active XCR0_7 */
	fd = open(ARTITUX_KMOD_DEVICE_PATH, O_RDONLY);
	CHECK(fd >= 0, "worker open /dev/artitux failed");
	if (fd >= 0) {
		uint32_t zero = 0;
		CHECK(ioctl(fd, ARTITUX_IOCTL_ARM_EXEC, &zero) == -1 && errno == EPERM,
		      "dropping active XCR0_7 should return EPERM (errno=%d)", errno);
		close(fd);
	}

	/* AVX-512 must raise SIGILL (real hardware XCR0 == 7) */
	if ((host_xcr0 & 0xe0) == 0xe0) {
		CHECK(!try_avx512_insn(), "AVX-512 unexpectedly executed under XCR0=7");
		CHECK(read_xcr0() == 7, "XCR0 drifted after SIGILL: 0x%llx", (unsigned long long)read_xcr0());
	}

	/* Userspace XSAVE must produce xstate_bv <= 7 */
	uint8_t xsave_buf[4096] __attribute__((aligned(64)));
	memset(xsave_buf, 0, sizeof(xsave_buf));
	__asm__ volatile("xsave64 %0" : "=m"(xsave_buf) : "a"(0xffffffffU), "d"(0xffffffffU) : "memory");
	uint64_t xstate_bv = 0;
	memcpy(&xstate_bv, xsave_buf + 512, sizeof(xstate_bv));
	CHECK((xstate_bv & ~7ULL) == 0, "userspace XSAVE xstate_bv=0x%llx has bits > 7",
	      (unsigned long long)xstate_bv);

	/* UMIP must also work simultaneously */
	CHECK(read_sgdt_stack() == 0x007f, "xcr0+umip sgdt limit=0x%04x", read_sgdt_stack());

	/* Synchronous signals + YMM preservation */
	struct sigaction sa = {0};
	sa.sa_handler = usr1_handler;
	sigaction(SIGUSR1, &sa, NULL);
	sig_count = 0;
	uint64_t in_ymm[4] = { 0x1122334455667788ULL, 0x99aabbccddeeff00ULL,
			       0xdeadbeefcafebabeULL, 0x0123456789abcdefULL };
	uint64_t out_ymm[4] = {0};
	__asm__ volatile("vmovdqu %0, %%ymm2" :: "m"(in_ymm) : "xmm2");
	for (int i = 0; i < 40; i++) {
		kill(getpid(), SIGUSR1);
		CHECK(sig_xcr0_seen == 7, "signal handler saw xcr0=0x%llx", (unsigned long long)sig_xcr0_seen);
		CHECK(read_xcr0() == 7, "post-sigreturn saw xcr0=0x%llx", (unsigned long long)read_xcr0());
	}
	__asm__ volatile("vmovdqu %%ymm2, %0" : "=m"(out_ymm) :: "memory");
	CHECK(memcmp(in_ymm, out_ymm, sizeof(in_ymm)) == 0, "YMM2 corrupted across signals");
	CHECK(sig_count == 40, "expected 40 signals, got %d", sig_count);

	/* Asynchronous ITIMER_REAL SIGALRM storm during busy syscall + AVX2 work */
	struct sigaction sa_alrm = {0};
	sa_alrm.sa_handler = alrm_handler;
	sigaction(SIGALRM, &sa_alrm, NULL);
	struct itimerval itv = {
		.it_interval = { .tv_sec = 0, .tv_usec = 500 },
		.it_value    = { .tv_sec = 0, .tv_usec = 500 },
	};
	setitimer(ITIMER_REAL, &itv, NULL);
	alrm_count = 0;
	alrm_bad_xcr0 = 0;
	for (int i = 0; alrm_count < 200 && i < 100000000; i++) {
		if (read_xcr0() != 7) {
			CHECK(false, "async SIGALRM loop saw xcr0=0x%llx at iter %d",
			      (unsigned long long)read_xcr0(), i);
			break;
		}
		if (i % 1000 == 0)
			(void)syscall(SYS_getpid);
	}
	memset(&itv, 0, sizeof(itv));
	setitimer(ITIMER_REAL, &itv, NULL);
	CHECK(alrm_count >= 200, "expected >=200 async SIGALRM signals, got %d", alrm_count);
	CHECK(alrm_bad_xcr0 == 0, "SIGALRM handler saw bad xcr0 %d times", alrm_bad_xcr0);
	printf("INFO: async SIGALRM storm delivered %d signals (bad_xcr0=%d)\n", alrm_count, alrm_bad_xcr0);

	/* Fast syscall laziness test */
	long sw_before = read_sysfs_long("/sys/module/artitux_kmod/parameters/xcr0_switches");
	for (int i = 0; i < 20000; i++)
		(void)syscall(SYS_getpid);
	long sw_after = read_sysfs_long("/sys/module/artitux_kmod/parameters/xcr0_switches");
	CHECK(read_xcr0() == 7, "post-getpid loop xcr0=0x%llx", (unsigned long long)read_xcr0());
	printf("INFO: 20000 fast syscalls caused %ld xcr0_switches\n", sw_after - sw_before);
	CHECK(sw_after - sw_before < 200, "too many xcr0_switches (%ld) during fast syscalls",
	      sw_after - sw_before);

	/* ptrace PTRACE_GETREGSET / PTRACE_SETREGSET NT_X86_XSTATE on restricted child */
	pid_t pt = fork();
	if (pt == 0) {
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		raise(SIGSTOP);
		_exit(read_xcr0() == 7 ? 0 : 1);
	}
	int pst = 0;
	waitpid(pt, &pst, 0);
	if (WIFSTOPPED(pst)) {
		uint8_t ptbuf[4096] __attribute__((aligned(64)));
		struct iovec iov = { .iov_base = ptbuf, .iov_len = sizeof(ptbuf) };
		CHECK(ptrace(PTRACE_GETREGSET, pt, (void *)NT_X86_XSTATE, &iov) == 0,
		      "PTRACE_GETREGSET failed: %s", strerror(errno));
		CHECK(ptrace(PTRACE_SETREGSET, pt, (void *)NT_X86_XSTATE, &iov) == 0,
		      "PTRACE_SETREGSET failed: %s", strerror(errno));
		ptrace(PTRACE_CONT, pt, NULL, NULL);
		waitpid(pt, &pst, 0);
		CHECK(WIFEXITED(pst) && WEXITSTATUS(pst) == 0,
		      "ptrace child failed after SETREGSET (status=%d)", pst);
	} else {
		CHECK(false, "ptrace child did not stop");
	}

	/* 16 threads migrating across all vCPUs + kernel crypto */
	pthread_t tids[16];
	for (int i = 0; i < 16; i++)
		CHECK(pthread_create(&tids[i], NULL, xcr0_thread_fn, (void *)(intptr_t)i) == 0,
		      "pthread_create %d failed", i);
	for (int i = 0; i < 16; i++) {
		void *rv = NULL;
		pthread_join(tids[i], &rv);
		CHECK(rv == NULL, "thread %d failed", i);
	}

	/* 200 forked children verifying inheritance */
	for (int i = 0; i < 200; i++) {
		pid_t p = fork();
		if (p == 0) {
			int ok = (read_xcr0() == 7) && (read_sgdt_stack() == 0x007f);
			_exit(ok ? 0 : 1);
		}
		int st = 0;
		waitpid(p, &st, 0);
		CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "fork child %d failed (status=%d)", i, st);
	}

	/* 32-bit (ia32) legacy sigreturn + rt_sigreturn regression check */
	pid_t p32 = fork();
	if (p32 == 0) {
		char *a[] = { "/ia32_sig_test", NULL };
		execv("/ia32_sig_test", a);
		_exit(errno == ENOEXEC ? 126 : 127);
	}
	int st32 = 0;
	waitpid(p32, &st32, 0);
	if (WIFEXITED(st32) && WEXITSTATUS(st32) == 126) {
		printf("INFO: ia32 sigreturn test skipped (IA32_EMULATION disabled)\n");
	} else {
		CHECK(WIFEXITED(st32) && WEXITSTATUS(st32) == 0,
		      "ia32 sigreturn test failed (status=0x%x, exit=%d, sig=%d)",
		      st32, WIFEXITED(st32) ? WEXITSTATUS(st32) : -1,
		      WIFSIGNALED(st32) ? WTERMSIG(st32) : 0);
	}

	printf("PASS: xcr0+umip worker (xsave/ptrace/sigalrm/ia32-sigreturn/threads/forks/lazy-syscall passed)\n");
	return failures ? 1 : 0;
}

static bool check_kmsg_clean(void)
{
	int fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
	if (fd < 0)
		return true;
	char line[1024];
	bool clean = true;
	while (1) {
		ssize_t n = read(fd, line, sizeof(line) - 1);
		if (n <= 0)
			break;
		line[n] = '\0';
		if (strstr(line, "artitux_kmod"))
			printf("KMSG: %s", line);
		if (strstr(line, "BUG:") || strstr(line, "Oops") ||
		    strstr(line, "Call Trace") || strstr(line, "WARNING: CPU:") ||
		    strstr(line, "general protection fault") || strstr(line, "Missing ENDBR")) {
			fprintf(stderr, "KMSG ERROR: %s", line);
			clean = false;
		}
	}
	close(fd);
	return clean;
}

static int load_module(void)
{
	int modfd = open("/artitux_kmod.ko", O_RDONLY);
	if (modfd < 0)
		return -1;
	long r = syscall(SYS_finit_module, modfd, "", 0);
	close(modfd);
	return (int)r;
}

int main(int argc, char **argv)
{
	if (argc >= 3 && strcmp(argv[1], "--worker") == 0) {
		uint64_t hx = strtoull(argv[3], NULL, 0);
		if (strcmp(argv[2], "umip-only") == 0)
			return run_umip_only_worker(hx);
		if (strcmp(argv[2], "xcr0-test") == 0)
			return run_xcr0_worker(hx);
		return 2;
	}

	mkdir("/proc", 0755);
	mkdir("/sys", 0755);
	mkdir("/dev", 0755);
	mount("proc", "/proc", "proc", 0, NULL);
	mount("sysfs", "/sys", "sysfs", 0, NULL);
	mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);

	printf("=== artitux_kmod VM torture suite ===\n");
	uint64_t host_xcr0 = read_xcr0();
	bool has_pku = !!(host_xcr0 & (1ULL << 9));
	printf("INFO: guest boot XCR0 = 0x%llx (PKU=%d), CPUs = %ld\n",
	       (unsigned long long)host_xcr0, has_pku, sysconf(_SC_NPROCESSORS_ONLN));
	CHECK((host_xcr0 & 0xe0) == 0xe0, "VM guest lacks AVX-512 (xcr0=0x%llx)",
	      (unsigned long long)host_xcr0);

	CHECK(load_module() == 0, "finit_module failed: %s", strerror(errno));

	struct stat st_dev;
	CHECK(stat(ARTITUX_KMOD_DEVICE_PATH, &st_dev) == 0 && (st_dev.st_mode & 0777) == 0666,
	      "/dev/artitux missing or wrong mode");

	int devfd = open(ARTITUX_KMOD_DEVICE_PATH, O_RDONLY);
	CHECK(devfd >= 0, "open /dev/artitux failed: %s", strerror(errno));

	struct artitux_kmod_info info = {0};
	CHECK(ioctl(devfd, ARTITUX_IOCTL_GET_INFO, &info) == 0, "GET_INFO failed");
	printf("INFO: abi=%u caps=0x%x host_xcr0=0x%llx\n",
	       info.abi_version, info.capabilities, (unsigned long long)info.host_xcr0);
	CHECK(info.abi_version == ARTITUX_KMOD_ABI_VERSION, "bad abi version");
	CHECK(info.host_xcr0 == host_xcr0, "host_xcr0 mismatch");
	CHECK(info.capabilities & ARTITUX_CAP_XCR0_HOOK, "XCR0 hook not active");
	CHECK(info.capabilities & ARTITUX_CAP_UMIP_HOOK, "UMIP hook not active");

	CHECK(try_avx512_insn(), "unrestricted process AVX-512 failed");
	CHECK(read_sgdt_stack() == 0x0000, "unrestricted sgdt should be 0x0000 (got 0x%04x)",
	      read_sgdt_stack());

	char hx_str[32];
	snprintf(hx_str, sizeof(hx_str), "0x%llx", (unsigned long long)host_xcr0);

	/* Test 1: UMIP-only worker (must keep AVX-512!) */
	pid_t p1 = fork();
	if (p1 == 0) {
		uint32_t fl = ARTITUX_FLAG_UMIP;
		if (ioctl(devfd, ARTITUX_IOCTL_ARM_EXEC, &fl) != 0)
			_exit(99);
		close(devfd);
		char *a[] = { "/init", "--worker", "umip-only", hx_str, NULL };
		execv("/init", a);
		_exit(98);
	}
	int w1 = 0;
	waitpid(p1, &w1, 0);
	CHECK(WIFEXITED(w1) && WEXITSTATUS(w1) == 0, "umip-only worker failed (status=%d)", w1);

	/* Test 2: Concurrent unrestricted AVX-512 + PKRU stressor + XCR0=7+UMIP torture worker */
	pid_t stress = fork();
	if (stress == 0) {
		close(devfd);
		int ncpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
		uint8_t rnd[64];
		uint32_t orig_pkru = has_pku ? read_pkru() : 0;
		uint32_t test_pkru = (orig_pkru & 0x3U) | 0x0000000cU; /* disable key 1 only */
		if (has_pku)
			write_pkru(test_pkru);
		for (int i = 0; i < 3000; i++) {
			pin_cpu(i % ncpus);
			if (read_xcr0() != host_xcr0 || !try_avx512_insn())
				_exit(1);
			if (has_pku && read_pkru() != test_pkru) {
				fprintf(stderr, "FAIL: unrestricted PKRU clobbered: 0x%x != 0x%x\n",
					read_pkru(), test_pkru);
				_exit(2);
			}
			if (i % 50 == 0)
				(void)getrandom(rnd, sizeof(rnd), 0);
		}
		if (has_pku)
			write_pkru(orig_pkru);
		_exit(0);
	}

	pid_t p2 = fork();
	if (p2 == 0) {
		uint32_t fl = ARTITUX_FLAG_XCR0_7 | ARTITUX_FLAG_UMIP;
		if (ioctl(devfd, ARTITUX_IOCTL_ARM_EXEC, &fl) != 0)
			_exit(99);
		close(devfd);
		char *a[] = { "/init", "--worker", "xcr0-test", hx_str, NULL };
		execv("/init", a);
		_exit(98);
	}

	/* Verify delete_module is safely refused (EWOULDBLOCK/EAGAIN) while active tasks exist */
	usleep(30000);
	long busy_ret = syscall(SYS_delete_module, "artitux_kmod", O_NONBLOCK);
	CHECK(busy_ret == -1 && (errno == EWOULDBLOCK || errno == EAGAIN || errno == EBUSY),
	      "delete_module should refuse while tasks are active (ret=%ld errno=%d)", busy_ret, errno);

	int w2 = 0, ws = 0;
	waitpid(p2, &w2, 0);
	waitpid(stress, &ws, 0);
	CHECK(WIFEXITED(w2) && WEXITSTATUS(w2) == 0, "xcr0+umip worker failed (status=%d)", w2);
	CHECK(WIFEXITED(ws) && WEXITSTATUS(ws) == 0, "concurrent AVX-512/PKRU stressor failed (status=%d)", ws);

	/* Test 3: CPU hotplug offline/online cycle while module is loaded */
	int hpfd = open("/sys/devices/system/cpu/cpu1/online", O_WRONLY);
	if (hpfd >= 0) {
		if (write(hpfd, "0\n", 2) == 2) {
			close(hpfd);
			hpfd = open("/sys/devices/system/cpu/cpu1/online", O_WRONLY);
			CHECK(hpfd >= 0 && write(hpfd, "1\n", 2) == 2, "failed to bring cpu1 back online");
			if (hpfd >= 0)
				close(hpfd);
			pin_cpu(1);
			CHECK(read_xcr0() == host_xcr0, "post-hotplug cpu1 xcr0=0x%llx",
			      (unsigned long long)read_xcr0());
			CHECK(try_avx512_insn(), "post-hotplug cpu1 AVX-512 failed");
			printf("PASS: cpu1 hotplug offline/online cycle\n");
		} else {
			close(hpfd);
		}
	}

	close(devfd);
	usleep(250000);

	long tracked = read_sysfs_long("/sys/module/artitux_kmod/parameters/tracked_tasks");
	long act_xcr0 = read_sysfs_long("/sys/module/artitux_kmod/parameters/active_xcr0_tasks");
	long missed = read_sysfs_long("/sys/module/artitux_kmod/parameters/switch_fpu_missed");
	long umip_cnt = read_sysfs_long("/sys/module/artitux_kmod/parameters/umip_fixups");
	long sw_cnt = read_sysfs_long("/sys/module/artitux_kmod/parameters/xcr0_switches");
	printf("INFO: tracked=%ld active_xcr0=%ld missed=%ld umip_fixups=%ld xcr0_switches=%ld\n",
	       tracked, act_xcr0, missed, umip_cnt, sw_cnt);
	CHECK(tracked == 0, "tracked_tasks leaked: %ld", tracked);
	CHECK(act_xcr0 == 0, "active_xcr0_tasks leaked: %ld", act_xcr0);
	CHECK(missed == 0, "switch_fpu_missed non-zero: %ld", missed);
	CHECK(umip_cnt > 0, "umip_fixups == 0");
	CHECK(sw_cnt > 0, "xcr0_switches == 0");

	/* Unload -> Reload -> Re-verify -> Unload cycle */
	CHECK(syscall(SYS_delete_module, "artitux_kmod", 0) == 0,
	      "first delete_module failed: %s", strerror(errno));
	CHECK(load_module() == 0, "reload finit_module failed: %s", strerror(errno));
	devfd = open(ARTITUX_KMOD_DEVICE_PATH, O_RDWR);
	CHECK(devfd >= 0, "reopen /dev/artitux O_RDWR after reload failed");
	if (devfd >= 0) {
		char rbuf[256] = {0};
		ssize_t rn = read(devfd, rbuf, sizeof(rbuf) - 1);
		CHECK(rn > 0 && strstr(rbuf, "xcr0_hook=1") && strstr(rbuf, "umip=1"),
		      "read(/dev/artitux) unexpected: '%s'", rbuf);
		pid_t p3 = fork();
		if (p3 == 0) {
			const char *cmd = "umip xcr0\n";
			if (write(devfd, cmd, strlen(cmd)) != (ssize_t)strlen(cmd))
				_exit(99);
			close(devfd);
			char *a[] = { "/init", "--worker", "xcr0-test", hx_str, NULL };
			execv("/init", a);
			_exit(98);
		}
		int w3 = 0;
		waitpid(p3, &w3, 0);
		CHECK(WIFEXITED(w3) && WEXITSTATUS(w3) == 0,
		      "post-reload write() worker failed (status=%d)", w3);
		close(devfd);
	}
	usleep(200000);
	CHECK(syscall(SYS_delete_module, "artitux_kmod", 0) == 0,
	      "second delete_module failed: %s", strerror(errno));

	int ncpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
	for (int c = 0; c < ncpus; c++) {
		pin_cpu(c);
		CHECK(read_xcr0() == host_xcr0, "post-unload cpu %d xcr0=0x%llx", c, (unsigned long long)read_xcr0());
		CHECK(try_avx512_insn(), "post-unload cpu %d AVX-512 failed", c);
	}

	CHECK(check_kmsg_clean(), "kernel warnings/errors found in dmesg");

	printf("=== VM TEST RESULT: %s (failures=%d) ===\n",
	       failures == 0 ? "ALL PASSED" : "FAILED", failures);
	fflush(stdout);
	fflush(stderr);
	sync();
	reboot(RB_POWER_OFF);
	return failures ? 1 : 0;
}
