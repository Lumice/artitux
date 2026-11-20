obj-m += artitux_kmod.o
artitux_kmod-y := main.o

ifneq ($(srctree),)
HAVE_X86_TASK_FPU := $(shell grep -q 'x86_task_fpu' $(srctree)/arch/x86/include/asm/processor.h 2>/dev/null && echo 1 || echo 0)
HAVE_FPROBE_FTRACE_REGS := $(shell grep -q 'struct ftrace_regs \*regs' $(srctree)/include/linux/fprobe.h 2>/dev/null && echo 1 || echo 0)
ccflags-y += -DARTITUX_HAVE_X86_TASK_FPU=$(HAVE_X86_TASK_FPU) \
             -DARTITUX_FPROBE_FTRACE_REGS=$(HAVE_FPROBE_FTRACE_REGS)
endif

KDIR ?= /lib/modules/$(shell uname -r)/build
ARTITUX_LLVM ?= $(shell grep -qx CONFIG_CC_IS_CLANG=y $(KDIR)/.config 2>/dev/null && echo LLVM=1)

.PHONY: all cli clean vm-test

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) $(ARTITUX_LLVM) modules

cli: artitux-kmod-run

artitux-kmod-run: artitux-kmod-run.c artitux_kmod.h
	$(CC) -O2 -Wall -Wextra -o $@ $<

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
	rm -f artitux-kmod-run

vm-test: all
	$(CURDIR)/tests/run_vm_test.sh $(CURDIR)/artitux_kmod.ko
