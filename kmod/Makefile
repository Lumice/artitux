obj-m += artitux_kmod.o
artitux_kmod-y := main.o

ifneq ($(srctree),)
HAVE_X86_TASK_FPU := $(shell grep -q 'x86_task_fpu' $(srctree)/arch/x86/include/asm/processor.h 2>/dev/null && echo 1 || echo 0)
HAVE_FPROBE_FTRACE_REGS := $(shell grep -q 'struct ftrace_regs \*regs' $(srctree)/include/linux/fprobe.h 2>/dev/null && echo 1 || echo 0)
ccflags-y += -DARTITUX_HAVE_X86_TASK_FPU=$(HAVE_X86_TASK_FPU) \
             -DARTITUX_FPROBE_FTRACE_REGS=$(HAVE_FPROBE_FTRACE_REGS)
else

KREL ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KREL)/build
ARTITUX_LLVM ?= $(shell grep -qx CONFIG_CC_IS_CLANG=y $(KDIR)/.config 2>/dev/null && echo LLVM=1)
DKMS_NAME := artitux-kmod
DKMS_VER := $(shell sed -n 's/^PACKAGE_VERSION="\([^"]*\)"/\1/p' $(CURDIR)/dkms.conf)
DKMS_SRC := /usr/src/$(DKMS_NAME)-$(DKMS_VER)

.PHONY: all cli clean vm-test install-dkms uninstall-dkms

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

install-dkms:
	@set -eu; \
	PATH="$$PATH:/usr/sbin:/sbin"; \
	if [ "$$(id -u)" -ne 0 ]; then \
		echo "install-dkms must be run as root (use sudo)" >&2; \
		exit 1; \
	fi; \
	for v in $$(dkms status -m $(DKMS_NAME) 2>/dev/null | sed -n 's|^$(DKMS_NAME)[,/][[:space:]]*\([^,:[:space:]]*\).*|\1|p' | sort -u); do \
		dkms remove -m $(DKMS_NAME) -v "$$v" --all; \
	done; \
	rm -rf /usr/src/$(DKMS_NAME)-*; \
	[ -n "$(DKMS_VER)" ] || { echo "could not read PACKAGE_VERSION from dkms.conf" >&2; exit 1; }; \
	install -d -m 0755 "$(DKMS_SRC)"; \
	install -m 0644 $(CURDIR)/artitux_kmod.h $(CURDIR)/main.c $(CURDIR)/Makefile $(CURDIR)/dkms.conf "$(DKMS_SRC)/"; \
	dkms add -m $(DKMS_NAME) -v $(DKMS_VER); \
	dkms install -m $(DKMS_NAME) -v $(DKMS_VER) -k "$(KREL)"; \
	install -D -m 0644 $(CURDIR)/modules-load.d/artitux.conf /etc/modules-load.d/artitux.conf; \
	if [ -d /sys/module/artitux_kmod ]; then \
		if modprobe -r artitux_kmod 2>/dev/null; then \
			modprobe artitux_kmod; \
		else \
			echo "artitux_kmod $(DKMS_VER) installed via DKMS; reload once tracked games exit (sudo modprobe -r artitux_kmod && sudo modprobe artitux_kmod) or reboot." >&2; \
		fi; \
	else \
		modprobe artitux_kmod; \
	fi

uninstall-dkms:
	@set -eu; \
	PATH="$$PATH:/usr/sbin:/sbin"; \
	if [ "$$(id -u)" -ne 0 ]; then \
		echo "uninstall-dkms must be run as root (use sudo)" >&2; \
		exit 1; \
	fi; \
	if [ -d /sys/module/artitux_kmod ]; then \
		if ! modprobe -r artitux_kmod; then \
			echo "artitux_kmod is currently in use; close tracked games and try again." >&2; \
			exit 1; \
		fi; \
	fi; \
	rm -f /etc/modules-load.d/artitux.conf; \
	for v in $$(dkms status -m $(DKMS_NAME) 2>/dev/null | sed -n 's|^$(DKMS_NAME)[,/][[:space:]]*\([^,:[:space:]]*\).*|\1|p' | sort -u); do \
		dkms remove -m $(DKMS_NAME) -v "$$v" --all; \
	done; \
	rm -rf /usr/src/$(DKMS_NAME)-*

endif
