# artitux_kmod

Per-process `XCR0 = 0x7` and UMIP (`SGDT`/`SIDT` limit) DKMS kernel module for Artitux.

## How it works

- Exposes `/dev/artitux` (mode `0666`) with both `ioctl` ([artitux_kmod.h](artitux_kmod.h)) and text `read`/`write` interfaces.
- Policies are armed on the calling task before `exec` and inherited across `fork`, threads, and `exec`:
  - `umip` (`ARTITUX_FLAG_UMIP`): writes `umip_dummy_limit` (`0x007F`) for `SGDT` and `umip_idt_limit` (`0x0FFF`) for `SIDT` under UMIP while keeping full AVX-512.
  - `xcr0` (`ARTITUX_FLAG_XCR0_7`): switches userspace `XCR0` to `0x7` lazily on the kernel FPU lifecycle (`sched_switch`, `kernel_fpu_begin_mask`, `XSAVE`/`XRSTOR` paths, `switch_fpu_return`, and `user_return_notifier`).
- Unloads cleanly (`modprobe -r artitux_kmod`) once no tracked processes remain.

## Build, install & test

```sh
make -C kmod all
make -C kmod vm-test
sudo make -C kmod install-dkms
sudo make -C kmod uninstall-dkms
```

`make vm-test` boots `/boot/vmlinuz-$(uname -r)` in a disposable QEMU/KVM guest (`-cpu host -smp 4`) to verify UMIP, `XCR0 = 0x7`, 64-bit and ia32 signals/sigreturn, `ptrace`, threads/forks, concurrent AVX-512/PKRU, and module unload/reload. `install-dkms` handles both first-time installation and upgrades from earlier versions.

## Interface & parameters

- Read status: `cat /dev/artitux`
- Arm before `exec`: `echo "umip" >/dev/artitux` or `echo "umip xcr0" >/dev/artitux`
- `umip_global=0|1` (default `0`): apply the UMIP `SGDT`/`SIDT` fixup systemwide instead of per-process.
- `umip_dummy_limit=0x007f`: 16-bit GDT limit written for `SGDT`.
- `umip_idt_limit=0x0fff`: 16-bit IDT limit written for `SIDT`.
- Read-only counters under `/sys/module/artitux_kmod/parameters/`: `host_xcr0`, `tracked_tasks`, `active_xcr0_tasks`, `xcr0_switches`, `umip_fixups`, `switch_fpu_missed`.
