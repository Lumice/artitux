# artitux_kmod

Per-process `XCR0 = 0x7` and UMIP (`SGDT`/`SIDT` limit) DKMS kernel module for Artitux.

## How it works

- Exposes `/dev/artitux` (mode `0666`) with both `ioctl` ([artitux_kmod.h](artitux_kmod.h)) and text `read`/`write` interfaces.
- Policies are armed on the calling task before `exec` and inherited across `fork`, threads, and `exec`:
  - `umip` (`ARTITUX_FLAG_UMIP`): writes `umip_dummy_limit` (`0x007F`) for `SGDT`/`SIDT` under UMIP while keeping full AVX-512.
  - `xcr0` (`ARTITUX_FLAG_XCR0_7`): switches userspace `XCR0` to `0x7` lazily on the kernel FPU lifecycle (`sched_switch`, `kernel_fpu_begin_mask`, `XSAVE`/`XRSTOR` paths, `switch_fpu_return`, and `user_return_notifier`).
- Unloads cleanly (`modprobe -r artitux_kmod`) once no tracked processes remain.

## Build & test

```sh
make -C kmod all
make -C kmod vm-test
```

`make vm-test` boots `/boot/vmlinuz-$(uname -r)` in a disposable QEMU/KVM guest (`-cpu host -smp 4`) to verify UMIP, `XCR0 = 0x7`, signals, `ptrace`, threads/forks, concurrent AVX-512/PKRU, and module unload/reload.

## Interface & parameters

- Read status: `cat /dev/artitux`
- Arm before `exec`: `echo "umip" >/dev/artitux` or `echo "umip xcr0" >/dev/artitux`
- `umip_global=0|1` (default `0`): apply the UMIP `SGDT`/`SIDT` fixup systemwide instead of per-process.
- `umip_dummy_limit=0x007f`: 16-bit limit written for `SGDT`/`SIDT`.
- Read-only counters under `/sys/module/artitux_kmod/parameters/`: `host_xcr0`, `tracked_tasks`, `active_xcr0_tasks`, `xcr0_switches`, `umip_fixups`, `switch_fpu_missed`.
