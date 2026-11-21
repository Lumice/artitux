# VBS 2.0

## How Artitux selects the mode

Artitux recognizes VBS 2.0 releases by itself: their `artifact.dll` contains
the check that asks you to run `VBS.cmd`. Other releases use VBS 1.9 mode.

A VBS 2.0 release only starts when `XCR0` is `0x7`. Otherwise it shows a
dialog that says to run `VBS.cmd`.

To choose the mode yourself, set `ARTITUX_VBS20=1` (VBS 2.0) or
`ARTITUX_VBS20=0` (VBS 1.9) for the game. For Steam:

```text
ARTITUX_VBS20=1 /home/USERNAME/.local/bin/artitux %command%
```

VBS 2.0 mode already reports AVX support. It does not need `PROTON_AVX=1`.

## Option 1: Keep AVX-512 with `artitux_kmod` (recommended)

Artitux includes a DKMS kernel module in [kmod/](../kmod/README.md) that sets
`XCR0 = 0x7` only for VBS 2.0 games and handles UMIP (`SGDT`/`SIDT`). VBS 1.9
games and the rest of the system keep full AVX-512 and PKU. It can be unloaded
normally with `modprobe -r artitux_kmod` when no tracked games are running.

1. Install your kernel headers and DKMS (and QEMU/KVM if you want to run the
   optional VM check), then clone this repository:

   ```sh
   git clone https://github.com/Lumice/artitux.git
   cd artitux
   ```

2. Optional: test the module in a disposable QEMU/KVM guest against your
   installed kernel:

   ```sh
   make -C kmod vm-test
   ```

3. Install (or upgrade) via DKMS and enable loading at boot (signs
   automatically if DKMS MOK signing is configured for Secure Boot):

   ```sh
   sudo make -C kmod install-dkms
   ```

   To remove the module later:

   ```sh
   sudo make -C kmod uninstall-dkms
   ```

4. If you installed Artitux before `v1.1.1`, re-run `install.sh` so your
   `artitux` launcher knows how to arm `/dev/artitux`. Then check readiness:

   ```sh
   ~/.local/bin/artitux --check
   ```

   Both `UMIP` and `XCR0` should report `ok` via `artitux_kmod`.

5. Launch games in Steam normally with no extra wrapper:

   ```text
   /home/USERNAME/.local/bin/artitux %command%
   ```

   `artitux` arms UMIP automatically and only arms `XCR0 = 0x7` when the game
   is a VBS 2.0 release (or when `ARTITUX_XCR0=1` / `ARTITUX_VBS20=1` is set).

> [!WARNING]
> Do not use per-process `XCR0 = 0x7` on a distribution whose Wine or system
> libraries are built for x86-64-v4 or znver4 (AVX-512 required).

## Option 2: Set `XCR0` to `0x7` with a kernel parameter

If you prefer not to install a kernel module, you can disable AVX-512 and PKU
systemwide at boot. Check which features your CPU exposes:

```sh
grep -owE 'avx512f|ospke' /proc/cpuinfo | sort -u
```

Add a `clearcpuid` kernel parameter for each listed feature:

- Both: `clearcpuid=avx512f,pku`
- Only `ospke`: `clearcpuid=pku`
- Only `avx512f`: `clearcpuid=avx512f`
- Neither: `XCR0` is already `0x7`. No change is needed.

Reboot, then run `artitux --check` to confirm `XCR0` reports `ok`.
