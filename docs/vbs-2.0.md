# VBS 2.0

## How Artitux selects the mode

Artitux recognizes VBS 2.0 releases by itself: their `artifact.dll` contains
the check that asks you to run `VBS.cmd`. Other releases use VBS 1.9 mode.

A VBS 2.0 release only starts when XCR0 is `0x7` (see below). Otherwise it
shows a dialog that says to run `VBS.cmd`.

To choose the mode yourself, set `ARTITUX_VBS20=1` (VBS 2.0) or
`ARTITUX_VBS20=0` (VBS 1.9) for the game. For Steam:

```text
ARTITUX_VBS20=1 /home/USERNAME/.local/bin/artitux %command%
```

VBS 2.0 mode already reports AVX support. It does not need `PROTON_AVX=1`.

## Set XCR0 to 0x7 with a kernel parameter

XCR0 controls which extended CPU state is enabled. VBS 2.0 requires its value
to be exactly `0x7`. Artitux cannot change it, so the host must provide it.
The `XCR0` line in `artitux --check` shows whether it does, and which
`clearcpuid` value is still needed.

Two CPU features usually add bits to XCR0: AVX-512 and memory protection keys
(PKU). Check which ones your CPU has:

```sh
grep -owE 'avx512f|ospke' /proc/cpuinfo | sort -u
```

Add a `clearcpuid` kernel parameter for each feature that is listed:

- Both: `clearcpuid=avx512f,pku`
- Only `ospke`: `clearcpuid=pku`
- Only `avx512f`: `clearcpuid=avx512f`
- Neither: XCR0 is already `0x7`. No change is needed.

These parameters affect the whole system and require a reboot. Use your
distribution's instructions to edit the bootloader configuration.

Run `artitux --check` after the reboot. The `XCR0` line shows `ok` when the
value is `0x7`. Otherwise it names the `clearcpuid` value that is still needed.

## Keep AVX-512 for other programs (optional)

Instead of `clearcpuid`, you can use the `pingu-policy` kernel module from the
separate [Pingu Launcher](https://github.com/MagicalBroccoli/Pingu-Launcher)
project. It sets XCR0 to `0x7` only for the game, and the rest of the system
keeps AVX-512. You do not need Pingu Launcher itself to run the game.

> [!WARNING]
> `pingu-policy` is not part of Artitux. It changes running kernel code, and
> its authors call it experimental. It can crash your system. Keep a working
> kernel to boot from, and read that project's documentation first. Do not use
> it on a distribution whose packages are built for x86-64-v4 or znver4 (for
> example CachyOS's optimized repositories): the game then cannot use those
> libraries.

1. Download `pingu-launcher` from the
   [Pingu Launcher releases](https://github.com/MagicalBroccoli/Pingu-Launcher/releases)
   and check its `.sha256` file.
2. Build and load the module. You need DKMS, the headers for your kernel and,
   for the module's safety test, QEMU with KVM. With Secure Boot, DKMS must
   sign modules with a key that you enrolled. The commands use module version
   `0.4.0`. If `module export` prints a different version, use that one.

   ```sh
   sudo ./pingu-launcher-*-x86_64 module export /usr/src/pingu-policy-0.4.0
   sudo dkms add -m pingu-policy -v 0.4.0
   sudo dkms install -m pingu-policy -v 0.4.0 -k "$(uname -r)"
   sudo modprobe pingu_policy
   cat /sys/module/pingu_policy/parameters/ready
   ```

   The last command must print `Y`. If a step fails, stop and do not continue.
3. Install the helper that turns on the policy for one game:

   ```sh
   install -m755 /usr/src/pingu-policy-0.4.0/validation/avx2-run-static ~/.local/bin/
   ```

4. Use this launch configuration in Steam:

   ```text
   AVX2_POLICY=xcr0-only /home/USERNAME/.local/bin/avx2-run-static /home/USERNAME/.local/bin/artitux %command%
   ```

The module is not loaded at boot. Run `sudo modprobe pingu_policy` after each
reboot, or follow that project's instructions to load it automatically.
