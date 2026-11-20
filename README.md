# Artitux

[![Latest release](https://img.shields.io/github/v/release/Lumice/artitux)](https://github.com/Lumice/artitux/releases/latest)
[![Check](https://github.com/Lumice/artitux/actions/workflows/check.yml/badge.svg)](https://github.com/Lumice/artitux/actions/workflows/check.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE)

Artitux is a fork of [LinUwUx](https://github.com/brcly/linuwux-runtime) for
Artifact releases. It loads into the game through `LD_PRELOAD` and works with
stock Proton and Wine. It does not patch the Proton installation or the game
executable. If a game already works with LinUwUx, use LinUwUx.

## Quick start

1. Install Artitux:

   ```sh
   curl -fsSL https://raw.githubusercontent.com/Lumice/artitux/main/install.sh | bash
   ```

2. Check your system:

   ```sh
   ~/.local/bin/artitux --check
   ```

   If a line shows `FAIL`, fix it before you continue. See
   [Requirements](#requirements).

3. In Steam, set the game's launch options to:

   ```text
   /home/USERNAME/.local/bin/artitux %command%
   ```

   Replace `USERNAME` with your user name. For other launchers, Gamescope and
   MangoHud, see [docs/launchers.md](docs/launchers.md).

## Confirmed titles

- Planet Zoo 2 v1.0.10
- Anno 117: Pax Romana v3.0.1
- Assassin's Creed Black Flag Resynced Title Update 1.0.8
- F1 25 v1.0.141.7865
- Crimson Desert
- Stellar Blade
- Final Fantasy Resonance v1.0.1.0
- Phantom Blade Zero build 26367565 (VBS 2.0)

VBS 2.0 support is experimental. See [VBS 2.0](#vbs-20).

## Requirements

- x86-64 Linux with glibc 2.34 or newer
- A 64-bit Wine or Proton (Valve Proton, Proton Experimental, GE-Proton or
  UMU), or a modern WoW64 setup
- CPUID faulting, FSGSBASE in user space, and UMIP disabled or handled.
  `artitux --check` checks all of these:
  - **UMIP**: Intel 9th generation and newer and AMD Ryzen 3000 and newer
    usually have it. Install the included `artitux_kmod` module in
    [kmod/](kmod/README.md) (recommended: handles both UMIP and VBS 2.0
    `XCR0 = 0x7` per-process), or load `umip_patch`. The `clearcpuid=514`
    kernel parameter is not tested yet.
  - **CPUID faulting**: AMD AM4 CPUs up to the Ryzen 5000 series and the Steam
    Deck need the `cpuid_fault_emulation` DKMS module (not included). It needs
    the kernel headers and AMD virtualization enabled in the firmware.

Native 32-bit Wine processes cannot load the library and may print a
`wrong ELF class` warning.

## VBS 2.0

Artitux selects VBS 1.9 or VBS 2.0 mode by itself. VBS 2.0 releases need the
CPU state XCR0 to be `0x7`. The `XCR0` line in `artitux --check` shows whether
your system is ready. Install the included [artitux_kmod](kmod/README.md)
module to apply `XCR0 = 0x7` automatically only to VBS 2.0 games while keeping
AVX-512 enabled for everything else, or use a `clearcpuid` kernel parameter.
See [docs/vbs-2.0.md](docs/vbs-2.0.md) for setup steps.

## Troubleshooting

- Run `~/.local/bin/artitux --check` first, especially after a reboot.
- An Artifact dialog such as `Intercepted DeleteFileW` usually means that a
  prerequisite is missing. Run `artitux --check` before changing game files.
- A dialog that says to run `VBS.cmd` means a VBS 2.0 game and XCR0 is not
  `0x7`. See [docs/vbs-2.0.md](docs/vbs-2.0.md).
- An error about a missing Visual C++ runtime: with Steam closed, run
  `protontricks APPID vcrun2022` for the game's prefix.
- `artitux: command not found`: use the full path.
- The game does not start: try it with no other wrappers, and make sure a
  sandboxed launcher can see the wrapper and the library.

To collect a debug log, use:

```text
ARTITUX_DEBUG=1 ARTITUX_LOG=/tmp/artitux.log PROTON_LOG=1 /home/USERNAME/.local/bin/artitux %command%
```

Then open a
[bug report](https://github.com/Lumice/artitux/issues/new?template=bug_report.yml)
with the output of `artitux --version` and `--check`, the Artitux log, and the
Proton or launcher log. All settings are listed in
[docs/configuration.md](docs/configuration.md). See
[CONTRIBUTING.md](CONTRIBUTING.md) for pull requests and building from source,
and [SECURITY.md](SECURITY.md) for security issues.

## Uninstall

```sh
rm -f "$HOME/.local/bin/artitux" "$HOME/.local/share/artitux/Artitux.so"
```

If you installed with `--global`, also remove `/usr/local/bin/artitux`. Then
remove `artitux` from your launch options.

## AI disclosure

AI coding assistants helped develop this fork. Changes are checked with
builds, automated tests, and live game tests where applicable.

## License and credits

Artitux is distributed under the terms in [LICENSE](LICENSE) (AGPL-3.0).

Artitux is a fork of [LinUwUx](https://github.com/brcly/linuwux-runtime) by
brcly (`Copyright (C) 2026 LinUwUx`, AGPL-3.0). Lumice forked and modified it
in November 2026.
