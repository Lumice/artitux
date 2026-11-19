# Artitux

[![Latest release](https://img.shields.io/github/v/release/Lumice/artitux)](https://github.com/Lumice/artitux/releases/latest)
[![Check](https://github.com/Lumice/artitux/actions/workflows/check.yml/badge.svg)](https://github.com/Lumice/artitux/actions/workflows/check.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE)

Artitux is a fork of [LinUwUx](https://github.com/brcly/linuwux-runtime) for
Artifact releases. It loads into the game through `LD_PRELOAD` and works with
stock Proton and Wine. It does not change Proton, the game files, or the Wine
prefix. If a game already works with LinUwUx, use LinUwUx.

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
   [CPU and kernel prerequisites](#cpu-and-kernel-prerequisites).

3. In Steam, set the game's launch options to:

   ```text
   /home/USERNAME/.local/bin/artitux %command%
   ```

   Replace `USERNAME` with your user name. For other launchers, see
   [Other launchers](#other-launchers).

## Confirmed titles

- Planet Zoo 2 v1.0.10
- Anno 117: Pax Romana v3.0.1
- Assassin's Creed Black Flag Resynced Title Update 1.0.8
- F1 25 v1.0.141.7865
- Crimson Desert
- Stellar Blade

Artitux supports Artifact releases prepared with VBS 1.9, not VBS 2.0.

## Requirements

Valve Proton, Proton Experimental, GE-Proton, and UMU-managed builds are
expected to work. The host needs:

- x86-64 Linux with glibc 2.34 or newer
- A 64-bit Wine or Proton host process, or a modern WoW64 setup
- Working `LD_PRELOAD` support
- Access to the installed library from inside any launcher sandbox

Native 32-bit Wine processes cannot load the library and may print a
`wrong ELF class` warning.

### CPU and kernel prerequisites

Artitux needs CPUID faulting, FSGSBASE in user space, and UMIP (User-Mode
Instruction Prevention) either disabled or handled by the `umip_patch` module.
`artitux --check` checks all of these.

Intel 9th generation and newer and AMD Ryzen 3000 and newer usually have UMIP.
AMD AM4 CPUs up to the Ryzen 5000 series and the Steam Deck usually also need
the `cpuid_fault_emulation` DKMS module.

#### UMIP

The tested setups load the `umip_patch` kernel module. Disabling UMIP with the
`clearcpuid=514` kernel parameter is not tested with Artitux yet. It also
affects the whole system and taints the kernel.

#### CPUID faulting on AMD

If `artitux --check` reports no CPUID faulting on an AMD AM4 system or a Steam
Deck, install the `cpuid_fault_emulation` DKMS module. It needs kernel headers
for your kernel and AMD virtualization enabled in the firmware. The installer
does not include it.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/Lumice/artitux/main/install.sh | bash
```

To install a specific release, set `ARTITUX_VERSION`:

```sh
curl -fsSL https://raw.githubusercontent.com/Lumice/artitux/main/install.sh | ARTITUX_VERSION=v1.0.4 bash
```

The installer writes these files and needs no root access:

```text
~/.local/bin/artitux
~/.local/share/artitux/Artitux.so
```

To also create `/usr/local/bin/artitux`, pass `--global` (asks for `sudo`):

```sh
curl -fsSL https://raw.githubusercontent.com/Lumice/artitux/main/install.sh | bash -s -- --global
```

Launchers often do not use your shell's `PATH`, so use the full path
`/home/USERNAME/.local/bin/artitux` in launch options.

## Steam

Add this line under **Properties > Launch Options**:

```text
/home/USERNAME/.local/bin/artitux %command%
```

Put environment variables before it, for example
`PROTON_LOG=1 /home/USERNAME/.local/bin/artitux %command%`. Flatpak Steam must
be able to read `~/.local/share/artitux/Artitux.so`.

## Gamescope and MangoHud

For normal launches, put `artitux` before the game command:

```text
mangohud /home/USERNAME/.local/bin/artitux %command%
MANGOHUD=1 /home/USERNAME/.local/bin/artitux %command%
```

With Gamescope, put `artitux` before Gamescope so it stays loaded:

```text
/home/USERNAME/.local/bin/artitux gamescope -f -- %command%
/home/USERNAME/.local/bin/artitux gamescope --mangoapp -f -- %command%
```


## Steam app ID

Steam releases include a `steam_settings/steam_appid.txt` file next to the
game's `.exe`. The wrapper reads the app ID from that file and passes it to the
game. Without this, games added to Steam as non-Steam games can close at
startup. F1 25 is one of them.

To turn this off, set `ARTITUX_STEAM_IDS=0`.

## Other launchers

- Faugus Launcher: In **Tools > Launch Settings**, set **Launch Arguments**
  (not **Game Arguments**) to `/home/USERNAME/.local/bin/artitux`, without
  `%command%`. For Gamescope, use `/home/USERNAME/.local/bin/artitux gamescope --`.
- Lutris: Open **Configure > Advanced options > System options**. Set **Command
  prefix** to `/home/USERNAME/.local/bin/artitux`.
- Heroic, Bottles, and other frontends: Put `/home/USERNAME/.local/bin/artitux`
  in the game's **Wrapper** or **Command prefix** field.

Flatpak launchers need access to the installed library. If a launcher accepts
only environment variables, set
`LD_PRELOAD=/home/USERNAME/.local/share/artitux/Artitux.so`. The path must not
contain spaces or colons.

## Configuration

Artitux needs no variables by default.

| Variable | Effect |
| --- | --- |
| `ARTITUX_DEBUG=1` | Turns on diagnostics |
| `ARTITUX_LOG=/absolute/path.log` | Writes diagnostics to a private file |
| `ARTITUX_STEAM_IDS=0` | Turns off the [Steam app ID](#steam-app-id) handling |
| `PROTON_AVX=1` | Reports AVX in the default CPU presentation |
| `ARTITUX_SYSCALL_HACK=1` | Makes Wine use the direct syscall path. Only for titles that need it |
| `ARTITUX_LEGACY_PROFILE=1` | Uses the LinUwUx CPU presentation |
| `ARTITUX_WIN32U_FREE_GUARD=1` | Guards against a duplicate `free` in `win32u` |
| `ARTITUX_RESOLVER_BRIDGE=0` | Diagnosis only. Artifact games need the bridge |
| `ARTITUX_ARTIFACT_NATIVE_STUBS=0` | Diagnosis only. Artifact games need the stubs |

Artitux sets `PROTON_DISABLE_LSTEAMCLIENT=1` unless it is already set. On CPUs
with more than 16 threads, it also limits Wine to 16 CPUs with
`WINE_CPU_TOPOLOGY`, because Artifact reports at most 16. Without this, games
such as Planet Zoo 2 stop at startup. Your own `WINE_CPU_TOPOLOGY` value takes
precedence.

## Known issues

- VBS 2.0 releases do not work.
- `clearcpuid=514` is not tested yet. See [UMIP](#umip).
- Wine uses at most 16 CPU threads. See [Configuration](#configuration).
- Native 32-bit Wine processes cannot load the library.

## Troubleshooting

- Run `~/.local/bin/artitux --check` first.
- `artitux: command not found`: use the full path.
- The game does not start: try it with no other wrappers, and make sure a
  sandboxed launcher can see the wrapper and the library.

To collect a debug log:

```text
ARTITUX_DEBUG=1 ARTITUX_LOG=/tmp/artitux.log /home/USERNAME/.local/bin/artitux %command%
```

Then open a
[bug report](https://github.com/Lumice/artitux/issues/new?template=bug_report.yml)
with the output of `artitux --version` and `--check`, the Artitux log, and the
Proton or launcher log. See [CONTRIBUTING.md](CONTRIBUTING.md) for pull requests
and [SECURITY.md](SECURITY.md) for security issues.

## Build from source

Install Rust 1.98 or newer, a native C linker, and GNU binutils. Then run:

```sh
cargo xtask build
```

The library is written to `target/runtime/Artitux.so`. Use `--debug` for a
debug build or `--output /absolute/path/Artitux.so` for another location.

## Uninstall

```sh
rm -f "$HOME/.local/bin/artitux" "$HOME/.local/share/artitux/Artitux.so"
```

With `--global`, also remove `/usr/local/bin/artitux`. Then remove `artitux`
from your launch options.

## AI disclosure

AI coding assistants helped develop this fork. Each change was tested with a
build, the unit tests, an independent code review, and live game tests.

## License and credits

Artitux is distributed under the terms in [LICENSE](LICENSE) (AGPL-3.0).

Artitux is a fork of [LinUwUx](https://github.com/brcly/linuwux-runtime) by
brcly (`Copyright (C) 2026 LinUwUx`, AGPL-3.0). Lumice forked and modified it
in November 2026.
