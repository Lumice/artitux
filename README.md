# Artitux

[![Latest release](https://img.shields.io/github/v/release/Lumice/artitux)](https://github.com/Lumice/artitux/releases/latest)
[![Check](https://github.com/Lumice/artitux/actions/workflows/check.yml/badge.svg)](https://github.com/Lumice/artitux/actions/workflows/check.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE)

Artitux is a Linux compatibility runtime for Windows games that run through
Wine or Proton. It loads into the game through `LD_PRELOAD`. It keeps these
parts of the system consistent across the game and its child processes: the CPU
profile, the Windows shared system data (`KUSER_SHARED_DATA`), the loader
state, the process heap table, the clocks, the signal handling, and the Wine
environment. Artitux does not change Proton, the game files, or the Wine
prefixes.

Artitux is a fork of [LinUwUx](https://github.com/brcly/linuwux-runtime). It
keeps the core runtime features of LinUwUx: CPUID trapping, KUSER shared data,
signal and syscall routing, Gamescope support, and environment handling. It
adds support for titles that LinUwUx does not cover. If a game already works
with LinUwUx, use LinUwUx.

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
- F1.25.Update.v1.0.141.7865

Artitux works with Artifact releases prepared with VBS 1.9. It does not work
with releases prepared with VBS 2.0. Before you report a problem, find out which
VBS version the release uses.

## Requirements

Valve Proton, Proton Experimental, GE-Proton, and UMU-managed builds are
expected to work. The host needs:

- x86-64 Linux with glibc 2.34 or newer
- A 64-bit Wine or Proton host process, or a modern WoW64 setup
- Working `LD_PRELOAD` support
- Access to the installed library from inside any launcher sandbox

Native 32-bit Wine processes cannot load the 64-bit library. They can print a
`wrong ELF class` warning.

### CPU and kernel prerequisites

Artitux needs UMIP disabled and CPUID faulting available. UMIP (User-Mode
Instruction Prevention) is a CPU security feature. CPUID faulting lets Artitux
answer CPU identification requests from the game. Read both flags first:

```sh
grep -m1 '^flags' /proc/cpuinfo | tr ' ' '\n' | grep -E '^(umip|cpuid_fault)$'
```

- If the output shows `umip`, UMIP is enabled and you must disable it.
- If the output shows `cpuid_fault`, the CPU supports CPUID faulting and you do
  not need an emulation module.

After you install Artitux, `artitux --check` does the same check. It also
reports a loaded `umip_patch` or `cpuid_fault_emulation` module, and whether
the kernel allows FSGSBASE in user space, which Artifact games also need.

Intel 9th generation CPUs and newer, and AMD Ryzen 3000 CPUs and newer, usually
need UMIP disabled. AMD Ryzen AM4 CPUs up to the Ryzen 5000 series and the Steam
Deck usually also need the `cpuid_fault_emulation` DKMS module. The flags are
more reliable than the model name.

#### Disable UMIP

If the output shows `umip`, add this parameter to your kernel command line.
Follow your distribution's bootloader instructions, then reboot:

```text
clearcpuid=514
```

After the reboot, make sure that the change applied:

```sh
cat /proc/cmdline
grep -qw umip /proc/cpuinfo && echo 'UMIP is still enabled' || echo 'UMIP is not enabled'
```

This parameter changes the whole system. The kernel documentation describes
`clearcpuid` as a debugging aid that taints the kernel. To undo the change,
remove the parameter and reboot.

Note: `clearcpuid=514` is not tested with Artitux yet. The tested setups
disabled UMIP with a kernel module instead.

#### CPUID faulting on AMD

If `cpuid_fault` is missing on an AMD AM4 system or a Steam Deck, install the
`cpuid_fault_emulation` DKMS module. The module needs DKMS, build tools, kernel
headers that match your kernel, and AMD virtualization enabled in the firmware.

The Artitux installer does not include this module. Get it from a source that
you trust.

## Install

Run the installer:

```sh
curl -fsSL https://raw.githubusercontent.com/Lumice/artitux/main/install.sh | bash
```

To install a specific release instead of the latest release, set
`ARTITUX_VERSION`:

```sh
curl -fsSL https://raw.githubusercontent.com/Lumice/artitux/main/install.sh | ARTITUX_VERSION=v1.0.3 bash
```

You can also build Artitux from source. See "Build from source" below. The
installer writes these files:

```text
~/.local/bin/artitux
~/.local/share/artitux/Artitux.so
```

The default install does not need root access. To also create the symlink
`/usr/local/bin/artitux`, pass `--global`. The installer then asks for your
`sudo` password:

```sh
curl -fsSL https://raw.githubusercontent.com/Lumice/artitux/main/install.sh | bash -s -- --global
```

If `~/.local/bin` is not in your `PATH` after a default install, add this line
to your shell profile. Then sign out and sign in again:

```sh
export PATH="$HOME/.local/bin:$PATH"
```

Then set the game's launch command to:

```text
/home/USERNAME/.local/bin/artitux %command%
```

## Steam

Add this line under **Properties > Launch Options**:

```text
/home/USERNAME/.local/bin/artitux %command%
```

`artitux` is a command prefix. Put any environment variables before it, for
example `PROTON_LOG=1 /home/USERNAME/.local/bin/artitux %command%`.

For Flatpak Steam, use the full path above. Make sure that the Flatpak can read
`/home/USERNAME/.local/share/artitux/Artitux.so`.

## Gamescope and MangoHud

For normal launches, put `artitux` before the game command:

```text
mangohud /home/USERNAME/.local/bin/artitux %command%
MANGOHUD=1 /home/USERNAME/.local/bin/artitux %command%
```

When Gamescope starts the game, put `artitux` before Gamescope. Gamescope can
start itself again or change the environment that its child processes get.
In this position, Artitux stays loaded when that happens:

```text
/home/USERNAME/.local/bin/artitux gamescope -f -- %command%
/home/USERNAME/.local/bin/artitux gamescope --mangoapp -f -- %command%
```

If you put `artitux` after Gamescope, Artitux loads only in the game process.

When the wrapped command is `gamescope`, the wrapper removes any
`gameoverlayrenderer.so` entry from the inherited `LD_PRELOAD`. This stops
Gamescope from loading a Steam overlay that Artitux did not request.

## Steam app ID

Steam releases include a `steam_settings/steam_appid.txt` file next to the
game's `.exe`. The wrapper reads the app ID from that file and passes it to the
game. Without this, games added to Steam as non-Steam games can close at
startup. F1 25 is one of them.

To turn this off, set `ARTITUX_STEAM_IDS=0`.

## Other launchers

- Faugus Launcher: Edit the game and open **Tools > Launch Settings**. Set
  **Launch Arguments** to `/home/USERNAME/.local/bin/artitux`. Use **Launch
  Arguments**, not **Game Arguments**. Do not add `%command%`. Faugus does not
  replace it, so the launch fails. You can keep the built-in GameMode and
  MangoHud switches on. For Gamescope, set the launch argument to
  `/home/USERNAME/.local/bin/artitux gamescope --`.
- Lutris: Open **Configure > Advanced options > System options**. Set **Command
  prefix** to `/home/USERNAME/.local/bin/artitux`.
- Heroic, Bottles, and other frontends: Put `/home/USERNAME/.local/bin/artitux`
  in the game's **Wrapper** or **Command prefix** field.

For Flatpak launchers, use `/home/USERNAME/.local/bin/artitux` and give the
launcher access to the installed library. If a launcher accepts only
environment variables, set:

| Name | Value |
| --- | --- |
| `LD_PRELOAD` | `/home/USERNAME/.local/share/artitux/Artitux.so` |

The wrapper always loads the installed Artitux library. It puts the library
first in the existing `LD_PRELOAD` value. Use an absolute path with no spaces
and no colons.

## Configuration

Artitux needs no variables by default. You can set these variables:

| Variable | Effect |
| --- | --- |
| `ARTITUX_DEBUG=1` | Turns on runtime diagnostics |
| `ARTITUX_STEAM_IDS=0` | Stops the wrapper from passing the app ID from `steam_settings/steam_appid.txt`. See [Steam app ID](#steam-app-id) |
| `ARTITUX_LOG=/absolute/path.log` | Writes diagnostics to a private file with mode `0600` |
| `PROTON_AVX=1` | Reports AVX in the default CPU presentation. It has no effect with `ARTITUX_LEGACY_PROFILE=1`, which always reports AVX |
| `ARTITUX_SYSCALL_HACK=1` | Clears Wine's `KUSER_SHARED_DATA.SystemCall` flag, so Wine uses the direct syscall path. Set it only for titles that need it |
| `ARTITUX_LEGACY_PROFILE=1` | Uses the generic LinUwUx CPU presentation for the whole process |
| `ARTITUX_WIN32U_FREE_GUARD=1` | Turns on the guard against a duplicate `free` in `win32u`. It is off by default |
| `ARTITUX_RESOLVER_BRIDGE=0` | Turns off the Artifact resolver bridge. Use it only for diagnosis. Artifact games need the bridge |
| `ARTITUX_ARTIFACT_NATIVE_STUBS=0` | Turns off Artitux's native Artifact stubs. Use it only for diagnosis. Artifact games need the stubs |

The first time Artitux runs in a process tree, it sets
`PROTON_DISABLE_LSTEAMCLIENT=1`. It does not change this variable if it already
has a value that is not empty.

On CPUs with more than 16 threads, Artitux also sets `WINE_CPU_TOPOLOGY`. Wine
then uses only the first 16 CPUs that the game can run on, for example
`16:0,1,2,…,15`. Artifact reports at most 16 processors, and Wine must use the
same count. If the counts are different, Wine's random-number calls fail and
some games stop at startup. For example, Planet Zoo 2 shows
`DStorageGetFactory: 0x80004001`. If you set `WINE_CPU_TOPOLOGY` to a value
that is not empty, Artitux uses your value.

## Known issues

- Artifact releases prepared with VBS 2.0 do not work. See
  [Confirmed titles](#confirmed-titles).
- `clearcpuid=514` is not tested with Artitux yet. See
  [Disable UMIP](#disable-umip).
- If the game can run on more than 16 CPU threads, Wine uses only 16 of
  them. See [Configuration](#configuration).
- Native 32-bit Wine processes cannot load the library.

## Troubleshooting

- Run `~/.local/bin/artitux --check` first. It reports the most common setup
  problems.
- `artitux: command not found`: Use the wrapper's full path, or add
  `~/.local/bin` to `PATH`.
- The game does not start: Try `/home/USERNAME/.local/bin/artitux %command%`
  with no other wrappers. For launchers that run in a container, make sure that
  the sandbox can see the wrapper and the library. Also make sure that the
  runner starts a 64-bit Wine host.

To collect a debug log, use:

```text
ARTITUX_DEBUG=1 ARTITUX_LOG=/tmp/artitux.log /home/USERNAME/.local/bin/artitux %command%
```

After you collect the log, remove the debug variables. To report a problem,
open a
[bug report](https://github.com/Lumice/artitux/issues/new?template=bug_report.yml).
Include the output of `~/.local/bin/artitux --version` and `--check`. Attach the
full Artitux log and the Proton, UMU, or launcher log. Before you
open a pull request, read [CONTRIBUTING.md](CONTRIBUTING.md). Report security
issues privately, as [SECURITY.md](SECURITY.md) describes.

## Build from source

Install Rust 1.98 or newer, a native C linker, and GNU binutils. Then run:

```sh
cargo xtask build
```

The build writes the library to `target/runtime/Artitux.so`. You can also use:

```sh
cargo xtask build --debug
cargo xtask build --output /absolute/path/Artitux.so
```

With `--debug`, the build writes to `target/runtime-debug/Artitux.so` instead.

The build checks the public exports, the constructor order, the ELF
architecture, and the linker hardening.

## Uninstall

```sh
rm -f "$HOME/.local/bin/artitux" "$HOME/.local/share/artitux/Artitux.so"
```

If you installed with `install.sh --global`, also remove
`/usr/local/bin/artitux`. Then remove `artitux` or the `LD_PRELOAD` entry from
each launcher.

## AI disclosure

AI coding assistants helped develop this fork. Each change was tested with a
build, the unit tests, an independent code review, and live game tests.

## License and credits

Artitux is distributed under the terms in [LICENSE](LICENSE) (AGPL-3.0).

Artitux is a fork of [LinUwUx](https://github.com/brcly/linuwux-runtime) by
brcly (`Copyright (C) 2026 LinUwUx`, AGPL-3.0). Lumice forked and modified it
in November 2026.
